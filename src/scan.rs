//! Running a scan: what to run, what to run it on, and watching it go.

use crate::*;

/// Build the scanner's argument list from the form.
///
/// Loki's own defaults are the baseline; a control only appears here when it
/// departs from them. `--no-tui` and `--jsonl` are not negotiable: the TUI would
/// fight a child process, and the JSONL *is* the module's input.
pub(crate) fn scan_args(cfg: &Value, target: Option<&str>, out: &Path) -> Vec<String> {
    let flag = |k: &str| cfg.get(k).and_then(Value::as_bool).unwrap_or(false);
    let text_of = |k: &str| {
        cfg.get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };

    let mut a: Vec<String> = vec![
        "--no-tui".into(),
        "-j".into(),
        out.to_string_lossy().into_owned(),
        // Loki also writes a plaintext log and an HTML report by default, both
        // named after the host and the clock and dropped in the working
        // directory — which for us is the scanner's own folder inside `tools/`.
        // The JSONL is what this module reads, so the other two would only
        // accumulate there, one pair per scan, unseen.
        "--no-log".into(),
        "--no-html".into(),
    ];

    match target {
        // Scanning something on disk. Processes are their own scan now, so they
        // are switched off here rather than quietly doubling the work.
        Some(t) => {
            a.push("--folder".into());
            a.push(walkable(t));
            a.push("--no-procs".into());

            // Loki reads only executables and scripts unless told otherwise, so a
            // scan of a folder of documents would examine nothing and report it
            // clean. On by default, and turning it off is the deliberate act.
            if flag("all_files") {
                a.push("--scan-all-files".into());
            }
            if !flag("archives") {
                a.push("--no-archive".into());
            }
        }
        // Scanning this machine's processes. Without `--no-fs` Loki would walk
        // the whole filesystem as well, which is a different job entirely and
        // one nobody asked for here.
        None => a.push("--no-fs".into()),
    }

    // `all-2` etc. are Loki's own spellings for negative thread counts.
    let threads = match text_of("threads").as_str() {
        "all" => Some("0"),
        "all-1" => Some("-1"),
        "all-2" => Some("-2"),
        "1" => Some("1"),
        _ => None,
    };
    if let Some(t) = threads {
        // `--threads=-2`, not `--threads -2`: a negative value as its own
        // argument is read as a flag, and the scanner exits on a usage error
        // having scanned nothing. The equals form leaves no doubt.
        a.push(format!("--threads={t}"));
    }
    for (key, flagname) in [
        ("cpu", "--cpu-limit"),
        ("alert", "--alert-level"),
        ("warning", "--warning-level"),
        ("notice", "--notice-level"),
        ("max_size", "-m"),
    ] {
        let v = text_of(key);
        // Only pass through what is actually a number — a stray character would
        // otherwise make the scanner refuse to start, with the reason buried in
        // output nobody sees.
        if !v.is_empty() && v.chars().all(|c| c.is_ascii_digit()) {
            // These are unsigned, so the separate form is safe — but written the
            // same way as `--threads` so nothing here can drift into the bug
            // that one had.
            a.push(format!("{flagname}={v}"));
        }
    }
    a
}

/// Whether this scan can actually read process memory.
///
/// Loki does not refuse an unprivileged process scan — it logs one line and
/// carries on reading nothing, which looks exactly like a machine with nothing
/// wrong. Better to say so before the scan than to hand back an empty report.
///
/// `None` where it cannot be determined, which is not the same as "no".
pub(crate) fn is_elevated() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        // The effective uid, from the kernel rather than a C call: `Uid:` gives
        // real, effective, saved, filesystem — the second is the one that
        // decides what this process may read.
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = status.lines().find(|l| l.starts_with("Uid:"))?;
        let euid = line.split_whitespace().nth(2)?;
        return Some(euid == "0");
    }
    #[allow(unreachable_code)]
    None
}

/// What this scan is looking at.
///
/// Three different jobs rather than one with switches: they take different
/// inputs, need different privileges, and share almost none of their settings.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Mode {
    /// A folder or a single file the user chose.
    #[default]
    Files,
    /// This machine's running processes.
    Procs,
    /// What starts automatically on this machine, by way of the autoruns module.
    Autoruns,
}

impl Mode {
    pub(crate) fn from_str(s: &str) -> Self {
        match s {
            "procs" => Mode::Procs,
            "autoruns" => Mode::Autoruns,
            _ => Mode::Files,
        }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Mode::Files => "files",
            Mode::Procs => "procs",
            Mode::Autoruns => "autoruns",
        }
    }
    /// The next one to offer, so one button cycles all three.
    pub(crate) fn next(self) -> Self {
        match self {
            Mode::Files => Mode::Procs,
            Mode::Procs => Mode::Autoruns,
            Mode::Autoruns => Mode::Files,
        }
    }
}

/// The capability the autoruns module provides. Optional: the scan is offered
/// only when something in the session actually provides it.
pub(crate) const AUTORUNS_CAP: &str = "autoruns.local";

/// Ask the autoruns module what starts on this machine.
///
/// `list` is its data method — it enumerates on every call and returns plain
/// JSON, so this does not depend on the user having opened its tab.
pub(crate) fn autorun_entries(host: &Host, enabled_only: bool) -> Result<(Vec<Value>, u64), String> {
    let v = host
        .call(AUTORUNS_CAP, "list", json!({}))
        .map_err(|e| e.to_string())?;
    let total = v.get("total").and_then(Value::as_u64).unwrap_or(0);
    let entries: Vec<Value> = v
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| !enabled_only || e.get("enabled").and_then(Value::as_bool).unwrap_or(true))
        .collect();
    Ok((entries, total))
}

/// The program a command line runs, as a path.
///
/// Autostart commands carry arguments and are quoted inconsistently, so the
/// executable has to be picked out rather than assumed to be the whole string.
pub(crate) fn command_target(command: &str) -> Option<PathBuf> {
    let c = command.trim();
    let first = if let Some(rest) = c.strip_prefix('"') {
        rest.split('"').next()?.to_string()
    } else {
        // Unquoted: up to the first space. A path with spaces and no quotes is
        // ambiguous by construction — Windows resolves it by probing, and
        // guessing wrong here would scan the wrong file.
        c.split_whitespace().next()?.to_string()
    };
    let p = PathBuf::from(first);
    p.is_file().then_some(p)
}

/// One autostart entry, laid out for the scanner and kept for the report.
#[derive(Clone)]
pub(crate) struct Staged {
    /// The index its files are named after — the whole mapping back.
    id: usize,
    name: String,
    location: String,
    command: String,
    /// Whether the program it names was found and copied.
    pub(crate) binary: bool,
}

/// Write each entry as its own pair of files for one scan pass.
///
/// A file per entry rather than one manifest, because the mapping back is then
/// the filename: Loki reports per file, so per entry is what the user reads. The
/// files are named by index, never by the entry's own name — that name comes
/// from the registry and is the attacker's to choose, so it has no business in a
/// path.
///
/// Two files each: the command as text, which the YARA rules read as strings,
/// and a copy of the program it runs, which they read as a binary. Copying is
/// what lets one pass cover both; nothing here parses untrusted input, and the
/// programs are already on the machine and already run at boot.
pub(crate) fn stage_autoruns(dir: &Path, entries: &[Value]) -> Vec<Staged> {
    let _ = std::fs::remove_dir_all(dir);
    if std::fs::create_dir_all(dir).is_err() {
        return Vec::new();
    }
    let field = |e: &Value, k: &str| {
        e.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let mut staged = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let command = field(e, "command");
        if command.trim().is_empty() {
            continue;
        }
        // Only the command goes in the text: the entry's name and location are
        // ours to display and would only add strings the rules never asked about.
        if std::fs::write(dir.join(format!("{i:05}.cmd")), &command).is_err() {
            continue;
        }
        let binary = command_target(&command)
            .is_some_and(|src| std::fs::copy(&src, dir.join(format!("{i:05}.bin"))).is_ok());
        staged.push(Staged {
            id: i,
            name: field(e, "name"),
            location: field(e, "location"),
            command,
            binary,
        });
    }
    staged
}

/// Point a finding at the autostart entry it came from.
///
/// Loki reports the scratch file it read; the user needs the key. The index in
/// the filename is the whole mapping.
pub(crate) fn relabel_autorun(ev: &mut Value, staged: &[Staged]) {
    let Some(path) = ev.get("file_path").and_then(Value::as_str) else {
        return;
    };
    let stem = Path::new(path).file_stem().and_then(|s| s.to_str());
    let Some(id) = stem.and_then(|s| s.parse::<usize>().ok()) else {
        return;
    };
    let Some(entry) = staged.iter().find(|s| s.id == id) else {
        return;
    };
    // The location is where it is declared — the registry key, the unit file —
    // which is the thing the user can actually go and change.
    let shown = if entry.location.is_empty() {
        entry.name.clone()
    } else {
        format!("{}  ({})", entry.location, entry.name)
    };
    ev["file_path"] = Value::String(shown);
    // Keep the command where the detail view will show it.
    ev["autorun_command"] = Value::String(entry.command.clone());
}

/// The paths Loki refuses to walk. Its own list, printed at the top of every
/// run: `/proc, /dev, /sys, /run, /media, /volumes, /Volumes, CloudStorage`.
const SKIPPED: [&str; 7] = [
    "/proc", "/dev", "/sys", "/run", "/media", "/volumes", "/Volumes",
];

/// Whether Loki would refuse to walk this target where it stands.
///
/// A prefix test, so the mount point itself counts as well as anything under it,
/// and `/media-backup` is not mistaken for `/media`.
pub(crate) fn is_skipped(target: &str) -> bool {
    let t = format!("{}/", target.trim_end_matches('/'));
    SKIPPED.iter().any(|p| t.starts_with(&format!("{p}/")))
}

/// The chosen target, spelled so the scanner will actually walk it.
///
/// Removable media mounts under [`SKIPPED`] on every desktop Linux there is —
/// `/run/media/<user>/<label>` — which is the exact place a suspect disk gets
/// examined from, and a scan of one read nothing and called it clean.
///
/// `--scan-all-drives` is what Loki's help offers for that, and it is not what
/// the name suggests: it does not mean "and this folder too", it **replaces**
/// the target with every mount on the machine. Choosing one file on a USB stick
/// started a seven-drive scan of the whole system, which is how this was found.
///
/// The exclusion is a prefix test against the path as it was handed over, so the
/// same place named differently is walked normally. A doubled leading slash is
/// that name: the kernel collapses it, every file underneath is read, and the
/// scanner reports the paths back with the same doubling — which [`Event::parse`]
/// undoes before anything else sees them.
///
/// Never on Windows, where a leading `//` names a network share rather than the
/// same path spelled twice.
pub(crate) fn walkable(target: &str) -> String {
    if cfg!(windows) || !is_skipped(target) {
        return target.to_string();
    }
    format!("/{target}")
}

/// Whether the target is inside a cloud-storage folder.
///
/// The one exclusion no spelling gets past: Loki matches `CloudStorage` anywhere
/// in the path rather than at the front of it. Worth telling the user about
/// before the scan, because the alternative is a scan that reads nothing and
/// says everything is fine.
pub(crate) fn is_cloud(target: &str) -> bool {
    target.contains("CloudStorage")
}

/// How far a running scan has got, read from the reports it is writing.
pub(crate) fn scan_progress(outs: &[PathBuf]) -> (usize, usize) {
    let mut lines = 0;
    let mut hits = 0;
    for out in outs {
        let Ok(text) = std::fs::read_to_string(out) else {
            continue;
        };
        for l in text.lines() {
            if l.trim().is_empty() {
                continue;
            }
            lines += 1;
            if Event::parse(l).is_some_and(|e| e.is_match()) {
                hits += 1;
            }
        }
    }
    (lines, hits)
}

/// What the scanner has said so far, most recent last.
///
/// Loki writes no per-file activity — that lives only in its TUI, which is off
/// because it would fight a child process. What it does write is worth showing:
/// which paths it excluded, how many threads it took, whether it is running
/// elevated, and each finding as it lands.
pub(crate) fn scan_output(outs: &[PathBuf], keep: usize) -> Vec<String> {
    let mut out = Vec::new();
    for p in outs {
        let Ok(text) = std::fs::read_to_string(p) else {
            continue;
        };
        for l in text.lines() {
            if let Some(m) = serde_json::from_str::<Value>(l)
                .ok()
                .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string))
                .filter(|m| !m.is_empty())
            {
                out.push(m);
            }
        }
    }
    if out.len() > keep {
        out.drain(..out.len() - keep);
    }
    out
}

/// A scan, running on its own thread.
///
/// Waiting on the scanner is slow I/O, and does not belong on the thread that
/// draws. The worker owns the child process; the UI only ever reads these
/// handles.
pub(crate) struct Job {
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The report being written.
    pub(crate) outs: std::sync::Arc<std::sync::Mutex<Vec<PathBuf>>>,
    pub(crate) error: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

impl Job {
    /// Run the scanner and wait for it.
    pub(crate) fn spawn(
        bin: PathBuf,
        workdir: PathBuf,
        scan_dir: PathBuf,
        target: Option<String>,
        cfg: Value,
    ) -> Job {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};

        let job = Job {
            done: Arc::new(AtomicBool::new(false)),
            cancel: Arc::new(AtomicBool::new(false)),
            outs: Arc::new(Mutex::new(Vec::new())),
            error: Arc::new(Mutex::new(None)),
        };

        let (done, cancel) = (job.done.clone(), job.cancel.clone());
        let outs = job.outs.clone();
        let error = job.error.clone();

        std::thread::spawn(move || {
            use limen_proto::NoConsole;

            let out = scan_dir.join("report.jsonl");
            let _ = std::fs::remove_file(&out);
            outs.lock().unwrap().push(out.clone());
            let args = scan_args(&cfg, target.as_deref(), &out);

            if !cancel.load(Ordering::Relaxed) {
                match std::process::Command::new(&bin)
                    .args(&args)
                    .current_dir(&workdir)
                    .no_console()
                    .spawn()
                {
                    Ok(mut child) => loop {
                        if cancel.load(Ordering::Relaxed) {
                            let _ = child.kill();
                            let _ = child.wait();
                            break;
                        }
                        match child.try_wait() {
                            Ok(Some(_)) | Err(_) => break,
                            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(120)),
                        }
                    },
                    Err(e) => *error.lock().unwrap() = Some(e.to_string()),
                }
            }

            done.store(true, Ordering::Release);
        });

        job
    }

    pub(crate) fn finished(&self) -> bool {
        self.done.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn stop(&self) {
        self.cancel
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Asked to stop, but the worker has not wound up yet.
    pub(crate) fn stopping(&self) -> bool {
        self.cancel.load(std::sync::atomic::Ordering::Relaxed) && !self.finished()
    }
}
