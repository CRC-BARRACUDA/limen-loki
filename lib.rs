//! Runs [Loki-RS](https://github.com/Neo23x0/Loki-RS) from inside Limen and
//! reads what it finds.
//!
//! Loki-RS writes one JSON object per line (`--jsonl <file>`), each a `LogEvent`:
//! a scan boundary, a file or process match, or a plain log line. This module
//! installs the scanner on first use, runs it, and turns that stream into a
//! verdict, a findings table ordered by score, and a detail view carrying the
//! rules that matched and the strings that triggered them.
//!
//! The scanner is not vendored. It is fetched from its own release into `tools/`
//! inside this module, so removing the module removes it, and updating the
//! module re-fetches whatever version that module expects.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use limen_sdk_rust::ui::{
    button, checkbox, file, label, row, select, separator, step, table, text, window, window_auto,
    window_modal_sized, Widget,
};
use limen_sdk_rust::{export_module, json, rpc, Catalog, Handler, Host, RpcError, Value};

/// Severity, as Loki-RS scores it. `ALERT` at 80, `WARNING` at 60, `NOTICE` at
/// 40 by default, though the thresholds are configurable at scan time — so the
/// level is read from the record rather than recomputed from the score.
const LEVELS: [&str; 6] = ["ALERT", "WARNING", "NOTICE", "INFO", "ERROR", "DEBUG"];

/// Levels shown unless the user asks for more. A full scan logs thousands of
/// `INFO` lines; opening on those would bury the handful that matter.
const DEFAULT_LEVELS: [&str; 3] = ["ALERT", "WARNING", "ERROR"];

const PAGE: usize = 60;

/// The Loki-RS release this module is built and tested against.
///
/// Pinned rather than resolved to `latest`: a scan report's shape is this
/// module's input, and a scanner that changed underneath it could quietly stop
/// matching. Raising this is a deliberate edit, and because `tools/` is wiped
/// when the module updates, a new module version fetches its own scanner.
const LOKI_VERSION: &str = "2.12.0";

/// Where the release lives. Asset names are `loki-<os>-<arch>-v<ver>.<ext>`,
/// each with a `.sha256` sidecar beside it.
const LOKI_RELEASES: &str = "https://github.com/Neo23x0/Loki-RS/releases/download";

/// This module's own translations (its `locales/*.toml`, embedded). English is
/// the default/fallback; `host.locale()` selects the active one at render time.
fn catalog() -> &'static Catalog {
    static C: std::sync::OnceLock<Catalog> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        Catalog::new(&[
            ("en", include_str!("locales/en.toml")),
            ("uk", include_str!("locales/uk.toml")),
        ])
    })
}

/// The install steps, as keys — resolved against the catalog at render time.
const STEP_KEYS: [&str; 4] = [
    "steps.platform",
    "steps.download",
    "steps.verify",
    "steps.unpack",
];

// ---------------------------------------------------------------------------
// Reading a report
// ---------------------------------------------------------------------------

/// One parsed line of the report.
///
/// Kept as the raw `Value` plus the few fields worth indexing: the schema has
/// some twenty optional fields and more will arrive, so the detail view reads
/// from the original object rather than from anything this struct chose to keep.
#[derive(Clone)]
struct Event {
    raw: Value,
    level: String,
    event_type: String,
    score: f64,
}

impl Event {
    fn parse(line: &str) -> Option<Self> {
        let raw: Value = serde_json::from_str(line).ok()?;
        Some(Event {
            level: str_of(&raw, "level").unwrap_or_default(),
            event_type: str_of(&raw, "event_type").unwrap_or_default(),
            score: raw.get("score").and_then(Value::as_f64).unwrap_or(0.0),
            raw,
        })
    }

    /// Whether this line is a finding rather than a scan boundary or a log line.
    fn is_match(&self) -> bool {
        matches!(self.event_type.as_str(), "file_match" | "process_match")
    }

    /// What the finding is about: a path for a file, `name (pid)` for a process.
    fn subject(&self) -> String {
        if let Some(p) = str_of(&self.raw, "file_path") {
            return p;
        }
        match (
            self.raw.get("pid").and_then(Value::as_u64),
            str_of(&self.raw, "process_name"),
        ) {
            (Some(pid), Some(name)) => format!("{name} ({pid})"),
            (Some(pid), None) => format!("pid {pid}"),
            _ => str_of(&self.raw, "message").unwrap_or_default(),
        }
    }

    /// The rules that matched, joined for the table's one-line summary.
    fn rules(&self) -> String {
        let Some(rs) = self.raw.get("reasons").and_then(Value::as_array) else {
            return str_of(&self.raw, "message").unwrap_or_default();
        };
        rs.iter()
            .filter_map(|r| str_of(r, "message"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn str_of(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

/// The tallies Loki prints when a scan ends.
///
/// It reports them as one English sentence, which is no use in another language
/// and no use as data. The numbers are pulled out so the module can say them in
/// its own words — and show them or not, depending on how much detail was asked
/// for.
#[derive(Default, Clone)]
struct Stats {
    files: u64,
    files_matched: u64,
    procs: u64,
    procs_matched: u64,
    /// Seconds rather than the string Loki printed, so they can be added up and
    /// formatted for whoever is reading them.
    secs: f64,
}

impl Stats {
    /// Fold another scan's tallies into these.
    fn merge(&mut self, other: &Stats) {
        self.files += other.files;
        self.files_matched += other.files_matched;
        self.procs += other.procs;
        self.procs_matched += other.procs_matched;
        self.secs += other.secs;
    }
}

/// `4.8` -> `4.8s`, `92.0` -> `1m 32s`.
fn fmt_secs(secs: f64) -> String {
    if secs < 60.0 {
        format!("{secs:.1}s")
    } else {
        format!("{}m {}s", (secs / 60.0) as u64, (secs % 60.0) as u64)
    }
}

impl Stats {
    /// Read `Files scanned: 0 Matched: 0 | Processes scanned: 0 Matched: 0 …
    /// Scan Duration: 4.80s`.
    ///
    /// Positional rather than regex: the two `Matched:` counts are told apart by
    /// which section they follow, so the file count cannot be read as the
    /// process one.
    fn parse(msg: &str) -> Option<Self> {
        let num_after = |hay: &str, key: &str| -> Option<u64> {
            let i = hay.find(key)? + key.len();
            hay[i..]
                .trim_start()
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|d| d.parse().ok())
        };
        let files_part = msg.split('|').next().unwrap_or("");
        let procs_part = msg.split('|').nth(1).unwrap_or("");
        // "4.80s" -> 4.80. Anything else leaves it at zero rather than guessing.
        let secs = msg
            .find("Scan Duration:")
            .and_then(|i| {
                msg[i + "Scan Duration:".len()..]
                    .split_whitespace()
                    .next()
                    .map(|d| d.trim_end_matches('s'))
                    .and_then(|d| d.parse::<f64>().ok())
            })
            .unwrap_or(0.0);
        Some(Stats {
            files: num_after(files_part, "Files scanned:")?,
            files_matched: num_after(files_part, "Matched:").unwrap_or(0),
            procs: num_after(procs_part, "Processes scanned:").unwrap_or(0),
            procs_matched: num_after(procs_part, "Matched:").unwrap_or(0),
            secs,
        })
    }
}

/// `2026-08-03T19:44:38.546148389+00:00` -> `2026-08-03 19:44:38`.
///
/// The offset and the nanoseconds are noise on screen; nobody reading a scan
/// report needs the ninth decimal place of when it started.
fn pretty_time(ts: &str) -> String {
    let Some(t) = ts.find('T') else {
        return ts.to_string();
    };
    // Cut at the fractional seconds or the offset, whichever comes first. The
    // search starts after the `T` because the date half uses `-` as a separator
    // and a negative offset would otherwise be found inside the year.
    let time = &ts[t + 1..];
    let cut = time.find(['.', '+', '-', 'Z']).unwrap_or(time.len());
    format!("{} {}", &ts[..t], &time[..cut])
}

/// A parsed report: the findings, plus whatever the scan boundaries told us.
#[derive(Default)]
struct Report {
    path: String,
    findings: Vec<Event>,
    /// Level -> how many findings carried it, for the filter chips.
    counts: BTreeMap<String, usize>,
    hostname: String,
    started: String,
    ended: String,
    summary: String,
    stats: Option<Stats>,
    /// An autostart scan: how many entries were checked, and how many named a
    /// program that could not be read. The second number matters — autoruns
    /// skips keys it cannot see without admin, and a command whose program is
    /// missing was only ever checked as text.
    autoruns: Option<(usize, usize)>,
    /// Lines that were not valid JSON. A scan killed part-way leaves a truncated
    /// last line, so this is expected rather than exceptional — but it is
    /// reported, because silently dropping input is how a reader lies.
    skipped: usize,
}

/// Parse a report.
///
/// Every line is independent, so a bad one is skipped rather than failing the
/// file: a report from an interrupted scan is exactly when you most want to read
/// what did get written.
///
fn parse(text: &str) -> Report {
    let mut r = Report::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(ev) = Event::parse(line) else {
            r.skipped += 1;
            continue;
        };
        match ev.event_type.as_str() {
            "scan_start" => {
                r.hostname = str_of(&ev.raw, "hostname").unwrap_or_default();
                // The earliest start and the latest finish bracket the whole run.
                let started = str_of(&ev.raw, "timestamp").unwrap_or_default();
                if r.started.is_empty() || started < r.started {
                    r.started = started;
                }
            }
            "scan_end" => {
                let ended = str_of(&ev.raw, "timestamp").unwrap_or_default();
                if ended > r.ended {
                    r.ended = ended;
                }
                r.summary = str_of(&ev.raw, "message").unwrap_or_default();
                if let Some(s) = Stats::parse(&r.summary) {
                    match &mut r.stats {
                        Some(acc) => acc.merge(&s),
                        None => r.stats = Some(s),
                    }
                }
            }
            _ => {}
        }
        if ev.is_match() {
            *r.counts.entry(ev.level.clone()).or_insert(0) += 1;
            r.findings.push(ev);
        }
    }
    // Worst first — that is the order anyone reading a scan report wants.
    r.findings.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    r
}

// ---------------------------------------------------------------------------
// Installing the scanner
// ---------------------------------------------------------------------------

/// Where this module keeps the scanner: `tools/loki-<version>/` inside its own
/// directory.
///
/// Inside the module, not beside Limen, so the tool's life is the module's life
/// — remove the module and the scanner goes with it, update the module and the
/// scanner is re-fetched at whatever version that module expects. `tools/` is
/// excluded from the module's trust digest, so filling it does not revoke the
/// module's approval.
fn install_root(host: &Host) -> Option<PathBuf> {
    let dir = host.module_dir()?;
    Some(
        Path::new(&dir)
            .join("tools")
            .join(format!("loki-{LOKI_VERSION}")),
    )
}

/// The scanner binary, if it is there.
fn loki_bin(host: &Host) -> Option<PathBuf> {
    let root = install_root(host)?;
    let name = if cfg!(windows) { "loki.exe" } else { "loki" };
    // The archive unpacks flat, but look one level down too rather than assume.
    let direct = root.join(name);
    if direct.exists() {
        return Some(direct);
    }
    std::fs::read_dir(&root)
        .ok()?
        .flatten()
        .map(|e| e.path().join(name))
        .find(|p| p.exists())
}

/// The release asset for this machine, or `None` where Loki-RS publishes none.
fn asset_name(os: &str, arch: &str) -> Option<String> {
    let ext = match os {
        "windows" => "zip",
        "linux" | "macos" => "tar.gz",
        _ => return None,
    };
    if !matches!(arch, "x86_64" | "aarch64") {
        return None;
    }
    Some(format!("loki-{os}-{arch}-v{LOKI_VERSION}.{ext}"))
}

/// Fetch `url` to `dest` with curl.
///
/// curl rather than a bundled HTTP stack: a module that shells out stays small
/// and inherits the system's TLS trust. `-f` so an HTTP error is a failure
/// rather than a saved error page, `-L` to follow the release redirect.
fn fetch(url: &str, dest: &Path) -> Result<(), String> {
    use limen_proto::NoConsole;
    let out = std::process::Command::new("curl")
        .args(["-fsSL", "--max-time", "600", "-o"])
        .arg(dest)
        .arg(url)
        .no_console()
        .output()
        .map_err(|e| format!("curl could not be started: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "download failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// SHA-256 of a file, lower-case hex.
fn sha256_of(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(format!("{:x}", h.finalize()))
}

/// Unpack the release archive into `dest`.
///
/// `tar` handles both: GNU tar for `.tar.gz`, and bsdtar — which is `tar` on
/// Windows 10+ and macOS — reads zip, so there is no second code path and no
/// unzip dependency.
fn unpack(archive: &Path, dest: &Path) -> Result<(), String> {
    use limen_proto::NoConsole;
    std::fs::create_dir_all(dest).map_err(|e| format!("creating {}: {e}", dest.display()))?;
    let gz = archive.to_string_lossy().ends_with(".tar.gz");
    let out = std::process::Command::new("tar")
        .arg(if gz { "-xzf" } else { "-xf" })
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .no_console()
        .output()
        .map_err(|e| format!("tar could not be started: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "unpacking failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Make the unpacked binaries executable.
///
/// A tarball carries its modes, but a zip does not — and on Unix an extracted
/// file without `+x` cannot be run, which would fail later and further away.
#[cfg(unix)]
fn make_executable(root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p
                .file_name()
                .is_some_and(|n| n == "loki" || n == "loki-util")
            {
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755));
            }
        }
    }
}

#[cfg(not(unix))]
fn make_executable(_root: &Path) {}

/// One step of the install. Returns the message to show if it fails.
///
/// Each runs in its own invocation, so the UI reports progress instead of
/// freezing for the length of a 12 MB download.
fn run_install_step(host: &Host, lang: &str, step: usize) -> Result<(), String> {
    let t = |k: &str| catalog().tr(lang, k);
    let root = install_root(host).ok_or_else(|| t("install.no_dir"))?;
    let tools = root.parent().unwrap_or(&root).to_path_buf();
    let staging = tools.join(".download");
    let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
    let asset = asset_name(os, arch)
        .ok_or_else(|| t("install.unsupported").replace("{platform}", &format!("{os}-{arch}")))?;
    let archive = staging.join(&asset);

    match step {
        // Decide what to fetch, and start from a clean slate so a half-finished
        // earlier attempt cannot be mistaken for a good install.
        0 => {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&staging);
            std::fs::create_dir_all(&staging).map_err(|e| format!("{}: {e}", staging.display()))?;
            Ok(())
        }
        // The archive and the checksum published beside it.
        1 => {
            let base = format!("{LOKI_RELEASES}/v{LOKI_VERSION}");
            fetch(&format!("{base}/{asset}"), &archive)?;
            fetch(
                &format!("{base}/{asset}.sha256"),
                &staging.join(format!("{asset}.sha256")),
            )
        }
        // Verify before unpacking, never after: this is a binary that will be
        // run, so a mismatch must stop the install rather than be reported once
        // the thing is already on disk and executable.
        2 => {
            let sidecar = std::fs::read_to_string(staging.join(format!("{asset}.sha256")))
                .map_err(|e| format!("reading checksum: {e}"))?;
            // `sha256sum` format: "<hash>  <filename>".
            let want = sidecar
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_lowercase();
            let got = sha256_of(&archive)?;
            if want.is_empty() || want != got {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(t("install.bad_checksum")
                    .replace("{want}", &want)
                    .replace("{got}", &got));
            }
            Ok(())
        }
        // Unpack, make it runnable, and drop the archive — keeping 12 MB of
        // tarball beside the unpacked copy helps nobody.
        3 => {
            unpack(&archive, &root)?;
            make_executable(&root);
            let _ = std::fs::remove_dir_all(&staging);
            if loki_bin(host).is_none() {
                return Err(t("install.no_binary"));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Settings, and the signatures the user brings
// ---------------------------------------------------------------------------

/// Scan settings live here rather than on the scan screen.
///
/// The tab asks one question — what do you want scanned — and everything else
/// sits behind Configure, where it is set once and remembered. Kept as JSON
/// because that is what the form sends back and what is written to disk.
fn default_settings() -> Value {
    json!({
        "archives": true,
        "all_files": true,
        "threads": "all-2",
        "cpu": "100",
        "alert": "80",
        "warning": "60",
        "notice": "40",
        "max_size": "64000000",
    })
}

/// Where settings and user-supplied signatures live: `tools/`, inside the
/// module.
///
/// `tools/` is excluded from the module's trust digest, so writing here does not
/// revoke the module's approval — settings saved in the UI would otherwise mark
/// the module as modified. It also survives a scanner reinstall, which only
/// clears `tools/loki-<version>/`.
fn tools_root(host: &Host) -> Option<PathBuf> {
    Some(Path::new(&host.module_dir()?).join("tools"))
}

fn settings_path(host: &Host) -> Option<PathBuf> {
    Some(tools_root(host)?.join("settings.json"))
}

/// Read saved settings, filling in anything absent from the defaults.
///
/// Merged rather than replaced so a settings file written by an older version —
/// missing whatever was added since — still loads instead of resetting
/// everything the user chose.
fn load_settings(host: &Host) -> Value {
    let mut s = default_settings();
    let saved = settings_path(host)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| serde_json::from_str::<Value>(&t).ok());
    if let (Some(Value::Object(saved)), Some(base)) = (saved, s.as_object_mut()) {
        for (k, v) in saved {
            if base.contains_key(&k) {
                base.insert(k, v);
            }
        }
    }
    s
}

fn save_settings(host: &Host, s: &Value) {
    let Some(p) = settings_path(host) else { return };
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, serde_json::to_string_pretty(s).unwrap_or_default());
}

/// The IOC files Loki reads, by the name it expects on disk.
///
/// These paths are fixed in the scanner — it looks for `iocs/hash-iocs.txt` and
/// the rest by name — so a file the user adds cannot simply be dropped in beside
/// them under its own name. It is filed by kind and merged into these at scan
/// time.
/// `keywords.txt` ships in the signatures directory but Loki 2.12.0 never loads
/// it — a full debug run mentions keywords nowhere. It is deliberately absent
/// here: offering a kind the scanner ignores would take someone's indicators and
/// quietly do nothing with them.
const IOC_KINDS: [(&str, &str); 3] = [
    ("hashes", "hash-iocs.txt"),
    ("filenames", "filename-iocs.txt"),
    ("c2", "c2-iocs.txt"),
];

/// Where a user-supplied signature is kept: `tools/custom/yara/` for rules,
/// `tools/custom/iocs/<kind>/` for indicators.
fn custom_dir(host: &Host, kind: &str) -> Option<PathBuf> {
    let root = tools_root(host)?.join("custom");
    Some(match kind {
        "yara" => root.join("yara"),
        k => root.join("iocs").join(k),
    })
}

/// What the bundled YARA rule set is, as `(rule count, build date)`.
///
/// Read from the file rather than remembered, because `loki-util update`
/// replaces it behind our back — and because a rule set's age is the thing worth
/// showing: the set shipped in a release is as old as the release.
fn bundled_rules(host: &Host) -> Option<(usize, String)> {
    let text = std::fs::read_to_string(
        install_root(host)?
            .join("signatures")
            .join("yara")
            .join("yara-rules-core.yar"),
    )
    .ok()?;
    let count = text.lines().filter(|l| l.starts_with("rule ")).count();
    // YARA-Forge stamps the package header with the date it was generated.
    let date = text
        .lines()
        .take(40)
        .find_map(|l| l.split("Creation Date:").nth(1))
        .map(|d| d.trim().to_string())
        .unwrap_or_default();
    Some((count, date))
}

/// Refresh the bundled rule set from YARA-Forge.
fn update_bundled_rules(host: &Host) -> Result<(), String> {
    use limen_proto::NoConsole;
    let root = install_root(host).ok_or_else(|| "no module directory".to_string())?;
    let util = root.join(if cfg!(windows) { "loki-util.exe" } else { "loki-util" });
    if !util.exists() {
        return Err("loki-util is not installed".into());
    }
    let out = std::process::Command::new(&util)
        .arg("update")
        // It writes into `./signatures`, so it has to run from the scanner's own
        // directory just as the scanner does.
        .current_dir(&root)
        .no_console()
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let last = err.lines().last().unwrap_or("").trim();
        return Err(if last.is_empty() {
            "the updater exited with an error".into()
        } else {
            last.to_string()
        });
    }
    Ok(())
}

/// Everything the user has added, as `(kind, file name)`.
fn list_custom(host: &Host) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for kind in std::iter::once("yara").chain(IOC_KINDS.iter().map(|(k, _)| *k)) {
        let Some(dir) = custom_dir(host, kind) else {
            continue;
        };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        out.extend(names.into_iter().map(|n| (kind.to_string(), n)));
    }
    out
}

/// Copy a signature file the user picked into the module's own store.
///
/// Copied rather than remembered by path: a rule referenced where it happens to
/// sit today would silently stop being scanned the moment it is moved, and a
/// scan quietly missing a rule is worse than one that never had it.
fn add_custom(host: &Host, kind: &str, src: &str) -> Result<(), String> {
    let src = Path::new(src.trim());
    if !src.is_file() {
        return Err("not a file".into());
    }
    let name = src
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| "no file name".to_string())?;
    let dir = custom_dir(host, kind).ok_or_else(|| "no module directory".to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::copy(src, dir.join(name)).map_err(|e| e.to_string())?;
    Ok(())
}

fn remove_custom(host: &Host, kind: &str, name: &str) {
    // Only ever a bare file name from our own listing — a path from elsewhere
    // could otherwise walk out of the store and delete something else.
    if name.contains(['/', '\\']) || name.contains("..") {
        return;
    }
    if let Some(dir) = custom_dir(host, kind) {
        let _ = std::fs::remove_file(dir.join(name));
    }
}

/// Put the user's signatures where the scanner will look, just before a scan.
///
/// The scanner's own `signatures/` directory is rebuilt from the store each
/// time rather than written to once: a reinstall replaces that directory
/// wholesale, and settings that survive a reinstall but signatures that quietly
/// do not would be the worst of both.
fn sync_signatures(host: &Host) {
    let Some(root) = install_root(host) else {
        return;
    };
    let sigs = root.join("signatures");
    if !sigs.is_dir() {
        return;
    }

    // Rules: each is its own file, so they are copied in under a marked name and
    // any from a previous scan are cleared first.
    let yara = sigs.join("yara");
    if let Ok(entries) = std::fs::read_dir(&yara) {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().starts_with("limen-custom-") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    if let Some(dir) = custom_dir(host, "yara") {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let _ = std::fs::copy(e.path(), yara.join(format!("limen-custom-{name}")));
            }
        }
    }

    // Indicators: the scanner reads four fixed files, so everything of a kind is
    // concatenated into the one file it expects.
    for (kind, filename) in IOC_KINDS {
        let mut merged = String::from("# Written by Limen from the module's signature store.\n");
        if let Some(dir) = custom_dir(host, kind) {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                let mut files: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
                files.sort();
                for f in files {
                    if let Ok(text) = std::fs::read_to_string(&f) {
                        merged.push_str(&text);
                        if !text.ends_with('\n') {
                            merged.push('\n');
                        }
                    }
                }
            }
        }
        let _ = std::fs::write(sigs.join("iocs").join(filename), merged);
    }
}

// ---------------------------------------------------------------------------
// Running a scan
// ---------------------------------------------------------------------------

/// Build the scanner's argument list from the form.
///
/// Loki's own defaults are the baseline; a control only appears here when it
/// departs from them. `--no-tui` and `--jsonl` are not negotiable: the TUI would
/// fight a child process, and the JSONL *is* the module's input.
fn scan_args(cfg: &Value, target: Option<&str>, out: &Path) -> Vec<String> {
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
            a.push(t.to_string());
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
            // Loki excludes /media, /Volumes and cloud-storage mounts by default,
            // so a folder chosen from one of them would be scanned as zero files
            // and reported clean. Nobody picking a folder should have to know
            // that list exists, so the flag follows the target rather than a
            // control the user has to find.
            if target_needs_all_drives(t) {
                a.push("--scan-all-drives".into());
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
        a.push("--threads".into());
        a.push(t.into());
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
            a.push(flagname.into());
            a.push(v);
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
fn is_elevated() -> Option<bool> {
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
enum Mode {
    /// A folder or a single file the user chose.
    #[default]
    Files,
    /// This machine's running processes.
    Procs,
    /// What starts automatically on this machine, by way of the autoruns module.
    Autoruns,
}

impl Mode {
    fn from_str(s: &str) -> Self {
        match s {
            "procs" => Mode::Procs,
            "autoruns" => Mode::Autoruns,
            _ => Mode::Files,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Mode::Files => "files",
            Mode::Procs => "procs",
            Mode::Autoruns => "autoruns",
        }
    }
    /// The next one to offer, so one button cycles all three.
    fn next(self) -> Self {
        match self {
            Mode::Files => Mode::Procs,
            Mode::Procs => Mode::Autoruns,
            Mode::Autoruns => Mode::Files,
        }
    }
}

/// The capability the autoruns module provides. Optional: the scan is offered
/// only when something in the session actually provides it.
const AUTORUNS_CAP: &str = "autoruns.local";

/// Ask the autoruns module what starts on this machine.
///
/// `list` is its data method — it enumerates on every call and returns plain
/// JSON, so this does not depend on the user having opened its tab.
fn autorun_entries(host: &Host, enabled_only: bool) -> Result<(Vec<Value>, u64), String> {
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
        .filter(|e| {
            !enabled_only || e.get("enabled").and_then(Value::as_bool).unwrap_or(true)
        })
        .collect();
    Ok((entries, total))
}

/// The program a command line runs, as a path.
///
/// Autostart commands carry arguments and are quoted inconsistently, so the
/// executable has to be picked out rather than assumed to be the whole string.
fn command_target(command: &str) -> Option<PathBuf> {
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
struct Staged {
    /// The index its files are named after — the whole mapping back.
    id: usize,
    name: String,
    location: String,
    command: String,
    /// Whether the program it names was found and copied.
    binary: bool,
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
fn stage_autoruns(dir: &Path, entries: &[Value]) -> Vec<Staged> {
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
fn relabel_autorun(ev: &mut Value, staged: &[Staged]) {
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

/// Whether the chosen target sits somewhere Loki skips unless told otherwise.
///
/// Its default exclusions cover removable and mounted media — the exact places
/// people scan a suspect disk from. Asked of the target rather than offered as a
/// setting: a scan of a USB stick that quietly reads nothing is worse than one
/// that takes a moment longer.
fn target_needs_all_drives(target: &str) -> bool {
    const MOUNTED: [&str; 5] = ["/media/", "/mnt/", "/Volumes/", "/volumes/", "/run/media/"];
    // Trailing separator so the prefix matches the mount point itself as well as
    // anything under it, and `/media-backup` is not mistaken for `/media`.
    let t = format!("{}/", target.trim_end_matches('/'));
    MOUNTED.iter().any(|m| t.starts_with(m)) || t.contains("CloudStorage/")
}

/// How far a running scan has got, read from the reports it is writing.
fn scan_progress(outs: &[PathBuf]) -> (usize, usize) {
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

/// A scan, running on its own thread.
///
/// Waiting on the scanner is slow I/O, and does not belong on the thread that
/// draws. The worker owns the child process; the UI only ever reads these
/// handles.
struct Job {
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The report being written.
    outs: std::sync::Arc<std::sync::Mutex<Vec<PathBuf>>>,
    error: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

impl Job {
    /// Run the scanner and wait for it.
    fn spawn(
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

    fn finished(&self) -> bool {
        self.done.load(std::sync::atomic::Ordering::Acquire)
    }

    fn stop(&self) {
        self.cancel
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Asked to stop, but the worker has not wound up yet.
    fn stopping(&self) -> bool {
        self.cancel.load(std::sync::atomic::Ordering::Relaxed) && !self.finished()
    }
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

/// Offered when the scanner is not installed.
fn install_view(lang: &str, err: Option<&str>) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    // A native module is compiled for the machine it runs on, so its own build
    // constants *are* the host's platform — no round trip needed.
    let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
    let asset = asset_name(os, arch);

    let mut w = vec![
        label(t("install.missing")).strong(),
        label(t("install.what")).weak(),
        separator(),
    ];
    match &asset {
        Some(a) => {
            w.push(label(format!("{}  v{LOKI_VERSION}", t("install.version"))).mono());
            w.push(label(format!("{}  {os}-{arch}", t("install.platform"))).mono());
            w.push(label(format!("{}  {a}", t("install.download"))).mono());
            w.push(label(t("install.size_note")).weak());
            w.push(separator());
            w.push(
                button(
                    t("install.button").replace("{version}", LOKI_VERSION),
                    "scan.ioc",
                    "install",
                )
                .primary(),
            );
        }
        // Say so plainly rather than offering a button that cannot work.
        None => w.push(
            label(t("install.unsupported").replace("{platform}", &format!("{os}-{arch}"))).strong(),
        ),
    }
    if let Some(e) = err {
        w.push(separator());
        w.push(label(e).strong());
    }
    window(t("title"), w)
}

/// The install, one step at a time.
///
/// `done` steps are behind us, `done` is running. Each view auto-invokes the
/// next step, so a 12 MB download reports progress instead of freezing.
fn installing_view(lang: &str, done: usize) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    let mut w = vec![label(t("install.running").replace("{version}", LOKI_VERSION)).strong()];
    for (i, key) in STEP_KEYS.iter().enumerate() {
        let state = match i.cmp(&done) {
            std::cmp::Ordering::Less => "done",
            std::cmp::Ordering::Equal => "loading",
            std::cmp::Ordering::Greater => "pending",
        };
        w.push(step(t(key), state));
    }
    if done >= STEP_KEYS.len() {
        // Finished: stop the chain by returning a plain window.
        w.push(separator());
        w.push(label(t("install.done")).strong());
        w.push(button(t("install.continue_btn"), "scan.ioc", "ui").primary());
        return window(t("title"), w);
    }
    window_auto(t("title"), w, "scan.ioc", "i_step", json!({ "step": done }))
}

/// The tab: one question — what should be scanned — and the button that answers
/// it.
///
/// Everything else is behind Configure. A scan target is what changes every
/// time; thresholds and thread counts are set once and then wanted out of the
/// way, so they live in a pop-up rather than competing with the field that
/// actually needs filling in.
fn main_view(
    lang: &str,
    cfg: &Value,
    custom: usize,
    mode: Mode,
    has_autoruns: bool,
    err: Option<&str>,
) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    let mut w = vec![
        // The version and the way to replace it belong together: reinstalling is
        // something you reach for *because* of what the version says.
        row(vec![
            label(format!("Loki-RS v{LOKI_VERSION}")).strong(),
            button(t("scan.reinstall"), "scan.ioc", "install"),
        ]),
        separator(),
        // One button naming the scan it takes you to. The three are different
        // jobs — a path you choose, this machine's processes, what it starts on
        // its own — so almost nothing on this screen is shared between them.
        // Autostart is skipped when nothing provides it.
        {
            let mut next = mode.next();
            if next == Mode::Autoruns && !has_autoruns {
                next = next.next();
            }
            button(t(&format!("scan.to_{}", next.as_str())), "scan.ioc", "mode")
                .args(json!({ "mode": next.as_str() }))
        },
        separator(),
    ];

    if mode == Mode::Autoruns {
        w.push(label(t("scan.autoruns_what")).weak());
    } else if mode == Mode::Procs {
        // No privilege warning here: the scan asks the operating system for
        // what it needs when it starts. Saying it twice — once as a warning and
        // again as a prompt — only makes the prompt look like a failure.
        w.push(label(t("scan.procs_what")).weak());
    } else {
        // Loki takes a folder or a single file, so the field does too.
        w.push(
            file("target")
                .label(t("scan.target"))
                .placeholder(t("scan.target_hint"))
                .files_or_dirs()
                .browse(t("scan.browse_file"))
                .browse_dir(t("scan.browse_dir")),
        );
    }

    w.push(separator());
    // What the scan will actually do, in one line — the settings are out of
    // sight, and a scan whose behaviour is invisible is one nobody can trust.
    w.push(label(settings_summary(lang, cfg, custom, mode)).weak());
    w.push(row(vec![
        button(t("scan.run"), "scan.ioc", "scan").primary(),
        button(t("scan.configure"), "scan.ioc", "config"),
    ]));

    if let Some(e) = err {
        w.push(separator());
        w.push(label(e).strong());
    }
    window(t("title"), w)
}

/// A checkbox that opens in the state it was saved in. The SDK's `checked()`
/// only sets the default on, so the "off" case needs the plain widget.
fn boxed(w: Widget, on: bool) -> Widget {
    if on {
        w.checked()
    } else {
        w
    }
}

/// One line describing what the current settings will do.
fn settings_summary(lang: &str, cfg: &Value, custom: usize, mode: Mode) -> String {
    let t = |k: &str| catalog().tr(lang, k);
    let flag = |k: &str| cfg.get(k).and_then(Value::as_bool).unwrap_or(false);
    let mut parts = Vec::new();
    if mode == Mode::Autoruns {
        parts.push(t("summary.autoruns_mode"));
    } else if mode == Mode::Procs {
        parts.push(t("summary.procs_mode"));
    } else {
        parts.push(if flag("all_files") {
            t("summary.all_files")
        } else {
            t("summary.exe_only")
        });
        if flag("archives") {
            parts.push(t("summary.archives"));
        }
    }
    if custom > 0 {
        parts.push(t("summary.custom").replace("{n}", &custom.to_string()));
    }
    parts.join(" · ")
}

/// The settings pop-up, over the tab it was opened from.
fn settings_modal(lang: &str, cfg: &Value, mode: Mode) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    let on = |k: &str| cfg.get(k).and_then(Value::as_bool).unwrap_or(false);
    let txt = |k: &str| {
        cfg.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    // The saved value first, so the control opens on what is actually set rather
    // than on the list's own first entry.
    let choices = |k: &str, rest: &[&str]| {
        let cur = txt(k);
        let mut v = vec![cur.clone()];
        v.extend(rest.iter().filter(|c| **c != cur).map(|c| c.to_string()));
        v
    };

    let mut w = Vec::new();
    // A process or autostart scan reads no folder, so file settings would only
    // be controls that do nothing — worse than not offering them.
    if mode == Mode::Files {
        w.push(label(t("scan.section_scanning")).weak());
        w.push(boxed(checkbox("all_files", t("scan.all_files")), on("all_files")));
        w.push(boxed(checkbox("archives", t("scan.archives")), on("archives")));
        w.push(separator());
    }
    w.extend(vec![
        row(vec![
            select("threads", choices("threads", &["all-2", "all-1", "all", "1"]))
                .label(t("scan.threads")),
            select("cpu", choices("cpu", &["100", "80", "60", "40"])).label(t("scan.cpu")),
        ]),
        separator(),
        label(t("scan.section_thresholds")).weak(),
        row(vec![
            text("alert").label(t("scan.alert")).default(txt("alert")),
            text("warning").label(t("scan.warning")).default(txt("warning")),
            text("notice").label(t("scan.notice")).default(txt("notice")),
        ]),
    ]);
    if mode == Mode::Files {
        w.push(
            text("max_size")
                .label(t("scan.max_size"))
                .default(txt("max_size")),
        );
    }
    w.extend(vec![
        separator(),
        button(t("sig.open"), "scan.ioc", "signatures"),
        separator(),
        row(vec![
            button(t("scan.save"), "scan.ioc", "config_save").primary(),
            // Nothing to cancel remotely — the pop-up just closes.
            button(t("scan.cancel"), "scan.ioc", "config").dismiss(),
        ]),
    ]);
    // Reinstalling now sits beside the version on the tab, where the number that
    // prompts it is.
    // Wide: the thresholds sit three to a row and the checkbox labels are full
    // sentences, both of which read badly in a narrow column.
    window_modal_sized(t("scan.settings_title"), "loki.settings", 860.0, w)
}

/// The signature pop-up, opened from the settings one — a pop-up raising a
/// pop-up, with the settings still behind it to go back to.
fn signatures_modal(
    lang: &str,
    custom: &[(String, String)],
    bundled: Option<(usize, String)>,
    err: Option<&str>,
) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    let kind_label = |k: &str| t(&format!("sig.kind_{k}"));

    let mut add_row = vec![button(t("sig.add"), "scan.ioc", "sig_add").primary()];
    // The bundled set is a signature source like any other, so it belongs in the
    // list — and when it is not there, the way to get it belongs next to the way
    // to add anything else.
    add_row.push(
        button(
            t(if bundled.is_some() {
                "sig.core_update"
            } else {
                "sig.core_install"
            }),
            "scan.ioc",
            "sig_core",
        ),
    );

    let mut w = vec![
        label(t("sig.what")).weak(),
        separator(),
        file("sig_file")
            .label(t("sig.file"))
            .browse(t("scan.browse_file")),
        row(vec![
            select(
                "sig_kind",
                std::iter::once("yara".to_string())
                    .chain(IOC_KINDS.iter().map(|(k, _)| k.to_string()))
                    .collect(),
            )
            .label(t("sig.kind")),
            // Beside the picker, because what it explains is whatever the picker
            // is showing. Each kind has its own format, and getting one wrong
            // fails silently — the scanner just skips the line.
            button(t("sig.help"), "scan.ioc", "sig_help"),
        ]),
        row(add_row),
    ];

    if let Some(e) = err {
        w.push(label(e).strong());
    }

    w.push(separator());

    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut ids: Vec<String> = Vec::new();
    let mut menus: Vec<Vec<limen_sdk_rust::ui::MenuItem>> = Vec::new();

    if let Some((count, date)) = &bundled {
        rows.push(vec![
            t("sig.kind_bundled"),
            t("sig.core_row")
                .replace("{n}", &count.to_string())
                .replace("{date}", date),
        ]);
        ids.push("bundled".into());
    }
    for (k, n) in custom {
        // The id carries both halves: a name alone would not say which kind's
        // directory to remove it from.
        rows.push(vec![kind_label(k), n.clone()]);
        ids.push(format!("{k}/{n}"));
    }

    for id in &ids {
        let (question, subject) = if id == "bundled" {
            (t("sig.confirm_bundled"), t("sig.core_file"))
        } else {
            (
                t("sig.confirm_custom"),
                id.split_once('/').map(|(_, n)| n.to_string()).unwrap_or_default(),
            )
        };
        menus.push(vec![
            limen_sdk_rust::ui::menu_item(t("sig.info"), "scan.ioc", "sig_info"),
            // Reading the rules themselves is the reason to have them on disk;
            // the host hands the file to whatever the desktop opens .yar with.
            limen_sdk_rust::ui::menu_item(t("sig.open_editor"), "scan.ioc", "sig_open"),
            // The same thing in a tab, for keeping it open beside the list.
            limen_sdk_rust::ui::menu_item(t("sig.info_tab"), "scan.ioc", "sig_info")
                .args(json!({ "in_tab": true }))
                .open_in_tab(),
            // The host asks before this reaches us, with the same dialog the
            // module manager uses to remove a module.
            limen_sdk_rust::ui::menu_item(t("sig.remove"), "scan.ioc", "sig_remove")
                .confirm_labelled(&question, &subject, &t("sig.remove"), &t("scan.cancel")),
        ]);
    }

    if rows.is_empty() {
        w.push(label(t("sig.none")).weak());
    } else {
        w.push(
            table(vec![t("sig.col_kind"), t("sig.col_file")], rows)
                .row_ids(ids)
                .row_menus(menus)
                // In place, not a new tab: a table inside a pop-up should open
                // its detail in the same window rather than taking the user out
                // of the one they are working in.
                .on_activate_here("scan.ioc", "sig_info"),
        );
        w.push(label(t("sig.row_hint")).weak());
    }

    w.push(separator());
    w.push(button(t("sig.back"), "scan.ioc", "config"));
    // Narrower: a file list and two controls. Stepping in from settings shrinks
    // the pop-up to fit, rather than leaving it wide and mostly empty.
    window_modal_sized(t("sig.title"), "loki.signatures", 620.0, w)
}

/// What a signature file actually contains, for the row that was opened.
///
/// Read on demand rather than kept: the bundled set is 7 MB and its contents
/// change under us whenever it is updated, so the only honest number is the one
/// taken when asked.
/// What one signature file turned out to be: its id, the facts worth a row
/// each, and a sample of what is inside it.
struct SigInfo {
    id: String,
    facts: Vec<(String, String)>,
    sample: Vec<String>,
}

/// Where a listed signature actually is, by the id its row carries.
fn signature_path(host: &Host, id: &str) -> Option<PathBuf> {
    if id == "bundled" {
        return Some(
            install_root(host)?
                .join("signatures")
                .join("yara")
                .join("yara-rules-core.yar"),
        );
    }
    let (kind, name) = id.split_once('/')?;
    // Only ever a bare file name from our own listing — a path from elsewhere
    // could otherwise walk out of the store.
    if name.contains(['/', '\\']) || name.contains("..") {
        return None;
    }
    Some(custom_dir(host, kind)?.join(name))
}

fn signature_info(host: &Host, id: &str) -> Option<SigInfo> {
    let path = signature_path(host, id)?;
    let name = path.file_name()?.to_string_lossy().into_owned();
    let text = std::fs::read_to_string(&path).ok()?;
    let bytes = text.len() as u64;

    let mut facts = vec![
        ("file".into(), name),
        ("size".into(), format!("{} KB", bytes / 1024)),
        ("path".into(), path.to_string_lossy().into_owned()),
    ];
    let mut sample = Vec::new();

    let rules: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("rule "))
        .map(|r| r.split([' ', '{', ':']).next().unwrap_or(r))
        .collect();

    if rules.is_empty() {
        // An indicator file: comments and blanks are not indicators.
        let entries: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        facts.push(("indicators".into(), entries.len().to_string()));
        sample.extend(entries.iter().take(12).map(|e| e.to_string()));
    } else {
        facts.push(("rules".into(), rules.len().to_string()));
        if let Some(d) = text
            .lines()
            .take(40)
            .find_map(|l| l.split("Creation Date:").nth(1))
        {
            facts.push(("built".into(), d.trim().to_string()));
        }
        // Who the rules came from, by the prefix each set stamps on its names —
        // the useful summary of five thousand rules nobody will read.
        let mut by_source: BTreeMap<&str, usize> = BTreeMap::new();
        for r in &rules {
            let src = r.split('_').next().unwrap_or(r);
            if src.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) && src.len() > 2 {
                *by_source.entry(src).or_insert(0) += 1;
            }
        }
        let mut top: Vec<(&&str, &usize)> = by_source.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1));
        sample.extend(top.iter().take(10).map(|(s, n)| format!("{s}  ×{n}")));
        if sample.is_empty() {
            sample.extend(rules.iter().take(12).map(|r| r.to_string()));
        }
    }
    Some(SigInfo {
        id: id.to_string(),
        facts,
        sample,
    })
}

/// The detail step for one signature file.
///
/// A step of the same window when opened from the list, and a plain view when
/// opened in a tab — a tab has no pop-up to be a step of, and no way back to a
/// list it is not showing.
fn signature_info_modal(lang: &str, info: Option<SigInfo>, in_tab: bool) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    let Some(SigInfo { id, facts, sample }) = info else {
        let w = vec![label(t("sig.info_missing")).strong()];
        return if in_tab {
            window(t("sig.info"), w)
        } else {
            window_modal_sized(t("sig.info"), "loki.sig_info", 620.0, w)
        };
    };

    let title = if id == "bundled" {
        t("sig.kind_bundled")
    } else {
        id.split_once('/')
            .map(|(k, _)| t(&format!("sig.kind_{k}")))
            .unwrap_or_else(|| t("sig.info"))
    };

    let mut w = vec![
        label(title).heading(),
        separator(),
        table(
            vec![String::new(), String::new()],
            facts
                .into_iter()
                .map(|(k, v)| vec![t(&format!("sig.f_{k}")), v])
                .collect(),
        ),
    ];
    if !sample.is_empty() {
        w.push(separator());
        w.push(label(t("sig.contents")).weak());
        for line in sample {
            w.push(label(line).mono());
        }
    }
    if in_tab {
        return window(t("sig.info"), w);
    }
    w.push(separator());
    w.push(button(t("sig.back_list"), "scan.ioc", "signatures"));
    // Wider than the list it came from, so opening it resizes the window into
    // something that fits paths and rule names.
    window_modal_sized(t("sig.info"), "loki.sig_info", 820.0, w)
}

/// Shown while the rule set downloads — several thousand rules over the network,
/// so it is not instant and should not look like a frozen screen.
fn core_updating_modal(lang: &str) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    let mut v = window_modal_sized(
        t("sig.title"),
        "loki.sig_core",
        520.0,
        vec![
            step(t("sig.core_working"), "loading"),
            label(t("sig.core_why")).weak(),
        ],
    );
    if let Value::Object(m) = &mut v {
        m.insert(
            "auto".into(),
            json!({ "capability": "scan.ioc", "method": "sig_core_run", "args": {} }),
        );
    }
    v
}

/// Shown while the scanner runs; re-invokes itself to poll.
///
/// Unpacking comes first and can take a while on a folder full of archives, so
/// it says which of the two it is doing rather than showing one unchanging
/// "Scanning…" for the whole run.
fn scanning_view(lang: &str, lines: usize, hits: usize, stopping: bool) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    // Stopping is not instant — the worker notices between files — so say so
    // rather than leave "Scanning…" up after the button was pressed.
    if stopping {
        return window_auto(
            t("title"),
            vec![
                label(t("scan.stopping")).strong(),
                step(t("scan.stopping_step"), "loading"),
            ],
            "scan.ioc",
            "s_poll",
            json!({}),
        );
    }
    let w = vec![
        label(t("scan.running")).strong(),
        step(t("scan.working"), "loading"),
        label(
            t("scan.progress")
                .replace("{lines}", &lines.to_string())
                .replace("{hits}", &hits.to_string()),
        )
        .weak(),
        separator(),
        button(t("scan.stop"), "scan.ioc", "stop").danger(),
    ];
    window_auto(t("title"), w, "scan.ioc", "s_poll", json!({}))
}

/// The findings, at the level of detail that was asked for.
///
/// Basic answers the only question a basic scan asked — was anything found —
/// and shows what. Advanced adds what the scanner actually did: how much it
/// looked at, how long it took, and where the report is.
fn results_view(lang: &str, r: &Report, levels: &[String], page: usize) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    let shown: Vec<&Event> = r
        .findings
        .iter()
        .filter(|e| levels.iter().any(|l| l == &e.level))
        .collect();

    let mut w = Vec::new();

    let total: usize = r.counts.values().sum();
    let serious: usize = ["ALERT", "WARNING", "ERROR"]
        .iter()
        .filter_map(|l| r.counts.get(*l))
        .sum();
    // A scan that read nothing is not a clean scan. Saying "nothing suspicious"
    // over zero examined files is the one answer here that could mislead.
    let examined = r.stats.as_ref().map_or(1, |s| s.files + s.procs);
    if examined == 0 && total == 0 {
        w.push(label(t("results.nothing_scanned")).heading());
        w.push(label(t("results.nothing_scanned_why")).weak());
    } else {
        w.push(
            label(if serious > 0 {
                t("results.found").replace("{n}", &serious.to_string())
            } else if total > 0 {
                t("results.only_minor").replace("{n}", &total.to_string())
            } else {
                t("results.clean")
            })
            .heading(),
        );
    }

    // An autostart scan counts entries, not files: saying "40 files scanned"
    // for 20 entries would be true and useless.
    if let Some((checked, no_binary)) = r.autoruns {
        w.push(
            label(t("results.autoruns_line").replace("{n}", &checked.to_string())).weak(),
        );
        if no_binary > 0 {
            // Those were checked as text only. Not a failure, but not the same
            // as having been scanned, and the difference is the user's to know.
            w.push(
                label(t("results.autoruns_no_binary").replace("{n}", &no_binary.to_string()))
                    .weak(),
            );
        }
    }

    // What was looked at, in every mode — "nothing found" is only reassuring if
    // you know something was actually scanned.
    if let Some(st) = &r.stats {
        w.push(
            label(
                t("results.scanned_line")
                    .replace("{files}", &st.files.to_string())
                    .replace("{procs}", &st.procs.to_string())
                    .replace("{duration}", &fmt_secs(st.secs)),
            )
            .weak(),
        );
    }

    {
        w.push(separator());
        let mut rows: Vec<Vec<String>> = Vec::new();
        if !r.hostname.is_empty() {
            rows.push(vec![t("results.host"), r.hostname.clone()]);
        }
        if !r.started.is_empty() {
            rows.push(vec![t("results.started"), pretty_time(&r.started)]);
        }
        if !r.ended.is_empty() {
            rows.push(vec![t("results.ended"), pretty_time(&r.ended)]);
        }
        if let Some(st) = &r.stats {
            let of_which = |n: u64, m: u64| {
                t("results.of_which")
                    .replace("{n}", &n.to_string())
                    .replace("{m}", &m.to_string())
            };
            rows.push(vec![t("results.files"), of_which(st.files, st.files_matched)]);
            rows.push(vec![t("results.procs"), of_which(st.procs, st.procs_matched)]);
            if st.secs > 0.0 {
                rows.push(vec![t("results.duration"), fmt_secs(st.secs)]);
            }
        }
        if r.skipped > 0 {
            rows.push(vec![
                t("results.skipped_label"),
                t("results.skipped").replace("{count}", &r.skipped.to_string()),
            ]);
        }
        if !r.path.is_empty() {
            rows.push(vec![t("results.report_file"), r.path.clone()]);
        }
        if !rows.is_empty() {
            w.push(table(vec![String::new(), String::new()], rows));
        }
    }

    // Filter chips, one per level that actually occurred.
    let mut chips: Vec<limen_sdk_rust::ui::Widget> = Vec::new();
    for l in LEVELS {
        let n = r.counts.get(l).copied().unwrap_or(0);
        if n == 0 {
            continue;
        }
        let on = levels.iter().any(|x| x == l);
        let next: Vec<String> = if on {
            levels.iter().filter(|x| x.as_str() != l).cloned().collect()
        } else {
            levels
                .iter()
                .cloned()
                .chain(std::iter::once(l.to_string()))
                .collect()
        };
        let b = button(
            format!(
                "{}{} ({n})",
                if on { "✓ " } else { "" },
                t(&format!("level.{}", l.to_lowercase()))
            ),
            "scan.ioc",
            "filter",
        )
        .args(json!({ "levels": next.join(",") }));
        chips.push(if on { b.primary() } else { b });
    }

    // Processes were either scanned or they were not; naming the kind on every
    // row of a file-only scan is a column of the same word.
    let has_procs = r.findings.iter().any(|e| e.event_type == "process_match");

    let pages = shown.len().div_ceil(PAGE).max(1);
    let page = page.min(pages - 1);
    let slice = &shown[page * PAGE..((page + 1) * PAGE).min(shown.len())];

    if !chips.is_empty() {
        w.push(separator());
        w.push(row(chips));
    }

    if slice.is_empty() {
        if total > 0 {
            w.push(label(t("results.nothing_at_levels")).weak());
        }
    } else {
        let rows: Vec<Vec<String>> = slice
            .iter()
            .map(|e| {
                let mut cells = vec![
                    t(&format!("level.{}", e.level.to_lowercase())),
                    if e.score > 0.0 {
                        format!("{:.0}", e.score)
                    } else {
                        "—".into()
                    },
                ];
                // The kind column earns its place only when both kinds can
                // appear — a scan that left processes alone has one kind.
                if has_procs {
                    cells.push(if e.event_type == "process_match" {
                        t("detail.process")
                    } else {
                        t("detail.file")
                    });
                }
                cells.push(e.subject());
                cells.push(e.rules());
                cells
            })
            .collect();
        let mut cols = vec![t("cols.level"), t("cols.score")];
        if has_procs {
            cols.push(t("cols.kind"));
        }
        cols.push(t("cols.subject"));
        cols.push(t("cols.matched"));

        let ids: Vec<String> = slice
            .iter()
            .enumerate()
            .map(|(i, _)| (page * PAGE + i).to_string())
            .collect();
        w.push(
            table(cols, rows)
                .row_ids(ids)
                .on_activate("scan.ioc", "detail"),
        );
    }

    if pages > 1 {
        let mut pager = Vec::new();
        if page > 0 {
            pager.push(
                button(t("results.prev"), "scan.ioc", "filter")
                    .args(json!({ "levels": levels.join(","), "page": page - 1 })),
            );
        }
        pager.push(
            label(
                t("results.page")
                    .replace("{page}", &(page + 1).to_string())
                    .replace("{pages}", &pages.to_string()),
            )
            .weak(),
        );
        if page + 1 < pages {
            pager.push(
                button(t("results.next"), "scan.ioc", "filter")
                    .args(json!({ "levels": levels.join(","), "page": page + 1 })),
            );
        }
        w.push(row(pager));
    }

    w.push(separator());
    w.push(button(t("results.new_scan"), "scan.ioc", "ui").primary());
    window(t("title"), w)
}

/// One finding in full: what matched, where, and why.
fn detail_view(lang: &str, e: &Event) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    let mut w = vec![
        label(e.subject()).strong(),
        label(format!(
            "{} · {} · {}",
            t(&format!("level.{}", e.level.to_lowercase())),
            if e.score > 0.0 {
                format!("{:.0}", e.score)
            } else {
                "—".into()
            },
            e.event_type
        ))
        .weak(),
        separator(),
    ];

    let bytes = |b: u64| t("detail.bytes").replace("{n}", &b.to_string());
    let u64_of = |k: &str| e.raw.get(k).and_then(Value::as_u64);
    let facts: Vec<(String, Option<String>)> = vec![
        (t("detail.time"), str_of(&e.raw, "timestamp").map(|s| pretty_time(&s))),
        (t("detail.host"), str_of(&e.raw, "hostname")),
        (t("detail.type"), str_of(&e.raw, "file_type")),
        (t("detail.size"), u64_of("file_size").map(bytes)),
        // Hash names are not words in any language.
        ("MD5".into(), str_of(&e.raw, "md5")),
        ("SHA1".into(), str_of(&e.raw, "sha1")),
        ("SHA256".into(), str_of(&e.raw, "sha256")),
        (t("detail.created"), str_of(&e.raw, "file_created")),
        (t("detail.modified"), str_of(&e.raw, "file_modified")),
        (t("detail.accessed"), str_of(&e.raw, "file_accessed")),
        (t("detail.run_time"), str_of(&e.raw, "run_time")),
        (t("detail.memory"), u64_of("memory_bytes").map(bytes)),
        (
            t("detail.connections"),
            u64_of("connection_count").map(|n| n.to_string()),
        ),
        (
            t("detail.listening"),
            e.raw
                .get("listening_ports")
                .and_then(Value::as_array)
                .map(|ps| {
                    ps.iter()
                        .filter_map(Value::as_u64)
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                }),
        ),
    ];
    let rows: Vec<Vec<String>> = facts
        .into_iter()
        .filter_map(|(k, v)| v.filter(|s| !s.is_empty()).map(|s| vec![k, s]))
        .collect();
    if !rows.is_empty() {
        w.push(table(vec![String::new(), String::new()], rows));
    }

    // Why it matched: every rule, with its own score, and the strings that fired
    // it — the part that decides whether a hit is real.
    if let Some(reasons) = e.raw.get("reasons").and_then(Value::as_array) {
        w.push(separator());
        w.push(label(t("detail.matched")).strong());
        for r in reasons {
            let name = str_of(r, "message").unwrap_or_default();
            w.push(
                label(match r.get("score").and_then(Value::as_i64) {
                    Some(s) => format!("{name}  ({s})"),
                    None => name,
                })
                .strong(),
            );
            for key in ["description", "author", "reference"] {
                if let Some(v) = str_of(r, key).filter(|s| !s.is_empty()) {
                    w.push(label(format!("{key}: {v}")).weak());
                }
            }
            if let Some(ms) = r.get("matched_strings").and_then(Value::as_array) {
                let joined = ms
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("  ");
                if !joined.is_empty() {
                    w.push(label(joined).mono());
                }
            }
        }
    }

    // The record as it arrived, so nothing is hidden by the fields chosen above.
    w.push(separator());
    w.push(label(t("detail.raw")).weak());
    w.push(label(serde_json::to_string_pretty(&e.raw).unwrap_or_else(|_| e.raw.to_string())).mono());
    w.push(separator());
    w.push(button(t("detail.back"), "scan.ioc", "filter"));
    window(t("detail.matched"), w)
}

/// What a signature file of *this* kind has to look like.
///
/// One pop-up per kind rather than one table for all four: the rules differ in
/// ways that matter — a bare hash is dropped but a bare C2 address is kept, and
/// C2 indicators do nothing at all unless process scanning is on. Everything
/// here was read off the scanner rather than its documentation, because a
/// malformed line is skipped in silence and a wrong example would cost somebody
/// a rule without ever saying so.
fn signature_help_modal(lang: &str, kind: &str) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    let kind = if kind == "yara" || IOC_KINDS.iter().any(|(k, _)| *k == kind) {
        kind
    } else {
        "yara"
    };
    let key = |suffix: &str| format!("sig.h_{kind}_{suffix}");

    let mut w = vec![
        label(t(&format!("sig.kind_{kind}"))).heading(),
        separator(),
        label(t("sig.help_col_ext")).weak(),
        label(t(&key("file"))).mono(),
        separator(),
        label(t("sig.help_col_example")).weak(),
        label(t(&key("example"))).mono(),
        separator(),
    ];

    // Notes run n1..n4 and kinds do not all have the same number. A key with no
    // translation resolves to itself, which is how the end of the list is known
    // without keeping a count in two places.
    for i in 1..=4 {
        let k = key(&format!("n{i}"));
        let line = t(&k);
        if line == k {
            break;
        }
        w.push(label(format!("· {line}")));
    }

    w.push(separator());
    w.push(button(t("sig.help_back"), "scan.ioc", "signatures"));
    // Same id whichever kind is being explained, so switching kinds redraws this
    // pop-up rather than stacking another one over it.
    window_modal_sized(t("sig.help_title"), "loki.sig_help", 700.0, w)
}

/// Shown while the operating system is asking the user for privileges.
///
/// A pop-up rather than a line on the tab: an authorization prompt is a question
/// waiting to be answered, and nothing else on the screen can proceed until it
/// is. It polls itself, so it leaves as soon as the prompt does.
fn authorizing_modal(lang: &str) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    let mut v = window_modal_sized(
        t("scan.authorizing_title"),
        "loki.authorizing",
        520.0,
        vec![
            step(t("scan.authorizing"), "loading"),
            label(t("scan.authorizing_why")).weak(),
        ],
    );
    // Poll from inside the pop-up, so it replaces itself the moment the prompt
    // is answered either way.
    if let Value::Object(m) = &mut v {
        m.insert(
            "auto".into(),
            json!({ "capability": "scan.ioc", "method": "s_poll", "args": {} }),
        );
    }
    v
}

/// Which levels the user asked to see, defaulting to the ones worth opening on.
fn wanted_levels(params: &Value) -> Vec<String> {
    match params.get("levels").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => s.split(',').map(str::to_string).collect(),
        _ => DEFAULT_LEVELS.iter().map(|s| s.to_string()).collect(),
    }
}

// ---------------------------------------------------------------------------

#[derive(Default)]
struct Loki {
    report: Option<Report>,
    /// Scan settings, loaded from `tools/settings.json` on first use and kept
    /// here so a scan does not have to re-read them off the disk.
    settings: Option<Value>,
    /// What this tab is set to scan. Decides most of the screen, because the
    /// three take different inputs and share almost no settings.
    mode: Mode,
    /// The autostart entries the last autoruns scan was built from, kept so its
    /// findings can name the key rather than the scratch file Loki read.
    staged: Vec<Staged>,
    /// An elevation the host is running for us: the authorization prompt is on
    /// screen, or the elevated scan is under way. Polled rather than waited on,
    /// so the module keeps drawing while the user answers.
    elevation: Option<(u64, PathBuf)>,
    /// The running scan, if any. A scan takes minutes to hours, so it runs on
    /// its own thread and the view polls it — the module never blocks.
    job: Option<Job>,
}

impl Handler for Loki {
    fn capabilities(&self) -> Vec<String> {
        vec!["scan.ioc".into()]
    }

    fn invoke(
        &mut self,
        _capability: &str,
        method: &str,
        params: Value,
        host: &Host,
    ) -> Result<Value, RpcError> {
        // One lookup per call, then every view renders in that language.
        let lang = host.locale();
        let lang = lang.as_str();
        let t = |k: &str| catalog().tr(lang, k);

        match method {
            // The entry point decides which screen you get: no scanner ->
            // install it, scanner present -> the scan screen.
            "ui" => {
                self.report = None;
                Ok(if loki_bin(host).is_some() {
                    self.screen(host, lang, None)
                } else {
                    install_view(lang, None)
                })
            }
            "install" => Ok(installing_view(lang, 0)),
            // Perform one step, then hand the next to the view. A failure ends
            // the chain on the install screen carrying the reason, rather than
            // leaving the steps spinning forever.
            "i_step" => {
                let step = params.get("step").and_then(Value::as_u64).unwrap_or(0) as usize;
                match run_install_step(host, lang, step) {
                    Ok(()) => Ok(installing_view(lang, step + 1)),
                    Err(why) => Ok(install_view(lang, Some(&why))),
                }
            }
            // Open the settings pop-up over the scan screen.
            // Which scan is showing decides which settings are worth offering.
            "mode" => {
                self.mode = Mode::from_str(
                    params.get("mode").and_then(Value::as_str).unwrap_or("files"),
                );
                self.report = None;
                Ok(self.screen(host, lang, None))
            }
            "config" => {
                let mode = self.mode;
                Ok(settings_modal(lang, self.cfg(host), mode))
            }
            // Save what the pop-up sent and return to the scan screen. The reply
            // is an ordinary view, which closes the pop-up over it.
            "config_save" => {
                let mut cfg = self.cfg(host).clone();
                if let Some(map) = cfg.as_object_mut() {
                    // Only keys we know: the form also carries the scan target
                    // and the signature fields, which are not settings.
                    for k in default_settings()
                        .as_object()
                        .map(|m| m.keys().cloned().collect::<Vec<_>>())
                        .unwrap_or_default()
                    {
                        // A checkbox arrives as a bool, the rest as strings.
                        if let Some(v) = params.get(&k) {
                            let keep = match map.get(&k) {
                                Some(Value::Bool(_)) => Value::Bool(v.as_bool().unwrap_or(false)),
                                _ => Value::String(
                                    v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()),
                                ),
                            };
                            map.insert(k, keep);
                        } else if matches!(map.get(&k), Some(Value::Bool(_))) {
                            // An unticked checkbox may simply not be sent, and
                            // an absent one must read as off rather than as
                            // "leave it alone" — otherwise it could never be
                            // turned off.
                            map.insert(k, Value::Bool(false));
                        }
                    }
                }
                save_settings(host, &cfg);
                self.settings = Some(cfg);
                Ok(self.screen(host, lang, None))
            }
            // The signature pop-up, raised from the settings one.
            "signatures" => Ok(signatures_modal(lang, &list_custom(host), bundled_rules(host), None)),
            "sig_add" => {
                let src = params
                    .get("sig_file")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let kind = params
                    .get("sig_kind")
                    .and_then(Value::as_str)
                    .unwrap_or("yara")
                    .to_string();
                let err = if src.is_empty() {
                    Some(t("sig.no_file"))
                } else {
                    add_custom(host, &kind, &src)
                        .err()
                        .map(|e| t("sig.add_failed").replace("{error}", &e))
                };
                // Same pop-up id, so this redraws in place rather than opening
                // another over it.
                Ok(signatures_modal(lang, &list_custom(host), bundled_rules(host), err.as_deref()))
            }
            // The picker's current value rides along in the form, so the help
            // explains whatever kind is selected.
            "sig_help" => Ok(signature_help_modal(
                lang,
                params.get("sig_kind").and_then(Value::as_str).unwrap_or("yara"),
            )),
            // Fetch (or refresh) the bundled YARA-Forge set. The pop-up shows a
            // spinner and invokes the work itself, so the download does not look
            // like a frozen screen.
            // Hand the file to the desktop's editor. Returns nothing: the
            // pop-up should stay exactly as it was, with the list still open
            // behind the editor that just launched.
            "sig_open" => {
                if let Some(p) = params
                    .get("id")
                    .and_then(Value::as_str)
                    .and_then(|id| signature_path(host, id))
                {
                    host.open("edit", &p.to_string_lossy());
                }
                Ok(Value::Null)
            }
            // Double-click, or "Open info" from the row menu.
            "sig_info" => {
                let id = params.get("id").and_then(Value::as_str).unwrap_or_default();
                let in_tab = params.get("in_tab").and_then(Value::as_bool).unwrap_or(false);
                Ok(signature_info_modal(
                    lang,
                    signature_info(host, id),
                    in_tab,
                ))
            }
            "sig_core" => Ok(core_updating_modal(lang)),
            "sig_core_run" => {
                let err = update_bundled_rules(host)
                    .err()
                    .map(|e| t("sig.core_failed").replace("{error}", &e));
                Ok(signatures_modal(
                    lang,
                    &list_custom(host),
                    bundled_rules(host),
                    err.as_deref(),
                ))
            }
            "sig_remove" => {
                match params.get("id").and_then(Value::as_str) {
                    // The bundled set is a file like any other; deleting it
                    // leaves the scan with only what the user added, and the
                    // button beside Add turns back into Install.
                    Some("bundled") => {
                        if let Some(root) = install_root(host) {
                            let _ = std::fs::remove_file(
                                root.join("signatures").join("yara").join("yara-rules-core.yar"),
                            );
                        }
                    }
                    Some(id) => {
                        if let Some((kind, name)) = id.split_once('/') {
                            remove_custom(host, kind, name);
                        }
                    }
                    None => {}
                }
                Ok(signatures_modal(lang, &list_custom(host), bundled_rules(host), None))
            }
            // Start the scanner and hand the screen to the poller.
            "scan" => {
                // Only a file scan has a target the user chose; the other two
                // are this machine.
                let target = if self.mode != Mode::Files {
                    String::new()
                } else {
                    let chosen = params
                        .get("target")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if chosen.is_empty() {
                        let msg = t("scan.no_target");
                        return Ok(self.screen(host, lang, Some(&msg)));
                    }
                    chosen
                };
                let Some(bin) = loki_bin(host) else {
                    return Ok(install_view(lang, Some(&t("scan.not_installed"))));
                };
                let Some(root) = install_root(host) else {
                    return Ok(self.screen(host, lang, Some(&t("install.no_dir"))));
                };
                // Put the user's own rules and indicators where the scanner
                // looks, every time — a reinstall replaces that directory.
                sync_signatures(host);

                let dir = root.parent().unwrap_or(&root).join(".scan");
                let _ = std::fs::create_dir_all(&dir);
                let cfg = self.cfg(host).clone();

                // A process scan is worthless without privileges — Loki reads
                // nothing and reports a clean machine. Ask the OS, and let the
                // host wait for the answer so this module keeps drawing.
                if self.mode == Mode::Procs && is_elevated() != Some(true) {
                    let (can, _how) = host.can_elevate();
                    if !can {
                        return Ok(self.screen(host, lang, Some(&t("scan.no_elevation"))));
                    }
                    let out = dir.join("report.jsonl");
                    let _ = std::fs::remove_file(&out);
                    let args = scan_args(&cfg, None, &out);
                    let mut argv: Vec<&str> = vec![bin.to_str().unwrap_or_default()];
                    argv.extend(args.iter().map(String::as_str));
                    let workdir = bin.parent().unwrap_or(&root).to_string_lossy().into_owned();
                    match host.elevate_async(&argv, Some(&workdir)) {
                        Some(id) => {
                            self.elevation = Some((id, out));
                            return Ok(authorizing_modal(lang));
                        }
                        None => {
                            return Ok(self.screen(host, lang, Some(&t("scan.no_elevation"))))
                        }
                    }
                }

                // An autostart scan asks the autoruns module what starts on this
                // machine, then lays each entry out as files the scanner can
                // read — the command as text for the string rules, and the
                // program it runs for the rest.
                let folder = if self.mode == Mode::Autoruns {
                    let enabled_only = cfg
                        .get("autoruns_enabled_only")
                        .and_then(Value::as_bool)
                        .unwrap_or(true);
                    let (entries, total) = match autorun_entries(host, enabled_only) {
                        Ok(v) => v,
                        Err(e) => {
                            let msg = t("scan.autoruns_failed").replace("{error}", &e);
                            return Ok(self.screen(host, lang, Some(&msg)));
                        }
                    };
                    let staged = stage_autoruns(&dir.join("autoruns"), &entries);
                    if staged.is_empty() {
                        let msg = t("scan.autoruns_none").replace("{n}", &total.to_string());
                        return Ok(self.screen(host, lang, Some(&msg)));
                    }
                    self.staged = staged;
                    Some(dir.join("autoruns").to_string_lossy().into_owned())
                } else {
                    (self.mode == Mode::Files).then_some(target)
                };

                // Running the scanner and waiting on it happen on the worker's
                // thread, not this one.
                self.job = Some(Job::spawn(
                    bin.clone(),
                    // Signatures are resolved relative to the scanner, so it runs
                    // from its own directory.
                    bin.parent().unwrap_or(&root).to_path_buf(),
                    dir,
                    folder,
                    cfg.clone(),
                ));
                Ok(scanning_view(lang, 0, 0, false))
            }
            // Still going, or finished and ready to read.
            "s_poll" => {
                // An elevated scan is run by the host, not by our own worker, so
                // it is polled here rather than through `Job`.
                if let Some((id, out)) = self.elevation.clone() {
                    let Some(done) = host.elevate_status(id) else {
                        // Still going. Once the report has lines the prompt has
                        // been answered and the scan is under way, so swap the
                        // authorization pop-up for real progress.
                        let (lines, hits) = scan_progress(std::slice::from_ref(&out));
                        return Ok(if lines == 0 {
                            authorizing_modal(lang)
                        } else {
                            scanning_view(lang, lines, hits, false)
                        });
                    };
                    self.elevation = None;
                    if !done.ran {
                        let key = if done.refused() {
                            "scan.auth_refused"
                        } else if done.unavailable() {
                            "scan.no_elevation"
                        } else {
                            "scan.auth_failed"
                        };
                        let msg = t(key).replace("{error}", &done.message);
                        return Ok(self.screen(host, lang, Some(&msg)));
                    }
                    return Ok(self.finish_paths(lang, &[out]));
                }

                // Everything is read off the job first so the borrow ends before
                // the job is cleared or consumed.
                let (err, running, outs, stopping) = match &self.job {
                    Some(job) => (
                        job.error.lock().unwrap().clone(),
                        !job.finished(),
                        job.outs.lock().unwrap().clone(),
                        job.stopping(),
                    ),
                    None => return Ok(self.screen(host, lang, None)),
                };
                if let Some(e) = err {
                    self.job = None;
                    return Ok(self.screen(
                        host,
                        lang,
                        Some(&t("scan.failed").replace("{error}", &e)),
                    ));
                }
                if running {
                    let (lines, hits) = scan_progress(&outs);
                    return Ok(scanning_view(lang, lines, hits, stopping));
                }
                Ok(self.finish(lang))
            }
            // Stop a scan the user no longer wants.
            //
            // The worker notices between files, so this asks rather than waits —
            // blocking here would freeze the UI for as long as the scanner took
            // to die. Whatever was written by then is still a readable report,
            // and the next poll shows it.
            "stop" => {
                match &self.job {
                    Some(job) => job.stop(),
                    None => return Ok(self.screen(host, lang, None)),
                }
                Ok(scanning_view(lang, 0, 0, true))
            }
            "filter" => {
                let Some(r) = &self.report else {
                    return Ok(self.screen(host, lang, None));
                };
                let page = params.get("page").and_then(Value::as_u64).unwrap_or(0) as usize;
                Ok(results_view(lang, r, &wanted_levels(&params), page))
            }
            "detail" => {
                let Some(r) = &self.report else {
                    return Ok(self.screen(host, lang, None));
                };
                let levels = wanted_levels(&params);
                let shown: Vec<&Event> = r
                    .findings
                    .iter()
                    .filter(|e| levels.iter().any(|l| l == &e.level))
                    .collect();
                let idx = params
                    .get("id")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(usize::MAX);
                match shown.get(idx) {
                    Some(e) => Ok(detail_view(lang, e)),
                    None => Ok(results_view(lang, r, &levels, 0)),
                }
            }
            "about" => Ok(json!({
                "name": "loki",
                "summary": "Runs Loki-RS (YARA + IOC) and reads its reports.",
                "methods": ["ui", "config", "signatures", "scan", "filter", "detail"],
            })),
            other => Err(RpcError::new(
                rpc::METHOD_NOT_FOUND,
                format!("no method {other}"),
            )),
        }
    }
}

impl Loki {
    /// Settings, loaded from disk the first time they are wanted.
    fn cfg(&mut self, host: &Host) -> &Value {
        self.settings.get_or_insert_with(|| load_settings(host))
    }

    /// The scan screen, with the current settings summarised on it.
    fn screen(&mut self, host: &Host, lang: &str, err: Option<&str>) -> Value {
        let custom = list_custom(host).len();
        let mode = self.mode;
        // Offered only when something in this session actually provides it.
        let has_autoruns = host.has_capability(AUTORUNS_CAP);
        main_view(lang, self.cfg(host), custom, mode, has_autoruns, err)
    }

    /// Read a report the host ran on our behalf, with no `Job` behind it.
    fn finish_paths(&mut self, lang: &str, outs: &[PathBuf]) -> Value {
        let text = outs
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .collect::<Vec<_>>()
            .join("\n");
        let mut r = parse(&text);
        r.path = outs
            .first()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let view = results_view(lang, &r, &wanted_levels(&Value::Null), 0);
        self.report = Some(r);
        view
    }

    /// Read the report a finished (or stopped) scan left behind.
    fn finish(&mut self, lang: &str) -> Value {
        let Some(job) = self.job.take() else {
            return window(catalog().tr(lang, "title"), vec![]);
        };
        let outs = job.outs.lock().unwrap().clone();
        let text = outs
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .collect::<Vec<_>>()
            .join("\n");
        let mut r = parse(&text);
        r.path = outs
            .first()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        // A finding from an autostart scan is reported against the entry the
        // user can actually go and change, not the scratch file Loki read.
        if !self.staged.is_empty() {
            r.autoruns = Some((
                self.staged.len(),
                self.staged.iter().filter(|s| !s.binary).count(),
            ));
            for ev in &mut r.findings {
                relabel_autorun(&mut ev.raw, &self.staged);
            }
            // The layout has served its purpose; leaving copies of every
            // autostart program lying about would be a poor way to end a scan.
            if let Some(scan_dir) = outs.first().and_then(|p| p.parent()) {
                let _ = std::fs::remove_dir_all(scan_dir.join("autoruns"));
            }
        }

        let view = results_view(lang, &r, &wanted_levels(&Value::Null), 0);
        self.report = Some(r);
        view
    }
}

export_module!(Loki);

#[cfg(test)]
mod tests {
    use super::*;

    /// Lines shaped exactly like Loki-RS's `LogEvent`: RFC3339 timestamp,
    /// upper-case level, snake_case event type, `reasons` carrying the rule.
    const SAMPLE: &str = r#"
{"timestamp":"2026-08-03T10:00:00+00:00","level":"INFO","event_type":"scan_start","hostname":"srv-01","message":"Loki-RS scan started VERSION: 2.12.0"}
{"timestamp":"2026-08-03T10:00:05+00:00","level":"ALERT","event_type":"file_match","hostname":"srv-01","message":"YARA match","file_path":"/tmp/evil.bin","score":95.0,"file_size":2048,"md5":"d41d8cd98f00b204e9800998ecf8427e","reasons":[{"message":"MAL_Backdoor_Gen","score":80,"description":"Generic backdoor","author":"Florian Roth","matched_strings":["$s1: cmd.exe /c"]}]}
{"timestamp":"2026-08-03T10:00:06+00:00","level":"WARNING","event_type":"process_match","hostname":"srv-01","message":"Suspicious memory","pid":4412,"process_name":"sshd","score":65.0,"listening_ports":[22,2222]}
{"timestamp":"2026-08-03T10:00:07+00:00","level":"NOTICE","event_type":"file_match","hostname":"srv-01","message":"Odd name","file_path":"/tmp/x.tmp","score":45.0}
{"timestamp":"2026-08-03T10:00:08+00:00","level":"INFO","event_type":"info","hostname":"srv-01","message":"scanned 1000 files"}
{"timestamp":"2026-08-03T10:01:00+00:00","level":"INFO","event_type":"scan_end","hostname":"srv-01","message":"Loki-RS scan finished. Summary - Files scanned: 1240 Matched: 2 | Processes scanned: 87 Matched: 1 | Alerts: 1 Warnings: 1 Notices: 1. Scan Duration: 55.0s (Start: 2026-08-03 10:00:00, End: 2026-08-03 10:01:00)"}
"#;

    fn catalog_keys(toml: &str) -> Vec<String> {
        let mut section = String::new();
        let mut out = Vec::new();
        for line in toml.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = format!("{name}.");
            } else if let Some((k, _)) = line.split_once('=') {
                out.push(format!("{section}{}", k.trim()));
            }
        }
        out
    }

    #[test]
    fn reads_boundaries_and_keeps_only_matches() {
        let r = parse(SAMPLE);
        // scan_start/scan_end and the plain info line are not findings.
        assert_eq!(r.findings.len(), 3);
        assert_eq!(r.hostname, "srv-01");
        let st = r.stats.as_ref().expect("stats parsed from the summary");
        assert_eq!(st.files, 1240);
        assert_eq!(st.procs, 87);
    }

    #[test]
    fn orders_worst_first() {
        let r = parse(SAMPLE);
        let scores: Vec<f64> = r.findings.iter().map(|e| e.score).collect();
        assert_eq!(scores, vec![95.0, 65.0, 45.0]);
    }

    #[test]
    fn counts_every_level_even_when_filtered_out() {
        let r = parse(SAMPLE);
        assert_eq!(r.counts.get("ALERT"), Some(&1));
        assert_eq!(r.counts.get("WARNING"), Some(&1));
        // NOTICE is hidden by default but still counted, or the filter chip
        // could not tell you what it is hiding.
        assert_eq!(r.counts.get("NOTICE"), Some(&1));
    }

    /// A scan killed part-way leaves a truncated final line. That must not cost
    /// us the rest of the report.
    #[test]
    fn a_truncated_line_is_skipped_not_fatal() {
        let text = format!("{SAMPLE}\n{{\"timestamp\":\"2026-08-03T10:02\",\"level\":\"ALER");
        let r = parse(&text);
        assert_eq!(r.findings.len(), 3, "the good lines must survive");
        assert_eq!(r.skipped, 1, "and the bad one must be reported, not hidden");
    }

    #[test]
    fn subject_names_files_and_processes_differently() {
        let r = parse(SAMPLE);
        assert_eq!(r.findings[0].subject(), "/tmp/evil.bin");
        assert_eq!(r.findings[1].subject(), "sshd (4412)");
    }

    #[test]
    fn the_scanners_summary_becomes_numbers() {
        let st = Stats::parse(
            "Summary - Files scanned: 1240 Matched: 3 | Processes scanned: 87 Matched: 1 | \
             Alerts: 2. Scan Duration: 4.80s",
        )
        .expect("parses");
        assert_eq!(st.files, 1240);
        // The two `Matched:` counts must not be confused for one another.
        assert_eq!(st.files_matched, 3);
        assert_eq!(st.procs, 87);
        assert_eq!(st.procs_matched, 1);
        assert!((st.secs - 4.80).abs() < 1e-9);
    }

    /// Unpacked archives are scanned as a second pass, but the person reading
    /// the report ran one scan — so the two sets of tallies add up rather than
    /// the last one winning.
    #[test]
    fn two_passes_read_as_one_scan() {
        let end = |files: u64, matched: u64, secs: &str, ts: &str| {
            format!(
                r#"{{"timestamp":"{ts}","level":"INFO","event_type":"scan_end","hostname":"h",
                "message":"Summary - Files scanned: {files} Matched: {matched} | Processes scanned: 0 Matched: 0. Scan Duration: {secs}"}}"#
            )
            .replace('\n', "")
        };
        let r = parse(&format!(
            "{}\n{}",
            end(100, 1, "10.0s", "2026-08-03T10:01:00+00:00"),
            end(5, 2, "2.0s", "2026-08-03T10:02:00+00:00")
        ));
        let st = r.stats.expect("stats");
        assert_eq!(st.files, 105, "both passes counted");
        assert_eq!(st.files_matched, 3);
        assert!((st.secs - 12.0).abs() < 1e-9, "durations add up");
        // The run ends when the last pass ends.
        assert_eq!(pretty_time(&r.ended), "2026-08-03 10:02:00");
    }

    #[test]
    fn long_scans_are_not_reported_in_bare_seconds() {
        assert_eq!(fmt_secs(4.8), "4.8s");
        assert_eq!(fmt_secs(92.0), "1m 32s");
    }

    #[test]
    fn timestamps_lose_their_noise() {
        assert_eq!(
            pretty_time("2026-08-03T19:44:38.546148389+00:00"),
            "2026-08-03 19:44:38"
        );
        assert_eq!(pretty_time("2026-08-03T19:44:38"), "2026-08-03 19:44:38");
        // An offset with no fractional part must go too, and the `-` in a
        // negative offset must not be mistaken for a date separator.
        assert_eq!(pretty_time("2026-08-03T10:02:00+00:00"), "2026-08-03 10:02:00");
        assert_eq!(pretty_time("2026-08-03T10:02:00-05:00"), "2026-08-03 10:02:00");
        assert_eq!(pretty_time("2026-08-03T10:02:00Z"), "2026-08-03 10:02:00");
        assert_eq!(pretty_time(""), "");
    }

    #[test]
    fn every_published_platform_resolves_to_an_asset() {
        for os in ["linux", "macos", "windows"] {
            for arch in ["x86_64", "aarch64"] {
                let a = asset_name(os, arch).expect("published by Loki-RS");
                assert!(a.starts_with(&format!("loki-{os}-{arch}-v")));
                assert!(a.ends_with(if os == "windows" { ".zip" } else { ".tar.gz" }));
            }
        }
        // ...and one that is not published says so rather than guessing a name.
        assert!(asset_name("linux", "riscv64").is_none());
        assert!(asset_name("freebsd", "x86_64").is_none());
    }

    #[test]
    fn install_steps_run_then_stop() {
        let mid = installing_view("en", 1).to_string();
        assert!(mid.contains("\"auto\""), "must invoke the next step itself");
        // Finished: no auto, or it would loop forever.
        let end = installing_view("en", STEP_KEYS.len()).to_string();
        assert!(!end.contains("\"auto\""));
    }

    /// Loki reads only executables and scripts unless told otherwise, so a basic
    /// scan of a documents folder would examine nothing and call it clean.
    #[test]
    fn the_default_settings_read_every_file() {
        let d = scan_args(&default_settings(), Some("/srv"), Path::new("/o"));
        assert!(d.contains(&"--scan-all-files".to_string()));
        // ...and turning it off is the deliberate act.
        let mut cfg = default_settings();
        cfg["all_files"] = json!(false);
        assert!(!scan_args(&cfg, Some("/srv"), Path::new("/o")).contains(&"--scan-all-files".to_string()));
    }

    /// The program a command runs has to be picked out of it — autostart
    /// commands carry arguments and are quoted inconsistently, and scanning the
    /// wrong file is worse than scanning none.
    #[test]
    fn the_program_is_found_inside_an_autostart_command() {
        let tmp = std::env::temp_dir().join("loki-test-cmd");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let exe = tmp.join("thing.exe");
        std::fs::write(&exe, b"MZ").unwrap();
        let p = exe.to_string_lossy().into_owned();

        // Bare, with arguments, and quoted.
        assert_eq!(command_target(&p).as_deref(), Some(exe.as_path()));
        assert_eq!(
            command_target(&format!("{p} /background --quiet")).as_deref(),
            Some(exe.as_path())
        );
        assert_eq!(
            command_target(&format!("\"{p}\" /background")).as_deref(),
            Some(exe.as_path())
        );
        // A command naming something that is not there yields nothing rather
        // than a path that would be scanned as if it were.
        assert!(command_target("C:\\nope\\gone.exe").is_none());
        assert!(command_target("").is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Each entry becomes its own files, named by index — the mapping back is
    /// the filename. Never by the entry's own name: that comes from the registry
    /// and is the attacker's to choose, so it has no business in a path.
    #[test]
    fn autostart_entries_are_staged_one_per_file_and_map_back() {
        let tmp = std::env::temp_dir().join("loki-test-autoruns");
        let bin = tmp.join("real.exe");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(&bin, b"MZ payload").unwrap();

        let entries = vec![
            json!({ "name": "Updater", "command": "powershell -enc AAA",
                    "location": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run" }),
            json!({ "name": "../../evil", "command": format!("{} /q", bin.display()),
                    "location": "HKLM\\Run" }),
            // No command: nothing to scan, so nothing is written.
            json!({ "name": "Empty", "command": "", "location": "x" }),
        ];
        let dir = tmp.join("stage");
        let staged = stage_autoruns(&dir, &entries);
        assert_eq!(staged.len(), 2, "the entry with no command is skipped");

        let mut files: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        files.sort();
        // Index-named, and the second entry's program was copied beside it.
        assert_eq!(files, vec!["00000.cmd", "00001.bin", "00001.cmd"]);
        assert!(!staged[0].binary, "its command names no real file");
        assert!(staged[1].binary);
        // The hostile name never reached the filesystem.
        assert!(!files.iter().any(|f| f.contains("evil")));

        // A finding on a scratch file comes back naming the key.
        let mut ev = json!({ "file_path": dir.join("00000.cmd").to_string_lossy() });
        relabel_autorun(&mut ev, &staged);
        let shown = ev["file_path"].as_str().unwrap();
        assert!(shown.contains("CurrentVersion") && shown.contains("Updater"), "{shown}");
        assert_eq!(ev["autorun_command"], "powershell -enc AAA");

        // Something we did not stage is left alone.
        let mut other = json!({ "file_path": "/srv/unrelated.exe" });
        relabel_autorun(&mut other, &staged);
        assert_eq!(other["file_path"], "/srv/unrelated.exe");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// An autostart scan counts entries, not files — and has to say how many it
    /// could only read as text. autoruns skips keys it cannot see without admin,
    /// so a count that looks complete is exactly the thing to distrust.
    #[test]
    fn an_autostart_scan_says_what_it_could_and_could_not_check() {
        let mut r = parse(SAMPLE);
        r.autoruns = Some((40, 6));
        let v = results_view("en", &r, &wanted_levels(&Value::Null), 0).to_string();
        assert!(v.contains("40 autostart entries checked"));
        assert!(v.contains("6 of them named a program that could not be read"));

        // Nothing unreadable: no second line to explain away.
        let mut clean = parse(SAMPLE);
        clean.autoruns = Some((40, 0));
        let v = results_view("en", &clean, &wanted_levels(&Value::Null), 0).to_string();
        assert!(v.contains("40 autostart entries checked"));
        assert!(!v.contains("could not be read"));

        // A file scan says nothing about autostart at all.
        let files = parse(SAMPLE);
        let v = results_view("en", &files, &wanted_levels(&Value::Null), 0).to_string();
        assert!(!v.contains("autostart entries checked"));
    }

    /// Loki skips /media and /Volumes by default, so scanning a USB stick would
    /// read nothing and call it clean. The flag follows the target, because
    /// nobody choosing a folder should have to know that exclusion list exists.
    #[test]
    fn a_target_on_removable_media_is_scanned_without_being_asked() {
        let cfg = default_settings();
        let args = |t: &str| scan_args(&cfg, Some(t), Path::new("/o"));
        let all_drives = |t: &str| args(t).contains(&"--scan-all-drives".to_string());

        assert!(all_drives("/media/usb/stuff"));
        assert!(all_drives("/run/media/me/STICK"));
        assert!(all_drives("/Volumes/Backup"));
        assert!(all_drives("/media/usb"), "the mount point itself, not just under it");
        assert!(all_drives("/home/me/Library/CloudStorage/Dropbox"));

        // An ordinary path does not pay for it...
        assert!(!all_drives("/home/me/Downloads"));
        assert!(!all_drives("/srv"));
        // ...and a name that merely starts the same way is not a mount.
        assert!(!all_drives("/media-backup/old"));
    }

    /// The tab asks one question. Everything else moved behind Configure, so
    /// the settings must not be on the tab and the way to them must be.
    #[test]
    fn the_tab_asks_one_question_and_points_at_the_rest() {
        let v = main_view("en", &default_settings(), 0, Mode::Files, true, None).to_string();
        assert!(v.contains("Scan target"));
        assert!(v.contains("Configure scan"));
        // Reinstalling sits beside the version it replaces, on the tab — it was
        // once at the bottom of the settings pop-up, three clicks from the
        // number that prompts it.
        assert!(v.contains("Reinstall scanner"));
        assert!(v.contains(&format!("Loki-RS v{LOKI_VERSION}")));
        // The controls themselves belong to the pop-up now.
        assert!(!v.contains("CPU limit"));
        assert!(!v.contains("Thresholds"));
        // ...and the tab is not itself a pop-up.
        assert!(!v.contains("\"modal\""));
    }

    /// A pop-up that opens on the list's first entry instead of on what is
    /// saved would silently reset a setting the moment it was opened and saved.
    #[test]
    fn the_settings_pop_up_opens_on_what_is_saved() {
        let mut cfg = default_settings();
        cfg["cpu"] = json!("40");
        cfg["threads"] = json!("1");
        cfg["alert"] = json!("70");
        let v = settings_modal("en", &cfg, Mode::Files);
        let s = v.to_string();

        assert_eq!(v["modal"], "loki.settings", "it is a pop-up, with an identity");
        // A select's first option is the one shown.
        let opts = |id: &str| -> Vec<String> {
            v["widgets"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|w| {
                    let mut all = vec![w.clone()];
                    if let Some(ch) = w.get("children").and_then(Value::as_array) {
                        all.extend(ch.iter().cloned());
                    }
                    all
                })
                .find(|w| w.get("id").and_then(Value::as_str) == Some(id))
                .and_then(|w| w.get("options").cloned())
                .and_then(|o| serde_json::from_value(o).ok())
                .unwrap_or_default()
        };
        assert_eq!(opts("cpu").first().map(String::as_str), Some("40"));
        assert_eq!(opts("threads").first().map(String::as_str), Some("1"));
        assert!(s.contains(r#""default":"70""#), "threshold shows the saved value");
        // A saved checkbox opens ticked, and one that is off opens unticked.
        let boxes: Vec<&Value> = v["widgets"].as_array().unwrap().iter().collect();
        let checked = |id: &str| {
            boxes
                .iter()
                .find(|w| w.get("id").and_then(Value::as_str) == Some(id))
                .and_then(|w| w.get("default"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
        };
        assert!(!checked("all_drives"));
    }

    /// Cancel has nothing to ask the module, and the way back from the
    /// signature pop-up must land on the settings pop-up, not on the tab.
    #[test]
    fn the_pop_ups_can_always_be_left() {
        let settings = settings_modal("en", &default_settings(), Mode::Files);
        let cancel = settings["widgets"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|w| {
                w.get("children")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
            })
            .find(|w| w.get("text").and_then(Value::as_str) == Some("Cancel"))
            .expect("a Cancel button");
        assert_eq!(cancel["dismiss"], true, "answered by the host, not a round trip");

        let sigs = signatures_modal("en", &[], None, None);
        assert_eq!(sigs["modal"], "loki.signatures");
        assert!(sigs.to_string().contains("Back to settings"));
    }

    /// Every kind offered has to be one Loki really loads — `keywords.txt` ships
    /// in the signatures directory but 2.12.0 never reads it, so offering it
    /// would swallow someone's indicators in silence.
    #[test]
    fn the_picker_offers_only_kinds_the_scanner_reads() {
        let kinds: Vec<&str> = IOC_KINDS.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, vec!["hashes", "filenames", "c2"]);
        assert!(!kinds.contains(&"keywords"), "not loaded by Loki 2.12.0");
    }

    /// While the operating system is asking, the module must show that it is
    /// asking — a scan that appears to hang is one the user kills.
    #[test]
    fn the_authorization_prompt_is_visible_and_polls_itself() {
        let v = authorizing_modal("en");
        assert_eq!(v["modal"], "loki.authorizing", "it is a pop-up: nothing else can proceed");
        // It has to poll, or it would sit there after the prompt is answered.
        assert_eq!(v["auto"]["method"], "s_poll");
        let s = v.to_string();
        assert!(s.contains("Waiting for authorization"));
        // And say why, since a password prompt out of nowhere is alarming.
        assert!(s.contains("process memory"));
        assert!(s.contains("loading"), "with a spinner, not a dead screen");
    }

    /// Every way an elevated scan can fail has to be tellable apart: refusing is
    /// the user's choice, an unavailable helper is theirs to fix, and a crash is
    /// ours. One message for all three would leave nobody knowing what to do.
    #[test]
    fn each_authorization_outcome_says_something_different() {
        let t = |k: &str| catalog().tr("en", k);
        let refused = t("scan.auth_refused");
        let none = t("scan.no_elevation");
        let failed = t("scan.auth_failed");
        assert!(refused.contains("refused"));
        assert!(none.contains("pkexec") && none.contains("start Limen as administrator"));
        assert!(failed.contains("{error}"), "carries the detail");
        for m in [&refused, &none, &failed] {
            assert!(!m.starts_with("scan."), "untranslated key leaked: {m}");
        }
        // Ukrainian says all three too.
        for k in ["scan.auth_refused", "scan.no_elevation", "scan.auth_failed"] {
            assert_ne!(catalog().tr("uk", k), k, "{k} missing from uk");
        }
    }

    /// Each kind gets its own help, because the rules genuinely differ — and the
    /// differences are the kind that cost you a rule in silence.
    #[test]
    fn each_kind_is_explained_on_its_own_terms() {
        let help = |k: &str| signature_help_modal("en", k).to_string();

        // A YARA rule carries its own weight; an indicator never does.
        let yara = help("yara");
        assert!(yara.contains(".yar"));
        assert!(yara.contains("score = 85"), "a rule sets its own score");
        assert!(yara.contains("scores 75"), "and what it scores without one");

        // A bare hash is dropped...
        let hashes = help("hashes");
        assert!(hashes.contains("44d88612fea8a8f36de82e1278abb02f;EICAR test file"));
        assert!(hashes.contains("description is required"));
        // An example is something people paste in unchanged. d41d8cd9… is the
        // MD5 of an empty file, so that one would have flagged every empty file
        // on the machine as an indicator of compromise.
        assert!(
            !hashes.contains("d41d8cd98f00b204e9800998ecf8427e"),
            "an example must not match something ordinary"
        );

        // ...but a bare C2 address is kept, so the help must not say otherwise.
        let c2 = help("c2");
        assert!(c2.contains("optional"));
        assert!(!c2.contains("description is required"));
        // The one that decides whether these do anything at all.
        assert!(c2.contains("Scan process memory"));

        let names = help("filenames");
        assert!(names.contains("regular expression"));
        assert!(names.contains("does not compile"));

        // All four share the pop-up, so switching kinds redraws rather than
        // stacking, and an unknown kind still lands somewhere sensible.
        for k in ["yara", "hashes", "filenames", "c2", "nonsense"] {
            assert_eq!(signature_help_modal("en", k)["modal"], "loki.sig_help");
        }
    }

    /// The bundled set is a signature source too, so it belongs in the list —
    /// and when it is missing, the way to get it belongs beside the way to add
    /// anything else.
    #[test]
    fn the_bundled_rules_are_listed_and_installable() {
        // Missing: offered, and the list does not pretend to be empty of it.
        let absent = signatures_modal("en", &[], None, None).to_string();
        assert!(absent.contains("Install YARA-Forge Core"));
        assert!(!absent.contains("yara-rules-core.yar"));

        // Present: listed with its age, and the button becomes an update.
        let v = signatures_modal("en", &[], Some((5069, "2026-08-02".into())), None);
        let s = v.to_string();
        assert!(s.contains("yara-rules-core.yar"));
        assert!(s.contains("5069") && s.contains("2026-08-02"), "its age is the point");
        assert!(s.contains("Update YARA-Forge Core"));
        assert!(!s.contains("Install YARA-Forge Core"));
    }

    /// Every row offers the same three things, and the destructive one asks
    /// first — a delete is no less destructive for being in a menu.
    #[test]
    fn every_row_can_be_opened_here_opened_in_a_tab_or_deleted() {
        let v = signatures_modal(
            "en",
            &[("yara".into(), "mine.yar".into())],
            Some((5069, "2026-08-02".into())),
            None,
        );
        let table = v["widgets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w.get("kind").and_then(Value::as_str) == Some("table"))
            .expect("a table, so rows can be activated and right-clicked");

        // Double-click opens in the same window, not a tab: a table inside a
        // pop-up should not throw the user out of it.
        assert_eq!(table["on_activate"]["action"]["method"], "sig_info");
        assert_eq!(table["on_activate"]["open_in_tab"], false);

        assert_eq!(table["row_ids"][0], "bundled");
        assert_eq!(table["row_ids"][1], "yara/mine.yar");

        for row in table["row_menus"].as_array().unwrap() {
            let items = row.as_array().unwrap();
            let labels: Vec<&str> = items
                .iter()
                .filter_map(|i| i["label"].as_str())
                .collect();
            assert_eq!(
                labels,
                vec![
                    "Signature details",
                    "Open in editor",
                    "Open details in a new tab",
                    "Remove"
                ]
            );
            // Only the tab one opens a tab.
            assert!(items[0].get("open_in_tab").is_none());
            assert!(items[1].get("open_in_tab").is_none());
            assert_eq!(items[2]["open_in_tab"], true);
            assert_eq!(items[2]["args"]["in_tab"], true);
            // ...and only the delete asks.
            assert!(items[0].get("confirm").is_none());
            assert!(items[1].get("confirm").is_none());
            assert!(items[3]["confirm"]["title"].as_str().unwrap().contains("Remove"));
        }
    }

    /// The detail is a step of the same window when opened from the list, and a
    /// plain view in a tab — a tab has no pop-up to be a step of, and no list to
    /// go back to.
    #[test]
    fn signature_details_suit_where_they_were_opened() {
        let info = || SigInfo {
            id: "bundled".to_string(),
            facts: vec![("rules".to_string(), "5069".to_string())],
            sample: vec!["MALPEDIA  ×1557".to_string()],
        };
        let here = signature_info_modal("en", Some(info()), false);
        assert_eq!(here["modal"], "loki.sig_info");
        assert_eq!(here["modal_width"], 820.0, "wider than the list, so the window grows");
        assert!(here.to_string().contains("Back to signatures"));

        let tab = signature_info_modal("en", Some(info()), true);
        assert!(tab.get("modal").is_none(), "a tab is not a pop-up");
        assert!(!tab.to_string().contains("Back to signatures"));
        // Both still show what they were opened for.
        for v in [&here, &tab] {
            assert!(v.to_string().contains("MALPEDIA"));
            assert!(v.to_string().contains("5069"));
        }
    }

    /// Adding a file redraws the same pop-up rather than opening another over
    /// it — the id is what stops a list that refreshes from stacking up.
    #[test]
    fn the_signature_pop_up_keeps_its_identity_as_it_refreshes() {
        let empty = signatures_modal("en", &[], None, None);
        let one = signatures_modal(
            "en",
            &[("yara".to_string(), "my-rules.yar".to_string())],
            None,
            None,
        );
        assert_eq!(empty["modal"], one["modal"]);
        assert!(empty.to_string().contains("Nothing added yet"));
        let s = one.to_string();
        assert!(s.contains("my-rules.yar"));
        assert!(s.contains("YARA rules"), "the kind is named, not a bare key");
        // The row id carries the kind too: a name alone would not say which
        // directory to remove it from.
        assert!(s.contains("yara/my-rules.yar"));
    }

    /// The settings are out of sight, so the tab has to say what they will do —
    /// a scan whose behaviour is invisible is one nobody can check.
    #[test]
    fn the_tab_says_what_the_settings_will_do() {
        let mut cfg = default_settings();
        let line = settings_summary("en", &cfg, 0, Mode::Files);
        assert!(line.contains("every file"));
        assert!(line.contains("inside ZIP archives"));

        cfg["all_files"] = json!(false);
        let line = settings_summary("en", &cfg, 2, Mode::Files);
        assert!(line.contains("executables and scripts only"));
        assert!(line.contains("2 of your own"));
    }

    /// Settings written by an older build are missing whatever was added since;
    /// merging keeps the rest instead of resetting every choice.
    #[test]
    fn saved_settings_merge_over_the_defaults() {
        let mut s = default_settings();
        let saved: Value = json!({ "cpu": "40", "gone_key": "x" });
        if let (Value::Object(saved), Some(base)) = (saved, s.as_object_mut()) {
            for (k, v) in saved {
                if base.contains_key(&k) {
                    base.insert(k, v);
                }
            }
        }
        assert_eq!(s["cpu"], "40", "what was saved wins");
        assert_eq!(s["alert"], "80", "what was not saved keeps its default");
        assert!(s.get("gone_key").is_none(), "a key we no longer know is dropped");
    }

    #[test]
    fn scan_args_reflect_the_form() {
        let out = Path::new("/tmp/r.jsonl");
        let bare = scan_args(&json!({}), Some("/srv"), out);
        assert!(bare.windows(2).any(|w| w == ["--folder", "/srv"]));
        assert!(bare.contains(&"--no-tui".to_string()));
        // Loki drops a .log and an .html beside itself unless told not to, and
        // the JSONL is the only one this module reads.
        assert!(bare.contains(&"--no-log".to_string()));
        assert!(bare.contains(&"--no-html".to_string()));
        // Processes are their own scan now, so a file scan never wanders into
        // them — it would double the work and double-count every hit.
        assert!(bare.contains(&"--no-procs".to_string()));
        // Loki looks inside archives by default, so this only appears when the
        // box is unticked.
        assert!(bare.contains(&"--no-archive".to_string()));

        let full = scan_args(
            &json!({ "archives": true, "threads": "all", "cpu": "60",
                     "alert": "70", "max_size": "1000" }),
            Some("/srv"),
            out,
        );
        assert!(!full.contains(&"--no-archive".to_string()));
        assert!(full.windows(2).any(|w| w == ["--threads", "0"]));
        assert!(full.windows(2).any(|w| w == ["--cpu-limit", "60"]));
        assert!(full.windows(2).any(|w| w == ["--alert-level", "70"]));
        assert!(full.windows(2).any(|w| w == ["-m", "1000"]));
    }

    /// A process scan is a different job: this machine, not a path. Without
    /// `--no-fs` Loki walks the whole filesystem as well, which is neither what
    /// was asked for nor something the user would notice until it took hours.
    #[test]
    fn a_process_scan_reads_no_files_and_needs_no_target() {
        let a = scan_args(&default_settings(), None, Path::new("/o"));
        assert!(a.contains(&"--no-fs".to_string()));
        assert!(!a.contains(&"--folder".to_string()), "there is no target");
        assert!(!a.contains(&"--no-procs".to_string()), "processes are the point");
        // File-only settings have no business in it.
        for flag in ["--scan-all-files", "--no-archive", "--scan-all-drives"] {
            assert!(!a.contains(&flag.to_string()), "{flag} is meaningless here");
        }
        // Tuning still applies to both.
        assert!(a.windows(2).any(|w| w == ["--alert-level", "80"]));
    }

    /// The two scans share almost nothing, so the screen must not offer the
    /// other one's controls — a setting that cannot do anything is worse than
    /// one that is absent.
    #[test]
    fn each_scan_offers_only_its_own_settings() {
        let cfg = default_settings();
        let files = settings_modal("en", &cfg, Mode::Files).to_string();
        let procs = settings_modal("en", &cfg, Mode::Procs).to_string();

        assert!(files.contains("Scan every file"));
        assert!(files.contains("Max file size"));
        assert!(!procs.contains("Scan every file"));
        assert!(!procs.contains("Max file size"));
        assert!(!procs.contains("archives"));
        // Tuning belongs to both.
        for v in [&files, &procs] {
            assert!(v.contains("CPU limit"));
            assert!(v.contains("Thresholds"));
        }

        // And the tab asks for a path only when there is one to ask for.
        let ftab = main_view("en", &cfg, 0, Mode::Files, true, None).to_string();
        let ptab = main_view("en", &cfg, 0, Mode::Procs, true, None).to_string();
        assert!(ftab.contains("Scan target"));
        assert!(!ptab.contains("Scan target"), "a process scan has no target");
        assert!(ptab.contains("running processes"));
        // One button cycles the three, so none is a dead end.
        assert!(ftab.contains("Scan running processes instead"));
        assert!(ptab.contains("Scan what starts automatically instead"));
        let atab = main_view("en", &cfg, 0, Mode::Autoruns, true, None).to_string();
        assert!(atab.contains("Scan files or a folder instead"));

        // ...and autostart is skipped entirely when nothing provides it, rather
        // than offering a scan that cannot run.
        let no_ar = main_view("en", &cfg, 0, Mode::Procs, false, None).to_string();
        assert!(no_ar.contains("Scan files or a folder instead"));
        assert!(!no_ar.contains("starts automatically instead"));
    }

    /// A number that is not a number must be dropped, not handed to the scanner
    /// — it would refuse to start and the reason would be buried.
    #[test]
    fn nonsense_tuning_is_not_passed_through() {
        let a = scan_args(
            &json!({ "cpu": "60%", "alert": "high", "max_size": "" }),
            Some("/x"),
            Path::new("/o"),
        );
        assert!(!a.contains(&"--cpu-limit".to_string()));
        assert!(!a.contains(&"--alert-level".to_string()));
        assert!(!a.contains(&"-m".to_string()));
    }

    /// Results always show what the scan did — how much it read and how long it
    /// took. "Nothing found" only reassures if you can see something was looked at.
    #[test]
    fn results_show_what_the_scan_actually_did() {
        let r = parse(SAMPLE);
        let v = results_view("en", &r, &wanted_levels(&Value::Null), 0).to_string();
        assert!(v.contains("need attention"), "a verdict");
        assert!(v.contains("/tmp/evil.bin"), "the findings");
        assert!(v.contains("Started") && v.contains("Processes"), "and the scan's own numbers");
    }

    /// The kind column is a column of the same word unless processes were
    /// actually scanned, so it appears only when it can differ.
    #[test]
    fn the_kind_column_appears_only_when_it_says_something() {
        let both = parse(SAMPLE);
        assert!(results_view("en", &both, &wanted_levels(&Value::Null), 0)
            .to_string()
            .contains("Kind"));

        // The same report with the one process match dropped.
        let files_only: String = SAMPLE
            .lines()
            .filter(|l| !l.contains("process_match"))
            .collect::<Vec<_>>()
            .join("\n");
        let r = parse(&files_only);
        assert!(!results_view("en", &r, &wanted_levels(&Value::Null), 0)
            .to_string()
            .contains("Kind"));
    }

    /// "Nothing suspicious" over zero examined files is the one answer here that
    /// could actually mislead someone.
    #[test]
    fn a_scan_that_read_nothing_does_not_claim_to_be_clean() {
        let empty = r#"{"timestamp":"2026-08-03T10:00:00+00:00","level":"INFO","event_type":"scan_end","hostname":"h","message":"Summary - Files scanned: 0 Matched: 0 | Processes scanned: 0 Matched: 0. Scan Duration: 4.8s"}"#;
        let r = parse(empty);
        let v = results_view("en", &r, &wanted_levels(&Value::Null), 0).to_string();
        assert!(!v.contains("Nothing suspicious found"));
        assert!(v.contains("No files were examined"));
    }

    #[test]
    fn the_detail_view_shows_the_rule_and_what_it_matched() {
        let r = parse(SAMPLE);
        let v = detail_view("en", &r.findings[0]).to_string();
        assert!(v.contains("MAL_Backdoor_Gen"));
        assert!(v.contains("Florian Roth"));
        assert!(v.contains("cmd.exe /c"), "matched strings are the evidence");
        assert!(v.contains("d41d8cd98f00b204e9800998ecf8427e"));
    }

    #[test]
    fn default_levels_hide_the_noise() {
        let r = parse(SAMPLE);
        let v = results_view("en", &r, &wanted_levels(&Value::Null), 0).to_string();
        assert!(v.contains("/tmp/evil.bin"));
        assert!(!v.contains("/tmp/x.tmp"), "NOTICE is not shown by default");
        // ...but the chip still advertises it.
        assert!(v.contains("NOTICE (1)"));
    }

    #[test]
    fn an_empty_report_does_not_panic() {
        let r = parse("");
        assert_eq!(r.findings.len(), 0);
        let _ = results_view("en", &r, &wanted_levels(&Value::Null), 0);
    }

    #[test]
    fn ukrainian_covers_every_english_key() {
        let en = catalog_keys(include_str!("locales/en.toml"));
        let uk = catalog_keys(include_str!("locales/uk.toml"));
        let missing: Vec<&String> = en.iter().filter(|k| !uk.contains(k)).collect();
        assert!(missing.is_empty(), "Ukrainian is missing: {missing:?}");
    }

    /// A key that resolves to itself is in no catalog at all — the fallback
    /// chain is lang -> en -> the key, so that is how a typo surfaces. Matched
    /// exactly: prose can contain "report." simply by ending a sentence.
    #[test]
    fn no_rendered_key_falls_through_to_itself() {
        let keys = catalog_keys(include_str!("locales/en.toml"));
        for lang in ["en", "uk"] {
            for v in [
                install_view(lang, None),
                installing_view(lang, 1),
                main_view(lang, &default_settings(), 1, Mode::Files, true, None),
                settings_modal(lang, &default_settings(), Mode::Files),
                signatures_modal(lang, &[("yara".into(), "r.yar".into())], Some((5069, "2026-08-02".into())), None),
                scanning_view(lang, 1, 0, false),
            ] {
                let s = v.to_string();
                for k in &keys {
                    assert!(
                        !s.contains(&format!(":\"{k}\"")),
                        "{lang}: key rendered instead of its translation: {k}"
                    );
                }
            }
        }
    }

    /// Rendering in Ukrainian must not leave English prose behind — a hardcoded
    /// literal is not a key, so the leak test above cannot catch it.
    #[test]
    fn the_ukrainian_views_carry_no_english_prose() {
        const ENGLISH: [&str; 12] = [
            "Version",
            "Platform",
            "Download",
            "verified against",
            "Install Loki",
            "Scan target",
            "Threads",
            "process memory",
            "Configure scan",
            "Signatures",
            "every file",
            "Back to settings",
        ];
        for v in [
            install_view("uk", None),
            installing_view("uk", 1),
            main_view("uk", &default_settings(), 1, Mode::Files, true, None),
            settings_modal("uk", &default_settings(), Mode::Files),
            signatures_modal("uk", &[("hashes".into(), "h.txt".into())], Some((5069, "2026-08-02".into())), None),
            signature_help_modal("uk", "c2"),
            signature_help_modal("uk", "yara"),
            scanning_view("uk", 0, 0, false),
        ] {
            let s = v.to_string();
            for word in ENGLISH {
                assert!(!s.contains(word), "English left in a Ukrainian view: {word:?}");
            }
        }
    }
}

