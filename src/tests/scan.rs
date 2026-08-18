//! Setting a scan up, running it, and stopping it.

use super::*;

/// Loki reads only executables and scripts unless told otherwise, so a basic
/// scan of a documents folder would examine nothing and call it clean.
#[test]
fn the_default_settings_read_every_file() {
    let d = scan_args(&default_settings(), Some("/srv"), Path::new("/o"));
    assert!(d.contains(&"--scan-all-files".to_string()));
    // ...and turning it off is the deliberate act.
    let mut cfg = default_settings();
    cfg["all_files"] = json!(false);
    assert!(!scan_args(&cfg, Some("/srv"), Path::new("/o"))
        .contains(&"--scan-all-files".to_string()));
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
    assert!(
        shown.contains("CurrentVersion") && shown.contains("Updater"),
        "{shown}"
    );
    assert_eq!(ev["autorun_command"], "powershell -enc AAA");

    // Something we did not stage is left alone.
    let mut other = json!({ "file_path": "/srv/unrelated.exe" });
    relabel_autorun(&mut other, &staged);
    assert_eq!(other["file_path"], "/srv/unrelated.exe");
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Loki writes no per-file activity, so the panel shows what it *does* say —
/// which paths it excluded, whether it is elevated, each finding as it
/// lands. Capped, because the view is redrawn on every poll.
#[test]
fn the_scanner_output_can_be_shown_and_is_bounded() {
    let dir = std::env::temp_dir().join("loki-test-output");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("report.jsonl");
    let mut text = String::new();
    for i in 0..120 {
        text.push_str(&format!(
            "{{\"event_type\":\"info\",\"message\":\"line {i}\"}}\n"
        ));
    }
    // A line that is not JSON at all — an interrupted scan leaves one.
    text.push_str("{ truncated\n");
    std::fs::write(&out, text).unwrap();

    let shown = scan_output(std::slice::from_ref(&out), 40);
    assert_eq!(shown.len(), 40, "capped");
    assert_eq!(shown.last().unwrap(), "line 119", "most recent last");
    assert_eq!(shown.first().unwrap(), "line 80");

    // Hidden by default: the button offers to show it, and the panel is not
    // there until asked for.
    let hidden = scanning_view("en", 3, 0, false, None).to_string();
    assert!(hidden.contains("Show scanner output"));
    assert!(!hidden.contains("line 119"));

    // Shown: the lines appear, and the button offers to put them away.
    let open = scanning_view("en", 3, 0, false, Some(&shown)).to_string();
    assert!(open.contains("Hide scanner output"));
    assert!(open.contains("line 119"));
    // ...and it keeps polling either way, or the scan would appear to stall.
    assert_eq!(
        serde_json::from_str::<Value>(&open).unwrap()["auto"]["method"],
        "s_poll"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Stop has to do something. On an elevated scan it cannot actually stop the
/// scanner — root — so the one thing it must not do is show a screen that
/// looks like it ended.
#[test]
fn a_scan_that_could_not_be_stopped_says_it_is_still_running() {
    let mut r = parse(SAMPLE);
    r.still_running = true;
    let v = results_view("en", &r, &wanted_levels(&Value::Null), 0, 0).to_string();
    assert!(v.contains("could not be stopped from here"));
    assert!(v.contains("still going"));
    // ...and what is shown is flagged as partial.
    assert!(v.contains("only what it had written"));

    // A scan that ended normally carries none of that.
    let done = parse(SAMPLE);
    let v = results_view("en", &done, &wanted_levels(&Value::Null), 0, 0).to_string();
    assert!(!v.contains("could not be stopped"));
}

/// What was found decides what the notice says.
///
/// The levels are counted under Loki's own spelling, which is upper case,
/// and this asked for "alert". It matched nothing, so every scan fell
/// through to "Nothing found" — a green notice on a machine with a YARA
/// match sitting in the results behind it.
#[test]
fn the_notice_reports_what_was_actually_found() {
    let loki = Loki::default();
    let view = || window(catalog().tr("en", "title"), vec![]);

    // SAMPLE carries one ALERT and one WARNING.
    let r = parse(SAMPLE);
    assert_eq!(r.counts.get("ALERT"), Some(&1), "the sample lost its alert");
    let v = loki.scan_notice("en", &r, view()).to_string();
    assert!(v.contains(r#""level":"error""#), "an alert is not a clean scan: {v}");
    assert!(v.contains("1 alert"), "{v}");

    // The same scan with the alert taken out is a warning, not an error.
    let warned = parse(&SAMPLE.replace(r#""level":"ALERT""#, r#""level":"NOTICE""#));
    let v = loki.scan_notice("en", &warned, view()).to_string();
    assert!(v.contains(r#""level":"warning""#), "{v}");

    // And one that finished with nothing at all is the only "ok".
    let clean = parse(
        &SAMPLE
            .lines()
            .filter(|l| !l.contains("_match"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let v = loki.scan_notice("en", &clean, view()).to_string();
    assert!(v.contains(r#""level":"ok""#), "{v}");

    // ...but only if it read something. A scan that walked away from every path
    // it was given finishes exactly like an empty folder does, and calling that
    // "nothing found" is the module vouching for a machine it never looked at.
    let nothing = parse(
        &SAMPLE
            .replace("Files scanned: 1240", "Files scanned: 0")
            .replace("Processes scanned: 87", "Processes scanned: 0")
            .lines()
            .filter(|l| !l.contains("_match"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let v = loki.scan_notice("en", &nothing, view()).to_string();
    assert!(v.contains(r#""level":"warning""#), "read nothing, said clean: {v}");
    assert!(v.contains("Nothing was read"), "{v}");
}

/// A scan announces itself when it begins — and only then.
///
/// A scan is minutes to hours of a progress line, and an elevated one begins
/// behind a password prompt; the user has usually looked away by the time it
/// is answered. The trap is that the running screen is redrawn on a poll, so
/// the obvious place to say it is one that says it several times a second.
#[test]
fn a_scan_says_it_started_once() {
    let mut loki = Loki::default();
    let view = || scanning_view("en", 0, 0, false, None);

    let first = loki.started_notice("en", view()).to_string();
    assert!(first.contains(r#""level":"ok""#), "a scan starting is good news: {first}");
    assert!(first.contains("Scan started"), "{first}");

    // Every redraw after it is the same scan, not a new one.
    for _ in 0..5 {
        let again = loki.started_notice("en", view()).to_string();
        assert!(!again.contains("Scan started"), "the alert was raised twice: {again}");
    }

    // The next scan is a new event, and clears the flag itself.
    loki.announced = false;
    let next = loki.started_notice("en", view()).to_string();
    assert!(next.contains("Scan started"), "{next}");
}

/// A prompt that was refused, dismissed, or never appeared has to be said out
/// loud.
///
/// The screen behind it explains what to do; the alert exists for the user
/// who put the prompt aside and went back to something else, and would
/// otherwise come back to a scan screen that simply never started.
#[test]
fn an_unauthorized_scan_is_an_error_not_a_silence() {
    let ended = |reason: &str| limen_sdk_rust::Elevated {
        ran: false,
        code: None,
        reason: reason.into(),
        message: "polkit said no".into(),
    };

    // Each of the three ways it can fail says something true, and the corner
    // never carries the long "install pkexec" explanation the screen does.
    for (reason, screen, alert) in [
        ("refused", "scan.auth_refused", "notice.auth_refused"),
        ("unavailable", "scan.no_elevation", "notice.no_elevation"),
        ("error", "scan.auth_failed", "notice.auth_failed"),
    ] {
        assert_eq!(auth_keys(&ended(reason)), (screen, alert), "for {reason}");
        // The corner is narrow: the alert says the scan did not start, and
        // leaves the advice about installing pkexec to the screen.
        let corner = catalog().tr("en", alert);
        assert!(!corner.contains("pkexec"), "the alert is the whole explanation: {corner}");
        assert!(!corner.contains("{error}"), "nothing fills that in here: {corner}");
    }
}

/// Pressing Stop is not a failure.
///
/// A stopped scan has no summary, and "no summary" was read as "it broke" —
/// so asking it to stop answered with a red error saying the scan did not
/// finish. It did not, because that is what was asked for. What it found
/// before stopping is still real, though, so findings win over the wording.
#[test]
fn stopping_a_scan_is_not_an_error() {
    let loki = Loki::default();
    let view = || window(catalog().tr("en", "title"), vec![]);

    // Stopped with nothing found: said plainly, not in red, and never as
    // "nothing found" — it stopped before it could know that.
    let mut r = parse("");
    r.stopped = true;
    let v = loki.scan_notice("en", &r, view()).to_string();
    assert!(v.contains(r#""level":"info""#), "a deliberate stop is not an error: {v}");
    assert!(v.contains("Scan stopped"), "{v}");
    assert!(!v.contains("Nothing found"), "a stopped scan cannot report a clean machine");

    // Stopped after something matched: the finding is what matters.
    let mut found = parse(SAMPLE);
    found.stopped = true;
    let v = loki.scan_notice("en", &found, view()).to_string();
    assert!(v.contains(r#""level":"error""#), "findings survive the stop: {v}");

    // And a scan that really did break still says so.
    let broken = parse("");
    let v = loki.scan_notice("en", &broken, view()).to_string();
    assert!(v.contains(r#""level":"error""#), "{v}");
    assert!(v.contains("did not finish"), "{v}");
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
    assert!(full.contains(&"--threads=0".to_string()));
    assert!(full.contains(&"--cpu-limit=60".to_string()));
    assert!(full.contains(&"--alert-level=70".to_string()));
    assert!(full.contains(&"-m=1000".to_string()));
}

/// A process scan is a different job: this machine, not a path. Without
/// `--no-fs` Loki walks the whole filesystem as well, which is neither what
/// was asked for nor something the user would notice until it took hours.
#[test]
fn a_process_scan_reads_no_files_and_needs_no_target() {
    let a = scan_args(&default_settings(), None, Path::new("/o"));
    assert!(a.contains(&"--no-fs".to_string()));
    assert!(!a.contains(&"--folder".to_string()), "there is no target");
    assert!(
        !a.contains(&"--no-procs".to_string()),
        "processes are the point"
    );
    // File-only settings have no business in it.
    for flag in ["--scan-all-files", "--no-archive", "--scan-all-drives"] {
        assert!(!a.contains(&flag.to_string()), "{flag} is meaningless here");
    }
    // Tuning still applies to both.
    assert!(a.contains(&"--alert-level=80".to_string()));
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
    let ftab = main_view("en", &cfg, 0, Mode::Files, true, None, None).to_string();
    let ptab = main_view("en", &cfg, 0, Mode::Procs, true, None, None).to_string();
    assert!(ftab.contains("Scan target"));
    assert!(
        !ptab.contains("Scan target"),
        "a process scan has no target"
    );
    assert!(ptab.contains("running processes"));
    // One button cycles the three, so none is a dead end.
    assert!(ftab.contains("Scan running processes instead"));
    assert!(ptab.contains("Scan what starts automatically instead"));
    let atab = main_view("en", &cfg, 0, Mode::Autoruns, true, None, None).to_string();
    assert!(atab.contains("Scan files or a folder instead"));

    // ...and autostart is skipped entirely when nothing provides it, rather
    // than offering a scan that cannot run.
    let no_ar = main_view("en", &cfg, 0, Mode::Procs, false, None, None).to_string();
    assert!(no_ar.contains("Scan files or a folder instead"));
    assert!(!no_ar.contains("starts automatically instead"));
}

/// A negative value must never be its own argument: the scanner reads it as
/// a flag, prints usage and exits having scanned nothing — which looked
/// exactly like a fast, clean scan. The default thread setting is negative,
/// so this broke every scan there was.
#[test]
fn negative_numbers_are_joined_to_their_flag() {
    for (setting, expect) in [("all-2", "--threads=-2"), ("all-1", "--threads=-1")] {
        let mut cfg = default_settings();
        cfg["threads"] = json!(setting);
        let a = scan_args(&cfg, Some("/x"), Path::new("/o"));
        assert!(a.contains(&expect.to_string()), "{setting} -> {a:?}");
        // Never as two arguments, whatever else is in there.
        assert!(
            !a.iter().any(|x| x == "--threads"),
            "the separate form is the bug: {a:?}"
        );
        // The real hazard: a bare negative number standing on its own,
        // which the parser can only read as a flag.
        assert!(
            !a.iter().any(|x| x.parse::<i64>().is_ok_and(|n| n < 0)),
            "a negative value stands alone: {a:?}"
        );
    }
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
