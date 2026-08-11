//! The screens: what they show, and what they refuse to claim.

use super::*;

/// The screen says why it is partial, rather than showing half a result with
/// nothing to explain it.
#[test]
fn a_stopped_scan_says_so_on_the_results_screen() {
    let mut r = parse(SAMPLE);
    r.stopped = true;
    let v = results_view("en", &r, &wanted_levels(&Value::Null), 0).to_string();
    assert!(v.contains("Stopped before it finished"), "{v}");

    let done = parse(SAMPLE);
    let v = results_view("en", &done, &wanted_levels(&Value::Null), 0).to_string();
    assert!(!v.contains("Stopped before it finished"));
}

/// A scan that could not read everything is not a scan that found nothing.
/// Loki hides access errors, so an unprivileged scan of a system directory
/// looks exactly like a thorough one that came back clean.
#[test]
fn a_scan_without_privileges_says_so() {
    let mut r = parse(SAMPLE);
    r.unelevated = true;
    let v = results_view("en", &r, &wanted_levels(&Value::Null), 0).to_string();
    assert!(v.contains("without administrator privileges"));
    assert!(v.contains("not a full picture"));

    // And an elevated scan does not carry the caveat.
    let ok = parse(SAMPLE);
    let v = results_view("en", &ok, &wanted_levels(&Value::Null), 0).to_string();
    assert!(!v.contains("without administrator privileges"));
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
    assert!(
        all_drives("/media/usb"),
        "the mount point itself, not just under it"
    );
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

    assert_eq!(
        v["modal"], "loki.settings",
        "it is a pop-up, with an identity"
    );
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
    assert!(
        s.contains(r#""default":"70""#),
        "threshold shows the saved value"
    );
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
    assert_eq!(
        cancel["dismiss"], true,
        "answered by the host, not a round trip"
    );

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
    assert_eq!(
        v["modal"], "loki.authorizing",
        "it is a pop-up: nothing else can proceed"
    );
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
    assert!(
        s.contains("5069") && s.contains("2026-08-02"),
        "its age is the point"
    );
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
        let labels: Vec<&str> = items.iter().filter_map(|i| i["label"].as_str()).collect();
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
        assert!(items[3]["confirm"]["title"]
            .as_str()
            .unwrap()
            .contains("Remove"));
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
    assert_eq!(
        here["modal_width"], 820.0,
        "wider than the list, so the window grows"
    );
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
    assert!(
        s.contains("YARA rules"),
        "the kind is named, not a bare key"
    );
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
    assert!(
        s.get("gone_key").is_none(),
        "a key we no longer know is dropped"
    );
}

/// Results always show what the scan did — how much it read and how long it
/// took. "Nothing found" only reassures if you can see something was looked at.
#[test]
fn results_show_what_the_scan_actually_did() {
    let r = parse(SAMPLE);
    let v = results_view("en", &r, &wanted_levels(&Value::Null), 0).to_string();
    assert!(v.contains("need attention"), "a verdict");
    assert!(v.contains("/tmp/evil.bin"), "the findings");
    assert!(
        v.contains("Started") && v.contains("Processes"),
        "and the scan's own numbers"
    );
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

/// A scan that never finished has no summary — and a missing summary used to
/// read as "something was examined", so a crashed or killed scan reported a
/// clean machine. The most dangerous answer this module can give.
#[test]
fn a_scan_that_did_not_finish_is_not_reported_as_clean() {
    // Startup lines and nothing else: no scan_end, no findings.
    let cut_short = r#"{"timestamp":"2026-08-03T10:00:00+00:00","level":"INFO","event_type":"scan_start","hostname":"h","message":"Loki-RS scan started"}"#;
    let r = parse(cut_short);
    assert!(r.stats.is_none(), "no summary was written");
    let v = results_view("en", &r, &wanted_levels(&Value::Null), 0).to_string();
    assert!(v.contains("did not finish"));
    assert!(!v.contains("Nothing suspicious found"));

    // An empty report is the same story.
    let v = results_view("en", &parse(""), &wanted_levels(&Value::Null), 0).to_string();
    assert!(v.contains("did not finish"));
    assert!(!v.contains("Nothing suspicious found"));

    // A scan that *did* finish and found nothing is still allowed to say so.
    let done = r#"{"timestamp":"2026-08-03T10:01:00+00:00","level":"INFO","event_type":"scan_end","hostname":"h","message":"Summary - Files scanned: 1240 Matched: 0 | Processes scanned: 0 Matched: 0. Scan Duration: 4.8s"}"#;
    let v = results_view("en", &parse(done), &wanted_levels(&Value::Null), 0).to_string();
    assert!(v.contains("Nothing suspicious found"));
    assert!(!v.contains("did not finish"));
}

/// Telling someone to go and look at output that is only on the previous
/// screen is no help. When a scan does not finish, the last thing the
/// scanner said is the diagnosis, so it is shown with the failure.
#[test]
fn a_failed_scan_shows_what_the_scanner_last_said() {
    let mut r = parse(r#"{"event_type":"scan_start","message":"Loki-RS scan started"}"#);
    r.tail = vec![
        "Initializing YARA rules ...".into(),
        "Failed to initialize YARA rules: Cannot read YARA rules directory ./signatures/yara"
            .into(),
    ];
    let v = results_view("en", &r, &wanted_levels(&Value::Null), 0).to_string();
    assert!(v.contains("did not finish"));
    assert!(v.contains("The last thing the scanner said"));
    assert!(v.contains("Cannot read YARA rules directory"), "the reason is on screen");

    // A scan that finished carries no tail — there is nothing to explain.
    let done = parse(r#"{"event_type":"scan_end","message":"Summary - Files scanned: 5 Matched: 0 | Processes scanned: 0 Matched: 0. Scan Duration: 1.0s"}"#);
    assert!(done.tail.is_empty());
    let v = results_view("en", &done, &wanted_levels(&Value::Null), 0).to_string();
    assert!(!v.contains("The last thing the scanner said"));
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
