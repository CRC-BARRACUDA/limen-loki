//! Reading a report: what the scanner wrote, and what it adds up to.

use super::*;

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
    assert_eq!(
        pretty_time("2026-08-03T10:02:00+00:00"),
        "2026-08-03 10:02:00"
    );
    assert_eq!(
        pretty_time("2026-08-03T10:02:00-05:00"),
        "2026-08-03 10:02:00"
    );
    assert_eq!(pretty_time("2026-08-03T10:02:00Z"), "2026-08-03 10:02:00");
    assert_eq!(pretty_time(""), "");
}
