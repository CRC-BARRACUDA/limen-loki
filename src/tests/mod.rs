//! What the module is expected to do, in the language of what it is for.
//!
//! A cdylib has no rlib to link an integration test against, so these live in
//! the crate: one file per part, and the fixtures they share here.

use crate::*;

mod i18n;
mod install;
mod report;
mod scan;
mod view;

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
