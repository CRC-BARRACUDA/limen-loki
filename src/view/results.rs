//! What a finished scan looks like: the findings, and one of them in full.

use crate::*;

/// The findings, at the level of detail that was asked for.
///
/// Basic answers the only question a basic scan asked — was anything found —
/// and shows what. Advanced adds what the scanner actually did: how much it
/// looked at, how long it took, and where the report is.
pub(crate) fn results_view(lang: &str, r: &Report, levels: &[String], page: usize) -> Value {
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
    // Three different answers, and only one of them is "clean".
    //
    // Loki writes a summary when it finishes. No summary means it did not: it
    // was killed, it crashed, or it never got as far as scanning. That is not a
    // clean machine, and it used to be reported as one — a missing summary was
    // read as "something was examined" and fell through to the good news.
    match r.stats.as_ref().map(|s| s.files + s.procs) {
        None => {
            w.push(label(t("results.no_summary")).heading());
            w.push(label(t("results.no_summary_why")).weak());
            // Whatever it managed to say before it stopped. Usually the reason.
            if !r.tail.is_empty() {
                w.push(separator());
                w.push(label(t("results.last_output")).weak());
                for l in &r.tail {
                    w.push(label(l.clone()).mono());
                }
            }
        }
        // It finished, and looked at nothing.
        Some(0) if total == 0 => {
            w.push(label(t("results.nothing_scanned")).heading());
            w.push(label(t("results.nothing_scanned_why")).weak());
        }
        _ => {
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
    }

    // Stopping an elevated scan does not stop it — the kernel will not let an
    // unprivileged process signal a root one. Saying so beats a screen that
    // looks like it ended.
    if r.still_running {
        w.push(label(t("scan.still_running")).strong());
    }

    // Ended early because it was asked to. Without this the screen shows a
    // partial result with nothing to say why it is partial.
    if r.stopped && !r.still_running {
        w.push(label(t("results.stopped")).strong());
    }

    // A scan that could not read everything is not a scan that found nothing.
    if r.unelevated {
        w.push(label(t("results.unelevated")).strong());
    }

    // An autostart scan counts entries, not files: saying "40 files scanned"
    // for 20 entries would be true and useless.
    if let Some((checked, no_binary)) = r.autoruns {
        w.push(label(t("results.autoruns_line").replace("{n}", &checked.to_string())).weak());
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
            rows.push(vec![
                t("results.files"),
                of_which(st.files, st.files_matched),
            ]);
            rows.push(vec![
                t("results.procs"),
                of_which(st.procs, st.procs_matched),
            ]);
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
        // Opened here, in the report's own tab: a finding is a step further
        // into the report, and the detail screen's Back button is the way out
        // of it. Its own tab per finding would be a tab per click.
        w.push(
            table(cols, rows)
                .row_ids(ids)
                .on_activate_here("scan.ioc", "detail"),
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

    window(t("results.tab_title"), w)
}

/// One finding in full: what matched, where, and why.
pub(crate) fn detail_view(lang: &str, e: &Event) -> Value {
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
        (
            t("detail.time"),
            str_of(&e.raw, "timestamp").map(|s| pretty_time(&s)),
        ),
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
    w.push(
        label(serde_json::to_string_pretty(&e.raw).unwrap_or_else(|_| e.raw.to_string())).mono(),
    );
    w.push(separator());
    w.push(button(t("detail.back"), "scan.ioc", "filter"));
    window(t("detail.matched"), w)
}
