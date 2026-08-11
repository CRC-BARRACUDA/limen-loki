//! What a scan looks like while it is running, or waiting to be allowed to.

use crate::*;

/// Shown while the scanner runs; re-invokes itself to poll.
///
/// Unpacking comes first and can take a while on a folder full of archives, so
/// it says which of the two it is doing rather than showing one unchanging
/// "Scanning…" for the whole run.
pub(crate) fn scanning_view(
    lang: &str,
    lines: usize,
    hits: usize,
    stopping: bool,
    output: Option<&[String]>,
) -> Value {
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
    let mut w = vec![
        label(t("scan.running")).strong(),
        step(t("scan.working"), "loading"),
        label(
            t("scan.progress")
                .replace("{lines}", &lines.to_string())
                .replace("{hits}", &hits.to_string()),
        )
        .weak(),
        separator(),
        row(vec![
            button(t("scan.stop"), "scan.ioc", "stop").danger(),
            button(
                t(if output.is_some() {
                    "scan.hide_output"
                } else {
                    "scan.show_output"
                }),
                "scan.ioc",
                "toggle_output",
            ),
        ]),
    ];
    if let Some(lines) = output {
        w.push(separator());
        if lines.is_empty() {
            w.push(label(t("scan.no_output_yet")).weak());
        }
        for l in lines {
            w.push(label(l.clone()).mono());
        }
    }
    window_auto(t("title"), w, "scan.ioc", "s_poll", json!({}))
}

/// Shown while the operating system is asking the user for privileges.
///
/// A pop-up rather than a line on the tab: an authorization prompt is a question
/// waiting to be answered, and nothing else on the screen can proceed until it
/// is. It polls itself, so it leaves as soon as the prompt does.
pub(crate) fn authorizing_modal(lang: &str) -> Value {
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

/// What to say when an elevated scan never ran at all: the reason on the screen,
/// and the shorter one for the corner.
///
/// Two of them, because they are read in different places. The screen explains
/// what can be done about it and has the room to; the alert is what reaches a
/// user who put the password prompt aside and went back to something else, so it
/// says only that the scan did not start.
pub(crate) fn auth_keys(done: &limen_sdk_rust::Elevated) -> (&'static str, &'static str) {
    if done.refused() {
        ("scan.auth_refused", "notice.auth_refused")
    } else if done.unavailable() {
        ("scan.no_elevation", "notice.no_elevation")
    } else {
        ("scan.auth_failed", "notice.auth_failed")
    }
}

/// Which levels the user asked to see, defaulting to the ones worth opening on.
pub(crate) fn wanted_levels(params: &Value) -> Vec<String> {
    match params.get("levels").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => s.split(',').map(str::to_string).collect(),
        _ => DEFAULT_LEVELS.iter().map(|s| s.to_string()).collect(),
    }
}
