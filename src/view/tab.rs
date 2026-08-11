//! The tab, and the settings pop-up behind it.

use crate::*;

/// The tab: one question — what should be scanned — and the button that answers
/// it.
///
/// Everything else is behind Configure. A scan target is what changes every
/// time; thresholds and thread counts are set once and then wanted out of the
/// way, so they live in a pop-up rather than competing with the field that
/// actually needs filling in.
pub(crate) fn main_view(
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
pub(crate) fn settings_summary(lang: &str, cfg: &Value, custom: usize, mode: Mode) -> String {
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
pub(crate) fn settings_modal(lang: &str, cfg: &Value, mode: Mode) -> Value {
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
        w.push(boxed(
            checkbox("all_files", t("scan.all_files")),
            on("all_files"),
        ));
        w.push(boxed(
            checkbox("archives", t("scan.archives")),
            on("archives"),
        ));
        w.push(separator());
    }
    w.extend(vec![
        row(vec![
            select(
                "threads",
                choices("threads", &["all-2", "all-1", "all", "1"]),
            )
            .label(t("scan.threads")),
            select("cpu", choices("cpu", &["100", "80", "60", "40"])).label(t("scan.cpu")),
        ]),
        separator(),
        label(t("scan.section_thresholds")).weak(),
        row(vec![
            text("alert").label(t("scan.alert")).default(txt("alert")),
            text("warning")
                .label(t("scan.warning"))
                .default(txt("warning")),
            text("notice")
                .label(t("scan.notice"))
                .default(txt("notice")),
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
