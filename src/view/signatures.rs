//! The signature screens: the list, one file's details, and the help.

use crate::*;

/// The signature pop-up, opened from the settings one — a pop-up raising a
/// pop-up, with the settings still behind it to go back to.
pub(crate) fn signatures_modal(
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
    add_row.push(button(
        t(if bundled.is_some() {
            "sig.core_update"
        } else {
            "sig.core_install"
        }),
        "scan.ioc",
        "sig_core",
    ));

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
                id.split_once('/')
                    .map(|(_, n)| n.to_string())
                    .unwrap_or_default(),
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

/// The detail step for one signature file.
///
/// A step of the same window when opened from the list, and a plain view when
/// opened in a tab — a tab has no pop-up to be a step of, and no way back to a
/// list it is not showing.
pub(crate) fn signature_info_modal(lang: &str, info: Option<SigInfo>, in_tab: bool) -> Value {
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
pub(crate) fn core_updating_modal(lang: &str) -> Value {
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

/// What a signature file of *this* kind has to look like.
///
/// One pop-up per kind rather than one table for all four: the rules differ in
/// ways that matter — a bare hash is dropped but a bare C2 address is kept, and
/// C2 indicators do nothing at all unless process scanning is on. Everything
/// here was read off the scanner rather than its documentation, because a
/// malformed line is skipped in silence and a wrong example would cost somebody
/// a rule without ever saying so.
pub(crate) fn signature_help_modal(lang: &str, kind: &str) -> Value {
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
