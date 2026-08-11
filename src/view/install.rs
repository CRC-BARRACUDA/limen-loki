//! The install screens.

use crate::*;

/// Offered when the scanner is not installed.
pub(crate) fn install_view(lang: &str, err: Option<&str>) -> Value {
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
pub(crate) fn installing_view(lang: &str, done: usize) -> Value {
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
