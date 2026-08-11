//! Scan settings: the defaults, and where the user's own are kept.

use crate::*;

/// Scan settings live here rather than on the scan screen.
///
/// The tab asks one question — what do you want scanned — and everything else
/// sits behind Configure, where it is set once and remembered. Kept as JSON
/// because that is what the form sends back and what is written to disk.
pub(crate) fn default_settings() -> Value {
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
pub(crate) fn tools_root(host: &Host) -> Option<PathBuf> {
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
pub(crate) fn load_settings(host: &Host) -> Value {
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

pub(crate) fn save_settings(host: &Host, s: &Value) {
    let Some(p) = settings_path(host) else { return };
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, serde_json::to_string_pretty(s).unwrap_or_default());
}
