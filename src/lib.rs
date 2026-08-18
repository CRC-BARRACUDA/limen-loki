//! Runs [Loki-RS](https://github.com/Neo23x0/Loki-RS) from inside Limen and
//! reads what it finds.
//!
//! Loki-RS writes one JSON object per line (`--jsonl <file>`), each a `LogEvent`:
//! a scan boundary, a file or process match, or a plain log line. This module
//! installs the scanner on first use, runs it, and turns that stream into a
//! verdict, a findings table ordered by score, and a detail view carrying the
//! rules that matched and the strings that triggered them.
//!
//! The scanner is not vendored. It is fetched from its own release into `tools/`
//! inside this module, so removing the module removes it, and updating the
//! module re-fetches whatever version that module expects.
//!
//! ```text
//!   handler   what a call does, and what is remembered between calls
//!   install   fetching the scanner and putting it where we can run it
//!   report    reading what it wrote
//!   scan      what to run, on what, and watching it go
//!   settings  the scan's own settings
//!   signatures  the rules and indicators it reads
//!   view      everything the module draws
//! ```

mod handler;
mod install;
mod report;
mod scan;
mod settings;
mod signatures;
mod view;

#[cfg(test)]
mod tests;

// This was one file, and reads best as one: each part takes `use crate::*` and
// finds everything the way it did before the split, rather than every file
// carrying a list of its neighbours that has to be maintained by hand.
pub(crate) use handler::*;
pub(crate) use install::*;
pub(crate) use report::*;
pub(crate) use scan::*;
pub(crate) use settings::*;
pub(crate) use signatures::*;
pub(crate) use view::*;

pub(crate) use std::collections::BTreeMap;
pub(crate) use std::path::{Path, PathBuf};

pub(crate) use limen_sdk_rust::ui::{
    auto_in_tab, button, checkbox, file, label, notice, row, select, separator, step, table, text,
    window, window_auto, window_modal_sized, Widget,
};
pub(crate) use limen_sdk_rust::{json, rpc, Catalog, Handler, Host, RpcError, Value};

use limen_sdk_rust::export_module;

/// Severity, as Loki-RS scores it. `ALERT` at 80, `WARNING` at 60, `NOTICE` at
/// 40 by default, though the thresholds are configurable at scan time — so the
/// level is read from the record rather than recomputed from the score.
const LEVELS: [&str; 6] = ["ALERT", "WARNING", "NOTICE", "INFO", "ERROR", "DEBUG"];

/// Levels shown unless the user asks for more. A full scan logs thousands of
/// `INFO` lines; opening on those would bury the handful that matter.
const DEFAULT_LEVELS: [&str; 3] = ["ALERT", "WARNING", "ERROR"];

const PAGE: usize = 60;

/// The Loki-RS release this module is built and tested against.
///
/// Pinned rather than resolved to `latest`: a scan report's shape is this
/// module's input, and a scanner that changed underneath it could quietly stop
/// matching. Raising this is a deliberate edit, and because `tools/` is wiped
/// when the module updates, a new module version fetches its own scanner.
const LOKI_VERSION: &str = "2.12.0";

/// Where the release lives. Asset names are `loki-<os>-<arch>-v<ver>.<ext>`,
/// each with a `.sha256` sidecar beside it.
const LOKI_RELEASES: &str = "https://github.com/Neo23x0/Loki-RS/releases/download";

/// This module's own translations (its `locales/*.toml`, embedded). English is
/// the default/fallback; `host.locale()` selects the active one at render time.
fn catalog() -> &'static Catalog {
    static C: std::sync::OnceLock<Catalog> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        Catalog::new(&[
            ("en", include_str!("../resources/locales/en.toml")),
            ("uk", include_str!("../resources/locales/uk.toml")),
        ])
    })
}

/// The install steps, as keys — resolved against the catalog at render time.
const STEP_KEYS: [&str; 4] = [
    "steps.platform",
    "steps.download",
    "steps.verify",
    "steps.unpack",
];

export_module!(Loki);
