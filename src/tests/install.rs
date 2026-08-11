//! Fetching the scanner.

use super::*;

#[test]
fn every_published_platform_resolves_to_an_asset() {
    for os in ["linux", "macos", "windows"] {
        for arch in ["x86_64", "aarch64"] {
            let a = asset_name(os, arch).expect("published by Loki-RS");
            assert!(a.starts_with(&format!("loki-{os}-{arch}-v")));
            assert!(a.ends_with(if os == "windows" { ".zip" } else { ".tar.gz" }));
        }
    }
    // ...and one that is not published says so rather than guessing a name.
    assert!(asset_name("linux", "riscv64").is_none());
    assert!(asset_name("freebsd", "x86_64").is_none());
}

#[test]
fn install_steps_run_then_stop() {
    let mid = installing_view("en", 1).to_string();
    assert!(mid.contains("\"auto\""), "must invoke the next step itself");
    // Finished: no auto, or it would loop forever.
    let end = installing_view("en", STEP_KEYS.len()).to_string();
    assert!(!end.contains("\"auto\""));
}
