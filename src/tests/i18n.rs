//! Both languages say the same things, and neither leaks the other.

use super::*;

#[test]
fn ukrainian_covers_every_english_key() {
    let en = catalog_keys(include_str!("../../resources/locales/en.toml"));
    let uk = catalog_keys(include_str!("../../resources/locales/uk.toml"));
    let missing: Vec<&String> = en.iter().filter(|k| !uk.contains(k)).collect();
    assert!(missing.is_empty(), "Ukrainian is missing: {missing:?}");
}

/// A key that resolves to itself is in no catalog at all — the fallback
/// chain is lang -> en -> the key, so that is how a typo surfaces. Matched
/// exactly: prose can contain "report." simply by ending a sentence.
#[test]
fn no_rendered_key_falls_through_to_itself() {
    let keys = catalog_keys(include_str!("../../resources/locales/en.toml"));
    for lang in ["en", "uk"] {
        for v in [
            install_view(lang, None),
            installing_view(lang, 1),
            main_view(lang, &default_settings(), 1, Mode::Files, true, false, None),
            settings_modal(lang, &default_settings(), Mode::Files),
            signatures_modal(
                lang,
                &[("yara".into(), "r.yar".into())],
                Some((5069, "2026-08-02".into())),
                None,
            ),
            scanning_view(lang, 1, 0, false, None),
        ] {
            let s = v.to_string();
            for k in &keys {
                assert!(
                    !s.contains(&format!(":\"{k}\"")),
                    "{lang}: key rendered instead of its translation: {k}"
                );
            }
        }
    }
}

/// Rendering in Ukrainian must not leave English prose behind — a hardcoded
/// literal is not a key, so the leak test above cannot catch it.
#[test]
fn the_ukrainian_views_carry_no_english_prose() {
    const ENGLISH: [&str; 12] = [
        "Version",
        "Platform",
        "Download",
        "verified against",
        "Install Loki",
        "Scan target",
        "Threads",
        "process memory",
        "Configure scan",
        "Signatures",
        "every file",
        "Back to settings",
    ];
    for v in [
        install_view("uk", None),
        installing_view("uk", 1),
        main_view("uk", &default_settings(), 1, Mode::Files, true, false, None),
        settings_modal("uk", &default_settings(), Mode::Files),
        signatures_modal(
            "uk",
            &[("hashes".into(), "h.txt".into())],
            Some((5069, "2026-08-02".into())),
            None,
        ),
        signature_help_modal("uk", "c2"),
        signature_help_modal("uk", "yara"),
        scanning_view("uk", 0, 0, false, None),
    ] {
        let s = v.to_string();
        for word in ENGLISH {
            assert!(
                !s.contains(word),
                "English left in a Ukrainian view: {word:?}"
            );
        }
    }
}
