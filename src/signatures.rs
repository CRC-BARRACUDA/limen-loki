//! The rules and indicators a scan reads — the bundled set, and the files
//! the user brings.

use crate::*;

/// The IOC files Loki reads, by the name it expects on disk.
///
/// These paths are fixed in the scanner — it looks for `iocs/hash-iocs.txt` and
/// the rest by name — so a file the user adds cannot simply be dropped in beside
/// them under its own name. It is filed by kind and merged into these at scan
/// time.
/// `keywords.txt` ships in the signatures directory but Loki 2.12.0 never loads
/// it — a full debug run mentions keywords nowhere. It is deliberately absent
/// here: offering a kind the scanner ignores would take someone's indicators and
/// quietly do nothing with them.
pub(crate) const IOC_KINDS: [(&str, &str); 3] = [
    ("hashes", "hash-iocs.txt"),
    ("filenames", "filename-iocs.txt"),
    ("c2", "c2-iocs.txt"),
];

/// Where a user-supplied signature is kept: `tools/custom/yara/` for rules,
/// `tools/custom/iocs/<kind>/` for indicators.
fn custom_dir(host: &Host, kind: &str) -> Option<PathBuf> {
    let root = tools_root(host)?.join("custom");
    Some(match kind {
        "yara" => root.join("yara"),
        k => root.join("iocs").join(k),
    })
}

/// What the bundled YARA rule set is, as `(rule count, build date)`.
///
/// Read from the file rather than remembered, because `loki-util update`
/// replaces it behind our back — and because a rule set's age is the thing worth
/// showing: the set shipped in a release is as old as the release.
pub(crate) fn bundled_rules(host: &Host) -> Option<(usize, String)> {
    let text = std::fs::read_to_string(
        install_root(host)?
            .join("signatures")
            .join("yara")
            .join("yara-rules-core.yar"),
    )
    .ok()?;
    let count = text.lines().filter(|l| l.starts_with("rule ")).count();
    // YARA-Forge stamps the package header with the date it was generated.
    let date = text
        .lines()
        .take(40)
        .find_map(|l| l.split("Creation Date:").nth(1))
        .map(|d| d.trim().to_string())
        .unwrap_or_default();
    Some((count, date))
}

/// Refresh the bundled rule set from YARA-Forge.
pub(crate) fn update_bundled_rules(host: &Host) -> Result<(), String> {
    use limen_proto::NoConsole;
    let root = install_root(host).ok_or_else(|| "no module directory".to_string())?;
    let util = root.join(if cfg!(windows) {
        "loki-util.exe"
    } else {
        "loki-util"
    });
    if !util.exists() {
        return Err("loki-util is not installed".into());
    }
    let out = std::process::Command::new(&util)
        .arg("update")
        // It writes into `./signatures`, so it has to run from the scanner's own
        // directory just as the scanner does.
        .current_dir(&root)
        .no_console()
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let last = err.lines().last().unwrap_or("").trim();
        return Err(if last.is_empty() {
            "the updater exited with an error".into()
        } else {
            last.to_string()
        });
    }
    Ok(())
}

/// Everything the user has added, as `(kind, file name)`.
pub(crate) fn list_custom(host: &Host) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for kind in std::iter::once("yara").chain(IOC_KINDS.iter().map(|(k, _)| *k)) {
        let Some(dir) = custom_dir(host, kind) else {
            continue;
        };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        out.extend(names.into_iter().map(|n| (kind.to_string(), n)));
    }
    out
}

/// Copy a signature file the user picked into the module's own store.
///
/// Copied rather than remembered by path: a rule referenced where it happens to
/// sit today would silently stop being scanned the moment it is moved, and a
/// scan quietly missing a rule is worse than one that never had it.
pub(crate) fn add_custom(host: &Host, kind: &str, src: &str) -> Result<(), String> {
    let src = Path::new(src.trim());
    if !src.is_file() {
        return Err("not a file".into());
    }
    let name = src
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| "no file name".to_string())?;
    let dir = custom_dir(host, kind).ok_or_else(|| "no module directory".to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::copy(src, dir.join(name)).map_err(|e| e.to_string())?;
    Ok(())
}

pub(crate) fn remove_custom(host: &Host, kind: &str, name: &str) {
    // Only ever a bare file name from our own listing — a path from elsewhere
    // could otherwise walk out of the store and delete something else.
    if name.contains(['/', '\\']) || name.contains("..") {
        return;
    }
    if let Some(dir) = custom_dir(host, kind) {
        let _ = std::fs::remove_file(dir.join(name));
    }
}

/// Put the user's signatures where the scanner will look, just before a scan.
///
/// The scanner's own `signatures/` directory is rebuilt from the store each
/// time rather than written to once: a reinstall replaces that directory
/// wholesale, and settings that survive a reinstall but signatures that quietly
/// do not would be the worst of both.
pub(crate) fn sync_signatures(host: &Host) {
    let Some(root) = install_root(host) else {
        return;
    };
    let sigs = root.join("signatures");
    if !sigs.is_dir() {
        return;
    }

    // Rules: each is its own file, so they are copied in under a marked name and
    // any from a previous scan are cleared first.
    let yara = sigs.join("yara");
    if let Ok(entries) = std::fs::read_dir(&yara) {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().starts_with("limen-custom-") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    if let Some(dir) = custom_dir(host, "yara") {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let _ = std::fs::copy(e.path(), yara.join(format!("limen-custom-{name}")));
            }
        }
    }

    // Indicators: the scanner reads four fixed files, so everything of a kind is
    // concatenated into the one file it expects.
    for (kind, filename) in IOC_KINDS {
        let mut merged = String::from("# Written by Limen from the module's signature store.\n");
        if let Some(dir) = custom_dir(host, kind) {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                let mut files: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
                files.sort();
                for f in files {
                    if let Ok(text) = std::fs::read_to_string(&f) {
                        merged.push_str(&text);
                        if !text.ends_with('\n') {
                            merged.push('\n');
                        }
                    }
                }
            }
        }
        let _ = std::fs::write(sigs.join("iocs").join(filename), merged);
    }
}

/// What a signature file actually contains, for the row that was opened.
///
/// Read on demand rather than kept: the bundled set is 7 MB and its contents
/// change under us whenever it is updated, so the only honest number is the one
/// taken when asked.
/// What one signature file turned out to be: its id, the facts worth a row
/// each, and a sample of what is inside it.
pub(crate) struct SigInfo {
    pub(crate) id: String,
    pub(crate) facts: Vec<(String, String)>,
    pub(crate) sample: Vec<String>,
}

/// Where a listed signature actually is, by the id its row carries.
pub(crate) fn signature_path(host: &Host, id: &str) -> Option<PathBuf> {
    if id == "bundled" {
        return Some(
            install_root(host)?
                .join("signatures")
                .join("yara")
                .join("yara-rules-core.yar"),
        );
    }
    let (kind, name) = id.split_once('/')?;
    // Only ever a bare file name from our own listing — a path from elsewhere
    // could otherwise walk out of the store.
    if name.contains(['/', '\\']) || name.contains("..") {
        return None;
    }
    Some(custom_dir(host, kind)?.join(name))
}

pub(crate) fn signature_info(host: &Host, id: &str) -> Option<SigInfo> {
    let path = signature_path(host, id)?;
    let name = path.file_name()?.to_string_lossy().into_owned();
    let text = std::fs::read_to_string(&path).ok()?;
    let bytes = text.len() as u64;

    let mut facts = vec![
        ("file".into(), name),
        ("size".into(), format!("{} KB", bytes / 1024)),
        ("path".into(), path.to_string_lossy().into_owned()),
    ];
    let mut sample = Vec::new();

    let rules: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("rule "))
        .map(|r| r.split([' ', '{', ':']).next().unwrap_or(r))
        .collect();

    if rules.is_empty() {
        // An indicator file: comments and blanks are not indicators.
        let entries: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        facts.push(("indicators".into(), entries.len().to_string()));
        sample.extend(entries.iter().take(12).map(|e| e.to_string()));
    } else {
        facts.push(("rules".into(), rules.len().to_string()));
        if let Some(d) = text
            .lines()
            .take(40)
            .find_map(|l| l.split("Creation Date:").nth(1))
        {
            facts.push(("built".into(), d.trim().to_string()));
        }
        // Who the rules came from, by the prefix each set stamps on its names —
        // the useful summary of five thousand rules nobody will read.
        let mut by_source: BTreeMap<&str, usize> = BTreeMap::new();
        for r in &rules {
            let src = r.split('_').next().unwrap_or(r);
            if src
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                && src.len() > 2
            {
                *by_source.entry(src).or_insert(0) += 1;
            }
        }
        let mut top: Vec<(&&str, &usize)> = by_source.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1));
        sample.extend(top.iter().take(10).map(|(s, n)| format!("{s}  ×{n}")));
        if sample.is_empty() {
            sample.extend(rules.iter().take(12).map(|r| r.to_string()));
        }
    }
    Some(SigInfo {
        id: id.to_string(),
        facts,
        sample,
    })
}
