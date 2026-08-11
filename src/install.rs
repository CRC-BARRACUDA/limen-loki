//! Fetching the scanner and putting it where this module can run it.

use crate::*;

/// Where this module keeps the scanner: `tools/loki-<version>/` inside its own
/// directory.
///
/// Inside the module, not beside Limen, so the tool's life is the module's life
/// — remove the module and the scanner goes with it, update the module and the
/// scanner is re-fetched at whatever version that module expects. `tools/` is
/// excluded from the module's trust digest, so filling it does not revoke the
/// module's approval.
pub(crate) fn install_root(host: &Host) -> Option<PathBuf> {
    let dir = host.module_dir()?;
    Some(
        Path::new(&dir)
            .join("tools")
            .join(format!("loki-{LOKI_VERSION}")),
    )
}

/// The scanner binary, if it is there.
pub(crate) fn loki_bin(host: &Host) -> Option<PathBuf> {
    let root = install_root(host)?;
    let name = if cfg!(windows) { "loki.exe" } else { "loki" };
    // The archive unpacks flat, but look one level down too rather than assume.
    let direct = root.join(name);
    if direct.exists() {
        return Some(direct);
    }
    std::fs::read_dir(&root)
        .ok()?
        .flatten()
        .map(|e| e.path().join(name))
        .find(|p| p.exists())
}

/// The release asset for this machine, or `None` where Loki-RS publishes none.
pub(crate) fn asset_name(os: &str, arch: &str) -> Option<String> {
    let ext = match os {
        "windows" => "zip",
        "linux" | "macos" => "tar.gz",
        _ => return None,
    };
    if !matches!(arch, "x86_64" | "aarch64") {
        return None;
    }
    Some(format!("loki-{os}-{arch}-v{LOKI_VERSION}.{ext}"))
}

/// Fetch `url` to `dest` with curl.
///
/// curl rather than a bundled HTTP stack: a module that shells out stays small
/// and inherits the system's TLS trust. `-f` so an HTTP error is a failure
/// rather than a saved error page, `-L` to follow the release redirect.
fn fetch(url: &str, dest: &Path) -> Result<(), String> {
    use limen_proto::NoConsole;
    let out = std::process::Command::new("curl")
        .args(["-fsSL", "--max-time", "600", "-o"])
        .arg(dest)
        .arg(url)
        .no_console()
        .output()
        .map_err(|e| format!("curl could not be started: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "download failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// SHA-256 of a file, lower-case hex.
fn sha256_of(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(format!("{:x}", h.finalize()))
}

/// Unpack the release archive into `dest`.
///
/// `tar` handles both: GNU tar for `.tar.gz`, and bsdtar — which is `tar` on
/// Windows 10+ and macOS — reads zip, so there is no second code path and no
/// unzip dependency.
pub(crate) fn unpack(archive: &Path, dest: &Path) -> Result<(), String> {
    use limen_proto::NoConsole;
    std::fs::create_dir_all(dest).map_err(|e| format!("creating {}: {e}", dest.display()))?;
    let gz = archive.to_string_lossy().ends_with(".tar.gz");
    let out = std::process::Command::new("tar")
        .arg(if gz { "-xzf" } else { "-xf" })
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .no_console()
        .output()
        .map_err(|e| format!("tar could not be started: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "unpacking failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Make the unpacked binaries executable.
///
/// A tarball carries its modes, but a zip does not — and on Unix an extracted
/// file without `+x` cannot be run, which would fail later and further away.
#[cfg(unix)]
fn make_executable(root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p
                .file_name()
                .is_some_and(|n| n == "loki" || n == "loki-util")
            {
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755));
            }
        }
    }
}

#[cfg(not(unix))]
fn make_executable(_root: &Path) {}

/// One step of the install. Returns the message to show if it fails.
///
/// Each runs in its own invocation, so the UI reports progress instead of
/// freezing for the length of a 12 MB download.
pub(crate) fn run_install_step(host: &Host, lang: &str, step: usize) -> Result<(), String> {
    let t = |k: &str| catalog().tr(lang, k);
    let root = install_root(host).ok_or_else(|| t("install.no_dir"))?;
    let tools = root.parent().unwrap_or(&root).to_path_buf();
    let staging = tools.join(".download");
    let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
    let asset = asset_name(os, arch)
        .ok_or_else(|| t("install.unsupported").replace("{platform}", &format!("{os}-{arch}")))?;
    let archive = staging.join(&asset);

    match step {
        // Decide what to fetch, and start from a clean slate so a half-finished
        // earlier attempt cannot be mistaken for a good install.
        0 => {
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&staging);
            std::fs::create_dir_all(&staging).map_err(|e| format!("{}: {e}", staging.display()))?;
            Ok(())
        }
        // The archive and the checksum published beside it.
        1 => {
            let base = format!("{LOKI_RELEASES}/v{LOKI_VERSION}");
            fetch(&format!("{base}/{asset}"), &archive)?;
            fetch(
                &format!("{base}/{asset}.sha256"),
                &staging.join(format!("{asset}.sha256")),
            )
        }
        // Verify before unpacking, never after: this is a binary that will be
        // run, so a mismatch must stop the install rather than be reported once
        // the thing is already on disk and executable.
        2 => {
            let sidecar = std::fs::read_to_string(staging.join(format!("{asset}.sha256")))
                .map_err(|e| format!("reading checksum: {e}"))?;
            // `sha256sum` format: "<hash>  <filename>".
            let want = sidecar
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_lowercase();
            let got = sha256_of(&archive)?;
            if want.is_empty() || want != got {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(t("install.bad_checksum")
                    .replace("{want}", &want)
                    .replace("{got}", &got));
            }
            Ok(())
        }
        // Unpack, make it runnable, and drop the archive — keeping 12 MB of
        // tarball beside the unpacked copy helps nobody.
        3 => {
            unpack(&archive, &root)?;
            make_executable(&root);
            let _ = std::fs::remove_dir_all(&staging);
            if loki_bin(host).is_none() {
                return Err(t("install.no_binary"));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
