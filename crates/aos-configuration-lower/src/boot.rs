//! Mounts the checked configuration result of an explicitly bound generation.
//!
//! The package runtime resolves publication sequence/content through its native
//! journal. This reader interprets only this package's operation result and
//! verifies its immutable lower receipt before invoking the AOS mount tool.

use std::fs;
use std::io::Read as _;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, ensure};

use crate::lower::{Tools, validate_beneath};
use crate::model::Lower;

/// Mounts a native profile generation's verified lower into the boot namespace.
///
/// The binding is image-owned and contains the derived top-level effect ID.
/// An uninitialized native profile uses the image's existing configuration base;
/// an initialized profile with missing or inconsistent results fails closed.
///
/// # Errors
/// Returns an error for a malformed binding, uncommitted generation, mismatched
/// lower checksums, invalid image, or a failed mount operation.
#[allow(clippy::too_many_arguments)]
pub fn mount_generation(
    root: &Path,
    profile: &Path,
    generation: u32,
    binding: &Path,
    destination: &Path,
    runtime: &Path,
    mount: &Path,
    tools: &Tools,
) -> Result<()> {
    if generation == 0 {
        // Zero identifies the verified-image bootstrap before any publication.
        // An interrupted first activation may have journals, but it cannot have
        // a published generation that this reader silently skips.
        ensure!(
            fs::symlink_metadata(profile.join("current"))
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "bootstrap generation cannot replace a published native profile"
        );
        fs::create_dir_all(destination)?;
        return Ok(());
    }
    let metadata = fs::symlink_metadata(binding)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 128,
        "configuration binding is not a bounded immutable file"
    );
    let effect = fs::read_to_string(binding)?;
    let effect = effect.trim_end_matches('\n');
    ensure!(
        effect.len() == 64
            && effect
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "configuration binding is not a canonical effect identity"
    );

    let mut child = Command::new(runtime)
        .env_clear()
        .arg("deployment-result")
        .arg("--committed-during-recovery")
        .arg("--profile")
        .arg(profile)
        .arg("--generation")
        .arg(generation.to_string())
        .arg("--effect")
        .arg(effect)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .context("capturing committed lower result")?
        .take(16 * 1024 + 1)
        .read_to_end(&mut output)?;
    let status = child.wait()?;
    ensure!(
        status.success() && output.len() <= 16 * 1024,
        "native generation result inspection failed"
    );
    let lower: Lower =
        serde_json::from_slice(&output).context("decoding checked configuration lower result")?;
    validate_beneath(&lower, &lower.receipt_effect, tools, root)?;

    fs::create_dir_all(destination)?;
    let image = root.join(Path::new(&lower.image).strip_prefix("/")?);
    let status = Command::new(mount)
        .env_clear()
        .args(["-t", "erofs", "-o", "ro,nodev,nosuid"])
        .arg(image)
        .arg(destination)
        .status()?;
    ensure!(
        status.success(),
        "mounting the native configuration lower failed: {status}"
    );
    Ok(())
}
