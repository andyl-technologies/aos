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
    let metadata = fs::symlink_metadata(binding)
        .with_context(|| format!("inspecting configuration binding {}", binding.display()))?;
    ensure!(
        metadata.is_file() && metadata.len() <= 128,
        "configuration binding is not a bounded immutable file"
    );
    let effect = fs::read_to_string(binding)
        .with_context(|| format!("reading configuration binding {}", binding.display()))?;
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
        .spawn()
        .with_context(|| {
            format!(
                "reading committed configuration result for generation {generation}, effect {effect}, using {}",
                runtime.display()
            )
        })?;
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
    validate_beneath(&lower, &lower.receipt_effect, tools, root).with_context(|| {
        format!(
            "validating committed configuration lower {} beneath {}",
            lower.directory,
            root.display()
        )
    })?;

    fs::create_dir_all(destination)?;
    let image = root.join(Path::new(&lower.image).strip_prefix("/")?);
    let status = Command::new(mount)
        .env_clear()
        .args(["-t", "erofs", "-o", "ro,nodev,nosuid"])
        .arg(&image)
        .arg(destination)
        .status()
        .with_context(|| {
            format!(
                "mounting configuration image {} at {} using {}",
                image.display(),
                destination.display(),
                mount.display()
            )
        })?;
    ensure!(
        status.success(),
        "mounting the native configuration lower failed: {status}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn nonzero_generation(root: &Path) -> anyhow::Error {
        mount_generation(
            root,
            &root.join("var/lib/profiles/system"),
            8,
            &root.join("usr/lib/aos/configuration-lower-effect"),
            &root.join("run/etc/config-8/etc"),
            &root.join("absent-runtime"),
            &root.join("absent-mount"),
            &Tools {
                mkfs: root.join("absent-mkfs"),
                fsck: root.join("absent-fsck"),
            },
        )
        .unwrap_err()
    }

    #[test]
    fn nonzero_generation_requires_the_image_binding_before_any_mutation() {
        let root = tempfile::tempdir().unwrap();
        let binding = root.path().join("usr/lib/aos/configuration-lower-effect");

        let error = format!("{:#}", nonzero_generation(root.path()));

        assert!(error.contains(&format!(
            "inspecting configuration binding {}",
            binding.display()
        )));
        assert!(!root.path().join("run").exists());
        assert!(!root.path().join("var").exists());
    }

    #[test]
    fn regular_canonical_binding_is_consumed_for_the_selected_generation() {
        let root = tempfile::tempdir().unwrap();
        let binding = root.path().join("usr/lib/aos/configuration-lower-effect");
        fs::create_dir_all(binding.parent().unwrap()).unwrap();
        let effect = "a".repeat(64);
        fs::write(&binding, format!("{effect}\n")).unwrap();

        // An absent runtime stops at the process boundary without fabricating
        // a committed journal or lower result. The error binds the exact input.
        let error = format!("{:#}", nonzero_generation(root.path()));

        assert!(error.contains(&format!("generation 8, effect {effect}")));
        assert!(error.contains(&root.path().join("absent-runtime").display().to_string()));
        assert_eq!(fs::read_to_string(binding).unwrap(), format!("{effect}\n"));
        assert!(!root.path().join("run").exists());
    }

    #[test]
    fn malformed_and_symlink_bindings_are_refused_before_runtime_lookup() {
        let root = tempfile::tempdir().unwrap();
        let binding = root.path().join("usr/lib/aos/configuration-lower-effect");
        fs::create_dir_all(binding.parent().unwrap()).unwrap();
        fs::write(&binding, "A".repeat(64)).unwrap();

        let malformed = nonzero_generation(root.path()).to_string();
        assert!(malformed.contains("not a canonical effect identity"));

        fs::remove_file(&binding).unwrap();
        let target = root.path().join("foreign-binding");
        fs::write(&target, "a".repeat(64)).unwrap();
        symlink(&target, &binding).unwrap();

        let substituted = nonzero_generation(root.path()).to_string();
        assert!(substituted.contains("not a bounded immutable file"));
        assert_eq!(fs::read_to_string(target).unwrap(), "a".repeat(64));
        assert!(!root.path().join("run").exists());
    }
}
