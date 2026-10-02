//! Resolves the copied verified-image attachment to its retained store bundle.
//!
//! The image owns the fixed attachment and toplevel pointer. The attachment is
//! a copy of the producer's symlink members, not a separate evaluator root.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};

/// Checks the image attachment before selecting its original immutable bundle.
///
/// The caller must establish image integrity and register the retained store
/// before resolving these fixed image-owned pointers.
///
/// # Errors
/// Returns an error for unresolved or non-store pointers, invalid member aliases,
/// an oversized or empty bundle, or any difference in the copied member set.
pub(super) fn retained_bundle(image_bundle: &Path, toplevel: &Path) -> Result<PathBuf> {
    let toplevel = fs::canonicalize(toplevel).context("resolving the image toplevel")?;
    crate::deployment::nix::store_root_and_suffix(&toplevel)?;
    let original = fs::canonicalize(toplevel.join("host-deployment"))
        .context("resolving the retained host deployment")?;
    crate::deployment::nix::store_root_and_suffix(&original)?;
    verify_member_aliases(image_bundle, &original)?;
    Ok(original)
}

fn verify_member_aliases(image_bundle: &Path, original: &Path) -> Result<()> {
    let original_members = member_aliases(original)?;
    let image_members = member_aliases(image_bundle)?;
    ensure!(
        original_members == image_members,
        "verified-image host attachment differs from its retained deployment"
    );
    Ok(())
}

fn member_aliases(directory: &Path) -> Result<BTreeMap<std::ffi::OsString, PathBuf>> {
    let mut members = BTreeMap::new();
    for entry in fs::read_dir(directory).context("reading image deployment members")? {
        let entry = entry?;
        ensure!(members.len() < 32, "image deployment has too many members");
        ensure!(
            entry.file_type()?.is_symlink(),
            "image deployment member must preserve its immutable alias"
        );
        let target = fs::read_link(entry.path())?;
        crate::deployment::nix::store_root_and_suffix(&target)?;
        members.insert(entry.file_name(), target);
    }
    ensure!(!members.is_empty(), "image deployment has no members");
    Ok(members)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn copied_producer_aliases_require_exact_member_identity() -> Result<()> {
        let scratch = tempfile::tempdir()?;
        let original = scratch.path().join("original");
        let image = scratch.path().join("image");
        fs::create_dir(&original)?;
        fs::create_dir(&image)?;
        let identity = "/nix/store/00000000000000000000000000000000-document";
        for member in [
            "admission.json",
            "admission-sha256",
            "evaluation.json",
            "packages.json",
            "transaction.json",
        ] {
            let target = Path::new(identity).join(member);
            symlink(&target, original.join(member))?;
            symlink(&target, image.join(member))?;
        }
        verify_member_aliases(&image, &original)?;

        fs::remove_file(image.join("admission.json"))?;
        symlink(format!("{identity}/other"), image.join("admission.json"))?;
        assert!(verify_member_aliases(&image, &original).is_err());
        fs::remove_file(image.join("admission.json"))?;
        symlink(
            format!("{identity}/admission.json"),
            image.join("admission.json"),
        )?;

        symlink(format!("{identity}/extra"), image.join("extra"))?;
        assert!(verify_member_aliases(&image, &original).is_err());
        fs::remove_file(image.join("extra"))?;
        fs::remove_file(image.join("evaluation.json"))?;
        assert!(verify_member_aliases(&image, &original).is_err());
        fs::write(image.join("evaluation.json"), b"copied bytes")?;
        assert!(verify_member_aliases(&image, &original).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires an actual source-built producer bundle"]
    fn actual_producer_copy_resolves_through_retained_toplevel() -> Result<()> {
        let original = PathBuf::from(
            std::env::var_os("AOS_BOOT_IMAGE_HOST_BUNDLE")
                .context("actual source-built bundle is required")?,
        );
        let scratch = tempfile::tempdir()?;
        let image = scratch.path().join("host");
        let toplevel = scratch.path().join("toplevel");
        fs::create_dir(&image)?;
        // The actual toplevel is already a registered store object; its alias
        // retains the original bundle independently of the copied attachment.
        symlink(
            std::env::var_os("AOS_BOOT_IMAGE_TOPLEVEL")
                .context("actual source-built toplevel is required")?,
            &toplevel,
        )?;
        for entry in fs::read_dir(&original)? {
            let entry = entry?;
            symlink(fs::read_link(entry.path())?, image.join(entry.file_name()))?;
        }
        assert_eq!(
            retained_bundle(&image, &toplevel)?,
            fs::canonicalize(&original)?
        );
        fs::remove_file(image.join("admission-sha256"))?;
        symlink(
            original.join("admission.json"),
            image.join("admission-sha256"),
        )?;
        assert!(retained_bundle(&image, &toplevel).is_err());
        Ok(())
    }
}
