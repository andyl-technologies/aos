//! Owns the copied Envoy finding after its original campaign disappears.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

use super::finding_exact_vm::{bundle_fingerprints, copy_bundle, verify_command};

/// Keeps an independent copy and its exact exported file fingerprints alive.
pub(super) struct FindingBundle {
    investigator: TempDir,
    bundle: PathBuf,
    files: BTreeMap<PathBuf, [u8; 32]>,
}

impl FindingBundle {
    /// Copies an exported bundle without retaining original owner paths.
    ///
    /// # Errors
    ///
    /// Returns an error for nonregular entries, incomplete copies, or filesystem failures.
    pub(super) fn copy_from(source: &Path) -> Result<Self, Box<dyn Error>> {
        if !fs::symlink_metadata(source)?.file_type().is_dir() {
            return Err("Envoy finding source bundle is not a directory".into());
        }
        let files = bundle_fingerprints(source)?;
        if files.is_empty() {
            return Err("Envoy finding source bundle is empty".into());
        }

        let investigator = TempDir::new()?;
        let bundle = investigator.path().join("finding-bundle");
        copy_bundle(source, &bundle)?;
        let copied = Self {
            investigator,
            bundle,
            files,
        };
        copied.require_unchanged()?;
        Ok(copied)
    }

    /// Builds the existing exact verifier only after the source owner is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if source paths remain, the copy changed, or runtime configuration is missing.
    pub(super) fn verify_command(&self, source_owner: &Path) -> Result<Command, Box<dyn Error>> {
        require_source_absent(source_owner)?;
        self.require_unchanged()?;
        verify_command(&self.bundle, self.investigator.path())
    }

    /// Rejects any missing, added, nonregular, or changed copied file.
    ///
    /// # Errors
    ///
    /// Returns an error if the copied bundle differs from the original export.
    pub(super) fn require_unchanged(&self) -> Result<(), Box<dyn Error>> {
        if !fs::symlink_metadata(&self.bundle)?.file_type().is_dir() {
            return Err("Envoy finding copied bundle is not a directory".into());
        }
        if bundle_fingerprints(&self.bundle)? != self.files {
            return Err("Envoy finding copied bundle differs from its original export".into());
        }
        Ok(())
    }
}

fn require_source_absent(source_owner: &Path) -> Result<(), Box<dyn Error>> {
    // symlink_metadata also refuses a dangling alias at the old owner path.
    match fs::symlink_metadata(source_owner) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("Envoy finding source owner remains available".into()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn source_bundle(owner: &Path) -> Result<PathBuf, Box<dyn Error>> {
        let bundle = owner.join("exported-finding");
        fs::create_dir_all(bundle.join("archive/objects"))?;
        fs::write(bundle.join("manifest"), b"finite handoff fixture manifest")?;
        fs::write(bundle.join("ledger"), b"finite handoff fixture ledger")?;
        fs::write(bundle.join("archive/objects/retained"), b"retained object")?;
        Ok(bundle)
    }

    #[test]
    fn copied_bundle_survives_owner_removal_with_exact_original_bytes() -> Result<(), Box<dyn Error>>
    {
        let owner = TempDir::new()?;
        let source = source_bundle(owner.path())?;
        let original = bundle_fingerprints(&source)?;
        let copied = FindingBundle::copy_from(&source)?;

        let error = copied.verify_command(owner.path()).unwrap_err();
        assert!(error.to_string().contains("source owner remains available"));
        fs::remove_dir_all(owner.path())?;

        require_source_absent(owner.path())?;
        copied.require_unchanged()?;
        assert_eq!(bundle_fingerprints(&copied.bundle)?, original);
        assert_eq!(
            fs::read(copied.bundle.join("archive/objects/retained"))?,
            b"retained object"
        );
        Ok(())
    }

    #[test]
    fn missing_objects_partial_copies_and_changed_bytes_refuse() -> Result<(), Box<dyn Error>> {
        let owner = TempDir::new()?;
        let source = source_bundle(owner.path())?;
        let copied = FindingBundle::copy_from(&source)?;

        fs::remove_file(copied.bundle.join("archive/objects/retained"))?;
        assert!(copied.require_unchanged().is_err());
        fs::write(
            copied.bundle.join("archive/objects/retained"),
            b"retained object",
        )?;
        copied.require_unchanged()?;

        fs::remove_file(copied.bundle.join("ledger"))?;
        assert!(copied.require_unchanged().is_err());
        fs::write(copied.bundle.join("ledger"), b"altered ledger")?;
        assert!(copied.require_unchanged().is_err());
        fs::write(
            copied.bundle.join("ledger"),
            b"finite handoff fixture ledger",
        )?;
        copied.require_unchanged()?;

        fs::write(copied.bundle.join("extra"), b"unexpected file")?;
        assert!(copied.require_unchanged().is_err());
        Ok(())
    }

    #[test]
    fn symlinked_source_copy_and_old_owner_alias_refuse() -> Result<(), Box<dyn Error>> {
        let owner = TempDir::new()?;
        let source = source_bundle(owner.path())?;
        let copied = FindingBundle::copy_from(&source)?;
        let source_alias = owner.path().join("source-alias");
        symlink(&source, &source_alias)?;
        assert!(FindingBundle::copy_from(&source_alias).is_err());
        symlink(source.join("ledger"), source.join("alias"))?;
        assert!(FindingBundle::copy_from(&source).is_err());
        fs::remove_file(source.join("alias"))?;

        fs::remove_file(copied.bundle.join("ledger"))?;
        symlink(source.join("ledger"), copied.bundle.join("ledger"))?;
        assert!(copied.require_unchanged().is_err());

        let original_owner = owner.path().join("old-owner");
        symlink(owner.path().join("missing"), &original_owner)?;
        assert!(require_source_absent(&original_owner).is_err());
        Ok(())
    }
}
