//! Retains immutable image labeling inputs for native configuration lowers.
//!
//! The signed root image supplies its selected contexts as a direct EROFS
//! inode, avoiding the writable store overlay and the active `/etc` view.
//! Each generated lower binds the snapshot's SHA-256 in its ordinary input
//! receipt and keeps those exact bytes beside the image for historical checks.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use sha2::{Digest as _, Sha256};

use crate::model::Input;

const IMAGE_CONTEXTS: &str = "usr/lib/aos/selinux-file-contexts";
const SNAPSHOT: &str = "selinux-file-contexts";
const MAXIMUM_BYTES: u64 = 8 * 1024 * 1024;
const EROFS_SUPER_MAGIC: u32 = 0xe0f5_e1e2;

pub(super) struct Contexts {
    bytes: Vec<u8>,
}

impl Contexts {
    pub(super) fn capture(root: &Path) -> Result<Option<Self>> {
        let path = root.join(IMAGE_CONTEXTS);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            result => {
                result.context("inspecting immutable SELinux file-context reference")?;
            }
        }

        let file = File::from(
            rustix::fs::open(
                &path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK,
                rustix::fs::Mode::empty(),
            )
            .context("opening immutable SELinux file contexts")?,
        );
        ensure!(
            rustix::fs::fstatfs(&file)?.f_type as u32 == EROFS_SUPER_MAGIC,
            "image SELinux file contexts are not on EROFS"
        );
        Ok(Some(Self { bytes: read(file)? }))
    }

    pub(super) fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }

    pub(super) fn write(&self, directory: &Path) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(directory.join(SNAPSHOT))?;
        file.write_all(&self.bytes)?;
        file.sync_all()?;
        Ok(())
    }

    pub(super) fn configure_mkfs(&self, command: &mut std::process::Command, directory: &Path) {
        command
            .arg("--mount-point=/etc")
            .arg("--file-contexts")
            .arg(directory.join(SNAPSHOT));
    }
}

pub(super) fn bind(input: &Input, contexts: Option<&Contexts>) -> Result<Input> {
    let digest = contexts.map(Contexts::digest);
    ensure!(
        input.selinux_file_contexts_sha256.is_none()
            || input.selinux_file_contexts_sha256 == digest,
        "configuration input selects another image's SELinux file contexts"
    );

    let mut input = input.clone();
    input.selinux_file_contexts_sha256 = digest;
    Ok(input)
}

// Historical generations keep their original labeling input. New preparation
// and reuse bind the current signed image before choosing a content identity.
pub(super) fn verify_snapshot(input: &Input, directory: &Path) -> Result<()> {
    let Some(expected) = input.selinux_file_contexts_sha256 else {
        return Ok(());
    };
    let file = File::from(rustix::fs::open(
        directory.join(SNAPSHOT),
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?);
    let observed: [u8; 32] = Sha256::digest(read(file)?).into();
    ensure!(
        observed == expected,
        "retained SELinux file contexts differ"
    );
    Ok(())
}

fn read(mut file: File) -> Result<Vec<u8>> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() > 0 && metadata.len() <= MAXIMUM_BYTES,
        "SELinux file contexts are not a bounded nonempty regular file"
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAXIMUM_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "SELinux file contexts changed while reading"
    );
    Ok(bytes)
}

/// Reads a bounded SELinux context from a real configuration directory.
///
/// The directory descriptor rejects symlink substitution. The returned context
/// preserves the verified lower's actual inode label, including any MLS range.
///
/// # Errors
/// Returns an error for an inaccessible or substituted directory, unavailable
/// label, or context containing bytes that cannot form a safe mount option.
pub(super) fn root_context(path: &Path) -> Result<String> {
    let directory = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?;
    let mut bytes = [0_u8; 4096];
    let length = rustix::fs::fgetxattr(&directory, "security.selinux", &mut bytes[..])
        .context("reading configuration overlay root label")?;
    parse_root_context(&bytes[..length])
}

fn parse_root_context(bytes: &[u8]) -> Result<String> {
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    ensure!(
        !bytes.is_empty()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_:.,-".contains(byte)),
        "configuration root label contains invalid mount-option bytes"
    );
    let context = std::str::from_utf8(bytes)?;
    ensure!(
        context
            .split(':')
            .take(3)
            .filter(|part| !part.is_empty())
            .count()
            == 3,
        "configuration root label lacks a user, role, or type"
    );
    Ok(context.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    #[test]
    fn root_context_preserves_non_mls_and_category_ranges() {
        for context in [
            "system_u:object_r:etc_t",
            "system_u:object_r:etc_t:s0:c0,c3.c7",
        ] {
            assert_eq!(parse_root_context(context.as_bytes()).unwrap(), context);
            let terminated = format!("{context}\0");
            assert_eq!(parse_root_context(terminated.as_bytes()).unwrap(), context);
        }
    }

    #[test]
    fn root_context_rejects_option_injection_and_malformed_labels() {
        for bytes in [
            b"".as_slice(),
            b"system_u:object_r",
            b"system_u::etc_t",
            b"system_u:object_r:etc_t\0\0",
            b"system_u:object_r:etc_t\n",
            b"system_u:object_r:etc_t,context=other",
            b"system_u:object_r:etc_t\"",
            b"system_u:object_r:etc_t\\",
            b"system_u:object_r:\xff",
        ] {
            assert!(parse_root_context(bytes).is_err(), "{bytes:?}");
        }
    }

    fn input() -> Input {
        serde_json::from_value(serde_json::json!({
            "files": {}, "jobScripts": {}, "removedPaths": [], "baselinePaths": [],
            "ownership": {"etcTrees": {}, "files": {}, "jobScripts": {}},
            "storePaths": [], "retainedRoot": "/var/lib/aos/configuration-lowers"
        }))
        .unwrap()
    }

    #[test]
    fn unlabeled_images_preserve_the_existing_input_identity() {
        let original = input();
        let bound = bind(&original, None).unwrap();

        let original = serde_json::to_value(original).unwrap();
        assert_eq!(original, serde_json::to_value(bound).unwrap());
        assert!(original.get("selinuxFileContextsSha256").is_none());
    }

    #[test]
    fn another_policy_changes_identity_and_cannot_replace_an_existing_pin() {
        let first = Contexts {
            bytes: b"/etc/first -- system_u:object_r:etc_t\n".to_vec(),
        };
        let second = Contexts {
            bytes: b"/etc/second -- system_u:object_r:etc_t\n".to_vec(),
        };
        let original = input();
        let bound = bind(&original, Some(&first)).unwrap();

        assert_ne!(
            serde_json::to_value(&bound).unwrap(),
            serde_json::to_value(bind(&original, Some(&second)).unwrap()).unwrap(),
        );
        assert!(bind(&bound, Some(&second)).is_err());
        assert!(bind(&bound, None).is_err());
    }

    #[test]
    fn retained_snapshot_rejects_changed_bytes_and_symlink_substitution() {
        let directory = tempfile::tempdir().unwrap();
        let contexts = Contexts {
            bytes: b"/etc(/.*)? system_u:object_r:etc_t\n".to_vec(),
        };
        let bound = bind(&input(), Some(&contexts)).unwrap();
        contexts.write(directory.path()).unwrap();

        verify_snapshot(&bound, directory.path()).unwrap();
        assert!(contexts.write(directory.path()).is_err());
        let snapshot = directory.path().join(SNAPSHOT);
        fs::set_permissions(&snapshot, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&snapshot, b"changed").unwrap();
        assert!(verify_snapshot(&bound, directory.path()).is_err());

        fs::remove_file(&snapshot).unwrap();
        let alternate = directory.path().join("alternate");
        fs::write(&alternate, &contexts.bytes).unwrap();
        symlink(&alternate, &snapshot).unwrap();
        assert!(verify_snapshot(&bound, directory.path()).is_err());
    }

    #[test]
    fn image_contexts_must_be_direct_immutable_erofs_files() {
        let root = tempfile::tempdir().unwrap();
        let reference = root.path().join(IMAGE_CONTEXTS);
        fs::create_dir_all(reference.parent().unwrap()).unwrap();
        symlink("absent", &reference).unwrap();

        assert!(Contexts::capture(root.path()).is_err());

        fs::remove_file(&reference).unwrap();
        fs::write(&reference, b"mutable contexts").unwrap();
        assert!(Contexts::capture(root.path()).is_err());
    }
}
