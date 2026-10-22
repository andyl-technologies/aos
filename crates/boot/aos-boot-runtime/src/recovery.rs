//! Validates the recovery copy paired with one staged systemd image generation.
//!
//! Recovery payloads stay private until boot selection publishes their exact
//! bytes before the normal UKI. The evidence uses the same snake_case fields
//! written by initrd profile seeding; it belongs to this provider, not APM.
//!
//! The generation's provider evidence contains this optional `recovery` object:
//!
//! ```json
//! {
//!   "copy": "B",
//!   "uki_path": "EFI/AOS/recovery-b.efi",
//!   "entry_path": "loader/entries/recovery-b.conf",
//!   "source_path": "candidates/2/recovery-b.efi",
//!   "sha256": "sha256:<64 lowercase hexadecimal digits>",
//!   "byte_size": 63362024,
//!   "release": "1.2.3",
//!   "recovery_abi": 1
//! }
//! ```
//!
//! A seeded, already installed generation instead records its original artifact
//! name in `source_path`. Only staged sources are read from the image profile.

use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_boot_identity::{parse_recovery, pe::read_uki_text};
use aos_core::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::image_profile::parse_candidate_path;

const MAX_RECOVERY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 4096;
const RECOVERY_CMDLINE: &str =
    "console=ttyS0,115200 rd.systemd.unit=aos-recovery.target aos.recovery=1 rd.luks=0";

/// Records the authenticated recovery identity and its owned publication paths.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryEvidence {
    /// Names the root slot whose recovery copy is replaced.
    pub(crate) copy: String,
    /// Names the recovery UKI relative to the ESP.
    pub(crate) uki_path: String,
    /// Names the loader entry relative to the ESP.
    pub(crate) entry_path: String,
    /// Names the retained source relative to the image profile when staged.
    pub(crate) source_path: String,
    /// Identifies the exact UKI bytes, with an optional `sha256:` prefix.
    pub(crate) sha256: String,
    /// Bounds the exact UKI length.
    pub(crate) byte_size: u64,
    /// Names the release embedded in the paired recovery UKI.
    pub(crate) release: String,
    /// Identifies the recovery protocol embedded in the paired UKI.
    pub(crate) recovery_abi: u32,
}

/// Holds checked bytes ready for ordered firmware publication.
pub(crate) struct RecoveryPayload {
    /// Contains the exact recovery UKI bytes named by the evidence.
    pub(crate) uki: Vec<u8>,
    /// Contains the canonical loader entry for the same release and copy.
    pub(crate) entry: Vec<u8>,
}

impl RecoveryEvidence {
    /// Checks that the evidence owns only the selected slot's recovery paths.
    ///
    /// # Errors
    /// Returns an error for mismatched slots, paths, malformed release or
    /// digest, an invalid byte bound, or a zero recovery ABI.
    pub(crate) fn validate_identity(&self, slot: &str) -> Result<()> {
        ensure!(
            matches!(slot, "A" | "B") && self.copy == slot,
            "recovery copy differs from candidate slot"
        );
        let lower = slot.to_ascii_lowercase();
        ensure!(
            self.uki_path == format!("EFI/AOS/recovery-{lower}.efi")
                && self.entry_path == format!("loader/entries/recovery-{lower}.conf"),
            "recovery publication paths differ from the paired copy"
        );
        validate_release(&self.release)?;
        ensure!(
            self.byte_size > 0 && self.byte_size <= MAX_RECOVERY_BYTES,
            "recovery UKI exceeds its byte bound"
        );
        ensure!(self.recovery_abi > 0, "recovery ABI is zero");
        self.digest()?;
        Ok(())
    }

    /// Produces the canonical loader entry for the paired release and copy.
    ///
    /// # Errors
    /// Returns an error when the evidence has an invalid identity.
    pub(crate) fn entry_bytes(&self) -> Result<Vec<u8>> {
        self.validate_identity(&self.copy)?;
        Ok(format!(
            "title AOS Recovery {} ({})\nefi /{}\n",
            self.copy, self.release, self.uki_path
        )
        .into_bytes())
    }

    /// Reads a staged recovery pair after checking its identity and exact bytes.
    ///
    /// # Errors
    /// Returns an error for an aliased or noncanonical source, a missing or
    /// changed payload, mismatched embedded identity, or a noncanonical entry.
    pub(crate) fn checked_payload(
        &self,
        profile: &Path,
        candidate_source: &Path,
    ) -> Result<RecoveryPayload> {
        let (uki_path, entry_path) = self.staged_paths(candidate_source)?;
        let parent = profile.join(uki_path.parent().context("recovery source has no parent")?);
        ensure!(
            fs::canonicalize(&parent)? == parent,
            "staged recovery source traverses an alias"
        );
        let source = profile.join(uki_path);
        let uki = read_regular_bounded(&source, self.byte_size)?;
        ensure!(
            uki.len() as u64 == self.byte_size && Sha256Digest::of_bytes(&uki) == self.digest()?,
            "staged recovery UKI size or digest changed"
        );
        ensure!(
            validate_uki_identity(&source, &self.copy, &self.release)? == self.recovery_abi,
            "staged recovery ABI changed"
        );
        let entry = read_regular_bounded(&profile.join(entry_path), MAX_ENTRY_BYTES)?;
        ensure!(
            entry == self.entry_bytes()?,
            "staged recovery loader entry is not canonical"
        );
        Ok(RecoveryPayload { uki, entry })
    }

    /// Resolves the paired files in the same owned directory as a staged UKI.
    ///
    /// This checks path identity without requiring the files to exist, allowing
    /// interrupted retirement to resume after one file has already been removed.
    ///
    /// # Errors
    /// Returns an error for invalid evidence, candidate source or recovery source.
    pub(crate) fn staged_paths(&self, candidate_source: &Path) -> Result<(PathBuf, PathBuf)> {
        self.validate_identity(&self.copy)?;
        let candidate = parse_candidate_path(
            candidate_source
                .to_str()
                .context("candidate source is not UTF-8")?,
        )?;
        let directory = candidate
            .parent()
            .context("candidate source has no parent")?;
        let lower = self.copy.to_ascii_lowercase();
        let expected = directory.join(format!("recovery-{lower}.efi"));
        ensure!(
            Some(self.source_path.as_str()) == expected.to_str(),
            "recovery source differs from staged candidate directory"
        );
        Ok((expected, directory.join(format!("recovery-{lower}.conf"))))
    }

    fn digest(&self) -> Result<Sha256Digest> {
        if self.sha256.starts_with("sha256:") {
            Sha256Digest::parse(&self.sha256)
        } else {
            Sha256Digest::parse(&format!("sha256:{}", self.sha256))
        }
    }
}

/// Checks the release, copy, ABI and allowed command line in an authenticated UKI.
///
/// The caller authenticates the complete file against signed artifact metadata
/// before using this parser. Parsing alone does not establish that provenance.
///
/// # Errors
/// Returns an error for malformed PE sections, duplicate or missing identity
/// fields, a changed copy or release, a zero ABI, or an unsupported command line.
pub(crate) fn validate_uki_identity(path: &Path, copy: &str, release: &str) -> Result<u32> {
    ensure!(matches!(copy, "A" | "B"), "invalid recovery copy");
    validate_release(release)?;
    let cmdline = read_uki_text(path, "cmdline")?;
    // Profile seeding compares exact signed text, including token order and
    // whitespace. Refuse a candidate here rather than after switching slots.
    ensure!(
        cmdline == RECOVERY_CMDLINE,
        "recovery UKI command line differs from the boot seed contract"
    );
    parse_recovery(&cmdline)?;
    let osrel = read_uki_text(path, "osrel")?;
    ensure!(
        osrel_value(&osrel, "VERSION_ID")? == release,
        "recovery UKI release differs from candidate"
    );
    ensure!(
        osrel_value(&osrel, "AOS_RECOVERY_COPY")? == copy,
        "recovery UKI copy differs from candidate"
    );
    let abi = osrel_value(&osrel, "AOS_RECOVERY_ABI")?
        .parse::<u32>()
        .context("invalid recovery ABI")?;
    ensure!(abi > 0, "recovery ABI is zero");
    Ok(abi)
}

fn validate_release(release: &str) -> Result<()> {
    ensure!(
        !release.is_empty()
            && release.len() <= 256
            && release
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte)),
        "invalid recovery release"
    );
    Ok(())
}

fn osrel_value<'a>(osrel: &'a str, key: &str) -> Result<&'a str> {
    let mut fields = osrel
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(name, _)| *name == key);
    let (_, value) = fields
        .next()
        .with_context(|| format!("recovery UKI lacks {key}"))?;
    ensure!(fields.next().is_none(), "recovery UKI repeats {key}");
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    ensure!(
        !value.is_empty() && !value.contains(['"', '\\', '\'']),
        "invalid recovery UKI {key}"
    );
    Ok(value)
}

fn read_regular_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        fs::symlink_metadata(path)?.is_file(),
        "recovery source is not regular"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "recovery source exceeds its byte bound"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMDLINE: &str = RECOVERY_CMDLINE;

    fn write_uki(path: &Path, cmdline: &str, osrel: &str) -> Vec<u8> {
        let sections = [(".cmdline", cmdline), (".osrel", osrel)];
        let mut bytes = vec![0; 512 + cmdline.len() + osrel.len()];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64_u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[68..70].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[70..72].copy_from_slice(&2_u16.to_le_bytes());
        bytes[84..86].copy_from_slice(&240_u16.to_le_bytes());
        bytes[88..90].copy_from_slice(&0x20b_u16.to_le_bytes());

        let mut offset = 512;
        for (index, (name, content)) in sections.iter().enumerate() {
            let header = 328 + index * 40;
            let size = content.len() as u32;
            bytes[header..header + name.len()].copy_from_slice(name.as_bytes());
            bytes[header + 8..header + 12].copy_from_slice(&size.to_le_bytes());
            bytes[header + 16..header + 20].copy_from_slice(&size.to_le_bytes());
            bytes[header + 20..header + 24].copy_from_slice(&(offset as u32).to_le_bytes());
            bytes[offset..offset + content.len()].copy_from_slice(content.as_bytes());
            offset += content.len();
        }
        fs::write(path, &bytes).unwrap();
        bytes
    }

    fn fixture(profile: &Path) -> RecoveryEvidence {
        let directory = profile.join("candidates/2");
        fs::create_dir_all(&directory).unwrap();
        let bytes = write_uki(
            &directory.join("recovery-b.efi"),
            CMDLINE,
            "VERSION_ID=\"1.2.3\"\nAOS_RECOVERY_COPY=B\nAOS_RECOVERY_ABI=1\n",
        );
        let evidence = RecoveryEvidence {
            copy: "B".into(),
            uki_path: "EFI/AOS/recovery-b.efi".into(),
            entry_path: "loader/entries/recovery-b.conf".into(),
            source_path: "candidates/2/recovery-b.efi".into(),
            sha256: Sha256Digest::of_bytes(&bytes).to_string(),
            byte_size: bytes.len() as u64,
            release: "1.2.3".into(),
            recovery_abi: 1,
        };
        fs::write(
            directory.join("recovery-b.conf"),
            evidence.entry_bytes().unwrap(),
        )
        .unwrap();
        evidence
    }

    #[test]
    fn staged_pair_matches_authenticated_bytes_and_seeded_evidence_shape() {
        let profile = tempfile::tempdir().unwrap();
        let mut evidence = fixture(profile.path());

        let payload = evidence
            .checked_payload(profile.path(), Path::new("candidates/2/candidate.efi"))
            .unwrap();
        assert_eq!(
            payload.entry,
            b"title AOS Recovery B (1.2.3)\nefi /EFI/AOS/recovery-b.efi\n"
        );
        assert_eq!(payload.uki.len() as u64, evidence.byte_size);
        evidence.sha256 = Sha256Digest::of_bytes(&payload.uki).hex();
        evidence
            .checked_payload(profile.path(), Path::new("candidates/2/candidate.efi"))
            .unwrap();

        evidence.source_path = "recovery-b.efi".into();
        let encoded = serde_json::to_value(&evidence).unwrap();
        let seeded: RecoveryEvidence = serde_json::from_value(encoded).unwrap();
        seeded.validate_identity("B").unwrap();
    }

    #[test]
    fn recovery_identity_rejects_other_slot_paths_and_loader_injection() {
        let profile = tempfile::tempdir().unwrap();
        let evidence = fixture(profile.path());
        assert!(evidence.validate_identity("A").is_err());
        for field in ["copy", "uki_path", "entry_path", "sha256", "release"] {
            let mut value = serde_json::to_value(&evidence).unwrap();
            value[field] = serde_json::json!(match field {
                "copy" => "b",
                "uki_path" => "EFI/AOS/recovery-a.efi",
                "entry_path" => "loader/entries/../recovery-b.conf",
                "sha256" => "sha256:1234",
                _ => "1.2.3\nefi /other.efi",
            });
            let changed: RecoveryEvidence = serde_json::from_value(value).unwrap();
            assert!(changed.validate_identity("B").is_err(), "accepted {field}");
        }
        for size in [0, MAX_RECOVERY_BYTES + 1] {
            let mut changed = evidence.clone();
            changed.byte_size = size;
            assert!(changed.validate_identity("B").is_err());
        }
        let mut changed = evidence;
        changed.recovery_abi = 0;
        assert!(changed.validate_identity("B").is_err());
    }

    #[test]
    fn recovery_uki_rejects_mismatched_or_ambiguous_embedded_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("recovery.efi");
        for osrel in [
            "VERSION_ID=1.2.4\nAOS_RECOVERY_COPY=B\nAOS_RECOVERY_ABI=1\n",
            "VERSION_ID=1.2.3\nAOS_RECOVERY_COPY=A\nAOS_RECOVERY_ABI=1\n",
            "VERSION_ID=1.2.3\nVERSION_ID=1.2.3\nAOS_RECOVERY_COPY=B\nAOS_RECOVERY_ABI=1\n",
            "VERSION_ID=1.2.3\nAOS_RECOVERY_COPY=B\nAOS_RECOVERY_ABI=0\n",
            "VERSION_ID=1.2.3\nAOS_RECOVERY_COPY=B\n",
        ] {
            write_uki(&path, CMDLINE, osrel);
            assert!(validate_uki_identity(&path, "B", "1.2.3").is_err());
        }
        for cmdline in [
            format!("{CMDLINE} init=/other"),
            "aos.recovery=1 console=ttyS0,115200 rd.systemd.unit=aos-recovery.target rd.luks=0"
                .into(),
            format!("{CMDLINE}\n"),
        ] {
            write_uki(
                &path,
                &cmdline,
                "VERSION_ID=1.2.3\nAOS_RECOVERY_COPY=B\nAOS_RECOVERY_ABI=1\n",
            );
            assert!(validate_uki_identity(&path, "B", "1.2.3").is_err());
        }
    }

    #[test]
    fn staged_pair_rejects_drift_missing_files_and_foreign_sources() {
        let profile = tempfile::tempdir().unwrap();
        let evidence = fixture(profile.path());
        let candidate = Path::new("candidates/2/candidate.efi");
        for source in [
            "../recovery-b.efi",
            "candidates/3/recovery-b.efi",
            "candidates/2/./recovery-b.efi",
        ] {
            let mut changed = evidence.clone();
            changed.source_path = source.into();
            assert!(
                changed.checked_payload(profile.path(), candidate).is_err(),
                "accepted {source}"
            );
        }
        let mut changed = evidence.clone();
        changed.recovery_abi = 2;
        assert!(changed.checked_payload(profile.path(), candidate).is_err());

        let entry = profile.path().join("candidates/2/recovery-b.conf");
        fs::write(
            &entry,
            b"title stale release\nefi /EFI/AOS/recovery-b.efi\n",
        )
        .unwrap();
        assert!(evidence.checked_payload(profile.path(), candidate).is_err());
        fs::write(&entry, evidence.entry_bytes().unwrap()).unwrap();
        let uki = profile.path().join(&evidence.source_path);
        fs::write(&uki, b"changed bytes").unwrap();
        assert!(evidence.checked_payload(profile.path(), candidate).is_err());
        fs::remove_file(&uki).unwrap();
        assert!(evidence.checked_payload(profile.path(), candidate).is_err());
    }

    #[test]
    fn staged_pair_rejects_file_and_directory_aliases() {
        use std::os::unix::fs::symlink;

        let profile = tempfile::tempdir().unwrap();
        let evidence = fixture(profile.path());
        let candidate = Path::new("candidates/2/candidate.efi");
        let source = profile.path().join(&evidence.source_path);
        fs::rename(&source, source.with_extension("outside")).unwrap();
        symlink(source.with_extension("outside"), &source).unwrap();
        assert!(evidence.checked_payload(profile.path(), candidate).is_err());

        fs::remove_file(&source).unwrap();
        fs::rename(source.with_extension("outside"), &source).unwrap();
        let directory = profile.path().join("candidates/2");
        fs::rename(&directory, profile.path().join("outside")).unwrap();
        symlink(profile.path().join("outside"), &directory).unwrap();
        assert!(evidence.checked_payload(profile.path(), candidate).is_err());
    }
}
