//! Protected LocalLive export publication readback.
//!
//! ```text
//! AOSSXC01 | version:u16be=1 | reserved[6]=0 |
//! catalog-generation:u64be | row-count:u32be | reserved[4]=0 |
//! repeated sorted rows:
//!   export-id[16] | export-generation:u64be | revocation-digest[32] |
//!   workspace-id[32] | source-assignment-digest[32] |
//!   owner-sandbox[16] | source-incarnation[16] |
//!   state:u8 (1 active, 2 revoked) | reserved[7]=0
//! ```
//!
//! This is a read-only custody slice, not an export publisher. Only a root
//! controlled file can supply a row, and exact current-file readback is
//! required before selecting it. A protected journal retains the generation
//! floor and terminal tombstones across restart. This module still does not
//! issue leases or advertise LocalLive: an authenticated export-publication
//! writer and consumer admission are absent.

use std::fs::File;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

use aos_sandbox::{Journal, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::storage_live_export_lease::StorageLiveExportSourceV1;
use rustix::fs::{FileType, Mode, OFlags};
use sha2::{Digest as _, Sha256};

use crate::live_export_key::{open_protected_directory, same_stable_file_metadata};
use crate::live_export_origin::StorageLiveExportOriginV1;

const CATALOG_FILE: &str = "storage-live-export-catalog-v1";
const JOURNAL_FILE: &str = "storage-live-export-publications.journal";
const JOURNAL_HEAD_KEY: &[u8] = b"live-export-catalog-head-v1";
const MAGIC: &[u8; 8] = b"AOSSXC01";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 32;
const ROW_BYTES: usize = 160;
const MAXIMUM_ROWS: usize = 4096;
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.live-export-catalog.v1\0";
const JOURNAL_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.storage.live-export-publication.v1\0";

/// Rejects absent, unsafe, changed, or noncanonical export publication state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StorageLiveExportCatalogErrorV1 {
    /// Protected publication file custody is missing or changed.
    #[error("protected live-export catalog custody is unavailable")]
    Custody,
    /// A catalog header, row, ordering, or lifecycle field is invalid.
    #[error("protected live-export catalog is noncanonical")]
    InvalidRecord,
    /// The selected export is absent, revoked, or belongs to another origin.
    #[error("live export is unavailable for this workspace origin")]
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExportRowV1 {
    export_id: [u8; 16],
    generation: u64,
    revocation_digest: ObjectDigest,
    workspace_id: [u8; 32],
    assignment_digest: ObjectDigest,
    owner_sandbox: [u8; 16],
    source_incarnation: [u8; 16],
    active: bool,
}

struct ParsedCatalogV1 {
    generation: u64,
    digest: ObjectDigest,
    rows: Vec<ExportRowV1>,
}

/// Retains the exact current root-owned export publication snapshot.
///
/// Its protected journal rejects rollback and tombstone resurrection on
/// restart. A separate authenticated publisher must still supply each new
/// export definition before lease issuance can be enabled.
pub(crate) struct StorageLiveExportCatalogV1 {
    journal: Journal,
    directory: OwnedFd,
    directory_path: PathBuf,
    directory_device: u64,
    directory_inode: u64,
    file_device: u64,
    file_inode: u64,
    bytes: Vec<u8>,
    parsed: ParsedCatalogV1,
    expected_owner: u32,
}

impl StorageLiveExportCatalogV1 {
    /// Opens the fixed root-owned publication file without creating rows.
    ///
    /// # Errors
    ///
    /// Returns [`StorageLiveExportCatalogErrorV1`] for an unsafe path or an
    /// absent, changed, malformed, or unbounded publication file.
    pub(crate) fn open_root_owned(
        directory: &Path,
    ) -> Result<Self, StorageLiveExportCatalogErrorV1> {
        Self::open_with_owner(directory, 0)
    }

    fn open_with_owner(
        directory: &Path,
        expected_owner: u32,
    ) -> Result<Self, StorageLiveExportCatalogErrorV1> {
        let directory_path = directory.to_path_buf();
        let directory = open_protected_directory(directory, expected_owner)
            .map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?;
        let directory_identity =
            rustix::fs::fstat(&directory).map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?;
        let (bytes, file_device, file_inode) = read_catalog(&directory, expected_owner)?;
        let parsed = parse_catalog(&bytes)?;
        let mut journal = if expected_owner == 0 {
            Journal::open_protected_at(&directory_path, JOURNAL_FILE, journal_limits())
        } else {
            Journal::open_protected_at_for_uid(
                &directory_path,
                JOURNAL_FILE,
                journal_limits(),
                expected_owner,
            )
        }
        .map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?
        .0;
        reconcile_publication_head(&mut journal, &bytes, &parsed)?;
        Ok(Self {
            journal,
            directory,
            directory_path,
            directory_device: directory_identity.st_dev,
            directory_inode: directory_identity.st_ino,
            file_device,
            file_inode,
            bytes,
            parsed,
            expected_owner,
        })
    }

    pub(crate) fn select_current(
        &self,
        export_id: [u8; 16],
        origin: &StorageLiveExportOriginV1,
    ) -> Result<StorageLiveExportSourceV1, StorageLiveExportCatalogErrorV1> {
        self.validate_current()?;
        let row = self
            .parsed
            .rows
            .iter()
            .find(|row| row.export_id == export_id && row.active)
            .ok_or(StorageLiveExportCatalogErrorV1::Unavailable)?;
        let (workspace_id, workspace_digest) = origin.workspace();
        let (owner_sandbox, source_incarnation) = origin.owner();
        if row.workspace_id != workspace_id
            || row.assignment_digest != origin.source_assignment_digest()
            || row.owner_sandbox != owner_sandbox
            || row.source_incarnation != source_incarnation
        {
            return Err(StorageLiveExportCatalogErrorV1::Unavailable);
        }
        let (boot_id, device, inode, mount_id) = origin.physical_identity();
        StorageLiveExportSourceV1::new(
            row.assignment_digest,
            row.owner_sandbox,
            row.source_incarnation,
            row.export_id,
            row.generation,
            row.revocation_digest,
            workspace_id,
            workspace_digest,
            boot_id,
            device,
            inode,
            mount_id,
        )
        .map_err(|_| StorageLiveExportCatalogErrorV1::InvalidRecord)
    }

    pub(crate) fn validate_current(&self) -> Result<(), StorageLiveExportCatalogErrorV1> {
        let current_directory = open_protected_directory(&self.directory_path, self.expected_owner)
            .map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?;
        let identity = rustix::fs::fstat(&current_directory)
            .map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?;
        if (identity.st_dev, identity.st_ino) != (self.directory_device, self.directory_inode) {
            return Err(StorageLiveExportCatalogErrorV1::Custody);
        }
        let (bytes, device, inode) = read_catalog(&self.directory, self.expected_owner)?;
        if (device, inode) != (self.file_device, self.file_inode) || bytes != self.bytes {
            return Err(StorageLiveExportCatalogErrorV1::Custody);
        }
        let current = parse_catalog(&bytes)?;
        if current.generation != self.parsed.generation || current.digest != self.parsed.digest {
            return Err(StorageLiveExportCatalogErrorV1::Custody);
        }
        if self
            .journal
            .get(RecordNamespace::AuthorityPublication, JOURNAL_HEAD_KEY)
            != Some(self.bytes.as_slice())
        {
            return Err(StorageLiveExportCatalogErrorV1::Custody);
        }
        Ok(())
    }
}

fn reconcile_publication_head(
    journal: &mut Journal,
    bytes: &[u8],
    parsed: &ParsedCatalogV1,
) -> Result<(), StorageLiveExportCatalogErrorV1> {
    let mut authority = journal
        .claim_protected_authority(RecordNamespace::AuthorityPublication)
        .map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?;
    let previous = authority
        .get(JOURNAL_HEAD_KEY)
        .map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?
        .map(ToOwned::to_owned);
    let needs_commit = match previous {
        None => {
            if !authority
                .is_materialized_empty()
                .map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?
                || parsed.generation != 1
            {
                return Err(StorageLiveExportCatalogErrorV1::Custody);
            }
            true
        }
        Some(previous) if previous == bytes => false,
        Some(previous) => {
            let old = parse_catalog(&previous)?;
            validate_transition(&old, parsed)?;
            true
        }
    };
    if needs_commit {
        let digest = Sha256::new()
            .chain_update(JOURNAL_TRANSACTION_DOMAIN)
            .chain_update(parsed.generation.to_be_bytes())
            .chain_update(parsed.digest.as_bytes())
            .finalize();
        let transaction_id: [u8; 16] = digest[..16]
            .try_into()
            .map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::AuthorityPublication,
                JOURNAL_HEAD_KEY.to_vec(),
                bytes.to_vec(),
            )],
        )
        .map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?;
        authority
            .commit(&transaction)
            .map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?;
    }
    if authority
        .records()
        .map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?
        .collect::<Vec<_>>()
        != vec![(JOURNAL_HEAD_KEY, bytes)]
    {
        return Err(StorageLiveExportCatalogErrorV1::Custody);
    }
    Ok(())
}

fn validate_transition(
    previous: &ParsedCatalogV1,
    next: &ParsedCatalogV1,
) -> Result<(), StorageLiveExportCatalogErrorV1> {
    if next.generation
        != previous
            .generation
            .checked_add(1)
            .ok_or(StorageLiveExportCatalogErrorV1::InvalidRecord)?
        || next.rows.len() < previous.rows.len()
    {
        return Err(StorageLiveExportCatalogErrorV1::InvalidRecord);
    }
    let mut changed = false;
    for prior in &previous.rows {
        let current = next
            .rows
            .iter()
            .find(|row| row.export_id == prior.export_id)
            .ok_or(StorageLiveExportCatalogErrorV1::InvalidRecord)?;
        if current == prior {
            continue;
        }
        if !prior.active
            || current.owner_sandbox != prior.owner_sandbox
            || current.generation != next.generation
            || current.revocation_digest == prior.revocation_digest
            || (!current.active
                && (current.workspace_id != prior.workspace_id
                    || current.assignment_digest != prior.assignment_digest
                    || current.source_incarnation != prior.source_incarnation))
        {
            return Err(StorageLiveExportCatalogErrorV1::InvalidRecord);
        }
        changed = true;
    }
    for current in &next.rows {
        if !previous
            .rows
            .iter()
            .any(|row| row.export_id == current.export_id)
        {
            if !current.active || current.generation != next.generation {
                return Err(StorageLiveExportCatalogErrorV1::InvalidRecord);
            }
            changed = true;
        }
    }
    if !changed {
        return Err(StorageLiveExportCatalogErrorV1::InvalidRecord);
    }
    Ok(())
}

const fn journal_limits() -> JournalLimits {
    const MAXIMUM_CATALOG_BYTES: usize = HEADER_BYTES + ROW_BYTES * MAXIMUM_ROWS;
    JournalLimits {
        maximum_journal_bytes: 256 * 1024 * 1024,
        maximum_record_bytes: MAXIMUM_CATALOG_BYTES,
        maximum_key_bytes: 64,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: MAXIMUM_CATALOG_BYTES + 1024,
        maximum_transactions: 256,
        maximum_materialized_bytes: MAXIMUM_CATALOG_BYTES + 64,
        maximum_materialized_records: 1,
    }
}

fn read_catalog(
    directory: &OwnedFd,
    expected_owner: u32,
) -> Result<(Vec<u8>, u64, u64), StorageLiveExportCatalogErrorV1> {
    let descriptor = rustix::fs::openat(
        directory.as_fd(),
        CATALOG_FILE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?;
    let before =
        rustix::fs::fstat(&descriptor).map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?;
    let maximum_bytes = HEADER_BYTES + ROW_BYTES * MAXIMUM_ROWS;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != expected_owner
        || before.st_mode & 0o777 != 0o600
        || before.st_nlink != 1
        || before.st_size < HEADER_BYTES as i64
        || before.st_size > maximum_bytes as i64
        || before.st_dev == 0
        || before.st_ino == 0
    {
        return Err(StorageLiveExportCatalogErrorV1::Custody);
    }
    let size =
        usize::try_from(before.st_size).map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?;
    let file = File::from(descriptor);
    let mut bytes = vec![0; size];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?;
    let mut repeated = vec![0; size];
    file.read_exact_at(&mut repeated, 0)
        .map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?;
    let after = rustix::fs::fstat(&file).map_err(|_| StorageLiveExportCatalogErrorV1::Custody)?;
    if !same_stable_file_metadata(&before, &after) || bytes != repeated {
        return Err(StorageLiveExportCatalogErrorV1::Custody);
    }
    Ok((bytes, before.st_dev, before.st_ino))
}

fn parse_catalog(bytes: &[u8]) -> Result<ParsedCatalogV1, StorageLiveExportCatalogErrorV1> {
    if bytes.len() < HEADER_BYTES
        || &bytes[..8] != MAGIC
        || bytes[8..10] != VERSION.to_be_bytes()
        || bytes[10..16] != [0; 6]
        || bytes[28..32] != [0; 4]
    {
        return Err(StorageLiveExportCatalogErrorV1::InvalidRecord);
    }
    let generation = u64::from_be_bytes(
        bytes[16..24]
            .try_into()
            .map_err(|_| StorageLiveExportCatalogErrorV1::InvalidRecord)?,
    );
    let count = u32::from_be_bytes(
        bytes[24..28]
            .try_into()
            .map_err(|_| StorageLiveExportCatalogErrorV1::InvalidRecord)?,
    );
    let count =
        usize::try_from(count).map_err(|_| StorageLiveExportCatalogErrorV1::InvalidRecord)?;
    if generation == 0 || count > MAXIMUM_ROWS || bytes.len() != HEADER_BYTES + ROW_BYTES * count {
        return Err(StorageLiveExportCatalogErrorV1::InvalidRecord);
    }

    let mut rows = Vec::with_capacity(count);
    let mut previous = None;
    for chunk in bytes[HEADER_BYTES..].chunks_exact(ROW_BYTES) {
        let export_id: [u8; 16] = chunk[..16]
            .try_into()
            .map_err(|_| StorageLiveExportCatalogErrorV1::InvalidRecord)?;
        let row_generation = u64::from_be_bytes(
            chunk[16..24]
                .try_into()
                .map_err(|_| StorageLiveExportCatalogErrorV1::InvalidRecord)?,
        );
        let revocation_digest = ObjectDigest::from_bytes(
            chunk[24..56]
                .try_into()
                .map_err(|_| StorageLiveExportCatalogErrorV1::InvalidRecord)?,
        );
        let workspace_id: [u8; 32] = chunk[56..88]
            .try_into()
            .map_err(|_| StorageLiveExportCatalogErrorV1::InvalidRecord)?;
        let assignment_digest = ObjectDigest::from_bytes(
            chunk[88..120]
                .try_into()
                .map_err(|_| StorageLiveExportCatalogErrorV1::InvalidRecord)?,
        );
        let owner_sandbox: [u8; 16] = chunk[120..136]
            .try_into()
            .map_err(|_| StorageLiveExportCatalogErrorV1::InvalidRecord)?;
        let source_incarnation: [u8; 16] = chunk[136..152]
            .try_into()
            .map_err(|_| StorageLiveExportCatalogErrorV1::InvalidRecord)?;
        let active = match chunk[152] {
            1 => true,
            2 => false,
            _ => return Err(StorageLiveExportCatalogErrorV1::InvalidRecord),
        };
        if export_id == [0; 16]
            || previous.is_some_and(|prior| prior >= export_id)
            || row_generation == 0
            || row_generation > generation
            || revocation_digest.as_bytes() == &[0; 32]
            || workspace_id == [0; 32]
            || assignment_digest.as_bytes() == &[0; 32]
            || owner_sandbox == [0; 16]
            || source_incarnation == [0; 16]
            || chunk[153..] != [0; 7]
        {
            return Err(StorageLiveExportCatalogErrorV1::InvalidRecord);
        }
        rows.push(ExportRowV1 {
            export_id,
            generation: row_generation,
            revocation_digest,
            workspace_id,
            assignment_digest,
            owner_sandbox,
            source_incarnation,
            active,
        });
        previous = Some(export_id);
    }
    let digest = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(DIGEST_DOMAIN)
            .chain_update(bytes)
            .finalize()
            .into(),
    );
    Ok(ParsedCatalogV1 {
        generation,
        digest,
        rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog_bytes() -> Vec<u8> {
        let mut bytes = vec![0; HEADER_BYTES + ROW_BYTES * 2];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[16..24].copy_from_slice(&3_u64.to_be_bytes());
        bytes[24..28].copy_from_slice(&2_u32.to_be_bytes());
        for (index, row) in bytes[HEADER_BYTES..]
            .chunks_exact_mut(ROW_BYTES)
            .enumerate()
        {
            row[..16].copy_from_slice(&[u8::try_from(index + 1).unwrap(); 16]);
            row[16..24].copy_from_slice(&u64::try_from(index + 1).unwrap().to_be_bytes());
            row[24..56].copy_from_slice(&[3; 32]);
            row[56..88].copy_from_slice(&[4; 32]);
            row[88..120].copy_from_slice(&[5; 32]);
            row[120..136].copy_from_slice(&[6; 16]);
            row[136..152].copy_from_slice(&[7; 16]);
            row[152] = if index == 0 { 1 } else { 2 };
        }
        bytes
    }

    #[test]
    fn catalog_accepts_exact_sorted_publication_and_revocation() {
        let bytes = catalog_bytes();
        let parsed = parse_catalog(&bytes).unwrap();
        assert_eq!(parsed.generation, 3);
        assert_eq!(parsed.rows.len(), 2);
        assert!(parsed.rows[0].active);
        assert!(!parsed.rows[1].active);
        assert_ne!(parsed.digest.as_bytes(), &[0; 32]);
    }

    #[test]
    fn catalog_rejects_stale_or_ambiguous_rows() {
        let original = catalog_bytes();
        for (offset, value) in [
            (0, 0),
            (9, 0),
            (10, 1),
            (23, 0),
            (27, 0),
            (28, 1),
            (HEADER_BYTES + 23, 0),
            (HEADER_BYTES + 152, 3),
            (HEADER_BYTES + 153, 1),
        ] {
            let mut changed = original.clone();
            changed[offset] = value;
            assert!(parse_catalog(&changed).is_err(), "changed byte {offset}");
        }

        let mut unsorted = original.clone();
        unsorted[HEADER_BYTES + ROW_BYTES..HEADER_BYTES + ROW_BYTES + 16].copy_from_slice(&[1; 16]);
        assert!(parse_catalog(&unsorted).is_err());
        assert!(parse_catalog(&original[..original.len() - 1]).is_err());
    }

    #[test]
    fn publication_transition_retains_tombstones_and_rejects_rollback() {
        let previous_bytes = catalog_bytes();
        let previous = parse_catalog(&previous_bytes).unwrap();
        let mut revoked_bytes = previous_bytes.clone();
        revoked_bytes[16..24].copy_from_slice(&4_u64.to_be_bytes());
        let first = &mut revoked_bytes[HEADER_BYTES..HEADER_BYTES + ROW_BYTES];
        first[16..24].copy_from_slice(&4_u64.to_be_bytes());
        first[24..56].copy_from_slice(&[9; 32]);
        first[152] = 2;
        let revoked = parse_catalog(&revoked_bytes).unwrap();

        assert!(validate_transition(&previous, &revoked).is_ok());
        assert!(validate_transition(&revoked, &previous).is_err());
        assert!(validate_transition(&previous, &previous).is_err());

        let mut rewritten_origin = revoked_bytes.clone();
        rewritten_origin[HEADER_BYTES + 56..HEADER_BYTES + 88].fill(8);
        let rewritten_origin = parse_catalog(&rewritten_origin).unwrap();
        assert!(validate_transition(&previous, &rewritten_origin).is_err());

        let mut revived_bytes = revoked_bytes.clone();
        revived_bytes[16..24].copy_from_slice(&5_u64.to_be_bytes());
        let first = &mut revived_bytes[HEADER_BYTES..HEADER_BYTES + ROW_BYTES];
        first[16..24].copy_from_slice(&5_u64.to_be_bytes());
        first[24..56].copy_from_slice(&[10; 32]);
        first[152] = 1;
        let revived = parse_catalog(&revived_bytes).unwrap();
        assert!(validate_transition(&revoked, &revived).is_err());

        let mut lost_tombstone = revoked_bytes;
        lost_tombstone.truncate(HEADER_BYTES + ROW_BYTES);
        lost_tombstone[24..28].copy_from_slice(&1_u32.to_be_bytes());
        lost_tombstone[16..24].copy_from_slice(&5_u64.to_be_bytes());
        let lost_tombstone = parse_catalog(&lost_tombstone).unwrap();
        assert!(validate_transition(&revoked, &lost_tombstone).is_err());
    }
}
