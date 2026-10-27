//! Independent archive reader claims in the authoritative ref namespace.
//!
//! Claims use `archive-readers/<unique-token>` so the archive GC
//! inventory authenticates their selected closure. Creation holds only a short
//! publication fence; the reader retains no namespace-wide GC exclusion.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::*;
use crate::CampaignArchiveManifestId;

const ARCHIVE_PREFIX: &str = "archives/";
const READER_PREFIX: &str = "archive-readers/";
const READER_NAME_BYTES: usize = READER_PREFIX.len() + 64;

/// Retains one published archive independently of its original named ref.
///
/// Retirement removes only this owner's expected binding. Process death or a
/// failed retirement leaves conservative durable retention. Automatic stale
/// claim recovery is not implemented; explicit reconciliation must establish
/// that the former reader has stopped before retiring a surviving claim.
/// This capability grants retention only, without granting execution readiness.
pub struct CampaignArchiveLease {
    manifest: CampaignArchiveManifestId,
    claim: RefName,
    refs: Arc<dyn MutableRefBackend>,
    // The claim's name and original credit outlive its final ref mutation.
    _credit: crucible_store::owned_decode::DecodeScratch,
}

impl Drop for CampaignArchiveLease {
    fn drop(&mut self) {
        let _ = self
            .refs
            .compare_remove(&self.claim, self.manifest.content_id());
    }
}

impl CampaignRepository {
    /// Retains the expected published archive under an independent reader claim.
    ///
    /// The named ref is checked and the reader claim is installed under the
    /// same short GC exclusion. Later replacement of the named ref cannot
    /// remove this owner's retention. Each call creates a distinct claim.
    ///
    /// # Errors
    ///
    /// Refuses unavailable original metadata authority, a changed or missing
    /// named ref, cancellation, or a failed claim publication.
    pub fn retain_campaign_archive_ref_with_boundary(
        &self,
        name: &str,
        expected: CampaignArchiveManifestId,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<CampaignArchiveLease, CampaignRepositoryError> {
        self.verify_ram_admission()?;
        let original = self
            .ram_admission()
            .original()
            .ok_or(StoreError::Unsupported {
                capability: "campaign-archive-reader-original",
            })?;
        // Both ref names and the fixed owner are prepaid before allocation.
        let published_bytes = name
            .len()
            .checked_add(ARCHIVE_PREFIX.len())
            .ok_or(StoreError::Quota)?;
        let name_bytes = published_bytes
            .checked_add(READER_NAME_BYTES)
            .ok_or(StoreError::Quota)?;
        let credit = original
            .reserve_scratch_bytes(
                (std::mem::size_of::<CampaignArchiveLease>() as u64)
                    .checked_add(name_bytes as u64)
                    .ok_or(StoreError::Quota)?,
            )
            .map_err(|source| {
                CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
                    original, source,
                ))
            })?;
        let mut published = String::with_capacity(published_bytes);
        published.push_str(ARCHIVE_PREFIX);
        published.push_str(name);
        let published = RefName::new(published)?;
        let mut check = || {
            let verify = || {
                original.verify_live().map_err(|source| {
                    CampaignRepositoryError::Ram(
                        crucible_store::ram::RamStoreError::from_admission(original, source),
                    )
                })
            };
            verify()?;
            boundary().map_err(CampaignRepositoryError::Ram)?;
            verify()
        };
        let _publication = self.acquire_gc_exclusion_guard()?;
        check()?;
        let current = self.refs.read_ref(&published)?;
        if current != Some(expected.content_id()) {
            return Err(CampaignRepositoryError::RefConflict { current });
        }

        for _ in 0..4 {
            check()?;
            let entropy_descriptor = original.reserve_descriptors(1).map_err(|source| {
                CampaignRepositoryError::Ram(crucible_store::ram::RamStoreError::from_admission(
                    original, source,
                ))
            })?;
            let claim = unique_archive_claim()?;
            drop(entropy_descriptor);
            match self
                .refs
                .compare_exchange(&claim, None, expected.content_id())?
            {
                RefCasOutcome::Advanced { next } if next == expected.content_id() => {
                    let lease = CampaignArchiveLease {
                        manifest: expected,
                        claim,
                        refs: Arc::clone(&self.refs),
                        _credit: credit,
                    };
                    check()?;
                    return Ok(lease);
                }
                RefCasOutcome::Conflict { .. } => continue,
                _ => return Err(integrity("campaign-archive-reader-receipt-mismatch")),
            }
        }
        Err(integrity("campaign-archive-reader-ownership-collision"))
    }
}

fn unique_archive_claim() -> Result<RefName, StoreError> {
    let path = Path::new("/dev/urandom");
    let mut nonce = [0_u8; 32];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut nonce))
        .map_err(|source| StoreError::Io {
            operation: "read-archive-reader-ownership-token",
            path: path.to_path_buf(),
            source,
        })?;
    let mut claim = String::with_capacity(READER_NAME_BYTES);
    claim.push_str(READER_PREFIX);
    claim.push_str(blake3::hash(&nonce).to_hex().as_str());
    RefName::new(claim)
}
