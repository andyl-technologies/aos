//! Protected consumer interest for one exact native Storage issuance.
//!
//! ```text
//! storage-native-issuance.journal, AuthorityPublication
//! key = provider-id[16] | acquisition-id[32]
//! value = AOSNSI01 | version:u16be=1 | reserved[6]=0 |
//!         provider-terminal-digest[32] | cleanup-digest[32] |
//!         request-length:u32be | acceptance-length:u32be |
//!         canonical-signed-native-request-v2 | canonical-native-acceptance-v3
//! ```
//!
//! Both terminal digests are zero for an active interest and nonzero for its
//! exact retirement. Tombstones retain the original request and acceptance;
//! neither timeout nor missing descriptor custody implicitly releases a hold.
//! This journal is separate from the primary Storage catalog so acceptance
//! cannot change the receipt head that it commits. Its writer is acquired after
//! the primary Storage and workspace writers and retained by the same runtime.
//! The framed value accepts only AOSZNA03 acceptance bytes. Unreleased V2
//! acceptance rows fail closed on replay and are never silently rewritten.
//!
//! Production admission requires authenticated intent and a live original
//! descriptor under the held final cut; cleanup remains closed. A shaped request or
//! acceptance is not proof of authorization, currentness, or descriptor custody.
//! No method here signs a receipt, transfers an FD, or opens Acquire.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use aos_sandbox::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2, STORAGE_NATIVE_ACCEPTANCE_BYTES_V3,
    SignedStorageNativeAcquireRequestV2, StorageNativeAcceptanceV3, ZfsHeldSnapshotProofV1,
};
use sha2::{Digest as _, Sha256};

use crate::broker::{StorageHeldSnapshotCatalogCutV1, StorageHeldSnapshotSelectorV1};
use crate::live_export_request_trust::{
    AuthenticatedStorageNativeAcceptanceReadbackQueryV1, AuthenticatedStorageNativeRequestV2,
};
use crate::runtime::StorageHeldSnapshotReadbackWithMountV1;
use crate::{CatalogPlanV1, StorageAdmissionCoordinator};
use aos_sandbox_source_provider_protocol::StorageNativeAcquireReplyV3;

const JOURNAL_FILE: &str = "storage-native-issuance.journal";
const MAGIC: &[u8; 8] = b"AOSNSI01";
const HEADER_BYTES: usize = 88;
const MAXIMUM_VALUE_BYTES: usize = HEADER_BYTES
    + MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2
    + STORAGE_NATIVE_ACCEPTANCE_BYTES_V3;
const MAXIMUM_ISSUANCES: usize = 1024;
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.storage.native-issuance.transaction.v1\0";

pub(crate) mod held_completion;
mod held_custody;

/// Rejects malformed, stale, conflicting, or indeterminate issuance state.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StorageNativeIssuanceErrorV1 {
    /// A record, its framing, or its retained binding is not canonical.
    #[error("Storage native issuance journal is noncanonical")]
    Noncanonical,
    /// A retained acquisition, attempt, challenge, or issuance identity differs.
    #[error("Storage native issuance conflicts with retained consumer identity")]
    Conflict,
    /// The held final cut or durable native hold lineage changed.
    #[error("Storage native issuance no longer names the exact active hold")]
    StaleHold,
    /// At least one exact consumer still retains this physical hold.
    #[error("Storage native consumer interest excludes ReleaseHold")]
    HoldInUse,
    /// Protected custody, capacity, append, or recovery failed closed.
    #[error("Storage native issuance journal failed: {0}")]
    Journal(#[from] JournalError),
    /// Same-parser history retained the first cause and any final bookend debt.
    #[error(transparent)]
    History(#[from] aos_sandbox::StorageNativeIssuanceHistoryErrorV1),
    /// The sole mixed reducer rejected canonical history or continuation geometry.
    #[error(transparent)]
    Held(Box<held_completion::StorageHeldCompletionErrorV1>),
    /// Independently held current role pins could not authenticate an archive.
    #[error(transparent)]
    Trust(#[from] crate::live_export_request_trust::StorageLiveExportRequestTrustErrorV1),
    /// The dedicated original signing credential changed.
    #[error(transparent)]
    Credential(Box<crate::service::StorageServiceError>),
    /// Bounded retention could not reserve its actual bytes.
    #[error(transparent)]
    Allocation(#[from] std::collections::TryReserveError),
    /// Validation refused first and the same writer also failed its final bookend.
    #[error("native issuance validation failed: {primary}; final custody also failed: {bookend}")]
    HeldBookend {
        #[source]
        primary: Box<StorageNativeIssuanceErrorV1>,
        bookend: JournalError,
    },
}

impl From<held_completion::StorageHeldCompletionErrorV1> for StorageNativeIssuanceErrorV1 {
    fn from(cause: held_completion::StorageHeldCompletionErrorV1) -> Self {
        Self::Held(Box::new(cause))
    }
}

/// Distinguishes a durable new row from an exact replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IssuanceCommitOutcomeV1 {
    Recorded,
    ExactReplay,
}

/// Seals an owner-verified live request, acceptance, and current catalog cut.
///
/// Only owner admission seals authenticated intent and a measured original
/// descriptor under the runtime's final Storage cut. Private fields prevent
/// callers from promoting protocol-shaped bytes to this token.
struct PreparedStorageNativeIssuanceV1 {
    row: NativeIssuanceRowV1,
    cut: StorageHeldSnapshotCatalogCutV1,
}

/// Seals the exact joined Provider terminal record and cleanup authority.
///
/// Production construction remains closed until protected Provider recovery
/// supplies authenticated release/cleanup for this original acceptance. In
/// particular, descriptor loss, expiration, and scalar caller flags cannot
/// construct this token.
struct PreparedStorageNativeRetirementV1 {
    original: NativeIssuanceRowV1,
    provider_terminal_digest: ObjectDigest,
    cleanup_digest: ObjectDigest,
}

/// Retains one protected historical metadata observation without live authority.
///
/// Only the issuance owner constructs this projection. Found may name an active
/// or tombstoned row; NotFound is transient and does not fence future admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StorageNativeAcceptanceMetadataV1 {
    query_digest: ObjectDigest,
    issuance_sequence: u64,
    acceptance: Option<StorageNativeAcceptanceV3>,
}

impl StorageNativeAcceptanceMetadataV1 {
    /// Returns the diagnostic sequence of the retained issuance writer.
    pub(crate) const fn sequence(&self) -> u64 {
        self.issuance_sequence
    }

    /// Returns immutable unsigned acceptance metadata, including tombstones.
    pub(crate) fn acceptance(&self) -> Option<&StorageNativeAcceptanceV3> {
        self.acceptance.as_ref()
    }

    /// Checks exact signed metadata intent, not historical Acquire validity.
    pub(crate) fn matches_query(
        &self,
        authenticated: &AuthenticatedStorageNativeAcceptanceReadbackQueryV1<'_>,
    ) -> bool {
        self.query_digest == authenticated.query().digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeIssuanceRowV1 {
    request: SignedStorageNativeAcquireRequestV2,
    acceptance: StorageNativeAcceptanceV3,
    retirement: Option<(ObjectDigest, ObjectDigest)>,
}

#[derive(Default)]
struct NativeIssuanceIdentityIndexV1 {
    issuance_ids: BTreeSet<[u8; 16]>,
    challenges: BTreeSet<([u8; 16], [u8; 32])>,
    attempts: BTreeSet<([u8; 16], [u8; 32])>,
    requests: BTreeSet<[u8; 32]>,
}

impl NativeIssuanceIdentityIndexV1 {
    // Recovery and admission share one non-recycling policy. Retired rows
    // deliberately remain in the index; terminal cleanup is not nonce reuse.
    fn insert(&mut self, row: &NativeIssuanceRowV1) -> Result<(), StorageNativeIssuanceErrorV1> {
        let claims = row.request.request().claims();
        let provider = claims.provider_acquisition().0;
        let (challenge, attempt) = claims.attempt();
        if !self.issuance_ids.insert(row.acceptance.issuance_id())
            || !self.challenges.insert((provider, challenge))
            || !self.attempts.insert((provider, *attempt.as_bytes()))
            || !self.requests.insert(*row.request.digest().as_bytes())
        {
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        Ok(())
    }
}

impl NativeIssuanceRowV1 {
    fn key(&self) -> [u8; 48] {
        let (provider, acquisition) = self.request.request().claims().provider_acquisition();
        let mut key = [0; 48];
        key[..16].copy_from_slice(&provider);
        key[16..].copy_from_slice(acquisition.as_bytes());
        key
    }

    fn native_claim(&self) -> Result<ZfsHeldSnapshotProofV1, StorageNativeIssuanceErrorV1> {
        let claims = self.request.request().claims();
        let catalog = claims.catalog();
        let (_, snapshot) = catalog
            .select_under_head(
                catalog.generation(),
                catalog.digest(),
                catalog.namespace_digest(),
                claims.selection().0,
            )
            .map_err(|_| StorageNativeIssuanceErrorV1::Noncanonical)?;
        Ok(snapshot)
    }

    fn validate(&self) -> Result<(), StorageNativeIssuanceErrorV1> {
        if self.acceptance.request_digest() != self.request.digest()
            || self.retirement.is_some_and(|(terminal, cleanup)| {
                terminal.as_bytes() == &[0; 32] || cleanup.as_bytes() == &[0; 32]
            })
        {
            return Err(StorageNativeIssuanceErrorV1::Noncanonical);
        }
        self.native_claim()?;
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, StorageNativeIssuanceErrorV1> {
        self.validate()?;
        let request = self.request.to_canonical_bytes();
        let acceptance = self.acceptance.to_canonical_bytes();
        let length = HEADER_BYTES
            .checked_add(request.len())
            .and_then(|length| length.checked_add(acceptance.len()))
            .filter(|length| *length <= MAXIMUM_VALUE_BYTES)
            .ok_or(StorageNativeIssuanceErrorV1::Noncanonical)?;
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        let (terminal, cleanup) = self.retirement.unwrap_or((
            ObjectDigest::from_bytes([0; 32]),
            ObjectDigest::from_bytes([0; 32]),
        ));
        bytes.extend_from_slice(terminal.as_bytes());
        bytes.extend_from_slice(cleanup.as_bytes());
        bytes.extend_from_slice(&(request.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(acceptance.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&request);
        bytes.extend_from_slice(&acceptance);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, StorageNativeIssuanceErrorV1> {
        if bytes.len() < HEADER_BYTES
            || bytes.len() > MAXIMUM_VALUE_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes.get(10..16) != Some([0; 6].as_slice())
        {
            return Err(StorageNativeIssuanceErrorV1::Noncanonical);
        }
        let terminal = ObjectDigest::from_bytes(array(bytes, 16)?);
        let cleanup = ObjectDigest::from_bytes(array(bytes, 48)?);
        let request_length = u32::from_be_bytes(array(bytes, 80)?) as usize;
        let acceptance_length = u32::from_be_bytes(array(bytes, 84)?) as usize;
        let request_end = HEADER_BYTES
            .checked_add(request_length)
            .ok_or(StorageNativeIssuanceErrorV1::Noncanonical)?;
        if request_end.checked_add(acceptance_length) != Some(bytes.len())
            || (terminal.as_bytes() == &[0; 32]) != (cleanup.as_bytes() == &[0; 32])
        {
            return Err(StorageNativeIssuanceErrorV1::Noncanonical);
        }
        let row = Self {
            request: SignedStorageNativeAcquireRequestV2::from_canonical_bytes(
                bytes
                    .get(HEADER_BYTES..request_end)
                    .ok_or(StorageNativeIssuanceErrorV1::Noncanonical)?,
            )
            .map_err(|_| StorageNativeIssuanceErrorV1::Noncanonical)?,
            acceptance: StorageNativeAcceptanceV3::from_canonical_bytes(
                bytes
                    .get(request_end..)
                    .ok_or(StorageNativeIssuanceErrorV1::Noncanonical)?,
            )
            .map_err(|_| StorageNativeIssuanceErrorV1::Noncanonical)?,
            retirement: (terminal.as_bytes() != &[0; 32]).then_some((terminal, cleanup)),
        };
        if row.encode()? != bytes {
            return Err(StorageNativeIssuanceErrorV1::Noncanonical);
        }
        Ok(row)
    }

    fn retired(&self, terminal: ObjectDigest, cleanup: ObjectDigest) -> Self {
        Self {
            retirement: Some((terminal, cleanup)),
            ..self.clone()
        }
    }

    fn transaction(&self) -> Result<JournalTransaction, StorageNativeIssuanceErrorV1> {
        let key = self.key();
        let value = self.encode()?;
        let digest = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(key)
            .chain_update(&value)
            .finalize();
        Ok(JournalTransaction::new(
            digest[..16]
                .try_into()
                .map_err(|_| StorageNativeIssuanceErrorV1::Noncanonical)?,
            vec![JournalRecord::put(
                RecordNamespace::AuthorityPublication,
                key.to_vec(),
                value,
            )],
        )?)
    }
}

/// Owns the exclusive, separate Storage consumer-interest writer.
pub(crate) struct StorageNativeIssuanceLedgerV1 {
    journal: Journal,
    state_directory: PathBuf,
    custody: NativeIssuanceCustodyV1,
}

enum NativeIssuanceCustodyV1 {
    RootOwned,
    // Selected only by the actual original-startup construction attempt.
    RootOwnedHeld,
    #[cfg(test)]
    UidFixture {
        device: u64,
        inode: u64,
    },
}

impl StorageNativeIssuanceLedgerV1 {
    /// Observes exact original metadata without reviving a retired acquisition.
    ///
    /// Historical holder and signed request bytes are immutable. An occupied
    /// Provider/acquisition key with different claims is a conflict, never a
    /// negative lookup. No original expiry, receipt, hold, or FD is renewed.
    ///
    /// # Errors
    ///
    /// Rejects changed current query trust, unsafe or poisoned journal custody,
    /// noncanonical retained state, or an occupied-key scope/digest conflict.
    pub(crate) fn readback_acceptance(
        &mut self,
        authenticated: &AuthenticatedStorageNativeAcceptanceReadbackQueryV1<'_>,
    ) -> Result<StorageNativeAcceptanceMetadataV1, StorageNativeIssuanceErrorV1> {
        authenticated
            .recheck()
            .map_err(|_| StorageNativeIssuanceErrorV1::Noncanonical)?;
        self.validate_boundary()?;
        let signed = authenticated.query();
        let query = signed.query();
        let (provider, holder, acquisition) = query.scope();
        let mut acceptance = None;
        for row in self.rows()? {
            let claims = row.request.request().claims();
            if claims.provider_acquisition() != (provider, acquisition) {
                continue;
            }
            if claims.holder_session().0 != holder || row.request.digest() != query.request_digest()
            {
                return Err(StorageNativeIssuanceErrorV1::Conflict);
            }
            acceptance = Some(row.acceptance);
        }

        authenticated
            .recheck()
            .map_err(|_| StorageNativeIssuanceErrorV1::Noncanonical)?;
        self.validate_boundary()?;
        Ok(StorageNativeAcceptanceMetadataV1 {
            query_digest: signed.digest(),
            issuance_sequence: self.journal.snapshot_sequence(),
            acceptance,
        })
    }

    /// Checks retained identity before any physical measurement or remount.
    ///
    /// # Errors
    ///
    /// Rejects unsafe custody or a conflicting/retired original acquisition.
    pub(crate) fn retained_acceptance(
        &mut self,
        request: &SignedStorageNativeAcquireRequestV2,
    ) -> Result<Option<StorageNativeAcceptanceV3>, StorageNativeIssuanceErrorV1> {
        self.validate_boundary()?;
        let (provider, acquisition) = request.request().claims().provider_acquisition();
        for row in self.rows()? {
            if row.request.request().claims().provider_acquisition() == (provider, acquisition) {
                if row.request != *request || row.retirement.is_some() {
                    return Err(StorageNativeIssuanceErrorV1::Conflict);
                }
                return Ok(Some(row.acceptance));
            }
        }
        Ok(None)
    }

    /// Mints admission only from authenticated claims and the measured original FD.
    ///
    /// # Errors
    ///
    /// Rejects changed signed intent, descriptor, held cut, capacity, or durable readback.
    pub(crate) fn accept_live(
        &mut self,
        authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
        held: &StorageHeldSnapshotReadbackWithMountV1,
        reply: &StorageNativeAcquireReplyV3,
        current: &StorageHeldSnapshotCatalogCutV1,
    ) -> Result<(), StorageNativeIssuanceErrorV1> {
        authenticated
            .recheck()
            .map_err(|_| StorageNativeIssuanceErrorV1::Noncanonical)?;
        let descriptor = held
            .observe_root()
            .map_err(|_| StorageNativeIssuanceErrorV1::StaleHold)?;
        let acceptance = reply.acceptance().acceptance();
        if acceptance.request_digest() != authenticated.request().digest()
            || acceptance.receipt_digest() != reply.receipt().digest()
            || acceptance.descriptor() != &descriptor
        {
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        let prepared = PreparedStorageNativeIssuanceV1 {
            row: NativeIssuanceRowV1 {
                request: authenticated.request().clone(),
                acceptance: acceptance.clone(),
                retirement: None,
            },
            cut: held.readback.cut.clone(),
        };
        self.accept(&prepared, current)?;
        if self.retained_acceptance(authenticated.request())?.as_ref() != Some(acceptance) {
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        Ok(())
    }

    /// Opens and validates retained exact interests without issuing authority.
    ///
    /// # Errors
    ///
    /// Rejects unsafe writer custody, malformed/foreign records, equivocation,
    /// or insufficient reserved capacity to retire every active consumer.
    pub(crate) fn open_root_owned(
        state_directory: &Path,
    ) -> Result<Self, StorageNativeIssuanceErrorV1> {
        let journal =
            Journal::open_protected_at(state_directory, JOURNAL_FILE, journal_limits())?.0;
        Self::from_journal(journal, state_directory, NativeIssuanceCustodyV1::RootOwned)
    }

    /// Retains existing native custody without creating names or repairing a tail.
    pub(crate) fn open_existing_root_owned(
        state_directory: &Path,
    ) -> Result<Self, StorageNativeIssuanceErrorV1> {
        let journal = Journal::open_existing_protected_at(
            state_directory,
            JOURNAL_FILE,
            journal_limits(),
        )?.0;
        Self::from_journal(journal, state_directory, NativeIssuanceCustodyV1::RootOwned)
    }

    /// Rechecks the complete retained native rows and the same writer's exact cut.
    pub(crate) fn operator_terminal_readback_cut_v4(
        &mut self,
    ) -> Result<(u64, ObjectDigest), StorageNativeIssuanceErrorV1> {
        self.validate_boundary()?;
        if self.uses_original_held_route() {
            self.held_offer_funding()?;
        } else {
            let rows = self.rows()?;
            self.preflight_retirements(&rows, None)?;
        }

        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.operator-repair-native-cut.v4\0");
        digest.update(self.journal.snapshot_sequence().to_be_bytes());
        for (namespace, key, value) in self.journal.all_records() {
            digest.update((namespace as u16).to_be_bytes());
            digest.update((key.len() as u64).to_be_bytes());
            digest.update(key);
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }
        Ok((
            self.journal.snapshot_sequence(),
            ObjectDigest::from_bytes(digest.finalize().into()),
        ))
    }

    fn from_journal(
        journal: Journal,
        state_directory: &Path,
        custody: NativeIssuanceCustodyV1,
    ) -> Result<Self, StorageNativeIssuanceErrorV1> {
        let mut owner = Self {
            journal,
            state_directory: state_directory.to_path_buf(),
            custody,
        };
        owner.validate_boundary()?;
        let rows = owner.rows()?;
        owner.preflight_retirements(&rows, None)?;
        Ok(owner)
    }

    fn validate_boundary(&mut self) -> Result<(), StorageNativeIssuanceErrorV1> {
        match self.custody {
            NativeIssuanceCustodyV1::RootOwned | NativeIssuanceCustodyV1::RootOwnedHeld => self
                .journal
                .validate_held_root_owned_at(&self.state_directory, JOURNAL_FILE)?,
            #[cfg(test)]
            NativeIssuanceCustodyV1::UidFixture { device, inode } => {
                use std::os::unix::fs::MetadataExt as _;
                let current = std::fs::symlink_metadata(&self.state_directory)
                    .map_err(|_| StorageNativeIssuanceErrorV1::Noncanonical)?;
                if !current.is_dir() || current.dev() != device || current.ino() != inode {
                    return Err(StorageNativeIssuanceErrorV1::Noncanonical);
                }
                self.journal.validate_held_protected_names()?;
            }
        }
        let _authority = self
            .journal
            .claim_protected_authority(RecordNamespace::AuthorityPublication)?;
        Ok(())
    }

    fn rows(&self) -> Result<Vec<NativeIssuanceRowV1>, StorageNativeIssuanceErrorV1> {
        if matches!(self.custody, NativeIssuanceCustodyV1::RootOwnedHeld) {
            return self.held_original_rows();
        }
        self.journal.ensure_healthy()?;
        let mut rows = Vec::new();
        let mut identities = NativeIssuanceIdentityIndexV1::default();
        for (namespace, key, bytes) in self.journal.all_records() {
            if namespace != RecordNamespace::AuthorityPublication || rows.len() >= MAXIMUM_ISSUANCES
            {
                return Err(StorageNativeIssuanceErrorV1::Noncanonical);
            }
            let row = NativeIssuanceRowV1::decode(bytes)?;
            if key != row.key() {
                return Err(StorageNativeIssuanceErrorV1::Conflict);
            }
            identities.insert(&row)?;
            rows.push(row);
        }
        Ok(rows)
    }

    fn preflight_retirements(
        &self,
        rows: &[NativeIssuanceRowV1],
        transition: Option<JournalTransaction>,
    ) -> Result<(), StorageNativeIssuanceErrorV1> {
        let mut transactions = transition.into_iter().collect::<Vec<_>>();
        // Retirement replaces exactly two fixed-size digest fields. Their
        // future authenticated values cannot increase any frame or retained
        // record bound. Preflighting ALL interests reserves every future
        // cleanup even when subsequent admissions or exact replays occur.
        for row in rows.iter().filter(|row| row.retirement.is_none()) {
            transactions.push(
                row.retired(
                    ObjectDigest::from_bytes([0xA1; 32]),
                    ObjectDigest::from_bytes([0xA2; 32]),
                )
                .transaction()?,
            );
        }
        self.journal.preflight_transactions(&transactions)?;
        Ok(())
    }

    fn accept(
        &mut self,
        prepared: &PreparedStorageNativeIssuanceV1,
        current: &StorageHeldSnapshotCatalogCutV1,
    ) -> Result<IssuanceCommitOutcomeV1, StorageNativeIssuanceErrorV1> {
        if self.uses_original_held_route() {
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        self.validate_boundary()?;
        if prepared.row.retirement.is_some() {
            return Err(StorageNativeIssuanceErrorV1::Noncanonical);
        }
        prepared
            .cut
            .ensure_unchanged(current)
            .map_err(|_| StorageNativeIssuanceErrorV1::StaleHold)?;
        validate_hold_cut(&prepared.row, current)?;
        let mut rows = self.rows()?;
        if let Some(previous) = rows.iter().find(|row| row.key() == prepared.row.key()) {
            return if previous == &prepared.row {
                Ok(IssuanceCommitOutcomeV1::ExactReplay)
            } else {
                Err(StorageNativeIssuanceErrorV1::Conflict)
            };
        }
        reject_identity_reuse(&rows, &prepared.row)?;
        if rows.len() >= MAXIMUM_ISSUANCES {
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        rows.push(prepared.row.clone());
        let transaction = prepared.row.transaction()?;
        self.preflight_retirements(&rows, Some(transaction.clone()))?;
        self.commit_row(&prepared.row, transaction)?;
        Ok(IssuanceCommitOutcomeV1::Recorded)
    }

    fn retire(
        &mut self,
        proof: &PreparedStorageNativeRetirementV1,
    ) -> Result<IssuanceCommitOutcomeV1, StorageNativeIssuanceErrorV1> {
        if self.uses_original_held_route() {
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        self.validate_boundary()?;
        if proof.original.retirement.is_some() {
            return Err(StorageNativeIssuanceErrorV1::Noncanonical);
        }
        let retired = proof
            .original
            .retired(proof.provider_terminal_digest, proof.cleanup_digest);
        let mut rows = self.rows()?;
        let previous = rows
            .iter_mut()
            .find(|row| row.key() == retired.key())
            .ok_or(StorageNativeIssuanceErrorV1::Conflict)?;
        if previous == &retired {
            return Ok(IssuanceCommitOutcomeV1::ExactReplay);
        }
        if previous != &proof.original {
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        *previous = retired.clone();
        let transaction = retired.transaction()?;
        self.preflight_retirements(&rows, Some(transaction.clone()))?;
        self.commit_row(&retired, transaction)?;
        Ok(IssuanceCommitOutcomeV1::Recorded)
    }

    fn commit_row(
        &mut self,
        row: &NativeIssuanceRowV1,
        transaction: JournalTransaction,
    ) -> Result<(), StorageNativeIssuanceErrorV1> {
        self.validate_boundary()?;
        self.journal
            .claim_protected_authority(RecordNamespace::AuthorityPublication)?
            .commit(&transaction)?;

        self.validate_boundary()?;
        if self
            .journal
            .get(RecordNamespace::AuthorityPublication, &row.key())
            != Some(row.encode()?.as_slice())
        {
            return Err(StorageNativeIssuanceErrorV1::Noncanonical);
        }
        Ok(())
    }

    /// Validates every active interest under the retained primary writer.
    ///
    /// # Errors
    ///
    /// Rejects poisoned history, absent/released holds, changed native lineage,
    /// or changed authenticated root policy. FD loss cannot retire an interest.
    pub(crate) fn validate_active_holds(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
    ) -> Result<(), StorageNativeIssuanceErrorV1> {
        self.validate_boundary()?;
        for row in self.rows()?.iter().filter(|row| row.retirement.is_none()) {
            let selector = StorageHeldSnapshotSelectorV1::from_native_claim(&row.native_claim()?)
                .map_err(|_| StorageNativeIssuanceErrorV1::StaleHold)?;
            let cut = coordinator
                .held_snapshot_catalog_cut(selector)
                .map_err(|_| StorageNativeIssuanceErrorV1::StaleHold)?;
            validate_hold_cut(row, &cut)?;
        }
        Ok(())
    }

    /// Excludes physical ReleaseHold while any exact consumer remains active.
    ///
    /// The runtime retains both journal writers across this check and dispatch.
    /// GUID/hold matching deliberately ignores handle/name aliases: an alias
    /// cannot release the same physical hold around an active consumer row.
    ///
    /// # Errors
    ///
    /// Rejects unsafe journal custody or an active interest on the physical hold.
    pub(crate) fn check_release(
        &mut self,
        plan: &CatalogPlanV1,
    ) -> Result<(), StorageNativeIssuanceErrorV1> {
        self.validate_boundary()?;
        let CatalogPlanV1::ReleaseHold { snapshot, hold_id } = plan else {
            return Ok(());
        };
        for row in self.rows()?.iter().filter(|row| row.retirement.is_none()) {
            let claim = row.native_claim()?;
            if claim.dataset_guid() == snapshot.dataset().guid()
                && claim.snapshot_guid() == snapshot.guid()
                && claim.hold_id() == hold_id.as_bytes()
            {
                return Err(StorageNativeIssuanceErrorV1::HoldInUse);
            }
        }
        Ok(())
    }
}

fn validate_hold_cut(
    row: &NativeIssuanceRowV1,
    cut: &StorageHeldSnapshotCatalogCutV1,
) -> Result<(), StorageNativeIssuanceErrorV1> {
    if !cut.matches_native_journal_claim(&row.native_claim()?) {
        return Err(StorageNativeIssuanceErrorV1::StaleHold);
    }
    Ok(())
}

fn reject_identity_reuse(
    rows: &[NativeIssuanceRowV1],
    proposed: &NativeIssuanceRowV1,
) -> Result<(), StorageNativeIssuanceErrorV1> {
    let mut identities = NativeIssuanceIdentityIndexV1::default();
    for row in rows {
        identities.insert(row)?;
    }
    identities.insert(proposed)
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], StorageNativeIssuanceErrorV1> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(N)
                    .ok_or(StorageNativeIssuanceErrorV1::Noncanonical)?,
        )
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(StorageNativeIssuanceErrorV1::Noncanonical)
}

fn journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 256 * 1024 * 1024,
        maximum_record_bytes: MAXIMUM_VALUE_BYTES + 128,
        maximum_key_bytes: 48,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: MAXIMUM_VALUE_BYTES + 128,
        maximum_transactions: MAXIMUM_ISSUANCES * 2,
        maximum_materialized_bytes: 128 * 1024 * 1024,
        maximum_materialized_records: MAXIMUM_ISSUANCES,
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn native_request_fixture_for_test() -> (
    SignedStorageNativeAcquireRequestV2,
    StorageHeldSnapshotCatalogCutV1,
) {
    let prepared = tests::fixture(1, 2);
    (prepared.row.request, prepared.cut)
}

#[cfg(test)]
pub(crate) fn native_issuance_fixture_for_test(directory: &Path) -> StorageNativeIssuanceLedgerV1 {
    tests::open(directory, journal_limits()).unwrap()
}

#[cfg(test)]
pub(crate) fn try_native_issuance_fixture_for_test(
    directory: &Path,
) -> Result<StorageNativeIssuanceLedgerV1, StorageNativeIssuanceErrorV1> {
    tests::open(directory, journal_limits())
}

#[cfg(test)]
pub(crate) fn populate_native_metadata_fixture_for_test(
    owner: &mut StorageNativeIssuanceLedgerV1,
    retired: bool,
) -> (
    SignedStorageNativeAcquireRequestV2,
    StorageNativeAcceptanceV3,
) {
    let prepared = tests::fixture(1, 42);
    owner.accept(&prepared, &prepared.cut).unwrap();
    if retired {
        owner
            .retire(&PreparedStorageNativeRetirementV1 {
                original: prepared.row.clone(),
                provider_terminal_digest: ObjectDigest::from_bytes([40; 32]),
                cleanup_digest: ObjectDigest::from_bytes([41; 32]),
            })
            .unwrap();
    }
    (prepared.row.request, prepared.row.acceptance)
}

#[cfg(test)]
pub(crate) fn native_metadata_request_fixture_for_test() -> SignedStorageNativeAcquireRequestV2 {
    tests::fixture(1, 42).row.request
}

#[cfg(test)]
pub(crate) fn conflicting_native_request_fixture_for_test() -> SignedStorageNativeAcquireRequestV2 {
    tests::fixture(1, 3).row.request
}
