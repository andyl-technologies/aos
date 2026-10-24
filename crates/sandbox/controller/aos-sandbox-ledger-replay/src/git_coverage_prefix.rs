//! Shares canonical Git-prefix hashing and fixed catalog comparison DATA.
//!
//! Actual Domain and Mount owners keep their native parser, immutable writer
//! borrow, bookends, role semantics and financial originals. This module accepts
//! only already parsed transactions, coordinates and catalog DATA; it opens no
//! File, supplies no currentness or role factory, and issues no append grant.
//!
//! ```text
//! SHA256("aos.sandbox.git-upload.native-prefix.v1\0" || canonical native frames)
//! ```

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;
use aos_sandbox_model::format::git_upload_enrollment::{
    GitCoverageBirthV1, GitCoverageCatalogV1, GitCoverageFenceV1, GitCoverageJournalProfileV1,
    MAXIMUM_COVERAGE_OWNERS_V1,
};
use aos_sandbox_model::{ObjectDigest, RecordNamespace};
use aos_sandbox_protocol::domain_ledger::transaction::{
    JournalTransaction, encode_transaction, encoded_transaction_append_bytes,
};
use sha2::{Digest as _, Sha256};

const PREFIX_DOMAIN: &[u8] = b"aos.sandbox.git-upload.native-prefix.v1\0";

/// Compares fixed Cache policy and Clock history DATA.
pub mod cache;

mod mount_cleanup;
pub use mount_cleanup::require_mount_original_source_cleanup_v1;

/// Accumulates only the original canonical prefix's hash and coordinates.
///
/// Native callers validate coordinates first, run their existing role/catalog
/// checks, then finish that same actual transaction. These are DATA operations,
/// not independently usable native or authority completion.
pub struct GitCoverageNativePrefixDataV1 {
    digest: Sha256,
    next_sequence: u64,
    end_offset: u64,
    transactions: usize,
    records: usize,
    last_transaction: Option<[u8; 16]>,
    last_commit_sequence: Option<u64>,
}

impl GitCoverageNativePrefixDataV1 {
    /// Creates the original empty-prefix hash and initial coordinates.
    #[must_use]
    pub fn new() -> Self {
        Self {
            digest: Sha256::new().chain_update(PREFIX_DOMAIN),
            next_sequence: 1,
            end_offset: 0,
            transactions: 0,
            records: 0,
            last_transaction: None,
            last_commit_sequence: None,
        }
    }

    /// Compares actual BEGIN/COMMIT/offset coordinates before role predicates.
    ///
    /// # Errors
    /// Preserves compaction, discontinuity, width and overflow refusals.
    pub fn validate_transaction_v1(
        &self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), CanonicalJournalMechanicalErrorV1> {
        // Compaction is not an original native history, even when its current
        // map happens to preserve all coverage values and logical sequences.
        if transaction.id()[8..] == *b"compact1"
            || begin_sequence != self.next_sequence
            || begin_offset != self.end_offset
        {
            return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
        }
        let append_bytes = encoded_transaction_append_bytes(transaction)?;
        if begin_offset.checked_add(append_bytes) != Some(end_offset)
            || begin_sequence
                .checked_add(transaction.records().len() as u64)
                .and_then(|sequence| sequence.checked_add(1))
                != Some(commit_sequence)
        {
            return Err(CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot);
        }

        Ok(())
    }

    /// Hashes the same validated transaction after its original role checks.
    ///
    /// An optional catalog is the actual catalog transaction selected by the
    /// caller's original closed recipe. Its prefix advances at the original
    /// pre-counter frontier. No role, File or callback enters this DATA engine.
    /// # Errors
    /// Preserves the sole encoder and original sequence/count overflow errors.
    pub fn finish_transaction_v1(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        end_offset: u64,
        catalog: Option<&mut GitCoverageFixedCatalogDataV1<'_>>,
    ) -> Result<(), CanonicalJournalMechanicalErrorV1> {
        // Reuse the sole encoder after the sole parser's complete transaction
        // validation. These bounded temporary frames are ordinary allocation,
        // not funded retained storage or a second serialization engine.
        let frames = encode_transaction(transaction, begin_sequence)?;
        for frame in frames {
            self.digest.update(frame);
        }
        if let Some(catalog) = catalog {
            catalog.prefix = self.digest.clone().finalize().into();
        }
        self.next_sequence = commit_sequence
            .checked_add(1)
            .ok_or(CanonicalJournalMechanicalErrorV1::SequenceExhausted)?;
        self.end_offset = end_offset;
        self.transactions = self.transactions.checked_add(1).ok_or(
            CanonicalJournalMechanicalErrorV1::LimitExceeded("coverage native transactions"),
        )?;
        self.records = self
            .records
            .checked_add(transaction.records().len())
            .ok_or(CanonicalJournalMechanicalErrorV1::LimitExceeded(
                "coverage native records",
            ))?;
        self.last_transaction = Some(*transaction.id());
        self.last_commit_sequence = Some(commit_sequence);
        Ok(())
    }

    /// Borrows the existing prefix hash as comparison DATA without advancing it.
    #[must_use]
    pub fn prefix_digest_v1(&self) -> [u8; 32] {
        self.digest.clone().finalize().into()
    }

    /// Returns the validated transaction and record counts.
    #[must_use]
    pub fn counts_v1(&self) -> (usize, usize) {
        (self.transactions, self.records)
    }

    /// Returns the last completely observed UUID and COMMIT, when present.
    #[must_use]
    pub fn last_commit_v1(&self) -> Option<([u8; 16], u64)> {
        self.last_transaction.zip(self.last_commit_sequence)
    }

    /// Compares the completed counters with the native owner's actual replay.
    ///
    /// The caller separately joins all materialized native fields and bookends.
    /// # Errors
    /// Refuses any byte, sequence, transaction or record-count mismatch.
    pub fn require_complete_v1(
        &self,
        physical_bytes: u64,
        next_sequence: u64,
        transactions: usize,
        records: usize,
    ) -> Result<(), CanonicalJournalMechanicalErrorV1> {
        if self.end_offset != physical_bytes
            || self.next_sequence != next_sequence
            || self.transactions != transactions
            || self.records != records
        {
            return Err(CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Consumes the original final prefix hash without changing its bytes.
    #[must_use]
    pub fn into_digest_v1(self) -> [u8; 32] {
        self.digest.finalize().into()
    }
}

impl Default for GitCoverageNativePrefixDataV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Compares fixed catalog PUTs and the original prebirth prefix.
///
/// Each genuine fixed owner runs its existing semantic validator separately.
/// This compares UUID/PUT/order and prefix DATA without interpreting partition
/// state or granting owner authority.
pub struct GitCoverageFixedCatalogDataV1<'data> {
    catalog: &'data GitCoverageCatalogV1<'data>,
    profile: GitCoverageJournalProfileV1,
    records: [usize; MAXIMUM_COVERAGE_OWNERS_V1],
    prefix: [u8; 32],
}

// Publisher admission and runtime/output namespaces reside in the same actual
// Controller journal. They retain distinct signed members and attribution;
// this closed table shares only their physical native-prefix comparison.
fn belongs_to_catalog_writer(
    writer: GitCoverageJournalProfileV1,
    member: GitCoverageJournalProfileV1,
) -> bool {
    writer.is_native_writer_member_v1(member)
}

impl<'data> GitCoverageFixedCatalogDataV1<'data> {
    /// Creates the original fixed-catalog comparison without native work.
    ///
    /// # Errors
    /// Preserves the existing nonpartition fixed-member lookup refusal.
    pub fn new(
        catalog: &'data GitCoverageCatalogV1<'data>,
        profile: GitCoverageJournalProfileV1,
    ) -> Result<Self, CanonicalJournalMechanicalErrorV1> {
        if !profile.is_partition_owned() {
            catalog
                .fixed_member(profile, [0; 32])
                .map_err(|_| CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
        }
        Ok(Self {
            catalog,
            profile,
            records: [0; MAXIMUM_COVERAGE_OWNERS_V1],
            prefix: Sha256::new().chain_update(PREFIX_DOMAIN).finalize().into(),
        })
    }

    /// Borrows the same signed catalog as comparison DATA.
    #[must_use]
    pub fn catalog_v1(&self) -> &'data GitCoverageCatalogV1<'data> {
        self.catalog
    }

    /// Returns the original physical writer's catalog profile DATA.
    #[must_use]
    pub fn profile_v1(&self) -> GitCoverageJournalProfileV1 {
        self.profile
    }

    /// Compares the prebirth prefix before the native owner's Clock extension.
    #[must_use]
    pub fn catalogued_prefix_complete_v1(&self) -> bool {
        let has_member = self
            .catalog
            .members()
            .any(|member| belongs_to_catalog_writer(self.profile, member.profile()));
        let complete = has_member
            && self
                .catalog
                .members()
                .enumerate()
                .filter(|(_, member)| belongs_to_catalog_writer(self.profile, member.profile()))
                .all(|(index, member)| {
                    self.records.get(index).copied() == Some(member.infrastructure_count() as usize)
                        && member.predecessor_prefix() == self.prefix
                });
        complete
    }

    /// Compares actual PUT coordinates, attribution, namespace and value digests.
    ///
    /// The native caller runs its Clock/role extension first, where applicable.
    /// # Errors
    /// Preserves the original catalog, duplicate, sequence and count failures.
    pub fn observe_transaction_v1(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
    ) -> Result<(), CanonicalJournalMechanicalErrorV1> {
        // The initial logical state is entirely in each genuine checkpoint.
        // This first profile does not classify later durable state mutations
        // as infrastructure, even when a signed catalog names their bytes.
        if self.profile == GitCoverageJournalProfileV1::CacheState {
            return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
        }
        for (index, record) in transaction.records().iter().enumerate() {
            // Only the closed Clock recipe admits repeated provisioning-key
            // versions. An immutable bootstrap/authority/Genesis key cannot
            // hide an overwritten tenant value behind a later current map.
            if self.profile != GitCoverageJournalProfileV1::CacheClock
                && self
                    .catalog
                    .infrastructure()
                    .filter(|row| {
                        row.key() == record.key()
                            && self.catalog.members().any(|member| {
                                belongs_to_catalog_writer(self.profile, member.profile())
                                    && member.digest() == row.attribution()
                            })
                    })
                    .count()
                    != 1
            {
                return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
            }
            let sequence = begin_sequence
                .checked_add(index as u64)
                .and_then(|value| value.checked_add(1))
                .ok_or(CanonicalJournalMechanicalErrorV1::SequenceExhausted)?;
            let value = record
                .value()
                .ok_or(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
            let value_digest = ObjectDigest::from_bytes(Sha256::digest(value).into());
            let mut declared = self.catalog.infrastructure().filter(|row| {
                row.key() == record.key()
                    && row.transaction() == transaction.id()
                    && row.put_sequence() == sequence
                    && self.catalog.members().any(|member| {
                        belongs_to_catalog_writer(self.profile, member.profile())
                            && member.digest() == row.attribution()
                    })
            });
            let row = declared
                .next()
                .ok_or(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
            let member_index = self
                .catalog
                .members()
                .position(|member| {
                    belongs_to_catalog_writer(self.profile, member.profile())
                        && member.digest() == row.attribution()
                })
                .ok_or(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
            let member = self
                .catalog
                .members()
                .nth(member_index)
                .ok_or(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
            if declared.next().is_some()
                || !catalog_namespace_matches(member.profile(), record.namespace())
                || row.family() != 1
                || row.transaction() != transaction.id()
                || row.put_sequence() != sequence
                || row.value_digest() != value_digest.as_bytes()
            {
                return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
            }
            let count = self
                .records
                .get_mut(member_index)
                .ok_or(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
            *count =
                count
                    .checked_add(1)
                    .ok_or(CanonicalJournalMechanicalErrorV1::LimitExceeded(
                        "coverage fixed Cache records",
                    ))?;
        }
        Ok(())
    }

    /// Compares all catalogued members to the actual completed origin DATA.
    ///
    /// # Errors
    /// Refuses missing members, counts, prefix or original identity mismatch.
    pub fn require_complete_v1(
        &self,
        origin: [u8; 32],
    ) -> Result<(), CanonicalJournalMechanicalErrorV1> {
        let mut members = 0_usize;
        for (index, member) in self.catalog.members().enumerate() {
            if !belongs_to_catalog_writer(self.profile, member.profile()) {
                continue;
            }
            members = members
                .checked_add(1)
                .ok_or(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
            if self.records.get(index).copied() != Some(member.infrastructure_count() as usize)
                || member.predecessor_prefix() != self.prefix
                || member.provision_origin() != origin
            {
                return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
            }
        }
        if members == 0 {
            return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
        }
        Ok(())
    }
}

fn catalog_namespace_matches(
    profile: GitCoverageJournalProfileV1,
    namespace: RecordNamespace,
) -> bool {
    match profile {
        // The existing Controller constructor validates its fixed node
        // identity. Prior DesiredState is not empty-domain infrastructure:
        // operation/effect/admission state cannot be relabeled by a catalog.
        // The new denial pair is handled separately by the observer above.
        GitCoverageJournalProfileV1::Controller => namespace == RecordNamespace::ControllerIdentity,
        GitCoverageJournalProfileV1::PublisherAdmission => {
            namespace == RecordNamespace::PublisherPolicy
        }
        // Any actual runtime/output history is charged tenant state in the
        // first profile; a signed catalog cannot relabel it infrastructure.
        GitCoverageJournalProfileV1::RuntimeOutput => false,
        GitCoverageJournalProfileV1::RootAuthority
        | GitCoverageJournalProfileV1::RootPolicyState
        | GitCoverageJournalProfileV1::Source => namespace == RecordNamespace::DesiredState,
        GitCoverageJournalProfileV1::StorageCatalog => matches!(
            namespace,
            RecordNamespace::StorageCatalogTransition
                | RecordNamespace::StorageCatalogHead
                | RecordNamespace::StorageRuntimeConfiguration
        ),
        GitCoverageJournalProfileV1::StorageNative => {
            namespace == RecordNamespace::AuthorityPublication
        }
        GitCoverageJournalProfileV1::StorageWorkspace => {
            namespace == RecordNamespace::StorageResourceInventory
        }
        GitCoverageJournalProfileV1::StorageOutput => {
            namespace == RecordNamespace::StorageExecutionOutput
        }
        // These provisioning recipes use DesiredState. Their original owners
        // independently validate the complete value semantics and fixed keys.
        GitCoverageJournalProfileV1::Mount
        | GitCoverageJournalProfileV1::CacheBootstrap
        | GitCoverageJournalProfileV1::CacheAuthority
        | GitCoverageJournalProfileV1::CacheState
        | GitCoverageJournalProfileV1::CacheClock
        | GitCoverageJournalProfileV1::CachePolicyHold => {
            namespace == RecordNamespace::DesiredState
        }
        _ => false,
    }
}

/// Compares the sole birth/fence pair to its actual preceding native prefix.
///
/// This checks canonical DATA only and constructs no owner or mutation right.
/// # Errors
/// Preserves the original shape, codec, catalog and prefix mismatch refusal.
pub fn require_owner_fence_transaction_v1(
    profile: GitCoverageJournalProfileV1,
    transaction: &JournalTransaction,
    commit_sequence: u64,
    predecessor: [u8; 32],
    catalog: &GitCoverageCatalogV1<'_>,
) -> Result<(), CanonicalJournalMechanicalErrorV1> {
    let records = transaction.records();
    if records.len() != 2
        || records[0].namespace() != RecordNamespace::DesiredState
        || records[0].key() != b"z-git-birth-v1"
        || records[1].namespace() != RecordNamespace::DesiredState
        || records[1].key() != b"z-git-fence-v1"
    {
        return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
    }
    let birth = GitCoverageBirthV1::decode(
        records[0]
            .value()
            .ok_or(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?,
    )
    .map_err(|_| CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
    let fence = GitCoverageFenceV1::decode(
        records[1]
            .value()
            .ok_or(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?,
    )
    .map_err(|_| CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
    fence
        .compare_birth(&birth)
        .map_err(|_| CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
    let original = birth.fields();
    let denial = fence.fields();
    let member = catalog
        .fixed_member(profile, [0; 32])
        .map_err(|_| CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
    if original.owner != profile.owner()
        || original.transaction != *transaction.id()
        || denial.transaction != *transaction.id()
        || original.commit_sequence != commit_sequence
        || original.predecessor_prefix != predecessor
        || denial.predecessor_prefix != predecessor
        || original.catalog != catalog.digest()
        || original.provision_origin.as_slice() != member.provision_origin()
        || predecessor.as_slice() != member.predecessor_prefix()
    {
        return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
    }
    Ok(())
}

/// Detects either actual durable denial key without interpreting its value.
///
/// A malformed partial pair remains a denial, never a proved empty domain.
#[must_use]
pub fn has_durable_owner_fence_v1(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> bool {
    state.keys().any(|(namespace, key)| {
        *namespace == RecordNamespace::DesiredState
            && matches!(key.as_slice(), b"z-git-birth-v1" | b"z-git-fence-v1")
    })
}

/// Hashes only the original name and ordered native inode-pair comparison DATA.
///
/// The native owner supplies its actual held directory, file and lock samples.
/// The result is not a physical witness, role, currentness or provisioning grant.
#[must_use]
pub fn provision_origin_digest_v1(name: Option<&str>, identities: [(u64, u64); 3]) -> [u8; 32] {
    let mut digest = Sha256::new().chain_update(b"aos.sandbox.git-upload.native-origin.v1\0");
    if let Some(name) = name {
        digest.update(name.as_bytes());
    }
    digest.update([0]);
    for (device, inode) in identities {
        digest.update(device.to_be_bytes());
        digest.update(inode.to_be_bytes());
    }
    digest.finalize().into()
}

/// Refuses ordinary mutation of the actual Cache hold file after its Git fence.
///
/// The same protected basename and existing materialized keys only select a
/// denial. This comparison performs no IO and supplies no native exception.
///
/// # Errors
/// Refuses the existing protected Cache hold name with either durable fence key.
pub fn require_no_cache_exclusive_mutation_v1<P>(
    read: aos_sandbox_broker::canonical_journal::coordinator::CanonicalWriterReadViewV1<'_, P>,
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), CanonicalJournalMechanicalErrorV1> {
    if read.protected_view().map(|location| location.name()) == Some(aos_sandbox_protocol::cache_state::fixed_journals::CACHE_HOLD_BASENAME_V1)
        && state.keys().any(|(namespace, key)| {
            *namespace == RecordNamespace::DesiredState
                && (key.as_slice() == aos_sandbox_protocol::cache_state::hold_state::GIT_BIRTH_KEY || key.as_slice() == aos_sandbox_protocol::cache_state::hold_state::GIT_FENCE_KEY)
        })
    {
        return Err(CanonicalJournalMechanicalErrorV1::ProtectedBoundary);
    }
    Ok(())
}
