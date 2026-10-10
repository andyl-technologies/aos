//! Streaming Git-cohort native-prefix DATA from the original protected writer.
//!
//! The existing COMMIT parser and materializer validate every actual native
//! transaction. This child hashes their sole canonical frame encoding without
//! retaining a transaction forest, prefix maps or another replay reducer.
//!
//! ```text
//! SHA256("aos.sandbox.git-upload.native-prefix.v1\0" || canonical native frames)
//! ```
//!
//! The loan prevents writer mutation while borrowed. It establishes only a
//! parser-validated physical prefix; live role, clock, signature, catalog,
//! admission and physical residual checks belong to the genuine owners.

use sha2::{Digest as _, Sha256};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_core::format::git_upload_enrollment::{
    GitCoverageBirthV1, GitCoverageCatalogV1, GitCoverageFenceV1,
    GitCoverageJournalProfileV1, MAXIMUM_COVERAGE_OWNERS_V1,
};

use super::runtime_deployment_history::ReadAtCursorV1;
use super::{
    DeploymentHistoryObserverV1, FileIdentity, Journal, JournalError,
    JournalTransaction, ProtectedWriterNameWitness, RecordNamespace, ReplayState,
    encode_transaction, encoded_transaction_append_bytes, replay_original_observed,
};

const PREFIX_DOMAIN: &[u8] = b"aos.sandbox.git-upload.native-prefix.v1\0";
const PROVISION_ORIGIN_DOMAIN: &[u8] = b"aos.sandbox.git-upload.native-origin.v1\0";

fn has_durable_owner_fence_v1(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> bool {
    state.keys().any(|(namespace, key)| {
        *namespace == RecordNamespace::DesiredState
            && matches!(key.as_slice(), b"z-git-birth-v1" | b"z-git-fence-v1")
    })
}

// Before a permanent empty-domain fence, an opt-in owner may still have real
// original debt. Compare complete canonical graphs, not a caller-selected
// mutation tag, so negative cleanup cannot introduce an acquisition or retry.
fn require_original_source_cleanup_v1(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    use aos_sandbox_protocol::mount_source_acquisition_state::{
        ProviderMethodV2, ProviderQueryOwnerV2, SourceAcquisitionPhaseV2,
        native_held_completion::{
            validate_native_root_cold_transition_v2, validate_native_root_graph_v2,
        },
    };

    let mut prospective: std::collections::BTreeMap<&[u8], &[u8]> = state.iter()
        .filter(|((namespace, _), _)| {
            *namespace == RecordNamespace::MountSourceAcquisition
        })
        .map(|((_, key), value)| (key.as_slice(), value.as_slice()))
        .collect();
    let before = validate_native_root_graph_v2(
        prospective.iter().map(|(key, value)| (*key, *value)),
    ).map_err(|_| JournalError::ProtectedBoundary)?;

    for record in transaction.records().iter().filter(|record| {
        record.namespace() == RecordNamespace::MountSourceAcquisition
    }) {
        let value = record.value().ok_or(JournalError::ProtectedBoundary)?;
        prospective.insert(record.key(), value);
    }
    let after = validate_native_root_graph_v2(
        prospective.iter().map(|(key, value)| (*key, *value)),
    ).map_err(|_| JournalError::ProtectedBoundary)?;
    let original = before.legacy();
    let next = after.legacy();

    if original.holder_sequences != next.holder_sequences
        || original.acquisitions.len() != next.acquisitions.len()
        || original.provider_heads.len() != next.provider_heads.len()
        || before.v1_sidecars() != after.v1_sidecars()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    for (id, row) in &next.acquisitions {
        let old = original.acquisitions.get(id)
            .ok_or(JournalError::ProtectedBoundary)?;
        if !preserves_source_acquisition_v1(old, row)
            || (row.phase != old.phase && !matches!(row.phase,
                SourceAcquisitionPhaseV2::Releasing
                    | SourceAcquisitionPhaseV2::Released
                    | SourceAcquisitionPhaseV2::Faulted))
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    for scope in next.provider_heads.keys() {
        if !original.provider_heads.contains_key(scope) {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    for (id, session) in &next.provider_sessions {
        if let Some(old) = original.provider_sessions.get(id) {
            if old != session {
                return Err(JournalError::ProtectedBoundary);
            }
        } else if !original.provider_heads.contains_key(&(
            session.scope.holder_authority_id,
            session.scope.provider_authority_id,
        )) {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    for (id, attempt) in &next.provider_attempts {
        if let Some(old) = original.provider_attempts.get(id) {
            if !preserves_source_attempt_v1(old, attempt) {
                return Err(JournalError::ProtectedBoundary);
            }
            continue;
        }
        match (attempt.method, attempt.owner) {
            (ProviderMethodV2::Release, ProviderQueryOwnerV2::Release { acquisition_id })
                if original.acquisitions.get(&acquisition_id)
                    .is_some_and(|row| row.scope == attempt.scope) => {}
            (ProviderMethodV2::Inventory, ProviderQueryOwnerV2::Inventory)
                if original.provider_heads.contains_key(&(
                    attempt.scope.holder_authority_id,
                    attempt.scope.provider_authority_id,
                )) => {}
            _ => return Err(JournalError::ProtectedBoundary),
        }
    }

    for (attempt, sidecar) in after.sidecars() {
        if before.sidecars().get(attempt) == Some(sidecar) {
            continue;
        }
        if !original.provider_attempts.contains_key(attempt)
            || before.sidecars().get(attempt).is_some_and(|old| {
                old.original_scope() != sidecar.original_scope()
            })
        {
            return Err(JournalError::ProtectedBoundary);
        }
        // The existing closed cold reducer rejects hot preparation, receive,
        // CAS and Accepted, while retaining genuine intermediate cleanup.
        validate_native_root_cold_transition_v2(
            &before, &after, *attempt, *transaction.id(),
        ).map_err(|_| JournalError::ProtectedBoundary)?;
    }
    Ok(())
}

fn preserves_source_acquisition_v1(
    old: &aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionRowV2,
    next: &aos_sandbox_protocol::mount_source_acquisition_state::SourceAcquisitionRowV2,
) -> bool {
    old.acquisition_id == next.acquisition_id
        && old.provider_acquisition == next.provider_acquisition
        && old.scope == next.scope
        && old.acquire == next.acquire
        && old.mount_acquire_request == next.mount_acquire_request
        && old.acquire_intent_digest == next.acquire_intent_digest
        && old.acquire_lineage == next.acquire_lineage
        && old.assignment == next.assignment
        && old.prospective_mount_template == next.prospective_mount_template
        && old.prospective_mount_template_digest == next.prospective_mount_template_digest
        && old.source_binding == next.source_binding
        && old.source_binding_digest == next.source_binding_digest
        && old.mount_plan_digest == next.mount_plan_digest
        && old.ownership_lease_digest == next.ownership_lease_digest
        && old.manager_custody == next.manager_custody
        && old.descriptor_custody_digest == next.descriptor_custody_digest
        && old.positive_custody_digest == next.positive_custody_digest
        && old.consumption == next.consumption
}

fn preserves_source_attempt_v1(
    old: &aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderQueryAttemptV2,
    next: &aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderQueryAttemptV2,
) -> bool {
    old.attempt_id == next.attempt_id
        && old.scope == next.scope
        && old.method == next.method
        && old.owner == next.owner
        && old.intent == next.intent
        && old.provider_acquisition == next.provider_acquisition
        && old.immutable_intent_digest == next.immutable_intent_digest
        && old.lineage_root_attempt_id == next.lineage_root_attempt_id
        && old.previous_attempt_id == next.previous_attempt_id
        && old.attempt_number == next.attempt_number
        && old.session_id == next.session_id
        && old.session_record_digest == next.session_record_digest
        && old.signer_set_commitment == next.signer_set_commitment
        && old.trust_digest == next.trust_digest
        && old.revocation_digest == next.revocation_digest
        && old.route_digest == next.route_digest
        && old.process_execution_digest == next.process_execution_digest
        && old.normalized_acquire_intent == next.normalized_acquire_intent
        && old.acquire_verification_floor == next.acquire_verification_floor
        && old.inventory_correlations == next.inventory_correlations
        && old.request_id == next.request_id
        && old.request_sequence == next.request_sequence
        && old.signed_request == next.signed_request
        && old.signed_request_digest == next.signed_request_digest
        && old.owner_predecessor_revision == next.owner_predecessor_revision
        && old.owner_predecessor_digest == next.owner_predecessor_digest
        && old.owner_predecessor == next.owner_predecessor
}

#[derive(Clone, Copy)]
enum NativePrefixRecipeV1 {
    Original,
    CachePolicy,
    OwnerCoverage(GitCoverageJournalProfileV1),
}

/// Retains the first actual parser/check error and independent final debt.
#[derive(Debug, thiserror::Error)]
#[error("Git coverage native prefix failed: {first}")]
pub struct GitCoverageNativeHistoryErrorV1 {
    #[source]
    first: JournalError,
    final_bookend: Option<JournalError>,
}

impl GitCoverageNativeHistoryErrorV1 {
    pub(crate) fn from_first(first: JournalError) -> Self {
        Self { first, final_bookend: None }
    }

    /// Borrows the unchanged first owning native cause.
    #[must_use]
    pub fn first_cause(&self) -> &JournalError {
        &self.first
    }

    /// Borrows later physical/name debt without replacing the first cause.
    #[must_use]
    pub fn final_bookend_cause(&self) -> Option<&JournalError> {
        self.final_bookend.as_ref()
    }
}

/// Borrows one original protected writer and its completely observed prefix.
///
/// This is DATA, not current role authority or an append/floor permit. No
/// method opens, clones, seeks, mutates or extracts the original Journal.
pub struct GitCoverageNativePrefixLoanV1<'journal> {
    journal: &'journal Journal,
    witness: ProtectedWriterNameWitness,
    prefix: [u8; 32],
    transactions: usize,
    records: usize,
    last_transaction: Option<[u8; 16]>,
    last_commit_sequence: Option<u64>,
    ended: bool,
    controller_account_seen: bool,
    controller_floor_seen: bool,
}

impl GitCoverageNativePrefixLoanV1<'_> {
    pub(crate) fn existing_controller_read_floor_v1(&self) -> Result<bool, JournalError> {
        if self.ended || !self.controller_account_seen {
            return Err(JournalError::ProtectedBoundary);
        }
        // False describes absence in this COMPLETE replay, not the current map.
        Ok(self.controller_floor_seen)
    }

    /// Returns the whole original native-prefix commitment as comparison DATA.
    #[must_use]
    pub fn prefix_digest(&self) -> [u8; 32] {
        self.prefix
    }

    /// Commits the original protected name and three retained inode identities.
    ///
    /// The separate prefix commits actual contents. This stable local-origin
    /// DATA excludes mutable lengths/timestamps and supplies no independent
    /// startup, role, project, policy, or physical-residual authority.
    #[must_use]
    pub fn provision_origin_digest(&self) -> [u8; 32] {
        provision_origin(self.journal, &self.witness)
    }

    /// Returns actual validated transaction and record counts, not quotas.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        (self.transactions, self.records)
    }

    /// Returns the last actual UUID and COMMIT sequence, if a COMMIT exists.
    #[must_use]
    pub fn last_commit(&self) -> Option<([u8; 16], u64)> {
        self.last_transaction.zip(self.last_commit_sequence)
    }

    /// Rechecks the same original writer's physical/name cut while borrowed.
    ///
    /// # Errors
    /// Rejects poison, replaced names, changed file identity or sequence. This
    /// observational check grants no current policy or remote owner authority.
    pub fn recheck(&mut self) -> Result<(), JournalError> {
        if self.ended {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        self.ended = true;
        require_bookend(self.journal, &self.witness)?;
        self.ended = false;
        Ok(())
    }
}

pub(super) struct NativePrefixObserverV1<'data> {
    recipe: NativePrefixRecipeV1,
    fixed_cache_catalog: Option<FixedCacheCatalogAuditV1<'data>>,
    digest: Sha256,
    next_sequence: u64,
    end_offset: u64,
    transactions: usize,
    records: usize,
    last_transaction: Option<[u8; 16]>,
    last_commit_sequence: Option<u64>,
    owner_fence_seen: bool,
    publisher_account_seen: bool,
    controller_floor: Option<crate::cli_model::authorization_adapter::ProtectedTimeFloorRevisionV1>,
    initial_issuance: crate::public_capability_issuance::GitCoverageInitialIssuanceHistoryV1,
}

impl<'data> NativePrefixObserverV1<'data> {
    fn new(recipe: NativePrefixRecipeV1) -> Self {
        Self {
            recipe,
            fixed_cache_catalog: None,
            digest: Sha256::new().chain_update(PREFIX_DOMAIN),
            next_sequence: 1,
            end_offset: 0,
            transactions: 0,
            records: 0,
            last_transaction: None,
            last_commit_sequence: None,
            owner_fence_seen: false,
            publisher_account_seen: false,
            controller_floor: None,
            initial_issuance: Default::default(),
        }
    }

    pub(super) fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), JournalError> {
        // Compaction is not an original native history, even when its current
        // map happens to preserve all coverage values and logical sequences.
        if transaction.id()[8..] == *b"compact1"
            || begin_sequence != self.next_sequence
            || begin_offset != self.end_offset
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let append_bytes = encoded_transaction_append_bytes(transaction)?;
        if begin_offset.checked_add(append_bytes) != Some(end_offset)
            || begin_sequence.checked_add(transaction.records().len() as u64)
                .and_then(|sequence| sequence.checked_add(1)) != Some(commit_sequence)
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }

        if let NativePrefixRecipeV1::CachePolicy = self.recipe {
            super::cache_policy_hold::require_coverage_native_transaction_v1(
                self.transactions,
                transaction,
                commit_sequence,
                self.digest.clone().finalize().into(),
            )?;
        }
        let mut catalog_transaction = !matches!(self.recipe, NativePrefixRecipeV1::CachePolicy)
            || self.transactions == 0;
        if let NativePrefixRecipeV1::OwnerCoverage(profile) = self.recipe {
            if self.owner_fence_seen {
                // Controller's first covered account is one subsequent
                // immutable three-PUT transaction. No later effect, overwrite
                // or retirement is classified by this bounded first profile.
                if profile != GitCoverageJournalProfileV1::Controller {
                    return Err(JournalError::ProtectedBoundary);
                }
                if !self.publisher_account_seen {
                    crate::publisher_policy::require_coverage_native_account_transaction(transaction)
                        .map_err(|_| JournalError::ProtectedBoundary)?;
                    self.publisher_account_seen = true;
                } else if transaction.records().first().is_some_and(|record| {
                    record.namespace() == RecordNamespace::CliAuthorizationTime
                }) {
                    self.controller_floor = Some(
                        crate::cli_model::authorization_adapter::require_git_coverage_floor_transaction_v1(
                            transaction, self.controller_floor,
                        ).map_err(|_| JournalError::ProtectedBoundary)?,
                    );
                } else {
                    if self.controller_floor.is_none() {
                        return Err(JournalError::ProtectedBoundary);
                    }
                    self.initial_issuance.observe(transaction)
                        .map_err(|_| JournalError::ProtectedBoundary)?;
                }
                catalog_transaction = false;
            } else if transaction.records().iter().any(|record| {
                record.namespace() == RecordNamespace::DesiredState
                    && matches!(record.key(), b"z-git-birth-v1" | b"z-git-fence-v1")
            }) {
                require_owner_fence_transaction(
                    profile,
                    transaction,
                    commit_sequence,
                    self.digest.clone().finalize().into(),
                    self.fixed_cache_catalog.as_ref()
                        .ok_or(JournalError::ProtectedBoundary)?.catalog,
                )?;
                self.owner_fence_seen = true;
                catalog_transaction = false;
            }
        }
        if let Some(catalog) = self.fixed_cache_catalog.as_mut() {
            // A persisted exclusive hold adds its denial fence after the
            // catalogued Genesis. Its predecessor remains that original
            // Genesis prefix; the future fence prefix is never provisioned.
            if catalog_transaction {
                catalog_transaction = catalog.observe(transaction, begin_sequence)?;
            }
        }

        // Reuse the sole encoder after the sole parser's complete transaction
        // validation. These bounded temporary frames are ordinary allocation,
        // not funded retained storage or a second serialization engine.
        let frames = encode_transaction(transaction, begin_sequence)?;
        for frame in frames {
            self.digest.update(frame);
        }
        if let Some(catalog) = self.fixed_cache_catalog.as_mut() {
            if catalog_transaction {
                catalog.prefix = self.digest.clone().finalize().into();
            }
        }
        self.next_sequence = commit_sequence.checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
        self.end_offset = end_offset;
        self.transactions = self.transactions.checked_add(1)
            .ok_or(JournalError::LimitExceeded("coverage native transactions"))?;
        self.records = self.records.checked_add(transaction.records().len())
            .ok_or(JournalError::LimitExceeded("coverage native records"))?;
        self.last_transaction = Some(*transaction.id());
        self.last_commit_sequence = Some(commit_sequence);
        Ok(())
    }
}

// Each genuine fixed owner runs its existing semantic validator separately.
// The closed recipes add native UUID/PUT/order and physical-prefix
// comparison. They do not interpret partition state or grant owner authority.
struct FixedCacheCatalogAuditV1<'data> {
    catalog: &'data GitCoverageCatalogV1<'data>,
    profile: GitCoverageJournalProfileV1,
    records: [usize; MAXIMUM_COVERAGE_OWNERS_V1],
    prefix: [u8; 32],
    previous_clock: Option<(ObjectDigest, u64, u64)>,
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

impl FixedCacheCatalogAuditV1<'_> {
    fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
    ) -> Result<bool, JournalError> {
        if self.profile == GitCoverageJournalProfileV1::CacheClock {
            let has_member = self.catalog.members()
                .any(|member| belongs_to_catalog_writer(self.profile, member.profile()));
            let catalogued_prefix_complete = has_member && self.catalog.members().enumerate()
                .filter(|(_, member)| belongs_to_catalog_writer(self.profile, member.profile()))
                .all(|(index, member)| {
                    self.records.get(index).copied() == Some(member.infrastructure_count() as usize)
                        && member.predecessor_prefix() == self.prefix
                });
            self.previous_clock = Some(
                crate::cache_residency::CacheResidencyProtectedOwnerV1::compare_git_coverage_clock_transaction_v1(
                    transaction, self.previous_clock,
                )?,
            );
            if catalogued_prefix_complete {
                // The signed catalog commits only the actual prebirth prefix.
                // Later floors are classified by the SAME Clock chain, not
                // by invented future catalog rows or overwritten current keys.
                return Ok(false);
            }
        }
        // The initial logical state is entirely in each genuine checkpoint.
        // This first profile does not classify later durable state mutations
        // as infrastructure, even when a signed catalog names their bytes.
        if self.profile == GitCoverageJournalProfileV1::CacheState {
            return Err(JournalError::ProtectedBoundary);
        }
        for (index, record) in transaction.records().iter().enumerate() {
            // Only the closed Clock recipe admits repeated provisioning-key
            // versions. An immutable bootstrap/authority/Genesis key cannot
            // hide an overwritten tenant value behind a later current map.
            if self.profile != GitCoverageJournalProfileV1::CacheClock
                && self.catalog.infrastructure().filter(|row| {
                    row.key() == record.key()
                        && self.catalog.members().any(|member| {
                            belongs_to_catalog_writer(self.profile, member.profile())
                                && member.digest() == row.attribution()
                        })
                }).count() != 1
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let sequence = begin_sequence.checked_add(index as u64)
                .and_then(|value| value.checked_add(1))
                .ok_or(JournalError::SequenceExhausted)?;
            let value = record.value().ok_or(JournalError::ProtectedBoundary)?;
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
            let row = declared.next().ok_or(JournalError::ProtectedBoundary)?;
            let member_index = self.catalog.members().position(|member| {
                belongs_to_catalog_writer(self.profile, member.profile())
                    && member.digest() == row.attribution()
            }).ok_or(JournalError::ProtectedBoundary)?;
            let member = self.catalog.members().nth(member_index)
                .ok_or(JournalError::ProtectedBoundary)?;
            if declared.next().is_some()
                || !catalog_namespace_matches(member.profile(), record.namespace())
                || row.family() != 1
                || row.transaction() != transaction.id()
                || row.put_sequence() != sequence
                || row.value_digest() != value_digest.as_bytes()
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let count = self.records.get_mut(member_index)
                .ok_or(JournalError::ProtectedBoundary)?;
            *count = count.checked_add(1)
                .ok_or(JournalError::LimitExceeded("coverage fixed Cache records"))?;
        }
        Ok(true)
    }

    fn require_complete(
        &self,
        origin: [u8; 32],
    ) -> Result<(), JournalError> {
        let mut members = 0_usize;
        for (index, member) in self.catalog.members().enumerate() {
            if !belongs_to_catalog_writer(self.profile, member.profile()) {
                continue;
            }
            members = members.checked_add(1).ok_or(JournalError::ProtectedBoundary)?;
            if self.records.get(index).copied() != Some(member.infrastructure_count() as usize)
                || member.predecessor_prefix() != self.prefix
                || member.provision_origin() != origin
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        if members == 0 {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

impl Journal {
    /// Refuses a new admission under the original permanent Controller fence.
    ///
    /// This is a negative check on the same protected writer, not an empty
    /// domain proof or a permission when no row exists. The first-profile
    /// capture separately checks the complete native history before installing
    /// its fence. Original negative recovery remains outside this NEW boundary.
    ///
    /// # Errors
    /// Refuses either durable fence row, including a malformed partial pair.
    /// Absence does not replace the caller's independent physical currentness,
    /// protected writer/name, native preflight or commit checks.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn require_git_coverage_new_admission_v1(&self) -> Result<(), JournalError> {
        if !self.controller_git_coverage_fenced_v1(self.native.state()) {
            return Ok(());
        }
        Err(JournalError::ProtectedBoundary)
    }

    fn controller_git_coverage_fenced_v1(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> bool {
        *self.native.path() == std::path::Path::new("/var/lib/aos/sandboxd/controller.journal")
            && has_durable_owner_fence_v1(state)
    }

    pub(super) fn require_owner_git_coverage_transition_v1(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        let fixed_remote_owner = matches!(self.native.path().to_str(),
            Some("/var/lib/aos/sandbox-mount/mount.journal")
                | Some("/var/lib/aos/sandbox-storage/storage-state.journal")
                | Some("/var/lib/aos/sandbox/policy-compiler/authority.journal")
                | Some("/var/lib/aos/sandbox/policy-compiler/state.journal"));
        if fixed_remote_owner && has_durable_owner_fence_v1(state) {
            // These owners have no admitted successor mutation in the first
            // empty-cohort profile. Readback and original Broker-session
            // outcome journals are separate and retain their existing engine.
            return Err(JournalError::ProtectedBoundary);
        }
        if !self.controller_git_coverage_fenced_v1(state) {
            return Ok(());
        }

        if transaction.records().first().is_some_and(|record| {
            matches!(record.namespace(), RecordNamespace::CliAuthorizationTime
                | RecordNamespace::PublisherAuthority)
        }) {
            crate::publisher_policy::PublisherPolicyStore::require_complete_coverage_read_state_v1(state)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            return match transaction.records()[0].namespace() {
                RecordNamespace::CliAuthorizationTime =>
                    crate::cli_model::authorization_adapter::require_git_coverage_floor_from_state_v1(
                        transaction, state,
                    ).map_err(|_| JournalError::ProtectedBoundary),
                RecordNamespace::PublisherAuthority => {
                    if !state.keys().any(|(namespace, _)| {
                        *namespace == RecordNamespace::CliAuthorizationTime
                    }) {
                        return Err(JournalError::ProtectedBoundary);
                    }
                    crate::public_capability_issuance::require_git_coverage_initial_from_state_v1(
                        transaction, state,
                    ).map_err(|_| JournalError::ProtectedBoundary)
                }
                _ => Err(JournalError::ProtectedBoundary),
            };
        }

        // The only new durable work in this first profile is its sole existing
        // three-PUT account successor. The shared account codec validates its
        // relation; the genuine store/capture performs authority and CAS.
        // No earlier Operation/Effect can coexist with the audited birth, so
        // this never reclassifies an original negative cleanup as NEW work.
        crate::publisher_policy::require_coverage_native_account_transaction(transaction)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if transaction.records().get(1).is_none_or(|record| {
            state.keys().any(|(namespace, key)| {
                *namespace == record.namespace() && key.as_slice() == record.key()
            })
        }) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn controller_git_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_owner_catalog_v1(
            catalog, GitCoverageJournalProfileV1::Controller,
            "/var/lib/aos/sandboxd", "controller.journal",
            NativePrefixRecipeV1::OwnerCoverage(GitCoverageJournalProfileV1::Controller),
        )
    }

    pub(crate) fn existing_controller_coverage_birth_nonce_v1(
        &self,
        catalog: &GitCoverageCatalogV1<'_>,
    ) -> Result<[u8; 16], GitCoverageNativeHistoryErrorV1> {
        let mut loan = self.controller_git_coverage_native_prefix_v1(catalog)?;
        loan.existing_controller_read_floor_v1()
            .map_err(GitCoverageNativeHistoryErrorV1::from_first)?;
        let nonce = (|| {
            let birth = GitCoverageBirthV1::decode(self.get(
                RecordNamespace::DesiredState, b"z-git-birth-v1",
            ).ok_or(JournalError::ProtectedBoundary)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let fence = GitCoverageFenceV1::decode(self.get(
                RecordNamespace::DesiredState, b"z-git-fence-v1",
            ).ok_or(JournalError::ProtectedBoundary)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            fence.compare_birth(&birth).map_err(|_| JournalError::ProtectedBoundary)?;
            Ok(fence.fields().prepare_nonce)
        })();
        let postchecked = loan.recheck();
        match (nonce, postchecked) {
            (Ok(nonce), Ok(())) => Ok(nonce),
            (Err(first), final_bookend) => Err(GitCoverageNativeHistoryErrorV1 {
                first, final_bookend: final_bookend.err(),
            }),
            (Ok(_), Err(first)) => Err(GitCoverageNativeHistoryErrorV1::from_first(first)),
        }
    }

    pub(crate) fn root_authority_git_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_owner_catalog_v1(
            catalog, GitCoverageJournalProfileV1::RootAuthority,
            "/var/lib/aos/sandbox/policy-compiler", "authority.journal",
            NativePrefixRecipeV1::OwnerCoverage(GitCoverageJournalProfileV1::RootAuthority),
        )
    }

    pub(crate) fn root_state_git_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_owner_catalog_v1(
            catalog, GitCoverageJournalProfileV1::RootPolicyState,
            "/var/lib/aos/sandbox/policy-compiler", "state.journal",
            NativePrefixRecipeV1::OwnerCoverage(GitCoverageJournalProfileV1::RootPolicyState),
        )
    }

    pub(crate) fn source_git_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_owner_catalog_v1(
            catalog, GitCoverageJournalProfileV1::Source,
            "/var/lib/aos/sandbox/source-domains", "source-domains-v1.journal",
            NativePrefixRecipeV1::Original,
        )
    }

    // Only the named purpose methods above select these fixed roots. The
    // original witness and complete parser/materializer bookends are shared;
    // no public path/profile/callback selector or Journal getter is exposed.
    fn capture_fixed_owner_catalog_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
        profile: GitCoverageJournalProfileV1,
        directory: &'static str,
        name: &'static str,
        recipe: NativePrefixRecipeV1,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        if *self.native.path() != std::path::Path::new(directory).join(name) {
            return Err(GitCoverageNativeHistoryErrorV1 {
                first: JournalError::ProtectedBoundary,
                final_bookend: None,
            });
        }
        self.capture_fixed_cache_catalog_v1(catalog, profile, name, recipe)
    }

    /// Retains a monotone NEW-Source denial for the fixed Mount cohort recipe.
    ///
    /// The original credential reservoir may still be partial or failed. This
    /// operation only denies effects; it does not attest enrollment or an empty
    /// domain. The same writer cannot reset this disposition or reopen it.
    ///
    /// # Errors
    /// Rejects another fixed recipe or an unsafe/replaced original Mount writer.
    #[cfg(target_os = "linux")]
    pub fn retain_mount_git_coverage_denial_v1(
        &mut self,
        inputs: &crate::public_api_session::GitCoverageCredentialCustodyV1,
    ) -> Result<(), JournalError> {
        if !inputs.retains_mount_recipe_v1() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.mount_git_coverage_denied = true;
        self.validate_held_root_owned_at("/var/lib/aos/sandbox-mount", "mount.journal")
    }

    /// Reports a refusal disposition from this same original Journal.
    ///
    /// A false result is never a permission or currentness proof. Temporary
    /// fixed owners may cache only this negative observation while their
    /// exclusive in-process borrow prevents installing through that same
    /// owner. This does not establish cross-process physical currentness:
    /// original writer/name checks and commit/preflight still inspect every
    /// actual current and prospective mutation independently.
    #[doc(hidden)]
    #[must_use]
    pub fn mount_git_coverage_denies_new_v1(&self) -> bool {
        self.mount_git_coverage_denied
            || has_durable_owner_fence_v1(self.native.state())
    }

    pub(super) fn require_mount_git_coverage_source_transition_v1(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if !transaction.records().iter()
            .any(|record| record.namespace() == RecordNamespace::MountSourceAcquisition)
        {
            return Ok(());
        }
        let durable = has_durable_owner_fence_v1(state);
        if !self.mount_git_coverage_denied && !durable {
            return Ok(());
        }
        if durable {
            // The first profile requires the complete Source history to be
            // empty before this fence. No earlier debt can be hidden here.
            return Err(JournalError::ProtectedBoundary);
        }
        super::validate_transaction(transaction, self.native.limits())?;
        require_original_source_cleanup_v1(state, transaction)
    }

    pub(super) fn require_storage_git_coverage_transition_v1(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if !has_durable_owner_fence_v1(state)
            || self.protected.as_ref().is_none_or(|location| {
                location.name() != "storage-state.journal"
            })
        {
            return Ok(());
        }
        if transaction.records().iter().any(|record| matches!(record.namespace(),
            RecordNamespace::DesiredState
                | RecordNamespace::Operation
                | RecordNamespace::Effect
                | RecordNamespace::AuthorityPublication
                | RecordNamespace::StorageCatalogReservation
                | RecordNamespace::StorageCatalogTransition
                | RecordNamespace::StorageCatalogHead
                | RecordNamespace::StorageRuntimeConfiguration
                | RecordNamespace::StorageWorkspacePublicationIntent
                | RecordNamespace::StorageWorkspacePinAttempt
                | RecordNamespace::StorageCatalogPreparation
                | RecordNamespace::StorageWorkspacePinRepairIntent
                | RecordNamespace::StorageResolverPolicyFloor
                | RecordNamespace::StorageGuestRootPublicationAttempt))
        {
            // The permanent Storage fence is appended only after the genuine
            // complete history/census is empty. It cannot cover earlier debt.
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Lends the completely observed native prefix of this original writer.
    ///
    /// Uses the same parser/materializer and a positioned original-file cursor;
    /// it never opens a name, changes the append OFD offset or copies histories.
    /// The caller's genuine owner remains responsible for retained failure and
    /// uncaught-unwind custody during ordinary parser/encoder allocation.
    ///
    /// # Errors
    /// Returns the first typed health/parser/shape/snapshot failure and any
    /// separate final bookend debt. Refuses compaction or incomplete tails.
    pub fn git_coverage_native_prefix_v1(
        &self,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_git_coverage_native_prefix_v1(NativePrefixRecipeV1::Original, None)
    }

    /// Compares the original fixed Mount prefix with its full signed catalog.
    ///
    /// This is native-history DATA only. The genuine Mount owner separately
    /// compares every resource table, physical root, worker and PID1 FD store.
    ///
    /// # Errors
    /// Rejects a different protected name, undeclared historical mutation,
    /// compaction, changed native identity or a malformed permanent fence pair.
    pub fn mount_git_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog, GitCoverageJournalProfileV1::Mount, "mount.journal",
            NativePrefixRecipeV1::OwnerCoverage(GitCoverageJournalProfileV1::Mount),
        )
    }

    /// Compares the original fixed Storage catalog prefix with its signed input.
    ///
    /// Storage's existing configuration and catalog validators remain required;
    /// this loan supplies neither physical-empty nor allocation authority.
    ///
    /// # Errors
    /// Rejects a different protected name, foreign namespace, undeclared row,
    /// compaction, changed native identity or a malformed permanent fence pair.
    pub fn storage_git_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog, GitCoverageJournalProfileV1::StorageCatalog, "storage-state.journal",
            NativePrefixRecipeV1::OwnerCoverage(GitCoverageJournalProfileV1::StorageCatalog),
        )
    }

    /// Compares the original fixed native-issuance prefix with its signed member.
    ///
    /// This DATA loan does not issue or retire a consumer interest. The actual
    /// native owner independently requires its complete interest history empty.
    ///
    /// # Errors
    /// Rejects another name, namespace, undeclared mutation or changed prefix.
    pub fn storage_native_git_coverage_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog,
            GitCoverageJournalProfileV1::StorageNative,
            "storage-native-issuance.journal",
            NativePrefixRecipeV1::Original,
        )
    }

    /// Compares the original fixed workspace prefix with its signed member.
    ///
    /// The existing workspace owner separately checks the identity pool, head,
    /// plan and physical pin root. No allocation or inventory permit is lent.
    ///
    /// # Errors
    /// Rejects another name, namespace, undeclared mutation or changed prefix.
    pub fn storage_workspace_git_coverage_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog,
            GitCoverageJournalProfileV1::StorageWorkspace,
            "storage-workspaces.journal",
            NativePrefixRecipeV1::Original,
        )
    }

    /// Compares the original fixed output prefix with its signed member.
    ///
    /// The genuine output custody independently authenticates its configuration,
    /// MAC key and empty obligations; a catalog signature cannot replace them.
    ///
    /// # Errors
    /// Rejects another name, namespace, undeclared mutation or changed prefix.
    pub fn storage_output_git_coverage_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog,
            GitCoverageJournalProfileV1::StorageOutput,
            "execution-output.journal",
            NativePrefixRecipeV1::Original,
        )
    }

    // This closed recipe also checks the original Genesis and sole paired
    // birth/fence transaction. It cannot reinterpret an old released hold as
    // fresh enrollment, and opens no additional policy writer.
    pub(crate) fn cache_coverage_native_prefix_v1(
        &self,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        if self.protected.as_ref().map(|location| location.name())
            != Some(super::cache_policy_hold::NAME)
        {
            return Err(GitCoverageNativeHistoryErrorV1 {
                first: JournalError::ProtectedBoundary,
                final_bookend: None,
            });
        }
        self.capture_git_coverage_native_prefix_v1(NativePrefixRecipeV1::CachePolicy, None)
    }

    pub(crate) fn cache_bootstrap_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        if self.protected.as_ref().map(|location| location.name()) != Some("bootstrap-v1.journal") {
            return Err(GitCoverageNativeHistoryErrorV1 {
                first: JournalError::ProtectedBoundary,
                final_bookend: None,
            });
        }
        self.capture_git_coverage_native_prefix_v1(
            NativePrefixRecipeV1::Original,
            Some((catalog, GitCoverageJournalProfileV1::CacheBootstrap)),
        )
    }

    pub(crate) fn cache_clock_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog, GitCoverageJournalProfileV1::CacheClock,
            "clock.journal", NativePrefixRecipeV1::Original,
        )
    }

    pub(crate) fn cache_hold_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog, GitCoverageJournalProfileV1::CachePolicyHold,
            super::cache_policy_hold::NAME, NativePrefixRecipeV1::CachePolicy,
        )
    }

    pub(crate) fn cache_authority_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog, GitCoverageJournalProfileV1::CacheAuthority,
            "authority.journal", NativePrefixRecipeV1::Original,
        )
    }

    pub(crate) fn cache_state_coverage_native_prefix_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        self.capture_fixed_cache_catalog_v1(
            catalog, GitCoverageJournalProfileV1::CacheState,
            "state.journal", NativePrefixRecipeV1::Original,
        )
    }

    fn capture_fixed_cache_catalog_v1<'data>(
        &self,
        catalog: &'data GitCoverageCatalogV1<'data>,
        profile: GitCoverageJournalProfileV1,
        name: &'static str,
        recipe: NativePrefixRecipeV1,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        if self.protected.as_ref().map(|location| location.name()) != Some(name) {
            return Err(GitCoverageNativeHistoryErrorV1 {
                first: JournalError::ProtectedBoundary,
                final_bookend: None,
            });
        }
        self.capture_git_coverage_native_prefix_v1(recipe, Some((catalog, profile)))
    }

    fn capture_git_coverage_native_prefix_v1<'data>(
        &self,
        recipe: NativePrefixRecipeV1,
        fixed_cache_catalog: Option<(&'data GitCoverageCatalogV1<'data>, GitCoverageJournalProfileV1)>,
    ) -> Result<GitCoverageNativePrefixLoanV1<'_>, GitCoverageNativeHistoryErrorV1> {
        let capture = (|| {
            self.ensure_protected_authority()?;
            self.require_protected_names_current()?;
            self.protected_writer_name_witness()
        })();
        let witness = capture.map_err(|first| GitCoverageNativeHistoryErrorV1 {
            first, final_bookend: None,
        })?;

        let result = (|| {
            let mut observer = NativePrefixObserverV1::new(recipe);
            if let Some((catalog, profile)) = fixed_cache_catalog {
                if !profile.is_partition_owned() {
                    catalog.fixed_member(profile, [0; 32])
                        .map_err(|_| JournalError::ProtectedBoundary)?;
                }
                observer.fixed_cache_catalog = Some(FixedCacheCatalogAuditV1 {
                    catalog,
                    profile,
                    records: [0; MAXIMUM_COVERAGE_OWNERS_V1],
                    prefix: Sha256::new().chain_update(PREFIX_DOMAIN).finalize().into(),
                    previous_clock: None,
                });
            }
            let mut cursor = ReadAtCursorV1::new(self.native.file(), witness.file().byte_len());
            let replayed = replay_original_observed(
                &mut cursor,
                self.native.limits(),
                None,
                Some(DeploymentHistoryObserverV1::GitCoverage(&mut observer)),
            )?;
            require_replayed_snapshot(self, &replayed, &observer, witness.file().byte_len())?;
            if matches!(
                recipe,
                NativePrefixRecipeV1::OwnerCoverage(GitCoverageJournalProfileV1::Controller,)
            ) && observer.publisher_account_seen
            {
                crate::publisher_policy::PublisherPolicyStore::require_complete_coverage_read_state_v1(
                    self.native.state(),
                ).map_err(|_| JournalError::ProtectedBoundary)?;
                crate::cli_model::authorization_adapter::compare_git_coverage_floor_history_v1(
                    self, observer.controller_floor,
                ).map_err(|_| JournalError::ProtectedBoundary)?;
                observer.initial_issuance.compare_final(self)
                    .map_err(|_| JournalError::ProtectedBoundary)?;
            }
            if let Some(catalog) = observer.fixed_cache_catalog.as_ref() {
                catalog.require_complete(provision_origin(self, &witness))?;
            }
            Ok(observer)
        })();
        let bookend = require_bookend(self, &witness);
        let observer = match (result, bookend) {
            (Ok(observer), Ok(())) => observer,
            (Err(first), final_bookend) => {
                return Err(GitCoverageNativeHistoryErrorV1 {
                    first, final_bookend: final_bookend.err(),
                });
            }
            (Ok(_), Err(first)) => {
                return Err(GitCoverageNativeHistoryErrorV1 {
                    first, final_bookend: None,
                });
            }
        };

        Ok(GitCoverageNativePrefixLoanV1 {
            journal: self,
            witness,
            prefix: observer.digest.finalize().into(),
            transactions: observer.transactions,
            records: observer.records,
            last_transaction: observer.last_transaction,
            last_commit_sequence: observer.last_commit_sequence,
            ended: false,
            controller_account_seen: observer.publisher_account_seen,
            controller_floor_seen: observer.controller_floor.is_some(),
        })
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
        GitCoverageJournalProfileV1::Controller => {
            namespace == RecordNamespace::ControllerIdentity
        }
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
        | GitCoverageJournalProfileV1::CachePolicyHold => namespace == RecordNamespace::DesiredState,
        _ => false,
    }
}

fn require_owner_fence_transaction(
    profile: GitCoverageJournalProfileV1,
    transaction: &JournalTransaction,
    commit_sequence: u64,
    predecessor: [u8; 32],
    catalog: &GitCoverageCatalogV1<'_>,
) -> Result<(), JournalError> {
    let records = transaction.records();
    if records.len() != 2
        || records[0].namespace() != RecordNamespace::DesiredState
        || records[0].key() != b"z-git-birth-v1"
        || records[1].namespace() != RecordNamespace::DesiredState
        || records[1].key() != b"z-git-fence-v1"
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let birth = GitCoverageBirthV1::decode(
        records[0].value().ok_or(JournalError::ProtectedBoundary)?,
    ).map_err(|_| JournalError::ProtectedBoundary)?;
    let fence = GitCoverageFenceV1::decode(
        records[1].value().ok_or(JournalError::ProtectedBoundary)?,
    ).map_err(|_| JournalError::ProtectedBoundary)?;
    fence.compare_birth(&birth).map_err(|_| JournalError::ProtectedBoundary)?;
    let original = birth.fields();
    let denial = fence.fields();
    let member = catalog.fixed_member(profile, [0; 32])
        .map_err(|_| JournalError::ProtectedBoundary)?;
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
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn provision_origin(journal: &Journal, witness: &ProtectedWriterNameWitness) -> [u8; 32] {
    let mut digest = Sha256::new().chain_update(PROVISION_ORIGIN_DOMAIN);
    if let Some(location) = &journal.protected {
        digest.update(location.name().as_bytes());
    }
    digest.update([0]);
    for identity in [&witness.directory(), &witness.file(), &witness.lock()] {
        digest.update(identity.physical_pair().0.to_be_bytes());
        digest.update(identity.physical_pair().1.to_be_bytes());
    }
    digest.finalize().into()
}

fn require_bookend(
    journal: &Journal,
    witness: &ProtectedWriterNameWitness,
) -> Result<(), JournalError> {
    journal.ensure_healthy()?;
    journal.require_protected_names_current()?;
    journal.validate_protected_writer_name_witness(witness)?;
    if FileIdentity::of::<crate::journal::JournalError>(journal.native.file())? != witness.file() {
        return Err(JournalError::StaleAuthoritySnapshot);
    }
    Ok(())
}

fn require_replayed_snapshot(
    journal: &Journal,
    replayed: &ReplayState,
    observer: &NativePrefixObserverV1<'_>,
    physical_bytes: u64,
) -> Result<(), JournalError> {
    if replayed.durable_end != physical_bytes
        || observer.end_offset != physical_bytes
        || replayed.next_sequence != journal.native.next_sequence()
        || observer.next_sequence != journal.native.next_sequence()
        || replayed.committed_transactions != journal.native.committed_transactions()
        || observer.transactions != journal.native.committed_transactions()
        || observer.records != replayed.committed_records
        || replayed.transaction_ids != *journal.native.transaction_ids()
        || replayed.committed_namespaces != *journal.native.committed_namespaces()
        || replayed.state != *journal.native.state()
        || replayed.materialized_bytes != journal.native.materialized_bytes()
        || replayed.idempotency != journal.idempotency
        || replayed.q04_lower_history_present != journal.q04_lower_history_present
        || replayed.source_history_compacted
    {
        return Err(JournalError::StaleAuthoritySnapshot);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{has_durable_owner_fence_v1, require_original_source_cleanup_v1};
    use crate::journal::{JournalRecord, JournalTransaction, RecordNamespace};

    #[test]
    fn partial_owner_pair_remains_a_denial_not_absence() {
        let mut records = BTreeMap::new();
        assert!(!has_durable_owner_fence_v1(&records));

        records.insert(
            (RecordNamespace::DesiredState, b"z-git-birth-v1".to_vec()),
            Vec::new(),
        );
        assert!(has_durable_owner_fence_v1(&records));

        records.clear();
        records.insert(
            (RecordNamespace::DesiredState, b"z-git-fence-v1".to_vec()),
            Vec::new(),
        );
        assert!(has_durable_owner_fence_v1(&records));
    }

    #[test]
    fn foreign_namespace_and_near_prefix_are_not_owner_fences() {
        let records = BTreeMap::from([
            ((RecordNamespace::Effect, b"z-git-fence-v1".to_vec()), Vec::new()),
            ((RecordNamespace::DesiredState, b"z-git-fence-v1-extra".to_vec()), Vec::new()),
        ]);

        assert!(!has_durable_owner_fence_v1(&records));
    }

    #[test]
    fn partial_source_cleanup_cannot_delete_or_create_malformed_history() {
        let original = BTreeMap::new();
        let deletion = JournalTransaction::new([1; 16], vec![JournalRecord::delete(
            RecordNamespace::MountSourceAcquisition, b"unknown".to_vec(),
        )]).unwrap();
        let malformed = JournalTransaction::new([2; 16], vec![JournalRecord::put(
            RecordNamespace::MountSourceAcquisition, b"unknown".to_vec(), vec![1],
        )]).unwrap();

        assert!(require_original_source_cleanup_v1(&original, &deletion).is_err());
        assert!(require_original_source_cleanup_v1(&original, &malformed).is_err());
    }
}
