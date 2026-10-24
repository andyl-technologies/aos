//! Shares the complete canonical Cache reconstruction between actual native readers.
//!
//! These are passive raw-view comparisons. Source/Cache/Root native roles keep
//! their own fixed files, original receiving loan, cold replay and all posts;
//! no decoded map or successful model result supplies role authority.

use std::collections::BTreeMap;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;
use aos_sandbox_model::{ObjectDigest, ResourceDimension as D, ResourceVector, ProjectId};
use aos_sandbox_protocol::{
    cache_state::{
        NodeCacheQuotaV1,
        authority_record::{
            CacheAuthorityPurposeV1, CacheAuthorityRecordDataErrorV1,
            cache_authority_record_digest_v1, encode_cache_authority_record_v1,
        },
        clock_floor::{
            CACHE_CLOCK_KEY, CacheClockFloorDataErrorV1, CacheClockFloorDataV1,
            decode_cache_clock_floor,
        },
        fixed_journals::{CACHE_MAXIMUM_BOOTSTRAP_PARTITIONS_V1, CacheJournalRecipeRoleV1 as Role},
        protected_replay::{self as historical, CacheResidencyHistoricalSchemaDataV1 as Schema},
        recovery::{
            CacheRecoveryInventoryDataV1, CacheRecoveryLimitsV1, RecoveryError,
            recover_historical_inventory_data_v1,
            representation::{
                CacheReplayRepresentationPhaseV1, general_replay_representation_bound_v1,
            },
        },
        replay_envelope::{CacheReplayEnvelopeDataErrorV1, CacheReplayPartitionEvidenceDataV1},
        replay_evidence::{
            self, CACHE_MAXIMUM_REPLAY_MANIFESTS_V1, CACHE_REPLAY_MANIFEST_KEY_PREFIX_V1,
            CacheBootstrapHistoryDataErrorV1, cache_fixed_owner_scope_data_v1,
        },
    },
    domain_ledger::{
        DomainLedgerDataError,
        records::{ProtectedDomainProjectionV1, replay_projection_records},
    },
};

use aos_sandbox_protocol::cache_state::{
    complete_node_quotas::{CompleteNodeQuotaDataErrorV1, complete_node_quota_digest_v2},
    current_selection::{
        self, CacheCurrentSelectionDataErrorV1, CurrentProjectPhysicalCacheHeadDataV1,
    },
    hold_state::{CachePolicyHoldReadbackDataV1, decode_full_state},
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1;
use aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1;
/// Holds materialized canonical record keys and values as passive DATA.
pub type State = BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>;
type Evidence = CacheReplayPartitionEvidenceDataV1;

/// Preserves the actual typed canonical model refusal across native owners.
#[derive(Debug, thiserror::Error)]
pub enum CacheCurrentModelErrorV1 {
    /// Retains the canonical mechanical namespace/capacity refusal.
    #[error(transparent)]
    Mechanical(#[from] CanonicalJournalMechanicalErrorV1),
    /// Retains malformed bootstrap history.
    #[error(transparent)]
    Bootstrap(#[from] CacheBootstrapHistoryDataErrorV1),
    /// Retains malformed replay evidence framing.
    #[error(transparent)]
    Envelope(#[from] CacheReplayEnvelopeDataErrorV1),
    /// Retains the canonical recovery model refusal.
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
    /// Retains malformed canonical saved rows.
    #[error(transparent)]
    Projection(#[from] DomainLedgerDataError),
    /// Retains a malformed clock floor.
    #[error(transparent)]
    Clock(#[from] CacheClockFloorDataErrorV1),
    /// Retains malformed authority records.
    #[error(transparent)]
    Authority(#[from] CacheAuthorityRecordDataErrorV1),
    /// Retains malformed protected Hold history.
    #[error(transparent)]
    Hold(#[from] ProtectedHistoryDataErrorV1),
    /// Retains malformed Create history framing.
    #[error(transparent)]
    History(#[from] HistoryErrorV1),
    /// Retains an invalid current project selection.
    #[error(transparent)]
    Selection(#[from] CacheCurrentSelectionDataErrorV1),
    /// Retains an invalid complete node quota inventory.
    #[error(transparent)]
    Quotas(#[from] CompleteNodeQuotaDataErrorV1),
    /// Rejects disagreeing actual historical views.
    #[error("actual Cache historical views disagree")]
    Changed,
}

/// Borrows one complete saved native view as nonauthorizing comparison DATA.
///
/// Native roles independently establish parser, names, original payment and
/// posts. Public assembly preserves historical claims and supplies no proof.
#[derive(Clone, Copy)]
pub struct CacheRawJournalDataV1<'rows> {
    /// Holds the actual replayed map.
    pub state: &'rows State,
    /// Holds every namespace reached in committed native history.
    pub namespaces: &'rows std::collections::BTreeSet<aos_sandbox_model::RecordNamespace>,
    /// Holds the actual parser recovery counters.
    pub report: aos_sandbox_broker::canonical_journal::RecoveryReport,
}

/// Borrows the fixed complete five-view roster as comparison DATA only.
#[derive(Clone, Copy)]
pub struct CacheCurrentRawViewsDataV1<'rows> {
    /// Holds the Bootstrap history.
    pub bootstrap: CacheRawJournalDataV1<'rows>,
    /// Holds the Hold history.
    pub hold: CacheRawJournalDataV1<'rows>,
    /// Holds the State history.
    pub state: CacheRawJournalDataV1<'rows>,
    /// Holds the Authority history.
    pub authority: CacheRawJournalDataV1<'rows>,
    /// Holds the Clock history.
    pub clock: CacheRawJournalDataV1<'rows>,
}

impl CacheCurrentRawViewsDataV1<'_> {
    fn reader_v1(&self, role: Role) -> Option<&CacheRawJournalDataV1<'_>> {
        Some(match role {
            Role::Bootstrap => &self.bootstrap, Role::Hold => &self.hold,
            Role::State => &self.state, Role::Authority => &self.authority, Role::Clock => &self.clock,
        })
    }

    fn state_v1(&self, role: Role) -> Option<&State> { Some(self.reader_v1(role)?.state) }
}

impl CacheRawJournalDataV1<'_> {
    /// Checks the existing single-owner namespace and capacity-family grammar.
    ///
    /// # Errors
    /// Rejects foreign committed/materialized namespaces or capacity ownership.
    pub fn require_single_namespace_data_v1(&self, namespace: aos_sandbox_model::RecordNamespace)
        -> Result<(), CanonicalJournalMechanicalErrorV1>
    {
        use CanonicalJournalMechanicalErrorV1 as E;
        use aos_sandbox_model::RecordNamespace;
        use aos_sandbox_protocol::domain_ledger::capacity_family::{self, family};
        let state = self.state;
        family::require_legacy_reservations(state).map_err(E::from)?;
        let namespaces = self.namespaces;
        if namespaces.iter().any(|actual| {
            *actual != namespace && *actual != RecordNamespace::GlobalCapacityReservation
        }) || state.keys().any(|(actual, _)| {
            *actual != namespace && *actual != RecordNamespace::GlobalCapacityReservation
        }) || !capacity_family::all_reservations_owned_by(state, namespace).map_err(E::from)? {
            return Err(E::ForeignAuthorityNamespace);
        }
        Ok(())
    }

    /// Checks the existing Hold owner namespace and capacity-family grammar.
    ///
    /// # Errors
    /// Rejects foreign committed/materialized namespaces or capacity ownership.
    pub fn require_cache_hold_namespaces_data_v1(&self) -> Result<(), CanonicalJournalMechanicalErrorV1> {
        use CanonicalJournalMechanicalErrorV1 as E;
        use aos_sandbox_model::RecordNamespace as N;
        use aos_sandbox_protocol::domain_ledger::capacity_family::{self, family};
        let state = self.state;
        family::require_legacy_reservations(state).map_err(E::from)?;
        let namespaces = self.namespaces;
        let allowed = |namespace| matches!(namespace,
            N::DesiredState | N::CreateStorageHistory | N::GlobalCapacityReservation);
        if namespaces.iter().any(|namespace| !allowed(*namespace))
            || state.keys().any(|(namespace, _)| !allowed(*namespace))
            || !capacity_family::all_reservations_owned_by(state, N::DesiredState).map_err(E::from)? {
            return Err(E::ForeignAuthorityNamespace);
        }
        Ok(())
    }

    fn recovery_report_v1(&self) -> Option<aos_sandbox_broker::canonical_journal::RecoveryReport> { Some(self.report) }
}

/// Retains the canonical complete reconstructed Cache families as passive DATA.
pub struct CacheCurrentInventoryDataV1 {
    bootstrap: BTreeMap<ObjectDigest, Evidence>,
    authority: BTreeMap<ObjectDigest, Evidence>,
    projection: ProtectedDomainProjectionV1<Schema>,
    inventories: BTreeMap<ObjectDigest, CacheRecoveryInventoryDataV1>,
    quotas: Vec<NodeCacheQuotaV1>,
    selected: CurrentProjectPhysicalCacheHeadDataV1,
    quota_digest: ObjectDigest,
}

impl CacheCurrentInventoryDataV1 {
    /// Borrows every complete historical partition reducer without copying it.
    ///
    /// These DATA references create no Native Cache inventory or currentness.
    pub fn historical_inventories_data_v2(&self)
        -> impl ExactSizeIterator<Item = &CacheRecoveryInventoryDataV1> {
        self.inventories.values()
    }

    /// Gives the same canonical protected projection root as historical DATA.
    ///
    /// It commits the whole retained history, including nonactionable records.
    pub fn projection_root_data_v2(&self) -> ObjectDigest { self.projection.root() }

    /// Borrows the complete canonical node quotas.
    pub fn quotas_v1(&self) -> &[NodeCacheQuotaV1] { &self.quotas }

    /// Borrows the canonical project physical-head selection.
    pub fn selected_v1(&self) -> &CurrentProjectPhysicalCacheHeadDataV1 { &self.selected }

    /// Returns the complete canonical quota commitment.
    pub fn quota_digest_v1(&self) -> ObjectDigest { self.quota_digest }

    /// Checks each retained authority's unchanged expiry against an actual sample.
    ///
    /// # Errors
    /// Rejects a zero sample or any expired authority scope.
    pub fn require_live_at_v1(&self, now: u64) -> Result<(), CacheCurrentModelErrorV1> {
        if now == 0 || self.authority.values().any(|evidence| now >= evidence.scope.valid_until()) {
            return Err(CacheCurrentModelErrorV1::Changed);
        }
        Ok(())
    }
}

/// Decodes the complete canonical Cache clock family from a saved raw view.
///
/// # Errors
/// Rejects foreign namespaces, an invalid/duplicate clock row or owner scope.
pub fn decode_clock_v1(view: CacheRawJournalDataV1<'_>)
    -> Result<CacheClockFloorDataV1, CacheCurrentModelErrorV1> {
    use CacheCurrentModelErrorV1::Changed;
    use aos_sandbox_model::RecordNamespace;
    view.require_single_namespace_data_v1(RecordNamespace::DesiredState)?;
    let mut rows = view.state.iter();
    let Some(((namespace, key), bytes)) = rows.next() else { return Err(Changed); };
    let clock = decode_cache_clock_floor(bytes)?;
    if *namespace != RecordNamespace::DesiredState || key.as_slice() != CACHE_CLOCK_KEY
        || rows.next().is_some() || clock.owner_scope != cache_fixed_owner_scope_data_v1() {
        return Err(Changed);
    }
    Ok(clock)
}

/// Decodes the complete canonical Cache hold family without a role grant.
///
/// # Errors
/// Rejects foreign namespaces or a malformed/conflicting hold/pending family.
pub fn decode_hold_v1(view: CacheRawJournalDataV1<'_>)
    -> Result<CachePolicyHoldReadbackDataV1, CacheCurrentModelErrorV1> {
    use aos_sandbox_model::RecordNamespace;
    view.require_cache_hold_namespaces_data_v1()?;
    Ok(decode_full_state(view.state.iter()
        .filter(|((namespace, _), _)| *namespace == RecordNamespace::DesiredState)
        .map(|((_, key), value)| (key.as_slice(), value.as_slice())))?)
}

/// Reconstructs complete Bootstrap, Authority and State families once.
///
/// # Errors
/// Rejects malformed/foreign raw rows, incomplete rosters, invalid evidence,
/// history/group/quota disagreements or an unavailable project selection.
pub fn reconstruct_inventory_v1(journals: &CacheCurrentRawViewsDataV1<'_>, now: u64, project: ProjectId)
    -> Result<CacheCurrentInventoryDataV1, CacheCurrentModelErrorV1>
{
    use CacheCurrentModelErrorV1::Changed;
    use aos_sandbox_model::RecordNamespace;
    let limits = CacheRecoveryLimitsV1::default();
    let owner = cache_fixed_owner_scope_data_v1();
    let bootstrap_reader = journals.reader_v1(Role::Bootstrap).ok_or(Changed)?;
    bootstrap_reader.require_single_namespace_data_v1(RecordNamespace::DesiredState)?;
    let raw_bootstrap = actual_state(journals, Role::Bootstrap)?;
    let mut bootstrap = BTreeMap::new();
    for ((namespace, key), value) in raw_bootstrap {
        if *namespace != RecordNamespace::DesiredState
            || bootstrap.len() >= CACHE_MAXIMUM_BOOTSTRAP_PARTITIONS_V1
        {
            return Err(Changed);
        }
        let partition = replay_evidence::validate_source_record(key, value, limits)?;
        let evidence = replay_evidence::decode_genesis_manifest(value, limits)?;
        if bootstrap.insert(partition, evidence).is_some() {
            return Err(Changed);
        }
    }
    let report = bootstrap_reader.recovery_report_v1().ok_or(Changed)?;
    if bootstrap.is_empty()
        || report.truncated_bytes != 0
        || report.committed_transactions == 0
        || report.committed_transactions > bootstrap.len()
        || report.committed_records != bootstrap.len()
    {
        return Err(Changed);
    }

    let authority_reader = journals.reader_v1(Role::Authority).ok_or(Changed)?;
    authority_reader.require_single_namespace_data_v1(RecordNamespace::DesiredState)?;
    let raw_authority = actual_state(journals, Role::Authority)?;
    let mut authority = BTreeMap::new();
    let mut partitions = BTreeMap::new();
    let mut record_digests = BTreeMap::new();
    for ((namespace, key), value) in raw_authority {
        if *namespace != RecordNamespace::DesiredState
            || !key.starts_with(CACHE_REPLAY_MANIFEST_KEY_PREFIX_V1)
        {
            continue;
        }
        if authority.len() >= CACHE_MAXIMUM_REPLAY_MANIFESTS_V1 {
            return Err(Changed);
        }
        let evidence = replay_evidence::decode_cache_replay_manifest(value, limits)?;
        let partition = evidence.partition.digest();
        if key.get(CACHE_REPLAY_MANIFEST_KEY_PREFIX_V1.len()..)
            != Some(partition.as_bytes().as_slice())
            || evidence.purpose != CacheAuthorityPurposeV1::Replay
            || evidence.scope.partition() != partition
            || now >= evidence.scope.valid_until()
        {
            return Err(Changed);
        }
        let record = raw_authority
            .get(&(RecordNamespace::DesiredState, evidence.record_key.clone()))
            .ok_or(Changed)?;
        let expected = encode_cache_authority_record_v1(owner, evidence.purpose, evidence.scope);
        if record.as_slice() != expected.as_slice() {
            return Err(Changed);
        }
        let digest = cache_authority_record_digest_v1(&evidence.record_key, record);
        // Native admission validates the complete checkpoint-only inventory
        // before any State suffix. Use that same canonical recovery here.
        recover_historical_inventory_data_v1(
            evidence.partition,
            &evidence.typed_checkpoint,
            evidence.prior_typed_checkpoint.as_deref(),
            evidence.floor,
            std::iter::empty(),
            limits,
            evidence.scope,
            digest,
        )?;
        let source = bootstrap.get(&partition).ok_or(Changed)?;
        if replay_evidence::encode_cache_replay_manifest(source, limits)?.as_slice()
            != value.as_slice()
        {
            return Err(Changed);
        }
        if partitions.insert(partition, evidence.partition).is_some()
            || record_digests.insert(partition, digest).is_some()
            || authority.insert(partition, evidence).is_some()
        {
            return Err(Changed);
        }
    }
    if authority.is_empty() || authority.len() != bootstrap.len() {
        return Err(Changed);
    }

    let state = actual_state(journals, Role::State)?;
    let projection = replay_projection_records::<Schema>(
        state
            .iter()
            .map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice())),
        &limits,
    )?;
    let historical::CachePartitionHistoryDataV1 {
        partitions,
        mut records_by_partition,
        mut checkpoints_by_partition,
    } = historical::group_cache_history_data_v1::<Schema>(
        projection.records(),
        &limits,
        limits,
        partitions,
    )?;
    let mut inventories = BTreeMap::new();
    let mut quotas = Vec::new();
    for (digest, partition) in partitions {
        let evidence = authority.get(&digest).ok_or(Changed)?;
        let checkpoints = checkpoints_by_partition.remove(&digest).unwrap_or_default();
        let records = records_by_partition
            .remove(&digest)
            .unwrap_or_default()
            .into_values()
            .collect::<Vec<_>>();
        replay_evidence::validate_partition_session_history_data_v1(
            evidence,
            partition,
            evidence.scope,
            &checkpoints,
        )?;
        let inventory = recover_historical_inventory_data_v1(
            partition,
            &evidence.typed_checkpoint,
            evidence.prior_typed_checkpoint.as_deref(),
            evidence.floor,
            records.iter().cloned(),
            limits,
            evidence.scope,
            *record_digests.get(&digest).ok_or(Changed)?,
        )?;
        historical::validate_partition_history_tail_data_v1(
            &inventory, &records, partition, limits,
        )?;
        quotas.push(inventory.global.node_quota);
        inventories.insert(digest, inventory);
    }
    historical::validate_projection_transaction_groups_data_v1(&projection, &limits, limits)?;
    let selected = current_selection::select_project_physical_cache_head(
        project,
        inventories.values(),
    )?;
    let quota_digest = complete_node_quota_digest_v2(&quotas)?;
    Ok(CacheCurrentInventoryDataV1 {
        bootstrap, authority, projection, inventories, quotas, selected, quota_digest,
    })
}

fn actual_state<'a>(journals: &'a CacheCurrentRawViewsDataV1<'_>, role: Role)
    -> Result<&'a State, CacheCurrentModelErrorV1> {
    journals.state_v1(role).ok_or(CacheCurrentModelErrorV1::Changed)
}

/// Computes the original complete reconstruction bound from actual raw rows.
///
/// # Errors
/// Rejects unavailable raw families or overflowing cardinality/byte geometry.
pub fn model_geometry_v1(
    journals: &CacheCurrentRawViewsDataV1<'_>,
) -> Result<ResourceVector, RecoveryError> {
    let mut encoded = 0usize;
    let mut rows = 0usize;
    for role in [Role::Bootstrap, Role::Authority, Role::State] {
        let state = journals
            .state_v1(role)
            .ok_or(RecoveryError::AnchorMismatch)?;
        for ((_, key), value) in state {
            encoded = encoded
                .checked_add(key.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or(RecoveryError::Capacity)?;
            rows = rows.checked_add(1).ok_or(RecoveryError::Capacity)?;
        }
    }
    let base = general_replay_representation_bound_v1(
        encoded,
        rows,
        CacheReplayRepresentationPhaseV1::InitialInventory,
    )?;
    // This additional output Vec is distinct from every recovered global quota.
    let quota_bytes = rows
        .max(4)
        .checked_mul(std::mem::size_of::<NodeCacheQuotaV1>())
        .and_then(|bytes| bytes.checked_mul(3))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(RecoveryError::Capacity)?;
    // The canonical project selector constructs its own candidate Vec while
    // the inventory map and complete quota output remain resident.
    let candidate_bytes = rows
        .max(4)
        .checked_mul(std::mem::size_of::<CurrentProjectPhysicalCacheHeadDataV1>())
        .and_then(|bytes| bytes.checked_mul(3))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(RecoveryError::Capacity)?;
    let raw_views_bytes = std::mem::size_of::<CacheCurrentRawViewsDataV1<'static>>()
        .checked_mul(2).and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(RecoveryError::Capacity)?;
    let additional_bytes = quota_bytes
        .checked_add(candidate_bytes).and_then(|bytes| bytes.checked_add(raw_views_bytes))
        .and_then(|bytes| {
            let history_bytes = std::mem::size_of::<historical::CachePartitionHistoryDataV1>()
                .checked_mul(2)
                .and_then(|bytes| u64::try_from(bytes).ok())?;
            bytes.checked_add(history_bytes)
        })
        .ok_or(RecoveryError::Capacity)?;
    base.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, additional_bytes))
        .map_err(|_| RecoveryError::Capacity)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use aos_sandbox_model::RecordNamespace;

    #[test]
    fn committed_foreign_namespace_is_rejected_even_when_no_row_survives() {
        let rows = State::new();
        let namespaces = BTreeSet::from([RecordNamespace::Effect]);
        let report = Default::default();
        let actual = CacheRawJournalDataV1 { state: &rows, namespaces: &namespaces, report };

        assert!(matches!(actual.require_single_namespace_data_v1(RecordNamespace::CreateStorageHistory),
            Err(CanonicalJournalMechanicalErrorV1::ForeignAuthorityNamespace)));
    }
}
