//! Explicit, fail-closed `AOSMSA01` to `AOSMSA02` migration planning.
//!
//! The v2 decoder never accepts v1 bytes. This module separately decodes the
//! complete canonical legacy graph, then requires a fully validated v2 graph
//! carrying supplemental four-key trust, execution, normalized-intent, floor,
//! attempt, and holder-sequence provenance before it can emit v2 records.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};

use super::format::{
    MAXIMUM_SOURCE_ACQUISITIONS, MAXIMUM_SOURCE_PROVIDER_HEADS, encode_mount_source_state_record_v2,
};
use super::migration_v1::{
    ProviderDispositionCheckpointV1, ProviderMethodV1, ProviderStatusV1, SourceAcquisitionPhaseV1,
    SourceAcquisitionProofClassV1, SourceAcquisitionRowV1, SourceProviderHeadV1, StoredEnvelopeV1,
    StoredRecordV1,
};
use super::model::{SourceAcquisitionPhaseV2, SourceAcquisitionProofClassV2, StoredRecordV2};
use super::{
    MountSourceAcquisitionStateError, MountSourceAcquisitionStateV2, Result,
    validate_mount_source_state_graph_v2,
};

const LEGACY_SCHEMA: &str = "AOSMSA01";
const LEGACY_VERSION: u16 = 1;
const LEGACY_ACQUISITION_PREFIX: &[u8] = b"aos.mount.source-acquisition.v1\0";
const LEGACY_HEAD_PREFIX: &[u8] = b"aos.mount.source-provider-head.v1\0";
const LEGACY_RECORD_DOMAIN: &[u8] = b"aos.sandbox.mount.source-acquisition-record.v1\0";
const MAXIMUM_LEGACY_VALUE_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_LEGACY_MATERIALIZED_BYTES: usize = 512 * 1024 * 1024;

/// Holds one strictly decoded canonical legacy graph without granting authority.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct LegacyMountSourceStateV1 {
    acquisitions: BTreeMap<[u8; 32], SourceAcquisitionRowV1>,
    provider_heads: BTreeMap<([u8; 16], [u8; 16]), SourceProviderHeadV1>,
}

impl LegacyMountSourceStateV1 {
    /// Returns the number of retained legacy acquisitions and provider heads.
    #[must_use]
    pub fn record_counts(&self) -> (usize, usize) {
        (self.acquisitions.len(), self.provider_heads.len())
    }

    fn is_empty(&self) -> bool {
        self.acquisitions.is_empty() && self.provider_heads.is_empty()
    }
}

/// Contains the exact canonical v2 records authorized by a migration plan.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct MountSourceStateMigrationPlanV2 {
    records: Vec<(Vec<u8>, Vec<u8>)>,
}

impl MountSourceStateMigrationPlanV2 {
    /// Returns canonical v2 key/value pairs in bytewise key order.
    #[must_use]
    pub fn records(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.records
    }
}

/// Classifies an explicit migration without mutating either journal.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub enum MountSourceStateMigrationDispositionV2 {
    /// Migration is fully proven and these canonical v2 records may be staged.
    Ready(MountSourceStateMigrationPlanV2),
    /// Retained v1 authority cannot be upgraded without complete v2 provenance.
    NeedsProvenance {
        /// Number of legacy acquisition rows requiring exact provenance.
        acquisition_count: usize,
        /// Number of legacy provider heads requiring exact provenance.
        provider_head_count: usize,
    },
    /// The supplied graph cannot be represented without fabricating authority.
    Unsupported,
}

/// Strictly decodes a complete explicit legacy namespace-40 snapshot.
///
/// This does not make v1 an alternative input to the v2 decoder. It exists
/// solely for the bounded migration planner and validates exact keys,
/// canonical serde encoding, record identity, self-digests, uniqueness, count,
/// and aggregate materialization limits.
///
/// # Errors
///
/// Returns an error for any unsupported key/value, noncanonical or unknown
/// field, digest mismatch, duplicate identity, or exceeded bound.
#[doc(hidden)]
pub fn decode_mount_source_state_graph_v1<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<LegacyMountSourceStateV1> {
    let mut acquisitions = BTreeMap::new();
    let mut provider_heads = BTreeMap::new();
    let mut materialized_bytes = 0usize;

    for (key, value) in records {
        materialized_bytes = materialized_bytes
            .checked_add(key.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or_else(|| invalid("legacy materialized byte count overflowed"))?;
        if value.is_empty()
            || value.len() > MAXIMUM_LEGACY_VALUE_BYTES
            || materialized_bytes > MAXIMUM_LEGACY_MATERIALIZED_BYTES
        {
            return Err(invalid("legacy record exceeds a migration bound"));
        }
        let envelope: StoredEnvelopeV1 = serde_json::from_slice(value)
            .map_err(|_| invalid("legacy record is not closed canonical JSON"))?;
        if envelope.schema != LEGACY_SCHEMA
            || envelope.version != LEGACY_VERSION
            || serde_json::to_vec(&envelope)
                .map_err(|_| invalid("legacy record could not be reproduced"))?
                != value
        {
            return Err(invalid("legacy schema, version, or encoding differs"));
        }

        match envelope.record {
            StoredRecordV1::Acquisition { row } => {
                if key != legacy_acquisition_key(row.acquisition_id)
                    || row.record_digest != legacy_acquisition_digest(&row)?
                    || !valid_legacy_row(&row)
                    || acquisitions.insert(row.acquisition_id, row).is_some()
                    || acquisitions.len() > MAXIMUM_SOURCE_ACQUISITIONS
                {
                    return Err(invalid("legacy acquisition identity or digest differs"));
                }
            }
            StoredRecordV1::ProviderHead { head } => {
                let identity = (head.holder_authority_id, head.provider_authority_id);
                if key != legacy_head_key(identity.0, identity.1)
                    || !valid_legacy_head(&head)
                    || provider_heads.insert(identity, head).is_some()
                    || provider_heads.len() > MAXIMUM_SOURCE_PROVIDER_HEADS
                {
                    return Err(invalid("legacy provider-head identity differs"));
                }
            }
        }
    }

    Ok(LegacyMountSourceStateV1 {
        acquisitions,
        provider_heads,
    })
}

fn valid_legacy_row(row: &SourceAcquisitionRowV1) -> bool {
    let request_digest =
        super::super::mount_source_acquisition_request_digest_v1(&row.mount_acquire_request);
    let expected_id =
        super::super::mount_source_acquisition_id_v1(row.acquire.operation_id, request_digest);
    let provider = &row.provider;
    let provider_shape = provider.holder_authority_id != [0; 16]
        && provider.holder_generation > 0
        && provider.holder_authority_digest != [0; 32]
        && provider.node_id != [0; 16]
        && provider.kernel_boot_id != [0; 16]
        && provider.revocation_digest != [0; 32]
        && provider.provider_route_id != [0; 16]
        && provider.provider_route_generation > 0
        && provider.provider_route_digest != [0; 32]
        && provider.provider_authority_id != [0; 16]
        && provider.provider_authority_generation > 0
        && provider.provider_authority_digest != [0; 32]
        && provider.provider_key_id != [0; 16]
        && provider.provider_key_generation > 0
        && provider.provider_public_key_digest != [0; 32]
        && provider.resource_namespace_digest != [0; 32]
        && provider.session_binding != [0; 32];
    let consumption_presence = [
        row.consumed_source_pin_record_digest.is_some(),
        row.consumed_create_effect_record_digest.is_some(),
        row.consumed_create_operation_record_digest.is_some(),
    ];
    let consumption_shape = consumption_presence.iter().all(|value| *value)
        || consumption_presence.iter().all(|value| !*value);
    let release_presence = [
        row.release.is_some(),
        row.mount_release_request.is_some(),
        row.release_authority.is_some(),
        row.release_provider.is_some(),
        row.release_inventory_observation_floor.is_some(),
        row.provider_release_request.is_some(),
        row.provider_release_request_digest.is_some(),
        row.initial_provider_release_request.is_some(),
        row.initial_provider_release_request_digest.is_some(),
    ];
    let effective_phase = if row.phase == SourceAcquisitionPhaseV1::Faulted {
        row.faulted_from
    } else {
        Some(row.phase)
    };
    let requires_release = matches!(
        effective_phase,
        Some(SourceAcquisitionPhaseV1::Releasing | SourceAcquisitionPhaseV1::Released)
    );
    let requires_evidence = matches!(
        effective_phase,
        Some(
            SourceAcquisitionPhaseV1::DescriptorCustodied
                | SourceAcquisitionPhaseV1::Active
                | SourceAcquisitionPhaseV1::Consumed
                | SourceAcquisitionPhaseV1::Releasing
                | SourceAcquisitionPhaseV1::Released
        )
    );
    row.revision > 0
        && row.acquire.operation_id != [0; 16]
        && row.acquire.request_digest == *request_digest.as_bytes()
        && row.acquisition_id == *expected_id.as_bytes()
        && row.prospective_mount_template_digest != [0; 32]
        && row.source_binding_digest != [0; 32]
        && row.mount_plan_digest != [0; 32]
        && row.ownership_lease_digest != [0; 32]
        && provider_shape
        && consumption_shape
        && (!requires_evidence || row.evidence.is_some())
        && (if requires_release {
            release_presence.iter().all(|value| *value)
        } else {
            release_presence.iter().all(|value| !*value)
        })
        && (row.phase == SourceAcquisitionPhaseV1::Faulted)
            == (row.faulted_from.is_some() && row.fault_digest.is_some())
        && (row.retained_faulted_from.is_some() == row.retained_fault_digest.is_some())
}

fn valid_legacy_head(head: &SourceProviderHeadV1) -> bool {
    let direction_shape = match &head.pending_query {
        None => head.next_request_sequence == head.next_response_sequence,
        Some(pending) => {
            head.next_response_sequence < u64::MAX
                && head.next_request_sequence == head.next_response_sequence + 1
                && pending.request_sequence == head.next_response_sequence
                && pending.request_sequence > 0
                && pending.signed_request_digest != [0; 32]
                && !pending.signed_request.is_empty()
        }
    };
    let inventory_presence = [
        head.inventory_generation.is_some(),
        head.inventory_digest.is_some(),
        head.signed_inventory_digest.is_some(),
        !head.signed_inventory.is_empty(),
        head.catalog_generation.is_some(),
        head.catalog_digest.is_some(),
    ];
    head.holder_authority_id != [0; 16]
        && head.holder_generation > 0
        && head.holder_authority_digest != [0; 32]
        && head.provider_authority_id != [0; 16]
        && head.provider_authority_generation > 0
        && head.provider_authority_digest != [0; 32]
        && head.session_binding != [0; 32]
        && head.kernel_boot_id != [0; 16]
        && head.next_request_sequence > 0
        && head.next_response_sequence > 0
        && head.route_generation > 0
        && head.route_id != [0; 16]
        && head.route_digest != [0; 32]
        && head.provider_key_generation > 0
        && head.provider_key_id != [0; 16]
        && head.provider_public_key_digest != [0; 32]
        && head.resource_namespace_digest != [0; 32]
        && head.revocation_digest != [0; 32]
        && direction_shape
        && (inventory_presence.iter().all(|value| *value)
            || inventory_presence.iter().all(|value| !*value))
}

/// Plans one explicit hard-cut migration to canonical `AOSMSA02` records.
///
/// Empty legacy state migrates deterministically to an empty v2 graph. Any
/// retained row or head requires a complete supplemental v2 snapshot. The
/// planner validates that snapshot using the ordinary v2 whole-graph verifier,
/// then exact-crosslinks every legacy fact that remains meaningful in v2. It
/// never synthesizes missing trust, execution, intent, floor, sequence, or
/// attempt evidence. A consumed legacy row requires exact companion-record
/// provenance that this namespace-only planner cannot accept, so it remains
/// `NeedsProvenance` rather than inventing new v2 consumption correlations.
///
/// # Errors
///
/// Returns an error when either supplied graph is malformed or supplemental
/// records fail exact legacy-to-v2 correlation.
#[doc(hidden)]
pub fn plan_mount_source_state_migration_v2(
    legacy_records: &[(Vec<u8>, Vec<u8>)],
    supplemental_v2_records: Option<&[(Vec<u8>, Vec<u8>)]>,
) -> Result<MountSourceStateMigrationDispositionV2> {
    let legacy = decode_mount_source_state_graph_v1(
        legacy_records
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )?;
    if legacy.is_empty() {
        return Ok(MountSourceStateMigrationDispositionV2::Ready(
            MountSourceStateMigrationPlanV2 {
                records: Vec::new(),
            },
        ));
    }
    if legacy
        .acquisitions
        .values()
        .any(legacy_consumption_requires_companion_provenance)
    {
        return Ok(MountSourceStateMigrationDispositionV2::NeedsProvenance {
            acquisition_count: legacy.acquisitions.len(),
            provider_head_count: legacy.provider_heads.len(),
        });
    }
    let Some(supplemental) = supplemental_v2_records else {
        return Ok(MountSourceStateMigrationDispositionV2::NeedsProvenance {
            acquisition_count: legacy.acquisitions.len(),
            provider_head_count: legacy.provider_heads.len(),
        });
    };
    let state = validate_mount_source_state_graph_v2(
        supplemental
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )?;
    if validate_legacy_join(&legacy, &state).is_err() {
        return Ok(MountSourceStateMigrationDispositionV2::Unsupported);
    }

    Ok(MountSourceStateMigrationDispositionV2::Ready(
        MountSourceStateMigrationPlanV2 {
            records: encode_state(&state)?,
        },
    ))
}

fn validate_legacy_join(
    legacy: &LegacyMountSourceStateV1,
    current: &MountSourceAcquisitionStateV2,
) -> Result<()> {
    if legacy.acquisitions.len() != current.acquisitions.len()
        || legacy.provider_heads.len() != current.provider_heads.len()
    {
        return Err(invalid(
            "supplemental graph does not preserve legacy members",
        ));
    }
    let legacy_holders = legacy
        .provider_heads
        .keys()
        .map(|(holder, _)| *holder)
        .chain(
            legacy
                .acquisitions
                .values()
                .map(|row| row.provider.holder_authority_id),
        )
        .collect::<std::collections::BTreeSet<_>>();
    if current
        .holder_sequences
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        != legacy_holders
    {
        return Err(invalid(
            "supplemental graph changes stable holder-sequence membership",
        ));
    }
    for (id, old) in &legacy.acquisitions {
        let new = current
            .acquisitions
            .get(id)
            .ok_or_else(|| invalid("supplemental graph omits a legacy acquisition"))?;
        if new.revision != old.revision
            || new.acquisition_id != old.acquisition_id
            || new.phase != phase(old.phase)
            || new.acquire.operation_id != old.acquire.operation_id
            || new.acquire.request_digest != old.acquire.request_digest
            || new.mount_acquire_request != old.mount_acquire_request
            || new.scope.holder_authority_id != old.provider.holder_authority_id
            || new.scope.provider_authority_id != old.provider.provider_authority_id
            || new.scope.route_id != old.provider.provider_route_id
            || new.scope.resource_namespace_digest != old.provider.resource_namespace_digest
            || new.provider_acquisition.holder_authority_id != old.provider.holder_authority_id
            || new.provider_acquisition.holder_authority_generation
                != old.provider.holder_generation
            || new.provider_acquisition.holder_authority_digest
                != old.provider.holder_authority_digest
            || new.assignment.sandbox_id != old.assignment.sandbox_id
            || new.assignment.incarnation_id != old.assignment.incarnation_id
            || new.assignment.assignment_epoch != old.assignment.assignment_epoch
            || new.assignment.desired_generation != old.assignment.desired_generation
            || new.assignment.assignment_digest != old.assignment.assignment_digest
            || new.assignment.namespace_generation != old.assignment.namespace_generation
            || new.prospective_mount_template != old.prospective_mount_template
            || new.prospective_mount_template_digest != old.prospective_mount_template_digest
            || new.source_binding != old.source_binding
            || new.source_binding_digest != old.source_binding_digest
            || new.mount_plan_digest != old.mount_plan_digest
            || new.ownership_lease_digest != old.ownership_lease_digest
            || new.descriptor_custody_digest != old.descriptor_custody_digest
            || new.positive_custody_digest != old.positive_custody_digest
            || new.negative_custody_digest != old.negative_custody_digest
            || !consumption_matches(old, new)
            || !release_proof_matches(old, new)
            || new.faulted_from.map(phase_v2_to_v1) != old.faulted_from
            || new.fault_digest != old.fault_digest
            || new.retained_faulted_from.map(phase_v2_to_v1) != old.retained_faulted_from
            || new.retained_fault_digest != old.retained_fault_digest
            || !release_matches(old, new, current)
            || !evidence_matches(old, new)
            || !attempt_history_matches(old, current)
            || !provider_context_matches_acquire(old, new, current)
        {
            return Err(invalid("supplemental acquisition changes a legacy fact"));
        }
    }
    for (identity, old) in &legacy.provider_heads {
        let new = current
            .provider_heads
            .get(identity)
            .ok_or_else(|| invalid("supplemental graph omits a legacy provider head"))?;
        let session = current
            .provider_sessions
            .get(&new.current_session_id)
            .ok_or_else(|| invalid("supplemental head session is absent"))?;
        let provider_outcome_signer = &session.signers[3];
        if new.revision != old.revision
            || new.scope.holder_authority_id != old.holder_authority_id
            || new.scope.provider_authority_id != old.provider_authority_id
            || new.scope.route_id != old.route_id
            || new.scope.resource_namespace_digest != old.resource_namespace_digest
            || new.holder_authority_generation != old.holder_generation
            || new.holder_authority_digest != old.holder_authority_digest
            || new.provider_authority_generation != old.provider_authority_generation
            || new.provider_authority_digest != old.provider_authority_digest
            || new.next_request_sequence != old.next_request_sequence
            || new.next_response_sequence != old.next_response_sequence
            || new.inventory_observation_ordinal != old.inventory_observation_ordinal
            || session.session_binding != old.session_binding
            || session.kernel_boot_id != old.kernel_boot_id
            || session.route_generation != old.route_generation
            || session.route_digest != old.route_digest
            || session.revocation_digest != old.revocation_digest
            || provider_outcome_signer.key_id != old.provider_key_id
            || provider_outcome_signer.key_generation != old.provider_key_generation
            || provider_outcome_signer.public_key_fingerprint != old.provider_public_key_digest
            || new
                .last_reconciliation
                .as_ref()
                .is_some_and(|value| value.residual_count > 0)
                != old.has_untracked_inventory_residuals
            || new
                .last_reconciliation
                .as_ref()
                .is_some_and(|value| value.conflict_count > 0)
                != old.has_inventory_authority_conflicts
            || !head_history_matches(old, new, current)
        {
            return Err(invalid("supplemental provider head changes a legacy fact"));
        }
    }
    Ok(())
}

fn attempt_history_matches(
    old: &SourceAcquisitionRowV1,
    state: &MountSourceAcquisitionStateV2,
) -> bool {
    let mut acquire_attempts = state
        .provider_attempts
        .values()
        .filter(|attempt| {
            attempt.owner.owner_id() == old.acquisition_id
                && attempt.method == super::model::ProviderMethodV2::Acquire
        })
        .collect::<Vec<_>>();
    acquire_attempts.sort_by_key(|attempt| attempt.attempt_number);
    let acquire_checkpoints = old
        .acquire_history
        .iter()
        .chain(old.acquire_checkpoint.iter())
        .collect::<Vec<_>>();
    if !lineage_attempts_match(
        &acquire_attempts,
        &acquire_checkpoints,
        &old.provider_acquire_request,
        old.provider_acquire_request_digest,
    ) {
        return false;
    }

    let mut release_attempts = state
        .provider_attempts
        .values()
        .filter(|attempt| {
            attempt.owner.owner_id() == old.acquisition_id
                && attempt.method == super::model::ProviderMethodV2::Release
        })
        .collect::<Vec<_>>();
    release_attempts.sort_by_key(|attempt| attempt.attempt_number);
    let release_checkpoints = old
        .release_history
        .iter()
        .chain(old.release_checkpoint.iter())
        .collect::<Vec<_>>();
    match (
        &old.provider_release_request,
        old.provider_release_request_digest,
    ) {
        (None, None) => release_attempts.is_empty() && release_checkpoints.is_empty(),
        (Some(request), Some(digest)) => {
            lineage_attempts_match(&release_attempts, &release_checkpoints, request, digest)
        }
        _ => false,
    }
}

fn lineage_attempts_match(
    attempts: &[&super::model::SourceProviderQueryAttemptV2],
    checkpoints: &[&ProviderDispositionCheckpointV1],
    current_request: &[u8],
    current_request_digest: [u8; 32],
) -> bool {
    let consumed_count = attempts
        .iter()
        .take_while(|attempt| {
            matches!(
                attempt.state,
                super::model::ProviderAttemptStateV2::DispositionConsumed { .. }
            )
        })
        .count();
    if consumed_count != checkpoints.len()
        || !attempts[..consumed_count]
            .iter()
            .zip(checkpoints)
            .all(|(attempt, checkpoint)| checkpoint_matches_attempt(checkpoint, attempt))
        || attempts.len() > consumed_count + 1
        || attempts.get(consumed_count).is_some_and(|attempt| {
            !matches!(
                attempt.state,
                super::model::ProviderAttemptStateV2::Reserved
            )
        })
    {
        return false;
    }
    attempts.last().is_some_and(|attempt| {
        attempt.signed_request == current_request
            && attempt.signed_request_digest == current_request_digest
    })
}

fn checkpoint_matches_attempt(
    checkpoint: &ProviderDispositionCheckpointV1,
    attempt: &super::model::SourceProviderQueryAttemptV2,
) -> bool {
    let method = match checkpoint.method {
        ProviderMethodV1::Acquire => super::model::ProviderMethodV2::Acquire,
        ProviderMethodV1::Release => super::model::ProviderMethodV2::Release,
        ProviderMethodV1::Inventory => super::model::ProviderMethodV2::Inventory,
    };
    let status = match checkpoint.status {
        ProviderStatusV1::Complete => super::model::ProviderStatusV2::Complete,
        ProviderStatusV1::Pending => super::model::ProviderStatusV2::Pending,
        ProviderStatusV1::Rejected => super::model::ProviderStatusV2::Rejected,
        ProviderStatusV1::Unavailable => super::model::ProviderStatusV2::Unavailable,
    };
    attempt.method == method
        && attempt.request_sequence == checkpoint.request_sequence
        && attempt.signed_request == checkpoint.signed_request
        && attempt.signed_request_digest == checkpoint.signed_request_digest
        && matches!(
            &attempt.state,
            super::model::ProviderAttemptStateV2::DispositionConsumed {
                response_sequence,
                status: attempt_status,
                signed_status,
                signed_status_digest,
                signed_result,
                signed_result_digest,
                ..
            } if *response_sequence == checkpoint.response_sequence
                && *attempt_status == status
                && signed_status == &checkpoint.signed_status
                && *signed_status_digest == checkpoint.signed_status_digest
                && signed_result == &checkpoint.signed_result
                && *signed_result_digest == checkpoint.result_digest
        )
}

fn head_history_matches(
    old: &SourceProviderHeadV1,
    new: &super::model::SourceProviderHeadV2,
    state: &MountSourceAcquisitionStateV2,
) -> bool {
    let pending_matches = match (&old.pending_query, new.pending_attempt) {
        (None, None) => true,
        (Some(old), Some(reference)) => {
            let expected_owner = match old.owner {
                super::migration_v1::ProviderQueryOwnerV1::Acquire { acquisition_id } => {
                    super::model::ProviderQueryOwnerV2::Acquire { acquisition_id }
                }
                super::migration_v1::ProviderQueryOwnerV1::Release { acquisition_id } => {
                    super::model::ProviderQueryOwnerV2::Release { acquisition_id }
                }
                super::migration_v1::ProviderQueryOwnerV1::Inventory => {
                    super::model::ProviderQueryOwnerV2::Inventory
                }
            };
            state
                .provider_attempts
                .get(&reference.id)
                .is_some_and(|attempt| {
                    attempt.revision == reference.revision
                        && attempt.record_digest == reference.record_digest
                        && matches!(
                            attempt.state,
                            super::model::ProviderAttemptStateV2::Reserved
                        )
                        && attempt.owner == expected_owner
                        && attempt.request_sequence == old.request_sequence
                        && attempt.signed_request_digest == old.signed_request_digest
                        && attempt.signed_request == old.signed_request
                })
        }
        _ => false,
    };
    let floor_matches = match (
        old.inventory_generation,
        old.inventory_digest,
        old.signed_inventory_digest,
        old.catalog_generation,
        old.catalog_digest,
        &new.inventory_floor,
    ) {
        (None, None, None, None, None, None) => old.signed_inventory.is_empty(),
        (
            Some(inventory_generation),
            Some(inventory_digest),
            Some(signed_result_digest),
            Some(catalog_generation),
            Some(catalog_digest),
            Some(floor),
        ) => {
            floor.inventory_generation == inventory_generation
                && floor.inventory_digest == inventory_digest
                && floor.signed_result_digest == signed_result_digest
                && floor.catalog_generation == catalog_generation
                && floor.catalog_digest == catalog_digest
                && state
                    .provider_attempts
                    .get(&floor.attempt.id)
                    .is_some_and(|attempt| {
                        attempt.revision == floor.attempt.revision
                            && attempt.record_digest == floor.attempt.record_digest
                            && matches!(
                                &attempt.state,
                                super::model::ProviderAttemptStateV2::DispositionConsumed {
                                    status: super::model::ProviderStatusV2::Complete,
                                    signed_result,
                                    signed_result_digest: digest,
                                    ..
                                } if signed_result == &old.signed_inventory
                                    && digest == &signed_result_digest
                            )
                    })
        }
        _ => false,
    };
    let last_checkpoint_matches = match (&old.last_inventory_checkpoint, new.last_inventory_attempt)
    {
        (None, None) => true,
        (Some(checkpoint), Some(reference)) => state
            .provider_attempts
            .get(&reference.id)
            .is_some_and(|attempt| {
                attempt.revision == reference.revision
                    && attempt.record_digest == reference.record_digest
                    && inventory_checkpoint_matches_attempt(
                        checkpoint,
                        &old.signed_inventory,
                        attempt,
                    )
            }),
        _ => false,
    };
    let retained_inventory_attempts = state
        .provider_attempts
        .values()
        .filter(|attempt| {
            attempt.scope == new.scope
                && attempt.method == super::model::ProviderMethodV2::Inventory
        })
        .map(|attempt| attempt.attempt_id)
        .collect::<std::collections::BTreeSet<_>>();
    let expected_inventory_attempts = new
        .pending_attempt
        .into_iter()
        .chain(new.inventory_floor.as_ref().map(|floor| floor.attempt))
        .chain(new.last_inventory_attempt)
        .filter_map(|reference| {
            state
                .provider_attempts
                .get(&reference.id)
                .filter(|attempt| attempt.method == super::model::ProviderMethodV2::Inventory)
                .map(|attempt| attempt.attempt_id)
        })
        .collect::<std::collections::BTreeSet<_>>();
    pending_matches
        && floor_matches
        && last_checkpoint_matches
        && retained_inventory_attempts == expected_inventory_attempts
}

fn inventory_checkpoint_matches_attempt(
    checkpoint: &ProviderDispositionCheckpointV1,
    retained_inventory: &[u8],
    attempt: &super::model::SourceProviderQueryAttemptV2,
) -> bool {
    if checkpoint.method != ProviderMethodV1::Inventory
        || attempt.method != super::model::ProviderMethodV2::Inventory
        || attempt.request_sequence != checkpoint.request_sequence
        || attempt.signed_request != checkpoint.signed_request
        || attempt.signed_request_digest != checkpoint.signed_request_digest
    {
        return false;
    }
    let expected_status = match checkpoint.status {
        ProviderStatusV1::Complete => super::model::ProviderStatusV2::Complete,
        ProviderStatusV1::Pending => super::model::ProviderStatusV2::Pending,
        ProviderStatusV1::Rejected => super::model::ProviderStatusV2::Rejected,
        ProviderStatusV1::Unavailable => super::model::ProviderStatusV2::Unavailable,
    };
    matches!(
        &attempt.state,
        super::model::ProviderAttemptStateV2::DispositionConsumed {
            response_sequence,
            status,
            signed_status,
            signed_status_digest,
            signed_result,
            signed_result_digest,
            ..
        } if *response_sequence == checkpoint.response_sequence
            && *status == expected_status
            && signed_status == &checkpoint.signed_status
            && *signed_status_digest == checkpoint.signed_status_digest
            && *signed_result_digest == checkpoint.result_digest
            && if checkpoint.status == ProviderStatusV1::Complete {
                signed_result == retained_inventory
            } else {
                signed_result == &checkpoint.signed_result
            }
    )
}

fn consumption_matches(
    old: &SourceAcquisitionRowV1,
    new: &super::model::SourceAcquisitionRowV2,
) -> bool {
    match &new.consumption {
        None => {
            old.consumed_source_pin_record_digest.is_none()
                && old.consumed_create_effect_record_digest.is_none()
                && old.consumed_create_operation_record_digest.is_none()
        }
        Some(value) => {
            Some(value.source_pin_record_digest) == old.consumed_source_pin_record_digest
                && Some(value.create_effect_record_digest)
                    == old.consumed_create_effect_record_digest
                && Some(value.create_operation_record_digest)
                    == old.consumed_create_operation_record_digest
        }
    }
}

fn legacy_consumption_requires_companion_provenance(row: &SourceAcquisitionRowV1) -> bool {
    row.consumed_source_pin_record_digest.is_some()
        || row.consumed_create_effect_record_digest.is_some()
        || row.consumed_create_operation_record_digest.is_some()
}

fn release_proof_matches(
    old: &SourceAcquisitionRowV1,
    new: &super::model::SourceAcquisitionRowV2,
) -> bool {
    match (
        old.release_generation,
        old.provider_inventory_digest,
        old.provider_inventory_observation_ordinal,
        &new.release_proof,
    ) {
        (None, None, None, None) => true,
        (
            Some(old_generation),
            None,
            None,
            Some(super::model::ReleaseProofV2::ProviderReceipt {
                release_generation, ..
            }),
        ) => *release_generation == old_generation,
        (
            None,
            Some(old_digest),
            Some(old_ordinal),
            Some(super::model::ReleaseProofV2::ProviderInventory {
                inventory_digest,
                inventory_observation_ordinal,
                ..
            }),
        ) => *inventory_digest == old_digest && *inventory_observation_ordinal == old_ordinal,
        _ => false,
    }
}

fn release_matches(
    old: &SourceAcquisitionRowV1,
    new: &super::model::SourceAcquisitionRowV2,
    state: &MountSourceAcquisitionStateV2,
) -> bool {
    let operation = old
        .release
        .map(|value| (value.operation_id, value.request_digest));
    let authority = old.release_authority.map(|value| {
        (
            value.sandbox_id,
            value.incarnation_id,
            value.assignment_epoch,
            value.desired_generation,
            value.assignment_digest,
            value.expected_revision,
            value.expected_record_digest,
        )
    });
    let release_floor_matches = match (
        old.release_inventory_observation_floor,
        &new.release_inventory_fence,
    ) {
        (None, None) => true,
        (Some(ordinal), Some(fence)) => fence.inventory_observation_floor == ordinal,
        _ => false,
    };
    let release_context_matches = match (&old.release_provider, &new.release_lineage) {
        (None, None) => true,
        (Some(context), Some(lineage)) => {
            attempt_session_matches_context(state, lineage.tail, context)
        }
        _ => false,
    };
    let initial_request_matches = match (
        &old.initial_provider_release_request,
        old.initial_provider_release_request_digest,
        &new.release_lineage,
    ) {
        (None, None, None) => true,
        (Some(request), Some(digest), Some(lineage)) => state
            .provider_attempts
            .get(&lineage.root.id)
            .is_some_and(|attempt| {
                attempt.revision == lineage.root.revision
                    && attempt.record_digest == lineage.root.record_digest
                    && attempt.signed_request == *request
                    && attempt.signed_request_digest == digest
            }),
        _ => false,
    };
    new.release
        .map(|value| (value.operation_id, value.request_digest))
        == operation
        && new.mount_release_request == old.mount_release_request
        && new.release_authority.map(|value| {
            (
                value.sandbox_id,
                value.incarnation_id,
                value.assignment_epoch,
                value.desired_generation,
                value.assignment_digest,
                value.expected_revision,
                value.expected_record_digest,
            )
        }) == authority
        && release_floor_matches
        && release_context_matches
        && initial_request_matches
}

fn provider_context_matches_acquire(
    old: &SourceAcquisitionRowV1,
    new: &super::model::SourceAcquisitionRowV2,
    state: &MountSourceAcquisitionStateV2,
) -> bool {
    attempt_session_matches_context(state, new.acquire_lineage.tail, &old.provider)
}

fn attempt_session_matches_context(
    state: &MountSourceAcquisitionStateV2,
    attempt_ref: super::model::RecordRefV2,
    context: &super::migration_v1::SourceProviderContextSnapshotV1,
) -> bool {
    let Some(attempt) = state.provider_attempts.get(&attempt_ref.id) else {
        return false;
    };
    let Some(session) = state.provider_sessions.get(&attempt.session_id) else {
        return false;
    };
    let signer = &session.signers[3];
    attempt.revision == attempt_ref.revision
        && attempt.record_digest == attempt_ref.record_digest
        && session.scope.holder_authority_id == context.holder_authority_id
        && session.root_mount_authority_generation == context.holder_generation
        && session.root_mount_authority_digest == context.holder_authority_digest
        && session.node_id == context.node_id
        && session.kernel_boot_id == context.kernel_boot_id
        && session.revocation_digest == context.revocation_digest
        && session.scope.route_id == context.provider_route_id
        && session.route_generation == context.provider_route_generation
        && session.route_digest == context.provider_route_digest
        && session.scope.provider_authority_id == context.provider_authority_id
        && session.provider_authority_generation == context.provider_authority_generation
        && session.provider_authority_digest == context.provider_authority_digest
        && signer.key_id == context.provider_key_id
        && signer.key_generation == context.provider_key_generation
        && signer.public_key_fingerprint == context.provider_public_key_digest
        && session.scope.resource_namespace_digest == context.resource_namespace_digest
        && session.session_binding == context.session_binding
}

fn evidence_matches(
    old: &SourceAcquisitionRowV1,
    new: &super::model::SourceAcquisitionRowV2,
) -> bool {
    match (&old.evidence, &new.evidence) {
        (None, None) => true,
        (Some(old), Some(new)) => {
            new.provider_resource_id == old.provider_resource_id
                && new.provider_resource_generation == old.provider_resource_generation
                && new.provider_resource_digest == old.provider_resource_digest
                && new.provider_catalog_generation == old.provider_catalog_generation
                && new.provider_catalog_digest == old.provider_catalog_digest
                && new.provider_selection_generation == old.provider_selection_generation
                && new.provider_selection_digest == old.provider_selection_digest
                && new.proof_class == proof_class(old.proof_class)
                && new.provider_proof_digest == old.provider_proof_digest
                && new.lease_id == old.lease_id
                && new.signed_lease_digest == old.signed_lease_digest
                && new.lease_issued_seconds == old.lease_issued_seconds
                && new.lease_expires_seconds == old.lease_expires_seconds
                && new.source_realization_handle == old.source_realization_handle
                && new.source_physical_proof_digest == old.source_physical_proof_digest
                && new.source_kernel_boot_id == old.source_kernel_boot_id
                && new.source_device == old.source_device
                && new.source_inode == old.source_inode
                && new.source_unique_mount_id == old.source_unique_mount_id
                && new.descriptor_commitment == old.descriptor_commitment
        }
        _ => false,
    }
}

fn encode_state(state: &MountSourceAcquisitionStateV2) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut records = Vec::new();
    for value in state.acquisitions.values() {
        records.push(encode_mount_source_state_record_v2(
            &StoredRecordV2::Acquisition {
                value: value.clone(),
            },
        )?);
    }
    for value in state.holder_sequences.values() {
        records.push(encode_mount_source_state_record_v2(
            &StoredRecordV2::HolderSequence {
                value: value.clone(),
            },
        )?);
    }
    for value in state.provider_heads.values() {
        records.push(encode_mount_source_state_record_v2(
            &StoredRecordV2::ProviderHead {
                value: value.clone(),
            },
        )?);
    }
    for value in state.provider_sessions.values() {
        records.push(encode_mount_source_state_record_v2(
            &StoredRecordV2::ProviderSession {
                value: value.clone(),
            },
        )?);
    }
    for value in state.provider_attempts.values() {
        records.push(encode_mount_source_state_record_v2(
            &StoredRecordV2::ProviderQueryAttempt {
                value: value.clone(),
            },
        )?);
    }
    records.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(records)
}

fn legacy_acquisition_digest(row: &SourceAcquisitionRowV1) -> Result<[u8; 32]> {
    let mut body = row.clone();
    body.record_digest = [0; 32];
    let bytes = serde_json::to_vec(&body)
        .map_err(|_| invalid("legacy acquisition digest encoding failed"))?;
    let mut digest = Sha256::new();
    digest.update(LEGACY_RECORD_DOMAIN);
    digest.update(bytes);
    Ok(digest.finalize().into())
}

fn legacy_acquisition_key(id: [u8; 32]) -> Vec<u8> {
    [LEGACY_ACQUISITION_PREFIX, id.as_slice()].concat()
}

fn legacy_head_key(holder: [u8; 16], provider: [u8; 16]) -> Vec<u8> {
    [LEGACY_HEAD_PREFIX, holder.as_slice(), provider.as_slice()].concat()
}

const fn phase(value: SourceAcquisitionPhaseV1) -> SourceAcquisitionPhaseV2 {
    match value {
        SourceAcquisitionPhaseV1::PendingQuery => SourceAcquisitionPhaseV2::PendingQuery,
        SourceAcquisitionPhaseV1::DescriptorCustodied => {
            SourceAcquisitionPhaseV2::DescriptorCustodied
        }
        SourceAcquisitionPhaseV1::Active => SourceAcquisitionPhaseV2::Active,
        SourceAcquisitionPhaseV1::Consumed => SourceAcquisitionPhaseV2::Consumed,
        SourceAcquisitionPhaseV1::Releasing => SourceAcquisitionPhaseV2::Releasing,
        SourceAcquisitionPhaseV1::Released => SourceAcquisitionPhaseV2::Released,
        SourceAcquisitionPhaseV1::Faulted => SourceAcquisitionPhaseV2::Faulted,
    }
}

const fn phase_v2_to_v1(value: SourceAcquisitionPhaseV2) -> SourceAcquisitionPhaseV1 {
    match value {
        SourceAcquisitionPhaseV2::PendingQuery => SourceAcquisitionPhaseV1::PendingQuery,
        SourceAcquisitionPhaseV2::DescriptorCustodied => {
            SourceAcquisitionPhaseV1::DescriptorCustodied
        }
        SourceAcquisitionPhaseV2::Active => SourceAcquisitionPhaseV1::Active,
        SourceAcquisitionPhaseV2::Consumed => SourceAcquisitionPhaseV1::Consumed,
        SourceAcquisitionPhaseV2::Releasing => SourceAcquisitionPhaseV1::Releasing,
        SourceAcquisitionPhaseV2::Released => SourceAcquisitionPhaseV1::Released,
        SourceAcquisitionPhaseV2::Faulted => SourceAcquisitionPhaseV1::Faulted,
    }
}

const fn proof_class(value: SourceAcquisitionProofClassV1) -> SourceAcquisitionProofClassV2 {
    match value {
        SourceAcquisitionProofClassV1::ImmutableTree => {
            SourceAcquisitionProofClassV2::ImmutableTree
        }
        SourceAcquisitionProofClassV1::LocalLive => SourceAcquisitionProofClassV2::LocalLive,
        SourceAcquisitionProofClassV1::BestEffortReplica => {
            SourceAcquisitionProofClassV2::BestEffortReplica
        }
    }
}

fn invalid(message: &'static str) -> MountSourceAcquisitionStateError {
    MountSourceAcquisitionStateError::Invalid(message)
}
