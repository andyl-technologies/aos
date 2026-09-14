//! Full recovered-object-graph validation for `AOSMSA02`.
//!
//! Local shape checks are followed by exact reference, lineage, sequence,
//! projection, and global-history checks. Recovery therefore accepts only a
//! state reachable through an all-old or all-new bounded transaction graph.

use std::collections::{BTreeMap, BTreeSet};

use aos_proto::aos::sandbox::local::v1::ReleaseMountSourceAcquisitionRequest;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::{
    decode_historical_acquire_mount_source_request, mount_source_acquisition_id_v1,
    mount_source_acquisition_request_digest_v1, mount_source_physical_proof_digest_v1,
    mount_source_proof_class_from_provider_v1, mount_source_realization_handle_v1,
    MountSourcePhysicalProofV1, SourceRealizationBindingV1,
};
use aos_sandbox_source_provider_protocol::{
    decode_acquire_request, decode_inventory_request, decode_release_request,
    digest_acquire_request, digest_inventory, digest_inventory_request,
    digest_logical_binding_bytes, digest_provider_proof, digest_release_request,
    digest_signed_export_lease, provider_resource_commitment_v1,
    source_root_descriptor_commitment_v1, verify_inventory, verify_provider_receipt,
    verify_provider_receipt_and_lease, verify_release_receipt, NormalizedAcquisitionIntentV1,
    SignedSourceExportLeaseV1, SignedSourceProviderInventoryV1, SignedSourceProviderReceiptV1,
    SignedSourceProviderRequestV1, SignedSourceReleaseReceiptV1, SourceProviderAuthorityV1,
    SourceProviderDescriptorRole, SourceProviderKeyUsageV1, SourceProviderSigningKeyV1,
    SourceResourceV1, SourceRootObservationV1, SourceSelectionFloorV1, SourceUseV1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::checkpoint::{signer_matches, validate_attempt_checkpoint, validate_session_checkpoint};
use super::format::{
    attempt_id, death_digest, execution_digest, intent_digest, record_digest, request_id,
    session_id, state_error, MAXIMUM_LINEAGE_ATTEMPTS, MAXIMUM_SOURCE_ACQUISITIONS,
    MAXIMUM_SOURCE_PROVIDER_ATTEMPTS, MAXIMUM_SOURCE_PROVIDER_HEADS,
    MAXIMUM_SOURCE_PROVIDER_SESSIONS,
};
use super::history::{attempt_is_terminal, validate_global_history};
use super::model::*;
use super::projection::{
    inventory_entry_matches_evidence, project_row, project_scope, projection_from_entries,
    reconciliation_conflict, reproduce_reconciliation,
};
use super::SourceAcquisitionTableV2;
use crate::Result;

pub(super) fn validate_recovered_table(table: &SourceAcquisitionTableV2) -> Result<()> {
    if table.acquisitions.len() > MAXIMUM_SOURCE_ACQUISITIONS
        || table.provider_heads.len() > MAXIMUM_SOURCE_PROVIDER_HEADS
        || table.provider_sessions.len() > MAXIMUM_SOURCE_PROVIDER_SESSIONS
        || table.provider_attempts.len() > MAXIMUM_SOURCE_PROVIDER_ATTEMPTS
    {
        return Err(state_error("AOSMSA02 table exceeds a fixed record bound"));
    }

    for session in table.provider_sessions.values() {
        validate_session(session)?;
    }
    for attempt in table.provider_attempts.values() {
        validate_attempt(attempt, table)?;
    }
    for row in table.acquisitions.values() {
        validate_row(row, table)?;
    }
    for head in table.provider_heads.values() {
        validate_head(head, table)?;
    }

    validate_global_history(&table.acquisitions, &table.provider_sessions)?;
    validate_lineages(table)?;
    validate_sequence_and_reservation_graph(table)?;
    validate_recovery_graph(table)?;
    validate_resolution_causality(table)?;
    validate_session_reachability(table)?;
    Ok(())
}

fn validate_session_reachability(table: &SourceAcquisitionTableV2) -> Result<()> {
    let mut reachable = BTreeSet::new();
    for head in table.provider_heads.values() {
        let mut current = Some(head.current_session_id);
        let mut scope_chain = BTreeSet::new();
        while let Some(session_id) = current {
            if !scope_chain.insert(session_id) || !reachable.insert(session_id) {
                return Err(state_error(
                    "provider session belongs to a cyclic or aliased head chain",
                ));
            }
            let session = table
                .provider_sessions
                .get(&session_id)
                .ok_or_else(|| state_error("provider head session chain is missing"))?;
            if session.scope != head.scope {
                return Err(state_error("provider session chain changes stable scope"));
            }
            current = session.predecessor_session_id;
        }
    }
    for attempt in table.provider_attempts.values() {
        if !reachable.contains(&attempt.session_id) {
            return Err(state_error(
                "provider attempt references a session outside its head chain",
            ));
        }
    }
    for session in table.provider_sessions.values() {
        if !reachable.contains(&session.session_id) {
            return Err(state_error(
                "provider session is unreachable from durable state",
            ));
        }
    }
    Ok(())
}

fn validate_session(session: &SourceProviderSessionV2) -> Result<()> {
    if session.revision != 1
        || session.session_id == [0; 32]
        || session.session_id != session_id(session)
        || !valid_scope(session.scope)
        || session.node_id == [0; 16]
        || session.kernel_boot_id == [0; 16]
        || session.root_mount_authority_generation == 0
        || session.root_mount_authority_digest == [0; 32]
        || session.provider_authority_generation == 0
        || session.provider_authority_digest == [0; 32]
        || session.route_generation == 0
        || session.route_digest == [0; 32]
        || session.authenticated_at_seconds < 0
        || session.current_valid_until_seconds <= session.authenticated_at_seconds
        || session.trusted_clock_evidence_digest == [0; 32]
        || session.trust_generation == 0
        || session.trust_digest == [0; 32]
        || session.revocation_generation == 0
        || session.revocation_digest == [0; 32]
        || session.root_mount_process_instance == [0; 16]
        || session.provider_process_instance == [0; 16]
        || session.record_digest == [0; 32]
    {
        return Err(state_error(
            "SourceProvider session has an invalid scalar field",
        ));
    }
    if !session.negotiated_capabilities.signed_lease_receipts
        || !session.negotiated_capabilities.separated_signing_roles
        || session.negotiated_capabilities.proof_class_capabilities == 0
        || session.negotiated_capabilities.proof_class_capabilities & !0b1111 != 0
    {
        return Err(state_error(
            "SourceProvider session lacks mandatory capabilities",
        ));
    }
    validate_authority_and_signer_snapshots(session)?;
    validate_execution(session)?;
    validate_session_checkpoint(session)
}

fn validate_authority_and_signer_snapshots(session: &SourceProviderSessionV2) -> Result<()> {
    let root = &session.authority_trust[0];
    let provider = &session.authority_trust[1];
    if root.authority_id != session.scope.holder_authority_id
        || root.authority_generation != session.root_mount_authority_generation
        || root.authority_digest != session.root_mount_authority_digest
        || provider.authority_id != session.scope.provider_authority_id
        || provider.authority_generation != session.provider_authority_generation
        || provider.authority_digest != session.provider_authority_digest
        || root.state != AuthorityAdmissionStateV2::Trusted
        || provider.state != AuthorityAdmissionStateV2::Trusted
        || !interval_contains(
            root.valid_from_seconds,
            root.valid_until_seconds,
            session.authenticated_at_seconds,
        )
        || !interval_contains(
            provider.valid_from_seconds,
            provider.valid_until_seconds,
            session.authenticated_at_seconds,
        )
    {
        return Err(state_error(
            "SourceProvider authority-trust snapshot is inconsistent",
        ));
    }

    let mut key_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    let mut current_valid_until = root.valid_until_seconds.min(provider.valid_until_seconds);
    for signer in &session.signers {
        if signer.authority_id == [0; 16]
            || signer.authority_generation == 0
            || signer.authority_digest == [0; 32]
            || signer.key_id == [0; 16]
            || signer.key_generation == 0
            || signer.public_key == [0; 32]
            || signer.public_key_fingerprint == [0; 32]
            || signer.authority_state != AuthorityAdmissionStateV2::Trusted
            || signer.key_state != KeyAdmissionStateV2::Eligible
            || signer.superseded_by_key_generation != 0
            || !interval_contains(
                signer.authority_valid_from_seconds,
                signer.authority_valid_until_seconds,
                session.authenticated_at_seconds,
            )
            || !interval_contains(
                signer.key_valid_from_seconds,
                signer.key_valid_until_seconds,
                session.authenticated_at_seconds,
            )
            || !key_ids.insert(signer.key_id)
            || !public_keys.insert(signer.public_key)
            || !fingerprints.insert(signer.public_key_fingerprint)
        {
            return Err(state_error(
                "SourceProvider signer snapshot is invalid or aliased",
            ));
        }
        let authority = match signer.role {
            SignerRoleV2::RootMountHello | SignerRoleV2::RootMountRecord => root,
            SignerRoleV2::ProviderHello | SignerRoleV2::ProviderOutcome => provider,
        };
        if signer.authority_id != authority.authority_id
            || signer.authority_generation != authority.authority_generation
            || signer.authority_digest != authority.authority_digest
            || signer.authority_valid_from_seconds != authority.valid_from_seconds
            || signer.authority_valid_until_seconds != authority.valid_until_seconds
        {
            return Err(state_error(
                "SourceProvider signer authority is inconsistent",
            ));
        }
        current_valid_until = current_valid_until
            .min(signer.authority_valid_until_seconds)
            .min(signer.key_valid_until_seconds);
    }
    if session.current_valid_until_seconds != current_valid_until {
        return Err(state_error(
            "SourceProvider session current-valid-until does not reproduce",
        ));
    }
    Ok(())
}

fn validate_execution(session: &SourceProviderSessionV2) -> Result<()> {
    let execution = &session.provider_execution;
    let writer = &session.actual_writer_root_mount_process;
    if execution.pid == 0
        || execution.tgid == 0
        || execution.ppid == 0
        || execution.start_time_ticks == 0
        || execution.cgroup_id == 0
        || execution.process_execution_digest == [0; 32]
        || execution.process_execution_digest != execution_digest(session)?
        || writer.tgid == 0
        || writer.start_time_ticks == 0
        || writer.cgroup_digest == [0; 32]
    {
        return Err(state_error("SourceProvider execution snapshot is invalid"));
    }
    Ok(())
}

fn validate_attempt(
    attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let session = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
    let head = table
        .provider_heads
        .get(&(
            attempt.scope.holder_authority_id,
            attempt.scope.provider_authority_id,
        ))
        .ok_or_else(|| state_error("provider attempt owner head is missing"))?;
    if !valid_scope(attempt.scope)
        || attempt.scope != attempt.intent.scope()
        || attempt.scope != session.scope
        || attempt.attempt_id == [0; 32]
        || attempt.attempt_number == 0
        || attempt.request_sequence == 0
        || attempt.request_id == [0; 16]
        || attempt.immutable_intent_digest == [0; 32]
        || attempt.immutable_intent_digest != intent_digest(&attempt.intent)?
        || attempt.attempt_id != attempt_id(attempt)
        || attempt.request_id != request_id(attempt.attempt_id)
        || attempt.signer_set_commitment != session.signer_set_commitment
        || attempt.trust_digest != session.trust_digest
        || attempt.revocation_digest != session.revocation_digest
        || attempt.route_digest != session.route_digest
        || attempt.process_execution_digest != session.provider_execution.process_execution_digest
        || attempt.signed_request_digest == [0; 32]
        || head.scope != attempt.scope
        || attempt.record_digest == [0; 32]
        || !method_owner_intent_match(attempt)
    {
        return Err(state_error(
            "SourceProvider attempt has an invalid identity or snapshot",
        ));
    }
    validate_attempt_normalization(attempt, session)?;
    validate_owner_predecessor(attempt, head, table)?;
    validate_intent(&attempt.intent)?;
    validate_attempt_revision(attempt)?;
    validate_provider_request(attempt, session, table)?;
    validate_attempt_checkpoint(attempt, session)?;
    validate_consumed_result(attempt, session)?;
    validate_abandoned_attempt(attempt, table)
}

fn validate_attempt_normalization(
    attempt: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
) -> Result<()> {
    match (&attempt.intent, &attempt.normalized_acquire_intent) {
        (ProviderIntentV2::Acquire { .. }, Some(normalized)) => {
            let value = NormalizedAcquisitionIntentV1::from_canonical_bytes(&normalized.bytes)
                .map_err(|_| state_error("attempt AOSNPI01 normalization is invalid"))?;
            if normalized.bytes.is_empty()
                || value.digest().as_bytes() != &normalized.digest
                || normalized.maximum_lease_expiry_seconds <= session.authenticated_at_seconds
                || normalized.maximum_lease_expiry_seconds > session.current_valid_until_seconds
            {
                return Err(state_error(
                    "attempt Acquire normalization has an invalid bound or digest",
                ));
            }
        }
        (ProviderIntentV2::Acquire { .. }, None) => {
            return Err(state_error("Acquire attempt lacks AOSNPI01 normalization"));
        }
        (_, Some(_)) => {
            return Err(state_error(
                "non-Acquire attempt retains AOSNPI01 normalization",
            ));
        }
        (_, None) => {}
    }
    Ok(())
}

fn validate_owner_predecessor(
    attempt: &SourceProviderQueryAttemptV2,
    head: &SourceProviderHeadV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let initial_acquire = attempt.method == ProviderMethodV2::Acquire
        && attempt.attempt_number == 1
        && attempt.previous_attempt_id.is_none();
    let zero_witness =
        attempt.owner_predecessor_revision == 0 && attempt.owner_predecessor_digest == [0; 32];
    let partial_zero =
        (attempt.owner_predecessor_revision == 0) != (attempt.owner_predecessor_digest == [0; 32]);
    if partial_zero
        || initial_acquire != zero_witness
        || initial_acquire != attempt.owner_predecessor.is_none()
    {
        return Err(state_error(
            "provider attempt has an invalid owner-predecessor witness",
        ));
    }

    if let Some(predecessor) = &attempt.owner_predecessor {
        validate_owner_predecessor_witness(attempt, predecessor, table)?;
    }

    match attempt.owner {
        ProviderQueryOwnerV2::Acquire { acquisition_id }
        | ProviderQueryOwnerV2::Release { acquisition_id } => {
            let row = table
                .acquisitions
                .get(&acquisition_id)
                .ok_or_else(|| state_error("provider attempt owner row is missing"))?;
            if attempt.owner_predecessor_revision >= row.revision && !initial_acquire {
                return Err(state_error(
                    "provider attempt owner witness is not older than its row",
                ));
            }
            if matches!(attempt.state, ProviderAttemptStateV2::Reserved)
                && attempt.owner_predecessor_revision.checked_add(1) != Some(row.revision)
            {
                return Err(state_error(
                    "reserved provider attempt does not advance its owner row once",
                ));
            }
        }
        ProviderQueryOwnerV2::Inventory => {
            if attempt.owner_predecessor_revision >= head.revision {
                return Err(state_error(
                    "provider Inventory owner witness is not older than its head",
                ));
            }
            if matches!(attempt.state, ProviderAttemptStateV2::Reserved)
                && attempt.owner_predecessor_revision.checked_add(1) != Some(head.revision)
            {
                return Err(state_error(
                    "reserved provider Inventory does not advance its head once",
                ));
            }
        }
    }
    Ok(())
}

fn validate_owner_predecessor_witness(
    attempt: &SourceProviderQueryAttemptV2,
    predecessor: &OwnerPredecessorWitnessV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    match (attempt.owner, predecessor) {
        (
            ProviderQueryOwnerV2::Acquire { acquisition_id }
            | ProviderQueryOwnerV2::Release { acquisition_id },
            OwnerPredecessorWitnessV2::Acquisition { value },
        ) => {
            let current = table
                .acquisitions
                .get(&acquisition_id)
                .ok_or_else(|| state_error("provider attempt owner row is missing"))?;
            if value.record.id != acquisition_id
                || value.acquisition_id != acquisition_id
                || value.scope != attempt.scope
                || value.record.revision != attempt.owner_predecessor_revision
                || value.record.record_digest != attempt.owner_predecessor_digest
                || !same_acquisition_identity(value, current)
            {
                return Err(state_error(
                    "provider attempt acquisition predecessor does not reproduce",
                ));
            }
            validate_predecessor_evidence(value)?;
            validate_predecessor_phase(value)?;
            validate_predecessor_terminal_evidence(value, table)?;
            exact_attempt(table, value.acquire_lineage.root)?;
            exact_attempt(table, value.acquire_lineage.tail)?;
            if let Some(lineage) = &value.release_lineage {
                exact_attempt(table, lineage.root)?;
                exact_attempt(table, lineage.tail)?;
            }
            validate_acquisition_predecessor_lineage(attempt, value, current)
        }
        (ProviderQueryOwnerV2::Inventory, OwnerPredecessorWitnessV2::ProviderHead { value }) => {
            let session = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
            validate_provider_head_predecessor_witness(value, attempt, table)?;
            let ProviderIntentV2::Inventory { value: intent } = &attempt.intent else {
                return Err(state_error(
                    "provider Inventory predecessor has the wrong intent",
                ));
            };
            if value.record.id != provider_head_record_id(value.scope)
                || value.scope != attempt.scope
                || value.record.revision != attempt.owner_predecessor_revision
                || value.record.record_digest != attempt.owner_predecessor_digest
                || value.current_session_id != attempt.session_id
                || value.current_session_record_digest != attempt.session_record_digest
                || value.holder_authority_generation != session.root_mount_authority_generation
                || value.holder_authority_digest != session.root_mount_authority_digest
                || value.provider_authority_generation != session.provider_authority_generation
                || value.provider_authority_digest != session.provider_authority_digest
                || value.pending_attempt.is_some()
                || value.next_request_sequence != attempt.request_sequence
                || value.next_response_sequence != attempt.request_sequence
                || value.inventory_observation_ordinal != intent.known_observation_ordinal
                || !inventory_intent_matches_floor(intent, value.inventory_floor.as_ref())
                || (matches!(attempt.state, ProviderAttemptStateV2::Reserved)
                    && !reserved_head_follows_predecessor(value, attempt, table))
            {
                return Err(state_error(
                    "provider Inventory head predecessor does not reproduce",
                ));
            }
            if let Some(floor) = &value.inventory_floor {
                let prior = exact_attempt(table, floor.attempt)?;
                if !attempt_happens_after(table, prior, attempt)? {
                    return Err(state_error(
                        "Inventory predecessor floor is not historically prior",
                    ));
                }
            }
            if let Some(reference) = value.last_inventory_attempt {
                let prior = exact_attempt(table, reference)?;
                if !attempt_happens_after(table, prior, attempt)? {
                    return Err(state_error(
                        "Inventory predecessor tail is not historically prior",
                    ));
                }
            }
            if let Some(barrier) = &value.recovery_barrier {
                let root = exact_attempt(table, barrier.root_attempt)?;
                if !attempt_happens_after(table, root, attempt)? {
                    return Err(state_error(
                        "Inventory predecessor recovery root is not historically prior",
                    ));
                }
                if let Some(tail) = barrier.recovery_inventory_tail {
                    let prior = exact_attempt(table, tail)?;
                    if !attempt_happens_after(table, prior, attempt)? {
                        return Err(state_error(
                            "Inventory predecessor recovery tail is not historically prior",
                        ));
                    }
                }
            }
            Ok(())
        }
        _ => Err(state_error(
            "provider attempt has the wrong owner-predecessor record kind",
        )),
    }
}

fn provider_head_record_id(scope: ProviderScopeV2) -> [u8; 32] {
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(&scope.holder_authority_id);
    id[16..].copy_from_slice(&scope.provider_authority_id);
    id
}

fn validate_provider_head_predecessor_witness(
    value: &ProviderHeadPredecessorWitnessV2,
    reserved_attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let session = exact_session(
        table,
        value.current_session_id,
        value.current_session_record_digest,
    )?;
    if value.record.id != provider_head_record_id(value.scope)
        || value.record.revision == 0
        || value.record.record_digest == [0; 32]
        || !valid_scope(value.scope)
        || session.scope != value.scope
        || value.holder_authority_generation != session.root_mount_authority_generation
        || value.holder_authority_digest != session.root_mount_authority_digest
        || value.provider_authority_generation != session.provider_authority_generation
        || value.provider_authority_digest != session.provider_authority_digest
        || value.next_request_sequence == 0
        || value.next_request_sequence != value.next_response_sequence
        || value.pending_attempt.is_some()
        || value.current_projection_digest == [0; 32]
        || value.inventory_floor.is_some() != (value.inventory_observation_ordinal != 0)
    {
        return Err(state_error(
            "provider-head predecessor witness has invalid shape",
        ));
    }
    if value
        .last_reconciliation
        .as_ref()
        .is_some_and(|reconciliation| {
            value.inventory_floor.is_none()
                || reconciliation.projection_epoch != value.current_projection_epoch
                || reconciliation.projection_digest != value.current_projection_digest
                || reconciliation.residual_digest == [0; 32]
                || reconciliation.conflict_digest == [0; 32]
                || reconciliation_commitment(reconciliation) == [0; 32]
        })
    {
        return Err(state_error(
            "provider-head predecessor reconciliation is invalid",
        ));
    }
    validate_predecessor_inventory_history(value, reserved_attempt, table)?;
    validate_predecessor_recovery_barrier(value, reserved_attempt, table)
}

fn validate_predecessor_inventory_history(
    value: &ProviderHeadPredecessorWitnessV2,
    reserved_attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let mut terminal = Vec::new();
    for attempt in table.provider_attempts.values().filter(|attempt| {
        attempt.scope == value.scope
            && attempt.method == ProviderMethodV2::Inventory
            && attempt_is_terminal(&attempt.state)
    }) {
        if attempt_happens_after(table, attempt, reserved_attempt)? {
            terminal.push(attempt);
        }
    }
    if value.last_inventory_attempt.is_some() != !terminal.is_empty() {
        return Err(state_error(
            "provider-head predecessor Inventory tail has invalid presence",
        ));
    }
    let complete_count = terminal
        .iter()
        .filter(|attempt| is_complete(attempt))
        .count();
    if u64::try_from(complete_count)
        .map_err(|_| state_error("predecessor Inventory count exceeds u64"))?
        != value.inventory_observation_ordinal
    {
        return Err(state_error(
            "provider-head predecessor Inventory ordinal does not reproduce",
        ));
    }
    if let Some(reference) = value.last_inventory_attempt {
        let last = resolve_historical_attempt(table, reference)?;
        if last.scope != value.scope
            || last.method != ProviderMethodV2::Inventory
            || !attempt_is_terminal(&last.state)
            || !attempt_happens_after(table, &last, reserved_attempt)?
        {
            return Err(state_error(
                "provider-head predecessor Inventory tail is invalid",
            ));
        }
        for earlier in &terminal {
            if earlier.attempt_id != last.attempt_id
                && !attempt_happens_after(table, earlier, &last)?
            {
                return Err(state_error(
                    "provider-head predecessor Inventory tail is not latest",
                ));
            }
        }
    }
    let Some(floor) = &value.inventory_floor else {
        return Ok(());
    };
    let attempt = exact_attempt(table, floor.attempt)?;
    let session = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Complete,
        signed_result,
        signed_result_digest,
        ..
    } = &attempt.state
    else {
        return Err(state_error(
            "provider-head predecessor floor is not Complete Inventory",
        ));
    };
    let inventory = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("provider-head predecessor Inventory is invalid"))?;
    if attempt.scope != value.scope
        || attempt.method != ProviderMethodV2::Inventory
        || !attempt_happens_after(table, attempt, reserved_attempt)?
        || floor.provider_authority_generation != session.provider_authority_generation
        || floor.provider_authority_digest != session.provider_authority_digest
        || floor.provider_outcome_signer_digest != session.signers[3].public_key_fingerprint
        || floor.inventory_generation != inventory.subject().inventory_generation()
        || floor.inventory_digest != *digest_inventory(inventory.subject()).as_bytes()
        || floor.catalog_generation != inventory.subject().catalog_generation()
        || floor.catalog_digest != *inventory.subject().catalog_digest().as_bytes()
        || floor.signed_result_digest != *signed_result_digest
    {
        return Err(state_error(
            "provider-head predecessor Inventory floor does not reproduce",
        ));
    }
    for later_complete in terminal
        .into_iter()
        .filter(|candidate| is_complete(candidate))
    {
        if later_complete.attempt_id != attempt.attempt_id
            && !attempt_happens_after(table, later_complete, attempt)?
        {
            return Err(state_error(
                "provider-head predecessor Inventory floor is not latest Complete",
            ));
        }
    }
    Ok(())
}

fn validate_predecessor_recovery_barrier(
    value: &ProviderHeadPredecessorWitnessV2,
    reserved_attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let ProviderIntentV2::Inventory {
        value: reserved_intent,
    } = &reserved_attempt.intent
    else {
        return Err(state_error(
            "provider-head predecessor owner is not Inventory",
        ));
    };
    let barrier = match (
        value.recovery_barrier.as_ref(),
        reserved_intent.recovery_root_attempt_id,
    ) {
        (None, None) => return Ok(()),
        (Some(barrier), Some(root_id)) if barrier.root_attempt.id == root_id => barrier,
        _ => {
            return Err(state_error(
                "provider-head predecessor recovery barrier and intent differ",
            ));
        }
    };
    let root = resolve_historical_attempt(table, barrier.root_attempt)?;
    let ProviderAttemptStateV2::AbandonedIndeterminate {
        recovery_root_attempt_id,
        resolution: None,
        ..
    } = &root.state
    else {
        return Err(state_error(
            "provider-head predecessor recovery root is not unresolved",
        ));
    };
    if root.scope != value.scope
        || *recovery_root_attempt_id != root.attempt_id
        || barrier.required_session_id != value.current_session_id
        || barrier.replacement_count == 0
        || barrier.baseline_inventory_ordinal != value.inventory_observation_ordinal
        || !attempt_happens_after(table, &root, reserved_attempt)?
    {
        return Err(state_error(
            "provider-head predecessor recovery barrier is inconsistent",
        ));
    }
    recovery_session_chain(
        table,
        &root,
        value.current_session_id,
        barrier.replacement_count,
    )?;
    if reserved_intent.recovery_root_attempt_id != Some(root.attempt_id)
        || reserved_intent.known_observation_ordinal != barrier.baseline_inventory_ordinal
        || !inventory_intent_matches_floor(reserved_intent, value.inventory_floor.as_ref())
    {
        return Err(state_error(
            "provider-head predecessor recovery reservation does not join its root",
        ));
    }
    let tail = barrier
        .recovery_inventory_tail
        .map(|reference| exact_attempt(table, reference))
        .transpose()?;
    if let Some(tail) = tail {
        let ProviderIntentV2::Inventory { value: tail_intent } = &tail.intent else {
            return Err(state_error(
                "provider-head predecessor recovery tail is not Inventory",
            ));
        };
        if tail.scope != value.scope
            || tail.method != ProviderMethodV2::Inventory
            || tail_intent.recovery_root_attempt_id != Some(root.attempt_id)
            || tail_intent.known_observation_ordinal != barrier.baseline_inventory_ordinal
            || !inventory_intent_matches_floor(tail_intent, value.inventory_floor.as_ref())
            || !attempt_happens_after(table, tail, reserved_attempt)?
        {
            return Err(state_error(
                "provider-head predecessor recovery Inventory tail is inconsistent",
            ));
        }
    }
    let owner_follows_tail = match tail {
        None => {
            reserved_attempt.previous_attempt_id.is_none()
                && reserved_attempt.attempt_number == 1
                && reserved_attempt.lineage_root_attempt_id == reserved_attempt.attempt_id
        }
        Some(tail) => {
            reserved_attempt.previous_attempt_id == Some(tail.attempt_id)
                && tail.attempt_number.checked_add(1) == Some(reserved_attempt.attempt_number)
                && reserved_attempt.lineage_root_attempt_id == tail.lineage_root_attempt_id
        }
    };
    if !owner_follows_tail {
        return Err(state_error(
            "provider-head predecessor recovery owner does not advance its tail",
        ));
    }
    let mut recovery_attempts = Vec::new();
    for attempt in table.provider_attempts.values() {
        let belongs_to_root = matches!(
            &attempt.intent,
            ProviderIntentV2::Inventory { value: intent }
                if intent.recovery_root_attempt_id == Some(root.attempt_id)
        );
        if attempt.attempt_id != reserved_attempt.attempt_id
            && belongs_to_root
            && attempt_happens_after(table, attempt, reserved_attempt)?
        {
            recovery_attempts.push(attempt);
        }
    }
    if tail.is_none() && !recovery_attempts.is_empty() {
        return Err(state_error(
            "provider-head predecessor recovery Inventory lacks a tail",
        ));
    }
    if let Some(tail) = tail {
        for recovery_attempt in recovery_attempts {
            if recovery_attempt.scope != value.scope
                || recovery_attempt.method != ProviderMethodV2::Inventory
                || recovery_attempt.lineage_root_attempt_id != tail.lineage_root_attempt_id
                || (recovery_attempt.attempt_id != tail.attempt_id
                    && !attempt_happens_after(table, recovery_attempt, tail)?)
            {
                return Err(state_error(
                    "provider-head predecessor recovery Inventory join is inconsistent",
                ));
            }
        }
    }
    Ok(())
}

fn reserved_head_follows_predecessor(
    predecessor: &ProviderHeadPredecessorWitnessV2,
    attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> bool {
    let Some(current) = table.provider_heads.get(&(
        predecessor.scope.holder_authority_id,
        predecessor.scope.provider_authority_id,
    )) else {
        return false;
    };
    let attempt_reference = RecordRefV2 {
        id: attempt.attempt_id,
        revision: attempt.revision,
        record_digest: attempt.record_digest,
    };
    predecessor.record.revision.checked_add(1) == Some(current.revision)
        && current.scope == predecessor.scope
        && current.holder_authority_generation == predecessor.holder_authority_generation
        && current.holder_authority_digest == predecessor.holder_authority_digest
        && current.provider_authority_generation == predecessor.provider_authority_generation
        && current.provider_authority_digest == predecessor.provider_authority_digest
        && current.current_session_id == predecessor.current_session_id
        && current.current_session_record_digest == predecessor.current_session_record_digest
        && predecessor.next_request_sequence.checked_add(1) == Some(current.next_request_sequence)
        && current.next_response_sequence == predecessor.next_response_sequence
        && current.pending_attempt == Some(attempt_reference)
        && current.inventory_observation_ordinal == predecessor.inventory_observation_ordinal
        && current.inventory_floor == predecessor.inventory_floor
        && current.last_inventory_attempt == predecessor.last_inventory_attempt
        && current.current_projection_epoch == predecessor.current_projection_epoch
        && current.current_projection_digest == predecessor.current_projection_digest
        && current.last_reconciliation == predecessor.last_reconciliation
        && current.recovery_barrier == predecessor.recovery_barrier
}

fn validate_predecessor_evidence(value: &AcquisitionPredecessorWitnessV2) -> Result<()> {
    if value.record.revision == 0
        || value.record.record_digest == [0; 32]
        || value.descriptor_custody_digest == Some([0; 32])
        || value.positive_custody_digest == Some([0; 32])
        || value.negative_custody_digest == Some([0; 32])
        || value.fault_digest == Some([0; 32])
        || value.retained_fault_digest == Some([0; 32])
        || value.consumption.as_ref().is_some_and(|evidence| {
            evidence.source_pin_record_digest == [0; 32]
                || evidence.create_effect_record_digest == [0; 32]
                || evidence.create_operation_record_digest == [0; 32]
        })
    {
        return Err(state_error(
            "provider attempt predecessor has invalid scalar evidence",
        ));
    }
    if value.evidence.as_ref().is_some_and(|evidence| {
        evidence.acquire_attempt.id == [0; 32]
            || evidence.session_id == [0; 32]
            || evidence.provider_outcome_signer_digest == [0; 32]
            || evidence.provider_resource_id == [0; 32]
            || evidence.provider_resource_generation == 0
            || evidence.provider_resource_digest == [0; 32]
            || evidence.provider_catalog_generation == 0
            || evidence.provider_catalog_digest == [0; 32]
            || evidence.provider_selection_generation == 0
            || evidence.provider_selection_digest == [0; 32]
            || !(1..=4).contains(&evidence.provider_proof_class)
            || evidence.provider_proof_digest == [0; 32]
            || evidence.lease_id == [0; 16]
            || evidence.signed_lease_digest == [0; 32]
            || evidence.lease_issued_seconds < 0
            || evidence.lease_expires_seconds <= evidence.lease_issued_seconds
            || evidence.source_realization_handle == [0; 32]
            || evidence.source_physical_proof_digest == [0; 32]
            || evidence.source_kernel_boot_id == [0; 16]
            || evidence.source_device == 0
            || evidence.source_inode == 0
            || evidence.source_unique_mount_id == 0
            || evidence.descriptor_commitment == [0; 32]
    }) {
        return Err(state_error(
            "provider attempt predecessor acquisition evidence is invalid",
        ));
    }
    if value.release_inventory_fence.as_ref().is_some_and(|fence| {
        fence.inventory_observation_floor == 0
            || fence.projection_epoch == 0
            || fence.projection_digest == [0; 32]
            || fence.projection_entry_count == 0
            || usize::try_from(fence.projection_entry_count).ok()
                > Some(MAXIMUM_SOURCE_ACQUISITIONS)
    }) {
        return Err(state_error(
            "provider attempt predecessor Release fence is invalid",
        ));
    }
    Ok(())
}

fn validate_predecessor_phase(value: &AcquisitionPredecessorWitnessV2) -> Result<()> {
    let has_evidence = value.evidence.is_some();
    let has_descriptor = value.descriptor_custody_digest.is_some();
    let has_positive = value.positive_custody_digest.is_some();
    let has_consumption = value.consumption.is_some();
    let release_fields = [
        value.release.is_some(),
        value.release_authority.is_some(),
        value.release_from_phase.is_some(),
        value.release_intent_digest.is_some(),
        value.release_lineage.is_some(),
        value.release_inventory_fence.is_some(),
    ];
    if release_fields.iter().any(|field| *field) && release_fields.iter().any(|field| !*field) {
        return Err(state_error(
            "provider attempt predecessor has partial Release intent",
        ));
    }
    let acquisition_shape = |phase| match phase {
        SourceAcquisitionPhaseV2::PendingQuery => {
            !has_descriptor && !has_positive && !has_consumption
        }
        SourceAcquisitionPhaseV2::DescriptorCustodied => {
            has_evidence && has_descriptor && !has_positive && !has_consumption
        }
        SourceAcquisitionPhaseV2::Active => {
            has_evidence && has_descriptor && has_positive && !has_consumption
        }
        SourceAcquisitionPhaseV2::Consumed => {
            has_evidence && has_descriptor && has_positive && has_consumption
        }
        SourceAcquisitionPhaseV2::Releasing
        | SourceAcquisitionPhaseV2::Released
        | SourceAcquisitionPhaseV2::Faulted => false,
    };
    let release_shape = value.release_from_phase.is_some_and(acquisition_shape);
    let phase_shape = |phase| match phase {
        SourceAcquisitionPhaseV2::PendingQuery
        | SourceAcquisitionPhaseV2::DescriptorCustodied
        | SourceAcquisitionPhaseV2::Active
        | SourceAcquisitionPhaseV2::Consumed => {
            acquisition_shape(phase)
                && value.release_lineage.is_none()
                && value.release_proof.is_none()
                && value.negative_custody_digest.is_none()
        }
        SourceAcquisitionPhaseV2::Releasing => {
            release_shape
                && value.release_proof.is_none()
                && value.negative_custody_digest.is_none()
        }
        SourceAcquisitionPhaseV2::Released => {
            release_shape
                && value.release_proof.is_some()
                && value.negative_custody_digest.is_some()
        }
        SourceAcquisitionPhaseV2::Faulted => false,
    };
    let shape = match value.phase {
        SourceAcquisitionPhaseV2::Faulted => value.faulted_from.is_some_and(phase_shape),
        phase => phase_shape(phase),
    };
    let fault_pair = value.faulted_from.is_some() == value.fault_digest.is_some();
    let retained_pair =
        value.retained_faulted_from.is_some() == value.retained_fault_digest.is_some();
    if !shape
        || !fault_pair
        || !retained_pair
        || (value.phase != SourceAcquisitionPhaseV2::Faulted && value.faulted_from.is_some())
        || matches!(
            value.faulted_from,
            Some(SourceAcquisitionPhaseV2::Faulted | SourceAcquisitionPhaseV2::Released)
        )
        || matches!(
            value.retained_faulted_from,
            Some(SourceAcquisitionPhaseV2::Faulted | SourceAcquisitionPhaseV2::Released)
        )
        || (value.retained_faulted_from.is_some()
            && !matches!(
                value.phase,
                SourceAcquisitionPhaseV2::Releasing | SourceAcquisitionPhaseV2::Released
            ))
        || value
            .retained_faulted_from
            .is_some_and(|origin| !predecessor_retained_origin_evidence_is_present(value, origin))
    {
        return Err(state_error(
            "provider attempt predecessor lifecycle shape is invalid",
        ));
    }
    Ok(())
}

fn predecessor_retained_origin_evidence_is_present(
    value: &AcquisitionPredecessorWitnessV2,
    origin: SourceAcquisitionPhaseV2,
) -> bool {
    match origin {
        SourceAcquisitionPhaseV2::PendingQuery => true,
        SourceAcquisitionPhaseV2::DescriptorCustodied => {
            value.evidence.is_some() && value.descriptor_custody_digest.is_some()
        }
        SourceAcquisitionPhaseV2::Active => {
            value.evidence.is_some()
                && value.descriptor_custody_digest.is_some()
                && value.positive_custody_digest.is_some()
        }
        SourceAcquisitionPhaseV2::Consumed => {
            value.evidence.is_some()
                && value.descriptor_custody_digest.is_some()
                && value.positive_custody_digest.is_some()
                && value.consumption.is_some()
        }
        SourceAcquisitionPhaseV2::Releasing => value.release_lineage.is_some(),
        SourceAcquisitionPhaseV2::Released | SourceAcquisitionPhaseV2::Faulted => false,
    }
}

fn validate_predecessor_terminal_evidence(
    value: &AcquisitionPredecessorWitnessV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    if value.acquire_terminal_attempt.is_some() != value.evidence.is_some() {
        return Err(state_error(
            "acquisition predecessor Acquire terminal evidence has partial presence",
        ));
    }
    if let Some(reference) = value.acquire_terminal_attempt {
        let attempt = exact_attempt(table, reference)?;
        if reference != value.acquire_lineage.tail
            || attempt.method != ProviderMethodV2::Acquire
            || attempt.owner
                != (ProviderQueryOwnerV2::Acquire {
                    acquisition_id: value.acquisition_id,
                })
            || !is_complete(attempt)
            || value.evidence.as_ref().is_none_or(|evidence| {
                evidence.acquire_attempt != reference || evidence.session_id != attempt.session_id
            })
        {
            return Err(state_error(
                "acquisition predecessor Acquire evidence has the wrong terminal attempt",
            ));
        }
    }

    match &value.release_proof {
        Some(ReleaseProofV2::ProviderReceipt { attempt, .. }) => {
            let lineage = value
                .release_lineage
                .as_ref()
                .ok_or_else(|| state_error("acquisition predecessor Release lineage is missing"))?;
            let terminal = exact_attempt(table, *attempt)?;
            if value.release_terminal_attempt != Some(*attempt)
                || lineage.tail != *attempt
                || terminal.method != ProviderMethodV2::Release
                || terminal.owner
                    != (ProviderQueryOwnerV2::Release {
                        acquisition_id: value.acquisition_id,
                    })
                || !is_complete(terminal)
            {
                return Err(state_error(
                    "acquisition predecessor Release receipt has the wrong terminal attempt",
                ));
            }
        }
        Some(ReleaseProofV2::ProviderInventory { .. }) | None => {
            if value.release_terminal_attempt.is_some() {
                return Err(state_error(
                    "retryable acquisition predecessor retains a terminal Release attempt",
                ));
            }
        }
    }
    Ok(())
}

fn same_acquisition_identity(
    snapshot: &AcquisitionPredecessorWitnessV2,
    current: &SourceAcquisitionRowV2,
) -> bool {
    snapshot.acquisition_id == current.acquisition_id
        && snapshot.scope == current.scope
        && snapshot.acquire == current.acquire
        && snapshot.acquire.request_digest
            == *mount_source_acquisition_request_digest_v1(&current.mount_acquire_request)
                .as_bytes()
        && snapshot.acquire_intent_digest == current.acquire_intent_digest
        && snapshot.acquire_lineage.root == current.acquire_lineage.root
        && snapshot.assignment == current.assignment
        && snapshot.prospective_mount_template_digest == current.prospective_mount_template_digest
        && snapshot.source_binding_digest == current.source_binding_digest
        && snapshot.mount_plan_digest == current.mount_plan_digest
        && snapshot.ownership_lease_digest == current.ownership_lease_digest
}

fn validate_acquisition_predecessor_lineage(
    attempt: &SourceProviderQueryAttemptV2,
    snapshot: &AcquisitionPredecessorWitnessV2,
    current: &SourceAcquisitionRowV2,
) -> Result<()> {
    if attempt.method == ProviderMethodV2::Release && attempt.attempt_number == 1 {
        if attempt.previous_attempt_id.is_some()
            || snapshot.release.is_some()
            || snapshot.release_lineage.is_some()
            || snapshot.release_intent_digest.is_some()
            || !matches!(&snapshot.recovery, AcquisitionRecoveryV2::Ready)
            || current.release_from_phase != Some(effective_predecessor_phase(snapshot))
            || snapshot.acquire_lineage != current.acquire_lineage
            || snapshot.acquire_terminal_attempt != current.acquire_terminal_attempt
            || snapshot.evidence != current.evidence
            || snapshot.descriptor_custody_digest != current.descriptor_custody_digest
            || snapshot.positive_custody_digest != current.positive_custody_digest
            || snapshot.consumption != current.consumption
            || !initial_release_fault_handoff_is_exact(snapshot, current)
        {
            return Err(state_error(
                "initial Release predecessor already contains Release state",
            ));
        }
        return Ok(());
    }
    let previous = attempt
        .previous_attempt_id
        .ok_or_else(|| state_error("noninitial acquisition attempt lacks predecessor"))?;
    let predecessor_tail = match attempt.method {
        ProviderMethodV2::Acquire => snapshot.acquire_lineage.tail,
        ProviderMethodV2::Release => {
            snapshot
                .release_lineage
                .as_ref()
                .ok_or_else(|| state_error("Release retry predecessor lacks lineage"))?
                .tail
        }
        ProviderMethodV2::Inventory => {
            return Err(state_error(
                "Inventory attempt uses an acquisition predecessor",
            ));
        }
    };
    let recovery_allows_retry = matches!(&snapshot.recovery, AcquisitionRecoveryV2::Ready)
        || matches!(
            &snapshot.recovery,
            AcquisitionRecoveryV2::RetryPermitted { root_attempt }
                if *root_attempt == predecessor_tail && predecessor_tail.id == previous
        );
    if !recovery_allows_retry {
        return Err(state_error(
            "provider retry predecessor is not ready for another query",
        ));
    }
    let (snapshot_lineage, current_lineage) = match attempt.method {
        ProviderMethodV2::Acquire => (&snapshot.acquire_lineage, &current.acquire_lineage),
        ProviderMethodV2::Release => {
            let snapshot_lineage = snapshot
                .release_lineage
                .as_ref()
                .ok_or_else(|| state_error("Release retry predecessor lacks lineage"))?;
            let current_lineage = current
                .release_lineage
                .as_ref()
                .ok_or_else(|| state_error("Release retry owner lacks lineage"))?;
            if snapshot.release != current.release
                || snapshot.release_authority != current.release_authority
                || snapshot.release_from_phase != current.release_from_phase
                || snapshot.release_intent_digest != current.release_intent_digest
                || !release_inventory_fence_witness_matches(
                    snapshot.release_inventory_fence.as_ref(),
                    current.release_inventory_fence.as_ref(),
                )
                || snapshot.evidence != current.evidence
                || snapshot.acquire_lineage != current.acquire_lineage
                || snapshot.acquire_terminal_attempt != current.acquire_terminal_attempt
                || snapshot.descriptor_custody_digest != current.descriptor_custody_digest
                || snapshot.positive_custody_digest != current.positive_custody_digest
                || snapshot.consumption != current.consumption
                || !release_retry_fault_handoff_is_exact(snapshot, current)
            {
                return Err(state_error(
                    "Release retry predecessor changes immutable Release intent",
                ));
            }
            (snapshot_lineage, current_lineage)
        }
        ProviderMethodV2::Inventory => {
            return Err(state_error(
                "Inventory attempt uses an acquisition predecessor",
            ));
        }
    };
    if snapshot_lineage.tail.id != previous
        || snapshot_lineage.next_attempt_number != attempt.attempt_number
        || snapshot_lineage.root != current_lineage.root
    {
        return Err(state_error(
            "provider retry does not advance its exact owner lineage",
        ));
    }
    Ok(())
}

fn initial_release_fault_handoff_is_exact(
    predecessor: &AcquisitionPredecessorWitnessV2,
    current: &SourceAcquisitionRowV2,
) -> bool {
    if predecessor.phase == SourceAcquisitionPhaseV2::Faulted {
        current.faulted_from.is_none()
            && current.fault_digest.is_none()
            && current.retained_faulted_from == predecessor.faulted_from
            && current.retained_fault_digest == predecessor.fault_digest
    } else {
        current.retained_faulted_from == predecessor.retained_faulted_from
            && current.retained_fault_digest == predecessor.retained_fault_digest
    }
}

fn release_retry_fault_handoff_is_exact(
    predecessor: &AcquisitionPredecessorWitnessV2,
    current: &SourceAcquisitionRowV2,
) -> bool {
    if predecessor.phase == SourceAcquisitionPhaseV2::Faulted
        && predecessor.faulted_from == Some(SourceAcquisitionPhaseV2::Releasing)
    {
        current.faulted_from.is_none()
            && current.fault_digest.is_none()
            && current.retained_faulted_from == predecessor.faulted_from
            && current.retained_fault_digest == predecessor.fault_digest
    } else {
        current.retained_faulted_from == predecessor.retained_faulted_from
            && current.retained_fault_digest == predecessor.retained_fault_digest
    }
}

fn release_inventory_fence_witness_matches(
    witness: Option<&ReleaseInventoryFenceWitnessV2>,
    current: Option<&ReleaseInventoryFenceV2>,
) -> bool {
    match (witness, current) {
        (Some(witness), Some(current)) => {
            witness.inventory_observation_floor == current.inventory_observation_floor
                && witness.projection_epoch == current.projection_epoch
                && witness.projection_digest == current.projection_digest
                && usize::try_from(witness.projection_entry_count).ok()
                    == Some(current.projection_entries.len())
        }
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

fn effective_acquisition_phase(row: &SourceAcquisitionRowV2) -> SourceAcquisitionPhaseV2 {
    if row.phase == SourceAcquisitionPhaseV2::Faulted {
        row.faulted_from
            .unwrap_or(SourceAcquisitionPhaseV2::Faulted)
    } else {
        row.phase
    }
}

fn effective_predecessor_phase(
    value: &AcquisitionPredecessorWitnessV2,
) -> SourceAcquisitionPhaseV2 {
    if value.phase == SourceAcquisitionPhaseV2::Faulted {
        value
            .faulted_from
            .unwrap_or(SourceAcquisitionPhaseV2::Faulted)
    } else {
        value.phase
    }
}

fn validate_consumed_result(
    attempt: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
) -> Result<()> {
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Complete,
        signed_result,
        ..
    } = &attempt.state
    else {
        return Ok(());
    };
    match attempt.method {
        ProviderMethodV2::Acquire => {
            let receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(signed_result)
                .map_err(|_| state_error("retained provider Acquire receipt is invalid"))?;
            if !signer_matches(&session.signers[3], receipt.signer()) {
                return Err(state_error(
                    "retained provider Acquire receipt signer differs from session",
                ));
            }
            verify_provider_receipt(&receipt, &session.signers[3].public_key)
                .map_err(|_| state_error("retained provider Acquire receipt is unauthenticated"))
        }
        ProviderMethodV2::Release => {
            let receipt = SignedSourceReleaseReceiptV1::from_canonical_bytes(signed_result)
                .map_err(|_| state_error("retained provider Release receipt is invalid"))?;
            if !signer_matches(&session.signers[3], receipt.signer()) {
                return Err(state_error(
                    "retained provider Release receipt signer differs from session",
                ));
            }
            verify_release_receipt(&receipt, &session.signers[3].public_key)
                .map_err(|_| state_error("retained provider Release receipt is unauthenticated"))
        }
        ProviderMethodV2::Inventory => {
            let inventory = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
                .map_err(|_| state_error("retained provider Inventory is invalid"))?;
            if !signer_matches(&session.signers[3], inventory.signer()) {
                return Err(state_error(
                    "retained provider Inventory signer differs from session",
                ));
            }
            verify_inventory(&inventory, &session.signers[3].public_key)
                .map_err(|_| state_error("retained provider Inventory is unauthenticated"))?;
            validate_complete_inventory_attempt(attempt, session, &inventory)
        }
    }
}

fn validate_complete_inventory_attempt(
    attempt: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
    signed_inventory: &SignedSourceProviderInventoryV1,
) -> Result<()> {
    let ProviderIntentV2::Inventory { value: intent } = &attempt.intent else {
        return Err(state_error("Complete Inventory has a non-Inventory intent"));
    };
    let signed_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
            .map_err(|_| state_error("retained Inventory request is invalid"))?;
    let request = decode_inventory_request(signed_request.subject())
        .map_err(|_| state_error("retained Inventory request body is invalid"))?;
    let inventory = signed_inventory.subject();
    if inventory.request_id() != attempt.request_id
        || inventory.request_digest() != digest_inventory_request(&request)
        || inventory.holder_authority_id() != intent.scope.holder_authority_id
        || inventory.holder_generation() != session.root_mount_authority_generation
        || inventory.holder_authority_digest().as_bytes() != &session.root_mount_authority_digest
        || inventory.provider().authority_id() != intent.scope.provider_authority_id
        || inventory.provider().authority_generation() != session.provider_authority_generation
        || inventory.provider().authority_digest().as_bytes() != &session.provider_authority_digest
        || inventory.provider_process_instance() != session.provider_process_instance
        || session.authenticated_at_seconds >= request.deadline_seconds()
        || intent.known_inventory_generation.is_some_and(|generation| {
            inventory.inventory_generation() < generation
                || (inventory.inventory_generation() == generation
                    && intent.known_inventory_digest
                        != Some(*digest_inventory(inventory).as_bytes()))
        })
        || intent.known_catalog_generation.is_some_and(|generation| {
            inventory.catalog_generation() < generation
                || (inventory.catalog_generation() == generation
                    && intent.known_catalog_digest != Some(*inventory.catalog_digest().as_bytes()))
        })
    {
        return Err(state_error(
            "Complete provider Inventory graph contradicts its intent",
        ));
    }
    validate_inventory_entries(
        inventory,
        intent.scope,
        session.negotiated_capabilities.proof_class_capabilities,
    )
}

fn validate_intent(intent: &ProviderIntentV2) -> Result<()> {
    match intent {
        ProviderIntentV2::Acquire { value } => {
            if !valid_scope(value.scope)
                || value.acquisition_id == [0; 32]
                || value.mount_request.is_empty()
                || value.mount_request_digest == [0; 32]
                || value.assignment.sandbox_id == [0; 16]
                || value.assignment.incarnation_id == [0; 16]
                || value.assignment.assignment_epoch == 0
                || value.assignment.desired_generation == 0
                || value.assignment.assignment_digest == [0; 32]
                || value.assignment.namespace_generation == 0
                || value.mount_plan_digest == [0; 32]
                || value.ownership_lease_digest == [0; 32]
                || value.prospective_mount_template.is_empty()
                || value.prospective_mount_template_digest == [0; 32]
                || value.source_binding.is_empty()
                || value.source_binding_digest == [0; 32]
                || value.requested_lease_seconds == 0
                || (!value.recursive && value.requested_maximum_submounts != 0)
            {
                return Err(state_error("immutable provider Acquire intent is invalid"));
            }
        }
        ProviderIntentV2::Release { value } => {
            if !valid_scope(value.scope)
                || value.acquisition_id == [0; 32]
                || value.mount_request.is_empty()
                || value.mount_operation.operation_id == [0; 16]
                || value.mount_operation.request_digest == [0; 32]
                || value.authority.sandbox_id == [0; 16]
                || value.authority.incarnation_id == [0; 16]
                || value.authority.assignment_epoch == 0
                || value.authority.desired_generation == 0
                || value.authority.assignment_digest == [0; 32]
                || value.authority.expected_revision == 0
                || value.authority.expected_record_digest == [0; 32]
                || value.lease_id == [0; 16]
                || value.signed_lease_digest == [0; 32]
                || value.provider_resource_id == [0; 32]
                || value.provider_resource_digest == [0; 32]
                || value.provider_proof_digest == [0; 32]
                || value.descriptor_commitment == [0; 32]
            {
                return Err(state_error("immutable provider Release intent is invalid"));
            }
        }
        ProviderIntentV2::Inventory { value } => {
            if !valid_scope(value.scope)
                || value.known_inventory_generation.is_some()
                    != value.known_inventory_digest.is_some()
                || value.known_catalog_generation.is_some() != value.known_catalog_digest.is_some()
                || value.known_inventory_generation == Some(0)
                || value.known_inventory_digest == Some([0; 32])
                || value.known_catalog_generation == Some(0)
                || value.known_catalog_digest == Some([0; 32])
                || value.recovery_root_attempt_id == Some([0; 32])
            {
                return Err(state_error(
                    "immutable provider Inventory intent is invalid",
                ));
            }
        }
    }
    Ok(())
}

fn validate_attempt_revision(attempt: &SourceProviderQueryAttemptV2) -> Result<()> {
    let expected = match &attempt.state {
        ProviderAttemptStateV2::Reserved => 1,
        ProviderAttemptStateV2::DispositionConsumed { .. } => 2,
        ProviderAttemptStateV2::AbandonedIndeterminate { resolution, .. } => {
            if resolution.is_some() {
                if match &attempt.state {
                    ProviderAttemptStateV2::AbandonedIndeterminate {
                        recovery_root_attempt_id,
                        ..
                    } => *recovery_root_attempt_id != attempt.attempt_id,
                    _ => true,
                } {
                    return Err(state_error("only a recovery root may retain resolution"));
                }
                3
            } else {
                2
            }
        }
    };
    if attempt.revision != expected {
        return Err(state_error(
            "SourceProvider attempt revision contradicts state",
        ));
    }
    Ok(())
}

fn validate_provider_request(
    attempt: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
        .map_err(|_| state_error("retained SourceProvider request is invalid"))?;
    let common_matches = |binding: &[u8; 32], sequence, request| {
        binding == &session.session_binding
            && sequence == attempt.request_sequence
            && request == attempt.request_id
    };
    match (&attempt.intent, attempt.method, attempt.owner) {
        (
            ProviderIntentV2::Acquire { value },
            ProviderMethodV2::Acquire,
            ProviderQueryOwnerV2::Acquire { acquisition_id },
        ) => {
            let request = decode_acquire_request(signed.subject())
                .map_err(|_| state_error("retained provider Acquire body is invalid"))?;
            let normalized = NormalizedAcquisitionIntentV1::from_acquire_request(
                &request,
                session_provider_authority(session)?,
                session_holder_authority(session)?,
                session.node_id,
                session.kernel_boot_id,
                session.scope.route_id,
                session.route_generation,
                ObjectDigest::from_bytes(session.route_digest),
                ObjectDigest::from_bytes(session.scope.resource_namespace_digest),
                session.revocation_generation,
                ObjectDigest::from_bytes(session.revocation_digest),
            )
            .map_err(|_| state_error("provider Acquire intent cannot be normalized"))?;
            let retained_normalization = attempt
                .normalized_acquire_intent
                .as_ref()
                .ok_or_else(|| state_error("provider Acquire normalization is missing"))?;
            if acquisition_id != value.acquisition_id
                || !common_matches(
                    request.session_binding().as_bytes(),
                    request.sequence(),
                    request.request_id(),
                )
                || request.acquisition_id().as_bytes() != &value.acquisition_id
                || request.holder_authority_id() != value.scope.holder_authority_id
                || request.holder_generation() != session.root_mount_authority_generation
                || request.holder_authority_digest().as_bytes()
                    != &session.root_mount_authority_digest
                || request.node_id() != session.node_id
                || request.boot_id() != session.kernel_boot_id
                || request.prospective_apply_template() != value.prospective_mount_template
                || request.prospective_apply_template_digest().as_bytes()
                    != &value.prospective_mount_template_digest
                || request.binding() != value.source_binding
                || request.binding_digest().as_bytes() != &value.source_binding_digest
                || request.requested_lease_seconds() != value.requested_lease_seconds
                || request.requested_maximum_submounts() != value.requested_maximum_submounts
                || request.recursive() != value.recursive
                || request.kernel_coupled() != value.kernel_coupled
                || session.authenticated_at_seconds >= request.deadline_seconds()
                || normalized.to_canonical_bytes() != retained_normalization.bytes
                || normalized.digest().as_bytes() != &retained_normalization.digest
                || request.source_use() != SourceUseV1::MountCreate
            {
                return Err(state_error(
                    "provider Acquire request contradicts immutable intent",
                ));
            }
        }
        (
            ProviderIntentV2::Release { value },
            ProviderMethodV2::Release,
            ProviderQueryOwnerV2::Release { acquisition_id },
        ) => {
            let request = decode_release_request(signed.subject())
                .map_err(|_| state_error("retained provider Release body is invalid"))?;
            if acquisition_id != value.acquisition_id
                || !common_matches(
                    request.session_binding().as_bytes(),
                    request.sequence(),
                    request.request_id(),
                )
                || request.acquisition_id().as_bytes() != &value.acquisition_id
                || request.holder_authority_id() != value.scope.holder_authority_id
                || request.holder_generation() != session.root_mount_authority_generation
                || request.holder_authority_digest().as_bytes()
                    != &session.root_mount_authority_digest
                || request.lease_id() != value.lease_id
                || request.lease_digest().as_bytes() != &value.signed_lease_digest
                || session.authenticated_at_seconds >= request.deadline_seconds()
            {
                return Err(state_error(
                    "provider Release request contradicts immutable intent",
                ));
            }
        }
        (
            ProviderIntentV2::Inventory { value },
            ProviderMethodV2::Inventory,
            ProviderQueryOwnerV2::Inventory,
        ) => {
            let request = decode_inventory_request(signed.subject())
                .map_err(|_| state_error("retained provider Inventory body is invalid"))?;
            if !common_matches(
                request.session_binding().as_bytes(),
                request.sequence(),
                request.request_id(),
            ) || request.holder_authority_id() != value.scope.holder_authority_id
                || request.holder_generation() != session.root_mount_authority_generation
                || request.holder_authority_digest().as_bytes()
                    != &session.root_mount_authority_digest
                || request
                    .known_inventory_digest()
                    .map(|digest| *digest.as_bytes())
                    != value.known_inventory_digest
                || session.authenticated_at_seconds >= request.deadline_seconds()
            {
                return Err(state_error(
                    "provider Inventory request contradicts immutable intent",
                ));
            }
            validate_inventory_intent_history(attempt, value, table)?;
        }
        _ => {
            return Err(state_error(
                "SourceProvider method, owner, and intent disagree",
            ));
        }
    }
    Ok(())
}

fn validate_inventory_intent_history(
    attempt: &SourceProviderQueryAttemptV2,
    intent: &InventoryIntentV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let mut prior = Vec::new();
    for candidate in table.provider_attempts.values().filter(|candidate| {
        candidate.scope == attempt.scope
            && candidate.method == ProviderMethodV2::Inventory
            && is_complete(candidate)
            && candidate.attempt_id != attempt.attempt_id
    }) {
        if attempt_happens_after(table, candidate, attempt)? {
            prior.push(candidate);
        } else if !attempt_happens_after(table, attempt, candidate)? {
            return Err(state_error(
                "Inventory intent history is not chronologically ordered",
            ));
        }
    }
    let expected_ordinal = u64::try_from(prior.len())
        .map_err(|_| state_error("Inventory intent history exceeds u64"))?;
    if intent.known_observation_ordinal != expected_ordinal {
        return Err(state_error(
            "Inventory intent observation floor does not reproduce",
        ));
    }
    let latest = prior.into_iter().try_fold(None, |latest, candidate| {
        let Some(current) = latest else {
            return Ok::<_, crate::MountError>(Some(candidate));
        };
        if attempt_happens_after(table, current, candidate)? {
            Ok(Some(candidate))
        } else if attempt_happens_after(table, candidate, current)? {
            Ok(Some(current))
        } else {
            Err(state_error(
                "Inventory intent predecessors are not chronologically ordered",
            ))
        }
    })?;
    let expected = latest.map(inventory_attempt_floor).transpose()?;
    let retained = (
        intent.known_inventory_generation,
        intent.known_inventory_digest,
        intent.known_catalog_generation,
        intent.known_catalog_digest,
    );
    if retained != expected.unwrap_or((None, None, None, None)) {
        return Err(state_error(
            "Inventory intent does not retain its exact prior stable floor",
        ));
    }
    Ok(())
}

type InventoryIntentFloorV2 = (Option<u64>, Option<[u8; 32]>, Option<u64>, Option<[u8; 32]>);

fn inventory_attempt_floor(
    attempt: &SourceProviderQueryAttemptV2,
) -> Result<InventoryIntentFloorV2> {
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Complete,
        signed_result,
        ..
    } = &attempt.state
    else {
        return Err(state_error("Inventory floor source is not Complete"));
    };
    let signed = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("Inventory floor source is invalid"))?;
    let inventory = signed.subject();
    Ok((
        Some(inventory.inventory_generation()),
        Some(*digest_inventory(inventory).as_bytes()),
        Some(inventory.catalog_generation()),
        Some(*inventory.catalog_digest().as_bytes()),
    ))
}

fn validate_abandoned_attempt(
    attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let ProviderAttemptStateV2::AbandonedIndeterminate {
        dead_execution,
        successor_session_id,
        recovery_root_attempt_id,
        outcome_may_exist,
        resolution,
    } = &attempt.state
    else {
        return Ok(());
    };
    let old = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
    let successor = table
        .provider_sessions
        .get(successor_session_id)
        .ok_or_else(|| state_error("abandoned attempt successor session is missing"))?;
    let recovery_root = table
        .provider_attempts
        .get(recovery_root_attempt_id)
        .ok_or_else(|| state_error("abandoned attempt recovery root is missing"))?;
    let joins_root = if attempt.attempt_id == recovery_root.attempt_id {
        true
    } else {
        matches!(
            &attempt.intent,
            ProviderIntentV2::Inventory { value }
                if value.recovery_root_attempt_id == Some(recovery_root.attempt_id)
        )
    };
    if !*outcome_may_exist
        || dead_execution.old_session_id != old.session_id
        || dead_execution.old_session_record_digest != old.record_digest
        || dead_execution.node_id != old.node_id
        || dead_execution.old_kernel_boot_id != old.kernel_boot_id
        || dead_execution.provider_process_instance != old.provider_process_instance
        || dead_execution.process_execution_digest
            != old.provider_execution.process_execution_digest
        || dead_execution.death_evidence_digest != death_digest(dead_execution)?
        || successor.predecessor_session_id != Some(old.session_id)
        || successor.scope != old.scope
        || recovery_root.scope != attempt.scope
        || !matches!(
            recovery_root.state,
            ProviderAttemptStateV2::AbandonedIndeterminate { .. }
        )
        || !joins_root
    {
        return Err(state_error(
            "abandoned provider execution graph is inconsistent",
        ));
    }
    match dead_execution.proof_kind {
        DeadProviderExecutionProofKindV2::PidfdExited => {
            if dead_execution.observed_kernel_boot_id != old.kernel_boot_id {
                return Err(state_error(
                    "same-boot provider death proof changed boot identity",
                ));
            }
        }
        DeadProviderExecutionProofKindV2::BootReplaced => {
            if dead_execution.observed_kernel_boot_id == old.kernel_boot_id
                || dead_execution.observed_kernel_boot_id == [0; 16]
            {
                return Err(state_error(
                    "cross-boot provider death proof did not replace boot",
                ));
            }
        }
    }
    if resolution.as_ref().is_some_and(|resolution| {
        !matches!(
            (attempt.method, resolution),
            (
                ProviderMethodV2::Acquire,
                RecoveryResolutionV2::RetryAcquireSameIntent { .. }
                    | RecoveryResolutionV2::Conflict { .. }
            ) | (
                ProviderMethodV2::Release,
                RecoveryResolutionV2::RetryReleaseSameIntent { .. }
                    | RecoveryResolutionV2::ProviderTerminalObserved { .. }
                    | RecoveryResolutionV2::Conflict { .. }
            ) | (
                ProviderMethodV2::Inventory,
                RecoveryResolutionV2::InventoryReconciled { .. }
                    | RecoveryResolutionV2::Conflict { .. }
            )
        )
    }) {
        return Err(state_error(
            "provider recovery resolution contradicts abandoned method",
        ));
    }
    if let Some(resolution) = resolution {
        validate_recovery_resolution(attempt, resolution, table)?;
    }
    Ok(())
}

fn validate_recovery_resolution(
    root: &SourceProviderQueryAttemptV2,
    resolution: &RecoveryResolutionV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let (proof, conflict_digest) = match resolution {
        RecoveryResolutionV2::RetryAcquireSameIntent { proof }
        | RecoveryResolutionV2::RetryReleaseSameIntent { proof }
        | RecoveryResolutionV2::ProviderTerminalObserved { proof }
        | RecoveryResolutionV2::InventoryReconciled { proof } => (proof, None),
        RecoveryResolutionV2::Conflict {
            proof,
            conflict_digest,
        } => (proof, Some(*conflict_digest)),
    };
    let inventory_attempt = exact_attempt(table, proof.inventory_attempt)?;
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Complete,
        signed_result,
        ..
    } = &inventory_attempt.state
    else {
        return Err(state_error(
            "provider recovery resolution lacks Complete Inventory",
        ));
    };
    let ProviderIntentV2::Inventory { value: intent } = &inventory_attempt.intent else {
        return Err(state_error(
            "provider recovery resolution points to a non-Inventory intent",
        ));
    };
    let signed_inventory = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("provider recovery resolution Inventory is invalid"))?;
    let head = table
        .provider_heads
        .get(&(
            root.scope.holder_authority_id,
            root.scope.provider_authority_id,
        ))
        .ok_or_else(|| state_error("provider recovery resolution head is missing"))?;
    if inventory_attempt.scope != root.scope
        || intent.scope != root.scope
        || intent.recovery_root_attempt_id != Some(root.attempt_id)
        || proof.inventory_digest == [0; 32]
        || proof.inventory_observation_ordinal == 0
        || proof.inventory_observation_ordinal <= intent.known_observation_ordinal
        || proof.inventory_observation_ordinal > head.inventory_observation_ordinal
        || proof.projection_epoch > head.current_projection_epoch
        || proof.projection_digest == [0; 32]
        || proof.reconciliation_digest == [0; 32]
        || proof.reconciliation.projection_epoch != proof.projection_epoch
        || proof.reconciliation.projection_digest != proof.projection_digest
        || reconciliation_commitment(&proof.reconciliation) != proof.reconciliation_digest
        || digest_inventory(signed_inventory.subject()).as_bytes() != &proof.inventory_digest
        || conflict_digest == Some([0; 32])
    {
        return Err(state_error(
            "provider recovery resolution does not join its root",
        ));
    }
    if proof.inventory_observation_ordinal == head.inventory_observation_ordinal
        && (head.inventory_floor.as_ref().is_none_or(|floor| {
            floor.attempt != proof.inventory_attempt
                || floor.inventory_digest != proof.inventory_digest
        }) || (head.current_projection_epoch == proof.projection_epoch
            && head.last_reconciliation.as_ref() != Some(&proof.reconciliation)))
    {
        return Err(state_error(
            "current recovery Inventory floor differs from retained resolution",
        ));
    }
    if inventory_observation_ordinal(table, root.scope, inventory_attempt)?
        != proof.inventory_observation_ordinal
    {
        return Err(state_error(
            "provider recovery Inventory ordinal does not reproduce",
        ));
    }

    let row = match root.owner {
        ProviderQueryOwnerV2::Acquire { acquisition_id }
        | ProviderQueryOwnerV2::Release { acquisition_id } => {
            table.acquisitions.get(&acquisition_id)
        }
        ProviderQueryOwnerV2::Inventory => None,
    };
    let entry = row.and_then(|row| {
        signed_inventory
            .subject()
            .entries()
            .iter()
            .find(|entry| entry.acquisition_id().as_bytes() == &row.acquisition_id)
    });
    let evidence_matches = row.zip(entry).is_some_and(|(row, entry)| {
        row.evidence
            .as_ref()
            .is_some_and(|evidence| inventory_entry_matches_evidence(entry, evidence))
    });
    let acquire_retry = root.method == ProviderMethodV2::Acquire
        && (entry.is_none()
            || entry.is_some_and(|entry| {
                entry.state() == aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Active
                    && evidence_matches
            }));
    let release_retry = root.method == ProviderMethodV2::Release
        && entry.is_some_and(|entry| {
            matches!(
                entry.state(),
                aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Active
                    | aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Reaping
            ) && evidence_matches
        });
    let release_terminal = root.method == ProviderMethodV2::Release
        && (entry.is_none()
            || entry.is_some_and(|entry| {
                entry.state()
                    == aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Released
                    && evidence_matches
            }));
    let target_conflicts = match root.method {
        ProviderMethodV2::Acquire => !acquire_retry,
        ProviderMethodV2::Release => !release_retry && !release_terminal,
        ProviderMethodV2::Inventory => proof.reconciliation.conflict_count != 0,
    };
    let resolution_matches = match resolution {
        RecoveryResolutionV2::RetryAcquireSameIntent { .. } => acquire_retry,
        RecoveryResolutionV2::RetryReleaseSameIntent { .. } => release_retry,
        RecoveryResolutionV2::ProviderTerminalObserved { .. } => release_terminal,
        RecoveryResolutionV2::InventoryReconciled { .. } => {
            root.method == ProviderMethodV2::Inventory
        }
        RecoveryResolutionV2::Conflict {
            conflict_digest, ..
        } => {
            target_conflicts
                && proof.reconciliation.conflict_count != 0
                && proof.reconciliation.conflict_digest == *conflict_digest
        }
    };
    if !resolution_matches {
        return Err(state_error(
            "provider recovery resolution contradicts Inventory evidence",
        ));
    }
    Ok(())
}

fn validate_head(head: &SourceProviderHeadV2, table: &SourceAcquisitionTableV2) -> Result<()> {
    let session = exact_session(
        table,
        head.current_session_id,
        head.current_session_record_digest,
    )?;
    if head.revision == 0
        || head.record_digest == [0; 32]
        || !valid_scope(head.scope)
        || session.scope != head.scope
        || head.holder_authority_generation != session.root_mount_authority_generation
        || head.holder_authority_digest != session.root_mount_authority_digest
        || head.provider_authority_generation != session.provider_authority_generation
        || head.provider_authority_digest != session.provider_authority_digest
        || head.next_request_sequence == 0
        || head.next_response_sequence == 0
    {
        return Err(state_error(
            "SourceProvider head is inconsistent with current session",
        ));
    }
    match head.pending_attempt {
        None if head.next_request_sequence != head.next_response_sequence => {
            return Err(state_error(
                "idle SourceProvider head sequence coordinates differ",
            ));
        }
        Some(reference) => {
            let attempt = exact_attempt(table, reference)?;
            if !matches!(attempt.state, ProviderAttemptStateV2::Reserved)
                || attempt.session_id != head.current_session_id
                || attempt.scope != head.scope
                || attempt.request_sequence != head.next_response_sequence
                || head.next_request_sequence.checked_sub(1) != Some(head.next_response_sequence)
            {
                return Err(state_error(
                    "pending SourceProvider head edge is inconsistent",
                ));
            }
        }
        None => {}
    }
    validate_inventory_floor(head, table)?;
    let projection = project_scope(
        head.scope,
        head.current_projection_epoch,
        &table.acquisitions,
    )?;
    if projection.digest != head.current_projection_digest
        || usize::try_from(projection.count).ok()
            != Some(
                table
                    .acquisitions
                    .values()
                    .filter(|row| row.scope == head.scope)
                    .count(),
            )
    {
        return Err(state_error(
            "SourceProvider head projection digest is stale",
        ));
    }
    if let Some(reconciliation) = &head.last_reconciliation {
        if head.inventory_floor.is_none()
            || reconciliation.projection_epoch != head.current_projection_epoch
            || reconciliation.projection_digest != head.current_projection_digest
            || reconciliation.residual_digest == [0; 32]
            || reconciliation.conflict_digest == [0; 32]
        {
            return Err(state_error(
                "SourceProvider reconciliation checkpoint is invalid",
            ));
        }
        if reconciliation
            != &reproduce_reconciliation(head, &table.provider_attempts, &table.acquisitions)?
        {
            return Err(state_error(
                "SourceProvider reconciliation diagnostics do not reproduce",
            ));
        }
    }
    Ok(())
}

fn validate_inventory_floor(
    head: &SourceProviderHeadV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    if head.inventory_floor.is_some() != (head.inventory_observation_ordinal != 0) {
        return Err(state_error(
            "SourceProvider Inventory floor has incomplete presence",
        ));
    }
    let terminal_inventory_attempts = table
        .provider_attempts
        .values()
        .filter(|attempt| {
            attempt.scope == head.scope
                && attempt.method == ProviderMethodV2::Inventory
                && attempt_is_terminal(&attempt.state)
        })
        .collect::<Vec<_>>();
    let complete_inventory_count = terminal_inventory_attempts
        .iter()
        .filter(|attempt| is_complete(attempt))
        .count();
    if u64::try_from(complete_inventory_count)
        .map_err(|_| state_error("Complete provider Inventory count exceeds u64"))?
        != head.inventory_observation_ordinal
    {
        return Err(state_error(
            "provider Inventory ordinal does not equal its Complete history",
        ));
    }
    if head.last_inventory_attempt.is_some() != !terminal_inventory_attempts.is_empty() {
        return Err(state_error(
            "last provider Inventory attempt has incomplete presence",
        ));
    }
    if let Some(reference) = head.last_inventory_attempt {
        let last = exact_attempt(table, reference)?;
        if last.method != ProviderMethodV2::Inventory
            || last.scope != head.scope
            || !attempt_is_terminal(&last.state)
        {
            return Err(state_error(
                "last provider Inventory attempt is not a terminal Inventory",
            ));
        }
        for earlier in terminal_inventory_attempts {
            if earlier.attempt_id != last.attempt_id
                && !attempt_happens_after(table, earlier, last)?
            {
                return Err(state_error(
                    "last provider Inventory attempt is not chronologically last",
                ));
            }
        }
    }
    let Some(floor) = &head.inventory_floor else {
        return Ok(());
    };
    let attempt = exact_attempt(table, floor.attempt)?;
    let session = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Complete,
        signed_result,
        signed_result_digest,
        ..
    } = &attempt.state
    else {
        return Err(state_error(
            "SourceProvider Inventory floor does not reference Complete Inventory",
        ));
    };
    let signed_inventory = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("retained signed provider Inventory is invalid"))?;
    let inventory = signed_inventory.subject();
    let signed_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
            .map_err(|_| state_error("retained Inventory request is invalid"))?;
    let request = decode_inventory_request(signed_request.subject())
        .map_err(|_| state_error("retained Inventory request body is invalid"))?;
    verify_inventory(&signed_inventory, &session.signers[3].public_key)
        .map_err(|_| state_error("retained provider Inventory signature is invalid"))?;
    let ProviderIntentV2::Inventory { value: intent } = &attempt.intent else {
        return Err(state_error("Inventory floor attempt has the wrong intent"));
    };
    if inventory_observation_ordinal(table, head.scope, attempt)?
        != head.inventory_observation_ordinal
    {
        return Err(state_error(
            "SourceProvider Inventory floor is not the latest Complete observation",
        ));
    }
    if attempt.method != ProviderMethodV2::Inventory
        || attempt.scope != head.scope
        || floor.provider_authority_generation == 0
        || floor.provider_authority_digest == [0; 32]
        || floor.provider_outcome_signer_digest == [0; 32]
        || floor.inventory_generation == 0
        || floor.inventory_digest == [0; 32]
        || floor.catalog_generation == 0
        || floor.catalog_digest == [0; 32]
        || floor.signed_result_digest == [0; 32]
    {
        return Err(state_error(
            "SourceProvider Inventory floor does not reference Complete Inventory",
        ));
    }
    if !signer_matches(&session.signers[3], signed_inventory.signer())
        || inventory.request_id() != attempt.request_id
        || inventory.request_digest() != digest_inventory_request(&request)
        || inventory.holder_authority_id() != head.scope.holder_authority_id
        || inventory.holder_generation() != session.root_mount_authority_generation
        || inventory.holder_authority_digest().as_bytes() != &session.root_mount_authority_digest
        || inventory.provider().authority_id() != head.scope.provider_authority_id
        || inventory.provider().authority_generation() != floor.provider_authority_generation
        || inventory.provider().authority_digest().as_bytes() != &floor.provider_authority_digest
        || inventory.provider_process_instance() != session.provider_process_instance
        || session.authenticated_at_seconds >= request.deadline_seconds()
        || inventory.inventory_generation() != floor.inventory_generation
        || digest_inventory(inventory).as_bytes() != &floor.inventory_digest
        || inventory.catalog_generation() != floor.catalog_generation
        || inventory.catalog_digest().as_bytes() != &floor.catalog_digest
        || session.signers[3].public_key_fingerprint != floor.provider_outcome_signer_digest
        || signed_result_digest != &floor.signed_result_digest
        || intent.scope != head.scope
        || intent.known_inventory_generation.is_some() != intent.known_inventory_digest.is_some()
        || intent.known_catalog_generation.is_some() != intent.known_catalog_digest.is_some()
        || intent.known_inventory_generation.is_some_and(|generation| {
            inventory.inventory_generation() < generation
                || (inventory.inventory_generation() == generation
                    && intent.known_inventory_digest
                        != Some(*digest_inventory(inventory).as_bytes()))
        })
        || intent.known_catalog_generation.is_some_and(|generation| {
            inventory.catalog_generation() < generation
                || (inventory.catalog_generation() == generation
                    && intent.known_catalog_digest != Some(*inventory.catalog_digest().as_bytes()))
        })
    {
        return Err(state_error(
            "SourceProvider Inventory floor disagrees with its signed result",
        ));
    }
    validate_inventory_entries(
        inventory,
        head.scope,
        session.negotiated_capabilities.proof_class_capabilities,
    )?;
    Ok(())
}

fn validate_inventory_entries(
    inventory: &aos_sandbox_source_provider_protocol::SourceProviderInventoryV1,
    scope: ProviderScopeV2,
    proof_capabilities: u8,
) -> Result<()> {
    let mut acquisition_ids = BTreeSet::new();
    for entry in inventory.entries() {
        let resource = entry.resource();
        let proof_bit = 1_u8
            .checked_shl(u32::from(entry.proof_class().saturating_sub(1)))
            .unwrap_or(0);
        if !acquisition_ids.insert(*entry.acquisition_id().as_bytes())
            || resource.resource_namespace_digest().as_bytes() != &scope.resource_namespace_digest
            || resource.catalog_generation() > inventory.catalog_generation()
            || (resource.catalog_generation() == inventory.catalog_generation()
                && resource.catalog_digest() != inventory.catalog_digest())
            || entry.proof_class() == 0
            || entry.proof_class() > 4
            || proof_bit & proof_capabilities == 0
            || entry.resource_commitment()
                != provider_resource_commitment_v1(resource, entry.proof_digest())
        {
            return Err(state_error(
                "retained provider Inventory entry violates its floor",
            ));
        }
    }
    Ok(())
}

fn validate_row(row: &SourceAcquisitionRowV2, table: &SourceAcquisitionTableV2) -> Result<()> {
    if table
        .provider_heads
        .get(&(
            row.scope.holder_authority_id,
            row.scope.provider_authority_id,
        ))
        .is_none_or(|head| head.scope != row.scope)
    {
        return Err(state_error("acquisition row provider head is missing"));
    }
    let request = decode_historical_acquire_mount_source_request(&row.mount_acquire_request)?;
    let request_digest = mount_source_acquisition_request_digest_v1(&row.mount_acquire_request);
    if row.revision == 0
        || row.record_digest == [0; 32]
        || !valid_scope(row.scope)
        || row.acquire.operation_id != *request.header().request_id()
        || row.acquire.request_digest != *request_digest.as_bytes()
        || row.acquisition_id
            != *mount_source_acquisition_id_v1(row.acquire.operation_id, request_digest).as_bytes()
        || row.acquisition_id != *request.acquisition_id().as_bytes()
        || row.assignment.sandbox_id != *request.fence().sandbox_id()
        || row.assignment.incarnation_id != *request.fence().incarnation_id()
        || row.assignment.assignment_epoch != request.fence().assignment_epoch()
        || row.assignment.desired_generation != request.fence().desired_generation()
        || row.assignment.assignment_digest != *request.fence().assignment_digest()
        || row.assignment.namespace_generation != request.prospective_namespace_generation()
        || row.prospective_mount_template != request.prospective_mount_template()
        || row.prospective_mount_template_digest
            != *request.prospective_mount_template_digest().as_bytes()
        || row.source_binding != request.source_binding().canonical_bytes()
        || row.source_binding_digest
            != *digest_logical_binding_bytes(&row.source_binding).as_bytes()
        || row.mount_plan_digest == [0; 32]
        || row.ownership_lease_digest == [0; 32]
    {
        return Err(state_error(
            "AOSMSA02 acquisition row contradicts its Mount request",
        ));
    }
    let acquire_root = exact_attempt(table, row.acquire_lineage.root)?;
    let ProviderIntentV2::Acquire { value: intent } = &acquire_root.intent else {
        return Err(state_error(
            "acquisition row points to a non-Acquire lineage",
        ));
    };
    if row.acquire_intent_digest != acquire_root.immutable_intent_digest
        || intent.scope != row.scope
        || intent.acquisition_id != row.acquisition_id
        || intent.mount_request != row.mount_acquire_request
        || intent.mount_request_digest != row.acquire.request_digest
        || intent.assignment != row.assignment
        || intent.mount_plan_digest != row.mount_plan_digest
        || intent.ownership_lease_digest != row.ownership_lease_digest
        || intent.prospective_mount_template != row.prospective_mount_template
        || intent.prospective_mount_template_digest != row.prospective_mount_template_digest
        || intent.source_binding != row.source_binding
        || intent.source_binding_digest != row.source_binding_digest
    {
        return Err(state_error(
            "acquisition row contradicts immutable Acquire intent",
        ));
    }
    validate_release_row(row, table)?;
    validate_scalar_evidence(row)?;
    validate_row_phase(row)?;
    validate_row_attempt_evidence(row, table)
}

fn validate_scalar_evidence(row: &SourceAcquisitionRowV2) -> Result<()> {
    if row.descriptor_custody_digest == Some([0; 32])
        || row.positive_custody_digest == Some([0; 32])
        || row.negative_custody_digest == Some([0; 32])
        || row.fault_digest == Some([0; 32])
        || row.retained_fault_digest == Some([0; 32])
        || row.consumption.as_ref().is_some_and(|value| {
            value.source_pin_record_digest == [0; 32]
                || value.create_effect_record_digest == [0; 32]
                || value.create_operation_record_digest == [0; 32]
        })
    {
        return Err(state_error("AOSMSA02 evidence contains a zero commitment"));
    }
    if let Some(evidence) = &row.evidence {
        if evidence.acquire_attempt.id == [0; 32]
            || evidence.session_id == [0; 32]
            || evidence.provider_outcome_signer_digest == [0; 32]
            || evidence.provider_resource_id == [0; 32]
            || evidence.provider_resource_generation == 0
            || evidence.provider_resource_digest == [0; 32]
            || evidence.provider_catalog_generation == 0
            || evidence.provider_catalog_digest == [0; 32]
            || evidence.provider_selection_generation == 0
            || evidence.provider_selection_digest == [0; 32]
            || !(1..=4).contains(&evidence.provider_proof_class)
            || evidence.provider_proof_digest == [0; 32]
            || evidence.lease_id == [0; 16]
            || evidence.signed_lease_digest == [0; 32]
            || evidence.lease_issued_seconds < 0
            || evidence.lease_expires_seconds <= evidence.lease_issued_seconds
            || evidence.source_realization_handle == [0; 32]
            || evidence.source_physical_proof_digest == [0; 32]
            || evidence.source_kernel_boot_id == [0; 16]
            || evidence.source_device == 0
            || evidence.source_inode == 0
            || evidence.source_unique_mount_id == 0
            || evidence.descriptor_commitment == [0; 32]
        {
            return Err(state_error("AOSMSA02 acquisition evidence is invalid"));
        }
    }
    Ok(())
}

fn validate_release_row(
    row: &SourceAcquisitionRowV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let fields_present = [
        row.release.is_some(),
        row.mount_release_request.is_some(),
        row.release_authority.is_some(),
        row.release_from_phase.is_some(),
        row.release_intent_digest.is_some(),
        row.release_lineage.is_some(),
        row.release_inventory_fence.is_some(),
    ];
    if fields_present.iter().any(|value| *value) && fields_present.iter().any(|value| !*value) {
        return Err(state_error("AOSMSA02 Release intent has partial presence"));
    }
    let Some(lineage) = &row.release_lineage else {
        return Ok(());
    };
    let root = exact_attempt(table, lineage.root)?;
    let ProviderIntentV2::Release { value: intent } = &root.intent else {
        return Err(state_error(
            "acquisition row points to a non-Release lineage",
        ));
    };
    let release = row
        .release
        .ok_or_else(|| state_error("Release operation is missing"))?;
    let body = row
        .mount_release_request
        .as_deref()
        .ok_or_else(|| state_error("Release body is missing"))?;
    let authority = row
        .release_authority
        .ok_or_else(|| state_error("Release authority is missing"))?;
    let evidence = row
        .evidence
        .as_ref()
        .ok_or_else(|| state_error("Release intent lacks retained Acquire evidence"))?;
    let acquire_attempt = exact_attempt(table, evidence.acquire_attempt)?;
    let inventory_fence = row
        .release_inventory_fence
        .as_ref()
        .ok_or_else(|| state_error("Release Inventory fence is missing"))?;
    let release_from = row
        .release_from_phase
        .ok_or_else(|| state_error("Release predecessor phase is missing"))?;
    let retained_projection = projection_from_entries(
        row.scope,
        inventory_fence.projection_epoch,
        &inventory_fence.projection_entries,
    )?;
    let mut releasing_row = row.clone();
    releasing_row.phase = SourceAcquisitionPhaseV2::Releasing;
    releasing_row.release_proof = None;
    releasing_row.negative_custody_digest = None;
    let expected_target_projection = project_row(&releasing_row);
    validate_mount_release_body(body, release, authority, row.acquisition_id)?;
    if row.release_intent_digest != Some(root.immutable_intent_digest)
        || intent.scope != row.scope
        || intent.acquisition_id != row.acquisition_id
        || intent.mount_request != body
        || intent.mount_operation != release
        || intent.authority != authority
        || intent.lease_id != evidence.lease_id
        || intent.signed_lease_digest != evidence.signed_lease_digest
        || intent.provider_resource_id != evidence.provider_resource_id
        || intent.provider_resource_digest != evidence.provider_resource_digest
        || intent.provider_proof_digest != evidence.provider_proof_digest
        || intent.descriptor_commitment != evidence.descriptor_commitment
        || root.owner_predecessor_revision != authority.expected_revision
        || root.owner_predecessor_digest != authority.expected_record_digest
        || !attempt_happens_after(table, acquire_attempt, root)?
        || !release_authority_dominates(row.assignment, authority)
        || !matches!(
            release_from,
            SourceAcquisitionPhaseV2::PendingQuery
                | SourceAcquisitionPhaseV2::DescriptorCustodied
                | SourceAcquisitionPhaseV2::Active
                | SourceAcquisitionPhaseV2::Consumed
        )
        || inventory_fence.projection_epoch == 0
        || inventory_fence.projection_digest == [0; 32]
        || inventory_fence.projection_entries.is_empty()
        || inventory_fence.projection_entries.len() > MAXIMUM_SOURCE_ACQUISITIONS
        || retained_projection.digest != inventory_fence.projection_digest
        || inventory_fence
            .projection_entries
            .binary_search_by_key(&row.acquisition_id, |entry| entry.acquisition_id)
            .ok()
            .and_then(|index| inventory_fence.projection_entries.get(index))
            != Some(&expected_target_projection)
    {
        return Err(state_error(
            "acquisition row contradicts immutable Release intent",
        ));
    }
    Ok(())
}

fn release_authority_dominates(acquire: AssignmentV2, release: ReleaseAuthorityV2) -> bool {
    if acquire.sandbox_id != release.sandbox_id
        || acquire.incarnation_id != release.incarnation_id
        || release.assignment_epoch < acquire.assignment_epoch
    {
        return false;
    }
    if release.assignment_epoch > acquire.assignment_epoch {
        return true;
    }
    if release.desired_generation < acquire.desired_generation {
        return false;
    }
    release.desired_generation > acquire.desired_generation
        || release.assignment_digest == acquire.assignment_digest
}

fn validate_mount_release_body(
    bytes: &[u8],
    operation: MountOperationV2,
    authority: ReleaseAuthorityV2,
    acquisition_id: [u8; 32],
) -> Result<()> {
    let body = ReleaseMountSourceAcquisitionRequest::decode_from_slice(bytes)
        .map_err(|_| state_error("retained Mount Release body is invalid"))?;
    if body.encode_to_vec() != bytes || !body.__buffa_unknown_fields.is_empty() {
        return Err(state_error("retained Mount Release body is noncanonical"));
    }
    let header = body
        .header
        .as_option()
        .ok_or_else(|| state_error("Mount Release header is missing"))?;
    let fence = body
        .fence
        .as_option()
        .ok_or_else(|| state_error("Mount Release fence is missing"))?;
    let digest = mount_source_acquisition_request_digest_v1(bytes);
    if !header.__buffa_unknown_fields.is_empty()
        || !fence.__buffa_unknown_fields.is_empty()
        || header.protocol_major != 2
        || header.protocol_minor != 0
        || header.deadline_boottime_nanoseconds == 0
        || !(aos_sandbox_protocol::MINIMUM_RESPONSE_BYTES
            ..=aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES)
            .contains(&header.maximum_response_bytes)
        || header.audience.as_known()
            != Some(aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER)
        || header.request_id.as_slice() != operation.operation_id
        || digest.as_bytes() != &operation.request_digest
        || body.acquisition_id.as_slice() != acquisition_id
        || body.expected_revision != authority.expected_revision
        || body.expected_record_digest.as_slice() != authority.expected_record_digest
        || fence.sandbox_id.as_slice() != authority.sandbox_id
        || fence.incarnation_id.as_slice() != authority.incarnation_id
        || fence.assignment_epoch != authority.assignment_epoch
        || fence.desired_generation != authority.desired_generation
        || fence.assignment_digest.as_slice() != authority.assignment_digest
        || authority.sandbox_id == [0; 16]
        || authority.incarnation_id == [0; 16]
        || authority.assignment_epoch == 0
        || authority.desired_generation == 0
        || authority.assignment_digest == [0; 32]
        || authority.expected_revision == 0
        || authority.expected_record_digest == [0; 32]
    {
        return Err(state_error(
            "retained Mount Release body contradicts durable authority",
        ));
    }
    Ok(())
}

fn validate_row_phase(row: &SourceAcquisitionRowV2) -> Result<()> {
    let shape = match row.phase {
        SourceAcquisitionPhaseV2::Faulted => row
            .faulted_from
            .is_some_and(|phase| phase_shape(row, phase, false)),
        phase => phase_shape(row, phase, true),
    };
    let fault_pair = row.faulted_from.is_some() == row.fault_digest.is_some();
    let retained_pair = row.retained_faulted_from.is_some() == row.retained_fault_digest.is_some();
    if !shape
        || !fault_pair
        || !retained_pair
        || (row.phase != SourceAcquisitionPhaseV2::Faulted && row.faulted_from.is_some())
        || matches!(
            row.faulted_from,
            Some(SourceAcquisitionPhaseV2::Faulted | SourceAcquisitionPhaseV2::Released)
        )
        || matches!(
            row.retained_faulted_from,
            Some(SourceAcquisitionPhaseV2::Faulted | SourceAcquisitionPhaseV2::Released)
        )
        || (row.retained_faulted_from.is_some()
            && !matches!(
                row.phase,
                SourceAcquisitionPhaseV2::Releasing | SourceAcquisitionPhaseV2::Released
            ))
        || row
            .retained_faulted_from
            .is_some_and(|origin| !retained_origin_evidence_is_present(row, origin))
    {
        return Err(state_error(
            "AOSMSA02 lifecycle phase has invalid field presence",
        ));
    }
    Ok(())
}

fn phase_shape(
    row: &SourceAcquisitionRowV2,
    phase: SourceAcquisitionPhaseV2,
    require_no_fault: bool,
) -> bool {
    let has_evidence = row.evidence.is_some();
    let has_descriptor = row.descriptor_custody_digest.is_some();
    let has_positive = row.positive_custody_digest.is_some();
    let has_consumption = row.consumption.is_some();
    let has_release = row.release_lineage.is_some();
    let has_release_proof = row.release_proof.is_some();
    let has_negative = row.negative_custody_digest.is_some();
    let acquisition_shape = |origin| match origin {
        SourceAcquisitionPhaseV2::PendingQuery => {
            !has_descriptor && !has_positive && !has_consumption
        }
        SourceAcquisitionPhaseV2::DescriptorCustodied => {
            has_evidence && has_descriptor && !has_positive && !has_consumption
        }
        SourceAcquisitionPhaseV2::Active => {
            has_evidence && has_descriptor && has_positive && !has_consumption
        }
        SourceAcquisitionPhaseV2::Consumed => {
            has_evidence && has_descriptor && has_positive && has_consumption
        }
        SourceAcquisitionPhaseV2::Releasing
        | SourceAcquisitionPhaseV2::Released
        | SourceAcquisitionPhaseV2::Faulted => false,
    };
    let release_from_shape = || row.release_from_phase.is_some_and(acquisition_shape);
    let shape = match phase {
        SourceAcquisitionPhaseV2::PendingQuery
        | SourceAcquisitionPhaseV2::DescriptorCustodied
        | SourceAcquisitionPhaseV2::Active
        | SourceAcquisitionPhaseV2::Consumed => {
            acquisition_shape(phase)
                && !has_release
                && row.release_from_phase.is_none()
                && !has_release_proof
                && !has_negative
        }
        SourceAcquisitionPhaseV2::Releasing => {
            has_release && release_from_shape() && !has_release_proof && !has_negative
        }
        SourceAcquisitionPhaseV2::Released => {
            has_release && release_from_shape() && has_release_proof && has_negative
        }
        SourceAcquisitionPhaseV2::Faulted => false,
    };
    shape && (!require_no_fault || row.faulted_from.is_none())
}

fn retained_origin_evidence_is_present(
    row: &SourceAcquisitionRowV2,
    origin: SourceAcquisitionPhaseV2,
) -> bool {
    match origin {
        SourceAcquisitionPhaseV2::PendingQuery => true,
        SourceAcquisitionPhaseV2::DescriptorCustodied => {
            row.evidence.is_some() && row.descriptor_custody_digest.is_some()
        }
        SourceAcquisitionPhaseV2::Active => {
            row.evidence.is_some()
                && row.descriptor_custody_digest.is_some()
                && row.positive_custody_digest.is_some()
        }
        SourceAcquisitionPhaseV2::Consumed => {
            row.evidence.is_some()
                && row.descriptor_custody_digest.is_some()
                && row.positive_custody_digest.is_some()
                && row.consumption.is_some()
        }
        SourceAcquisitionPhaseV2::Releasing => row.release_lineage.is_some(),
        SourceAcquisitionPhaseV2::Released | SourceAcquisitionPhaseV2::Faulted => false,
    }
}

fn validate_row_attempt_evidence(
    row: &SourceAcquisitionRowV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    if row.acquire_terminal_attempt.is_some() != row.evidence.is_some() {
        return Err(state_error(
            "Acquire terminal attempt and evidence presence differ",
        ));
    }
    if let Some(reference) = row.acquire_terminal_attempt {
        let attempt = exact_attempt(table, reference)?;
        if attempt.method != ProviderMethodV2::Acquire
            || attempt.owner
                != (ProviderQueryOwnerV2::Acquire {
                    acquisition_id: row.acquisition_id,
                })
            || !is_complete(attempt)
            || row.evidence.as_ref().is_some_and(|evidence| {
                evidence.acquire_attempt != reference || evidence.session_id != attempt.session_id
            })
        {
            return Err(state_error(
                "Acquire terminal evidence references the wrong attempt",
            ));
        }
        validate_complete_acquire(row, attempt, table)?;
    }
    let receipt_proof = matches!(
        row.release_proof.as_ref(),
        Some(ReleaseProofV2::ProviderReceipt { .. })
    );
    if receipt_proof && row.release_terminal_attempt.is_none() {
        return Err(state_error(
            "provider receipt proof lacks its terminal Release attempt",
        ));
    }
    if let Some(reference) = row.release_terminal_attempt {
        let attempt = exact_attempt(table, reference)?;
        let effective_phase = if row.phase == SourceAcquisitionPhaseV2::Faulted {
            row.faulted_from
        } else {
            Some(row.phase)
        };
        if attempt.method != ProviderMethodV2::Release
            || attempt.owner
                != (ProviderQueryOwnerV2::Release {
                    acquisition_id: row.acquisition_id,
                })
            || !is_complete(attempt)
            || (!receipt_proof
                && (row.release_proof.is_some()
                    || effective_phase != Some(SourceAcquisitionPhaseV2::Releasing)))
        {
            return Err(state_error(
                "Release terminal proof references the wrong attempt",
            ));
        }
        validate_complete_release(row, attempt, table)?;
    }
    match &row.release_proof {
        Some(ReleaseProofV2::ProviderReceipt {
            attempt,
            release_generation,
        }) => {
            if Some(*attempt) != row.release_terminal_attempt || *release_generation == 0 {
                return Err(state_error("provider Release proof is incomplete"));
            }
        }
        Some(ReleaseProofV2::ProviderInventory {
            attempt,
            inventory_digest,
            inventory_observation_ordinal,
            projection_epoch,
        }) => {
            if row.release_terminal_attempt.is_some() {
                return Err(state_error(
                    "Inventory release proof retains a Release terminal attempt",
                ));
            }
            let inventory = exact_attempt(table, *attempt)?;
            let release_tail = exact_attempt(
                table,
                row.release_lineage
                    .as_ref()
                    .ok_or_else(|| state_error("Release lineage is missing"))?
                    .tail,
            )?;
            let fence = row
                .release_inventory_fence
                .as_ref()
                .ok_or_else(|| state_error("Release Inventory fence is missing"))?;
            let head = table
                .provider_heads
                .get(&(
                    row.scope.holder_authority_id,
                    row.scope.provider_authority_id,
                ))
                .ok_or_else(|| state_error("Release Inventory provider head is missing"))?;
            if inventory.method != ProviderMethodV2::Inventory
                || !is_complete(inventory)
                || *inventory_digest == [0; 32]
                || *inventory_observation_ordinal <= fence.inventory_observation_floor
                || *inventory_observation_ordinal > head.inventory_observation_ordinal
                || inventory_observation_ordinal(table, row.scope, inventory)?
                    != *inventory_observation_ordinal
                || *projection_epoch < fence.projection_epoch
                || *projection_epoch > head.current_projection_epoch
                || !attempt_happens_after(table, release_tail, inventory)?
                || !terminal_inventory_matches(table, row, inventory, *inventory_digest)?
            {
                return Err(state_error("provider Inventory release proof is invalid"));
            }
            if *inventory_observation_ordinal == head.inventory_observation_ordinal
                && head.inventory_floor.as_ref().is_none_or(|floor| {
                    floor.attempt != *attempt || floor.inventory_digest != *inventory_digest
                })
            {
                return Err(state_error(
                    "current Inventory ordinal differs from retained Release proof",
                ));
            }
            if *inventory_observation_ordinal < head.inventory_observation_ordinal {
                let floor = head
                    .inventory_floor
                    .as_ref()
                    .ok_or_else(|| state_error("advanced Inventory head lacks a current floor"))?;
                let current = exact_attempt(table, floor.attempt)?;
                if !attempt_happens_after(table, inventory, current)?
                    || !terminal_inventory_matches(table, row, current, floor.inventory_digest)?
                {
                    return Err(state_error(
                        "released acquisition reappears in current provider Inventory",
                    ));
                }
            }
        }
        None => {}
    }
    Ok(())
}

fn terminal_inventory_matches(
    table: &SourceAcquisitionTableV2,
    row: &SourceAcquisitionRowV2,
    attempt: &SourceProviderQueryAttemptV2,
    expected_digest: [u8; 32],
) -> Result<bool> {
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Complete,
        signed_result,
        ..
    } = &attempt.state
    else {
        return Ok(false);
    };
    let signed = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("Release proof Inventory is invalid"))?;
    let session = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
    if attempt.method != ProviderMethodV2::Inventory
        || attempt.scope != row.scope
        || signed.subject().holder_authority_id() != row.scope.holder_authority_id
        || signed.subject().provider().authority_id() != row.scope.provider_authority_id
        || signed.subject().holder_generation() != session.root_mount_authority_generation
        || signed.subject().holder_authority_digest().as_bytes()
            != &session.root_mount_authority_digest
        || signed.subject().provider().authority_generation()
            != session.provider_authority_generation
        || signed.subject().provider().authority_digest().as_bytes()
            != &session.provider_authority_digest
        || digest_inventory(signed.subject()).as_bytes() != &expected_digest
    {
        return Ok(false);
    }
    let entry = signed
        .subject()
        .entries()
        .iter()
        .find(|entry| entry.acquisition_id().as_bytes() == &row.acquisition_id);
    Ok(match entry {
        None => true,
        Some(entry) => {
            entry.state() == aos_sandbox_source_provider_protocol::InventoryLeaseStateV1::Released
                && row
                    .evidence
                    .as_ref()
                    .is_some_and(|evidence| inventory_entry_matches_evidence(entry, evidence))
        }
    })
}

fn validate_complete_acquire(
    row: &SourceAcquisitionRowV2,
    attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let session = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
    let ProviderAttemptStateV2::DispositionConsumed {
        signed_status,
        signed_result,
        ..
    } = &attempt.state
    else {
        return Err(state_error("Acquire evidence attempt is not consumed"));
    };
    let signed_receipt = SignedSourceProviderReceiptV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("retained provider Acquire receipt is invalid"))?;
    let receipt = signed_receipt.subject();
    let signed_lease =
        SignedSourceExportLeaseV1::from_canonical_bytes(receipt.signed_export_lease())
            .map_err(|_| state_error("retained provider export lease is invalid"))?;
    let lease = signed_lease.subject();
    let resource = lease.resource();
    let provider = lease.provider();
    let signed_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
            .map_err(|_| state_error("retained provider Acquire request is invalid"))?;
    let request = decode_acquire_request(signed_request.subject())
        .map_err(|_| state_error("retained provider Acquire request body is invalid"))?;
    let signed_status =
        aos_sandbox_source_provider_protocol::SignedSourceProviderStatusV1::from_canonical_bytes(
            signed_status,
        )
        .map_err(|_| state_error("retained provider Acquire status is invalid"))?;
    let proof_digest = digest_provider_proof(lease.proof());
    let resource_digest = provider_resource_commitment_v1(resource, proof_digest);
    let evidence = row
        .evidence
        .as_ref()
        .ok_or_else(|| state_error("Complete Acquire lacks durable evidence"))?;
    let selection_floor = historical_selection_floor(evidence)?;
    let lease_signer = &evidence.historical_lease_signer.signer;
    verify_provider_receipt_and_lease(
        &signed_receipt,
        &session.signers[3].public_key,
        &lease_signer.public_key,
    )
    .map_err(|_| state_error("retained provider Acquire graph signature is invalid"))?;
    let mount_proof = mount_source_proof_class_from_provider_v1(lease.proof());
    let proof_class = match mount_proof {
        aos_sandbox_protocol::MountSourceProofClassV1::ImmutableTree => {
            SourceAcquisitionProofClassV2::ImmutableTree
        }
        aos_sandbox_protocol::MountSourceProofClassV1::LocalLive => {
            SourceAcquisitionProofClassV2::LocalLive
        }
        aos_sandbox_protocol::MountSourceProofClassV1::BestEffortReplica => {
            SourceAcquisitionProofClassV2::BestEffortReplica
        }
    };
    if proof_class != expected_binding_proof_class(&row.source_binding)? {
        return Err(state_error(
            "provider proof class differs from immutable Acquire intent",
        ));
    }
    let physical = mount_source_physical_proof_digest_v1(MountSourcePhysicalProofV1 {
        binding_digest: row.source_binding_digest,
        proof_class: mount_proof,
        provider_authority_id: provider.authority_id(),
        provider_authority_generation: provider.authority_generation(),
        provider_authority_digest: *provider.authority_digest().as_bytes(),
        provider_resource_id: resource.resource_id(),
        provider_resource_generation: resource.resource_generation(),
        provider_resource_digest: *resource_digest.as_bytes(),
        provider_catalog_generation: resource.catalog_generation(),
        provider_catalog_digest: *resource.catalog_digest().as_bytes(),
        kernel_boot_id: receipt.kernel_boot_id(),
        device: receipt.device(),
        inode: receipt.inode(),
        unique_mount_id: receipt.unique_mount_id(),
    });
    let observation = SourceRootObservationV1::new(
        receipt.kernel_boot_id(),
        receipt.device(),
        receipt.inode(),
        receipt.unique_mount_id(),
        true,
        true,
        true,
    )
    .map_err(|_| state_error("retained SourceRoot observation is invalid"))?;
    let descriptor = source_root_descriptor_commitment_v1(&observation);
    let expected = SourceAcquisitionEvidenceV2 {
        acquire_attempt: RecordRefV2 {
            id: attempt.attempt_id,
            revision: attempt.revision,
            record_digest: attempt.record_digest,
        },
        session_id: session.session_id,
        provider_outcome_signer_digest: session.signers[3].public_key_fingerprint,
        historical_lease_signer: evidence.historical_lease_signer.clone(),
        provider_resource_id: resource.resource_id(),
        provider_resource_generation: resource.resource_generation(),
        provider_resource_digest: *resource_digest.as_bytes(),
        provider_catalog_generation: resource.catalog_generation(),
        provider_catalog_digest: *resource.catalog_digest().as_bytes(),
        provider_selection_generation: resource.selection_generation(),
        provider_selection_digest: *resource.selection_digest().as_bytes(),
        provider_proof_class: lease.proof().class_code(),
        proof_class,
        provider_proof_digest: *proof_digest.as_bytes(),
        lease_id: lease.lease_id(),
        signed_lease_digest: *digest_signed_export_lease(&signed_lease).as_bytes(),
        lease_issued_seconds: lease.issued_seconds(),
        lease_expires_seconds: lease.expires_seconds(),
        source_realization_handle: mount_source_realization_handle_v1(
            row.source_binding_digest,
            physical,
        ),
        source_physical_proof_digest: physical,
        source_kernel_boot_id: receipt.kernel_boot_id(),
        source_device: receipt.device(),
        source_inode: receipt.inode(),
        source_unique_mount_id: receipt.unique_mount_id(),
        descriptor_commitment: *descriptor.as_bytes(),
    };
    let duration = lease
        .expires_seconds()
        .checked_sub(lease.issued_seconds())
        .and_then(|seconds| u64::try_from(seconds).ok());
    let proof_bit = lease.proof().capability_bit();
    let floor_snapshot = &evidence.historical_lease_signer.selection_floor;
    let historical_floor = &evidence.historical_lease_signer;
    if row.evidence.as_ref() != Some(&expected)
        || !signer_matches(&session.signers[3], signed_receipt.signer())
        || !signer_matches(lease_signer, signed_lease.signer())
        || <[u8; 32]>::from(Sha256::digest(lease_signer.public_key))
            != lease_signer.public_key_fingerprint
        || !interval_contains(
            lease_signer.authority_valid_from_seconds,
            lease_signer.authority_valid_until_seconds,
            lease.issued_seconds(),
        )
        || !interval_contains(
            lease_signer.key_valid_from_seconds,
            lease_signer.key_valid_until_seconds,
            lease.issued_seconds(),
        )
        || receipt.request_id() != attempt.request_id
        || receipt.request_digest() != digest_acquire_request(&request)
        || receipt.acquisition_id().as_bytes() != &row.acquisition_id
        || receipt.provider_process_instance() != session.provider_process_instance
        || receipt.kernel_boot_id() != request.boot_id()
        || receipt.descriptor_role() != SourceProviderDescriptorRole::SourceRoot
        || receipt.lease_digest() != digest_signed_export_lease(&signed_lease)
        || receipt.observed_proof_digest() != proof_digest
        || lease.request_id() != attempt.request_id
        || lease.request_digest() != digest_acquire_request(&request)
        || lease.holder_authority_id() != session.scope.holder_authority_id
        || lease.holder_generation() != session.root_mount_authority_generation
        || lease.holder_authority_digest().as_bytes() != &session.root_mount_authority_digest
        || lease.binding_digest().as_bytes() != &row.source_binding_digest
        || lease.revocation_digest() != request.revocation_digest()
        || matches!(
            lease.proof(),
            aos_sandbox_source_provider_protocol::SourceProviderProofV1::LocalLiveExport {
                proof,
                ..
            } if proof.consumer_authority_id() != request.holder_authority_id()
                || proof.consumer_generation() != request.holder_generation()
        )
        || session.authenticated_at_seconds >= request.deadline_seconds()
        || lease.issued_seconds() < session.authenticated_at_seconds
        || session.authenticated_at_seconds >= lease.expires_seconds()
        || lease.expires_seconds() > request.deadline_seconds()
        || lease.expires_seconds()
            > attempt
                .normalized_acquire_intent
                .as_ref()
                .map_or(0, |value| value.maximum_lease_expiry_seconds)
        || duration
            .is_none_or(|seconds| seconds == 0 || seconds > request.requested_lease_seconds())
        || provider.authority_id() != lease_signer.authority_id
        || provider.authority_generation() != lease_signer.authority_generation
        || provider.authority_digest().as_bytes() != &lease_signer.authority_digest
        || !generation_dominates_snapshot(
            lease_signer.authority_generation,
            lease_signer.authority_digest,
            session.provider_authority_generation,
            session.provider_authority_digest,
        )
        || resource.resource_namespace_digest().as_bytes()
            != &session.scope.resource_namespace_digest
        || proof_bit & session.negotiated_capabilities.proof_class_capabilities == 0
        || lease.proof().requires_kernel_coupled() != request.kernel_coupled()
        || (request.kernel_coupled() && !session.negotiated_capabilities.supports_kernel_coupled)
        || (request.recursive() && !session.negotiated_capabilities.supports_recursive)
        || lease.proof().topology().observed_submounts() > request.requested_maximum_submounts()
        || (!request.recursive() && lease.proof().topology().observed_submounts() != 0)
        || selection_floor.acquisition_id() != request.acquisition_id()
        || selection_floor.provider_authority_id() != provider.authority_id()
        || selection_floor.route_id() != session.scope.route_id
        || selection_floor.resource() != resource
        || selection_floor.outcome_signer() != signed_lease.signer()
        || selection_floor.lease_id() != lease.lease_id()
        || selection_floor.signed_lease_digest() != digest_signed_export_lease(&signed_lease)
        || selection_floor.proof_class() != lease.proof().class_code()
        || selection_floor.proof_digest() != proof_digest
        || selection_floor.resource_commitment() != resource_digest
        || floor_snapshot.acquisition_id != row.acquisition_id
        || floor_snapshot.provider_authority_id != provider.authority_id()
        || floor_snapshot.route_id != session.scope.route_id
        || floor_snapshot.resource_namespace_digest != session.scope.resource_namespace_digest
        || floor_snapshot.catalog_generation != resource.catalog_generation()
        || floor_snapshot.catalog_digest != *resource.catalog_digest().as_bytes()
        || floor_snapshot.resource_id != resource.resource_id()
        || floor_snapshot.resource_generation != resource.resource_generation()
        || floor_snapshot.resource_digest != *resource.resource_digest().as_bytes()
        || floor_snapshot.selection_generation != resource.selection_generation()
        || floor_snapshot.selection_digest != *resource.selection_digest().as_bytes()
        || floor_snapshot.lease_id != lease.lease_id()
        || floor_snapshot.signed_lease_digest
            != *digest_signed_export_lease(&signed_lease).as_bytes()
        || floor_snapshot.proof_class != lease.proof().class_code()
        || floor_snapshot.proof_digest != *proof_digest.as_bytes()
        || floor_snapshot.resource_commitment != *resource_digest.as_bytes()
        || historical_floor.catalog_floor_provider_authority_id
            != session.scope.provider_authority_id
        || historical_floor.catalog_floor_resource_namespace_digest
            != session.scope.resource_namespace_digest
        || historical_floor.minimum_catalog_generation == 0
        || historical_floor.minimum_catalog_digest == [0; 32]
        || resource.catalog_generation() < historical_floor.minimum_catalog_generation
        || (resource.catalog_generation() == historical_floor.minimum_catalog_generation
            && resource.catalog_digest().as_bytes() != &historical_floor.minimum_catalog_digest)
        || !generation_dominates_snapshot(
            floor_snapshot.trust_generation,
            floor_snapshot.trust_digest,
            session.trust_generation,
            session.trust_digest,
        )
        || !generation_dominates_snapshot(
            floor_snapshot.revocation_generation,
            floor_snapshot.revocation_digest,
            session.revocation_generation,
            session.revocation_digest,
        )
        || signed_status.subject().descriptor_commitment() != descriptor
    {
        return Err(state_error(
            "Complete provider Acquire graph differs from durable evidence",
        ));
    }
    Ok(())
}

fn validate_complete_release(
    row: &SourceAcquisitionRowV2,
    attempt: &SourceProviderQueryAttemptV2,
    table: &SourceAcquisitionTableV2,
) -> Result<()> {
    let session = exact_session(table, attempt.session_id, attempt.session_record_digest)?;
    let ProviderAttemptStateV2::DispositionConsumed { signed_result, .. } = &attempt.state else {
        return Err(state_error("Release evidence attempt is not consumed"));
    };
    let signed_receipt = SignedSourceReleaseReceiptV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("retained provider Release receipt is invalid"))?;
    let receipt = signed_receipt.subject();
    let signed_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
            .map_err(|_| state_error("retained provider Release request is invalid"))?;
    let request = decode_release_request(signed_request.subject())
        .map_err(|_| state_error("retained provider Release body is invalid"))?;
    verify_release_receipt(&signed_receipt, &session.signers[3].public_key)
        .map_err(|_| state_error("retained provider Release receipt signature is invalid"))?;
    let evidence = row
        .evidence
        .as_ref()
        .ok_or_else(|| state_error("provider Release receipt lacks acquisition evidence"))?;
    let release_generation = receipt.release_generation();
    if let Some(ReleaseProofV2::ProviderReceipt {
        attempt: reference,
        release_generation: retained_generation,
    }) = row.release_proof.as_ref()
    {
        if reference.id != attempt.attempt_id || *retained_generation != release_generation {
            return Err(state_error(
                "Release receipt proof does not reference terminal attempt",
            ));
        }
    } else if row.release_proof.is_some() {
        return Err(state_error(
            "Release receipt attempt conflicts with Inventory terminal proof",
        ));
    }
    if !signer_matches(&session.signers[3], signed_receipt.signer())
        || receipt.request_id() != attempt.request_id
        || receipt.request_digest() != digest_release_request(&request)
        || receipt.lease_id() != evidence.lease_id
        || receipt.lease_digest().as_bytes() != &evidence.signed_lease_digest
        || receipt.provider().authority_id() != session.scope.provider_authority_id
        || receipt.provider().authority_generation() != session.provider_authority_generation
        || receipt.provider().authority_digest().as_bytes() != &session.provider_authority_digest
        || receipt.provider_process_instance() != session.provider_process_instance
        || release_generation == 0
        || receipt.released_seconds() < session.authenticated_at_seconds
        || receipt.released_seconds() > request.deadline_seconds()
        || session.authenticated_at_seconds >= request.deadline_seconds()
    {
        return Err(state_error(
            "Complete provider Release graph is inconsistent",
        ));
    }
    Ok(())
}

fn expected_binding_proof_class(bytes: &[u8]) -> Result<SourceAcquisitionProofClassV2> {
    let binding = SourceRealizationBindingV1::from_canonical_bytes(bytes)
        .map_err(|_| state_error("retained source binding is invalid"))?;
    match binding.consistency() {
        aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION => Ok(SourceAcquisitionProofClassV2::ImmutableTree),
        aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE => Ok(SourceAcquisitionProofClassV2::LocalLive),
        aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA => Ok(SourceAcquisitionProofClassV2::BestEffortReplica),
        _ => Err(state_error("retained source binding uses an unsupported consistency")),
    }
}

fn validate_lineages(table: &SourceAcquisitionTableV2) -> Result<()> {
    let mut successors = BTreeMap::new();
    for attempt in table.provider_attempts.values() {
        if let Some(predecessor) = attempt.previous_attempt_id {
            if successors.insert(predecessor, attempt.attempt_id).is_some() {
                return Err(state_error("provider query attempt lineage forks"));
            }
        }
    }
    if table
        .provider_attempts
        .values()
        .any(|attempt| is_complete(attempt) && successors.contains_key(&attempt.attempt_id))
    {
        return Err(state_error(
            "Complete provider disposition has a later lineage attempt",
        ));
    }

    let mut authoritative_roots = BTreeSet::new();
    for row in table.acquisitions.values() {
        validate_lineage(
            table,
            &successors,
            &row.acquire_lineage,
            ProviderQueryOwnerV2::Acquire {
                acquisition_id: row.acquisition_id,
            },
            ProviderMethodV2::Acquire,
            row.acquire_intent_digest,
        )?;
        validate_lineage_terminal_join(
            table,
            row.acquire_lineage.root.id,
            row.acquire_lineage.tail.id,
            row.acquire_terminal_attempt,
        )?;
        authoritative_roots.insert(row.acquire_lineage.root.id);
        if let Some(lineage) = &row.release_lineage {
            let digest = row
                .release_intent_digest
                .ok_or_else(|| state_error("Release lineage lacks intent digest"))?;
            validate_lineage(
                table,
                &successors,
                lineage,
                ProviderQueryOwnerV2::Release {
                    acquisition_id: row.acquisition_id,
                },
                ProviderMethodV2::Release,
                digest,
            )?;
            validate_lineage_terminal_join(
                table,
                lineage.root.id,
                lineage.tail.id,
                row.release_terminal_attempt,
            )?;
            authoritative_roots.insert(lineage.root.id);
        }
        if let Some(ReleaseProofV2::ProviderInventory { attempt, .. }) = &row.release_proof {
            let inventory = exact_attempt(table, *attempt)?;
            authoritative_roots.insert(inventory.lineage_root_attempt_id);
        }
    }
    for head in table.provider_heads.values() {
        for reference in [
            head.last_inventory_attempt,
            head.inventory_floor.as_ref().map(|floor| floor.attempt),
            head.recovery_barrier
                .as_ref()
                .and_then(|barrier| barrier.recovery_inventory_tail),
        ]
        .into_iter()
        .flatten()
        {
            let tail = exact_attempt(table, reference)?;
            validate_attempt_chain(
                table,
                tail,
                ProviderQueryOwnerV2::Inventory,
                ProviderMethodV2::Inventory,
                tail.immutable_intent_digest,
            )?;
            authoritative_roots.insert(tail.lineage_root_attempt_id);
        }
        for reference in [
            head.last_inventory_attempt,
            head.recovery_barrier
                .as_ref()
                .and_then(|barrier| barrier.recovery_inventory_tail),
        ]
        .into_iter()
        .flatten()
        {
            if successors.contains_key(&reference.id) {
                return Err(state_error(
                    "provider head Inventory tail has an unreferenced successor",
                ));
            }
        }
        if let Some(barrier) = &head.recovery_barrier {
            let root = exact_attempt(table, barrier.root_attempt)?;
            validate_attempt_chain(
                table,
                root,
                root.owner,
                root.method,
                root.immutable_intent_digest,
            )?;
            authoritative_roots.insert(barrier.root_attempt.id);
        }
        if let Some(reference) = head.pending_attempt {
            let pending = exact_attempt(table, reference)?;
            if pending.owner == ProviderQueryOwnerV2::Inventory {
                validate_attempt_chain(
                    table,
                    pending,
                    pending.owner,
                    pending.method,
                    pending.immutable_intent_digest,
                )?;
                authoritative_roots.insert(pending.lineage_root_attempt_id);
            }
        }
    }
    for attempt in table.provider_attempts.values() {
        if let ProviderAttemptStateV2::AbandonedIndeterminate {
            resolution: Some(resolution),
            ..
        } = &attempt.state
        {
            let inventory = exact_attempt(table, recovery_inventory_reference(resolution))?;
            authoritative_roots.insert(inventory.lineage_root_attempt_id);
        }
    }

    for attempt in table.provider_attempts.values() {
        if !authoritative_roots.contains(&attempt.lineage_root_attempt_id) {
            return Err(state_error(
                "provider attempt is unreachable from every durable owner",
            ));
        }
        let root = table
            .provider_attempts
            .get(&attempt.lineage_root_attempt_id)
            .ok_or_else(|| state_error("provider attempt lineage root is missing"))?;
        if root.previous_attempt_id.is_some()
            || root.attempt_number != 1
            || root.lineage_root_attempt_id != root.attempt_id
        {
            return Err(state_error("provider attempt lineage root is invalid"));
        }
        validate_attempt_chain(
            table,
            attempt,
            root.owner,
            root.method,
            root.immutable_intent_digest,
        )?;
    }
    Ok(())
}

fn validate_lineage_terminal_join(
    table: &SourceAcquisitionTableV2,
    root_id: [u8; 32],
    tail_id: [u8; 32],
    retained_terminal: Option<RecordRefV2>,
) -> Result<()> {
    let complete = table
        .provider_attempts
        .values()
        .filter(|attempt| attempt.lineage_root_attempt_id == root_id && is_complete(attempt))
        .collect::<Vec<_>>();
    match (complete.as_slice(), retained_terminal) {
        ([], None) => Ok(()),
        ([attempt], Some(reference))
            if attempt.attempt_id == tail_id
                && reference.id == attempt.attempt_id
                && reference.revision == attempt.revision
                && reference.record_digest == attempt.record_digest =>
        {
            Ok(())
        }
        _ => Err(state_error(
            "provider query lineage Complete outcome is not its retained terminal",
        )),
    }
}

fn validate_lineage(
    table: &SourceAcquisitionTableV2,
    successors: &BTreeMap<[u8; 32], [u8; 32]>,
    lineage: &QueryLineageV2,
    owner: ProviderQueryOwnerV2,
    method: ProviderMethodV2,
    intent_digest: [u8; 32],
) -> Result<()> {
    let root = exact_attempt(table, lineage.root)?;
    let tail = exact_attempt(table, lineage.tail)?;
    if root.previous_attempt_id.is_some()
        || root.attempt_number != 1
        || root.lineage_root_attempt_id != root.attempt_id
        || tail.lineage_root_attempt_id != root.attempt_id
        || successors.contains_key(&tail.attempt_id)
        || lineage.next_attempt_number
            != tail
                .attempt_number
                .checked_add(1)
                .ok_or_else(|| state_error("provider attempt number overflow"))?
    {
        return Err(state_error("provider query lineage endpoints are invalid"));
    }
    validate_attempt_chain(table, tail, owner, method, intent_digest)
}

fn validate_attempt_chain(
    table: &SourceAcquisitionTableV2,
    tail: &SourceProviderQueryAttemptV2,
    owner: ProviderQueryOwnerV2,
    method: ProviderMethodV2,
    intent_digest: [u8; 32],
) -> Result<()> {
    let mut current = tail;
    let mut expected_number = tail.attempt_number;
    let mut count = 0usize;
    loop {
        count += 1;
        if count > MAXIMUM_LINEAGE_ATTEMPTS
            || current.owner != owner
            || current.method != method
            || current.immutable_intent_digest != intent_digest
            || current.intent != tail.intent
            || current.scope != tail.scope
            || current.attempt_number != expected_number
            || current.lineage_root_attempt_id != tail.lineage_root_attempt_id
        {
            return Err(state_error(
                "provider query lineage is inconsistent or over limit",
            ));
        }
        match current.previous_attempt_id {
            Some(previous) => {
                expected_number = expected_number
                    .checked_sub(1)
                    .ok_or_else(|| state_error("provider attempt number underflow"))?;
                let next = table
                    .provider_attempts
                    .get(&previous)
                    .ok_or_else(|| state_error("provider attempt predecessor is missing"))?;
                if next.owner_predecessor_revision >= current.owner_predecessor_revision
                    || !attempt_happens_after(table, next, current)?
                {
                    return Err(state_error(
                        "provider attempt lineage time or owner witness is not monotonic",
                    ));
                }
                current = next;
            }
            None => {
                if expected_number != 1 || current.attempt_id != tail.lineage_root_attempt_id {
                    return Err(state_error("provider query lineage root is invalid"));
                }
                return Ok(());
            }
        }
    }
}

fn recovery_inventory_reference(resolution: &RecoveryResolutionV2) -> RecordRefV2 {
    match resolution {
        RecoveryResolutionV2::RetryAcquireSameIntent { proof }
        | RecoveryResolutionV2::RetryReleaseSameIntent { proof }
        | RecoveryResolutionV2::ProviderTerminalObserved { proof }
        | RecoveryResolutionV2::InventoryReconciled { proof }
        | RecoveryResolutionV2::Conflict { proof, .. } => proof.inventory_attempt,
    }
}

fn validate_sequence_and_reservation_graph(table: &SourceAcquisitionTableV2) -> Result<()> {
    let mut reserved = BTreeSet::new();
    let mut sequences = BTreeMap::<[u8; 32], Vec<u64>>::new();
    let mut abandoned_sequences = BTreeMap::<[u8; 32], Vec<u64>>::new();
    for attempt in table.provider_attempts.values() {
        if attempt.request_sequence == u64::MAX {
            return Err(state_error("provider attempt sequence is exhausted"));
        }
        sequences
            .entry(attempt.session_id)
            .or_default()
            .push(attempt.request_sequence);
        if matches!(attempt.state, ProviderAttemptStateV2::Reserved) {
            reserved.insert(attempt.attempt_id);
        }
        if matches!(
            attempt.state,
            ProviderAttemptStateV2::AbandonedIndeterminate { .. }
        ) {
            abandoned_sequences
                .entry(attempt.session_id)
                .or_default()
                .push(attempt.request_sequence);
        }
    }
    for (session_id, values) in &mut sequences {
        values.sort_unstable();
        for (index, sequence) in values.iter().enumerate() {
            let expected = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| state_error("provider session sequence count overflow"))?;
            if *sequence != expected {
                return Err(state_error(
                    "provider session sequences are not a contiguous prefix",
                ));
            }
        }
        if !table.provider_sessions.contains_key(session_id) {
            return Err(state_error("provider sequence session is missing"));
        }
        let last_sequence = u64::try_from(values.len())
            .map_err(|_| state_error("provider session sequence count exceeds u64"))?;
        if abandoned_sequences
            .get(session_id)
            .is_some_and(|abandoned| abandoned.len() != 1 || abandoned[0] != last_sequence)
        {
            return Err(state_error(
                "provider abandonment is not the final request in its session",
            ));
        }
    }
    for head in table.provider_heads.values() {
        if head.next_request_sequence == u64::MAX || head.next_response_sequence == u64::MAX {
            return Err(state_error("provider head sequence is exhausted"));
        }
        let attempt_count = sequences.get(&head.current_session_id).map_or(0, Vec::len);
        let next_after_prefix = u64::try_from(attempt_count)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| state_error("provider session sequence count overflow"))?;
        if let Some(reference) = head.pending_attempt {
            if !reserved.remove(&reference.id) {
                return Err(state_error("provider head pending edge is duplicated"));
            }
            if head.next_request_sequence != next_after_prefix
                || head.next_response_sequence.checked_add(1) != Some(next_after_prefix)
                || reference.id
                    != table
                        .provider_attempts
                        .values()
                        .find(|attempt| {
                            attempt.session_id == head.current_session_id
                                && attempt.request_sequence == head.next_response_sequence
                        })
                        .map_or([0; 32], |attempt| attempt.attempt_id)
            {
                return Err(state_error(
                    "pending provider attempt does not advance its exact session prefix",
                ));
            }
        } else if head.next_request_sequence != next_after_prefix
            || head.next_response_sequence != next_after_prefix
        {
            return Err(state_error(
                "idle provider head does not follow its exact session prefix",
            ));
        }
    }
    if !reserved.is_empty() {
        return Err(state_error(
            "reserved provider attempt has no exact head owner",
        ));
    }
    Ok(())
}

fn validate_recovery_graph(table: &SourceAcquisitionTableV2) -> Result<()> {
    let mut unresolved_roots = BTreeSet::new();
    let mut covered_abandoned_attempts = BTreeSet::new();
    for head in table.provider_heads.values() {
        let Some(barrier) = &head.recovery_barrier else {
            continue;
        };
        let root = exact_attempt(table, barrier.root_attempt)?;
        let ProviderAttemptStateV2::AbandonedIndeterminate {
            recovery_root_attempt_id,
            resolution: None,
            ..
        } = &root.state
        else {
            return Err(state_error(
                "SourceProvider recovery root is not unresolved and abandoned",
            ));
        };
        let replacement_attempts = recovery_session_chain(
            table,
            root,
            head.current_session_id,
            barrier.replacement_count,
        )?;
        if replacement_attempts
            .into_iter()
            .any(|id| !covered_abandoned_attempts.insert(id))
            || barrier.required_session_id != head.current_session_id
            || barrier.replacement_count == 0
            || barrier.baseline_inventory_ordinal != head.inventory_observation_ordinal
            || root.scope != head.scope
            || *recovery_root_attempt_id != root.attempt_id
            || !unresolved_roots.insert(root.attempt_id)
            || session_successor_distance(table, root.session_id, head.current_session_id)?
                != barrier.replacement_count
        {
            return Err(state_error(
                "SourceProvider recovery barrier is inconsistent",
            ));
        }
        if let Some(tail) = barrier.recovery_inventory_tail {
            let inventory = exact_attempt(table, tail)?;
            let ProviderIntentV2::Inventory { value: intent } = &inventory.intent else {
                return Err(state_error(
                    "SourceProvider recovery tail lacks Inventory intent",
                ));
            };
            if inventory.method != ProviderMethodV2::Inventory
                || inventory.scope != head.scope
                || intent.scope != head.scope
                || intent.recovery_root_attempt_id != Some(root.attempt_id)
                || intent.known_observation_ordinal != barrier.baseline_inventory_ordinal
                || !inventory_intent_matches_floor(intent, head.inventory_floor.as_ref())
                || (matches!(inventory.state, ProviderAttemptStateV2::Reserved)
                    && inventory.session_id != head.current_session_id)
            {
                return Err(state_error(
                    "SourceProvider recovery Inventory tail is inconsistent",
                ));
            }
        }
    }
    for row in table.acquisitions.values() {
        match &row.recovery {
            AcquisitionRecoveryV2::InventoryRequired { root_attempt } => {
                let root = exact_attempt(table, *root_attempt)?;
                let head = table
                    .provider_heads
                    .get(&(
                        row.scope.holder_authority_id,
                        row.scope.provider_authority_id,
                    ))
                    .ok_or_else(|| state_error("recovery row provider head is missing"))?;
                if head
                    .recovery_barrier
                    .as_ref()
                    .map(|barrier| barrier.root_attempt)
                    != Some(*root_attempt)
                    || root.scope != row.scope
                    || !matches!(
                        root.owner,
                        ProviderQueryOwnerV2::Acquire { acquisition_id }
                            | ProviderQueryOwnerV2::Release { acquisition_id }
                            if acquisition_id == row.acquisition_id
                    )
                {
                    return Err(state_error(
                        "acquisition recovery edge does not match provider head",
                    ));
                }
            }
            AcquisitionRecoveryV2::RetryPermitted { root_attempt } => {
                let root = exact_attempt(table, *root_attempt)?;
                let head = table
                    .provider_heads
                    .get(&(
                        row.scope.holder_authority_id,
                        row.scope.provider_authority_id,
                    ))
                    .ok_or_else(|| state_error("retry-permitted row provider head is missing"))?;
                let resolution = match &root.state {
                    ProviderAttemptStateV2::AbandonedIndeterminate {
                        resolution: Some(resolution),
                        ..
                    } => resolution,
                    _ => {
                        return Err(state_error(
                            "retry-permitted row lacks a resolved abandoned root",
                        ));
                    }
                };
                let proof = recovery_resolution_proof(resolution);
                let method_matches = matches!(
                    (root.method, resolution),
                    (
                        ProviderMethodV2::Acquire,
                        RecoveryResolutionV2::RetryAcquireSameIntent { .. }
                    ) | (
                        ProviderMethodV2::Release,
                        RecoveryResolutionV2::RetryReleaseSameIntent { .. }
                    )
                );
                let lineage_tail = match root.method {
                    ProviderMethodV2::Acquire => Some(row.acquire_lineage.tail),
                    ProviderMethodV2::Release => {
                        row.release_lineage.as_ref().map(|lineage| lineage.tail)
                    }
                    ProviderMethodV2::Inventory => None,
                };
                let phase_matches = match root.method {
                    ProviderMethodV2::Acquire => {
                        row.phase == SourceAcquisitionPhaseV2::PendingQuery
                            && row.release_proof.is_none()
                    }
                    ProviderMethodV2::Release => {
                        row.phase == SourceAcquisitionPhaseV2::Releasing
                            && row.release_proof.is_none()
                            && row.negative_custody_digest.is_none()
                    }
                    ProviderMethodV2::Inventory => false,
                };
                if !method_matches
                    || root.scope != row.scope
                    || !matches!(
                        root.owner,
                        ProviderQueryOwnerV2::Acquire { acquisition_id }
                            | ProviderQueryOwnerV2::Release { acquisition_id }
                            if acquisition_id == row.acquisition_id
                    )
                    || lineage_tail != Some(*root_attempt)
                    || !phase_matches
                    || head.pending_attempt.is_some()
                    || head.recovery_barrier.is_some()
                    || head.inventory_floor.as_ref().map(|floor| floor.attempt)
                        != Some(proof.inventory_attempt)
                    || head.last_reconciliation.as_ref() != Some(&proof.reconciliation)
                {
                    return Err(state_error(
                        "retry-permitted acquisition does not retain exact recovery proof",
                    ));
                }
            }
            AcquisitionRecoveryV2::Conflict {
                inventory_attempt,
                reconciliation_digest,
                conflict_digest,
            } => {
                let inventory = exact_attempt(table, *inventory_attempt)?;
                let head = table
                    .provider_heads
                    .get(&(
                        row.scope.holder_authority_id,
                        row.scope.provider_authority_id,
                    ))
                    .ok_or_else(|| state_error("conflict row provider head is missing"))?;
                let reconciliation = head
                    .last_reconciliation
                    .as_ref()
                    .ok_or_else(|| state_error("conflict row lacks reconciliation"))?;
                let ProviderAttemptStateV2::DispositionConsumed { signed_result, .. } =
                    &inventory.state
                else {
                    return Err(state_error("conflict Inventory is not consumed"));
                };
                let signed_inventory =
                    SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
                        .map_err(|_| state_error("conflict Inventory is invalid"))?;
                let entry = signed_inventory
                    .subject()
                    .entries()
                    .iter()
                    .find(|entry| entry.acquisition_id().as_bytes() == &row.acquisition_id);
                if inventory.scope != row.scope
                    || inventory.method != ProviderMethodV2::Inventory
                    || !is_complete(inventory)
                    || head.inventory_floor.as_ref().map(|floor| floor.attempt)
                        != Some(*inventory_attempt)
                    || *reconciliation_digest == [0; 32]
                    || *conflict_digest == [0; 32]
                    || reconciliation.conflict_count == 0
                    || reconciliation.conflict_digest != *conflict_digest
                    || reconciliation_commitment(reconciliation) != *reconciliation_digest
                    || reconciliation_conflict(row, entry).is_none()
                    || !table.provider_attempts.values().any(|attempt| {
                        matches!(
                            (&attempt.owner, &attempt.state),
                            (
                                ProviderQueryOwnerV2::Acquire { acquisition_id }
                                    | ProviderQueryOwnerV2::Release { acquisition_id },
                                ProviderAttemptStateV2::AbandonedIndeterminate {
                                    resolution: Some(RecoveryResolutionV2::Conflict {
                                        proof,
                                        conflict_digest: resolution_conflict,
                                    }),
                                    ..
                                }
                            ) if acquisition_id == &row.acquisition_id
                                && proof.inventory_attempt == *inventory_attempt
                                && proof.reconciliation_digest == *reconciliation_digest
                                && resolution_conflict == conflict_digest
                        )
                    })
                {
                    return Err(state_error(
                        "acquisition recovery conflict lacks exact Inventory evidence",
                    ));
                }
            }
            AcquisitionRecoveryV2::Ready => {}
        }
    }
    for attempt in table.provider_attempts.values() {
        let ProviderAttemptStateV2::AbandonedIndeterminate {
            recovery_root_attempt_id,
            resolution,
            ..
        } = &attempt.state
        else {
            continue;
        };
        let root = table
            .provider_attempts
            .get(recovery_root_attempt_id)
            .ok_or_else(|| state_error("abandoned attempt recovery root is missing"))?;
        if root.scope != attempt.scope
            || !matches!(
                root.state,
                ProviderAttemptStateV2::AbandonedIndeterminate { .. }
            )
            || (attempt.attempt_id != root.attempt_id
                && attempt.method != ProviderMethodV2::Inventory)
        {
            return Err(state_error(
                "abandoned provider attempt does not join its recovery root",
            ));
        }
        let unresolved = matches!(
            root.state,
            ProviderAttemptStateV2::AbandonedIndeterminate {
                resolution: None,
                ..
            }
        );
        let barrier_exists = table.provider_heads.values().any(|head| {
            head.recovery_barrier
                .as_ref()
                .is_some_and(|barrier| barrier.root_attempt.id == *recovery_root_attempt_id)
        });
        if unresolved != barrier_exists {
            return Err(state_error(
                "abandoned provider attempt and recovery barrier disagree",
            ));
        }
        if attempt.attempt_id == root.attempt_id {
            if let Some(resolution) = resolution {
                let inventory = exact_attempt(table, recovery_inventory_reference(resolution))?;
                let replacement_count =
                    session_successor_distance(table, root.session_id, inventory.session_id)?;
                let replacement_attempts =
                    recovery_session_chain(table, root, inventory.session_id, replacement_count)?;
                if replacement_attempts
                    .into_iter()
                    .any(|id| !covered_abandoned_attempts.insert(id))
                {
                    return Err(state_error(
                        "abandoned provider attempt belongs to multiple recovery chains",
                    ));
                }
            }
            match root.owner {
                ProviderQueryOwnerV2::Acquire { acquisition_id }
                | ProviderQueryOwnerV2::Release { acquisition_id } => {
                    let row = table
                        .acquisitions
                        .get(&acquisition_id)
                        .ok_or_else(|| state_error("recovery root owner row is missing"))?;
                    if unresolved
                        != matches!(
                            &row.recovery,
                            AcquisitionRecoveryV2::InventoryRequired { root_attempt }
                                if root_attempt.id == root.attempt_id
                        )
                    {
                        return Err(state_error(
                            "recovery root and acquisition recovery state disagree",
                        ));
                    }
                }
                ProviderQueryOwnerV2::Inventory => {}
            }
        }
    }
    let all_abandoned = table
        .provider_attempts
        .values()
        .filter(|attempt| {
            matches!(
                attempt.state,
                ProviderAttemptStateV2::AbandonedIndeterminate { .. }
            )
        })
        .map(|attempt| attempt.attempt_id)
        .collect::<BTreeSet<_>>();
    if covered_abandoned_attempts != all_abandoned {
        return Err(state_error(
            "abandoned provider attempt is outside its exact replacement chain",
        ));
    }
    Ok(())
}

fn validate_resolution_causality(table: &SourceAcquisitionTableV2) -> Result<()> {
    let successors = table
        .provider_attempts
        .values()
        .filter_map(|attempt| {
            attempt
                .previous_attempt_id
                .map(|previous| (previous, attempt))
        })
        .collect::<BTreeMap<_, _>>();

    for root in table.provider_attempts.values() {
        let ProviderAttemptStateV2::AbandonedIndeterminate {
            resolution: Some(resolution),
            ..
        } = &root.state
        else {
            continue;
        };
        let proof = recovery_resolution_proof(resolution);
        let inventory = exact_attempt(table, proof.inventory_attempt)?;
        let successor = successors.get(&root.attempt_id).copied();

        match resolution {
            RecoveryResolutionV2::RetryAcquireSameIntent { .. }
            | RecoveryResolutionV2::RetryReleaseSameIntent { .. } => {
                let acquisition_id = match root.owner {
                    ProviderQueryOwnerV2::Acquire { acquisition_id }
                    | ProviderQueryOwnerV2::Release { acquisition_id } => acquisition_id,
                    ProviderQueryOwnerV2::Inventory => {
                        return Err(state_error(
                            "provider retry resolution has no acquisition owner",
                        ));
                    }
                };
                let row = table
                    .acquisitions
                    .get(&acquisition_id)
                    .ok_or_else(|| state_error("provider retry owner row is missing"))?;
                match successor {
                    None => {
                        if !matches!(
                            &row.recovery,
                            AcquisitionRecoveryV2::RetryPermitted { root_attempt }
                                if root_attempt.id == root.attempt_id
                                    && root_attempt.revision == root.revision
                                    && root_attempt.record_digest == root.record_digest
                        ) {
                            return Err(state_error(
                                "resolved provider retry lacks its durable permit",
                            ));
                        }
                    }
                    Some(retry) => {
                        if retry.method != root.method
                            || retry.owner != root.owner
                            || retry.immutable_intent_digest != root.immutable_intent_digest
                            || retry.attempt_number
                                != root.attempt_number.checked_add(1).ok_or_else(|| {
                                    state_error("provider retry attempt number overflow")
                                })?
                            || !attempt_happens_after(table, inventory, retry)?
                            || matches!(
                                &row.recovery,
                                AcquisitionRecoveryV2::RetryPermitted { .. }
                                    | AcquisitionRecoveryV2::Conflict { .. }
                            )
                            || (row.release_proof.is_some()
                                && root.method == ProviderMethodV2::Release)
                        {
                            return Err(state_error(
                                "provider retry does not follow its recovery Inventory",
                            ));
                        }
                    }
                }
            }
            RecoveryResolutionV2::ProviderTerminalObserved { .. } => {
                if successor.is_some() || root.method != ProviderMethodV2::Release {
                    return Err(state_error(
                        "terminal provider recovery has a retry successor",
                    ));
                }
                let ProviderQueryOwnerV2::Release { acquisition_id } = root.owner else {
                    return Err(state_error(
                        "terminal provider recovery has no Release owner",
                    ));
                };
                let row = table
                    .acquisitions
                    .get(&acquisition_id)
                    .ok_or_else(|| state_error("terminal provider recovery row is missing"))?;
                let proof_matches = matches!(
                    row.release_proof.as_ref(),
                    Some(ReleaseProofV2::ProviderInventory {
                        attempt,
                        inventory_digest,
                        inventory_observation_ordinal,
                        projection_epoch,
                    }) if *attempt == proof.inventory_attempt
                        && *inventory_digest == proof.inventory_digest
                        && *inventory_observation_ordinal == proof.inventory_observation_ordinal
                        && *projection_epoch == proof.projection_epoch
                );
                let terminal_pending_manager = row.phase == SourceAcquisitionPhaseV2::Releasing
                    && row.release_proof.is_none()
                    && row.negative_custody_digest.is_none()
                    && row
                        .release_lineage
                        .as_ref()
                        .is_some_and(|lineage| lineage.tail.id == root.attempt_id);
                if (!proof_matches && !terminal_pending_manager)
                    || !matches!(&row.recovery, AcquisitionRecoveryV2::Ready)
                {
                    return Err(state_error(
                        "terminal provider recovery is not retained by its row",
                    ));
                }
            }
            RecoveryResolutionV2::Conflict {
                conflict_digest, ..
            } => {
                if successor.is_some() {
                    return Err(state_error(
                        "conflicting provider recovery has a retry successor",
                    ));
                }
                let acquisition_id = match root.owner {
                    ProviderQueryOwnerV2::Acquire { acquisition_id }
                    | ProviderQueryOwnerV2::Release { acquisition_id } => acquisition_id,
                    ProviderQueryOwnerV2::Inventory => continue,
                };
                let row = table
                    .acquisitions
                    .get(&acquisition_id)
                    .ok_or_else(|| state_error("provider conflict owner row is missing"))?;
                if !matches!(
                    &row.recovery,
                    AcquisitionRecoveryV2::Conflict {
                        inventory_attempt,
                        reconciliation_digest,
                        conflict_digest: row_conflict,
                    } if *inventory_attempt == proof.inventory_attempt
                        && *reconciliation_digest == proof.reconciliation_digest
                        && *row_conflict == *conflict_digest
                ) {
                    return Err(state_error(
                        "provider conflict resolution is not retained by its row",
                    ));
                }
            }
            RecoveryResolutionV2::InventoryReconciled { .. } => {
                if successor.is_some() || root.method != ProviderMethodV2::Inventory {
                    return Err(state_error(
                        "reconciled Inventory recovery has a retry successor",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn recovery_resolution_proof(resolution: &RecoveryResolutionV2) -> &RecoveryInventoryProofV2 {
    match resolution {
        RecoveryResolutionV2::RetryAcquireSameIntent { proof }
        | RecoveryResolutionV2::RetryReleaseSameIntent { proof }
        | RecoveryResolutionV2::ProviderTerminalObserved { proof }
        | RecoveryResolutionV2::InventoryReconciled { proof }
        | RecoveryResolutionV2::Conflict { proof, .. } => proof,
    }
}

fn recovery_session_chain(
    table: &SourceAcquisitionTableV2,
    root: &SourceProviderQueryAttemptV2,
    terminal_session_id: [u8; 32],
    expected_replacement_count: u64,
) -> Result<Vec<[u8; 32]>> {
    if expected_replacement_count == 0 {
        return Err(state_error(
            "provider recovery has no successor-session transition",
        ));
    }
    let mut current = terminal_session_id;
    let mut replacements = Vec::new();
    while current != root.session_id {
        let session = table
            .provider_sessions
            .get(&current)
            .ok_or_else(|| state_error("provider recovery successor session is missing"))?;
        let predecessor = session
            .predecessor_session_id
            .ok_or_else(|| state_error("provider recovery successor lacks predecessor"))?;
        let mut matches = table.provider_attempts.values().filter(|attempt| {
            if attempt.session_id != predecessor {
                return false;
            }
            matches!(
                &attempt.state,
                ProviderAttemptStateV2::AbandonedIndeterminate {
                    successor_session_id,
                    recovery_root_attempt_id,
                    ..
                } if *successor_session_id == current
                    && *recovery_root_attempt_id == root.attempt_id
            )
        });
        let replacement = matches
            .next()
            .ok_or_else(|| state_error("provider recovery session edge lacks death evidence"))?;
        if matches.next().is_some()
            || (predecessor == root.session_id && replacement.attempt_id != root.attempt_id)
            || (predecessor != root.session_id
                && (!matches!(replacement.owner, ProviderQueryOwnerV2::Inventory)
                    || !matches!(
                        &replacement.intent,
                        ProviderIntentV2::Inventory { value }
                            if value.recovery_root_attempt_id == Some(root.attempt_id)
                    )))
        {
            return Err(state_error(
                "provider recovery session edge has an invalid attempt witness",
            ));
        }
        replacements.push(replacement.attempt_id);
        current = predecessor;
    }
    let count = u64::try_from(replacements.len())
        .map_err(|_| state_error("provider recovery replacement count exceeds u64"))?;
    if count != expected_replacement_count {
        return Err(state_error(
            "provider recovery replacement count does not reproduce",
        ));
    }
    Ok(replacements)
}

fn inventory_intent_matches_floor(
    intent: &InventoryIntentV2,
    floor: Option<&InventoryFloorV2>,
) -> bool {
    match floor {
        Some(floor) => {
            intent.known_inventory_generation == Some(floor.inventory_generation)
                && intent.known_inventory_digest == Some(floor.inventory_digest)
                && intent.known_catalog_generation == Some(floor.catalog_generation)
                && intent.known_catalog_digest == Some(floor.catalog_digest)
        }
        None => {
            intent.known_inventory_generation.is_none()
                && intent.known_inventory_digest.is_none()
                && intent.known_catalog_generation.is_none()
                && intent.known_catalog_digest.is_none()
        }
    }
}

fn session_successor_distance(
    table: &SourceAcquisitionTableV2,
    ancestor: [u8; 32],
    descendant: [u8; 32],
) -> Result<u64> {
    let mut current = descendant;
    let mut distance = 0_u64;
    loop {
        if current == ancestor {
            return Ok(distance);
        }
        let session = table
            .provider_sessions
            .get(&current)
            .ok_or_else(|| state_error("provider recovery session chain is missing"))?;
        current = session
            .predecessor_session_id
            .ok_or_else(|| state_error("provider recovery session is not a successor"))?;
        distance = distance
            .checked_add(1)
            .ok_or_else(|| state_error("provider recovery replacement count overflow"))?;
    }
}

fn attempt_happens_after(
    table: &SourceAcquisitionTableV2,
    earlier: &SourceProviderQueryAttemptV2,
    later: &SourceProviderQueryAttemptV2,
) -> Result<bool> {
    if earlier.session_id == later.session_id {
        return Ok(earlier.request_sequence < later.request_sequence);
    }
    Ok(session_successor_distance(table, earlier.session_id, later.session_id).is_ok())
}

fn inventory_observation_ordinal(
    table: &SourceAcquisitionTableV2,
    scope: ProviderScopeV2,
    target: &SourceProviderQueryAttemptV2,
) -> Result<u64> {
    if target.scope != scope || target.method != ProviderMethodV2::Inventory || !is_complete(target)
    {
        return Err(state_error(
            "Inventory observation ordinal target is not Complete",
        ));
    }
    let mut ordinal = 0_u64;
    for attempt in table.provider_attempts.values().filter(|attempt| {
        attempt.scope == scope
            && attempt.method == ProviderMethodV2::Inventory
            && is_complete(attempt)
    }) {
        if attempt.attempt_id == target.attempt_id || attempt_happens_after(table, attempt, target)?
        {
            ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| state_error("Inventory observation ordinal overflow"))?;
        } else if !attempt_happens_after(table, target, attempt)? {
            return Err(state_error(
                "Complete Inventory observations are not chronologically ordered",
            ));
        }
    }
    Ok(ordinal)
}

fn reconciliation_commitment(value: &ReconciliationV2) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.mount.source-provider-reconciliation.v2\0");
    digest.update(value.projection_epoch.to_be_bytes());
    digest.update(value.projection_digest);
    digest.update(value.residual_count.to_be_bytes());
    digest.update(value.residual_digest);
    digest.update(value.conflict_count.to_be_bytes());
    digest.update(value.conflict_digest);
    digest.finalize().into()
}

fn exact_session(
    table: &SourceAcquisitionTableV2,
    id: [u8; 32],
    digest: [u8; 32],
) -> Result<&SourceProviderSessionV2> {
    table
        .provider_sessions
        .get(&id)
        .filter(|session| session.record_digest == digest)
        .ok_or_else(|| state_error("provider session reference is dangling or stale"))
}

fn exact_attempt(
    table: &SourceAcquisitionTableV2,
    reference: RecordRefV2,
) -> Result<&SourceProviderQueryAttemptV2> {
    table
        .provider_attempts
        .get(&reference.id)
        .filter(|attempt| {
            attempt.revision == reference.revision
                && attempt.record_digest == reference.record_digest
        })
        .ok_or_else(|| state_error("provider attempt reference is dangling or stale"))
}

fn resolve_historical_attempt(
    table: &SourceAcquisitionTableV2,
    reference: RecordRefV2,
) -> Result<SourceProviderQueryAttemptV2> {
    let current = table
        .provider_attempts
        .get(&reference.id)
        .ok_or_else(|| state_error("historical provider attempt is missing"))?;
    if current.revision == reference.revision && current.record_digest == reference.record_digest {
        return Ok(current.clone());
    }
    if reference.revision != 2 || current.revision != 3 {
        return Err(state_error(
            "historical provider attempt reference has an invalid revision",
        ));
    }

    let mut historical = current.clone();
    let attempt_id = historical.attempt_id;
    let ProviderAttemptStateV2::AbandonedIndeterminate {
        recovery_root_attempt_id,
        resolution,
        ..
    } = &mut historical.state
    else {
        return Err(state_error(
            "historical provider attempt is not a resolved abandoned root",
        ));
    };
    if *recovery_root_attempt_id != attempt_id || resolution.take().is_none() {
        return Err(state_error(
            "historical provider attempt resolution is not reconstructible",
        ));
    }
    historical.revision = 2;
    historical.record_digest = record_digest(&StoredRecordV2::ProviderQueryAttempt {
        value: historical.clone(),
    })?;
    if historical.record_digest != reference.record_digest {
        return Err(state_error(
            "historical provider attempt digest does not reconstruct",
        ));
    }
    Ok(historical)
}

fn session_holder_authority(
    session: &SourceProviderSessionV2,
) -> Result<SourceProviderAuthorityV1> {
    SourceProviderAuthorityV1::new(
        session.scope.holder_authority_id,
        session.root_mount_authority_generation,
        ObjectDigest::from_bytes(session.root_mount_authority_digest),
    )
    .map_err(|_| state_error("retained Root Mount authority is invalid"))
}

fn session_provider_authority(
    session: &SourceProviderSessionV2,
) -> Result<SourceProviderAuthorityV1> {
    SourceProviderAuthorityV1::new(
        session.scope.provider_authority_id,
        session.provider_authority_generation,
        ObjectDigest::from_bytes(session.provider_authority_digest),
    )
    .map_err(|_| state_error("retained provider authority is invalid"))
}

fn historical_outcome_signer(snapshot: &SignerSnapshotV2) -> Result<SourceProviderSigningKeyV1> {
    if snapshot.role != SignerRoleV2::ProviderOutcome
        || snapshot.authority_state != AuthorityAdmissionStateV2::Trusted
        || snapshot.key_state != KeyAdmissionStateV2::Eligible
        || snapshot.public_key == [0; 32]
        || (snapshot.superseded_by_key_generation != 0
            && snapshot.superseded_by_key_generation <= snapshot.key_generation)
        || <[u8; 32]>::from(Sha256::digest(snapshot.public_key)) != snapshot.public_key_fingerprint
    {
        return Err(state_error(
            "historical lease signer lacks ProviderOutcome trust",
        ));
    }
    SourceProviderSigningKeyV1::new(
        snapshot.authority_id,
        snapshot.authority_generation,
        ObjectDigest::from_bytes(snapshot.authority_digest),
        snapshot.key_id,
        snapshot.key_generation,
        ObjectDigest::from_bytes(snapshot.public_key_fingerprint),
        SourceProviderKeyUsageV1::ProviderOutcome,
    )
    .map_err(|_| state_error("historical lease signer is invalid"))
}

fn historical_selection_floor(
    evidence: &SourceAcquisitionEvidenceV2,
) -> Result<SourceSelectionFloorV1> {
    let historical = &evidence.historical_lease_signer;
    let snapshot = &historical.selection_floor;
    let signer = historical_outcome_signer(&historical.signer)?;
    let resource = SourceResourceV1::new(
        ObjectDigest::from_bytes(snapshot.resource_namespace_digest),
        snapshot.resource_id,
        snapshot.resource_generation,
        ObjectDigest::from_bytes(snapshot.resource_digest),
        snapshot.catalog_generation,
        ObjectDigest::from_bytes(snapshot.catalog_digest),
        snapshot.selection_generation,
        ObjectDigest::from_bytes(snapshot.selection_digest),
    )
    .map_err(|_| state_error("historical selection-floor resource is invalid"))?;
    let floor = SourceSelectionFloorV1::new(
        ObjectDigest::from_bytes(snapshot.acquisition_id),
        snapshot.provider_authority_id,
        snapshot.route_id,
        resource,
        signer,
        snapshot.lease_id,
        ObjectDigest::from_bytes(snapshot.signed_lease_digest),
        snapshot.proof_class,
        ObjectDigest::from_bytes(snapshot.proof_digest),
        ObjectDigest::from_bytes(snapshot.resource_commitment),
        snapshot.trust_generation,
        ObjectDigest::from_bytes(snapshot.trust_digest),
        snapshot.revocation_generation,
        ObjectDigest::from_bytes(snapshot.revocation_digest),
    )
    .map_err(|_| state_error("historical selection floor is invalid"))?;
    if floor.digest().as_bytes() != &historical.selection_floor_digest {
        return Err(state_error("historical selection-floor digest differs"));
    }
    Ok(floor)
}

fn interval_contains(start: i64, end: i64, value: i64) -> bool {
    start >= 0 && start < end && start <= value && value < end
}

fn generation_dominates_snapshot(
    old_generation: u64,
    old_digest: [u8; 32],
    current_generation: u64,
    current_digest: [u8; 32],
) -> bool {
    current_generation > old_generation
        || (current_generation == old_generation && current_digest == old_digest)
}

fn valid_scope(scope: ProviderScopeV2) -> bool {
    scope.holder_authority_id != [0; 16]
        && scope.provider_authority_id != [0; 16]
        && scope.route_id != [0; 16]
        && scope.resource_namespace_digest != [0; 32]
}

fn method_owner_intent_match(attempt: &SourceProviderQueryAttemptV2) -> bool {
    matches!(
        (&attempt.intent, attempt.method, attempt.owner),
        (
            ProviderIntentV2::Acquire { .. },
            ProviderMethodV2::Acquire,
            ProviderQueryOwnerV2::Acquire { .. }
        ) | (
            ProviderIntentV2::Release { .. },
            ProviderMethodV2::Release,
            ProviderQueryOwnerV2::Release { .. }
        ) | (
            ProviderIntentV2::Inventory { .. },
            ProviderMethodV2::Inventory,
            ProviderQueryOwnerV2::Inventory
        )
    ) && attempt.method.tag() == attempt.owner.tag()
}

fn is_complete(attempt: &SourceProviderQueryAttemptV2) -> bool {
    matches!(
        attempt.state,
        ProviderAttemptStateV2::DispositionConsumed {
            status: ProviderStatusV2::Complete,
            ..
        }
    )
}
