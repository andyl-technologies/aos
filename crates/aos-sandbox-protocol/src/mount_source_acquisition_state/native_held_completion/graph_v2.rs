//! Independent current-graph validation followed by exact historical cut joins.
//!
//! The current legacy graph is never replaced with historical companions to
//! make its validator pass. Reconstructed companions feed only historical
//! archive checks and the original pure response-CAS projection.
//!
//! Checked data cannot construct either future protected proof: original hot
//! current companions require retained writer/socket/FD/clock custody; current
//! committed historical completion requires actual journal commit/readback,
//! today's eligible signer and the exact recovery association.

use std::collections::BTreeMap;

use aos_sandbox_source_provider_protocol::{
    SignedSourceProviderRequestV1, decode_acquire_request,
    native_held_completion::{
        NativeHeldControlKindV1 as Kind,
        assertion::{NativeHeldDispositionV1, RootNativeObservationV1},
    },
};

use super::{
    RootNativeHeldGraphV1, RootNativeHeldSidecarV1,
    codec::is_sidecar_key,
    codec_v2::{RootNativeHeldSidecarV2, is_sidecar_key_v2, native_root_sidecar_key_v2},
    cut::RootNativeReconstructedCutV1,
};
use crate::mount_source_acquisition_state::{
    AcquisitionRecoveryV2, MAXIMUM_MOUNT_SOURCE_STATE_MATERIALIZED_BYTES,
    MAXIMUM_SOURCE_PROVIDER_ATTEMPTS, ManagerCustodyLossKindV2, MountSourceAcquisitionStateV2,
    ProviderAttemptStateV2, ProviderMethodV2, ProviderQueryOwnerV2, ProviderStatusV2, RecordRefV2,
    Result, SourceAcquisitionPhaseV2, SourceAcquisitionRowV2, SourceProviderQueryAttemptV2,
    format::state_error, key_kind, validate_mount_source_state_graph_v2,
};

/// Classifies checked native data without selecting any effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootNativeDataClassV2 {
    /// Today's applicable companions still equal the original cut/CAS projection.
    LiveOriginal,
    /// Genuine legacy recovery descendants retain outstanding native obligations.
    ClosedRecoveryPending,
    /// A genuine stored terminal ACK permits independent later legacy lifecycle.
    BarrierTerminal,
    /// An authenticated dedicated no-dispatch settlement retired local interest.
    NoInterestTerminal,
}

/// Holds independently checked current records and original native historical data.
#[derive(Clone, Debug)]
pub struct RootNativeHeldGraphV2 {
    pub(super) canonical: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(super) legacy: MountSourceAcquisitionStateV2,
    pub(super) sidecars: BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
    pub(super) v1_sidecars: BTreeMap<[u8; 32], RootNativeHeldSidecarV1>,
    classes: BTreeMap<[u8; 32], RootNativeDataClassV2>,
}

impl RootNativeHeldGraphV2 {
    /// Returns the complete canonical current snapshot including native sidecars.
    #[must_use]
    pub fn canonical_records(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.canonical
    }

    /// Returns the independently validated entire current legacy graph.
    #[must_use]
    pub const fn legacy(&self) -> &MountSourceAcquisitionStateV2 {
        &self.legacy
    }

    /// Returns explicit v2 sidecars by immutable original Mount-attempt ID.
    #[must_use]
    pub fn sidecars(&self) -> &BTreeMap<[u8; 32], RootNativeHeldSidecarV2> {
        &self.sidecars
    }

    /// Returns frozen v1 diagnostics without inferential migration.
    #[must_use]
    pub fn v1_sidecars(&self) -> &BTreeMap<[u8; 32], RootNativeHeldSidecarV1> {
        &self.v1_sidecars
    }

    /// Returns a derived data classification, never a hot or cold signing guard.
    #[must_use]
    pub fn data_class(&self, attempt: [u8; 32]) -> Option<RootNativeDataClassV2> {
        self.classes.get(&attempt).copied()
    }
}

/// Validates today's entire legacy graph before reconstructing historical cuts.
///
/// # Errors
///
/// Rejects aggregate/cardinality bounds, duplicates, near-prefix or mixed-version
/// original keys, any current legacy invariant, missing original lineage,
/// altered cut bytes, invalid archives or impermissible lifecycle resurrection.
pub fn validate_native_root_graph_v2<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<RootNativeHeldGraphV2> {
    let mut canonical = BTreeMap::new();
    let mut sidecars = BTreeMap::new();
    let mut v1_sidecars = BTreeMap::new();
    let mut materialized = 0usize;
    for (key, value) in records {
        materialized = materialized
            .checked_add(key.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or_else(|| state_error("native Root v2 materialized overflow"))?;
        if materialized > MAXIMUM_MOUNT_SOURCE_STATE_MATERIALIZED_BYTES
            || canonical.contains_key(key)
        {
            return Err(state_error("native Root v2 duplicate or aggregate bound"));
        }
        if is_sidecar_key_v2(key) {
            if sidecars.len() + v1_sidecars.len() >= MAXIMUM_SOURCE_PROVIDER_ATTEMPTS {
                return Err(state_error("native Root v2 sidecar cardinality"));
            }
            let sidecar = RootNativeHeldSidecarV2::from_canonical_bytes(key, value)?;
            sidecars.insert(*sidecar.original_scope().mount_attempt.as_bytes(), sidecar);
        } else if is_sidecar_key(key) {
            if sidecars.len() + v1_sidecars.len() >= MAXIMUM_SOURCE_PROVIDER_ATTEMPTS {
                return Err(state_error("native Root v2 sidecar cardinality"));
            }
            let sidecar = RootNativeHeldSidecarV1::from_canonical_bytes(key, value)?;
            v1_sidecars.insert(*sidecar.original_scope().mount_attempt.as_bytes(), sidecar);
        } else {
            key_kind(key)?;
            if value.len() > crate::mount_source_acquisition_state::format::MAXIMUM_VALUE_BYTES {
                return Err(state_error("native Root v2 legacy value bound"));
            }
        }
        if sidecars.len() + v1_sidecars.len() > MAXIMUM_SOURCE_PROVIDER_ATTEMPTS {
            return Err(state_error("native Root v2 sidecar cardinality"));
        }
        canonical.insert(key.to_vec(), value.to_vec());
    }
    if sidecars
        .keys()
        .any(|attempt| v1_sidecars.contains_key(attempt))
    {
        return Err(state_error("native Root mixed v1/v2 original sidecars"));
    }

    // This validates the actual current rows. Historical data never enters this
    // iterator and cannot hide a dangling current reference or forged barrier.
    let legacy = validate_mount_source_state_graph_v2(
        canonical
            .iter()
            .filter(|(key, _)| !is_sidecar_key(key) && !is_sidecar_key_v2(key))
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )?;
    // V2-only snapshots do not need a second complete graph for v1 diagnostics.
    if !v1_sidecars.is_empty() {
        let diagnostics = RootNativeHeldGraphV1 {
            canonical: canonical.clone(),
            legacy: legacy.clone(),
            sidecars: v1_sidecars.clone(),
        };
        for sidecar in diagnostics.sidecars.values() {
            super::graph::validate_sidecar(&diagnostics, sidecar)?;
        }
    }

    let mut graph = RootNativeHeldGraphV2 {
        canonical,
        legacy,
        sidecars,
        v1_sidecars,
        classes: BTreeMap::new(),
    };
    for (attempt, sidecar) in &graph.sidecars {
        let class = validate_v2_sidecar(&graph, sidecar)?;
        graph.classes.insert(*attempt, class);
    }
    Ok(graph)
}

fn validate_v2_sidecar(
    graph: &RootNativeHeldGraphV2,
    sidecar: &RootNativeHeldSidecarV2,
) -> Result<RootNativeDataClassV2> {
    sidecar.validate()?;
    let attempt_id = *sidecar.original_scope().mount_attempt.as_bytes();
    let admission = sidecar
        .admission_cut
        .reconstruct(&graph.legacy, attempt_id)?;
    let current_attempt = graph
        .legacy
        .provider_attempts
        .get(&attempt_id)
        .ok_or_else(|| state_error("native Root v2 retained original Attempt absent"))?;
    validate_original_scope(sidecar, current_attempt, &admission)?;
    let disposition = sidecar
        .disposition_cut
        .as_ref()
        .map(|cut| cut.reconstruct(&graph.legacy, attempt_id))
        .transpose()?;
    let applicable = disposition.as_ref().unwrap_or(&admission);
    let current_row = graph
        .legacy
        .acquisitions
        .get(&current_attempt.owner.owner_id())
        .ok_or_else(|| state_error("native Root v2 retained original Acquisition absent"))?;
    if !same_original_acquisition(current_row, &admission.acquisition)
        || current_row.acquire_lineage.root.id != attempt_id
        || current_row.acquire_lineage.tail.id != attempt_id
        || current_row.acquire_lineage.next_attempt_number != 2
    {
        return Err(state_error(
            "native Root v2 original acquisition/lineage changed",
        ));
    }
    let cas = sidecar.response_transaction() != [0; 16];
    if cas
        && (current_attempt.revision != 2
            || !matches!(
                current_attempt.state,
                ProviderAttemptStateV2::DispositionConsumed {
                    status: ProviderStatusV2::Complete,
                    ..
                }
            )
            || sidecar.suffix().control(Kind::ProviderHeld).is_none())
    {
        return Err(state_error("native Root v2 CAS original Complete history"));
    }
    if let Some(r) = sidecar.disposition() {
        if r.records != *applicable.witnesses()
            || (r.observation == RootNativeObservationV1::ProviderHeldObserved)
                != sidecar.suffix().control(Kind::ProviderHeld).is_some()
        {
            return Err(state_error("native Root v2 R exact disposition cut"));
        }
        if let Some(held) = sidecar.suffix().control(Kind::ProviderHeld) {
            if &r.scope != held.scope() || held.section(aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldSectionTagV1::SourceArtifact) != Some(r.source_artifact.as_bytes()) {
                return Err(state_error("native Root v2 R original observed scope/artifact"));
            }
        }
        if cas
            && (current_row.evidence != applicable.acquisition.evidence
                || applicable.attempt != *current_attempt
                || r.source_artifact != super::graph::response_artifact(current_attempt)?)
        {
            return Err(state_error(
                "native Root v2 retained original response/evidence",
            ));
        }
        if r.disposition == NativeHeldDispositionV1::Accepted
            && (!cas
                || applicable
                    .acquisition
                    .evidence
                    .as_ref()
                    .is_none_or(|e| r.descriptor_commitment.as_bytes() != &e.descriptor_commitment))
        {
            return Err(state_error(
                "native Root v2 Accepted original descriptor/CAS",
            ));
        }
    }
    let historical_attempt = if cas {
        current_attempt
    } else {
        &applicable.attempt
    };
    super::graph::validate_historical_archives(
        &sidecar.claims,
        historical_attempt,
        &admission.session,
        applicable.witnesses(),
        Some(admission.witnesses()),
    )?;

    if let Some(marker) = sidecar.no_interest_terminal() {
        if cas
            || marker.settled_attempt != reference(current_attempt)
            || marker.faulted_acquisition
                != (RecordRefV2 {
                    id: current_row.acquisition_id,
                    revision: current_row.revision,
                    record_digest: current_row.record_digest,
                })
            || !matches!(
                current_attempt.state,
                ProviderAttemptStateV2::NativeNoDispatchSettled { .. }
            )
            || current_row.phase != SourceAcquisitionPhaseV2::Faulted
            || current_row.faulted_from != Some(SourceAcquisitionPhaseV2::PendingQuery)
            || current_row.evidence.is_some()
            || current_row.recovery != AcquisitionRecoveryV2::Ready
        {
            return Err(state_error(
                "native Root v2 no-interest exact terminal companions",
            ));
        }
        return Ok(RootNativeDataClassV2::NoInterestTerminal);
    }
    if matches!(sidecar.suffix().phase(), 7 | 13) {
        if !cas
            && (current_row.evidence.is_some()
                || current_row.release.is_some()
                || current_row.manager_custody.is_some()
                || current_row.consumption.is_some())
        {
            return Err(state_error(
                "native Root v2 pre-CAS Closed cannot acquire lease/custody",
            ));
        }
        if sidecar
            .disposition()
            .is_some_and(|r| r.disposition == NativeHeldDispositionV1::Closed)
            && (matches!(
                current_row.phase,
                SourceAcquisitionPhaseV2::DescriptorCustodied
                    | SourceAcquisitionPhaseV2::Active
                    | SourceAcquisitionPhaseV2::Consumed
            ) || current_row.manager_custody.is_some()
                || current_row
                    .manager_custody_loss
                    .is_some_and(|loss| loss.kind != ManagerCustodyLossKindV2::NoPriorCustody)
                || current_row
                    .faulted_from
                    .is_some_and(|phase| phase != SourceAcquisitionPhaseV2::PendingQuery))
        {
            return Err(state_error(
                "native Root Closed cannot resurrect positive custody",
            ));
        }
        return Ok(RootNativeDataClassV2::BarrierTerminal);
    }
    if super::pending_v5::has_original_pending_closed_cut_v5(graph, sidecar)? {
        return Ok(if current_companions_equal(graph, applicable) {
            RootNativeDataClassV2::LiveOriginal
        } else {
            RootNativeDataClassV2::ClosedRecoveryPending
        });
    }
    if current_companions_equal(graph, applicable)
        && matches!(
            current_attempt.state,
            ProviderAttemptStateV2::Reserved
                | ProviderAttemptStateV2::DispositionConsumed {
                    status: ProviderStatusV2::Complete,
                    ..
                }
        )
    {
        return Ok(RootNativeDataClassV2::LiveOriginal);
    }
    if sidecar.suffix().phase() == 3 {
        validate_original_cas_projection(graph, sidecar, &admission)?;
        return Ok(RootNativeDataClassV2::LiveOriginal);
    }
    if current_row.phase != SourceAcquisitionPhaseV2::PendingQuery
        || current_row.manager_custody.is_some()
        || current_row.manager_custody_loss.is_some()
        || current_row.consumption.is_some()
        || current_row.release.is_some()
        || current_row.release_proof.is_some()
        || current_row.fault_digest.is_some()
        || (!cas && current_row.evidence.is_some())
        || (!cas
            && !matches!(
                current_attempt.state,
                ProviderAttemptStateV2::AbandonedIndeterminate { .. }
                    | ProviderAttemptStateV2::SupersededIndeterminate { .. }
            ))
    {
        return Err(state_error(
            "native Root v2 unproved original recovery descendant",
        ));
    }
    Ok(RootNativeDataClassV2::ClosedRecoveryPending)
}

fn validate_original_scope(
    sidecar: &RootNativeHeldSidecarV2,
    attempt: &SourceProviderQueryAttemptV2,
    admission: &RootNativeReconstructedCutV1,
) -> Result<()> {
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
        .map_err(|_| state_error("native Root v2 original signed request"))?;
    let request = decode_acquire_request(signed.subject())
        .map_err(|_| state_error("native Root v2 original Acquire"))?;
    let provider = attempt
        .provider_acquisition
        .ok_or_else(|| state_error("native Root v2 provider acquisition absent"))?;
    let scope = sidecar.original_scope();
    if request.native_catalog().is_none()
        || attempt.method != ProviderMethodV2::Acquire
        || attempt.attempt_number != 1
        || attempt.previous_attempt_id.is_some()
        || attempt.lineage_root_attempt_id != attempt.attempt_id
        || attempt.owner
            != (ProviderQueryOwnerV2::Acquire {
                acquisition_id: admission.acquisition.acquisition_id,
            })
        || scope.original_source_session.as_bytes() != &admission.session.session_binding
        || scope.provider_acquisition.as_bytes() != &provider.acquisition_id
        || scope.original_root_request.as_bytes() != &attempt.signed_request_digest
        || request.acquisition_id().as_bytes() != &provider.acquisition_id
    {
        return Err(state_error("native Root v2 immutable original scope"));
    }
    Ok(())
}

pub(super) fn current_companions_equal(
    graph: &RootNativeHeldGraphV2,
    cut: &RootNativeReconstructedCutV1,
) -> bool {
    cut.canonical_records()
        .iter()
        .all(|(key, value)| graph.canonical.get(key) == Some(value))
}

pub(super) fn original_rows<'a>(
    graph: &'a RootNativeHeldGraphV2,
    sidecar: &RootNativeHeldSidecarV2,
) -> Result<(
    &'a SourceProviderQueryAttemptV2,
    &'a crate::mount_source_acquisition_state::SourceProviderSessionV2,
)> {
    let attempt = graph
        .legacy
        .provider_attempts
        .get(sidecar.original_scope().mount_attempt.as_bytes())
        .ok_or_else(|| state_error("native Root v2 original Attempt absent"))?;
    let session = graph
        .legacy
        .provider_sessions
        .get(&attempt.session_id)
        .filter(|session| session.record_digest == attempt.session_record_digest)
        .ok_or_else(|| state_error("native Root v2 original Session absent"))?;
    Ok((attempt, session))
}

fn same_original_acquisition(
    row: &SourceAcquisitionRowV2,
    original: &SourceAcquisitionRowV2,
) -> bool {
    row.acquisition_id == original.acquisition_id
        && row.provider_acquisition == original.provider_acquisition
        && row.scope == original.scope
        && row.acquire == original.acquire
        && row.mount_acquire_request == original.mount_acquire_request
        && row.acquire_intent_digest == original.acquire_intent_digest
        && row.assignment == original.assignment
        && row.prospective_mount_template == original.prospective_mount_template
        && row.prospective_mount_template_digest == original.prospective_mount_template_digest
        && row.source_binding == original.source_binding
        && row.source_binding_digest == original.source_binding_digest
        && row.mount_plan_digest == original.mount_plan_digest
        && row.ownership_lease_digest == original.ownership_lease_digest
}

fn reference(attempt: &SourceProviderQueryAttemptV2) -> RecordRefV2 {
    RecordRefV2 {
        id: attempt.attempt_id,
        revision: attempt.revision,
        record_digest: attempt.record_digest,
    }
}

pub(super) fn validate_original_cas_projection(
    graph: &RootNativeHeldGraphV2,
    sidecar: &RootNativeHeldSidecarV2,
    admission: &RootNativeReconstructedCutV1,
) -> Result<()> {
    // The shadow is only the input of the existing exact pure CAS calculation.
    // No historical shadow is passed to the complete current legacy validator.
    let mut before = RootNativeHeldGraphV1 {
        canonical: graph.canonical.clone(),
        legacy: graph.legacy.clone(),
        sidecars: BTreeMap::new(),
    };
    before
        .legacy
        .provider_attempts
        .insert(admission.attempt.attempt_id, admission.attempt.clone());
    before.legacy.acquisitions.insert(
        admission.acquisition.acquisition_id,
        admission.acquisition.clone(),
    );
    before.legacy.provider_heads.insert(
        (
            admission.head.scope.holder_authority_id,
            admission.head.scope.provider_authority_id,
        ),
        admission.head.clone(),
    );
    let after = RootNativeHeldGraphV1 {
        canonical: graph.canonical.clone(),
        legacy: graph.legacy.clone(),
        sidecars: BTreeMap::new(),
    };
    let mut old_claims = sidecar.claims.clone();
    old_claims.response_transaction = [0; 16];
    let mut puts = BTreeMap::new();
    for key in admission.canonical_records().keys() {
        if key_kind(key)? != crate::mount_source_acquisition_state::RecordKindV2::ProviderSession {
            puts.insert(
                key.clone(),
                graph
                    .canonical
                    .get(key)
                    .cloned()
                    .ok_or_else(|| state_error("native Root v2 CAS companion missing"))?,
            );
        }
    }
    // Reuse the frozen pure four-key CAS checker; the public proposal remains v2.
    puts.insert(
        super::native_root_sidecar_key_v1(admission.attempt.attempt_id)?,
        sidecar.claims.to_canonical_bytes()?,
    );
    super::reducer::validate_response_cas(
        &before,
        &after,
        &old_claims,
        &sidecar.claims,
        sidecar.response_transaction(),
        &puts,
    )
}
