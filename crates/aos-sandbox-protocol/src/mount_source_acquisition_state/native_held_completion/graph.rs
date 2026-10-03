//! Native sidecar joins over the entire unchanged canonical Mount object graph.
//!
//! Every legacy record passes the original decoder and full graph validator.
//! Only the exact native sidecar prefix is split out; arbitrary extra records
//! cannot bypass the legacy graph. Stored signature/projection checks establish
//! historical consistency, never protected currentness or actual FD custody.

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1 as Kind, NativeHeldScopeV1, NativeHeldSectionTagV1 as Tag,
    assertion::{NativeHeldDispositionV1, NativeHeldSettlementV1, RootNativeObservationV1},
    frame::{NativeHeldSignerV1, SignedNativeHeldControlV1},
    recovery::{
        NativeHeldRecoveryModeV1, NativeHeldRecoveryQueryV1, NativeHeldRecoveryRowClassV1,
        ProviderNativeRecoveryStateV1, RootNativeRecoveryAssertionV1,
    },
    witness::{
        NativeHeldByteWitnessV1, NativeHeldOwnerWitnessV1, NativeHeldRecordFamilyV1 as Family,
        native_held_record_byte_digest_v1,
    },
};
use aos_sandbox_source_provider_protocol::{
    AcquireSourceResponseV1, SignedSourceProviderRequestV1, SignedSourceProviderStatusV1,
    SourceProviderKeyUsageV1, SourceProviderMethod, SourceProviderSigningKeyV1,
    decode_acquire_request, encode_acquire_response, provider_response_artifact_digest_v1,
    source_provider_request_attempt_digest_v1,
};

use super::codec::is_sidecar_key;
use super::{RootNativeHeldSidecarV1, native_root_sidecar_key_v1};
use crate::mount_source_acquisition_state::{
    MAXIMUM_MOUNT_SOURCE_STATE_MATERIALIZED_BYTES, MAXIMUM_SOURCE_PROVIDER_ATTEMPTS,
    MountSourceAcquisitionStateV2, ProviderAttemptStateV2, ProviderMethodV2, ProviderQueryOwnerV2,
    ProviderStatusV2, Result, SignerSnapshotV2, SourceAcquisitionPhaseV2,
    SourceProviderQueryAttemptV2, SourceProviderSessionV2, acquisition_key, format::state_error,
    provider_attempt_key, provider_head_key, provider_session_key,
    validate_mount_source_state_graph_v2,
};

/// Holds fully checked historical native and legacy Root data, without authority.
#[derive(Clone, Debug)]
pub struct RootNativeHeldGraphV1 {
    pub(super) canonical: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(super) legacy: MountSourceAcquisitionStateV2,
    pub(super) sidecars: BTreeMap<[u8; 32], RootNativeHeldSidecarV1>,
}

impl RootNativeHeldGraphV1 {
    /// Returns the complete canonical snapshot including unchanged legacy values.
    #[must_use]
    pub fn canonical_records(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.canonical
    }

    /// Returns the validated legacy graph without turning it into a live owner.
    #[must_use]
    pub const fn legacy(&self) -> &MountSourceAcquisitionStateV2 {
        &self.legacy
    }

    /// Returns the original Mount-attempt keyed native sidecars.
    #[must_use]
    pub fn sidecars(&self) -> &BTreeMap<[u8; 32], RootNativeHeldSidecarV1> {
        &self.sidecars
    }
}

/// Validates the entire Mount graph and each exact native sidecar/companion join.
///
/// # Errors
///
/// Rejects duplicate/unknown keys, bounds, invalid legacy graphs, original scope,
/// response/descriptor/terminal joins or signature/projection inconsistencies.
pub fn validate_native_root_graph_v1<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<RootNativeHeldGraphV1> {
    let mut canonical = BTreeMap::new();
    let mut sidecars = BTreeMap::new();
    let mut materialized = 0usize;
    for (key, value) in records {
        materialized = materialized
            .checked_add(key.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or_else(|| state_error("native Root materialized overflow"))?;
        if materialized > MAXIMUM_MOUNT_SOURCE_STATE_MATERIALIZED_BYTES
            || canonical.contains_key(key)
        {
            return Err(state_error("native Root duplicate or materialized limit"));
        }
        if is_sidecar_key(key) {
            if sidecars.len() >= MAXIMUM_SOURCE_PROVIDER_ATTEMPTS {
                return Err(state_error("native Root sidecar count"));
            }
            let sidecar = RootNativeHeldSidecarV1::from_canonical_bytes(key, value)?;
            sidecars.insert(*sidecar.original_scope.mount_attempt.as_bytes(), sidecar);
        } else {
            // Unknown and nearly matching native keys still hit the exact legacy
            // key classifier before any input bytes are copied.
            crate::mount_source_acquisition_state::key_kind(key)?;
            if value.len() > crate::mount_source_acquisition_state::format::MAXIMUM_VALUE_BYTES {
                return Err(state_error("native Root legacy value limit"));
            }
        }
        canonical.insert(key.to_vec(), value.to_vec());
    }
    let legacy = validate_mount_source_state_graph_v2(
        canonical
            .iter()
            .filter(|(key, _)| !is_sidecar_key(key))
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )?;
    let graph = RootNativeHeldGraphV1 {
        canonical,
        legacy,
        sidecars,
    };
    for sidecar in graph.sidecars.values() {
        validate_sidecar(&graph, sidecar)?;
    }
    Ok(graph)
}

pub(super) fn original_rows<'a>(
    graph: &'a RootNativeHeldGraphV1,
    sidecar: &RootNativeHeldSidecarV1,
) -> Result<(
    &'a SourceProviderQueryAttemptV2,
    &'a SourceProviderSessionV2,
)> {
    let attempt = graph
        .legacy
        .provider_attempts
        .get(sidecar.original_scope.mount_attempt.as_bytes())
        .ok_or_else(|| state_error("native Root original attempt absent"))?;
    let session = graph
        .legacy
        .provider_sessions
        .get(&attempt.session_id)
        .filter(|session| session.record_digest == attempt.session_record_digest)
        .ok_or_else(|| state_error("native Root original session absent"))?;
    Ok((attempt, session))
}

pub(super) fn companion_witnesses(
    graph: &RootNativeHeldGraphV1,
    sidecar: &RootNativeHeldSidecarV1,
) -> Result<[NativeHeldByteWitnessV1; 4]> {
    let (attempt, session) = original_rows(graph, sidecar)?;
    let ProviderQueryOwnerV2::Acquire { acquisition_id } = attempt.owner else {
        return Err(state_error("native Root attempt owner"));
    };
    let keys = [
        provider_session_key(session.session_id),
        provider_attempt_key(attempt.attempt_id),
        acquisition_key(acquisition_id),
        provider_head_key(
            session.scope.holder_authority_id,
            session.scope.provider_authority_id,
        ),
    ];
    let families = [
        Family::RootSession,
        Family::RootAttempt,
        Family::RootAcquisition,
        Family::RootHead,
    ];
    let mut witnesses = Vec::with_capacity(4);
    for (key, family) in keys.into_iter().zip(families) {
        let digest = match graph.canonical.get(&key) {
            Some(bytes) => native_held_record_byte_digest_v1(family, &key, bytes)
                .map_err(|_| state_error("native Root companion digest"))?,
            None if family == Family::RootAcquisition => ObjectDigest::from_bytes([0; 32]),
            None => return Err(state_error("native Root mandatory companion absent")),
        };
        witnesses.push(
            NativeHeldByteWitnessV1::new(family, key, digest)
                .map_err(|_| state_error("native Root companion key"))?,
        );
    }
    witnesses
        .try_into()
        .map_err(|_| state_error("native Root companion count"))
}

pub(super) fn validate_sidecar(
    graph: &RootNativeHeldGraphV1,
    sidecar: &RootNativeHeldSidecarV1,
) -> Result<()> {
    let (attempt, session) = original_rows(graph, sidecar)?;
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
        .map_err(|_| state_error("native Root original request"))?;
    let request = decode_acquire_request(signed.subject())
        .map_err(|_| state_error("native Root original Acquire"))?;
    request
        .native_catalog()
        .ok_or_else(|| state_error("native Root requires original native V3"))?;
    let acquisition = attempt
        .provider_acquisition
        .ok_or_else(|| state_error("native Root provider acquisition"))?;
    let scope = sidecar.original_scope;
    if attempt.method != ProviderMethodV2::Acquire
        || attempt.attempt_number != 1
        || attempt.previous_attempt_id.is_some()
        || attempt.lineage_root_attempt_id != attempt.attempt_id
        || attempt.scope != session.scope
        || scope.original_source_session.as_bytes() != &session.session_binding
        || scope.provider_acquisition.as_bytes() != &acquisition.acquisition_id
        || scope.original_root_request.as_bytes() != &attempt.signed_request_digest
        || request.acquisition_id().as_bytes() != &acquisition.acquisition_id
    {
        return Err(state_error("native Root original graph scope"));
    }
    validate_phase_slots(sidecar)?;
    let cas = sidecar.response_transaction != [0; 16];
    if cas {
        if attempt.revision != 2
            || sidecar.suffix.control(Kind::ProviderHeld).is_none()
            || !matches!(
                attempt.state,
                ProviderAttemptStateV2::DispositionConsumed {
                    status: ProviderStatusV2::Complete,
                    ..
                }
            )
        {
            return Err(state_error(
                "native Root CAS requires genuine Complete attempt",
            ));
        }
    } else if attempt.revision != 1 || !matches!(attempt.state, ProviderAttemptStateV2::Reserved) {
        return Err(state_error("native Root pre-CAS attempt changed"));
    }
    let row = graph.legacy.acquisitions.get(&attempt.owner.owner_id());
    if let Some(row) = row {
        // No native stage asserts or advances manager custody. A later, separately
        // reviewed lifecycle must not use this reducer as its permission.
        if row.phase != SourceAcquisitionPhaseV2::PendingQuery
            || row.manager_custody.is_some()
            || row.descriptor_custody_digest.is_some()
            || row.positive_custody_digest.is_some()
            || row.consumption.is_some()
            || row.release.is_some()
            || row.release_proof.is_some()
        {
            return Err(state_error(
                "native Root cannot grant manager or lifecycle state",
            ));
        }
        if cas
            && row
                .evidence
                .as_ref()
                .is_none_or(|e| e.acquire_attempt.id != attempt.attempt_id)
        {
            return Err(state_error("native Root CAS acquisition evidence absent"));
        }
    } else if cas {
        return Err(state_error("native Root CAS acquisition absent"));
    }

    let expected = companion_witnesses(graph, sidecar)?;
    if let Some(r) = &sidecar.disposition {
        if r.records != expected {
            return Err(state_error("native Root R canonical companion bytes"));
        }
        let held = sidecar.suffix.control(Kind::ProviderHeld);
        if (r.observation == RootNativeObservationV1::ProviderHeldObserved) != held.is_some() {
            return Err(state_error("native Root observed/partial disposition"));
        }
        if let Some(held) = held {
            if &r.scope != held.scope()
                || r.source_artifact.as_bytes() != required(held, Tag::SourceArtifact)?
            {
                return Err(state_error(
                    "native Root R original observed scope/artifact",
                ));
            }
        }
        if r.disposition == NativeHeldDispositionV1::Accepted {
            let evidence = row
                .and_then(|row| row.evidence.as_ref())
                .ok_or_else(|| state_error("native Root Accepted evidence"))?;
            if r.descriptor_commitment.as_bytes() != &evidence.descriptor_commitment || !cas {
                return Err(state_error("native Root Accepted original descriptor/CAS"));
            }
        }
        if r.observation == RootNativeObservationV1::ProviderHeldObserved
            && cas
            && r.source_artifact != response_artifact(attempt)?
        {
            return Err(state_error("native Root observed original response"));
        }
    }

    validate_historical_archives(sidecar, attempt, session, &expected, None)?;

    // Root phase0 has no signed1, but its exact unsigned1 still binds all of the
    // initial canonical rows. Graph validation never synthesizes a signature.
    if graph
        .canonical
        .get(&native_root_sidecar_key_v1(attempt.attempt_id)?)
        .is_none()
    {
        return Err(state_error("native Root sidecar canonical value absent"));
    }
    Ok(())
}

pub(super) fn validate_historical_archives(
    sidecar: &RootNativeHeldSidecarV1,
    attempt: &SourceProviderQueryAttemptV2,
    session: &SourceProviderSessionV2,
    expected: &[NativeHeldByteWitnessV1; 4],
    admission_expected: Option<&[NativeHeldByteWitnessV1; 4]>,
) -> Result<()> {
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&attempt.signed_request)
        .map_err(|_| state_error("native Root retained original request"))?;
    let request = decode_acquire_request(signed.subject())
        .map_err(|_| state_error("native Root retained original Acquire"))?;
    let catalog = request
        .native_catalog()
        .ok_or_else(|| state_error("native Root original native catalog absent"))?;
    let scope = sidecar.original_scope;
    let phase = sidecar.suffix.phase();
    let cas = sidecar.response_transaction != [0; 16];
    validate_phase_slots(sidecar)?;
    let original = sidecar.suffix.control(Kind::RootPrepared);
    let mut last_slot = 0;
    for control in sidecar.suffix.controls() {
        let slot = match control.kind() {
            Kind::RootPrepared => 1,
            Kind::ProviderHeld => 2,
            Kind::RootAccepted | Kind::RootClosed => 3,
            Kind::ProviderSettled | Kind::ProviderRecoveryState => 4,
            Kind::RootTerminalRecorded | Kind::RootRecoveryQuery => 5,
            _ => return Err(state_error("native Root unexpected archive")),
        };
        if slot <= last_slot {
            return Err(state_error("native Root archive chronology"));
        }
        last_slot = slot;
        join_scope(control.scope(), &scope)?;
        if !control.scope().is_root_only()
            && control.scope().provider_attempt
                != source_provider_request_attempt_digest_v1(
                    signed.signer(),
                    SourceProviderMethod::Acquire,
                    attempt.request_id,
                )
        {
            return Err(state_error("native Root full original provider attempt"));
        }
        if matches!(control.kind(), Kind::ProviderHeld | Kind::ProviderSettled) {
            validate_provider_witness(required(control, Tag::Witness)?, session, catalog)?;
        }
        if control.kind().sender()
            == aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldOwnerV1::Root
            && control.kind() != Kind::RootRecoveryQuery
        {
            validate_root_witness(
                required(control, Tag::Witness)?,
                session,
                catalog,
                if control.kind() == Kind::RootPrepared {
                    admission_expected.unwrap_or(expected)
                } else {
                    expected
                },
                admission_expected.is_some() || control.kind() != Kind::RootPrepared || !cas,
            )?;
        }
        match control.kind() {
            Kind::RootPrepared => {
                verify_original(
                    control,
                    &session.signers[1],
                    SourceProviderKeyUsageV1::RootMountRecord,
                )?;
            }
            Kind::ProviderHeld => {
                verify_original(
                    control,
                    &session.signers[3],
                    SourceProviderKeyUsageV1::ProviderOutcome,
                )?;
                let storage = SignedNativeHeldControlV1::from_canonical_bytes(required(
                    control,
                    Tag::StorageHeld,
                )?)
                .map_err(|_| state_error("native Root nested StorageHeld"))?;
                if original.is_none_or(|one| {
                    storage.section(Tag::RootPrepared) != Some(one.to_canonical_bytes().as_slice())
                }) || control.scope().provider_attempt
                    != source_provider_request_attempt_digest_v1(
                        signed.signer(),
                        SourceProviderMethod::Acquire,
                        attempt.request_id,
                    )
                    || (cas
                        && required(control, Tag::SourceArtifact)?
                            != response_artifact(attempt)?.as_bytes())
                {
                    return Err(state_error("native Root original ProviderHeld graph"));
                }
            }
            Kind::RootAccepted | Kind::RootClosed => {
                verify_original(
                    control,
                    &session.signers[1],
                    SourceProviderKeyUsageV1::RootMountRecord,
                )?;
                let r = sidecar
                    .disposition
                    .as_ref()
                    .ok_or_else(|| state_error("native Root archived R absent"))?;
                if required(control, Tag::RootDispositionAssertion)?
                    != r.to_canonical_bytes()
                        .map_err(|_| state_error("native Root R bytes"))?
                        .as_slice()
                {
                    return Err(state_error("native Root archived irreversible R"));
                }
                let predecessor = if r.observation == RootNativeObservationV1::PreparedOnly {
                    original
                } else {
                    sidecar.suffix.control(Kind::ProviderHeld)
                };
                if predecessor.is_none_or(|prior| prior.digest() != control.predecessor()) {
                    return Err(state_error("native Root disposition predecessor"));
                }
            }
            Kind::ProviderSettled => {
                verify_original(
                    control,
                    &session.signers[3],
                    SourceProviderKeyUsageV1::ProviderOutcome,
                )?;
                if Some(
                    NativeHeldSettlementV1::from_canonical_bytes(required(
                        control,
                        Tag::Settlement,
                    )?)
                    .map_err(|_| state_error("native Root terminal S"))?,
                ) != sidecar.settlement
                {
                    return Err(state_error("native Root original terminal stable IDs"));
                }
                // Source7's Storage6 predecessor is independently authenticated
                // by Source. Root never invents a dedicated Storage trust role.
            }
            Kind::ProviderRecoveryState => validate_terminal_recovery(sidecar, control, session)?,
            Kind::RootTerminalRecorded => {
                verify_original(
                    control,
                    &session.signers[1],
                    SourceProviderKeyUsageV1::RootMountRecord,
                )?;
                let terminal = terminal_control(sidecar)
                    .ok_or_else(|| state_error("native Root ACK terminal absent"))?;
                if control.predecessor() != terminal.digest()
                    || Some(
                        NativeHeldSettlementV1::from_canonical_bytes(required(
                            control,
                            Tag::Settlement,
                        )?)
                        .map_err(|_| state_error("native Root ACK S"))?,
                    ) != sidecar.settlement
                {
                    return Err(state_error("native Root ACK original terminal"));
                }
            }
            Kind::RootRecoveryQuery => {
                let NativeHeldSignerV1::SourceProvider(signer) = control.prepared().signer() else {
                    return Err(state_error("native Root own recovery signer role"));
                };
                let q = NativeHeldRecoveryQueryV1::from_canonical_bytes(required(
                    control,
                    Tag::RecoveryQuery,
                )?)
                .map_err(|_| state_error("native Root terminal query"))?;
                let k = RootNativeRecoveryAssertionV1::from_canonical_bytes(required(
                    control,
                    Tag::RootRecoveryAssertion,
                )?)
                .map_err(|_| state_error("native Root terminal K"))?;
                if q.mode != NativeHeldRecoveryModeV1::RecordRootTerminal
                    || signer.authority_id() != session.scope.holder_authority_id
                    || q.original_prepared
                        != original.map_or(
                            ObjectDigest::from_bytes([0; 32]),
                            SignedNativeHeldControlV1::digest,
                        )
                    || k.phase != if phase == 7 { 6 } else { 12 }
                    || k.disposition != sidecar.disposition
                    || k.settlement != sidecar.settlement
                    || &k.records != expected
                    || k.hot_archive
                        != sidecar
                            .suffix
                            .control(Kind::RootAccepted)
                            .or_else(|| sidecar.suffix.control(Kind::RootClosed))
                            .map(SignedNativeHeldControlV1::to_canonical_bytes)
                {
                    return Err(state_error("native Root terminal owning query"));
                }
                // This is Root's own current-role signature, whose eligible
                // signing owner is deliberately absent from this pure API.
            }
            _ => return Err(state_error("native Root control kind")),
        }
    }
    if sidecar.terminal_verifier.is_some()
        != sidecar
            .suffix
            .control(Kind::ProviderRecoveryState)
            .is_some()
    {
        return Err(state_error("native Root exact recovery verifier presence"));
    }
    if let Some(prepared) = sidecar.suffix.prepared() {
        join_scope(prepared.scope(), &scope)?;
        let expected_signer = signer_reference(
            &session.signers[1],
            SourceProviderKeyUsageV1::RootMountRecord,
        )?;
        if prepared.signer() != &NativeHeldSignerV1::SourceProvider(expected_signer) {
            return Err(state_error("native Root prepared original signer"));
        }
        if let Some(r) = &sidecar.disposition {
            if matches!(prepared.kind(), Kind::RootAccepted | Kind::RootClosed)
                && prepared.section(Tag::RootDispositionAssertion)
                    != Some(
                        r.to_canonical_bytes()
                            .map_err(|_| state_error("native Root prepared R"))?
                            .as_slice(),
                    )
            {
                return Err(state_error("native Root prepared disposition"));
            }
        }
        validate_root_witness(
            prepared
                .section(Tag::Witness)
                .ok_or_else(|| state_error("native Root prepared witness absent"))?,
            session,
            catalog,
            if prepared.kind() == Kind::RootPrepared {
                admission_expected.unwrap_or(expected)
            } else {
                expected
            },
            true,
        )?;
        if matches!(prepared.kind(), Kind::RootAccepted | Kind::RootClosed) {
            let r = sidecar
                .disposition
                .as_ref()
                .ok_or_else(|| state_error("native Root prepared disposition absent"))?;
            let predecessor = if r.observation == RootNativeObservationV1::PreparedOnly {
                original
            } else {
                sidecar.suffix.control(Kind::ProviderHeld)
            };
            if predecessor.is_none_or(|prior| prior.digest() != prepared.predecessor()) {
                return Err(state_error("native Root prepared disposition predecessor"));
            }
        }
        if prepared.kind() == Kind::RootTerminalRecorded {
            if terminal_control(sidecar)
                .is_none_or(|terminal| prepared.predecessor() != terminal.digest())
                || prepared.section(Tag::Settlement)
                    != sidecar
                        .settlement
                        .as_ref()
                        .map(NativeHeldSettlementV1::to_canonical_bytes)
                        .transpose()
                        .map_err(|_| state_error("native Root prepared terminal S"))?
                        .as_ref()
                        .map(|bytes| bytes.as_slice())
            {
                return Err(state_error("native Root prepared terminal ACK"));
            }
        }
    }
    Ok(())
}

fn validate_phase_slots(sidecar: &RootNativeHeldSidecarV1) -> Result<()> {
    let phase = sidecar.suffix.phase();
    for control in sidecar.suffix.controls() {
        let allowed = match control.kind() {
            Kind::RootPrepared => phase != 0,
            Kind::ProviderHeld => matches!(phase, 2..=7 | 10..=13),
            Kind::RootAccepted => matches!(phase, 5..=7),
            Kind::RootClosed => matches!(phase, 11..=13),
            Kind::ProviderSettled | Kind::ProviderRecoveryState => matches!(phase, 6 | 7 | 12 | 13),
            Kind::RootTerminalRecorded | Kind::RootRecoveryQuery => matches!(phase, 7 | 13),
            _ => false,
        };
        if !allowed {
            return Err(state_error("native Root archive outside exact phase"));
        }
    }
    let prepared = sidecar.suffix.prepared().map(|prepared| prepared.kind());
    let valid = match phase {
        0 => prepared == Some(Kind::RootPrepared),
        4 => prepared == Some(Kind::RootAccepted),
        6 | 12 => prepared == Some(Kind::RootTerminalRecorded),
        10 => prepared.is_none() || prepared == Some(Kind::RootClosed),
        _ => prepared.is_none(),
    };
    if !valid {
        return Err(state_error("native Root exact durable preparation slot"));
    }
    Ok(())
}

fn validate_root_witness(
    bytes: &[u8],
    session: &SourceProviderSessionV2,
    catalog: &aos_sandbox_source_provider_protocol::NativeAcquireCatalogBindingV3,
    expected: &[NativeHeldByteWitnessV1; 4],
    compare_records: bool,
) -> Result<()> {
    let NativeHeldOwnerWitnessV1::Root(w) = NativeHeldOwnerWitnessV1::from_canonical_bytes(
        aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldOwnerV1::Root,
        bytes,
    )
    .map_err(|_| state_error("native Root owner witness"))?
    else {
        return Err(state_error("native Root witness owner"));
    };
    if w.trust.generation != session.trust_generation
        || w.trust.digest.as_bytes() != &session.trust_digest
        || w.revocation.generation != session.revocation_generation
        || w.revocation.digest.as_bytes() != &session.revocation_digest
        || (w.provider_head.generation, w.provider_head.digest) != catalog.head()
        || (w.provider_floor.generation, w.provider_floor.digest) != catalog.floor()
        || w.publication != catalog.canonical_publication_digest()
        || (compare_records && &w.records != expected)
    {
        return Err(state_error("native Root original witness claims/bytes"));
    }
    Ok(())
}

fn validate_provider_witness(
    bytes: &[u8],
    session: &SourceProviderSessionV2,
    catalog: &aos_sandbox_source_provider_protocol::NativeAcquireCatalogBindingV3,
) -> Result<()> {
    let NativeHeldOwnerWitnessV1::Provider(w) = NativeHeldOwnerWitnessV1::from_canonical_bytes(
        aos_sandbox_source_provider_protocol::native_held_completion::NativeHeldOwnerV1::Provider,
        bytes,
    )
    .map_err(|_| state_error("native Root Provider witness"))?
    else {
        return Err(state_error("native Root Provider witness owner"));
    };
    if w.authority.authority_id() != session.scope.provider_authority_id
        || w.authority.authority_generation() != session.provider_authority_generation
        || w.authority.authority_digest().as_bytes() != &session.provider_authority_digest
        || w.native_namespace != catalog.resource_namespace_digest()
        || (w.catalog_head.generation, w.catalog_head.digest) != catalog.head()
        || (w.catalog_floor.generation, w.catalog_floor.digest) != catalog.floor()
        || w.head_commitment != catalog.current_head_commitment()
        || w.publication != catalog.canonical_publication_digest()
    {
        return Err(state_error(
            "native Root Provider original catalog/authority claims",
        ));
    }
    Ok(())
}

fn validate_terminal_recovery(
    sidecar: &RootNativeHeldSidecarV1,
    control: &SignedNativeHeldControlV1,
    session: &SourceProviderSessionV2,
) -> Result<()> {
    let evidence = sidecar
        .terminal_verifier
        .as_ref()
        .ok_or_else(|| state_error("native Root terminal verifier absent"))?;
    evidence.verify_terminal(control, session.scope.provider_authority_id)?;
    let q = NativeHeldRecoveryQueryV1::from_canonical_bytes(required(control, Tag::RecoveryQuery)?)
        .map_err(|_| state_error("native Root terminal recovery Q"))?;
    let state = ProviderNativeRecoveryStateV1::from_canonical_bytes(required(
        control,
        Tag::ProviderRecoveryState,
    )?)
    .map_err(|_| state_error("native Root terminal recovery V"))?;
    let fields = state.fields;
    let s = sidecar
        .settlement
        .as_ref()
        .ok_or_else(|| state_error("native Root recovery S absent"))?;
    let original = sidecar
        .suffix
        .control(Kind::RootPrepared)
        .ok_or_else(|| state_error("native Root recovery original1 absent"))?;
    if q.mode != NativeHeldRecoveryModeV1::SettleRecordedDisposition
        || q.original_prepared != original.digest()
        || fields.row_class != NativeHeldRecoveryRowClassV1::Native
        || fields.disposition != sidecar.disposition
        || fields.root_disposition != s.root_disposition
        || fields.storage_settlement != s.storage_settlement
        || fields.provider_settlement != s.provider_settlement
        || fields.own_assertion.is_empty()
    {
        return Err(state_error("native Root recovery terminal owning IDs"));
    }
    Ok(())
}

pub(super) fn terminal_control(
    sidecar: &RootNativeHeldSidecarV1,
) -> Option<&SignedNativeHeldControlV1> {
    sidecar
        .suffix
        .control(Kind::ProviderSettled)
        .or_else(|| sidecar.suffix.control(Kind::ProviderRecoveryState))
}

pub(super) fn required(control: &SignedNativeHeldControlV1, tag: Tag) -> Result<&[u8]> {
    control
        .section(tag)
        .ok_or_else(|| state_error("native Root required control section"))
}

fn join_scope(scope: &NativeHeldScopeV1, original: &NativeHeldScopeV1) -> Result<()> {
    if scope.is_root_only() {
        if scope != original {
            return Err(state_error("native Root immutable partial scope"));
        }
    } else {
        scope
            .require_root_prefix(original)
            .map_err(|_| state_error("native Root immutable full prefix"))?;
    }
    Ok(())
}

fn verify_original(
    control: &SignedNativeHeldControlV1,
    snapshot: &SignerSnapshotV2,
    usage: SourceProviderKeyUsageV1,
) -> Result<()> {
    control
        .verify_signature_claim(
            &NativeHeldSignerV1::SourceProvider(signer_reference(snapshot, usage)?),
            &snapshot.public_key,
        )
        .map_err(|_| state_error("native Root original control signature"))
}

fn signer_reference(
    snapshot: &SignerSnapshotV2,
    usage: SourceProviderKeyUsageV1,
) -> Result<SourceProviderSigningKeyV1> {
    SourceProviderSigningKeyV1::new(
        snapshot.authority_id,
        snapshot.authority_generation,
        ObjectDigest::from_bytes(snapshot.authority_digest),
        snapshot.key_id,
        snapshot.key_generation,
        ObjectDigest::from_bytes(snapshot.public_key_fingerprint),
        usage,
    )
    .map_err(|_| state_error("native Root retained signer reference"))
}

pub(super) fn response_artifact(attempt: &SourceProviderQueryAttemptV2) -> Result<ObjectDigest> {
    let ProviderAttemptStateV2::DispositionConsumed {
        signed_status,
        signed_result,
        status: ProviderStatusV2::Complete,
        ..
    } = &attempt.state
    else {
        return Err(state_error("native Root original Complete response absent"));
    };
    let status = SignedSourceProviderStatusV1::from_canonical_bytes(signed_status)
        .map_err(|_| state_error("native Root original status"))?;
    let response = AcquireSourceResponseV1::new(status, Some(signed_result.clone()))
        .map_err(|_| state_error("native Root original response shape"))?;
    Ok(provider_response_artifact_digest_v1(
        SourceProviderMethod::Acquire,
        &encode_acquire_response(&response),
    ))
}
