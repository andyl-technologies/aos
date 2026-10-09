//! Checks new provider-facing sends while original launch custody stays owned.
//!
//! The native singleton census and exact original refusal population are checked
//! before every resend. Independent transmitted/decoded frames are compared
//! with the unchanged original observational journal; no cached call is credited.

use crucible::node_adapters::cnp::{CnpLaunchGuard, CnpReferenceQualification};
use crucible::node_contract::{EffectKnowledge, OperationFailure};
use crucible_node_contract::{Bytes, ClosedGateRecord, ContentRef, HashRef, Id, U64, canonical};
use crucible_node_provider::{
    ProviderError,
    bodies::RealizeResult,
    client::{
        ObservationHandle, ObservationLimits, ObservedRequestKey, RecordedReferenceObservation,
        TransmissionObservationHandle,
    },
    envelope::{Envelope, RequestOrigin},
    reference_service::ReferenceProfile,
};
use serde::{Deserialize, Serialize};

use super::{
    installation::SourcePublicReferenceInstallation, native::ProviderOnlyEnrollment,
    source_resend_plan::SourceResendPlan,
};

const MAXIMUM_SNAPSHOT_BYTES: usize = 1024 * 1024;

#[derive(Serialize)]
pub(super) struct OriginalSourceResends {
    schema: &'static str,
    fixture: ContentRef,
    before: ProviderOnlyEnrollment,
    after: ProviderOnlyEnrollment,
    original_snapshot: ContentRef,
    transmitted_snapshot: ContentRef,
    exact_original_count: usize,
}

/// Checks the exact wire observations without assigning a qualification verdict.
///
/// # Errors
/// Refuses changed original fixtures, native premises or journals; exhausted
/// finite data credits; missing actual sends or changed semantic replies.
pub(super) fn collect(
    installed: &SourcePublicReferenceInstallation,
    guard: &mut CnpLaunchGuard,
    plan: &SourceResendPlan,
    observer: &ObservationHandle,
    transmissions: &TransmissionObservationHandle,
) -> Result<(OriginalSourceResends, Vec<u8>, Vec<u8>), ProviderError> {
    let expected = SourceResendPlan::build(installed)?;
    if expected.reference != plan.reference
        || expected.bytes != plan.bytes
        || expected.objects != plan.objects
        || expected.requests() != plan.requests()
    {
        return Err(ProviderError::Correlation(
            "source retained-original resend fixture changed",
        ));
    }
    let original = original_observation(plan, observer)?;
    plan.originals.verify(&original)?;
    let before = enroll(installed, guard)?;
    let qualifier = ResendQualification {
        installed,
        plan,
        observer,
    };
    #[cfg(test)]
    verify_local_refusals(installed, guard, plan, &qualifier, transmissions)?;
    guard
        .resend_pre_realization_originals(&qualifier, plan.requests())
        .map_err(|error| ProviderError::Io(std::io::Error::other(error.reason)))?;
    before.authenticate(&installed.package, &installed.bootstrap.resource_limits)?;
    let after = enroll(installed, guard)?;
    let unchanged = original_observation(plan, observer)?;
    plan.originals.verify(&unchanged)?;
    let original_bytes = original.encode(MAXIMUM_SNAPSHOT_BYTES)?;
    if unchanged.encode(MAXIMUM_SNAPSHOT_BYTES)? != original_bytes {
        return Err(ProviderError::Correlation(
            "wire resend replaced an original journal",
        ));
    }
    let value = serde_json::to_value(transmissions.snapshot(MAXIMUM_SNAPSHOT_BYTES)?)
        .map_err(crucible_node_contract::ContractError::from)?;
    let transmitted_bytes = canonical::canonical_json(&value)?;
    if transmitted_bytes.len() > MAXIMUM_SNAPSHOT_BYTES {
        return Err(ProviderError::ResourceExhausted(
            "source wire observation encoding ceiling",
        ));
    }
    let observed: WireObservation = serde_json::from_value(value.clone())
        .map_err(crucible_node_contract::ContractError::from)?;
    verify_wire(&observed, &original, plan.requests())?;
    #[cfg(test)]
    verify_observed_mutations(&value, &original, plan.requests())?;
    Ok((
        OriginalSourceResends {
            schema: "crucible.reference.source-original-wire-resends.v1",
            fixture: plan.reference.clone(),
            before,
            after,
            original_snapshot: canonical::content_ref(&original_bytes, "application/json")?,
            transmitted_snapshot: canonical::content_ref(&transmitted_bytes, "application/json")?,
            exact_original_count: plan.requests().len(),
        },
        original_bytes,
        transmitted_bytes,
    ))
}

struct ResendQualification<'a> {
    installed: &'a SourcePublicReferenceInstallation,
    plan: &'a SourceResendPlan,
    observer: &'a ObservationHandle,
}

impl CnpReferenceQualification for ResendQualification<'_> {
    fn authenticate_provider(
        &self,
        guard: &CnpLaunchGuard,
        profile: &ReferenceProfile,
    ) -> Result<(), OperationFailure> {
        self.installed.authenticate_provider(guard, profile)
    }

    fn authenticate_realization(
        &self,
        guard: &CnpLaunchGuard,
        result: &RealizeResult,
        gate: &ClosedGateRecord,
        companion: u32,
    ) -> Result<(), OperationFailure> {
        self.installed
            .authenticate_realization(guard, result, gate, companion)
    }

    fn authenticate_pre_realization_resends(
        &self,
        guard: &CnpLaunchGuard,
        requests: &[Id],
    ) -> Result<(), OperationFailure> {
        let result = (|| {
            if requests != self.plan.requests() {
                return Err(ProviderError::Correlation(
                    "unplanned original wire resend IDs",
                ));
            }
            self.plan
                .originals
                .verify(&original_observation(self.plan, self.observer)?)?;
            enroll(self.installed, guard)?;
            Ok(())
        })();
        result.map_err(|error: ProviderError| OperationFailure {
            effects: EffectKnowledge::None,
            reason: error.to_string(),
        })
    }
}

fn enroll(
    installed: &SourcePublicReferenceInstallation,
    guard: &CnpLaunchGuard,
) -> Result<ProviderOnlyEnrollment, ProviderError> {
    ProviderOnlyEnrollment::enroll(
        guard.provider_pid().ok_or(ProviderError::Correlation(
            "original resend provider unavailable",
        ))?,
        guard.supervision_id(),
        &installed.package,
        &installed.bootstrap.resource_limits,
    )
}

fn original_observation(
    plan: &SourceResendPlan,
    observer: &ObservationHandle,
) -> Result<RecordedReferenceObservation, ProviderError> {
    let keys = plan
        .requests()
        .iter()
        .map(|request| ObservedRequestKey {
            origin: RequestOrigin::Controller,
            request_id: request.clone(),
        })
        .collect::<Vec<_>>();
    observer.snapshot(
        &keys,
        &[],
        ObservationLimits {
            maximum_requests: 3,
            maximum_objects: 1,
            maximum_bytes: MAXIMUM_SNAPSHOT_BYTES,
        },
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireScope {
    session: Id,
    incarnation: Id,
    connection: Id,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum WireOrigin {
    Controller,
    Provider,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRow {
    transmission: U64,
    origin: WireOrigin,
    request_id: Id,
    identity: HashRef,
    sent_sequence: U64,
    write_completed: bool,
    semantic_response_verified: bool,
    request_start: usize,
    request_length: usize,
    received: Option<(usize, usize)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireObservation {
    schema: String,
    encoding: String,
    scope: WireScope,
    rows: Vec<WireRow>,
    bytes: Bytes,
    incomplete: bool,
}

fn verify_wire(
    wire: &WireObservation,
    original: &RecordedReferenceObservation,
    requests: &[Id],
) -> Result<(), ProviderError> {
    let scope = &original.evidence.scope;
    if wire.schema != "crucible.reference.original-wire-resends.v1"
        || wire.encoding != "canonical-transmitted-and-decoded-envelope-v1"
        || wire.incomplete
        || wire.rows.len() != requests.len()
        || wire.scope.session != scope.session_id
        || wire.scope.incarnation != scope.incarnation_id
        || wire.scope.connection != scope.connection_id
    {
        return Err(ProviderError::Correlation(
            "source wire resend scope or completion differs",
        ));
    }
    let mut prior_sequence = 0;
    let mut next_byte = 0;
    for (index, (row, request_id)) in wire.rows.iter().zip(requests).enumerate() {
        let original = original
            .evidence
            .requests
            .iter()
            .find(|entry| &entry.key.request_id == request_id)
            .ok_or(ProviderError::Correlation(
                "source wire resend original absent",
            ))?;
        if row.transmission.get() != index as u64 + 1
            || row.origin != WireOrigin::Controller
            || &row.request_id != request_id
            || row.identity != original.identity
            || !row.write_completed
            || !row.semantic_response_verified
            || row.sent_sequence.get() <= prior_sequence
        {
            return Err(ProviderError::Correlation(
                "source wire resend tuple or original identity differs",
            ));
        }
        let request = decode_frame(&wire.bytes, row.request_start, row.request_length)?;
        let (response_start, response_length) = row.received.ok_or(ProviderError::Correlation(
            "source wire resend actual response absent",
        ))?;
        if row.request_start != next_byte
            || row.request_start.checked_add(row.request_length) != Some(response_start)
        {
            return Err(ProviderError::Correlation(
                "source wire resend original ranges are not contiguous",
            ));
        }
        next_byte =
            response_start
                .checked_add(response_length)
                .ok_or(ProviderError::Correlation(
                    "source wire resend response range overflow",
                ))?;
        let response = decode_frame(&wire.bytes, response_start, response_length)?;
        let mut retained_request: Envelope = serde_json::from_value(canonical::parse_json(
            original.request.bytes.as_slice(),
            MAXIMUM_SNAPSHOT_BYTES,
        )?)
        .map_err(crucible_node_contract::ContractError::from)?;
        if request.sequence != row.sent_sequence || request.sequence <= retained_request.sequence {
            return Err(ProviderError::Correlation(
                "source wire resend did not use a fresh transport sequence",
            ));
        }
        retained_request.sequence = row.sent_sequence;
        let retained_response = original
            .response
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "source wire original response unknown",
            ))?;
        let mut retained_response: Envelope = serde_json::from_value(canonical::parse_json(
            retained_response.bytes.as_slice(),
            MAXIMUM_SNAPSHOT_BYTES,
        )?)
        .map_err(crucible_node_contract::ContractError::from)?;
        retained_response.sequence = response.sequence;
        request.matches_response(&response)?;
        if retained_request != request
            || retained_response != response
            || request.request_hash(RequestOrigin::Controller)? != row.identity
        {
            return Err(ProviderError::Correlation(
                "source wire resend changed semantic original",
            ));
        }
        prior_sequence = row.sent_sequence.get();
    }
    if next_byte != wire.bytes.as_slice().len() {
        return Err(ProviderError::Correlation(
            "source wire resend archive contains unassigned bytes",
        ));
    }
    Ok(())
}

fn decode_frame(bytes: &Bytes, start: usize, length: usize) -> Result<Envelope, ProviderError> {
    let end = start
        .checked_add(length)
        .ok_or(ProviderError::Correlation("wire original range overflow"))?;
    let body = bytes
        .as_slice()
        .get(start..end)
        .ok_or(ProviderError::Correlation(
            "wire original range outside archive",
        ))?;
    let value = canonical::parse_json(body, MAXIMUM_SNAPSHOT_BYTES)?;
    if canonical::canonical_json(&value)? != body {
        return Err(ProviderError::Correlation(
            "wire original envelope is not canonical",
        ));
    }
    serde_json::from_value(value)
        .map_err(crucible_node_contract::ContractError::from)
        .map_err(ProviderError::from)
}

/// Checks retained actual frames and rehashed data mutations, not native refusals.
#[cfg(test)]
fn verify_observed_mutations(
    value: &serde_json::Value,
    original: &RecordedReferenceObservation,
    requests: &[Id],
) -> Result<(), ProviderError> {
    for mutation in 0..6 {
        let mut changed = value.clone();
        match mutation {
            0 => changed["incomplete"] = true.into(),
            1 => {
                changed["rows"]
                    .as_array_mut()
                    .ok_or(ProviderError::Correlation("wire rows absent"))?
                    .pop();
            }
            2 => changed["rows"][0]["request_start"] = 1.into(),
            3 => changed["rows"][0]["sent_sequence"] = "0".into(),
            4 => changed["scope"]["session"] = "foreign-session".into(),
            _ => changed["rows"][0]["semantic_response_verified"] = false.into(),
        }
        let changed: WireObservation =
            serde_json::from_value(changed).map_err(crucible_node_contract::ContractError::from)?;
        if verify_wire(&changed, original, requests).is_ok() {
            return Err(ProviderError::Correlation("wire mutation was accepted"));
        }
    }
    Ok(())
}

/// Checks local authorization failures against the genuine attached original.
#[cfg(test)]
fn verify_local_refusals(
    installed: &SourcePublicReferenceInstallation,
    guard: &mut CnpLaunchGuard,
    plan: &SourceResendPlan,
    qualifier: &ResendQualification<'_>,
    transmissions: &TransmissionObservationHandle,
) -> Result<(), ProviderError> {
    let before = canonical::canonical_json(
        &serde_json::to_value(transmissions.snapshot(MAXIMUM_SNAPSHOT_BYTES)?)
            .map_err(crucible_node_contract::ContractError::from)?,
    )?;
    let changed = vec![Id::new("unplanned-original")?];
    let duplicate = vec![plan.requests()[0].clone(), plan.requests()[0].clone()];
    for (qualification, ids) in [
        (installed as &dyn CnpReferenceQualification, plan.requests()),
        (
            qualifier as &dyn CnpReferenceQualification,
            changed.as_slice(),
        ),
        (
            qualifier as &dyn CnpReferenceQualification,
            duplicate.as_slice(),
        ),
        (qualifier as &dyn CnpReferenceQualification, &[]),
    ] {
        let Err(error) = guard.resend_pre_realization_originals(qualification, ids) else {
            return Err(ProviderError::Correlation(
                "unplanned source resend was allowed",
            ));
        };
        if error.effects != EffectKnowledge::None {
            return Err(ProviderError::Correlation(
                "local source resend refusal claimed effects",
            ));
        }
        let after = canonical::canonical_json(
            &serde_json::to_value(transmissions.snapshot(MAXIMUM_SNAPSHOT_BYTES)?)
                .map_err(crucible_node_contract::ContractError::from)?,
        )?;
        if after != before {
            return Err(ProviderError::Correlation(
                "local source refusal transmitted a frame",
            ));
        }
    }
    Ok(())
}
