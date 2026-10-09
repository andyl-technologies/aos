//! Assembles original live public-window evidence and independent oracle facts.
//!
//! The output is a bounded observation artifact. It covers the declared window
//! properties only; it neither invents other case results nor grants ledger
//! acceptance, Ready, repeatability or native continuation support.

use serde::Serialize;
use std::{collections::BTreeSet, io::Write};

use crucible_node_contract::{Bytes, ContentRef, Validate, canonical};
use crucible_node_provider::{
    ProviderError,
    bodies::{
        BeginArguments, MethodResult, RequestBody, ResponseShape, decode_request, decode_response,
    },
    client::{ObservationHandle, ObservationLimits, RecordedReferenceObservation},
    envelope::{Envelope, Method, RequestOrigin},
};

use crate::node_qualification::{
    ReferenceOracleContract, ReferenceOracleResult, ReferenceWindowObservation,
    verify_reference_windows,
};

use super::installation::SourcePublicReferenceInstallation;

/// Contains original evidence bytes without assigning a qualification verdict.
pub(super) struct OriginalPublicWindowWitness {
    pub(super) reference: ContentRef,
    pub(super) bytes: Bytes,
}

#[derive(Serialize)]
struct WindowWitness<'a> {
    schema: &'static str,
    implementation: &'a ContentRef,
    source_enrollment: &'a super::native::NativePublicEnrollment,
    observations: &'a RecordedReferenceObservation,
    windows: &'a [ReferenceWindowObservation],
    independent_oracle: &'a ReferenceOracleResult,
    lifecycle: &'a super::lifecycle_witness::LifecycleObservation,
}

struct SerializationBudget(usize);

impl Write for SerializationBudget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|count| *count <= 16 * 1024 * 1024)
            .ok_or_else(|| std::io::Error::other("original window witness byte ceiling"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Validates the complete predeclared window population against actual custody.
pub(super) fn collect_original_windows(
    installation: &SourcePublicReferenceInstallation,
    observations: &ObservationHandle,
    contract: &ReferenceOracleContract,
    activation: &crucible::node_contract::WorldActivation,
    windows: &[ReferenceWindowObservation],
) -> Result<OriginalPublicWindowWitness, ProviderError> {
    if windows.is_empty()
        || windows.len() > 16
        || contract.maximum_windows > 16
        || contract.owner != installation.bootstrap.owner_id
        || contract.incarnation != installation.bootstrap.authority.incarnation_id
        || contract.generation != installation.bootstrap.authority.owner_generation
        || contract.quantum_ps != installation.bootstrap.quantum_ps
        || contract.host_budget_ns != installation.bootstrap.host_budget_ns
    {
        return Err(ProviderError::Correlation(
            "original window witness scope differs",
        ));
    }
    let enrollment = installation.enrollment()?;
    enrollment.authenticate(
        &installation.package,
        &installation.bootstrap.resource_limits,
    )?;
    let keys = observations.request_keys()?;
    let references = observations.content_references()?;
    let recorded = observations.snapshot(
        &keys,
        &references,
        ObservationLimits {
            maximum_requests: 1024,
            maximum_objects: 1024,
            maximum_bytes: 8 * 1024 * 1024,
        },
    )?;
    if !recorded.recording_complete
        || recorded.observed_unknown
        || recorded.recording_failure.0.is_some()
    {
        return Err(ProviderError::Correlation(
            "original public observation population incomplete",
        ));
    }
    let source = &recorded.evidence;
    let (binding, _) = installation.profile.bind_qualified(
        installation.bootstrap.authority.clone(),
        &installation.qualifications,
    )?;
    if source.scope.selected_features != super::unit::required_features()?
        || source.scope.provider_executable
            != *installation
                .package
                .artifact_content("provider")
                .map_err(package_error)?
        || source.scope.session_id != installation.bootstrap.authority.session_id
        || source.scope.incarnation_id != installation.bootstrap.authority.incarnation_id
        || source.scope.compatibility != binding.compatibility
        || source.scope.binding_hash != binding.identity()?
    {
        return Err(ProviderError::Correlation(
            "native window observations belong to another realization",
        ));
    }
    let mut begun = BTreeSet::new();
    let mut closed = BTreeSet::new();
    for original in &source.requests {
        if original.key.origin != RequestOrigin::Controller {
            continue;
        }
        let request = Envelope::decode(original.request.bytes.as_slice(), 1_048_576)?;
        if !matches!(request.method, Method::Begin | Method::QuantumClose) {
            continue;
        }
        let body = decode_request(request.method, &request.body)?;
        let matching = match &body {
            RequestBody::Begin(begin) => match begin.decoded_arguments()? {
                BeginArguments::QuantumBegin(arguments) => Some(arguments.grant_id),
                _ => None,
            },
            RequestBody::QuantumClose(close) => Some(close.grant_id.clone()),
            _ => None,
        };
        let Some(window) = matching else {
            continue;
        };
        let observed = windows
            .iter()
            .find(|observed| observed.original_grant.window_id == window)
            .ok_or(ProviderError::Correlation(
                "unplanned original native window observed",
            ))?;
        let response = original
            .response
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("native window response unknown"))?;
        let response = Envelope::decode(response.bytes.as_slice(), 1_048_576)?;
        let response = decode_response(&body, &response.body)?;
        if !matches!(response.shape, ResponseShape::Completed { .. }) {
            return Err(ProviderError::Correlation(
                "native window did not originally complete",
            ));
        }
        match response.result {
            Some(MethodResult::QuantumBegin(result))
                if result.physical_measurement_ref == observed.receipt =>
            {
                if !begun.insert(window) {
                    return Err(ProviderError::Correlation(
                        "duplicate original window Begin",
                    ));
                }
            }
            Some(MethodResult::QuantumClose(result)) if result.grant_id == window => {
                if !closed.insert(window) {
                    return Err(ProviderError::Correlation(
                        "duplicate original window Close",
                    ));
                }
            }
            _ => {
                return Err(ProviderError::Correlation(
                    "original public window response differs",
                ));
            }
        }
    }
    let expected = windows
        .iter()
        .map(|window| window.original_grant.window_id.clone())
        .collect::<BTreeSet<_>>();
    if expected.len() != windows.len() || begun != expected || closed != expected {
        return Err(ProviderError::Correlation(
            "original native window controls incomplete",
        ));
    }
    for window in windows {
        for (reference, bytes) in [
            (&window.receipt, &window.receipt_bytes),
            (&window.payload, &window.payload_bytes),
        ] {
            reference.validate()?;
            reference.verify(bytes.as_slice())?;
            if !source
                .objects
                .iter()
                .any(|object| &object.reference == reference && &object.bytes == bytes)
            {
                return Err(ProviderError::Correlation(
                    "native window bytes absent from original transferred custody",
                ));
            }
        }
    }
    let lifecycle = super::lifecycle_witness::verify(installation, source, activation, windows)?;
    let oracle = verify_reference_windows(contract, windows)
        .map_err(|error| ProviderError::Io(std::io::Error::other(error.to_string())))?;
    // Preflight base64 and nested-control expansion before constructing a JSON
    // tree or owned serialized output. Preserve the inert archive's truthful
    // canonical-envelope label and latest-response scope unchanged.
    let witness = WindowWitness {
        schema: "crucible.reference.native-window-observation.v1",
        implementation: installation.package.identity(),
        source_enrollment: &enrollment,
        observations: &recorded,
        windows,
        independent_oracle: &oracle,
        lifecycle: &lifecycle,
    };
    let mut budget = SerializationBudget(0);
    serde_json::to_writer(&mut budget, &witness)
        .map_err(crucible_node_contract::ContractError::from)?;
    let value =
        serde_json::to_value(&witness).map_err(crucible_node_contract::ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(ProviderError::ResourceExhausted(
            "original native window witness serialization",
        ));
    }
    let reference = canonical::content_ref(&bytes, "application/json")?;
    Ok(OriginalPublicWindowWitness {
        reference,
        bytes: Bytes::new(bytes),
    })
}

fn package_error(error: super::super::NodeObservedError) -> ProviderError {
    ProviderError::Io(std::io::Error::other(error.to_string()))
}
