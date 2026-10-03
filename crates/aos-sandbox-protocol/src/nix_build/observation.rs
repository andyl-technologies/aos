//! Canonical nonauthorizing V2 observation and exact original-request linkage.
//!
//! ```text
//! AOSNXO02 | canonical-json-length:u32be | canonical JSON
//! ```
//!
//! The fixed lower physical owner independently verifies signed frame origin,
//! current Query52 lineage, actual root custody and portable backing. Parsing
//! this carrier cannot substitute any of those live checks.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_core::ObjectDigest;
use serde::{Deserialize, Serialize};

use super::{
    NIX_MAXIMUM_OBJECTS_V2, NIX_MAXIMUM_OUTPUTS_V2, NIX_RESPONSE_MAXIMUM_BYTES_V2,
    NixBuildSchemaErrorV2, NixExpectedOutputV2, NixStoreObjectV2, ValidatedNixBuildRequestV2,
};
use crate::ProtocolValidationError;

const MAGIC: &[u8; 8] = b"AOSNXO02";
const HEADER_BYTES: usize = 12;

/// Describes one claimed fixed-domain observation without granting currentness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NixBuildObservationV2 {
    /// Exact closed method50,51or52 whose signed response carries this object.
    pub method: u16,
    /// Method-separated canonical original request body commitment.
    pub request: ObjectDigest,
    /// Original durable Controller parent operation.
    pub operation: [u8; 16],
    /// Exact independently signed recipe artifact identity.
    pub recipe: ObjectDigest,
    /// Exact admitted fixed physical domain identity.
    pub domain: ObjectDigest,
    /// Original disclosure coordinate, not permission for unrelated path reads.
    pub disclosure: ObjectDigest,
    /// Exact selected Environment portable descriptor digest.
    pub environment: ObjectDigest,
    /// Genuine retained public Start admission carrier identity.
    pub parent_admission: ObjectDigest,
    /// Exact observed recipe input-map identity.
    pub input_presentation: ObjectDigest,
    /// Exact independently admitted predicted output-map identity.
    pub expected_output_map: ObjectDigest,
    /// Exact retained pre-effect build transaction; absent for Resolve.
    pub build_transaction: Option<ObjectDigest>,
    /// Original signed Realize request identity; required only by Query52.
    pub original_realization: Option<ObjectDigest>,
    /// Owner-retained attempt identity; absent before realization.
    pub attempt: Option<ObjectDigest>,
    /// Owner-retained complete root-set receipt; absent before realization.
    pub retained_roots: Option<ObjectDigest>,
    /// Complete actual observed recipe input closure, never predicted outputs.
    pub inputs: Vec<NixStoreObjectV2>,
    /// Exact actual output readback set; empty for Resolve.
    pub outputs: Vec<NixExpectedOutputV2>,
}

impl NixBuildObservationV2 {
    /// Encodes one bounded canonical shape without signing or admitting it.
    ///
    /// # Errors
    /// Rejects malformed maps, invalid sentinels or the complete carrier bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NixBuildSchemaErrorV2> {
        self.validate()?;
        let json = serde_json::to_vec(self).map_err(NixBuildSchemaErrorV2::Json)?;
        let length = u32::try_from(json.len()).map_err(|_| NixBuildSchemaErrorV2::Invalid)?;
        let total = HEADER_BYTES.checked_add(json.len()).ok_or(NixBuildSchemaErrorV2::Invalid)?;
        if total > NIX_RESPONSE_MAXIMUM_BYTES_V2 {
            return Err(NixBuildSchemaErrorV2::Invalid);
        }

        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&json);
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), NixBuildSchemaErrorV2> {
        if !matches!(self.method, 50..=52)
            || self.operation == [0; 16]
            || [self.request, self.recipe, self.domain, self.disclosure, self.environment,
                self.parent_admission, self.input_presentation, self.expected_output_map]
                .iter().any(|digest| digest.as_bytes() == &[0; 32])
            || [self.build_transaction, self.original_realization, self.attempt, self.retained_roots]
                .iter().flatten().any(|digest| digest.as_bytes() == &[0; 32])
            || self.inputs.is_empty()
            || self.inputs.len() > NIX_MAXIMUM_OBJECTS_V2
            || !self.inputs.windows(2).all(|pair| pair[0].path < pair[1].path)
            || self.outputs.len() > NIX_MAXIMUM_OUTPUTS_V2
            || !self.outputs.windows(2).all(|pair| pair[0].name < pair[1].name)
        {
            return Err(NixBuildSchemaErrorV2::Invalid);
        }
        let mut reconstruction_records = 0_usize;
        for input in &self.inputs {
            input.validate()?;
            reconstruction_records = reconstruction_records.checked_add(input.portable_objects.len())
                .ok_or(NixBuildSchemaErrorV2::Invalid)?;
        }
        for output in &self.outputs {
            if !super::valid_output_name(&output.name) {
                return Err(NixBuildSchemaErrorV2::Invalid);
            }
            output.object.validate()?;
            reconstruction_records = reconstruction_records.checked_add(output.object.portable_objects.len())
                .ok_or(NixBuildSchemaErrorV2::Invalid)?;
            if self.inputs.iter().any(|input| input.path == output.object.path)
                || self.outputs.iter().filter(|other| other.object.path == output.object.path).count() != 1
            {
                return Err(NixBuildSchemaErrorV2::Invalid);
            }
        }
        let resolve = self.method == 50;
        if reconstruction_records > NIX_MAXIMUM_OBJECTS_V2
            || resolve != self.outputs.is_empty()
            || resolve != self.build_transaction.is_none()
            || resolve != self.attempt.is_none()
            || resolve != self.retained_roots.is_none()
            || (self.method == 52) != self.original_realization.is_some()
        {
            return Err(NixBuildSchemaErrorV2::Invalid);
        }
        Ok(())
    }
}

/// Decodes a bounded canonical observation against its exact original request.
///
/// # Errors
/// Rejects truncation, trailing data, unknown fields, noncanonical shape,
/// cross-method substitution and changed original coordinates.
pub fn decode_nix_build_observation_v2(
    bytes: &[u8],
    request: &ValidatedNixBuildRequestV2,
) -> Result<NixBuildObservationV2, ProtocolValidationError> {
    compare_nix_build_observation_v2(bytes, &request.comparison())
}

pub(super) fn compare_nix_build_observation_v2(
    bytes: &[u8],
    request: &super::NixRequestComparisonV2<'_>,
) -> Result<NixBuildObservationV2, ProtocolValidationError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > NIX_RESPONSE_MAXIMUM_BYTES_V2
        || !bytes.starts_with(MAGIC)
    {
        return Err(ProtocolValidationError::InvalidField("Nix observation framing"));
    }
    let length = u32::from_be_bytes(bytes[8..12].try_into()
        .map_err(|_| ProtocolValidationError::InvalidField("Nix observation length"))?) as usize;
    if HEADER_BYTES.checked_add(length) != Some(bytes.len()) {
        return Err(ProtocolValidationError::InvalidField("Nix observation length"));
    }
    let observation: NixBuildObservationV2 = serde_json::from_slice(&bytes[HEADER_BYTES..])
        .map_err(|_| ProtocolValidationError::InvalidField("Nix observation JSON"))?;
    if observation.canonical_bytes().map_err(|_| ProtocolValidationError::InvalidField("Nix observation shape"))? != bytes {
        return Err(ProtocolValidationError::InvalidField("Nix observation canonical encoding"));
    }

    let wire = request.wire();
    let method = match request.method() {
        BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2 => 50,
        BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2 => 51,
        BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2 => 52,
        _ => return Err(ProtocolValidationError::MethodMismatch),
    };
    if observation.method != method || observation.request.as_bytes() != &request.commitment()
        || observation.operation.as_slice() != wire.operation_id
        || observation.recipe.as_bytes().as_slice() != wire.recipe_digest
        || observation.domain.as_bytes().as_slice() != wire.domain_digest
        || observation.disclosure.as_bytes().as_slice() != wire.disclosure_digest
        || observation.environment.as_bytes().as_slice() != wire.environment_digest
        || observation.parent_admission.as_bytes().as_slice() != wire.parent_admission_digest
        || observation.input_presentation.as_bytes().as_slice() != wire.input_presentation_digest
        || observation.expected_output_map.as_bytes().as_slice() != wire.expected_output_map_digest
        || observation.build_transaction.map(|digest| digest.as_bytes().to_vec()).unwrap_or_default() != wire.build_transaction_digest
        || observation.original_realization.map(|digest| digest.as_bytes().to_vec()).unwrap_or_default() != wire.original_realization_digest
    {
        return Err(ProtocolValidationError::InvalidField("Nix observation original coordinates"));
    }
    Ok(observation)
}
