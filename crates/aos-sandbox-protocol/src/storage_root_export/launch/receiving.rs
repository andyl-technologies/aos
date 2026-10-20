//! Dominant byte representation for the complete original Host launch decoder.
//!
//! The list follows the eight-message ApplyRuntimeRequest protobuf closure and
//! its typed projections. Core owns the sole CBOR plan/signature/lease bound.
//! This recipe parses nothing and supplies neither funding nor admission.

use std::mem::size_of;

use aos_proto::aos::sandbox::local::v1 as wire;

use super::STORAGE_ROOT_LAUNCH_EXPORT_MAXIMUM_BYTES_V2;

/// Bounds the complete body, Guardian and original authorization model graph.
///
/// Every protobuf collection element or unknown field requires an actual wire
/// token. The largest real model width per input byte bounds even malformed
/// intermediate models before later validators reject them. Three planes pay
/// resident/constructor and simultaneous old/new collection backing. Three
/// additional raw planes pay the received frame, copied protobuf byte fields
/// and typed Guardian/model-error text. The Core helper separately bounds both
/// Host and embedded Guardian CBOR plans from their aggregate actual extent.
///
/// The actual enrolled Root/Ownership trust-policy verification bytes, upper
/// native carrier layout, native transport/files, saved State/catalog models
/// and worker demand must be added by their genuine owners. Rust model fields
/// and parser collections here are bytes, never namespace entries.
/// `None` reports overflow or a packet extent beyond the closed wire ceiling.
#[must_use]
pub fn decoding_receiving_bytes_v2(encoded_bytes: usize) -> Option<usize> {
    if encoded_bytes > STORAGE_ROOT_LAUNCH_EXPORT_MAXIMUM_BYTES_V2 {
        return None;
    }
    let widest = [
        size_of::<wire::ApplyRuntimeRequest>(),
        size_of::<wire::RequestHeader>(),
        size_of::<wire::AssignmentFence>(),
        size_of::<wire::RuntimePlan>(),
        size_of::<wire::Descriptor>(),
        size_of::<wire::ResourceLimit>(),
        size_of::<wire::Feature>(),
        size_of::<wire::GuardianArmCompanionV1>(),
        size_of::<buffa::UnknownField>(),
        size_of::<buffa::UnknownFieldData>(),
        size_of::<crate::LiveHostRuntimeEnvelopeDataV2>(),
        size_of::<crate::ValidatedRuntimeTemplateV1>(),
        size_of::<crate::ValidatedRuntimePlan>(),
        size_of::<crate::ValidatedResourceLimit>(),
        size_of::<aos_sandbox_core::FeatureRef>(),
        size_of::<aos_sandbox_core::ObjectDescriptor>(),
        size_of::<Vec<u8>>(),
        size_of::<[u8; 32]>(),
    ].into_iter().max()?;
    let models = widest.checked_mul(encoded_bytes)?.checked_mul(3)?;
    let raw = encoded_bytes.checked_mul(3)?;
    let (artifacts, _) = aos_sandbox_core::format::authorization_capture::
        authorization_artifact_plan_set_dynamic_footprint_v1(encoded_bytes, 2)?;
    let fixed = size_of::<super::StorageRootLaunchExportRequestV2<'_>>()
        .checked_add(size_of::<crate::LiveHostRuntimeEnvelopeDataV2>())?
        .checked_add(size_of::<aos_sandbox_core::VerifiedBrokerPlan>())?
        .checked_add(size_of::<aos_sandbox_core::VerifiedOwnershipLease>())?
        .checked_add(size_of::<crate::ProtocolValidationError>())?
        .checked_mul(3)?;
    models.checked_add(raw)?.checked_add(usize::try_from(artifacts).ok()?)?
        .checked_add(fixed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_excessive_frame_before_model_arithmetic() {
        assert!(decoding_receiving_bytes_v2(STORAGE_ROOT_LAUNCH_EXPORT_MAXIMUM_BYTES_V2).is_some());
        assert!(decoding_receiving_bytes_v2(STORAGE_ROOT_LAUNCH_EXPORT_MAXIMUM_BYTES_V2 + 1).is_none());
        assert!(decoding_receiving_bytes_v2(usize::MAX).is_none());
    }
}
