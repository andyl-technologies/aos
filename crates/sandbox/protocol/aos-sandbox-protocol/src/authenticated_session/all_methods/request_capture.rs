//! Actual retained Inventory and Prepare request DATA through historical comparison.
//!
//! These actual selected methods share ordinary admission and retain reached
//! Core authorization, protobuf, canonical and traffic DATA. Other selected
//! methods still need their own reached-prefix closure.

use super::*;
use aos_sandbox_api::aos::sandbox::local::v1::InventoryStorageRequest;
use aos_sandbox_broker_session_protocol::projection::{
    CanonicalBrokerRequestDecodeCaptureV1, CanonicalBrokerRequestEnvelopeV1,
};
use aos_sandbox_broker_session_protocol::traffic::BrokerRequestAdmissionCaptureV1;

/// Retains the same Inventory/Prepare request and authenticated admission.
///
/// This is comparison DATA, never a Session, Journal, effect or receiving grant.
#[derive(Default)]
pub struct AuthenticatedBrokerMethodRequestCaptureV1 {
    pub(super) canonical_decode: CanonicalBrokerRequestDecodeCaptureV1,
    pub(super) canonical: Option<CanonicalBrokerRequestEnvelopeV1>,
    pub(super) raw_envelope: BrokerRequestEnvelope,
    pub(super) envelope: Option<ValidatedBrokerRequestEnvelope>,
    pub(super) body: RequestBodyCaptureV1,
    pub(super) authorization: crate::session::AuthorizationArtifactsCaptureV1,
    pub(super) semantic: Option<ValidatedRequestSemanticV1>,
    pub(super) traffic: BrokerRequestAdmissionCaptureV1,
    pub(super) admission: Option<BrokerRequestAdmissionV1>,
    pub(super) replay: Option<BrokerSessionReplayEvidenceV1>,
    result: Option<Result<AuthenticatedBrokerMethodRequestAdmissionV1, AuthenticatedBrokerMethodErrorV1>>,
    attempted: bool,
    closed: Option<AuthenticatedBrokerMethodErrorV1>,
}

impl AuthenticatedBrokerMethodRequestCaptureV1 {
    /// Constructs inert destinations without allocation or admission.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Borrows the first returned admission classification.
    #[must_use]
    pub fn failure(&self) -> Option<&AuthenticatedBrokerMethodErrorV1> {
        self.result.as_ref().and_then(|result| result.as_ref().err()).or(self.closed.as_ref())
    }

    /// Borrows the actual reached decoder or cryptographic cause first.
    #[must_use]
    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.canonical_decode.failure().map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.authorization.cause()).or_else(|| self.body.cause())
            .or_else(|| self.traffic.cause())
            .or_else(|| self.failure().map(|cause| cause as _))
    }

    /// Borrows the same Host1 model validated by the retained request engine.
    ///
    /// This performs no second decode and lends no native or live authority.
    #[doc(hidden)]
    pub fn retained_host_apply_runtime_data_v2(&self) -> Option<&crate::ValidatedRuntimeRequest> {
        if self.failure().is_some() { return None; }
        self.body.host_runtime.as_ref()
    }

    /// Borrows complete admission DATA while its candidate traffic stays held.
    #[must_use]
    pub fn value(&self) -> Option<&AuthenticatedBrokerMethodRequestAdmissionV1> {
        if self.closed.is_some() { return None; }
        self.result.as_ref()?.as_ref().ok()
    }

    /// Moves the actual completed request admission to its real writer once.
    ///
    /// # Errors
    /// Refuses failed, incomplete, repeated or already moved admission state.
    #[doc(hidden)]
    pub fn take_admission_once_v1(&mut self)
        -> Result<AuthenticatedBrokerMethodRequestAdmissionV1, AuthenticatedBrokerMethodErrorV1> {
        if let Some(cause) = self.failure() { return Err(cause.clone()); }
        self.result.take().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?
    }

    /// Runs the existing request engine once with actual destinations.
    ///
    /// # Errors
    /// Refuses reentry, another selected method, forbidden Inventory authority
    /// carriers or the ordinary canonical, authorization, header and traffic checks.
    #[allow(clippy::too_many_arguments)]
    pub fn capture_once_v1(
        &mut self,
        direction: AuthenticatedBrokerRequestDirectionV1,
        traffic: &BrokerSessionTrafficStateV1,
        bytes: &[u8],
        retained_replay: Option<&AuthenticatedBrokerMethodRequestV1>,
        actual_descriptor_count: usize,
        peer: PeerCredentials,
        policy: PeerPolicy,
        now: u64,
        bindings: AuthenticatedBrokerSemanticBindingsV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<(), AuthenticatedBrokerMethodErrorV1> {
        if self.attempted {
            self.closed.get_or_insert(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
        }
        self.attempted = true;
        let result = super::admit_authenticated_broker_method_request_engine(direction,
            traffic, bytes, retained_replay, actual_descriptor_count, peer, policy, now,
            bindings, context, Some(self));
        let returned = result.as_ref().map(|_| ()).map_err(Clone::clone);
        self.result = Some(result);
        returned
    }

    // Preserve the existing retained diagnostic backing budget in memory.
    // These bounded decoder/admission destinations are not namespace entries.
    fn diagnostic_receiving_bytes_v1() -> Option<u64> {
        let destinations = 33usize
            // Two actual Network decoder lanes retain decode/result/entry.
            .checked_add(2usize.checked_mul(3)?)?
            .checked_add(CanonicalBrokerRequestDecodeCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(BrokerRequestAdmissionCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(aos_sandbox_model::format::authorization_capture::authorization_artifact_metadata_cells_v1()?)?;
        u64::try_from(destinations).ok()?.checked_mul(256)
    }

    /// Prices dynamic request memory excluding its embedded inline owner.
    ///
    /// The genuine payer must derive P from the same complete captured history
    /// prefix containing this request and HELLO records, and debit before work.
    /// Prior-history replay is separately paid by its actual caller. This
    /// request capsule creates no path or durable key/index: its protobuf,
    /// authorization and parser collections are model memory. The Session
    /// schema separately prices its actual durable request/transaction indexes.
    #[must_use]
    pub fn dynamic_receiving_demand_v1(actual_prefix_bytes: usize)
        -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        use aos_sandbox_broker_session_protocol::receiving_geometry::schema_protobuf_carriers_v1;
        let p = u64::try_from(actual_prefix_bytes).ok()?;
        // Outer canonical model, raw envelope clone, body partial/model,
        // signed packet and final request/state replacement overlap.
        // Two reached Prepare raw bodies include nested header and fence.
        // Four further lanes cover canonical outer/raw clone and replacement.
        let models = schema_protobuf_carriers_v1(p, 2).ok()?.checked_mul(8)?;
        let (authorization_bytes, _) =
            aos_sandbox_model::format::authorization_capture::authorization_artifact_dynamic_footprint_v1(actual_prefix_bytes)?;
        let bytes = p.checked_mul(8)?.checked_add(models)?.checked_add(authorization_bytes)?
            // Network's canonical encoder starts at512; Storage's at400.
            // The same two actual header/context lanes use the larger bound.
            .checked_add(2u64.checked_mul(512)?)?
            .checked_add(u64::try_from(2usize.checked_mul(std::mem::size_of::<BrokerSessionTrafficStateV1>())?).ok()?)?
            .checked_add(u64::try_from(aos_sandbox_broker_session_protocol::artifact::BrokerSessionArtifactVerifyCaptureV1::receiving_heap_bytes_v1()?).ok()?)?
            .checked_add(Self::diagnostic_receiving_bytes_v1()?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    /// Bounds the additional two actual workspace metadata decode passes.
    ///
    /// This is passive geometry. The same payer must already fund the ordinary
    /// request invoice and actual fixed capture owner before calling it.
    #[must_use]
    pub fn storage_apply_additional_receiving_demand_v1(actual_prefix_bytes: usize)
        -> Option<aos_sandbox_model::ResourceVector>
    {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let (bytes, entries) = crate::semantics::storage::workspace_metadata_receiving_obligations_v1(
            actual_prefix_bytes, actual_prefix_bytes)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?.checked_mul(2)?)
            .with(D::MetadataEntries, u64::try_from(entries).ok()?.checked_mul(2)?))
    }

}

#[derive(Default)]
pub(super) struct InventoryBodyCaptureV1 {
    raw: InventoryStorageRequest,
    decode: Option<Result<(), buffa::DecodeError>>,
    result: Option<Result<ValidatedHeader, ProtocolValidationError>>,
}

impl InventoryBodyCaptureV1 {
    pub(super) fn decode_once(&mut self, bytes: &[u8], peer: PeerCredentials, policy: PeerPolicy, now: u64)
        -> Result<ValidatedHeader, ProtocolValidationError> {
        if self.result.is_some() { return Err(ProtocolValidationError::MethodMismatch); }
        self.result = Some(crate::storage_inventory::decode_storage_resource_inventory_request_engine(
            bytes, peer, policy, now, Some((&mut self.raw, &mut self.decode))));
        self.result.as_ref().ok_or(ProtocolValidationError::MethodMismatch)?
            .as_ref().copied().map_err(Clone::clone)
    }

    fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.decode.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}

pub(super) fn traffic_admission_value(
    traffic: &BrokerSessionTrafficStateV1,
    canonical: &CanonicalBrokerRequestEnvelopeV1,
    request_id: [u8; 16],
    maximum: u32,
    context: &ProtectedBrokerSessionVerificationContextV1,
    capture: Option<&mut BrokerRequestAdmissionCaptureV1>,
) -> Result<BrokerRequestAdmissionV1, BrokerSessionSequenceError> {
    match capture {
        Some(capture) => {
            traffic.admit_request_retaining(canonical, request_id, maximum, context, capture)?;
            capture.take_admission_once()
        }
        None => traffic.admit_request(canonical, request_id, maximum, context),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_api::aos::sandbox::local::v1::{Audience, RequestHeader};
    use buffa::Message as _;

    fn peer() -> PeerCredentials { PeerCredentials { uid: 7, gid: 8, pid: Some(9) } }

    fn policy() -> PeerPolicy {
        PeerPolicy { uid: 7, gid: Some(8), audience: Audience::AUDIENCE_NODE_CONTROLLER }
    }

    fn request() -> InventoryStorageRequest {
        InventoryStorageRequest { header: Some(RequestHeader {
            protocol_major: 1, protocol_minor: 0, request_id: vec![3; 16],
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: 100, maximum_response_bytes: 4096,
            ..Default::default()
        }).into(), ..Default::default() }
    }

    #[test]
    fn incomplete_late_field_keeps_actual_prior_header_and_decode_cause() {
        let mut bytes = request().encode_to_vec();
        bytes.push(0x80);
        let mut original = InventoryBodyCaptureV1::default();

        assert!(original.decode_once(&bytes, peer(), policy(), 1).is_err());

        assert_eq!(original.raw.header.as_option().unwrap().request_id, vec![3; 16]);
        let cause = original.decode.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::eq(cause, original.cause().unwrap().downcast_ref::<buffa::DecodeError>().unwrap()));
        let first = cause as *const buffa::DecodeError;
        assert!(original.decode_once(&[], peer(), policy(), 1).is_err());
        assert!(std::ptr::eq(first, original.decode.as_ref().unwrap().as_ref().unwrap_err()));
    }

    #[test]
    fn header_peer_error_keeps_actual_complete_message_and_ordinary_error_class() {
        let bytes = request().encode_to_vec();
        let mut original = InventoryBodyCaptureV1::default();
        let wrong = PeerCredentials { uid: 99, ..peer() };

        let retained = original.decode_once(&bytes, wrong, policy(), 1).unwrap_err();
        let ordinary = crate::decode_storage_resource_inventory_request(&bytes, wrong, policy(), 1).unwrap_err();

        assert_eq!(retained, ordinary);
        assert!(matches!(original.decode, Some(Ok(()))));
        assert!(original.raw.header.as_option().is_some());
        assert_eq!(original.raw.header.as_option().unwrap().request_id, vec![3; 16]);
    }

    #[test]
    fn excessive_request_refuses_before_partial_decoder_entry() {
        let bytes = vec![0; crate::MAXIMUM_REQUEST_BYTES + 1];
        let mut original = InventoryBodyCaptureV1::default();

        assert!(matches!(original.decode_once(&bytes, peer(), policy(), 1), Err(ProtocolValidationError::RequestTooLarge)));

        assert!(original.decode.is_none());
        assert!(original.raw.header.as_option().is_none());
    }
}


#[derive(Default)]
pub(super) struct RequestBodyCaptureV1 {
    pub(super) host_runtime: Option<crate::ValidatedRuntimeRequest>,
    pub(super) inventory: InventoryBodyCaptureV1,
    pub(super) preparation_header: PreparationBodyCaptureV1,
    pub(super) preparation_context: PreparationBodyCaptureV1,
    pub(super) apply_header: ApplyBodyCaptureV1,
    pub(super) apply_context: ApplyBodyCaptureV1,
    pub(super) network_header: NetworkBodyCaptureV4,
    pub(super) network_context: NetworkBodyCaptureV4,
}

impl RequestBodyCaptureV1 {
    fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inventory.cause().or_else(|| self.preparation_header.cause())
            .or_else(|| self.preparation_context.cause())
            .or_else(|| self.apply_header.cause()).or_else(|| self.apply_context.cause())
            .or_else(|| self.network_header.cause()).or_else(|| self.network_context.cause())
    }
}

#[derive(Default)]
pub(super) struct PreparationBodyCaptureV1 {
    raw: aos_sandbox_api::aos::sandbox::local::v1::PrepareStorageCatalogRequest,
    decode: Option<Result<(), buffa::DecodeError>>,
    canonical: Vec<u8>,
    result: Option<Result<CanonicalStoragePreparationSemanticsV1,
        crate::semantics::StoragePreparationSemanticsError>>,
    entered: bool,
}

impl PreparationBodyCaptureV1 {
    pub(super) fn decode_once(&mut self, bytes: &[u8], peer: PeerCredentials,
        policy: PeerPolicy, now: u64) -> Result<CanonicalStoragePreparationSemanticsV1,
        crate::semantics::StoragePreparationSemanticsError> {
        if self.entered { return Err(ProtocolValidationError::MethodMismatch.into()); }
        self.entered = true;
        self.result = Some(CanonicalStoragePreparationSemanticsV1::decode_engine(bytes, peer,
            policy, now, Some((&mut self.raw, &mut self.decode, &mut self.canonical))));
        match self.result.as_ref() {
            Some(Ok(_)) => {},
            Some(Err(cause)) => return Err(cause.clone()),
            None => return Err(ProtocolValidationError::MethodMismatch.into()),
        }
        self.result.take().ok_or(ProtocolValidationError::MethodMismatch)?
    }

    fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.decode.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}

#[derive(Default)]
pub(super) struct NetworkBodyCaptureV4 {
    raw: aos_sandbox_api::aos::sandbox::local::v1::ApplyNetworkRequest,
    decode: Option<Result<(), buffa::DecodeError>>,
    result: Option<Result<CanonicalNetworkSemanticsV1, crate::semantics::network::NetworkSemanticsError>>,
    entered: bool,
}

impl NetworkBodyCaptureV4 {
    pub(super) fn decode_once(&mut self, bytes: &[u8], peer: PeerCredentials,
        policy: PeerPolicy, now: u64)
        -> Result<CanonicalNetworkSemanticsV1, crate::semantics::network::NetworkSemanticsError> {
        if self.entered { return Err(ProtocolValidationError::MethodMismatch.into()); }
        self.entered = true;
        self.result = Some(CanonicalNetworkSemanticsV1::decode_engine_v4(bytes, peer, policy,
            now, Some((&mut self.raw, &mut self.decode))));
        match self.result.as_ref() {
            Some(Ok(_)) => {}, Some(Err(cause)) => return Err(cause.clone()),
            None => return Err(ProtocolValidationError::MethodMismatch.into()),
        }
        self.result.take().ok_or(ProtocolValidationError::MethodMismatch)?
    }

    fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.decode.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

// The two actual request-engine passes retain distinct raw/semantic prefixes.
// This closed DATA capsule cannot authorize Apply or create a live Session.
#[derive(Default)]
pub(super) struct ApplyBodyCaptureV1 {
    raw: aos_sandbox_api::aos::sandbox::local::v1::ApplyStorageRequest,
    decode: Option<Result<(), buffa::DecodeError>>,
    workspace: Option<crate::semantics::storage::CanonicalStorageWorkspaceMetadataV1>,
    canonical: Vec<u8>,
    result: Option<Result<CanonicalStorageSemanticsV1, crate::semantics::StorageSemanticsError>>,
    entered: bool,
}

impl ApplyBodyCaptureV1 {
    pub(super) fn decode_once(&mut self, bytes: &[u8], catalog: crate::semantics::CatalogBindingV1,
        peer: PeerCredentials, policy: PeerPolicy, now: u64)
        -> Result<CanonicalStorageSemanticsV1, crate::semantics::StorageSemanticsError>
    {
        if self.entered { return Err(ProtocolValidationError::MethodMismatch.into()); }
        self.entered = true;
        self.result = Some(CanonicalStorageSemanticsV1::decode_engine(bytes, catalog, peer, policy, now,
            Some((&mut self.raw, &mut self.decode, &mut self.workspace, &mut self.canonical))));
        match self.result.as_ref() {
            Some(Ok(_)) => {}, Some(Err(cause)) => return Err(cause.clone()),
            None => return Err(ProtocolValidationError::MethodMismatch.into()),
        }
        self.result.take().ok_or(ProtocolValidationError::MethodMismatch)?
    }

    fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.decode.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

#[cfg(test)]
mod apply_tests {
    use super::*;
    use aos_sandbox_api::aos::sandbox::local::v1::{ApplyStorageRequest, Audience, RequestHeader};
    use aos_sandbox_model::ObjectDigest;
    use buffa::Message as _;

    #[test]
    fn retained_apply_late_wire_error_keeps_the_same_partial_header_and_cause() {
        let request = ApplyStorageRequest { header: Some(RequestHeader {
            request_id: vec![9;16], ..Default::default()
        }).into(), ..Default::default() };
        let mut bytes = request.encode_to_vec();
        bytes.push(0x80);
        let mut actual = ApplyBodyCaptureV1::default();
        let catalog = crate::semantics::CatalogBindingV1::from_publisher(1, ObjectDigest::from_bytes([8;32])).unwrap();
        let peer = PeerCredentials { uid: 7, gid: 8, pid: Some(9) };
        let policy = PeerPolicy { uid: 7, gid: Some(8), audience: Audience::AUDIENCE_NODE_CONTROLLER };

        assert!(actual.decode_once(&bytes, catalog, peer, policy, 1).is_err());
        let cause = actual.decode.as_ref().unwrap().as_ref().unwrap_err();
        assert_eq!(actual.raw.header.as_option().unwrap().request_id, vec![9;16]);
        assert!(std::ptr::eq(cause, actual.cause().unwrap().downcast_ref::<buffa::DecodeError>().unwrap()));
        let identity = cause as *const buffa::DecodeError;

        assert!(actual.decode_once(&[], catalog, peer, policy, 1).is_err());
        assert!(std::ptr::eq(identity, actual.decode.as_ref().unwrap().as_ref().unwrap_err()));
    }
}

#[cfg(test)]
mod receiving_namespace_tests {
    use super::AuthenticatedBrokerMethodRequestCaptureV1;
    use aos_sandbox_model::ResourceDimension as D;

    #[test]
    fn larger_parser_inputs_add_memory_without_minting_namespace_entries() {
        let small = AuthenticatedBrokerMethodRequestCaptureV1::dynamic_receiving_demand_v1(128).unwrap();
        let large = AuthenticatedBrokerMethodRequestCaptureV1::dynamic_receiving_demand_v1(8192).unwrap();

        assert!(large.get(D::MemoryBytes) > small.get(D::MemoryBytes));
        for demand in [small, large] {
            assert_eq!(demand.get(D::MetadataEntries), 0);
            assert_eq!(demand.get(D::OpenFiles), 0);
        }
    }
}
