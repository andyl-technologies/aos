//! Once-only reached terminal DATA for closed Controller Inventory and Prepare.
//!
//! The ordinary all-method API remains unchanged. This explicitly bounded
//! retaining component refuses other selected methods before typed growth;
//! It reuses the ordinary method validators for the four fixed Inventory
//! methods. Their genuine caller must pay the method-specific decoder geometry
//! before entry; supporting DATA here creates no IO or financial authority.

use super::*;

mod pricing;
mod controller_inventory_pricing;
mod controller_inventory_model;
pub use controller_inventory_model::{ControllerInventoryModelDataV2,
    ControllerInventoryDecodedOriginalV2, decode_controller_inventory_model_v2};
use aos_sandbox_broker_session_protocol::projection::{
    CanonicalBrokerResponseDecodeCaptureV1, CanonicalBrokerResponseEnvelopeV1,
};
use aos_sandbox_broker_session_protocol::traffic::packet_capture::BrokerOutcomePacketAdmissionCaptureV1;
use crate::session::{ResponseEnvelopeCaptureV1, ValidatedBrokerResponseEnvelope};
use crate::storage_inventory::InventoryResponseCaptureV1;
use super::storage::PreparationResponseCaptureV1;

/// Binds one sole-decoded passive model to its exact canonical outcome packet.
///
/// Its private issuer is the actual completed capture below. It constructs no
/// native completion, current peer, receiving grant or effect authority.
#[doc(hidden)]
pub struct CapturedBrokerMethodModelDataV2<T> {
    model: T,
    packet_digest: [u8; 32],
}

impl<T> CapturedBrokerMethodModelDataV2<T> {
    /// Borrows the same capture's validated model without reparsing or cloning.
    #[must_use]
    pub const fn model_data_v2(&self) -> &T { &self.model }

    /// Returns SHA-256 of the exact original canonical authenticated packet.
    #[must_use]
    pub const fn outcome_packet_digest_data_v2(&self) -> [u8; 32] { self.packet_digest }

    /// Compares the complete original packet, including its signed envelope.
    #[must_use]
    pub fn matches_outcome_packet_data_v2(&self, packet: &[u8]) -> bool {
        use sha2::Digest as _;
        let actual: [u8; 32] = sha2::Sha256::digest(packet).into();
        actual == self.packet_digest
    }
}

/// Retains actual partial decoding, semantic prefixes and complete admission.
///
/// Values are comparison DATA, not a persisted CAS, authenticated native peer,
/// purpose grant, receiving original or permission to use an outcome.
#[derive(Default)]
pub struct AuthenticatedBrokerMethodOutcomeCaptureV1 {
    pub(super) packet: BrokerOutcomePacketAdmissionCaptureV1,
    pub(super) traffic_admission: Option<BrokerOutcomeAdmissionV1>,
    pub(super) verified_outcome: Option<aos_sandbox_broker_session_protocol::CryptographicallyVerifiedBrokerOutcomeV1>,
    pub(super) next_traffic: Option<Box<BrokerSessionTrafficStateV1>>,
    pub(super) replay: Option<BrokerSessionReplayEvidenceV1>,
    pub(super) canonical_decode: CanonicalBrokerResponseDecodeCaptureV1,
    pub(super) canonical: Option<CanonicalBrokerResponseEnvelopeV1>,
    pub(super) envelope_partial: ResponseEnvelopeCaptureV1,
    pub(super) envelope: Option<ValidatedBrokerResponseEnvelope>,
    pub(super) bodies: StorageBodyCaptureV1,
    result: Option<Result<AuthenticatedBrokerMethodOutcomeAdmissionV1, AuthenticatedBrokerMethodErrorV1>>,
    attempted: bool,
    closed: Option<AuthenticatedBrokerMethodErrorV1>,
}

impl AuthenticatedBrokerMethodOutcomeCaptureV1 {
    /// Constructs inert fixed destinations without allocation, IO or authority.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Borrows the first returned method-classification failure.
    #[must_use]
    pub fn failure(&self) -> Option<&AuthenticatedBrokerMethodErrorV1> {
        self.result.as_ref().and_then(|result| result.as_ref().err()).or(self.closed.as_ref())
    }

    /// Borrows the earliest reached lower decode, cryptographic or model cause.
    #[must_use]
    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.packet.cause()
            .or_else(|| self.canonical_decode.failure().map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.envelope_partial.failure())
            .or_else(|| self.bodies.cause())
            .or_else(|| self.failure().map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

    /// Borrows completed admission DATA while its actual owners stay resident.
    #[must_use]
    pub fn value(&self) -> Option<&AuthenticatedBrokerMethodOutcomeAdmissionV1> {
        if self.closed.is_some() { return None; }
        self.result.as_ref().and_then(|result| result.as_ref().ok())
    }

    /// Borrows the same canonically validated successful Apply body as DATA.
    ///
    /// This is available only with this capture's complete authenticated
    /// outcome. It grants no workspace, publication or native currentness.
    #[must_use]
    pub fn storage_apply_response_data_v1(&self)
        -> Option<&aos_proto::aos::sandbox::local::v1::StorageResult>
    {
        match self.value()? {
            AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, .. }
                if outcome.method() == BrokerMethod::BROKER_METHOD_STORAGE_APPLY => self.bodies.apply.value(),
            _ => None,
        }
    }

    /// Borrows this same authenticated Inventory's complete semantic and wire DATA.
    ///
    /// This supplies no native workspace, catalog authority or currentness.
    #[must_use]
    pub fn storage_inventory_response_data_v1(&self)
        -> Option<&(crate::storage_inventory::ValidatedStorageInventory,
            aos_proto::aos::sandbox::local::v1::InventoryStorageResourcesResponse)>
    {
        match self.value()? {
            AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, .. }
                if outcome.method() == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES => self.bodies.inventory.value(),
            _ => None,
        }
    }

    /// Borrows the sole validated Prepare26 response after its admission moved.
    ///
    /// The original successful decoder and complete authenticated/native owner
    /// remain separate requirements. This comparison DATA grants no catalog,
    /// physical resource, receiving capacity or permission to issue Apply7.
    #[doc(hidden)]
    #[must_use]
    pub fn retained_storage_preparation_response_data_v3(&self)
        -> Option<&aos_proto::aos::sandbox::local::v1::PrepareStorageCatalogResponse> {
        if self.failure().is_some() { return None; }
        self.bodies.preparation.value_v3()
    }

    /// Borrows the original validated Apply model after admission moved to its writer.
    ///
    /// This pure DATA view does not prove that writer's native CAS or posts.
    #[doc(hidden)]
    pub fn retained_storage_apply_response_data_v1(&self)
        -> Option<&aos_proto::aos::sandbox::local::v1::StorageResult> {
        if self.failure().is_some() { return None; }
        self.bodies.apply.value()
    }

    /// Borrows the original validated Inventory model after admission moved.
    ///
    /// Its caller separately retains the authenticated outcome and native owner.
    #[doc(hidden)]
    pub fn retained_storage_inventory_response_data_v1(&self)
        -> Option<&(crate::storage_inventory::ValidatedStorageInventory,
            aos_proto::aos::sandbox::local::v1::InventoryStorageResourcesResponse)> {
        if self.failure().is_some() { return None; }
        self.bodies.inventory.value()
    }

    /// Borrows the sole method31 decoder's complete current-publication DATA.
    ///
    /// The signed terminal and the actual protected completed Storage state
    /// remain independent requirements. This view confers no workspace grant.
    #[doc(hidden)]
    pub fn retained_storage_guest_root_response_data_v2(&self)
        -> Option<&crate::semantics::storage_guest_root::StorageGuestRootResponseDataV2>
    {
        if self.failure().is_some() {
            return None;
        }
        self.bodies.guest_root_publication.as_ref()?.as_ref().ok()
    }

    /// Borrows the same validated Network63 result after its admission moved.
    ///
    /// This DATA grants no native namespace, currentness or Root publication.
    #[doc(hidden)]
    pub fn retained_network_prepare_response_data_v4(&self)
        -> Option<&aos_proto::aos::sandbox::local::v1::NetworkResult> {
        if self.failure().is_some() { return None; }
        self.bodies.network_prepare.as_ref()?.as_ref().ok()
    }

    /// Borrows the sole-decoded Destroy9 result after actual terminal validation.
    ///
    /// This passive DATA supplies no worker acknowledgement or live authority.
    #[doc(hidden)]
    pub fn retained_network_destroy_response_data_v4(&self)
        -> Option<&aos_proto::aos::sandbox::local::v1::NetworkResult> {
        if self.failure().is_some() { return None; }
        self.bodies.network_apply.destroy_data_v4()
    }

    /// Borrows the same complete Network19 model after its admission moved.
    ///
    /// The actual signed terminal and native Session remain separately owed.
    #[doc(hidden)]
    pub fn retained_network_inventory_response_data_v4(&self)
        -> Option<&crate::ValidatedNetworkInventory> {
        if self.failure().is_some() { return None; }
        self.bodies.network_inventory.as_ref()?.as_ref().ok()
    }

    /// Borrows the sole decoded Host1 receipt retained by outcome validation.
    ///
    /// This DATA supplies no live Runtime, Guardian or native completion grant.
    #[doc(hidden)]
    pub fn retained_host_apply_observation_data_v2(&self)
        -> Option<&aos_proto::aos::sandbox::local::v1::RuntimeObservation> {
        if self.failure().is_some() { return None; }
        self.bodies.host_apply.as_ref()?.as_ref().ok()
    }

    /// Borrows the same sole Host3 decoder's complete canonical inventory DATA.
    ///
    /// The actual authenticated packet and native Session owner remain separate.
    /// This borrow performs no decoding and grants no runtime or currentness.
    #[doc(hidden)]
    pub fn retained_host_inventory_data_v2(&self)
        -> Option<&aos_proto::aos::sandbox::local::v1::InventoryRuntimeResponse> {
        if self.failure().is_some() { return None; }
        self.bodies.host_inventory.as_ref()?.as_ref().ok()
    }

    /// Borrows the actual sole Mount62 decoder's complete namespace resource.
    ///
    /// This comparison DATA supplies no native namespace or completion grant.
    #[doc(hidden)]
    pub fn retained_mount_namespace_result_data_v2(&self)
        -> Option<&crate::mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1> {
        if self.failure().is_some() { return None; }
        self.bodies.mount_namespace.as_ref()?.as_ref().ok()
    }

    /// Borrows the same complete Mount16 inventory after its admission moved.
    ///
    /// This DATA proves no native namespace or current assignment by itself.
    #[doc(hidden)]
    pub fn retained_mount_namespace_inventory_data_v2(&self) -> Option<&crate::ValidatedDestinationSlotInventory> {
        if self.failure().is_some() { return None; }
        self.bodies.mount_inventory.as_ref()?.as_ref().ok()
    }

    /// Moves the same sole-decoded Storage18 model with its canonical packet hash.
    ///
    /// Native custody, persisted CAS and Root completion remain separate.
    #[doc(hidden)]
    pub fn take_retained_storage_inventory_data_v2(&mut self)
        -> Option<CapturedBrokerMethodModelDataV2<(crate::ValidatedStorageInventory,
            aos_proto::aos::sandbox::local::v1::InventoryStorageResourcesResponse)>> {
        let packet_digest = self.model_packet_digest_data_v2()?;
        let model = self.bodies.inventory.take_value_data_v2()?;
        Some(CapturedBrokerMethodModelDataV2 { model, packet_digest })
    }

    /// Moves the sole Network19 model with its exact original packet association.
    #[doc(hidden)]
    pub fn take_retained_network_inventory_data_v2(&mut self)
        -> Option<CapturedBrokerMethodModelDataV2<crate::ValidatedNetworkInventory>> {
        let packet_digest = self.model_packet_digest_data_v2()?;
        let model = take_success_data_v2(&mut self.bodies.network_inventory)?;
        Some(CapturedBrokerMethodModelDataV2 { model, packet_digest })
    }

    /// Moves the sole Mount62 model with its exact original packet association.
    #[doc(hidden)]
    pub fn take_retained_mount_namespace_data_v2(&mut self)
        -> Option<CapturedBrokerMethodModelDataV2<crate::mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1>> {
        let packet_digest = self.model_packet_digest_data_v2()?;
        let model = take_success_data_v2(&mut self.bodies.mount_namespace)?;
        Some(CapturedBrokerMethodModelDataV2 { model, packet_digest })
    }

    /// Moves the sole full Mount16 model with its exact canonical packet hash.
    #[doc(hidden)]
    pub fn take_retained_mount_inventory_data_v2(&mut self)
        -> Option<CapturedBrokerMethodModelDataV2<crate::ValidatedDestinationSlotInventory>> {
        let packet_digest = self.model_packet_digest_data_v2()?;
        let model = take_success_data_v2(&mut self.bodies.mount_inventory)?;
        Some(CapturedBrokerMethodModelDataV2 { model, packet_digest })
    }

    fn model_packet_digest_data_v2(&self) -> Option<[u8; 32]> {
        use sha2::Digest as _;
        if self.failure().is_some() || self.verified_outcome.is_none() { return None; }
        Some(sha2::Sha256::digest(self.canonical.as_ref()?.encoded_bytes()).into())
    }

    /// Moves the completed admission to its real owner at most once.
    ///
    /// # Errors
    /// Refuses failed, incomplete, repeated or already moved capture state.
    pub fn take_admission_once(&mut self) -> Result<AuthenticatedBrokerMethodOutcomeAdmissionV1, AuthenticatedBrokerMethodErrorV1> {
        if let Some(error) = self.failure() { return Err(error.clone()); }
        self.result.take().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?
    }

    fn capture_once(
        &mut self,
        direction: AuthenticatedBrokerOutcomeDirectionV1,
        traffic: &BrokerSessionTrafficStateV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        bytes: &[u8],
        replay: Option<&AuthenticatedBrokerMethodOutcomeV1>,
        actual_descriptor_count: usize,
        context: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<(), AuthenticatedBrokerMethodErrorV1> {
        if self.attempted {
            self.closed.get_or_insert(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
            return Err(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink);
        }
        self.attempted = true;
        let result = if supported_method(request.method()) {
            super::admit_authenticated_broker_method_outcome_engine(
                direction, traffic, request, bytes, replay, actual_descriptor_count, context, Some(self),
            )
        } else {
            Err(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod)
        };
        let returned = result.as_ref().map(|_| ()).map_err(Clone::clone);
        self.result = Some(result);
        returned
    }
}

pub(super) fn supported_method(method: BrokerMethod) -> bool {
    matches!(method, BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
        | BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES
        | BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
        | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
        | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
        | BrokerMethod::BROKER_METHOD_STORAGE_APPLY
        | BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT
        | BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2
        | BrokerMethod::BROKER_METHOD_NETWORK_APPLY
        | BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
        | BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2
        | BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1
        | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS)
}

#[derive(Default)]
pub(super) struct StorageBodyCaptureV1 {
    pub(super) inventory: InventoryResponseCaptureV1,
    pub(super) preparation: PreparationResponseCaptureV1,
    pub(super) apply: super::storage::ApplyResponseCaptureV1,
    pub(super) guest_root_publication: Option<Result<crate::semantics::storage_guest_root::StorageGuestRootResponseDataV2, crate::ProtocolValidationError>>,
    pub(super) network_prepare: Option<Result<aos_proto::aos::sandbox::local::v1::NetworkResult, crate::ProtocolValidationError>>,
    pub(super) network_apply: super::network::NetworkApplyResponseCaptureV4,
    pub(super) network_inventory: Option<Result<crate::ValidatedNetworkInventory, crate::ProtocolValidationError>>,
    pub(super) host_apply: Option<Result<aos_proto::aos::sandbox::local::v1::RuntimeObservation, crate::ProtocolValidationError>>,
    pub(super) host_inventory: Option<Result<aos_proto::aos::sandbox::local::v1::InventoryRuntimeResponse, crate::ProtocolValidationError>>,
    pub(super) mount_namespace: Option<Result<crate::mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1, crate::ProtocolValidationError>>,
    pub(super) mount_inventory: Option<Result<crate::ValidatedDestinationSlotInventory, crate::ProtocolValidationError>>,
    result: Option<Result<Option<[u8; 32]>, AuthenticatedBrokerMethodErrorV1>>,
}

impl StorageBodyCaptureV1 {
    pub(super) fn validate_once(&mut self, request: &AuthenticatedBrokerMethodRequestV1, bytes: &[u8])
        -> Result<Option<[u8; 32]>, AuthenticatedBrokerMethodErrorV1> {
        if self.result.is_some() || !supported_method(request.method()) {
            return Err(AuthenticatedBrokerMethodErrorV1::UnsupportedMethod);
        }
        self.result = Some(super::validate_success_semantics_engine(request, bytes, Some(self)));
        self.result.as_ref().ok_or(AuthenticatedBrokerMethodErrorV1::InconsistentCrossLink)?
            .as_ref().copied().map_err(Clone::clone)
    }

    fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inventory.failure().or_else(|| self.preparation.failure()).or_else(|| self.apply.failure())
            .or_else(|| self.guest_root_publication.as_ref()?.as_ref().err().map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.network_prepare.as_ref()?.as_ref().err().map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.network_apply.cause())
            .or_else(|| self.network_inventory.as_ref()?.as_ref().err().map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.host_apply.as_ref()?.as_ref().err().map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.host_inventory.as_ref()?.as_ref().err().map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.mount_namespace.as_ref()?.as_ref().err().map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.mount_inventory.as_ref()?.as_ref().err().map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}

/// Retains the same protected server-send terminal semantic engine.
///
/// # Errors
/// Refuses unsupported selected methods, repeated capture, canonical/crypto,
/// profile, descriptor, Error or Inventory/Prepare semantic failures.
pub fn prepare_server_sent_outcome_retaining_v1(
    traffic: &BrokerSessionTrafficStateV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    bytes: &[u8],
    retained_replay: Option<&AuthenticatedBrokerMethodOutcomeV1>,
    actual_descriptor_count: usize,
    context: &ProtectedBrokerSessionVerificationContextV1,
    capture: &mut AuthenticatedBrokerMethodOutcomeCaptureV1,
) -> Result<(), AuthenticatedBrokerMethodErrorV1> {
    capture.capture_once(AuthenticatedBrokerOutcomeDirectionV1::ServerSend,
        traffic, request, bytes, retained_replay, actual_descriptor_count, context)
}

/// Retains the same protected client-receive terminal semantic engine.
///
/// # Errors
/// Refuses the same closed method, partial decode, cryptographic, envelope,
/// response-bound and semantic failures as the ordinary client adapter.
pub fn admit_client_received_outcome_retaining_v1(
    traffic: &BrokerSessionTrafficStateV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    bytes: &[u8],
    retained_replay: Option<&AuthenticatedBrokerMethodOutcomeV1>,
    actual_descriptor_count: usize,
    context: &ProtectedBrokerSessionVerificationContextV1,
    capture: &mut AuthenticatedBrokerMethodOutcomeCaptureV1,
) -> Result<(), AuthenticatedBrokerMethodErrorV1> {
    capture.capture_once(AuthenticatedBrokerOutcomeDirectionV1::ClientReceive,
        traffic, request, bytes, retained_replay, actual_descriptor_count, context)
}

// DATA extraction never drops a failed Result or invokes another decoder.
fn take_success_data_v2<T, E>(source: &mut Option<Result<T, E>>) -> Option<T> {
    match source.take() {
        Some(Ok(value)) => Some(value),
        retained => { *source = retained; None }
    }
}

#[cfg(test)]
mod retained_model_tests {
    use super::*;
    use sha2::Digest as _;

    #[test]
    fn model_packet_association_rejects_changed_prefix_and_extra_suffix() {
        let packet = b"canonical complete signed outcome";
        // This tests passive comparison only, not a native/protected issuer.
        let model = CapturedBrokerMethodModelDataV2 { model: (), packet_digest: sha2::Sha256::digest(packet).into() };
        assert!(model.matches_outcome_packet_data_v2(packet));

        let mut changed = packet.to_vec();
        changed[0] ^= 1;
        assert!(!model.matches_outcome_packet_data_v2(&changed));
        assert!(!model.matches_outcome_packet_data_v2(&packet[..packet.len() - 1]));
        let mut suffix = packet.to_vec();
        suffix.push(0);
        assert!(!model.matches_outcome_packet_data_v2(&suffix));
    }

    #[test]
    fn passive_move_preserves_the_exact_failed_model_result() {
        let mut failed: Option<Result<(), ProtocolValidationError>> = Some(Err(
            ProtocolValidationError::InvalidField("retained model original failure")));
        let first = failed.as_ref().unwrap().as_ref().unwrap_err() as *const _;

        assert!(take_success_data_v2(&mut failed).is_none());
        assert_eq!(first, failed.as_ref().unwrap().as_ref().unwrap_err() as *const _);
        assert!(take_success_data_v2(&mut failed).is_none());
        assert_eq!(first, failed.as_ref().unwrap().as_ref().unwrap_err() as *const _);
    }
}
