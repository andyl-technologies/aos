//! Reserves the exact C6 Prepare request through the existing Session engine.
//!
//! This adapter owns no new signer, request encoder, CAS or native IO machine.
//! It admits the same U, delegates the ordinary retained flight, and always
//! finishes the actual C8/Root post after an entered preparation outcome.

use super::*;
use buffa::Message as _;
use aos_sandbox_model::SignatureVerificationError;
use aos_sandbox_protocol::session::{AuthorizationArtifactBytes, encode_authorized_request_envelope};

impl OriginalStorageCreatePreparationFlightV1 {
    pub(crate) fn prepare_request_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        ready: &mut aos_sandbox_controller_domain::OriginalCreateStorageReadyV1<'_, '_>,
        bundle: &OriginalStorageReadyBundleFlightV1, inventory: &OriginalStorageInventoryClientFlightV1,
    ) -> bool {
        if self.use_first.is_some() || self.request_admission.is_some() || self.shared.inner.closed
            || !matches!(self.recorded_signed, Some(Ok(()))) || bundle.proposed_for_create_use_v1().is_none() {
            return self.close_use(UsePreparationFailureV1::Closed);
        }
        // A single finalizer follows every result of this concrete body. Native
        // admits the genuine C7/U entry even when the upper Journal borrow is
        // absent, so its prepaid negative post cannot be bypassed.
        if let Err(first) = self.prepare_request_body_once(session, ready, inventory) {
            self.use_first.get_or_insert(first);
        }
        self.finish_request_once(session, ready)
    }

    fn prepare_request_body_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        ready: &mut aos_sandbox_controller_domain::OriginalCreateStorageReadyV1<'_, '_>,
        inventory: &OriginalStorageInventoryClientFlightV1,
    ) -> Result<(), UsePreparationFailureV1> {
        let journal = match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => Some(journal),
            Err(cause) => {
                self.shared.inner.protected_failure.get_or_insert(cause);
                None
            }
        };
        self.request_admission = Some(ready.admit_original_storage_preparation_once(
            journal, &session.socket, &session.transcript));
        if journal.is_none() {
            return Err(UsePreparationFailureV1::RequestShared);
        }
        if !matches!(self.request_admission, Some(Ok(()))) {
            return Err(UsePreparationFailureV1::RequestNative);
        }
        self.request_predecessor = Some(
            self.request_predecessor_originals
                .as_deref_mut()
                .ok_or(BrokerSessionSecurityError::Currentness)
                .and_then(|originals| inventory.compare_bundle_predecessor_v1(session, originals)),
        );
        self.request_predecessor.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(UsePreparationFailureV1::RequestPredecessor)?;

        self.check_request_window_once(ready);
        if let Some(first) = self.use_first {
            return Err(first);
        }
        self.request_encoded = Some(self.encode_request_once(ready));
        let encoded = self.request_encoded.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(UsePreparationFailureV1::RequestEnvelope)?;
        self.request_decoded = Some(BrokerRequestEnvelope::decode(&mut encoded.as_slice()));
        let envelope = self.request_decoded.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(UsePreparationFailureV1::RequestDecode)?;
        self.request_header = Some(aos_sandbox_api::aos::sandbox::local::v1::PrepareStorageCatalogRequest::decode(&mut envelope.body.as_slice()));
        self.request_header.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(UsePreparationFailureV1::RequestHeader)?;

        self.shared.inner.coordinates = Some((|| {
            let inputs = ready.original_storage_prepare_inputs_v1().map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let header = self.request_header.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|request| request.header.as_option()).ok_or(BrokerSessionSecurityError::Currentness)?;
            crate::dormant_handshake::original_create_storage_prepare_coordinates_v1(session,
                inputs.request_id, inputs.cutoff, header)
        })());
        self.shared.inner.coordinates.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(UsePreparationFailureV1::RequestShared)?;
        let maximum = ready.original_storage_prepare_inputs_v1()
            .map_err(|_| UsePreparationFailureV1::RequestNative)?.request_shape_bytes;
        self.request_prepared = Some(self.shared.inner.prepare_engine(session, envelope.clone(), Some(maximum)));
        if self.request_prepared == Some(true) { Ok(()) }
        else { Err(UsePreparationFailureV1::RequestShared) }
    }

    fn encode_request_once(&self, ready: &aos_sandbox_controller_domain::OriginalCreateStorageReadyV1<'_, '_>)
        -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let inputs = ready.original_storage_prepare_inputs_v1()?;
        let ownership = ready.borrow_storage_use_plan_inputs_v1()?;
        let signed = self.signed_plan.as_ref().ok_or(OutputPreparationClosedV1)?;
        if signed.canonical_plan() != inputs.plan || signed.canonical_signature() != inputs.signature {
            return Err(Box::new(OutputPreparationClosedV1));
        }
        Ok(encode_authorized_request_envelope(aos_sandbox_model::ProtocolId::StorageBroker,
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG, inputs.request_body, &[],
            AuthorizationArtifactBytes { broker_plan: inputs.plan, broker_plan_signature: inputs.signature,
                ownership_lease: ownership.lease.canonical_lease(),
                ownership_lease_signature: ownership.lease.canonical_signature() })?)
    }

    fn check_request_window_once(&mut self, ready: &aos_sandbox_controller_domain::OriginalCreateStorageReadyV1<'_, '_>) {
        self.request_clock = Some(ready.original_storage_preparation_clock_v1());
        let Some(Ok(clock)) = self.request_clock.as_ref() else {
            self.use_first.get_or_insert(UsePreparationFailureV1::RequestClock);
            return;
        };
        let Some(signed) = self.signed_plan.as_ref() else {
            self.use_first.get_or_insert(UsePreparationFailureV1::Closed);
            return;
        };
        let plan = signed.plan();
        self.request_window = Some(if clock.wall_seconds() < plan.issued_seconds() {
            Err(SignatureVerificationError::NotYetValid)
        } else if clock.wall_seconds() >= plan.expires_seconds() {
            Err(SignatureVerificationError::Expired)
        } else { Ok(()) });
        if !matches!(self.request_window, Some(Ok(()))) {
            self.use_first.get_or_insert(UsePreparationFailureV1::RequestWindow);
        }
    }

    fn finish_request_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        ready: &mut aos_sandbox_controller_domain::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> bool {
        // The retained Journal getter is borrow-only. Even its refusal cannot
        // suppress Root's prearmed after-check: Native receives an absent
        // Session/request, refuses and still runs its original negative post.
        self.request_finish = Some(match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => ready.finish_original_storage_request_once(Some(journal),
                if self.request_prepared == Some(true) { self.shared.request() } else { None }),
            Err(cause) => {
                self.shared.inner.protected_failure.get_or_insert(cause);
                self.use_first.get_or_insert(UsePreparationFailureV1::RequestShared);
                ready.finish_original_storage_request_once(None, None)
            }
        });
        if !matches!(self.request_finish, Some(Ok(()))) {
            self.use_first.get_or_insert(UsePreparationFailureV1::RequestNative);
        }
        if self.use_first.is_none() {
            self.check_request_window_once(ready);
        }
        if self.use_first.is_some() { self.shared.inner.closed = true; false } else { true }
    }
}
