//! Retains selected initial method inputs, replies and proof work in one owner.
//!
//! The private Source action authorizes these calls. This SDK API derives the
//! body from the same installed codec and never accepts arbitrary serialized
//! arguments. An owner is installed before construction or transport can fail.

use super::*;
use crate::client::session::object;
use crate::connection::{ReceivedBody, ReceivedFrame};
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};

/// Retains an initial request, response and any unfinished immutable proof.
///
/// This owner carries data and custody only. Source/current Child, closed gate,
/// behavioral validation and the keyed once-Admit remain separate checks.
#[must_use = "retain original initial replies across all Source checks"]
pub struct OriginalPacketHostInitialResponse {
    pub(in crate::client) actor: std::rc::Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    pub(in crate::client) request_id: Id,
    pub(in crate::client) method: Method,
    pub(in crate::client) original: Option<Envelope>,
    pub(in crate::client) received: Option<ReceivedFrame>,
    pub(in crate::client) proof_received: Option<ReceivedFrame>,
    pub(in crate::client) proof_transfer: Option<(Id, ContentRef, usize)>,
    pub(in crate::client) proof_objects: usize,
    pub(in crate::client) completed: bool,
}

impl OriginalPacketHostInitialResponse {
    /// Authenticates the same actual controller actor without reconstructing data.
    ///
    /// # Errors
    /// Refuses a foreign creator, changed actor or different controller owner.
    pub fn authenticate_original_controller_data(
        &self,
        controller: &CnpController,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        controller.protocol_owner.ensure_current()?;
        if !std::rc::Rc::ptr_eq(&self.actor, &controller.protocol_owner) {
            return Err(refused());
        }
        Ok(())
    }

    /// Borrows the same assigned original after its body has been retained.
    ///
    /// # Errors
    /// Refuses foreign origin or an original not yet constructed.
    pub fn original_data(&self) -> Result<&Envelope, ProviderError> {
        self.actor.ensure_current()?;
        self.original.as_ref().ok_or_else(refused)
    }

    /// Borrows the actual retained response envelope without reconstructing it.
    ///
    /// # Errors
    /// Refuses foreign origin or a response not yet received.
    pub fn response_original_data(&self) -> Result<&Envelope, ProviderError> {
        self.actor.ensure_current()?;
        Ok(&self.received.as_ref().ok_or_else(refused)?.envelope)
    }

    /// Borrows the complete decoded reply after its promised evidence arrived.
    ///
    /// # Errors
    /// Refuses foreign origin, an incomplete call or a nonresponse slot.
    pub fn response_data(&self) -> Result<&ResponseBody, ProviderError> {
        self.actor.ensure_current()?;
        if !self.completed {
            return Err(refused());
        }
        match &self.received.as_ref().ok_or_else(refused)?.body {
            ReceivedBody::Response(body) => Ok(body),
            _ => Err(refused()),
        }
    }

    /// Observes the actual original, typed reply and partial proof owners.
    ///
    /// This closed walk invokes no transport, erased callback or serializer.
    /// The enclosing owner header and preadmitted fixed counter are separate.
    ///
    /// # Errors
    /// Refuses foreign origin, an unexpected body family or bounded traversal.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.actor.ensure_current()?;
        let Self {
            actor,
            request_id,
            method,
            original,
            received,
            proof_received,
            proof_transfer,
            proof_objects,
            completed,
        } = self;
        let mut observer = MetadataObserver::new();
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::ProtocolOwner,
            actor.as_ref(),
        )?;
        observer.observe(request_id)?;
        // Method is an inline discriminator; this closed family owns no enum
        // payload. Observe its scalar event without allocating a method name.
        observer.observe(&matches!(method, Method::Discover | Method::Realize))?;
        observer.observe(proof_objects)?;
        observer.observe(completed)?;
        if let Some(original) = original {
            observer.observe(original)?;
        }
        if let Some(frame) = received {
            observe_frame(frame, &mut observer)?;
        }
        if let Some(frame) = proof_received {
            observe_frame(frame, &mut observer)?;
        }
        if let Some((transfer, reference, offset)) = proof_transfer {
            observer.observe(transfer)?;
            observer.observe(reference)?;
            observer.observe(offset)?;
        }
        self.actor.ensure_current()?;
        Ok(observer.finish())
    }
}

impl CnpController {
    /// Calls one exact selected initial Discover or Realize with retained output.
    ///
    /// The caller consumes its genuine installed action before this method.
    /// Request bodies derive only from the same installed source codec. The
    /// original physical cut is tightened, never reset. This grants no Admit,
    /// graph, gate-opening or execution permission.
    ///
    /// # Errors
    /// Refuses an occupied slot, unsupported/out-of-order method, changed actor,
    /// insufficient finite custody, malformed response or uncertain transport.
    /// Surviving original/typed/proof owners remain in `completed` on refusal.
    pub fn call_original_host_initial_lifecycle_into(
        &mut self,
        request_id: Id,
        method: Method,
        completed: &mut Option<OriginalPacketHostInitialResponse>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if completed.is_some() {
            return Err(refused());
        }
        *completed = Some(OriginalPacketHostInitialResponse {
            actor: std::rc::Rc::clone(&self.protocol_owner),
            request_id,
            method,
            original: None,
            received: None,
            proof_received: None,
            proof_transfer: None,
            proof_objects: 0,
            completed: false,
        });
        let owner = completed.as_mut().ok_or_else(refused)?;
        self.protocol_owner.ensure_current()?;
        self.ensure_no_pending_original_ack_admit()?;
        if self.fenced || !matches!(method, Method::Discover | Method::Realize) {
            return Err(refused());
        }
        self.custody
            .authenticate_original_host_initial_order(method)?;
        let sequence = self.session.original_host_initial_sequence_data()?;
        let selection = self.session.original_host_initial_selection_data()?;
        let body = match method {
            Method::Discover => object(DiscoverRequest {
                profile_ids: selection
                    .provider
                    .supported_profiles
                    .iter()
                    .map(|profile| profile.profile_id.clone())
                    .collect(),
                cursor: None,
                extensions: Extensions::new(),
            })?,
            Method::Realize => object(&selection.realize)?,
            _ => return Err(refused()),
        };
        owner.original = Some(Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(self.authority().session_id().clone())),
            incarnation_id: Nullable(Some(self.authority().incarnation_id().clone())),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(owner.request_id.clone())),
            operation_id: Nullable(None),
            sequence,
            method,
            body,
            extensions: Extensions::new(),
        });
        let result =
            self.session
                .exchange_original_host_initial_into(&mut self.custody, owner, self.budget);
        if result.is_err() {
            self.fenced = true;
        }
        result?;
        self.protocol_owner.ensure_current()?;
        owner.completed = true;
        Ok(())
    }
}

fn observe_frame(
    frame: &ReceivedFrame,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    observer.observe(&frame.envelope)?;
    match &frame.body {
        ReceivedBody::Response(body) => {
            observer.boxed_value(body.as_ref())?;
            match &body.shape {
                ResponseShape::Completed {
                    operation_state,
                    result,
                    extensions,
                } => {
                    observer.observe(operation_state)?;
                    observer.observe(result)?;
                    observer.observe(extensions)?;
                }
                _ => return Err(refused()),
            }
            match &body.result {
                Some(MethodResult::Discover(value)) => {
                    observer.observe(&value.provider_manifest)?;
                    observer.observe(&value.profiles)?;
                    observer.observe(&value.facet_schemas)?;
                    observer.observe(&value.complete)?;
                    observer.observe(&value.next_cursor)?;
                }
                Some(MethodResult::Realize(value)) => {
                    observer.observe(&value.realization_manifest)?;
                    observer.observe(&value.prepared_token)?;
                    observer.observe(&value.closed_gate_receipt)?;
                }
                _ => return Err(refused()),
            }
        }
        ReceivedBody::Request(body) => {
            observer.boxed_value(body.as_ref())?;
            match body.as_ref() {
                RequestBody::BlobBegin(body) => {
                    observer.observe(&body.transfer_id)?;
                    observer.observe(&body.content)?;
                    observer.observe(&body.extensions)?;
                }
                RequestBody::BlobChunk(body) => {
                    observer.observe(&body.transfer_id)?;
                    observer.observe(&body.offset)?;
                    observer.observe(&body.bytes)?;
                    observer.observe(&body.extensions)?;
                }
                RequestBody::BlobFinish(body) => {
                    observer.observe(&body.transfer_id)?;
                    observer.observe(&body.extensions)?;
                }
                _ => return Err(refused()),
            }
        }
        _ => return Err(refused()),
    }
    Ok(())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original host initial lifecycle")
}

impl CnpController {
    pub(in crate::client) fn prepare_original_host_initial_capacity_data(
        &mut self,
        journal_growth: usize,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.custody
            .prepare_original_host_initial_capacity_data(journal_growth)
    }

    pub(in crate::client) fn original_host_initial_content_layout_data(
        &self,
        raw_capacity: usize,
    ) -> Result<usize, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.custody
            .content()
            .fresh_report_requested_layout_data(raw_capacity)
    }
}

#[cfg(test)]
mod tests {
    //! Actual socket-only SDK controls; no Child, Hello or Source grant is modeled.
    use super::*;
    use crate::{
        client::ClientContent,
        connection::OriginalRetainedSupervisor,
        transport::{original_frames::OriginalFrameReservation, write_frame},
    };
    use std::{os::unix::net::UnixStream, rc::Rc};

    fn fixture() -> (
        crate::handshake::Handshake,
        CnpController,
        UnixStream,
        crate::reference_packet::control::PacketControlSelection,
        OriginalRetainedSupervisor,
    ) {
        let (handshake, authority, selection, coordinator) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let (operational, supervisor) = OriginalRetainedSupervisor::reserve().unwrap();
        let (session, peer) = ClientSession::controller_fixture(
            authority,
            operational,
            Rc::new(crate::client::host_startup::hello::InitialHelloSchema),
        )
        .unwrap();
        let custody =
            ClientCustody::new(64, ClientContent::new(4 * 1024 * 1024, 64, 4096).unwrap()).unwrap();
        let route = ControllerRoute {
            node: selection.realization.descriptors[0].id.clone(),
            execution_owner: selection.realization.owner_bindings[0].owner.id.clone(),
        };
        let mut controller =
            CnpController::new(session, custody, route, Duration::from_secs(2)).unwrap();
        let mut frames = Some(OriginalFrameReservation::reserve(262144, 64).unwrap());
        controller
            .install_native5_source_ack_emitter_codec_with_metadata_extent(
                &mut frames,
                selection.clone(),
                coordinator,
                crate::reference_packet::service::PacketNative5CaptureProfile::OriginalArrays6,
                crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
            )
            .unwrap();
        (handshake, controller, peer, selection, supervisor)
    }

    fn response(
        controller: &CnpController,
        selection: &crate::reference_packet::control::PacketControlSelection,
        request: &Id,
        sequence: u64,
    ) -> Envelope {
        Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Response,
            session_id: Nullable(Some(controller.authority().session_id().clone())),
            incarnation_id: Nullable(Some(controller.authority().incarnation_id().clone())),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            operation_id: Nullable(None),
            request_id: Nullable(Some(request.clone())),
            sequence: U64::new(sequence),
            method: Method::Discover,
            body: object(ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result: serde_json::to_value(DiscoverResult {
                    provider_manifest: selection.provider.clone(),
                    profiles: selection.provider.supported_profiles.clone(),
                    facet_schemas: selection.provider.implementation.formats.clone(),
                    complete: true,
                    next_cursor: Nullable(None),
                })
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
                extensions: Extensions::new(),
            })
            .unwrap(),
            extensions: Extensions::new(),
        }
    }

    #[test]
    fn actual_selected_discover_retains_reply_and_same_nonrenewed_cut() {
        let (_handshake, mut controller, mut peer, selection, _supervisor) = fixture();
        // The fixture transport already owns a thirty-second cut. A larger
        // per-call allowance must preserve that earlier absolute deadline.
        controller.budget = Duration::from_secs(60);
        let before = controller
            .session
            .current_original_complete_restore_cut()
            .unwrap()
            .1;
        let id = Id::new("selected-initial-discover").unwrap();
        let reply = response(&controller, &selection, &id, 2);
        write_frame(&mut peer, &serde_json::to_value(&reply).unwrap(), 65536).unwrap();
        let mut result = None;
        controller
            .call_original_host_initial_lifecycle_into(id, Method::Discover, &mut result)
            .unwrap();
        let result = result.as_ref().unwrap();
        assert_eq!(result.response_original_data().unwrap(), &reply);
        assert!(matches!(
            result.response_data().unwrap().result,
            Some(MethodResult::Discover(_))
        ));
        assert_eq!(
            controller
                .session
                .current_original_complete_restore_cut()
                .unwrap()
                .1,
            before
        );
        assert!(
            result
                .original_retained_metadata_facts()
                .unwrap()
                .capacity_records
                > 0
        );
        result
            .authenticate_original_controller_data(&controller)
            .unwrap();
        let (_other_handshake, other_controller, _other_peer, _same_selection, _other_supervisor) =
            fixture();
        assert!(
            result
                .authenticate_original_controller_data(&other_controller)
                .is_err()
        );
    }

    #[test]
    fn actual_selected_discover_tightens_a_longer_original_cut() {
        let (_handshake, mut controller, mut peer, selection, _supervisor) = fixture();
        let before = controller
            .session
            .current_original_complete_restore_cut()
            .unwrap()
            .1;
        let id = Id::new("selected-initial-discover-tighten").unwrap();
        let reply = response(&controller, &selection, &id, 2);
        write_frame(&mut peer, &serde_json::to_value(&reply).unwrap(), 65536).unwrap();
        let mut result = None;

        controller
            .call_original_host_initial_lifecycle_into(id, Method::Discover, &mut result)
            .unwrap();

        let after = controller
            .session
            .current_original_complete_restore_cut()
            .unwrap()
            .1;
        assert!(after < before);
        assert_eq!(result.unwrap().response_original_data().unwrap(), &reply);
    }

    #[test]
    fn actual_selected_discover_keeps_typed_reply_before_sequence_refusal() {
        let (_handshake, mut controller, mut peer, selection, supervisor) = fixture();
        let id = Id::new("initial-sequence-refusal").unwrap();
        let reply = response(&controller, &selection, &id, 3);
        write_frame(&mut peer, &serde_json::to_value(&reply).unwrap(), 65536).unwrap();
        let mut result = None;
        assert!(
            controller
                .call_original_host_initial_lifecycle_into(id, Method::Discover, &mut result)
                .is_err()
        );
        let result = result.as_ref().unwrap();
        assert_eq!(result.response_original_data().unwrap(), &reply);
        assert!(result.response_data().is_err());
        assert!(
            result
                .original_retained_metadata_facts()
                .unwrap()
                .capacity_records
                > 0
        );
        assert!(!supervisor.is_empty_data().unwrap());
        assert!(controller.fenced);
    }

    #[test]
    fn actual_selected_discover_rejects_extra_result_before_typed_decode() {
        let (_handshake, mut controller, mut peer, selection, supervisor) = fixture();
        let id = Id::new("initial-extra-result").unwrap();
        let mut reply = response(&controller, &selection, &id, 2);
        reply
            .body
            .get_mut("result")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "unexpected".into(),
                Value::String("not-a-closed-result".into()),
            );
        write_frame(&mut peer, &serde_json::to_value(&reply).unwrap(), 65536).unwrap();
        let mut result = None;
        assert!(
            controller
                .call_original_host_initial_lifecycle_into(id, Method::Discover, &mut result)
                .is_err()
        );
        let result = result.as_ref().unwrap();
        assert!(result.original_data().is_ok());
        assert!(result.received.is_none());
        assert!(!supervisor.is_empty_data().unwrap());
    }
}
