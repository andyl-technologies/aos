//! Quotes the actual fresh Control/model owners and their existing gate proof.
//!
//! The opaque quote is valid only while the endpoint's selected transfer guard
//! prevents ordinary dispatch. It retains the real original allocation identity;
//! its measured capacities and receipt are data, not a restored-world permit.

use super::*;
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use serde::Deserialize;
use std::rc::Rc;

pub(crate) struct PacketFreshRestoreControlAllocation {
    creator: u32,
    identity: Rc<()>,
    policy: Rc<super::super::Native5Policy>,
    facts: RetainedProtocolMetadataFacts,
    endpoint: super::super::endpoint::PacketEndpointRestoreAllocation,
    gate: ContentRef,
}

impl PacketFreshRestoreControlAllocation {
    pub(crate) fn authenticate_original(
        &self,
        policy: &Rc<super::super::Native5Policy>,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || !Rc::ptr_eq(&self.policy, policy) {
            return Err(ProviderError::Correlation(
                "restore actual fresh Control quote",
            ));
        }
        self.endpoint.authenticate_original(policy)
    }
    pub(crate) fn endpoint_facts(&self) -> RetainedProtocolMetadataFacts {
        self.endpoint.facts()
    }
    pub(crate) fn startup_endpoint_reserved_bytes_data(&self) -> Result<usize, ProviderError> {
        self.endpoint.authenticate_original(&self.policy)?;
        self.endpoint.startup_reserved_bytes_data()
    }

    pub(crate) fn endpoint_header_bytes(&self) -> usize {
        self.endpoint.owner_header_bytes()
    }
    pub(crate) fn facts(&self) -> RetainedProtocolMetadataFacts {
        self.facts
    }
}

impl PacketControl {
    pub(crate) fn quote_original_fresh_restore_control(
        &self,
        policy: &Rc<super::super::Native5Policy>,
        endpoint: super::super::endpoint::PacketEndpointRestoreAllocation,
    ) -> Result<PacketFreshRestoreControlAllocation, ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation("restore Control origin"));
        }
        policy.authenticate_original_control_selection(&self.selection)?;
        if !self.realized || !self.admitted || self.fenced || self.native_effect_attempted
            || self.staged.is_some() || self.active.is_some() || self.current_operation.is_some()
            || !self.begins.is_empty() || !self.begin_requests.is_empty() || !self.terminals.is_empty()
            || self.common_coordinator.is_some() || self.world_coordinator.is_some() || self.connected_coordinator.is_some()
            || self.complete_coordinator.is_none()
            || self.complete_restore_selection != Some(super::super::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            return Err(ProviderError::Correlation("restore Control is not an untouched selected owner"));
        }
        let mut observer = MetadataObserver::new();
        observer.observe(&self.selection)?;
        observer.shared_value(self.capture_identity.as_ref())?;
        observer.tree::<Id, (HashRef, PacketControlReply)>(self.originals.len())?;
        let mut gate = None;
        for (id, (hash, reply)) in &self.originals {
            observer.observe(id)?;
            observer.observe(hash)?;
            observer.observe(&reply.body)?;
            observer.vector::<(ContentRef, Vec<u8>)>(reply.evidence.capacity())?;
            for (reference, bytes) in &reply.evidence {
                observer.observe(reference)?;
                observer.observe(bytes)?;
            }
            // Only Realize constructs this exact closed result in the private
            // original cache. The SDK separately checks its actual literal pair.
            if let Some(result) = reply.body.get("result").and_then(Value::as_object)
                && result.len() == 3
                && result.contains_key("realization_manifest")
                && result.get("prepared_token").and_then(Value::as_str)
                    == Some(self.selection.prepared_token.as_str())
                && let Some(reference) = result.get("closed_gate_receipt")
            {
                let reference = ContentRef::deserialize(reference).map_err(ContractError::from)?;
                let bytes = reply
                    .evidence
                    .iter()
                    .find_map(|(actual, bytes)| (actual == &reference).then_some(bytes))
                    .ok_or(ProviderError::Correlation(
                        "restore original gate proof absent",
                    ))?;
                reference.verify(bytes)?;
                if gate.replace(reference).is_some() {
                    return Err(ProviderError::Correlation(
                        "restore original Realize is not unique",
                    ));
                }
            }
        }
        observer.tree::<Id, BeginRequest>(self.begins.len())?;
        observer.tree::<Id, Id>(self.begin_requests.len())?;
        observer.tree::<Id, Map<String, Value>>(self.terminals.len())?;
        observer.observe(&self.content)?;
        observer.observe(
            self.complete_coordinator
                .as_ref()
                .ok_or(ProviderError::Correlation("restore coordinator absent"))?,
        )?;
        match &self.program {
            NativeProgram::OutputOnly(program) => {
                program.observe_fresh_restore_metadata(&mut observer)?
            }
            NativeProgram::Connected(program) => {
                program.observe_fresh_restore_metadata(&mut observer)?
            }
            NativeProgram::RestorationInProgress => {
                return Err(ProviderError::Conflict("packet restored model incomplete"));
            }
        }
        let gate = gate.ok_or(ProviderError::Correlation(
            "restore original Realize proof absent",
        ))?;
        observer.observe(&gate)?;
        observer.shared_value(self.capture_identity.as_ref())?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::NativePolicy,
            policy.as_ref(),
        )?;
        policy.observe_owned11_metadata(&mut observer)?;
        Ok(PacketFreshRestoreControlAllocation {
            creator: self.capture_creator,
            identity: Rc::clone(&self.capture_identity),
            policy: Rc::clone(policy),
            facts: observer.finish(),
            endpoint,
            gate,
        })
    }

    pub(crate) fn original_restore_prepare_result_data(
        &self,
        quote: &PacketFreshRestoreControlAllocation,
        request: &super::super::service::complete_restore::transfer::PacketCompleteRestorePrepareRequest,
    ) -> Result<PrepareRestoreResult, ProviderError> {
        if self.capture_creator != std::process::id()
            || !Rc::ptr_eq(&self.capture_identity, &quote.identity)
            || self.fenced
            || self.staged.is_some()
            || self.active.is_some()
            || self.current_operation.is_some()
        {
            return Err(ProviderError::Correlation("restore fresh gate changed"));
        }
        quote.authenticate_original(&quote.policy)?;
        let target = &request.restoration;
        let owner = self
            .selection
            .realization
            .owner_bindings
            .first()
            .ok_or(ProviderError::Correlation("restore owner absent"))?;
        if target.target_world != self.selection.world
            || target.target_owner_binding != owner.identity()?
            || target.target_owner != owner.owner.id
        {
            return Err(ProviderError::Correlation("restore target owner changed"));
        }
        Ok(PrepareRestoreResult {
            transaction_id: request.transaction_id.clone(),
            prepared_token: self.selection.prepared_token.clone(),
            world_binding_hash: self.selection.world.clone(),
            owner_binding_hash: target.target_owner_binding.clone(),
            staged_owner_ids: std::iter::once(target.target_owner.clone()).collect(),
            closed_gate_receipt: quote.gate.clone(),
            validated_manifest: target.capture_manifest.clone(),
        })
    }
}

pub(crate) struct PacketLiveCaptureControlCurrency {
    creator: u32,
    identity: Rc<()>,
    originals_before: usize,
    cursor: Position,
}

impl PacketLiveCaptureControlCurrency {
    pub(super) fn authenticate_produced_receipt_identity(
        &self,
        creator: u32,
        identity: &Rc<()>,
    ) -> Result<(), ProviderError> {
        if creator != std::process::id()
            || creator != self.creator
            || !Rc::ptr_eq(identity, &self.identity)
        {
            return Err(ProviderError::Correlation(
                "native Observe receipt has another producer",
            ));
        }
        Ok(())
    }

    pub(crate) fn cursor(&self) -> Position {
        self.cursor
    }
    pub(crate) fn originals_before(&self) -> usize {
        self.originals_before
    }

    pub(crate) fn authenticate_before_observe(
        &self,
        control: &PacketControl,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id()
            || control.capture_creator != self.creator
            || !Rc::ptr_eq(&control.capture_identity, &self.identity)
            || control.originals.len() != self.originals_before
            || control.fenced
            || !control.immediate
            || control.current_operation.is_some()
        {
            return Err(ProviderError::Correlation(
                "native Observe original quote currency changed",
            ));
        }
        let mut observer = MetadataObserver::new();
        if control.observe_live_capture_children(&mut observer)? != self.cursor {
            return Err(ProviderError::Correlation(
                "native Observe model changed after quote",
            ));
        }
        Ok(())
    }

    fn authenticate_completed_observe_owner(
        &self,
        control: &PacketControl,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id()
            || control.capture_creator != self.creator
            || !Rc::ptr_eq(&control.capture_identity, &self.identity)
            || control.originals.len()
                != self
                    .originals_before
                    .checked_add(1)
                    .ok_or(ProviderError::ResourceExhausted(
                        "native Observe currency population",
                    ))?
        {
            return Err(ProviderError::Correlation(
                "native Observe Control currency changed",
            ));
        }
        Ok(())
    }

    pub(super) fn authenticate_owned_observe_dispatch(
        &self,
        dispatch: &OriginalObserveDispatch<'_>,
    ) -> Result<(), ProviderError> {
        dispatch.authenticate_currency_data(self)?;
        let control = dispatch.control_data();
        self.authenticate_completed_observe_owner(control)?;
        let mut observer = MetadataObserver::new();
        if control.observe_live_capture_children_with_dispatch(&mut observer, Some(dispatch))?
            != self.cursor
        {
            return Err(ProviderError::Correlation(
                "native Observe owned dispatch model cursor changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn authenticate_completed_observe(
        &self,
        control: &PacketControl,
    ) -> Result<(), ProviderError> {
        self.authenticate_completed_observe_owner(control)?;
        let mut observer = MetadataObserver::new();
        if control.observe_live_capture_children(&mut observer)? != self.cursor {
            return Err(ProviderError::Correlation(
                "native Observe model cursor changed",
            ));
        }
        Ok(())
    }
}

impl PacketControl {
    pub(crate) fn observe_original_live_capture_metadata(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<PacketLiveCaptureControlCurrency, ProviderError> {
        let cursor = self.observe_live_capture_children(observer)?;
        let currency = PacketLiveCaptureControlCurrency {
            creator: self.capture_creator,
            identity: Rc::clone(&self.capture_identity),
            originals_before: self.originals.len(),
            cursor,
        };
        // Both the Control and its newly retained currency have real strong
        // headers. The zero-field payload is visited once, with no child banks.
        roots.observe_shared(
            observer,
            crate::retained_metadata::aliases::MetadataSharedKind::NativeControlIdentity,
            self.capture_identity.as_ref(),
        )?;
        roots.observe_shared(
            observer,
            crate::retained_metadata::aliases::MetadataSharedKind::NativeControlIdentity,
            currency.identity.as_ref(),
        )?;
        Ok(currency)
    }

    pub(super) fn observe_live_capture_children(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<Position, ProviderError> {
        self.observe_live_capture_children_with_dispatch(observer, None)
    }

    fn observe_live_capture_children_with_dispatch(
        &self,
        observer: &mut MetadataObserver,
        dispatch: Option<&OriginalObserveDispatch<'_>>,
    ) -> Result<Position, ProviderError> {
        // A held fence is valid only through this exact exclusive dispatch
        // borrow and its same produced receipt. Ordinary callers retain the
        // unchanged unfenced guard and cannot opt in with a scalar flag.
        let held = if let Some(dispatch) = dispatch {
            dispatch.authenticate_observer_owner(self)?;
            true
        } else {
            false
        };
        let Self {
            selection,
            program,
            complete_restored_evidence,
            complete_restored_hold,
            restoration_activation_required,
            capture_creator,
            capture_identity: _,
            originals,
            begins,
            begin_requests,
            content,
            content_bytes,
            realized,
            admitted,
            staged,
            active,
            fenced,
            native_effect_attempted,
            immediate,
            current_operation,
            terminals,
            common_coordinator,
            world_coordinator,
            connected_coordinator,
            complete_coordinator,
            complete_storage,
            complete_capture_profile,
            complete_confirmation_selection,
            complete_ack_emitter_selection,
            complete_restore_selection,
            complete_protocol_metadata_limits,
            complete_protocol_metadata_birth_facts,
            complete_restore_input_emitter_selection,
            complete_capture_allocation_selection,
        } = self;
        if *capture_creator != std::process::id()
            || !*realized
            || !*admitted
            || (*fenced != held)
            || !*immediate
            || active.is_none()
            || current_operation.is_some()
            || complete_restored_evidence.is_some()
            || complete_restored_hold.is_some()
            || common_coordinator.is_some()
            || world_coordinator.is_some()
            || connected_coordinator.is_some()
            || complete_coordinator.is_none()
        {
            return Err(ProviderError::Correlation(
                "native live complete Capture owner unresolved",
            ));
        }
        observer.observe(restoration_activation_required)?;
        observer.observe(selection)?;
        observer.tree::<Id, (HashRef, PacketControlReply)>(originals.len())?;
        for (id, (hash, reply)) in originals {
            observer.observe(id)?;
            observer.observe(hash)?;
            let PacketControlReply { body, evidence } = reply;
            observer.observe(body)?;
            observer.observe(&ReplyEvidenceMetadata(evidence))?;
        }
        observer.observe(begins)?;
        observer.observe(begin_requests)?;
        observer.observe(content)?;
        observer.observe(content_bytes)?;
        observer.observe(realized)?;
        observer.observe(admitted)?;
        if let Some((request, reference)) = staged {
            let ActivateRequest {
                admission_id,
                activation_id,
                world_generation,
                prepared_token,
                world_binding_hash,
                gate_id,
                extensions,
            } = request;
            observer.observe(admission_id)?;
            observer.observe(activation_id)?;
            observer.observe(world_generation)?;
            observer.observe(prepared_token)?;
            observer.observe(world_binding_hash)?;
            observer.observe(gate_id)?;
            observer.observe(extensions)?;
            observer.observe(reference)?;
        }
        if let Some(request) = active {
            let WorldActivateRequest {
                transaction_id,
                activation_id,
                world_generation,
                prepared_token,
                world_binding_hash,
                gate_id,
                activation_manifest,
                extensions,
            } = request;
            observer.observe(transaction_id)?;
            observer.observe(activation_id)?;
            observer.observe(world_generation)?;
            observer.observe(prepared_token)?;
            observer.observe(world_binding_hash)?;
            observer.observe(gate_id)?;
            observer.observe(activation_manifest)?;
            observer.observe(extensions)?;
        }
        observer.observe(fenced)?;
        observer.observe(native_effect_attempted)?;
        observer.observe(immediate)?;
        observer.observe(current_operation)?;
        observer.observe(terminals)?;
        observer.observe(complete_coordinator)?;
        observer.observe(complete_storage)?;
        observer.observe(complete_capture_profile)?;
        observer.observe(complete_confirmation_selection)?;
        observer.observe(complete_ack_emitter_selection)?;
        observer.observe(complete_restore_selection)?;
        observer.observe(complete_protocol_metadata_limits)?;
        observer.observe(complete_protocol_metadata_birth_facts)?;
        observer.observe(complete_restore_input_emitter_selection)?;
        observer.observe(complete_capture_allocation_selection)?;
        let cursor = match program {
            NativeProgram::OutputOnly(program) => {
                program.observe_original_live_capture_metadata(observer)?
            }
            NativeProgram::Connected(program) => {
                program.observe_original_live_capture_metadata(observer)?
            }
            NativeProgram::RestorationInProgress => {
                return Err(ProviderError::Conflict("native Capture model incomplete"));
            }
        };
        if *capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native Capture Control origin changed",
            ));
        }
        Ok(cursor)
    }
}

impl PacketLiveCaptureControlCurrency {
    pub(crate) fn authenticate_capture_boundary(
        &self,
        control: &PacketControl,
        capture: Option<&Envelope>,
    ) -> Result<(), ProviderError> {
        let observe_count =
            self.originals_before
                .checked_add(1)
                .ok_or(ProviderError::ResourceExhausted(
                    "native Capture currency originals",
                ))?;
        if self.creator != std::process::id()
            || control.capture_creator != self.creator
            || !Rc::ptr_eq(&self.identity, &control.capture_identity)
            || control.fenced
            || !control.immediate
            || control.active.is_none()
            || control.complete_restored_evidence.is_some()
            || control.complete_restored_hold.is_some()
        {
            return Err(ProviderError::Correlation(
                "native Capture currency owner changed",
            ));
        }
        if control.originals.len() == observe_count {
            if control.current_operation.is_some() {
                return Err(ProviderError::Correlation(
                    "native Capture currency has another operation",
                ));
            }
        } else {
            let capture = capture.ok_or(ProviderError::Correlation(
                "native Capture currency request absent",
            ))?;
            let request = capture
                .request_id
                .0
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "native Capture currency ID absent",
                ))?;
            let operation = capture
                .operation_id
                .0
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "native Capture currency operation absent",
                ))?;
            if control.originals.len()
                != observe_count
                    .checked_add(1)
                    .ok_or(ProviderError::ResourceExhausted(
                        "native Capture currency population",
                    ))?
                || !control.originals.contains_key(request)
                || control.begin_requests.get(operation) != Some(request)
                || control
                    .begins
                    .get(operation)
                    .is_none_or(|begin| begin.kind != BeginKind::Capture)
                || control
                    .current_operation
                    .as_ref()
                    .is_some_and(|actual| actual != operation)
            {
                return Err(ProviderError::Correlation(
                    "native Capture currency crossed another dispatch",
                ));
            }
        }
        let mut metadata = MetadataObserver::new();
        let cursor = match &control.program {
            NativeProgram::OutputOnly(program) => {
                program.observe_original_live_capture_metadata(&mut metadata)?
            }
            NativeProgram::Connected(program) => {
                program.observe_original_live_capture_metadata(&mut metadata)?
            }
            NativeProgram::RestorationInProgress => {
                return Err(ProviderError::Conflict(
                    "native Capture currency model incomplete",
                ));
            }
        };
        if cursor != self.cursor {
            return Err(ProviderError::Correlation(
                "native Capture currency model moved",
            ));
        }
        Ok(())
    }

    // The same currency payload is projected before Observe registration. This
    // authenticates that earlier cut explicitly instead of invoking the later
    // completed-Observe owner guard on a stand-in owner.
    pub(crate) fn borrowed_before_observe_currency_data<'a>(
        &'a self,
        control: &'a PacketControl,
    ) -> Result<impl serde::Serialize + 'a, ProviderError> {
        self.authenticate_before_observe(control)?;
        Ok((
            "source-private.native-control-capture-currency/12",
            self.creator,
            self.originals_before,
            self.cursor,
            "source-private.native-control-identity-owner/12",
            "source-private.native-control-identity-owner/12",
        ))
    }

    pub(crate) fn observe_before_observe_currency_data(
        &self,
        control: &PacketControl,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_before_observe(control)?;
        use crate::retained_metadata::aliases::MetadataSharedKind;
        observer.shared_original(
            MetadataSharedKind::NativeControlIdentity,
            control.capture_identity.as_ref(),
        )?;
        observer.shared_original(
            MetadataSharedKind::NativeControlIdentity,
            self.identity.as_ref(),
        )?;
        observer.observe(&self.creator)?;
        observer.observe(&self.originals_before)?;
        observer.observe(&self.cursor)?;
        self.authenticate_before_observe(control)
    }

    pub(crate) fn borrowed_owned12_protocol_view<'a>(
        &'a self,
        control: &'a PacketControl,
        capture: Option<&Envelope>,
    ) -> Result<impl serde::Serialize + 'a, ProviderError> {
        self.authenticate_capture_boundary(control, capture)?;
        Ok((
            "source-private.native-control-capture-currency/12",
            self.creator,
            self.originals_before,
            self.cursor,
            "source-private.native-control-identity-owner/12",
            "source-private.native-control-identity-owner/12",
        ))
    }

    pub(crate) fn observe_owned12_metadata(
        &self,
        control: &PacketControl,
        capture: Option<&Envelope>,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_capture_boundary(control, capture)?;
        use crate::retained_metadata::aliases::MetadataSharedKind;
        observer.shared_original(
            MetadataSharedKind::NativeControlIdentity,
            control.capture_identity.as_ref(),
        )?;
        observer.shared_original(
            MetadataSharedKind::NativeControlIdentity,
            self.identity.as_ref(),
        )?;
        observer.observe(&self.creator)?;
        observer.observe(&self.originals_before)?;
        observer.observe(&self.cursor)
    }
}

impl PacketControl {
    pub(crate) fn quote_original_startup_fresh_restore_control(
        &self,
        policy: &Rc<super::super::Native5Policy>,
        endpoint: super::super::endpoint::PacketEndpointRestoreAllocation,
    ) -> Result<PacketFreshRestoreControlAllocation, ProviderError> {
        policy.authenticate_original_control_selection(&self.selection)?;
        endpoint.authenticate_original(policy)?;
        let view = self.borrow_original_fresh_report_data(policy)?;
        // The separate fixed Prepare action precedes this constructor. Clone
        // only the actual retained gate reference, never a model/inventory DTO.
        let gate = view.gate_receipt_data().clone();
        let mut roots = crate::retained_metadata::NativeCaptureMetadataRoots::new();
        let mut observer = MetadataObserver::new();
        self.observe_original_fresh_report_metadata(policy, &mut roots, &mut observer)?;
        observer.observe(&gate)?;
        roots.observe_shared_edge(
            &mut observer,
            crate::retained_metadata::aliases::MetadataSharedKind::NativeControlIdentity,
            self.capture_identity.as_ref(),
        )?;
        if roots.observe_shared(
            &mut observer,
            crate::retained_metadata::aliases::MetadataSharedKind::NativePolicy,
            policy.as_ref(),
        )? {
            policy.observe_unique_capture_metadata(&mut roots, &mut observer)?;
        }
        roots.finish()?;
        policy.authenticate_original_control_selection(&self.selection)?;
        if !self.original_fresh_report_window_data()? {
            return Err(ProviderError::Correlation(
                "startup restore Control changed",
            ));
        }
        Ok(PacketFreshRestoreControlAllocation {
            creator: self.capture_creator,
            identity: Rc::clone(&self.capture_identity),
            policy: Rc::clone(policy),
            facts: observer.finish(),
            endpoint,
            gate,
        })
    }
}

// These closed borrowed views preserve the Vec and pair visit boundaries while
// charging the actual owned tuple slots and each independent child allocation.
// They create no replacement evidence and do not add a generic tuple observer.
struct ReplyEvidenceMetadata<'a>(&'a Vec<(ContentRef, Vec<u8>)>);

struct ReplyEvidenceRow<'a>(&'a ContentRef, &'a Vec<u8>);

impl crate::retained_metadata::ObserveMetadata for ReplyEvidenceMetadata<'_> {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.vector::<(ContentRef, Vec<u8>)>(self.0.capacity())?;
        for (reference, bytes) in self.0 {
            observer.observe(&ReplyEvidenceRow(reference, bytes))?;
        }
        Ok(())
    }
}

impl crate::retained_metadata::ObserveMetadata for ReplyEvidenceRow<'_> {
    fn observe_metadata(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.observe(self.0)?;
        observer.observe(self.1)
    }
}

#[cfg(test)]
mod reply_evidence_metadata_tests {
    use super::*;

    #[test]
    fn actual_evidence_walk_preserves_tuple_slots_child_capacity_and_byte_visits()
    -> Result<(), ProviderError> {
        let mut first = Vec::with_capacity(37);
        first.extend_from_slice(b"first original");
        let mut second = Vec::with_capacity(101);
        second.extend_from_slice(b"second original retained bank");
        let mut evidence = Vec::with_capacity(7);
        evidence.push((
            canonical::content_ref(&first, "application/octet-stream")?,
            first,
        ));
        evidence.push((
            canonical::content_ref(&second, "application/octet-stream")?,
            second,
        ));
        let identity = (evidence.as_ptr(), evidence.len(), evidence.capacity());

        let mut actual = MetadataObserver::new();
        actual.observe(&ReplyEvidenceMetadata(&evidence))?;
        let actual = actual.finish();
        let mut children = MetadataObserver::new();
        for (reference, bytes) in &evidence {
            children.observe(reference)?;
            children.observe(bytes)?;
        }
        let children = children.finish();

        assert_eq!(actual.vector_banks, children.vector_banks + 1);
        assert_eq!(actual.capacity_records, children.capacity_records + 1);
        assert_eq!(
            actual.vector_capacity_bytes,
            children.vector_capacity_bytes
                + evidence.capacity() * std::mem::size_of::<(ContentRef, Vec<u8>)>()
        );
        assert_eq!(
            actual.observed_nodes,
            children.observed_nodes + 1 + evidence.len()
        );
        assert_eq!(actual.string_capacity_bytes, children.string_capacity_bytes);
        assert_eq!(
            identity,
            (evidence.as_ptr(), evidence.len(), evidence.capacity())
        );
        for (reference, bytes) in &evidence {
            reference.verify(bytes)?;
        }
        Ok(())
    }

    #[test]
    fn empty_evidence_walk_retains_original_spare_tuple_capacity() -> Result<(), ProviderError> {
        let evidence = Vec::with_capacity(9);
        let mut observer = MetadataObserver::new();
        observer.observe(&ReplyEvidenceMetadata(&evidence))?;
        let facts = observer.finish();
        assert_eq!(facts.vector_banks, 1);
        assert_eq!(facts.capacity_records, 1);
        assert_eq!(facts.observed_nodes, 1);
        assert_eq!(
            facts.vector_capacity_bytes,
            evidence.capacity() * std::mem::size_of::<(ContentRef, Vec<u8>)>()
        );
        Ok(())
    }
}

mod settled_quote17;
