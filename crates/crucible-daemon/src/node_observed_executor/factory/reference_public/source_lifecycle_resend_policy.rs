//! Authenticates completed originals before the optional guarded transport probe.
//!
//! Policy receives read-only adopted facts. Actual original envelopes and codec
//! bodies come from the inert archive, while kernel measurements authenticate
//! the current original process group. Neither source supplies a progress token.

use std::{cell::RefCell, rc::Rc};

use crucible::node_adapters::cnp::{
    CnpCompletedLifecycleQualification, CnpCompletedLifecycleScope, CnpLaunchGuard,
};
use crucible::node_contract::{EffectKnowledge, OperationFailure};
use crucible_node_contract::{ContentRef, canonical};
use crucible_node_provider::{
    ProviderError,
    bodies::{decode_request, decode_response},
    client::{ObservationHandle, ObservationLimits, ObservedContent, ObservedRequestKey},
    envelope::{Envelope, RequestOrigin},
    reference_service::ReferenceServiceBootstrap,
};

use super::{
    installation::SourcePublicReferenceInstallation,
    native::NativePublicEnrollment,
    package::InstalledPublicReferencePackage,
    source_lifecycle_evidence::{SourceLifecycleEvidence, SourceLifecycleEvidenceContext},
    source_lifecycle_requests::{SourceLifecycleRequestContext, SourceLifecycleRequests},
    source_lifecycle_resend_plan::SourceLifecycleResendPlan,
    source_lifecycle_world::SourceLifecycleWorld,
};

const MAXIMUM_OBSERVATION_BYTES: usize = 8 * 1024 * 1024;

pub(super) struct SourceLifecycleResendPolicy {
    package: Rc<InstalledPublicReferencePackage>,
    bootstrap: ReferenceServiceBootstrap,
    binding: crucible_node_contract::NodeBinding,
    owner: crucible_node_contract::OwnerBinding,
    profile: crucible_node_provider::reference_service::ReferenceProfile,
    plan: SourceLifecycleResendPlan,
    bindings: Vec<(
        crucible_node_contract::NodeBinding,
        crucible_node_contract::OwnerBinding,
    )>,
    grants: Vec<crucible_node_provider::reference_device::DeviceGrant>,
    world: Rc<SourceLifecycleWorld>,
    requests: RefCell<SourceLifecycleRequests>,
    evidence: RefCell<SourceLifecycleEvidence>,
    observer: RefCell<Option<ObservationHandle>>,
    peer_observers: Vec<Rc<RefCell<Option<ObservationHandle>>>>,
    native_origins: Vec<Rc<RefCell<Option<NativePublicEnrollment>>>>,
    selected: RefCell<Vec<OriginalLifecyclePremise>>,
    root_slots: RefCell<Vec<Vec<ContentRef>>>,
    #[cfg(test)]
    window_loss: RefCell<Option<Rc<super::source_window_provider_loss::SourceWindowProviderLoss>>>,
    #[cfg(test)]
    original_loss:
        RefCell<Option<Rc<super::source_original_response_loss::SourceOriginalResponseLoss>>>,
    #[cfg(test)]
    original_controls: RefCell<
        Vec<(
            CnpCompletedLifecycleScope,
            crucible_node_provider::bodies::RequestBody,
        )>,
    >,
}

/// Retains data authenticated from an actual completed original control.
pub(super) struct OriginalLifecycleFacts {
    pub(super) body: crucible_node_provider::bodies::RequestBody,
    pub(super) request: ContentRef,
    pub(super) response: ContentRef,
    pub(super) connection: crucible_node_contract::Id,
    pub(super) native: NativePublicEnrollment,
}

#[derive(serde::Serialize)]
pub(super) struct OriginalLifecyclePremise {
    request: crucible_node_contract::Id,
    original_request: ContentRef,
    original_response: ContentRef,
    evidence_roots: Vec<ContentRef>,
    native: NativePublicEnrollment,
}

impl SourceLifecycleResendPolicy {
    /// Checks inert mutations against authentic callback scopes and publication.
    ///
    /// # Errors
    /// Refuses missing original data or an adverse mutation accepted by the
    /// production codec reader. The helper sends no controls and grants no scope.
    #[cfg(test)]
    pub(super) fn verify_reader_adverse_controls(
        &self,
        peer: &Self,
    ) -> Result<serde_json::Value, ProviderError> {
        let mut peer_originals = Vec::new();
        peer_originals.try_reserve_exact(2).map_err(|_| {
            ProviderError::ResourceExhausted("reader counterfactual peer snapshot slots")
        })?;
        for slot in &self.peer_observers {
            let observer = slot.borrow();
            let observer = observer.as_ref().ok_or(ProviderError::Correlation(
                "original reader peer observation unavailable",
            ))?;
            peer_originals.push(observer.snapshot(
                &observer.request_keys()?,
                &observer.content_references()?,
                ObservationLimits {
                    maximum_requests: 1024,
                    maximum_objects: 1024,
                    maximum_bytes: MAXIMUM_OBSERVATION_BYTES,
                },
            )?);
        }
        let index = self
            .bindings
            .iter()
            .position(|(binding, _)| binding == &self.binding)
            .ok_or(ProviderError::Correlation(
                "original reader owner unavailable",
            ))?;
        let original = peer_originals.get(index).ok_or(ProviderError::Correlation(
            "original reader archive unavailable",
        ))?;
        if self.native_origins.len() != 2 {
            return Err(ProviderError::Correlation(
                "original reader native roster differs",
            ));
        }
        let mut original_companion_pids = [0u32; 2];
        for (index, origin) in self.native_origins.iter().enumerate() {
            original_companion_pids[index] = origin
                .borrow()
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "original reader native enrollment absent",
                ))?
                .original_companion_pid()?;
        }
        let own_controls = self.original_controls.borrow();
        let peer_controls = peer.original_controls.borrow();
        super::source_lifecycle_evidence_tests::verify_reader_adverse_controls(
            &own_controls,
            &peer_controls,
            SourceLifecycleEvidenceContext {
                original,
                peer_originals: &peer_originals,
                bindings: &self.bindings,
                grants: &self.grants,
                world: &self.world,
                original_companion_pids: &original_companion_pids,
            },
        )
    }

    /// Retains the source-selected population and finite observation slots.
    ///
    /// # Errors
    /// Refuses installation binding drift or failed pre-effect reservation.
    pub(super) fn new(
        installed: &SourcePublicReferenceInstallation,
        plan: SourceLifecycleResendPlan,
        bindings: Vec<(
            crucible_node_contract::NodeBinding,
            crucible_node_contract::OwnerBinding,
        )>,
        grants: Vec<crucible_node_provider::reference_device::DeviceGrant>,
        world: Rc<SourceLifecycleWorld>,
        peer_observers: Vec<Rc<RefCell<Option<ObservationHandle>>>>,
        native_origins: Vec<Rc<RefCell<Option<NativePublicEnrollment>>>>,
    ) -> Result<Self, ProviderError> {
        let (binding, owner) = installed.profile.bind_qualified(
            installed.bootstrap.authority.clone(),
            &installed.qualifications,
        )?;
        let mut selected = Vec::new();
        selected
            .try_reserve_exact(super::source_lifecycle_resend_plan::MAXIMUM_SELECTED_CONTROLS)
            .map_err(|_| ProviderError::ResourceExhausted("source lifecycle observation slots"))?;
        let mut root_slots = Vec::new();
        root_slots
            .try_reserve_exact(super::source_lifecycle_resend_plan::MAXIMUM_SELECTED_CONTROLS)
            .map_err(|_| ProviderError::ResourceExhausted("source lifecycle closure slots"))?;
        for _ in 0..super::source_lifecycle_resend_plan::MAXIMUM_SELECTED_CONTROLS {
            let mut roots = Vec::new();
            roots
                .try_reserve_exact(1024)
                .map_err(|_| ProviderError::ResourceExhausted("source lifecycle closure rows"))?;
            root_slots.push(roots);
        }
        #[cfg(test)]
        let original_controls = {
            let mut controls = Vec::new();
            controls
                .try_reserve_exact(super::source_lifecycle_resend_plan::MAXIMUM_SELECTED_CONTROLS)
                .map_err(|_| {
                    ProviderError::ResourceExhausted("original reader test control slots")
                })?;
            RefCell::new(controls)
        };
        Ok(Self {
            package: Rc::clone(&installed.package),
            bootstrap: installed.bootstrap.clone(),
            binding,
            owner,
            profile: installed.profile.clone(),
            plan,
            bindings,
            grants,
            world,
            requests: RefCell::new(SourceLifecycleRequests::reserve()?),
            evidence: RefCell::new(SourceLifecycleEvidence::reserve()?),
            observer: RefCell::new(None),
            peer_observers,
            native_origins,
            selected: RefCell::new(selected),
            root_slots: RefCell::new(root_slots),
            #[cfg(test)]
            original_controls,
            #[cfg(test)]
            window_loss: RefCell::new(None),
            #[cfg(test)]
            original_loss: RefCell::new(None),
        })
    }

    /// Selects the exact declared consumer native completion before launch.
    ///
    /// # Errors
    /// Refuses missing original fixture scope or replacement of its custody.
    #[cfg(test)]
    pub(super) fn window_loss_target(&self) -> Result<crucible_node_contract::Id, ProviderError> {
        self.plan
            .targets
            .iter()
            .find(|target| {
                target.phase
                    == crucible::node_adapters::cnp::CnpCompletedLifecyclePhase::WindowCompleted
                    && target
                        .grant
                        .as_ref()
                        .is_some_and(|grant| grant.quantum.get() == 1)
            })
            .map(|target| target.request.clone())
            .ok_or(ProviderError::Correlation("loss original target absent"))
    }

    /// Retains the declared adverse fixture before observation or native controls.
    ///
    /// # Errors
    /// Refuses missing original fixture scope or replacement of its custody.
    #[cfg(test)]
    pub(super) fn attach_window_loss(
        &self,
        loss: Rc<super::source_window_provider_loss::SourceWindowProviderLoss>,
    ) -> Result<(), ProviderError> {
        if self.window_loss.borrow().is_some() || self.observer.borrow().is_some() {
            return Err(ProviderError::Correlation(
                "loss fixture must precede original controls",
            ));
        }
        *self.window_loss.borrow_mut() = Some(loss);
        Ok(())
    }

    /// Opens the loss anchor while the original Child is still guarded.
    ///
    /// # Errors
    /// Refuses missing original fixture scope or replacement of its custody.
    #[cfg(test)]
    pub(super) fn arm_window_loss(&self, guard: &CnpLaunchGuard) -> Result<(), ProviderError> {
        if let Some(loss) = self.window_loss.borrow().as_ref() {
            loss.arm(guard)?;
        }
        if let Some(loss) = self.original_loss.borrow().as_ref() {
            loss.arm(guard)?;
        }
        Ok(())
    }

    /// Retains a distinct original-response loss fixture before any controls.
    ///
    /// # Errors
    /// Refuses late or duplicate source plan installation.
    #[cfg(test)]
    pub(super) fn attach_original_loss(
        &self,
        loss: Rc<super::source_original_response_loss::SourceOriginalResponseLoss>,
    ) -> Result<(), ProviderError> {
        if self.original_loss.borrow().is_some() || self.observer.borrow().is_some() {
            return Err(ProviderError::Correlation(
                "original-loss fixture already installed",
            ));
        }
        *self.original_loss.borrow_mut() = Some(loss);
        Ok(())
    }

    /// Reserves the distinct first-original loss archive before controller effects.
    ///
    /// # Errors
    /// Refuses unavailable finite source plan or controller observation custody.
    #[cfg(test)]
    pub(super) fn install_original_loss(
        &self,
        controller: &mut crucible_node_provider::client::ReferenceController,
    ) -> Result<(), ProviderError> {
        if let Some(loss) = self.original_loss.borrow().as_ref() {
            loss.install(controller)?;
        }
        Ok(())
    }

    /// Associates the inert archive before the first original control.
    ///
    /// # Errors
    /// Refuses replacement of the one original archive or an already used policy.
    pub(super) fn attach_observer(&self, observer: ObservationHandle) -> Result<(), ProviderError> {
        let mut original = self.observer.borrow_mut();
        if original.is_some() || !self.selected.borrow().is_empty() {
            return Err(ProviderError::Correlation(
                "original lifecycle archive already attached",
            ));
        }
        *original = Some(observer);
        Ok(())
    }

    /// Retains the actual successful realization's independent kernel enrollment.
    ///
    /// # Errors
    /// Refuses an absent original source slot or replacement after realization.
    pub(super) fn record_original_native(
        &self,
        original: NativePublicEnrollment,
    ) -> Result<(), ProviderError> {
        let index = self
            .bindings
            .iter()
            .position(|(binding, _)| binding == &self.binding)
            .ok_or(ProviderError::Correlation(
                "original source owner not enrolled",
            ))?;
        let slot = self
            .native_origins
            .get(index)
            .ok_or(ProviderError::Correlation(
                "original source native slot absent",
            ))?;
        let mut retained = slot.borrow_mut();
        if retained.is_some() {
            return Err(ProviderError::Correlation(
                "original source native enrollment cannot be replaced",
            ));
        }
        *retained = Some(original);
        Ok(())
    }

    pub(super) fn retained_premises(&self) -> serde_json::Value {
        serde_json::json!({
            "fixture":self.plan.fixture,
            "fixture_bytes":crucible_node_contract::Bytes::new(self.plan.bytes.clone()),
            "original_activation":crucible::node_contract::SavedRuntimeActivation::from(&self.plan.activation),
            "targets":self.plan.targets.iter().map(|target| serde_json::json!({
                "request":target.request,"phase":phase_name(target.phase),"operation":target.operation,
                "method":target.method,"grant":target.grant,"selected":target.selected,
                "window":target.window.as_ref().map(|window|serde_json::json!({
                    "grant":window.grant,"input_cut":window.input_cut,
                    "input_sequence":window.input_sequence,"expected_input":window.expected_input
                }))
            })).collect::<Vec<_>>(),
            "selected": &*self.selected.borrow()
        })
    }

    /// Collects the exact successful transport population after original windows.
    ///
    /// # Errors
    /// Refuses missing selected controls, changed immutable originals, incomplete
    /// actual transmissions or a mismatch with the original safe prefix. Failure
    /// leaves the actor's original native and transmission journals owned.
    pub(super) fn collect(
        &self,
        transmissions: &crucible_node_provider::client::TransmissionObservationHandle,
        safe_requests: &[crucible_node_contract::Id],
    ) -> Result<serde_json::Value, ProviderError> {
        let selected = self.selected.borrow();
        if safe_requests.len() != 3
            || selected.len() != super::source_lifecycle_resend_plan::MAXIMUM_SELECTED_CONTROLS
        {
            return Err(ProviderError::Correlation(
                "original lifecycle selected population incomplete",
            ));
        }
        let mut requests = Vec::new();
        requests
            .try_reserve_exact(13)
            .map_err(|_| ProviderError::ResourceExhausted("lifecycle completed population"))?;
        requests.extend_from_slice(safe_requests);
        requests.extend(selected.iter().map(|row| row.request.clone()));
        let keys = requests
            .iter()
            .map(|request| ObservedRequestKey {
                origin: RequestOrigin::Controller,
                request_id: request.clone(),
            })
            .collect::<Vec<_>>();
        let observer = self.observer.borrow();
        let observer = observer.as_ref().ok_or(ProviderError::Correlation(
            "original lifecycle archive absent",
        ))?;
        let original = observer.snapshot(
            &keys,
            &observer.content_references()?,
            ObservationLimits {
                maximum_requests: 13,
                maximum_objects: 1024,
                maximum_bytes: MAXIMUM_OBSERVATION_BYTES,
            },
        )?;
        if !original.recording_complete
            || original.observed_unknown
            || original.recording_failure.0.is_some()
        {
            return Err(ProviderError::Correlation(
                "original lifecycle archive incomplete",
            ));
        }
        for row in selected.iter() {
            let control = original
                .evidence
                .requests
                .iter()
                .find(|control| control.key.request_id == row.request)
                .ok_or(ProviderError::Correlation(
                    "original lifecycle control missing",
                ))?;
            if control.request.reference != row.original_request
                || control
                    .response
                    .0
                    .as_ref()
                    .map(|response| &response.reference)
                    != Some(&row.original_response)
            {
                return Err(ProviderError::Correlation(
                    "original lifecycle journal replaced",
                ));
            }
        }
        let wire = serde_json::to_value(transmissions.snapshot(MAXIMUM_OBSERVATION_BYTES)?)
            .map_err(crucible_node_contract::ContractError::from)?;
        super::source_resend_execution::verify_complete_population(&wire, &original, &requests)?;
        Ok(serde_json::json!({
            "schema":"crucible.reference.source-completed-resends.v1",
            "fixture":self.plan.fixture,"fixture_bytes":crucible_node_contract::Bytes::new(self.plan.bytes.clone()),
            "selected":&*selected,
            "original_snapshot_bytes":crucible_node_contract::Bytes::new(original.encode(MAXIMUM_OBSERVATION_BYTES)?),
            "transmitted_snapshot_bytes":crucible_node_contract::Bytes::new(canonical::canonical_json(&wire)?),
            "exclusions":["body-conflict","reconnect","whole-clause-credit","ordinary-ready"]
        }))
    }

    fn authenticate_original(
        &self,
        guard: &CnpLaunchGuard,
        scope: &CnpCompletedLifecycleScope,
    ) -> Result<bool, ProviderError> {
        if self
            .plan
            .targets
            .iter()
            .find(|target| target.request == scope.request_id)
            .is_some_and(|target| !target.selected)
        {
            // Excluded originals still need exact scope validation, but consume
            // none of the ten evidence slots reserved for selected sends.
            let mut unused_roots = Vec::new();
            if self
                .inspect_original(guard, scope, &mut unused_roots)?
                .is_some()
            {
                return Err(ProviderError::Correlation(
                    "excluded original selected evidence",
                ));
            }
            return Ok(false);
        }
        if self
            .selected
            .borrow()
            .iter()
            .any(|row| row.request == scope.request_id)
        {
            return Err(ProviderError::Correlation(
                "completed original population repeated",
            ));
        }
        let mut roots =
            self.root_slots
                .borrow_mut()
                .pop()
                .ok_or(ProviderError::ResourceExhausted(
                    "source lifecycle closure slot exhausted",
                ))?;
        let Some(facts) = self.inspect_original(guard, scope, &mut roots)? else {
            self.root_slots.borrow_mut().push(roots);
            return Ok(false);
        };
        self.selected.borrow_mut().push(OriginalLifecyclePremise {
            request: scope.request_id.clone(),
            original_request: facts.request,
            original_response: facts.response,
            evidence_roots: roots,
            native: facts.native,
        });
        #[cfg(test)]
        self.original_controls
            .borrow_mut()
            .push((scope.clone(), facts.body));
        #[cfg(test)]
        if let Some(loss) = self.window_loss.borrow().as_ref() {
            let selected = self.selected.borrow();
            let premise = selected
                .last()
                .ok_or(ProviderError::Correlation("loss original premise absent"))?;
            let observer = self.observer.borrow();
            loss.after_adoption(
                guard,
                scope,
                premise,
                observer
                    .as_ref()
                    .ok_or(ProviderError::Correlation("loss original observer absent"))?,
            )?;
        }
        Ok(true)
    }

    /// Rechecks immutable originals and live enrollment for a distinct probe.
    ///
    /// # Errors
    /// Refuses any changed scope, source recipe, typed closure or original native
    /// group. The caller provides its separately reserved evidence slots.
    pub(super) fn inspect_original(
        &self,
        guard: &CnpLaunchGuard,
        scope: &CnpCompletedLifecycleScope,
        evidence_roots: &mut Vec<ContentRef>,
    ) -> Result<Option<OriginalLifecycleFacts>, ProviderError> {
        let target = self
            .plan
            .targets
            .iter()
            .find(|target| target.request == scope.request_id)
            .ok_or(ProviderError::Correlation("unplanned completed original"))?;
        if target.phase != scope.phase
            || target.operation != scope.operation_id
            || target.method != scope.method
            || target.grant != scope.grant
            || self.plan.activation != scope.activation
            || self.binding.identity()? != scope.binding_hash
            || self.owner.identity()? != scope.owner_binding_hash
        {
            return Err(ProviderError::Correlation(
                "completed original scope differs",
            ));
        }
        if !target.selected {
            return Ok(None);
        }
        let keys = [ObservedRequestKey {
            origin: RequestOrigin::Controller,
            request_id: scope.request_id.clone(),
        }];
        let observer = self.observer.borrow();
        let observer = observer.as_ref().ok_or(ProviderError::Correlation(
            "original lifecycle archive absent",
        ))?;
        let references = observer.content_references()?;
        let original = observer.snapshot(
            &keys,
            &references,
            ObservationLimits {
                maximum_requests: 1,
                maximum_objects: 1024,
                maximum_bytes: MAXIMUM_OBSERVATION_BYTES,
            },
        )?;
        let expected_scope = &original.evidence.scope;
        if !original.recording_complete
            || original.observed_unknown
            || original.recording_failure.0.is_some()
            || expected_scope.session_id != self.bootstrap.authority.session_id
            || expected_scope.incarnation_id != self.bootstrap.authority.incarnation_id
            || expected_scope.compatibility != self.binding.compatibility
            || expected_scope.binding_hash != self.binding.identity()?
            || expected_scope.selected_features != super::unit::required_features()?
            || original.evidence.requests.len() != 1
        {
            return Err(ProviderError::Correlation(
                "completed original observation unavailable",
            ));
        }
        let control = &original.evidence.requests[0];
        let response = control
            .response
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation("original completion unknown"))?;
        let request = envelope(&control.request)?;
        let reply = envelope(response)?;
        request.matches_response(&reply)?;
        let owned = matches!(
            scope.method,
            crucible_node_provider::envelope::Method::Input
                | crucible_node_provider::envelope::Method::Begin
                | crucible_node_provider::envelope::Method::QuantumClose
                | crucible_node_provider::envelope::Method::Retire
        );
        if request.request_id.0.as_ref() != Some(&scope.request_id)
            || request.operation_id.0 != scope.operation_id
            || request.method != scope.method
            || request.session_id.0.as_ref() != Some(&self.bootstrap.authority.session_id)
            || request.incarnation_id.0.as_ref() != Some(&self.bootstrap.authority.incarnation_id)
            || request.node_id.0 != owned.then(|| self.bootstrap.node_id.clone())
            || request.execution_owner_id.0 != owned.then(|| self.bootstrap.owner_id.clone())
            || request.capture_owner_id.0.is_some()
            || request.request_hash(RequestOrigin::Controller)? != control.identity
            || decode_response(&decode_request(request.method, &request.body)?, &reply.body)?
                .result
                .as_ref()
                != Some(&scope.original_result)
        {
            return Err(ProviderError::Correlation(
                "completed original control or result differs",
            ));
        }
        let body = decode_request(request.method, &request.body)?;
        self.requests.borrow_mut().verify(
            &body,
            SourceLifecycleRequestContext {
                profile: &self.profile,
                bootstrap: &self.bootstrap,
                owner: &self.owner,
                target,
                scope,
                original: &original,
            },
        )?;
        let mut peer_originals = Vec::new();
        peer_originals
            .try_reserve_exact(2)
            .map_err(|_| ProviderError::ResourceExhausted("source peer snapshot slots"))?;
        if self.peer_observers.len() != 2 {
            return Err(ProviderError::Correlation(
                "source peer archive roster differs",
            ));
        }
        for (peer_slot, (binding, _)) in self.peer_observers.iter().zip(&self.bindings) {
            let peer = peer_slot.borrow();
            let peer = peer
                .as_ref()
                .ok_or(ProviderError::Correlation("source peer archive absent"))?;
            let recorded = peer.snapshot(
                &peer.request_keys()?,
                &peer.content_references()?,
                ObservationLimits {
                    maximum_requests: 1024,
                    maximum_objects: 1024,
                    maximum_bytes: MAXIMUM_OBSERVATION_BYTES,
                },
            )?;
            if !recorded.recording_complete
                || recorded.observed_unknown
                || recorded.recording_failure.0.is_some()
                || recorded.evidence.scope.provider_executable
                    != *self.package.artifact_content("provider").map_err(|error| {
                        ProviderError::Io(std::io::Error::other(error.to_string()))
                    })?
                || recorded.evidence.scope.compatibility != binding.compatibility
                || recorded.evidence.scope.binding_hash != binding.identity()?
                || recorded.evidence.scope.selected_features != super::unit::required_features()?
            {
                return Err(ProviderError::Correlation(
                    "source peer archive scope differs",
                ));
            }
            peer_originals.push(recorded);
        }
        if self.native_origins.len() != 2 {
            return Err(ProviderError::Correlation(
                "original native enrollment roster differs",
            ));
        }
        let mut original_companion_pids = [0u32; 2];
        for (index, origin) in self.native_origins.iter().enumerate() {
            original_companion_pids[index] = origin
                .borrow()
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "original native enrollment absent",
                ))?
                .original_companion_pid()?;
        }
        let mut reader = self.evidence.borrow_mut();
        let verified = reader.verify(
            scope,
            &body,
            SourceLifecycleEvidenceContext {
                original: &original,
                peer_originals: &peer_originals,
                bindings: &self.bindings,
                grants: &self.grants,
                world: &self.world,
                original_companion_pids: &original_companion_pids,
            },
        )?;
        if !evidence_roots.is_empty() || evidence_roots.capacity() < 1024 {
            return Err(ProviderError::ResourceExhausted(
                "distinct original closure slots unavailable",
            ));
        }
        evidence_roots.extend_from_slice(verified);
        drop(reader);
        // Discover actual ancestry from the kernel, never from the supplied
        // phase/receipt or cached guard companion metadata.
        let native = NativePublicEnrollment::enroll_original_group(
            guard
                .provider_pid()
                .ok_or(ProviderError::Correlation("original provider unavailable"))?,
            guard.supervision_id(),
            &self.package,
            &self.bootstrap.resource_limits,
        )?;
        let peer = self
            .bindings
            .iter()
            .position(|(binding, _)| binding == &self.binding)
            .ok_or(ProviderError::Correlation("original source peer missing"))?;
        if self.native_origins[peer].borrow().as_ref() != Some(&native) {
            return Err(ProviderError::Correlation(
                "actual native enrollment changed from original realization",
            ));
        }
        Ok(Some(OriginalLifecycleFacts {
            body,
            request: control.request.reference.clone(),
            response: response.reference.clone(),
            connection: expected_scope.connection_id.clone(),
            native,
        }))
    }
}

impl CnpCompletedLifecycleQualification for SourceLifecycleResendPolicy {
    fn authenticate(
        &self,
        guard: &CnpLaunchGuard,
        scope: &CnpCompletedLifecycleScope,
    ) -> Result<bool, OperationFailure> {
        self.authenticate_original(guard, scope)
            .map_err(|error| OperationFailure {
                effects: EffectKnowledge::Unknown,
                reason: error.to_string(),
            })
    }
}

fn envelope(content: &ObservedContent) -> Result<Envelope, ProviderError> {
    content.reference.verify(content.bytes.as_slice())?;
    let value = canonical::parse_json(content.bytes.as_slice(), MAXIMUM_OBSERVATION_BYTES)?;
    if canonical::canonical_json(&value)? != content.bytes.as_slice() {
        return Err(ProviderError::Correlation("original control noncanonical"));
    }
    let envelope: Envelope =
        serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
    envelope.validate()?;
    Ok(envelope)
}

fn phase_name(phase: crucible::node_adapters::cnp::CnpCompletedLifecyclePhase) -> &'static str {
    use crucible::node_adapters::cnp::CnpCompletedLifecyclePhase;
    match phase {
        CnpCompletedLifecyclePhase::Prepared => "prepared",
        CnpCompletedLifecyclePhase::WorldActivated => "world-activated",
        CnpCompletedLifecyclePhase::InputAccepted => "input-accepted",
        CnpCompletedLifecyclePhase::WindowCompleted => "window-completed",
        CnpCompletedLifecyclePhase::PublicationClosed => "publication-closed",
        CnpCompletedLifecyclePhase::PublicationConsumed => "publication-consumed",
    }
}
