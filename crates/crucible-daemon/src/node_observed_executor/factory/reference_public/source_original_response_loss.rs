//! Retains an original sent Begin with no completion read and unknown effects.
//!
//! The fixture signals only the original guarded provider through a retained
//! pidfd. Its companion, original request journal and known predecessor remain
//! in original custody. This does not prove that the selected native run completed.

use std::{cell::RefCell, os::fd::OwnedFd, rc::Rc, time::Duration};

use crucible::node_adapters::cnp::CnpLaunchGuard;
use crucible_node_contract::{Bytes, ContentRef, Id, OperatingMode};
use crucible_node_provider::{
    ProviderError,
    bodies::{BeginArguments, RequestBody, decode_request},
    client::{
        OriginalResponseLossObservationHandle, OriginalResponseLossQualification,
        ReferenceController,
    },
    envelope::{Envelope, Method, RequestOrigin},
    reference_device::{DeviceGrant, DeviceReceipt},
    reference_service::{ReferenceProfile, ReferenceServiceBootstrap},
};
use rustix::{
    event::{PollFd, PollFlags, poll},
    process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal},
};
use serde_json::Value;

use super::{
    installation::SourcePublicReferenceInstallation, native::NativePublicEnrollment,
    package::InstalledPublicReferencePackage,
};

/// Declares the exact source loss recipe independently of live process IDs.
pub(super) fn fixture() -> Value {
    serde_json::json!({
        "schema":"crucible.reference.original-response-loss-fixture.v1",
        "node":"consumer","quantum":"1","phase":"first-original-write-before-any-reply-read",
        "predecessor":"actual original quantum0 receipt processed0/checksum0; same owner/incarnation/generation",
        "input":"exact original coordinator frozen38bytes; no claimed resulting checksum",
        "maximum_original_frame_bytes":65536,"maximum_input_bytes":4096,
        "signal":"original provider-only pidfd SIGKILL after connection fences",
        "maximum_signals":1,"terminal_wait_ns":"3000000000",
        "retention":"original first sent envelope/write completion, original journal response=None, authentic runtime uncertain token",
        "exclusions":["guaranteed native progress","known physical completion","reconnect","cancellation","whole-clause credit","ordinary Ready"]
    })
}

#[derive(serde::Serialize)]
struct OriginalPredecessor {
    reference: ContentRef,
    bytes: Bytes,
    receipt: DeviceReceipt,
}

/// Keeps the exact signal anchor, known native predecessor and loss attempt.
pub(super) struct SourceOriginalResponseLoss {
    request: Id,
    operation: Id,
    grant: DeviceGrant,
    owner_hash: crucible_node_contract::HashRef,
    bootstrap: ReferenceServiceBootstrap,
    profile: ReferenceProfile,
    package: Rc<InstalledPublicReferencePackage>,
    native_origin: Rc<RefCell<Option<NativePublicEnrollment>>>,
    archive: RefCell<Option<OriginalResponseLossObservationHandle>>,
    provider: RefCell<Option<(u32, OwnedFd)>>,
    original_input: RefCell<Option<Vec<u8>>>,
    predecessor: RefCell<Option<OriginalPredecessor>>,
    original: RefCell<Option<Value>>,
    recovery: RefCell<Option<Value>>,
}

impl SourceOriginalResponseLoss {
    /// Reserves the one source-selected attempted population before Child.
    pub(super) fn new(
        installed: &SourcePublicReferenceInstallation,
        request: Id,
        case: &crate::node_qualification::ReferenceWindowCase,
        native_origin: Rc<RefCell<Option<NativePublicEnrollment>>>,
    ) -> Result<Self, ProviderError> {
        let (_, owner) = installed.profile.bind_qualified(
            installed.bootstrap.authority.clone(),
            &installed.qualifications,
        )?;
        Ok(Self {
            request,
            operation: case.operation.clone(),
            grant: case.grant.clone(),
            owner_hash: owner.identity()?,
            bootstrap: installed.bootstrap.clone(),
            profile: installed.profile.clone(),
            package: Rc::clone(&installed.package),
            native_origin,
            archive: RefCell::new(None),
            provider: RefCell::new(None),
            original_input: RefCell::new(None),
            predecessor: RefCell::new(None),
            original: RefCell::new(None),
            recovery: RefCell::new(None),
        })
    }

    /// Installs the finite inert hook while the controller still precedes all controls.
    ///
    /// # Errors
    /// Refuses late installation or unavailable complete original-frame credit.
    pub(super) fn install(
        self: &Rc<Self>,
        controller: &mut ReferenceController,
    ) -> Result<(), ProviderError> {
        if self.archive.borrow().is_some() {
            return Err(refused("original-loss observer already installed"));
        }
        let archive =
            controller.install_original_response_loss(self.request.clone(), self.clone(), 65536)?;
        *self.archive.borrow_mut() = Some(archive);
        Ok(())
    }

    /// Reads only the original bounded frame observation.
    ///
    /// # Errors
    /// Refuses an absent original observer or exhausted read cap.
    pub(super) fn wire(&self) -> Result<Value, ProviderError> {
        let archive = self.archive.borrow();
        let archive = archive
            .as_ref()
            .ok_or(refused("original-loss observer absent"))?;
        serde_json::to_value(archive.snapshot(65536)?)
            .map_err(crucible_node_contract::ContractError::from)
            .map_err(ProviderError::from)
    }

    /// Anchors the unreaped original Child before its first native control.
    ///
    /// # Errors
    /// Refuses a missing guarded provider, reused anchor or failed pidfd open.
    pub(super) fn arm(&self, guard: &CnpLaunchGuard) -> Result<(), ProviderError> {
        if self.provider.borrow().is_some() {
            return Err(refused("loss anchor already installed"));
        }
        let provider = guard
            .provider_pid()
            .ok_or(refused("loss original provider absent"))?;
        let pid = i32::try_from(provider)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or(refused("loss original PID invalid"))?;
        let descriptor = pidfd_open(pid, PidfdFlags::empty()).map_err(std::io::Error::from)?;
        *self.provider.borrow_mut() = Some((provider, descriptor));
        Ok(())
    }

    /// Retains the earlier actual common-runtime receipt before this run.
    ///
    /// # Errors
    /// Refuses missing, changed, nonzero or replacement predecessor evidence.
    pub(super) fn record_predecessor(
        &self,
        window: &crate::node_qualification::ReferenceWindowObservation,
    ) -> Result<(), ProviderError> {
        if self.predecessor.borrow().is_some() || window.receipt_bytes.as_slice().len() > 65536 {
            return Err(refused("loss original predecessor unavailable"));
        }
        window.receipt.verify(window.receipt_bytes.as_slice())?;
        let receipt: DeviceReceipt = serde_json::from_slice(window.receipt_bytes.as_slice())
            .map_err(crucible_node_contract::ContractError::from)?;
        if receipt.grant != window.original_grant
            || receipt.grant.quantum.get() != 0
            || receipt.output.bytes_processed.get() != 0
            || receipt.output.checksum.get() != 0
            || !receipt.application_parked
        {
            return Err(refused(
                "loss predecessor is not the known parked initial window",
            ));
        }
        *self.predecessor.borrow_mut() = Some(OriginalPredecessor {
            reference: window.receipt.clone(),
            bytes: window.receipt_bytes.clone(),
            receipt,
        });
        Ok(())
    }

    /// Retains the exact coordinator-frozen input before the native Begin.
    ///
    /// # Errors
    /// Refuses empty/oversized input or replacement of the original input.
    pub(super) fn record_input(&self, input: Vec<u8>) -> Result<(), ProviderError> {
        if input.is_empty() || input.len() > 4096 || self.original_input.borrow().is_some() {
            return Err(refused("loss input is not one original nonempty batch"));
        }
        *self.original_input.borrow_mut() = Some(input);
        Ok(())
    }

    /// Retains one immutable cached-denial observation without rerunning work.
    ///
    /// # Errors
    /// Refuses replacement of the original recovery evidence.
    pub(super) fn retain_recovery(&self, value: Value) -> Result<(), ProviderError> {
        if self.recovery.borrow().is_some() {
            return Err(refused("loss recovery cannot be replaced"));
        }
        *self.recovery.borrow_mut() = Some(value);
        Ok(())
    }

    /// Copies the original partial loss data without creating native authority.
    pub(super) fn retained(&self) -> Value {
        serde_json::json!({"fixture":fixture(),"target_request":self.request,"original":&*self.original.borrow(),"recovery":&*self.recovery.borrow(),"ordinary_qualification":false})
    }
}

impl OriginalResponseLossQualification for SourceOriginalResponseLoss {
    fn authenticate_before_send(&self, original: &Envelope) -> Result<(), ProviderError> {
        if self.original.borrow().is_some()
            || original.method != Method::Begin
            || original.request_id.0.as_ref() != Some(&self.request)
            || original.operation_id.0.as_ref() != Some(&self.operation)
            || original.session_id.0.as_ref() != Some(&self.bootstrap.authority.session_id)
            || original.incarnation_id.0.as_ref() != Some(&self.bootstrap.authority.incarnation_id)
            || original.node_id.0.as_ref() != Some(&self.bootstrap.node_id)
            || original.execution_owner_id.0.as_ref() != Some(&self.bootstrap.owner_id)
            || original.capture_owner_id.0.is_some()
            || !original.extensions.is_empty()
        {
            return Err(refused("original-loss original envelope differs"));
        }
        let RequestBody::Begin(body) = decode_request(original.method, &original.body)? else {
            return Err(refused("original-loss Begin body absent"));
        };
        let BeginArguments::QuantumBegin(arguments) = body.decoded_arguments()? else {
            return Err(refused("original-loss original quantum arguments absent"));
        };
        if body.binding_hash != self.owner_hash
            || body.owner_generation != self.grant.generation
            || body.activation_id.0.as_ref() != Some(&self.bootstrap.activation_id)
            || body.world_generation != self.bootstrap.world_generation
            || !body.extensions.is_empty()
            || arguments.grant_id != self.grant.window_id
            || arguments.participant_ids != self.profile.owner.participant_ids
            || arguments.realization_id != self.bootstrap.authority.realization_id
            || arguments.activation_id != self.bootstrap.activation_id
            || arguments.world_generation != self.bootstrap.world_generation
            || arguments.owner_generation != self.grant.generation
            || arguments.input_epoch != self.bootstrap.authority.input_epoch
            || arguments.mode != OperatingMode::Quantized
            || arguments.ordering_profile != "superdense-v1"
            || arguments.quantum_index != self.grant.quantum
            || arguments.from_ps != self.grant.start.time_ps
            || arguments.until_ps != self.grant.publication.time_ps
            || arguments.input_watermark
                != self
                    .grant
                    .quantum
                    .checked_add(crucible_node_contract::U64::new(1))?
            || arguments.policy_hash != self.profile.operating_contract.policy_ref.hash
            || arguments.wall_budget_ns != self.grant.host_budget_ns
        {
            return Err(refused("original-loss exact original body differs"));
        }
        let input = self.original_input.borrow();
        let input = input
            .as_ref()
            .ok_or(refused("original-loss frozen input absent"))?;
        if input.as_slice() != br#"{"bytes_processed":"0","checksum":"0"}"# {
            return Err(refused("original-loss original frozen38B differs"));
        }
        let predecessor = self.predecessor.borrow();
        let predecessor = predecessor
            .as_ref()
            .ok_or(refused("original-loss predecessor absent"))?;
        if predecessor.receipt.grant.owner_id != self.grant.owner_id
            || predecessor.receipt.grant.incarnation_id != self.grant.incarnation_id
            || predecessor.receipt.grant.generation != self.grant.generation
        {
            return Err(refused("original-loss original predecessor owner differs"));
        }
        let native = self.native_origin.borrow();
        let native = native
            .as_ref()
            .ok_or(refused("original-loss native enrollment absent"))?;
        native.authenticate(&self.package, &self.bootstrap.resource_limits)?;
        if self.provider.borrow().as_ref().map(|(pid, _)| *pid)
            != Some(native.original_provider_pid()?)
        {
            return Err(refused(
                "original-loss pidfd differs from original native enrollment",
            ));
        }
        *self.original.borrow_mut() = Some(serde_json::json!({
            "original_native_premise":native,"original_predecessor":predecessor,
            "frozen_input":input,"original_request_hash":original.request_hash(RequestOrigin::Controller)?,
            "expected_grant":self.grant,"effect_knowledge":"UNKNOWN",
            "signal_attempted":false,"completion_read":false
        }));
        Ok(())
    }

    fn after_original_write(&self, original: &Envelope) -> Result<(), ProviderError> {
        let mut retained = self.original.borrow_mut();
        let retained = retained
            .as_mut()
            .ok_or(refused("original-loss prior authentication absent"))?;
        if retained["original_request_hash"]
            != serde_json::to_value(original.request_hash(RequestOrigin::Controller)?)
                .map_err(crucible_node_contract::ContractError::from)?
        {
            return Err(refused("original-loss sent frame differs"));
        }
        retained["signal_attempted"] = Value::Bool(true);
        let provider = self.provider.borrow();
        let (pid, descriptor) = provider
            .as_ref()
            .ok_or(refused("original-loss pidfd absent"))?;
        retained["provider_pid"] = serde_json::json!(pid);
        pidfd_send_signal(descriptor, Signal::KILL).map_err(std::io::Error::from)?;
        let timeout = rustix::time::Timespec::try_from(Duration::from_secs(3))
            .map_err(|_| refused("original-loss terminal wait overflow"))?;
        let mut descriptors = [PollFd::new(descriptor, PollFlags::IN)];
        if poll(&mut descriptors, Some(&timeout)).map_err(std::io::Error::from)? != 1
            || !descriptors[0].revents().contains(PollFlags::IN)
        {
            return Err(refused("original-loss provider not terminal"));
        }
        retained["provider_terminal"] = Value::Bool(true);
        Ok(())
    }
}

fn refused(reason: &'static str) -> ProviderError {
    ProviderError::Correlation(reason)
}

/// Executes one real frozen-input window and retains its uncertain original token.
///
/// # Errors
/// Refuses changed input, grant, duplicate journal or any cached promotion.
/// The caller retains the same common runtime throughout the failed original.
pub(super) fn collect_original_response_loss(
    runtime: &mut crucible::node_contract::NodeRuntime,
    graph: &crucible::node_admission::AdmittedGraph,
    activation: &crucible::node_contract::WorldActivation,
    case: &crate::node_qualification::ReferenceWindowCase,
    context: &mut std::task::Context<'_>,
    loss: &SourceOriginalResponseLoss,
) -> Result<(), ProviderError> {
    use crucible::node_contract::{BeginResult, EffectKnowledge, Lifecycle, RuntimePollFailure};
    use std::task::Poll;

    let staged = runtime
        .scheduler(graph, activation)
        .map_err(diagnostic)?
        .prepare_input_batch(
            &case.node,
            case.stage.clone(),
            case.batch.clone(),
            case.input_cut,
        )
        .map_err(diagnostic)?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(4096)
        .map_err(|_| ProviderError::ResourceExhausted("loss frozen input credit"))?;
    for delivery in staged.deliveries() {
        let object = staged
            .payloads()
            .iter()
            .find(|object| object.reference == delivery.payload)
            .ok_or(refused("loss original input body absent"))?;
        object.reference.verify(&object.bytes)?;
        if input
            .len()
            .checked_add(object.bytes.len())
            .is_none_or(|total| total > 4096)
        {
            return Err(refused("loss original input exceeds declared ceiling"));
        }
        input.extend_from_slice(&object.bytes);
    }
    loss.record_input(input)?;
    runtime.stage_inputs(staged).map_err(diagnostic)?;
    let retained = runtime
        .recover_input_staging(activation, &case.stage)
        .map_err(diagnostic)?;
    let input_commit = runtime
        .commit_input_acknowledgement(retained)
        .map_err(diagnostic)?;
    runtime
        .commit_input_staging(&input_commit)
        .map_err(diagnostic)?;
    let grant = runtime
        .scheduler(graph, activation)
        .map_err(diagnostic)?
        .admit_quantum(
            &case.node,
            case.operation.clone(),
            case.grant.window_id.clone(),
            case.batch.clone(),
        )
        .map_err(diagnostic)?;
    if grant.start() != case.grant.start || grant.limit() != case.grant.publication {
        return Err(refused("loss admitted original grant differs"));
    }

    let before = loss.wire()?;
    // Keep the actual token returned for this uncertain submission. Recovering
    // an ID later must yield this same opaque authority, never a replacement.
    let BeginResult::Uncertain { token, effects } =
        runtime.begin_admitted(grant).map_err(diagnostic)?
    else {
        return Err(refused(
            "loss original Begin did not retain uncertain authority",
        ));
    };
    if effects != EffectKnowledge::Unknown
        || token.operation() != &case.operation
        || token.route().node != case.node
        || runtime.owner_lifecycle(&case.grant.owner_id) != Some(Lifecycle::Quarantined)
    {
        return Err(refused("loss original authority or containment changed"));
    }
    let attempted = loss.wire()?;
    if before["write_completed"] != false
        || attempted["write_completed"] != true
        || attempted["fenced_before_read"] != true
        || attempted["response_read"] != false
        || attempted["loss_action_completed"] != true
    {
        return Err(refused("original-loss first original frame not retained"));
    }
    let recovered = runtime.recover(&case.operation).map_err(diagnostic)?;
    if !token.same_authority(&recovered) {
        return Err(refused("loss original token was replaced"));
    }
    let first = match runtime.poll(&token, context) {
        Poll::Ready(Err(RuntimePollFailure::Native(failure)))
            if failure.effects == EffectKnowledge::Unknown =>
        {
            failure
        }
        _ => return Err(refused("loss poll promoted original completion")),
    };
    let second = match runtime.poll(&recovered, context) {
        Poll::Ready(Err(RuntimePollFailure::Native(failure))) if failure == first => failure,
        _ => return Err(refused("loss cached poll changed original failure")),
    };
    let close_refused = runtime.close_quantum(&recovered).is_err();
    let after = loss.wire()?;
    if !close_refused || after != attempted {
        return Err(refused("loss cached recovery emitted a new transmission"));
    }
    loss.retain_recovery(serde_json::json!({"same_original_authority":true,"operation":token.operation(),"effects":effects,"first_failure":format!("{first:?}"),"retained_failure":format!("{second:?}"),"close_refused":close_refused,"before":before,"attempted":attempted,"after_cached_checks":after}))
}

fn diagnostic(error: impl std::fmt::Display) -> ProviderError {
    ProviderError::Io(std::io::Error::other(error.to_string()))
}
