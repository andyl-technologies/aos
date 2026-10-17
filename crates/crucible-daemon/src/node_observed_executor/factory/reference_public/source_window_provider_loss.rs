//! Records duplicate transport loss after a known nonempty native window.
//!
//! The fixture signals only the original guarded provider through a retained
//! pidfd. Its companion, controller journal and adopted native receipt remain
//! in the original custody. This is not loss during physical execution.

use std::{cell::RefCell, os::fd::OwnedFd, time::Duration};

use crucible::node_adapters::cnp::{
    CnpCompletedLifecyclePhase, CnpCompletedLifecycleScope, CnpLaunchGuard,
};
use crucible_node_contract::{Bytes, ContentRef, Id};
use crucible_node_provider::{
    ProviderError, bodies::MethodResult, client::ObservationHandle, reference_device::DeviceReceipt,
};
use rustix::{
    event::{PollFd, PollFlags, poll},
    process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal},
};
use serde_json::Value;

use super::source_lifecycle_resend_policy::OriginalLifecyclePremise;

/// Declares the exact source loss recipe independently of live process IDs.
pub(super) fn fixture() -> Value {
    serde_json::json!({
        "schema":"crucible.reference.known-window-provider-loss-fixture.v1",
        "node":"consumer", "quantum":"1", "phase":"window-completed",
        "native_premise":"original nonempty input and adopted native Close",
        "predecessor":"original quantum0 parked receipt; identical owner/incarnation/generation, processed0/checksum0",
        "maximum_measurement_bytes":65536,"maximum_frozen_input_bytes":4096,
        "signal":"SIGKILL to original provider pidfd only",
        "terminal_wait_ns":"3000000000", "maximum_signals":1,
        "transmission":"same retained original after provider becomes terminal",
        "recovery":"same opaque original token; no replacement dispatch",
        "exclusions":["loss during physical execution","reconnect","cancellation","whole-clause credit","ordinary Ready"]
    })
}

#[derive(serde::Serialize)]
struct OriginalPredecessor {
    reference: ContentRef,
    bytes: Bytes,
    receipt: DeviceReceipt,
}

/// Keeps the exact signal anchor, known native predecessor and loss attempt.
pub(super) struct SourceWindowProviderLoss {
    request: Id,
    provider: RefCell<Option<(u32, OwnedFd)>>,
    original_input: RefCell<Option<Vec<u8>>>,
    predecessor: RefCell<Option<OriginalPredecessor>>,
    original: RefCell<Option<Value>>,
    recovery: RefCell<Option<Value>>,
}

impl SourceWindowProviderLoss {
    /// Reserves the one source-selected attempted population before Child.
    pub(super) fn new(request: Id) -> Self {
        Self {
            request,
            provider: RefCell::new(None),
            original_input: RefCell::new(None),
            predecessor: RefCell::new(None),
            original: RefCell::new(None),
            recovery: RefCell::new(None),
        }
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

    /// Signals only after the owning source policy authenticates this original.
    ///
    /// # Errors
    /// Refuses changed original scope, native oracle, anchor or terminal wait.
    /// Once signalled, the retained premise cannot be replaced by another trial.
    pub(super) fn after_adoption(
        &self,
        guard: &CnpLaunchGuard,
        scope: &CnpCompletedLifecycleScope,
        premise: &OriginalLifecyclePremise,
        observer: &ObservationHandle,
    ) -> Result<(), ProviderError> {
        if scope.request_id != self.request {
            return Ok(());
        }
        if self.original.borrow().is_some()
            || scope.phase != CnpCompletedLifecyclePhase::WindowCompleted
        {
            return Err(refused("loss original phase already attempted or changed"));
        }
        let MethodResult::QuantumBegin(result) = &scope.original_result else {
            return Err(refused("loss original native result absent"));
        };
        let input = self.original_input.borrow();
        let input = input
            .as_ref()
            .ok_or(refused("loss original frozen input absent"))?;
        let snapshot = observer.snapshot(
            &[],
            std::slice::from_ref(&result.physical_measurement_ref),
            crucible_node_provider::client::ObservationLimits {
                maximum_requests: 1,
                maximum_objects: 1,
                maximum_bytes: 65536,
            },
        )?;
        let object = snapshot
            .evidence
            .objects
            .first()
            .ok_or(refused("loss original measurement body absent"))?;
        object.reference.verify(object.bytes.as_slice())?;
        let receipt: DeviceReceipt = serde_json::from_slice(object.bytes.as_slice())
            .map_err(crucible_node_contract::ContractError::from)?;
        let predecessor = self.predecessor.borrow();
        let predecessor = predecessor
            .as_ref()
            .ok_or(refused("loss known predecessor receipt absent"))?;
        if predecessor.receipt.grant.owner_id != receipt.grant.owner_id
            || predecessor.receipt.grant.incarnation_id != receipt.grant.incarnation_id
            || predecessor.receipt.grant.generation != receipt.grant.generation
        {
            return Err(refused("loss original predecessor owner differs"));
        }
        let checksum = input
            .iter()
            .fold(predecessor.receipt.output.checksum.get(), |state, byte| {
                state.wrapping_mul(257).wrapping_add(u64::from(*byte))
            });
        if !snapshot.recording_complete
            || snapshot.observed_unknown
            || scope.grant.as_ref() != Some(&receipt.grant)
            || receipt.grant.quantum.get() != 1
            || receipt.output.bytes_processed.get() != input.len() as u64
            || receipt.output.checksum.get() != checksum
            || !receipt.application_parked
        {
            return Err(refused("loss independent original native oracle differs"));
        }
        let provider = self.provider.borrow();
        let (pid, descriptor) = provider
            .as_ref()
            .ok_or(refused("loss pidfd anchor absent"))?;
        if guard.provider_pid() != Some(*pid) {
            return Err(refused("loss guarded original provider changed"));
        }
        // The retained premise precedes the signal. Failure after this point
        // remains one immutable attempted loss under the existing native owner.
        *self.original.borrow_mut() = Some(
            serde_json::json!({"fixture":fixture(),"scope":format!("{:?}",scope.phase),"request":scope.request_id,"operation":scope.operation_id,"original_premise":premise,"original_predecessor":predecessor,"receipt":receipt,"receipt_body":object,"frozen_input":input,"provider_pid":pid,"signal_attempted":true}),
        );
        pidfd_send_signal(descriptor, Signal::KILL).map_err(std::io::Error::from)?;
        let timeout = rustix::time::Timespec::try_from(Duration::from_secs(3))
            .map_err(|_| refused("loss terminal wait overflow"))?;
        let mut descriptors = [PollFd::new(descriptor, PollFlags::IN)];
        if poll(&mut descriptors, Some(&timeout)).map_err(std::io::Error::from)? != 1
            || !descriptors[0].revents().contains(PollFlags::IN)
        {
            return Err(refused("loss original provider did not become terminal"));
        }
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

fn refused(reason: &'static str) -> ProviderError {
    ProviderError::Correlation(reason)
}

/// Executes one real frozen-input window and retains its uncertain original token.
///
/// # Errors
/// Refuses changed input, grant, duplicate journal or any cached promotion.
/// The caller retains the same common runtime throughout the failed original.
pub(super) fn collect_original_uncertain_window(
    runtime: &mut crucible::node_contract::NodeRuntime,
    graph: &crucible::node_admission::AdmittedGraph,
    activation: &crucible::node_contract::WorldActivation,
    case: &crate::node_qualification::ReferenceWindowCase,
    context: &mut std::task::Context<'_>,
    loss: &SourceWindowProviderLoss,
    transmission_sink: &RefCell<
        Option<crucible_node_provider::client::TransmissionObservationHandle>,
    >,
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

    let observer = transmission_sink.borrow();
    let observer = observer
        .as_ref()
        .ok_or(refused("loss original transmission archive absent"))?;
    let before = serde_json::to_value(observer.snapshot(1024 * 1024)?)
        .map_err(crucible_node_contract::ContractError::from)?;
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
    let attempted = serde_json::to_value(observer.snapshot(1024 * 1024)?)
        .map_err(crucible_node_contract::ContractError::from)?;
    let before_rows = before["rows"]
        .as_array()
        .ok_or(refused("loss wire prefix malformed"))?;
    let after_rows = attempted["rows"]
        .as_array()
        .ok_or(refused("loss wire attempt malformed"))?;
    if attempted["incomplete"] != true
        || after_rows.len() != before_rows.len() + 1
        || after_rows[..before_rows.len()] != *before_rows
        || after_rows.last().is_none_or(|row| {
            row["semantic_response_verified"] != false || !row["received"].is_null()
        })
    {
        return Err(refused(
            "loss original incomplete wire row was not retained",
        ));
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
    let after = serde_json::to_value(observer.snapshot(1024 * 1024)?)
        .map_err(crucible_node_contract::ContractError::from)?;
    if !close_refused || after != attempted {
        return Err(refused("loss cached recovery emitted a new transmission"));
    }
    loss.retain_recovery(serde_json::json!({"same_original_authority":true,"operation":token.operation(),"effects":effects,"first_failure":format!("{first:?}"),"retained_failure":format!("{second:?}"),"close_refused":close_refused,"before":before,"attempted":attempted,"after_cached_checks":after}))
}

fn diagnostic(error: impl std::fmt::Display) -> ProviderError {
    ProviderError::Io(std::io::Error::other(error.to_string()))
}
