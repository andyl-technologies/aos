//! Runs the sole actual observer child programme from inherited native Source.
//!
//! The protected parent prepays the whole finite programme before PID1 creates
//! this child. Bootstrap and custody use that same native Source; read effects
//! additionally require the original signed operation, completed lease and D.
//! Process exit retains failed native owners until actual parent containment.

use super::disposition::ObserverInputDispositionOriginalV3;
use super::execution::ObserverReadExecutionOriginalV2;
use super::handoff::ObserverHandoffOriginalV3;
use super::ready::ObserverReadyOriginalV2;
use super::terminal::ObserverTerminalOriginalV2;
use super::*;
use crate::observation_worker_runtime::read_admission_v2::{
    NetworkObserverReadOriginalV2, ObserverReadClosedV2,
};
use crate::worker_process::{
    NetworkWorkerFailureCauseV2 as Cause, NetworkWorkerFailurePhaseV2 as Phase,
    NetworkWorkerNegativeV2, NetworkWorkerResultV1,
};
use aos_sandbox_broker::receiving::{
    NetworkChildOperationBindingDataV2, NetworkChildOriginOriginalV2,
};
use aos_sandbox_model::ObjectDigest;
use aos_linux_descriptors::pidfd::PidFd;

#[derive(Clone, Copy)]
enum First {
    Startup,
    Ready,
    Handoff,
    Read,
    Geometry,
    Funding,
    Count,
    Execution,
    Result,
    Panic,
}

/// Owns all reached prefixes until native ACK/custody and actual process exit.
pub(super) struct ObserverActorOriginalV2 {
    first: Option<First>,
    startup: ObserverStartupOriginalV2,
    socket: Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
    ready: ObserverReadyOriginalV2,
    handoff: ObserverHandoffOriginalV3,
    read: NetworkObserverReadOriginalV2,
    read_borrow_failure: Option<ObserverReadClosedV2>,
    whole: Option<programme::ObserverWholeProgrammeDataV2>,
    execution: ObserverReadExecutionOriginalV2,
    terminal: ObserverTerminalOriginalV2,
    disposition: ObserverInputDispositionOriginalV3,
    panic_payload: Option<Box<dyn std::any::Any + Send>>,
    custody_panic_payload: Option<Box<dyn std::any::Any + Send>>,
}

impl ObserverActorOriginalV2 {
    fn new() -> Self {
        Self {
            first: None,
            startup: ObserverStartupOriginalV2::new(),
            socket: None,
            ready: ObserverReadyOriginalV2::new(),
            handoff: ObserverHandoffOriginalV3::new(),
            read: NetworkObserverReadOriginalV2::new(),
            read_borrow_failure: None,
            whole: None,
            execution: ObserverReadExecutionOriginalV2::new(),
            terminal: ObserverTerminalOriginalV2::new(),
            disposition: ObserverInputDispositionOriginalV3::new(),
            panic_payload: None,
            custody_panic_payload: None,
        }
    }

    fn run_positive<'native>(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'native>,
        binding: NetworkChildOperationBindingDataV2,
        paid: ResourceVector,
    ) {
        if self.startup.capture_once_v2(source).is_err() {
            self.first = Some(First::Startup);
        }
        // The actual socket/error owner moves once; startup's failed native
        // prefix and every original observation remain on the same actor.
        self.socket = self.startup.socket.take();
        if self.first.is_some() {
            return;
        }
        let Some(Ok(socket)) = self.socket.as_mut() else {
            self.first = Some(First::Startup);
            return;
        };
        if self.ready.send_once_v2(source, socket).is_err() {
            self.first = Some(First::Ready);
            return;
        }
        if self
            .handoff
            .capture_once_v3(source, socket, &mut self.read)
            .is_err()
        {
            self.first = Some(First::Handoff);
            return;
        }
        let request = match self.read.request() {
            Ok(request) => request,
            Err(cause) => {
                self.read_borrow_failure = Some(cause);
                self.first = Some(First::Read);
                return;
            }
        };
        let Some(sections) = self.handoff.section_lengths_data_v3() else {
            self.first = Some(First::Geometry);
            return;
        };
        let effect = match self.read.original_effect_v2() {
            Ok(effect) => effect,
            Err(cause) => {
                self.read_borrow_failure = Some(cause);
                self.first = Some(First::Read);
                return;
            }
        };
        // This is a denial check, not a grant. The genuine protected parent
        // already debited its SAME Source ledger including actual crypto.
        // ZERO here excludes only crypto already performed by that prepaid
        // issuer/receiver interval; it never asserts a whole-price proof.
        self.whole = programme::observer_whole_programme_data_v2(
            &request.plan,
            effect.verb(),
            sections,
            binding.native_limits,
            ResourceVector::ZERO,
        );
        let Some(whole) = self.whole.as_mut() else {
            self.first = Some(First::Geometry);
            return;
        };
        if paid.checked_sub(whole.demand).is_err()
            || whole.demand.get(D::MemoryBytes) > binding.native_limits[0]
        {
            self.first = Some(First::Funding);
            return;
        }
        if whole.source_queries != binding.source_probe_count {
            self.first = Some(First::Count);
            return;
        }
        let Some(recipe) = whole.recipe.take() else {
            self.first = Some(First::Geometry);
            return;
        };
        let read = match self.read.borrow_live_read_v2(source) {
            Ok(read) => read,
            Err(cause) => {
                self.read_borrow_failure = Some(cause);
                self.first = Some(First::Read);
                return;
            }
        };
        if self
            .execution
            .execute_once_v2(
                source,
                socket,
                &self.read,
                &read,
                &self.startup,
                sections[8],
                recipe,
            )
            .is_err()
        {
            self.first = Some(First::Execution);
            return;
        }
        let Some(response) = self.execution.response() else {
            self.first = Some(First::Execution);
            return;
        };
        if self
            .terminal
            .send_positive_once_v2(source, socket, &read, response)
            .is_err()
        {
            self.first = Some(First::Result);
        }
    }

    fn negative_data(
        &self,
        binding: NetworkChildOperationBindingDataV2,
    ) -> Option<NetworkWorkerNegativeV2> {
        let cause = match self.first? {
            First::Funding | First::Count | First::Geometry => Cause::Funding,
            First::Read => Cause::Authority,
            First::Handoff => Cause::Protocol,
            First::Startup | First::Ready | First::Execution | First::Result | First::Panic => {
                Cause::Native
            }
        };
        if let Ok(request) = self.read.request() {
            let correlation = NetworkWorkerResultV1::new(
                request.request_id,
                request.effect_digest,
                request.kernel_plan_digest,
                request.kernel_boot_id,
                request.namespace,
            )
            .ok()?;
            return NetworkWorkerNegativeV2::new(
                correlation,
                cause,
                if matches!(self.first, Some(First::Result)) {
                    Phase::Handback
                } else {
                    Phase::Observation
                },
            )
            .ok();
        }
        NetworkWorkerNegativeV2::bootstrap_data(
            binding.request_id,
            ObjectDigest::from_bytes(binding.effect_digest),
            binding.boot,
            cause,
        )
        .ok()
    }

    fn finish_custody(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        donor: &PidFd,
        binding: NetworkChildOperationBindingDataV2,
        paid: ResourceVector,
    ) -> bool {
        let negative = self.negative_data(binding);
        let Some(Ok(socket)) = self.socket.as_mut() else {
            return false;
        };
        if self.first.is_some() && !self.terminal.positive_native_send_was_entered_v2() {
            if let Some(negative) = negative {
                // Keep the body cause primary even if native negative delivery
                // or its independently owed posts also fail.
                let _ = self
                    .terminal
                    .send_negative_once_v2(source, socket, negative);
            } else {
                return false;
            }
        }
        self.disposition
            .capture_once_v3(
                source,
                socket,
                donor,
                binding,
                paid,
                &self.handoff,
                &self.read,
                &self.execution,
            )
            .is_ok()
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Startup => error(&self.socket).or_else(|| self.startup.failure()),
            First::Ready => self.ready.failure(),
            First::Handoff => self.handoff.failure(&self.read),
            First::Read => self
                .read
                .failure()
                .or_else(|| self.read_borrow_failure.as_ref().map(|cause| cause as _)),
            First::Execution => self.execution.failure(),
            First::Result => self.terminal.failure(),
            First::Geometry | First::Funding | First::Count | First::Panic => None,
        }
    }
}

/// Runs the Source-first observer and exits only after its finite custody port.
///
/// The fixed command line remains unchanged. It is read once, bounded and
/// retained after native Source bootstrap; no ordinary argv allocation or
/// startup effect precedes that actual payer. A successful result requires the
/// parent to join real normal worker exit and UnitResult success separately.
///
/// # Panics
///
/// Reached native panics are retained through prepaid custody when possible.
/// Process termination keeps unresolved native owners under parent containment.
pub fn run_inherited_network_observation_worker_entry_v2() -> ! {
    let mut origin = NetworkChildOriginOriginalV2::new();
    let mut initial = NetworkChildSourceProbeOriginalV2::new();
    let capture = origin.capture_inherited_once_v2(NetworkWorkerBirthPurposeV2::Observation);
    if capture.is_err() {
        // No child Source or startup permission exists. The parent already
        // holds the actual issued child custody and must observe death/Empty.
        std::process::exit(1);
    }
    let source_result = origin.borrow_live_source_once_v2(&mut initial);
    let Ok(mut source) = source_result else {
        std::process::exit(1);
    };
    let Some(binding) = source.operation_binding_data_v2() else {
        std::process::exit(1);
    };
    let Some(paid) = source.prepaid_fee_data_v2() else {
        std::process::exit(1);
    };
    let Ok(donor) = source.original_netd_pidfd_for_worker_wait_v2() else {
        std::process::exit(1);
    };
    let mut actor = ObserverActorOriginalV2::new();
    let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        actor.run_positive(&mut source, binding, paid);
    }));
    if let Err(payload) = body {
        actor.first.get_or_insert(First::Panic);
        actor.panic_payload = Some(payload);
        // capture_once may have unwound before its normal once-move.
        if actor.socket.is_none() {
            actor.socket = actor.startup.socket.take();
        }
    }
    let custody = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        actor.finish_custody(&mut source, donor, binding, paid)
    }));
    let custody_ok = match custody {
        Ok(complete) => complete,
        Err(payload) => {
            actor.first.get_or_insert(First::Panic);
            actor.custody_panic_payload = Some(payload);
            false
        }
    };
    let successful = actor.first.is_none() && custody_ok;
    if let Some(cause) = actor.failure() {
        eprintln!("aos-sandbox-network-observation-worker: {cause}");
    }
    // Avoid dropping an ambiguous native helper graph during negative exit.
    // The real parent's held PIDFD/cgroup/death/Empty join owns final cleanup.
    std::process::exit(if successful { 0 } else { 1 });
}
