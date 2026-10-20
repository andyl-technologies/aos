//! Runs the sole Source-first P child, actual63/9 effects and retained ACK exit.
//!
//! The protected parent prepays this whole programme before PID1 creates the
//! worker. The native Source bridge precedes startup; original signed method
//! admission and unchanged D precede effects. Positive packet delivery alone
//! cannot attest success: parent FL03 must join actual clean worker exit.

use super::disposition::PreparationDispositionOriginalV2;
use super::execution::PreparationExecutionOriginalV2;
use super::programme::PreparationWholeProgrammeDataV2;
use super::signed_admission::PreparationSignedOriginalV2;
use super::terminal::PreparationPositiveSendOriginalV2;
use super::*;
use crate::worker_process::{
    NetworkWorkerFailureCauseV2 as Cause, NetworkWorkerFailurePhaseV2 as Phase,
    NetworkWorkerNegativeV2, NetworkWorkerResultV1,
};
use crate::worker_runtime::child_intake_v2::{
    NetworkPreparationIntakeOriginalV2, PreparationIntakeClosedV2,
};
use aos_sandbox_broker::receiving::{
    NetworkChildOperationBindingDataV2, NetworkChildOriginOriginalV2,
};
use aos_sandbox_model::{BrokerVerb, ObjectDigest};
use aos_sandbox_linux::pidfd::PidFd;

#[derive(Clone, Copy)]
enum First {
    Startup,
    Ready,
    Width,
    Intake,
    Signed,
    Geometry,
    Funding,
    Count,
    Effects,
    Result,
    Panic,
}

pub(super) struct PreparationActorOriginalV2 {
    first: Option<First>,
    startup: PreparationStartupOriginalV2,
    socket: Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
    ready: PreparationPositiveSendOriginalV2,
    intake: NetworkPreparationIntakeOriginalV2,
    width_gate: Option<Result<(), PreparationIntakeClosedV2>>,
    width_fit: Option<Result<ResourceVector, aos_sandbox_model::AccountingError>>,
    signed: PreparationSignedOriginalV2,
    whole: Option<PreparationWholeProgrammeDataV2>,
    funding: Option<Result<ResourceVector, aos_sandbox_model::AccountingError>>,
    native_fit: Option<Result<(), aos_sandbox_model::AccountingError>>,
    effects: PreparationExecutionOriginalV2,
    result: Option<Result<NetworkWorkerResultV1, crate::worker_process::NetworkWorkerProcessError>>,
    terminal: PreparationPositiveSendOriginalV2,
    disposition: PreparationDispositionOriginalV2,
    panic: Option<Box<dyn std::any::Any + Send>>,
    custody_panic: Option<Box<dyn std::any::Any + Send>>,
}

impl PreparationActorOriginalV2 {
    fn new() -> Self {
        Self {
            first: None,
            startup: PreparationStartupOriginalV2::new(),
            socket: None,
            ready: PreparationPositiveSendOriginalV2::new(),
            intake: NetworkPreparationIntakeOriginalV2::new(),
            width_gate: None,
            width_fit: None,
            signed: PreparationSignedOriginalV2::new(),
            whole: None,
            funding: None,
            native_fit: None,
            effects: PreparationExecutionOriginalV2::new(),
            result: None,
            terminal: PreparationPositiveSendOriginalV2::new(),
            disposition: PreparationDispositionOriginalV2::new(),
            panic: None,
            custody_panic: None,
        }
    }

    fn run_positive(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        binding: NetworkChildOperationBindingDataV2,
        paid: ResourceVector,
    ) {
        if self.startup.capture_once_v2(source).is_err() {
            self.first = Some(First::Startup);
        }
        self.socket = self.startup.socket.take();
        if self.first.is_some() {
            return;
        }
        let (Some(Ok(socket)), Some(namespace), Some(cgroup)) = (
            self.socket.as_mut(),
            self.startup.namespace.as_ref(),
            self.startup.cgroup.as_ref(),
        ) else {
            self.first = Some(First::Startup);
            return;
        };
        if self
            .ready
            .send_ready_once_v2(source, socket, cgroup, namespace)
            .is_err()
        {
            self.first = Some(First::Ready);
            return;
        }
        let width_gate = &mut self.width_gate;
        let width_fit = &mut self.width_fit;
        let intake = self.intake.capture_once_v2(source, socket, |width| {
            // This is only a denial comparison against the already-issued
            // parent payment. It creates no new bank or Source permission.
            *width_fit = NetworkPreparationIntakeOriginalV2::receiving_demand_data_v2(width)
                .map(|demand| paid.checked_sub(demand));
            *width_gate = Some(if matches!(*width_fit, Some(Ok(_))) {
                Ok(())
            } else {
                Err(PreparationIntakeClosedV2)
            });
            match width_gate.as_ref() {
                Some(Ok(())) => Ok(()),
                _ => Err(PreparationIntakeClosedV2),
            }
        });
        if intake.is_err() {
            self.first = Some(if self.intake.aggregate_gate_failure_selected_v2() {
                First::Width
            } else {
                First::Intake
            });
            return;
        }
        let (Some(authority), Some(replay)) = (
            self.startup.authority.as_ref(),
            self.startup.replay.as_mut(),
        ) else {
            self.first = Some(First::Startup);
            return;
        };
        if self
            .signed
            .capture_once_v2(source, &mut self.intake, authority, replay, namespace)
            .is_err()
        {
            self.first = Some(First::Signed);
            return;
        }
        let Some(input) = self.intake.completed_input_data_v2() else {
            self.first = Some(First::Intake);
            return;
        };
        let Some(plan) = self.signed.receiving_plan_data_v2() else {
            self.first = Some(First::Signed);
            return;
        };
        let verb = match input.method {
            63 => BrokerVerb::NetworkPrepare,
            9 => BrokerVerb::NetworkDestroy,
            _ => {
                self.first = Some(First::Signed);
                return;
            }
        };
        let Some(width) = self.intake.known_total_bytes_data_v3() else {
            self.first = Some(First::Intake);
            return;
        };
        let Some(request_bytes) = self.signed.request_body_bytes_data_v2() else {
            self.first = Some(First::Signed);
            return;
        };
        // Parent quote includes its actual protected signed-verification
        // supplier. ZERO here recomputes only a deny-only noncrypto bound;
        // financial authority remains that real private parent composition.
        self.whole = programme::preparation_whole_programme_data_v2(
            plan,
            verb,
            width,
            request_bytes,
            binding.native_limits,
            ResourceVector::ZERO,
        );
        let Some(whole) = self.whole.as_ref() else {
            self.first = Some(First::Geometry);
            return;
        };
        self.funding = Some(paid.checked_sub(whole.demand));
        self.native_fit = Some((|| {
            for (dimension, limit) in [
                (D::MemoryBytes, binding.native_limits[0]),
                (D::Pids, binding.native_limits[2]),
            ] {
                let attempted = whole.demand.get(dimension);
                if attempted > limit {
                    return Err(aos_sandbox_model::AccountingError::LimitExceeded {
                        dimension,
                        limit,
                        attempted,
                    });
                }
            }
            Ok(())
        })());
        if !matches!(self.funding, Some(Ok(_))) || !matches!(self.native_fit, Some(Ok(()))) {
            self.first = Some(First::Funding);
            return;
        }
        if whole.source_queries != binding.source_probe_count {
            self.first = Some(First::Count);
            return;
        }
        if self
            .effects
            .execute_once_v2(
                source,
                &mut self.signed,
                &self.startup,
                input.trusted_current_fence,
                whole.maximum_table,
            )
            .is_err()
        {
            self.first = Some(First::Effects);
            return;
        }
        let Some(plan) = self.signed.receiving_plan_data_v2() else {
            self.first = Some(First::Signed);
            return;
        };
        let target = if input.method == 63 {
            Some(namespace)
        } else {
            self.signed.destroy_target_v2()
        };
        let Some(target) = target else {
            self.first = Some(First::Signed);
            return;
        };
        self.result = Some(NetworkWorkerResultV1::new(
            binding.request_id,
            ObjectDigest::from_bytes(binding.effect_digest),
            plan.digest(),
            binding.boot,
            target.identity(),
        ));
        let Some(Ok(result)) = self.result.as_ref() else {
            self.first = Some(First::Result);
            return;
        };
        let Some(operation) = self.signed.result_authority_v2(input.trusted_current_fence) else {
            self.first = Some(First::Signed);
            return;
        };
        if self
            .terminal
            .send_result_once_v2(source, socket, *result, authority, operation)
            .is_err()
        {
            self.first = Some(First::Result);
        }
    }

    fn negative_data(
        &self,
        binding: NetworkChildOperationBindingDataV2,
    ) -> Option<NetworkWorkerNegativeV2> {
        let first = self.first?;
        let cause = match first {
            First::Width | First::Geometry | First::Funding | First::Count => Cause::Funding,
            First::Signed => Cause::Authority,
            First::Intake => Cause::Protocol,
            _ => Cause::Native,
        };
        // Startup/READY may fail before delivery or in its owed post. The
        // parent accepts this unknown-prefix negative on either side of READY;
        // retaining a fresh namespace does not prove that READY was received.
        if matches!(first, First::Startup | First::Ready | First::Panic) {
            return NetworkWorkerNegativeV2::bootstrap_data(
                binding.request_id,
                ObjectDigest::from_bytes(binding.effect_digest),
                binding.boot,
                cause,
            ).ok();
        }
        if let Some(Ok(result)) = self.result.as_ref() {
            return NetworkWorkerNegativeV2::new(*result, cause, Phase::Handback).ok();
        }
        if let (Some(plan), Some(namespace)) = (
            self.signed.receiving_plan_data_v2(),
            self.startup.namespace.as_ref(),
        ) {
            let target = if self.signed.method_data_v2() == Some(9) {
                self.signed.destroy_target_v2()?
            } else {
                namespace
            };
            let correlation = NetworkWorkerResultV1::new(
                binding.request_id,
                ObjectDigest::from_bytes(binding.effect_digest),
                plan.digest(),
                binding.boot,
                target.identity(),
            )
            .ok()?;
            return NetworkWorkerNegativeV2::new(correlation, cause, Phase::Preparation).ok();
        }
        if let Some(namespace) = self.startup.namespace.as_ref() {
            return NetworkWorkerNegativeV2::admission_data(
                binding.request_id,
                ObjectDigest::from_bytes(binding.effect_digest),
                binding.boot,
                namespace.identity(),
                cause,
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
        let negative = if self.first.is_some() && !self.terminal.native_entered_v2() {
            self.negative_data(binding)
        } else {
            None
        };
        let Some(Ok(socket)) = self.socket.as_mut() else {
            return false;
        };
        self.disposition
            .capture_once_v2(source, socket, donor, &self.intake, paid, negative)
            .is_ok()
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Startup => failed(&self.socket).or_else(|| self.startup.failure()),
            First::Ready => self.ready.failure(),
            First::Intake => self.intake.failure(),
            First::Width => failed(&self.width_fit).or_else(|| failed(&self.width_gate)),
            First::Signed => self.signed.failure(),
            First::Effects => self.effects.failure(),
            First::Result => self.terminal.failure().or_else(|| failed(&self.result)),
            First::Funding => failed(&self.funding).or_else(|| failed(&self.native_fit)),
            First::Geometry | First::Count | First::Panic => None,
        }
    }
}

/// Runs the canonical fixed P worker from actual native Source through ACK exit.
///
/// The fixed argv is read only after initial Source and all native bootstrap
/// posts succeed. The actual parent must separately join FL03 normal exit and
/// UnitResult success; a queued result with failed child posts exits nonzero.
pub fn run_inherited_network_prepare_worker_entry_v2() -> ! {
    let mut origin = NetworkChildOriginOriginalV2::new();
    let mut initial = NetworkChildSourceProbeOriginalV2::new();
    if origin
        .capture_inherited_once_v2(NetworkWorkerBirthPurposeV2::Preparation)
        .is_err()
    {
        if let Some(cause) = origin.failure() {
            eprintln!("aos-sandbox-network-worker: {cause}");
        }
        std::process::exit(1);
    }
    let Ok(mut source) = origin.borrow_live_source_once_v2(&mut initial) else {
        if let Some(cause) = initial.failure() {
            eprintln!("aos-sandbox-network-worker: {cause}");
        }
        std::process::exit(1);
    };
    let (Some(binding), Some(paid), Ok(donor)) = (
        source.operation_binding_data_v2(),
        source.prepaid_fee_data_v2(),
        source.original_netd_pidfd_for_worker_wait_v2(),
    ) else {
        std::process::exit(1);
    };
    let mut actor = PreparationActorOriginalV2::new();
    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        actor.run_positive(&mut source, binding, paid);
    })) {
        actor.first.get_or_insert(First::Panic);
        actor.panic = Some(payload);
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
            actor.custody_panic = Some(payload);
            false
        }
    };
    if let Some(cause) = actor.failure().or_else(|| actor.disposition.failure()) {
        eprintln!("aos-sandbox-network-worker: {cause}");
    }
    // Reached ambiguous helpers stay resident until actual native containment;
    // Rust Drop is not used as a claim that a child or cgroup became empty.
    std::process::exit(if actor.first.is_none() && custody_ok {
        0
    } else {
        1
    });
}
