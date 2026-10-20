//! Runs the shared O transaction on the same completed P parent programme.
//!
//! Original signed public sections accompany six actual credential rights.
//! The ordinary two-namespace request is constructed once and reused verbatim
//! as the public handoff's ninth section. Neither record alone grants read
//! authority; the child retains its independent same-Source signed admission.

use super::*;
use crate::worker_process::{
    NetworkWorkerBirthExecutionOriginalV2, NetworkWorkerFailurePhaseV2, NetworkWorkerNegativeV2,
};
use crate::worker_runtime::{
    NetworkParentMutationOriginalV2, NetworkParentTransportOriginalV2, WorkerQuiescenceOriginalV4,
};
use aos_sandbox_broker::ProtectedBrokerPublicCredentials;
use aos_sandbox_broker::receiving::{
    FixedServiceOperationClosedV4 as Closed, NetworkChildOperationBindingDataV2,
    NetworkWorkerBirthPurposeV2, NetworkWorkerBirthReservationV2, NetworkWorkerCleanupClockScopeV4,
};
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};

/// Borrows the same completed P result and its continuously held target.
pub(crate) struct NetworkParentObservationInputV2<'a> {
    mutation: &'a NetworkParentMutationOriginalV2,
    target: &'a NamespaceFd,
    plan: &'a NetworkKernelPlanV1,
}

impl<'a> NetworkParentObservationInputV2<'a> {
    /// Joins exact P correlation DATA without constructing Source or authority.
    ///
    /// # Errors
    /// Refuses incomplete P, changed actual target or substituted plan.
    pub(crate) fn new(
        mutation: &'a NetworkParentMutationOriginalV2,
        target: &'a NamespaceFd,
        plan: &'a NetworkKernelPlanV1,
    ) -> Result<Self, NetworkObservationWorkerError> {
        let completed = mutation.completed_result_v2().ok_or_else(marker)?;
        if completed.namespace() != target.identity()
            || completed.kernel_plan_digest() != plan.digest()
        {
            return Err(marker());
        }
        Ok(Self {
            mutation,
            target,
            plan,
        })
    }
}

#[derive(Clone, Copy)]
enum First {
    Order,
    Request,
    Birth,
    Arm,
    Ready,
    ReadyAffinity,
    Handoff,
    Exchange,
    TerminalAffinity,
    Correlation,
    Negative,
    Natural,
    Cleanup,
    TerminalK,
    Completion,
    Recipe,
}

/// Retains the real O parent transport, native custody, result and disposition.
pub(crate) struct NetworkParentObservationOriginalV2 {
    entered: bool,
    transport: NetworkParentTransportOriginalV2,
    request: Option<Result<ObservationRequestFieldsV2, NetworkObservationWorkerError>>,
    encoded: Option<Result<Vec<u8>, NetworkObservationWorkerError>>,
    binding: Option<NetworkChildOperationBindingDataV2>,
    birth_result: Option<Result<(), Closed>>,
    arm_result: Option<Result<(), Closed>>,
    drain_result: Option<Result<(), Closed>>,
    ready: Option<Result<ObservationReadyV1, NetworkObservationWorkerError>>,
    ready_negative: Option<Result<NetworkWorkerNegativeV2, NetworkWorkerProcessError>>,
    ready_affinity: NetworkWorkerBirthExecutionOriginalV2,
    ready_affinity_result: Option<Result<(), NetworkWorkerProcessError>>,
    terminal_affinity: NetworkWorkerBirthExecutionOriginalV2,
    terminal_affinity_result: Option<Result<(), NetworkWorkerProcessError>>,
    terminal_negative: Option<Result<NetworkWorkerNegativeV2, NetworkWorkerProcessError>>,
    response: Option<Result<PreparedNetworkObservationV1, NetworkObservationWorkerError>>,
    quiescence: WorkerQuiescenceOriginalV4,
    natural_result: Option<Result<(), NetworkWorkerRuntimeError>>,
    cleanup_entered: bool,
    cleanup_result: Option<Result<(), Closed>>,
    terminal_k: Option<Result<(), Closed>>,
    returned: Option<Result<PreparedNetworkObservationV1, NetworkObservationWorkerError>>,
    first: Option<First>,
}

impl NetworkParentObservationOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            entered: false,
            transport: NetworkParentTransportOriginalV2::new(
                NetworkWorkerBirthPurposeV2::Observation,
            ),
            request: None,
            encoded: None,
            binding: None,
            birth_result: None,
            arm_result: None,
            drain_result: None,
            ready: None,
            ready_negative: None,
            ready_affinity: NetworkWorkerBirthExecutionOriginalV2::new(),
            ready_affinity_result: None,
            terminal_affinity: NetworkWorkerBirthExecutionOriginalV2::new(),
            terminal_affinity_result: None,
            terminal_negative: None,
            response: None,
            quiescence: WorkerQuiescenceOriginalV4::new(),
            natural_result: None,
            cleanup_entered: false,
            cleanup_result: None,
            terminal_k: None,
            returned: None,
            first: None,
        }
    }

    /// Quotes exact P/O-shared input widths before P effects or O allocation.
    pub(crate) fn receiving_demand_v2(
        plan: &NetworkKernelPlanV1,
        sections: [&[u8]; 8],
    ) -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let request = REQUEST_HEADER_BYTES
            .checked_add(plan.as_bytes().len())
            .ok_or(overflow)?;
        let lengths = std::array::from_fn(|index| {
            if index == 8 {
                request
            } else {
                sections[index].len()
            }
        });
        let handoff =
            crate::observer_handoff_v2::observer_handoff_length_data_v2(lengths).ok_or(overflow)?;
        let mut demand = NetworkParentTransportOriginalV2::receiving_demand_v2(
            NetworkWorkerBirthPurposeV2::Observation,
            request,
            Some(handoff),
        )?;
        for (bytes, files, names) in [
            NetworkWorkerBirthExecutionOriginalV2::receiving_obligations_v2().ok_or(overflow)?,
            NetworkWorkerBirthExecutionOriginalV2::receiving_obligations_v2().ok_or(overflow)?,
            WorkerQuiescenceOriginalV4::receiving_obligations_v4().ok_or(overflow)?,
        ] {
            demand = demand.checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| overflow)?)
                    .with(D::OpenFiles, u64::try_from(files).map_err(|_| overflow)?)
                    .with(
                        D::MetadataEntries,
                        u64::try_from(names).map_err(|_| overflow)?,
                    ),
            )?;
        }
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(request.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(MAXIMUM_CGROUP_BYTES * 2))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(overflow)?;
        demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    /// Runs the real O programme after the closed caller paid its exact quote.
    ///
    /// The first eight sections are borrowed unchanged from the same completed
    /// signed admission/current fence/operation fence/pending effect originals.
    /// The ninth is built here once and reused for the namespace transfer.
    ///
    /// # Errors
    /// Retains wrong operation, native transport/admission, negative, response,
    /// ACK, real quiescence, K or independently owed post refusal.
    pub(crate) fn execute_once_v2(
        &mut self,
        executor: &mut SystemdNetworkObservationExecutor,
        reservation: &mut NetworkWorkerBirthReservationV2<'_, '_>,
        cleanup_scope: &mut NetworkWorkerCleanupClockScopeV4,
        input: NetworkParentObservationInputV2<'_>,
        credentials: &ProtectedBrokerPublicCredentials,
        sections: [&[u8]; 8],
    ) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            return Err(marker());
        }
        self.entered = true;
        let mut native = ParentObservationV2 {
            original: self,
            executor,
            reservation,
            cleanup_scope,
            input,
            credentials,
            sections,
            completed: false,
        };
        let result = observe_recipe_v4(&mut native);
        let positive = result.as_ref().ok().copied();
        native.original.returned = Some(result);
        if positive.is_none() {
            native.original.first.get_or_insert(First::Recipe);
            if !native.original.cleanup_entered {
                let _ = native.cleanup();
            }
        }
        native.completed = true;
        positive.ok_or_else(marker)
    }

    pub(crate) fn completed_observation_v2(&self) -> Option<PreparedNetworkObservationV1> {
        if self.first.is_some() {
            return None;
        }
        self.returned.as_ref()?.as_ref().ok().copied()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let native: Option<&(dyn std::error::Error + 'static)> = match self.first? {
            First::Request => self
                .request
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| {
                    self.encoded
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::Ready => self
                .transport
                .failure_v2()
                .or_else(|| self.ready.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::ReadyAffinity => self.ready_affinity.failure(),
            First::Handoff | First::Exchange => self.transport.failure_v2(),
            First::TerminalAffinity => self.terminal_affinity.failure(),
            First::Correlation => self
                .response
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| {
                    self.terminal_negative
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                })
                .or_else(|| {
                    self.ready_negative
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::Natural | First::Cleanup => self.quiescence.failure(),
            First::Recipe => self
                .transport
                .failure_v2()
                .or_else(|| {
                    self.request
                        .as_ref()
                        .and_then(|value| value.as_ref().err())
                        .map(|cause| cause as _)
                })
                .or_else(|| {
                    self.encoded
                        .as_ref()
                        .and_then(|value| value.as_ref().err())
                        .map(|cause| cause as _)
                })
                .or_else(|| {
                    self.returned
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::Order | First::Birth | First::Arm | First::Negative | First::TerminalK | First::Completion => None,
        };
        native.or(Some(&Closed))
    }

    pub(crate) fn birth_failure_selected_v2(&self) -> bool {
        matches!(
            self.first,
            Some(First::Birth | First::Arm | First::TerminalK | First::Completion)
        ) || matches!(self.first, Some(First::Cleanup)) && self.quiescence.failure().is_none()
    }

    pub(crate) fn parent_failure_selected_v2(&self) -> bool {
        matches!(
            self.first,
            Some(First::Ready | First::Handoff | First::Exchange | First::Recipe)
        ) && self.transport.parent_failure_selected_v2()
    }
}

struct ParentObservationV2<'a, 'birth, 'financial, 'input, 'sections> {
    original: &'a mut NetworkParentObservationOriginalV2,
    executor: &'a mut SystemdNetworkObservationExecutor,
    reservation: &'a mut NetworkWorkerBirthReservationV2<'birth, 'financial>,
    cleanup_scope: &'a mut NetworkWorkerCleanupClockScopeV4,
    input: NetworkParentObservationInputV2<'input>,
    credentials: &'a ProtectedBrokerPublicCredentials,
    sections: [&'sections [u8]; 8],
    completed: bool,
}

impl ParentObservationV2<'_, '_, '_, '_, '_> {
    fn require_negative(
        &self,
        negative: NetworkWorkerNegativeV2,
        before_ready: bool,
    ) -> Result<(), NetworkObservationWorkerError> {
        let request = self
            .original
            .request
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(marker)?;
        if negative.request_id() != request.request_id
            || negative.effect_digest() != request.effect_digest
            || negative.kernel_boot_id() != request.kernel_boot_id
        {
            return Err(marker());
        }
        if let Some(complete) = negative.correlation() {
            if complete.kernel_plan_digest() == request.kernel_plan_digest
                && complete.namespace() == request.namespace
            {
                return Ok(());
            }
        } else if negative.phase() == NetworkWorkerFailurePhaseV2::Bootstrap
            && negative.namespace_data_v2().is_none()
        {
            return Ok(());
        } else if !before_ready
            && negative.phase() == NetworkWorkerFailurePhaseV2::Admission
            && negative.namespace_data_v2() == Some(request.namespace)
        {
            return Ok(());
        }
        Err(marker())
    }

    fn terminal_data(
        &mut self,
    ) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
        let record = self
            .original
            .transport
            .terminal_record_v2()
            .ok_or_else(marker)?;
        if self.original.terminal_affinity_result.is_none() {
            let (process, cgroup, _) = self
                .reservation
                .retained_birth_native_data_v2()
                .ok_or_else(marker)?;
            self.original.terminal_affinity_result = Some(
                self.original
                    .terminal_affinity
                    .capture_once_v2(process, cgroup, record.subject()),
            );
        }
        if !matches!(self.original.terminal_affinity_result, Some(Ok(()))) {
            self.original.first.get_or_insert(First::TerminalAffinity);
            return Err(marker());
        }
        if record.payload().starts_with(b"AOSNERR2") {
            if self.original.terminal_negative.is_none() {
                self.original.terminal_negative =
                    Some(NetworkWorkerNegativeV2::decode(record.payload()));
            }
            if !matches!(self.original.terminal_negative, Some(Ok(_))) {
                self.original.first.get_or_insert(First::Correlation);
            }
            let negative = self
                .original
                .terminal_negative
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .ok_or_else(marker)?;
            self.require_negative(negative, self.original.ready.is_none())?;
            self.original.first.get_or_insert(First::Negative);
            let _ = self.original.transport.acknowledge_once_v2();
            return Err(marker());
        }
        if self.original.response.is_none() {
            self.original.response = Some(decode_response(record.payload()));
        }
        if !matches!(self.original.response, Some(Ok(_))) {
            self.original.first.get_or_insert(First::Correlation);
        }
        let response = self
            .original
            .response
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or_else(marker)?;
        let request = self
            .original
            .request
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(marker)?;
        if response.request_id != request.request_id
            || response.effect_digest != request.effect_digest
            || response.kernel_plan_digest != request.kernel_plan_digest
            || response.kernel_boot_id != request.kernel_boot_id
            || response.namespace != request.namespace
            || response.observed_state != request.expected_state
        {
            self.original.first.get_or_insert(First::Correlation);
            return Err(marker());
        }
        self.original.transport.acknowledge_once_v2()?;
        Ok(response)
    }

    fn terminal_k(&mut self) -> Result<(), NetworkObservationWorkerError> {
        if self.original.terminal_k.is_none() {
            self.original.terminal_k = Some(self.reservation.send_owed_birth_terminal_once_v2());
        }
        if matches!(self.original.terminal_k, Some(Ok(()))) {
            Ok(())
        } else {
            self.original.first.get_or_insert(First::TerminalK);
            Err(marker())
        }
    }
}

impl ObservationNativeV4 for ParentObservationV2<'_, '_, '_, '_, '_> {
    fn begin(&mut self) -> Result<(), NetworkObservationWorkerError> {
        if !self.executor.fixed_service || self.executor.fail_stopped {
            return Err(marker());
        }
        let mutation = self
            .input
            .mutation
            .completed_result_v2()
            .ok_or_else(marker)?;
        let parent = self
            .input
            .mutation
            .completed_binding_data_v2()
            .ok_or_else(marker)?;
        let binding = self
            .reservation
            .child_operation_binding_data_v2()
            .ok_or_else(marker)?;
        if binding.purpose != 2
            || binding.boot != parent.boot
            || binding.source_invocation != parent.source_invocation
            || binding.request_id != parent.request_id
            || binding.effect_digest != parent.effect_digest
            || binding.operation_ordinal != parent.operation_ordinal
        {
            return Err(marker());
        }
        self.original.binding = Some(binding);
        let fields = ObservationRequestFieldsV2 {
            request_id: mutation.request_id(),
            effect_digest: mutation.effect_digest(),
            kernel_plan_digest: mutation.kernel_plan_digest(),
            kernel_boot_id: mutation.kernel_boot_id(),
            namespace: self.input.target.identity(),
            expected_state: self
                .input
                .mutation
                .expected_observation_state_data_v2()
                .ok_or_else(marker)?,
        };
        self.original.request = Some(fields.validate(self.input.plan).map(|()| fields));
        if !matches!(self.original.request, Some(Ok(_))) {
            self.original.first.get_or_insert(First::Request);
            return Err(marker());
        }
        let request = self
            .original
            .request
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(marker)?;
        self.original.encoded = Some(request.encode(self.input.plan));
        if !matches!(self.original.encoded, Some(Ok(_))) {
            self.original.first.get_or_insert(First::Request);
            return Err(marker());
        }
        self.original
            .transport
            .connect_once_v2(self.reservation, &self.executor.systemd_manager_cgroup)?;
        self.original.birth_result = Some(self.reservation.receive_birth_custody_once_v2());
        if !matches!(self.original.birth_result, Some(Ok(()))) {
            self.original.first.get_or_insert(First::Birth);
            return Err(marker());
        }
        self.original.arm_result = Some(self.reservation.send_birth_armed_once_v2());
        if !matches!(self.original.arm_result, Some(Ok(()))) {
            self.original.first.get_or_insert(First::Arm);
            return Err(marker());
        }
        Ok(())
    }

    fn ready(&mut self) -> Result<(), NetworkObservationWorkerError> {
        let receiving = self
            .original
            .transport
            .receive_ready_once_v2(self.reservation);
        if receiving.is_err() {
            self.original.first.get_or_insert(First::Ready);
        }
        let record = self
            .original
            .transport
            .ready_record_v2()
            .ok_or_else(marker)?;
        let (process, cgroup, _) = self
            .reservation
            .retained_birth_native_data_v2()
            .ok_or_else(marker)?;
        self.original.ready_affinity_result = Some(self.original.ready_affinity.capture_once_v2(
            process,
            cgroup,
            record.subject(),
        ));
        if !matches!(self.original.ready_affinity_result, Some(Ok(()))) {
            self.original.first.get_or_insert(First::ReadyAffinity);
            return Err(marker());
        }
        if record.payload().starts_with(b"AOSNERR2") {
            self.original.ready_negative = Some(NetworkWorkerNegativeV2::decode(record.payload()));
            if !matches!(self.original.ready_negative, Some(Ok(_))) {
                self.original.first.get_or_insert(First::Correlation);
            }
            let negative = self
                .original
                .ready_negative
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .ok_or_else(marker)?;
            self.require_negative(negative, true)?;
            self.original.first.get_or_insert(First::Negative);
            let _ = self.original.transport.acknowledge_once_v2();
            return Err(marker());
        }
        receiving?;
        self.original.ready = Some(ObservationReadyV1::decode_receiving_v4(record.payload()));
        if !matches!(self.original.ready, Some(Ok(_))) {
            self.original.first.get_or_insert(First::Ready);
            return Err(marker());
        }
        Ok(())
    }

    fn population(&mut self) -> Result<(), NetworkObservationWorkerError> {
        self.reservation
            .retained_birth_native_data_v2()
            .ok_or_else(marker)
            .map(|_| ())
    }

    fn exchange(&mut self) -> Result<PreparedNetworkObservationV1, NetworkObservationWorkerError> {
        let packet = self
            .original
            .encoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(marker)?;
        let [a, b, c, d, e, f, g, h] = self.sections;
        self.original
            .transport
            .send_observer_handoff_once_v2(
                self.reservation,
                self.credentials,
                [a, b, c, d, e, f, g, h, packet],
            )
            .inspect_err(|_| {
                self.original.first.get_or_insert(First::Handoff);
            })?;
        self.original.transport.send_observation_request_once_v2(
            self.reservation,
            packet,
            self.input.target,
            &self.executor.host_namespace,
        )?;
        let received = self
            .original
            .transport
            .receive_terminal_once_v2(self.reservation);
        if received.is_err() {
            self.original.first.get_or_insert(First::Exchange);
        }
        let decoded = self.terminal_data();
        received?;
        decoded
    }

    fn natural_exit(&mut self) -> Result<(), NetworkObservationWorkerError> {
        let (process, _, monitor) = self
            .reservation
            .retained_birth_native_data_v2()
            .ok_or_else(marker)?;
        self.original.natural_result = Some(
            self.original.quiescence.natural_birth_once_v2(
                process,
                monitor,
                self.original
                    .transport
                    .cutoff_data_v2()
                    .ok_or_else(marker)?,
            ),
        );
        if !matches!(self.original.natural_result, Some(Ok(()))) {
            self.original.first.get_or_insert(First::Natural);
            return Err(marker());
        }
        self.terminal_k()?;
        if self.reservation.require_positive_birth_completion_v3().is_err() {
            self.original.first.get_or_insert(First::Completion);
            return Err(marker());
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), NetworkObservationWorkerError> {
        if self.original.cleanup_entered {
            return Err(marker());
        }
        self.original.cleanup_entered = true;
        if self.reservation.retained_birth_native_data_v2().is_none() {
            self.original.drain_result =
                Some(self.reservation.receive_owed_birth_custody_once_v2());
        }
        if !self.original.transport.ack_entered_v2() && self.original.ready_negative.is_none() {
            if !self.original.transport.terminal_entered_v2() {
                let _ = self
                    .original
                    .transport
                    .receive_terminal_once_v2(self.reservation);
            }
            if self.original.transport.terminal_record_v2().is_some() {
                let _ = self.terminal_data();
            }
        }
        let quiescence = &mut self.original.quiescence;
        self.original.cleanup_result = Some(self.reservation.with_issued_birth_cleanup_once_v2(
            self.cleanup_scope,
            |process, cgroup, monitor, _, _| {
                quiescence
                    .cleanup_issued_birth_once_v2(process, cgroup, monitor)
                    .map_err(|_| Closed)
            },
        ));
        let terminal = self.terminal_k();
        let completion = self.reservation.receive_owed_birth_completion_once_v3();
        if !matches!(self.original.cleanup_result, Some(Ok(()))) {
            self.original.first.get_or_insert(First::Cleanup);
            return Err(marker());
        }
        terminal?;
        if completion.is_err() {
            self.original.first.get_or_insert(First::Completion);
            return Err(marker());
        }
        Ok(())
    }

    fn fail_stop(&mut self) {
        self.executor.fail_stopped = true;
    }
}

impl Drop for ParentObservationV2<'_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed && !self.original.cleanup_entered {
            self.original.first.get_or_insert(First::Recipe);
            if self.cleanup().is_err() {
                self.executor.fail_stopped = true;
            }
        }
    }
}

fn marker() -> NetworkObservationWorkerError {
    NetworkObservationWorkerError::Protocol("actual O parent original retained")
}
