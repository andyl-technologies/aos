//! Runs the shared P transaction with actual issued native parent custody.
//!
//! The private service caller supplies the same completed signed Source and
//! its synchronous original domain binder. This adapter retains the existing
//! native engines through result, ACK, real death/Empty and PID1 K; a child
//! result remains correlation DATA until all those obligations complete.

use super::super::*;
use super::parent_transport_v2::NetworkParentTransportOriginalV2;
use super::preparation::{PreparationNativeV4, execute_prepare_recipe_v4};
use super::quiescence::WorkerQuiescenceOriginalV4;
use crate::lifecycle_worker_protocol::NetworkLifecycleWorkerDispatchV1;
use crate::worker_process::{
    NetworkWorkerBirthExecutionOriginalV2, NetworkWorkerFailurePhaseV2, NetworkWorkerNegativeV2,
    NetworkWorkerReadyOriginalV4,
};
use aos_sandbox_broker::receiving::{
    FixedServiceOperationClosedV4 as Closed, NetworkServiceReceivingLoanV4,
    NetworkWorkerBirthPurposeV2, NetworkWorkerBirthReservationV2, NetworkWorkerCleanupClockScopeV4,
};
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};

/// Borrows one actual completed signed63 or signed9 dispatch and its real target.
pub(crate) enum NetworkParentMutationInputV2<'a> {
    Prepare(&'a NetworkPrepareWorkerDispatchV1),
    Destroy {
        dispatch: &'a NetworkLifecycleWorkerDispatchV1,
        target: &'a NamespaceFd,
        trusted_current_fence: &'a [u8],
    },
}

impl NetworkParentMutationInputV2<'_> {
    fn request(&self) -> [u8; 16] {
        match self {
            Self::Prepare(value) => value.request_id(),
            Self::Destroy { dispatch, .. } => dispatch.request_id(),
        }
    }

    fn effect(&self) -> ObjectDigest {
        match self {
            Self::Prepare(value) => value.effect_digest(),
            Self::Destroy { dispatch, .. } => dispatch.effect_digest(),
        }
    }

    fn plan(&self) -> ObjectDigest {
        match self {
            Self::Prepare(value) => value.kernel_plan().digest(),
            Self::Destroy { dispatch, .. } => dispatch.kernel_plan().digest(),
        }
    }

    pub(crate) fn encoded_length_data_v2(&self) -> Option<usize> {
        let dispatch = match self {
            Self::Prepare(value) => value.encoded_length_data_v2(),
            Self::Destroy { dispatch, .. } => dispatch.encoded_length_data_v2(),
        }?;
        let (method, fence) = self.envelope_fields();
        super::super::preparation_input_v2::encoded_length_data_v2(method, dispatch, fence.len())
    }

    fn encode(&self) -> Result<Vec<u8>, NetworkWorkerProtocolError> {
        let dispatch = match self {
            Self::Prepare(value) => value.encode(),
            Self::Destroy { dispatch, .. } => dispatch.encode(),
        }?;
        let (method, fence) = self.envelope_fields();
        super::super::preparation_input_v2::encode_data_v2(method, &dispatch, fence)
            .ok_or(NetworkWorkerProtocolError::TooLarge)
    }

    fn envelope_fields(&self) -> (u16, &[u8]) {
        match self {
            Self::Prepare(_) => (63, &[]),
            Self::Destroy { trusted_current_fence, .. } => (9, trusted_current_fence),
        }
    }

    fn retained_target(&self) -> Option<&NamespaceFd> {
        match self {
            Self::Prepare(_) => None,
            Self::Destroy { target, .. } => Some(target),
        }
    }
}

#[derive(Clone, Copy)]
enum First {
    Order,
    Encode,
    Birth,
    Arm,
    Ready,
    ReadyNative,
    ReadyAffinity,
    Custody,
    Terminal,
    TerminalAffinity,
    Correlation,
    Negative,
    Ack,
    Natural,
    Cleanup,
    TerminalK,
    Completion,
    Recipe,
}

/// Retains the complete P parent interval on the same prepaid service owner.
pub(crate) struct NetworkParentMutationOriginalV2 {
    entered: bool,
    destroy: bool,
    binding: Option<aos_sandbox_broker::receiving::NetworkChildOperationBindingDataV2>,
    transport: NetworkParentTransportOriginalV2,
    encoded: Option<Result<Vec<u8>, NetworkWorkerProtocolError>>,
    birth_result: Option<Result<(), Closed>>,
    arm_result: Option<Result<(), Closed>>,
    drain_result: Option<Result<(), Closed>>,
    ready: Option<Result<NetworkWorkerReadyV1, NetworkWorkerProcessError>>,
    ready_native: NetworkWorkerReadyOriginalV4,
    ready_native_result: Option<Result<(), crate::worker_process::NetworkWorkerReadyRefusalV4>>,
    ready_affinity: NetworkWorkerBirthExecutionOriginalV2,
    ready_affinity_result: Option<Result<(), NetworkWorkerProcessError>>,
    target: Option<NamespaceFd>,
    ready_cgroup: Option<RetainedCgroupAnchor>,
    ready_negative: Option<Result<NetworkWorkerNegativeV2, NetworkWorkerProcessError>>,
    terminal_negative: Option<Result<NetworkWorkerNegativeV2, NetworkWorkerProcessError>>,
    terminal_result: Option<Result<NetworkWorkerResultV1, NetworkWorkerProcessError>>,
    terminal_affinity: NetworkWorkerBirthExecutionOriginalV2,
    terminal_affinity_result: Option<Result<(), NetworkWorkerProcessError>>,
    custody_result: Option<Result<(), Closed>>,
    quiescence: WorkerQuiescenceOriginalV4,
    natural_result: Option<Result<(), NetworkWorkerRuntimeError>>,
    cleanup_entered: bool,
    cleanup_result: Option<Result<(), Closed>>,
    terminal_k: Option<Result<(), Closed>>,
    returned: Option<Result<(), NetworkWorkerRuntimeError>>,
    result: Option<NetworkWorkerResultV1>,
    taken: bool,
    first: Option<First>,
}

impl NetworkParentMutationOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            entered: false,
            destroy: false,
            binding: None,
            transport: NetworkParentTransportOriginalV2::new(
                NetworkWorkerBirthPurposeV2::Preparation,
            ),
            encoded: None,
            birth_result: None,
            arm_result: None,
            drain_result: None,
            ready: None,
            ready_native: NetworkWorkerReadyOriginalV4::new(),
            ready_native_result: None,
            ready_affinity: NetworkWorkerBirthExecutionOriginalV2::new(),
            ready_affinity_result: None,
            target: None,
            ready_cgroup: None,
            ready_negative: None,
            terminal_negative: None,
            terminal_result: None,
            terminal_affinity: NetworkWorkerBirthExecutionOriginalV2::new(),
            terminal_affinity_result: None,
            custody_result: None,
            quiescence: WorkerQuiescenceOriginalV4::new(),
            natural_result: None,
            cleanup_entered: false,
            cleanup_result: None,
            terminal_k: None,
            returned: None,
            result: None,
            taken: false,
            first: None,
        }
    }

    pub(crate) fn receiving_demand_v2(
        input: &NetworkParentMutationInputV2<'_>,
    ) -> Result<ResourceVector, AccountingError> {
        let overflow = AccountingError::ArithmeticOverflow {
            dimension: D::MemoryBytes,
        };
        let length = input.encoded_length_data_v2().ok_or(overflow)?;
        let mut demand = NetworkParentTransportOriginalV2::receiving_demand_v2(
            NetworkWorkerBirthPurposeV2::Preparation,
            length,
            None,
        )?;
        for (bytes, files, names) in [
            NetworkWorkerReadyOriginalV4::receiving_obligations_v4().ok_or(overflow)?,
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
            .and_then(|bytes| bytes.checked_add(length.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(MAXIMUM_CGROUP_BYTES * 2))
            .and_then(|bytes| bytes.checked_add(recipe_message_bytes()?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(overflow)?;
        demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    /// Runs only after the closed caller paid this quote on the same loan.
    /// The callback is the existing protected binder and retains its original
    /// Journal/catalog/store result before returning its marker.
    pub(crate) fn execute_once_v2<'financial>(
        &mut self,
        executor: &mut SystemdNetworkPrepareExecutor,
        reservation: &mut NetworkWorkerBirthReservationV2<'_, 'financial>,
        cleanup_scope: &mut NetworkWorkerCleanupClockScopeV4,
        input: NetworkParentMutationInputV2<'_>,
        custody: impl FnOnce(
            &NamespaceFd,
            &mut NetworkServiceReceivingLoanV4<'financial>,
        ) -> Result<(), Closed>,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            return Err(marker());
        }
        self.entered = true;
        self.destroy = matches!(input, NetworkParentMutationInputV2::Destroy { .. });
        let mut native = ParentMutationV2 {
            original: self,
            executor,
            reservation,
            cleanup_scope,
            input,
            custody: Some(custody),
            completed: false,
        };
        let returned = execute_prepare_recipe_v4(&mut native);
        let success = returned.is_ok();
        native.original.returned = Some(returned);
        if !success {
            native.original.first.get_or_insert(First::Recipe);
            if !native.original.cleanup_entered {
                let _ = native.cleanup();
            }
        }
        native.completed = true;
        if success { Ok(()) } else { Err(marker()) }
    }

    pub(crate) fn completed_namespace_v2(&self) -> Option<&NamespaceFd> {
        if self.destroy || self.first.is_some() || !matches!(self.returned, Some(Ok(()))) {
            return None;
        }
        self.target.as_ref()
    }

    pub(crate) fn completed_result_v2(&self) -> Option<NetworkWorkerResultV1> {
        if self.first.is_some() || !matches!(self.returned, Some(Ok(()))) {
            return None;
        }
        self.result
    }

    pub(crate) fn completed_binding_data_v2(
        &self,
    ) -> Option<aos_sandbox_broker::receiving::NetworkChildOperationBindingDataV2> {
        self.completed_result_v2()?;
        self.binding
    }

    pub(crate) fn expected_observation_state_data_v2(
        &self,
    ) -> Option<crate::NetworkNamespaceObservedStateV1> {
        self.completed_result_v2()?;
        Some(if self.destroy {
            crate::NetworkNamespaceObservedStateV1::absent()
        } else {
            crate::NetworkNamespaceObservedStateV1::default_drop()
        })
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let native: Option<&(dyn std::error::Error + 'static)> = match self.first? {
            First::Encode => self
                .encoded
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Ready => self.original_transport_or_ready_failure(),
            First::ReadyNative => self.ready_native.failure(),
            First::ReadyAffinity => self.ready_affinity.failure(),
            First::Terminal | First::Ack => self.transport.failure_v2(),
            First::TerminalAffinity => self.terminal_affinity.failure(),
            First::Correlation => self
                .terminal_result
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| {
                    self.ready_negative
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                })
                .or_else(|| {
                    self.terminal_negative
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
                    self.encoded
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                })
                .or_else(|| {
                    self.returned
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause as _)
                }),
            First::Order
            | First::Birth
            | First::Arm
            | First::Custody
            | First::Negative
            | First::TerminalK
            | First::Completion => None,
        };
        native.or(Some(&Closed))
    }

    fn original_transport_or_ready_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.transport
            .failure_v2()
            .or_else(|| self.ready.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    /// Selects the actual sibling birth original's retained refusal.
    pub(crate) fn birth_failure_selected_v2(&self) -> bool {
        matches!(
            self.first,
            Some(First::Birth | First::Arm | First::TerminalK | First::Completion)
        ) || matches!(self.first, Some(First::Cleanup)) && self.quiescence.failure().is_none()
    }

    /// Selects the actual same-loan native/financial gate cause.
    pub(crate) fn parent_failure_selected_v2(&self) -> bool {
        matches!(
            self.first,
            Some(First::Ready | First::Terminal | First::Ack | First::Recipe)
        ) && self.transport.parent_failure_selected_v2()
    }

    /// Selects the caller's original protected Journal/store interval cause.
    pub(crate) fn custody_failure_selected_v2(&self) -> bool {
        matches!(self.first, Some(First::Custody))
    }

    pub(crate) fn take_prepared_output_once_v2(&mut self) -> Option<PreparedNetworkWorkerOutput> {
        if self.taken || self.completed_namespace_v2().is_none() {
            return None;
        }
        let result = self.result?;
        let target = self.target.take()?;
        self.taken = true;
        Some(output_from_result(target, result))
    }
}

struct ParentMutationV2<'a, 'birth, 'financial, 'input, F>
where
    F: FnOnce(&NamespaceFd, &mut NetworkServiceReceivingLoanV4<'financial>) -> Result<(), Closed>,
{
    original: &'a mut NetworkParentMutationOriginalV2,
    executor: &'a mut SystemdNetworkPrepareExecutor,
    reservation: &'a mut NetworkWorkerBirthReservationV2<'birth, 'financial>,
    cleanup_scope: &'a mut NetworkWorkerCleanupClockScopeV4,
    input: NetworkParentMutationInputV2<'input>,
    custody: Option<F>,
    completed: bool,
}

impl<'financial, F> ParentMutationV2<'_, '_, 'financial, '_, F>
where
    F: FnOnce(&NamespaceFd, &mut NetworkServiceReceivingLoanV4<'financial>) -> Result<(), Closed>,
{
    fn expected_namespace(&self) -> Option<NamespaceIdentity> {
        self.input
            .retained_target()
            .or(self.original.target.as_ref())
            .map(|target| target.identity())
    }

    fn require_result(
        &self,
        result: NetworkWorkerResultV1,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        let binding = self
            .reservation
            .issued_child_operation_binding_data_v2()
            .ok_or_else(marker)?;
        if result.request_id() != self.input.request()
            || result.effect_digest() != self.input.effect()
            || result.kernel_plan_digest() != self.input.plan()
            || result.kernel_boot_id() != binding.boot
            || Some(result.namespace()) != self.expected_namespace()
        {
            return Err(marker());
        }
        Ok(())
    }

    fn require_negative(
        &self,
        negative: NetworkWorkerNegativeV2,
        before_ready: bool,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        let binding = self
            .reservation
            .issued_child_operation_binding_data_v2()
            .ok_or_else(marker)?;
        if negative.request_id() != self.input.request()
            || negative.effect_digest() != self.input.effect()
            || negative.kernel_boot_id() != binding.boot
        {
            return Err(marker());
        }
        if let Some(result) = negative.correlation() {
            return self.require_result(result);
        }
        match negative.phase() {
            NetworkWorkerFailurePhaseV2::Bootstrap if negative.namespace_data_v2().is_none() => {
                Ok(())
            }
            NetworkWorkerFailurePhaseV2::Admission
                if !before_ready
                    && negative.namespace_data_v2()
                        == self
                            .original
                            .target
                            .as_ref()
                            .map(|target| target.identity()) =>
            {
                Ok(())
            }
            _ => Err(marker()),
        }
    }

    fn terminal_data(&mut self) -> Result<NetworkWorkerResultV1, NetworkWorkerRuntimeError> {
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
        if self.original.terminal_result.is_none() {
            self.original.terminal_result = Some(NetworkWorkerResultV1::decode(record.payload()));
        }
        if !matches!(self.original.terminal_result, Some(Ok(_))) {
            self.original.first.get_or_insert(First::Correlation);
        }
        let result = self
            .original
            .terminal_result
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or_else(marker)?;
        self.require_result(result).inspect_err(|_| {
            self.original.first.get_or_insert(First::Correlation);
        })?;
        self.original
            .transport
            .acknowledge_once_v2()
            .inspect_err(|_| {
                self.original.first.get_or_insert(First::Ack);
            })?;
        Ok(result)
    }

    fn terminal_k(&mut self) -> Result<(), NetworkWorkerRuntimeError> {
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

impl<'financial, F> PreparationNativeV4 for ParentMutationV2<'_, '_, 'financial, '_, F>
where
    F: FnOnce(&NamespaceFd, &mut NetworkServiceReceivingLoanV4<'financial>) -> Result<(), Closed>,
{
    type Output = ();

    fn begin(&mut self) -> Result<(), NetworkWorkerRuntimeError> {
        if !matches!(self.executor.origin, ExecutorOriginV4::FixedService)
            || self.executor.fail_stopped
        {
            self.original.first.get_or_insert(First::Order);
            return Err(marker());
        }
        let binding = self
            .reservation
            .child_operation_binding_data_v2()
            .ok_or_else(marker)?;
        if binding.purpose != 1
            || binding.request_id != self.input.request()
            || binding.effect_digest != *self.input.effect().as_bytes()
        {
            return Err(marker());
        }
        self.original.binding = Some(binding);
        if let NetworkParentMutationInputV2::Destroy { dispatch, target, .. } = &self.input {
            let identity = dispatch.target_identity();
            if dispatch.lifecycle_action() != crate::NetworkNamespaceLifecycleActionV1::Destroy
                || dispatch.desired_state().kind()
                    != crate::NetworkNamespaceObservedStateKindV1::Absent
                || identity.kernel_boot_id() != binding.boot
                || identity.namespace_device() != target.identity().device
                || identity.namespace_inode() != target.identity().inode
                || target.identity() == self.executor.host_namespace.identity()
            {
                return Err(marker());
            }
        }
        self.original.encoded = Some(self.input.encode());
        if !matches!(self.original.encoded, Some(Ok(_))) {
            self.original.first.get_or_insert(First::Encode);
            return Err(marker());
        }
        let encoded = self
            .original
            .encoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(marker)?;
        if Some(encoded.len()) != self.input.encoded_length_data_v2() {
            self.original.first.get_or_insert(First::Encode);
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

    fn ready(&mut self) -> Result<(), NetworkWorkerRuntimeError> {
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
        self.original.ready = Some(NetworkWorkerReadyV1::decode_receiving_v4(record.payload()));
        if !matches!(self.original.ready, Some(Ok(_))) {
            self.original.first.get_or_insert(First::Ready);
        }
        let ready = self
            .original
            .ready
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(marker)?;
        let record = self
            .original
            .transport
            .ready_record_mut_v2()
            .ok_or_else(marker)?;
        let descriptor = record
            .take_fixed_service_preparation_descriptor_data_v4()
            .ok_or_else(marker)?;
        self.original.ready_native_result = Some(self.original.ready_native.observe_once_v4(
            ready,
            record.subject(),
            vec![descriptor],
            &self.executor.worker_parent_cgroup,
            &self.executor.host_namespace,
        ));
        if !matches!(self.original.ready_native_result, Some(Ok(()))) {
            self.original.first.get_or_insert(First::ReadyNative);
            return Err(marker());
        }
        let (ready_cgroup, target) = self
            .original
            .ready_native
            .take_completed_custody_once_v4()
            .ok_or_else(marker)?;
        self.original.ready_cgroup = Some(ready_cgroup);
        self.original.target = Some(target);
        if self
            .original
            .ready_cgroup
            .as_ref()
            .map(|scope| scope.kernel_id())
            != Some(cgroup.kernel_id())
        {
            self.original.first.get_or_insert(First::ReadyAffinity);
            return Err(marker());
        }
        if self.input.retained_target().is_some_and(|target| {
            Some(target.identity()) == self.original.target.as_ref().map(|value| value.identity())
        }) {
            self.original.first.get_or_insert(First::ReadyAffinity);
            return Err(marker());
        }
        Ok(())
    }

    fn population(&mut self) -> Result<(), NetworkWorkerRuntimeError> {
        self.reservation
            .retained_birth_native_data_v2()
            .ok_or_else(marker)
            .map(|_| ())
    }

    fn custody(&mut self) -> Result<(), NetworkWorkerRuntimeError> {
        let target = self
            .input
            .retained_target()
            .or(self.original.target.as_ref())
            .ok_or_else(marker)?;
        let callback = self.custody.take().ok_or_else(marker)?;
        self.original.custody_result = Some(
            self.reservation
                .with_parent_domain_custody_once_v2(|loan| callback(target, loan)),
        );
        if matches!(self.original.custody_result, Some(Ok(()))) {
            Ok(())
        } else {
            self.original.first.get_or_insert(First::Custody);
            Err(marker())
        }
    }

    fn exchange(&mut self) -> Result<NetworkWorkerResultV1, NetworkWorkerRuntimeError> {
        let encoded = self
            .original
            .encoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(marker)?;
        self.original.transport.send_preparation_frames_once_v2(
            self.reservation,
            encoded,
            &self.executor.host_namespace,
            self.input.retained_target(),
        )?;
        let received = self
            .original
            .transport
            .receive_terminal_once_v2(self.reservation);
        if received.is_err() {
            self.original.first.get_or_insert(First::Terminal);
        }
        let decoded = self.terminal_data();
        received?;
        decoded
    }

    fn natural_exit(&mut self) -> Result<(), NetworkWorkerRuntimeError> {
        let (process, _, monitor) = self
            .reservation
            .retained_birth_native_data_v2()
            .ok_or_else(marker)?;
        let cutoff = self
            .original
            .transport
            .cutoff_data_v2()
            .ok_or_else(marker)?;
        self.original.natural_result = Some(
            self.original
                .quiescence
                .natural_birth_once_v2(process, monitor, cutoff),
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

    fn cleanup(&mut self) -> Result<(), NetworkWorkerRuntimeError> {
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
        // Status collection is independent of cleanup/K posts. A negative
        // child status never suppresses already-owed containment or retires
        // the parent's earlier failure as a successful operation.
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

    fn output(&mut self, result: NetworkWorkerResultV1) {
        self.original.result = Some(result);
    }
}

impl<'financial, F> Drop for ParentMutationV2<'_, '_, 'financial, '_, F>
where
    F: FnOnce(&NamespaceFd, &mut NetworkServiceReceivingLoanV4<'financial>) -> Result<(), Closed>,
{
    fn drop(&mut self) {
        if !self.completed && !self.original.cleanup_entered {
            self.original.first.get_or_insert(First::Recipe);
            if self.cleanup().is_err() {
                self.executor.fail_stopped = true;
            }
        }
    }
}

fn marker() -> NetworkWorkerRuntimeError {
    NetworkWorkerRuntimeError::Protocol(PARENT_MARKER_TEXT)
}

const PARENT_MARKER_TEXT: &str = "actual P parent original retained";

fn recipe_message_bytes() -> Option<usize> {
    // The selected adapter retains raw causes locally and passes only these
    // static protocol markers to the existing recipe's three format branches.
    let marker = PARENT_MARKER_TEXT
        .len()
        .max(NetworkParentTransportOriginalV2::marker_text_v2().len());
    let display = "Network worker runtime protocol is invalid: "
        .len()
        .checked_add(marker)?;
    let natural = "successful worker did not terminate naturally: "
        .len()
        .checked_add(display)?;
    let refused = "successful worker remained live (); cancellation was not proved ()"
        .len()
        .checked_add(display.checked_mul(2)?)?;
    let exchange = "worker exchange failed (); cancellation was not proved ()"
        .len()
        .checked_add(display.checked_mul(2)?)?;
    natural.max(refused).max(exchange).checked_mul(2)
}
