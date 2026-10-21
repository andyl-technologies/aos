//! Admits the actual Source-bound signed63 or signed9 P input once.
//!
//! The input owner has already retained every frame and original namespace
//! donation through all native and Source posts. This owner performs the
//! distinct canonical dispatch admission and original replay claim, with real
//! retained kernel clocks. Native Source binding cannot substitute for that
//! signed admission, and signed admission cannot construct a Source or bank.

use super::*;
use crate::NetworkAdmissionError;
use crate::lifecycle_worker_protocol::{
    NetworkLifecycleExecutionAuthorizationV1, NetworkLifecycleWorkerDispatchV1,
};
use crate::namespace_catalog::NetworkNamespaceLifecycleActionV1;
use crate::worker_protocol::{
    NetworkMutationAuthorizationV1, NetworkPrepareWorkerDispatchV1, NetworkWorkerProtocolError,
};
use crate::worker_runtime::child_intake_v2::NetworkPreparationIntakeOriginalV2;
use aos_sandbox_broker::kernel_clock::{
    KernelPairedClockErrorV1, RetainedKernelPairedClockAttemptV1,
};
use aos_sandbox_model::{ObjectDigest, RawPairedClockSample};
use aos_sandbox_linux::pidfd::{NamespaceAdoptionFailureV2, NamespaceKind};

#[derive(Debug, thiserror::Error)]
pub(super) enum PreparationClockErrorV2 {
    #[error("the actual P clock differs from its original native boot")]
    Changed,
    #[error(transparent)]
    Native(aos_linux_descriptors::Error),
}

impl KernelPairedClockErrorV1 for PreparationClockErrorV2 {
    fn stale() -> Self {
        Self::Changed
    }

    fn kernel(cause: aos_linux_descriptors::Error) -> Self {
        Self::Native(cause)
    }
}

/// Keeps one actual clock pair without replacing an earlier native cause.
pub(super) struct PreparationClockOriginalV2 {
    native: RetainedKernelPairedClockAttemptV1<PreparationClockErrorV2>,
    result: Option<Result<RawPairedClockSample, PreparationClockErrorV2>>,
}

impl PreparationClockOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            native: RetainedKernelPairedClockAttemptV1::default(),
            result: None,
        }
    }

    pub(super) fn observe_once_v2(
        &mut self,
        boot: [u8; 16],
    ) -> Result<RawPairedClockSample, NetworkAdmissionError> {
        if self.result.is_some() {
            return Err(NetworkAdmissionError::FenceRejected);
        }
        self.result = Some(self.native.observe_once(None).and_then(|sample| {
            if sample.host_boot_id() == boot {
                Ok(sample)
            } else {
                Err(PreparationClockErrorV2::Changed)
            }
        }));
        self.result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(NetworkAdmissionError::FenceRejected)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native.failure().or_else(|| failed(&self.result))
    }

    pub(super) fn realtime_data_v2(&self) -> Option<rustix::time::Timespec> {
        self.native.realtime_observation_data_v1()
    }

    pub(super) fn sample_data_v2(&self) -> Option<RawPairedClockSample> {
        self.result.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn receiving_obligations_data_v2() -> Option<ResourceVector> {
        type Native = RetainedKernelPairedClockAttemptV1<PreparationClockErrorV2>;
        Some(
            ResourceVector::ZERO
                .with(
                    D::MemoryBytes,
                    u64::try_from(
                        std::mem::size_of::<Self>()
                            .checked_mul(2)?
                            .checked_add(Native::dominant_requested_bytes_v1()?)?,
                    )
                    .ok()?,
                )
                .with(
                    D::OpenFiles,
                    u64::try_from(Native::MAXIMUM_RETAINED_FILES_V1).ok()?,
                )
                .with(
                    D::MetadataEntries,
                    u64::try_from(Native::receiving_metadata_cells_v1()?).ok()?,
                ),
        )
    }
}

#[derive(Clone, Copy)]
enum First {
    Order,
    SourceBefore,
    Input,
    Namespace(usize),
    Decode,
    Binding,
    Authenticate,
    Authorize,
    Body,
    SourceAfter,
}

/// Owns only actual admitted signed authority and original donated namespaces.
pub(super) struct PreparationSignedOriginalV2 {
    entered: bool,
    first: Option<First>,
    before: NetworkChildSourceProbeOriginalV2,
    before_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    method: Option<u16>,
    raw_namespaces: Vec<OwnedFd>,
    namespaces: [Option<Result<NamespaceFd, NamespaceAdoptionFailureV2>>; 2],
    decode: Option<Result<(), NetworkWorkerProtocolError>>,
    binding: Option<Result<(), NetworkWorkerProtocolError>>,
    authenticate: Option<Result<(), NetworkWorkerProtocolError>>,
    preparation: Option<Result<NetworkMutationAuthorizationV1, NetworkWorkerProtocolError>>,
    destroy: Option<Result<NetworkLifecycleExecutionAuthorizationV1, NetworkWorkerProtocolError>>,
    clocks: [PreparationClockOriginalV2; 2],
    clock_next: usize,
    clock_failure: Option<usize>,
    after: NetworkChildSourceProbeOriginalV2,
    after_result: Option<Result<(), NetworkChildOriginClosedV2>>,
    closed: NetworkWorkerRuntimeError,
}

impl PreparationSignedOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            first: None,
            before: NetworkChildSourceProbeOriginalV2::new(),
            before_result: None,
            method: None,
            raw_namespaces: Vec::new(),
            namespaces: std::array::from_fn(|_| None),
            decode: None,
            binding: None,
            authenticate: None,
            preparation: None,
            destroy: None,
            clocks: std::array::from_fn(|_| PreparationClockOriginalV2::new()),
            clock_next: 0,
            clock_failure: None,
            after: NetworkChildSourceProbeOriginalV2::new(),
            after_result: None,
            closed: NetworkWorkerRuntimeError::Protocol("actual signed P input is closed"),
        }
    }

    /// Admits exactly the completed native intake, never caller-supplied bytes.
    pub(super) fn capture_once_v2(
        &mut self,
        source: &mut NetworkChildSourceLoanV2<'_>,
        intake: &mut NetworkPreparationIntakeOriginalV2,
        authority: &NetworkAuthorityV1,
        replay: &mut NetworkWorkerReplayLedger,
        bootstrap: &NamespaceFd,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        if self.entered || self.first.is_some() {
            self.first.get_or_insert(First::Order);
            return Err(NetworkWorkerRuntimeError::Protocol(
                "signed P admission was reused",
            ));
        }
        self.entered = true;
        self.before_result = Some(source.require_live_before_once_v2(&mut self.before, None));
        if !matches!(self.before_result, Some(Ok(()))) {
            self.first = Some(First::SourceBefore);
        }
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if self.first.is_none() {
                self.capture_local_v2(source, intake, authority, replay, bootstrap);
            }
        }));
        if body.is_err() {
            self.first.get_or_insert(First::Body);
        }

        // This post remains owed independently after decode, namespace, replay,
        // authority, clock or panic failure. It cannot reopen either authority.
        self.after_result = Some(if source.operation_binding_data_v2().is_some() {
            source.require_live_before_once_v2(&mut self.after, None)
        } else {
            source.observe_owed_native_after_once_v2(&mut self.after)
        });
        if !matches!(self.after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::SourceAfter);
        }
        if let Err(payload) = body {
            std::panic::resume_unwind(payload);
        }
        if self.first.is_some() {
            Err(NetworkWorkerRuntimeError::Protocol(
                "signed P admission failed",
            ))
        } else {
            Ok(())
        }
    }

    fn capture_local_v2(
        &mut self,
        source: &NetworkChildSourceLoanV2<'_>,
        intake: &mut NetworkPreparationIntakeOriginalV2,
        authority: &NetworkAuthorityV1,
        replay: &mut NetworkWorkerReplayLedger,
        bootstrap: &NamespaceFd,
    ) {
        let Some(descriptors) = intake.take_namespace_descriptors_data_once_v2() else {
            self.first = Some(First::Input);
            return;
        };
        self.raw_namespaces = descriptors;
        let Some(input) = intake.completed_input_data_v2() else {
            self.first = Some(First::Input);
            return;
        };
        self.method = Some(input.method);
        let expected = match input.method {
            63 => 1,
            9 => 2,
            _ => {
                self.first = Some(First::Input);
                return;
            }
        };
        if self.raw_namespaces.len() != expected {
            self.first = Some(First::Input);
            return;
        }
        for index in 0..expected {
            let descriptor = self.raw_namespaces.remove(0);
            self.namespaces[index] = Some(NamespaceFd::from_owned_retaining_v2(
                descriptor,
                NamespaceKind::Network,
            ));
            if !matches!(self.namespaces[index], Some(Ok(_))) {
                self.first = Some(First::Namespace(index));
                return;
            }
        }
        let Some(binding) = source.operation_binding_data_v2() else {
            self.first = Some(First::Binding);
            return;
        };
        match input.method {
            63 => {
                let dispatch = match NetworkPrepareWorkerDispatchV1::decode(input.dispatch) {
                    Ok(dispatch) => {
                        self.decode = Some(Ok(()));
                        dispatch
                    }
                    Err(cause) => {
                        self.decode = Some(Err(cause));
                        self.first = Some(First::Decode);
                        return;
                    }
                };
                self.binding = Some(compare_binding_v2(
                    binding,
                    dispatch.request_id(),
                    dispatch.effect_digest(),
                    self.namespaces[0]
                        .as_ref()
                        .and_then(|value| value.as_ref().ok())
                        .is_some_and(|host| host.identity() != bootstrap.identity()),
                ));
                if !matches!(self.binding, Some(Ok(()))) {
                    self.first = Some(First::Binding);
                    return;
                }
                let authenticated = match dispatch.authenticate(authority) {
                    Ok(authenticated) => {
                        self.authenticate = Some(Ok(()));
                        authenticated
                    }
                    Err(cause) => {
                        self.authenticate = Some(Err(cause));
                        self.first = Some(First::Authenticate);
                        return;
                    }
                };
                let clocks = &mut self.clocks;
                let next = &mut self.clock_next;
                let failure = &mut self.clock_failure;
                self.preparation = Some(authenticated.authorize_mutation(
                    authority,
                    replay,
                    &mut || next_clock_v2(clocks, next, failure, binding.boot),
                ));
                if !matches!(self.preparation, Some(Ok(_))) {
                    self.first = Some(First::Authorize);
                }
            }
            9 => {
                let dispatch = match NetworkLifecycleWorkerDispatchV1::decode(input.dispatch) {
                    Ok(dispatch) => {
                        self.decode = Some(Ok(()));
                        dispatch
                    }
                    Err(cause) => {
                        self.decode = Some(Err(cause));
                        self.first = Some(First::Decode);
                        return;
                    }
                };
                let namespace_match = match (&self.namespaces[0], &self.namespaces[1]) {
                    (Some(Ok(target)), Some(Ok(host))) => {
                        let claimed = dispatch.claimed_target_namespace();
                        dispatch.lifecycle_action() == NetworkNamespaceLifecycleActionV1::Destroy
                            && claimed.namespace_device() == target.identity().device
                            && claimed.namespace_inode() == target.identity().inode
                            && target.identity() != host.identity()
                            && target.identity() != bootstrap.identity()
                            && host.identity() != bootstrap.identity()
                    }
                    _ => false,
                };
                self.binding = Some(compare_binding_v2(
                    binding,
                    dispatch.request_id(),
                    dispatch.effect_digest(),
                    namespace_match,
                ));
                if !matches!(self.binding, Some(Ok(()))) {
                    self.first = Some(First::Binding);
                    return;
                }
                let authenticated = match dispatch.authenticate(authority) {
                    Ok(authenticated) => {
                        self.authenticate = Some(Ok(()));
                        authenticated
                    }
                    Err(cause) => {
                        self.authenticate = Some(Err(cause));
                        self.first = Some(First::Authenticate);
                        return;
                    }
                };
                let clocks = &mut self.clocks;
                let next = &mut self.clock_next;
                let failure = &mut self.clock_failure;
                // The second slice is the separately supplied genuine parent
                // coordinator original carried by this same native intake.
                // The dispatch's claimed_current_fence is never a supplier.
                self.destroy = Some(authenticated.authorize_execution(
                    authority,
                    replay,
                    &mut || Ok(input.trusted_current_fence.to_vec()),
                    &mut || next_clock_v2(clocks, next, failure, binding.boot),
                ));
                if !matches!(self.destroy, Some(Ok(_))) {
                    self.first = Some(First::Authorize);
                }
            }
            _ => self.first = Some(First::Input),
        }
    }

    pub(super) fn method_data_v2(&self) -> Option<u16> {
        self.first.is_none().then_some(self.method).flatten()
    }

    pub(super) fn receiving_plan_data_v2(&self) -> Option<&crate::NetworkKernelPlanV1> {
        match self.method_data_v2()? {
            63 => Some(self.preparation.as_ref()?.as_ref().ok()?.kernel_plan()),
            9 => Some(
                self.destroy
                    .as_ref()?
                    .as_ref()
                    .ok()?
                    .receiving_plan_data_v2(),
            ),
            _ => None,
        }
    }

    pub(super) fn preparation_parts_v2(
        &self,
    ) -> Option<(&NetworkMutationAuthorizationV1, &NamespaceFd)> {
        Some((self.preparation_v2()?, self.host_v2()?))
    }

    pub(super) fn destroy_parts_v2(
        &mut self,
    ) -> Option<(
        &mut NetworkLifecycleExecutionAuthorizationV1,
        &NamespaceFd,
        &NamespaceFd,
    )> {
        if self.first.is_some() || self.method != Some(9) {
            return None;
        }
        let authorization = self.destroy.as_mut()?.as_mut().ok()?;
        let target = self.namespaces[0].as_ref()?.as_ref().ok()?;
        let host = self.namespaces[1].as_ref()?.as_ref().ok()?;
        Some((authorization, target, host))
    }

    pub(super) fn result_authority_v2<'held>(
        &'held self,
        trusted: &'held [u8],
    ) -> Option<super::terminal::PreparationResultAuthorityV2<'held>> {
        if self.first.is_some() {
            return None;
        }
        match self.method? {
            63 => Some(super::terminal::PreparationResultAuthorityV2::Prepare(
                self.preparation.as_ref()?.as_ref().ok()?,
            )),
            9 => Some(super::terminal::PreparationResultAuthorityV2::Destroy(
                self.destroy.as_ref()?.as_ref().ok()?,
                trusted,
            )),
            _ => None,
        }
    }

    pub(super) fn request_body_bytes_data_v2(&self) -> Option<usize> {
        match self.method_data_v2()? {
            63 => Some(
                self.preparation
                    .as_ref()?
                    .as_ref()
                    .ok()?
                    .original_request_body_bytes_data_v2(),
            ),
            9 => Some(
                self.destroy
                    .as_ref()?
                    .as_ref()
                    .ok()?
                    .original_request_body_bytes_data_v2(),
            ),
            _ => None,
        }
    }

    pub(super) fn preparation_v2(&self) -> Option<&NetworkMutationAuthorizationV1> {
        if self.first.is_some() {
            return None;
        }
        self.preparation.as_ref()?.as_ref().ok()
    }

    pub(super) fn destroy_v2(&mut self) -> Option<&mut NetworkLifecycleExecutionAuthorizationV1> {
        if self.first.is_some() {
            return None;
        }
        self.destroy.as_mut()?.as_mut().ok()
    }

    pub(super) fn host_v2(&self) -> Option<&NamespaceFd> {
        if self.first.is_some() {
            return None;
        }
        let index = match self.method? {
            63 => 0,
            9 => 1,
            _ => return None,
        };
        self.namespaces[index].as_ref()?.as_ref().ok()
    }

    pub(super) fn destroy_target_v2(&self) -> Option<&NamespaceFd> {
        if self.first.is_some() || self.method != Some(9) {
            return None;
        }
        self.namespaces[0].as_ref()?.as_ref().ok()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            First::SourceBefore => self.before.failure(),
            First::Namespace(index) => self.namespaces[index]
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause.cause() as _),
            First::Decode => failed(&self.decode),
            First::Binding => failed(&self.binding),
            First::Authenticate => failed(&self.authenticate),
            First::Authorize => self
                .clock_failure
                .and_then(|index| self.clocks.get(index))
                .and_then(PreparationClockOriginalV2::failure)
                .or_else(|| failed(&self.preparation))
                .or_else(|| failed(&self.destroy)),
            First::SourceAfter => self.after.failure(),
            First::Order | First::Input | First::Body => None,
        };
        cause.or(Some(&self.closed))
    }

    /// Adds this actual stage; enclosing crypto, Protocol and plan quotes remain owed.
    pub(super) fn receiving_obligations_data_v2(input_bytes: usize) -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(input_bytes.checked_mul(3)?)?;
        let mut demand = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?);
        demand = demand
            .checked_add(NetworkChildSourceProbeOriginalV2::programme_obligations_data_v2(2)?)
            .ok()?;
        for _ in 0..2 {
            demand = demand
                .checked_add(PreparationClockOriginalV2::receiving_obligations_data_v2()?)
                .ok()?;
        }
        Some(demand)
    }
}

fn compare_binding_v2(
    binding: aos_sandbox_broker::receiving::NetworkChildOperationBindingDataV2,
    request: [u8; 16],
    effect: ObjectDigest,
    namespaces_match: bool,
) -> Result<(), NetworkWorkerProtocolError> {
    if binding.purpose == 1
        && binding.request_id == request
        && &binding.effect_digest == effect.as_bytes()
        && namespaces_match
    {
        Ok(())
    } else {
        Err(NetworkWorkerProtocolError::Authority)
    }
}

fn next_clock_v2(
    clocks: &mut [PreparationClockOriginalV2],
    next: &mut usize,
    failure: &mut Option<usize>,
    boot: [u8; 16],
) -> Result<RawPairedClockSample, NetworkAdmissionError> {
    let index = *next;
    let Some(clock) = clocks.get_mut(index) else {
        return Err(NetworkAdmissionError::FenceRejected);
    };
    *next += 1;
    let result = clock.observe_once_v2(boot);
    if result.is_err() {
        failure.get_or_insert(index);
    }
    result
}
