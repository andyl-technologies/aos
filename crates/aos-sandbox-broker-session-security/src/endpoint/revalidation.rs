//! Fixed selected endpoint observations under the actual receiving originals.
//!
//! This owns at most a failed primary and one independently owed after check.
//! A positive check drops its actual fresh probes only after execution-before,
//! complete file comparison, and execution-after have all succeeded. There is
//! no lifetime request counter, caller-sized archive or financial reset.

use super::*;
use crate::protected_files::ProtectedEndpointFilesRevalidationV1;
use aos_sandbox_linux::self_execution::SelfExecutionObservationV1;
use aos_sandbox::{
    ControllerInitialBrokerSessionCaptureShapeV1, ControllerInitialBrokerSessionClosedV1,
    ControllerInitialBrokerSessionReceivingLoanV1, CreateStorageClientSessionClosedV1,
    CreateStorageEndpointRevalidationShapeDataV1,
    OriginalCreateStorageClientSessionV1, StoragePrepareReceivingLoanV1, StorageReceivingClosedV1,
};

/// Describes additional private custody without admitting work.
pub(crate) type EndpointRevalidationFootprintV1 = CreateStorageEndpointRevalidationShapeDataV1;

/// Describes the additional private archive and its construction temporary.
///
/// Enclosing Session/Activation sizeof already pays the embedded header; the
/// separate inline term conservatively pays Box construction outside that owner.
pub(crate) fn endpoint_revalidation_footprint_v1() -> Option<EndpointRevalidationFootprintV1> {
    let file_heap = ProtectedEndpointFilesRevalidationV1::secret_heap_bytes_v1();
    let native_heap = SelfExecutionObservationV1::receiving_heap_bytes_v1();
    let file_descriptors = ProtectedEndpointFilesRevalidationV1::opened_file_bound_v1();
    let native_descriptors = SelfExecutionObservationV1::opened_file_bound_v1();
    let file_cells = ProtectedEndpointFilesRevalidationV1::metadata_cell_bound_v1();
    let native_cells = SelfExecutionObservationV1::metadata_cell_bound_v1();

    Some(EndpointRevalidationFootprintV1 {
        inline_bytes: std::mem::size_of::<EndpointRevalidationArchiveV1>(),
        heap_bytes: std::mem::size_of::<EndpointRevalidationArchiveV1>()
            .checked_add(2_usize.checked_mul(file_heap.checked_add(native_heap)?)?)?,
        // A negative before stops this observation. A positive before really
        // disposes its native scratch, so at most its after can coexist with
        // four file probes. Two actual failed/owed observations remain live.
        file_descriptors: 2_usize.checked_mul(file_descriptors.checked_add(native_descriptors)?)?,
        metadata_cells: 2_usize.checked_mul(file_cells)?
            .checked_add(4_usize.checked_mul(native_cells)?)?.checked_add(2)?,
    })
}

/// Maps the same endpoint custody shape into the closed initial B receiver.
///
/// This passive layout carries no original, authority or resource payment.
/// The actual initial supplier includes it before any endpoint allocation.
pub(crate) fn controller_initial_endpoint_revalidation_shape_v1(
) -> Option<ControllerInitialBrokerSessionCaptureShapeV1> {
    endpoint_revalidation_footprint_v1().map(|footprint| {
        ControllerInitialBrokerSessionCaptureShapeV1 {
            inline_bytes: footprint.inline_bytes,
            heap_bytes: footprint.heap_bytes,
            open_files: footprint.file_descriptors,
            metadata_cells: footprint.metadata_cells,
        }
    })
}

enum Admission {
    StartNetwork(Result<(), aos_sandbox::ResourceReservationErrorV1>),
    ControllerInitial(Result<(), ControllerInitialBrokerSessionClosedV1>),
    Client(Result<(), CreateStorageClientSessionClosedV1>),
    Broker(Result<(), StorageReceivingClosedV1>),
    StorageHost(Result<(), StorageReceivingClosedV1>),
    FixedService(Result<(), aos_sandbox_broker::receiving::FixedServiceOperationClosedV4>),
}

impl Admission {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StartNetwork(result) => result.as_ref().err().map(|cause| cause as &dyn std::error::Error),
            Self::ControllerInitial(result) => result.as_ref().err().map(|cause| cause as &dyn std::error::Error),
            Self::Client(result) => result.as_ref().err().map(|cause| cause as &dyn std::error::Error),
            Self::Broker(result) | Self::StorageHost(result) => result.as_ref().err().map(|cause| cause as &dyn std::error::Error),
            Self::FixedService(result) => result.as_ref().err().map(|cause| cause as &dyn std::error::Error),
        }
    }
}

pub(super) struct EndpointRevalidationReceivingV1 {
    admission: Option<Admission>,
    archive: Option<Box<EndpointRevalidationArchiveV1>>,
    closed: Option<BrokerSessionSecurityError>,
}

impl EndpointRevalidationReceivingV1 {
    pub(super) const fn new() -> Self {
        Self {
            admission: None,
            archive: None,
            closed: None,
        }
    }

    fn require_unentered(&mut self) -> Result<(), BrokerSessionSecurityError> {
        if self.admission.is_some() || self.archive.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    pub(super) fn arm_controller_initial_client_once(
        &mut self,
        receiving: &mut ControllerInitialBrokerSessionReceivingLoanV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_unentered()?;
        let Some(footprint) = controller_initial_endpoint_revalidation_shape_v1() else {
            self.closed = Some(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        };
        self.admission = Some(Admission::ControllerInitial(
            receiving.require_endpoint_revalidation_shape_v1(footprint),
        ));
        self.finish_admission()
    }

    pub(super) fn arm_start_network_once_v2(&mut self,
        receiving: &mut aos_sandbox::StartResourceSessionOpeningLoanV2<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_unentered()?;
        if endpoint_revalidation_footprint_v1().is_none() {
            self.closed = Some(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.admission = Some(Admission::StartNetwork(receiving.require_fixed_capture_current_v2()));
        self.finish_admission()
    }

    pub(super) fn arm_client_once(
        &mut self,
        receiving: &mut OriginalCreateStorageClientSessionV1<'_, '_, '_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_unentered()?;
        let Some(footprint) = endpoint_revalidation_footprint_v1() else {
            self.closed = Some(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        };
        self.admission = Some(Admission::Client(
            receiving.require_fixed_endpoint_preparation_v1(footprint),
        ));
        self.finish_admission()
    }

    pub(super) fn arm_broker_once(
        &mut self,
        receiving: &mut StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_unentered()?;
        if endpoint_revalidation_footprint_v1().is_none() {
            self.closed = Some(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.admission = Some(Admission::Broker(receiving.require_session_fixed_current_v1()));
        self.finish_admission()
    }

    pub(super) fn arm_storage_host_once(
        &mut self,
        lifecycle: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_unentered()?;
        let footprint = endpoint_revalidation_footprint_v1().ok_or(BrokerSessionSecurityError::Currentness)?;
        let memory = footprint.inline_bytes.checked_add(footprint.heap_bytes)
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(BrokerSessionSecurityError::Currentness)?;
        let files = u64::try_from(footprint.file_descriptors).map_err(|_| BrokerSessionSecurityError::Currentness)?;
        // This archive observes exactly the already paid custody/proc names.
        // Native/result fields and repeated samples create no namespace entries.
        let demand = aos_sandbox_core::ResourceVector::ZERO
            .with(aos_sandbox_core::ResourceDimension::MemoryBytes, memory)
            .with(aos_sandbox_core::ResourceDimension::OpenFiles, files);
        self.admission = Some(Admission::StorageHost(
            lifecycle.reserve_domain_additional_v1(session, socket, demand)));
        self.finish_admission()
    }

    pub(super) fn arm_fixed_service_once_v4(
        &mut self,
        role: FixedServiceBrokerRoleV4,
        loan: &mut FixedServiceOpeningLoanV5<'_, '_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_unentered()?;
        // The named loader already prepaid this exact archive before native
        // loading. This real role gate selects only its genuine opening loan.
        self.admission = Some(Admission::FixedService(role.require_current(loan)));
        self.finish_admission()
    }

    fn finish_admission(&mut self) -> Result<(), BrokerSessionSecurityError> {
        if self.admission.as_ref().is_none_or(|admission| admission.failure().is_some()) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        // Every closed constructor borrows its actual genuine purpose loan.
        // Each fixed supplier includes this exact private shape before entry.
        self.archive = Some(Box::new(EndpointRevalidationArchiveV1::new()));
        Ok(())
    }

    pub(super) fn observe_once(
        &mut self,
        execution: &EndpointExecution,
        files: &ProtectedEndpointFiles,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.closed.is_some() || self.admission.as_ref().is_some_and(|admission| admission.failure().is_some()) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        match self.archive.as_mut() {
            Some(archive) => archive.observe_once(execution, files),
            None if self.admission.is_none() => {
                let mut observation = EndpointCurrentnessObservationV1::new();
                observation.observe_once(execution, files, Disposition::Ordinary);
                observation.classified_result()
            }
            None => Err(BrokerSessionSecurityError::Currentness),
        }
    }

    pub(super) fn require_healthy(&self) -> Result<(), BrokerSessionSecurityError> {
        if self.closed.is_some()
            || self.admission.as_ref().is_none_or(|admission| admission.failure().is_some())
            || self.archive.as_ref().is_none_or(|archive| archive.failure().is_some())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    pub(super) fn failure_for(
        &self, error: &BrokerSessionSecurityError,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        self.archive.as_ref()?.failure_for(error)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.admission.as_ref().and_then(Admission::failure)
            .or_else(|| self.archive.as_ref().and_then(|archive| archive.failure()))
            .or_else(|| self.closed.as_ref().map(|cause| cause as &dyn std::error::Error))
    }
}

#[derive(Clone, Copy)]
enum Disposition {
    Ordinary,
    Retained,
}

impl EndpointExecution {
    fn validate_for_revalidation(
        &self,
        disposition: Disposition,
        native: &mut SelfExecutionObservationV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        match disposition {
            Disposition::Ordinary => self.validate_current(),
            Disposition::Retained => match self {
                Self::Retained(guard) => guard.validate_current_retaining(native),
                Self::ControllerInitial(guard) => guard.validate_current_retaining(native)
                    .map_err(|_| BrokerSessionSecurityError::ExecutionChanged),
                Self::ControllerNative(custody) => custody.validate_current_retaining(native)
                    .map_err(|_| BrokerSessionSecurityError::ExecutionChanged),
                #[cfg(test)]
                Self::Scripted(guard) => guard.validate_current(),
            },
        }
    }
}

struct EndpointCurrentnessObservationV1 {
    before_native: SelfExecutionObservationV1,
    before: Option<Result<(), BrokerSessionSecurityError>>,
    files: ProtectedEndpointFilesRevalidationV1,
    file_result: Option<Result<(), BrokerSessionSecurityError>>,
    after_native: SelfExecutionObservationV1,
    after: Option<Result<(), BrokerSessionSecurityError>>,
}

impl EndpointCurrentnessObservationV1 {
    const fn new() -> Self {
        Self {
            before_native: SelfExecutionObservationV1::new(),
            before: None,
            files: ProtectedEndpointFilesRevalidationV1::new(),
            file_result: None,
            after_native: SelfExecutionObservationV1::new(),
            after: None,
        }
    }

    fn observe_once(
        &mut self,
        execution: &EndpointExecution,
        files: &ProtectedEndpointFiles,
        disposition: Disposition,
    ) {
        if self.before.is_some() {
            return;
        }
        self.before = Some(execution.validate_for_revalidation(disposition, &mut self.before_native));
        if !matches!(self.before, Some(Ok(()))) {
            return;
        }

        self.file_result = Some(match disposition {
            Disposition::Ordinary => files.revalidate(),
            Disposition::Retained => {
                files.revalidate_into(&mut self.files);
                match self.files.classified_failure() {
                    Some(cause) => Err(cause),
                    None if self.files.completed() => Ok(()),
                    None => Err(BrokerSessionSecurityError::Currentness),
                }
            }
        });
        if !matches!(self.file_result, Some(Ok(()))) {
            return;
        }

        self.after = Some(execution.validate_for_revalidation(disposition, &mut self.after_native));
    }

    fn completed(&self) -> bool {
        matches!(self.before, Some(Ok(()))) && matches!(self.file_result, Some(Ok(())))
            && matches!(self.after, Some(Ok(())))
    }

    fn classified_result(&self) -> Result<(), BrokerSessionSecurityError> {
        for result in [&self.before, &self.file_result, &self.after] {
            if let Some(Err(cause)) = result {
                return Err(cause.clone());
            }
        }
        if self.completed() {
            Ok(())
        } else {
            Err(BrokerSessionSecurityError::Currentness)
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before_native.failure()
            .or_else(|| self.before.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.files.failure())
            .or_else(|| self.file_result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.after_native.failure())
            .or_else(|| self.after.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
    }
}

// These are the actual successful Result values moved out of a completed
// observation; this private DATA receipt cannot authorize a later check.
struct CompletedEndpointComparisonV1 {
    _execution_before: Result<(), BrokerSessionSecurityError>,
    _files: Result<(), BrokerSessionSecurityError>,
    _execution_after: Result<(), BrokerSessionSecurityError>,
}

pub(super) struct EndpointRevalidationArchiveV1 {
    observations: [Option<EndpointCurrentnessObservationV1>; 2],
    last_completed: Option<CompletedEndpointComparisonV1>,
    exhausted: Option<BrokerSessionSecurityError>,
}

impl EndpointRevalidationArchiveV1 {
    pub(super) const fn new() -> Self {
        Self {
            observations: [None, None],
            last_completed: None,
            exhausted: None,
        }
    }

    pub(super) fn observe_once(
        &mut self,
        execution: &EndpointExecution,
        files: &ProtectedEndpointFiles,
    ) -> Result<(), BrokerSessionSecurityError> {
        let Some(index) = self.observations.iter().position(Option::is_none) else {
            self.exhausted.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        };
        if self.exhausted.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        self.observations[index] = Some(EndpointCurrentnessObservationV1::new());
        let Some(observation) = self.observations[index].as_mut() else {
            std::process::abort()
        };
        observation.observe_once(execution, files, Disposition::Retained);
        let result = observation.classified_result();
        if observation.completed() {
            let (Some(before), Some(files), Some(after)) = (
                observation.before.take(),
                observation.file_result.take(),
                observation.after.take(),
            ) else {
                std::process::abort()
            };
            self.last_completed = Some(CompletedEndpointComparisonV1 {
                _execution_before: before,
                _files: files,
                _execution_after: after,
            });
            // This actually disposes all fresh files and secret buffers now,
            // after the real trailing execution post, before peak reuse.
            drop(self.observations[index].take());
        }
        // Only this exact failed destination emits its index. Independent
        // later posts must not replace an earlier unrelated semantic failure.
        result.map_err(|_| BrokerSessionSecurityError::EndpointRevalidation { observation: index })
    }

    pub(super) fn failure_for(
        &self, error: &BrokerSessionSecurityError,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        let BrokerSessionSecurityError::EndpointRevalidation { observation } = error else {
            return None;
        };
        self.observations.get(*observation)?.as_ref()?.failure()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.observations.iter().flatten().find_map(EndpointCurrentnessObservationV1::failure)
            .or_else(|| self.exhausted.as_ref().map(|cause| cause as &dyn std::error::Error))
    }

    #[cfg(test)]
    pub(super) fn retained_file_count(&self) -> usize {
        self.observations.iter().flatten().map(|observation| observation.files.retained_file_count()).sum()
    }

    #[cfg(test)]
    pub(super) fn has_completed(&self) -> bool { self.last_completed.is_some() }
}


/// Owns a closed negative-capable observation of the same retained endpoint.
///
/// Each successful complete execution/files/execution comparison disposes its
/// fresh native prefix before reuse. Failed prefixes remain here independently
/// of the original B archive and cannot consume another interval's owed slot.
pub(crate) struct RetainedEndpointRevalidationOriginalV1 {
    active: Option<EndpointCurrentnessObservationV1>,
    completed: [Option<CompletedEndpointComparisonV1>; 2],
    returned: Option<Result<(), BrokerSessionSecurityError>>,
    closed: Option<BrokerSessionSecurityError>,
}

impl Default for RetainedEndpointRevalidationOriginalV1 {
    fn default() -> Self {
        Self { active: None, completed: [None, None], returned: None, closed: None }
    }
}

impl RetainedEndpointRevalidationOriginalV1 {
    /// Bounds this concrete native owner using the same endpoint probe suppliers.
    pub(crate) fn receiving_demand_v1() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(ProtectedEndpointFilesRevalidationV1::secret_heap_bytes_v1())?
            .checked_add(SelfExecutionObservationV1::receiving_heap_bytes_v1())?;
        let files = ProtectedEndpointFilesRevalidationV1::opened_file_bound_v1()
            .checked_add(SelfExecutionObservationV1::opened_file_bound_v1())?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.active.as_ref().and_then(EndpointCurrentnessObservationV1::failure)
            .or_else(|| self.returned.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
            .or_else(|| self.closed.as_ref().map(|e| e as _))
    }

    pub(super) fn observe_endpoint_once_v1(&mut self, endpoint: &mut ProtectedEndpointV1)
        -> Result<(), BrokerSessionSecurityError>
    {
        if self.active.is_some() || self.returned.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let poisoned = endpoint.poisoned;
        self.returned = Some((|| {
            // The old handshake engine compares twice. A whole positive first
            // prefix is physically disposed before the second native entry.
            for completed in &mut self.completed {
                self.active = Some(EndpointCurrentnessObservationV1::new());
                let original = self.active.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?;
                original.observe_once(&endpoint.execution, &endpoint.files, Disposition::Retained);
                original.classified_result()?;
                let (Some(before), Some(files), Some(after)) = (
                    original.before.take(), original.file_result.take(), original.after.take())
                else { return Err(BrokerSessionSecurityError::Currentness); };
                *completed = Some(CompletedEndpointComparisonV1 {
                    _execution_before: before, _files: files, _execution_after: after,
                });
                drop(self.active.take());
            }
            // Negative observations never restore a poisoned endpoint.
            if poisoned { return Err(BrokerSessionSecurityError::Poisoned); }
            Ok(())
        })());
        if !matches!(self.returned, Some(Ok(()))) { endpoint.poisoned = true; }
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(BrokerSessionSecurityError::Currentness) }
    }
}

#[cfg(test)]
impl RetainedEndpointRevalidationOriginalV1 {
    pub(crate) fn retained_file_count_v1(&self) -> usize {
        self.active.as_ref().map_or(0, |original| original.files.retained_file_count())
    }

    pub(crate) fn retained_manifest_pair_v1(&self) -> Option<(&[u8], &[u8])> {
        self.active.as_ref()?.files.retained_manifest_pair_v1()
    }
}
