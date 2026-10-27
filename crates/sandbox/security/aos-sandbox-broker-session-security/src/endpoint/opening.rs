//! Actual partial endpoint acquisition for ordinary and retained dispositions.
//!
//! The common loader owns self-process capture, partial protected file/lock/
//! secret slots, entropy and both original posts before creating an endpoint.
//! Selected admission retains this original on failure; ordinary load maps its
//! existing redacted classification and drops the same partial at return.

use super::*;
use crate::controller_session_receiving::{ControllerClientReceivingV4, ControllerClientReceivingErrorV4};
use crate::protected_files::{ProtectedEndpointFilesOpeningV1, ProtectedEndpointFilesRevalidationV1};
use aos_sandbox_linux::self_execution::RetainedSelfExecutionCaptureError;

// The same file verifier has two disposal policies. Ordinary callers keep
// their old file-local scratch lifetime; selected callers retain actual probes
// through the subsequent self-execution post and joint upper disposition.
enum EndpointFilesPostV1 {
    Ordinary(Option<Result<(), BrokerSessionSecurityError>>),
    Retained(ProtectedEndpointFilesRevalidationV1),
}

impl EndpointFilesPostV1 {
    fn is_ordinary(&self) -> bool {
        matches!(self, Self::Ordinary(_))
    }

    fn observe(&mut self, files: &ProtectedEndpointFiles) {
        match self {
            Self::Ordinary(result) => *result = Some(files.revalidate()),
            Self::Retained(retained) => files.revalidate_into(retained),
        }
    }

    fn completed(&self) -> bool {
        match self {
            Self::Ordinary(result) => matches!(result, Some(Ok(()))),
            Self::Retained(retained) => retained.completed(),
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ordinary(result) => result.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            Self::Retained(retained) => retained.failure(),
        }
    }

    fn retire_completed_probes_v1(&mut self) -> bool {
        match self {
            Self::Ordinary(_) => false,
            Self::Retained(original) => original.retire_completed_probes_v1(),
        }
    }

    fn classified_failure(&self) -> Option<BrokerSessionSecurityError> {
        match self {
            Self::Ordinary(result) => result.as_ref()?.as_ref().err().cloned(),
            Self::Retained(retained) => retained.classified_failure(),
        }
    }
}

pub(super) struct EndpointOpeningV1 {
    native_entered: bool,
    finish_entered: bool,
    capture: Option<Result<RetainedSelfExecutionGuard, RetainedSelfExecutionCaptureError>>,
    ordinary_capture: Option<Result<(), BrokerSessionSecurityError>>,
    execution_entry: Option<Result<(), BrokerSessionSecurityError>>,
    execution_entry_observation: aos_sandbox_linux::self_execution::SelfExecutionObservationV1,
    controller_capture: Option<Result<aos_sandbox_broker::endpoint_native_files::ControllerEndpointExecutionOriginalV1,
        aos_sandbox_broker::endpoint_native_files::ControllerEndpointExecutionCaptureErrorV1>>,
    execution: Option<EndpointExecution>,
    files: ProtectedEndpointFilesOpeningV1,
    entropy: Option<Result<[u8; 16], BrokerSessionSecurityError>>,
    files_post: EndpointFilesPostV1,
    execution_post: Option<Result<(), BrokerSessionSecurityError>>,
    execution_observation: aos_sandbox_linux::self_execution::SelfExecutionObservationV1,
    endpoint: Option<ProtectedEndpointV1>,
    native_custody: aos_sandbox_broker::endpoint_native_files::ControllerEndpointNativeCustodyCaptureV1,
    native_execution: Option<aos_sandbox_broker::endpoint_native_files::ControllerEndpointExecutionOriginalV1>,
    native_execution_post: Option<aos_sandbox_linux::self_execution::SelfExecutionObservationV1>,
    native_handoff: Option<Result<(), ControllerClientReceivingErrorV4>>,
}

impl EndpointOpeningV1 {
    pub(super) const fn new() -> Self {
        Self {
            native_entered: false,
            finish_entered: false,
            capture: None,
            ordinary_capture: None,
            execution_entry: None,
            execution_entry_observation: aos_sandbox_linux::self_execution::SelfExecutionObservationV1::new(),
            controller_capture: None,
            execution: None,
            files: ProtectedEndpointFilesOpeningV1::new(),
            entropy: None,
            files_post: EndpointFilesPostV1::Retained(ProtectedEndpointFilesRevalidationV1::new()),
            execution_post: None,
            execution_observation: aos_sandbox_linux::self_execution::SelfExecutionObservationV1::new(),
            endpoint: None,
            native_custody: aos_sandbox_broker::endpoint_native_files::ControllerEndpointNativeCustodyCaptureV1::new(),
            native_execution: None,
            native_execution_post: None,
            native_handoff: None,
        }
    }

    pub(super) fn ordinary() -> Self {
        Self {
            files: ProtectedEndpointFilesOpeningV1::ordinary(),
            files_post: EndpointFilesPostV1::Ordinary(None),
            ..Self::new()
        }
    }

    #[cfg(test)]
    pub(super) fn with_execution(execution: EndpointExecution) -> Self {
        Self {
            execution: Some(execution),
            ..Self::ordinary()
        }
    }

    pub(super) fn load_native_once<Entropy: EntropySource>(
        &mut self,
        path: &Path,
        role: EndpointRole,
        entropy: &mut Entropy,
    ) {
        self.load_native_with_initial_once(path, role, entropy, None);
    }

    fn load_controller_native_once<Entropy: EntropySource>(
        &mut self,
        receiving: &mut ControllerClientReceivingV4<'_, '_>,
        entropy: &mut Entropy,
    ) {
        let path = receiving.role().endpoint_custody_path_v1();
        self.load_native_with_initial_once(Path::new(path), EndpointRole::Client, entropy, Some(receiving));
    }

    fn load_native_with_initial_once<Entropy: EntropySource>(
        &mut self,
        path: &Path,
        role: EndpointRole,
        entropy: &mut Entropy,
        initial: Option<&mut ControllerClientReceivingV4<'_, '_>>,
    ) {
        if self.native_entered || self.finish_entered {
            return;
        }
        self.native_entered = true;
        if self.files_post.is_ordinary() {
            let captured = RetainedSelfExecutionGuard::capture();
            self.ordinary_capture = Some(match captured {
                Ok(execution) => {
                    self.execution = Some(EndpointExecution::Retained(execution));
                    Ok(())
                }
                Err(cause) => Err(cause),
            });
            if !matches!(self.ordinary_capture, Some(Ok(()))) {
                return;
            }
            self.finish_with_initial_once(path, role, entropy, initial);
            return;
        }

        if let Some(receiving) = initial {
            self.controller_capture = Some(receiving.capture_execution_once());
            if !matches!(self.controller_capture, Some(Ok(_))) { return; }
            let Some(Ok(execution)) = self.controller_capture.take() else { std::process::abort() };
            self.execution_entry = Some(execution.observe_role_entry_v1(&mut self.execution_entry_observation)
                .map_err(|_| BrokerSessionSecurityError::ExecutionChanged));
            self.execution = Some(EndpointExecution::ControllerInitial(execution));
            if !matches!(self.execution_entry, Some(Ok(()))) {
                // The same immutable guard still permits its independent
                // native post. Keep both actual refused destinations; no
                // endpoint-file growth follows the failed entry sandwich.
                self.observe_execution_post();
                return;
            }
            self.finish_with_initial_once(path, role, entropy, Some(receiving));
            return;
        }

        self.capture = Some(RetainedSelfExecutionGuard::capture_retaining());
        if !matches!(self.capture, Some(Ok(_))) {
            return;
        }
        let Some(Ok(execution)) = self.capture.take() else {
            std::process::abort()
        };
        self.execution = Some(EndpointExecution::Retained(execution));
        self.finish_with_initial_once(path, role, entropy, initial);
    }

    pub(super) fn finish_once<Entropy: EntropySource>(
        &mut self,
        path: &Path,
        role: EndpointRole,
        entropy: &mut Entropy,
    ) {
        self.finish_with_initial_once(path, role, entropy, None);
    }

    fn finish_with_initial_once<Entropy: EntropySource>(
        &mut self,
        path: &Path,
        role: EndpointRole,
        entropy: &mut Entropy,
        mut initial: Option<&mut ControllerClientReceivingV4<'_, '_>>,
    ) {
        if self.finish_entered || self.execution.is_none() {
            return;
        }
        self.finish_entered = true;
        self.prepare_files_once(path, role, entropy, initial.as_deref_mut());
        let primary_complete = self.files.completed_ref().is_some()
            && matches!(self.entropy, Some(Ok(_)))
            && self.files_post.completed();
        if self.files_post.is_ordinary() && !primary_complete {
            return;
        }

        // Selected file/entropy refusals still owe the independently captured
        // process post. The whole earlier partial and first cause stay resident.
        self.observe_execution_post();
        if !primary_complete || !matches!(self.execution_post, Some(Ok(()))) {
            return;
        }

        if !self.files_post.is_ordinary()
            && (!self.files.retire_completed_probes_v1()
                || !self.files_post.retire_completed_probes_v1())
        {
            return;
        }
        if let Some(receiving) = initial {
            let Some(files) = self.files.completed_ref() else { return; };
            let execution = match self.execution.take() {
                Some(EndpointExecution::ControllerInitial(execution)) => execution,
                other => { self.execution = other; return; }
            };
            self.native_execution = Some(execution);
            self.native_execution_post = Some(std::mem::replace(
                &mut self.execution_observation,
                aos_sandbox_linux::self_execution::SelfExecutionObservationV1::new(),
            ));
            self.native_handoff = Some(receiving.capture_custody_once(
                &mut self.native_custody, &mut self.native_execution,
                &mut self.native_execution_post, files.native_files_v1(),
            ));
            if !matches!(self.native_handoff, Some(Ok(()))) { return; }
            let Some(custody) = self.native_custody.take_completed() else { return; };
            self.execution = Some(EndpointExecution::ControllerNative(custody));
        }

        // Both actual file comparisons and their independent process post
        // have completed. Keep the real endpoint/guard; the fresh probes are
        // neither identity anchors nor inputs to later floor operations.
        let Some(files) = self.files.take_completed() else {
            std::process::abort()
        };
        let Some(Ok(process_execution_id)) = self.entropy.take() else {
            std::process::abort()
        };
        let Some(execution) = self.execution.take() else {
            std::process::abort()
        };
        self.endpoint = Some(ProtectedEndpointV1 {
            launch_image: None,
            files,
            execution,
            process_execution_id,
            next_nonce_counter: Some(1),
            poisoned: false,
            #[cfg(target_os = "linux")]
            receiving: EndpointRevalidationReceivingV1::new(),
        });
    }

    fn prepare_files_once<Entropy: EntropySource>(
        &mut self,
        path: &Path,
        role: EndpointRole,
        entropy: &mut Entropy,
        initial: Option<&mut ControllerClientReceivingV4<'_, '_>>,
    ) {
        match initial {
            Some(receiving) => self.files.load_controller_context_v4(receiving),
            None => self.files.load_once(path, role),
        }
        if self.files.failure().is_some() {
            return;
        }

        self.entropy = Some(nonzero_random(entropy));
        if !matches!(self.entropy, Some(Ok(_))) {
            return;
        }

        let Some(files) = self.files.completed_ref() else {
            return;
        };
        self.files_post.observe(files);
    }

    fn observe_execution_post(&mut self) {
        if self.execution_post.is_some() {
            return;
        }
        let Some(execution) = self.execution.as_ref() else {
            std::process::abort()
        };
        self.execution_post = Some(if self.files_post.is_ordinary() {
            execution.validate_current()
        } else {
            match execution {
                EndpointExecution::Retained(execution) => execution.validate_current_retaining(&mut self.execution_observation),
                EndpointExecution::ControllerInitial(execution) => execution.validate_current_retaining(&mut self.execution_observation)
                    .map_err(|_| BrokerSessionSecurityError::ExecutionChanged),
                EndpointExecution::ControllerNative(custody) => custody.validate_current_retaining(&mut self.execution_observation)
                    .map_err(|_| BrokerSessionSecurityError::ExecutionChanged),
                #[cfg(test)]
                EndpointExecution::Scripted(execution) => execution.validate_current(),
            }
        });
    }

    fn classified_failure(&self) -> Option<BrokerSessionSecurityError> {
        if let Some(Err(cause)) = self.ordinary_capture.as_ref() {
            return Some(cause.clone());
        }
        if matches!(self.capture, Some(Err(_))) || matches!(self.controller_capture, Some(Err(_))) {
            return Some(BrokerSessionSecurityError::ExecutionChanged);
        }
        if let Some(Err(cause)) = &self.execution_entry { return Some(cause.clone()); }
        self.files.classified_failure()
            .or_else(|| self.entropy.as_ref().and_then(|result| result.as_ref().err()).cloned())
            .or_else(|| self.files_post.classified_failure())
            .or_else(|| self.execution_post.as_ref().and_then(|result| result.as_ref().err()).cloned())
            .or_else(|| self.native_handoff.as_ref().and_then(|result| result.as_ref().err()).map(|_| BrokerSessionSecurityError::Currentness))
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.ordinary_capture.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.capture.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.controller_capture.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.execution_entry_observation.failure())
            .or_else(|| self.execution_entry.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.files.failure())
            .or_else(|| self.entropy.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.files_post.failure())
            .or_else(|| self.execution_observation.failure())
            .or_else(|| self.execution_post.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.native_custody.failure().map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.native_handoff.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
    }

    pub(super) fn into_result(mut self) -> Result<ProtectedEndpointV1, BrokerSessionSecurityError> {
        let result = self.endpoint.take().ok_or_else(|| {
            self.classified_failure().unwrap_or(BrokerSessionSecurityError::Currentness)
        });

        // This adapter is used only by ordinary loads. Their file-local partial
        // or complete files must close before the earlier self-execution guard,
        // including an entropy or second-currentness refusal. The selected
        // owner never enters this immediate disposition.
        let files = std::mem::replace(&mut self.files, ProtectedEndpointFilesOpeningV1::ordinary());
        drop(files.into_result());
        result
    }
}

mod fixed_service;

/// Retains the actual fixed broker's lower acquisition, without exposing keys.
pub(crate) struct ProtectedBrokerSessionBrokerOpeningV1 {
    fixed_service: Option<fixed_service::FixedServiceBrokerOpeningAdmissionV4>,
    inner: EndpointOpeningV1,
    completed: Option<ProtectedBrokerSessionBrokerV1>,
    arming: Option<Result<(), BrokerSessionSecurityError>>,
    closed: Option<BrokerSessionSecurityError>,
}

impl ProtectedBrokerSessionBrokerOpeningV1 {
    pub(crate) const fn new() -> Self {
        Self {
            fixed_service: None,
            inner: EndpointOpeningV1::new(),
            completed: None,
            arming: None,
            closed: None,
        }
    }

    pub(crate) fn load_once(&mut self, path: &Path) {
        if self.completed.is_some() || self.arming.is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return;
        }
        self.inner.load_native_once(path, EndpointRole::Broker, &mut KernelEntropy);
        self.completed = self.inner.endpoint.take()
            .map(|inner| ProtectedBrokerSessionBrokerV1 { inner });
    }

    pub(crate) fn arm_original_once(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.arming.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let Some(completed) = self.completed.as_mut() else {
            return Err(self.classified_failure().unwrap_or(BrokerSessionSecurityError::Currentness));
        };
        self.arming = Some(completed.arm_original_storage_revalidation_once(receiving));
        match self.arming.as_ref() {
            Some(result) => result.clone(),
            None => std::process::abort(),
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.fixed_service.is_some() { return self.fixed_service_failure_v4(); }
        self.inner.failure()
            .or_else(|| self.arming.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.closed.as_ref().map(|cause| cause as &dyn std::error::Error))
    }

    pub(crate) fn classified_failure(&self) -> Option<BrokerSessionSecurityError> {
        self.inner.classified_failure()
            .or_else(|| self.arming.as_ref()?.as_ref().err().cloned())
            .or_else(|| self.closed.clone())
    }

    pub(crate) fn take_completed(&mut self) -> Option<ProtectedBrokerSessionBrokerV1> {
        if self.closed.is_some() || !matches!(self.arming, Some(Ok(())))
            || self.fixed_service.as_ref().is_some_and(|original| !original.is_positive_v4())
        {
            return None;
        }
        self.completed.take()
    }
}

/// Holds the actual fixed Controller Client acquisition under one B loan.
///
/// The fixed role comes only from that original. Native loading and both
/// independently owed posts use the same EndpointOpening engine as ordinary
/// and Storage broker loading; a failure never drops its partial owner here.
pub(crate) struct ProtectedBrokerSessionControllerClientOpeningV1 {
    inner: EndpointOpeningV1,
    entry: Option<Result<(), ControllerClientReceivingErrorV4>>,
    completed: Option<ProtectedBrokerSessionClientV1>,
    arming: Option<Result<(), BrokerSessionSecurityError>>,
    closed: Option<BrokerSessionSecurityError>,
}

impl ProtectedBrokerSessionControllerClientOpeningV1 {
    pub(crate) const fn new() -> Self {
        Self {
            inner: EndpointOpeningV1::new(),
            entry: None,
            completed: None,
            arming: None,
            closed: None,
        }
    }

    // Representation DATA only: no role, account, path or grant enters this
    // owning engine's bound. Each lower owner supplies its actual heap/FD/cell
    // reservoir; inline layout includes this entire retained wrapper once.
    pub(crate) fn receiving_shape_v1()
        -> Option<aos_sandbox_controller_domain::ControllerInitialBrokerSessionCaptureShapeV1>
    {
        use aos_sandbox_linux::self_execution::{
            RetainedSelfExecutionGuard as NativeGuard,
            SelfExecutionObservationV1 as NativeObservation,
        };
        use crate::protected_files::{
            ProtectedEndpointFilesOpeningV1 as FilesOpening,
            ProtectedEndpointFilesRevalidationV1 as FilesPost,
        };

        Some(aos_sandbox_controller_domain::ControllerInitialBrokerSessionCaptureShapeV1 {
            inline_bytes: std::mem::size_of::<Self>(),
            heap_bytes: FilesOpening::secret_heap_bytes_v1()
                .checked_add(aos_sandbox_broker::endpoint_native_files::EndpointNativeFileV1::selected_origin_heap_bytes_v1())?
                .checked_add(aos_sandbox_broker::endpoint_native_files::ControllerEndpointNativeCustodyCaptureV1::receiving_heap_bytes_v1())?
                .checked_add(FilesPost::secret_heap_bytes_v1())?
                .checked_add(NativeGuard::selected_capture_heap_bytes_v1())?
                .checked_add(NativeObservation::receiving_heap_bytes_v1())?
                .checked_add(NativeObservation::receiving_heap_bytes_v1())?,
            open_files: FilesOpening::opened_file_bound_v1()
                .checked_add(FilesPost::opened_file_bound_v1())?
                .checked_add(NativeGuard::selected_capture_opened_file_bound_v1())?
                .checked_add(NativeObservation::opened_file_bound_v1())?,
            metadata_cells: FilesOpening::metadata_cell_bound_v1()
                .checked_add(FilesPost::metadata_cell_bound_v1())?
                .checked_add(NativeGuard::selected_capture_metadata_cell_bound_v1())?
                .checked_add(NativeObservation::metadata_cell_bound_v1())?,
        })
    }

    pub(crate) fn load_controller_once(&mut self,
        receiving: &mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>) {
        self.load_controller_context_v4(&mut ControllerClientReceivingV4::Initial(receiving));
    }

    pub(crate) fn load_start_network_once_v2(&mut self,
        receiving: &mut aos_sandbox_controller_domain::StartResourceSessionOpeningLoanV2<'_>) {
        self.load_controller_context_v4(&mut ControllerClientReceivingV4::StartResource(receiving));
    }

    fn load_controller_context_v4(&mut self, receiving: &mut ControllerClientReceivingV4<'_, '_>) {
        if self.entry.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return;
        }
        self.entry = Some(receiving.require_current());
        if !matches!(self.entry, Some(Ok(()))) { return; }
        self.inner.load_controller_native_once(receiving, &mut KernelEntropy);
        self.completed = self.inner.endpoint.take().map(|inner| ProtectedBrokerSessionClientV1 { inner });
        let Some(client) = self.completed.as_mut() else { return; };
        self.arming = Some(match receiving {
            ControllerClientReceivingV4::Initial(loan) => client.arm_original_controller_initial_revalidation_once(loan),
            ControllerClientReceivingV4::StartResource(loan) => client.arm_start_resource_revalidation_once_v2(loan),
        });
    }

    pub(crate) fn completed_ref_v1(&self) -> Option<&ProtectedBrokerSessionClientV1> {
        if self.failure().is_some() || !matches!(self.arming, Some(Ok(()))) {
            return None;
        }
        self.completed.as_ref()
    }

    pub(crate) fn take_completed(&mut self) -> Option<ProtectedBrokerSessionClientV1> {
        if self.failure().is_some() || !matches!(self.arming, Some(Ok(()))) {
            return None;
        }
        self.completed.take()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.entry.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.inner.failure())
            .or_else(|| self.arming.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.closed.as_ref().map(|cause| cause as &dyn std::error::Error))
    }

    pub(crate) fn classified_failure(&self) -> Option<BrokerSessionSecurityError> {
        if matches!(self.entry, Some(Err(_))) {
            return Some(BrokerSessionSecurityError::Currentness);
        }
        self.inner.classified_failure()
            .or_else(|| self.arming.as_ref()?.as_ref().err().cloned())
            .or_else(|| self.closed.clone())
    }
}

/// Retains the fixed Storage-to-Host endpoint under the actual Storage F.
///
/// The sole EndpointOpening loader keeps all partial files, self-process
/// observations and independently owed native posts. This adapter supplies
/// neither a HELLO nor a verified Host outcome or physical Capture permit.
pub(crate) struct ProtectedBrokerSessionStorageHostClientOpeningV1 {
    inner: EndpointOpeningV1,
    demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>,
    payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    completed: Option<ProtectedBrokerSessionClientV1>,
    first: Option<StorageHostEndpointFailureV1>,
    binding: Option<Result<(), BrokerSessionSecurityError>>,
    arming: Option<Result<(), BrokerSessionSecurityError>>,
}

#[derive(Clone, Copy)]
enum StorageHostEndpointFailureV1 { Demand, Payment, Native, Binding, Arming }

impl ProtectedBrokerSessionStorageHostClientOpeningV1 {
    pub(crate) const fn new() -> Self {
        Self {
            inner: EndpointOpeningV1::new(), demand: None,
            payment: None, completed: None, first: None, binding: None, arming: None,
        }
    }

    fn demand_v1() -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError> {
        use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
        use aos_sandbox_linux::self_execution::{RetainedSelfExecutionGuard as Guard, SelfExecutionObservationV1 as Observation};
        use crate::protected_files::{ProtectedEndpointFilesOpeningV1 as Files, ProtectedEndpointFilesRevalidationV1 as Post};

        let overflow = || AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
        let memory = std::mem::size_of::<Self>()
            .checked_add(Files::secret_heap_bytes_v1()).and_then(|bytes| bytes.checked_add(Post::secret_heap_bytes_v1()))
            .and_then(|bytes| bytes.checked_add(Guard::selected_capture_heap_bytes_v1()))
            .and_then(|bytes| bytes.checked_add(Observation::receiving_heap_bytes_v1()))
            .and_then(|bytes| bytes.checked_add(Observation::receiving_heap_bytes_v1()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(overflow)?;
        let files = Files::opened_file_bound_v1().checked_add(Post::opened_file_bound_v1())
            .and_then(|files| files.checked_add(Guard::selected_capture_opened_file_bound_v1()))
            .and_then(|files| files.checked_add(Observation::opened_file_bound_v1()))
            .and_then(|files| u64::try_from(files).ok())
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
        // Eight root-to-custody names plus manifest, two local secrets and
        // two required-absent opposite secrets. The fixed self recipe adds
        // /proc, PID/stat and sys/kernel/random/boot_id (seven more names;
        // root is shared). Repeated before/after observations add no names.
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory)
            .with(D::OpenFiles, files).with(D::MetadataEntries, 20))
    }

    pub(crate) fn load_once(
        &mut self,
        path: &Path,
        lifecycle: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) {
        if self.payment.is_some() || self.first.is_some() { return; }
        self.load_inner_v1(path, lifecycle, session, socket);
    }

    fn load_inner_v1(
        &mut self,
        path: &Path,
        lifecycle: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) {
        self.demand = Some(Self::demand_v1());
        let Some(Ok(demand)) = self.demand.as_ref() else {
            self.first = Some(StorageHostEndpointFailureV1::Demand);
            return;
        };
        self.payment = Some(lifecycle.reserve_domain_additional_v1(session, socket, *demand));
        if !matches!(self.payment, Some(Ok(()))) {
            self.first = Some(StorageHostEndpointFailureV1::Payment);
            return;
        }
        self.inner.load_native_once(path, EndpointRole::Client, &mut KernelEntropy);
        self.completed = self.inner.endpoint.take().map(|inner| ProtectedBrokerSessionClientV1 { inner });
        if self.completed.is_none() { self.first = Some(StorageHostEndpointFailureV1::Native); }
        if let Some(client) = self.completed.as_mut() {
            self.arming = Some(client.arm_original_storage_host_revalidation_once_v1(lifecycle, session, socket));
            if !matches!(self.arming, Some(Ok(()))) {
                self.first.get_or_insert(StorageHostEndpointFailureV1::Arming);
            }
        }
    }

    pub(crate) fn take_completed_matching_v1(
        &mut self,
        protocol: aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1,
        node: [u8; 16],
    ) -> Option<ProtectedBrokerSessionClientV1> {
        if self.first.is_some() || !matches!(self.payment, Some(Ok(()))) { return None; }
        self.binding = Some(if self.completed.as_ref()
            .is_some_and(|custody| custody.protected_protocol_and_node() == (protocol, node))
        { Ok(()) } else { Err(BrokerSessionSecurityError::Currentness) });
        if !matches!(self.binding, Some(Ok(()))) {
            self.first = Some(StorageHostEndpointFailureV1::Binding);
            return None;
        }
        self.completed.take()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn original(slot: &Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        match self.first? {
            StorageHostEndpointFailureV1::Demand => self.demand.as_ref()?.as_ref().err().map(|cause| cause as _),
            StorageHostEndpointFailureV1::Payment => original(&self.payment),
            StorageHostEndpointFailureV1::Native => self.inner.failure(),
            StorageHostEndpointFailureV1::Binding => self.binding.as_ref()?.as_ref().err().map(|cause| cause as _),
            StorageHostEndpointFailureV1::Arming => self.completed.as_ref().and_then(|client| client.retained_revalidation_failure())
                .or_else(|| self.arming.as_ref()?.as_ref().err().map(|cause| cause as _)),
        }
    }

    pub(crate) fn classified_failure(&self) -> BrokerSessionSecurityError {
        if matches!(self.first, Some(StorageHostEndpointFailureV1::Native)) {
            self.inner.classified_failure().unwrap_or(BrokerSessionSecurityError::Currentness)
        } else { BrokerSessionSecurityError::Currentness }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_file_open_refusal_still_owes_the_actual_process_post() {
        let temporary = tempfile::tempdir().unwrap();
        let absent = temporary.path().join("absent");
        let mut selected = EndpointOpeningV1::new();
        let mut ordinary = EndpointOpeningV1::ordinary();

        selected.load_native_once(&absent, EndpointRole::Broker, &mut KernelEntropy);
        ordinary.load_native_once(&absent, EndpointRole::Broker, &mut KernelEntropy);

        assert!(selected.files.failure().is_some());
        assert!(selected.entropy.is_none());
        assert!(selected.execution.is_some());
        assert!(selected.endpoint.is_none());
        assert!(matches!(selected.execution_post, Some(Ok(()))));
        assert!(selected.execution_observation.failure().is_none());
        assert!(ordinary.execution_post.is_none());
        assert_eq!(selected.classified_failure(), ordinary.classified_failure());
        assert_eq!(
            selected.failure().and_then(|cause| cause.downcast_ref::<rustix::io::Errno>()),
            Some(&rustix::io::Errno::NOENT),
        );
    }

    #[test]
    fn complete_endpoint_posts_retire_only_fresh_probes_before_handoff() {
        use crate::test_signed_endpoint::{
            install_endpoint, manifest_and_secrets, TestEndpointRole,
        };

        let temporary = tempfile::tempdir().unwrap();
        let (manifest, secrets) = manifest_and_secrets(
            aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage,
        );
        install_endpoint(temporary.path(), &manifest, &secrets, TestEndpointRole::Client);
        let mut selected = EndpointOpeningV1::new();

        selected.load_native_once(temporary.path(), EndpointRole::Client, &mut KernelEntropy);

        assert!(matches!(selected.execution_post, Some(Ok(()))));
        assert!(selected.failure().is_none());
        assert_eq!(selected.files.retained_probe_file_count_v1(), 0);
        let EndpointFilesPostV1::Retained(post) = &selected.files_post else {
            panic!("selected fixture must retain its actual post");
        };
        assert!(post.completed());
        assert_eq!(post.retained_file_count(), 0);
        let endpoint = selected.endpoint.as_ref().unwrap();
        assert!(endpoint.files.revalidate().is_ok());
        assert!(endpoint.execution.validate_current().is_ok());

        std::fs::set_permissions(temporary.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    }

    #[test]
    fn failed_entropy_retains_earlier_positive_file_probes_through_owed_post() {
        use crate::test_signed_endpoint::{
            install_endpoint, manifest_and_secrets, TestEndpointRole,
        };

        struct RefusingEntropy;
        impl EntropySource for RefusingEntropy {
            fn fill_once(&mut self, _output: &mut [u8]) -> Result<usize, rustix::io::Errno> {
                Err(rustix::io::Errno::IO)
            }
        }

        let temporary = tempfile::tempdir().unwrap();
        let (manifest, secrets) = manifest_and_secrets(
            aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Storage,
        );
        install_endpoint(temporary.path(), &manifest, &secrets, TestEndpointRole::Client);
        let mut selected = EndpointOpeningV1::new();

        selected.load_native_once(temporary.path(), EndpointRole::Client, &mut RefusingEntropy);

        assert!(selected.endpoint.is_none());
        assert!(matches!(selected.execution_post, Some(Ok(()))));
        assert!(selected.failure().is_some());
        assert_eq!(selected.files.retained_probe_file_count_v1(), 4);
        assert!(selected.files.completed_ref().unwrap().revalidate().is_ok());

        std::fs::set_permissions(temporary.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    }

}
