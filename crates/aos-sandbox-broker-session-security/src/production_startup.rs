//! Closed startup tables for the existing floor and original Storage owners.
//!
//! The original PID 1 image is observed only through the fixed unit's named
//! `OpenFile=/proc/1/exe:aos-method46-pid1-image:read-only` entry. Environment
//! names select slots, not authority. This module exposes no caller-supplied
//! FD/image constructor. The floor's measured-image and genuine-manager guard
//! independently validate this parent-only observation before any TPM use.
//! Genuine original Storage worker startup may retain the same image in
//! legacy-closed mode without constructing a method-46 launch or floor owner.

use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;

use aos_sandbox::normal_root::{
    ControllerInitialCaptureFailureRefV1, ProductionControllerInitialCaptureAttemptV1,
    ProductionControllerNormalRootCaptureV1, ProductionControllerNormalRootProfileV1,
    ProductionControllerNormalRootStartupPartsV1,
};
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_storage::activation::{
    StorageOriginalWorkerStartupErrorV3, StorageOriginalWorkerStartupV3, take_systemd_startup,
};
use aos_sandbox_storage::service::StorageServiceError;

use crate::{ProductionBrokerSessionActivationV1, ProtectedBrokerSessionFixedEndpointV1};

/// Retains an original launch observation, not a currentness or TPM proof.
#[derive(Clone)]
pub(crate) struct Pid1LaunchImageV1 {
    endpoint: ProtectedBrokerSessionFixedEndpointV1,
    process: u32,
    file: LaunchImageFile,
    profile_delivery: ControllerProfileDeliveryV1,
}

// Legacy keeps its literal allocation interval. The retained destination is
// empty BEFORE capture and receives only the same actual original afterward.
#[derive(Clone)]
enum LaunchImageFile {
    Legacy(Arc<File>),
    Retained(Arc<Option<File>>),
}

// Pending capture cannot stand in for genuinely admitted profile absence.
#[derive(Clone)]
enum ControllerProfileDeliveryV1 {
    Storage,
    Pending,
    Admitted(Option<Arc<ProductionControllerNormalRootProfileV1>>),
}

impl Pid1LaunchImageV1 {
    pub(crate) fn require_endpoint(
        &self,
        endpoint: ProtectedBrokerSessionFixedEndpointV1,
    ) -> Result<(), crate::BrokerSessionSecurityError> {
        let admitted_role = matches!(
            (&self.profile_delivery, endpoint),
            (
                ControllerProfileDeliveryV1::Storage,
                ProtectedBrokerSessionFixedEndpointV1::StorageBroker
            ) | (
                ControllerProfileDeliveryV1::Admitted(_),
                ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient
            )
        );
        if self.endpoint != endpoint || self.process != std::process::id() || !admitted_role {
            return Err(crate::BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    // Both dispositions bind only the same genuinely admitted profile.
    pub(crate) fn bind_controller_profile(
        mut self,
        profile: Option<Arc<ProductionControllerNormalRootProfileV1>>,
    ) -> Result<Self, crate::BrokerSessionSecurityError> {
        self.bind_controller_profile_in_place(profile)
            .map_err(|_| crate::BrokerSessionSecurityError::Currentness)?;
        Ok(self)
    }

    fn bind_controller_profile_in_place(
        &mut self,
        profile: Option<Arc<ProductionControllerNormalRootProfileV1>>,
    ) -> Result<(), ControllerBindingFailure> {
        if self.endpoint != ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient
            || self.process != std::process::id()
            || !matches!(&self.profile_delivery, ControllerProfileDeliveryV1::Pending)
        {
            return Err(ControllerBindingFailure::Role(
                crate::BrokerSessionSecurityError::Currentness,
            ));
        }
        if let Some(profile) = &profile {
            profile
                .recheck()
                .map_err(ControllerBindingFailure::Profile)?;
        }
        self.profile_delivery = ControllerProfileDeliveryV1::Admitted(profile);
        Ok(())
    }

    pub(crate) fn recheck_profile_delivery(
        &self,
        endpoint: ProtectedBrokerSessionFixedEndpointV1,
    ) -> Result<Option<&Path>, crate::BrokerSessionSecurityError> {
        self.require_endpoint(endpoint)?;
        match &self.profile_delivery {
            ControllerProfileDeliveryV1::Admitted(Some(profile)) => {
                profile
                    .recheck()
                    .map_err(|_| crate::BrokerSessionSecurityError::Currentness)?;
                Ok(Some(profile.profile_path()))
            }
            ControllerProfileDeliveryV1::Storage | ControllerProfileDeliveryV1::Admitted(None) => {
                Ok(None)
            }
            ControllerProfileDeliveryV1::Pending => {
                Err(crate::BrokerSessionSecurityError::Currentness)
            }
        }
    }

    /// Borrows the same original launch image without another observation.
    ///
    /// # Errors
    ///
    /// Returns `Currentness` when a retained destination has no original file,
    /// before image measurement. Legacy images always return their original.
    pub(crate) fn file(&self) -> Result<&File, crate::BrokerSessionSecurityError> {
        match &self.file {
            LaunchImageFile::Legacy(file) => Ok(file.as_ref()),
            LaunchImageFile::Retained(slot) => slot
                .as_ref()
                .as_ref()
                .ok_or(crate::BrokerSessionSecurityError::Currentness),
        }
    }
}

enum ControllerBindingFailure {
    Role(crate::BrokerSessionSecurityError),
    Profile(aos_sandbox::normal_root::NormalRootStartupErrorV1),
}

/// Retains all existing Storage listeners and its private launch observation.
///
/// Construction captures the actual process-start table; it accepts no caller
/// descriptor or image claim. Optional floor image and worker custody remain
/// separate; worker-only delivery creates no method-46 launch owner.
pub struct ProductionStorageStartupV1 {
    activation: ProductionBrokerSessionActivationV1,
    export: RecordSubjectListener,
    live_export: Option<RecordSubjectListener>,
    zfs_hold: Option<RecordSubjectListener>,
    operator: Option<RecordSubjectListener>,
    existing_output: Option<RecordSubjectListener>,
}

/// Storage activation and its separately retained non-broker listeners.
pub type ProductionStorageStartupPartsV1 = (
    ProductionBrokerSessionActivationV1,
    RecordSubjectListener,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
);

// Own the genuine startup BEFORE the additional mode observation. This guard
// fences only this synchronous Security route: interruption closes the worker
// before disposal, but does not return a caught-unwind custody reservoir.
struct StorageWorkerImageRouteObservation {
    startup: Option<StorageOriginalWorkerStartupV3>,
    finished: bool,
}

impl StorageWorkerImageRouteObservation {
    fn begin(startup: Option<StorageOriginalWorkerStartupV3>) -> Self {
        Self {
            startup,
            finished: false,
        }
    }

    fn fail(
        mut self,
        cause: StorageServiceError,
    ) -> StorageOriginalWorkerStartupErrorV3 {
        let failure = StorageOriginalWorkerStartupErrorV3::retain_service_failure(
            cause,
            self.startup.take(),
        );
        self.finished = true;
        failure
    }

    fn finish(mut self) -> Option<StorageOriginalWorkerStartupV3> {
        self.finished = true;
        self.startup.take()
    }
}

impl Drop for StorageWorkerImageRouteObservation {
    fn drop(&mut self) {
        if !self.finished {
            // An empty Activation marker denotes route interruption, not an
            // invented I/O/Floor cause. It needs no string allocation.
            let interruption = StorageServiceError::Activation(String::new());
            let _closed = StorageOriginalWorkerStartupErrorV3::retain_service_failure(
                interruption,
                self.startup.take(),
            );
        }
    }
}

impl ProductionStorageStartupV1 {
    /// Captures the closed table before opening any retained service state.
    ///
    /// # Errors
    ///
    /// Rejects invalid activation, mismatched immutable floor mode/image
    /// presence, or any fixed broker-listener failure. This cannot be retried.
    pub fn capture() -> Result<Self, StorageServiceError> {
        let (listeners, image) = take_systemd_startup()?.into_parts();
        Self::admit_captured_parts(listeners, image)
    }

    /// Captures once and transfers genuine original worker startup downward.
    ///
    /// The existing six-listener tuple is unchanged. In legacy-closed mode,
    /// an admitted worker retains the image without a method-46 launch owner.
    /// Required mode still uses the original strict floor image admission.
    /// Missing original image yields no worker owner, not a grant.
    ///
    /// # Errors
    ///
    /// Rejects the same legacy activation/mode failures or typed original
    /// startup admission failures, retaining admitted worker custody on error.
    pub fn capture_original_worker_startup(
    ) -> Result<
        (
            Self,
            Option<aos_sandbox_storage::activation::StorageOriginalWorkerStartupV3>,
        ),
        aos_sandbox_storage::activation::StorageOriginalWorkerStartupErrorV3,
    > {
        let captured = take_systemd_startup()?;
        let (listeners, image, startup) = captured.into_original_worker_parts()?;
        let route = StorageWorkerImageRouteObservation::begin(startup);

        // This extra retained mode interval is worker-only. No-image capture
        // keeps the old strict admission, without another mode observation.
        let mode = if image.is_some() {
            if route.startup.is_none() {
                return Err(route.fail(startup_error(
                    "Storage worker image has no genuine startup owner",
                )));
            }
            match crate::recovery::ModePinV1::open_storage_worker_image_mode() {
                Ok(mode) => Some(mode),
                Err(_) => {
                    // Preserve the existing Service projection; the old
                    // strict presence checker also redacts its Floor cause.
                    return Err(route.fail(startup_error(
                        "Storage launch image differs from image floor mode",
                    )));
                }
            }
        } else {
            None
        };

        // Only the already admitted genuine worker may carry a LegacyClosed
        // image. The floor receives None; Required keeps its original image.
        let floor_image = if mode.as_ref().is_some_and(|mode| !mode.is_required()) {
            None
        } else {
            image
        };
        let startup_owner = match Self::admit_captured_parts(listeners, floor_image) {
            Ok(owner) => owner,
            Err(cause) => return Err(route.fail(cause)),
        };

        if let Some(mode) = &mode {
            if mode.revalidate().is_err() {
                return Err(route.fail(startup_error(
                    "Storage launch image differs from image floor mode",
                )));
            }
        }
        Ok((startup_owner, route.finish()))
    }

    // Both capture paths consume the same complete table through the original
    // image-mode and fixed-listener admission sequence, without a second scan.
    fn admit_captured_parts(
        listeners: aos_sandbox_storage::activation::StorageSystemdListenersV1,
        image: Option<OwnedFd>,
    ) -> Result<Self, StorageServiceError> {
        let (control, export, live_export, zfs_hold, operator, existing_output) = listeners;
        let endpoint = ProtectedBrokerSessionFixedEndpointV1::StorageBroker;
        let image = admit_launch_observation(endpoint, image)
            .map_err(|_| startup_error("Storage launch image differs from image floor mode"))?;
        let mut activation = ProductionBrokerSessionActivationV1::adopt_storage_listener(control)
            .map_err(|error| startup_error(error.to_string()))?;
        activation.retain_launch_image(image);
        Ok(Self {
            activation,
            export,
            live_export,
            zfs_hold,
            operator,
            existing_output,
        })
    }

    /// Transfers the fixed activation and every existing sidecar listener.
    #[must_use]
    pub fn into_parts(self) -> ProductionStorageStartupPartsV1 {
        (
            self.activation,
            self.export,
            self.live_export,
            self.zfs_hold,
            self.operator,
            self.existing_output,
        )
    }
}

pub(crate) fn capture_controller(
    publisher: bool,
) -> Result<
    (
        Option<OwnedFd>,
        Option<Pid1LaunchImageV1>,
        aos_sandbox::normal_root::ProductionControllerNormalRootCaptureV1,
    ),
    crate::BrokerSessionSecurityError,
> {
    let captured = capture_controller_with_backends(publisher, false, false)?;
    Ok((captured.publisher_descriptor, captured.launch_image, captured.normal_root_capture))
}

pub(crate) struct CapturedControllerStartupV1 {
    pub(crate) publisher_descriptor: Option<OwnedFd>,
    pub(crate) launch_image: Option<Pid1LaunchImageV1>,
    pub(crate) normal_root_capture: aos_sandbox::normal_root::ProductionControllerNormalRootCaptureV1,
    pub(crate) nix_capture: Option<aos_sandbox::normal_root::ProductionControllerNixStartupCaptureV1>,
    pub(crate) git_source_listener: Option<OwnedFd>,
}

pub(crate) fn capture_controller_with_backends(
    publisher: bool,
    nix_enabled: bool,
    git_source_cut: bool,
) -> Result<CapturedControllerStartupV1, crate::BrokerSessionSecurityError> {
    let (mut profile, publisher_fd, image) =
        aos_sandbox::normal_root::ProductionControllerNormalRootCaptureV1::capture_with_backends(
            publisher, nix_enabled, git_source_cut,
        ).map_err(|_| crate::BrokerSessionSecurityError::Currentness)?;
    let nix_capture = profile.take_nix_startup();
    let git_source_listener = profile.take_git_source_listener();
    let image = admit_launch_observation(
        ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
        image,
    )?;
    Ok(CapturedControllerStartupV1 {
        publisher_descriptor: publisher_fd,
        launch_image: image,
        normal_root_capture: profile,
        nix_capture,
        git_source_listener,
    })
}

fn admit_launch_observation(
    endpoint: ProtectedBrokerSessionFixedEndpointV1,
    descriptor: Option<OwnedFd>,
) -> Result<Option<Pid1LaunchImageV1>, crate::BrokerSessionSecurityError> {
    let profile_delivery = launch_profile_delivery(endpoint, descriptor.is_some())?;
    Ok(descriptor.map(|descriptor| Pid1LaunchImageV1 {
        endpoint,
        process: std::process::id(),
        file: LaunchImageFile::Legacy(Arc::new(File::from(descriptor))),
        profile_delivery,
    }))
}

fn launch_profile_delivery(
    endpoint: ProtectedBrokerSessionFixedEndpointV1,
    supplied: bool,
) -> Result<ControllerProfileDeliveryV1, crate::BrokerSessionSecurityError> {
    crate::recovery::require_launch_image_presence(endpoint, supplied)?;
    match endpoint {
        ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient => {
            Ok(ControllerProfileDeliveryV1::Pending)
        }
        ProtectedBrokerSessionFixedEndpointV1::StorageBroker => {
            Ok(ControllerProfileDeliveryV1::Storage)
        }
        _ => Err(crate::BrokerSessionSecurityError::Currentness),
    }
}

/// Borrows a cause from the same nested retained startup owner.
///
/// The view is short and by value; Security stores no self-borrow or cloned
/// Core cause. It grants no launch, selected-profile or floor authority.
pub(crate) enum ControllerStartupFailureRefV1<'attempt> {
    Core(ControllerInitialCaptureFailureRefV1<'attempt>),
    Launch(&'attempt crate::BrokerSessionSecurityError),
    Closed,
}

impl std::fmt::Debug for ControllerStartupFailureRefV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "original Controller capture refused",
            Self::Launch(_) => "original Controller launch delivery refused",
            Self::Closed => "original Controller startup closed",
        })
    }
}

enum StartupCaptureFailure {
    Core,
    Launch(crate::BrokerSessionSecurityError),
    Closed,
}

/// Keeps actual startup originals resident across launch-presence admission.
///
/// The empty image destination is allocated before initial capture, never
/// after an original has left its slot. Installed Controller startup uses this
/// same capture; unrelated consuming startup paths remain unchanged.
/// Failed/abandoned or unwinding attempts abort before field release; OS death
/// is not drain or Source-flight settlement. Lower unreturned custody remains
/// a separate functional prerequisite.
#[must_use]
pub(crate) struct ControllerStartupCaptureAttemptV1 {
    image_destination: Arc<Option<File>>,
    core: ProductionControllerInitialCaptureAttemptV1,
    parts: Option<ProductionControllerNormalRootStartupPartsV1>,
    git: Option<OwnedFd>,
    completed: Option<CapturedControllerStartupV1>,
    attempted: bool,
    failure: Option<StartupCaptureFailure>,
    armed: bool,
}

impl ControllerStartupCaptureAttemptV1 {
    pub(crate) fn new(publisher: bool, nix_enabled: bool, git_source_cut: bool) -> Self {
        // This is the sole retained-only allocation. It precedes any table IO
        // and contains no File, fabricated image or authorization claim.
        let image_destination = Arc::new(None);
        Self {
            image_destination,
            core: ProductionControllerNormalRootCaptureV1::begin_retained_capture(
                publisher, nix_enabled, git_source_cut,
            ),
            parts: None,
            git: None,
            completed: None,
            attempted: false,
            failure: None,
            armed: true,
        }
    }

    /// Captures and checks the same originals once, before any journal opens.
    ///
    /// # Errors
    /// Borrows the actual nested Core or launch cause without releasing partial
    /// originals. Repeats are closed and perform no observations.
    pub(crate) fn capture_once(&mut self) -> Result<(), ControllerStartupFailureRefV1<'_>> {
        if self.attempted {
            self.failure.get_or_insert(StartupCaptureFailure::Closed);
        } else {
            self.attempted = true;
            let result = {
                let _unwind = AbortStartupCaptureUnwind;
                self.capture_body()
            };
            match result {
                Ok(()) => return Ok(()),
                Err(cause) => {
                    self.failure.get_or_insert(cause);
                }
            }
        }
        Err(self.failure_view())
    }

    pub(crate) fn first_failure(&self) -> Option<ControllerStartupFailureRefV1<'_>> {
        self.failure.as_ref().map(|_| self.failure_view())
    }

    /// Moves the same completed startup once without observation or allocation.
    ///
    /// The destination must be parked before a fallible continuation. Its Core
    /// capture can then enter the genuine existing retained-profile producer.
    pub(crate) fn take_completed_startup(&mut self) -> Option<CapturedControllerStartupV1> {
        let mut completed = self.take_completed_profile_startup()?;
        completed.nix_capture = completed.normal_root_capture.take_nix_startup();
        Some(completed)
    }

    // The installed retained path keeps Nix nested with its producer-associated
    // delivery duplicate until FIRST6 finishes the same capture.
    fn take_completed_profile_startup(&mut self) -> Option<CapturedControllerStartupV1> {
        if self.failure.is_some()
            || self.completed.is_none()
            || self.parts.is_some()
            || self.git.is_some()
        {
            return None;
        }
        let completed = self.completed.take();
        self.armed = false;
        completed
    }

    fn failure_view(&self) -> ControllerStartupFailureRefV1<'_> {
        match &self.failure {
            Some(StartupCaptureFailure::Core) => match self.core.first_failure() {
                Some(cause) => ControllerStartupFailureRefV1::Core(cause),
                None => ControllerStartupFailureRefV1::Closed,
            },
            Some(StartupCaptureFailure::Launch(cause)) => {
                ControllerStartupFailureRefV1::Launch(cause)
            }
            Some(StartupCaptureFailure::Closed) | None => ControllerStartupFailureRefV1::Closed,
        }
    }

    fn capture_body(&mut self) -> Result<(), StartupCaptureFailure> {
        if self.parts.is_some() || self.git.is_some()
            || self.completed.is_some()
        {
            return Err(StartupCaptureFailure::Closed);
        }
        if self.core.capture_once().is_err() {
            return Err(StartupCaptureFailure::Core);
        }
        let Some(parts) = self.core.take_completed_parts() else {
            return Err(StartupCaptureFailure::Closed);
        };
        self.parts = Some(parts);
        let parts = self.parts.as_mut().ok_or(StartupCaptureFailure::Closed)?;
        self.git = parts.0.take_git_source_listener();

        let endpoint = ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient;
        let image_present = parts.2.is_some();
        let profile_delivery = launch_profile_delivery(endpoint, image_present)
            .map_err(StartupCaptureFailure::Launch)?;

        // Check unique ownership and the empty destination BEFORE taking the
        // raw original. This borrow cannot allocate or observe another image.
        let target = Arc::get_mut(&mut self.image_destination)
            .ok_or(StartupCaptureFailure::Closed)?;
        if target.is_some() || parts.2.is_some() != image_present {
            return Err(StartupCaptureFailure::Closed);
        }
        if let Some(original) = parts.2.take() {
            *target = Some(File::from(original));
        }
        let launch_image = if image_present {
            Some(Pid1LaunchImageV1 {
                endpoint,
                process: std::process::id(),
                file: LaunchImageFile::Retained(Arc::clone(&self.image_destination)),
                profile_delivery,
            })
        } else {
            None
        };

        // The image is already resident in the shared original destination.
        // No observation/allocation follows any startup tuple removal.
        if self.completed.is_some()
            || self.parts.as_ref().is_none_or(|parts| parts.2.is_some())
        {
            return Err(StartupCaptureFailure::Closed);
        }
        let originals = self.parts.take();
        match originals {
            Some((normal_root_capture, publisher_descriptor, None)) => {
                self.completed = Some(CapturedControllerStartupV1 {
                    publisher_descriptor,
                    launch_image,
                    normal_root_capture,
                    nix_capture: None,
                    git_source_listener: self.git.take(),
                });
                Ok(())
            }
            parts => {
                self.parts = parts;
                // The shared original image never left image_destination.
                Err(StartupCaptureFailure::Closed)
            }
        }
    }
}

impl Drop for ControllerStartupCaptureAttemptV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

struct AbortStartupCaptureUnwind;

impl Drop for AbortStartupCaptureUnwind {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

// This continuation is local (!Sync through FIRST6). Only successful existing
// Arc owners are shared with runtime. Publisher/lower/Arc-allocation custody
// exclusions are deliberate; no whole-role/drain guarantee is implied.
pub(crate) struct ControllerStartupContinuationV1 {
    capture: ControllerStartupCaptureAttemptV1,
    returned: Option<CapturedControllerStartupV1>,
    root: Option<aos_sandbox::normal_root::ProductionControllerSelectedProfileAdmissionV1>,
    profile: Option<Arc<ProductionControllerNormalRootProfileV1>>,
    nix: Option<aos_sandbox::normal_root::ProductionControllerNixStartupCaptureV1>,
    selector_attempt: Option<aos_sandbox::production_operation_compiler::ControllerNixSelectorAdmissionV2>,
    selector: Option<Arc<aos_sandbox::production_operation_compiler::ControllerNixStartRecipeSelectorV2>>,
    image: Option<Pid1LaunchImageV1>,
    publisher: Option<OwnedFd>,
    git: Option<OwnedFd>,
    issue: bool,
    root_completed: bool,
    first_failure: Option<ControllerContinuationFailure>,
    armed: bool,
}

enum ControllerContinuationFailure {
    Capture,
    Root,
    Selector,
    Binding(ControllerBindingFailure),
    Delivery(aos_sandbox::normal_root::SourceSuccessorCredentialErrorV2),
    Runtime(crate::controller_service::ControllerRuntimeError),
    Closed,
}

// Short views resolve markers against the same resident nested owners. No
// borrow is stored in the continuation and no actual cause is copied.
enum ControllerContinuationFailureRef<'attempt> {
    Capture(ControllerStartupFailureRefV1<'attempt>),
    Root(&'attempt aos_sandbox::normal_root::ControllerProfileAdmissionFailureV1),
    Selector(aos_sandbox::production_operation_compiler::ControllerNixSelectorFailureRefV2<'attempt>),
    Binding(&'attempt ControllerBindingFailure),
    Delivery(&'attempt aos_sandbox::normal_root::SourceSuccessorCredentialErrorV2),
    Runtime(&'attempt crate::controller_service::ControllerRuntimeError),
    Closed,
}

impl std::fmt::Debug for ControllerContinuationFailureRef<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Capture(_) => "original capture refused",
            Self::Root(_) => "original Root profile refused",
            Self::Selector(_) => "original Nix selector refused",
            Self::Binding(_) => "original launch binding refused",
            Self::Delivery(_) => "issue-only delivery refused",
            Self::Runtime(_) => "resident runtime continuation refused",
            Self::Closed => "original continuation closed",
        })
    }
}

impl ControllerStartupContinuationV1 {
    pub(crate) fn new(publisher: bool, nix: bool, issue: bool) -> Self {
        Self {
            capture: ControllerStartupCaptureAttemptV1::new(publisher, nix, false),
            returned: None,
            root: None,
            profile: None,
            nix: None,
            selector_attempt: None,
            selector: None,
            image: None,
            publisher: None,
            git: None,
            issue,
            root_completed: false,
            first_failure: None,
            armed: true,
        }
    }

    pub(crate) fn capture_once(&mut self) -> bool {
        if self.first_failure.is_some() || self.returned.is_some() || self.root.is_some() {
            self.first_failure.get_or_insert(ControllerContinuationFailure::Closed);
            return false;
        }
        if self.capture.capture_once().is_err() {
            self.first_failure = Some(ControllerContinuationFailure::Capture);
            return false;
        }
        let Some(returned) = self.capture.take_completed_profile_startup() else {
            self.first_failure = Some(ControllerContinuationFailure::Closed);
            return false;
        };
        self.returned = Some(returned);
        true
    }

    pub(crate) fn admit_root_once(&mut self, uid: u32, gid: u32) -> bool {
        if self.first_failure.is_some()
            || self.root_completed
            || self.root.is_some()
            || self.profile.is_some()
            || self.nix.is_some()
            || self.image.is_some()
            || self.publisher.is_some()
            || self.git.is_some()
            || self.returned.as_ref().is_none_or(|startup| startup.nix_capture.is_some())
        {
            self.first_failure.get_or_insert(ControllerContinuationFailure::Closed);
            return false;
        }
        let Some(returned) = self.returned.take() else {
            self.first_failure = Some(ControllerContinuationFailure::Closed);
            return false;
        };
        let CapturedControllerStartupV1 {
            publisher_descriptor,
            launch_image,
            normal_root_capture,
            nix_capture: _,
            git_source_listener,
        } = returned;
        self.publisher = publisher_descriptor;
        self.image = launch_image;
        self.git = git_source_listener;
        self.root = Some(normal_root_capture.begin_retained_selected_admission());

        let Some(root) = self.root.as_mut() else {
            self.first_failure = Some(ControllerContinuationFailure::Closed);
            return false;
        };
        let selected = match root.admit_selected_once(uid, gid) {
            Ok(profile) => profile.is_some(),
            Err(_) => {
                self.first_failure = Some(ControllerContinuationFailure::Root);
                return false;
            }
        };
        if self.issue && !selected {
            // Do not settle issue-only Absent or inherit ordinary None success.
            self.first_failure = Some(ControllerContinuationFailure::Closed);
            return false;
        }
        let (profile, nix) = match root.take_admitted_roles() {
            Ok(roles) => roles,
            Err(_) => {
                self.first_failure = Some(ControllerContinuationFailure::Root);
                return false;
            }
        };
        self.nix = nix;
        // Existing successful Arc sharing is a FUNDING exclusion, not a
        // recoverable allocation boundary or universal unwind guarantee.
        self.profile = profile.map(Arc::new);
        self.root_completed = true;
        if !self.issue
            && self.profile.is_none()
            && self.nix.is_none()
            && self.image.is_none()
            && self.publisher.is_none()
            && self.git.is_none()
        {
            // FIRST6 settled only its real early, empty nonpositive absence.
            self.armed = false;
        }
        true
    }

    pub(crate) fn require_source_delivery_absent(&mut self) -> bool {
        if self.first_failure.is_some() || !self.root_completed {
            self.first_failure.get_or_insert(ControllerContinuationFailure::Closed);
            return false;
        }
        match aos_sandbox::normal_root::require_source_successor_delivery_absent_v2(
            self.profile.as_deref(),
        ) {
            Ok(()) => true,
            Err(cause) => {
                self.first_failure.get_or_insert(ControllerContinuationFailure::Delivery(cause));
                false
            }
        }
    }

    pub(crate) fn bind_launch_in_place(&mut self) -> bool {
        if self.first_failure.is_some() || !self.root_completed {
            self.first_failure.get_or_insert(ControllerContinuationFailure::Closed);
            return false;
        }
        if let Some(image) = &mut self.image {
            if let Err(cause) = image.bind_controller_profile_in_place(self.profile.clone()) {
                self.first_failure.get_or_insert(ControllerContinuationFailure::Binding(cause));
                return false;
            }
        }
        true
    }

    pub(crate) fn admit_nix_once(
        &mut self,
        uid: u32,
        gid: u32,
        node: aos_sandbox_core::NodeId,
    ) -> bool {
        if self.first_failure.is_some() || !self.root_completed
            || self.selector_attempt.is_some() || self.selector.is_some()
            || self.nix.is_none()
        {
            self.first_failure.get_or_insert(ControllerContinuationFailure::Closed);
            return false;
        }
        let Some(capture) = self.nix.take() else {
            self.first_failure = Some(ControllerContinuationFailure::Closed);
            return false;
        };
        self.selector_attempt = Some(
            aos_sandbox::production_operation_compiler::ControllerNixStartRecipeSelectorV2::begin_retained_original(
                capture,
                uid,
                gid,
                node,
            ),
        );
        let Some(attempt) = self.selector_attempt.as_mut() else {
            self.first_failure = Some(ControllerContinuationFailure::Closed);
            return false;
        };
        if attempt.admit_once().is_err() {
            self.first_failure = Some(ControllerContinuationFailure::Selector);
            return false;
        }
        let Some(selector) = attempt.take_admitted_selector() else {
            self.first_failure = Some(ControllerContinuationFailure::Closed);
            return false;
        };
        self.selector = Some(Arc::new(selector));
        true
    }

    pub(crate) fn profile(&self) -> Option<&ProductionControllerNormalRootProfileV1> {
        self.profile.as_deref()
    }

    pub(crate) fn profile_share(&self) -> Option<Arc<ProductionControllerNormalRootProfileV1>> {
        self.profile.clone()
    }

    pub(crate) fn selector_share(&self) -> Option<Arc<aos_sandbox::production_operation_compiler::ControllerNixStartRecipeSelectorV2>> {
        self.selector.clone()
    }

    pub(crate) fn image_share(&self) -> Option<Pid1LaunchImageV1> {
        self.image.clone()
    }

    // The unchanged consuming publisher lower path remains a functional gap.
    pub(crate) fn take_publisher(&mut self) -> Option<OwnedFd> {
        self.publisher.take()
    }

    pub(crate) fn complete_worker_handoff(&mut self) {
        // Called only after actual successful spawn. Parent Arc shares remain
        // resident through later startup errors; no drain is inferred.
        if self.first_failure.is_some() || !self.root_completed || self.nix.is_some() {
            self.terminate_failed();
        }
        self.armed = false;
    }

    pub(crate) fn complete_issue_finish(&mut self) {
        // Called only after Core's SAME-flight Finish, without another Root
        // predicate. This is local lifetime settlement, never physical drain.
        self.armed = false;
    }

    pub(crate) fn must_retain_failure(&self) -> bool {
        self.armed || self.profile.is_some() || self.selector.is_some() || self.image.is_some()
    }

    pub(crate) fn fail_runtime(&mut self, cause: crate::controller_service::ControllerRuntimeError) -> ! {
        self.first_failure.get_or_insert(ControllerContinuationFailure::Runtime(cause));
        self.terminate_failed()
    }

    pub(crate) fn terminate_failed(&mut self) -> ! {
        // Diagnostic unwinding must not release post-handoff parent custody.
        self.armed = true;

        // Nested causes remain owned in the exact capture/admission attempt.
        self.first_failure.get_or_insert(ControllerContinuationFailure::Closed);
        eprintln!("aos-sandboxd: {:?}", self.failure_view());
        std::process::exit(1)
    }

    fn failure_view(&self) -> ControllerContinuationFailureRef<'_> {
        match &self.first_failure {
            Some(ControllerContinuationFailure::Capture) => self.capture.first_failure()
                .map(ControllerContinuationFailureRef::Capture)
                .unwrap_or(ControllerContinuationFailureRef::Closed),
            Some(ControllerContinuationFailure::Root) => self.root.as_ref()
                .and_then(|owner| owner.first_failure())
                .map(ControllerContinuationFailureRef::Root)
                .unwrap_or(ControllerContinuationFailureRef::Closed),
            Some(ControllerContinuationFailure::Selector) => self.selector_attempt.as_ref()
                .and_then(|owner| owner.first_failure())
                .map(ControllerContinuationFailureRef::Selector)
                .unwrap_or(ControllerContinuationFailureRef::Closed),
            Some(ControllerContinuationFailure::Binding(cause)) => {
                ControllerContinuationFailureRef::Binding(cause)
            }
            Some(ControllerContinuationFailure::Delivery(cause)) => {
                ControllerContinuationFailureRef::Delivery(cause)
            }
            Some(ControllerContinuationFailure::Runtime(cause)) => {
                ControllerContinuationFailureRef::Runtime(cause)
            }
            Some(ControllerContinuationFailure::Closed) | None => {
                ControllerContinuationFailureRef::Closed
            }
        }
    }
}

impl Drop for ControllerStartupContinuationV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

fn startup_error(message: impl Into<String>) -> StorageServiceError {
    StorageServiceError::Activation(message.into())
}

#[cfg(test)]
mod retained_destination_tests {
    use super::*;

    #[test]
    fn runtime_failure_view_borrows_the_original_without_diagnostic_detail() {
        let cause = crate::controller_service::ControllerRuntimeError::InvalidCredential;
        let view = ControllerContinuationFailureRef::Runtime(&cause);

        assert!(matches!(view, ControllerContinuationFailureRef::Runtime(retained)
            if std::ptr::eq(retained, &cause)));
        assert_eq!(format!("{view:?}"), "resident runtime continuation refused");
    }

    #[test]
    fn an_empty_destination_is_unique_before_any_original_exists() {
        let mut destination: Arc<Option<File>> = Arc::new(None);

        let slot = Arc::get_mut(&mut destination);

        assert!(matches!(slot, Some(None)));
    }

    #[test]
    fn a_shared_empty_destination_cannot_receive_an_original() {
        let mut destination: Arc<Option<File>> = Arc::new(None);
        let retained = Arc::clone(&destination);

        let slot = Arc::get_mut(&mut destination);

        assert!(slot.is_none());
        assert!(destination.as_ref().is_none());
        assert!(retained.as_ref().is_none());
    }
}

#[cfg(test)]
mod storage_worker_image_route_tests {
    use super::*;

    // These cover only pure guard/error behavior with no startup owner. They
    // do not manufacture genuine image, mode, listener or worker custody.
    #[test]
    fn route_is_armed_before_any_mode_observation() {
        let route = StorageWorkerImageRouteObservation::begin(None);

        assert!(!route.finished);
        assert!(route.startup.is_none());
    }

    #[test]
    fn successful_empty_route_returns_no_worker_authority() {
        let route = StorageWorkerImageRouteObservation::begin(None);

        let startup = route.finish();

        assert!(startup.is_none());
    }

    #[test]
    fn failed_route_keeps_the_existing_activation_projection() {
        let route = StorageWorkerImageRouteObservation::begin(None);
        let cause = startup_error("the original activation cause");
        let expected = cause.to_string();

        let failure = route.fail(cause);

        assert_eq!(failure.to_string(), expected);
        assert!(std::error::Error::source(&failure).is_some());
    }

    #[test]
    fn failed_route_keeps_an_existing_nonactivation_typed_cause() {
        let route = StorageWorkerImageRouteObservation::begin(None);
        let cause = StorageServiceError::Clock;
        let expected = cause.to_string();

        let failure = route.fail(cause);

        assert_eq!(failure.to_string(), expected);
        assert!(std::error::Error::source(&failure).is_some());
    }
}
