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

use aos_sandbox_controller_domain::normal_root::ControllerSharedStartupProfileV1;
use aos_sandbox_broker::controller_receiving::ControllerLaunchImageDeliveryOriginalV1;

use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_sandbox_storage::activation::{
    StorageOriginalWorkerStartupErrorV3, StorageOriginalWorkerStartupV3, take_systemd_startup,
};
use aos_sandbox_storage::service::StorageServiceError;

use crate::{ProductionBrokerSessionActivationV1, ProtectedBrokerSessionFixedEndpointV1};

mod floor_profile_currentness;
pub(crate) use floor_profile_currentness::LaunchProfileCurrentnessOriginalV1;

/// Retains an original launch observation, not a currentness or TPM proof.
#[derive(Clone)]
pub struct Pid1LaunchImageV1 {
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
    Admitted(ControllerSharedStartupProfileV1),
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

    /// Binds only an opaque successful admission from the actual upper coordinator.
    ///
    /// Genuine admitted absence is carried by the same private typed result;
    /// callers cannot substitute an arbitrary profile or `None` assertion.
    ///
    /// # Errors
    /// Preserves the actual profile recheck or rejects a foreign/repeated role.
    #[doc(hidden)]
    pub fn bind_controller_profile_original_v1(
        &mut self,
        profile: ControllerSharedStartupProfileV1,
    ) -> Result<(), ControllerLaunchImageBindingErrorV1> {
        if self.endpoint != ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient
            || self.process != std::process::id()
            || !matches!(&self.profile_delivery, ControllerProfileDeliveryV1::Pending)
        {
            return Err(ControllerLaunchImageBindingErrorV1::Role(
                crate::BrokerSessionSecurityError::Currentness,
            ));
        }
        if let Some(admitted) = profile.profile() {
            admitted.recheck().map_err(ControllerLaunchImageBindingErrorV1::Profile)?;
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
            ControllerProfileDeliveryV1::Admitted(binding) => {
                if let Some(profile) = binding.profile() {
                    profile.recheck().map_err(|_| crate::BrokerSessionSecurityError::Currentness)?;
                    Ok(Some(profile.profile_path()))
                } else {
                    Ok(None)
                }
            }
            ControllerProfileDeliveryV1::Storage => Ok(None),
            ControllerProfileDeliveryV1::Pending => Err(crate::BrokerSessionSecurityError::Currentness),
        }
    }

    /// Joins this genuine Storage launch to its actual receiving aggregate.
    pub(crate) fn associate_original_storage_receiving_layout_v1(
        &self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<aos_sandbox_linux::cgroup::StorageCgroupLayoutV1, crate::BrokerSessionSecurityError> {
        self.require_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageBroker)?;
        receiving.associate_original_launch_image_layout_v1(self.file()?)
            .map_err(|_| crate::BrokerSessionSecurityError::Currentness)
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

/// Preserves the actual original image-role or admitted-profile recheck cause.
#[derive(Debug, thiserror::Error)]
#[doc(hidden)]
pub enum ControllerLaunchImageBindingErrorV1 {
    /// The original image role, process or once-only stage differs.
    #[error(transparent)]
    Role(crate::BrokerSessionSecurityError),
    /// The same actual admitted profile failed its existing recheck.
    #[error(transparent)]
    Profile(aos_sandbox_controller_domain::normal_root::NormalRootStartupErrorV1),
}

/// Preserves image-mode failure separately from a closed destination.
#[derive(Debug, thiserror::Error)]
#[doc(hidden)]
pub enum ControllerLaunchImageCaptureFailureV1 {
    /// The actual mode/presence check returned this original failure.
    #[error(transparent)]
    Launch(crate::BrokerSessionSecurityError),
    /// The typed original or destination cannot move again.
    #[error("original Controller startup closed")]
    Closed,
}

/// Receives only the genuine fixed first table's original image or absence.
///
/// Its empty shared destination is allocated at the same pre-capture frontier.
/// This has no FD, pathname, decoded profile or caller-absence constructor.
#[doc(hidden)]
pub struct ControllerLaunchImageCaptureV1 {
    image_destination: Arc<Option<File>>,
    entered: bool,
}

impl ControllerLaunchImageCaptureV1 {
    /// Allocates the empty destination before any startup-table observation.
    #[must_use]
    pub fn new() -> Self {
        Self { image_destination: Arc::new(None), entered: false }
    }

    /// Moves only the same table's unconsumed original into the image owner.
    ///
    /// # Errors
    /// Preserves the existing required-image presence refusal and rejects a
    /// shared, repeated or contradictory original destination.
    pub fn capture_delivery_once(
        &mut self,
        delivery: &mut ControllerLaunchImageDeliveryOriginalV1,
    ) -> Result<Option<Pid1LaunchImageV1>, ControllerLaunchImageCaptureFailureV1> {
        if self.entered || !delivery.is_unconsumed() {
            return Err(ControllerLaunchImageCaptureFailureV1::Closed);
        }
        self.entered = true;
        let endpoint = ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient;
        let image_present = delivery.is_present();
        let profile_delivery = launch_profile_delivery(endpoint, image_present)
            .map_err(ControllerLaunchImageCaptureFailureV1::Launch)?;
        let target = Arc::get_mut(&mut self.image_destination)
            .ok_or(ControllerLaunchImageCaptureFailureV1::Closed)?;
        if target.is_some() || !delivery.is_unconsumed() {
            return Err(ControllerLaunchImageCaptureFailureV1::Closed);
        }
        if let Some(original) = delivery.take_file_once()
            .map_err(|_| ControllerLaunchImageCaptureFailureV1::Closed)?
        {
            *target = Some(original);
        }
        Ok(if image_present {
            Some(Pid1LaunchImageV1 {
                endpoint,
                process: std::process::id(),
                file: LaunchImageFile::Retained(Arc::clone(&self.image_destination)),
                profile_delivery,
            })
        } else {
            None
        })
    }
}

/// Retains all existing Storage listeners and its private launch observation.
///
/// Construction captures the actual process-start table; it accepts no caller
/// descriptor or image claim. Optional floor image and worker custody remain
/// separate; worker-only delivery creates no method-46 launch owner.
pub struct ProductionStorageStartupV1 {
    // This field fences selected unwind before activation or sidecars release.
    selected: Option<StorageResourceRecipientStartupCustodyV1>,
    activation: ProductionBrokerSessionActivationV1,
    export: RecordSubjectListener,
    live_export: Option<RecordSubjectListener>,
    zfs_hold: Option<RecordSubjectListener>,
    operator: Option<RecordSubjectListener>,
    existing_output: Option<RecordSubjectListener>,
    host_pins: Option<aos_sandbox_storage::activation::StorageHostPinDescriptorsV1>,
}

/// Storage activation and its separately retained non-broker listeners.
pub type ProductionStorageStartupPartsV1 = (
    ProductionBrokerSessionActivationV1,
    RecordSubjectListener,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
    Option<RecordSubjectListener>,
    Option<aos_sandbox_storage::activation::StorageHostPinDescriptorsV1>,
);

type StorageResourceRecipientWorkerPartsV1 = (
    aos_sandbox_storage::activation::StorageSystemdListenersV1,
    Option<OwnedFd>,
    Option<aos_sandbox_storage::activation::StorageHostPinDescriptorsV1>,
    Option<StorageOriginalWorkerStartupV3>,
);

#[derive(Clone, Copy)]
enum StorageResourceRecipientStartupStageV1 {
    Capture,
    ModeDemand,
    ModePayment,
    ModeArm,
    Mode,
    ModeOriginalPost,
    Presence,
    Profile,
    Listener,
    Post,
    Closed,
}

/// Retains selected original image and complete admission observations.
///
/// Startup moves this into its same activation at `into_parts`, without a
/// recursive owner or disposing the Legacy image. It grants no floor authority.
pub(crate) struct StorageResourceRecipientStartupCustodyV1 {
    initial_mode: crate::recovery::InitialModeOriginalV1,
    mode_comparison: crate::recovery::ModeRevalidationOriginalV1,
    mode_presence: crate::recovery::ModePresenceOriginalV1,
    mode_demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>,
    mode_payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    mode_arm: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    mode_original_post: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    image_destination: Arc<Option<File>>,
    legacy_image: Option<Pid1LaunchImageV1>,
    mode: Result<crate::recovery::ModePinV1, crate::recovery::FloorErrorV1>,
    presence: Result<(), crate::recovery::FloorErrorV1>,
    profile: Result<ControllerProfileDeliveryV1, crate::BrokerSessionSecurityError>,
    listener: Result<(), crate::ProductionBrokerSessionActivationErrorV1>,
    post: Result<(), crate::recovery::FloorErrorV1>,
}

impl Drop for StorageResourceRecipientStartupCustodyV1 {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

// Every selected returned original/result has a destination before its next
// check. An armed attempt aborts before any of these fields can be released.
struct StorageResourceRecipientStartupAttemptV1 {
    initial_mode: crate::recovery::InitialModeOriginalV1,
    mode_comparison: crate::recovery::ModeRevalidationOriginalV1,
    mode_presence: crate::recovery::ModePresenceOriginalV1,
    mode_demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>,
    mode_payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    mode_arm: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    mode_original_post: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    recipient: Option<aos_sandbox_storage::activation::StorageResourceRecipientCaptureV1>,
    captured: Option<Result<StorageResourceRecipientWorkerPartsV1, StorageOriginalWorkerStartupErrorV3>>,
    image_destination: Option<Arc<Option<File>>>,
    image: Option<Pid1LaunchImageV1>,
    control: Option<RecordSubjectListener>,
    export: Option<RecordSubjectListener>,
    live_export: Option<RecordSubjectListener>,
    zfs_hold: Option<RecordSubjectListener>,
    operator: Option<RecordSubjectListener>,
    existing_output: Option<RecordSubjectListener>,
    host_pins: Option<aos_sandbox_storage::activation::StorageHostPinDescriptorsV1>,
    worker: Option<StorageOriginalWorkerStartupV3>,
    failed_worker: Option<StorageOriginalWorkerStartupErrorV3>,
    activation: Option<ProductionBrokerSessionActivationV1>,
    mode: Option<Result<crate::recovery::ModePinV1, crate::recovery::FloorErrorV1>>,
    presence: Option<Result<(), crate::recovery::FloorErrorV1>>,
    profile: Option<Result<ControllerProfileDeliveryV1, crate::BrokerSessionSecurityError>>,
    listener: Option<Result<(), crate::ProductionBrokerSessionActivationErrorV1>>,
    post: Option<Result<(), crate::recovery::FloorErrorV1>>,
    first: Option<StorageResourceRecipientStartupStageV1>,
    attempted: bool,
    admitted: bool,
    armed: bool,
}

impl StorageResourceRecipientStartupAttemptV1 {
    fn new(recipient: aos_sandbox_storage::activation::StorageResourceRecipientCaptureV1) -> Self {
        Self {
            initial_mode: crate::recovery::InitialModeOriginalV1::new(),
            mode_comparison: crate::recovery::ModeRevalidationOriginalV1::new(),
            mode_presence: crate::recovery::ModePresenceOriginalV1::new(),
            mode_demand: None,
            mode_payment: None,
            mode_arm: None,
            mode_original_post: None,
            recipient: Some(recipient),
            captured: None,
            image_destination: Some(Arc::new(None)),
            image: None,
            control: None,
            export: None,
            live_export: None,
            zfs_hold: None,
            operator: None,
            existing_output: None,
            host_pins: None,
            worker: None,
            failed_worker: None,
            activation: Some(ProductionBrokerSessionActivationV1::prearm_storage_resource_recipient()),
            mode: None,
            presence: None,
            profile: None,
            listener: None,
            post: None,
            first: None,
            attempted: false,
            admitted: false,
            armed: true,
        }
    }

    fn capture_once(&mut self) -> bool {
        if self.attempted || self.first.is_some() {
            self.first.get_or_insert(StorageResourceRecipientStartupStageV1::Closed);
            return false;
        }
        self.attempted = true;
        let Some(recipient) = self.recipient.as_mut() else {
            self.first = Some(StorageResourceRecipientStartupStageV1::Closed);
            return false;
        };
        if recipient.capture_once() {
            recipient.admit_worker_once();
        }
        let Some(recipient) = self.recipient.take() else {
            self.first = Some(StorageResourceRecipientStartupStageV1::Closed);
            return false;
        };
        self.captured = Some(recipient.into_original_worker_parts());
        if !matches!(self.captured.as_ref(), Some(Ok(_))) {
            self.first = Some(StorageResourceRecipientStartupStageV1::Capture);
            return false;
        }

        let Some(destination) = self.image_destination.as_mut().and_then(Arc::get_mut) else {
            self.first = Some(StorageResourceRecipientStartupStageV1::Closed);
            return false;
        };
        if destination.is_some() {
            self.first = Some(StorageResourceRecipientStartupStageV1::Closed);
            return false;
        }
        let Some(Ok(((control, export, live_export, zfs_hold, operator, existing_output), image, host_pins, worker))) =
            self.captured.take()
        else {
            std::process::abort();
        };
        self.control = Some(control);
        self.export = Some(export);
        self.live_export = live_export;
        self.zfs_hold = zfs_hold;
        self.operator = operator;
        self.existing_output = existing_output;
        self.host_pins = host_pins;
        self.worker = worker;
        *destination = image.map(File::from);
        if destination.is_none() || self.worker.is_none() {
            self.first = Some(StorageResourceRecipientStartupStageV1::Closed);
            return false;
        }

        let Some(destination) = self.image_destination.as_ref() else {
            std::process::abort();
        };
        self.image = Some(Pid1LaunchImageV1 {
            endpoint: ProtectedBrokerSessionFixedEndpointV1::StorageBroker,
            process: std::process::id(),
            file: LaunchImageFile::Retained(Arc::clone(destination)),
            profile_delivery: ControllerProfileDeliveryV1::Pending,
        });
        true
    }

    fn admit_once(&mut self) -> bool {
        if self.first.is_some() || !self.attempted || self.admitted
            || self.image.is_none() || self.worker.is_none()
        {
            self.first.get_or_insert(StorageResourceRecipientStartupStageV1::Closed);
            return false;
        }
        self.admitted = true;
        self.mode_demand = Some(selected_initial_mode_demand_v1());
        let Some(Ok(demand)) = self.mode_demand.as_ref().copied() else {
            self.first = Some(StorageResourceRecipientStartupStageV1::ModeDemand);
            return false;
        };
        let Some(worker) = self.worker.as_mut() else {
            self.first = Some(StorageResourceRecipientStartupStageV1::Closed);
            return false;
        };
        let mut receiving = match worker.borrow_storage_prepare_receiving_v1() {
            Ok(receiving) => receiving,
            Err(cause) => {
                self.mode_payment = Some(Err(cause));
                self.first = Some(StorageResourceRecipientStartupStageV1::ModePayment);
                return false;
            }
        };
        self.mode_payment = Some(receiving.reserve_initial_mode_prefix_once_v1(demand));
        if !matches!(self.mode_payment, Some(Ok(()))) {
            self.first = Some(StorageResourceRecipientStartupStageV1::ModePayment);
            return false;
        }
        self.mode_arm = Some(receiving.arm_initial_mode_observation_post_v1());
        if !matches!(self.mode_arm, Some(Ok(()))) {
            self.first = Some(StorageResourceRecipientStartupStageV1::ModeArm);
            return false;
        }
        self.mode = Some(crate::recovery::ModePinV1::open_storage_worker_image_mode_retaining(
            &mut self.initial_mode,
        ));
        if let Some(Ok(mode)) = self.mode.as_ref() {
            let required = mode.is_required();
            Self::admit_image_and_listener(
                &self.mode, required, &mut self.image, &mut self.presence,
                &mut self.mode_presence,
                &mut self.profile, &mut self.activation, &mut self.control,
                &mut self.listener, &mut self.first,
            );
        } else {
            self.first = Some(StorageResourceRecipientStartupStageV1::Mode);
        }

        // The real returned pin receives its independent native post after
        // image/listener checks, retaining their original error chronology.
        if let Some(Ok(mode)) = self.mode.as_ref() {
            self.post = Some(mode.revalidate_retaining(&mut self.mode_comparison));
            if !matches!(self.post, Some(Ok(()))) {
                self.first.get_or_insert(StorageResourceRecipientStartupStageV1::Post);
            }
        }
        // Already paid before Mode IO; ordinary receiving poison must not
        // suppress this actual same-original observation on any failure.
        self.mode_original_post = Some(receiving.finish_initial_observation_post_v1());
        if !matches!(self.mode_original_post, Some(Ok(()))) {
            self.first.get_or_insert(StorageResourceRecipientStartupStageV1::ModeOriginalPost);
        }
        self.first.is_none()
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_image_and_listener(
        mode_result: &Option<Result<crate::recovery::ModePinV1, crate::recovery::FloorErrorV1>>,
        required: bool,
        image_slot: &mut Option<Pid1LaunchImageV1>,
        presence: &mut Option<Result<(), crate::recovery::FloorErrorV1>>,
        presence_original: &mut crate::recovery::ModePresenceOriginalV1,
        profile: &mut Option<Result<ControllerProfileDeliveryV1, crate::BrokerSessionSecurityError>>,
        activation_slot: &mut Option<ProductionBrokerSessionActivationV1>,
        control: &mut Option<RecordSubjectListener>,
        listener: &mut Option<Result<(), crate::ProductionBrokerSessionActivationErrorV1>>,
        first: &mut Option<StorageResourceRecipientStartupStageV1>,
    ) {
        let Some(Ok(mode)) = mode_result.as_ref() else {
            first.get_or_insert(StorageResourceRecipientStartupStageV1::Closed);
            return;
        };
        // Legacy keeps its worker original while the floor receives absence.
        let supplied = required && image_slot.is_some();
        *presence = Some(mode.require_storage_worker_launch_image_presence_retaining(
            supplied,
            presence_original,
        ));
        if !matches!(presence.as_ref(), Some(Ok(()))) {
            *first = Some(StorageResourceRecipientStartupStageV1::Presence);
            return;
        }
        *profile = Some(profile_delivery_for_endpoint(
            ProtectedBrokerSessionFixedEndpointV1::StorageBroker,
        ));
        if !matches!(profile.as_ref(), Some(Ok(ControllerProfileDeliveryV1::Storage))) {
            *first = Some(StorageResourceRecipientStartupStageV1::Profile);
            return;
        }
        let Some(image) = image_slot.as_mut() else {
            *first = Some(StorageResourceRecipientStartupStageV1::Closed);
            return;
        };
        image.profile_delivery = ControllerProfileDeliveryV1::Storage;

        let Some(activation) = activation_slot.as_mut() else {
            *first = Some(StorageResourceRecipientStartupStageV1::Closed);
            return;
        };
        *listener = Some(activation.admit_retained_storage_listener(control));
        if !matches!(listener.as_ref(), Some(Ok(()))) {
            *first = Some(StorageResourceRecipientStartupStageV1::Listener);
            return;
        }
        if required {
            activation.retain_launch_image(image_slot.take());
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            StorageResourceRecipientStartupStageV1::Capture => self.captured.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as &dyn std::error::Error),
            StorageResourceRecipientStartupStageV1::ModeDemand => self.mode_demand.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error),
            StorageResourceRecipientStartupStageV1::ModePayment
            | StorageResourceRecipientStartupStageV1::ModeArm
            | StorageResourceRecipientStartupStageV1::ModeOriginalPost => self.worker.as_ref()
                .and_then(StorageOriginalWorkerStartupV3::storage_receiving_failure_v1)
                .or_else(|| self.failed_worker.as_ref().and_then(std::error::Error::source))
                .or(Some(&aos_sandbox_controller_domain::StorageReceivingClosedV1)),
            StorageResourceRecipientStartupStageV1::Mode => self.initial_mode.failure()
                .or_else(|| self.mode.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as &dyn std::error::Error)),
            StorageResourceRecipientStartupStageV1::Presence => self.mode_presence.failure()
                .or_else(|| self.presence.as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as &dyn std::error::Error)),
            StorageResourceRecipientStartupStageV1::Profile => self.profile.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as &dyn std::error::Error),
            StorageResourceRecipientStartupStageV1::Listener => self.listener.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as &dyn std::error::Error),
            StorageResourceRecipientStartupStageV1::Post => self.mode_comparison.failure()
                .or_else(|| self.post.as_ref().and_then(|result| result.as_ref().err())
                    .map(|error| error as &dyn std::error::Error)),
            StorageResourceRecipientStartupStageV1::Closed => {
                Some(&crate::BrokerSessionSecurityError::Currentness)
            }
        }
    }

    fn into_startup(mut self) -> Result<
        (ProductionStorageStartupV1, Option<StorageOriginalWorkerStartupV3>),
        ProductionStorageResourceRecipientStartupErrorV1,
    > {
        let complete = self.first.is_none() && self.admitted
            && matches!(self.mode_payment, Some(Ok(())))
            && matches!(self.mode_arm, Some(Ok(())))
            && matches!(self.mode_original_post, Some(Ok(())))
            && self.activation.is_some() && self.export.is_some()
            && self.control.is_none() && self.worker.is_some()
            && self.image_destination.as_ref().is_some_and(|slot| slot.as_ref().is_some())
            && matches!(self.mode.as_ref(), Some(Ok(_)))
            && matches!(self.presence.as_ref(), Some(Ok(())))
            && matches!(self.profile.as_ref(), Some(Ok(ControllerProfileDeliveryV1::Storage)))
            && matches!(self.listener.as_ref(), Some(Ok(())))
            && matches!(self.post.as_ref(), Some(Ok(())));
        if !complete {
            self.first.get_or_insert(StorageResourceRecipientStartupStageV1::Closed);
            if self.worker.is_some() {
                self.failed_worker = Some(StorageOriginalWorkerStartupErrorV3::retain_service_failure(
                    startup_error("Storage resource-recipient startup is closed"),
                    self.worker.take(),
                ));
            }
            return Err(ProductionStorageResourceRecipientStartupErrorV1 { original: self });
        }

        let (Some(activation), Some(export), Some(image_destination), Some(worker),
            Some(mode), Some(presence), Some(profile), Some(listener), Some(post)) = (
            self.activation.take(), self.export.take(), self.image_destination.take(),
            self.worker.take(), self.mode.take(), self.presence.take(), self.profile.take(),
            self.listener.take(), self.post.take(),
        ) else {
            std::process::abort();
        };
        let startup = ProductionStorageStartupV1 {
            selected: Some(StorageResourceRecipientStartupCustodyV1 {
                initial_mode: std::mem::replace(&mut self.initial_mode, crate::recovery::InitialModeOriginalV1::new()),
                mode_comparison: std::mem::replace(&mut self.mode_comparison, crate::recovery::ModeRevalidationOriginalV1::new()),
                mode_presence: std::mem::replace(
                    &mut self.mode_presence,
                    crate::recovery::ModePresenceOriginalV1::new(),
                ),
                mode_demand: self.mode_demand.take(),
                mode_payment: self.mode_payment.take(),
                mode_arm: self.mode_arm.take(),
                mode_original_post: self.mode_original_post.take(),
                image_destination,
                legacy_image: self.image.take(),
                mode,
                presence,
                profile,
                listener,
                post,
            }),
            activation,
            export,
            live_export: self.live_export.take(),
            zfs_hold: self.zfs_hold.take(),
            operator: self.operator.take(),
            existing_output: self.existing_output.take(),
            host_pins: self.host_pins.take(),
        };
        self.armed = false;
        Ok((startup, Some(worker)))
    }
}

fn selected_initial_mode_demand_v1()
    -> Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>
{
    use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
    let invalid = || AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes };
    let initial = crate::recovery::mode_initial_receiving_demand_v1().ok_or_else(invalid)?;
    let comparison = crate::recovery::mode_revalidation_receiving_demand_v1().ok_or_else(invalid)?;
    let presence = crate::recovery::mode_presence_receiving_demand_v1().ok_or_else(invalid)?;
    let owners = std::mem::size_of::<StorageResourceRecipientStartupAttemptV1>()
        .checked_add(std::mem::size_of::<StorageResourceRecipientStartupCustodyV1>())
        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
    // Result and owner representations are byte obligations. Namespace entry
    // cardinality belongs to the actual fixed Mode readers' own suppliers.
    initial.checked_add(presence)?.checked_add(comparison)?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, owners))
}

impl Drop for StorageResourceRecipientStartupAttemptV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

/// Owns the first selected startup cause and every returned upper original.
///
/// The failed attempt cannot be retried or converted into admitted startup.
/// Its destruction aborts before originals release; formatting only borrows
/// the actual resident cause and never authorizes drain or recovery.
pub struct ProductionStorageResourceRecipientStartupErrorV1 {
    original: StorageResourceRecipientStartupAttemptV1,
}

impl std::fmt::Debug for ProductionStorageResourceRecipientStartupErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ProductionStorageResourceRecipientStartupErrorV1")
            .field("cause", &self.original.failure()).finish_non_exhaustive()
    }
}

impl std::fmt::Display for ProductionStorageResourceRecipientStartupErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.original.failure() {
            Some(error) => std::fmt::Display::fmt(error, formatter),
            None => formatter.write_str("selected Storage startup is closed"),
        }
    }
}

impl std::error::Error for ProductionStorageResourceRecipientStartupErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }
}

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
        let (listeners, image, host_pins) = take_systemd_startup()?.into_parts();
        Self::admit_captured_parts(listeners, image, host_pins)
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
        let (listeners, image, host_pins, startup) = captured.into_original_worker_parts()?;
        Self::admit_original_worker_route(listeners, image, host_pins, startup)
    }

    /// Admits only the selected actual resource-recipient table before startup.
    ///
    /// This retains the component outside Core's startup Box and uses the same
    /// fixed mode and listener engines. The selected upper owner retains the
    /// same returned image and listeners; it issues no native or Project permission.
    ///
    /// # Errors
    ///
    /// Owns the full failed recipient, worker and upper native observations.
    /// Destruction of a failed selected attempt aborts before originals release.
    pub fn capture_resource_recipient_startup(
        captured: aos_sandbox_storage::activation::StorageResourceRecipientCaptureV1,
    ) -> Result<
        (Self, Option<aos_sandbox_storage::activation::StorageOriginalWorkerStartupV3>),
        ProductionStorageResourceRecipientStartupErrorV1,
    > {
        let mut attempt = StorageResourceRecipientStartupAttemptV1::new(captured);
        if attempt.capture_once() {
            attempt.admit_once();
        }
        attempt.into_startup()
    }

    fn admit_original_worker_route(
        listeners: aos_sandbox_storage::activation::StorageSystemdListenersV1,
        image: Option<OwnedFd>,
        host_pins: Option<aos_sandbox_storage::activation::StorageHostPinDescriptorsV1>,
        startup: Option<aos_sandbox_storage::activation::StorageOriginalWorkerStartupV3>,
    ) -> Result<
        (Self, Option<aos_sandbox_storage::activation::StorageOriginalWorkerStartupV3>),
        aos_sandbox_storage::activation::StorageOriginalWorkerStartupErrorV3,
    > {
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
        let startup_owner = match Self::admit_captured_parts(listeners, floor_image, host_pins) {
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
        host_pins: Option<aos_sandbox_storage::activation::StorageHostPinDescriptorsV1>,
    ) -> Result<Self, StorageServiceError> {
        let (control, export, live_export, zfs_hold, operator, existing_output) = listeners;
        let endpoint = ProtectedBrokerSessionFixedEndpointV1::StorageBroker;
        let image = admit_launch_observation(endpoint, image)
            .map_err(|_| startup_error("Storage launch image differs from image floor mode"))?;
        let mut activation = ProductionBrokerSessionActivationV1::adopt_storage_listener(control)
            .map_err(|error| startup_error(error.to_string()))?;
        activation.retain_launch_image(image);
        Ok(Self {
            selected: None,
            activation,
            export,
            live_export,
            zfs_hold,
            operator,
            existing_output,
            host_pins,
        })
    }

    /// Transfers the fixed activation and every existing sidecar listener.
    #[must_use]
    pub fn into_parts(mut self) -> ProductionStorageStartupPartsV1 {
        if let Some(custody) = self.selected.take() {
            self.activation.retain_storage_recipient_startup(custody);
        }
        (
            self.activation,
            self.export,
            self.live_export,
            self.zfs_hold,
            self.operator,
            self.existing_output,
            self.host_pins,
        )
    }
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
    profile_delivery_for_endpoint(endpoint)
}

fn profile_delivery_for_endpoint(
    endpoint: ProtectedBrokerSessionFixedEndpointV1,
) -> Result<ControllerProfileDeliveryV1, crate::BrokerSessionSecurityError> {
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


fn startup_error(message: impl Into<String>) -> StorageServiceError {
    StorageServiceError::Activation(message.into())
}

#[cfg(test)]
mod retained_destination_tests {
    use super::*;

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

mod floor_physical_receiving;
