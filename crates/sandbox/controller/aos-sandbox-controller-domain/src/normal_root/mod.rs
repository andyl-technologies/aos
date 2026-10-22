//! Shared selected-image comparisons for the existing normal Root and Controller.
//!
//! Actual early PID1 launch descriptors, image-owned profile, immutable file
//! measurements, loaded policy and genuine fixed-unit/process custody remain
//! retained. Controller independently captures the same selected profile and
//! later joins genuine PID1 launch properties to the original Root stream.
//! Source's selected signer reuses the same Root comparison inputs and paid
//! status mechanics for its actual strict request peer. These comparisons are
//! NOT Source floor, fresh CurrentCut, FUSE read or method46 authority.
//!
//! The profile resolves DT_NEEDED and the current executable mappings; it does
//! not authenticate arbitrary future dlopen, freeze PID1 administration, prove
//! continuous manager image identity after reexec. The held-owner Source genesis
//! coordinator consumes these comparisons together with the original Root stream;
//! a selected profile alone cannot construct an original-flight proof.

mod client;
pub(crate) use client::RootMaintenanceStorageClientOriginalV3;
pub(crate) use client::root_connection::ControllerRootConnectionOriginalV1;
pub(crate) use client::{DeleteSourceBindingDataV3, DeleteSourceClockBoundDataV3};
pub(crate) use client::{RootDeleteChallengeLoanV1, RootDeleteClientOriginalV1};
pub(crate) use client::{RootDeletePlanningClientOriginalV1, RootDeletePlanningObservationLoanV1};
#[doc(hidden)]
pub use client::{RootFinalityRecoverClientClosedV1, RootFinalityRecoverClientOriginalV1};
#[doc(hidden)]
pub use client::{RootStopCleanupClientOriginalV1, RootStopCleanupClientClosedV1,
    RootStopCleanupSigningLoanV1, RootStopCleanupChildLoanV1,
    RootStopCleanupClientCompletedBorrowV1};
#[doc(hidden)]
#[doc(hidden)]
pub use client::{
    RootHostLaunchClientClosedV1, RootHostLaunchClientOriginalV1, RootHostPublicationTurnKindV2,
    RootStartAssignmentInputsClientOriginalV2, RootStartResourceCompletedOriginalV2,
    RootStartResourceConstructionTurnV2, RootStartResourceCurrentTurnV2,
    RootStartResourceExchangeDataV2, RootStartResourcePrepareAdmissionOriginalV2,
};
pub use client::{
    RootStorageApplyAdmissionOriginalV1, RootStorageApplyClientClosedV1,
    RootStorageApplyClientOriginalV1, RootStorageApplyCompletionOriginalV1,
    RootStorageApplyConstructionTurnV1, RootStorageApplyCurrentTurnV1,
};
mod admitted_profile;
pub use admitted_profile::{
    ControllerAdmittedStartupProfileV1, ControllerFloorServiceAnchorBorrowV1,
    ControllerSharedStartupProfileV1,
};

mod controller_peer;
mod receiving_guard;
pub(crate) use receiving_guard::{RootReceivingGuardV1, RootOwnedCurrentStageV1};
mod git_evidence_credential;
mod nix_offline_provision;
pub(crate) use nix_offline_provision::nix_offline_location_has_original_label_v5;
pub(crate) use nix_offline_provision::nix_offline_opening_has_original_label_v5;
pub(crate) mod images;
mod nix_startup;
mod root_policy_listener;
mod root_receiving_profile;
mod root_selected_startup;
mod root_service_currentness;
mod root_startup;
mod root_startup_credential_receiving;
mod root_startup_credential_recipe;
mod root_startup_failure;
pub(crate) use controller_peer::delete_receiving::{
    RootStopCleanupControllerPeerReceivingV1, RootStopCleanupStageReceivingV1, RootApplyControllerPeerReceivingV1, RootApplyStageReceivingV1, RootDeleteCacheStageReceivingV2,
    RootDeleteControllerPeerReceivingV1, RootEnvironmentControllerPeerReceivingV1,
    RootEnvironmentStageReceivingV1, RootFinalityRecoverControllerPeerReceivingV1,
    RootFinalityRecoverStageReceivingV1, RootHostLaunchControllerPeerReceivingV1,
    RootHostLaunchStageReceivingV1, RootMaintenanceStorageControllerPeerReceivingV2,
    RootMaintenanceStorageStageReceivingV2, RootPurposeControllerPeerReceivingV1,
};
pub(crate) use controller_peer::receiving::RootControllerChunkSubjectSampleV1;
pub(crate) use controller_peer::receiving::RootControllerPeerCurrentSampleV1;
pub(crate) use controller_peer::receiving::RootControllerPeerReceivingV1;
pub(crate) use root_policy_listener::RootCurrentOpenIdentityDataV1;
pub(crate) use root_policy_listener::RootPolicyPositiveCompletionPlanV2;

pub use root_policy_listener::{RootPolicyAcceptedFlightV1, RootPolicyListenerReceivingV1};
pub(crate) use root_receiving_profile::RootProfileOriginalReceivingV1;
pub(crate) use root_selected_startup::RootSelectedStartupReceivingV1;
pub(crate) use root_service_currentness::RootServiceCurrentnessV1;
pub use root_startup_credential_receiving::RootStartupCredentialReceivingLoanV1;
pub use root_startup_credential_recipe::RootStartupCredentialMemberV1;
pub(crate) use root_startup_credential_recipe::fixed_root_credential_demand_v1;
pub use root_startup_failure::RootReceivingStartupFailureV1;
pub(crate) mod profile;
mod service;
pub(crate) use service::CreateIntakeObserverGrowthErrorV1;
pub(crate) use service::fixed_property_observer_demand_v1;
pub(crate) mod startup;
mod storage_worker_origin;
#[cfg(test)]
mod tests;

use std::fs::File;
use std::io::Read as _;
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::guest_confinement::require_subject;
use aos_sandbox_linux::inherited_fd::duplicate_initial_activation_table;
use aos_linux_descriptors::pidfd::PidFd;
use aos_sandbox_linux::pidfd::PidFdProcessIdentity;
use aos_sandbox_linux::selinux_policy::VerifiedLiveSelinuxPolicy;
use rustix::fs::{Mode, OFlags, open};
use sha2::{Digest as _, Sha256};

use crate::immutable_image::RetainedImmutableFileV1;
use profile::{CONTEXT, NormalRootProfileV1, UNIT};

pub(crate) use client::CreateStorageRootPeerReceivingOriginalsV1;
pub(crate) use client::OriginalNormalRootPeerV1;
pub use client::source_successor_credential::{
    SourceSuccessorCredentialCustodyV2, SourceSuccessorCredentialErrorV2,
    require_source_successor_delivery_absent_v2,
};
pub use client::{
    ControllerInitialCaptureFailureRefV1, ControllerProfileAdmissionFailureV1,
    ControllerProfileFailureViewV1, ControllerProfileLocalCurrentnessOriginalV1,
    ControllerProfileRequestedCountsV1, ProductionControllerInitialCaptureAttemptV1,
    ProductionControllerNormalRootCaptureV1, ProductionControllerNormalRootProfileV1,
    ProductionControllerNormalRootStartupPartsV1, ProductionControllerSelectedProfileAdmissionV1,
};
pub(crate) use controller_peer::OriginalControllerPolicyPeerV1;
pub(crate) use git_evidence_credential::{
    RootGitEvidenceCredentialCustodyV1, RootGitEvidenceCredentialErrorV1,
};
pub use nix_offline_provision::{
    OfflineNixApprovalDeliveryOriginV6, OfflineNixApprovalDeliveryStartupV6,
    NixOfflineApprovedDataErrorV4, NixOfflineEffectApprovalDataV4, NixOfflineEffectApprovalKindV4,
    NixOfflineJobIdentityDataV5,
    OfflineNixHardwareOriginV5, OfflineNixPrepareOriginV3, OfflineNixPrepareStartupErrorV3,
    OfflineNixPrepareStartupV3, decode_nix_offline_effect_approval_data_v4,
    derive_nix_offline_public_candidates_v3,
    fill_nix_offline_static_preimage_v3, inspect_nix_offline_job_identity_v5,
    nix_offline_job_has_original_label_v5, require_nix_offline_effect_approval_v4,
    require_nix_offline_static_approval_v3, require_nix_offline_static_header_v3,
};
pub use nix_startup::{
    ControllerNixSessionFloorOriginV2, NixOwnerPublicSessionFloorOriginV2,
    NixOwnerSessionFloorStartupV2, ProductionControllerNixStartupCaptureV1,
    ProductionControllerNixStartupV1, ProductionNixOwnerStartupCaptureV1,
    ProductionNixOwnerStartupV1,
};
pub use root_startup::ProductionNormalRootInitialStartupV1;

pub use storage_worker_origin::{
    CapturedStorageLaunchV3, PID1_LAUNCH_IMAGE_FD_NAME, RejectedStorageWorkerOriginV3,
    StorageBoundPhysicalWorkerLoanV1, StorageCaptureStopQuiescenceV4, StorageCaptureWorkerBorrowV2,
    StorageCaptureWorkerDisposalV2, StorageCgroupRootErrorV3,
    StorageFloorPhysicalProgramReceivingV2, StorageGuestRootTemplateReceivingLoanV1,
    StorageInitialPinQuiescenceLoanV1, StorageInitialSessionHelloDisposalV1,
    StorageHostPinDescriptorsV1, StorageLaunchCaptureErrorV3, StorageLaunchListenersV3, StorageLifecycleDisposalErrorV1,
    StorageLifecyclePositiveDisposalV1, StorageLifecycleSessionLoanV1,
    StorageOutputOwedAfterOriginalV1, StoragePhysicalWorkerDisposalV1, StoragePhysicalWorkerLoanV1,
    StoragePrepareReceivingLoanV1, StoragePrepareSessionReplayLoanV1,
    StoragePrepareStartupJournalLoanV1, StorageReceivingClosedV1, StorageResidentCaptureWorkerV2,
    StorageResourceRecipientCaptureV1, StorageResourceRecipientErrorV1,
    StorageRootLaunchExportDisposalV2, StorageRootLaunchExportReceivingLoanV2,
    StorageSessionHelloDisposalErrorV1, StorageStateRecoveryEncodingLoanV1,
    StorageWorkerOriginAdmissionErrorV3, StorageWorkerOriginCauseV3, StorageWorkerOriginV3,
    capture_storage_launch_v3, open_storage_cgroup_root_retaining_v3, open_storage_cgroup_root_v3,
    storage_resource_recipient_selected_v1,
};

pub(super) const PID1_FD_NAME: &str = "aos-normal-root-pid1-image";
pub(super) const PROFILE_FD_NAME: &str = "aos-normal-root-profile";

/// Reports rejection of normal-Root startup comparison or original custody.
#[derive(Debug, thiserror::Error)]
pub enum NormalRootStartupErrorV1 {
    /// Owns a same-purpose native startup writer factory refusal.
    #[error(transparent)]
    StartupJournal(aos_sandbox_policy::native::RootStartupJournalErrorV1),
    /// The complete original launch descriptor table differs.
    #[error("normal Root original startup table differs")]
    Activation,
    /// Image-built profile shape, identity or unit commitment differs.
    #[error("normal Root immutable profile differs")]
    Profile,
    /// Actual retained image, loader mapping or current name differs.
    #[error("normal Root actual immutable image differs")]
    Image,
    /// Genuine PID1 unit, invocation, process or cgroup observation differs.
    #[error("normal Root actual fixed-unit custody differs")]
    Service,
    /// The same Root retains the actual failed service-observation debit.
    #[error("normal Root service-currentness receiving failed: {0}")]
    ServiceReceiving(
        #[source]
        std::sync::Arc<crate::controller_resource_reservation::ResourceReservationErrorV1>,
    ),
    /// The same permanent Root retains its original selected sampler or payer cause.
    #[error(transparent)]
    SelectedCurrentness(#[from] aos_sandbox_broker::receiving::RootSelectedCurrentnessFailureOriginalV1),
    /// Current enforcing subject, capabilities or canonical policy differs.
    #[error("normal Root actual confinement differs")]
    Confinement,
    /// The same original Root owner retains a failed receiving continuation.
    #[error(transparent)]
    Receiving(#[from] Box<RootReceivingStartupFailureV1>),
}

/// Reports fixed Storage startup comparison DATA, not an admitted owner.
///
/// Only the closed self-observer produces this value. A successful comparison
/// is point-in-time; it grants no dispatch, policy freeze, floor, or readiness.
#[derive(Debug, Eq, PartialEq)]
pub struct StorageWorkerParentDataV3 {
    fragment: std::path::PathBuf,
    invocation: [u8; 16],
    executable: String,
    arguments: Vec<String>,
}

impl StorageWorkerParentDataV3 {
    /// Borrows the observed immutable fixed-unit fragment name.
    pub fn fragment(&self) -> &Path {
        &self.fragment
    }

    /// Returns the observed invocation identifier as comparison DATA.
    pub const fn invocation(&self) -> [u8; 16] {
        self.invocation
    }

    /// Borrows the sole reported executable path, not image authority.
    pub fn executable(&self) -> &Path {
        Path::new(&self.executable)
    }

    /// Borrows the exact reported fixed command arguments.
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }
}

/// Observes this cap-empty direct-PID1 Storage process and its fixed unit.
///
/// There is no caller PID, unit, context, or observation argument. The caller
/// independently retains original pidfd, cgroup, image and launch custody;
/// these DATA checks are not an admission or portable currentness proof.
///
/// # Errors
///
/// Rejects unavailable process or unit observations, another process role,
/// nonzero credentials/capabilities, changed custody, or permissive SELinux.
pub fn observe_fixed_storage_worker_parent_v3()
-> Result<StorageWorkerParentDataV3, NormalRootStartupErrorV1> {
    observe_storage_worker_parent(false).map(|(parent, _producer)| parent)
}

pub(crate) fn observe_fixed_storage_resource_parent_with_archive_v1(
    archive: &mut service::FirstGlobalPropertyArchive,
) -> Result<(StorageWorkerParentDataV3, [u8; 16]), NormalRootStartupErrorV1> {
    let (parent, producer) = observe_storage_worker_parent_for(true, Some(archive))?;
    Ok((parent, producer.ok_or(NormalRootStartupErrorV1::Service)?))
}

fn observe_storage_worker_parent(
    resource_delivery: bool,
) -> Result<(StorageWorkerParentDataV3, Option<[u8; 16]>), NormalRootStartupErrorV1> {
    observe_storage_worker_parent_for(resource_delivery, None)
}

fn observe_storage_worker_parent_for(
    resource_delivery: bool,
    archive: Option<&mut service::FirstGlobalPropertyArchive>,
) -> Result<(StorageWorkerParentDataV3, Option<[u8; 16]>), NormalRootStartupErrorV1> {
    let process =
        PidFd::open(NonZeroU32::new(std::process::id()).ok_or(NormalRootStartupErrorV1::Service)?)
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
    let before = process
        .info()
        .map_err(|_| NormalRootStartupErrorV1::Service)?;
    let credentials = before
        .credentials()
        .ok_or(NormalRootStartupErrorV1::Confinement)?;
    if before.pid() != std::process::id()
        || before.thread_group_id() != std::process::id()
        || before.parent_pid() != 1
        || [
            credentials.real_user_id(),
            credentials.effective_user_id(),
            credentials.saved_user_id(),
            credentials.filesystem_user_id(),
            credentials.real_group_id(),
            credentials.effective_group_id(),
            credentials.saved_group_id(),
            credentials.filesystem_group_id(),
        ] != [0; 8]
    {
        return Err(NormalRootStartupErrorV1::Confinement);
    }
    let layout = if resource_delivery {
        aos_sandbox_linux::cgroup::StorageCgroupLayoutV1::ReceivingAggregate
    } else {
        aos_sandbox_linux::cgroup::StorageCgroupLayoutV1::Ordinary
    };
    let cgroup = retain_fixed_cgroup(Path::new(layout.main_relative_v1()))?;
    cgroup
        .verify_exact_membership(&process)
        .map_err(|_| NormalRootStartupErrorV1::Service)?;
    aos_sandbox_linux::selinux_policy::require_enforcing()
        .map_err(|_| NormalRootStartupErrorV1::Confinement)?;
    require_subject("system_u:system_r:aos_sandbox_storage_t")
        .map_err(|_| NormalRootStartupErrorV1::Confinement)?;
    require_status(&read_bounded("/proc/self/status", 64 * 1024)?)?;

    let (observed, producer) = match (resource_delivery, archive) {
        (true, Some(archive)) => {
            let (parent, producer) = service::observe_storage_resource_with_archive(archive)?;
            (parent, Some(producer))
        }
        (false, Some(archive)) => (service::observe_storage_with_archive(archive)?, None),
        (true, None) => {
            let (parent, producer) = service::observe_storage_resource()?;
            (parent, Some(producer))
        }
        (false, None) => (service::observe_storage()?, None),
    };

    cgroup
        .verify_exact_membership(&process)
        .map_err(|_| NormalRootStartupErrorV1::Service)?;
    if process
        .info()
        .map_err(|_| NormalRootStartupErrorV1::Service)?
        != before
        || !process
            .is_alive()
            .map_err(|_| NormalRootStartupErrorV1::Service)?
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    Ok((observed, producer))
}

/// Captures only the actual initial normal-Root process descriptor table.
///
/// Names/counts select slots, not authority. Capture must be the daemon's first
/// single-threaded operation, before credentials, journals or listeners open.
pub struct ProductionNormalRootStartupCaptureV1 {
    descriptors: Option<aos_sandbox_broker::receiving::RootLegacyStartupCaptureV1>,
    root: Option<crate::controller_resource_reservation::RootReceivingOriginalV1>,
}

impl ProductionNormalRootStartupCaptureV1 {
    /// Copies the closed launch table once without accepting caller descriptors.
    ///
    /// # Errors
    /// Rejects extra/missing/duplicate roles, foreign activation PID or kernel
    /// failure. A failed or repeated capture is not recoverable in-process.
    pub fn capture() -> Result<Self, NormalRootStartupErrorV1> {
        let native = aos_sandbox_broker::receiving::RootLegacyStartupCaptureV1::capture()?;
        Ok(Self {
            descriptors: Some(native),
            root: None,
        })
    }

    /// Requires recovery/administrative CLI invocations to have no normal roles.
    ///
    /// # Errors
    /// Rejects a CLI invocation carrying the normal unit's original profile.
    pub fn require_non_normal_invocation(&self) -> Result<(), NormalRootStartupErrorV1> {
        if self.root.is_some() {
            return Err(NormalRootStartupErrorV1::Activation);
        }
        if let Some(native) = &self.descriptors {
            native.require_non_normal_invocation()?;
        }
        Ok(())
    }

    /// Admits only server-local startup comparisons for the actual normal path.
    ///
    /// Empty legacy launch remains nonauthorizing; the fixed normal SELinux
    /// subject cannot fall back when its required original profile is absent.
    /// The argument tuple is compared with image-built unit bytes, not trusted
    /// merely because the caller supplies numbers.
    ///
    /// # Errors
    /// Rejects missing normal launch custody, substituted configured identities,
    /// image/profile/unit/policy changes, wrong subject or nonempty capabilities.
    pub fn admit_normal(
        mut self,
        identities: [u32; 4],
    ) -> Result<Option<ProductionNormalRootStartupV1>, NormalRootStartupErrorV1> {
        if let Some(root) = self.root.take() {
            let (mut startup, original) = root.into_selected_startup_parts(identities)?;
            startup.receiving = Some(std::sync::Arc::new(std::sync::Mutex::new(original)));
            return Ok(Some(startup));
        }
        let Some(native) = self.descriptors else {
            return Err(NormalRootStartupErrorV1::Activation);
        };
        Ok(native
            .admit_normal(identities)?
            .map(|native| ProductionNormalRootStartupV1 {
                native,
                receiving: None,
                receiving_financial: None,
            }))
    }
}

/// Retains nonauthorizing normal-Root startup prerequisites in the server only.
///
/// This has no serialization, scalar factory or proof conversion. Independent
/// Controller comparisons do not grant genuine Root-last read authority;
/// neither Source genesis nor FUSE can consume this as a read grant.
#[must_use = "retain and recheck the server-local startup owner while serving"]
pub struct ProductionNormalRootStartupV1 {
    native: aos_sandbox_broker::receiving::RootStartupNativeOriginalV1,
    receiving_financial: Option<aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1>,
    receiving: Option<
        std::sync::Arc<
            std::sync::Mutex<crate::controller_resource_reservation::RootReceivingOriginalV1>,
        >,
    >,
}

impl ProductionNormalRootStartupV1 {
    /// Lends the same sealed native startup to closed Root role adapters.
    ///
    /// The borrowed original is not a constructor or detached currentness grant.
    pub(crate) fn native_startup_original_v1(
        &self,
    ) -> &aos_sandbox_broker::receiving::RootStartupNativeOriginalV1 {
        &self.native
    }

    /// Returns the configured Cache signer task GID from the retained image profile.
    ///
    /// This comparison DATA grants no live peer, currentness or signing authority.
    #[must_use]
    pub fn cache_signer_gid(&self) -> u32 {
        self.native.fields().profile.cache_signer_gid
    }

    /// Reports whether this actual startup retains its original Root receiver.
    ///
    /// This is disposition DATA for selecting the receiving path. It does not
    /// prove currentness, successful admission or authority for another stage.
    #[must_use]
    pub fn is_resource_receiving(&self) -> bool {
        self.receiving.is_some()
    }

    /// Compares the original profile bytes with coverage catalog DATA.
    ///
    /// The whole bounded read result remains in the caller's one-shot slot.
    /// The caller retains its comparison result and independently rechecks the
    /// original startup, peer and writers; this comparison grants no authority.
    pub(crate) fn compare_git_coverage_profile_v1(
        &self,
        expected: [u8; 32],
        original_readback: &mut Option<
            Result<Vec<u8>, crate::immutable_image::ImmutableImageErrorV1>,
        >,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if expected == [0; 32] || original_readback.is_some() {
            return Err(NormalRootStartupErrorV1::Profile);
        }

        self.recheck()?;
        *original_readback = Some(self.native.fields().profile_file.read_bounded());

        match original_readback.as_ref() {
            Some(Ok(bytes)) if <[u8; 32]>::from(Sha256::digest(bytes)) == expected => Ok(()),
            _ => Err(NormalRootStartupErrorV1::Profile),
        }
    }

    /// Assembles one fixed administrative Git-evidence attempt before I/O.
    ///
    /// The actual startup borrow is retained, not converted into authority.
    /// Only the separately protected fixed credential can admit installation.
    /// This grants no Source, repository, validator measurement or Git backend.
    #[must_use]
    pub fn git_evidence_provisioning_attempt(
        &self,
    ) -> crate::git::RootGitEvidenceProvisioningAttemptV1<'_> {
        crate::git::RootGitEvidenceProvisioningAttemptV1::new(self)
    }

    /// Rechecks the same actual server-local launch, images, unit and policy.
    ///
    /// # Errors
    /// Rejects any name/content/policy/subject/capability/unit/invocation/process
    /// or retained cgroup change. This is not a trusted-admin policy freeze.
    pub fn recheck(&self) -> Result<(), NormalRootStartupErrorV1> {
        if self.receiving.is_some() {
            return self.native.borrow_selected_startup_v1().and_then(|loan| loan.recheck_v1())
                .map_err(|cause| match self.native.selected_currentness_failure_original_v1() {
                    Some(original) => NormalRootStartupErrorV1::SelectedCurrentness(original),
                    None => cause.into(),
                });
        }
        self.native.recheck_ordinary().map_err(Into::into)
    }

    /// Opens the fixed startup journal under this same original receiving owner.
    ///
    /// Four-role startup pays fixed native work, derives dominant replay demand
    /// from the held original prefix and checks the cumulative genuine RootR
    /// envelope before the unchanged semantic parser. Ordinary startup keeps
    /// its existing fixed native recipe. Neither path creates a domain grant.
    ///
    /// # Errors
    /// Rejects insufficient receiving provision, repeated entry, native/replay
    /// failure or changed selected originals. Failed custody remains resident;
    /// the normal daemon terminates intentionally without a recovery fallback.
    pub fn open_policy_startup_journal_once(
        &self,
        journal: &mut crate::policy_compiler::RootPolicyStartupJournalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.receiving.is_some() {
            let mut receiving = self.lock_receiving_v1()?;
            let returned = receiving.receive_startup_journal_native_once_v1(self, journal);
            receiving.finish_returned_v1(returned)
        } else {
            journal.open_once();
            Ok(())
        }
    }

    /// Borrows this actual startup journal through the fixed credential stage.
    ///
    /// Four-role startup admits the closed read/decoder/append recipe under the
    /// same original RootR before returning. Ordinary startup retains its actual
    /// writer and existing credential policy without claiming receiving.
    ///
    /// # Errors
    /// Rejects insufficient provision, repeated entry or changed original custody.
    pub fn borrow_startup_credentials_once<'original>(
        &'original self,
        journal: &'original mut crate::policy_compiler::RootPolicyStartupJournalV1,
    ) -> Result<RootStartupCredentialReceivingLoanV1<'original>, NormalRootStartupErrorV1> {
        RootStartupCredentialReceivingLoanV1::borrow_once(self, journal)
    }

    pub(crate) fn receive_create_storage_current_writers_once(
        &self,
        writers: &mut crate::policy_compiler::root_current_writers::RootCreateStorageCurrentWritersV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().receive_create_storage_current_writers_once(self, writers);
        receiving.finish_returned_v1(returned)
    }

    // The normal profile was compared with the actual parsed five arguments
    // before any journal/effect. These are distinct measured configuration DATA;
    // B and the Controller exchange cannot choose or substitute them.
    pub(crate) fn current_cache_signer_identity_data_v1(
        &self,
    ) -> Result<(u32, u32, u32), NormalRootStartupErrorV1> {
        if self.receiving.is_none() {
            return Err(NormalRootStartupErrorV1::Service);
        }
        aos_sandbox_broker::root_current_cache_signer_identity_data_v1!(
            uid = self.native.fields().profile.identities[2],
            gid = self.cache_signer_gid(),
            socket_gid = self.native.fields().profile.identities[1],
            error = NormalRootStartupErrorV1::Service
        )
    }

    pub(crate) fn prepay_create_storage_use_source_query_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        authorization: &crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
        reserved: &crate::policy_compiler::create_storage_current::use_reserved::RootCurrentUseReservedStateV1,
        ready: &crate::policy_compiler::create_storage_current::ready::RootCurrentReadyStateV1,
        trust: &crate::policy_compiler::create_storage_current::ownership_trust::RootCurrentOwnershipTrustStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_use_source_query_once(self, root, authorization, reserved, ready, trust);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_use_source_exchange_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        authorization: &crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
        reserved: &crate::policy_compiler::create_storage_current::use_reserved::RootCurrentUseReservedStateV1,
        ready: &crate::policy_compiler::create_storage_current::ready::RootCurrentReadyStateV1,
        query: &crate::policy_compiler::create_storage_current::source_current::RootCurrentSourceQueryStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_use_source_exchange_once(
                self,
                root,
                authorization,
                reserved,
                ready,
                query,
            );
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_use_cache_current_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        authorization: &crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
        reserved: &crate::policy_compiler::create_storage_current::use_reserved::RootCurrentUseReservedStateV1,
        source: &crate::policy_compiler::create_storage_current::source_current::RootCurrentSourceExchangeStateV1,
        pins: &crate::policy_compiler::create_storage_current::pins::RootCurrentPinsStateV1,
        ownership: &crate::policy_compiler::create_storage_current::bundle_ownership::RootCurrentBundleOwnershipStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_use_cache_current_once(
                self,
                root,
                authorization,
                reserved,
                source,
                pins,
                ownership,
            );
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_outcome_fixed_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        signed: &crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        admitted: &crate::policy_compiler::create_storage_current::use_admitted::RootCurrentUseAdmittedStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_outcome_fixed_once(self, root, admitted, signed);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_outcome_bytes_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        signed: &crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        reserved: &crate::policy_compiler::create_storage_current::use_reserved::RootCurrentUseReservedStateV1,
        input: &crate::policy_compiler::create_storage_current::outcome::input::RootOutcomeInputV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_outcome_bytes_once(self, root, signed, input, reserved);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_outcome_controller_native_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        signed: &crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        state: &crate::policy_compiler::create_storage_current::controller_readonly::RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_outcome_controller_native_once(self, root, signed, state);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_outcome_controller_semantic_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        signed: &crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        state: &crate::policy_compiler::create_storage_current::controller_readonly::RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_outcome_controller_semantic_once(self, root, signed, state);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_outcome_session_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        signed: &crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        read: &crate::policy_compiler::create_storage_current::outcome::read::RootCurrentOutcomeReadV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_outcome_session_once(self, root, signed, read);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn require_create_storage_outcome_controller_fixed(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        signed: &crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().require_current_outcome_controller_fixed(root, signed);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn require_create_storage_outcome_controller_semantic(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        signed: &crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().require_current_outcome_controller_semantic(root, signed);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_signed_fixed_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        admitted: &crate::policy_compiler::create_storage_current::use_admitted::RootCurrentUseAdmittedStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_signed_fixed_once(self, root, admitted);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_signed_bytes_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        admitted: &crate::policy_compiler::create_storage_current::use_admitted::RootCurrentUseAdmittedStateV1,
        reserved: &crate::policy_compiler::create_storage_current::use_reserved::RootCurrentUseReservedStateV1,
        input: &crate::policy_compiler::create_storage_current::signed_bound::input::RootSignedInputV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_signed_bytes_once(self, root, admitted, reserved, input);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_signed_controller_fixed_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        admitted: &crate::policy_compiler::create_storage_current::use_admitted::RootCurrentUseAdmittedStateV1,
        input: &crate::policy_compiler::create_storage_current::signed_bound::input::RootSignedInputV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_signed_controller_fixed_once(self, root, admitted, input);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_signed_controller_native_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        admitted: &crate::policy_compiler::create_storage_current::use_admitted::RootCurrentUseAdmittedStateV1,
        state: &crate::policy_compiler::create_storage_current::controller_readonly::RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_signed_controller_native_once(self, root, admitted, state);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_signed_controller_semantic_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        admitted: &crate::policy_compiler::create_storage_current::use_admitted::RootCurrentUseAdmittedStateV1,
        state: &crate::policy_compiler::create_storage_current::controller_readonly::RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_signed_controller_semantic_once(self, root, admitted, state);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn require_create_storage_signed_controller_fixed(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        admitted: &crate::policy_compiler::create_storage_current::use_admitted::RootCurrentUseAdmittedStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().require_current_signed_controller_fixed(root, admitted);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn require_create_storage_signed_controller_semantic(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        admitted: &crate::policy_compiler::create_storage_current::use_admitted::RootCurrentUseAdmittedStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().require_current_signed_controller_semantic(root, admitted);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_use_admitted_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        authorization: &crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
        reserved: &crate::policy_compiler::create_storage_current::use_reserved::RootCurrentUseReservedStateV1,
        source: &crate::policy_compiler::create_storage_current::source_current::RootCurrentSourceExchangeStateV1,
        cache: &crate::policy_compiler::create_storage_current::cache_current::RootCurrentCacheProofStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_use_admitted_once(self, root, authorization, reserved, source, cache);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_use_reserved_frame_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        authorization: &crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_use_reserved_frame_once(self, root, authorization);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_use_controller_readonly_fixed_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        authorization: &crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
        received: &crate::policy_compiler::create_storage_current::use_reserved::received::RootCurrentUseReservedReceivedV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_use_controller_readonly_fixed_once(self, root, authorization, received);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_use_controller_readonly_native_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        authorization: &crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
        state: &crate::policy_compiler::create_storage_current::controller_readonly::RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_use_controller_readonly_native_once(self, root, authorization, state);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_use_controller_readonly_semantic_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        authorization: &crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
        state: &crate::policy_compiler::create_storage_current::controller_readonly::RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_use_controller_readonly_semantic_once(self, root, authorization, state);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn require_create_storage_use_controller_readonly_fixed(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        authorization: &crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().require_current_use_controller_readonly_fixed(root, authorization);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn require_create_storage_use_controller_readonly_semantic(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        authorization: &crate::policy_compiler::create_storage_current::use_authorized::RootCurrentUseAuthorizedStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().require_current_use_controller_readonly_semantic(root, authorization);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_use_authorized_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        readonly: &crate::policy_compiler::create_storage_current::controller_readonly::RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_use_authorized_once(self, root, readonly);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_controller_readonly_fixed_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        cache: &crate::policy_compiler::create_storage_current::cache_current::RootCurrentCacheProofStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_controller_readonly_fixed_once(self, root, cache);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_controller_readonly_native_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        state: &crate::policy_compiler::create_storage_current::controller_readonly::RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_controller_readonly_native_once(self, root, state);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_controller_readonly_semantic_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        state: &crate::policy_compiler::create_storage_current::controller_readonly::RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_controller_readonly_semantic_once(self, root, state);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn require_create_storage_controller_readonly_fixed(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().require_current_controller_readonly_stage(root, false);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn require_create_storage_controller_readonly_semantic(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().require_current_controller_readonly_stage(root, true);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_cache_current_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        ownership: &crate::policy_compiler::create_storage_current::bundle_ownership::RootCurrentBundleOwnershipStateV1,
        pins: &crate::policy_compiler::create_storage_current::pins::RootCurrentPinsStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_cache_current_once(self, root, ownership, pins);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_bundle_ownership_fixed_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        source: &crate::policy_compiler::create_storage_current::source_current::RootCurrentSourceExchangeStateV1,
        trust: &crate::policy_compiler::create_storage_current::ownership_trust::RootCurrentOwnershipTrustStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_bundle_ownership_fixed_once(self, root, source, trust);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_bundle_ownership_typed_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        state: &crate::policy_compiler::create_storage_current::bundle_ownership::RootCurrentBundleOwnershipStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_bundle_ownership_typed_once(self, root, state);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_source_exchange_once(
        &self,
        root_open: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        ready: &crate::policy_compiler::create_storage_current::ready::RootCurrentReadyStateV1,
        query: &crate::policy_compiler::create_storage_current::source_current::RootCurrentSourceQueryStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_source_exchange_once(self, root_open, ready, query);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_ownership_trust_fixed_once(
        &self,
        root_open: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        policy_inputs: &crate::policy_compiler::create_storage_current::policy_inputs::RootCurrentPolicyInputsStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_ownership_trust_fixed_once(self, root_open, policy_inputs);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn require_create_storage_ownership_trust_fixed_v1(
        &self,
        root_open: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().require_current_ownership_trust_fixed_v1(root_open);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_ownership_trust_typed_once(
        &self,
        root_open: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        trust: &crate::policy_compiler::create_storage_current::ownership_trust::RootCurrentOwnershipTrustStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_ownership_trust_typed_once(self, root_open, trust);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_source_query_once(
        &self,
        root_open: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        ready: &crate::policy_compiler::create_storage_current::ready::RootCurrentReadyStateV1,
        trust: &crate::policy_compiler::create_storage_current::ownership_trust::RootCurrentOwnershipTrustStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_source_query_once(self, root_open, ready, trust);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_current_policy_inputs_once(
        &self,
        root_open: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        pins: &crate::policy_compiler::create_storage_current::pins::RootCurrentPinsStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_policy_inputs_once(self, root_open, pins);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_current_pins_once(
        &self,
        root_open: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        ready: &crate::policy_compiler::create_storage_current::ready::RootCurrentReadyStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_pins_once(self, root_open, ready);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_ready_fixed_once(
        &self,
        root_open: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_ready_fixed_once(self, root_open);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_ready_bytes_once(
        &self,
        index: aos_sandbox_protocol::domain_ledger::create_storage_history::transport::TransferIndexV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_ready_bytes_once(self, index);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_closed_fixed_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        signed: &crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        outcome: &crate::policy_compiler::create_storage_current::outcome::RootCurrentOutcomeStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_closed_fixed_once(self, root, signed, outcome);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_closed_controller_native_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        signed: &crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        outcome: &crate::policy_compiler::create_storage_current::outcome::RootCurrentOutcomeStateV1,
        read: &crate::policy_compiler::create_storage_current::controller_readonly::RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_closed_controller_native_once(self, root, signed, outcome, read);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_closed_controller_semantic_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        signed: &crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        outcome: &crate::policy_compiler::create_storage_current::outcome::RootCurrentOutcomeStateV1,
        read: &crate::policy_compiler::create_storage_current::controller_readonly::RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_closed_controller_semantic_once(self, root, signed, outcome, read);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn require_create_storage_closed_controller_fixed(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        signed: &crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        outcome: &crate::policy_compiler::create_storage_current::outcome::RootCurrentOutcomeStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().require_current_closed_controller_fixed(root, signed, outcome);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn require_create_storage_closed_controller_semantic(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        signed: &crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        outcome: &crate::policy_compiler::create_storage_current::outcome::RootCurrentOutcomeStateV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().require_current_closed_controller_semantic(root, signed, outcome);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_closed_release_once(
        &self,
        root: &crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenStateV1,
        signed: &crate::policy_compiler::create_storage_current::signed_bound::RootCurrentSignedBoundStateV1,
        outcome: &crate::policy_compiler::create_storage_current::outcome::RootCurrentOutcomeStateV1,
        read: &crate::policy_compiler::create_storage_current::closed::read::RootCurrentClosedReadV1,
        stage: crate::policy_compiler::create_storage_current::closed::ClosedFinancialStageV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_closed_release_once(self, root, signed, outcome, read, stage);
        receiving.finish_returned_v1(returned)
    }

    pub(crate) fn prepay_create_storage_root_open_once(
        &self,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let mut receiving = self.lock_receiving_v1()?;
        let returned = receiving.original_mut_v1().prepay_current_root_open_once(self);
        receiving.finish_returned_v1(returned)
    }

    /// Parks fixed listener custody only for this actual resource-received Root.
    ///
    /// This performs no IO. `bind_once` must admit the complete literal native
    /// recipe under this same RootR before inspecting or binding the socket.
    #[must_use]
    pub fn policy_authority_listener_receiving(&self) -> Option<RootPolicyListenerReceivingV1<'_>> {
        self.receiving.as_ref()?;
        Some(RootPolicyListenerReceivingV1::new(self))
    }
}

fn require_unit(
    fragment: &RetainedImmutableFileV1,
    profile_file: &RetainedImmutableFileV1,
    profile: &NormalRootProfileV1,
) -> Result<(), NormalRootStartupErrorV1> {
    aos_sandbox_broker::profile_data::images::require_unit(fragment, profile_file, profile)
        .map_err(Into::into)
}

fn valid_roles(names: &[String]) -> bool {
    aos_sandbox_broker::receiving::root_legacy_roles_match_data_v1(names)
}

fn retain_fixed_cgroup(path: &Path) -> Result<RetainedCgroupAnchor, NormalRootStartupErrorV1> {
    aos_sandbox_broker::profile_data::native_observation::retain_cgroup_anchor_data_v1(path)
        .map_err(Into::into)
}

fn read_bounded(path: &str, maximum: usize) -> Result<Vec<u8>, NormalRootStartupErrorV1> {
    aos_sandbox_broker::receiving::read_root_bounded_confinement_data_v1(path, maximum)
        .map_err(Into::into)
}

fn require_status(bytes: &[u8]) -> Result<(), NormalRootStartupErrorV1> {
    aos_sandbox_broker::profile_data::status::require_status(bytes).map_err(Into::into)
}

impl Drop for ProductionNormalRootStartupV1 {
    fn drop(&mut self) {
        if self.receiving.is_some() {
            // The actual financial owner may remain resident in Journal. Its
            // original invocation ends here, rather than at the last Arc Drop.
            match self.lock_receiving_v1() {
                Ok(original) => original.original_v1().end_native_journal_lifetime_v1(),
                Err(_) => std::process::abort(),
            }
        }
    }
}

pub(crate) mod root_history_post;
pub(crate) use root_history_post::RootHistoryPeerPostV1;

pub(crate) use client::RootEnvironmentClientOriginalV1;

pub(crate) use controller_peer::delete_receiving::{
    RootStartAssignmentInputsControllerPeerReceivingV2, RootStartAssignmentInputsStageReceivingV2,
};

#[doc(hidden)]
pub use client::{
    RootExecutionNoApplyClientAcquisitionBorrowV2, RootExecutionNoApplyClientClosedV2,
    RootExecutionNoApplyClientFloorBorrowV2, RootExecutionNoApplyClientOriginalV2,
};

pub(crate) use controller_peer::{RootExecutionNoApplyControllerPeerReceivingV2,
    RootExecutionNoApplyStageReceivingV2};
