//! Resident startup custody for manual offline preparation and static inspection.
//!
//! No TPM device, approval signer, runtime floor or journal is opened here.
//! Returned activation descriptors and parked partial observations stay in the
//! owner on error or unwind. Current-self pidfd adoption and original stat reads
//! use one resident lower DATA owner. Hardware startup also parks the returned
//! initial hierarchy/self-cgroup candidates through the shared lower validators.
//! Raw open/clone pre-return gaps and later consuming membership observations
//! remain functional dependencies; ordinary prepare/inspection is unchanged.
//! A genuine borrow exists only after selected image,
//! PID1 delivery, confinement, stopped-runtime and credential comparisons.
//! SecureBits=12 is a selected manager/unit configuration comparison, not a
//! direct kernel securebits observation or the child's exec precondition.
//!
//! ```text
//! AOS_NIX_OFFLINE_PREPARE_STARTUP_3: immutable image and selected-unit comparisons
//! node-id: 16 bytes; nix-floor-provision-approval-public-key-v3: key ID16/public32
//! ```

use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::Path;
use std::time::Duration;

use aos_sandbox_linux::cgroup::{CgroupPopulationState, CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::inherited_fd::{NixOfflinePrepareInitialTableV3, duplicate_descriptor};
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::pidfd::{CurrentSelfPidFdCustodyV1, PidFdProcessIdentity};
use aos_sandbox_linux::selinux_policy::VerifiedLiveSelinuxPolicy;
use aos_systemd::{OwnedValue, SystemdClient, Value};
use rustix::fs::{Mode, OFlags};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::immutable_image::{PendingImmutableFileV1, RetainedImmutableFileV1};
use crate::public_api_session::OfflinePrepareCredentialsV3;
use crate::systemd_property_data;

use super::{NormalRootStartupErrorV1, images, profile::ImagePinV1, service, startup};

mod approved_data;
pub use approved_data::{
    NixOfflineApprovedDataErrorV4, NixOfflineEffectApprovalKindV4,
    derive_nix_offline_public_candidates_v3, fill_nix_offline_static_preimage_v3,
    require_nix_offline_effect_approval_v4, require_nix_offline_static_approval_v3,
    require_nix_offline_static_header_v3,
    NixOfflineJobIdentityDataV5, inspect_nix_offline_job_identity_v5,
    nix_offline_job_has_original_label_v5,
};

const UNIT: &str = "aos-sandbox-nix-floor-provision.service";
const CONTEXT: &str = "system_u:system_r:aos_nix_offline_prepare_t";
const HELPER_CONTEXT: &str = "system_u:system_r:aos_nix_offline_tpm_helper_t";
const CGROUP: &str = "system.slice/aos-sandbox-nix-floor-provision.service";
const PROFILE_NAME: &str = "aos-nix-offline-prepare-profile";
const PID1_NAME: &str = "aos-nix-offline-prepare-pid1-image";
const PLACEHOLDER: &str = "@AOS_NIX_OFFLINE_PREPARE_PROFILE@";
const MAXIMUM_OBSERVATIONS: usize = 16;
const HARDWARE_INITIALIZE_OBSERVATIONS: usize = 79;
const HARDWARE_RECOVERY_OBSERVATIONS: usize = 83;
const HARDWARE_ADDRESS_SPACE: u64 = 1024 * 1024 * 1024;
const HARDWARE_DESCRIPTOR_LIMIT: u64 = 4096;
const HARDWARE_SERVICE_PROPERTIES: &[&str] = &[
    "ControlGroup", "OpenFile", "ExtraFileDescriptorNames",
    "FileDescriptorStoreMax", "NFileDescriptorStore", "SELinuxContext",
    "CapabilityBoundingSet", "AmbientCapabilities", "NoNewPrivileges",
    "SecureBits", "ExecStart", "ExecStartPre", "ExecStartPost", "LoadCredential",
    "LoadCredentialEncrypted", "SetCredential", "SetCredentialEncrypted",
    "ImportCredential", "ImportCredentialEx", "ExitType", "KillMode",
    "TimeoutStopUSec", "LimitNOFILE", "LimitNOFILESoft", "LimitAS", "LimitASSoft",
];
const SERVICE_PROPERTIES: &[&str] = &[
    "ControlGroup",
    "OpenFile",
    "ExtraFileDescriptorNames",
    "FileDescriptorStoreMax",
    "NFileDescriptorStore",
    "SELinuxContext",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "NoNewPrivileges",
    "SecureBits",
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "LoadCredential",
    "LoadCredentialEncrypted",
    "SetCredential",
    "SetCredentialEncrypted",
    "ImportCredential",
    "ImportCredentialEx",
    "ExitType",
    "KillMode",
    "TimeoutStopUSec",
];
const RUNTIME_CGROUPS: [&str; 2] = [
    "aos.slice/aos-control.slice/aos-sandboxd.service",
    "aos.slice/aos-control.slice/aos-sandbox-nixd.service",
];

/// Retains a concrete first failure of offline prepare startup custody.
#[derive(Debug, thiserror::Error)]
pub enum OfflineNixPrepareStartupErrorV3 {
    /// The initial table retains the actual cause in `initial_failure()`.
    #[error("offline prepare original activation observation failed")]
    InitialActivation,
    /// A selected immutable image or genuine fixed-unit comparison failed.
    #[error("offline prepare selected startup differs")]
    Startup(#[from] NormalRootStartupErrorV1),
    /// An actual kernel descriptor or process observation failed.
    #[error("offline prepare kernel observation failed")]
    Linux(#[from] aos_sandbox_linux::Error),
    /// An original file, credential or manager observation failed.
    #[error("offline prepare original I/O failed")]
    Io(#[from] io::Error),
    /// The original bounded profile read failed or found trailing bytes.
    #[error("offline prepare original exact read failed ({0:?})")]
    Read(aos_sandbox_linux::protected_file::ExactReadError),
    /// The closed purpose-specific profile or observation differs.
    #[error("offline prepare original purpose differs")]
    Rejected,
    /// This instance already failed or an observation was interrupted.
    #[error("offline prepare original owner is fenced")]
    Fenced,
    /// An actual manager cause remains in the selected absence observation.
    #[error("offline hardware runtime observation failed")]
    HardwareRuntime,
}

impl From<rustix::io::Errno> for OfflineNixPrepareStartupErrorV3 {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(io::Error::from_raw_os_error(error.raw_os_error()))
    }
}

type Error = OfflineNixPrepareStartupErrorV3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OfflinePrepareModeV3 {
    PrepareKeys,
    InspectApprovedJob,
    Initialize,
    Recover,
}

impl OfflinePrepareModeV3 {
    const fn command(self) -> &'static str {
        match self {
            Self::PrepareKeys => "prepare-keys",
            Self::InspectApprovedJob => "inspect-approved-job",
            Self::Initialize => "initialize",
            Self::Recover => "recover",
        }
    }

    const fn hardware(self) -> bool {
        matches!(self, Self::Initialize | Self::Recover)
    }

    const fn observations(self) -> usize {
        match self {
            Self::PrepareKeys | Self::InspectApprovedJob => MAXIMUM_OBSERVATIONS,
            Self::Initialize => HARDWARE_INITIALIZE_OBSERVATIONS,
            Self::Recover => HARDWARE_RECOVERY_OBSERVATIONS,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    format: String,
    unit: String,
    context: String,
    executable: ImagePinV1,
    pid1: ImagePinV1,
    loader: ImagePinV1,
    runtime_files: Vec<ImagePinV1>,
    canonical_policy: ImagePinV1,
    source_policy: ImagePinV1,
    effective_matrix: ImagePinV1,
    unit_sha256: [u8; 32],
    #[serde(default)]
    hardware: Option<HardwareProfileV5>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HardwareProfileV5 {
    format: String,
    unit_mode_neutral_sha256: [u8; 32],
    helper: ImagePinV1,
    loader: ImagePinV1,
    compiled_contract_sha256: [u8; 32],
    descriptor_limit: u64,
    address_space_limit: u64,
    child_descriptor_limit: u64,
    child_address_space_limit: u64,
}

impl Profile {
    fn require(&self) -> Result<(), Error> {
        if self.format != "AOS_NIX_OFFLINE_PREPARE_STARTUP_3"
            || self.unit != UNIT
            || self.context != CONTEXT
            || self.unit_sha256 == [0; 32]
            || self.runtime_files.is_empty()
            || self.runtime_files.len() > 512
            || self.runtime_files.windows(2).any(|pair| pair[0].path >= pair[1].path)
            || Path::new(&self.executable.path).file_name()
                .is_none_or(|name| name != "aos-sandbox-nix-floor-provision")
        {
            return Err(Error::Rejected);
        }
        for pin in self.runtime_files.iter().chain([
            &self.executable,
            &self.pid1,
            &self.loader,
            &self.canonical_policy,
            &self.source_policy,
            &self.effective_matrix,
        ]) {
            super::profile::require_store_path(&pin.path)?;
            if pin.sha256 == [0; 32] {
                return Err(Error::Rejected);
            }
        }
        for pin in [&self.executable, &self.loader] {
            if !self.runtime_files.iter().any(|member| {
                member.path == pin.path && member.sha256 == pin.sha256
            }) {
                return Err(Error::Rejected);
            }
        }

        if !self.canonical_policy.path.ends_with("-aos-selinux-kernel-policy-readback-1/policy.33")
            || !self.source_policy.path.ends_with("-aos-nix-offline-startup-profile-3/source-policy.33")
            || !self.effective_matrix.path.ends_with("-aos-nix-offline-startup-profile-3/effective-policy.tsv")
            || Path::new(&self.source_policy.path).parent() != Path::new(&self.effective_matrix.path).parent()
        {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    fn require_mode(&self, mode: OfflinePrepareModeV3) -> Result<(), Error> {
        self.require()?;
        match (&self.hardware, mode.hardware()) {
            (None, false) => Ok(()),
            (Some(hardware), true) => {
                if hardware.format != "AOS_NIX_OFFLINE_HARDWARE_5"
                    || hardware.unit_mode_neutral_sha256 == [0; 32]
                    || hardware.compiled_contract_sha256 == [0; 32]
                    || hardware.descriptor_limit != HARDWARE_DESCRIPTOR_LIMIT
                    || hardware.address_space_limit != HARDWARE_ADDRESS_SPACE
                    || hardware.child_descriptor_limit != 64
                    || hardware.child_address_space_limit != HARDWARE_ADDRESS_SPACE
                    || Path::new(&hardware.helper.path).file_name()
                        .is_none_or(|name| name != "aos-nix-offline-tpm-helper")
                {
                    return Err(Error::Rejected);
                }
                for pin in [&hardware.helper, &hardware.loader] {
                    if pin.sha256 == [0; 32]
                        || !self.runtime_files.iter().any(|member| {
                            member.path == pin.path && member.sha256 == pin.sha256
                        })
                    {
                        return Err(Error::Rejected);
                    }
                    super::profile::require_store_path(&pin.path)?;
                }
                Ok(())
            }
            _ => Err(Error::Rejected),
        }
    }
}

struct HardwareStartupV5 {
    helper: PendingImmutableFileV1,
    loader: PendingImmutableFileV1,
    boot: Option<File>,
    boot_bytes: [u8; 37],
    boot_original: Option<[u8; 16]>,
    boot_identity: Option<(u64, u64, MountId)>,
    first_cut: Option<(u64, u64)>,
    stopped: Vec<aos_systemd::NixOfflineAbsenceObservationV5>,
    cgroup_observations: Vec<[aos_sandbox_linux::cgroup::NixOfflineStoppedCgroupReadbackV5; 2]>,
    thread_failure: Option<io::Error>,
    unwind: Option<Box<dyn std::any::Any + Send>>,
    initial_cgroup: aos_sandbox_linux::cgroup::NixOfflineInitialCgroupReadbackV5,
}

impl HardwareStartupV5 {
    fn new() -> Self {
        Self {
            helper: PendingImmutableFileV1::default(),
            loader: PendingImmutableFileV1::default(),
            boot: None,
            boot_bytes: [0; 37],
            boot_original: None,
            boot_identity: None,
            first_cut: None,
            stopped: Vec::new(),
            cgroup_observations: Vec::new(),
            thread_failure: None,
            unwind: None,
            initial_cgroup: aos_sandbox_linux::cgroup::NixOfflineInitialCgroupReadbackV5::new(),
        }
    }
}

/// Holds original offline prepare startup and every partial retained observation.
///
/// Creation admits nothing. Capture must be the first single-threaded operation,
/// before protected files open. Errors and caught unwinds permanently fence this
/// instance; the caller keeps it alive until the explicit failed process exit.
pub struct OfflineNixPrepareStartupV3 {
    initial: NixOfflinePrepareInitialTableV3,
    attempted: bool,
    usable: bool,
    mode: Option<OfflinePrepareModeV3>,
    failure: Option<Error>,
    raw: Vec<File>,
    profile_file: Option<RetainedImmutableFileV1>,
    profile_bytes: Vec<u8>,
    profile: Option<Profile>,
    pid1: Option<RetainedImmutableFileV1>,
    executable: Option<RetainedImmutableFileV1>,
    runtime: Vec<RetainedImmutableFileV1>,
    evidence: Vec<RetainedImmutableFileV1>,
    policy: Option<VerifiedLiveSelinuxPolicy>,
    process: Option<CurrentSelfPidFdCustodyV1>,
    identity: Option<PidFdProcessIdentity>,
    cgroup: Option<RetainedCgroupAnchor>,
    cgroup_root: Option<CgroupV2Root>,
    cgroup_mount: Option<MountId>,
    cgroup_file_index: Option<usize>,
    runtime_anchors: Vec<RetainedCgroupAnchor>,
    fragment: Option<RetainedImmutableFileV1>,
    observed: Option<service::ServiceObservationV1>,
    flights: Vec<(Vec<OwnedValue>, Vec<OwnedValue>)>,
    stopped: Vec<[(Vec<OwnedValue>, Vec<OwnedValue>); 2]>,
    credentials: OfflinePrepareCredentialsV3,
    hardware: Option<HardwareStartupV5>,
}

impl OfflineNixPrepareStartupV3 {
    /// Creates empty retained slots without reading credentials or the process table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            initial: NixOfflinePrepareInitialTableV3::new(),
            attempted: false,
            usable: false,
            mode: None,
            failure: None,
            raw: Vec::new(),
            profile_file: None,
            profile_bytes: Vec::new(),
            profile: None,
            pid1: None,
            executable: None,
            runtime: Vec::new(),
            evidence: Vec::new(),
            policy: None,
            process: None,
            identity: None,
            cgroup: None,
            cgroup_root: None,
            cgroup_mount: None,
            cgroup_file_index: None,
            runtime_anchors: Vec::new(),
            fragment: None,
            observed: None,
            flights: Vec::new(),
            stopped: Vec::new(),
            credentials: OfflinePrepareCredentialsV3::new(),
            hardware: None,
        }
    }

    /// Captures the one complete initial table and admits only the selected prepare unit.
    ///
    /// # Errors
    /// Returns the resident first actual failure, or fences a repeat/interrupted
    /// observation. No original descriptor or partial read is moved out on error.
    pub fn capture_and_admit(&mut self) -> Result<(), &Error> {
        self.capture_mode(OfflinePrepareModeV3::PrepareKeys)
    }

    /// Captures the same original startup for static approved-job inspection only.
    ///
    /// # Errors
    /// Rejects repeated or interrupted capture, a different immutable selected
    /// command, or any original launch, confinement or credential mismatch.
    pub fn capture_and_admit_inspection(&mut self) -> Result<(), &Error> {
        self.capture_mode(OfflinePrepareModeV3::InspectApprovedJob)
    }

    /// Captures the fixed original manual hardware initialization startup.
    ///
    /// # Errors
    /// Retains the first actual startup failure and fences reentry or unwind.
    /// Admission alone approves no job, TPM contact or provisioning result.
    pub fn capture_and_admit_initialize(&mut self) -> Result<(), &Error> {
        self.capture_mode(OfflinePrepareModeV3::Initialize)
    }

    /// Captures the fixed original one-recovery startup without renewing a job.
    ///
    /// # Errors
    /// Retains original startup failures; rejects a different selected command
    /// or profile. The signed prior job and original cutoff are checked later.
    pub fn capture_and_admit_recovery(&mut self) -> Result<(), &Error> {
        self.capture_mode(OfflinePrepareModeV3::Recover)
    }

    fn capture_mode(&mut self, mode: OfflinePrepareModeV3) -> Result<(), &Error> {
        if self.attempted {
            return self.refuse();
        }
        self.attempted = true;
        self.usable = false;
        self.mode = Some(mode);
        if mode.hardware() {
            self.hardware = Some(HardwareStartupV5::new());
        }
        let result = self.admit_inner();
        self.complete(result)
    }

    /// Rechecks the same original selected unit, process, files and public delivery.
    ///
    /// # Errors
    /// Returns and retains the first actual observation failure. The prearmed
    /// instance remains closed on an unwind; successful completion alone reopens it.
    pub fn recheck(&mut self) -> Result<(), &Error> {
        self.recheck_mode(OfflinePrepareModeV3::PrepareKeys)
    }

    /// Rechecks the same original startup in its static inspection mode.
    ///
    /// # Errors
    /// Fences a prepare-mode, absent, interrupted, failed or changed owner.
    /// Success supplies no approval freshness, TPM floor or effect authority.
    pub fn recheck_inspection(&mut self) -> Result<(), &Error> {
        self.recheck_mode(OfflinePrepareModeV3::InspectApprovedJob)
    }

    fn recheck_mode(&mut self, mode: OfflinePrepareModeV3) -> Result<(), &Error> {
        if !self.usable || self.mode != Some(mode) {
            return self.refuse();
        }
        self.usable = false;
        let result = self.recheck_inner();
        self.complete(result)
    }

    /// Borrows the genuine admitted original startup, never caller-supplied fields.
    ///
    /// # Errors
    /// Rejects an absent, failed, interrupted or currently mismatching original.
    pub fn borrow_original(&mut self) -> Result<OfflineNixPrepareOriginV3<'_>, &Error> {
        if self.recheck().is_err() {
            return Err(self.failure.get_or_insert(Error::Fenced));
        }
        Ok(OfflineNixPrepareOriginV3 { startup: self })
    }

    /// Borrows only the genuine original startup selected for static inspection.
    ///
    /// # Errors
    /// Rejects a prepare-mode, absent, failed, interrupted or changed owner.
    /// The mutable loan cannot change its mode or establish live currentness.
    pub fn borrow_inspection(&mut self) -> Result<OfflineNixPrepareOriginV3<'_>, &Error> {
        if self.recheck_inspection().is_err() {
            return Err(self.failure.get_or_insert(Error::Fenced));
        }
        Ok(OfflineNixPrepareOriginV3 { startup: self })
    }

    /// Borrows the actual original selected for hardware initialization.
    ///
    /// # Errors
    /// Retains and returns the first startup cause, including interrupted
    /// observation. This does not approve a job or fund any TPM contact.
    pub fn borrow_initialize(&mut self) -> Result<OfflineNixHardwareOriginV5<'_>, &Error> {
        self.borrow_hardware(OfflinePrepareModeV3::Initialize)
    }

    /// Borrows the actual original selected for one independently approved recovery.
    ///
    /// # Errors
    /// Refuses a wrong-mode, failed or interrupted owner. Original job time,
    /// prior history and recovery approval remain mandatory native checks.
    pub fn borrow_recovery(&mut self) -> Result<OfflineNixHardwareOriginV5<'_>, &Error> {
        self.borrow_hardware(OfflinePrepareModeV3::Recover)
    }

    fn borrow_hardware(
        &mut self,
        mode: OfflinePrepareModeV3,
    ) -> Result<OfflineNixHardwareOriginV5<'_>, &Error> {
        if self.recheck_mode(mode).is_err() {
            return Err(self.failure.get_or_insert(Error::Fenced));
        }
        Ok(OfflineNixHardwareOriginV5 { startup: self })
    }

    /// Borrows the resident first returned failure without treating it as authority.
    pub fn failure(&self) -> Option<&Error> {
        self.failure.as_ref()
    }

    /// Borrows the actual first activation error from its resident table owner.
    ///
    /// This diagnostic neither releases partial descriptors nor admits a role.
    pub fn initial_failure(&self) -> Option<&aos_sandbox_linux::Error> {
        self.initial.failure()
    }

    fn complete(&mut self, result: Result<(), Error>) -> Result<(), &Error> {
        match result {
            Ok(()) => {
                self.usable = true;
                Ok(())
            }
            Err(error) => {
                if let Some(process) = &mut self.process {
                    process.fence();
                }
                self.failure.get_or_insert(error);
                self.refuse()
            }
        }
    }

    fn refuse(&mut self) -> Result<(), &Error> {
        self.usable = false;
        if let Some(process) = &mut self.process {
            process.fence();
        }
        Err(self.failure.get_or_insert(Error::Fenced))
    }

    fn admit_inner(&mut self) -> Result<(), Error> {
        let mode = self.mode.ok_or(Error::Rejected)?;
        let observations = mode.observations();
        self.raw
            .try_reserve_exact(if mode.hardware() { 852 } else { 600 })
            .map_err(io::Error::other)?;
        self.runtime.try_reserve_exact(512).map_err(io::Error::other)?;
        self.evidence
            .try_reserve_exact(3 + observations * 2)
            .map_err(io::Error::other)?;
        self.flights
            .try_reserve_exact(observations)
            .map_err(io::Error::other)?;
        self.stopped
            .try_reserve_exact(if mode.hardware() { 0 } else { MAXIMUM_OBSERVATIONS })
            .map_err(io::Error::other)?;
        self.runtime_anchors
            .try_reserve_exact(observations * 2)
            .map_err(io::Error::other)?;
        if let Some(hardware) = &mut self.hardware {
            hardware.stopped.try_reserve_exact(observations).map_err(io::Error::other)?;
            hardware.cgroup_observations.try_reserve_exact(observations).map_err(io::Error::other)?;
        }

        self.initial.observe().map_err(|_| Error::InitialActivation)?;
        let names = startup::names(2)?;
        if names != [PID1_NAME, PROFILE_NAME] {
            return Err(Error::Rejected);
        }
        let entries = self.initial.validated_entries().ok_or(Error::Rejected)?;
        for entry in entries {
            self.raw.push(File::from(duplicate_descriptor(entry)?));
        }
        let profile_original = self.raw.get(1).ok_or(Error::Rejected)?;
        let profile_path = std::fs::read_link(format!("/proc/self/fd/{}", profile_original.as_raw_fd()))?;
        super::profile::require_store_path(profile_path.to_str().ok_or(Error::Rejected)?)?;
        if !profile_path.to_string_lossy().ends_with("-aos-nix-offline-startup-profile-3/profile.json") {
            return Err(Error::Rejected);
        }
        self.profile_file = Some(
            RetainedImmutableFileV1::retain_with_profile(
                profile_path,
                profile_original.try_clone()?,
                None,
                1024 * 1024,
                false,
            )
            .map_err(|_| NormalRootStartupErrorV1::Image)?,
        );

        // Allocate only the extent already admitted and retained by the image owner.
        let retained_profile = self.profile_file.as_ref().ok_or(Error::Rejected)?;
        let length = usize::try_from(retained_profile.physical_identity().2)
            .map_err(|_| Error::Rejected)?;
        if length > 1024 * 1024 {
            return Err(Error::Rejected);
        }
        self.profile_bytes
            .try_reserve_exact(length)
            .map_err(io::Error::other)?;
        self.profile_bytes.resize(length, 0);

        retained_profile
            .revalidate()
            .map_err(|_| NormalRootStartupErrorV1::Image)?;
        aos_sandbox_linux::protected_file::read_exact_positioned_retaining_cause(
            profile_original,
            &mut self.profile_bytes,
        )
        .map_err(|failure| match failure {
            aos_sandbox_linux::protected_file::ExactReadFailure::Io(errno) => {
                Error::Io(io::Error::from_raw_os_error(errno.raw_os_error()))
            }
            failure => Error::Read(failure.legacy_classification()),
        })?;
        retained_profile
            .revalidate()
            .map_err(|_| NormalRootStartupErrorV1::Image)?;

        self.profile = Some(serde_json::from_slice(&self.profile_bytes).map_err(|_| Error::Rejected)?);
        let profile = self.profile.as_ref().ok_or(Error::Rejected)?;
        profile.require_mode(mode)?;
        self.pid1 = Some(images::retain_pin(
            &profile.pid1,
            Some(self.raw.first().ok_or(Error::Rejected)?.try_clone()?),
            true,
        )?);
        self.raw.push(File::open("/proc/self/exe")?);
        self.executable = Some(images::retain_pin(
            &profile.executable,
            Some(self.raw.last().ok_or(Error::Rejected)?.try_clone()?),
            true,
        )?);
        for pin in &profile.runtime_files {
            self.raw.push(File::from(rustix::fs::open(
                pin.path.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )?));
            self.runtime.push(images::retain_pin(
                pin,
                Some(self.raw.last().ok_or(Error::Rejected)?.try_clone()?),
                pin.path == profile.executable.path || pin.path == profile.loader.path,
            )?);
        }
        for pin in [
            &profile.canonical_policy,
            &profile.source_policy,
            &profile.effective_matrix,
        ] {
            self.raw.push(File::from(rustix::fs::open(
                pin.path.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )?));
            self.evidence.push(images::retain_pin(
                pin,
                Some(self.raw.last().ok_or(Error::Rejected)?.try_clone()?),
                false,
            )?);
        }
        if let Some(hardware) = &mut self.hardware {
            let selected = profile.hardware.as_ref().ok_or(Error::Rejected)?;
            hardware.helper.open_and_measure(
                selected.helper.path.clone().into(),
                Some(selected.helper.sha256),
                256 * 1024 * 1024,
                true,
            ).map_err(|_| NormalRootStartupErrorV1::Image)?;
            hardware.loader.open_and_measure(
                selected.loader.path.clone().into(),
                Some(selected.loader.sha256),
                256 * 1024 * 1024,
                true,
            ).map_err(|_| NormalRootStartupErrorV1::Image)?;
            hardware.boot = Some(File::from(rustix::fs::open(
                "/proc/sys/kernel/random/boot_id",
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )?));
            observe_hardware_boot(hardware)?;
            if mode == OfflinePrepareModeV3::Initialize {
                let initial = hardware_monotonic_nanoseconds()?;
                let deadline = initial.checked_add(300_000_000_000).ok_or(Error::Rejected)?;
                hardware.first_cut = Some((initial, deadline));
                observe_hardware_boot(hardware)?;
            }
        }
        self.policy = Some(
            VerifiedLiveSelinuxPolicy::verify(&profile.canonical_policy.path)
                .map_err(|_| NormalRootStartupErrorV1::Confinement)?,
        );
        self.process = Some(CurrentSelfPidFdCustodyV1::new());
        self.identity = Some(
            self.process
                .as_mut()
                .ok_or(Error::Rejected)?
                .capture_current()?,
        );
        self.raw.push(File::from(rustix::fs::open(
            "/sys/fs/cgroup",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?));
        let root_file = self.raw.last().ok_or(Error::Rejected)?;
        self.cgroup_mount = Some(MountId::from_fd(root_file.as_fd())?);
        self.cgroup_file_index = Some(self.raw.len() - 1);
        if mode.hardware() {
            let hardware = self.hardware.as_mut().ok_or(Error::Rejected)?;
            hardware
                .initial_cgroup
                .capture_provisioner(root_file.try_clone()?.into())?;
            let (root, anchor) = hardware
                .initial_cgroup
                .take_validated_pair()
                .ok_or(Error::Rejected)?;

            // Both owning moves are infallible; all partials and probes remain
            // on the same external startup owner before any later observation.
            self.cgroup_root = Some(root);
            self.cgroup = Some(anchor);
        } else {
            self.cgroup_root = Some(CgroupV2Root::from_owned(root_file.try_clone()?.into())?);
            self.cgroup = Some(self.cgroup_root.as_ref().ok_or(Error::Rejected)?.resolve(Path::new(CGROUP))?);
        }

        self.observe_selected()?;
        let observed = self.observed.as_ref().ok_or(Error::Rejected)?;
        self.raw.push(File::open(&observed.fragment)?);
        self.fragment = Some(
            RetainedImmutableFileV1::retain_with_profile(
                observed.fragment.clone(),
                self.raw.last().ok_or(Error::Rejected)?.try_clone()?,
                None,
                64 * 1024,
                false,
            )
            .map_err(|_| NormalRootStartupErrorV1::Image)?,
        );
        self.require_fragment()?;
        self.require_self()?;
        self.require_stopped()?;
        if mode.hardware() {
            self.credentials.admit_hardware()?;
        } else {
            self.credentials.admit()?;
        }
        self.recheck_inner()
    }

    fn recheck_inner(&mut self) -> Result<(), Error> {
        for file in self.profile_file.iter()
            .chain(&self.pid1)
            .chain(&self.executable)
            .chain(&self.fragment)
            .chain(&self.runtime)
            .chain(&self.evidence)
        {
            file.revalidate().map_err(|_| NormalRootStartupErrorV1::Image)?;
        }
        if let Some(hardware) = &mut self.hardware {
            hardware.helper.measurement()
                .and_then(RetainedImmutableFileV1::revalidate)
                .map_err(|_| NormalRootStartupErrorV1::Image)?;
            hardware.loader.measurement()
                .and_then(RetainedImmutableFileV1::revalidate)
                .map_err(|_| NormalRootStartupErrorV1::Image)?;
            observe_hardware_boot(hardware)?;
        }
        let profile = self.profile.as_ref().ok_or(Error::Rejected)?;
        self.executable.as_ref().ok_or(Error::Rejected)?
            .require_executed(std::process::id())
            .map_err(|_| NormalRootStartupErrorV1::Image)?;
        images::require_actual_mappings(&self.runtime, &[&profile.executable.path, &profile.loader.path])?;
        self.policy.ok_or(Error::Rejected)?
            .revalidate(&profile.canonical_policy.path)
            .map_err(|_| NormalRootStartupErrorV1::Confinement)?;
        self.require_self()?;
        self.observe_selected()?;
        self.require_fragment()?;
        self.require_stopped()?;
        self.credentials.recheck()?;
        self.require_stopped()?;
        self.observe_selected()?;
        self.require_self()
    }

    fn require_self(&mut self) -> Result<(), Error> {
        aos_sandbox_linux::guest_confinement::require_subject(CONTEXT)?;
        require_status(&super::read_bounded("/proc/self/status", 65_536)?)?;
        if rustix::process::getuid().as_raw() != 0
            || rustix::process::geteuid().as_raw() != 0
            || rustix::process::getgid().as_raw() != 0
            || rustix::process::getegid().as_raw() != 0
        {
            return Err(Error::Rejected);
        }
        if self.mode.is_some_and(OfflinePrepareModeV3::hardware) {
            let descriptors = rustix::process::getrlimit(rustix::process::Resource::Nofile);
            let address_space = rustix::process::getrlimit(rustix::process::Resource::As);
            if descriptors.current != Some(HARDWARE_DESCRIPTOR_LIMIT)
                || descriptors.maximum != Some(HARDWARE_DESCRIPTOR_LIMIT)
                || address_space.current != Some(HARDWARE_ADDRESS_SPACE)
                || address_space.maximum != Some(HARDWARE_ADDRESS_SPACE)
            {
                return Err(Error::Rejected);
            }
        }
        let identity = self
            .process
            .as_mut()
            .ok_or(Error::Rejected)?
            .observe_identity()?;
        if Some(identity) != self.identity {
            return Err(Error::Rejected);
        }
        let process = self
            .process
            .as_ref()
            .ok_or(Error::Rejected)?
            .pidfd()?;
        if !process.is_alive()? {
            return Err(Error::Rejected);
        }
        let info = self.cgroup.as_ref().ok_or(Error::Rejected)?.verify_exact_membership(process)?;
        let credentials = info.credentials().ok_or(Error::Rejected)?;
        if info.parent_pid() != 1
            || [
                credentials.real_user_id(),
                credentials.effective_user_id(),
                credentials.saved_user_id(),
                credentials.filesystem_user_id(),
            ] != [0; 4]
            || [
                credentials.real_group_id(),
                credentials.effective_group_id(),
                credentials.saved_group_id(),
                credentials.filesystem_group_id(),
            ] != [0; 4]
        {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    fn observe_selected(&mut self) -> Result<(), Error> {
        let mode = self.mode.ok_or(Error::Rejected)?;
        if self.flights.len() == mode.observations() {
            return Err(Error::Rejected);
        }
        let observed = if mode.hardware() {
            service::read_nix_offline_hardware_properties(HARDWARE_SERVICE_PROPERTIES)?
        } else {
            service::read_properties(UNIT, std::process::id(), SERVICE_PROPERTIES)?
        };
        self.flights.push(observed);
        let (values, unit) = self.flights.last().ok_or(Error::Rejected)?;
        let profile_path = self.profile_file.as_ref().ok_or(Error::Rejected)?.path();
        let profile = self.profile.as_ref().ok_or(Error::Rejected)?;
        require_service(
            values,
            profile_path,
            &profile.executable.path,
            self.mode.ok_or(Error::Rejected)?,
        )?;
        let observed = service::immutable_observation(service::decode_unit(unit, UNIT)?)?;
        if let Some(original) = &self.observed {
            service::require_same(original, &observed)?;
        } else {
            self.observed = Some(observed);
        }
        Ok(())
    }

    fn require_helper_original(
        &self,
        original: &aos_sandbox_linux::pidfd::PidFd,
        observations: &mut aos_sandbox_linux::pidfd::PidFdProcObservationsV1,
        before_hello: bool,
    ) -> Result<(), Error> {
        let identity = observations.observe_identity(original)?;
        let context = observations.observe_context(original)?;
        if context != HELPER_CONTEXT.as_bytes()
            && context.strip_suffix(&[0]) != Some(HELPER_CONTEXT.as_bytes())
            && context.strip_suffix(b"\n") != Some(HELPER_CONTEXT.as_bytes())
        {
            return Err(Error::Rejected);
        }
        let info = self.cgroup.as_ref().ok_or(Error::Rejected)?.verify_exact_membership(original)?;
        let credentials = info.credentials().ok_or(Error::Rejected)?;
        if info.parent_pid() != std::process::id()
            || [
                credentials.real_user_id(),
                credentials.effective_user_id(),
                credentials.saved_user_id(),
                credentials.filesystem_user_id(),
            ] != [0; 4]
            || [
                credentials.real_group_id(),
                credentials.effective_group_id(),
                credentials.saved_group_id(),
                credentials.filesystem_group_id(),
            ] != [0; 4]
        {
            return Err(Error::Rejected);
        }
        let hardware = self.hardware.as_ref().ok_or(Error::Rejected)?;
        let helper = hardware.helper.measurement().map_err(|_| NormalRootStartupErrorV1::Image)?;
        let loader = hardware.loader.measurement().map_err(|_| NormalRootStartupErrorV1::Image)?;
        if !helper.matches_nix_offline_executed_original_v5(original, observations)? {
            return Err(Error::Rejected);
        }
        if before_hello {
            let maps = std::str::from_utf8(observations.nix_offline_helper_maps_v1()?)
                .map_err(|_| Error::Rejected)?;
            if !loader.mapped_in_helper_data_v5(maps).map_err(|_| NormalRootStartupErrorV1::Image)? {
                return Err(Error::Rejected);
            }
        }
        require_status_recipe(observations.observe_nix_offline_helper_status_v1(original)?, true)?;
        helper.revalidate().map_err(|_| NormalRootStartupErrorV1::Image)?;
        loader.revalidate().map_err(|_| NormalRootStartupErrorV1::Image)?;
        if observations.observe_identity(original)? != identity || !original.is_alive()? {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    fn require_fragment(&self) -> Result<(), Error> {
        let file = self.fragment.as_ref().ok_or(Error::Rejected)?;
        let bytes = file.read_bounded().map_err(|_| NormalRootStartupErrorV1::Service)?;
        let path = self.profile_file.as_ref().ok_or(Error::Rejected)?.path();
        let normalized = normalized_unit(&bytes, path)?;
        if <[u8; 32]>::from(Sha256::digest(&normalized))
            != self.profile.as_ref().ok_or(Error::Rejected)?.unit_sha256
        {
            return Err(Error::Rejected);
        }
        if let Some(hardware) = &self.profile.as_ref().ok_or(Error::Rejected)?.hardware {
            let mode = self.mode.filter(|mode| mode.hardware()).ok_or(Error::Rejected)?;
            let executable = &self.profile.as_ref().ok_or(Error::Rejected)?.executable.path;
            let neutral = hardware_mode_neutral_unit(&normalized, executable, mode)?;
            if <[u8; 32]>::from(Sha256::digest(&neutral)) != hardware.unit_mode_neutral_sha256 {
                return Err(Error::Rejected);
            }
        }
        Ok(())
    }

    fn require_stopped(&mut self) -> Result<(), Error> {
        if self.mode.is_some_and(OfflinePrepareModeV3::hardware) {
            return self.require_hardware_stopped();
        }
        if self.stopped.len() == MAXIMUM_OBSERVATIONS {
            return Err(Error::Rejected);
        }
        let observed = std::thread::Builder::new()
            .name("nix-offline-stopped-readback".to_owned())
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                runtime.block_on(async {
                    tokio::time::timeout(Duration::from_secs(5), async {
                        SystemdClient::connect().await?
                            .observe_fixed_stopped_nix_units_v3().await
                    })
                    .await
                    .map_err(io::Error::other)?
                    .map_err(io::Error::other)
                })
            })?
            .join()
            .map_err(|_| Error::Rejected)??;
        self.stopped.push(observed);
        if self.stopped.first() != self.stopped.last() {
            return Err(Error::Rejected);
        }
        for ((values, unit), relative) in self.stopped.last().ok_or(Error::Rejected)?
            .iter().zip(RUNTIME_CGROUPS)
        {
            let [cgroup, _, pre, post] = values.as_slice() else {
                return Err(Error::Rejected);
            };
            let actual = <&str>::try_from(cgroup).map_err(|_| Error::Rejected)?;
            if !actual.is_empty() && actual != format!("/{relative}") {
                return Err(Error::Rejected);
            }
            for empty in [pre, post] {
                if !matches!(&**empty, Value::Array(commands) if commands.is_empty()) {
                    return Err(Error::Rejected);
                }
            }
            let [fragment, drop_ins, transient, _] = unit.as_slice() else {
                return Err(Error::Rejected);
            };
            if !matches!(&**drop_ins, Value::Array(paths) if paths.is_empty())
                || bool::try_from(transient).ok() != Some(false)
            {
                return Err(Error::Rejected);
            }
            let fragment = <&str>::try_from(fragment).map_err(|_| Error::Rejected)?;
            let path = std::fs::canonicalize(fragment)?;
            super::profile::require_store_path(path.to_str().ok_or(Error::Rejected)?)?;
            self.raw.push(File::from(rustix::fs::open(
                path.as_path(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )?));
            self.evidence.push(RetainedImmutableFileV1::retain_with_profile(
                path,
                self.raw.last().ok_or(Error::Rejected)?.try_clone()?,
                None,
                64 * 1024,
                false,
            ).map_err(|_| NormalRootStartupErrorV1::Image)?);
        }
        let root_index = self.cgroup_file_index.ok_or(Error::Rejected)?;
        if Some(MountId::from_fd(self.raw.get(root_index).ok_or(Error::Rejected)?.as_fd())?)
            != self.cgroup_mount
        {
            return Err(Error::Rejected);
        }
        for relative in RUNTIME_CGROUPS {
            match rustix::fs::openat2(
                self.raw.get(root_index).ok_or(Error::Rejected)?,
                relative,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                rustix::fs::ResolveFlags::BENEATH | rustix::fs::ResolveFlags::NO_SYMLINKS
                    | rustix::fs::ResolveFlags::NO_MAGICLINKS,
            ) {
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(error.into()),
                Ok(file) => {
                    self.raw.push(File::from(file));
                    self.runtime_anchors.push(
                        self.cgroup_root.as_ref().ok_or(Error::Rejected)?.resolve(Path::new(relative))?,
                    );
                    let anchor = self.runtime_anchors.last().ok_or(Error::Rejected)?;
                    if anchor.population_monitor()?.state()? != CgroupPopulationState::Empty {
                        return Err(Error::Rejected);
                    }
                    anchor.validate_active()?;
                }
            }
        }
        let root_file = self.raw.get(root_index).ok_or(Error::Rejected)?;
        if Some(MountId::from_fd(root_file.as_fd())?) != self.cgroup_mount {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    fn require_hardware_stopped(&mut self) -> Result<(), Error> {
        let maximum = self.mode.ok_or(Error::Rejected)?.observations();
        let hardware = self.hardware.as_mut().ok_or(Error::Rejected)?;
        if hardware.stopped.len() == maximum {
            return Err(Error::Rejected);
        }
        hardware.stopped.push(aos_systemd::NixOfflineAbsenceObservationV5::new());
        let observation = hardware.stopped.last_mut().ok_or(Error::Rejected)?;

        // The thread borrows resident slots. Neither an actual reader error nor
        // an unwind can destroy already-returned property or absence originals.
        let observed = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("nix-offline-hardware-stopped".to_owned())
                .spawn_scoped(scope, || -> Result<bool, io::Error> {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    runtime.block_on(async {
                        let client = SystemdClient::connect_nix_offline_hardware_observer()
                            .await
                            .map_err(io::Error::other)?;
                        tokio::time::timeout(
                            Duration::from_secs(5),
                            client.observe_fixed_offline_nix_units_v5(observation),
                        )
                        .await
                        .map(|result| result.is_ok())
                        .map_err(io::Error::other)
                    })
                })
                .map(|handle| handle.join())
        });
        match observed {
            Ok(Ok(Ok(true))) => {}
            Ok(Ok(Ok(false))) => return Err(Error::HardwareRuntime),
            Ok(Ok(Err(error))) | Err(error) => {
                hardware.thread_failure = Some(error);
                return Err(Error::HardwareRuntime);
            }
            Ok(Err(payload)) => {
                hardware.unwind = Some(payload);
                return Err(Error::HardwareRuntime);
            }
        }
        let observation = hardware.stopped.last().ok_or(Error::Rejected)?;
        let (controller, owner) = observation.properties().map_err(|_| Error::HardwareRuntime)?;
        for (observed, relative) in [(Some(controller), RUNTIME_CGROUPS[0]), (owner, RUNTIME_CGROUPS[1])] {
            let Some((values, unit)) = observed else {
                continue;
            };
            let [cgroup, _, pre, post] = values.as_slice() else {
                return Err(Error::Rejected);
            };
            let actual = <&str>::try_from(cgroup).map_err(|_| Error::Rejected)?;
            if !actual.is_empty() && actual != format!("/{relative}") {
                return Err(Error::Rejected);
            }
            for empty in [pre, post] {
                if !matches!(&**empty, Value::Array(commands) if commands.is_empty()) {
                    return Err(Error::Rejected);
                }
            }
            let [fragment, drop_ins, transient, _] = unit.as_slice() else {
                return Err(Error::Rejected);
            };
            if !matches!(&**drop_ins, Value::Array(paths) if paths.is_empty())
                || bool::try_from(transient).ok() != Some(false)
            {
                return Err(Error::Rejected);
            }
            let fragment = <&str>::try_from(fragment).map_err(|_| Error::Rejected)?;
            let path = std::fs::canonicalize(fragment)?;
            super::profile::require_store_path(path.to_str().ok_or(Error::Rejected)?)?;
            self.raw.push(File::from(rustix::fs::open(
                path.as_path(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )?));
            self.evidence.push(RetainedImmutableFileV1::retain_with_profile(
                path,
                self.raw.last().ok_or(Error::Rejected)?.try_clone()?,
                None,
                64 * 1024,
                false,
            ).map_err(|_| NormalRootStartupErrorV1::Image)?);
        }

        let root_index = self.cgroup_file_index.ok_or(Error::Rejected)?;
        let root_file = self.raw.get(root_index).ok_or(Error::Rejected)?;
        if Some(MountId::from_fd(root_file.as_fd())?) != self.cgroup_mount {
            return Err(Error::Rejected);
        }
        hardware.cgroup_observations.push(std::array::from_fn(|_| Default::default()));
        let pair = hardware.cgroup_observations.last_mut().ok_or(Error::Rejected)?;
        let root = self.cgroup_root.as_ref().ok_or(Error::Rejected)?;
        pair[0].capture_controller(root).map_err(|_| Error::HardwareRuntime)?;
        pair[1].capture_nix_owner(root).map_err(|_| Error::HardwareRuntime)?;
        for observed in pair {
            if observed.population() != Some(CgroupPopulationState::Empty)
                && observed.absence().is_none()
            {
                return Err(Error::Rejected);
            }
        }
        let root_file = self.raw.get(root_index).ok_or(Error::Rejected)?;
        if Some(MountId::from_fd(root_file.as_fd())?) != self.cgroup_mount {
            return Err(Error::Rejected);
        }
        Ok(())
    }
}

impl Default for OfflineNixPrepareStartupV3 {
    fn default() -> Self {
        Self::new()
    }
}

/// Borrows actual admitted startup in its retained, closed offline mode.
///
/// The external startup owns originals and typed failures for the full loan.
/// This neither approves generated candidates nor establishes a TPM floor.
pub struct OfflineNixPrepareOriginV3<'startup> {
    startup: &'startup mut OfflineNixPrepareStartupV3,
}

impl OfflineNixPrepareOriginV3<'_> {
    /// Rechecks this same externally retained genuine startup.
    ///
    /// # Errors
    /// Returns its resident first cause and permanently fences a failed observation.
    pub fn recheck(&mut self) -> Result<(), &Error> {
        self.startup.recheck()
    }

    /// Rechecks only the genuine original selected for static inspection.
    ///
    /// # Errors
    /// Returns the resident startup cause or fences a wrong-mode, failed or
    /// interrupted loan. A prepare-mode loan never passes this observation.
    pub fn recheck_inspection(&mut self) -> Result<(), &Error> {
        self.startup.recheck_inspection()
    }

    /// Copies only the independently delivered public node and approval originals.
    ///
    /// # Errors
    /// Rejects an interrupted or failed owner; secret or approval-signing bytes
    /// are never supplied by either closed offline mode.
    pub fn public_originals(&self) -> Result<([u8; 16], [u8; 48]), Error> {
        if !self.startup.usable {
            return Err(Error::Fenced);
        }
        let (node, approval) = self.startup.credentials.public_originals()?;
        let node = node.try_into().map_err(|_| Error::Rejected)?;
        let approval = approval.try_into().map_err(|_| Error::Rejected)?;
        Ok((node, approval))
    }
}

/// Lends the actual hardware-selected original startup without owning it twice.
///
/// The external resident startup owns all files, partial observations and
/// failures. This loan cannot be constructed from fields or establish native
/// job approval, TPM initialization, a session floor or process destruction.
pub struct OfflineNixHardwareOriginV5<'startup> {
    startup: &'startup mut OfflineNixPrepareStartupV3,
}

impl OfflineNixHardwareOriginV5<'_> {
    /// Rechecks this same selected hardware startup without renewing its mode.
    ///
    /// # Errors
    /// Returns the original resident cause; a failed or interrupted observation
    /// fences this owner. No replacement credential or startup is admitted.
    pub fn recheck(&mut self) -> Result<(), &Error> {
        let Some(mode) = self.startup.mode.filter(|mode| mode.hardware()) else {
            return self.startup.refuse();
        };
        self.startup.recheck_mode(mode)
    }

    /// Borrows the independently delivered original public node and approval key.
    ///
    /// # Errors
    /// Refuses a closed owner or incomplete original delivery. Secret hierarchy
    /// authorization bytes are not exposed by this public DATA readback.
    pub fn public_originals(&self) -> Result<([u8; 16], [u8; 48]), Error> {
        if !self.startup.usable {
            return Err(Error::Fenced);
        }
        let (node, approval) = self.startup.credentials.public_originals()?;
        Ok((
            node.try_into().map_err(|_| Error::Rejected)?,
            approval.try_into().map_err(|_| Error::Rejected)?,
        ))
    }

    /// Borrows the canonical domain credential retained at original admission.
    ///
    /// # Errors
    /// Refuses a closed owner or incomplete independently delivered domain.
    /// The returned bytes remain DATA, not a current policy or provisioning pin.
    pub fn domain_original(&self) -> Result<&[u8], Error> {
        if !self.startup.usable {
            return Err(Error::Fenced);
        }
        self.startup.credentials.hardware_domain_original().map_err(Error::Io)
    }

    /// Returns the original kernel boot identity from the same retained proc file.
    ///
    /// # Errors
    /// Refuses a closed owner or incomplete boot observation. The native owner
    /// must bind this DATA to its original admission and immutable cutoff.
    pub fn original_boot(&self) -> Result<[u8; 16], Error> {
        if !self.startup.usable {
            return Err(Error::Fenced);
        }
        self.startup.hardware.as_ref()
            .and_then(|hardware| hardware.boot_original)
            .ok_or(Error::Rejected)
    }

    /// Borrows the actual measured helper and loader originals before HELLO.
    ///
    /// # Errors
    /// Refuses a closed owner or incomplete measurements. These immutable files
    /// do not by themselves admit the child's executed image or loader maps.
    pub fn helper_originals(
        &self,
    ) -> Result<(&RetainedImmutableFileV1, &RetainedImmutableFileV1), Error> {
        if !self.startup.usable {
            return Err(Error::Fenced);
        }
        let hardware = self.startup.hardware.as_ref().ok_or(Error::Rejected)?;
        Ok((
            hardware.helper.measurement().map_err(|_| NormalRootStartupErrorV1::Image)?,
            hardware.loader.measurement().map_err(|_| NormalRootStartupErrorV1::Image)?,
        ))
    }

    pub(crate) fn hierarchy_original(&self) -> Result<&[u8; 32], Error> {
        if !self.startup.usable {
            return Err(Error::Fenced);
        }
        self.startup.credentials.hardware_auth_original().map_err(Error::Io)
    }

    pub(crate) fn recovery(&self) -> bool {
        self.startup.mode == Some(OfflinePrepareModeV3::Recover)
    }

    pub(crate) fn initial_cut(&self) -> Result<Option<(u64, u64)>, Error> {
        if !self.startup.usable {
            return Err(Error::Fenced);
        }
        Ok(self.startup.hardware.as_ref().ok_or(Error::Rejected)?.first_cut)
    }

    pub(crate) fn profile_original(&self) -> Result<&RetainedImmutableFileV1, Error> {
        if !self.startup.usable {
            return Err(Error::Fenced);
        }
        self.startup.profile_file.as_ref().ok_or(Error::Rejected)
    }

    pub(crate) fn profile_original_bytes(&self) -> Result<&[u8], Error> {
        if !self.startup.usable {
            return Err(Error::Fenced);
        }
        Ok(&self.startup.profile_bytes)
    }

    pub(crate) fn first_failure(&self) -> Option<&Error> {
        self.startup.failure()
    }

    pub(crate) fn observation_time(&self) -> Result<u64, Error> {
        if !self.startup.usable {
            return Err(Error::Fenced);
        }
        hardware_monotonic_nanoseconds()
    }

    pub(crate) fn require_initialize_profile(&self, original: &[u8]) -> Result<(), Error> {
        if !self.startup.usable || !self.recovery() || original.len() > 1024 * 1024 {
            return Err(Error::Fenced);
        }
        let admitted: Profile = serde_json::from_slice(original).map_err(|_| Error::Rejected)?;
        admitted.require_mode(OfflinePrepareModeV3::Initialize)?;
        let current = self.startup.profile.as_ref().ok_or(Error::Rejected)?;
        let old_hardware = admitted.hardware.as_ref().ok_or(Error::Rejected)?;
        let new_hardware = current.hardware.as_ref().ok_or(Error::Rejected)?;
        if old_hardware.unit_mode_neutral_sha256 != new_hardware.unit_mode_neutral_sha256 {
            return Err(Error::Rejected);
        }

        // Both full invocation hashes were admitted separately. No other field
        // may change, including helper/loader, delivery, limits or policy pins.
        let old: serde_json::Value = serde_json::from_slice(original).map_err(|_| Error::Rejected)?;
        let mut selected: serde_json::Value = serde_json::from_slice(&self.startup.profile_bytes)
            .map_err(|_| Error::Rejected)?;
        *selected.get_mut("unit_sha256").ok_or(Error::Rejected)? =
            old.get("unit_sha256").ok_or(Error::Rejected)?.clone();
        if selected != old {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    pub(crate) fn compiled_contract(&self) -> Result<[u8; 32], Error> {
        if !self.startup.usable {
            return Err(Error::Fenced);
        }
        self.startup.profile.as_ref()
            .and_then(|profile| profile.hardware.as_ref())
            .map(|hardware| hardware.compiled_contract_sha256)
            .ok_or(Error::Rejected)
    }

    pub(crate) fn require_helper_before_hello(
        &mut self,
        original: &aos_sandbox_linux::pidfd::PidFd,
        observations: &mut aos_sandbox_linux::pidfd::PidFdProcObservationsV1,
    ) -> Result<(), &Error> {
        self.require_helper(original, observations, true)
    }

    pub(crate) fn require_helper_continued(
        &mut self,
        original: &aos_sandbox_linux::pidfd::PidFd,
        observations: &mut aos_sandbox_linux::pidfd::PidFdProcObservationsV1,
    ) -> Result<(), &Error> {
        self.require_helper(original, observations, false)
    }

    fn require_helper(
        &mut self,
        original: &aos_sandbox_linux::pidfd::PidFd,
        observations: &mut aos_sandbox_linux::pidfd::PidFdProcObservationsV1,
        before_hello: bool,
    ) -> Result<(), &Error> {
        if !self.startup.usable {
            return self.startup.refuse();
        }
        self.startup.usable = false;
        let result = self.startup.require_helper_original(original, observations, before_hello);
        self.startup.complete(result)
    }
}

fn observe_hardware_boot(hardware: &mut HardwareStartupV5) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt as _;

    let file = hardware.boot.as_ref().ok_or(Error::Rejected)?;
    let metadata = file.metadata()?;
    let filesystem = rustix::fs::fstatfs(file)?;
    let flags = rustix::fs::fcntl_getfl(file)?;
    let identity = (metadata.dev(), metadata.ino(), MountId::from_fd(file.as_fd())?);
    if !metadata.is_file()
        || filesystem.f_type as u64 != 0x9fa0
        || flags & OFlags::ACCMODE != OFlags::RDONLY
        || flags.contains(OFlags::PATH)
        || hardware.boot_identity.is_some_and(|original| original != identity)
    {
        return Err(Error::Rejected);
    }
    hardware.boot_identity = Some(identity);
    aos_sandbox_linux::protected_file::read_exact_positioned_retaining_cause(
        file,
        &mut hardware.boot_bytes,
    ).map_err(|failure| match failure {
        aos_sandbox_linux::protected_file::ExactReadFailure::Io(errno) => {
            Error::Io(io::Error::from_raw_os_error(errno.raw_os_error()))
        }
        failure => Error::Read(failure.legacy_classification()),
    })?;
    let current = aos_sandbox_linux::boot::KernelBootId::parse(&hardware.boot_bytes)?.into_bytes();
    if hardware.boot_original.is_some_and(|original| original != current) {
        return Err(Error::Rejected);
    }
    hardware.boot_original = Some(current);
    Ok(())
}

pub(crate) fn hardware_monotonic_nanoseconds() -> Result<u64, Error> {
    let observed = rustix::time::clock_gettime_dynamic(
        rustix::time::DynamicClockId::Known(rustix::time::ClockId::Monotonic),
    )?;
    let seconds = u64::try_from(observed.tv_sec).map_err(|_| Error::Rejected)?;
    let nanos = u64::try_from(observed.tv_nsec).map_err(|_| Error::Rejected)?;
    if nanos >= 1_000_000_000 {
        return Err(Error::Rejected);
    }
    seconds.checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(nanos))
        .ok_or(Error::Rejected)
}

fn require_status(bytes: &[u8]) -> Result<(), Error> {
    require_status_recipe(bytes, false)
}

fn require_status_recipe(bytes: &[u8], helper: bool) -> Result<(), Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Rejected)?;
    for (name, expected) in [
        ("CapInh", 0),
        ("CapPrm", if helper { 0 } else { 3 }),
        ("CapEff", if helper { 0 } else { 3 }),
        ("CapBnd", 3),
        ("CapAmb", 0),
        ("NoNewPrivs", 1),
    ] {
        let prefix = format!("{name}:");
        let mut values = text.lines().filter_map(|line| line.strip_prefix(&prefix));
        let value = values.next().ok_or(Error::Rejected)?.trim();
        let actual = if name == "NoNewPrivs" {
            value.parse::<u64>().ok()
        } else {
            (value.len() == 16)
                .then(|| u64::from_str_radix(value, 16).ok())
                .flatten()
        };
        if values.next().is_some() || actual != Some(expected) {
            return Err(Error::Rejected);
        }
    }
    Ok(())
}

fn require_service(
    values: &[OwnedValue],
    profile: &Path,
    executable: &str,
    mode: OfflinePrepareModeV3,
) -> Result<(), Error> {
    let values = if mode.hardware() {
        let (original, limits) = values.split_at_checked(SERVICE_PROPERTIES.len())
            .ok_or(Error::Rejected)?;
        let [descriptors, descriptor_soft, address_space, address_space_soft] = limits else {
            return Err(Error::Rejected);
        };
        if u64::try_from(descriptors).ok() != Some(HARDWARE_DESCRIPTOR_LIMIT)
            || u64::try_from(descriptor_soft).ok() != Some(HARDWARE_DESCRIPTOR_LIMIT)
            || u64::try_from(address_space).ok() != Some(HARDWARE_ADDRESS_SPACE)
            || u64::try_from(address_space_soft).ok() != Some(HARDWARE_ADDRESS_SPACE)
        {
            return Err(Error::Rejected);
        }
        original
    } else {
        values
    };
    let [
        cgroup, files, extras, maximum, stored, context, bounding, ambient, nnp,
        securebits, start, pre, post, credentials, encrypted, set, set_encrypted,
        imported, imported_ex, exit_type, kill_mode, timeout,
    ] = values else {
        return Err(Error::Rejected);
    };
    if <&str>::try_from(cgroup).ok() != Some(format!("/{CGROUP}").as_str())
        || systemd_property_data::explicit_context(context) != Some(CONTEXT)
        || u32::try_from(maximum).ok() != Some(0)
        || u32::try_from(stored).ok() != Some(0)
        || u64::try_from(bounding).ok() != Some(3)
        || u64::try_from(ambient).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true)
        || i32::try_from(securebits).ok() != Some(12)
        || <&str>::try_from(exit_type).ok() != Some("cgroup")
        || <&str>::try_from(kill_mode).ok() != Some("control-group")
        || u64::try_from(timeout).ok() != Some(u64::MAX)
    {
        return Err(Error::Rejected);
    }
    for empty in [pre, post, encrypted, set, set_encrypted, imported, imported_ex] {
        if !matches!(&**empty, Value::Array(array) if array.is_empty()) {
            return Err(Error::Rejected);
        }
    }
    let command = systemd_property_data::single_exec_start(start).ok_or(Error::Rejected)?;
    if command.path != executable
        || command.pid != std::process::id()
        || command.argv.len() != 2
        || !matches!(command.argv.first(), Some(Value::Str(value)) if value.as_str() == executable)
        || !matches!(command.argv.get(1), Some(Value::Str(value)) if value.as_str() == mode.command())
    {
        return Err(Error::Rejected);
    }
    let expected_files = [
        ("/proc/1/exe", PID1_NAME),
        (profile.to_str().ok_or(Error::Rejected)?, PROFILE_NAME),
    ];
    let Value::Array(files) = &**files else {
        return Err(Error::Rejected);
    };
    let Value::Array(extras) = &**extras else {
        return Err(Error::Rejected);
    };
    if files.len() != 2
        || !extras.is_empty()
        || extras.element_signature() != Value::from("").value_signature()
    {
        return Err(Error::Rejected);
    }
    for (index, (path, name)) in expected_files.iter().enumerate() {
        let Some(Value::Structure(entry)) = files.inner().get(index) else {
            return Err(Error::Rejected);
        };
        let [Value::Str(actual_path), Value::Str(actual_name), Value::U64(flags)] = entry.fields() else {
            return Err(Error::Rejected);
        };
        if actual_path.as_str() != *path || actual_name.as_str() != *name || *flags != 1 {
            return Err(Error::Rejected);
        }
    }
    let Value::Array(credentials) = &**credentials else {
        return Err(Error::Rejected);
    };
    let ordinary = [
        ("node-id", "/etc/credstore/node-id"),
        (
            "nix-floor-provision-approval-public-key-v3",
            "/etc/credstore/nix-floor-provision-approval-public-key-v3",
        ),
    ];
    let hardware = [
        ordinary[0],
        ordinary[1],
        ("nix-fixed-domain-pins-v2", "/etc/credstore/nix-fixed-domain-pins-v2"),
        ("nix-floor-owner-hierarchy-auth-v4", "/etc/credstore/nix-floor-owner-hierarchy-auth-v4"),
    ];
    let expected = if mode.hardware() { hardware.as_slice() } else { ordinary.as_slice() };
    if credentials.len() != expected.len() {
        return Err(Error::Rejected);
    }
    for (entry, &(name, source)) in credentials.inner().iter().zip(expected) {
        let Value::Structure(entry) = entry else {
            return Err(Error::Rejected);
        };
        let [Value::Str(actual_name), Value::Str(actual_source)] = entry.fields() else {
            return Err(Error::Rejected);
        };
        if actual_name.as_str() != name || actual_source.as_str() != source {
            return Err(Error::Rejected);
        }
    }
    Ok(())
}

fn normalized_unit(bytes: &[u8], profile: &Path) -> Result<Vec<u8>, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Rejected)?;
    let actual = format!(
        "OpenFile={}:{}:read-only\n",
        profile.to_str().ok_or(Error::Rejected)?,
        PROFILE_NAME,
    );
    let replacement = format!("OpenFile={PLACEHOLDER}:{PROFILE_NAME}:read-only\n");
    if text.split_inclusive('\n').filter(|line| *line == actual).count() != 1 {
        return Err(Error::Rejected);
    }
    Ok(text.split_inclusive('\n')
        .map(|line| {
            if line == actual {
                replacement.as_str()
            } else {
                line
            }
        })
        .collect::<String>()
        .into_bytes())
}

// Only the independently checked hardware command may differ across Recovery.
// Full-unit comparison remains mandatory before this narrower comparison.
fn hardware_mode_neutral_unit(
    bytes: &[u8],
    executable: &str,
    mode: OfflinePrepareModeV3,
) -> Result<Vec<u8>, Error> {
    if !mode.hardware() {
        return Err(Error::Rejected);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Rejected)?;
    let actual = format!("ExecStart={executable} {}\n", mode.command());
    let mut commands = text.split_inclusive('\n')
        .filter(|line| line.starts_with("ExecStart="));
    if commands.next() != Some(actual.as_str()) || commands.next().is_some() {
        return Err(Error::Rejected);
    }

    Ok(text.split_inclusive('\n')
        .map(|line| {
            if line == actual {
                "ExecStart=@AOS_NIX_OFFLINE_HARDWARE_COMMAND@\n"
            } else {
                line
            }
        })
        .collect::<String>()
        .into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_modes_have_only_the_two_literal_commands() {
        assert_eq!(
            OfflinePrepareModeV3::PrepareKeys.command(),
            "prepare-keys",
        );
        assert_eq!(
            OfflinePrepareModeV3::InspectApprovedJob.command(),
            "inspect-approved-job",
        );
        assert_ne!(
            OfflinePrepareModeV3::PrepareKeys,
            OfflinePrepareModeV3::InspectApprovedJob,
        );
    }

    #[test]
    fn interrupted_inspection_cannot_make_either_origin_loan() {
        let mut resident = OfflineNixPrepareStartupV3::new();
        resident.attempted = true;
        resident.mode = Some(OfflinePrepareModeV3::InspectApprovedJob);

        assert!(resident.capture_and_admit_inspection().is_err());
        assert!(resident.borrow_inspection().is_err());
        assert!(resident.borrow_original().is_err());
        assert!(matches!(resident.failure(), Some(Error::Fenced)));
    }

    #[test]
    fn prepare_status_accepts_only_the_two_administrative_capabilities() {
        let exact = concat!(
            "CapInh:\t0000000000000000\n",
            "CapPrm:\t0000000000000003\n",
            "CapEff:\t0000000000000003\n",
            "CapBnd:\t0000000000000003\n",
            "CapAmb:\t0000000000000000\n",
            "NoNewPrivs:\t1\n",
        );
        assert!(require_status(exact.as_bytes()).is_ok());

        assert!(require_status(
            exact.replace("0000000000000003", "00000000000000c0").as_bytes(),
        ).is_err());
        assert!(require_status(
            exact.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0").as_bytes(),
        ).is_err());
        assert!(require_status(
            format!("{exact}CapEff:\t0000000000000003\n").as_bytes(),
        ).is_err());
    }

    #[test]
    fn only_one_profile_self_reference_is_normalized() {
        let path = Path::new(concat!(
            "/nix/store/00000000000000000000000000000000-",
            "aos-nix-offline-startup-profile-3/profile.json",
        ));
        let line = format!("OpenFile={}:{}:read-only\n", path.display(), PROFILE_NAME);
        let input = format!("[Service]\n{line}ExecStart=/fixed prepare-keys\n");

        let normalized = normalized_unit(input.as_bytes(), path).unwrap();
        assert!(std::str::from_utf8(&normalized).unwrap().contains(PLACEHOLDER));
        assert!(normalized_unit(format!("{input}{line}").as_bytes(), path).is_err());
        assert!(normalized_unit(b"[Service]\n", path).is_err());
    }

    #[test]
    fn hardware_neutral_comparison_changes_only_the_exact_command() {
        let executable = "/nix/store/original/bin/aos-sandbox-nix-floor-provision";
        let initialize = format!("[Service]\nExecStart={executable} initialize\nLimitNOFILE=4096\n");
        let recover = initialize.replace(" initialize\n", " recover\n");
        let original = hardware_mode_neutral_unit(
            initialize.as_bytes(), executable, OfflinePrepareModeV3::Initialize,
        ).unwrap();

        assert_eq!(original, hardware_mode_neutral_unit(
            recover.as_bytes(), executable, OfflinePrepareModeV3::Recover,
        ).unwrap());
        assert_ne!(original, hardware_mode_neutral_unit(
            recover.replace("4096", "8192").as_bytes(),
            executable, OfflinePrepareModeV3::Recover,
        ).unwrap());
        for invalid in [
            initialize.replace(" initialize", " recover"),
            initialize.replace(" initialize", "  initialize"),
            initialize.replace(executable, "/different"),
            format!("{initialize}ExecStart={executable} initialize\n"),
            format!("[Service]\nExecStart={executable} initialize"),
            "[Service]\n".to_owned(),
        ] {
            assert!(hardware_mode_neutral_unit(
                invalid.as_bytes(), executable, OfflinePrepareModeV3::Initialize,
            ).is_err());
        }
        assert!(hardware_mode_neutral_unit(
            initialize.as_bytes(), executable, OfflinePrepareModeV3::PrepareKeys,
        ).is_err());
    }

    #[test]
    fn interrupted_empty_startup_cannot_make_an_origin_loan() {
        let mut resident = OfflineNixPrepareStartupV3::new();
        resident.attempted = true;

        assert!(resident.capture_and_admit().is_err());
        assert!(resident.borrow_original().is_err());
        assert!(matches!(resident.failure(), Some(Error::Fenced)));
    }

    #[test]
    fn outer_prepare_failure_fences_resident_self_slots_and_retains_cause() {
        let mut resident = OfflineNixPrepareStartupV3::new();
        resident.process = Some(CurrentSelfPidFdCustodyV1::new());
        let result = resident.complete(Err(Error::Linux(
            aos_sandbox_linux::Error::WrongDescriptorType {
                expected: "pure failure sentinel",
            },
        )));

        assert!(matches!(
            result,
            Err(Error::Linux(
                aos_sandbox_linux::Error::WrongDescriptorType {
                    expected: "pure failure sentinel",
                },
            )),
        ));
        assert!(resident.process.as_ref().unwrap().pidfd().is_err());
        assert!(
            resident.process.as_mut().unwrap().capture_current().is_err(),
        );
        assert!(matches!(
            resident.failure(),
            Some(Error::Linux(
                aos_sandbox_linux::Error::WrongDescriptorType {
                    expected: "pure failure sentinel",
                },
            )),
        ));
    }
}
