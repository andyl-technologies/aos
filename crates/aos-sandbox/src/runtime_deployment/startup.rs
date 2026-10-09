//! Captures the deployment publisher's one original PID1 activation table.
//!
//! The profile is bounded immutable image DATA, not a transferable grant.
//! Admission retains original PID1 and profile OpenFiles, verifies the actual
//! executable/loader mappings and enforcing policy, and joins genuine fixed
//! unit readback to the retained process. There is no empty legacy admission.
//!
//! ```text
//! AOS_RUNTIME_DEPLOYMENT_STARTUP_1: fixed unit/context + image pins +
//! runtime closure + canonical/source/effective policy pins + normalized unit SHA256
//! ```

use std::fs::File;
use std::io::Read as _;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};

use aos_sandbox_linux::guest_confinement::require_subject;
use aos_sandbox_linux::inherited_fd::duplicate_initial_activation_table;
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcessIdentity};
use aos_sandbox_linux::selinux_policy::VerifiedLiveSelinuxPolicy;
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::immutable_image::{RetainedImmutableFileV1, require_readonly_launch_flags};

use super::service_policy::RetainedDeploymentServicePolicyV1;
use super::invocation::HostPhysicalInvocationStateV1;
use super::{
    HELPER_CONTEXT, LISTENER_FD_NAME, OWNER_CONTEXT, PID1_FD_NAME, PROFILE_FD_NAME, SOCKET_PATH,
    UNIT, RuntimeDeploymentStartupErrorV1, DeploymentAdmissionModeV2,
};

const MAXIMUM_PROFILE_BYTES: usize = 1024 * 1024;
const MAXIMUM_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_RUNTIME_FILES: usize = 512;
const PROFILE_SUFFIX: &str = "-aos-runtime-deployment-startup-profile-1/profile.json";
pub(super) const STORAGE_UNIT_V2: &str = "aos-storaged.service";
pub(super) const STORAGE_CONTEXT_V2: &str = "system_u:system_r:aos_sandbox_storage_t";
pub(super) const STORAGE_CGROUP_V2: &str = "/aos.slice/aos-control.slice/aos-storaged.service";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImagePinV1 {
    path: String,
    sha256: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeDeploymentProfileV1 {
    format: String,
    unit: String,
    owner_context: String,
    helper_context: String,
    executable: ImagePinV1,
    pid1: ImagePinV1,
    loader: ImagePinV1,
    runtime_files: Vec<ImagePinV1>,
    closure_roots: Vec<String>,
    canonical_policy: ImagePinV1,
    source_policy: ImagePinV1,
    effective_matrix: ImagePinV1,
    unit_sha256: [u8; 32],
}

/// Separates selected profile grammar from the literal ordinary serde schema.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CanaryRuntimeDeploymentProfileV2 {
    format: String,
    publisher: RuntimeDeploymentProfileV1,
    canary_storage: ImagePinV1,
}

impl RuntimeDeploymentProfileV1 {
    fn decode(bytes: &[u8]) -> Result<Self, RuntimeDeploymentStartupErrorV1> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_PROFILE_BYTES {
            return Err(RuntimeDeploymentStartupErrorV1::Profile);
        }
        let profile: Self = serde_json::from_slice(bytes)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Profile)?;
        Self::validate(profile)
    }

    fn validate(profile: Self) -> Result<Self, RuntimeDeploymentStartupErrorV1> {
        if profile.format != "AOS_RUNTIME_DEPLOYMENT_STARTUP_1"
            || profile.unit != UNIT
            || profile.owner_context != OWNER_CONTEXT
            || profile.helper_context != HELPER_CONTEXT
            || profile.unit_sha256 == [0; 32]
            || profile.runtime_files.is_empty()
            || profile.runtime_files.len() > MAXIMUM_RUNTIME_FILES
            || profile.closure_roots.is_empty()
            || profile.closure_roots.len() > MAXIMUM_RUNTIME_FILES
            || profile
                .runtime_files
                .windows(2)
                .any(|pair| pair[0].path >= pair[1].path)
            || profile
                .closure_roots
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(RuntimeDeploymentStartupErrorV1::Profile);
        }

        for root in &profile.closure_roots {
            require_path_shape(root)?;
            if Path::new(root).components().count() != 4 {
                return Err(RuntimeDeploymentStartupErrorV1::Profile);
            }
        }
        for pin in profile.runtime_files.iter().chain([
            &profile.executable,
            &profile.pid1,
            &profile.loader,
            &profile.canonical_policy,
            &profile.source_policy,
            &profile.effective_matrix,
        ]) {
            require_path_shape(&pin.path)?;
            if pin.sha256 == [0; 32] {
                return Err(RuntimeDeploymentStartupErrorV1::Profile);
            }
        }
        if profile
            .runtime_files
            .iter()
            .any(|pin| {
                !profile.closure_roots.iter().any(|root| {
                    Path::new(&pin.path)
                        .strip_prefix(root)
                        .is_ok_and(|suffix| suffix.components().count() > 0)
                })
            })
        {
            return Err(RuntimeDeploymentStartupErrorV1::Profile);
        }
        for required in [&profile.executable, &profile.loader] {
            if !profile
                .runtime_files
                .iter()
                .any(|member| member.path == required.path && member.sha256 == required.sha256)
            {
                return Err(RuntimeDeploymentStartupErrorV1::Profile);
            }
        }
        if Path::new(&profile.executable.path)
            .file_name()
            .is_none_or(|name| name != "aos-sandbox-runtime-publisher")
            || !profile
                .canonical_policy
                .path
                .ends_with("-aos-selinux-kernel-policy-readback-1/policy.33")
            || !profile
                .source_policy
                .path
                .ends_with("-aos-runtime-deployment-startup-profile-1/source-policy.33")
            || !profile
                .effective_matrix
                .path
                .ends_with("-aos-runtime-deployment-startup-profile-1/effective-policy.tsv")
            || Path::new(&profile.source_policy.path).parent()
                != Path::new(&profile.effective_matrix.path).parent()
        {
            return Err(RuntimeDeploymentStartupErrorV1::Profile);
        }
        Ok(profile)
    }
}

/// Captures the fixed publisher's original activation roles once at startup.
///
/// Capture must be the first single-threaded operation, before opening any
/// credential, journal or other descriptor. Role names locate original slots;
/// they do not authenticate an image, PID1 or a floor on their own.
pub struct ProductionRuntimeDeploymentStartupCaptureV1 {
    listener: OwnedFd,
    pid1: OwnedFd,
    profile: OwnedFd,
}

impl ProductionRuntimeDeploymentStartupCaptureV1 {
    /// Retains only the closed original listener, PID1 and profile table.
    ///
    /// # Errors
    ///
    /// Rejects missing, extra, duplicated or foreign-PID activation roles and
    /// any failed or repeated complete-table capture. There is no legacy mode.
    pub fn capture() -> Result<Self, RuntimeDeploymentStartupErrorV1> {
        let names = crate::normal_root::startup::names(3)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Activation)?;
        if !valid_roles(&names) {
            return Err(RuntimeDeploymentStartupErrorV1::Activation);
        }
        let descriptors = duplicate_initial_activation_table(names.len())
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Activation)?;

        let mut listener = None;
        let mut pid1 = None;
        let mut profile = None;
        for (name, descriptor) in names.iter().zip(descriptors) {
            match name.as_str() {
                LISTENER_FD_NAME => listener = Some(descriptor),
                PID1_FD_NAME => pid1 = Some(descriptor),
                PROFILE_FD_NAME => profile = Some(descriptor),
                _ => return Err(RuntimeDeploymentStartupErrorV1::Activation),
            }
        }
        Ok(Self {
            listener: listener.ok_or(RuntimeDeploymentStartupErrorV1::Activation)?,
            pid1: pid1.ok_or(RuntimeDeploymentStartupErrorV1::Activation)?,
            profile: profile.ok_or(RuntimeDeploymentStartupErrorV1::Activation)?,
        })
    }

    /// Joins the original roles to the actual fixed deployment publisher.
    ///
    /// No caller descriptor, pathname, profile, context or scalar can select
    /// this owner. The publisher has no runtime/guest/agent/output authority.
    /// Independent signed genesis and authenticated current NV must still be
    /// joined by its separate protected deployment owner before publication.
    ///
    /// # Errors
    ///
    /// Rejects substituted original roles, immutable images or mappings,
    /// unequal enforcing policy, wrong fixed unit/cgroup/invocation, nonempty
    /// capabilities or another credential/subject/process incarnation.
    pub fn admit(
        self,
    ) -> Result<ProductionRuntimeDeploymentStartupPartsV1, RuntimeDeploymentStartupErrorV1> {
        self.admit_mode(DeploymentAdmissionModeV2::Legacy)
    }

    /// Admits the fixed canary publisher using the same original capture recipe.
    ///
    /// This consumes the genuine initial table, not caller descriptors or a mode
    /// flag. The selected unit must execute exactly `--canary-association-v2`.
    /// Admission alone grants no journal, signature, physical floor or effect.
    ///
    /// # Errors
    /// Refuses the same original image, policy, process and activation failures
    /// as ordinary admission, or a different selected unit/command recipe.
    pub fn admit_canary_v2(
        self,
    ) -> Result<ProductionRuntimeDeploymentStartupPartsV1, RuntimeDeploymentStartupErrorV1> {
        self.admit_mode(DeploymentAdmissionModeV2::Canary)
    }

    fn admit_mode(
        self,
        mode: DeploymentAdmissionModeV2,
    ) -> Result<ProductionRuntimeDeploymentStartupPartsV1, RuntimeDeploymentStartupErrorV1> {
        let listener = RecordSubjectListener::from_owned(self.listener)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Activation)?;
        listener
            .require_local_filesystem_path(Path::new(SOCKET_PATH))
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Activation)?;
        let (profile_file, bytes) = retain_profile(File::from(self.profile))?;
        let profile_digest = Sha256::digest(&bytes).into();
        let (profile, storage_pin) = match mode {
            DeploymentAdmissionModeV2::Legacy => (RuntimeDeploymentProfileV1::decode(&bytes)?, None),
            DeploymentAdmissionModeV2::Canary => {
                if bytes.is_empty() || bytes.len() > MAXIMUM_PROFILE_BYTES {
                    return Err(RuntimeDeploymentStartupErrorV1::Profile);
                }
                let selected: CanaryRuntimeDeploymentProfileV2 = serde_json::from_slice(&bytes)
                    .map_err(|_| RuntimeDeploymentStartupErrorV1::Profile)?;
                require_path_shape(&selected.canary_storage.path)?;
                if selected.format != "AOS_RUNTIME_DEPLOYMENT_CANARY_STARTUP_2"
                    || selected.canary_storage.sha256 == [0; 32]
                    || !selected.canary_storage.path.ends_with(
                        "-aos-runtime-deployment-storage-profile-2/storage.json",
                    )
                {
                    return Err(RuntimeDeploymentStartupErrorV1::Profile);
                }
                (RuntimeDeploymentProfileV1::validate(selected.publisher)?, Some(selected.canary_storage))
            }
        };
        if profile_file.path().parent() != Path::new(&profile.effective_matrix.path).parent() {
            return Err(RuntimeDeploymentStartupErrorV1::Profile);
        }

        let manager = retain_pin(
            &profile.pid1,
            Some(File::from(self.pid1)),
            mode == DeploymentAdmissionModeV2::Legacy,
        )?;
        let executable = retain_pin(
            &profile.executable,
            Some(
                File::open("/proc/self/exe")
                    .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?,
            ),
            true,
        )?;
        let runtime = profile
            .runtime_files
            .iter()
            .map(|pin| {
                retain_pin(
                    pin,
                    None,
                    pin.path == profile.executable.path || pin.path == profile.loader.path,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let evidence = [
            &profile.canonical_policy,
            &profile.source_policy,
            &profile.effective_matrix,
        ]
        .into_iter()
        .map(|pin| retain_pin(pin, None, false))
        .collect::<Result<Vec<_>, _>>()?;
        let policy = VerifiedLiveSelinuxPolicy::verify(&profile.canonical_policy.path)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Confinement)?;
        if policy.digest() != profile.canonical_policy.sha256 {
            return Err(RuntimeDeploymentStartupErrorV1::Confinement);
        }

        let process = PidFd::open(
            NonZeroU32::new(std::process::id())
                .ok_or(RuntimeDeploymentStartupErrorV1::Service)?,
        )
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
        let identity = process
            .process_identity()
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
        let service = RetainedDeploymentServicePolicyV1::retain_mode(
            profile_file.path(),
            &profile.executable.path,
            profile.unit_sha256,
            &process,
            mode,
        )?;
        let listener_cookie = if mode == DeploymentAdmissionModeV2::Canary {
            Some(rustix::net::sockopt::socket_cookie(listener.as_fd())
                .ok().filter(|cookie| *cookie != 0)
                .ok_or(RuntimeDeploymentStartupErrorV1::Activation)?)
        } else {
            None
        };
        let canary_storage = match &storage_pin {
            Some(pin) => Some(RetainedCanaryStorageProfileV2::retain(pin)?),
            None => None,
        };
        let startup = ProductionRuntimeDeploymentStartupV1 {
            profile_file,
            profile,
            profile_digest,
            manager,
            executable,
            runtime,
            evidence,
            policy,
            process,
            identity,
            service,
            host_physical_invocation: HostPhysicalInvocationStateV1::new(),
            mode,
            listener_cookie,
            canary_storage,
        };
        startup.recheck()?;
        listener
            .validate_current()
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Activation)?;
        listener
            .require_local_filesystem_path(Path::new(SOCKET_PATH))
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Activation)?;
        Ok(ProductionRuntimeDeploymentStartupPartsV1 { listener, startup })
    }
}

/// Keeps the actual original listener together with its opaque local owner.
pub struct ProductionRuntimeDeploymentStartupPartsV1 {
    /// The original fixed record-subject listener; it is not floor authority.
    pub listener: RecordSubjectListener,
    /// The retained publisher startup prerequisite, requiring live rechecks.
    pub startup: ProductionRuntimeDeploymentStartupV1,
}

/// Retains the actual deployment-only publisher's original startup objects.
///
/// This owner has no serialization, scalar factory, cloning or proof conversion.
/// It neither seeds a journal/NV nor establishes installed production payload
/// equivalence. The separate TPM purpose owner consumes it only as an actual
/// startup prerequisite and still checks its own credentials, schema and cuts.
#[must_use = "retain and recheck the original deployment publisher owner"]
pub struct ProductionRuntimeDeploymentStartupV1 {
    profile_file: RetainedImmutableFileV1,
    profile: RuntimeDeploymentProfileV1,
    profile_digest: [u8; 32],
    manager: RetainedImmutableFileV1,
    executable: RetainedImmutableFileV1,
    runtime: Vec<RetainedImmutableFileV1>,
    evidence: Vec<RetainedImmutableFileV1>,
    policy: VerifiedLiveSelinuxPolicy,
    process: PidFd,
    identity: PidFdProcessIdentity,
    service: RetainedDeploymentServicePolicyV1,
    host_physical_invocation: HostPhysicalInvocationStateV1,
    mode: DeploymentAdmissionModeV2,
    listener_cookie: Option<u64>,
    canary_storage: Option<RetainedCanaryStorageProfileV2>,
}

impl ProductionRuntimeDeploymentStartupV1 {
    /// Compares the originally captured selected listener before a single operation.
    ///
    /// The publicly accessible Parts fields cannot substitute a different
    /// listening socket. This observes the original cookie and fixed pathname,
    /// never constructs a listener or permits another invocation.
    ///
    /// # Errors
    /// Refuses ordinary mode, substituted listener custody or startup drift.
    pub fn require_canary_listener_v2(
        &self,
        listener: &RecordSubjectListener,
    ) -> Result<(), RuntimeDeploymentStartupErrorV1> {
        self.recheck()?;
        if self.mode != DeploymentAdmissionModeV2::Canary
            || self.listener_cookie.is_none()
            || rustix::net::sockopt::socket_cookie(listener.as_fd()).ok() != self.listener_cookie
        {
            return Err(RuntimeDeploymentStartupErrorV1::Activation);
        }
        listener.validate_current().map_err(|_| RuntimeDeploymentStartupErrorV1::Activation)?;
        listener.require_local_filesystem_path(Path::new(SOCKET_PATH))
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Activation)?;
        self.recheck()
    }

    pub(super) const fn is_canary_v2(&self) -> bool {
        matches!(self.mode, DeploymentAdmissionModeV2::Canary)
    }

    /// Rechecks the same original image, policy, service and process custody.
    ///
    /// PID1's current executed inode is compared with the original OpenFile;
    /// its launch descriptor alone is not continuous reexec evidence. Current
    /// executable mappings are checked with the existing shared image reader.
    /// The canary adapter instead retains the original inherited PID1 launch
    /// file plus fixed unique-PID1 service bookends under trusted boot/manager
    /// administration; it does not assert executed-image continuity or reexec.
    /// The property readback remains point-in-time within trusted boot/PID1
    /// administration, not a policy freeze against the administrator.
    ///
    /// # Errors
    ///
    /// Rejects any original file/name/content/mount, mapping, policy, subject,
    /// capability/credential, unit/invocation, cgroup or process change.
    pub fn recheck(&self) -> Result<(), RuntimeDeploymentStartupErrorV1> {
        self.profile_file
            .revalidate()
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Profile)?;
        self.manager
            .revalidate()
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
        if self.mode == DeploymentAdmissionModeV2::Legacy {
            self.manager
                .require_executed(1)
                .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
        }
        self.executable
            .revalidate()
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
        self.executable
            .require_executed(std::process::id())
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
        for file in self.runtime.iter().chain(&self.evidence) {
            file.revalidate()
                .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
        }
        crate::normal_root::images::require_actual_mappings(
            &self.runtime,
            &[&self.profile.executable.path, &self.profile.loader.path],
        )
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;

        self.policy
            .revalidate(&self.profile.canonical_policy.path)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Confinement)?;
        require_subject(OWNER_CONTEXT)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Confinement)?;
        require_status(&read_bounded("/proc/thread-self/status", 64 * 1024)?)?;
        let info = self
            .process
            .info()
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
        let credentials = info
            .credentials()
            .ok_or(RuntimeDeploymentStartupErrorV1::Confinement)?;
        if !self
            .process
            .is_alive()
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?
            || info.pid() != std::process::id()
            || info.parent_pid() != 1
            || self
                .process
                .process_identity()
                .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?
                != self.identity
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
            return Err(RuntimeDeploymentStartupErrorV1::Confinement);
        }
        self.service.recheck(
            self.profile_file.path(),
            &self.profile.executable.path,
            self.profile.unit_sha256,
            &self.process,
        )?;
        if let Some(storage) = &self.canary_storage { storage.recheck()?; }

        if self.mode == DeploymentAdmissionModeV2::Legacy {
            self.manager
                .require_executed(1)
                .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
        }
        self.manager
            .revalidate()
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
        self.profile_file
            .revalidate()
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Profile)
    }

    /// Returns measured profile bytes for an independent signed-genesis join.
    ///
    /// This comparison digest cannot mint the startup owner or a current floor.
    #[must_use]
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }

    /// Returns parsed policy comparison DATA; callers still recheck live custody.
    pub(crate) const fn canonical_policy_digest(&self) -> [u8; 32] {
        self.profile.canonical_policy.sha256
    }

    /// Binds six selected contracts to the actual retained profile and grammar.
    pub(super) fn canary_contracts_v2(&self)
        -> Result<[[u8; 32]; 6], RuntimeDeploymentStartupErrorV1>
    {
        if !self.is_canary_v2() { return Err(RuntimeDeploymentStartupErrorV1::Profile); }
        let storage = self.canary_storage.as_ref().ok_or(RuntimeDeploymentStartupErrorV1::Profile)?;
        storage.recheck()?;
        if storage.profile.canonical_policy.sha256 != self.canonical_policy_digest() {
            return Err(RuntimeDeploymentStartupErrorV1::Confinement);
        }
        Ok([
            storage.digest,
            storage.profile.canonical_policy.sha256,
            storage.unit_contract(),
            super::genesis::canary_credential_contract_v2(),
            super::preparation::canary_schema_contract_v3(),
            canary_mode_recipe_v3(),
        ])
    }

    /// Returns one exact parsed runtime-file pin as immutable comparison DATA.
    ///
    /// This does not open the selected path, authenticate a remote collector or
    /// grant a Prepared permit. The caller must bracket comparison with actual
    /// startup rechecks and join the separately signed publisher-profile digest.
    #[must_use]
    pub(crate) fn retained_runtime_file_digest_v1(&self, path: &Path) -> Option<[u8; 32]> {
        retained_runtime_file_digest(&self.profile.runtime_files, path)
    }

    pub(crate) fn retained_pid1(&self) -> &RetainedImmutableFileV1 {
        &self.manager
    }

    pub(crate) const fn invocation_id(&self) -> [u8; 16] {
        self.service.invocation_id()
    }

    // Every Origins admitted from this actual startup shares this one-shot.
    // Ordinary comparison-only rechecks do not claim a physical invocation.
    pub(super) fn host_physical_invocation_state(&self) -> &HostPhysicalInvocationStateV1 {
        &self.host_physical_invocation
    }

    pub(super) fn retain_host_invocation_population(
        &self,
    ) -> aos_sandbox_linux::Result<aos_sandbox_linux::cgroup::CgroupPopulationMonitor> {
        self.service.retain_host_invocation_population()
    }

    pub(crate) fn require_child(
        &self,
        child: &PidFd,
    ) -> Result<(), RuntimeDeploymentStartupErrorV1> {
        self.recheck()?;
        self.service.require_child(&self.process, child)?;
        self.recheck()
    }
}

fn valid_roles(names: &[String]) -> bool {
    names.len() == 3
        && [LISTENER_FD_NAME, PID1_FD_NAME, PROFILE_FD_NAME]
            .iter()
            .all(|role| names.iter().filter(|name| name.as_str() == *role).count() == 1)
}

/// Names independently pinned Storage image inputs; none is a live subject.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CanaryStorageProfileV2 {
    format: String,
    unit: String,
    context: String,
    executable: ImagePinV1,
    loader: ImagePinV1,
    runtime_files: Vec<ImagePinV1>,
    closure_roots: Vec<String>,
    canonical_policy: ImagePinV1,
    unit_sha256: [u8; 32],
    arguments: Vec<String>,
}

struct RetainedCanaryStorageProfileV2 {
    original: RetainedImmutableFileV1,
    digest: [u8; 32],
    profile: CanaryStorageProfileV2,
    runtime: Vec<RetainedImmutableFileV1>,
    policy: RetainedImmutableFileV1,
}

impl RetainedCanaryStorageProfileV2 {
    fn retain(pin: &ImagePinV1) -> Result<Self, RuntimeDeploymentStartupErrorV1> {
        let original = retain_pin(pin, None, false)?;
        let bytes = original.read_bounded().map_err(|_| RuntimeDeploymentStartupErrorV1::Profile)?;
        if bytes.is_empty() || bytes.len() > MAXIMUM_PROFILE_BYTES {
            return Err(RuntimeDeploymentStartupErrorV1::Profile);
        }
        let profile: CanaryStorageProfileV2 = serde_json::from_slice(&bytes)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Profile)?;
        if profile.format != "AOS_RUNTIME_DEPLOYMENT_STORAGE_2"
            || profile.unit != STORAGE_UNIT_V2 || profile.context != STORAGE_CONTEXT_V2
            || profile.unit_sha256 == [0; 32]
            || profile.runtime_files.is_empty() || profile.runtime_files.len() > MAXIMUM_RUNTIME_FILES
            || profile.closure_roots.is_empty() || profile.closure_roots.len() > MAXIMUM_RUNTIME_FILES
            || profile.runtime_files.windows(2).any(|pair| pair[0].path >= pair[1].path)
            || profile.closure_roots.windows(2).any(|pair| pair[0] >= pair[1])
            || profile.arguments.len() != 12
            || profile.arguments.first().map(String::as_str) != Some(profile.executable.path.as_str())
            || profile.arguments.iter().any(|argument| argument.len() > 4096 || argument.contains('\0'))
            || Path::new(&profile.executable.path).file_name().is_none_or(|name| name != "aos-storaged")
        {
            return Err(RuntimeDeploymentStartupErrorV1::Profile);
        }
        for root in &profile.closure_roots {
            require_path_shape(root)?;
            if Path::new(root).components().count() != 4 {
                return Err(RuntimeDeploymentStartupErrorV1::Profile);
            }
        }
        for image in profile.runtime_files.iter().chain([
            &profile.executable, &profile.loader, &profile.canonical_policy,
        ]) {
            require_path_shape(&image.path)?;
            if image.sha256 == [0; 32] { return Err(RuntimeDeploymentStartupErrorV1::Profile); }
        }
        for image in &profile.runtime_files {
            if !profile.closure_roots.iter().any(|root| {
                Path::new(&image.path).strip_prefix(root)
                    .is_ok_and(|suffix| suffix.components().count() > 0)
            }) {
                return Err(RuntimeDeploymentStartupErrorV1::Profile);
            }
        }
        for required in [&profile.executable, &profile.loader] {
            if !profile.runtime_files.iter().any(|image| {
                image.path == required.path && image.sha256 == required.sha256
            }) {
                return Err(RuntimeDeploymentStartupErrorV1::Profile);
            }
        }
        let runtime = profile.runtime_files.iter()
            .map(|image| retain_pin(image, None, false))
            .collect::<Result<Vec<_>, _>>()?;
        let policy = retain_pin(&profile.canonical_policy, None, false)?;
        let owner = Self { original, digest: Sha256::digest(&bytes).into(), profile, runtime, policy };
        owner.recheck()?;
        Ok(owner)
    }

    fn recheck(&self) -> Result<(), RuntimeDeploymentStartupErrorV1> {
        self.original.revalidate().map_err(|_| RuntimeDeploymentStartupErrorV1::Profile)?;
        for image in &self.runtime {
            image.revalidate().map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
        }
        self.policy.revalidate().map_err(|_| RuntimeDeploymentStartupErrorV1::Confinement)
    }

    fn unit_contract(&self) -> [u8; 32] {
        let mut hash = Sha256::new()
            .chain_update(b"aos.runtime-deployment.canary-storage-unit-contract.v2\0");
        for text in [STORAGE_UNIT_V2, STORAGE_CGROUP_V2, STORAGE_CONTEXT_V2,
            self.profile.executable.path.as_str(), self.profile.loader.path.as_str()]
            .into_iter().chain(self.profile.arguments.iter().map(String::as_str))
        {
            hash.update((text.len() as u64).to_be_bytes());
            hash.update(text.as_bytes());
        }
        hash.update(self.profile.unit_sha256);
        hash.finalize().into()
    }
}

fn canary_mode_recipe_v3() -> [u8; 32] {
    let mut hash = Sha256::new().chain_update(b"aos.runtime-deployment.canary-mode-recipe.v3\0");
    for text in [UNIT, super::SOCKET_UNIT, SOCKET_PATH, OWNER_CONTEXT, HELPER_CONTEXT,
        "--canary-association-v2", "AOSRDCQ3", "3", "826", "120",
        "same-original-boot-and-exclusive-signed-deadline", "no-resend-or-reopen"]
    {
        hash.update((text.len() as u64).to_be_bytes());
        hash.update(text.as_bytes());
    }
    hash.finalize().into()
}

/// Retains an original Storage delegation received by this fixed publisher.
///
/// Empty construction is private and borrows the genuine startup and admitted
/// purpose. The caller keeps the actual socket and whole received record in
/// its resident operation; every observation requires those same originals.
/// No supplied PID, path, image, credential bytes or current-head DTO can
/// construct a completed delegation. Coordinates in the packet remain signed
/// delegate-held DATA, not independently reopened publisher observations.
#[must_use = "retain the delegate, its socket and whole original record together"]
pub struct RuntimeDeploymentStorageDelegateCaptureV2<'origin> {
    startup: &'origin ProductionRuntimeDeploymentStartupV1,
    purpose: &'origin aos_sandbox_protocol::runtime_deployment::canary::CanaryPurposeV2,
    request: Option<aos_sandbox_protocol::runtime_deployment::canary::CanaryPublisherRequestV3>,
    original_request: Option<Result<
        aos_sandbox_protocol::runtime_deployment::canary::CanaryPublisherRequestV3,
        aos_sandbox_protocol::runtime_deployment::DeploymentWireErrorV1,
    >>,
    original_request_phase: OriginalRequestPhaseV3,
    job: Option<aos_sandbox_protocol::host_canary_job::HostCanaryJobDataV1>,
    job_bytes: Vec<u8>,
    job_readback: Vec<u8>,
    proc: Option<aos_sandbox_linux::pidfd::PidFdProcObservationsV1>,
    identity: Option<PidFdProcessIdentity>,
    status: Option<File>,
    status_bytes: Vec<u8>,
    maps: Option<File>,
    maps_bytes: Vec<u8>,
    executable: Option<File>,
    comparison_executable: Option<File>,
    properties: Option<super::service_policy::StoragePropertiesResultV2>,
    comparison_properties: Option<super::service_policy::StoragePropertiesResultV2>,
    failed_property_site: Option<StoragePropertySiteV2>,
    observation: Option<super::service_policy::StoragePolicyObservationV2>,
    fragment: crate::immutable_image::PendingImmutableFileV1,
    cgroup_root: Option<OwnedFd>,
    measured_cgroup_root: Option<aos_sandbox_linux::cgroup::CgroupV2Root>,
    cgroup: Option<aos_sandbox_linux::cgroup::RetainedCgroupAnchor>,
    cookie: Option<std::num::NonZeroU64>,
    attempted: bool,
    ready: bool,
    first_failure: std::sync::Arc<Option<RuntimeDeploymentStorageDelegateErrorV2>>,
}

/// Preserves the original cause of selected Storage-delegation refusal.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeDeploymentStorageDelegateErrorV2 {
    /// An original kernel/process observation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// The original transport or received-origin observation failed.
    #[error(transparent)]
    Carrier(#[from] aos_sandbox_linux::seqpacket::SeqpacketError),
    /// The same received record no longer belongs to its original carrier.
    #[error(transparent)]
    Binding(#[from] aos_sandbox_linux::seqpacket::RecordBindingError),
    /// A native descriptor operation failed.
    #[error(transparent)]
    Descriptor(#[from] rustix::io::Errno),
    /// A retained file read or metadata observation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Creation of the original fixed property-observation thread failed.
    #[error("selected Storage property-observation thread could not start")]
    PropertyThreadSpawn(#[source] std::io::Error),
    /// The original fixed property-observation runtime could not be built.
    #[error("selected Storage property-observation runtime could not start")]
    PropertyRuntime(#[source] std::io::Error),
    /// The original fixed PID1 property observation failed.
    #[error("selected Storage original PID1 property observation failed")]
    PropertySystemd(#[source] aos_systemd::Error),
    /// The original fixed PID1 property observation exceeded its deadline.
    #[error("selected Storage property-observation deadline expired")]
    PropertyDeadline,
    /// The sole borrowed exact reader rejected the sealed job.
    #[error(transparent)]
    ExactRead(#[from] aos_sandbox_linux::protected_file::ExactReadFailure),
    /// The sole signed-job decoder rejected the full bytes.
    #[error(transparent)]
    Job(#[from] aos_sandbox_protocol::host_canary_job::HostCanaryJobDataErrorV1),
    /// The existing immutable image engine rejected an original.
    #[error(transparent)]
    Image(#[from] crate::immutable_image::ImmutableImageErrorV1),
    /// The original publisher or fixed Storage policy differs.
    #[error(transparent)]
    Startup(#[from] RuntimeDeploymentStartupErrorV1),
    /// The instance is fenced, incomplete or mismatched.
    #[error("selected Storage original delegation differs")]
    Changed,
}

/// Keeps a consumed failed Result distinct from a never-observed slot.
#[derive(Clone, Copy)]
enum StoragePropertySiteV2 {
    Initial,
    Comparison,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OriginalRequestPhaseV3 {
    Legacy,
    Parsing,
    Parsed,
    Capturing,
    Transferred,
}

// Selected observations borrow the moved request; Legacy keeps the same owned
// slot, decode position and ordinary wrappers. Neither disposition is a permit.
#[derive(Clone, Copy)]
enum DelegateRequestDispositionV3<'request> {
    Legacy,
    ParsedOriginal,
    Original(&'request super::RuntimeDeploymentOriginalWindowV3),
}

impl<'origin> RuntimeDeploymentStorageDelegateCaptureV2<'origin> {
    pub(super) fn new(
        startup: &'origin ProductionRuntimeDeploymentStartupV1,
        purpose: &'origin aos_sandbox_protocol::runtime_deployment::canary::CanaryPurposeV2,
    ) -> Self {
        Self {
            startup, purpose, request: None, job: None,
            original_request: None, original_request_phase: OriginalRequestPhaseV3::Legacy,
            job_bytes: Vec::new(), job_readback: Vec::new(), proc: None, identity: None,
            status: None, status_bytes: Vec::new(), maps: None, maps_bytes: Vec::new(),
            executable: None, comparison_executable: None, properties: None,
            comparison_properties: None, failed_property_site: None,
            observation: None, fragment: crate::immutable_image::PendingImmutableFileV1::default(),
            cgroup_root: None, measured_cgroup_root: None, cgroup: None, cookie: None, attempted: false,
            ready: false, first_failure: std::sync::Arc::new(None),
        }
    }

    /// Parks the selected route's sole request decode before authentication.
    ///
    /// This prepares only DATA on the genuine empty capture. No authenticated
    /// window, ready delegate or physical permission follows from decoding.
    ///
    /// # Errors
    /// Preserves the actual malformed-wire error in its original slot, or
    /// refuses occupied/repeated/fenced preparation. Failure stays closed.
    pub fn prepare_original_request_once(
        &mut self,
        record: &aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
    ) -> Result<(), aos_sandbox_protocol::runtime_deployment::DeploymentWireErrorV1> {
        use aos_sandbox_protocol::runtime_deployment::{
            DeploymentWireErrorV1, canary::CanaryPublisherRequestV3,
        };

        if self.attempted || self.ready || self.first_failure.is_some()
            || self.request.is_some() || self.original_request.is_some()
            || self.original_request_phase != OriginalRequestPhaseV3::Legacy
        {
            self.ready = false;
            self.original_request_phase = OriginalRequestPhaseV3::Parsing;
            return Err(DeploymentWireErrorV1);
        }

        self.original_request_phase = OriginalRequestPhaseV3::Parsing;
        self.original_request = Some(CanaryPublisherRequestV3::decode(record.payload()));

        match self.original_request.as_ref() {
            Some(Ok(_)) => {
                self.original_request_phase = OriginalRequestPhaseV3::Parsed;
                Ok(())
            }
            Some(Err(error)) => Err(*error),
            None => Err(DeploymentWireErrorV1),
        }
    }

    /// Authenticates the sole prepared request and transfers it only on success.
    ///
    /// The result owns the request and borrows only the immutable record, not
    /// this mutable capture or socket. Originals and all native checks remain
    /// in the same capture engine. No supplied request or scalar binds custody.
    ///
    /// # Errors
    /// Refuses missing/repeated preparation, changed originals or any existing
    /// capture failure. The authentic first error stays in this original owner.
    pub fn capture_original_request_once<'record>(
        &mut self,
        socket: &mut aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket,
        record: &'record aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
    ) -> Result<super::RuntimeDeploymentAuthenticatedRequestV3<'record>,
                super::RuntimeDeploymentComparisonErrorV1>
    {
        if self.first_failure.is_some() {
            return Err(self.diagnostic());
        }

        self.require_vacant_failure();

        let result = if self.attempted || self.ready
            || self.original_request_phase != OriginalRequestPhaseV3::Parsed
            || !matches!(self.original_request.as_ref(), Some(Ok(_)))
        {
            Err(RuntimeDeploymentStorageDelegateErrorV2::Changed)
        } else {
            self.attempted = true;
            self.ready = false;
            self.original_request_phase = OriginalRequestPhaseV3::Capturing;
            self.capture_inner(socket, record, DelegateRequestDispositionV3::ParsedOriginal)
        };
        self.retain_result(result)?;

        // All fallible capture/currentness gates precede this infallible move.
        // A malformed stage keeps its original Result rather than replacing it.
        let transfer = self.transfer_original_request(record);
        match transfer {
            Ok(original) => Ok(original),
            Err(error) => {
                self.retain_result(Err(error))?;
                Err(self.diagnostic())
            }
        }
    }

    fn transfer_original_request<'record>(
        &mut self,
        record: &'record aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
    ) -> Result<super::RuntimeDeploymentAuthenticatedRequestV3<'record>,
                RuntimeDeploymentStorageDelegateErrorV2>
    {
        if !self.ready || self.original_request_phase != OriginalRequestPhaseV3::Capturing {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        let cookie = self.cookie.ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        let identity = self.identity.ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        if !matches!(self.original_request.as_ref(), Some(Ok(_))) {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }

        self.original_request_phase = OriginalRequestPhaseV3::Transferred;
        match self.original_request.take() {
            Some(Ok(request)) => {
                Ok(super::RuntimeDeploymentAuthenticatedRequestV3::from_completed_capture(
                    request, record, cookie, identity,
                ))
            }
            result => {
                self.original_request = result;
                self.ready = false;
                Err(RuntimeDeploymentStorageDelegateErrorV2::Changed)
            }
        }
    }

    /// Rechecks the current delegate using its same transferred original request.
    ///
    /// # Errors
    /// Refuses a different/fenced capture, changed carrier, full request/job,
    /// process, service or original clock. Cookie/identity equality alone never
    /// substitutes for the existing full canonical/native comparison engine.
    pub fn recheck_original_request(
        &mut self,
        socket: &mut aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket,
        record: &aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
        original: &super::RuntimeDeploymentOriginalWindowV3,
    ) -> Result<(), super::RuntimeDeploymentComparisonErrorV1> {
        self.recheck_with_request(socket, record, DelegateRequestDispositionV3::Original(original))
    }

    /// Fills association DATA from the same current delegate and original window.
    ///
    /// # Errors
    /// Refuses missing/transposed originals, fenced custody or incomplete full
    /// request/job/current observations. This does not produce effect authority.
    pub fn fill_original_association_data_v2(
        &mut self,
        original: &super::RuntimeDeploymentOriginalWindowV3,
        fields: &mut aos_sandbox_protocol::runtime_deployment::canary::CanaryAssociationFieldsV2,
    ) -> Result<(), super::RuntimeDeploymentComparisonErrorV1> {
        self.fill_association_with_request(fields, DelegateRequestDispositionV3::Original(original))
    }

    fn request_for<'request>(
        &'request self,
        disposition: DelegateRequestDispositionV3<'request>,
    ) -> Result<&'request aos_sandbox_protocol::runtime_deployment::canary::CanaryPublisherRequestV3,
                RuntimeDeploymentStorageDelegateErrorV2>
    {
        match disposition {
            DelegateRequestDispositionV3::Legacy
                if self.original_request_phase == OriginalRequestPhaseV3::Legacy =>
            {
                self.request.as_ref().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)
            }
            DelegateRequestDispositionV3::ParsedOriginal
                if self.original_request_phase == OriginalRequestPhaseV3::Capturing =>
            {
                self.original_request.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)
            }
            DelegateRequestDispositionV3::Original(original)
                if self.original_request_phase == OriginalRequestPhaseV3::Transferred
                    && original.matches_capture(self.cookie, self.identity) =>
            {
                Ok(original.request())
            }
            _ => Err(RuntimeDeploymentStorageDelegateErrorV2::Changed),
        }
    }

    /// Captures the actual received full-job request and its fixed Storage origin once.
    ///
    /// # Errors
    /// Refuses repetition, wrong original carrier or subject, job seals/bytes,
    /// signature, purpose, image, policy, unit or current process disagreement.
    /// Error and unwind permanently fence this instance and retain its returned
    /// originals. The caller must also retain the socket and received record.
    pub fn capture_once(
        &mut self,
        socket: &mut aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket,
        record: &aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
    ) -> Result<(), super::RuntimeDeploymentComparisonErrorV1> {
        if self.first_failure.is_some() {
            return Err(self.diagnostic());
        }
        self.require_vacant_failure();
        let result = if self.attempted || self.first_failure.is_some()
            || self.original_request_phase != OriginalRequestPhaseV3::Legacy
        {
            Err(RuntimeDeploymentStorageDelegateErrorV2::Changed)
        } else {
            self.attempted = true;
            self.ready = false;
            self.capture_inner(socket, record, DelegateRequestDispositionV3::Legacy)
        };
        self.retain_result(result)
    }

    /// Rechecks the same original delegation, without replacing any admitted inputs.
    ///
    /// # Errors
    /// Refuses incomplete/fenced custody, changed received origin, process,
    /// full job, image, service, profile or signed original clock bounds.
    pub fn recheck(
        &mut self,
        socket: &mut aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket,
        record: &aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
    ) -> Result<(), super::RuntimeDeploymentComparisonErrorV1> {
        self.recheck_with_request(socket, record, DelegateRequestDispositionV3::Legacy)
    }

    fn recheck_with_request(
        &mut self,
        socket: &mut aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket,
        record: &aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
        request: DelegateRequestDispositionV3<'_>,
    ) -> Result<(), super::RuntimeDeploymentComparisonErrorV1> {
        if self.first_failure.is_some() {
            return Err(self.diagnostic());
        }
        self.require_vacant_failure();
        let result = if !self.ready || self.first_failure.is_some() {
            Err(RuntimeDeploymentStorageDelegateErrorV2::Changed)
        } else {
            self.ready = false;
            self.recheck_inner(socket, record, request)
        };
        self.retain_result(result)
    }

    /// Borrows the authentic first failure while all comparison originals remain resident.
    #[must_use]
    pub fn first_failure(&self) -> Option<&RuntimeDeploymentStorageDelegateErrorV2> {
        self.first_failure.as_ref().as_ref()
    }

    /// Fills only delegate-observed association DATA from this completed capture.
    ///
    /// Coordinates remain the authenticated delegate's statement; this method
    /// does not reopen its writer or produce a physical/currentness authority.
    ///
    /// # Errors
    /// Refuses incomplete or fenced capture, or missing original observations.
    pub fn fill_association_data_v2(
        &mut self,
        fields: &mut aos_sandbox_protocol::runtime_deployment::canary::CanaryAssociationFieldsV2,
    ) -> Result<(), super::RuntimeDeploymentComparisonErrorV1> {
        self.fill_association_with_request(fields, DelegateRequestDispositionV3::Legacy)
    }

    fn fill_association_with_request(
        &mut self,
        fields: &mut aos_sandbox_protocol::runtime_deployment::canary::CanaryAssociationFieldsV2,
        request: DelegateRequestDispositionV3<'_>,
    ) -> Result<(), super::RuntimeDeploymentComparisonErrorV1> {
        if self.first_failure.is_some() { return Err(self.diagnostic()); }
        self.require_vacant_failure();
        let result = if !self.ready {
            Err(RuntimeDeploymentStorageDelegateErrorV2::Changed)
        } else {
            self.ready = false;
            self.fill_association_inner(fields, request)
        };
        self.retain_result(result)
    }

    fn fill_association_inner(
        &self,
        fields: &mut aos_sandbox_protocol::runtime_deployment::canary::CanaryAssociationFieldsV2,
        disposition: DelegateRequestDispositionV3<'_>,
    ) -> Result<(), RuntimeDeploymentStorageDelegateErrorV2> {
        let request = self.request_for(disposition)?;
        if matches!(disposition, DelegateRequestDispositionV3::Original(_)) {
            self.require_job(disposition)?;
        }
        let job = self.job.as_ref().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        let observed = self.observation.as_ref().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        let identity = self.identity.ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        let storage = self.storage()?;
        fields.boot = job.boot_id;
        fields.attempt = job.job_id;
        fields.not_before = job.not_before;
        fields.deadline = job.deadline;
        fields.job_digest = job.digest;
        fields.request_digest = aos_sandbox_protocol::storage_root_export::StorageCanaryExportRequestV1::decode(
            &request.request,
        ).map_err(|_| RuntimeDeploymentStorageDelegateErrorV2::Changed)?
            .digest().map_err(|_| RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        fields.storage_invocation = observed.invocation;
        fields.storage_pid = identity.pid();
        fields.storage_start_ticks = identity.start_time_ticks();
        fields.storage_profile = storage.digest;
        fields.storage_policy = storage.profile.canonical_policy.sha256;
        fields.storage = request.storage;
        fields.marker_transaction = Sha256::new()
            .chain_update(b"aos.sandbox.storage.canary-export-bootstrap-transaction.v1\0")
            .chain_update(request.marker).finalize()[..16].try_into()
            .map_err(|_| RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        fields.marker_digest = Sha256::digest(request.marker).into();
        fields.held_identity = request.marker[48..80].try_into()
            .map_err(|_| RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        fields.nonce = job.nonce;
        Ok(())
    }

    fn retain_result(&mut self, result: Result<(), RuntimeDeploymentStorageDelegateErrorV2>)
        -> Result<(), super::RuntimeDeploymentComparisonErrorV1>
    {
        match result {
            Ok(()) => { self.ready = true; Ok(()) }
            Err(error) => {
                self.ready = false;
                let slot = std::sync::Arc::get_mut(&mut self.first_failure)
                    .unwrap_or_else(|| std::process::abort());
                *slot = Some(error);
                Err(self.diagnostic())
            }
        }
    }

    fn require_vacant_failure(&mut self) {
        if self.first_failure.is_some() || std::sync::Arc::get_mut(&mut self.first_failure).is_none() {
            std::process::abort();
        }
    }

    fn diagnostic(&self) -> super::RuntimeDeploymentComparisonErrorV1 {
        super::RuntimeDeploymentComparisonErrorV1::delegate_diagnostic(
            std::sync::Arc::clone(&self.first_failure),
        )
    }

    fn storage(&self) -> Result<&RetainedCanaryStorageProfileV2, RuntimeDeploymentStorageDelegateErrorV2> {
        self.startup.canary_storage.as_ref().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)
    }

    fn capture_inner(
        &mut self,
        socket: &mut aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket,
        record: &aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
        disposition: DelegateRequestDispositionV3<'_>,
    ) -> Result<(), RuntimeDeploymentStorageDelegateErrorV2> {
        use aos_sandbox_protocol::runtime_deployment::canary::CanaryPublisherRequestV3;
        use aos_sandbox_protocol::host_canary_job::decode_host_canary_job_v1;

        self.startup.recheck()?;
        self.cookie = Some(socket.peer().socket_cookie());
        self.require_subject(socket, record)?;
        if matches!(disposition, DelegateRequestDispositionV3::Legacy) {
            self.request = Some(CanaryPublisherRequestV3::decode(record.payload())
                .map_err(|_| RuntimeDeploymentStorageDelegateErrorV2::Changed)?);
        }
        let size = self.request_for(disposition)?.job_bytes as usize;
        self.require_job_descriptor(record, size)?;
        self.job_bytes.try_reserve_exact(size).map_err(|_| RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        self.job_readback.try_reserve_exact(size).map_err(|_| RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        self.job_bytes.resize(size, 0);
        self.job_readback.resize(size, 0);
        aos_sandbox_linux::protected_file::read_exact_positioned_retaining_cause(
            &record.descriptors()[0], &mut self.job_bytes,
        )?;
        self.job = Some(decode_host_canary_job_v1(&self.job_bytes, &self.purpose.approval_pin())?);
        self.require_job(disposition)?;

        let original = record.subject().pidfd();
        self.proc = Some(original.prepare_proc_observations_v1());
        self.identity = Some(self.proc.as_mut().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?
            .capture_stat(original)?);
        let context = self.proc.as_mut().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?
            .capture_context(original)?;
        if context.strip_suffix(b"\n").or_else(|| context.strip_suffix(&[0])).unwrap_or(context)
            != STORAGE_CONTEXT_V2.as_bytes()
        {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        let pid = record.subject().credentials().pid().get();
        self.status = Some(open_storage_proc_v2(pid, "status")?);
        self.maps = Some(open_storage_proc_v2(pid, "maps")?);
        self.status_bytes.try_reserve_exact(64 * 1024 + 1)
            .map_err(|_| RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        self.maps_bytes.try_reserve_exact(256 * 1024 + 1)
            .map_err(|_| RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        self.executable = Some(File::from(rustix::fs::open(
            format!("/proc/{pid}/exe").as_str(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?));
        self.require_executable(self.executable.as_ref().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?)?;
        self.properties = Some(super::service_policy::observe_storage_properties_v2(pid));
        self.observation = Some(self.decode_properties(pid)?);
        let observed = self.observation.as_ref().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        let fragment = observed.fragment.clone();
        let expected_fragment = self.storage()?.profile.unit_sha256;
        self.fragment.open_and_measure(
            fragment, Some(expected_fragment), 64 * 1024, false,
        )?;
        self.cgroup_root = Some(rustix::fs::open(
            "/sys/fs/cgroup", rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )?);
        // The exact root is parked before this consuming lower constructor.
        // That provider's pre-return adoption prefix remains outside custody.
        let raw = self.cgroup_root.take().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        self.measured_cgroup_root = Some(aos_sandbox_linux::cgroup::CgroupV2Root::from_owned(raw)?);
        self.cgroup = Some(self.measured_cgroup_root.as_ref()
            .ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?
            .resolve(Path::new(&STORAGE_CGROUP_V2[1..]))?);
        self.recheck_inner(socket, record, disposition)
    }

    fn require_subject(
        &self,
        socket: &mut aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket,
        record: &aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
    ) -> Result<(), RuntimeDeploymentStorageDelegateErrorV2> {
        socket.validate_received_origin_retaining(record)?;
        let subject = record.subject();
        let credentials = subject.credentials();
        let peer = socket.peer();
        let info = subject.pidfd().info()?;
        let ids = info.credentials().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        if self.cookie != Some(peer.socket_cookie()) || record.descriptors().len() != 1
            || credentials.pid() != peer.credentials().pid()
            || credentials.uid() != 0 || credentials.gid() != 0
            || peer.credentials().uid() != 0 || peer.credentials().gid() != 0
            || info != subject.initial_info() || peer.pidfd().info()? != peer.initial_info()
            || info != peer.pidfd().info()? || !subject.is_alive()? || !peer.is_alive()?
            || info.pid() <= 1 || info.thread_group_id() != info.pid() || info.parent_pid() != 1
            || [ids.real_user_id(), ids.effective_user_id(), ids.saved_user_id(), ids.filesystem_user_id()] != [0; 4]
            || [ids.real_group_id(), ids.effective_group_id(), ids.saved_group_id(), ids.filesystem_group_id()] != [0; 4]
        {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        Ok(())
    }

    fn require_job_descriptor(
        &self,
        record: &aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
        size: usize,
    ) -> Result<(), RuntimeDeploymentStorageDelegateErrorV2> {
        use rustix::fs::{FileType, OFlags, SealFlags};
        let [descriptor] = record.descriptors()
        else { return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed); };
        let stat = rustix::fs::fstat(descriptor)?;
        let flags = rustix::fs::fcntl_getfl(descriptor)?;
        let seals = rustix::fs::fcntl_get_seals(descriptor)?;
        if !(1032..=aos_sandbox_protocol::host_canary_job::MAXIMUM_HOST_CANARY_JOB_BYTES).contains(&size)
            || stat.st_size != size as i64 || stat.st_uid != 0 || stat.st_gid != 0 || stat.st_nlink != 0
            || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || flags & OFlags::ACCMODE != OFlags::RDONLY || flags.contains(OFlags::PATH)
            || !seals.contains(SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE)
        {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        Ok(())
    }

    fn require_job(&self, disposition: DelegateRequestDispositionV3<'_>)
        -> Result<(), RuntimeDeploymentStorageDelegateErrorV2>
    {
        let request = self.request_for(disposition)?;
        let job = self.job.as_ref().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        let original = aos_sandbox_protocol::storage_root_export::StorageCanaryExportRequestV1::decode(&request.request)
            .map_err(|_| RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        if job.node_id != self.purpose.bytes()[48..64]
            || request.nonce != job.nonce || request.boot != job.boot_id
            || request.not_before != job.not_before || request.deadline != job.deadline
            || original.job_digest != job.digest || original.nonce != job.nonce
            || original.boot_id != job.boot_id || original.deadline_boottime_nanoseconds != job.deadline
        {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        Ok(())
    }

    fn require_executable(&self, actual: &File) -> Result<(), RuntimeDeploymentStorageDelegateErrorV2> {
        use std::os::unix::fs::MetadataExt as _;
        let profile = self.storage()?;
        let image = profile.runtime.iter().find(|image| image.path() == Path::new(&profile.profile.executable.path))
            .ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        let metadata = actual.metadata()?;
        if !metadata.is_file() || (metadata.dev(), metadata.ino(), metadata.len()) != image.observed_identity()? {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        Ok(())
    }

    fn decode_properties(&mut self, pid: u32)
        -> Result<super::service_policy::StoragePolicyObservationV2, RuntimeDeploymentStorageDelegateErrorV2>
    {
        self.decode_properties_result(StoragePropertySiteV2::Initial, pid)
    }

    fn decode_properties_result(
        &mut self,
        site: StoragePropertySiteV2,
        pid: u32,
    ) -> Result<super::service_policy::StoragePolicyObservationV2, RuntimeDeploymentStorageDelegateErrorV2> {
        if self.failed_property_site.is_some() {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        let result = match site {
            StoragePropertySiteV2::Initial => self.properties.as_ref(),
            StoragePropertySiteV2::Comparison => self.comparison_properties.as_ref(),
        };
        if matches!(result, Some(Err(_)) | Some(Ok(Ok(Err(_))))) {
            // Only a proven failed Result moves. Its site remains sticky while
            // the actual native cause enters the existing first-source slot.
            self.failed_property_site = Some(site);
            let failed = match site {
                StoragePropertySiteV2::Initial => self.properties.take(),
                StoragePropertySiteV2::Comparison => self.comparison_properties.take(),
            };
            return Err(match failed {
                Some(Err(error)) => RuntimeDeploymentStorageDelegateErrorV2::PropertyThreadSpawn(error),
                Some(Ok(Ok(Err(super::service_policy::StoragePropertiesCauseV2::Runtime(error))))) => {
                    RuntimeDeploymentStorageDelegateErrorV2::PropertyRuntime(error)
                }
                Some(Ok(Ok(Err(super::service_policy::StoragePropertiesCauseV2::Systemd(error))))) => {
                    RuntimeDeploymentStorageDelegateErrorV2::PropertySystemd(error)
                }
                Some(Ok(Ok(Err(super::service_policy::StoragePropertiesCauseV2::Deadline)))) => {
                    RuntimeDeploymentStorageDelegateErrorV2::PropertyDeadline
                }
                _ => std::process::abort(),
            });
        }
        if matches!(result, Some(Ok(Err(_)))) {
            // A thread panic payload is not an Error. Leave that whole Result
            // parked through terminal observations instead of inventing one.
            self.failed_property_site = Some(site);
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        let Some(Ok(Ok(Ok((service, unit))))) = result
        else { return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed); };
        let storage = self.storage()?;
        super::service_policy::decode_storage_properties_v2(
            service, unit, pid, &storage.profile.executable.path, &storage.profile.arguments,
        ).map_err(Into::into)
    }

    fn recheck_inner(
        &mut self,
        socket: &mut aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket,
        record: &aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
        disposition: DelegateRequestDispositionV3<'_>,
    ) -> Result<(), RuntimeDeploymentStorageDelegateErrorV2> {
        self.startup.recheck()?;
        self.require_subject(socket, record)?;
        self.require_job(disposition)?;
        let request = self.request_for(disposition)?;
        if request.encode().map_err(|_| RuntimeDeploymentStorageDelegateErrorV2::Changed)?.as_slice() != record.payload() {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        let size = self.job_bytes.len();
        self.require_job_descriptor(record, size)?;
        aos_sandbox_linux::protected_file::read_exact_positioned_retaining_cause(
            &record.descriptors()[0], &mut self.job_readback,
        )?;
        if self.job_readback != self.job_bytes { return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed); }
        let original = record.subject().pidfd();
        let proc = self.proc.as_mut().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        if Some(proc.observe_identity(original)?) != self.identity {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        let context = proc.observe_context(original)?;
        if context.strip_suffix(b"\n").or_else(|| context.strip_suffix(&[0])).unwrap_or(context)
            != STORAGE_CONTEXT_V2.as_bytes()
        {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        read_storage_proc_v2(self.status.as_mut().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?,
            &mut self.status_bytes, 64 * 1024)?;
        require_status(&self.status_bytes)?;
        read_storage_proc_v2(self.maps.as_mut().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?,
            &mut self.maps_bytes, 256 * 1024)?;
        let maps = std::str::from_utf8(&self.maps_bytes).map_err(|_| RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        let storage = self.storage()?;
        crate::normal_root::images::require_executable_mapping_data_v2(
            &storage.runtime, &[&storage.profile.executable.path, &storage.profile.loader.path], maps,
        ).map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
        self.require_executable(self.executable.as_ref().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?)?;
        if self.comparison_executable.is_some() {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        let pid = record.subject().credentials().pid().get();
        self.comparison_executable = Some(File::from(rustix::fs::open(
            format!("/proc/{pid}/exe").as_str(), rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?));
        self.require_executable(self.comparison_executable.as_ref().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?)?;
        self.fragment.measurement()?.revalidate()?;
        self.cgroup.as_ref().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?
            .verify_exact_membership(original)?;
        // Successful readback DATA may be retired only after its entire
        // original/clock sandwich. A failed Result remains resident forever.
        if !matches!(self.properties.as_ref(), Some(Ok(Ok(Ok(_)))))
            || self.comparison_properties.is_some()
        {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        self.comparison_properties = Some(super::service_policy::observe_storage_properties_v2(pid));
        if self.decode_properties_result(StoragePropertySiteV2::Comparison, pid)?
            != *self.observation.as_ref().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?
        {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        self.require_subject(socket, record)?;
        self.startup.recheck()?;
        self.require_original_clock()?;
        self.comparison_executable = None;
        self.comparison_properties = None;
        Ok(())
    }

    pub(super) fn require_original_clock(&self) -> Result<(), RuntimeDeploymentStorageDelegateErrorV2> {
        let job = self.job.as_ref().ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        let boot = aos_sandbox_linux::boot::KernelBootId::current()?;
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let seconds = u64::try_from(now.tv_sec).map_err(|_| RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        let nanos = u64::try_from(now.tv_nsec).map_err(|_| RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        let now = seconds.checked_mul(1_000_000_000).and_then(|value| value.checked_add(nanos))
            .ok_or(RuntimeDeploymentStorageDelegateErrorV2::Changed)?;
        if boot.into_bytes() != job.boot_id || now < job.not_before || now >= job.deadline {
            return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
        }
        Ok(())
    }
}

fn open_storage_proc_v2(pid: u32, suffix: &str) -> Result<File, RuntimeDeploymentStorageDelegateErrorV2> {
    let descriptor = rustix::fs::open(format!("/proc/{pid}/{suffix}").as_str(),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty())?;
    Ok(File::from(descriptor))
}

fn read_storage_proc_v2(file: &mut File, bytes: &mut Vec<u8>, maximum: usize)
    -> Result<(), RuntimeDeploymentStorageDelegateErrorV2>
{
    use std::io::{Seek as _, SeekFrom};
    let flags = rustix::fs::fcntl_getfl(&*file)?;
    if flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
        || flags.contains(rustix::fs::OFlags::PATH)
        || rustix::fs::fstatfs(&*file)?.f_type as u64 != 0x9fa0
    {
        return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
    }
    bytes.clear();
    file.seek(SeekFrom::Start(0))?;
    file.take(maximum as u64 + 1).read_to_end(bytes)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(RuntimeDeploymentStorageDelegateErrorV2::Changed);
    }
    Ok(())
}

fn retained_runtime_file_digest(pins: &[ImagePinV1], path: &Path) -> Option<[u8; 32]> {
    if pins.len() > MAXIMUM_RUNTIME_FILES {
        return None;
    }

    pins.iter()
        .find(|pin| Path::new(&pin.path).as_os_str() == path.as_os_str())
        .map(|pin| pin.sha256)
}

fn retain_profile(
    file: File,
) -> Result<(RetainedImmutableFileV1, Vec<u8>), RuntimeDeploymentStartupErrorV1> {
    require_readonly_launch_flags(
        rustix::fs::fcntl_getfl(&file).map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?,
    )
    .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
    let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
    let name = path.to_str().ok_or(RuntimeDeploymentStartupErrorV1::Profile)?;
    require_path_shape(name)?;
    if !name.ends_with(PROFILE_SUFFIX) {
        return Err(RuntimeDeploymentStartupErrorV1::Profile);
    }
    let retained = RetainedImmutableFileV1::retain_with_profile(
        path,
        file,
        None,
        MAXIMUM_PROFILE_BYTES as u64,
        false,
    )
    .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
    let bytes = retained
        .read_bounded()
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
    Ok((retained, bytes))
}

fn retain_pin(
    pin: &ImagePinV1,
    original: Option<File>,
    executable: bool,
) -> Result<RetainedImmutableFileV1, RuntimeDeploymentStartupErrorV1> {
    let path = PathBuf::from(&pin.path);
    match original {
        Some(file) => {
            require_readonly_launch_flags(
                rustix::fs::fcntl_getfl(&file).map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?,
            )
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
            RetainedImmutableFileV1::retain_with_profile(
                path,
                file,
                Some(pin.sha256),
                MAXIMUM_IMAGE_BYTES,
                executable,
            )
        }
        None => RetainedImmutableFileV1::open_with_profile(
            path,
            Some(pin.sha256),
            MAXIMUM_IMAGE_BYTES,
            executable,
        ),
    }
    .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)
}

// Shared canonical store shape is only schema DATA. The immutable-file engine
// independently retains the actual current inode, bounded bytes and read-only
// store mount. Neither parser nor a selected profile can mint this owner.
fn require_path_shape(path: &str) -> Result<(), RuntimeDeploymentStartupErrorV1> {
    crate::normal_root::profile::require_store_path(path)
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Profile)
}

fn read_bounded(path: &str, maximum: usize) -> Result<Vec<u8>, RuntimeDeploymentStartupErrorV1> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Confinement)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Confinement)?;
    if bytes.len() > maximum {
        return Err(RuntimeDeploymentStartupErrorV1::Confinement);
    }
    Ok(bytes)
}

fn require_status(bytes: &[u8]) -> Result<(), RuntimeDeploymentStartupErrorV1> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Confinement)?;
    for name in [
        "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp",
    ] {
        let prefix = format!("{name}:");
        let mut values = text.lines().filter_map(|line| line.strip_prefix(&prefix));
        let value = values
            .next()
            .ok_or(RuntimeDeploymentStartupErrorV1::Confinement)?
            .trim();
        let expected = match name {
            "NoNewPrivs" => "1",
            "Seccomp" => "2",
            _ => "0000000000000000",
        };
        if value != expected || values.next().is_some() {
            return Err(RuntimeDeploymentStartupErrorV1::Confinement);
        }
    }
    for name in ["Uid", "Gid"] {
        let prefix = format!("{name}:");
        let mut values = text.lines().filter_map(|line| line.strip_prefix(&prefix));
        let credentials = values
            .next()
            .ok_or(RuntimeDeploymentStartupErrorV1::Confinement)?
            .split_whitespace()
            .collect::<Vec<_>>();
        if credentials != ["0"; 4] || values.next().is_some() {
            return Err(RuntimeDeploymentStartupErrorV1::Confinement);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inert_profile() -> serde_json::Value {
        let root = "/nix/store/00000000000000000000000000000000-publisher";
        let profile = "/nix/store/11111111111111111111111111111111-aos-runtime-deployment-startup-profile-1";
        let pin = |path: String| json!({"path": path, "sha256": ([1_u8; 32].as_slice())});
        let executable = pin(format!("{root}/bin/aos-sandbox-runtime-publisher"));
        let loader = pin(format!("{root}/lib/ld.so"));
        json!({
            "format": "AOS_RUNTIME_DEPLOYMENT_STARTUP_1",
            "unit": UNIT,
            "owner_context": OWNER_CONTEXT,
            "helper_context": HELPER_CONTEXT,
            "executable": executable,
            "pid1": pin(format!("{root}/lib/systemd/systemd")),
            "loader": loader,
            "runtime_files": [executable, loader],
            "closure_roots": [root],
            "canonical_policy": pin("/nix/store/22222222222222222222222222222222-aos-selinux-kernel-policy-readback-1/policy.33".into()),
            "source_policy": pin(format!("{profile}/source-policy.33")),
            "effective_matrix": pin(format!("{profile}/effective-policy.tsv")),
            "unit_sha256": ([2_u8; 32].as_slice()),
        })
    }

    #[test]
    fn inert_profile_is_closed_to_deployment_roles_images_and_policy() {
        let bytes = serde_json::to_vec(&inert_profile()).expect("inert JSON");
        assert!(RuntimeDeploymentProfileV1::decode(&bytes).is_ok());

        for (field, substitute) in [
            ("format", json!("AOS_NORMAL_ROOT_STARTUP_1")),
            ("unit", json!("aos-sandbox-policy-authorityd.service")),
            ("owner_context", json!(HELPER_CONTEXT)),
            ("helper_context", json!(OWNER_CONTEXT)),
            ("unit_sha256", json!(([0_u8; 32].as_slice()))),
            ("runtime_files", json!([])),
            ("closure_roots", json!([])),
            ("extra_runtime_authority", json!(true)),
        ] {
            let mut profile = inert_profile();
            profile[field] = substitute;
            assert!(
                RuntimeDeploymentProfileV1::decode(
                    &serde_json::to_vec(&profile).expect("inert JSON"),
                ).is_err(),
                "{field}",
            );
        }
    }

    #[test]
    fn inert_profile_refuses_duplicate_runtime_paths_or_missing_loader_commitment() {
        let mut profile = inert_profile();
        profile["runtime_files"][1] = profile["runtime_files"][0].clone();
        assert!(RuntimeDeploymentProfileV1::decode(
            &serde_json::to_vec(&profile).expect("inert JSON"),
        ).is_err());

        let mut profile = inert_profile();
        profile["loader"]["sha256"] = json!(([3_u8; 32].as_slice()));
        assert!(RuntimeDeploymentProfileV1::decode(
            &serde_json::to_vec(&profile).expect("inert JSON"),
        ).is_err());
    }

    #[test]
    fn deployment_capture_has_no_empty_or_method46_role_fallback() {
        let roles = [LISTENER_FD_NAME.into(), PID1_FD_NAME.into(), PROFILE_FD_NAME.into()];
        assert!(valid_roles(&roles));
        assert!(!valid_roles(&[]));
        assert!(!valid_roles(&roles[..2]));
        assert!(!valid_roles(&[LISTENER_FD_NAME.into(), PID1_FD_NAME.into(), PID1_FD_NAME.into()]));
        assert!(!valid_roles(&[LISTENER_FD_NAME.into(), "aos-method46-pid1-image".into(), PROFILE_FD_NAME.into()]));
    }

    #[test]
    fn deployment_publisher_requires_actual_empty_capabilities_and_filtering() {
        let status = concat!(
            "CapInh:\t0000000000000000\n",
            "CapPrm:\t0000000000000000\n",
            "CapEff:\t0000000000000000\n",
            "CapBnd:\t0000000000000000\n",
            "CapAmb:\t0000000000000000\n",
            "NoNewPrivs:\t1\nSeccomp:\t2\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
        ).as_bytes();
        assert!(require_status(status).is_ok());

        let text = std::str::from_utf8(status).expect("ASCII");
        for (before, after) in [
            ("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            ("Seccomp:\t2", "Seccomp:\t0"),
            ("Uid:\t0\t0\t0\t0", "Uid:\t0\t0\t0\t1"),
            ("Gid:\t0\t0\t0\t0", "Gid:\t0\t1\t0\t0"),
        ] {
            assert!(require_status(text.replace(before, after).as_bytes()).is_err());
        }
        assert!(require_status(format!("{text}CapBnd:\t0000000000000000\n").as_bytes()).is_err());
    }

    #[test]
    fn unrun_retained_runtime_pin_lookup_is_exact_bounded_comparison_data() {
        let bytes = serde_json::to_vec(&inert_profile()).expect("inert profile");
        let profile = RuntimeDeploymentProfileV1::decode(&bytes).expect("closed profile DATA");
        let path = profile.executable.path.as_str();
        assert_eq!(
            retained_runtime_file_digest(&profile.runtime_files, Path::new(path)),
            Some(profile.executable.sha256),
        );

        for alias in [
            path.replace("/bin/", "/bin//"),
            path.replace("/bin/", "/bin/./"),
            format!("{path}/"),
            path.replace("/nix/store/", "//nix/store/"),
            path.replace("runtime-publisher", "installed-filter-collector"),
        ] {
            assert_eq!(
                retained_runtime_file_digest(&profile.runtime_files, Path::new(&alias)),
                None,
            );
        }
        assert_eq!(retained_runtime_file_digest(&[], Path::new(path)), None);

        let oversized = (0..=MAXIMUM_RUNTIME_FILES)
            .map(|_| ImagePinV1 {
                path: path.to_owned(),
                sha256: profile.executable.sha256,
            })
            .collect::<Vec<_>>();
        assert_eq!(retained_runtime_file_digest(&oversized, Path::new(path)), None);
    }
}
