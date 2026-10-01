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
    UNIT, RuntimeDeploymentStartupErrorV1,
};

const MAXIMUM_PROFILE_BYTES: usize = 1024 * 1024;
const MAXIMUM_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_RUNTIME_FILES: usize = 512;
const PROFILE_SUFFIX: &str = "-aos-runtime-deployment-startup-profile-1/profile.json";

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

impl RuntimeDeploymentProfileV1 {
    fn decode(bytes: &[u8]) -> Result<Self, RuntimeDeploymentStartupErrorV1> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_PROFILE_BYTES {
            return Err(RuntimeDeploymentStartupErrorV1::Profile);
        }
        let profile: Self = serde_json::from_slice(bytes)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Profile)?;
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
        let listener = RecordSubjectListener::from_owned(self.listener)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Activation)?;
        listener
            .require_local_filesystem_path(Path::new(SOCKET_PATH))
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Activation)?;
        let (profile_file, bytes) = retain_profile(File::from(self.profile))?;
        let profile_digest = Sha256::digest(&bytes).into();
        let profile = RuntimeDeploymentProfileV1::decode(&bytes)?;
        if profile_file.path().parent() != Path::new(&profile.effective_matrix.path).parent() {
            return Err(RuntimeDeploymentStartupErrorV1::Profile);
        }

        let manager = retain_pin(&profile.pid1, Some(File::from(self.pid1)), true)?;
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
        let service = RetainedDeploymentServicePolicyV1::retain(
            profile_file.path(),
            &profile.executable.path,
            profile.unit_sha256,
            &process,
        )?;
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
}

impl ProductionRuntimeDeploymentStartupV1 {
    /// Rechecks the same original image, policy, service and process custody.
    ///
    /// PID1's current executed inode is compared with the original OpenFile;
    /// its launch descriptor alone is not continuous reexec evidence. Current
    /// executable mappings are checked with the existing shared image reader.
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
        self.manager
            .require_executed(1)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
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

        self.manager
            .require_executed(1)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Image)?;
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
        let pin = |path: String| json!({"path": path, "sha256": [1_u8; 32].as_slice()});
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
            "unit_sha256": [2_u8; 32].as_slice(),
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
            ("unit_sha256", json!([0_u8; 32].as_slice())),
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
        profile["loader"]["sha256"] = json!([3_u8; 32].as_slice());
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
