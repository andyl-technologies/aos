//! Original fixed-purpose Nix startup custody, captured before protected I/O.
//!
//! The Controller shares its one initial descriptor capture with normal Root;
//! the Nix owner consumes its own closed table. Immutable profiles are image
//! comparisons, not transferable authority. Actual original PID1, process,
//! invocation, cgroup, confinement and delivered descriptors remain retained.
//!
//! ```text
//! AOS_NIX_STARTUP_2: closed role + identities + immutable image/policy pins
//!                 + selected-unit SHA256 after one profile-path normalization
//! ```

mod floor_origin;

pub use floor_origin::{ControllerNixSessionFloorOriginV2, NixOwnerSessionFloorStartupV2};

use std::fs::File;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};

use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::guest_confinement::{require_subject, task_has_subject};
use aos_sandbox_linux::inherited_fd::duplicate_initial_activation_table;
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcessIdentity};
use aos_sandbox_linux::selinux_policy::VerifiedLiveSelinuxPolicy;
use aos_systemd::{OwnedValue, Value};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::immutable_image::{RetainedImmutableFileV1, require_readonly_launch_flags};
use crate::systemd_property_data;

use super::{NormalRootStartupErrorV1 as Error, images, profile::ImagePinV1, service, startup};

pub(super) const CONTROLLER_PROFILE_NAME: &str = "aos-nix-controller-profile";
pub(super) const CONTROLLER_PID1_NAME: &str = "aos-nix-controller-pid1-image";
const OWNER_PROFILE_NAME: &str = "aos-nix-owner-profile";
const OWNER_PID1_NAME: &str = "aos-nix-owner-pid1-image";
const OWNER_LISTENER_NAME: &str = "aos-sandbox-nixd-control";
const PROFILE_PLACEHOLDER: &str = "@AOS_NIX_PROFILE@";
const OWNER_CAPABILITIES: u64 = (1 << 6) | (1 << 7);

#[derive(Clone, Copy, Eq, PartialEq)]
enum Role {
    Controller,
    Owner,
}

impl Role {
    fn unit(self) -> &'static str {
        match self {
            Self::Controller => "aos-sandboxd.service",
            Self::Owner => "aos-sandbox-nixd.service",
        }
    }

    fn cgroup(self) -> &'static str {
        match self {
            Self::Controller => "aos.slice/aos-control.slice/aos-sandboxd.service",
            Self::Owner => "aos.slice/aos-control.slice/aos-sandbox-nixd.service",
        }
    }

    fn context(self) -> &'static str {
        match self {
            Self::Controller => "system_u:system_r:aos_sandbox_controller_t",
            Self::Owner => "system_u:system_r:aos_sandbox_nix_t",
        }
    }

    fn helper_context(self) -> &'static str {
        match self {
            Self::Controller => "system_u:system_r:aos_nix_controller_floor_helper_t",
            Self::Owner => "system_u:system_r:aos_nix_owner_floor_helper_t",
        }
    }

    fn profile_name(self) -> &'static str {
        match self {
            Self::Controller => CONTROLLER_PROFILE_NAME,
            Self::Owner => OWNER_PROFILE_NAME,
        }
    }

    fn pid1_name(self) -> &'static str {
        match self {
            Self::Controller => CONTROLLER_PID1_NAME,
            Self::Owner => OWNER_PID1_NAME,
        }
    }

    fn capabilities(self) -> u64 {
        match self {
            Self::Controller => 0,
            Self::Owner => OWNER_CAPABILITIES,
        }
    }

    fn helper_name(self) -> &'static str {
        match self {
            Self::Controller => "aos-nix-controller-tpm-helper",
            Self::Owner => "aos-nix-owner-tpm-helper",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NixStartupProfileV2 {
    format: String,
    role: String,
    unit: String,
    context: String,
    identities: [u32; 4],
    executable: ImagePinV1,
    pid1: ImagePinV1,
    loader: ImagePinV1,
    runtime_files: Vec<ImagePinV1>,
    helper: ImagePinV1,
    helper_loader: ImagePinV1,
    canonical_policy: ImagePinV1,
    source_policy: ImagePinV1,
    effective_matrix: ImagePinV1,
    unit_sha256: [u8; 32],
}

impl NixStartupProfileV2 {
    fn decode(bytes: &[u8], role: Role, identities: [u32; 4]) -> Result<Self, Error> {
        let profile: Self = serde_json::from_slice(bytes).map_err(|_| Error::Profile)?;
        let expected_role = match role {
            Role::Controller => "controller",
            Role::Owner => "owner",
        };
        let expected_executable = match role {
            Role::Controller => "aos-sandboxd",
            Role::Owner => "aos-sandbox-nixd",
        };
        if profile.format != "AOS_NIX_STARTUP_2"
            || profile.role != expected_role
            || profile.unit != role.unit()
            || profile.context != role.context()
            || profile.identities != identities
            || identities.contains(&0)
            || profile.unit_sha256 == [0; 32]
            || profile.runtime_files.is_empty()
            || profile.runtime_files.len() > 512
            || profile.runtime_files.windows(2).any(|pair| pair[0].path >= pair[1].path)
            || Path::new(&profile.executable.path).file_name().is_none_or(|name| name != expected_executable)
            || Path::new(&profile.helper.path).file_name().is_none_or(|name| name != role.helper_name())
        {
            return Err(Error::Profile);
        }

        for pin in profile.runtime_files.iter().chain([
            &profile.executable, &profile.pid1, &profile.loader,
            &profile.helper, &profile.helper_loader, &profile.canonical_policy,
            &profile.source_policy, &profile.effective_matrix,
        ]) {
            super::profile::require_store_path(&pin.path)?;
            if pin.sha256 == [0; 32] {
                return Err(Error::Profile);
            }
        }
        for pin in [&profile.executable, &profile.loader] {
            if !profile.runtime_files.iter().any(|member| {
                member.path == pin.path && member.sha256 == pin.sha256
            }) {
                return Err(Error::Profile);
            }
        }
        if Path::new(&profile.source_policy.path).parent()
            != Path::new(&profile.effective_matrix.path).parent()
            || !profile.canonical_policy.path.ends_with("-aos-selinux-kernel-policy-readback-1/policy.33")
            || !profile.source_policy.path.ends_with("-aos-nix-startup-profile-2/source-policy.33")
            || !profile.effective_matrix.path.ends_with("-aos-nix-startup-profile-2/effective-policy.tsv")
        {
            return Err(Error::Profile);
        }
        Ok(profile)
    }
}

/// Holds only the paired Nix roles from Controller's original complete table.
pub struct ProductionControllerNixStartupCaptureV1 {
    pid1: OwnedFd,
    profile: OwnedFd,
    root_profile: Option<OwnedFd>,
    method46_image: bool,
}

impl ProductionControllerNixStartupCaptureV1 {
    pub(super) fn from_initial_table(
        pid1: OwnedFd,
        profile: OwnedFd,
        root_profile: Option<OwnedFd>,
        method46_image: bool,
    ) -> Self {
        Self {
            pid1,
            profile,
            root_profile,
            method46_image,
        }
    }

    /// Admits actual selected Controller startup comparisons for Nix058.
    ///
    /// # Errors
    /// Rejects selected-image, configured identity, launch, process or policy
    /// substitution. This does not itself establish a current journal or floor.
    pub fn admit_selected(
        self,
        identities: [u32; 4],
    ) -> Result<ProductionControllerNixStartupV1, Error> {
        let root_profile = self
            .root_profile
            .map(|fd| images::retain_profile(File::from(fd)))
            .transpose()?
            .map(|(file, _)| file);

        Ok(ProductionControllerNixStartupV1 {
            retained: RetainedNixStartup::admit(
                Role::Controller,
                self.pid1,
                self.profile,
                root_profile,
                self.method46_image,
                identities,
            )?,
        })
    }
}

/// Holds Nix owner's complete original listener/profile/PID1 launch table.
pub struct ProductionNixOwnerStartupCaptureV1 {
    pid1: OwnedFd,
    profile: OwnedFd,
}

impl ProductionNixOwnerStartupCaptureV1 {
    /// Captures the sole fixed Nix owner launch table before protected I/O.
    ///
    /// # Errors
    /// Rejects missing, repeated, duplicate, foreign or additional launch roles.
    pub fn capture() -> Result<(Self, OwnedFd), Error> {
        let names = startup::names(3)?;
        let expected_names = [OWNER_PID1_NAME, OWNER_PROFILE_NAME, OWNER_LISTENER_NAME];
        let has_exact_names = expected_names.iter().all(|expected| {
            names.iter().filter(|name| name.as_str() == *expected).count() == 1
        });
        if names.len() != 3 || !has_exact_names
        {
            return Err(Error::Activation);
        }

        let descriptors = duplicate_initial_activation_table(3).map_err(|_| Error::Activation)?;
        let mut pid1 = None;
        let mut profile = None;
        let mut listener = None;
        for (name, fd) in names.iter().zip(descriptors) {
            match name.as_str() {
                OWNER_PID1_NAME => pid1 = Some(fd),
                OWNER_PROFILE_NAME => profile = Some(fd),
                OWNER_LISTENER_NAME => listener = Some(fd),
                _ => return Err(Error::Activation),
            }
        }
        Ok((
            Self {
                pid1: pid1.ok_or(Error::Activation)?,
                profile: profile.ok_or(Error::Activation)?,
            },
            listener.ok_or(Error::Activation)?,
        ))
    }

    /// Admits the selected root control owner with only credential-drop caps.
    ///
    /// # Errors
    /// Rejects substituted image, identities, actual root control credentials,
    /// capabilities, MAC, original invocation or cgroup custody.
    pub fn admit_selected(
        self,
        identities: [u32; 4],
    ) -> Result<ProductionNixOwnerStartupV1, Error> {
        Ok(ProductionNixOwnerStartupV1 {
            retained: RetainedNixStartup::admit(
                Role::Owner,
                self.pid1,
                self.profile,
                None,
                false,
                identities,
            )?,
        })
    }
}

/// Retains actual Controller Nix058 image, invocation and confinement custody.
pub struct ProductionControllerNixStartupV1 {
    retained: RetainedNixStartup,
}

/// Retains actual Nix059 root control-owner startup, not worker authority.
pub struct ProductionNixOwnerStartupV1 {
    retained: RetainedNixStartup,
}

macro_rules! startup_methods {
    ($owner:ty) => {
        impl $owner {
            /// Rechecks original selected images, unit, process and confinement.
            ///
            /// # Errors
            /// Rejects changed names, bytes, policy, roles, credentials or launch.
            pub fn recheck(&self) -> Result<(), Error> {
                self.retained.recheck()
            }

            pub(crate) fn retained_pid1(&self) -> &RetainedImmutableFileV1 {
                &self.retained.pid1
            }

            pub(crate) fn profile_path(&self) -> &Path {
                self.retained.profile_file.path()
            }

            pub(crate) fn invocation(&self) -> [u8; 16] {
                self.retained.observed.invocation
            }

            pub(crate) fn require_floor_helper(&self, process: &PidFd) -> Result<(), Error> {
                self.retained.require_floor_helper(process)
            }
        }
    };
}

startup_methods!(ProductionControllerNixStartupV1);
startup_methods!(ProductionNixOwnerStartupV1);

struct RetainedNixStartup {
    role: Role,
    profile_file: RetainedImmutableFileV1,
    profile: NixStartupProfileV2,
    pid1: RetainedImmutableFileV1,
    executable: RetainedImmutableFileV1,
    helper: RetainedImmutableFileV1,
    runtime: Vec<RetainedImmutableFileV1>,
    evidence: Vec<RetainedImmutableFileV1>,
    root_profile: Option<RetainedImmutableFileV1>,
    method46_image: bool,
    policy: VerifiedLiveSelinuxPolicy,
    process: PidFd,
    identity: PidFdProcessIdentity,
    cgroup: RetainedCgroupAnchor,
    fragment: RetainedImmutableFileV1,
    observed: service::ServiceObservationV1,
}

impl RetainedNixStartup {
    fn admit(
        role: Role,
        pid1: OwnedFd,
        profile_fd: OwnedFd,
        root_profile: Option<RetainedImmutableFileV1>,
        method46_image: bool,
        identities: [u32; 4],
    ) -> Result<Self, Error> {
        let (profile_file, bytes) = retain_profile(File::from(profile_fd), role)?;
        let profile = NixStartupProfileV2::decode(&bytes, role, identities)?;
        let pid1 = images::retain_pin(&profile.pid1, Some(File::from(pid1)), true)?;
        let executable = images::retain_pin(&profile.executable, Some(File::open("/proc/self/exe").map_err(|_| Error::Image)?), true)?;
        let helper = images::retain_pin(&profile.helper, None, true)?;
        let runtime = profile.runtime_files.iter().map(|pin| {
            images::retain_pin(pin, None, pin.path == profile.executable.path || pin.path == profile.loader.path)
        }).collect::<Result<Vec<_>, _>>()?;
        let evidence = [&profile.helper_loader, &profile.canonical_policy, &profile.source_policy, &profile.effective_matrix]
            .into_iter().map(|pin| images::retain_pin(pin, None, pin.path == profile.helper_loader.path))
            .collect::<Result<Vec<_>, _>>()?;
        let policy = VerifiedLiveSelinuxPolicy::verify(&profile.canonical_policy.path).map_err(|_| Error::Confinement)?;
        if policy.digest() != profile.canonical_policy.sha256 {
            return Err(Error::Confinement);
        }
        let process = PidFd::open(NonZeroU32::new(std::process::id()).ok_or(Error::Service)?)
            .map_err(|_| Error::Service)?;
        let identity = process.process_identity().map_err(|_| Error::Service)?;
        let cgroup = super::retain_fixed_cgroup(Path::new(role.cgroup()))?;
        let observed = observe_delivery(role, profile_file.path(), root_profile.as_ref().map(|file| file.path()), method46_image)?;
        let fragment = RetainedImmutableFileV1::observe_fragment(observed.fragment.clone()).map_err(|_| Error::Service)?;
        let retained = Self {
            role, profile_file, profile, pid1, executable, helper, runtime, evidence,
            root_profile, method46_image, policy, process, identity, cgroup, fragment, observed,
        };
        retained.recheck()?;
        Ok(retained)
    }

    fn recheck(&self) -> Result<(), Error> {
        for file in [&self.profile_file, &self.pid1, &self.executable, &self.helper, &self.fragment]
            .into_iter().chain(&self.runtime).chain(&self.evidence).chain(&self.root_profile)
        {
            file.revalidate().map_err(|_| Error::Image)?;
        }
        self.pid1.require_executed(1).map_err(|_| Error::Image)?;
        self.executable.require_executed(std::process::id()).map_err(|_| Error::Image)?;
        images::require_actual_mappings(&self.runtime, &[&self.profile.executable.path, &self.profile.loader.path])?;
        self.policy.revalidate(&self.profile.canonical_policy.path).map_err(|_| Error::Confinement)?;
        require_subject(self.role.context()).map_err(|_| Error::Confinement)?;
        require_status(&super::read_bounded("/proc/self/status", 65_536)?, self.role.capabilities(), self.role.capabilities())?;
        let uid = if self.role == Role::Controller { self.profile.identities[0] } else { 0 };
        let gid = if self.role == Role::Controller { self.profile.identities[1] } else { 0 };
        if rustix::process::getuid().as_raw() != uid || rustix::process::geteuid().as_raw() != uid
            || rustix::process::getgid().as_raw() != gid || rustix::process::getegid().as_raw() != gid
            || self.process.process_identity().map_err(|_| Error::Service)? != self.identity
        {
            return Err(Error::Confinement);
        }
        let info = self
            .cgroup
            .verify_exact_membership(&self.process)
            .map_err(|_| Error::Service)?;
        let credentials = info.credentials().ok_or(Error::Confinement)?;
        if [
            credentials.real_user_id(),
            credentials.effective_user_id(),
            credentials.saved_user_id(),
            credentials.filesystem_user_id(),
        ] != [uid; 4]
            || [
                credentials.real_group_id(),
                credentials.effective_group_id(),
                credentials.saved_group_id(),
                credentials.filesystem_group_id(),
            ] != [gid; 4]
        {
            return Err(Error::Confinement);
        }
        if info.parent_pid() != 1 || !self.process.is_alive().map_err(|_| Error::Service)? {
            return Err(Error::Service);
        }
        let observed = observe_delivery(self.role, self.profile_file.path(), self.root_profile.as_ref().map(|file| file.path()), self.method46_image)?;
        service::require_same(&self.observed, &observed)?;
        require_unit(&self.fragment, self.profile_file.path(), self.role, self.profile.unit_sha256)
    }

    fn require_floor_helper(&self, process: &PidFd) -> Result<(), Error> {
        self.recheck()?;
        let info = self.cgroup.verify_exact_membership(process).map_err(|_| Error::Service)?;
        let uid = if self.role == Role::Controller { self.profile.identities[0] } else { 0 };
        let gid = if self.role == Role::Controller { self.profile.identities[1] } else { 0 };
        let credentials = info.credentials().ok_or(Error::Confinement)?;
        if info.parent_pid() != std::process::id()
            || [credentials.real_user_id(), credentials.effective_user_id(), credentials.saved_user_id(), credentials.filesystem_user_id()] != [uid; 4]
            || [credentials.real_group_id(), credentials.effective_group_id(), credentials.saved_group_id(), credentials.filesystem_group_id()] != [gid; 4]
            || !process.is_alive().map_err(|_| Error::Service)?
            || !task_has_subject(process, self.role.helper_context()).map_err(|_| Error::Confinement)?
        {
            return Err(Error::Confinement);
        }
        self.helper.require_executed(info.thread_group_id()).map_err(|_| Error::Image)?;
        require_status(&super::read_bounded(&format!("/proc/{}/status", info.thread_group_id()), 65_536)?, 0, self.role.capabilities())?;
        self.recheck()
    }
}

fn retain_profile(file: File, role: Role) -> Result<(RetainedImmutableFileV1, Vec<u8>), Error> {
    require_readonly_launch_flags(rustix::fs::fcntl_getfl(&file).map_err(|_| Error::Image)?)
        .map_err(|_| Error::Image)?;
    let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(|_| Error::Image)?;
    super::profile::require_store_path(path.to_str().ok_or(Error::Profile)?)?;
    let basename = if role == Role::Controller { "controller.json" } else { "owner.json" };
    if !path.to_string_lossy().ends_with(&format!("-aos-nix-startup-profile-2/{basename}")) {
        return Err(Error::Profile);
    }
    let retained = RetainedImmutableFileV1::retain_with_profile(path, file, None, 1_048_576, false)
        .map_err(|_| Error::Image)?;
    let bytes = retained.read_bounded().map_err(|_| Error::Image)?;
    Ok((retained, bytes))
}

pub(super) fn retain_controller_profile(file: File) -> Result<RetainedImmutableFileV1, Error> {
    retain_profile(file, Role::Controller).map(|(retained, _)| retained)
}

fn observe_delivery(role: Role, profile: &Path, root_profile: Option<&Path>, method46_image: bool) -> Result<service::ServiceObservationV1, Error> {
    let (properties, unit) = service::read_properties(role.unit(), std::process::id(), service::SERVICE_PROPERTIES)?;
    service::immutable_observation(decode_delivery(&properties, &unit, role, profile, root_profile, method46_image)?)
}

fn decode_delivery(properties: &[OwnedValue], unit: &[OwnedValue], role: Role, profile: &Path, root_profile: Option<&Path>, method46_image: bool) -> Result<service::ServiceObservationV1, Error> {
    let [cgroup, files, extras, maximum, stored, context, bounding, ambient, nnp] = properties else {
        return Err(Error::Service);
    };
    let context = systemd_property_data::explicit_context(context).ok_or(Error::Service)?;
    let Value::Array(files) = &**files else { return Err(Error::Service); };
    let Value::Array(extras) = &**extras else { return Err(Error::Service); };
    let cgroup_path = format!("/{}", role.cgroup());
    if <&str>::try_from(cgroup).ok() != Some(cgroup_path.as_str())
        || context != role.context()
        || u64::try_from(bounding).ok() != Some(role.capabilities())
        || u64::try_from(ambient).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true)
        || u32::try_from(maximum).ok() != Some(0) || u32::try_from(stored).ok() != Some(0)
        || !extras.is_empty() || extras.element_signature() != Value::from("").value_signature()
    {
        return Err(Error::Service);
    }
    let mut expected = vec![(profile.to_path_buf(), role.profile_name()), (PathBuf::from("/proc/1/exe"), role.pid1_name())];
    if let Some(root) = root_profile {
        expected.push((root.to_path_buf(), super::client::PROFILE_NAME));
    }
    if method46_image {
        expected.push((PathBuf::from("/proc/1/exe"), "aos-method46-pid1-image"));
    }
    if files.len() != expected.len() {
        return Err(Error::Service);
    }
    let mut seen = vec![false; expected.len()];
    for entry in files.inner() {
        let Value::Structure(entry) = entry else { return Err(Error::Service); };
        let [Value::Str(path), Value::Str(name), Value::U64(1)] = entry.fields() else { return Err(Error::Service); };
        let index = expected.iter().position(|(expected_path, expected_name)| {
            Path::new(path.as_str()) == expected_path && name.as_str() == *expected_name
        }).ok_or(Error::Service)?;
        if seen[index] {
            return Err(Error::Service);
        }
        seen[index] = true;
    }
    service::decode_unit(unit, role.unit())
}

fn require_unit(fragment: &RetainedImmutableFileV1, profile: &Path, role: Role, expected: [u8; 32]) -> Result<(), Error> {
    let bytes = fragment.read_bounded().map_err(|_| Error::Service)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::Service)?;
    let actual = format!("OpenFile={}:{}:read-only\n", profile.to_str().ok_or(Error::Profile)?, role.profile_name());
    if text.split_inclusive('\n').filter(|line| *line == actual).count() != 1 {
        return Err(Error::Service);
    }
    let replacement = format!("OpenFile={PROFILE_PLACEHOLDER}:{}:read-only\n", role.profile_name());
    let normalized = text.split_inclusive('\n').map(|line| {
        if line == actual { replacement.as_str() } else { line }
    }).collect::<String>();
    if <[u8; 32]>::from(Sha256::digest(normalized.as_bytes())) != expected {
        return Err(Error::Service);
    }
    Ok(())
}

fn require_status(bytes: &[u8], effective: u64, bounding: u64) -> Result<(), Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Confinement)?;
    for (name, expected) in [("CapInh", 0), ("CapPrm", effective), ("CapEff", effective), ("CapBnd", bounding), ("CapAmb", 0), ("NoNewPrivs", 1)] {
        let mut values = text.lines().filter_map(|line| line.strip_prefix(&format!("{name}:")));
        let value = values.next().ok_or(Error::Confinement)?.trim();
        let actual = if name == "NoNewPrivs" { value.parse().ok() } else {
            (value.len() == 16).then(|| u64::from_str_radix(value, 16).ok()).flatten()
        };
        if values.next().is_some() || actual != Some(expected) {
            return Err(Error::Confinement);
        }
    }
    Ok(())
}
