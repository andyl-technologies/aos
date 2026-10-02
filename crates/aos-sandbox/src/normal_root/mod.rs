//! Shared selected-image comparisons for the existing normal Root and Controller.
//!
//! Actual early PID1 launch descriptors, image-owned profile, immutable file
//! measurements, loaded policy and genuine fixed-unit/process custody remain
//! retained. Controller independently captures the same selected profile and
//! later joins genuine PID1 launch properties to the original Root stream.
//! These comparisons are NOT Source floor, FUSE read or method46 authority.
//!
//! The profile resolves DT_NEEDED and the current executable mappings; it does
//! not authenticate arbitrary future dlopen, freeze PID1 administration, prove
//! continuous manager image identity after reexec. The held-owner Source genesis
//! coordinator consumes these comparisons together with the original Root stream;
//! a selected profile alone cannot construct an original-flight proof.

mod client;
mod controller_peer;
mod git_evidence_credential;
mod nix_offline_provision;
pub(crate) mod images;
mod nix_startup;
pub(crate) mod profile;
mod service;
pub(crate) mod startup;
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
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcessIdentity};
use aos_sandbox_linux::selinux_policy::VerifiedLiveSelinuxPolicy;
use rustix::fs::{Mode, OFlags, open};
use sha2::{Digest as _, Sha256};

use crate::immutable_image::RetainedImmutableFileV1;
use profile::{CONTEXT, NormalRootProfileV1, UNIT};

pub(crate) use client::OriginalNormalRootPeerV1;
pub use client::{
    ControllerInitialCaptureFailureRefV1, ProductionControllerInitialCaptureAttemptV1,
    ControllerProfileAdmissionFailureV1, ProductionControllerSelectedProfileAdmissionV1,
    ProductionControllerNormalRootCaptureV1, ProductionControllerNormalRootProfileV1,
    ProductionControllerNormalRootStartupPartsV1,
};
pub use client::source_successor_credential::{
    SourceSuccessorCredentialCustodyV2, SourceSuccessorCredentialErrorV2,
    require_source_successor_delivery_absent_v2,
};
pub(crate) use controller_peer::OriginalControllerPolicyPeerV1;
pub(crate) use git_evidence_credential::{
    RootGitEvidenceCredentialCustodyV1, RootGitEvidenceCredentialErrorV1,
};
pub use nix_startup::{
    ControllerNixSessionFloorOriginV2, NixOwnerPublicSessionFloorOriginV2,
    NixOwnerSessionFloorStartupV2,
    ProductionControllerNixStartupCaptureV1, ProductionControllerNixStartupV1,
    ProductionNixOwnerStartupCaptureV1, ProductionNixOwnerStartupV1,
};
pub use nix_offline_provision::{
    NixOfflineApprovedDataErrorV4, NixOfflineEffectApprovalKindV4,
    derive_nix_offline_public_candidates_v3, fill_nix_offline_static_preimage_v3,
    require_nix_offline_effect_approval_v4, require_nix_offline_static_approval_v3,
    require_nix_offline_static_header_v3,
    NixOfflineJobIdentityDataV5, inspect_nix_offline_job_identity_v5,
    nix_offline_job_has_original_label_v5,
    OfflineNixHardwareOriginV5, OfflineNixPrepareOriginV3,
    OfflineNixPrepareStartupErrorV3, OfflineNixPrepareStartupV3,
};

pub(super) const PID1_FD_NAME: &str = "aos-normal-root-pid1-image";
pub(super) const PROFILE_FD_NAME: &str = "aos-normal-root-profile";

/// Reports rejection of normal-Root startup comparison or original custody.
#[derive(Debug, thiserror::Error)]
pub enum NormalRootStartupErrorV1 {
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
    /// Current enforcing subject, capabilities or canonical policy differs.
    #[error("normal Root actual confinement differs")]
    Confinement,
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
pub fn observe_fixed_storage_worker_parent_v3(
) -> Result<StorageWorkerParentDataV3, NormalRootStartupErrorV1> {
    let process = PidFd::open(
        NonZeroU32::new(std::process::id()).ok_or(NormalRootStartupErrorV1::Service)?,
    )
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
    let cgroup = retain_fixed_cgroup(Path::new(
        "aos.slice/aos-control.slice/aos-storaged.service",
    ))?;
    cgroup
        .verify_exact_membership(&process)
        .map_err(|_| NormalRootStartupErrorV1::Service)?;
    aos_sandbox_linux::selinux_policy::require_enforcing()
        .map_err(|_| NormalRootStartupErrorV1::Confinement)?;
    require_subject("system_u:system_r:aos_sandbox_storage_t")
        .map_err(|_| NormalRootStartupErrorV1::Confinement)?;
    require_status(&read_bounded("/proc/self/status", 64 * 1024)?)?;

    let observed = service::observe_storage()?;

    cgroup
        .verify_exact_membership(&process)
        .map_err(|_| NormalRootStartupErrorV1::Service)?;
    if process.info().map_err(|_| NormalRootStartupErrorV1::Service)? != before
        || !process
            .is_alive()
            .map_err(|_| NormalRootStartupErrorV1::Service)?
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    Ok(observed)
}

/// Captures only the actual initial normal-Root process descriptor table.
///
/// Names/counts select slots, not authority. Capture must be the daemon's first
/// single-threaded operation, before credentials, journals or listeners open.
pub struct ProductionNormalRootStartupCaptureV1 {
    descriptors: Option<(OwnedFd, OwnedFd)>,
}

impl ProductionNormalRootStartupCaptureV1 {
    /// Copies the closed launch table once without accepting caller descriptors.
    ///
    /// # Errors
    /// Rejects extra/missing/duplicate roles, foreign activation PID or kernel
    /// failure. A failed or repeated capture is not recoverable in-process.
    pub fn capture() -> Result<Self, NormalRootStartupErrorV1> {
        let names = startup::names(2)?;
        let count = names.len();
        if !matches!(count, 0 | 2) {
            return Err(NormalRootStartupErrorV1::Activation);
        }
        if !valid_roles(&names) {
            return Err(NormalRootStartupErrorV1::Activation);
        }
        let descriptors = duplicate_initial_activation_table(count)
            .map_err(|_| NormalRootStartupErrorV1::Activation)?;
        if count == 0 {
            return Ok(Self { descriptors: None });
        }
        let mut pid1 = None;
        let mut profile = None;
        for (name, fd) in names.iter().zip(descriptors) {
            match name.as_str() {
                PID1_FD_NAME => pid1 = Some(fd),
                PROFILE_FD_NAME => profile = Some(fd),
                _ => return Err(NormalRootStartupErrorV1::Activation),
            }
        }
        Ok(Self {
            descriptors: Some((
                pid1.ok_or(NormalRootStartupErrorV1::Activation)?,
                profile.ok_or(NormalRootStartupErrorV1::Activation)?,
            )),
        })
    }

    /// Requires recovery/administrative CLI invocations to have no normal roles.
    ///
    /// # Errors
    /// Rejects a CLI invocation carrying the normal unit's original profile.
    pub fn require_non_normal_invocation(&self) -> Result<(), NormalRootStartupErrorV1> {
        if self.descriptors.is_some() {
            return Err(NormalRootStartupErrorV1::Activation);
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
        self,
        identities: [u32; 4],
    ) -> Result<Option<ProductionNormalRootStartupV1>, NormalRootStartupErrorV1> {
        let Some((pid1, profile_fd)) = self.descriptors else {
            // Legacy is never a proof. A labelled normal owner must have its
            // profile; failure to observe SELinux while mounted also closes.
            if Path::new("/sys/fs/selinux/enforce")
                .try_exists()
                .map_err(|_| NormalRootStartupErrorV1::Confinement)?
            {
                let context = read_bounded("/proc/thread-self/attr/current", 256)?;
                let context = context.strip_suffix(b"\n").unwrap_or(&context);
                let context = context.strip_suffix(&[0]).unwrap_or(context);
                if context == CONTEXT.as_bytes() {
                    return Err(NormalRootStartupErrorV1::Activation);
                }
            }
            return Ok(None);
        };
        let (profile_file, bytes) = images::retain_profile(File::from(profile_fd))?;
        let profile = NormalRootProfileV1::decode(&bytes)?;
        if profile.identities != identities
            || profile_file.path().parent() != Path::new(&profile.effective_matrix.path).parent()
        {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        let manager = images::retain_pin(&profile.pid1, Some(File::from(pid1)), true)?;
        let executable = images::retain_pin(
            &profile.executable,
            Some(File::open("/proc/self/exe").map_err(|_| NormalRootStartupErrorV1::Image)?),
            true,
        )?;
        let runtime = profile
            .runtime_files
            .iter()
            .map(|pin| {
                let executable =
                    pin.path == profile.executable.path || pin.path == profile.loader.path;
                images::retain_pin(pin, None, executable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let policy = VerifiedLiveSelinuxPolicy::verify(&profile.canonical_policy.path)
            .map_err(|_| NormalRootStartupErrorV1::Confinement)?;
        if policy.digest() != profile.canonical_policy.sha256 {
            return Err(NormalRootStartupErrorV1::Confinement);
        }
        let evidence = [
            &profile.canonical_policy,
            &profile.source_policy,
            &profile.effective_matrix,
        ]
        .into_iter()
        .map(|pin| images::retain_pin(pin, None, false))
        .collect::<Result<Vec<_>, _>>()?;
        let observed = service::observe(
            profile_file
                .path()
                .to_str()
                .ok_or(NormalRootStartupErrorV1::Profile)?,
        )?;
        let fragment = RetainedImmutableFileV1::observe_fragment(observed.fragment.clone())
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        require_unit(&fragment, &profile_file, &profile)?;
        let process = PidFd::open(
            NonZeroU32::new(std::process::id()).ok_or(NormalRootStartupErrorV1::Service)?,
        )
        .map_err(|_| NormalRootStartupErrorV1::Service)?;
        if process
            .info()
            .map_err(|_| NormalRootStartupErrorV1::Service)?
            .parent_pid()
            != 1
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        let identity = process
            .process_identity()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        let cgroup = retain_fixed_cgroup(Path::new(&format!("system.slice/{UNIT}")))?;
        let retained = ProductionNormalRootStartupV1 {
            profile_file,
            profile,
            manager,
            executable,
            runtime,
            evidence,
            fragment,
            policy,
            process,
            identity,
            cgroup,
            observed,
        };
        retained.recheck()?;
        Ok(Some(retained))
    }
}

/// Retains nonauthorizing normal-Root startup prerequisites in the server only.
///
/// This has no serialization, scalar factory or proof conversion. Independent
/// Controller comparisons do not grant genuine Root-last read authority;
/// neither Source genesis nor FUSE can consume this as a read grant.
#[must_use = "retain and recheck the server-local startup owner while serving"]
pub struct ProductionNormalRootStartupV1 {
    profile_file: RetainedImmutableFileV1,
    profile: NormalRootProfileV1,
    manager: RetainedImmutableFileV1,
    executable: RetainedImmutableFileV1,
    runtime: Vec<RetainedImmutableFileV1>,
    evidence: Vec<RetainedImmutableFileV1>,
    fragment: RetainedImmutableFileV1,
    policy: VerifiedLiveSelinuxPolicy,
    process: PidFd,
    identity: PidFdProcessIdentity,
    cgroup: RetainedCgroupAnchor,
    observed: service::ServiceObservationV1,
}

impl ProductionNormalRootStartupV1 {
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
        self.profile_file
            .revalidate()
            .map_err(|_| NormalRootStartupErrorV1::Profile)?;
        self.manager
            .revalidate()
            .map_err(|_| NormalRootStartupErrorV1::Image)?;
        self.executable
            .revalidate()
            .map_err(|_| NormalRootStartupErrorV1::Image)?;
        self.executable
            .require_executed(std::process::id())
            .map_err(|_| NormalRootStartupErrorV1::Image)?;
        for file in self.runtime.iter().chain(&self.evidence) {
            file.revalidate()
                .map_err(|_| NormalRootStartupErrorV1::Image)?;
        }
        images::require_actual_mappings(
            &self.runtime,
            &[&self.profile.executable.path, &self.profile.loader.path],
        )?;
        self.policy
            .revalidate(&self.profile.canonical_policy.path)
            .map_err(|_| NormalRootStartupErrorV1::Confinement)?;
        require_subject(CONTEXT).map_err(|_| NormalRootStartupErrorV1::Confinement)?;
        if rustix::process::getuid().as_raw() != 0
            || rustix::process::geteuid().as_raw() != 0
            || rustix::process::getgid().as_raw() != self.profile.identities[1]
            || rustix::process::getegid().as_raw() != self.profile.identities[1]
        {
            return Err(NormalRootStartupErrorV1::Confinement);
        }
        require_status(&read_bounded("/proc/self/status", 64 * 1024)?)?;
        if self
            .process
            .process_identity()
            .map_err(|_| NormalRootStartupErrorV1::Service)?
            != self.identity
            || self
                .process
                .info()
                .map_err(|_| NormalRootStartupErrorV1::Service)?
                .parent_pid()
                != 1
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.cgroup
            .verify_exact_membership(&self.process)
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        let observed = service::observe(
            self.profile_file
                .path()
                .to_str()
                .ok_or(NormalRootStartupErrorV1::Profile)?,
        )?;
        service::require_same(&self.observed, &observed)?;
        require_unit(&self.fragment, &self.profile_file, &self.profile)?;
        self.profile_file
            .revalidate()
            .map_err(|_| NormalRootStartupErrorV1::Profile)
    }
}

fn require_unit(
    fragment: &RetainedImmutableFileV1,
    profile_file: &RetainedImmutableFileV1,
    profile: &NormalRootProfileV1,
) -> Result<(), NormalRootStartupErrorV1> {
    let normalized = profile::normalized_unit(
        &fragment
            .read_bounded()
            .map_err(|_| NormalRootStartupErrorV1::Service)?,
        profile_file
            .path()
            .to_str()
            .ok_or(NormalRootStartupErrorV1::Profile)?,
    )?;
    if <[u8; 32]>::from(Sha256::digest(normalized)) != profile.unit_sha256 {
        return Err(NormalRootStartupErrorV1::Service);
    }
    Ok(())
}

fn valid_roles(names: &[String]) -> bool {
    names.is_empty()
        || names.len() == 2
            && names
                .iter()
                .filter(|name| name.as_str() == PID1_FD_NAME)
                .count()
                == 1
            && names
                .iter()
                .filter(|name| name.as_str() == PROFILE_FD_NAME)
                .count()
                == 1
}

fn retain_fixed_cgroup(path: &Path) -> Result<RetainedCgroupAnchor, NormalRootStartupErrorV1> {
    let root = CgroupV2Root::from_owned(
        open(
            "/sys/fs/cgroup",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| NormalRootStartupErrorV1::Service)?,
    )
    .map_err(|_| NormalRootStartupErrorV1::Service)?;
    root.resolve(path)
        .map_err(|_| NormalRootStartupErrorV1::Service)
}

fn read_bounded(path: &str, maximum: usize) -> Result<Vec<u8>, NormalRootStartupErrorV1> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| NormalRootStartupErrorV1::Confinement)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| NormalRootStartupErrorV1::Confinement)?;
    if bytes.len() > maximum {
        return Err(NormalRootStartupErrorV1::Confinement);
    }
    Ok(bytes)
}

fn require_status(bytes: &[u8]) -> Result<(), NormalRootStartupErrorV1> {
    let text = std::str::from_utf8(bytes).map_err(|_| NormalRootStartupErrorV1::Confinement)?;
    for name in [
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
    ] {
        let mut values = text
            .lines()
            .filter_map(|line| line.strip_prefix(&format!("{name}:")));
        let value = values
            .next()
            .ok_or(NormalRootStartupErrorV1::Confinement)?
            .trim();
        if values.next().is_some()
            || if name == "NoNewPrivs" {
                value != "1"
            } else {
                value.len() != 16 || !value.bytes().all(|byte| byte == b'0')
            }
        {
            return Err(NormalRootStartupErrorV1::Confinement);
        }
    }
    Ok(())
}
