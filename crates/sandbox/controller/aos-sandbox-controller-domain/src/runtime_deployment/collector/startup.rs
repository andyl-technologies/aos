//! Captures and continuously rechecks the one original fixed collector startup.
//!
//! All image/profile paths come from the original PID1 OpenFiles table and its
//! bounded immutable profile. No caller path, FD, context or capability scalar
//! can construct this owner. It supplies no Prepared floor permit or Ready.
//!
//! ```text
//! AOS_INSTALLED_FILTER_COLLECTOR_STARTUP_1:
//! fixed unit/MAC + executable/PID1/loader + closure + policy/unit SHA256 +
//! fixed reader/network/nspawn + specimen root/init/digest-pin commitments
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

use super::service_policy::RetainedCollectorServicePolicyV1;
use super::{
    CAPABILITIES, CONTEXT, InstalledCollectorStartupErrorV1 as Error,
    LISTENER_FD_NAME, PID1_FD_NAME, PROFILE_FD_NAME, SOCKET_PATH, UNIT,
};

const PROFILE_BYTES: usize = 1024 * 1024;
const IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const RUNTIME_FILES: usize = 512;
const PROFILE_SUFFIX: &str = "-aos-installed-filter-collector-startup-profile-1/profile.json";
const ROOT_SUFFIX: &str = "-aos-sandbox-deployment-specimen-root-0.1.0/root";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImagePinV1 {
    pub(super) path: String,
    pub(super) sha256: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CollectorProfileV1 {
    format: String,
    unit: String,
    context: String,
    pub(super) executable: ImagePinV1,
    pub(super) pid1: ImagePinV1,
    pub(super) loader: ImagePinV1,
    pub(super) runtime_files: Vec<ImagePinV1>,
    closure_roots: Vec<String>,
    pub(super) canonical_policy: ImagePinV1,
    pub(super) source_policy: ImagePinV1,
    pub(super) effective_matrix: ImagePinV1,
    pub(super) unit_sha256: [u8; 32],
    pub(super) reader: ImagePinV1,
    pub(super) network: ImagePinV1,
    pub(super) nspawn: ImagePinV1,
    pub(super) specimen_root: String,
    pub(super) specimen_root_sha256: [u8; 32],
    pub(super) specimen_init: ImagePinV1,
    pub(super) specimen_root_digest_pin: ImagePinV1,
}

impl CollectorProfileV1 {
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > PROFILE_BYTES {
            return Err(Error::Profile);
        }

        let profile: Self = serde_json::from_slice(bytes).map_err(|_| Error::Profile)?;
        if profile.format != "AOS_INSTALLED_FILTER_COLLECTOR_STARTUP_1"
            || profile.unit != UNIT
            || profile.context != CONTEXT
            || profile.unit_sha256 == [0; 32]
            || profile.specimen_root_sha256 == [0; 32]
            || profile.runtime_files.is_empty()
            || profile.runtime_files.len() > RUNTIME_FILES
            || profile.closure_roots.is_empty()
            || profile.closure_roots.len() > RUNTIME_FILES
            || profile
                .runtime_files
                .windows(2)
                .any(|pins| pins[0].path >= pins[1].path)
            || profile
                .closure_roots
                .windows(2)
                .any(|roots| roots[0] >= roots[1])
        {
            return Err(Error::Profile);
        }

        for root in &profile.closure_roots {
            require_store_shape(root)?;
            if Path::new(root).components().count() != 4 {
                return Err(Error::Profile);
            }
        }
        require_store_shape(&profile.specimen_root)?;
        if !profile.specimen_root.ends_with(ROOT_SUFFIX) {
            return Err(Error::Profile);
        }

        for pin in profile.runtime_files.iter().chain([
            &profile.executable,
            &profile.pid1,
            &profile.loader,
            &profile.canonical_policy,
            &profile.source_policy,
            &profile.effective_matrix,
            &profile.reader,
            &profile.network,
            &profile.nspawn,
            &profile.specimen_init,
            &profile.specimen_root_digest_pin,
        ]) {
            require_store_shape(&pin.path)?;
            if pin.sha256 == [0; 32] {
                return Err(Error::Profile);
            }
        }
        if profile.runtime_files.iter().any(|pin| {
            !profile.closure_roots.iter().any(|root| {
                Path::new(&pin.path)
                    .strip_prefix(root)
                    .is_ok_and(|suffix| suffix.components().count() > 0)
            })
        }) {
            return Err(Error::Profile);
        }
        for required in [
            &profile.executable,
            &profile.loader,
            &profile.reader,
            &profile.network,
            &profile.nspawn,
            &profile.specimen_init,
            &profile.specimen_root_digest_pin,
        ] {
            if !profile.runtime_files.iter().any(|member| {
                member.path == required.path && member.sha256 == required.sha256
            }) {
                return Err(Error::Profile);
            }
        }

        let fixed_roles = [
            (
                &profile.executable,
                "bin/aos-sandbox-installed-filter-collector",
            ),
            (&profile.reader, "libexec/aos-installed-filter-reader"),
            (&profile.network, "libexec/aos-deployment-specimen-network"),
            (&profile.nspawn, "bin/systemd-nspawn"),
        ];
        // The fixed sbin/init symlink is covered by the complete root tree.
        // RetainedImmutableFile custody instead pins its canonical target.
        if fixed_roles
            .iter()
            .any(|(pin, suffix)| !pin.path.ends_with(&format!("/{suffix}")))
            || profile.specimen_init.path
                != format!("{}/usr/lib/systemd/systemd", profile.specimen_root)
            || Path::new(&profile.specimen_root_digest_pin.path).parent()
                != Path::new(&profile.specimen_root).parent()
            || Path::new(&profile.specimen_root_digest_pin.path)
                .file_name()
                .is_none_or(|name| name != "specimen-root.sha256")
            || !profile
                .canonical_policy
                .path
                .ends_with("-aos-selinux-kernel-policy-readback-1/policy.33")
            || !profile
                .source_policy
                .path
                .ends_with("-aos-installed-filter-collector-startup-profile-1/source-policy.33")
            || !profile
                .effective_matrix
                .path
                .ends_with("-aos-installed-filter-collector-startup-profile-1/effective-policy.tsv")
            || Path::new(&profile.source_policy.path).parent()
                != Path::new(&profile.effective_matrix.path).parent()
        {
            return Err(Error::Profile);
        }

        Ok(profile)
    }
}

/// Retains only the original fixed collector listener, PID1 and profile table.
pub struct ProductionInstalledCollectorStartupCaptureV1 {
    listener: OwnedFd,
    pid1: OwnedFd,
    profile: OwnedFd,
}

impl ProductionInstalledCollectorStartupCaptureV1 {
    /// Captures the complete original table as the first single-threaded operation.
    ///
    /// # Errors
    ///
    /// Rejects foreign-PID, missing, duplicate, additional or previously captured
    /// roles. Empty/legacy activation is not accepted.
    pub fn capture() -> Result<Self, Error> {
        let names = crate::normal_root::startup::names(3).map_err(|_| Error::Activation)?;
        if names.len() != 3
            || [LISTENER_FD_NAME, PID1_FD_NAME, PROFILE_FD_NAME]
                .iter()
                .any(|role| names.iter().filter(|name| name.as_str() == *role).count() != 1)
        {
            return Err(Error::Activation);
        }

        let descriptors = duplicate_initial_activation_table(3).map_err(|_| Error::Activation)?;
        let mut listener = None;
        let mut pid1 = None;
        let mut profile = None;
        for (name, descriptor) in names.iter().zip(descriptors) {
            match name.as_str() {
                LISTENER_FD_NAME => listener = Some(descriptor),
                PID1_FD_NAME => pid1 = Some(descriptor),
                PROFILE_FD_NAME => profile = Some(descriptor),
                _ => return Err(Error::Activation),
            }
        }

        Ok(Self {
            listener: listener.ok_or(Error::Activation)?,
            pid1: pid1.ok_or(Error::Activation)?,
            profile: profile.ok_or(Error::Activation)?,
        })
    }

    /// Admits actual immutable images, enforcing policy and original unit custody.
    ///
    /// This admits no deployment effect. The independent publisher must join
    /// its signed profile membership and fresh Host055 Prepared cut before any
    /// root/net creation, specimen start or tracing operation.
    ///
    /// # Errors
    ///
    /// Rejects original role substitution, changed image/profile/closure,
    /// mappings, policy, fixed service, process, credentials or capabilities.
    pub fn admit(self) -> Result<ProductionInstalledCollectorStartupPartsV1, Error> {
        let listener =
            RecordSubjectListener::from_owned(self.listener).map_err(|_| Error::Activation)?;
        listener
            .require_local_filesystem_path(Path::new(SOCKET_PATH))
            .map_err(|_| Error::Activation)?;

        let profile_file = retain_original_profile(File::from(self.profile))?;
        let profile_bytes = profile_file.read_bounded().map_err(|_| Error::Profile)?;
        let profile_digest = Sha256::digest(&profile_bytes).into();
        let profile = CollectorProfileV1::decode(&profile_bytes)?;
        if profile_file.path().parent() != Path::new(&profile.effective_matrix.path).parent() {
            return Err(Error::Profile);
        }

        let manager = retain_pin(&profile.pid1, Some(File::from(self.pid1)), true)?;
        let executable = retain_pin(
            &profile.executable,
            Some(File::open("/proc/self/exe").map_err(|_| Error::Image)?),
            true,
        )?;
        let runtime = profile
            .runtime_files
            .iter()
            .map(|pin| {
                let executable = [
                    &profile.executable,
                    &profile.loader,
                    &profile.reader,
                    &profile.network,
                    &profile.nspawn,
                    &profile.specimen_init,
                ]
                .iter()
                .any(|required| required.path == pin.path);
                retain_pin(pin, None, executable)
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
            .map_err(|_| Error::Confinement)?;
        if policy.digest() != profile.canonical_policy.sha256 {
            return Err(Error::Confinement);
        }

        let process = PidFd::open(NonZeroU32::new(std::process::id()).ok_or(Error::Service)?)
            .map_err(|_| Error::Service)?;
        let identity = process.process_identity().map_err(|_| Error::Service)?;
        let service = RetainedCollectorServicePolicyV1::retain(
            profile_file.path(),
            &profile.executable.path,
            profile.unit_sha256,
            &process,
        )?;

        let startup = ProductionInstalledCollectorStartupV1 {
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
        };
        startup.recheck()?;
        listener.validate_current().map_err(|_| Error::Activation)?;
        listener
            .require_local_filesystem_path(Path::new(SOCKET_PATH))
            .map_err(|_| Error::Activation)?;

        Ok(ProductionInstalledCollectorStartupPartsV1 { listener, startup })
    }
}

/// Retains the original collector listener with its independently rechecked owner.
pub struct ProductionInstalledCollectorStartupPartsV1 {
    /// The original fixed listener, not a deployment permit or readiness proof.
    pub listener: RecordSubjectListener,
    /// The retained local actual startup, requiring live rechecks before use.
    pub startup: ProductionInstalledCollectorStartupV1,
}

/// Retains actual collector startup without serialization, cloning or scalar factories.
#[must_use = "retain and independently recheck original collector custody"]
pub struct ProductionInstalledCollectorStartupV1 {
    profile_file: RetainedImmutableFileV1,
    pub(super) profile: CollectorProfileV1,
    profile_digest: [u8; 32],
    manager: RetainedImmutableFileV1,
    executable: RetainedImmutableFileV1,
    runtime: Vec<RetainedImmutableFileV1>,
    evidence: Vec<RetainedImmutableFileV1>,
    policy: VerifiedLiveSelinuxPolicy,
    process: PidFd,
    identity: PidFdProcessIdentity,
    service: RetainedCollectorServicePolicyV1,
}

impl ProductionInstalledCollectorStartupV1 {
    /// Rechecks all original images, current mappings, policy and fixed process custody.
    ///
    /// # Errors
    ///
    /// Rejects file/name/content/mount, PID1, mapping, policy, subject, exact
    /// credentials/capabilities/NNP/seccomp, unit/invocation or cgroup drift.
    pub fn recheck(&self) -> Result<(), Error> {
        self.profile_file.revalidate().map_err(|_| Error::Profile)?;
        self.manager.revalidate().map_err(|_| Error::Image)?;
        self.manager.require_executed(1).map_err(|_| Error::Image)?;
        self.executable.revalidate().map_err(|_| Error::Image)?;
        self.executable
            .require_executed(std::process::id())
            .map_err(|_| Error::Image)?;
        for file in self.runtime.iter().chain(&self.evidence) {
            file.revalidate().map_err(|_| Error::Image)?;
        }
        crate::normal_root::images::require_actual_mappings(
            &self.runtime,
            &[&self.profile.executable.path, &self.profile.loader.path],
        )
        .map_err(|_| Error::Image)?;
        self.policy
            .revalidate(&self.profile.canonical_policy.path)
            .map_err(|_| Error::Confinement)?;
        require_subject(CONTEXT).map_err(|_| Error::Confinement)?;
        require_status(&read_status()?)?;

        let info = self.process.info().map_err(|_| Error::Service)?;
        let credentials = info.credentials().ok_or(Error::Confinement)?;
        if !self.process.is_alive().map_err(|_| Error::Service)?
            || info.pid() != std::process::id()
            || info.parent_pid() != 1
            || self.process.process_identity().map_err(|_| Error::Service)? != self.identity
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
            return Err(Error::Confinement);
        }

        self.service.recheck(
            self.profile_file.path(),
            &self.profile.executable.path,
            self.profile.unit_sha256,
            &self.process,
        )?;
        self.manager.require_executed(1).map_err(|_| Error::Image)?;
        self.manager.revalidate().map_err(|_| Error::Image)?;
        self.profile_file.revalidate().map_err(|_| Error::Profile)
    }

    /// Returns immutable profile comparison DATA, never a Prepared permit.
    #[must_use]
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }

    pub(super) fn require_child(&self, child: &PidFd) -> Result<(), Error> {
        self.recheck()?;
        self.service.require_child(&self.process, child)?;
        self.recheck()
    }

    pub(super) fn profile_file(&self) -> &RetainedImmutableFileV1 {
        &self.profile_file
    }
}

fn retain_original_profile(file: File) -> Result<RetainedImmutableFileV1, Error> {
    require_readonly_launch_flags(rustix::fs::fcntl_getfl(&file).map_err(|_| Error::Profile)?)
        .map_err(|_| Error::Profile)?;
    let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|_| Error::Profile)?;
    let name = path.to_str().ok_or(Error::Profile)?;
    require_store_shape(name)?;
    if !name.ends_with(PROFILE_SUFFIX) {
        return Err(Error::Profile);
    }

    RetainedImmutableFileV1::retain_with_profile(path, file, None, PROFILE_BYTES as u64, false)
        .map_err(|_| Error::Profile)
}

fn retain_pin(
    pin: &ImagePinV1,
    original: Option<File>,
    executable: bool,
) -> Result<RetainedImmutableFileV1, Error> {
    match original {
        Some(file) => {
            require_readonly_launch_flags(rustix::fs::fcntl_getfl(&file).map_err(|_| Error::Image)?)
                .map_err(|_| Error::Image)?;
            RetainedImmutableFileV1::retain_with_profile(
                PathBuf::from(&pin.path),
                file,
                Some(pin.sha256),
                IMAGE_BYTES,
                executable,
            )
        }
        None => RetainedImmutableFileV1::open_with_profile(
            PathBuf::from(&pin.path),
            Some(pin.sha256),
            IMAGE_BYTES,
            executable,
        ),
    }
    .map_err(|_| Error::Image)
}

fn require_store_shape(path: &str) -> Result<(), Error> {
    crate::normal_root::profile::require_store_path(path).map_err(|_| Error::Profile)
}

fn read_status() -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    File::open("/proc/thread-self/status")
        .map_err(|_| Error::Confinement)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Confinement)?;
    if bytes.len() > 64 * 1024 {
        return Err(Error::Confinement);
    }

    Ok(bytes)
}

fn require_status(bytes: &[u8]) -> Result<(), Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Confinement)?;
    for (name, expected, radix) in [
        ("CapInh", 0, 16),
        ("CapPrm", CAPABILITIES, 16),
        ("CapEff", CAPABILITIES, 16),
        ("CapBnd", CAPABILITIES, 16),
        ("CapAmb", 0, 16),
        ("NoNewPrivs", 1, 10),
        ("Seccomp", 0, 10),
    ] {
        let prefix = format!("{name}:");
        let mut values = text.lines().filter_map(|line| line.strip_prefix(&prefix));
        let value = values.next().ok_or(Error::Confinement)?.trim();
        if u64::from_str_radix(value, radix).ok() != Some(expected)
            || values.next().is_some()
        {
            return Err(Error::Confinement);
        }
    }

    for name in ["Uid", "Gid"] {
        let prefix = format!("{name}:");
        let mut values = text.lines().filter_map(|line| line.strip_prefix(&prefix));
        if values
            .next()
            .ok_or(Error::Confinement)?
            .split_whitespace()
            .collect::<Vec<_>>() != ["0"; 4]
            || values.next().is_some()
        {
            return Err(Error::Confinement);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
