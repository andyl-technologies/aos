//! Controller-owned selected-image inputs and original Root peer comparisons.
//!
//! Capture precedes every journal/listener open. Profile admission observes only
//! Controller's own PID1 delivery: concurrent Root startup is not readiness.
//! The original Root peer is joined later, under the real coordinator's lifetime.
//! None of these objects can produce Intent, Floor or CurrentRead authority.

use std::fs::File;
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::guest_confinement::require_subject;
use aos_sandbox_linux::inherited_fd::duplicate_initial_activation_table;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::selinux_policy::VerifiedLiveSelinuxPolicy;
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};
use aos_systemd::{OwnedValue, Value};

use crate::immutable_image::RetainedImmutableFileV1;

use super::{
    NormalRootStartupErrorV1, images, profile::NormalRootProfileV1, require_status, require_unit,
    retain_fixed_cgroup, service, startup,
};

const UNIT: &str = "aos-sandboxd.service";
const CGROUP: &str = "aos.slice/aos-control.slice/aos-sandboxd.service";
const CONTEXT: &str = "system_u:system_r:aos_sandbox_controller_t:s0";
const UNIT_CONTEXT: &str = "system_u:system_r:aos_sandbox_controller_t";
pub(super) const PROFILE_NAME: &str = "aos-normal-root-client-profile";
const PUBLISHER_NAME: &str = "aos-sandboxd-publisher";
const TPM_IMAGE_NAME: &str = "aos-method46-pid1-image";

/// Retains the selected profile from Controller's complete first launch table.
///
/// Other existing roles are returned to their existing owners. No caller file,
/// policy path or digest can construct this capture.
pub struct ProductionControllerNormalRootCaptureV1 {
    profile: Option<OwnedFd>,
    tpm_image: bool,
}

/// Keeps the existing publisher and method-46 roles separate from the profile.
pub type ProductionControllerNormalRootStartupPartsV1 = (
    ProductionControllerNormalRootCaptureV1,
    Option<OwnedFd>,
    Option<OwnedFd>,
);

impl ProductionControllerNormalRootCaptureV1 {
    /// Captures every initial descriptor before credentials or journals open.
    ///
    /// # Errors
    /// Rejects foreign activation, extra/duplicate roles or kernel failure.
    pub fn capture(
        publisher: bool,
    ) -> Result<ProductionControllerNormalRootStartupPartsV1, NormalRootStartupErrorV1> {
        let names = startup::names(3)?;
        if !valid_names(&names, publisher) {
            return Err(NormalRootStartupErrorV1::Activation);
        }
        let descriptors = duplicate_initial_activation_table(names.len())
            .map_err(|_| NormalRootStartupErrorV1::Activation)?;
        let mut profile = None;
        let mut publisher = None;
        let mut image = None;
        for (name, descriptor) in names.iter().zip(descriptors) {
            match name.as_str() {
                PROFILE_NAME => profile = Some(descriptor),
                PUBLISHER_NAME => publisher = Some(descriptor),
                TPM_IMAGE_NAME => image = Some(descriptor),
                _ => return Err(NormalRootStartupErrorV1::Activation),
            }
        }
        Ok((
            Self {
                profile,
                tpm_image: image.is_some(),
            },
            publisher,
            image,
        ))
    }

    /// Retains actual selected inputs without requiring Root to have started.
    ///
    /// The configured identities are comparison inputs, not authority. The
    /// actual fixed Controller unit must deliver this same immutable profile.
    ///
    /// # Errors
    /// Rejects unsafe selected inputs, changed image/policy/delivery, wrong
    /// Controller subject or identity, and nonempty capabilities.
    pub fn admit_selected(
        self,
        uid: u32,
        gid: u32,
    ) -> Result<Option<ProductionControllerNormalRootProfileV1>, NormalRootStartupErrorV1> {
        let Some(original) = self.profile else {
            // Normal Controller also serves configurations without Root. No
            // selected profile means this producer is unavailable, not legacy
            // authority inferred from policy equality or a later pathname.
            return Ok(None);
        };
        require_subject(CONTEXT).map_err(|_| NormalRootStartupErrorV1::Confinement)?;
        let (profile_file, bytes) = images::retain_profile(File::from(original))?;
        let profile = NormalRootProfileV1::decode(&bytes)?;
        if profile.identities[..2] != [uid, gid]
            || profile_file.path().parent() != Path::new(&profile.effective_matrix.path).parent()
        {
            return Err(NormalRootStartupErrorV1::Profile);
        }
        let policy = VerifiedLiveSelinuxPolicy::verify(&profile.canonical_policy.path)
            .map_err(|_| NormalRootStartupErrorV1::Confinement)?;
        if policy.digest() != profile.canonical_policy.sha256 {
            return Err(NormalRootStartupErrorV1::Confinement);
        }
        let files = profile
            .runtime_files
            .iter()
            .chain([
                &profile.pid1,
                &profile.canonical_policy,
                &profile.source_policy,
                &profile.effective_matrix,
            ])
            .map(|pin| {
                let executable = pin.path == profile.executable.path
                    || pin.path == profile.loader.path
                    || pin.path == profile.pid1.path;
                images::retain_pin(pin, None, executable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let observed = observe_delivery(profile_file.path(), self.tpm_image)?;
        let fragment = RetainedImmutableFileV1::observe_fragment(observed.fragment.clone())
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        let process = PidFd::open(
            NonZeroU32::new(std::process::id()).ok_or(NormalRootStartupErrorV1::Service)?,
        )
        .map_err(|_| NormalRootStartupErrorV1::Service)?;
        let cgroup = retain_fixed_cgroup(Path::new(CGROUP))?;
        let retained = ProductionControllerNormalRootProfileV1 {
            profile_file,
            profile,
            files,
            policy,
            fragment,
            observed,
            process,
            cgroup,
            tpm_image: self.tpm_image,
        };
        retained.recheck()?;
        Ok(Some(retained))
    }
}

/// Retains Controller's independent selected-profile and fixed delivery join.
///
/// This neither opens a Root stream nor authorizes a floor, read or mutation.
/// Its original profile remains owned through Controller's process lifetime.
pub struct ProductionControllerNormalRootProfileV1 {
    profile_file: RetainedImmutableFileV1,
    profile: NormalRootProfileV1,
    files: Vec<RetainedImmutableFileV1>,
    policy: VerifiedLiveSelinuxPolicy,
    fragment: RetainedImmutableFileV1,
    observed: service::ServiceObservationV1,
    process: PidFd,
    cgroup: RetainedCgroupAnchor,
    tpm_image: bool,
}

impl ProductionControllerNormalRootProfileV1 {
    /// Rechecks selected bytes, policy and Controller's original unit delivery.
    ///
    /// # Errors
    /// Rejects changed inputs, original invocation/cgroup/process, subject,
    /// capabilities, identities or delivery roles.
    pub fn recheck(&self) -> Result<(), NormalRootStartupErrorV1> {
        self.profile_file
            .revalidate()
            .map_err(|_| NormalRootStartupErrorV1::Profile)?;
        for file in &self.files {
            file.revalidate()
                .map_err(|_| NormalRootStartupErrorV1::Image)?;
        }
        self.policy
            .revalidate(&self.profile.canonical_policy.path)
            .map_err(|_| NormalRootStartupErrorV1::Confinement)?;
        require_subject(CONTEXT).map_err(|_| NormalRootStartupErrorV1::Confinement)?;
        if rustix::process::getuid().as_raw() != self.profile.identities[0]
            || rustix::process::geteuid().as_raw() != self.profile.identities[0]
            || rustix::process::getgid().as_raw() != self.profile.identities[1]
            || rustix::process::getegid().as_raw() != self.profile.identities[1]
        {
            return Err(NormalRootStartupErrorV1::Confinement);
        }
        require_status(&super::read_bounded("/proc/self/status", 64 * 1024)?)?;
        let info = self
            .cgroup
            .verify_exact_membership(&self.process)
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        if info.parent_pid() != 1
            || !self
                .process
                .is_alive()
                .map_err(|_| NormalRootStartupErrorV1::Service)?
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        let observed = observe_delivery(self.profile_file.path(), self.tpm_image)?;
        service::require_same(&self.observed, &observed)?;
        self.fragment
            .revalidate()
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    // Only the eventual original-flight coordinator can consume this real
    // stream join. No public digest/path/peer or readiness factory exists.
    pub(crate) fn observe_original_peer<'profile>(
        &'profile self,
        stream: &RetainedUnixStream,
    ) -> Result<OriginalNormalRootPeerV1<'profile>, NormalRootStartupErrorV1> {
        self.recheck()?;
        stream
            .revalidate_original()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        let cgroup = retain_fixed_cgroup(Path::new(
            "system.slice/aos-sandbox-policy-authorityd.service",
        ))?;
        let pid = stream.peer().credentials().pid();
        let observed = service::observe_peer(self.profile_file.path(), pid.get(), &self.profile)?;
        let fragment = RetainedImmutableFileV1::observe_fragment(observed.fragment.clone())
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        require_unit(&fragment, &self.profile_file, &self.profile)?;
        let retained = OriginalNormalRootPeerV1 {
            profile: self,
            pid,
            cgroup,
            fragment,
            observed,
        };
        retained.recheck_stream(stream)?;
        Ok(retained)
    }
}

pub(crate) struct OriginalNormalRootPeerV1<'profile> {
    profile: &'profile ProductionControllerNormalRootProfileV1,
    pid: NonZeroU32,
    cgroup: RetainedCgroupAnchor,
    fragment: RetainedImmutableFileV1,
    observed: service::ServiceObservationV1,
}

impl OriginalNormalRootPeerV1<'_> {
    pub(crate) fn source_uid(&self) -> u32 {
        self.profile.profile.identities[0]
    }

    pub(crate) fn recheck_stream(
        &self,
        stream: &RetainedUnixStream,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.profile.recheck()?;
        stream
            .revalidate_original()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        let credentials = stream.peer().credentials();
        if credentials.pid() != self.pid
            || credentials.uid() != 0
            || credentials.gid() != self.profile.profile.identities[1]
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.require_process(stream.peer().pidfd())?;
        let observed = service::observe_peer(
            self.profile.profile_file.path(),
            self.pid.get(),
            &self.profile.profile,
        )?;
        service::require_same(&self.observed, &observed)?;
        require_unit(
            &self.fragment,
            &self.profile.profile_file,
            &self.profile.profile,
        )
    }

    pub(crate) fn require_chunk(
        &self,
        stream: &RetainedUnixStream,
        chunk: &UnixStreamSubjectChunk,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.recheck_stream(stream)?;
        let actual = chunk.subject().credentials();
        let expected = stream.peer().credentials();
        if chunk.socket_context() != super::profile::CONTEXT.as_bytes()
            || actual.pid() != expected.pid()
            || actual.uid() != expected.uid()
            || actual.gid() != expected.gid()
            || !chunk
                .subject()
                .is_alive()
                .map_err(|_| NormalRootStartupErrorV1::Service)?
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.require_process(chunk.subject().pidfd())
    }

    fn require_process(&self, process: &PidFd) -> Result<(), NormalRootStartupErrorV1> {
        let info = self
            .cgroup
            .verify_exact_membership(process)
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        let credentials = info
            .credentials()
            .ok_or(NormalRootStartupErrorV1::Service)?;
        let gid = self.profile.profile.identities[1];
        if info.thread_group_id() != self.pid.get()
            || info.parent_pid() != 1
            || credentials.real_user_id() != 0
            || credentials.effective_user_id() != 0
            || credentials.saved_user_id() != 0
            || credentials.filesystem_user_id() != 0
            || credentials.real_group_id() != gid
            || credentials.effective_group_id() != gid
            || credentials.saved_group_id() != gid
            || credentials.filesystem_group_id() != gid
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        Ok(())
    }
}

fn observe_delivery(
    profile_path: &Path,
    tpm_image: bool,
) -> Result<service::ServiceObservationV1, NormalRootStartupErrorV1> {
    let (service, unit) =
        service::read_properties(UNIT, std::process::id(), service::SERVICE_PROPERTIES)?;
    service::immutable_observation(decode_delivery(&service, &unit, profile_path, tpm_image)?)
}

pub(super) fn decode_delivery(
    properties: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &Path,
    tpm_image: bool,
) -> Result<service::ServiceObservationV1, NormalRootStartupErrorV1> {
    let [
        cgroup,
        open_files,
        extras,
        maximum,
        stored,
        context,
        bounding,
        ambient,
        nnp,
    ] = properties
    else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Structure(context) = &**context else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let [Value::Bool(false), Value::Str(context)] = context.fields() else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Array(files) = &**open_files else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Array(extras) = &**extras else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let expected_cgroup = format!("/{CGROUP}");
    if <&str>::try_from(cgroup).ok() != Some(expected_cgroup.as_str())
        || context.as_str() != UNIT_CONTEXT
        || u64::try_from(bounding).ok() != Some(0)
        || u64::try_from(ambient).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true)
        || u32::try_from(maximum).ok() != Some(0)
        || u32::try_from(stored).ok() != Some(0)
        || !extras.is_empty()
        || extras.element_signature() != Value::from("").value_signature()
        || files.len() != 1 + usize::from(tpm_image)
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let mut found = [false; 2];
    for entry in files.inner() {
        let Value::Structure(entry) = entry else {
            return Err(NormalRootStartupErrorV1::Service);
        };
        let [Value::Str(path), Value::Str(name), Value::U64(1)] = entry.fields() else {
            return Err(NormalRootStartupErrorV1::Service);
        };
        let index = match (Path::new(path.as_str()), name.as_str()) {
            (path, PROFILE_NAME) if path == profile_path => 0,
            (path, TPM_IMAGE_NAME) if tpm_image && path == Path::new("/proc/1/exe") => 1,
            _ => return Err(NormalRootStartupErrorV1::Service),
        };
        if found[index] {
            return Err(NormalRootStartupErrorV1::Service);
        }
        found[index] = true;
    }
    if found != [true, tpm_image] {
        return Err(NormalRootStartupErrorV1::Service);
    }
    service::decode_unit(unit, UNIT)
}

pub(super) fn valid_names(names: &[String], publisher: bool) -> bool {
    names.len() <= 3
        && names
            .iter()
            .filter(|name| name.as_str() == PUBLISHER_NAME)
            .count()
            == usize::from(publisher)
        && names
            .iter()
            .filter(|name| name.as_str() == TPM_IMAGE_NAME)
            .count()
            <= 1
        && names
            .iter()
            .filter(|name| name.as_str() == PROFILE_NAME)
            .count()
            <= 1
        && names.iter().all(|name| {
            matches!(
                name.as_str(),
                PUBLISHER_NAME | TPM_IMAGE_NAME | PROFILE_NAME
            )
        })
}
