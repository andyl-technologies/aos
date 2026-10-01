//! Controller-owned selected-image inputs and original Root peer comparisons.
//!
//! Capture precedes every journal/listener open. Profile admission observes only
//! Controller's own PID1 delivery: concurrent Root startup is not readiness.
//! The original Root peer is joined later, under the real coordinator's lifetime.
//! None of these objects can produce Intent, Floor or CurrentRead authority.

pub(super) mod source_successor_credential;
mod admission;

pub use admission::{
    ControllerProfileAdmissionFailureV1, ProductionControllerSelectedProfileAdmissionV1,
};

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
    NormalRootStartupErrorV1, profile::NormalRootProfileV1, require_status, require_unit,
    retain_fixed_cgroup, service, startup,
};

const UNIT: &str = "aos-sandboxd.service";
const CGROUP: &str = "aos.slice/aos-control.slice/aos-sandboxd.service";
pub(super) const CONTEXT: &str = "system_u:system_r:aos_sandbox_controller_t";
pub(super) const PROFILE_NAME: &str = "aos-normal-root-client-profile";
const PUBLISHER_NAME: &str = "aos-sandboxd-publisher";
const TPM_IMAGE_NAME: &str = "aos-method46-pid1-image";
const GIT_SOURCE_LISTENER_NAME: &str = "aos-git-source-cut";

/// Retains the selected profile from Controller's complete first launch table.
///
/// Other existing roles are returned to their existing owners. No caller file,
/// policy path or digest can construct this capture.
pub struct ProductionControllerNormalRootCaptureV1 {
    profile: Option<OwnedFd>,
    tpm_image: bool,
    nix: Option<super::nix_startup::ProductionControllerNixStartupCaptureV1>,
    nix_delivery: Option<OwnedFd>,
    git_source_listener: Option<OwnedFd>,
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
        Self::capture_with_backends(publisher, false, false)
    }

    /// Captures only declared optional Nix and Git roles in the same table.
    ///
    /// The flags select closed roles, not authority. Their actual image, socket,
    /// unit and confinement owners must separately admit the returned captures.
    ///
    /// # Errors
    /// Rejects extra, duplicate, undeclared, unpaired or foreign launch roles.
    pub fn capture_with_backends(
        publisher: bool,
        nix_enabled: bool,
        git_source_cut: bool,
    ) -> Result<ProductionControllerNormalRootStartupPartsV1, NormalRootStartupErrorV1> {
        let names = startup::names(6)?;
        if !valid_backend_names(&names, publisher, nix_enabled, git_source_cut) {
            return Err(NormalRootStartupErrorV1::Activation);
        }
        let descriptors = duplicate_initial_activation_table(names.len())
            .map_err(|_| NormalRootStartupErrorV1::Activation)?;
        let mut profile = None;
        let mut publisher = None;
        let mut image = None;
        let mut nix_profile = None;
        let mut nix_pid1 = None;
        let mut git_source_listener = None;
        for (name, descriptor) in names.iter().zip(descriptors) {
            match name.as_str() {
                PROFILE_NAME => profile = Some(descriptor),
                PUBLISHER_NAME => publisher = Some(descriptor),
                TPM_IMAGE_NAME => image = Some(descriptor),
                super::nix_startup::CONTROLLER_PROFILE_NAME => nix_profile = Some(descriptor),
                super::nix_startup::CONTROLLER_PID1_NAME => nix_pid1 = Some(descriptor),
                GIT_SOURCE_LISTENER_NAME => git_source_listener = Some(descriptor),
                _ => return Err(NormalRootStartupErrorV1::Activation),
            }
        }
        let nix_delivery = nix_profile.as_ref().map(rustix::io::dup).transpose()
            .map_err(|_| NormalRootStartupErrorV1::Activation)?;
        let nix = match (nix_pid1, nix_profile) {
            (Some(pid1), Some(nix_profile)) => {
                let root_profile = profile.as_ref().map(rustix::io::dup).transpose()
                    .map_err(|_| NormalRootStartupErrorV1::Activation)?;
                Some(super::nix_startup::ProductionControllerNixStartupCaptureV1::from_initial_table(
                    pid1,
                    nix_profile,
                    root_profile,
                    image.is_some(),
                ))
            }
            (None, None) => None,
            _ => return Err(NormalRootStartupErrorV1::Activation),
        };

        Ok((
            Self {
                profile,
                tpm_image: image.is_some(),
                nix,
                nix_delivery,
                git_source_listener,
            },
            publisher,
            image,
        ))
    }

    /// Takes the paired Nix inputs from this same original launch table once.
    ///
    /// Missing inputs mean that the protected Nix continuation is unavailable.
    /// This never opens a later pathname or accepts descriptors from a caller.
    #[must_use]
    pub fn take_nix_startup(
        &mut self,
    ) -> Option<super::nix_startup::ProductionControllerNixStartupCaptureV1> {
        self.nix.take()
    }

    /// Takes the declared original Git socket for its fixed listener owner.
    ///
    /// This does not validate the socket or grant source-cut publication.
    #[must_use]
    pub fn take_git_source_listener(&mut self) -> Option<OwnedFd> {
        self.git_source_listener.take()
    }

    /// Moves this actual returned capture into an armed admission reservoir.
    ///
    /// This infallible move performs no observation, allocation or duplication.
    /// It cannot recover earlier table-copy or lower unreturned descriptions.
    /// Failure or abandonment requires intentional process termination while
    /// the retained attempt stays resident; no installed caller selects it yet.
    #[must_use]
    pub fn begin_retained_selected_admission(self) -> ProductionControllerSelectedProfileAdmissionV1 {
        ProductionControllerSelectedProfileAdmissionV1::new(self)
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
        admission::legacy_recipe(self, uid, gid)
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
    nix_delivery: Option<RetainedImmutableFileV1>,
}

impl ProductionControllerNormalRootProfileV1 {
    /// Returns the original selected profile path for exact delivery comparison.
    ///
    /// This borrowed name grants no readiness or journal authority. Consumers
    /// retain this admitted profile and call [`Self::recheck`] around observations.
    #[must_use]
    pub fn profile_path(&self) -> &Path {
        self.profile_file.path()
    }

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
        if let Some(profile) = &self.nix_delivery {
            profile.revalidate().map_err(|_| NormalRootStartupErrorV1::Profile)?;
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
        let observed = observe_delivery(
            self.profile_file.path(),
            self.tpm_image,
            self.nix_delivery.as_ref().map(|file| file.path()),
        )?;
        service::require_same(&self.observed, &observed)?;
        self.fragment
            .revalidate()
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    // Only the original-flight coordinator can consume this real
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
    nix_profile: Option<&Path>,
) -> Result<service::ServiceObservationV1, NormalRootStartupErrorV1> {
    let (service, unit) =
        service::read_properties(UNIT, std::process::id(), service::SERVICE_PROPERTIES)?;
    service::immutable_observation(decode_delivery_with_backends(
        &service, &unit, profile_path, tpm_image, nix_profile,
    )?)
}

pub(super) fn decode_delivery(
    properties: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &Path,
    tpm_image: bool,
) -> Result<service::ServiceObservationV1, NormalRootStartupErrorV1> {
    decode_delivery_with_backends(properties, unit, profile_path, tpm_image, None)
}

pub(super) fn decode_delivery_with_backends(
    properties: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &Path,
    tpm_image: bool,
    nix_profile: Option<&Path>,
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
        || context.as_str() != CONTEXT
        || u64::try_from(bounding).ok() != Some(0)
        || u64::try_from(ambient).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true)
        || u32::try_from(maximum).ok() != Some(0)
        || u32::try_from(stored).ok() != Some(0)
        || !extras.is_empty()
        || extras.element_signature() != Value::from("").value_signature()
        || files.len() != 1 + usize::from(tpm_image) + 2 * usize::from(nix_profile.is_some())
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let mut found = [false; 4];
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
            (path, super::nix_startup::CONTROLLER_PROFILE_NAME) if Some(path) == nix_profile => 2,
            (path, super::nix_startup::CONTROLLER_PID1_NAME)
                if nix_profile.is_some() && path == Path::new("/proc/1/exe") => 3,
            _ => return Err(NormalRootStartupErrorV1::Service),
        };
        if found[index] {
            return Err(NormalRootStartupErrorV1::Service);
        }
        found[index] = true;
    }
    if found != [true, tpm_image, nix_profile.is_some(), nix_profile.is_some()] {
        return Err(NormalRootStartupErrorV1::Service);
    }
    service::decode_unit(unit, UNIT)
}

pub(super) fn valid_names(names: &[String], publisher: bool) -> bool {
    valid_backend_names(names, publisher, false, false)
}

fn valid_backend_names(
    names: &[String],
    publisher: bool,
    nix_enabled: bool,
    git_source_cut: bool,
) -> bool {
    let nix_profile = names
        .iter()
        .filter(|name| name.as_str() == super::nix_startup::CONTROLLER_PROFILE_NAME)
        .count();
    let nix_pid1 = names
        .iter()
        .filter(|name| name.as_str() == super::nix_startup::CONTROLLER_PID1_NAME)
        .count();

    names.len() <= 6
        && nix_profile == usize::from(nix_enabled)
        && nix_profile == nix_pid1
        && names.iter().filter(|name| name.as_str() == GIT_SOURCE_LISTENER_NAME).count()
            == usize::from(git_source_cut)
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
                    | super::nix_startup::CONTROLLER_PROFILE_NAME
                    | super::nix_startup::CONTROLLER_PID1_NAME
                    | GIT_SOURCE_LISTENER_NAME
            )
        })
}

#[cfg(test)]
mod backend_tests {
    //! Pure closed-table/property vectors, authored and UNRUN.
    //!
    //! Literal names and PID1-shaped property DATA never create descriptors,
    //! admitted startup owners, launch images, floors or publication authority.

    use super::*;

    const ROOT_PROFILE: &str =
        "/nix/store/11111111111111111111111111111111-aos-normal-root-startup-profile-1/profile.json";
    const NIX_PROFILE: &str =
        "/nix/store/22222222222222222222222222222222-aos-nix-startup-profile-2/controller.json";

    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).unwrap()
    }

    fn files(tpm_image: bool, nix_enabled: bool) -> Vec<(String, String, u64)> {
        let mut files = vec![(ROOT_PROFILE.to_owned(), PROFILE_NAME.to_owned(), 1)];
        if tpm_image {
            files.push(("/proc/1/exe".to_owned(), TPM_IMAGE_NAME.to_owned(), 1));
        }
        if nix_enabled {
            files.push((
                NIX_PROFILE.to_owned(),
                super::super::nix_startup::CONTROLLER_PROFILE_NAME.to_owned(),
                1,
            ));
            files.push((
                "/proc/1/exe".to_owned(),
                super::super::nix_startup::CONTROLLER_PID1_NAME.to_owned(),
                1,
            ));
        }
        files
    }

    fn properties(files: Vec<(String, String, u64)>) -> (Vec<OwnedValue>, Vec<OwnedValue>) {
        let properties = vec![
            value(format!("/{CGROUP}")),
            value(files),
            value(Vec::<String>::new()),
            OwnedValue::from(0_u32),
            OwnedValue::from(0_u32),
            value((false, CONTEXT)),
            OwnedValue::from(0_u64),
            OwnedValue::from(0_u64),
            OwnedValue::from(true),
        ];
        let unit = vec![
            value("/nix/store/33333333333333333333333333333333-aos-sandboxd-0.1.0/aos-sandboxd.service"),
            value(Vec::<String>::new()),
            OwnedValue::from(false),
            value(vec![1_u8; 16]),
        ];
        (properties, unit)
    }

    #[test]
    fn declared_backend_table_preserves_every_legacy_role_combination() {
        for selection in 0..32 {
            let publisher = selection & 1 != 0;
            let nix_enabled = selection & 2 != 0;
            let git_source_cut = selection & 4 != 0;
            let root_profile = selection & 8 != 0;
            let method46_image = selection & 16 != 0;
            let mut names = Vec::new();
            for (selected, name) in [
                (publisher, PUBLISHER_NAME),
                (root_profile, PROFILE_NAME),
                (method46_image, TPM_IMAGE_NAME),
                (nix_enabled, super::super::nix_startup::CONTROLLER_PROFILE_NAME),
                (nix_enabled, super::super::nix_startup::CONTROLLER_PID1_NAME),
                (git_source_cut, GIT_SOURCE_LISTENER_NAME),
            ] {
                if selected {
                    names.push(name.to_owned());
                }
            }

            assert!(valid_backend_names(&names, publisher, nix_enabled, git_source_cut));
            names.reverse();
            assert!(valid_backend_names(&names, publisher, nix_enabled, git_source_cut));
            assert_eq!(valid_names(&names, publisher), !nix_enabled && !git_source_cut);
        }
    }

    #[test]
    fn backend_table_rejects_missing_duplicate_foreign_and_undeclared_roles() {
        let names: Vec<String> = [
            PROFILE_NAME, TPM_IMAGE_NAME, PUBLISHER_NAME,
            super::super::nix_startup::CONTROLLER_PROFILE_NAME,
            super::super::nix_startup::CONTROLLER_PID1_NAME,
            GIT_SOURCE_LISTENER_NAME,
        ].into_iter().map(str::to_owned).collect();

        assert!(valid_backend_names(&names, true, true, true));
        for index in 0..names.len() {
            let mut duplicate = names.clone();
            duplicate.remove(if index == 0 { 1 } else { 0 });
            duplicate.push(names[index].clone());
            assert_eq!(duplicate.len(), 6);
            assert!(!valid_backend_names(&duplicate, true, true, true));
        }
        for index in 2..names.len() {
            let mut missing = names.clone();
            missing.remove(index);
            assert!(!valid_backend_names(&missing, true, true, true));
        }
        for foreign in ["unknown", "aos-normal-root-pid1-image", "aos-nix-owner-profile"] {
            let mut changed = names.clone();
            changed[0] = foreign.to_owned();
            assert!(!valid_backend_names(&changed, true, true, true));
        }
        for flags in [(false, true, true), (true, false, true), (true, true, false)] {
            assert!(!valid_backend_names(&names, flags.0, flags.1, flags.2));
        }
    }

    #[test]
    fn legacy_capture_and_startup_parts_signature_is_preserved_without_capture() {
        let _legacy: fn(bool) -> Result<
            ProductionControllerNormalRootStartupPartsV1,
            NormalRootStartupErrorV1,
        > = ProductionControllerNormalRootCaptureV1::capture;
        let _combined: fn(bool, bool, bool) -> Result<
            ProductionControllerNormalRootStartupPartsV1,
            NormalRootStartupErrorV1,
        > = ProductionControllerNormalRootCaptureV1::capture_with_backends;
    }

    #[test]
    fn legacy_delivery_remains_no_nix_while_selected_delivery_requires_the_pair() {
        for tpm_image in [false, true] {
            let (legacy, unit) = properties(files(tpm_image, false));
            let decoded = decode_delivery(&legacy, &unit, Path::new(ROOT_PROFILE), tpm_image)
                .unwrap();
            let combined = decode_delivery_with_backends(
                &legacy, &unit, Path::new(ROOT_PROFILE), tpm_image, None,
            ).unwrap();
            assert_eq!(decoded, combined);

            let (selected, unit) = properties(files(tpm_image, true));
            assert!(decode_delivery_with_backends(
                &selected, &unit, Path::new(ROOT_PROFILE), tpm_image,
                Some(Path::new(NIX_PROFILE)),
            ).is_ok());
            assert!(decode_delivery(
                &selected, &unit, Path::new(ROOT_PROFILE), tpm_image,
            ).is_err());
            assert!(decode_delivery_with_backends(
                &selected, &unit, Path::new(ROOT_PROFILE), tpm_image, None,
            ).is_err());
        }
    }

    #[test]
    fn paired_delivery_rejects_missing_duplicate_substituted_and_git_openfile_roles() {
        let original = files(true, true);
        for index in [2, 3] {
            let mut missing = original.clone();
            missing.remove(index);
            let mut duplicate = original.clone();
            duplicate[if index == 2 { 3 } else { 2 }] = original[index].clone();
            let mut wrong_flags = original.clone();
            wrong_flags[index].2 = 0;
            let mut foreign_role = original.clone();
            foreign_role[index].1 = GIT_SOURCE_LISTENER_NAME.to_owned();

            for changed in [missing, duplicate, wrong_flags, foreign_role] {
                let (properties, unit) = properties(changed);
                assert!(decode_delivery_with_backends(
                    &properties, &unit, Path::new(ROOT_PROFILE), true,
                    Some(Path::new(NIX_PROFILE)),
                ).is_err());
            }
        }
        for (index, path) in [(2, "/other/controller.json"), (3, "/proc/self/exe")] {
            let mut changed = original.clone();
            changed[index].0 = path.to_owned();
            let (properties, unit) = properties(changed);
            assert!(decode_delivery_with_backends(
                &properties, &unit, Path::new(ROOT_PROFILE), true,
                Some(Path::new(NIX_PROFILE)),
            ).is_err());
        }
    }

    #[test]
    fn selected_delivery_keeps_exact_confinement_and_invocation_checks() {
        let (original, unit) = properties(files(true, true));
        let observed = decode_delivery_with_backends(
            &original, &unit, Path::new(ROOT_PROFILE), true, Some(Path::new(NIX_PROFILE)),
        ).unwrap();

        for (index, replacement) in [
            (0, value("/system.slice/aos-sandboxd.service")),
            (2, value(vec!["aos-git-source-cut".to_owned()])),
            (3, OwnedValue::from(1_u32)),
            (4, OwnedValue::from(1_u32)),
            (5, value((false, "system_u:system_r:aos_sandbox_nix_t"))),
            (6, OwnedValue::from(1_u64)),
            (7, OwnedValue::from(1_u64)),
            (8, OwnedValue::from(false)),
        ] {
            let (mut changed, unit) = properties(files(true, true));
            changed[index] = replacement;
            assert!(decode_delivery_with_backends(
                &changed, &unit, Path::new(ROOT_PROFILE), true, Some(Path::new(NIX_PROFILE)),
            ).is_err(), "property {index}");
        }

        let (properties, mut changed_unit) = properties(files(true, true));
        changed_unit[3] = value(vec![2_u8; 16]);
        let changed = decode_delivery_with_backends(
            &properties, &changed_unit, Path::new(ROOT_PROFILE), true,
            Some(Path::new(NIX_PROFILE)),
        ).unwrap();
        assert!(service::require_same(&observed, &changed).is_err());

        changed_unit[3] = value(vec![0_u8; 16]);
        assert!(decode_delivery_with_backends(
            &properties, &changed_unit, Path::new(ROOT_PROFILE), true,
            Some(Path::new(NIX_PROFILE)),
        ).is_err());
    }
}
