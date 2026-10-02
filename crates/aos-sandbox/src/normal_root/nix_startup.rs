//! Original fixed-purpose Nix startup custody, captured before protected I/O.
//!
//! The Controller shares its one initial descriptor capture with normal Root;
//! the Nix owner consumes its own closed table. Immutable profiles are image
//! comparisons, not transferable authority. Actual original PID1, process,
//! invocation, cgroup, confinement and delivered descriptors remain retained.
//! The PID1 file authenticates its original launch image, not a later manager
//! executable after reexec. Current unique-PID1 service observations remain
//! bookended within the trusted boot/system-manager administration boundary.
//!
//! ```text
//! AOS_NIX_STARTUP_2: closed role + identities + immutable image/policy pins
//!                 + selected-unit SHA256 after one profile-path normalization
//! ```

mod floor_origin;
mod owner_public;

pub use floor_origin::{ControllerNixSessionFloorOriginV2, NixOwnerSessionFloorStartupV2};
pub use owner_public::NixOwnerPublicSessionFloorOriginV2;

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

use crate::immutable_image::{
    PendingImmutableFileV1, RetainedImmutableFileV1, require_readonly_launch_flags,
};
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

/// Holds the paired Nix roles from Controller's one original launch table.
///
/// The retained disposition arms this same opaque capture before credential
/// loads. Its unused absent-Root duplicate is custody only, not a Root pin.
pub struct ProductionControllerNixStartupCaptureV1 {
    fence: NixCaptureFence,
    storage: NixAdmissionStorage,
    attempted: bool,
    first_failure: Option<NixAdmissionFailure>,
}

impl ProductionControllerNixStartupCaptureV1 {
    pub(super) fn from_initial_table(
        pid1: OwnedFd,
        profile: OwnedFd,
        root_profile: Option<OwnedFd>,
        method46_image: bool,
    ) -> Self {
        Self {
            fence: NixCaptureFence { armed: false },
            storage: NixAdmissionStorage::new(pid1, profile, root_profile, method46_image),
            attempted: false,
            first_failure: None,
        }
    }

    pub(super) fn can_park_absent_root_delivery(&self) -> bool {
        !self.fence.armed
            && !self.attempted
            && self.storage.raw.root_profile.is_none()
            && self.storage.absent_root_delivery.is_none()
    }

    // Only FIRST6's same-capture handoff calls this after its pair/slot checks.
    pub(super) fn park_absent_root_delivery(&mut self, delivery: OwnedFd) {
        self.storage.absent_root_delivery = Some(delivery);
    }

    /// Arms the same original capture before fixed credential admission.
    ///
    /// Success selects retained custody. Before this boundary the capture
    /// keeps its legacy release disposition; a pre-arm refusal records the
    /// first failure but does not itself arm custody.
    ///
    /// # Errors
    ///
    /// Rejects a repeated or consumed capture without another observation.
    pub fn retain_admission(&mut self) -> Result<(), &Error> {
        if self.fence.armed || self.attempted || self.first_failure.is_some() {
            return Err(&self.first_failure.get_or_insert_with(NixAdmissionFailure::ended).original);
        }
        self.fence.armed = true;
        Ok(())
    }

    /// Admits selected startup once while every returned object stays resident.
    ///
    /// # Errors
    ///
    /// Retains the actual first image, policy, process, unit or allocation
    /// failure. Its borrowed legacy classification exposes no private cause.
    pub fn admit_selected_once(&mut self, identities: [u32; 4]) -> Result<(), &Error> {
        if !self.fence.armed || self.attempted || self.first_failure.is_some() {
            return Err(&self.first_failure.get_or_insert_with(NixAdmissionFailure::ended).original);
        }
        self.attempted = true;
        let result = {
            let _unwind = AbortNixAdmissionUnwind;
            self.storage.admit_controller(identities)
        };
        match result {
            Ok(()) => Ok(()),
            Err(failure) => Err(&self.first_failure.get_or_insert(failure).original),
        }
    }

    /// Borrows the actual resident first refusal's legacy classification.
    pub fn first_failure(&self) -> Option<&Error> {
        self.first_failure.as_ref().map(|failure| &failure.original)
    }

    /// Moves the same completed startup once, without further observations.
    ///
    /// The caller parks it before sharing or any fallible continuation.
    #[must_use]
    pub fn take_admitted_startup(&mut self) -> Option<ProductionControllerNixStartupV1> {
        if !self.fence.armed
            || !self.attempted
            || self.first_failure.is_some()
            || self.storage.completed.is_none()
            || !self.storage.residuals_empty()
        {
            return None;
        }
        let completed = self.storage.completed.take();
        self.fence.armed = false;
        completed.map(|retained| ProductionControllerNixStartupV1 { retained })
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
        // Legacy cannot re-enter after selection, an attempt or a refusal.
        if self.fence.armed || self.attempted || self.first_failure.is_some() {
            return Err(Error::Profile);
        }
        let mut storage = self.storage;
        let root_profile = storage.raw.root_profile
            .take()
            .map(|fd| images::retain_profile(File::from(fd)))
            .transpose()?
            .map(|(file, _)| file);
        let originals = (storage.raw.pid1.take(), storage.raw.profile.take());
        let (pid1, profile) = match originals {
            (Some(pid1), Some(profile)) => (pid1, profile),
            (pid1, profile) => {
                storage.raw.pid1 = pid1;
                storage.raw.profile = profile;
                return Err(Error::Activation);
            }
        };
        let mut retained = RetainedNixStartup::admit(
            Role::Controller,
            pid1,
            profile,
            root_profile,
            storage.raw.method46_image,
            identities,
        )?;
        retained.absent_root_delivery = storage.absent_root_delivery.take();
        Ok(ProductionControllerNixStartupV1 { retained })
    }
}

struct NixCaptureFence {
    armed: bool,
}

impl Drop for NixCaptureFence {
    fn drop(&mut self) {
        if self.armed {
            // This first field fences every remaining original before release.
            std::process::abort();
        }
    }
}

struct AbortNixAdmissionUnwind;

impl Drop for AbortNixAdmissionUnwind {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

struct ControllerNixOriginals {
    // Field order preserves legacy partial-root-admission destruction order.
    pid1: Option<OwnedFd>,
    profile: Option<OwnedFd>,
    root_profile: Option<OwnedFd>,
    method46_image: bool,
}

#[allow(dead_code)]
enum NixAdmissionCause {
    Image(images::ImageObservationErrorV1),
    Linux(aos_sandbox_linux::Error),
    Policy(aos_sandbox_linux::selinux_policy::PolicyReadbackError),
    Allocation(std::collections::TryReserveError),
}

struct NixAdmissionFailure {
    original: Error,
    cause: Option<NixAdmissionCause>,
}

impl NixAdmissionFailure {
    fn plain(original: Error) -> Self {
        Self {
            original,
            cause: None,
        }
    }

    fn ended() -> Self {
        Self::plain(Error::Profile)
    }

    fn image(cause: images::ImageObservationErrorV1) -> Self {
        Self {
            original: cause.legacy_error(),
            cause: Some(NixAdmissionCause::Image(cause)),
        }
    }
}

struct NixAdmissionStorage {
    raw: ControllerNixOriginals,
    absent_root_delivery: Option<OwnedFd>,
    root_present: bool,
    root_profile: PendingImmutableFileV1,
    profile_file: PendingImmutableFileV1,
    profile: Option<NixStartupProfileV2>,
    pid1: PendingImmutableFileV1,
    executable: PendingImmutableFileV1,
    helper: PendingImmutableFileV1,
    runtime: Vec<RetainedImmutableFileV1>,
    evidence: Vec<RetainedImmutableFileV1>,
    pending_pin: PendingImmutableFileV1,
    policy: Option<VerifiedLiveSelinuxPolicy>,
    process: Option<PidFd>,
    identity: Option<PidFdProcessIdentity>,
    cgroup: Option<RetainedCgroupAnchor>,
    observed: Option<service::ServiceObservationV1>,
    fragment: PendingImmutableFileV1,
    completed: Option<RetainedNixStartup>,
}

// Storage dispositions are closed here. The literal legacy expressions and
// local-drop intervals remain separate from the retained resident prefix.
macro_rules! nix_direct {
    (legacy, $expression:expr) => { $expression? };
    (retained, $expression:expr) => { $expression.map_err(NixAdmissionFailure::plain)? };
}

macro_rules! nix_checked {
    (legacy, $expression:expr, $class:ident, $cause:ident) => {
        $expression.map_err(|_| Error::$class)?
    };
    (retained, $expression:expr, $class:ident, $cause:ident) => {
        $expression.map_err(|cause| NixAdmissionFailure {
            original: Error::$class,
            cause: Some(NixAdmissionCause::$cause(cause)),
        })?
    };
}

macro_rules! nix_bind {
    (legacy, $storage:ident, $name:ident, $expression:expr) => {
        let $name = $expression;
    };
    (retained, $storage:ident, $name:ident, $expression:expr) => {
        $storage.$name = Some($expression);
        let $name = $storage.$name.as_ref().ok_or_else(NixAdmissionFailure::ended)?;
    };
}

macro_rules! nix_profile {
    (legacy, $storage:ident, $profile_fd:ident, $role:ident, $file:ident, $bytes:ident) => {
        let ($file, $bytes) = retain_profile(File::from($profile_fd), $role)?;
    };
    (retained, $storage:ident, $profile_fd:ident, $role:ident, $file:ident, $bytes:ident) => {
        if $storage.profile_file.original().is_ok() || $storage.profile_file.measurement().is_ok() {
            return Err(NixAdmissionFailure::ended());
        }
        let Some(original) = $storage.raw.profile.take() else {
            return Err(NixAdmissionFailure::ended());
        };
        $storage.profile_file.park_original(File::from(original));
        let path = profile_path($storage.profile_file.original()
            .map_err(|cause| NixAdmissionFailure::image(cause.into()))?, $role)
            .map_err(NixAdmissionFailure::image)?;
        $storage.profile_file.measure_original(path, None, 1_048_576, false)
            .map_err(|cause| NixAdmissionFailure::image(cause.into()))?;
        $storage.profile_file.read_bounded()
            .map_err(|cause| NixAdmissionFailure::image(cause.into()))?;
        let $file = $storage.profile_file.measurement()
            .map_err(|cause| NixAdmissionFailure::image(cause.into()))?;
        let $bytes = $storage.profile_file.bytes();
    };
}

macro_rules! nix_image {
    (legacy, $storage:ident, $name:ident, $pin:expr, $original:expr, $kind:ident) => {
        let $name = images::retain_pin($pin, $original, true)?;
    };
    (retained, $storage:ident, $name:ident, $pin:expr, $original:expr, pid1) => {
        if $storage.pid1.original().is_ok() || $storage.pid1.measurement().is_ok() {
            return Err(NixAdmissionFailure::ended());
        }
        let Some(original) = $storage.raw.pid1.take() else {
            return Err(NixAdmissionFailure::ended());
        };
        $storage.pid1.park_original(File::from(original));
        images::park_original_pin($pin, true, &mut $storage.pid1)
            .map_err(NixAdmissionFailure::image)?;
        let $name = $storage.pid1.measurement()
            .map_err(|cause| NixAdmissionFailure::image(cause.into()))?;
    };
    (retained, $storage:ident, $name:ident, $pin:expr, $original:expr, executable) => {
        let original = File::open("/proc/self/exe")
            .map_err(|cause| NixAdmissionFailure::image(cause.into()))?;
        $storage.executable.park_original(original);
        images::park_original_pin($pin, true, &mut $storage.executable)
            .map_err(NixAdmissionFailure::image)?;
        let $name = $storage.executable.measurement()
            .map_err(|cause| NixAdmissionFailure::image(cause.into()))?;
    };
    (retained, $storage:ident, $name:ident, $pin:expr, $original:expr, helper) => {
        images::park_selected_pin($pin, true, &mut $storage.helper)
            .map_err(NixAdmissionFailure::image)?;
        let $name = $storage.helper.measurement()
            .map_err(|cause| NixAdmissionFailure::image(cause.into()))?;
    };
}

macro_rules! nix_pin_set {
    (legacy, $storage:ident, $name:ident, $pin:ident, $iterator:expr, $executable:expr) => {
        let $name = ($iterator).map(|$pin| {
            images::retain_pin($pin, None, $executable)
        }).collect::<Result<Vec<_>, _>>()?;
    };
    (retained, $storage:ident, $name:ident, $pin:ident, $iterator:expr, $executable:expr) => {
        for $pin in $iterator {
            $storage.$name.try_reserve(1).map_err(|cause| NixAdmissionFailure {
                original: Error::Image,
                cause: Some(NixAdmissionCause::Allocation(cause)),
            })?;
            images::park_selected_pin($pin, $executable, &mut $storage.pending_pin)
                .map_err(NixAdmissionFailure::image)?;
            let Some(original) = $storage.pending_pin.take_measurement() else {
                return Err(NixAdmissionFailure::ended());
            };
            $storage.$name.push(original);
        }
    };
}

macro_rules! nix_fragment {
    (legacy, $storage:ident, $observed:ident, $fragment:ident) => {
        let $fragment = RetainedImmutableFileV1::observe_fragment($observed.fragment.clone())
            .map_err(|_| Error::Service)?;
    };
    (retained, $storage:ident, $observed:ident, $fragment:ident) => {
        $storage.fragment.open_and_measure($observed.fragment.clone(), None, 64 * 1024, false)
            .map_err(|cause| NixAdmissionFailure {
                original: Error::Service,
                cause: Some(NixAdmissionCause::Image(cause.into())),
            })?;
    };
}

macro_rules! nix_root_reference {
    (legacy, $storage:ident, $root:ident) => {};
    (retained, $storage:ident, $root:ident) => {
        let $root = if $storage.root_present {
            Some($storage.root_profile.measurement()
                .map_err(|cause| NixAdmissionFailure::image(cause.into()))?)
        } else {
            None
        };
    };
}

macro_rules! nix_finish {
    (legacy, $storage:ident, $role:ident, $method:ident,
     $file:ident, $profile:ident, $pid1:ident, $executable:ident, $helper:ident,
     $runtime:ident, $evidence:ident, $root:ident, $policy:ident, $process:ident,
     $identity:ident, $cgroup:ident, $fragment:ident, $observed:ident) => {
        let retained = Self {
            role: $role, profile_file: $file, profile: $profile, pid1: $pid1,
            executable: $executable, helper: $helper, runtime: $runtime, evidence: $evidence,
            root_profile: $root, method46_image: $method, policy: $policy,
            process: $process, identity: $identity, cgroup: $cgroup,
            fragment: $fragment, observed: $observed,
            absent_root_delivery: None,
        };
        retained.recheck()?;
        Ok(retained)
    };
    (retained, $storage:ident, $role:ident, $method:ident,
     $file:ident, $profile:ident, $pid1:ident, $executable:ident, $helper:ident,
     $runtime:ident, $evidence:ident, $root:ident, $policy:ident, $process:ident,
     $identity:ident, $cgroup:ident, $fragment:ident, $observed:ident) => {
        $storage.assemble($role, $method)?;
        $storage.completed.as_ref().ok_or_else(NixAdmissionFailure::ended)?
            .recheck().map_err(NixAdmissionFailure::plain)?;
        Ok(())
    };
}

macro_rules! nix_admission_recipe {
    ($mode:ident, $storage:ident, $role:ident, $pid1:ident, $profile_fd:ident,
     $root_profile:ident, $method46_image:ident, $identities:ident) => {{
        nix_profile!($mode, $storage, $profile_fd, $role, profile_file, bytes);
        nix_bind!($mode, $storage, profile,
            nix_direct!($mode, NixStartupProfileV2::decode(&bytes, $role, $identities)));
        nix_image!($mode, $storage, pid1, &profile.pid1, Some(File::from($pid1)), pid1);
        nix_image!($mode, $storage, executable, &profile.executable,
            Some(File::open("/proc/self/exe").map_err(|_| Error::Image)?), executable);
        nix_image!($mode, $storage, helper, &profile.helper, None, helper);
        nix_pin_set!($mode, $storage, runtime, pin, profile.runtime_files.iter(),
            pin.path == profile.executable.path || pin.path == profile.loader.path);
        nix_pin_set!($mode, $storage, evidence, pin,
            [&profile.helper_loader, &profile.canonical_policy, &profile.source_policy, &profile.effective_matrix].into_iter(),
            pin.path == profile.helper_loader.path);
        nix_bind!($mode, $storage, policy,
            nix_checked!($mode, VerifiedLiveSelinuxPolicy::verify(&profile.canonical_policy.path), Confinement, Policy));
        if policy.digest() != profile.canonical_policy.sha256 {
            return Err(nix_direct_error!($mode, Error::Confinement));
        }
        nix_bind!($mode, $storage, process,
            nix_checked!($mode, PidFd::open(
                nix_direct!($mode, NonZeroU32::new(std::process::id()).ok_or(Error::Service))
            ), Service, Linux));
        nix_bind!($mode, $storage, identity,
            nix_checked!($mode, process.process_identity(), Service, Linux));
        nix_bind!($mode, $storage, cgroup,
            nix_direct!($mode, super::retain_fixed_cgroup(Path::new($role.cgroup()))));
        nix_root_reference!($mode, $storage, $root_profile);
        nix_bind!($mode, $storage, observed,
            nix_direct!($mode, observe_delivery($role, profile_file.path(),
                $root_profile.as_ref().map(|file| file.path()), $method46_image)));
        nix_fragment!($mode, $storage, observed, fragment);
        nix_finish!($mode, $storage, $role, $method46_image,
            profile_file, profile, pid1, executable, helper, runtime, evidence,
            $root_profile, policy, process, identity, cgroup, fragment, observed)
    }};
}

macro_rules! nix_direct_error {
    (legacy, $error:expr) => { $error };
    (retained, $error:expr) => { NixAdmissionFailure::plain($error) };
}

impl NixAdmissionStorage {
    fn new(
        pid1: OwnedFd,
        profile: OwnedFd,
        root_profile: Option<OwnedFd>,
        method46_image: bool,
    ) -> Self {
        Self {
            raw: ControllerNixOriginals {
                pid1: Some(pid1),
                profile: Some(profile),
                root_profile,
                method46_image,
            },
            absent_root_delivery: None,
            root_present: false,
            root_profile: PendingImmutableFileV1::default(),
            profile_file: PendingImmutableFileV1::default(),
            profile: None,
            pid1: PendingImmutableFileV1::default(),
            executable: PendingImmutableFileV1::default(),
            helper: PendingImmutableFileV1::default(),
            runtime: Vec::new(),
            evidence: Vec::new(),
            pending_pin: PendingImmutableFileV1::default(),
            policy: None,
            process: None,
            identity: None,
            cgroup: None,
            observed: None,
            fragment: PendingImmutableFileV1::default(),
            completed: None,
        }
    }

    fn admit_controller(&mut self, identities: [u32; 4]) -> Result<(), NixAdmissionFailure> {
        if self.raw.pid1.is_none() || self.raw.profile.is_none() || self.completed.is_some() {
            return Err(NixAdmissionFailure::ended());
        }
        self.root_present = self.raw.root_profile.is_some();
        if let Some(original) = self.raw.root_profile.take() {
            self.root_profile.park_original(File::from(original));
            images::park_controller_profile(&mut self.root_profile)
                .map_err(NixAdmissionFailure::image)?;
        }
        let role = Role::Controller;
        let method46_image = self.raw.method46_image;
        nix_admission_recipe!(retained, self, role, pid1, profile_fd, root_profile, method46_image, identities)
    }

    fn residuals_empty(&self) -> bool {
        self.raw.pid1.is_none() && self.raw.profile.is_none()
            && self.raw.root_profile.is_none() && self.absent_root_delivery.is_none()
            && self.profile.is_none() && self.policy.is_none()
            && self.process.is_none() && self.identity.is_none() && self.cgroup.is_none()
            && self.observed.is_none() && self.runtime.is_empty() && self.evidence.is_empty()
            && [&self.root_profile, &self.profile_file, &self.pid1, &self.executable,
                &self.helper, &self.pending_pin, &self.fragment].iter()
                .all(|pending| pending.original().is_err() && pending.measurement().is_err())
    }

    fn assemble(&mut self, role: Role, method46_image: bool) -> Result<(), NixAdmissionFailure> {
        if self.completed.is_some()
            || self.raw.pid1.is_some() || self.raw.profile.is_some() || self.raw.root_profile.is_some()
            || self.profile.is_none() || self.policy.is_none() || self.process.is_none()
            || self.identity.is_none() || self.cgroup.is_none() || self.observed.is_none()
            || self.root_profile.measurement().is_ok() != self.root_present
            || [&self.profile_file, &self.pid1, &self.executable, &self.helper, &self.fragment]
                .iter().any(|pending| pending.measurement().is_err())
            || self.pending_pin.original().is_ok() || self.pending_pin.measurement().is_ok()
        {
            return Err(NixAdmissionFailure::ended());
        }
        let originals = (
            self.profile_file.take_measurement(), self.profile.take(),
            self.pid1.take_measurement(), self.executable.take_measurement(),
            self.helper.take_measurement(), self.root_profile.take_measurement(),
            self.policy.take(), self.process.take(), self.identity.take(),
            self.cgroup.take(), self.fragment.take_measurement(), self.observed.take(),
            std::mem::take(&mut self.runtime), std::mem::take(&mut self.evidence),
        );
        match originals {
            (Some(profile_file), Some(profile), Some(pid1), Some(executable), Some(helper),
             root_profile, Some(policy), Some(process), Some(identity), Some(cgroup),
             Some(fragment), Some(observed), runtime, evidence)
                if root_profile.is_some() == self.root_present => {
                self.completed = Some(RetainedNixStartup {
                    role, profile_file, profile, pid1, executable, helper, runtime, evidence,
                    root_profile, method46_image, policy, process, identity, cgroup, fragment, observed,
                    absent_root_delivery: self.absent_root_delivery.take(),
                });
                Ok(())
            }
            (profile_file, profile, pid1, executable, helper, root_profile, policy,
             process, identity, cgroup, fragment, observed, runtime, evidence) => {
                self.profile_file.restore_measurement(profile_file);
                self.profile = profile;
                self.pid1.restore_measurement(pid1);
                self.executable.restore_measurement(executable);
                self.helper.restore_measurement(helper);
                self.root_profile.restore_measurement(root_profile);
                self.policy = policy;
                self.process = process;
                self.identity = identity;
                self.cgroup = cgroup;
                self.fragment.restore_measurement(fragment);
                self.observed = observed;
                self.runtime = runtime;
                self.evidence = evidence;
                Err(NixAdmissionFailure::ended())
            }
        }
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

            /// Observes the Nix-only current service population policy twice.
            ///
            /// # Errors
            ///
            /// Rejects original startup or either full barrier-flight mismatch.
            pub(crate) fn require_physical_service_barrier(&self) -> Result<(), Error> {
                self.retained.require_physical_service_barrier()
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
    // Unused same-producer delivery custody is not included in any pin/hash.
    absent_root_delivery: Option<OwnedFd>,
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
        nix_admission_recipe!(legacy, unused, role, pid1, profile_fd, root_profile, method46_image, identities)
    }

    fn recheck(&self) -> Result<(), Error> {
        for file in [&self.profile_file, &self.pid1, &self.executable, &self.helper, &self.fragment]
            .into_iter().chain(&self.runtime).chain(&self.evidence).chain(&self.root_profile)
        {
            file.revalidate().map_err(|_| Error::Image)?;
        }
        // The genuine inherited file measures PID1 at launch. Reopening proc1
        // is neither available to the confined Controller nor reexec custody.
        self.pid1.revalidate().map_err(|_| Error::Image)?;
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

    fn require_physical_service_barrier(&self) -> Result<(), Error> {
        self.recheck()?;
        // Both full flights independently match the retained original unit,
        // invocation and delivery, not merely each other's returned DATA.
        for _ in 0..2 {
            let (properties, unit) =
                service::read_nix_barrier_properties(self.role.unit(), std::process::id())?;
            let observed = service::immutable_observation(decode_delivery(
                &properties,
                &unit,
                self.role,
                self.profile_file.path(),
                self.root_profile.as_ref().map(|file| file.path()),
                self.method46_image,
            )?)?;
            service::require_same(&self.observed, &observed)?;
            require_unit(
                &self.fragment,
                self.profile_file.path(),
                self.role,
                self.profile.unit_sha256,
            )?;
            self.recheck()?;
        }
        Ok(())
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
    let path = profile_path(&file, role).map_err(images::ImageObservationErrorV1::into_legacy)?;
    let retained = RetainedImmutableFileV1::retain_with_profile(path, file, None, 1_048_576, false)
        .map_err(|_| Error::Image)?;
    let bytes = retained.read_bounded().map_err(|_| Error::Image)?;
    Ok((retained, bytes))
}

fn profile_path(file: &File, role: Role) -> Result<PathBuf, images::ImageObservationErrorV1> {
    let flags = rustix::fs::fcntl_getfl(file)?;
    require_readonly_launch_flags(flags)?;
    let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    super::profile::require_store_path(path.to_str().ok_or(Error::Profile)?)?;
    let basename = if role == Role::Controller { "controller.json" } else { "owner.json" };
    if !path.to_string_lossy().ends_with(&format!("-aos-nix-startup-profile-2/{basename}")) {
        return Err(Error::Profile.into());
    }
    Ok(path)
}

pub(super) fn retain_controller_profile(file: File) -> Result<RetainedImmutableFileV1, Error> {
    retain_profile(file, Role::Controller).map(|(retained, _)| retained)
}

pub(super) fn park_controller_profile(
    pending: &mut PendingImmutableFileV1,
) -> Result<(), images::ImageObservationErrorV1> {
    let path = profile_path(pending.original()?, Role::Controller)?;
    pending.measure_original(path, None, 1_048_576, false)?;
    pending.read_bounded()?;
    Ok(())
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

#[cfg(test)]
mod retained_failure_tests {
    use super::*;

    #[test]
    fn ended_refusal_does_not_replace_the_original_failure() {
        let mut first = Some(NixAdmissionFailure::plain(Error::Confinement));

        let retained = first.get_or_insert_with(NixAdmissionFailure::ended);

        assert!(matches!(retained.original, Error::Confinement));
        assert!(retained.cause.is_none());
    }
}
