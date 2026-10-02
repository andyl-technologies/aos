//! Closed legacy and retained dispositions of the same Controller admission recipe.
//!
//! The retained path owns only an actually returned initial capture. Original
//! files, read buffers and successful observations remain parked through later
//! failures. Earlier table capture and unreturned lower policy/pidfd/cgroup
//! descriptions are separate functional prerequisites, not recreated here.
//! This admits selected startup comparisons, never Source or Root authority.

use std::cell::Cell;
use std::collections::TryReserveError;
use std::error::Error as StdError;
use std::fmt;
use std::fs::File;
use std::num::NonZeroU32;
use std::path::Path;

use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::guest_confinement::require_subject;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::selinux_policy::{PolicyReadbackError, VerifiedLiveSelinuxPolicy};

use crate::immutable_image::{
    ImmutableImageErrorV1, PendingImmutableFileV1, RetainedImmutableFileV1,
};

use super::{
    CGROUP, CONTEXT, ProductionControllerNormalRootCaptureV1,
    ProductionControllerNormalRootProfileV1, observe_delivery,
};
use super::super::{
    NormalRootStartupErrorV1, images, nix_startup, profile::NormalRootProfileV1,
    retain_fixed_cgroup, service::ServiceObservationV1,
};

/// Retains the first owning admission cause without disclosing selected bytes.
///
/// The concrete operation cause remains private and owned. The public error
/// chain exposes its unchanged legacy classification, not private paths,
/// kernel descriptor details or partially read profile contents.
pub struct ControllerProfileAdmissionFailureV1 {
    stage: &'static str,
    original: NormalRootStartupErrorV1,
    cause: Option<OwnedCause>,
}

// Actual typed causes deliberately remain inaccessible to public diagnostic
// traversal. Retention, rather than observation or reconstruction, is their job.
#[allow(dead_code)]
enum OwnedCause {
    Image(images::ImageObservationErrorV1),
    Linux(aos_sandbox_linux::Error),
    Policy(PolicyReadbackError),
    Allocation(TryReserveError),
    Unwind,
    Unusable,
}

impl ControllerProfileAdmissionFailureV1 {
    /// Borrows the original consuming API's error classification.
    pub fn original_error(&self) -> &NormalRootStartupErrorV1 {
        &self.original
    }

    /// Returns the fixed phase of the first admission refusal.
    pub fn stage(&self) -> &'static str {
        self.stage
    }

    fn startup(stage: &'static str, original: NormalRootStartupErrorV1) -> Self {
        Self {
            stage,
            original,
            cause: None,
        }
    }

    fn image(stage: &'static str, cause: images::ImageObservationErrorV1) -> Self {
        Self {
            stage,
            original: cause.legacy_error(),
            cause: Some(OwnedCause::Image(cause)),
        }
    }

    fn immutable(stage: &'static str, cause: ImmutableImageErrorV1) -> Self {
        Self::image(stage, cause.into())
    }

    fn missing(stage: &'static str) -> Self {
        Self::startup(stage, NormalRootStartupErrorV1::Profile)
    }
}

impl fmt::Debug for ControllerProfileAdmissionFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ControllerProfileAdmissionFailureV1")
            .field("stage", &self.stage)
            .field("original", &self.original)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ControllerProfileAdmissionFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Controller selected-profile admission failed at {}", self.stage)
    }
}

impl StdError for ControllerProfileAdmissionFailureV1 {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.original)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AdmissionState {
    Captured,
    Attempted,
    Absent,
    Selected,
    Ended,
    Moved,
}

struct AdmissionStorage {
    capture: ProductionControllerNormalRootCaptureV1,
    profile_file: PendingImmutableFileV1,
    nix_file: PendingImmutableFileV1,
    nix_present: bool,
    profile: Option<NormalRootProfileV1>,
    policy: Option<VerifiedLiveSelinuxPolicy>,
    files: Vec<RetainedImmutableFileV1>,
    pending_pin: PendingImmutableFileV1,
    observed: Option<ServiceObservationV1>,
    fragment: PendingImmutableFileV1,
    process: Option<PidFd>,
    cgroup: Option<RetainedCgroupAnchor>,
    selected: Option<ProductionControllerNormalRootProfileV1>,
}

/// Owns one retained attempt to admit an actual returned Controller capture.
///
/// Construction performs no observation or duplication. A failed, absent or
/// abandoned attempt cannot be retried or dropped to release its originals;
/// armed Drop terminates before field release. Intentional process death is
/// release, not drain, queue settlement or completed Source-flight evidence.
/// Successful observation still grants no Root, Source, repository or funding
/// authority. The mutable phase/state cells intentionally keep this owner from
/// being Sync. Installed Controller startup selects this disposition; it does
/// not migrate unrelated consuming callers or establish all-role custody.
#[must_use = "retain the attempt until its exact successful profile is moved or the process terminates"]
pub struct ProductionControllerSelectedProfileAdmissionV1 {
    storage: AdmissionStorage,
    state: Cell<AdmissionState>,
    phase: Cell<&'static str>,
    first_failure: Option<ControllerProfileAdmissionFailureV1>,
    armed: bool,
}

impl ProductionControllerSelectedProfileAdmissionV1 {
    pub(super) fn new(capture: ProductionControllerNormalRootCaptureV1) -> Self {
        Self {
            storage: AdmissionStorage {
                capture,
                profile_file: PendingImmutableFileV1::default(),
                nix_file: PendingImmutableFileV1::default(),
                nix_present: false,
                profile: None,
                policy: None,
                files: Vec::new(),
                pending_pin: PendingImmutableFileV1::default(),
                observed: None,
                fragment: PendingImmutableFileV1::default(),
                process: None,
                cgroup: None,
                selected: None,
            },
            state: Cell::new(AdmissionState::Captured),
            phase: Cell::new("captured"),
            first_failure: None,
            armed: true,
        }
    }

    /// Performs the sole admission attempt while keeping originals resident.
    ///
    /// Configured identities are compared with genuine selected profile bytes,
    /// not accepted as authorization. Absence remains nonauthorizing.
    ///
    /// # Errors
    /// Retains the first actual selected-file, profile, policy, unit or process
    /// refusal. Repeated calls return an owning ended-state cause without any
    /// observations. Earlier unreturned lower descriptions remain unavailable.
    pub fn admit_selected_once(
        &mut self,
        uid: u32,
        gid: u32,
    ) -> Result<
        Option<&ProductionControllerNormalRootProfileV1>,
        &ControllerProfileAdmissionFailureV1,
    > {
        if self.state.get() != AdmissionState::Captured {
            self.state.set(AdmissionState::Ended);
            let failure = ControllerProfileAdmissionFailureV1 {
                stage: "ended",
                original: NormalRootStartupErrorV1::Profile,
                cause: Some(OwnedCause::Unusable),
            };
            return Err(self.first_failure.get_or_insert(failure));
        }
        self.state.set(AdmissionState::Attempted);

        let result = {
            let _unwind = AdmissionUnwindFence {
                state: &self.state,
                phase: &self.phase,
                first_failure: &mut self.first_failure,
            };
            retained_recipe(&mut self.storage, &self.phase, uid, gid)
        };
        match result {
            Err(failure) => {
                self.state.set(AdmissionState::Ended);
                Err(self.first_failure.get_or_insert(failure))
            }
            Ok(false) => {
                self.state.set(AdmissionState::Absent);
                Ok(None)
            }
            Ok(true) => {
                if self.storage.selected.is_none() {
                    self.state.set(AdmissionState::Ended);
                    return Err(self.first_failure.get_or_insert(
                        ControllerProfileAdmissionFailureV1::missing("completed-profile"),
                    ));
                }
                self.state.set(AdmissionState::Selected);
                Ok(self.storage.selected.as_ref())
            }
        }
    }

    /// Borrows the permanently retained first cause, if admission failed.
    pub fn first_failure(&self) -> Option<&ControllerProfileAdmissionFailureV1> {
        self.first_failure.as_ref()
    }

    /// Moves the same completed profile and producer-associated Nix capture.
    ///
    /// Nonpositive absence settles only the genuine early-return disposition.
    /// Its associated unused delivery duplicate remains private Nix custody,
    /// never a measured Root profile or an externally paired descriptor.
    ///
    /// # Errors
    /// Retains the first failure and all originals on contradictory, repeated
    /// or incomplete handoff. No observation or allocation follows removal.
    pub fn take_admitted_roles(
        &mut self,
    ) -> Result<
        (Option<ProductionControllerNormalRootProfileV1>,
         Option<nix_startup::ProductionControllerNixStartupCaptureV1>),
        &ControllerProfileAdmissionFailureV1,
    > {
        let state = self.state.get();
        let absent = state == AdmissionState::Absent;
        let capture = &self.storage.capture;
        let unused_delivery = capture.nix_delivery.is_some();
        let slots_empty = self.storage.profile.is_none()
            && self.storage.policy.is_none()
            && self.storage.files.is_empty()
            && self.storage.observed.is_none()
            && self.storage.process.is_none()
            && self.storage.cgroup.is_none()
            && [&self.storage.profile_file, &self.storage.nix_file,
                &self.storage.pending_pin, &self.storage.fragment]
                .iter().all(|pending| pending.original().is_err()
                    && pending.measurement().is_err());
        let absent_payload_empty = self.phase.get() == "captured"
            && !self.storage.nix_present
            && [&self.storage.profile_file, &self.storage.nix_file,
                &self.storage.pending_pin, &self.storage.fragment]
                .iter().all(|pending| pending.bytes().is_empty());
        let delivery_pair = if absent {
            capture.nix.is_some() == unused_delivery
                && capture.nix.as_ref().is_none_or(|nix| {
                    nix.can_park_absent_root_delivery()
                })
        } else {
            !unused_delivery
        };
        if self.first_failure.is_some()
            || !matches!(state, AdmissionState::Selected | AdmissionState::Absent)
            || self.storage.selected.is_some() == absent
            || capture.profile.is_some()
            || capture.git_source_listener.is_some()
            || !slots_empty
            || !delivery_pair
            || absent && !absent_payload_empty
        {
            self.state.set(AdmissionState::Ended);
            return Err(self.first_failure.get_or_insert_with(|| {
                ControllerProfileAdmissionFailureV1::missing("completed-roles")
            }));
        }

        if absent && unused_delivery {
            let originals = (
                self.storage.capture.nix.as_mut(),
                self.storage.capture.nix_delivery.take(),
            );
            match originals {
                (Some(nix), Some(delivery)) => nix.park_absent_root_delivery(delivery),
                (_, delivery) => {
                    self.storage.capture.nix_delivery = delivery;
                    self.state.set(AdmissionState::Ended);
                    return Err(self.first_failure.get_or_insert_with(|| {
                        ControllerProfileAdmissionFailureV1::missing("completed-role-pair")
                    }));
                }
            }
        }
        let roles = (self.storage.selected.take(), self.storage.capture.nix.take());
        self.state.set(AdmissionState::Moved);
        self.armed = false;
        Ok(roles)
    }

    /// Moves the same fully checked profile once without observation or allocation.
    ///
    /// The caller installs its destination before any fallible continuation.
    /// Unconsumed optional Nix/Git captures remain resident and keep this owner
    /// armed; their presence cannot authorize silent descriptor release.
    #[must_use]
    pub fn take_admitted_profile(&mut self) -> Option<ProductionControllerNormalRootProfileV1> {
        if self.state.get() != AdmissionState::Selected {
            return None;
        }
        if self.storage.selected.is_none() {
            self.state.set(AdmissionState::Ended);
            self.first_failure.get_or_insert(
                ControllerProfileAdmissionFailureV1::missing("completed-move"),
            );
            return None;
        }
        let retained_roles = self.storage.capture.nix.is_some()
            || self.storage.capture.git_source_listener.is_some();
        let selected = self.storage.selected.take();
        self.state.set(AdmissionState::Moved);
        self.armed = retained_roles;
        selected
    }
}

impl Drop for ProductionControllerSelectedProfileAdmissionV1 {
    fn drop(&mut self) {
        if self.armed {
            self.state.set(AdmissionState::Ended);
            self.first_failure.get_or_insert_with(|| {
                ControllerProfileAdmissionFailureV1::missing("abandoned")
            });
            std::process::abort();
        }
    }
}

struct AdmissionUnwindFence<'attempt> {
    state: &'attempt Cell<AdmissionState>,
    phase: &'attempt Cell<&'static str>,
    first_failure: &'attempt mut Option<ControllerProfileAdmissionFailureV1>,
}

impl Drop for AdmissionUnwindFence<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.state.set(AdmissionState::Ended);
            self.first_failure.get_or_insert(ControllerProfileAdmissionFailureV1 {
                stage: self.phase.get(),
                original: NormalRootStartupErrorV1::Profile,
                cause: Some(OwnedCause::Unwind),
            });
            // Every returned original is already in storage; no caller can
            // catch this unwind and revive or release the incomplete attempt.
            std::process::abort();
        }
    }
}

// These compile-time dispositions change storage only. The fixed recipe below
// remains the sole ordering/validation policy, with no injected hooks or sink.
macro_rules! phase {
    (legacy, $phase:ident, $stage:literal) => {};
    (retained, $phase:ident, $stage:literal) => { $phase.set($stage); };
}

macro_rules! original {
    (legacy, $capture:expr) => { ($capture).profile };
    (retained, $capture:expr) => { ($capture).profile.take() };
}

macro_rules! absent {
    (legacy) => { return Ok(None) };
    (retained) => { return Ok(false) };
}

macro_rules! park_original {
    (legacy, $storage:ident, $original:ident) => {};
    (retained, $storage:ident, $original:ident) => {
        $storage.profile_file.park_original(File::from($original));
    };
}

macro_rules! direct {
    (legacy, $stage:literal, $expression:expr) => { $expression? };
    (retained, $stage:literal, $expression:expr) => {
        $expression.map_err(|error| ControllerProfileAdmissionFailureV1::startup($stage, error))?
    };
}

macro_rules! check {
    (legacy, $stage:literal, $expression:expr, $classification:ident, $cause:ident) => {
        $expression.map_err(|_| NormalRootStartupErrorV1::$classification)?
    };
    (retained, $stage:literal, $expression:expr, $classification:ident, $cause:ident) => {
        $expression.map_err(|cause| ControllerProfileAdmissionFailureV1 {
            stage: $stage,
            original: NormalRootStartupErrorV1::$classification,
            cause: Some(OwnedCause::$cause(cause)),
        })?
    };
}

macro_rules! refusal {
    (legacy, $stage:literal, $classification:ident) => {
        return Err(NormalRootStartupErrorV1::$classification)
    };
    (retained, $stage:literal, $classification:ident) => {
        return Err(ControllerProfileAdmissionFailureV1::startup(
            $stage, NormalRootStartupErrorV1::$classification,
        ))
    };
}

macro_rules! bind {
    (legacy, $storage:ident, $name:ident, $expression:expr) => {
        let $name = $expression;
    };
    (retained, $storage:ident, $name:ident, $expression:expr) => {
        $storage.$name = Some($expression);
        let $name = $storage.$name.as_ref()
            .ok_or_else(|| ControllerProfileAdmissionFailureV1::missing(stringify!($name)))?;
    };
}

macro_rules! store {
    (legacy, $storage:ident, $name:ident, $old:expr, $parked:expr) => {
        let $name = $old;
    };
    (retained, $storage:ident, $name:ident, $old:expr, $parked:expr) => {
        $storage.$name = Some($parked);
    };
}

macro_rules! nix_profile {
    (legacy, $capture:expr, $storage:ident, $name:ident) => {
        let $name = ($capture).nix_delivery
            .map(|fd| nix_startup::retain_controller_profile(File::from(fd)))
            .transpose()?;
    };
    (retained, $capture:expr, $storage:ident, $name:ident) => {
        $storage.nix_present = ($capture).nix_delivery.is_some();
        if let Some(file) = ($capture).nix_delivery.take() {
            $storage.nix_file.park_original(File::from(file));
            nix_startup::park_controller_profile(&mut $storage.nix_file)
                .map_err(|cause| ControllerProfileAdmissionFailureV1::image("nix-profile", cause))?;
        }
        let $name = if $storage.nix_present {
            Some($storage.nix_file.measurement()
                .map_err(|cause| ControllerProfileAdmissionFailureV1::immutable("nix-profile", cause))?)
        } else {
            None
        };
    };
}

macro_rules! profile_file {
    (legacy, $storage:ident, $original:ident, $file:ident, $bytes:ident) => {
        let ($file, $bytes) = images::retain_profile(File::from($original))?;
    };
    (retained, $storage:ident, $original:ident, $file:ident, $bytes:ident) => {
        images::park_controller_profile(&mut $storage.profile_file)
            .map_err(|cause| ControllerProfileAdmissionFailureV1::image("profile-file", cause))?;
        let $file = $storage.profile_file.measurement()
            .map_err(|cause| ControllerProfileAdmissionFailureV1::immutable("profile-file", cause))?;
        let $bytes = $storage.profile_file.bytes();
    };
}

macro_rules! pins {
    (legacy, $storage:ident, $profile:ident, $name:ident) => {
        let $name = $profile.runtime_files.iter()
            .chain([
                &$profile.pid1,
                &$profile.canonical_policy,
                &$profile.source_policy,
                &$profile.effective_matrix,
            ])
            .map(|pin| {
                let executable = pin.path == $profile.executable.path
                    || pin.path == $profile.loader.path
                    || pin.path == $profile.pid1.path;
                images::retain_pin(pin, None, executable)
            })
            .collect::<Result<Vec<_>, _>>()?;
    };
    (retained, $storage:ident, $profile:ident, $name:ident) => {
        park_pins($profile, &mut $storage.files, &mut $storage.pending_pin)?;
    };
}

macro_rules! fragment {
    (legacy, $storage:ident, $observed:ident, $name:ident) => {
        let $name = RetainedImmutableFileV1::observe_fragment($observed.fragment.clone())
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
    };
    (retained, $storage:ident, $observed:ident, $name:ident) => {
        $storage.fragment.open_and_measure($observed.fragment.clone(), None, 64 * 1024, false)
            .map_err(|cause| ControllerProfileAdmissionFailureV1 {
                stage: "fragment",
                original: NormalRootStartupErrorV1::Service,
                cause: Some(OwnedCause::Image(cause.into())),
            })?;
    };
}

macro_rules! process_id {
    (legacy) => {
        NonZeroU32::new(std::process::id()).ok_or(NormalRootStartupErrorV1::Service)?
    };
    (retained) => {
        NonZeroU32::new(std::process::id()).ok_or_else(|| {
            ControllerProfileAdmissionFailureV1::startup("process", NormalRootStartupErrorV1::Service)
        })?
    };
}

macro_rules! finish {
    (legacy, $capture:expr, $storage:ident,
     $profile_file:ident, $profile:ident, $files:ident, $policy:ident,
     $fragment:ident, $observed:ident, $process:ident, $cgroup:ident, $nix:ident) => {
        let retained = ProductionControllerNormalRootProfileV1 {
            profile_file: $profile_file,
            profile: $profile,
            files: $files,
            policy: $policy,
            fragment: $fragment,
            observed: $observed,
            process: $process,
            cgroup: $cgroup,
            tpm_image: ($capture).tpm_image,
            nix_delivery: $nix,
        };
        retained.recheck()?;
        Ok(Some(retained))
    };
    (retained, $capture:expr, $storage:ident,
     $profile_file:ident, $profile:ident, $files:ident, $policy:ident,
     $fragment:ident, $observed:ident, $process:ident, $cgroup:ident, $nix:ident) => {
        $storage.assemble_profile()?;
        $storage.selected.as_ref()
            .ok_or_else(|| ControllerProfileAdmissionFailureV1::missing("completed-profile"))?
            .recheck()
            .map_err(|cause| ControllerProfileAdmissionFailureV1::startup("final-recheck", cause))?;
        Ok(true)
    };
}

macro_rules! selected_recipe {
    ($mode:ident, $capture:expr, $storage:ident, $phase:ident, $uid:ident, $gid:ident) => {{
        let Some(original) = original!($mode, $capture) else {
            absent!($mode);
        };
        park_original!($mode, $storage, original);

        phase!($mode, $phase, "nix-profile");
        nix_profile!($mode, $capture, $storage, nix_delivery);
        phase!($mode, $phase, "subject");
        check!($mode, "subject", require_subject(CONTEXT), Confinement, Linux);

        phase!($mode, $phase, "profile-file");
        profile_file!($mode, $storage, original, profile_file, bytes);
        phase!($mode, $phase, "profile-decode");
        bind!($mode, $storage, profile,
            direct!($mode, "profile-decode", NormalRootProfileV1::decode(&bytes)));
        if profile.identities[..2] != [$uid, $gid]
            || profile_file.path().parent() != Path::new(&profile.effective_matrix.path).parent()
        {
            refusal!($mode, "profile-selection", Profile);
        }

        phase!($mode, $phase, "policy");
        bind!($mode, $storage, policy,
            check!($mode, "policy",
                VerifiedLiveSelinuxPolicy::verify(&profile.canonical_policy.path), Confinement, Policy));
        if policy.digest() != profile.canonical_policy.sha256 {
            refusal!($mode, "policy-digest", Confinement);
        }
        phase!($mode, $phase, "pins");
        pins!($mode, $storage, profile, files);

        phase!($mode, $phase, "delivery");
        bind!($mode, $storage, observed,
            direct!($mode, "delivery", observe_delivery(
                profile_file.path(), ($capture).tpm_image,
                nix_delivery.as_ref().map(|file| file.path()),
            )));
        phase!($mode, $phase, "fragment");
        fragment!($mode, $storage, observed, fragment);
        phase!($mode, $phase, "process");
        store!($mode, $storage, process,
            PidFd::open(process_id!($mode)).map_err(|_| NormalRootStartupErrorV1::Service)?,
            check!(retained, "process", PidFd::open(process_id!(retained)), Service, Linux));
        phase!($mode, $phase, "cgroup");
        store!($mode, $storage, cgroup,
            retain_fixed_cgroup(Path::new(CGROUP))?,
            direct!(retained, "cgroup", retain_fixed_cgroup(Path::new(CGROUP))));

        phase!($mode, $phase, "final-recheck");
        finish!($mode, $capture, $storage,
            profile_file, profile, files, policy, fragment, observed, process, cgroup, nix_delivery)
    }};
}

pub(super) fn legacy_recipe(
    capture: ProductionControllerNormalRootCaptureV1,
    uid: u32,
    gid: u32,
) -> Result<Option<ProductionControllerNormalRootProfileV1>, NormalRootStartupErrorV1> {
    selected_recipe!(legacy, capture, capture, unused_phase, uid, gid)
}

fn retained_recipe(
    storage: &mut AdmissionStorage,
    phase: &Cell<&'static str>,
    uid: u32,
    gid: u32,
) -> Result<bool, ControllerProfileAdmissionFailureV1> {
    selected_recipe!(retained, storage.capture, storage, phase, uid, gid)
}

fn park_pins(
    profile: &NormalRootProfileV1,
    files: &mut Vec<RetainedImmutableFileV1>,
    pending: &mut PendingImmutableFileV1,
) -> Result<(), ControllerProfileAdmissionFailureV1> {
    for pin in profile.runtime_files.iter().chain([
        &profile.pid1, &profile.canonical_policy, &profile.source_policy, &profile.effective_matrix,
    ]) {
        // Reserve BEFORE any new File is opened or removed from its pending
        // slot. The only prefix Vec remains in the original storage owner.
        files.try_reserve(1).map_err(|cause| ControllerProfileAdmissionFailureV1 {
            stage: "pin-storage",
            original: NormalRootStartupErrorV1::Image,
            cause: Some(OwnedCause::Allocation(cause)),
        })?;
        let executable = pin.path == profile.executable.path
            || pin.path == profile.loader.path
            || pin.path == profile.pid1.path;
        images::park_selected_pin(pin, executable, pending)
            .map_err(|cause| ControllerProfileAdmissionFailureV1::image("pins", cause))?;
        let Some(file) = pending.take_measurement() else {
            return Err(ControllerProfileAdmissionFailureV1::missing("pin-storage"));
        };
        // Capacity was admitted before the new original was opened.
        // No observation, callback or allocation separates this exact move.
        files.push(file);
    }
    Ok(())
}

impl AdmissionStorage {
    fn assemble_profile(&mut self) -> Result<(), ControllerProfileAdmissionFailureV1> {
        if self.profile_file.measurement().is_err()
            || self.profile.is_none()
            || self.policy.is_none()
            || self.observed.is_none()
            || self.fragment.measurement().is_err()
            || self.process.is_none()
            || self.cgroup.is_none()
            || self.nix_present && self.nix_file.measurement().is_err()
        {
            return Err(ControllerProfileAdmissionFailureV1::missing("profile-assembly"));
        }

        let originals = (
            self.profile_file.take_measurement(),
            self.profile.take(),
            self.policy.take(),
            self.observed.take(),
            self.fragment.take_measurement(),
            self.process.take(),
            self.cgroup.take(),
            self.nix_file.take_measurement(),
            std::mem::take(&mut self.files),
        );
        match originals {
            (Some(profile_file), Some(profile), Some(policy), Some(observed), Some(fragment),
             Some(process), Some(cgroup), nix_delivery, files)
                if nix_delivery.is_some() == self.nix_present => {
                self.selected = Some(ProductionControllerNormalRootProfileV1 {
                    profile_file,
                    profile,
                    files,
                    policy,
                    fragment,
                    observed,
                    process,
                    cgroup,
                    tpm_image: self.capture.tpm_image,
                    nix_delivery,
                });
                Ok(())
            }
            (profile_file, profile, policy, observed, fragment, process, cgroup, nix_delivery, files) => {
                self.profile_file.restore_measurement(profile_file);
                self.profile = profile;
                self.policy = policy;
                self.observed = observed;
                self.fragment.restore_measurement(fragment);
                self.process = process;
                self.cgroup = cgroup;
                self.nix_file.restore_measurement(nix_delivery);
                self.files = files;
                Err(ControllerProfileAdmissionFailureV1::missing("profile-assembly"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_failure_insertion_keeps_the_original_typed_cause() {
        let first = ControllerProfileAdmissionFailureV1::missing("profile-selection");
        let mut slot = Some(first);
        let later = ControllerProfileAdmissionFailureV1::missing("ended");

        let retained = slot.get_or_insert(later);

        assert_eq!(retained.stage(), "profile-selection");
        assert!(matches!(retained.original_error(), NormalRootStartupErrorV1::Profile));
    }

    #[test]
    fn owning_error_diagnostics_do_not_disclose_private_operation_data() {
        let error = ControllerProfileAdmissionFailureV1::image("profile-file",
            images::ImageObservationErrorV1::Io(std::io::Error::other("private-profile-data")));

        let debug = format!("{error:?}");
        let display = error.to_string();
        let source = error.source().unwrap().to_string();

        assert!(!debug.contains("private-profile-data"));
        assert!(!display.contains("private-profile-data"));
        assert!(!source.contains("private-profile-data"));
        assert!(matches!(error.cause, Some(OwnedCause::Image(_))));
    }
}
