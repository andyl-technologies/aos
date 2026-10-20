//! Closed legacy and retained dispositions of the same Controller admission recipe.
//!
//! The retained path owns only an actually returned initial capture. Original
//! files, read buffers and successful observations remain parked through later
//! failures. Earlier table capture and lower returned policy/pidfd/cgroup
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
use rustix::fs::{open, Mode, OFlags};
use aos_sandbox_linux::guest_confinement::require_subject;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::selinux_policy::{PolicyReadbackError, VerifiedLiveSelinuxPolicy};

use crate::immutable_image::{
    ImmutableImageErrorV1, PendingImmutableFileV1, RetainedImmutableFileV1,
};
use aos_sandbox_linux::cgroup::{ControllerInitialCgroupReadbackV1, CgroupV2Root};
use aos_sandbox_linux::guest_confinement::CurrentThreadSubjectOriginalV1;
use aos_sandbox_linux::selinux_policy::RetainedLiveSelinuxPolicyReadbackV1;

use super::{
    ControllerProfileCaptureV1, ControllerSelfProfileOriginalV1,
    ControllerProfileErrorV1 as NormalRootStartupErrorV1, images,
    delivery::{CGROUP, CONTEXT, ServiceObservationV1},
    schema::{NormalRootProfileV1, RootProfileDecodeAttemptV1},
    observer::{self as service, observe_delivery},
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
    Baseline(std::sync::Arc<super::baseline::ControllerBaselineProfileV1>),
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

    pub(super) fn baseline(
        fallback: &'static str,
        owner: &std::sync::Arc<super::baseline::ControllerBaselineProfileV1>,
    ) -> Self {
        // Drop the private guard before any other baseline operation. Only
        // fixed phase/classification DATA crosses the public privacy boundary;
        // the same Arc keeps the actual parked native cause owned in place.
        let (stage, original) = match owner.failure_view() {
            Some(view) => (view.phase(), view.classification()),
            None => (fallback, NormalRootStartupErrorV1::Service),
        };
        Self {
            stage,
            original,
            cause: Some(OwnedCause::Baseline(std::sync::Arc::clone(owner))),
        }
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
    capture: ControllerProfileCaptureV1,
    profile_file: PendingImmutableFileV1,
    nix_file: PendingImmutableFileV1,
    nix_present: bool,
    profile: Option<NormalRootProfileV1>,
    profile_decode: RootProfileDecodeAttemptV1,
    baseline: Option<std::sync::Arc<super::baseline::ControllerBaselineProfileV1>>,
    policy: Option<VerifiedLiveSelinuxPolicy>,
    files: Vec<RetainedImmutableFileV1>,
    pending_pin: PendingImmutableFileV1,
    observed: Option<ServiceObservationV1>,
    fragment: PendingImmutableFileV1,
    process: Option<PidFd>,
    cgroup: Option<RetainedCgroupAnchor>,
    selected: Option<ControllerSelfProfileOriginalV1>,
    subject_original: CurrentThreadSubjectOriginalV1,
    policy_original: RetainedLiveSelinuxPolicyReadbackV1,
    cgroup_original: ControllerInitialCgroupReadbackV1,
    cgroup_root: Option<CgroupV2Root>,
    delivery_canonical: Option<std::io::Result<std::path::PathBuf>>,

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
pub struct ControllerSelectedProfileAdmissionV1 {
    storage: AdmissionStorage,
    state: Cell<AdmissionState>,
    phase: Cell<&'static str>,
    first_failure: Option<ControllerProfileAdmissionFailureV1>,
    armed: bool,
}

impl ControllerSelectedProfileAdmissionV1 {
    pub(in crate::controller_receiving) fn new(capture: ControllerProfileCaptureV1) -> Self {
        Self {
            storage: AdmissionStorage {
                capture,
                profile_file: PendingImmutableFileV1::default(),
                nix_file: PendingImmutableFileV1::default(),
                nix_present: false,
                profile: None,
                profile_decode: RootProfileDecodeAttemptV1::default(),
                baseline: None,
                policy: None,
                files: Vec::new(),
                pending_pin: PendingImmutableFileV1::default(),
                observed: None,
                fragment: PendingImmutableFileV1::default(),
                process: None,
                cgroup: None,
                selected: None,
                subject_original: CurrentThreadSubjectOriginalV1::new(),
                policy_original: RetainedLiveSelinuxPolicyReadbackV1::new(),
                cgroup_original: ControllerInitialCgroupReadbackV1::new(),
                cgroup_root: None,
                delivery_canonical: None,

            },
            state: Cell::new(AdmissionState::Captured),
            phase: Cell::new("captured"),
            first_failure: None,
            armed: true,
        }
    }

    // Only the same first-table C opening can call this Native-only entry.
    // The installed public/ordinary selected API accepts no resource vector.
    pub(in crate::controller_receiving) fn admit_with_controller_baseline_once(
        &mut self,
        original: std::sync::Arc<crate::controller_receiving::ControllerReceivingOriginalV1>,
        uid: u32,
        gid: u32,
    ) -> bool {
        if self.state.get() != AdmissionState::Captured || self.storage.baseline.is_some() {
            self.state.set(AdmissionState::Ended);
            self.first_failure.get_or_insert_with(|| ControllerProfileAdmissionFailureV1::missing("baseline-entry"));
            return false;
        }
        if original.bind_initial_program_fd_mode_v1(&self.storage.capture).is_err() {
            self.state.set(AdmissionState::Ended);
            self.first_failure.get_or_insert_with(||
                ControllerProfileAdmissionFailureV1::missing("initial-program-mode"));
            return false;
        }
        let baseline = std::sync::Arc::new(super::baseline::ControllerBaselineProfileV1::begin_initial(original));
        self.storage.baseline = Some(std::sync::Arc::clone(&baseline));
        if baseline.prepare_initial_once().is_err() {
            baseline.refuse_initial();
            self.state.set(AdmissionState::Ended);
            self.first_failure.get_or_insert_with(|| ControllerProfileAdmissionFailureV1::baseline("baseline-prefix", &baseline));
            return false;
        }
        match self.admit_selected_once(uid, gid) {
            Ok(Some(profile)) => {
                if baseline.finish_initial(profile).is_ok() {
                    true
                } else {
                    self.state.set(AdmissionState::Ended);
                    self.first_failure.get_or_insert_with(|| ControllerProfileAdmissionFailureV1::baseline("baseline-completion", &baseline));
                    false
                }
            }
            _ => {
                if self.state.get() == AdmissionState::Absent {
                    self.state.set(AdmissionState::Ended);
                    self.first_failure.get_or_insert_with(|| {
                        ControllerProfileAdmissionFailureV1::missing("selected-profile-absence")
                    });
                }
                baseline.refuse_initial();
                false
            }
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
        Option<&ControllerSelfProfileOriginalV1>,
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
        if self.storage.capture.resource_delivery && self.storage.baseline.is_none() {
            self.state.set(AdmissionState::Ended);
            return Err(self.first_failure.get_or_insert_with(|| ControllerProfileAdmissionFailureV1::missing("baseline-original")));
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

    /// Moves only this completed ordinary profile and unused Nix duplicate.
    ///
    /// The actual upper Nix capture retains the returned unused duplicate on
    /// nonpositive Root absence. No C pairing, pathname or file is accepted.
    ///
    /// # Errors
    /// Retains failed, selected-C, repeated or incomplete ordinary disposition.
    pub fn take_completed_ordinary_v1(
        &mut self,
    ) -> Result<(Option<ControllerSelfProfileOriginalV1>, Option<std::os::fd::OwnedFd>),
        &ControllerProfileAdmissionFailureV1>
    {
        let state = self.state.get();
        let absent = state == AdmissionState::Absent;
        let ordinary = !self.storage.capture.resource_delivery
            && !self.storage.capture.resource_launch
            && self.storage.baseline.is_none()
            && self.storage.selected.as_ref().is_none_or(|profile| profile.baseline.is_none());
        let completed = matches!(state, AdmissionState::Selected | AdmissionState::Absent)
            && self.storage.selected.is_some() != absent;
        let empty = self.storage.capture.profile.is_none()
            && self.storage.profile.is_none()
            && self.storage.policy.is_none()
            && self.storage.files.is_empty()
            && self.storage.observed.is_none()
            && self.storage.process.is_none()
            && self.storage.cgroup.is_none()
            && [&self.storage.profile_file, &self.storage.nix_file,
                &self.storage.pending_pin, &self.storage.fragment]
                .iter().all(|pending| pending.original().is_err()
                    && pending.measurement().is_err());
        let absent_empty = !absent || self.phase.get() == "captured"
            && !self.storage.nix_present
            && [&self.storage.profile_file, &self.storage.nix_file,
                &self.storage.pending_pin, &self.storage.fragment]
                .iter().all(|pending| pending.bytes().is_empty());
        if self.first_failure.is_some() || !ordinary || !completed || !empty || !absent_empty
            || !absent && self.storage.capture.nix_delivery.is_some()
        {
            self.state.set(AdmissionState::Ended);
            return Err(self.first_failure.get_or_insert_with(|| {
                ControllerProfileAdmissionFailureV1::missing("completed-ordinary-profile")
            }));
        }

        let completed = (self.storage.selected.take(), self.storage.capture.nix_delivery.take());
        self.state.set(AdmissionState::Moved);
        self.armed = false;
        Ok(completed)
    }

    /// Moves the same fully checked profile once without observation or allocation.
    ///
    /// The caller installs its destination before any fallible continuation.
    /// Unconsumed optional Nix/Git captures remain resident and keep this owner
    /// armed; their presence cannot authorize silent descriptor release.
    #[must_use]
    pub fn take_admitted_profile(&mut self) -> Option<ControllerSelfProfileOriginalV1> {
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
        let selected = self.storage.selected.take();
        self.state.set(AdmissionState::Moved);
        self.armed = false;
        selected
    }
}

impl Drop for ControllerSelectedProfileAdmissionV1 {
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
            .map(|fd| images::retain_nix_controller_profile(File::from(fd)))
            .transpose()?;
    };
    (retained, $capture:expr, $storage:ident, $name:ident) => {
        $storage.nix_present = ($capture).nix_delivery.is_some();
        if let Some(file) = ($capture).nix_delivery.take() {
            $storage.nix_file.park_original(File::from(file));
            images::park_nix_controller_profile(&mut $storage.nix_file)
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

// Both selected recipients use the same schema and bounded adapter. The
// retained Controller parks the actual Serde Result before a negative phase
// disposition and moves the completed model once into its existing slot.
macro_rules! decode_profile {
    (legacy, $storage:ident, $bytes:ident, $profile:ident) => {
        let $profile = NormalRootProfileV1::decode(&$bytes)?;
    };
    (retained, $storage:ident, $bytes:ident, $profile:ident) => {
        $storage.profile_decode.decode_once(&$bytes)
            .map_err(|cause| ControllerProfileAdmissionFailureV1::startup("profile-decode", cause))?;
        $storage.profile = Some($storage.profile_decode.take_completed()
            .ok_or_else(|| ControllerProfileAdmissionFailureV1::missing("profile-decode"))?);
        let $profile = $storage.profile.as_ref()
            .ok_or_else(|| ControllerProfileAdmissionFailureV1::missing("profile-decode"))?;
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
        if let Some(baseline) = &$storage.baseline {
            let count = $profile.runtime_files.len().checked_add(4)
                .ok_or_else(|| ControllerProfileAdmissionFailureV1::missing("pin-count"))?;
            baseline.require_pin_count(count)
                .map_err(|cause| ControllerProfileAdmissionFailureV1::startup("pin-budget", cause))?;
        }
        park_pins($profile, &mut $storage.files, &mut $storage.pending_pin)?;
    };
}

macro_rules! delivery {
    (legacy, $storage:ident, $capture:expr, $file:ident, $nix:ident, $name:ident) => {
        let $name = observe_delivery($file.path(), ($capture).tpm_image,
            $nix.as_ref().map(|file| file.path()), ($capture).resource_delivery, ($capture).resource_launch)?;
    };
    (retained, $storage:ident, $capture:expr, $file:ident, $nix:ident, $name:ident) => {
        let returned = if let Some(baseline) = &$storage.baseline {
            baseline.read(service::CONTROLLER_UNIT, std::process::id(), service::SERVICE_PROPERTIES)
                .and_then(|(properties, unit)| super::delivery::immutable_observation_into(super::delivery::decode_delivery_with_resource_launch(
                    &properties, &unit, $file.path(), ($capture).tpm_image,
                    $nix.as_ref().map(|file| file.path()), ($capture).resource_delivery, ($capture).resource_launch,
                )?, &mut $storage.delivery_canonical))
        } else {
            observe_delivery($file.path(), ($capture).tpm_image,
                $nix.as_ref().map(|file| file.path()), ($capture).resource_delivery, ($capture).resource_launch)
        };
        $storage.observed = Some(returned.map_err(|cause| ControllerProfileAdmissionFailureV1::startup("delivery", cause))?);
        let $name = $storage.observed.as_ref()
            .ok_or_else(|| ControllerProfileAdmissionFailureV1::missing("delivery"))?;
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
     $fragment:ident, $observed:ident, $process:ident, $cgroup:ident, $nix:ident) => {{
        let retained = ControllerSelfProfileOriginalV1 {
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
            resource_delivery: ($capture).resource_delivery,
            resource_launch: ($capture).resource_launch,
            baseline: None,
            original_observers: super::original_observers::OriginalObserverRegistryV1::new(),
        };
        retained.recheck()?;
        Ok(Some(retained))
    }};
    (retained, $capture:expr, $storage:ident,
     $profile_file:ident, $profile:ident, $files:ident, $policy:ident,
     $fragment:ident, $observed:ident, $process:ident, $cgroup:ident, $nix:ident) => {{
        $storage.assemble_profile()?;
        $storage.selected.as_ref()
            .ok_or_else(|| ControllerProfileAdmissionFailureV1::missing("completed-profile"))?
            .recheck()
            .map_err(|cause| ControllerProfileAdmissionFailureV1::startup("final-recheck", cause))?;
        Ok(true)
    }};
}

// These compile-time dispositions share existing lower native recipes. The
// selected caller owns every result destination before the first native step.
macro_rules! subject {
    (legacy, $storage:ident) => {
        require_subject(CONTEXT).map_err(|_| NormalRootStartupErrorV1::Confinement)?;
    };
    (retained, $storage:ident) => {
        check!(retained, "subject", $storage.subject_original.observe_once(CONTEXT), Confinement, Linux);
        if !$storage.subject_original.retire_completed_file_once_v1() {
            refusal!(retained, "subject-disposal", Confinement);
        }
    };
}

macro_rules! policy {
    (legacy, $storage:ident, $profile:ident, $policy:ident) => {
        let $policy = VerifiedLiveSelinuxPolicy::verify(&$profile.canonical_policy.path)
            .map_err(|_| NormalRootStartupErrorV1::Confinement)?;
    };
    (retained, $storage:ident, $profile:ident, $policy:ident) => {
        check!(retained, "policy", $storage.policy_original.verify_once(&$profile.canonical_policy.path),
            Confinement, Policy);
        $storage.policy = $storage.policy_original.verified();
        let $policy = $storage.policy.as_ref()
            .ok_or_else(|| ControllerProfileAdmissionFailureV1::missing("policy"))?;
    };
}

macro_rules! retire_policy {
    (legacy, $storage:ident) => {};
    (retained, $storage:ident) => {
        if !$storage.policy_original.retire_completed_files_once_v1() {
            refusal!(retained, "policy-disposal", Confinement);
        }
    };
}

macro_rules! cgroup {
    (legacy, $storage:ident, $name:ident) => {
        let $name = retain_fixed_cgroup(Path::new(CGROUP))?;
    };
    (retained, $storage:ident, $name:ident) => {
        check!(retained, "cgroup", $storage.cgroup_original.capture_once(), Service, Linux);
        let (root, anchor) = $storage.cgroup_original.take_validated_pair()
            .ok_or_else(|| ControllerProfileAdmissionFailureV1::missing("cgroup"))?;
        $storage.cgroup_root = Some(root);
        $storage.cgroup = Some(anchor);
    };
}

fn retain_fixed_cgroup(path: &Path) -> Result<RetainedCgroupAnchor, NormalRootStartupErrorV1> {
    crate::profile_data::native_observation::retain_cgroup_anchor_data_v1(path)
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
        subject!($mode, $storage);

        phase!($mode, $phase, "profile-file");
        profile_file!($mode, $storage, original, profile_file, bytes);
        phase!($mode, $phase, "profile-decode");
        decode_profile!($mode, $storage, bytes, profile);
        if profile.identities[..2] != [$uid, $gid]
            || profile_file.path().parent() != Path::new(&profile.effective_matrix.path).parent()
        {
            refusal!($mode, "profile-selection", Profile);
        }

        phase!($mode, $phase, "policy");
        policy!($mode, $storage, profile, policy);
        if policy.digest() != profile.canonical_policy.sha256 {
            refusal!($mode, "policy-digest", Confinement);
        }
        // The same complete policy and exact expected digest now agree. Only
        // selected temporary Files retire; all original outcomes remain owned.
        retire_policy!($mode, $storage);
        phase!($mode, $phase, "pins");
        pins!($mode, $storage, profile, files);

        phase!($mode, $phase, "delivery");
        delivery!($mode, $storage, $capture, profile_file, nix_delivery, observed);
        phase!($mode, $phase, "fragment");
        fragment!($mode, $storage, observed, fragment);
        phase!($mode, $phase, "process");
        store!($mode, $storage, process,
            PidFd::open(process_id!($mode)).map_err(|_| NormalRootStartupErrorV1::Service)?,
            check!(retained, "process", PidFd::open(process_id!(retained)), Service, Linux));
        phase!($mode, $phase, "cgroup");
        cgroup!($mode, $storage, cgroup);

        phase!($mode, $phase, "final-recheck");
        finish!($mode, $capture, $storage,
            profile_file, profile, files, policy, fragment, observed, process, cgroup, nix_delivery)
    }};
}

pub(in crate::controller_receiving) fn legacy_recipe(
    capture: ControllerProfileCaptureV1,
    uid: u32,
    gid: u32,
) -> Result<Option<ControllerSelfProfileOriginalV1>, NormalRootStartupErrorV1> {
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
                self.selected = Some(ControllerSelfProfileOriginalV1 {
                    profile_file,
                    profile,
                    files,
                    policy,
                    fragment,
                    observed,
                    process,
                    cgroup,
                    tpm_image: self.capture.tpm_image,
                    resource_delivery: self.capture.resource_delivery,
                    resource_launch: self.capture.resource_launch,
                    baseline: self.baseline.take(),
                    original_observers: super::original_observers::OriginalObserverRegistryV1::new(),
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
    fn selected_decode_refusal_keeps_the_first_serde_cause_across_reentry() {
        fn decode(
            storage: &mut AdmissionStorage,
            bytes: &[u8],
        ) -> Result<(), ControllerProfileAdmissionFailureV1> {
            decode_profile!(retained, storage, bytes, profile);
            let _ = profile;
            Ok(())
        }

        // This empty capture owns no originals and performs no observations.
        let capture = ControllerProfileCaptureV1 {
            profile: None,
            tpm_image: false,
            nix_delivery: None,
            resource_delivery: false,
            resource_launch: false,
        };
        let mut admission = ControllerSelectedProfileAdmissionV1::new(capture);
        admission.armed = false;
        let bytes = format!("{{\"format\":\"{}\"}}", "x".repeat(1025));

        let failure = decode(&mut admission.storage, bytes.as_bytes()).unwrap_err();
        assert_eq!(failure.stage(), "profile-decode");
        assert!(admission.storage.profile.is_none());
        let original = admission.storage.profile_decode.failure().unwrap()
            .downcast_ref::<serde_json::Error>().unwrap() as *const serde_json::Error;
        assert!(admission.storage.profile_decode.take_completed().is_none());

        assert!(decode(&mut admission.storage, b"{}").is_err());
        let retained = admission.storage.profile_decode.failure().unwrap()
            .downcast_ref::<serde_json::Error>().unwrap() as *const serde_json::Error;
        assert!(std::ptr::eq(original, retained));
        assert!(admission.storage.profile.is_none());
    }

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
