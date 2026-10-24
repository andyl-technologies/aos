//! Retains the actual first Controller descriptor table and its fixed routing.
//!
//! This is the sole constructor of the opaque image/enrollment delivery and
//! profile capture. Auxiliary entries remain descriptor DATA for their upper
//! consumers. No caller descriptor, pathname or decoded packet constructs either
//! protected original. Failed table/routing/duplicate prefixes remain resident.

use std::os::fd::OwnedFd;

use aos_sandbox_linux::inherited_fd::{
    ControllerInitialActivationTableV1, ControllerResourceInitialActivationTableV1,
    duplicate_initial_activation_table,
};

use super::profile::{ControllerProfileCaptureV1, ControllerProfileErrorV1};

const PROFILE_NAME: &str = "aos-normal-root-client-profile";
const PUBLISHER_NAME: &str = "aos-sandboxd-publisher";
const TPM_IMAGE_NAME: &str = "aos-method46-pid1-image";
const GIT_SOURCE_LISTENER_NAME: &str = "aos-git-source-cut";
const RESOURCE_POLICY_NAME: &str = "aos-resource-image-policy-v1";
const RESOURCE_ENROLLMENT_NAME: &str = "aos-resource-pid1-enrollment-v1";
const RESOURCE_LAUNCH_NAME: &str = "aos-resource-controller-successor-v1";
const CONTROLLER_PROFILE_NAME: &str = "aos-nix-controller-profile";
const CONTROLLER_PID1_NAME: &str = "aos-nix-controller-pid1-image";

/// Retains the original resource pair from the one fixed table router.
///
/// These files alone grant no bank enrollment or role authority. The same
/// Controller receiving owner must join them with its full measured profile.
pub struct ControllerEnrollmentDeliveryV1 {
    pub(in crate::controller_receiving) policy: std::fs::File,
    pub(in crate::controller_receiving) enrollment: std::fs::File,
    pub(in crate::controller_receiving) process: u32,
    launch: Option<OwnedFd>,
}

impl ControllerEnrollmentDeliveryV1 {
    fn from_original_table(policy: OwnedFd, enrollment: OwnedFd, launch: Option<OwnedFd>) -> Self {
        Self {
            policy: policy.into(),
            enrollment: enrollment.into(),
            process: std::process::id(),
            launch,
        }
    }

    /// Moves the original optional successor channel to its existing owner.
    ///
    /// This move supplies custody DATA, not launch or recipient authority.
    pub fn take_launch_once(&mut self) -> Option<OwnedFd> {
        self.launch.take()
    }
}

/// Carries the same original auxiliary Nix inputs to their upper owner.
///
/// This type makes no profile, process, image or launch-admission claim.
pub struct ControllerNixDeliveryDataV1 {
    pid1: OwnedFd,
    profile: OwnedFd,
    root_profile: Option<OwnedFd>,
    image_present: bool,
}

impl ControllerNixDeliveryDataV1 {
    fn from_initial_table(pid1: OwnedFd, profile: OwnedFd, root_profile: Option<OwnedFd>, image_present: bool) -> Self {
        Self {
            pid1,
            profile,
            root_profile,
            image_present,
        }
    }

    /// Moves the existing descriptor DATA without another observation.
    pub fn into_parts(self) -> (OwnedFd, OwnedFd, Option<OwnedFd>, bool) {
        (self.pid1, self.profile, self.root_profile, self.image_present)
    }
}

/// Retains the actual first table's original launch-image delivery or absence.
///
/// Construction stays inside the fixed router. Neither a caller descriptor nor
/// a boolean creates this token; its presence and consumed state remain private.
/// The file is custody DATA and alone proves no profile, floor or TPM authority.
///
/// ```compile_fail
/// use aos_sandbox_broker::controller_receiving::ControllerLaunchImageDeliveryOriginalV1;
/// let forged = ControllerLaunchImageDeliveryOriginalV1 {
///     image: None, present: false, consumed: false,
/// };
/// ```
pub struct ControllerLaunchImageDeliveryOriginalV1 {
    image: Option<OwnedFd>,
    present: bool,
    consumed: bool,
}

impl ControllerLaunchImageDeliveryOriginalV1 {
    fn from_initial_table(image: Option<OwnedFd>) -> Self {
        Self { present: image.is_some(), image, consumed: false }
    }

    /// Reports the actual original table's image presence without an observation.
    #[must_use]
    pub fn is_present(&self) -> bool { self.present }

    /// Reports whether its unconsumed slot still contains the actual routed value.
    #[must_use]
    pub fn is_unconsumed(&self) -> bool {
        !self.consumed
            && self.image.is_some() == self.present
    }

    /// Reports whether its original image or genuine absence moved once.
    #[must_use]
    pub fn is_consumed(&self) -> bool { self.consumed }

    /// Moves only the original file, or the same table's genuine absence.
    ///
    /// This performs no IO and cannot construct a launch/profile proof.
    ///
    /// # Errors
    /// Rejects a repeated or contradictory original handoff.
    pub fn take_file_once(&mut self) -> Result<Option<std::fs::File>, ControllerProfileErrorV1> {
        if !self.is_unconsumed() {
            return Err(ControllerProfileErrorV1::Activation);
        }
        self.consumed = true;
        Ok(self.image.take().map(std::fs::File::from))
    }
}

/// Keeps each completed first-table role separate until its existing owner takes it.
pub struct ControllerInitialDeliveryPartsV1 {
    pub(super) profile: ControllerProfileCaptureV1,
    pub(super) nix: Option<ControllerNixDeliveryDataV1>,
    pub(super) git: Option<OwnedFd>,
    pub(super) enrollment: Option<ControllerEnrollmentDeliveryV1>,
    pub(super) publisher: Option<OwnedFd>,
    pub(super) image: Option<OwnedFd>,
    pub(super) auxiliary_taken: bool,
}

impl ControllerInitialDeliveryPartsV1 {
    /// Reports whether this same fixed table supplied the enrollment pair.
    ///
    /// This is routing DATA and cannot admit a selected profile or bank.
    #[must_use]
    pub fn has_original_enrollment_v1(&self) -> bool {
        self.enrollment.is_some()
    }

    /// Moves only an ordinary profile after its auxiliary owners took custody.
    ///
    /// # Errors
    /// Returns the whole unchanged owner if an original enrollment or resource
    /// launch is present, or the auxiliary handoff has not completed. Selected
    /// profile and enrollment inputs cannot be separated through this method.
    pub fn into_ordinary_profile(self) -> Result<ControllerProfileCaptureV1, Self> {
        if self.enrollment.is_some() || !self.auxiliary_taken
            || !self.profile.is_ordinary_delivery_v1()
        {
            return Err(self);
        }
        Ok(self.profile)
    }

    /// Moves only the original optional auxiliary inputs once.
    ///
    /// The opaque profile and enrollment remain paired inside this same owner.
    /// Callers cannot reconstruct or replace that pair from the returned DATA.
    #[must_use]
    pub fn take_auxiliary_parts_once(&mut self) -> Option<(
        Option<ControllerNixDeliveryDataV1>, Option<OwnedFd>,
        Option<OwnedFd>, ControllerLaunchImageDeliveryOriginalV1,
    )> {
        if self.auxiliary_taken {
            return None;
        }
        self.auxiliary_taken = true;
        Some((self.nix.take(), self.git.take(), self.publisher.take(),
            ControllerLaunchImageDeliveryOriginalV1::from_initial_table(self.image.take())))
    }

    /// Moves the complete original roles without reading or duplicating a file.
    pub(in crate::controller_receiving) fn into_parts(self) -> (
        ControllerProfileCaptureV1, Option<ControllerNixDeliveryDataV1>, Option<OwnedFd>,
        Option<ControllerEnrollmentDeliveryV1>, Option<OwnedFd>, Option<OwnedFd>,
    ) {
        (self.profile, self.nix, self.git, self.enrollment, self.publisher, self.image)
    }
}

/// Captures the same ordinary first table with its immediate legacy disposition.
///
/// This retains the established ordinary error mapping and local drop order.
/// It shares the actual Linux duplication primitive and fixed-name predicate
/// with the retained router; only complete original parts can leave this call.
///
/// # Errors
/// Rejects the same foreign, extra, unpaired or unavailable initial entries.
pub fn capture_ordinary(
    publisher: bool,
    nix_enabled: bool,
    git_source_cut: bool,
) -> Result<ControllerInitialDeliveryPartsV1, ControllerProfileErrorV1> {
    let names = controller_names(publisher, nix_enabled, git_source_cut)?;
    let descriptors = duplicate_initial_activation_table(names.len())
        .map_err(|_| ControllerProfileErrorV1::Activation)?;
    let mut profile = None;
    let mut publisher = None;
    let mut image = None;
    let mut nix_profile = None;
    let mut nix_pid1 = None;
    let mut git_source_listener = None;
    let mut resource_policy = None;
    let mut resource_enrollment = None;
    let mut resource_launch = None;
    for (name, descriptor) in names.iter().zip(descriptors) {
        match controller_role(name) {
            Some(ControllerRole::Profile) => profile = Some(descriptor),
            Some(ControllerRole::Publisher) => publisher = Some(descriptor),
            Some(ControllerRole::Image) => image = Some(descriptor),
            Some(ControllerRole::NixProfile) => nix_profile = Some(descriptor),
            Some(ControllerRole::NixPid1) => nix_pid1 = Some(descriptor),
            Some(ControllerRole::Git) => git_source_listener = Some(descriptor),
            Some(ControllerRole::ResourcePolicy) => resource_policy = Some(descriptor),
            Some(ControllerRole::ResourceEnrollment) => resource_enrollment = Some(descriptor),
            Some(ControllerRole::ResourceLaunch) => resource_launch = Some(descriptor),
            None => return Err(ControllerProfileErrorV1::Activation),
        }
    }
    let nix_delivery = nix_profile.as_ref().map(rustix::io::dup).transpose()
        .map_err(|_| ControllerProfileErrorV1::Activation)?;
    let nix = match (nix_pid1, nix_profile) {
        (Some(pid1), Some(nix_profile)) => {
            let root_profile = profile.as_ref().map(rustix::io::dup).transpose()
                .map_err(|_| ControllerProfileErrorV1::Activation)?;
            Some(ControllerNixDeliveryDataV1::from_initial_table(
                pid1,
                nix_profile,
                root_profile,
                image.is_some(),
            ))
        }
        (None, None) => None,
        _ => return Err(ControllerProfileErrorV1::Activation),
    };

    let launch_present = resource_launch.is_some();
    let resource_enrollment = match (resource_policy, resource_enrollment) {
        (Some(policy), Some(enrollment)) => Some(
            ControllerEnrollmentDeliveryV1::from_original_table(policy, enrollment, resource_launch),
        ),
        (None, None) => None,
        _ => return Err(ControllerProfileErrorV1::Activation),
    };
    let resource_delivery = resource_enrollment.is_some();
    Ok(ControllerInitialDeliveryPartsV1 {
        profile: ControllerProfileCaptureV1::from_initial_delivery(
            profile, image.is_some(), nix_delivery, resource_delivery, launch_present,
        ),
        nix,
        git: git_source_listener,
        enrollment: resource_enrollment,
        publisher,
        image,
        auxiliary_taken: false,
    })
}

/// Borrows the same resident first failure without cloning its native cause.
pub enum ControllerInitialDeliveryFailureRefV1<'capture> {
    /// The same existing names or slot refusal is retained by Core.
    Startup(&'capture ControllerProfileErrorV1),
    /// The original Linux table owner retains this actual kernel cause.
    Table(&'capture aos_linux_descriptors::Error),
    /// Core retains the actual optional duplication refusal.
    Duplicate(&'capture rustix::io::Errno),
    /// The attempt is permanently closed without another observation.
    Closed,
}

impl std::fmt::Debug for ControllerInitialDeliveryFailureRefV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Startup(_) => "Controller capture names/slots refused",
            Self::Table(_) => "Controller original table refused",
            Self::Duplicate(_) => "Controller optional duplication refused",
            Self::Closed => "Controller capture closed",
        })
    }
}

enum InitialCaptureFailure {
    Startup(ControllerProfileErrorV1),
    Table,
    Duplicate(rustix::io::Errno),
    Closed,
}

/// Retains every returned original until the complete Core tuple moves once.
///
/// Raw prefixes, routed roles and optional duplicates stay resident on refusal.
/// Armed Drop and unwind abort before those fields release. Process death is
/// not drain or completed Source-flight evidence. Upper startup retains this
/// owner through its actual selected handoff.
#[must_use]
pub struct ControllerInitialDeliveryCaptureV1 {
    publisher_enabled: bool,
    nix_enabled: bool,
    git_enabled: bool,
    names: Vec<String>,
    table: Option<ControllerCaptureTable>,
    raw: [Option<OwnedFd>; 9],
    unrouted: Option<OwnedFd>,
    profile: Option<OwnedFd>,
    publisher: Option<OwnedFd>,
    image: Option<OwnedFd>,
    nix_profile: Option<OwnedFd>,
    nix_pid1: Option<OwnedFd>,
    nix_delivery: Option<OwnedFd>,
    root_duplicate: Option<OwnedFd>,
    nix: Option<ControllerNixDeliveryDataV1>,
    git: Option<OwnedFd>,
    resource_policy: Option<OwnedFd>,
    resource_enrollment: Option<OwnedFd>,
    resource_launch: Option<OwnedFd>,
    completed: Option<ControllerInitialDeliveryPartsV1>,
    attempted: bool,
    failure: Option<InitialCaptureFailure>,
    armed: bool,
}

impl ControllerInitialDeliveryCaptureV1 {
    pub fn new(publisher: bool, nix_enabled: bool, git_source_cut: bool) -> Self {
        Self {
            publisher_enabled: publisher,
            nix_enabled,
            git_enabled: git_source_cut,
            names: Vec::new(),
            table: None,
            raw: [None, None, None, None, None, None, None, None, None],
            unrouted: None,
            profile: None,
            publisher: None,
            image: None,
            nix_profile: None,
            nix_pid1: None,
            nix_delivery: None,
            root_duplicate: None,
            nix: None,
            git: None,
            resource_policy: None,
            resource_enrollment: None,
            resource_launch: None,
            completed: None,
            attempted: false,
            failure: None,
            armed: true,
        }
    }

    /// Captures the actual closed table once, retaining partial success.
    ///
    /// # Errors
    /// Borrows the first names, table, routing or optional-duplicate cause.
    /// A repeat performs no observation and cannot revive completed custody.
    pub fn capture_once(&mut self) -> Result<(), ControllerInitialDeliveryFailureRefV1<'_>> {
        if self.attempted {
            self.failure.get_or_insert(InitialCaptureFailure::Closed);
        } else {
            self.attempted = true;
            let result = {
                let _unwind = AbortControllerCaptureUnwind;
                self.capture_body()
            };
            match result {
                Ok(()) => return Ok(()),
                Err(cause) => {
                    self.failure.get_or_insert(cause);
                }
            }
        }
        Err(self.failure_view())
    }

    /// Borrows a short view over the same resident first cause.
    pub fn first_failure(&self) -> Option<ControllerInitialDeliveryFailureRefV1<'_>> {
        self.failure.as_ref().map(|_| self.failure_view())
    }

    /// Moves the same completed startup tuple without a fallible continuation.
    ///
    /// The caller parks it before profile or launch checks. A failed attempt
    /// exposes none of its partial roles and remains armed.
    #[must_use]
    pub fn take_completed_parts(&mut self) -> Option<ControllerInitialDeliveryPartsV1> {
        if self.failure.is_some()
            || self.completed.is_none()
            || self.raw.iter().any(Option::is_some)
            || self.unrouted.is_some()
            || self.profile.is_some()
            || self.publisher.is_some()
            || self.image.is_some()
            || self.nix_profile.is_some()
            || self.nix_pid1.is_some()
            || self.nix_delivery.is_some()
            || self.root_duplicate.is_some()
            || self.nix.is_some()
            || self.git.is_some()
            || self.resource_policy.is_some()
            || self.resource_enrollment.is_some()
            || self.resource_launch.is_some()
        {
            return None;
        }
        let completed = self.completed.take();
        self.armed = false;
        completed
    }

    fn failure_view(&self) -> ControllerInitialDeliveryFailureRefV1<'_> {
        match &self.failure {
            Some(InitialCaptureFailure::Startup(cause)) => {
                ControllerInitialDeliveryFailureRefV1::Startup(cause)
            }
            Some(InitialCaptureFailure::Duplicate(cause)) => {
                ControllerInitialDeliveryFailureRefV1::Duplicate(cause)
            }
            Some(InitialCaptureFailure::Table) => match self
                .table
                .as_ref()
                .and_then(ControllerCaptureTable::failure)
            {
                Some(cause) => ControllerInitialDeliveryFailureRefV1::Table(cause),
                None => ControllerInitialDeliveryFailureRefV1::Closed,
            },
            Some(InitialCaptureFailure::Closed) | None => {
                ControllerInitialDeliveryFailureRefV1::Closed
            }
        }
    }

    fn capture_body(&mut self) -> Result<(), InitialCaptureFailure> {
        self.names = controller_names(self.publisher_enabled, self.nix_enabled, self.git_enabled)
            .map_err(InitialCaptureFailure::Startup)?;
        if self.table.is_some() {
            return Err(InitialCaptureFailure::Closed);
        }

        // The permanent outer attempt latch precedes this one-time closed
        // choice. An unused armed ordinary table is never constructed/dropped.
        let resource_delivery = self.names.iter().any(|name| name == RESOURCE_POLICY_NAME);
        self.table = Some(if resource_delivery {
            ControllerCaptureTable::Resource(ControllerResourceInitialActivationTableV1::new())
        } else {
            ControllerCaptureTable::Ordinary(ControllerInitialActivationTableV1::new())
        });
        let table = self.table.as_mut().ok_or(InitialCaptureFailure::Closed)?;
        if table.observe_once(self.names.len()).is_err() {
            return Err(InitialCaptureFailure::Table);
        }
        if self.raw.iter().any(Option::is_some) || self.unrouted.is_some() {
            return Err(InitialCaptureFailure::Closed);
        }
        let Some(raw) = table.take_completed_entries() else {
            return Err(InitialCaptureFailure::Closed);
        };
        self.raw = raw;

        for (name, entry) in self.names.iter().zip(&mut self.raw) {
            let target = match controller_role(name) {
                Some(ControllerRole::Profile) => &mut self.profile,
                Some(ControllerRole::Publisher) => &mut self.publisher,
                Some(ControllerRole::Image) => &mut self.image,
                Some(ControllerRole::NixProfile) => &mut self.nix_profile,
                Some(ControllerRole::NixPid1) => &mut self.nix_pid1,
                Some(ControllerRole::Git) => &mut self.git,
                Some(ControllerRole::ResourcePolicy) => &mut self.resource_policy,
                Some(ControllerRole::ResourceEnrollment) => &mut self.resource_enrollment,
                Some(ControllerRole::ResourceLaunch) => &mut self.resource_launch,
                None => return Err(InitialCaptureFailure::Startup(ControllerProfileErrorV1::Activation)),
            };
            if target.is_some() || entry.is_none() || self.unrouted.is_some() {
                return Err(InitialCaptureFailure::Startup(ControllerProfileErrorV1::Activation));
            }
            self.unrouted = entry.take();
            *target = self.unrouted.take();
        }

        self.nix_delivery = self.nix_profile.as_ref().map(rustix::io::dup).transpose()
            .map_err(InitialCaptureFailure::Duplicate)?;
        if self.nix_pid1.is_some() != self.nix_profile.is_some() {
            return Err(InitialCaptureFailure::Startup(ControllerProfileErrorV1::Activation));
        }
        if self.nix_pid1.is_some() {
            self.root_duplicate = self.profile.as_ref().map(rustix::io::dup).transpose()
                .map_err(InitialCaptureFailure::Duplicate)?;
            if self.nix.is_some() || self.nix_delivery.is_none()
                || self.root_duplicate.is_some() != self.profile.is_some()
            {
                return Err(InitialCaptureFailure::Closed);
            }
            let image_present = self.image.is_some();
            let originals = (
                self.nix_pid1.take(), self.nix_profile.take(), self.root_duplicate.take(),
            );
            match originals {
                (Some(pid1), Some(profile), root_profile) => {
                    self.nix = Some(ControllerNixDeliveryDataV1::from_initial_table(
                        pid1, profile, root_profile, image_present,
                    ));
                }
                (pid1, profile, root_profile) => {
                    self.nix_pid1 = pid1;
                    self.nix_profile = profile;
                    self.root_duplicate = root_profile;
                    return Err(InitialCaptureFailure::Closed);
                }
            }
        }

        if self.raw.iter().any(Option::is_some)
            || self.unrouted.is_some()
            || self.completed.is_some()
            || self.root_duplicate.is_some()
            || self.nix_pid1.is_some()
            || self.nix_profile.is_some()
            || self.publisher.is_some() != self.publisher_enabled
            || self.nix.is_some() != self.nix_enabled
            || self.git.is_some() != self.git_enabled
            || self.nix_delivery.is_some() != self.nix_enabled
            || self.profile.is_some() != self.names.iter().any(|name| name == PROFILE_NAME)
            || self.image.is_some() != self.names.iter().any(|name| name == TPM_IMAGE_NAME)
        {
            return Err(InitialCaptureFailure::Closed);
        }
        let image_present = self.image.is_some();
        let resource_delivery = self.resource_policy.is_some();
        let launch_present = self.resource_launch.is_some();
        let resource_originals = (self.resource_policy.take(), self.resource_enrollment.take());
        let resource_enrollment = match resource_originals {
            (Some(policy), Some(enrollment)) => Some(
                ControllerEnrollmentDeliveryV1::from_original_table(policy, enrollment, self.resource_launch.take()),
            ),
            (None, None) => None,
            (policy, enrollment) => {
                self.resource_policy = policy;
                self.resource_enrollment = enrollment;
                return Err(InitialCaptureFailure::Closed);
            }
        };
        self.completed = Some(ControllerInitialDeliveryPartsV1 {
            profile: ControllerProfileCaptureV1::from_initial_delivery(
                self.profile.take(), image_present, self.nix_delivery.take(),
                resource_delivery, launch_present,
            ),
            nix: self.nix.take(),
            git: self.git.take(),
            enrollment: resource_enrollment,
            publisher: self.publisher.take(),
            image: self.image.take(),
            auxiliary_taken: false,
        });
        Ok(())
    }
}

impl Drop for ControllerInitialDeliveryCaptureV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

struct AbortControllerCaptureUnwind;

impl Drop for AbortControllerCaptureUnwind {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

// Both closed modes retain their own original Linux error and complete table.
// The shared Core routing reservoir receives all nine slots before any later
// fallible action; the ordinary six-slot transfer leaves three empty tail slots.
enum ControllerCaptureTable {
    Ordinary(ControllerInitialActivationTableV1),
    Resource(ControllerResourceInitialActivationTableV1),
}

impl ControllerCaptureTable {
    fn observe_once(&mut self, count: usize) -> Result<(), &aos_linux_descriptors::Error> {
        match self {
            Self::Ordinary(table) => table.observe_once(count),
            Self::Resource(table) => table.observe_once(count),
        }
    }

    fn failure(&self) -> Option<&aos_linux_descriptors::Error> {
        match self {
            Self::Ordinary(table) => table.failure(),
            Self::Resource(table) => table.failure(),
        }
    }

    fn take_completed_entries(&mut self) -> Option<[Option<OwnedFd>; 9]> {
        match self {
            Self::Ordinary(table) => {
                let original = table.take_completed_entries()?;
                let mut entries = [const { None }; 9];
                for (destination, descriptor) in entries.iter_mut().zip(original) {
                    *destination = descriptor;
                }

                Some(entries)
            }
            Self::Resource(table) => table.take_completed_entries(),
        }
    }
}

enum ControllerRole {
    Profile,
    Publisher,
    Image,
    NixProfile,
    NixPid1,
    Git,
    ResourcePolicy,
    ResourceEnrollment,
    ResourceLaunch,
}

fn controller_role(name: &str) -> Option<ControllerRole> {
    match name {
        PROFILE_NAME => Some(ControllerRole::Profile),
        PUBLISHER_NAME => Some(ControllerRole::Publisher),
        TPM_IMAGE_NAME => Some(ControllerRole::Image),
        CONTROLLER_PROFILE_NAME => Some(ControllerRole::NixProfile),
        CONTROLLER_PID1_NAME => Some(ControllerRole::NixPid1),
        GIT_SOURCE_LISTENER_NAME => Some(ControllerRole::Git),
        RESOURCE_POLICY_NAME => Some(ControllerRole::ResourcePolicy),
        RESOURCE_ENROLLMENT_NAME => Some(ControllerRole::ResourceEnrollment),
        RESOURCE_LAUNCH_NAME => Some(ControllerRole::ResourceLaunch),
        _ => None,
    }
}

fn controller_names(
    publisher: bool,
    nix_enabled: bool,
    git_source_cut: bool,
) -> Result<Vec<String>, ControllerProfileErrorV1> {
    let names = crate::receiving::original_activation_names_v1(9)
        .map_err(|_| ControllerProfileErrorV1::Activation)?;
    if !crate::profile_data::delivery::valid_backend_names(
        &names,
        publisher,
        nix_enabled,
        git_source_cut,
    ) {
        return Err(ControllerProfileErrorV1::Activation);
    }
    Ok(names)
}



#[cfg(test)]
mod launch_image_delivery_tests {
    use super::*;
    use std::os::fd::AsRawFd as _;

    // These exercise native DATA movement only. They create no actual startup
    // table, admitted profile, launch-image proof or financial authority.
    #[test]
    fn original_file_moves_once_without_duplication() {
        let file = tempfile::tempfile().unwrap();
        let original_descriptor = file.as_raw_fd();
        let mut delivery = ControllerLaunchImageDeliveryOriginalV1::from_initial_table(Some(file.into()));

        let held = delivery.take_file_once().unwrap().unwrap();

        assert_eq!(held.as_raw_fd(), original_descriptor);
        assert!(delivery.is_present());
        assert!(delivery.is_consumed());
        assert!(!delivery.is_unconsumed());
        assert!(delivery.take_file_once().is_err());
    }

    #[test]
    fn routed_absence_remains_absence_after_its_single_handoff() {
        let mut delivery = ControllerLaunchImageDeliveryOriginalV1::from_initial_table(None);

        let held = delivery.take_file_once().unwrap();

        assert!(held.is_none());
        assert!(!delivery.is_present());
        assert!(delivery.is_consumed());
        assert!(delivery.take_file_once().is_err());
    }
}
