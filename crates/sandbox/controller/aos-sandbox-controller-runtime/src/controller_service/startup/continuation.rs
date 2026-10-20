//! Owns the installed Controller's actual capture, Bank and startup continuation.
//!
//! Broker retains the same paired first-table transport. Security admits only
//! its opaque image original and genuine profile-binding token. Runtime owns
//! actual Nix, profile and Bank coordination plus every failed upper prefix.
//! No supplied FD, absent-value claim or callback constructs an admitted image.

use std::os::fd::OwnedFd;
use std::sync::Arc;

use aos_sandbox_controller_domain::normal_root::{
    ControllerInitialCaptureFailureRefV1, ProductionControllerInitialCaptureAttemptV1,
    ProductionControllerNormalRootCaptureV1, ProductionControllerNormalRootProfileV1,
    ProductionControllerNormalRootStartupPartsV1, ControllerSharedStartupProfileV1,
};
use aos_sandbox_broker_session_security::BrokerSessionSecurityError;
use aos_sandbox_broker_session_security::controller_composition::{
    ControllerLaunchImageCaptureV1, ControllerLaunchImageBindingErrorV1,
    ControllerLaunchImageCaptureFailureV1, Pid1LaunchImageV1,
};

pub(crate) struct CapturedControllerStartupV1 {
    pub(crate) publisher_descriptor: Option<OwnedFd>,
    pub(crate) launch_image: Option<Pid1LaunchImageV1>,
    pub(crate) normal_root_capture: aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootCaptureV1,
    pub(crate) nix_capture: Option<aos_sandbox_controller_domain::normal_root::ProductionControllerNixStartupCaptureV1>,
    pub(crate) git_source_listener: Option<OwnedFd>,
}


/// Borrows a cause from the same nested retained startup owner.
///
/// The view is short and by value; Security stores no self-borrow or cloned
/// Core cause. It grants no launch, selected-profile or floor authority.
pub(crate) enum ControllerStartupFailureRefV1<'attempt> {
    Core(ControllerInitialCaptureFailureRefV1<'attempt>),
    Launch(&'attempt BrokerSessionSecurityError),
    Closed,
}

impl std::fmt::Debug for ControllerStartupFailureRefV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Core(_) => "original Controller capture refused",
            Self::Launch(_) => "original Controller launch delivery refused",
            Self::Closed => "original Controller startup closed",
        })
    }
}

enum StartupCaptureFailure {
    Core,
    Launch(BrokerSessionSecurityError),
    Closed,
}

/// Keeps actual startup originals resident across launch-presence admission.
///
/// The empty image destination is allocated before initial capture, never
/// after an original has left its slot. Installed Controller startup uses this
/// same capture; unrelated consuming startup paths remain unchanged.
/// Failed/abandoned or unwinding attempts abort before field release; OS death
/// is not drain or Source-flight settlement. Lower unreturned custody remains
/// a separate functional prerequisite.
#[must_use]
pub(crate) struct ControllerStartupCaptureAttemptV1 {
    image_receiver: ControllerLaunchImageCaptureV1,
    core: ProductionControllerInitialCaptureAttemptV1,
    parts: Option<ProductionControllerNormalRootStartupPartsV1>,
    git: Option<OwnedFd>,
    completed: Option<CapturedControllerStartupV1>,
    attempted: bool,
    failure: Option<StartupCaptureFailure>,
    armed: bool,
}

impl ControllerStartupCaptureAttemptV1 {
    pub(crate) fn new(publisher: bool, nix_enabled: bool, git_source_cut: bool) -> Self {
        // This is the sole retained-only allocation. It precedes any table IO
        // and contains no File, fabricated image or authorization claim.
        let image_receiver = ControllerLaunchImageCaptureV1::new();
        Self {
            image_receiver,
            core: ProductionControllerNormalRootCaptureV1::begin_retained_capture(
                publisher, nix_enabled, git_source_cut,
            ),
            parts: None,
            git: None,
            completed: None,
            attempted: false,
            failure: None,
            armed: true,
        }
    }

    /// Captures and checks the same originals once, before any journal opens.
    ///
    /// # Errors
    /// Borrows the actual nested Core or launch cause without releasing partial
    /// originals. Repeats are closed and perform no observations.
    pub(crate) fn capture_once(&mut self) -> Result<(), ControllerStartupFailureRefV1<'_>> {
        if self.attempted {
            self.failure.get_or_insert(StartupCaptureFailure::Closed);
        } else {
            self.attempted = true;
            let result = {
                let _unwind = AbortStartupCaptureUnwind;
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

    pub(crate) fn first_failure(&self) -> Option<ControllerStartupFailureRefV1<'_>> {
        self.failure.as_ref().map(|_| self.failure_view())
    }

    // The installed retained path keeps Nix nested with its producer-associated
    // delivery duplicate until FIRST6 finishes the same capture.
    fn take_completed_profile_startup(&mut self) -> Option<CapturedControllerStartupV1> {
        if self.failure.is_some()
            || self.completed.is_none()
            || self.parts.is_some()
            || self.git.is_some()
        {
            return None;
        }
        let completed = self.completed.take();
        self.armed = false;
        completed
    }

    fn failure_view(&self) -> ControllerStartupFailureRefV1<'_> {
        match &self.failure {
            Some(StartupCaptureFailure::Core) => match self.core.first_failure() {
                Some(cause) => ControllerStartupFailureRefV1::Core(cause),
                None => ControllerStartupFailureRefV1::Closed,
            },
            Some(StartupCaptureFailure::Launch(cause)) => {
                ControllerStartupFailureRefV1::Launch(cause)
            }
            Some(StartupCaptureFailure::Closed) | None => ControllerStartupFailureRefV1::Closed,
        }
    }

    fn capture_body(&mut self) -> Result<(), StartupCaptureFailure> {
        if self.parts.is_some() || self.git.is_some()
            || self.completed.is_some()
        {
            return Err(StartupCaptureFailure::Closed);
        }
        if self.core.capture_once().is_err() {
            return Err(StartupCaptureFailure::Core);
        }
        let Some(parts) = self.core.take_completed_parts() else {
            return Err(StartupCaptureFailure::Closed);
        };
        self.parts = Some(parts);
        let parts = self.parts.as_mut().ok_or(StartupCaptureFailure::Closed)?;
        self.git = parts.0.take_git_source_listener();

        let launch_image = self.image_receiver.capture_delivery_once(&mut parts.2)
            .map_err(|cause| match cause {
                ControllerLaunchImageCaptureFailureV1::Launch(cause) => StartupCaptureFailure::Launch(cause),
                ControllerLaunchImageCaptureFailureV1::Closed => StartupCaptureFailure::Closed,
            })?;

        // The image is already resident in the shared original destination.
        // No observation/allocation follows any startup tuple removal.
        if self.completed.is_some()
            || self.parts.as_ref().is_none_or(|parts| !parts.2.is_consumed())
        {
            return Err(StartupCaptureFailure::Closed);
        }
        let originals = self.parts.take();
        match originals {
            Some((normal_root_capture, publisher_descriptor, delivery)) if delivery.is_consumed() => {
                self.completed = Some(CapturedControllerStartupV1 {
                    publisher_descriptor,
                    launch_image,
                    normal_root_capture,
                    nix_capture: None,
                    git_source_listener: self.git.take(),
                });
                Ok(())
            }
            parts => {
                self.parts = parts;
                // The shared original image never left image_receiver.
                Err(StartupCaptureFailure::Closed)
            }
        }
    }
}

impl Drop for ControllerStartupCaptureAttemptV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

struct AbortStartupCaptureUnwind;

impl Drop for AbortStartupCaptureUnwind {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

// This continuation is local (!Sync through FIRST6). Only successful existing
// Arc owners are shared with runtime. Publisher/lower/Arc-allocation custody
// exclusions are deliberate; no whole-role/drain guarantee is implied.
/// Retains the original Controller capture, admission, and startup failure destinations.
pub(crate) struct ControllerStartupContinuationV1 {
    capture: ControllerStartupCaptureAttemptV1,
    returned: Option<CapturedControllerStartupV1>,
    root: Option<aos_sandbox_controller_domain::normal_root::ProductionControllerSelectedProfileAdmissionV1>,
    profile: Option<ControllerSharedStartupProfileV1>,
    nix: Option<aos_sandbox_controller_domain::normal_root::ProductionControllerNixStartupCaptureV1>,
    selector_attempt: Option<aos_sandbox_controller_domain::production_operation_compiler::ControllerNixSelectorAdmissionV2>,
    selector: Option<Arc<aos_sandbox_controller_domain::production_operation_compiler::ControllerNixStartRecipeSelectorV2>>,
    image: Option<Pid1LaunchImageV1>,
    publisher: Option<OwnedFd>,
    git: Option<OwnedFd>,
    resource_opening: Option<aos_sandbox_controller_domain::ControllerResourceBankOpeningV1>,
    resource_failure: Option<aos_sandbox_broker::controller_receiving::ControllerBankOpeningFailureV1>,
    issue: bool,
    root_completed: bool,
    first_failure: Option<ControllerContinuationFailure>,
    armed: bool,
}

enum ControllerContinuationFailure {
    Capture,
    Root,
    Selector,
    Binding(ControllerLaunchImageBindingErrorV1),
    Delivery(aos_sandbox_controller_domain::normal_root::SourceSuccessorCredentialErrorV2),
    RuntimeRefused,
    Closed,
}

// Short views resolve markers against the same resident nested owners. No
// borrow is stored in the continuation and no actual cause is copied.
enum ControllerContinuationFailureRef<'attempt> {
    Capture(ControllerStartupFailureRefV1<'attempt>),
    Root(&'attempt (dyn std::error::Error + 'static)),
    Selector(aos_sandbox_controller_domain::production_operation_compiler::ControllerNixSelectorFailureRefV2<'attempt>),
    Binding(&'attempt ControllerLaunchImageBindingErrorV1),
    Delivery(&'attempt aos_sandbox_controller_domain::normal_root::SourceSuccessorCredentialErrorV2),
    RuntimeRefused,
    Closed,
}

impl std::fmt::Debug for ControllerContinuationFailureRef<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Capture(_) => "original capture refused",
            Self::Root(_) => "original Root profile refused",
            Self::Selector(_) => "original Nix selector refused",
            Self::Binding(_) => "original launch binding refused",
            Self::Delivery(_) => "issue-only delivery refused",
            Self::RuntimeRefused => "resident runtime continuation refused",
            Self::Closed => "original continuation closed",
        })
    }
}

impl ControllerStartupContinuationV1 {
    /// Creates only the original empty startup capture destinations.
    pub(crate) fn new(publisher: bool, nix: bool, issue: bool) -> Self {
        Self {
            capture: ControllerStartupCaptureAttemptV1::new(publisher, nix, false),
            returned: None,
            root: None,
            profile: None,
            nix: None,
            selector_attempt: None,
            selector: None,
            image: None,
            publisher: None,
            git: None,
            resource_opening: None,
            resource_failure: None,
            issue,
            root_completed: false,
            first_failure: None,
            armed: true,
        }
    }

    /// Captures the original installed Controller startup once.
    pub(crate) fn capture_once(&mut self) -> bool {
        if self.first_failure.is_some() || self.returned.is_some() || self.root.is_some() {
            self.first_failure.get_or_insert(ControllerContinuationFailure::Closed);
            return false;
        }
        if self.capture.capture_once().is_err() {
            self.first_failure = Some(ControllerContinuationFailure::Capture);
            return false;
        }
        let Some(returned) = self.capture.take_completed_profile_startup() else {
            self.first_failure = Some(ControllerContinuationFailure::Closed);
            return false;
        };
        self.returned = Some(returned);
        true
    }

    /// Admits only the original captured Controller root.
    pub(crate) fn admit_root_once(&mut self, uid: u32, gid: u32) -> bool {
        if self.first_failure.is_some()
            || self.root_completed
            || self.root.is_some()
            || self.profile.is_some()
            || self.nix.is_some()
            || self.image.is_some()
            || self.publisher.is_some()
            || self.git.is_some()
            || self.resource_opening.is_some()
            || self.resource_failure.is_some()
            || self.returned.as_ref().is_none_or(|startup| startup.nix_capture.is_some())
        {
            self.first_failure.get_or_insert(ControllerContinuationFailure::Closed);
            return false;
        }
        let Some(returned) = self.returned.take() else {
            self.first_failure = Some(ControllerContinuationFailure::Closed);
            return false;
        };
        let CapturedControllerStartupV1 {
            publisher_descriptor,
            launch_image,
            mut normal_root_capture,
            nix_capture: _,
            git_source_listener,
        } = returned;
        self.publisher = publisher_descriptor;
        self.image = launch_image;
        self.git = git_source_listener;
        let profile = if normal_root_capture.has_original_enrollment_v1() {
            // All auxiliary originals are already resident on this actual
            // continuation before the paired profile/enrollment move.
            self.nix = normal_root_capture.take_nix_startup();
            let Some(startup) = normal_root_capture.take_selected_startup_once_v1() else {
                self.returned = Some(CapturedControllerStartupV1 {
                    publisher_descriptor: None,
                    launch_image: None,
                    normal_root_capture,
                    nix_capture: None,
                    git_source_listener: None,
                });
                self.first_failure = Some(ControllerContinuationFailure::Closed);
                return false;
            };
            match aos_sandbox_controller_domain::ControllerResourceBankOpeningV1::begin_selected_startup(startup) {
                Ok(opening) => self.resource_opening = Some(opening),
                Err(failure) => {
                    self.resource_failure = Some(failure);
                    self.first_failure = Some(ControllerContinuationFailure::Root);
                    return false;
                }
            }
            let Some(opening) = self.resource_opening.as_mut() else {
                self.first_failure = Some(ControllerContinuationFailure::Closed);
                return false;
            };
            if !opening.admit_selected_profile_once(uid, gid) {
                self.first_failure = Some(ControllerContinuationFailure::Root);
                return false;
            }
            let Some(profile) = opening.take_admitted_profile_binding_once() else {
                self.first_failure = Some(ControllerContinuationFailure::Closed);
                return false;
            };
            profile
        } else {
            self.root = normal_root_capture.begin_retained_ordinary_admission_once_v1();
            let Some(root) = self.root.as_mut() else {
                self.returned = Some(CapturedControllerStartupV1 {
                    publisher_descriptor: None,
                    launch_image: None,
                    normal_root_capture,
                    nix_capture: None,
                    git_source_listener: None,
                });
                self.first_failure = Some(ControllerContinuationFailure::Closed);
                return false;
            };
            let selected = match root.admit_selected_once(uid, gid) {
                Ok(profile) => profile.is_some(),
                Err(_) => {
                    self.first_failure = Some(ControllerContinuationFailure::Root);
                    return false;
                }
            };
            if self.issue && !selected {
                self.first_failure = Some(ControllerContinuationFailure::Closed);
                return false;
            }
            match root.take_admitted_binding_once() {
                Ok((profile, nix)) => { self.nix = nix; profile }
                Err(_) => {
                    self.first_failure = Some(ControllerContinuationFailure::Root);
                    return false;
                }
            }
        };
        // Existing successful Arc sharing is a FUNDING exclusion, not a
        // recoverable allocation boundary or universal unwind guarantee.
        self.profile = Some(profile.into_shared());
        self.root_completed = true;
        if !self.issue
            && self.profile().is_none()
            && self.nix.is_none()
            && self.image.is_none()
            && self.publisher.is_none()
            && self.git.is_none()
            && self.resource_opening.is_none()
        {
            // FIRST6 settled only its real early, empty nonpositive absence.
            self.armed = false;
        }
        true
    }

    /// Checks the original source-delivery absence without manufacturing it.
    pub(crate) fn require_source_delivery_absent(&mut self) -> bool {
        if self.first_failure.is_some() || !self.root_completed {
            self.first_failure.get_or_insert(ControllerContinuationFailure::Closed);
            return false;
        }
        match aos_sandbox_controller_domain::normal_root::require_source_successor_delivery_absent_v2(
            self.profile(),
        ) {
            Ok(()) => true,
            Err(cause) => {
                self.first_failure.get_or_insert(ControllerContinuationFailure::Delivery(cause));
                false
            }
        }
    }

    /// Binds the original captured launch image in its existing destination.
    pub(crate) fn bind_launch_in_place(&mut self) -> bool {
        if self.first_failure.is_some() || !self.root_completed {
            self.first_failure.get_or_insert(ControllerContinuationFailure::Closed);
            return false;
        }
        if let Some(image) = &mut self.image {
            let Some(profile) = self.profile.as_ref() else {
                self.first_failure = Some(ControllerContinuationFailure::Closed);
                return false;
            };
            if let Err(cause) = image.bind_controller_profile_original_v1(profile.clone()) {
                self.first_failure.get_or_insert(ControllerContinuationFailure::Binding(cause));
                return false;
            }
        }
        true
    }

    /// Admits the original selected Nix startup without replacing its capture.
    pub(crate) fn admit_nix_once(
        &mut self,
        uid: u32,
        gid: u32,
        node: aos_sandbox_model::NodeId,
    ) -> bool {
        if self.first_failure.is_some() || !self.root_completed
            || self.selector_attempt.is_some() || self.selector.is_some()
            || self.nix.is_none()
        {
            self.first_failure.get_or_insert(ControllerContinuationFailure::Closed);
            return false;
        }
        let Some(capture) = self.nix.take() else {
            self.first_failure = Some(ControllerContinuationFailure::Closed);
            return false;
        };
        self.selector_attempt = Some(
            aos_sandbox_controller_domain::production_operation_compiler::ControllerNixStartRecipeSelectorV2::begin_retained_original(
                capture,
                uid,
                gid,
                node,
            ),
        );
        let Some(attempt) = self.selector_attempt.as_mut() else {
            self.first_failure = Some(ControllerContinuationFailure::Closed);
            return false;
        };
        if attempt.admit_once().is_err() {
            self.first_failure = Some(ControllerContinuationFailure::Selector);
            return false;
        }
        let Some(selector) = attempt.take_admitted_selector() else {
            self.first_failure = Some(ControllerContinuationFailure::Closed);
            return false;
        };
        self.selector = Some(Arc::new(selector));
        true
    }

    /// Borrows the original admitted Controller profile.
    pub(crate) fn profile(&self) -> Option<&ProductionControllerNormalRootProfileV1> {
        self.profile.as_ref().and_then(ControllerSharedStartupProfileV1::profile)
    }

    /// Moves the original admitted resource opening into its existing consumer.
    pub(crate) fn take_resource_opening(
        &mut self,
    ) -> Option<aos_sandbox_controller_domain::ControllerResourceBankOpeningV1> {
        self.resource_opening.take()
    }

    /// Shares only the original admitted Controller profile.
    pub(crate) fn profile_share(&self) -> Option<Arc<ProductionControllerNormalRootProfileV1>> {
        self.profile.as_ref().and_then(ControllerSharedStartupProfileV1::profile_share)
    }

    /// Shares only the original retained Nix selector.
    pub(crate) fn selector_share(&self) -> Option<Arc<aos_sandbox_controller_domain::production_operation_compiler::ControllerNixStartRecipeSelectorV2>> {
        self.selector.clone()
    }

    /// Shares only the original captured launch observation.
    pub(crate) fn image_share(&self) -> Option<Pid1LaunchImageV1> {
        self.image.clone()
    }

    // The unchanged consuming publisher lower path remains a functional gap.
    /// Moves the original captured publisher descriptor without admitting a substitute.
    pub(crate) fn take_publisher(&mut self) -> Option<OwnedFd> {
        self.publisher.take()
    }

    /// Settles the original local startup lifetime after its worker handoff.
    pub(crate) fn complete_worker_handoff(&mut self) {
        // Called only after actual successful spawn. Parent Arc shares remain
        // resident through later startup errors; no drain is inferred.
        if self.first_failure.is_some() || !self.root_completed || self.nix.is_some() {
            self.terminate_failed();
        }
        self.armed = false;
    }

    /// Settles the original local startup lifetime after Core's same-flight finish.
    pub(crate) fn complete_issue_finish(&mut self) {
        // Called only after Core's SAME-flight Finish, without another Root
        // predicate. This is local lifetime settlement, never physical drain.
        self.armed = false;
    }

    /// Observes whether the original startup custody must remain resident.
    pub(crate) fn must_retain_failure(&self) -> bool {
        self.armed || self.profile().is_some() || self.selector.is_some() || self.image.is_some()
    }

    /// Refuses runtime continuation without accepting or owning its upper cause.
    ///
    /// The application parks its actual typed failure before this call. Earlier
    /// capture/admission failures keep precedence and all resident custody stays
    /// armed through the unchanged process exit.
    pub(crate) fn terminate_runtime_refusal(&mut self) -> ! {
        self.first_failure.get_or_insert(ControllerContinuationFailure::RuntimeRefused);
        self.terminate_failed()
    }

    /// Terminates with the original startup failure and resident custody.
    pub(crate) fn terminate_failed(&mut self) -> ! {
        // Diagnostic unwinding must not release post-handoff parent custody.
        self.armed = true;

        // Nested causes remain owned in the exact capture/admission attempt.
        self.first_failure.get_or_insert(ControllerContinuationFailure::Closed);
        eprintln!("aos-sandboxd: {:?}", self.failure_view());
        std::process::exit(1)
    }

    fn failure_view(&self) -> ControllerContinuationFailureRef<'_> {
        match &self.first_failure {
            Some(ControllerContinuationFailure::Capture) => self.capture.first_failure()
                .map(ControllerContinuationFailureRef::Capture)
                .unwrap_or(ControllerContinuationFailureRef::Closed),
            Some(ControllerContinuationFailure::Root) => {
                let cause = self.resource_failure.as_ref().map(|failure| failure.failure())
                    .or_else(|| self.resource_opening.as_ref()
                        .and_then(|opening| opening.profile_admission_failure())
                        .map(|failure| failure.as_error()))
                    .or_else(|| self.root.as_ref().and_then(|owner| owner.first_failure()));
                cause.map(ControllerContinuationFailureRef::Root)
                    .unwrap_or(ControllerContinuationFailureRef::Closed)
            }
            Some(ControllerContinuationFailure::Selector) => self.selector_attempt.as_ref()
                .and_then(|owner| owner.first_failure())
                .map(ControllerContinuationFailureRef::Selector)
                .unwrap_or(ControllerContinuationFailureRef::Closed),
            Some(ControllerContinuationFailure::Binding(cause)) => {
                ControllerContinuationFailureRef::Binding(cause)
            }
            Some(ControllerContinuationFailure::Delivery(cause)) => {
                ControllerContinuationFailureRef::Delivery(cause)
            }
            Some(ControllerContinuationFailure::RuntimeRefused) => {
                ControllerContinuationFailureRef::RuntimeRefused
            }
            Some(ControllerContinuationFailure::Closed) | None => {
                ControllerContinuationFailureRef::Closed
            }
        }
    }
}

impl Drop for ControllerStartupContinuationV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_refusal_marker_preserves_the_fixed_diagnostic() {
        let view = ControllerContinuationFailureRef::RuntimeRefused;

        assert_eq!(format!("{view:?}"), "resident runtime continuation refused");
    }
}
