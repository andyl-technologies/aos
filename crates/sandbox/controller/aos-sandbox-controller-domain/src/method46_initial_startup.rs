//! Retains the funded startup of either manual initial METHOD46 producer.
//!
//! The closed role selects the actual Parent06 source receiver. Initial capture
//! precedes arguments and profile IO; the same ledger pays the retained body
//! before allocation and native before observations. No supplied descriptor,
//! decoded record or resource amount constructs this original. Captured startup
//! roles alone grant no journal, approval, TPM, checkpoint or readiness authority.

use std::cell::{Cell, RefCell};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use aos_sandbox_broker::immutable_image::{
    ImmutableFileAcquisitionOriginalV1, ImmutableFileAcquisitionRefusalV1,
    ImmutableFileRevalidationOriginalV1, ImmutableImageErrorV1,
};
use aos_sandbox_broker::receiving::{
    Method46InitialOriginComparisonDataV1, Method46InitialReceivingClosedV1,
    Method46InitialServiceRoleV1, Method46InitialSourceCaptureV1,
};
use aos_sandbox_linux::seqpacket::RecordSubjectListenerAdmissionAttemptV1;
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};

const PROFILE_BYTES: usize = 1024 * 1024;
const PATH_BYTES: usize = 1024;
const PROFILE_SUFFIX: &str = "-aos-method46-initial-startup-profile-1/profile.json";

#[derive(Clone, Copy)]
enum First {
    Source,
    Geometry,
    Body,
    Profile,
    Order,
}

/// Refuses manual startup while its actual source and reached owners stay live.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("manual initial METHOD46 startup is incomplete or refused")]
pub struct Method46InitialStartupClosedV1;

/// Retains one separately funded manual invocation and its original startup roles.
///
/// Construction is inert. Capture must precede argument, configuration, journal
/// and credential work. This owner is process-lifetime custody even before
/// capture; dropping its initial table aborts the process. The installed caller
/// retains it through failures, caught unwind and independently owed posts.
/// Neither capture nor its native after produces a semantic completion token.
#[must_use = "retain the actual source and every reached startup owner until exit"]
pub struct Method46InitialStartupOriginalV1 {
    source: RefCell<Method46InitialSourceCaptureV1>,
    origin: Option<Method46InitialOriginComparisonDataV1>,
    body: Option<Box<StartupRolesOriginalV1>>,
    geometry: RefCell<Option<Result<ResourceVector, AccountingError>>>,
    receiving: Cell<ResourceVector>,
    capture_attempted: bool,
    profile_attempted: bool,
    first: Cell<Option<First>>,
    after_attempted: Cell<bool>,
    after_result: Cell<Option<Result<(), Method46InitialReceivingClosedV1>>>,
    closed: Method46InitialStartupClosedV1,
}

// Only the genuine receiver can hand these roles to this owner. They remain
// parked here until purpose-specific image/profile admission consumes them.
struct StartupRolesOriginalV1 {
    listener: Option<RecordSubjectListenerAdmissionAttemptV1>,
    pid1: Option<File>,
    profile_original: Option<File>,
    profile: ImmutableFileAcquisitionOriginalV1,
    profile_flags: Option<Result<rustix::fs::OFlags, rustix::io::Errno>>,
    profile_path: Option<std::io::Result<PathBuf>>,
    profile_measure: Option<Result<(), ImmutableFileAcquisitionRefusalV1>>,
    profile_read: Option<Result<(), ImmutableImageErrorV1>>,
    profile_post: RefCell<ProfilePostOriginalV1>,
}

struct ProfilePostOriginalV1 {
    original: ImmutableFileRevalidationOriginalV1,
    result: Option<Result<(), ImmutableImageErrorV1>>,
}

impl StartupRolesOriginalV1 {
    fn new() -> Self {
        Self {
            listener: None,
            pid1: None,
            profile_original: None,
            profile: ImmutableFileAcquisitionOriginalV1::new(),
            profile_flags: None,
            profile_path: None,
            profile_measure: None,
            profile_read: None,
            profile_post: RefCell::new(ProfilePostOriginalV1 {
                original: ImmutableFileRevalidationOriginalV1::new(),
                result: None,
            }),
        }
    }
}

impl Method46InitialStartupOriginalV1 {
    /// Creates inert custody for the selected fixed manual service.
    ///
    /// The role is comparison DATA; no source original, authority or effect is
    /// obtained until the actual initial receiver independently authenticates.
    #[must_use]
    pub fn new(role: Method46InitialServiceRoleV1) -> Self {
        // Source counts its own constructor/return layout. Price only the
        // co-live upper header here; its separately boxed body is paid later.
        let upper_header = 2
            * (std::mem::size_of::<Self>()
                - std::mem::size_of::<RefCell<Method46InitialSourceCaptureV1>>());
        Self {
            source: RefCell::new(Method46InitialSourceCaptureV1::new(role, upper_header)),
            origin: None,
            body: None,
            geometry: RefCell::new(None),
            receiving: Cell::new(ResourceVector::ZERO),
            capture_attempted: false,
            profile_attempted: false,
            first: Cell::new(None),
            after_attempted: Cell::new(false),
            after_result: Cell::new(None),
            closed: Method46InitialStartupClosedV1,
        }
    }

    fn fail(&self, first: First) -> Method46InitialStartupClosedV1 {
        if self.first.get().is_none() {
            self.first.set(Some(first));
        }
        self.closed
    }

    fn fund_additional(
        &self,
        demand: Option<ResourceVector>,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        if self.first.get().is_some() || self.after_attempted.get() {
            return Err(self.closed);
        }
        let mut geometry = self
            .geometry
            .try_borrow_mut()
            .map_err(|_| self.fail(First::Order))?;
        *geometry = Some(
            demand
                .ok_or(AccountingError::ArithmeticOverflow {
                    dimension: D::MemoryBytes,
                })
                .and_then(|additional| self.receiving.get().checked_add(additional)),
        );
        let complete = geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or_else(|| self.fail(First::Geometry))?;

        let mut source = self
            .source
            .try_borrow_mut()
            .map_err(|_| self.fail(First::Order))?;
        if source.require_complete_v1(complete).is_err() {
            return Err(self.fail(First::Source));
        }
        self.receiving.set(complete);
        Ok(())
    }

    /// Captures the sole original table before arguments or protected IO.
    ///
    /// The same authenticated source prepays the complete startup body before
    /// its Box exists. Native before observations precede the one-way role
    /// handoff. This establishes custody only, without admitting a profile.
    ///
    /// # Errors
    /// Retains capture, geometry and native-before refusals. Reentry, prior
    /// poison or a completed source cannot probe or replace an initial table.
    pub fn capture_before_arguments_once_v1(
        &mut self,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        if self.capture_attempted || self.first.get().is_some() || self.after_attempted.get() {
            return Err(self.fail(First::Order));
        }
        self.capture_attempted = true;
        if self.source.get_mut().capture_once_v1().is_err() {
            return Err(self.fail(First::Source));
        }

        self.fund_additional(
            std::mem::size_of::<StartupRolesOriginalV1>()
                .checked_mul(2)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .map(|bytes| ResourceVector::ZERO.with(D::MemoryBytes, bytes)),
        )?;
        self.body = Some(Box::new(StartupRolesOriginalV1::new()));
        if self
            .source
            .get_mut()
            .observe_native_before_once_v1()
            .is_err()
        {
            return Err(self.fail(First::Source));
        }
        self.origin = self
            .source
            .get_mut()
            .origin_comparison_data_v1()
            .ok()
            .copied();
        if self.origin.is_none() {
            return Err(self.fail(First::Source));
        }
        let roles = self
            .source
            .get_mut()
            .take_completed_startup_roles_once_v1()
            .ok_or_else(|| self.fail(First::Source))?;
        let (listener, pid1, profile) = roles.into_parts_v1();
        let body = self.body.as_mut().ok_or(self.closed)?;
        body.listener = Some(RecordSubjectListenerAdmissionAttemptV1::new(listener));
        body.pid1 = Some(File::from(pid1));
        body.profile_original = Some(File::from(profile));
        Ok(())
    }

    /// Measures and reads only the actual inherited immutable profile once.
    ///
    /// The same source prepays bounded acquisition, bytes and the independently
    /// owed final comparison before native IO. Raw bytes and failed prefixes
    /// stay resident; this step admits no configuration, approval or authority.
    ///
    /// # Errors
    /// Refuses missing capture, reentry, exhausted funding, source changes or
    /// unsafe flags, names, mounts, metadata and bounded content reads.
    pub fn measure_profile_once_v1(&mut self) -> Result<(), Method46InitialStartupClosedV1> {
        if !self.capture_attempted
            || self.body.is_none()
            || self.profile_attempted
            || self.first.get().is_some()
            || self.after_attempted.get()
        {
            return Err(self.fail(First::Order));
        }
        self.profile_attempted = true;
        let result = self.measure_profile();
        if result.is_err() {
            self.fail(First::Profile);
        }
        result
    }

    fn measure_profile(&mut self) -> Result<(), Method46InitialStartupClosedV1> {
        self.source
            .get_mut()
            .require_current_v1()
            .map_err(|_| self.closed)?;
        let demand = (|| {
            // The funded boxed body already includes both copies of the inline
            // acquisition header; Source already paid its inherited descriptor.
            let controls =
                std::mem::size_of::<ImmutableFileAcquisitionOriginalV1>().checked_mul(2)?;
            let acquisition = ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(PATH_BYTES)?
                .checked_sub(
                    ResourceVector::ZERO
                        .with(D::MemoryBytes, u64::try_from(controls).ok()?)
                        .with(D::OpenFiles, 1),
                )
                .ok()?;
            let memory = 4097_usize
                .checked_mul(2)?
                .checked_add(128)?
                .checked_add(PROFILE_BYTES.checked_add(1)?.checked_mul(4)?)?;
            let input = ImmutableFileAcquisitionOriginalV1::materialized_input_bytes_v1(
                PROFILE_BYTES as u64,
            )?
            .checked_add((PROFILE_BYTES as u64).checked_add(1)?)?;
            acquisition
                .checked_add(
                    ResourceVector::ZERO
                        .with(D::MemoryBytes, u64::try_from(memory).ok()?)
                        .with(D::MetadataEntries, 10)
                        .with(D::OutputBytes, input),
                )
                .ok()?
                .checked_add(ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?)
                .ok()
        })();
        self.fund_additional(demand)?;

        let body = self.body.as_mut().ok_or(self.closed)?;
        let file = body.profile_original.as_ref().ok_or(self.closed)?;
        body.profile_flags = Some(rustix::fs::fcntl_getfl(file));
        let flags = body
            .profile_flags
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(self.closed)?;
        crate::immutable_image::require_readonly_launch_flags(flags).map_err(|_| self.closed)?;
        body.profile_path = Some(std::fs::read_link(format!(
            "/proc/self/fd/{}",
            file.as_raw_fd()
        )));
        let path = body
            .profile_path
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(self.closed)?;
        let name = path.to_str().ok_or(self.closed)?;
        crate::normal_root::profile::require_store_path(name).map_err(|_| self.closed)?;
        if name.len() > PATH_BYTES || !name.ends_with(PROFILE_SUFFIX) {
            return Err(self.closed);
        }
        let path = path.clone();
        let file = body.profile_original.take().ok_or(self.closed)?;
        body.profile_measure =
            Some(
                body.profile
                    .measure_original_once(path, file, None, PROFILE_BYTES as u64, false),
            );
        if !matches!(body.profile_measure, Some(Ok(()))) {
            return Err(self.closed);
        }
        body.profile_read = Some(body.profile.read_completed_bounded());
        if !matches!(body.profile_read, Some(Ok(()))) {
            return Err(self.closed);
        }
        Ok(())
    }

    fn finish_profile_post(&self) {
        let Some(body) = self.body.as_ref() else {
            return;
        };
        // Do not let a failed upper body suppress a reached file's post. The
        // lower source after remains independently owed even if this refuses.
        match body.profile_post.try_borrow_mut() {
            Ok(mut post) => {
                let result = body
                    .profile
                    .observe_available_held_once_v1(&mut post.original);
                if matches!(result, Some(Err(_))) {
                    self.fail(First::Profile);
                }
                post.result = result;
            }
            Err(_) => {
                self.fail(First::Order);
            }
        }
    }

    /// Attempts the reached profile post and same-source native after once.
    ///
    /// An upper refusal is latched before the lower observation; it cannot
    /// suppress either owed post or authorize a replacement source. All original
    /// roles remain resident. Success reports only these mechanical bookends.
    ///
    /// # Errors
    /// Refuses reentry, a prior body/source failure or the actual native after.
    /// No profile, journal, signature, checkpoint or readiness grant is issued.
    pub fn finish_source_after_owed_once_v1(
        &self,
        body: Result<(), Method46InitialStartupClosedV1>,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        if body.is_err() {
            self.fail(First::Body);
        }
        if self.after_attempted.replace(true) {
            return Err(self.fail(First::Order));
        }
        self.finish_profile_post();
        let result = self
            .source
            .try_borrow_mut()
            .map_err(|_| self.fail(First::Order))?
            .observe_native_after_owed_once_v1();
        self.after_result.set(Some(result));
        if result.is_err() {
            self.fail(First::Source);
        }
        if self.first.get().is_some() {
            Err(self.closed)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;

    fn purposes() -> [Method46InitialServiceRoleV1; 2] {
        [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ]
    }

    #[test]
    fn profile_before_capture_refuses_without_io_and_cannot_rearm() {
        for role in purposes() {
            let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));

            assert!(startup.measure_profile_once_v1().is_err());
            assert!(startup.capture_before_arguments_once_v1().is_err());
            assert!(startup.measure_profile_once_v1().is_err());

            assert!(matches!(startup.first.get(), Some(First::Order)));
            assert!(!startup.capture_attempted);
            assert!(!startup.profile_attempted);
            assert!(startup.body.is_none());
            assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
        }
    }

    #[test]
    fn profile_post_borrow_refusal_still_attempts_source_after() {
        for role in purposes() {
            let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));
            // Inert test sink only: no descriptor, capture or authority exists.
            startup.body = Some(Box::new(StartupRolesOriginalV1::new()));
            let held_post = startup.body.as_ref().unwrap().profile_post.borrow_mut();

            assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

            assert!(matches!(startup.first.get(), Some(First::Order)));
            assert!(startup.after_attempted.get());
            assert!(matches!(startup.after_result.get(), Some(Err(_))));
            drop(held_post);
        }
    }

    #[test]
    fn geometry_refusal_prevents_any_initial_capture_or_startup_role_handoff() {
        for role in purposes() {
            // The actual initial table has process lifetime, including while
            // pristine. This test deliberately never observes host descriptors.
            let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));

            assert!(startup.fund_additional(None).is_err());
            assert!(startup.capture_before_arguments_once_v1().is_err());

            assert!(!startup.capture_attempted);
            assert!(startup.body.is_none());
            assert!(startup.origin.is_none());
            assert!(matches!(startup.first.get(), Some(First::Geometry)));
        }
    }

    #[test]
    fn early_or_failed_after_cannot_rearm_the_initial_receiver() {
        for role in purposes() {
            let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));

            assert!(
                startup
                    .finish_source_after_owed_once_v1(Err(Method46InitialStartupClosedV1))
                    .is_err()
            );
            assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());
            assert!(startup.capture_before_arguments_once_v1().is_err());

            assert!(startup.after_attempted.get());
            assert!(matches!(startup.after_result.get(), Some(Err(_))));
            assert!(matches!(startup.first.get(), Some(First::Body)));
            assert!(!startup.capture_attempted);
            assert!(startup.body.is_none());
        }
    }
}
