//! Owns the shared fixed Host, Mount and Publisher native identity mechanism.
//!
//! Every role selects a closed compiled unit/cgroup recipe. Original PID1
//! observations, cgroup/probe/pidfd/membership outcomes, timeout and independent
//! native posts stay resident. The genuine role owner supplies all funding and
//! original/profile joins; this mechanism creates no payer or service authority.

use aos_sandbox_linux::cgroup::{
    CgroupV2Root, ControllerStartupHostCgroupReadbackV1,
    ControllerStartupMountCgroupReadbackV1, ControllerPublisherCgroupReadbackV1,
    ExactCgroupMembershipReadbackV1,
    ExactCgroupMembershipRefusalV1, RetainedCgroupAnchor,
};
use aos_linux_descriptors::pidfd::PidFd;
use aos_linux_descriptors::pidfd::PidFdInfo;
use aos_sandbox_linux::pidfd::PidFdOpenAttemptV1;
use aos_sandbox_linux::pidfd::PidFdOpenRefusalV1;
use aos_systemd_client::{
    ControllerAttachmentServiceV1, ControllerPropertyObserverAttemptV1,
    ServiceControlGroupObservation,
};

use std::time::Duration;


const SERVICE_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Reports a failed or incomplete fixed native identity flight.
#[derive(Debug, thiserror::Error)]
#[error("fixed service identity changed or is unavailable")]
pub struct ServiceIdentityRefusalV1;

#[derive(Clone, Copy)]
enum ServiceIdentityRoleV1 {
    Attachment(ControllerAttachmentServiceV1),
    Publisher { uid: u32, gid: u32 },
}

const MATERIALIZED_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy)]
enum IdentityFailureV1 {
    FirstRead,
    Kernel,
    SecondRead,
    MembershipPost,
    Comparison,
    Timeout,
    Settlement,
    Reentry,
}

enum StartupCgroup {
    Host(ControllerStartupHostCgroupReadbackV1),
    Mount(ControllerStartupMountCgroupReadbackV1),
    Publisher(ControllerPublisherCgroupReadbackV1),
}

impl StartupCgroup {
    fn capture_once(&mut self) -> aos_linux_descriptors::Result<()> {
        match self {
            Self::Host(read) => read.capture_once(),
            Self::Mount(read) => read.capture_once(),
            Self::Publisher(read) => read.capture_once(),
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Host(read) => read.failure(),
            Self::Mount(read) => read.failure(),
            Self::Publisher(read) => read.failure(),
        }
    }

    fn take_pair(&mut self) -> Option<(CgroupV2Root, RetainedCgroupAnchor)> {
        match self {
            Self::Host(read) => read.take_validated_pair(),
            Self::Mount(read) => read.take_validated_pair(),
            Self::Publisher(read) => read.take_validated_pair(),
        }
    }
}

/// Owns one fixed service's native observation without financial admission.
///
/// Successful native observations are comparison custody. A genuine role must
/// independently join its actual fixed purpose, payer, profile and retained
/// original before constructing an accepted Runtime or Publisher effect.
pub struct ServiceIdentityFlightV1 {
    role: ServiceIdentityRoleV1,
    observations: [Option<ControllerPropertyObserverAttemptV1>; 2],
    reads: [Option<aos_systemd_client::Result<()>>; 2],
    cgroup_read: Option<StartupCgroup>,
    cgroup_capture: Option<aos_linux_descriptors::Result<()>>,
    root: Option<CgroupV2Root>,
    anchor: Option<RetainedCgroupAnchor>,
    pidfd_read: PidFdOpenAttemptV1,
    pidfd_capture: Option<Result<(), PidFdOpenRefusalV1>>,
    process: Option<PidFd>,
    membership: [Option<ExactCgroupMembershipReadbackV1>; 2],
    membership_capture: [Option<Result<(), ExactCgroupMembershipRefusalV1>>; 2],
    kernel_capture: Option<Result<(), ServiceIdentityRefusalV1>>,
    comparison: Option<Result<(), ServiceIdentityRefusalV1>>,
    settlement: Option<Result<(), ServiceIdentityRefusalV1>>,
    completion: Option<Result<Result<(), ServiceIdentityRefusalV1>, tokio::time::error::Elapsed>>,
    entered: bool,
    complete: bool,
    temporary_proofs_retired: bool,
    first_failure: Option<IdentityFailureV1>,
}

impl ServiceIdentityFlightV1 {
    /// Creates empty destinations for the compiled Host service recipe.
    pub fn host() -> Self {
        Self::new(ServiceIdentityRoleV1::Attachment(ControllerAttachmentServiceV1::Host))
    }

    /// Creates empty destinations for the compiled Mount service recipe.
    pub fn mount() -> Self {
        Self::new(ServiceIdentityRoleV1::Attachment(ControllerAttachmentServiceV1::Mount))
    }

    /// Creates the compiled Publisher query with expected credential DATA.
    ///
    /// The credentials do not select another unit or grant registration.
    pub fn publisher(uid: u32, gid: u32) -> Self {
        Self::new(ServiceIdentityRoleV1::Publisher { uid, gid })
    }

    fn new(role: ServiceIdentityRoleV1) -> Self {
        Self {
            role,
            observations: [None, None],
            reads: [None, None],
            cgroup_read: Some(match role {
                ServiceIdentityRoleV1::Attachment(ControllerAttachmentServiceV1::Host) => StartupCgroup::Host(
                    ControllerStartupHostCgroupReadbackV1::new(),
                ),
                ServiceIdentityRoleV1::Attachment(ControllerAttachmentServiceV1::Mount) => StartupCgroup::Mount(
                    ControllerStartupMountCgroupReadbackV1::new(),
                ),
                ServiceIdentityRoleV1::Publisher { .. } => StartupCgroup::Publisher(
                    ControllerPublisherCgroupReadbackV1::new(),
                ),
            }),
            cgroup_capture: None,
            root: None,
            anchor: None,
            pidfd_read: PidFdOpenAttemptV1::new(),
            pidfd_capture: None,
            process: None,
            membership: std::array::from_fn(|_| Some(ExactCgroupMembershipReadbackV1::new())),
            membership_capture: [None, None],
            kernel_capture: None,
            comparison: None,
            settlement: None,
            completion: None,
            entered: false,
            complete: false,
            temporary_proofs_retired: false,
            first_failure: None,
        }
    }

    // Ordinary Host has no explicit Slice; selected startup requires the
    // actual PID1 locator to equal this finite profile before native opening.
    // Mount's installed module explicitly selects aos-control.slice.
    fn expected_cgroup(&self) -> &'static str {
        match self.role {
            ServiceIdentityRoleV1::Attachment(ControllerAttachmentServiceV1::Host) => "/system.slice/aos-sandbox-hostd.service",
            ServiceIdentityRoleV1::Attachment(ControllerAttachmentServiceV1::Mount) =>
                "/aos.slice/aos-control.slice/aos-sandbox-mountd.service",
            ServiceIdentityRoleV1::Publisher { .. } =>
                "/aos.slice/aos-control.slice/aos-view-publisher.service",
        }
    }

    /// Performs both fixed PID1 reads and the independent native posts once.
    ///
    /// # Errors
    /// Refuses repeated, timed-out, changed, incomplete or failed observation.
    ///
    /// # Panics
    /// Panics when polled without enabled Tokio IO and time drivers.
    pub async fn observe_once(
        &mut self,
    ) -> Result<(), ServiceIdentityRefusalV1> {
        if self.entered {
            self.first_failure.get_or_insert(IdentityFailureV1::Reentry);
            self.complete = false;
            return Err(ServiceIdentityRefusalV1);
        }
        self.entered = true;
        // Preserve the ordinary whole-flight five-second bound, rather than
        // renewing it for each of the two service observations.
        self.completion = Some(tokio::time::timeout(
            SERVICE_OBSERVATION_TIMEOUT, self.observe_inner(),
        ).await);
        if matches!(self.completion, Some(Err(_))) {
            self.first_failure.get_or_insert(IdentityFailureV1::Timeout);
        }
        // End every reached original transport even after a semantic error or
        // timeout. The independent native shutdown outcomes remain resident.
        self.settlement = Some(self.settle());
        if matches!(self.settlement, Some(Err(_))) {
            self.first_failure.get_or_insert(IdentityFailureV1::Settlement);
        }
        self.complete = matches!(self.completion, Some(Ok(Ok(()))))
            && matches!(self.settlement, Some(Ok(())));
        if self.complete {
            Ok(())
        } else {
            Err(ServiceIdentityRefusalV1)
        }
    }

    async fn observe_inner(&mut self) -> Result<(), ServiceIdentityRefusalV1> {
        self.observe_service(0).await;
        if matches!(self.reads[0], Some(Err(_))) {
            self.first_failure.get_or_insert(IdentityFailureV1::FirstRead);
        }
        self.kernel_capture = Some(self.capture_kernel());
        if matches!(self.kernel_capture, Some(Err(_))) {
            self.first_failure.get_or_insert(IdentityFailureV1::Kernel);
        }
        // A failed kernel acquisition does not suppress the independent fixed
        // PID1 post, or a fresh membership post when both originals exist.
        self.observe_service(1).await;
        if matches!(self.reads[1], Some(Err(_))) {
            self.first_failure.get_or_insert(IdentityFailureV1::SecondRead);
        }
        if let (Some(anchor), Some(process), Some(membership)) =
            (&self.anchor, &self.process, self.membership[1].as_mut())
        {
            self.membership_capture[1] = Some(membership.capture_once(anchor, process));
            if matches!(self.membership_capture[1], Some(Err(_))) {
                self.first_failure.get_or_insert(IdentityFailureV1::MembershipPost);
            }
        }
        self.comparison = Some(self.compare());
        if matches!(self.comparison, Some(Err(_))) {
            self.first_failure.get_or_insert(IdentityFailureV1::Comparison);
        }
        if !matches!(self.kernel_capture, Some(Ok(())))
            || !matches!(self.comparison, Some(Ok(())))
        {
            return Err(ServiceIdentityRefusalV1);
        }
        Ok(())
    }

    async fn observe_service(&mut self, index: usize) {
        self.observations[index] = Some(ControllerPropertyObserverAttemptV1::with_materialization_limit(
            MATERIALIZED_BYTES,
        ));
        let Some(observation) = self.observations[index].as_mut() else {
            return;
        };
        let mut cancellation = observation.cancellation_fence();
        self.reads[index] = Some(async {
            observation.connect().await?;
            match self.role {
                ServiceIdentityRoleV1::Attachment(role) =>
                    observation.observe_controller_attachment_service_v1(role).await,
                ServiceIdentityRoleV1::Publisher { .. } =>
                    observation.observe_controller_publisher_service_v1().await,
            }
        }.await);
        if matches!(self.reads[index], Some(Ok(()))) {
            cancellation.complete();
        }
    }

    fn observed(&self, index: usize) -> Option<&ServiceControlGroupObservation> {
        let observation = self.observations[index].as_ref()?;
        match self.role {
            ServiceIdentityRoleV1::Attachment(_) =>
                observation.control_group_result_v1()?.as_ref().ok(),
            ServiceIdentityRoleV1::Publisher { .. } =>
                observation.publisher_service_result_v1()?.as_ref().ok()?.as_ref(),
        }
    }

    fn capture_kernel(&mut self) -> Result<(), ServiceIdentityRefusalV1> {
        if self.publisher_absent(0) {
            return Ok(());
        }
        let first = self.observed(0).ok_or(ServiceIdentityRefusalV1)?;
        if first.control_group != self.expected_cgroup() {
            return Err(ServiceIdentityRefusalV1);
        }
        let main_pid = first.main_pid;
        let cgroup_read = self.cgroup_read.as_mut().ok_or(ServiceIdentityRefusalV1)?;
        self.cgroup_capture = Some(cgroup_read.capture_once());
        if !matches!(self.cgroup_capture, Some(Ok(()))) {
            return Err(ServiceIdentityRefusalV1);
        }
        let (root, anchor) = cgroup_read.take_pair()
            .ok_or(ServiceIdentityRefusalV1)?;
        self.root = Some(root);
        self.anchor = Some(anchor);
        self.pidfd_capture = Some(self.pidfd_read.capture_once(main_pid));
        if !matches!(self.pidfd_capture, Some(Ok(()))) {
            return Err(ServiceIdentityRefusalV1);
        }
        self.process = self.pidfd_read.take_validated();
        let anchor = self.anchor.as_ref().ok_or(ServiceIdentityRefusalV1)?;
        let process = self.process.as_ref().ok_or(ServiceIdentityRefusalV1)?;
        let membership = self.membership[0].as_mut().ok_or(ServiceIdentityRefusalV1)?;
        self.membership_capture[0] = Some(membership.capture_once(anchor, process));
        if !matches!(self.membership_capture[0], Some(Ok(()))) {
            return Err(ServiceIdentityRefusalV1);
        }
        Ok(())
    }

    fn compare(&self) -> Result<(), ServiceIdentityRefusalV1> {
        if self.publisher_absent(0) && self.publisher_absent(1)
            && self.reads.iter().all(|read| matches!(read, Some(Ok(()))))
        {
            return Ok(());
        }
        let first = self.observed(0).ok_or(ServiceIdentityRefusalV1)?;
        let second = self.observed(1).ok_or(ServiceIdentityRefusalV1)?;
        if first != second || first.control_group != self.expected_cgroup()
            || self.reads.iter().any(|read| !matches!(read, Some(Ok(()))))
        {
            return Err(ServiceIdentityRefusalV1);
        }
        for (capture, membership) in self.membership_capture.iter().zip(&self.membership) {
            let membership = membership.as_ref().ok_or(ServiceIdentityRefusalV1)?;
            if !matches!(capture, Some(Ok(()))) || membership.failure().is_some() {
                return Err(ServiceIdentityRefusalV1);
            }
            let info = membership.result().and_then(|result| result.as_ref().ok())
                .ok_or(ServiceIdentityRefusalV1)?;
            let (uid, gid) = match self.role {
                ServiceIdentityRoleV1::Attachment(_) => (0, 0),
                ServiceIdentityRoleV1::Publisher { uid, gid } => (uid, gid),
            };
            if !required_process(*info, first.main_pid.get(), uid, gid) {
                return Err(ServiceIdentityRefusalV1);
            }
        }
        Ok(())
    }

    fn settle(&self) -> Result<(), ServiceIdentityRefusalV1> {
        let mut positive = true;
        for observation in &self.observations {
            let Some(observation) = observation else {
                positive = false;
                continue;
            };
            observation.end();
            let (connected, rejected) = observation.shutdown_outcomes();
            if !matches!(connected, Some(Ok(()))) || rejected.is_some()
                || !observation.transport_ended_cleanly_v1()
            {
                positive = false;
            }
        }
        if positive {
            Ok(())
        } else {
            Err(ServiceIdentityRefusalV1)
        }
    }

    /// Borrows the original first reached native or completion refusal.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_failure? {
            IdentityFailureV1::FirstRead => self.read_failure(0),
            IdentityFailureV1::Kernel => self.cgroup_read.as_ref().and_then(StartupCgroup::failure)
                .or_else(|| self.pidfd_read.failure().map(|error| error as &dyn std::error::Error))
                .or_else(|| self.membership[0].as_ref()
                    .and_then(|read| read.failure())
                    .map(|error| error as &dyn std::error::Error))
                .or_else(|| result_error(&self.kernel_capture)),
            IdentityFailureV1::SecondRead => self.read_failure(1),
            IdentityFailureV1::MembershipPost => self.membership[1].as_ref()
                .and_then(|read| read.failure()).map(|error| error as &dyn std::error::Error),
            IdentityFailureV1::Comparison => result_error(&self.comparison),
            IdentityFailureV1::Timeout => self.completion.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error as &dyn std::error::Error),
            IdentityFailureV1::Settlement => {
                for observation in self.observations.iter().flatten() {
                    let (connected, rejected) = observation.shutdown_outcomes();
                    if let Some(error) = connected.and_then(|result| result.as_ref().err())
                        .or_else(|| rejected.and_then(|result| result.as_ref().err()))
                    {
                        return Some(error);
                    }
                }
                result_error(&self.settlement)
            }
            IdentityFailureV1::Reentry => Some(&ServiceIdentityRefusalV1),
        }
    }

    fn read_failure(&self, index: usize) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(observation) = &self.observations[index] {
            if let Some(Err(error)) = observation.constructor_result() {
                return Some(error);
            }
            if let Some(Err(error)) = observation.control_group_result_v1() {
                return Some(error);
            }
            if let Some(Err(error)) = observation.publisher_service_result_v1() {
                return Some(error);
            }
        }
        result_error(&self.reads[index])
    }

    /// Reports mechanical completion without granting role admission.
    pub fn completed_positive(&self) -> bool {
        self.complete && self.first_failure.is_none()
            && matches!(self.completion, Some(Ok(Ok(()))))
            && matches!(self.settlement, Some(Ok(())))
    }

    fn publisher_absent(&self, index: usize) -> bool {
        matches!(self.role, ServiceIdentityRoleV1::Publisher { .. })
            && self.observations[index].as_ref().is_some_and(|observation| {
                matches!(observation.publisher_service_result_v1(), Some(Ok(None)))
            })
    }

    // The Host/Mount wrapper preserves its existing transport-disposal point.
    // Publisher calls this only after its OWN additional original profile posts.
    /// Disposes completed transports after the actual role's additional posts.
    ///
    /// # Errors
    /// Refuses unless the mechanical flight completed successfully.
    pub fn dispose_positive_transports(&mut self) -> Result<(), ServiceIdentityRefusalV1> {
        if !self.complete {
            return Err(ServiceIdentityRefusalV1);
        }
        for observation in &mut self.observations {
            drop(observation.take());
        }
        Ok(())
    }

    /// Moves the native Publisher pair without granting registration authority.
    pub fn take_publisher_native(
        &mut self,
    ) -> Option<Option<FixedPublisherNativeIdentityDataV1>> {
        if !self.complete || !matches!(self.role, ServiceIdentityRoleV1::Publisher { .. }) {
            return None;
        }
        if self.publisher_absent(0) && self.publisher_absent(1) {
            self.complete = false;
            return Some(None);
        }
        if self.anchor.is_none() || self.process.is_none() {
            return None;
        }
        self.complete = false;
        match (self.anchor.take(), self.process.take()) {
            (Some(anchor), Some(expected_process)) => Some(Some(FixedPublisherNativeIdentityDataV1 { anchor, expected_process })),
            _ => None,
        }
    }

    // This inspects the actual owning destinations after take_cgroup. It is
    // not a role proof, DTO adoption, observation or authority constructor.
    fn attachment_temporaries_disposed_v1(&self) -> bool {
        matches!(self.role, ServiceIdentityRoleV1::Attachment(_))
            && self.entered && !self.complete && self.temporary_proofs_retired
            && self.first_failure.is_none()
            && matches!(self.completion, Some(Ok(Ok(()))))
            && matches!(self.settlement, Some(Ok(())))
            && matches!(self.kernel_capture, Some(Ok(())))
            && matches!(self.comparison, Some(Ok(())))
            && matches!(self.cgroup_capture, Some(Ok(())))
            && matches!(self.pidfd_capture, Some(Ok(())))
            && self.pidfd_read.failure().is_none()
            && self.reads.iter().all(|read| matches!(read, Some(Ok(()))))
            && self.membership_capture.iter().all(|read| matches!(read, Some(Ok(()))))
            && self.observations.iter().all(Option::is_none)
            && self.cgroup_read.is_none() && self.root.is_none()
            && self.anchor.is_none() && self.process.is_none()
            && self.membership.iter().all(Option::is_none)
    }

    /// Moves a completed attachment anchor at its original disposal frontier.
    pub fn take_cgroup(&mut self) -> Option<RetainedCgroupAnchor> {
        if !self.completed_positive()
            || !matches!(self.role, ServiceIdentityRoleV1::Attachment(_))
            || self.temporary_proofs_retired
        {
            return None;
        }
        let anchor = self.anchor.take()?;
        self.complete = false;
        // Keep the exact output anchor. No later Host/Mount caller borrows
        // the temporary cgroup/root/process/membership proofs. Their complete
        // independent posts and Ended outcome preceded this positive transfer.
        // Failed flights never enter; all outer Results and the pidfd open
        // readback (whose actual pidfd already moved) stay in this owner.
        drop(self.cgroup_read.take());
        drop(self.root.take());
        drop(self.process.take());
        for membership in &mut self.membership {
            drop(membership.take());
        }
        self.temporary_proofs_retired = true;
        Some(anchor)
    }
}

fn result_error<T, E: std::error::Error + 'static>(
    result: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err())
        .map(|error| error as &dyn std::error::Error)
}

fn required_process(info: PidFdInfo, main_pid: u32, uid: u32, gid: u32) -> bool {
    let Some(credentials) = info.credentials() else {
        return false;
    };
    info.pid() == main_pid
        && info.thread_group_id() == main_pid
        && info.parent_pid() == 1
        && credentials.real_user_id() == uid
        && credentials.effective_user_id() == uid
        && credentials.saved_user_id() == uid
        && credentials.filesystem_user_id() == uid
        && credentials.real_group_id() == gid
        && credentials.effective_group_id() == gid
        && credentials.saved_group_id() == gid
        && credentials.filesystem_group_id() == gid
}

/// Owns the actual observed Publisher native pair as nonauthorizing DATA.
///
/// It cannot construct a Controller loan, admitted Publisher scope, or financial
/// original. Only the actual role's existing purpose wrapper may accept it.
pub struct FixedPublisherNativeIdentityDataV1 {
    anchor: RetainedCgroupAnchor,
    expected_process: PidFd,
}

impl FixedPublisherNativeIdentityDataV1 {
    /// Moves the same anchor and process without admitting their role or payer.
    pub fn into_parts(self) -> (RetainedCgroupAnchor, PidFd) {
        (self.anchor, self.expected_process)
    }
}

/// Retains the installed Controller's fixed Host or Mount startup identity.
///
/// Empty construction grants no payment or service authority. The actual
/// selected Controller must admit this whole representation before observing.
#[doc(hidden)]
pub struct ControllerAttachmentStartupV1 {
    original: ServiceIdentityFlightV1,
}

impl ControllerAttachmentStartupV1 {
    pub(crate) fn into_original(self) -> ServiceIdentityFlightV1 {
        self.original
    }

    /// Prepares the fixed Host readback without IO or transport allocation.
    pub fn host() -> Self {
        Self { original: ServiceIdentityFlightV1::host() }
    }

    /// Prepares the fixed Mount readback without IO or transport allocation.
    pub fn mount() -> Self {
        Self { original: ServiceIdentityFlightV1::mount() }
    }

    /// Performs the existing whole bounded startup flight once.
    ///
    /// # Errors
    /// Retains every reached native Result and refuses timeout, identity,
    /// kernel, transport, incomplete or repeated observation.
    ///
    /// # Panics
    /// Panics if polled without the actual Tokio IO/time drivers enabled.
    pub async fn observe_once(&mut self) -> Result<(), ()> {
        self.original.observe_once().await.map_err(|_| ())?;
        self.original.dispose_positive_transports().map_err(|_| ())
    }

    /// Inspects actual completed native disposal after its anchor moved.
    ///
    /// This reports mechanical custody only. The genuine private assembly
    /// must still retain the SAME transferred anchor and original together.
    #[doc(hidden)]
    #[must_use]
    pub fn native_temporaries_disposed_v1(&self) -> bool {
        self.original.attachment_temporaries_disposed_v1()
    }

    /// Moves the checked cgroup and retires its completed temporary proofs.
    pub fn take_cgroup(&mut self) -> Option<RetainedCgroupAnchor> {
        self.original.take_cgroup()
    }
}
