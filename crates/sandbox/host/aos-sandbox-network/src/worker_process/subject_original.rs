//! Shares exact manager and result-subject checks with retained native custody.

use super::*;
use aos_sandbox_linux::cgroup::{CgroupActiveOriginalV2, RuntimeScopeMembershipOriginalV1};
use aos_linux_descriptors::pidfd::PidFd;
use aos_linux_descriptors::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::{PeerCredentials, RecordCredentials};

#[derive(Clone, Copy)]
enum Purpose {
    Manager,
    PreparationResult,
    Observation,
}

// Retain each native credential kind rather than pretending SO_PEERCRED is
// a kernel-authorized record nomination. This private projection only shares
// the existing scalar comparisons; it constructs neither native subject.
#[derive(Clone, Copy)]
enum SubjectCredentialsV4 {
    Connection(PeerCredentials),
    Record(RecordCredentials),
}

impl SubjectCredentialsV4 {
    fn pid(self) -> u32 {
        match self {
            Self::Connection(credentials) => credentials.pid().get(),
            Self::Record(credentials) => credentials.pid().get(),
        }
    }

    fn uid(self) -> u32 {
        match self {
            Self::Connection(credentials) => credentials.uid(),
            Self::Record(credentials) => credentials.uid(),
        }
    }

    fn gid(self) -> u32 {
        match self {
            Self::Connection(credentials) => credentials.gid(),
            Self::Record(credentials) => credentials.gid(),
        }
    }
}

trait SubjectNative {
    fn membership(
        &mut self,
        anchor: &RetainedCgroupAnchor,
        process: &PidFd,
    ) -> Result<PidFdInfo, NetworkWorkerProcessError>;
    fn alive(&mut self, process: &PidFd) -> Result<bool, NetworkWorkerProcessError>;
    fn current(&mut self, anchor: &RetainedCgroupAnchor) -> Result<(), NetworkWorkerProcessError>;
}

fn validate_subject(
    credentials: SubjectCredentialsV4,
    process: &PidFd,
    anchor: &RetainedCgroupAnchor,
    purpose: Purpose,
    native: &mut impl SubjectNative,
) -> Result<(), NetworkWorkerProcessError> {
    let info = native.membership(anchor, process)?;
    let expected_pid = match purpose {
        Purpose::Manager => 1,
        _ => credentials.pid(),
    };
    if (matches!(purpose, Purpose::Manager) && credentials.pid() != 1)
        || credentials.uid() != 0
        || credentials.gid() != 0
        || info.pid() != expected_pid
        || info.thread_group_id() != expected_pid
        || (!matches!(purpose, Purpose::PreparationResult) && !native.alive(process)?)
    {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    native.current(anchor)
}

struct LocalSubject;

impl SubjectNative for LocalSubject {
    fn membership(
        &mut self,
        anchor: &RetainedCgroupAnchor,
        process: &PidFd,
    ) -> Result<PidFdInfo, NetworkWorkerProcessError> {
        Ok(anchor.verify_exact_membership(process)?)
    }
    fn alive(&mut self, process: &PidFd) -> Result<bool, NetworkWorkerProcessError> {
        Ok(process.is_alive()?)
    }
    fn current(&mut self, anchor: &RetainedCgroupAnchor) -> Result<(), NetworkWorkerProcessError> {
        Ok(anchor.validate_current()?)
    }
}

pub(super) fn validate_manager_local(
    peer: &ConnectionPeerIdentity,
    manager: &RetainedCgroupAnchor,
) -> Result<(), NetworkWorkerProcessError> {
    validate_subject(
        SubjectCredentialsV4::Connection(peer.credentials()),
        peer.pidfd(),
        manager,
        Purpose::Manager,
        &mut LocalSubject,
    )
}

pub(super) fn validate_result_local(
    subject: &KernelAuthorizedRecordSubject,
    cgroup: &RetainedCgroupAnchor,
) -> Result<(), NetworkWorkerProcessError> {
    validate_subject(
        SubjectCredentialsV4::Record(subject.credentials()),
        subject.pidfd(),
        cgroup,
        Purpose::PreparationResult,
        &mut LocalSubject,
    )
}

pub(crate) fn validate_observer_local(
    subject: &KernelAuthorizedRecordSubject,
    cgroup: &RetainedCgroupAnchor,
) -> Result<(), NetworkWorkerProcessError> {
    validate_subject(
        SubjectCredentialsV4::Record(subject.credentials()),
        subject.pidfd(),
        cgroup,
        Purpose::Observation,
        &mut LocalSubject,
    )
}

#[derive(Clone, Copy)]
enum First {
    Membership,
    Alive,
    Current,
    Recipe,
    Closed,
}

pub(crate) struct NetworkWorkerSubjectOriginalV4 {
    membership: RuntimeScopeMembershipOriginalV1,
    current: CgroupActiveOriginalV2,
    alive: Option<aos_linux_descriptors::Result<bool>>,
    result: Option<Result<(), NetworkWorkerProcessError>>,
    first: Option<First>,
    closed: Option<NetworkWorkerProcessError>,
}

impl NetworkWorkerSubjectOriginalV4 {
    pub(crate) fn new() -> Self {
        Self {
            membership: RuntimeScopeMembershipOriginalV1::new(),
            current: CgroupActiveOriginalV2::new(),
            alive: None,
            result: None,
            first: None,
            closed: None,
        }
    }

    pub(crate) fn receiving_obligations_v4() -> Option<(usize, usize, usize)> {
        let mut bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<SubjectCredentialsV4>().checked_mul(2)?)?;
        let mut files = 0_usize;
        let mut names = 0_usize;
        for (memory, native, entries) in [
            RuntimeScopeMembershipOriginalV1::exact_receiving_demand_v1()?,
            CgroupActiveOriginalV2::receiving_obligations_v2()?,
        ] {
            bytes = bytes.checked_add(memory)?;
            files = files.checked_add(native)?;
            names = names.checked_add(entries)?;
        }
        Some((bytes, files, names))
    }

    pub(crate) fn capture_manager_once(
        &mut self,
        peer: &ConnectionPeerIdentity,
        manager: &RetainedCgroupAnchor,
    ) -> Result<(), NetworkWorkerProcessError> {
        self.capture(SubjectCredentialsV4::Connection(peer.credentials()), peer.pidfd(), manager, Purpose::Manager)
    }

    pub(crate) fn capture_result_once(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
        cgroup: &RetainedCgroupAnchor,
    ) -> Result<(), NetworkWorkerProcessError> {
        self.capture(
            SubjectCredentialsV4::Record(subject.credentials()),
            subject.pidfd(),
            cgroup,
            Purpose::PreparationResult,
        )
    }

    pub(crate) fn capture_observer_once(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
        cgroup: &RetainedCgroupAnchor,
    ) -> Result<(), NetworkWorkerProcessError> {
        self.capture(
            SubjectCredentialsV4::Record(subject.credentials()),
            subject.pidfd(),
            cgroup,
            Purpose::Observation,
        )
    }

    fn capture(
        &mut self,
        credentials: SubjectCredentialsV4,
        process: &PidFd,
        anchor: &RetainedCgroupAnchor,
        purpose: Purpose,
    ) -> Result<(), NetworkWorkerProcessError> {
        if self.result.is_some() || self.closed.is_some() {
            self.closed
                .get_or_insert(NetworkWorkerProcessError::Protocol(
                    "worker subject original is closed",
                ));
            self.first.get_or_insert(First::Closed);
            return Err(NetworkWorkerProcessError::Protocol(
                "worker subject original retained",
            ));
        }
        self.result = Some(validate_subject(
            credentials,
            process,
            anchor,
            purpose,
            self,
        ));
        if matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            self.first.get_or_insert(First::Recipe);
            Err(NetworkWorkerProcessError::Protocol(
                "worker subject original retained",
            ))
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Membership => self.membership.failure().map(|error| error as _),
            First::Current => self.current.failure().map(|error| error as _),
            First::Alive => self.alive.as_ref()?.as_ref().err().map(|error| error as _),
            First::Recipe => self.result.as_ref()?.as_ref().err().map(|error| error as _),
            First::Closed => self.closed.as_ref().map(|error| error as _),
        }
    }
}

impl SubjectNative for NetworkWorkerSubjectOriginalV4 {
    fn membership(
        &mut self,
        anchor: &RetainedCgroupAnchor,
        process: &PidFd,
    ) -> Result<PidFdInfo, NetworkWorkerProcessError> {
        if self.membership.capture_once(anchor, process, None).is_err() {
            self.first.get_or_insert(First::Membership);
            return Err(NetworkWorkerProcessError::Protocol(
                "worker membership native original retained",
            ));
        }
        self.membership
            .completed_info()
            .ok_or(NetworkWorkerProcessError::PeerMismatch)
    }
    fn alive(&mut self, process: &PidFd) -> Result<bool, NetworkWorkerProcessError> {
        self.alive = Some(process.is_alive());
        match self.alive.as_ref() {
            Some(Ok(alive)) => Ok(*alive),
            _ => {
                self.first.get_or_insert(First::Alive);
                Err(NetworkWorkerProcessError::Protocol(
                    "worker liveness native original retained",
                ))
            }
        }
    }
    fn current(&mut self, anchor: &RetainedCgroupAnchor) -> Result<(), NetworkWorkerProcessError> {
        if self.current.capture_once_v2(anchor).is_ok() {
            Ok(())
        } else {
            self.first.get_or_insert(First::Current);
            Err(NetworkWorkerProcessError::Protocol(
                "worker cgroup native original retained",
            ))
        }
    }
}

trait ExecutionLivenessV4 {
    fn alive(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
        index: usize,
    ) -> Result<bool, NetworkWorkerProcessError>;
}

struct LocalExecutionLivenessV4;

impl ExecutionLivenessV4 for LocalExecutionLivenessV4 {
    fn alive(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
        _: usize,
    ) -> Result<bool, NetworkWorkerProcessError> {
        Ok(subject.is_alive()?)
    }
}

fn validate_execution_v4(
    ready: &KernelAuthorizedRecordSubject,
    result: &KernelAuthorizedRecordSubject,
    native: &mut impl ExecutionLivenessV4,
) -> Result<(), NetworkWorkerProcessError> {
    if !native.alive(ready, 0)?
        || !native.alive(result, 1)?
        || ready.credentials() != result.credentials()
        || ready.initial_info().pid() != result.initial_info().pid()
        || ready.initial_info().thread_group_id() != result.initial_info().thread_group_id()
        || ready.initial_info().cgroup_id() != result.initial_info().cgroup_id()
    {
        return Err(NetworkWorkerProcessError::PeerMismatch);
    }
    Ok(())
}

pub(super) fn validate_execution_local_v4(
    ready: &KernelAuthorizedRecordSubject,
    result: &KernelAuthorizedRecordSubject,
) -> Result<(), NetworkWorkerProcessError> {
    validate_execution_v4(ready, result, &mut LocalExecutionLivenessV4)
}

pub(crate) struct NetworkWorkerExecutionOriginalV4 {
    alive: [Option<aos_linux_descriptors::Result<bool>>; 2],
    returned: Option<Result<(), NetworkWorkerProcessError>>,
    closed: Option<NetworkWorkerProcessError>,
}

impl NetworkWorkerExecutionOriginalV4 {
    pub(crate) fn new() -> Self {
        Self {
            alive: [None, None],
            returned: None,
            closed: None,
        }
    }

    pub(crate) fn receiving_bytes_v4() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(2 * 256)
    }

    pub(crate) fn capture_once(
        &mut self,
        ready: &KernelAuthorizedRecordSubject,
        result: &KernelAuthorizedRecordSubject,
    ) -> Result<(), NetworkWorkerProcessError> {
        if self.returned.is_some() || self.closed.is_some() {
            self.closed
                .get_or_insert(NetworkWorkerProcessError::Protocol(
                    "worker execution original is closed",
                ));
            return Err(NetworkWorkerProcessError::Protocol(
                "worker execution original retained",
            ));
        }
        self.returned = Some(validate_execution_v4(ready, result, self));
        if matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NetworkWorkerProcessError::Protocol(
                "worker execution original retained",
            ))
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.alive
            .iter()
            .find_map(|result| result.as_ref()?.as_ref().err().map(|error| error as _))
            .or_else(|| {
                self.returned
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|error| error as _)
            })
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

impl ExecutionLivenessV4 for NetworkWorkerExecutionOriginalV4 {
    fn alive(
        &mut self,
        subject: &KernelAuthorizedRecordSubject,
        index: usize,
    ) -> Result<bool, NetworkWorkerProcessError> {
        self.alive[index] = Some(subject.is_alive());
        match self.alive[index].as_ref() {
            Some(Ok(alive)) => Ok(*alive),
            _ => Err(NetworkWorkerProcessError::Protocol(
                "worker execution liveness original retained",
            )),
        }
    }
}
