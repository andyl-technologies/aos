//! Joins one actual worker record to the continuously held PID1 birth pins.
//!
//! A bootstrap negative can precede READY. The parent still has its issued
//! PIDFD and scope, so this adapter shares the existing exact subject/cgroup
//! validator and checks both live process pins before comparing their PIDs.
//! It supplies no Source, READY adoption or positive effect permission.

use super::*;
use aos_linux_descriptors::pidfd::PidFd;
use aos_linux_descriptors::pidfd::PidFdInfo;

#[derive(Clone, Copy)]
enum First {
    Order,
    BirthBefore,
    Subject,
    Identity,
    Coordinates,
    SubjectAfter,
    BirthAfter,
}

pub(crate) struct NetworkWorkerBirthExecutionOriginalV2 {
    entered: bool,
    birth_before: Option<aos_linux_descriptors::Result<bool>>,
    subject: NetworkWorkerSubjectOriginalV4,
    subject_result: Option<Result<(), NetworkWorkerProcessError>>,
    identity: Option<aos_linux_descriptors::Result<PidFdInfo>>,
    subject_after: Option<aos_linux_descriptors::Result<bool>>,
    birth_after: Option<aos_linux_descriptors::Result<bool>>,
    first: Option<First>,
}

impl NetworkWorkerBirthExecutionOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            entered: false,
            birth_before: None,
            subject: NetworkWorkerSubjectOriginalV4::new(),
            subject_result: None,
            identity: None,
            subject_after: None,
            birth_after: None,
            first: None,
        }
    }

    pub(crate) fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        let (bytes, files, names) = NetworkWorkerSubjectOriginalV4::receiving_obligations_v4()?;
        Some((
            bytes.checked_add(std::mem::size_of::<Self>().checked_mul(2)?)?,
            files,
            names,
        ))
    }

    pub(crate) fn capture_once_v2(
        &mut self,
        birth: &PidFd,
        scope: &RetainedCgroupAnchor,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<(), NetworkWorkerProcessError> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            return Err(marker());
        }
        self.entered = true;
        self.first = Some(First::BirthBefore);
        self.birth_before = Some(birth.is_alive());
        if matches!(self.birth_before, Some(Ok(true))) {
            self.first = Some(First::Subject);
            self.subject_result = Some(self.subject.capture_result_once(subject, scope));
            if matches!(self.subject_result, Some(Ok(()))) {
                self.first = Some(First::Identity);
                self.identity = Some(birth.info());
                if let Some(Ok(identity)) = self.identity.as_ref() {
                    if subject.credentials().uid() == 0
                        && subject.credentials().gid() == 0
                        && identity.pid() == subject.credentials().pid().get()
                        && identity.thread_group_id() == subject.initial_info().thread_group_id()
                        && identity.cgroup_id() == Some(scope.kernel_id())
                        && identity.cgroup_id() == subject.initial_info().cgroup_id()
                    {
                        self.first = None;
                    } else {
                        self.first = Some(First::Coordinates);
                    }
                }
            }
        }

        self.subject_after = Some(subject.is_alive());
        if !matches!(self.subject_after, Some(Ok(true))) {
            self.first.get_or_insert(First::SubjectAfter);
        }
        self.birth_after = Some(birth.is_alive());
        if !matches!(self.birth_after, Some(Ok(true))) {
            self.first.get_or_insert(First::BirthAfter);
        }
        if self.first.is_some() {
            Err(marker())
        } else {
            Ok(())
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let native: Option<&(dyn std::error::Error + 'static)> = match self.first? {
            First::BirthBefore => self
                .birth_before
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::BirthAfter => self
                .birth_after
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::Subject => self.subject.failure(),
            First::Identity => self
                .identity
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::SubjectAfter => self
                .subject_after
                .as_ref()?
                .as_ref()
                .err()
                .map(|error| error as _),
            First::Order | First::Coordinates => None,
        };
        native.or(Some(&NetworkWorkerProcessError::PeerMismatch))
    }
}

fn marker() -> NetworkWorkerProcessError {
    NetworkWorkerProcessError::Protocol("worker record differs from its held native birth")
}
