//! Controller-registered publisher channels pinned to one connection establisher.
//!
//! Unlike holder channels, publisher sockets cannot delegate record-writing
//! authority to another process, even inside the same cgroup. Both the retained
//! connection pidfd and each kernel record subject are checked on every receive.
//! Authenticated records carry raw publisher-request bytes; canonical decoding,
//! challenges, current authority, quotas, and publication effects belong elsewhere.
//!
//! Each packet is a single canonical publisher request, with no session header:
//!
//! ```text
//! canonical publisher-request bytes (1..32768 bytes)
//! ```
//!
//! After durable registration, the controller sends a fixed lookup-only greeting:
//!
//! ```text
//! magic "AOSPUBI1" (8 bytes) | publisher instance (16 bytes)
//! ```
//!
//! Fatal receives retire the transport but retain its process pin and service
//! reservation until an explicit controller operation observes process exit.
//! This process-local table starts empty and cannot restore sessions from a journal.

use aos_sandbox_core::{
    ChannelBinding, NodeId, PrincipalId, ProjectId, PublisherInstanceId, ResourceId,
};
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::{
    ReceivedRecord, RecordSubjectListener, SeqpacketError, SeqpacketSocket,
};

mod identities;
#[cfg(all(test, feature = "kernel-tests"))]
mod kernel_tests;
#[cfg(test)]
mod tests;

const MAXIMUM_SESSIONS: usize = 4096;
const MAXIMUM_REQUEST_BYTES: usize = 32768;

/// Bounds all active and retired publisher execution reservations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherSessionLimits {
    /// Fixed number of slots, from one through 4096.
    pub maximum_sessions: usize,
}

/// Describes the publisher service selected by trusted controller administration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublisherSessionScope {
    /// Protected service principal, never inferred from Unix credentials.
    pub principal: PrincipalId,
    /// Node whose publisher execution is registered.
    pub node: NodeId,
    /// Project served by this execution.
    pub project: ProjectId,
    /// Logical cache resource selected by protected configuration.
    pub cache_resource: ResourceId,
}

/// Reports publisher session configuration, execution, and transport failures.
#[derive(Debug, thiserror::Error)]
pub enum PublisherSessionError {
    /// The slot bound is zero or exceeds 4096.
    #[error("publisher session limit must be within 1..=4096")]
    InvalidLimit,
    /// A trusted scope contains a reserved zero identity.
    #[error("publisher session scope contains an unspecified binding")]
    InvalidScope,
    /// The fixed table allocation failed.
    #[error("publisher session allocation failed")]
    Allocation,
    /// All slots are active or retained for retired executions.
    #[error("publisher session capacity is exhausted")]
    Capacity,
    /// An active or retired entry already reserves this principal and node.
    #[error("publisher service execution is already reserved")]
    ServiceReserved,
    /// No process-local entry has this instance identity.
    #[error("publisher session is unknown")]
    UnknownSession,
    /// The connection has been retired and cannot receive records.
    #[error("publisher session is retired")]
    Retired,
    /// The requested release names a still-active entry.
    #[error("publisher session must be retired before release")]
    NotRetired,
    /// The pinned execution has not yet exited.
    #[error("publisher execution is still alive")]
    ExecutionAlive,
    /// A process observation differs from the originally pinned execution.
    #[error("publisher record does not match the pinned live execution")]
    ExecutionMismatch,
    /// Kernel randomness was unavailable.
    #[error("publisher session entropy is unavailable")]
    EntropyUnavailable,
    /// Bounded identity generation failed to produce a distinct binding.
    #[error("publisher session identity generation collided")]
    IdentityCollision,
    /// Transport adoption or record processing failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// A pidfd or retained cgroup observation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
}

/// Owns fixed-capacity publisher executions without reconstructing live authority.
pub struct PublisherSessionRegistry {
    slots: Vec<Option<PublisherSession>>,
}

impl PublisherSessionRegistry {
    /// Retains the registered execution without consuming another request record.
    pub(crate) fn retain_execution(
        &mut self,
        instance: PublisherInstanceId,
    ) -> Result<LivePublisherExecution<'_>, PublisherSessionError> {
        let index = self.index(instance)?;
        let session = self.slots[index]
            .as_mut()
            .ok_or(PublisherSessionError::UnknownSession)?;
        let mut retained = LivePublisherExecution { session };
        retained.recheck()?;
        Ok(retained)
    }

    /// Creates an empty table with storage reserved before accepting any peer.
    ///
    /// # Errors
    ///
    /// Rejects an invalid capacity or a failed fixed-table allocation.
    pub fn new(limits: PublisherSessionLimits) -> Result<Self, PublisherSessionError> {
        if !(1..=MAXIMUM_SESSIONS).contains(&limits.maximum_sessions) {
            return Err(PublisherSessionError::InvalidLimit);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limits.maximum_sessions)
            .map_err(|_| PublisherSessionError::Allocation)?;
        slots.resize_with(limits.maximum_sessions, || None);
        Ok(Self { slots })
    }

    /// Receives raw request bytes authenticated to the original live publisher process.
    ///
    /// This does not decode requests or grant current application authority.
    /// Fatal errors close the connection but retain the execution reservation.
    ///
    /// # Errors
    ///
    /// Rejects unknown or retired instances, transport violations, process exit,
    /// cgroup changes, and records written by a different process. Temporary
    /// transport interruption or absence of a record preserves an active session.
    pub fn receive(
        &mut self,
        instance: PublisherInstanceId,
    ) -> Result<AuthenticatedPublisherRecord<'_>, PublisherSessionError> {
        let index = self.index(instance)?;
        let session = self.slots[index]
            .as_mut()
            .ok_or(PublisherSessionError::UnknownSession)?;
        if session.retired {
            return Err(PublisherSessionError::Retired);
        }
        let result = (|| {
            session.check_current()?;
            let record = session.socket.receive(MAXIMUM_REQUEST_BYTES)?;
            let process_info = session.check_record(&record)?;
            Ok((record, process_info))
        })();
        match result {
            Ok((record, process_info)) => Ok(AuthenticatedPublisherRecord {
                session,
                record,
                process_info,
            }),
            Err(error) => {
                if !matches!(
                    error,
                    PublisherSessionError::Transport(
                        SeqpacketError::WouldBlock | SeqpacketError::Interrupted
                    )
                ) {
                    session.retire();
                }
                Err(error)
            }
        }
    }

    /// Closes a publisher transport while retaining its execution and service slot.
    ///
    /// Retirement is idempotent and releases neither durable authority nor quotas
    /// or permits. The retained pidfd continues to identify the old execution.
    ///
    /// # Errors
    ///
    /// Rejects an unknown process-local instance.
    pub fn retire(&mut self, instance: PublisherInstanceId) -> Result<(), PublisherSessionError> {
        let index = self.index(instance)?;
        self.slots[index]
            .as_mut()
            .ok_or(PublisherSessionError::UnknownSession)?
            .retire();
        Ok(())
    }

    pub(crate) fn prepare(
        &mut self,
        listener: &mut RecordSubjectListener,
        scope: PublisherSessionScope,
        anchor: RetainedCgroupAnchor,
    ) -> Result<PreparedPublisherSession<'_>, PublisherSessionError> {
        validate_scope(scope)?;
        if self.slots.iter().flatten().any(|session| {
            session.scope.principal == scope.principal && session.scope.node == scope.node
        }) {
            return Err(PublisherSessionError::ServiceReserved);
        }
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(PublisherSessionError::Capacity)?;
        let (instance, binding) = identities::generate(scope, &self.slots)?;
        let socket = listener.accept()?;
        let peer_info = anchor.verify_exact_membership(socket.peer().pidfd())?;
        let session = PublisherSession {
            socket,
            scope,
            anchor,
            instance,
            binding,
            peer_info,
            retired: false,
        };
        session.check_current()?;
        Ok(PreparedPublisherSession {
            registry: self,
            index,
            session,
        })
    }

    /// Releases only the process-local reservation after confirmed pinned-process exit.
    pub(crate) fn release_retired_after_exit(
        &mut self,
        instance: PublisherInstanceId,
    ) -> Result<PublisherInstanceId, PublisherSessionError> {
        let index = self.index(instance)?;
        let session = self.slots[index]
            .as_ref()
            .ok_or(PublisherSessionError::UnknownSession)?;
        if !session.retired {
            return Err(PublisherSessionError::NotRetired);
        }
        if session.socket.peer().is_alive()? {
            return Err(PublisherSessionError::ExecutionAlive);
        }
        self.slots[index].take();
        Ok(instance)
    }

    fn index(&self, instance: PublisherInstanceId) -> Result<usize, PublisherSessionError> {
        self.slots
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|session| session.instance == instance)
            })
            .ok_or(PublisherSessionError::UnknownSession)
    }
}

struct PublisherSession {
    socket: SeqpacketSocket,
    scope: PublisherSessionScope,
    anchor: RetainedCgroupAnchor,
    instance: PublisherInstanceId,
    binding: ChannelBinding,
    peer_info: PidFdInfo,
    retired: bool,
}

/// Borrows the original registered execution, not a replayed audit record.
pub(crate) struct LivePublisherExecution<'a> {
    session: &'a mut PublisherSession,
}

impl LivePublisherExecution<'_> {
    pub(crate) fn retire(&mut self) {
        self.session.retire();
    }

    pub(crate) fn instance(&self) -> PublisherInstanceId {
        self.session.instance
    }

    pub(crate) fn scope(&self) -> &PublisherSessionScope {
        &self.session.scope
    }

    pub(crate) fn channel_binding(&self) -> ChannelBinding {
        self.session.binding
    }

    /// Retires a failed channel but preserves its process reservation until exit.
    pub(crate) fn recheck(&mut self) -> Result<PidFdInfo, PublisherSessionError> {
        let result = (|| {
            if self.session.retired {
                return Err(PublisherSessionError::Retired);
            }
            crate::local_channel::check_connected(&self.session.socket)?;
            let info = self.session.check_current()?;
            crate::local_channel::check_connected(&self.session.socket)?;
            Ok(info)
        })();
        if result.is_err() {
            self.session.retire();
        }
        result
    }
}

impl PublisherSession {
    fn check_current(&self) -> Result<PidFdInfo, PublisherSessionError> {
        if !self.socket.peer().is_alive()? {
            return Err(PublisherSessionError::ExecutionMismatch);
        }
        let fresh = self
            .anchor
            .verify_exact_membership(self.socket.peer().pidfd())?;
        if !same_process(fresh, self.peer_info) || !self.socket.peer().is_alive()? {
            return Err(PublisherSessionError::ExecutionMismatch);
        }
        Ok(fresh)
    }

    fn check_record(&self, record: &ReceivedRecord) -> Result<PidFdInfo, PublisherSessionError> {
        let before = self.check_current()?;
        let subject = self
            .anchor
            .verify_exact_membership(record.subject().pidfd())?;
        let after = self.check_current()?;
        if !same_process(subject, before) || !same_process(subject, after) {
            return Err(PublisherSessionError::ExecutionMismatch);
        }
        Ok(subject)
    }

    fn retire(&mut self) {
        self.socket.close();
        self.retired = true;
    }
}

fn same_process(left: PidFdInfo, right: PidFdInfo) -> bool {
    left.pid() == right.pid() && left.thread_group_id() == right.thread_group_id()
}

fn validate_scope(scope: PublisherSessionScope) -> Result<(), PublisherSessionError> {
    if [
        scope.principal.as_bytes(),
        scope.node.as_bytes(),
        scope.project.as_bytes(),
        scope.cache_resource.as_bytes(),
    ]
    .iter()
    .any(|id| **id == [0; 16])
    {
        return Err(PublisherSessionError::InvalidScope);
    }
    Ok(())
}

/// Holds an accepted execution outside the live table until durable registration.
pub(crate) struct PreparedPublisherSession<'a> {
    registry: &'a mut PublisherSessionRegistry,
    index: usize,
    session: PublisherSession,
}

impl PreparedPublisherSession<'_> {
    pub(crate) fn instance(&self) -> PublisherInstanceId {
        self.session.instance
    }

    pub(crate) fn channel_binding(&self) -> ChannelBinding {
        self.session.binding
    }

    pub(crate) fn scope(&self) -> &PublisherSessionScope {
        &self.session.scope
    }

    #[cfg(all(test, feature = "kernel-tests"))]
    pub(crate) fn peer_info(&self) -> PidFdInfo {
        self.session.peer_info
    }

    pub(crate) fn check_current(&self) -> Result<PidFdInfo, PublisherSessionError> {
        self.session.check_current()
    }

    /// Sends the fixed lookup greeting only after durable registration and a fresh check.
    ///
    /// The greeting is not authority: it contains `AOSPUBI1` followed by the
    /// 16-byte instance identity, with no caller-selected fields.
    pub(crate) fn send_registration_greeting(&mut self) -> Result<(), PublisherSessionError> {
        let mut greeting = [0_u8; 24];
        greeting[..8].copy_from_slice(b"AOSPUBI1");
        greeting[8..].copy_from_slice(self.session.instance.as_bytes());
        self.session.socket.send(&greeting)?;
        Ok(())
    }

    /// Retains an inert execution reservation after a postcommit failure.
    pub(crate) fn retire(mut self) -> PublisherInstanceId {
        self.session.retire();
        self.activate()
    }

    /// Publishes the preallocated entry only after the controller commits registration.
    pub(crate) fn activate(self) -> PublisherInstanceId {
        let instance = self.session.instance;
        self.registry.slots[self.index] = Some(self.session);
        instance
    }
}

/// Borrows one channel and its kernel-authenticated, original-process record.
///
/// This observation is not a challenge response or publication authorization.
/// No public constructor or cloning operation can synthesize this context.
///
/// ```compile_fail
/// use aos_sandbox::publisher_sessions::AuthenticatedPublisherRecord;
/// fn duplicate<'a>(record: &AuthenticatedPublisherRecord<'a>) -> AuthenticatedPublisherRecord<'a> {
///     record.clone()
/// }
/// ```
pub struct AuthenticatedPublisherRecord<'a> {
    session: &'a PublisherSession,
    record: ReceivedRecord,
    process_info: PidFdInfo,
}

impl AuthenticatedPublisherRecord<'_> {
    /// Returns raw request bytes requiring canonical decoding and current authorization.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.record.payload()
    }

    /// Returns the controller-minted execution instance lookup identity.
    #[must_use]
    pub const fn instance(&self) -> PublisherInstanceId {
        self.session.instance
    }

    /// Returns the role-separated channel binding installed at registration.
    #[must_use]
    pub const fn channel_binding(&self) -> ChannelBinding {
        self.session.binding
    }

    /// Returns the trusted configuration snapshot, not current authority.
    #[must_use]
    pub const fn scope(&self) -> &PublisherSessionScope {
        &self.session.scope
    }

    /// Returns record-subject information observed during the initial receive.
    #[must_use]
    pub const fn process_info(&self) -> PidFdInfo {
        self.process_info
    }

    /// Reobserves the original execution and retained record subject through their pidfds.
    ///
    /// This does not fence later migration or exit. On failure the caller must
    /// discard this borrow and retire the session before further use.
    ///
    /// # Errors
    ///
    /// Rejects exit, cgroup mismatch, process mismatch, or failed kernel observations.
    pub fn recheck(&self) -> Result<PidFdInfo, PublisherSessionError> {
        self.session.check_record(&self.record)
    }
}
