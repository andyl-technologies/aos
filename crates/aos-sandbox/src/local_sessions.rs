//! Fixed-capacity, controller-issued local holder channels.
//!
//! A session becomes visible only after the controller commits its capability
//! and activates a prepared socket pair. Kernel record subjects are checked
//! against a retained cgroup; UIDs are never interpreted as project principals.
//! This module authenticates a channel and scope snapshot, not current authority.
//! Admission still requires the controller's healthy protected capability and
//! policy state. Sessions are process-local and do not survive controller restart.
//! Runtime-issued entries retain the complete original Host and payload proof,
//! not an extracted cgroup descriptor. Membership checks reobserve those pins
//! but do not renew the original observation or establish current authority.
//!
//! Each incoming sequenced packet has this exact framing:
//!
//! ```text
//! magic "AOSLHI01" (8 bytes)
//! relative_hint_length (u16, big endian, 0..4096)
//! relative_hint (raw Linux pathname bytes; empty selects exact cgroup)
//! payload (1..32768 bytes)
//! ```
//!
//! A nonempty hint selects a proper descendant and is merely an untrusted
//! locator: strict beneath-resolution and actual record-subject pidfd membership
//! must agree. Records contain no caller-selected channel or principal binding.

use std::os::fd::OwnedFd;

use aos_sandbox_core::{
    AssignmentEpoch, CapabilityId, ChannelBinding, IncarnationId, PrincipalId, ProjectId,
    ResourceId, SandboxId,
};
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::seqpacket::{ReceivedRecord, SeqpacketError, SeqpacketSocket};
use rand::{TryRngCore, rngs::OsRng};
use sha2::{Digest as _, Sha256};

mod frame;
#[cfg(all(test, feature = "kernel-tests"))]
mod tests;

#[cfg(test)]
mod pure_tests;

const MAXIMUM_SESSIONS: usize = 4096;
const MAXIMUM_IDENTITY_ATTEMPTS: usize = 4;
const CHANNEL_DOMAIN: &[u8] = b"aos-local-holder-channel-v1\0";

/// Identifies one process-local session without granting possession of its socket.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LocalSessionId([u8; 16]);

impl LocalSessionId {
    /// Parses an opaque lookup handle, not an authentication token.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrows the exact session lookup bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Bounds the number of installed or exclusively prepared local sessions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalSessionLimits {
    /// Fixed slot count, from one through 4096.
    pub maximum_sessions: usize,
}

/// Describes controller-resolved scope, without proving it is currently authorized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalSessionScope {
    /// Holder principal selected by protected controller state, not a local UID.
    pub holder: PrincipalId,
    /// Project selected by protected controller state.
    pub project: ProjectId,
    /// Sandbox whose execution scope is bound to this channel.
    pub sandbox: SandboxId,
    /// Incarnation recorded at issuance; currentness still requires controller validation.
    pub incarnation: IncarnationId,
    /// Assignment epoch observed at issuance.
    pub epoch: AssignmentEpoch,
    /// Logical cache resource whose domain mapping still requires current lookup.
    pub cache_resource: ResourceId,
}

/// Reports bounded local-session admission, transport, or membership failures.
#[derive(Debug, thiserror::Error)]
pub enum LocalSessionError {
    /// The fixed table size is zero or exceeds the implementation ceiling.
    #[error("local session limit must be within 1..=4096")]
    InvalidLimit,
    /// A trusted scope contains a reserved identity or generation.
    #[error("local session scope contains an unspecified binding")]
    InvalidScope,
    /// Initial table allocation failed.
    #[error("local session allocation failed")]
    Allocation,
    /// No free session slot remains.
    #[error("local session capacity is exhausted")]
    Capacity,
    /// The lookup handle names no live local channel.
    #[error("local session is absent or invalidated")]
    UnknownSession,
    /// Kernel randomness could not be obtained.
    #[error("local session entropy is unavailable")]
    EntropyUnavailable,
    /// Bounded generation could not select distinct non-sentinel identities.
    #[error("local session identity collision budget exhausted")]
    IdentityCollision,
    /// A frame violates the exact wire format or its fixed bounds.
    #[error("invalid local session frame: {0}")]
    InvalidFrame(&'static str),
    /// Kernel transport or record-subject validation failed.
    #[error("local session transport failed: {0}")]
    Transport(#[from] SeqpacketError),
    /// The kernel subject does not satisfy the retained execution scope.
    #[error("local session membership failed: {0}")]
    Membership(#[from] aos_sandbox_linux::Error),
    /// The original Host or payload execution behind a runtime-issued session changed.
    #[error(transparent)]
    RuntimeObservation(#[from] crate::runtime_scope::RuntimeScopeError),
}

/// Owns a preallocated fixed-capacity table of live holder channels.
///
/// Only the controller's crate-private issuance path can prepare and activate
/// entries. Public construction creates an empty table, not authenticated state.
pub struct LocalSessionRegistry {
    slots: Vec<Option<ActiveSession>>,
}

impl LocalSessionRegistry {
    /// Preallocates one bounded table without installing any sessions.
    ///
    /// # Errors
    ///
    /// Rejects an invalid slot count or allocation failure.
    pub fn new(limits: LocalSessionLimits) -> Result<Self, LocalSessionError> {
        if limits.maximum_sessions == 0 || limits.maximum_sessions > MAXIMUM_SESSIONS {
            return Err(LocalSessionError::InvalidLimit);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limits.maximum_sessions)
            .map_err(|_| LocalSessionError::Allocation)?;
        slots.resize_with(limits.maximum_sessions, || None);
        Ok(Self { slots })
    }

    /// Receives one bounded record and observes its kernel subject's scoped membership.
    ///
    /// Successful authentication borrows the active entry: invalidation cannot
    /// race use of the returned record through this registry. Current capability,
    /// revocation, policy and operation authority still require separate checks.
    ///
    /// # Errors
    ///
    /// Unknown handles fail without reading any channel. Would-block and
    /// interruption preserve the session; all other transport, framing, or
    /// membership failures invalidate and close its endpoint before returning.
    pub fn receive(
        &mut self,
        id: LocalSessionId,
    ) -> Result<AuthenticatedLocalRecord<'_>, LocalSessionError> {
        let index = self.index(id)?;
        let received = self.slots[index]
            .as_mut()
            .ok_or(LocalSessionError::UnknownSession)?
            .server
            .receive(frame::MAXIMUM_FRAME_BYTES);
        let record = match received {
            Ok(record) => record,
            Err(error) => {
                if !matches!(
                    error,
                    SeqpacketError::WouldBlock | SeqpacketError::Interrupted
                ) {
                    self.slots[index].take();
                }
                return Err(error.into());
            }
        };
        let validated = frame::validate(
            self.slots[index]
                .as_ref()
                .ok_or(LocalSessionError::UnknownSession)?,
            &record,
        );
        let (payload_offset, process_info) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                self.slots[index].take();
                return Err(error);
            }
        };
        let session = self.slots[index]
            .as_mut()
            .ok_or(LocalSessionError::UnknownSession)?;
        Ok(AuthenticatedLocalRecord {
            session,
            record,
            payload_offset,
            process_info,
        })
    }

    /// Closes a local channel before the controller performs durable revocation.
    ///
    /// This removes local possession only. The caller must still revoke its
    /// capability in protected state; no retained completion permit is cancelled.
    /// Returns the capability handle only after the local server endpoint closes.
    ///
    /// # Errors
    ///
    /// Returns [`LocalSessionError::UnknownSession`] if the handle is absent.
    pub fn invalidate(&mut self, id: LocalSessionId) -> Result<CapabilityId, LocalSessionError> {
        let index = self.index(id)?;
        let session = self.slots[index]
            .take()
            .ok_or(LocalSessionError::UnknownSession)?;
        let capability = session.identities.capability;
        drop(session);
        Ok(capability)
    }

    /// Looks up the capability handle for diagnostics or subsequent durable revocation.
    ///
    /// This lookup authenticates no caller and grants no capability authority.
    /// A controller can retain this handle before `receive`, since fatal receive
    /// failures close and remove the local channel but do not revoke durable state.
    ///
    /// # Errors
    ///
    /// Returns [`LocalSessionError::UnknownSession`] when no active entry exists.
    pub fn capability_id(&self, id: LocalSessionId) -> Result<CapabilityId, LocalSessionError> {
        let index = self.index(id)?;
        Ok(self.slots[index]
            .as_ref()
            .ok_or(LocalSessionError::UnknownSession)?
            .identities
            .capability)
    }

    pub(crate) fn prepare(
        &mut self,
        scope: LocalSessionScope,
        anchor: RetainedCgroupAnchor,
    ) -> Result<PreparedLocalSession<'_>, LocalSessionError> {
        self.prepare_with_execution(scope, SessionExecutionScope::TrustedAdministration(anchor))
    }

    pub(crate) fn prepare_runtime(
        &mut self,
        runtime: crate::runtime_scope::CurrentRuntimeScope,
        cache_resource: ResourceId,
    ) -> Result<PreparedLocalSession<'_>, LocalSessionError> {
        let binding = runtime.binding();
        let manifest = binding.manifest().manifest();
        let scope = LocalSessionScope {
            holder: binding.holder().ok_or(LocalSessionError::InvalidScope)?,
            project: manifest.project(),
            sandbox: manifest.sandbox(),
            incarnation: manifest.incarnation(),
            epoch: manifest.epoch(),
            cache_resource,
        };
        self.prepare_with_execution(
            scope,
            SessionExecutionScope::CurrentRuntime(Box::new(runtime)),
        )
    }

    fn prepare_with_execution(
        &mut self,
        scope: LocalSessionScope,
        execution: SessionExecutionScope,
    ) -> Result<PreparedLocalSession<'_>, LocalSessionError> {
        validate_scope(scope)?;
        execution.check_pins()?;
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(LocalSessionError::Capacity)?;
        let identities = self.generate_identities(scope)?;
        let (server, client) = SeqpacketSocket::pair_with_record_subjects()?;
        Ok(PreparedLocalSession {
            registry: self,
            index,
            active: ActiveSession {
                identities,
                scope,
                execution,
                server,
            },
            client,
        })
    }

    fn index(&self, id: LocalSessionId) -> Result<usize, LocalSessionError> {
        self.slots
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|session| session.identities.id == id)
            })
            .ok_or(LocalSessionError::UnknownSession)
    }

    fn generate_identities(
        &self,
        scope: LocalSessionScope,
    ) -> Result<SessionIdentities, LocalSessionError> {
        for _ in 0..MAXIMUM_IDENTITY_ATTEMPTS {
            let mut random = [0_u8; 64];
            OsRng
                .try_fill_bytes(&mut random)
                .map_err(|_| LocalSessionError::EntropyUnavailable)?;
            if random[..32].iter().all(|byte| *byte == 0) {
                continue;
            }
            let mut id = [0_u8; 16];
            id.copy_from_slice(&random[32..48]);
            let mut capability = [0_u8; 16];
            capability.copy_from_slice(&random[48..]);
            // Match the portable UUIDv4 profile without infallible UUID entropy.
            for bytes in [&mut id, &mut capability] {
                bytes[6] = (bytes[6] & 0x0f) | 0x40;
                bytes[8] = (bytes[8] & 0x3f) | 0x80;
            }
            let mut hash = Sha256::new();
            hash.update(CHANNEL_DOMAIN);
            hash.update(&random[..32]);
            hash.update(id);
            hash.update(capability);
            hash.update(scope.holder.as_bytes());
            hash.update(scope.project.as_bytes());
            hash.update(scope.sandbox.as_bytes());
            hash.update(scope.incarnation.as_bytes());
            hash.update(scope.epoch.get().to_be_bytes());
            hash.update(scope.cache_resource.as_bytes());
            let identities = SessionIdentities {
                id: LocalSessionId(id),
                capability: CapabilityId::from_bytes(capability),
                binding: ChannelBinding::new(hash.finalize().into()),
            };
            if !self.slots.iter().flatten().any(|active| {
                active.identities.id == identities.id
                    || active.identities.capability == identities.capability
                    || active.identities.binding == identities.binding
            }) {
                return Ok(identities);
            }
        }
        Err(LocalSessionError::IdentityCollision)
    }
}

fn validate_scope(scope: LocalSessionScope) -> Result<(), LocalSessionError> {
    if [
        scope.holder.as_bytes(),
        scope.project.as_bytes(),
        scope.sandbox.as_bytes(),
        scope.incarnation.as_bytes(),
        scope.cache_resource.as_bytes(),
    ]
    .iter()
    .any(|id| **id == [0; 16])
        || scope.epoch.get() == 0
    {
        return Err(LocalSessionError::InvalidScope);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct SessionIdentities {
    id: LocalSessionId,
    capability: CapabilityId,
    binding: ChannelBinding,
}

struct ActiveSession {
    identities: SessionIdentities,
    scope: LocalSessionScope,
    execution: SessionExecutionScope,
    server: SeqpacketSocket,
}

/// Keeps origin evidence intact without treating an old observation as current authority.
enum SessionExecutionScope {
    TrustedAdministration(RetainedCgroupAnchor),
    CurrentRuntime(Box<crate::runtime_scope::CurrentRuntimeScope>),
}

impl SessionExecutionScope {
    fn anchor(&self) -> &RetainedCgroupAnchor {
        match self {
            Self::TrustedAdministration(anchor) => anchor,
            Self::CurrentRuntime(runtime) => runtime.observed().anchor(),
        }
    }

    fn runtime(&self) -> Option<&crate::runtime_scope::CurrentRuntimeScope> {
        match self {
            Self::TrustedAdministration(_) => None,
            Self::CurrentRuntime(runtime) => Some(runtime),
        }
    }

    fn check_pins(&self) -> Result<(), LocalSessionError> {
        if let Some(runtime) = self.runtime() {
            runtime.observed().recheck()?;
        } else {
            self.anchor().validate_current()?;
        }
        Ok(())
    }
}

/// Holds an exclusive free slot and undisclosed endpoints pending durable installation.
///
/// Dropping preparation closes both endpoints and leaves the table unchanged.
pub(crate) struct PreparedLocalSession<'a> {
    registry: &'a mut LocalSessionRegistry,
    index: usize,
    active: ActiveSession,
    client: OwnedFd,
}

impl PreparedLocalSession<'_> {
    pub(crate) fn session_id(&self) -> LocalSessionId {
        self.active.identities.id
    }

    pub(crate) fn capability_id(&self) -> CapabilityId {
        self.active.identities.capability
    }

    pub(crate) fn channel_binding(&self) -> ChannelBinding {
        self.active.identities.binding
    }

    pub(crate) fn scope(&self) -> &LocalSessionScope {
        &self.active.scope
    }

    pub(crate) fn check_pending_anchor(&self) -> Result<(), LocalSessionError> {
        self.active.execution.check_pins()
    }

    pub(crate) fn runtime(&self) -> Option<&crate::runtime_scope::CurrentRuntimeScope> {
        self.active.execution.runtime()
    }

    /// Installs the prebuilt entry without allocation after capability durability.
    pub(crate) fn activate(self) -> LocalSessionEndpoint {
        let endpoint = LocalSessionEndpoint {
            client: self.client,
            identities: self.active.identities,
        };
        self.registry.slots[self.index] = Some(self.active);
        endpoint
    }
}

/// Owns the client endpoint whose delivery belongs to the controller.
///
/// Disclosure of metadata is not endpoint possession. Transferring this socket
/// delegates possession; every received record still undergoes cgroup checks.
#[derive(Debug)]
pub struct LocalSessionEndpoint {
    client: OwnedFd,
    identities: SessionIdentities,
}

impl LocalSessionEndpoint {
    /// Returns the process-local channel lookup handle.
    #[must_use]
    pub const fn session_id(&self) -> LocalSessionId {
        self.identities.id
    }

    /// Returns the capability handle requiring current protected lookup.
    #[must_use]
    pub const fn capability_id(&self) -> CapabilityId {
        self.identities.capability
    }

    /// Returns the server-minted channel binding.
    #[must_use]
    pub const fn channel_binding(&self) -> ChannelBinding {
        self.identities.binding
    }

    /// Transfers ownership of the endpoint for delivery to its intended holder.
    #[must_use]
    pub fn into_fd(self) -> OwnedFd {
        self.client
    }
}

/// Borrows a live channel while retaining one authenticated kernel-subject record.
///
/// This non-cloneable observation does not grant effects or prove current
/// capability/policy generations. All scope fields originate in the installed
/// session, never in a caller-selected record header.
///
/// ```compile_fail
/// use aos_sandbox::local_sessions::AuthenticatedLocalRecord;
/// fn duplicate<'a>(record: &AuthenticatedLocalRecord<'a>) -> AuthenticatedLocalRecord<'a> {
///     record.clone()
/// }
/// ```
///
/// The live borrow also prevents invalidation through the same table before the
/// authenticated record's last use:
///
/// ```compile_fail
/// use aos_sandbox::local_sessions::{LocalSessionId, LocalSessionRegistry};
/// fn invalidate_during_use(table: &mut LocalSessionRegistry, id: LocalSessionId) {
///     let record = table.receive(id).unwrap();
///     table.invalidate(id).unwrap();
///     println!("{}", record.payload().len());
/// }
/// ```
pub struct AuthenticatedLocalRecord<'a> {
    session: &'a mut ActiveSession,
    record: ReceivedRecord,
    payload_offset: usize,
    process_info: PidFdInfo,
}

impl AuthenticatedLocalRecord<'_> {
    pub(crate) fn runtime_origin(&self) -> Option<&crate::runtime_scope::CurrentRuntimeScope> {
        self.session.execution.runtime()
    }

    pub(crate) fn runtime_issuance(
        &self,
    ) -> Option<crate::publisher_authority::RuntimeIssuanceEvidenceV1> {
        self.session
            .execution
            .runtime()
            .map(crate::publisher_authority::RuntimeIssuanceEvidenceV1::from_scope)
    }

    /// Borrows the historical holder decision retained at runtime-backed issuance.
    ///
    /// Trusted-administration sessions return `None`. This identifies the
    /// channel's origin, not a current assignment or refreshed ownership lease.
    #[must_use]
    pub fn runtime_binding(&self) -> Option<&crate::runtime_authority::RuntimeAuthorityBindingV1> {
        self.session
            .execution
            .runtime()
            .map(crate::runtime_scope::CurrentRuntimeScope::binding)
    }

    /// Closes ingress immediately; a later receive removes the closed slot.
    pub(crate) fn close_channel(&mut self) {
        self.session.server.close();
    }

    /// Returns only the application payload after the checked frame header.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.record.payload()[self.payload_offset..]
    }

    /// Returns the installed session handle.
    #[must_use]
    pub const fn session_id(&self) -> LocalSessionId {
        self.session.identities.id
    }

    /// Returns the installed capability handle, not a grant.
    #[must_use]
    pub const fn capability_id(&self) -> CapabilityId {
        self.session.identities.capability
    }

    /// Returns the installed server-minted channel binding.
    #[must_use]
    pub const fn channel_binding(&self) -> ChannelBinding {
        self.session.identities.binding
    }

    /// Returns the controller-resolved scope snapshot.
    #[must_use]
    pub const fn scope(&self) -> &LocalSessionScope {
        &self.session.scope
    }

    /// Returns the pidfd information observed during the initial receive.
    #[must_use]
    pub const fn process_info(&self) -> PidFdInfo {
        self.process_info
    }

    /// Reobserves the retained record subject's execution scope using the same pidfd.
    ///
    /// This repeats strict hint resolution and membership checks rather than
    /// treating the earlier process-information snapshot as continuously valid.
    /// It grants no application principal or current capability authority and
    /// does not fence migration, exit, or removal after the observation.
    ///
    /// # Errors
    ///
    /// Returns a framing or membership error if the retained subject no longer
    /// satisfies the installed scope. A shared record borrow cannot invalidate
    /// its session: the caller must discard the record and then invalidate the
    /// session before further use after a failure.
    pub fn recheck_execution_scope(&self) -> Result<PidFdInfo, LocalSessionError> {
        crate::local_channel::check_connected(&self.session.server)?;
        let (_, info) = frame::validate(self.session, &self.record)?;
        crate::local_channel::check_connected(&self.session.server)?;
        Ok(info)
    }
}
