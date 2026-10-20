//! Names local holder lookup and scope DATA without authenticating a channel.
//!
//! A lookup ID does not establish possession of its socket. Scope and slot
//! limits do not authorize issuance, native membership or Publisher effects;
//! the actual retained owner must perform its independent protected checks.

use aos_sandbox_core::{
    AssignmentEpoch, IncarnationId, PrincipalId, ProjectId, ResourceId, SandboxId,
};

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
