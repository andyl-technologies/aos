//! Acquires a fresh attachment namespace target from protected controller custody.
//!
//! The Host socket is a fixed locator, not a service identity. Trusted startup
//! must provide the exact retained Host cgroup and pinned verification policy;
//! this adapter never derives either from a public request or a socket reply.

use std::path::Path;

use aos_sandbox::Journal;
use aos_sandbox::attachment_effect_owner::{
    ProtectedAttachmentEffectOwnerV1, ProtectedAttachmentTargetErrorV1,
};
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_authority::{
    RuntimeAuthorityError, RuntimeAuthorityStateV1, RuntimeAuthorityStore,
};
use aos_sandbox::runtime_scope::{
    CurrentRuntimeScopePolicy, HostServiceIdentity, NamespaceTargetOutcome, RuntimeScopeClient,
    RuntimeScopeError, RuntimeScopeHolder,
};
use aos_sandbox_core::SandboxId;

use crate::controller_ownership::sample_ownership_clock;

const HOST_SOCKET: &str = "/run/aos/sandbox-host/control.sock";

/// Reports why a production attachment target could not be freshly established.
#[derive(Debug, thiserror::Error)]
pub(super) enum ControllerAttachmentTargetErrorV1 {
    #[error("protected sandbox has no currently bound holder")]
    MissingHolder,
    #[error(transparent)]
    Authority(#[from] RuntimeAuthorityError),
    #[error(transparent)]
    Host(#[from] RuntimeScopeError),
    #[error(transparent)]
    Target(#[from] ProtectedAttachmentTargetErrorV1),
}

/// Consumes independently pinned deployment inputs for one Host observation.
pub(super) struct ControllerAttachmentTargetInputsV1 {
    pub(super) host: HostServiceIdentity,
    pub(super) policy: CurrentRuntimeScopePolicy,
}

impl ControllerAttachmentTargetInputsV1 {
    /// Selects the protected holder and binds a fresh signed namespace target.
    ///
    /// A returned advancement proposal still needs a signed assignment
    /// successor and another observation before any attachment effect can run.
    ///
    /// # Errors
    ///
    /// Rejects unavailable or revoked holder state, Host socket/identity
    /// failure, invalid authority, clock failure, or a changed namespace target.
    pub(super) fn acquire(
        self,
        journal: &mut Journal,
        sandbox: SandboxId,
    ) -> Result<NamespaceTargetOutcome, ControllerAttachmentTargetErrorV1> {
        let binding = RuntimeAuthorityStore::load(journal, self.policy.runtime_limits)?
            .current(sandbox)?
            .ok_or(ControllerAttachmentTargetErrorV1::MissingHolder)?;
        if binding.state() != RuntimeAuthorityStateV1::Bound {
            return Err(ControllerAttachmentTargetErrorV1::MissingHolder);
        }
        let holder = binding
            .holder()
            .ok_or(ControllerAttachmentTargetErrorV1::MissingHolder)?;

        let client = RuntimeScopeClient::connect(Path::new(HOST_SOCKET), self.host)?;
        let mut owner = ProtectedAttachmentEffectOwnerV1::claim(journal)
            .map_err(ProtectedAttachmentTargetErrorV1::from)?;
        let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
        owner
            .observe_current_target(
                RuntimeScopeHolder { sandbox, holder },
                client,
                self.policy,
                &mut clock,
            )
            .map_err(Into::into)
    }
}
