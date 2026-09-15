//! Current-authority contracts held across runtime admission and dispatch.

use aos_ability_model::{Binding, MethodReference, Operation};
use aos_ability_validate::CheckedEffectPlan;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::adapter::{InvocationPurpose, ResourceAdmissionEvidence};

/// Names one independently revocable authority required by a runtime invocation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeAuthorityRole {
    /// The consumer identity, exact binding, and caller grant remain authorized.
    CallerBindingGrant,
    /// The selected provider method and exact implementation remain authorized.
    ProviderMethodImplementation,
    /// The promised enforcement and native platform guarantees remain available.
    EnforcementPlatformGuarantee,
    /// The selected provider assignment and resource incarnations remain current.
    AssignmentIncarnation,
    /// The protected current-authority publication itself remains available.
    CurrentAuthorityPublication,
}

/// Names the runtime boundary at which current authority was checked.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityCheckBoundary {
    /// Current invocation authority is checked before acquiring resources.
    BeforeResourceAcquisition,
    /// Current assignments and guarantees are checked under acquired resources.
    AfterResourceAcquisition,
    /// All authority is checked under a fence immediately before adapter dispatch.
    FinalDispatch,
}

/// Associates a current-policy failure with the authority that was revoked.
#[derive(Debug, Error)]
#[error("{role:?} authority rejected the invocation: {source}")]
pub struct AuthorityRejection<Error> {
    role: RuntimeAuthorityRole,
    #[source]
    source: Error,
}

impl<Error> AuthorityRejection<Error> {
    /// Constructs a role-specific current-authority rejection.
    #[must_use]
    pub const fn new(role: RuntimeAuthorityRole, source: Error) -> Self {
        Self { role, source }
    }

    /// Returns the independently revocable authority that rejected the invocation.
    #[must_use]
    pub const fn role(&self) -> RuntimeAuthorityRole {
        self.role
    }

    /// Returns the policy-specific rejection detail.
    #[must_use]
    pub const fn source(&self) -> &Error {
        &self.source
    }

    pub(crate) fn into_parts(self) -> (RuntimeAuthorityRole, Error) {
        (self.role, self.source)
    }
}

/// Revalidates an exact invocation against one current-authority snapshot.
pub trait TrustedAuthoritySnapshot {
    /// Structured current-policy failure type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Authorizes one independently revocable invocation role.
    ///
    /// # Errors
    ///
    /// Returns an error when the snapshot no longer authorizes the role for
    /// the exact binding, method, implementation, or promised guarantees.
    fn authorize_role(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        method: &MethodReference,
        purpose: InvocationPurpose,
        role: RuntimeAuthorityRole,
    ) -> Result<(), Self::Error>;

    /// Authorizes current assignments and observations under held reservations.
    ///
    /// # Errors
    ///
    /// Returns an error when current policy no longer accepts the exact
    /// provider assignments, revisions, or precondition observations.
    fn authorize_resources(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        expected_provider: Option<&aos_ability_model::ProviderAssignment>,
        resources: &[ResourceAdmissionEvidence],
    ) -> Result<(), Self::Error>;
}

/// Revalidates current policy and provider assignment at every admission.
pub trait TrustedAdmissionPolicy: TrustedAuthoritySnapshot {
    /// Holds one current authority generation stable through adapter invocation.
    ///
    /// The fence linearizes revocation either before the returned snapshot is
    /// checked or after the adapter call using it returns. Implementations may
    /// hold an existing protected policy lock or use a monotonic provider fence;
    /// this interface does not create a resource broker or imply handle revocation.
    type DispatchFence: TrustedAuthoritySnapshot<Error = Self::Error>;

    /// Authorizes every independently revocable role for one invocation.
    ///
    /// This convenience method preserves the complete admission check for
    /// callers that do not need role-specific qualification observations.
    /// Runtime dispatch uses [`TrustedAuthoritySnapshot::authorize_role`]
    /// directly so a rejection retains its exact authority role.
    ///
    /// # Errors
    ///
    /// Returns the first current-authority rejection in deterministic role order.
    fn authorize(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> Result<(), Self::Error> {
        for role in [
            RuntimeAuthorityRole::CallerBindingGrant,
            RuntimeAuthorityRole::ProviderMethodImplementation,
            RuntimeAuthorityRole::EnforcementPlatformGuarantee,
            RuntimeAuthorityRole::AssignmentIncarnation,
        ] {
            self.authorize_role(plan, binding, operation, method, purpose, role)?;
        }
        Ok(())
    }

    /// Acquires a current-authority snapshot whose validity is held through dispatch.
    ///
    /// # Errors
    ///
    /// Returns a role-specific error when the fence cannot be acquired under
    /// current authority. The runtime performs all role and resource checks on
    /// the returned snapshot before invoking the adapter.
    fn acquire_dispatch_fence(
        &mut self,
        plan: &CheckedEffectPlan,
        binding: &Binding,
        operation: &Operation,
        method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> Result<Self::DispatchFence, AuthorityRejection<Self::Error>>;
}
