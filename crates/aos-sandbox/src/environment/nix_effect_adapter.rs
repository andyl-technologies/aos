//! Protected adapter for dormant constrained Nix build effects.
//!
//! The adapter owns no daemon connection and is not installed by any runtime.
//! A future service may inject a qualified backend. The adapter itself owns the
//! fixed qualified platform clock. Every
//! call checks the lifetime-bound journal handoff against live boot time before
//! dispatch and again before it reports that protected observation is required.

use aos_sandbox_core::ObjectDigest;

use super::{
    DormantNixBuildEffectV1, EnvironmentExecutionErrorV1, FixedLiveAuthorityClockV1,
    NixBuildAuthorityFenceV1, NixBuildEffectHandoffV1, NixBuildEffectOutcomeV1, NixBuildPolicyV1,
    NixBuildStateV1, ReadOnlyNixStorePresentationV1, fixed_live_authority_clock_v1,
};

/// Presents the exact protected inputs to an injected physical build backend.
pub struct ProtectedNixBuildInvocationV1<'handoff> {
    state: &'handoff NixBuildStateV1,
    policy: NixBuildPolicyV1,
    fence: NixBuildAuthorityFenceV1,
    client_boundary: super::NixClientBoundaryV1,
    presentation: &'handoff ReadOnlyNixStorePresentationV1,
    transaction: ObjectDigest,
}

impl ProtectedNixBuildInvocationV1<'_> {
    /// Borrows the exact durable request state.
    #[must_use]
    pub const fn state(&self) -> &NixBuildStateV1 {
        self.state
    }

    /// Returns the fixed protected build policy.
    #[must_use]
    pub const fn policy(&self) -> NixBuildPolicyV1 {
        self.policy
    }

    /// Returns the live boot-time authority fence.
    #[must_use]
    pub const fn authority_fence(&self) -> NixBuildAuthorityFenceV1 {
        self.fence
    }

    /// Returns the complete protected client/proxy boundary the backend must enforce.
    #[must_use]
    pub const fn client_boundary(&self) -> super::NixClientBoundaryV1 {
        self.client_boundary
    }

    /// Returns the client configuration commitment embedded in the protected capability.
    #[must_use]
    pub fn client_boundary_commitment(&self) -> ObjectDigest {
        self.client_boundary.commitment()
    }

    /// Borrows the complete protected read-only store presentation.
    #[must_use]
    pub const fn presentation(&self) -> &ReadOnlyNixStorePresentationV1 {
        self.presentation
    }

    /// Returns the exact committed pre-effect transaction.
    #[must_use]
    pub const fn transaction_commitment(&self) -> ObjectDigest {
        self.transaction
    }
}

/// Defines the injected physical boundary behind the protected adapter.
pub trait ProtectedNixBuildBackendV1 {
    /// Backend diagnostic retained only with outcome-unknown state.
    type Error;

    /// Starts one exact constrained request without accepting paths or options.
    ///
    /// The backend must enforce the protected endpoint, store trust domain,
    /// fixed daemon settings or closed proxy verbs, denied authorities, bounds,
    /// and boot-scoped currentness as one indivisible boundary.
    ///
    /// # Errors
    ///
    /// Returns a backend diagnostic only when protected observation is still
    /// required before retry can be classified.
    fn apply(&mut self, invocation: ProtectedNixBuildInvocationV1<'_>) -> Result<(), Self::Error>;
}

/// Identifies why an injected build effect remains outcome-unknown.
#[derive(Debug)]
pub enum ProtectedNixBuildEffectErrorV1<E> {
    /// Live boot-clock sampling failed before or after dispatch.
    Clock,
    /// The current boot-time sample fell outside the protected authority.
    AuthorityFence,
    /// The physical backend returned without a protected observation.
    Backend(E),
}

impl<E: std::fmt::Display> std::fmt::Display for ProtectedNixBuildEffectErrorV1<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clock => formatter.write_str("live Nix effect clock is unavailable"),
            Self::AuthorityFence => {
                formatter.write_str("Nix effect authority fence is not current")
            }
            Self::Backend(error) => write!(formatter, "Nix effect outcome is unknown: {error}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ProtectedNixBuildEffectErrorV1<E> {}

/// Adapts an injected physical build backend to the protected dormant effect.
pub struct ProtectedNixBuildEffectAdapterV1<B> {
    backend: B,
    clock: FixedLiveAuthorityClockV1,
}

impl<B> ProtectedNixBuildEffectAdapterV1<B> {
    /// Constructs a dormant adapter without registering it with any service.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            clock: fixed_live_authority_clock_v1(),
        }
    }

    /// Returns the injected components without applying an effect.
    #[must_use]
    pub fn into_backend(self) -> B {
        self.backend
    }
}

impl<B> DormantNixBuildEffectV1 for ProtectedNixBuildEffectAdapterV1<B>
where
    B: ProtectedNixBuildBackendV1,
{
    type Error = ProtectedNixBuildEffectErrorV1<B::Error>;

    fn apply(
        &mut self,
        handoff: NixBuildEffectHandoffV1<'_>,
    ) -> Result<NixBuildEffectOutcomeV1<Self::Error>, EnvironmentExecutionErrorV1> {
        let before = match self.clock.sample() {
            Ok(sample) => sample,
            Err(_) => {
                return NixBuildEffectOutcomeV1::outcome_unknown(
                    handoff,
                    ProtectedNixBuildEffectErrorV1::Clock,
                );
            }
        };
        if !handoff.authority_fence().admits(before) {
            return NixBuildEffectOutcomeV1::outcome_unknown(
                handoff,
                ProtectedNixBuildEffectErrorV1::AuthorityFence,
            );
        }
        if !handoff.client_boundary().matches_policy(handoff.policy()) {
            return NixBuildEffectOutcomeV1::outcome_unknown(
                handoff,
                ProtectedNixBuildEffectErrorV1::AuthorityFence,
            );
        }

        let invocation = ProtectedNixBuildInvocationV1 {
            state: handoff.state(),
            policy: handoff.policy(),
            fence: handoff.authority_fence(),
            client_boundary: handoff.client_boundary(),
            presentation: handoff.presentation(),
            transaction: handoff.transaction_commitment(),
        };
        let backend = self.backend.apply(invocation);
        let after = self.clock.sample();

        match (backend, after) {
            (Ok(()), Ok(sample))
                if sample.boot() == before.boot()
                    && sample.boottime_nanoseconds() >= before.boottime_nanoseconds()
                    && handoff.authority_fence().admits(sample) =>
            {
                NixBuildEffectOutcomeV1::observation_required(handoff)
            }
            (Err(error), _) => NixBuildEffectOutcomeV1::outcome_unknown(
                handoff,
                ProtectedNixBuildEffectErrorV1::Backend(error),
            ),
            (Ok(()), Err(_)) => NixBuildEffectOutcomeV1::outcome_unknown(
                handoff,
                ProtectedNixBuildEffectErrorV1::Clock,
            ),
            (Ok(()), Ok(_)) => NixBuildEffectOutcomeV1::outcome_unknown(
                handoff,
                ProtectedNixBuildEffectErrorV1::AuthorityFence,
            ),
        }
    }
}
