//! Revalidated non-secret provider configuration projection.
//!
//! The projection can be produced only from live protected custody after its
//! retained directory, files, keys, trust, route, and process identity have
//! all been revalidated. It contains public policy and public verification
//! keys only; possession grants no signing, request, effect, or send authority.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SourceProviderAuthorityTrustStateV1, SourceProviderAuthorityV1, SourceProviderKeyTrustStateV1,
    SourceProviderSigningKeyV1,
};

use crate::custody::ProtectedCustodyV1;
use crate::trust_file::ProtectedTrustHeadLinkV2;
use crate::{ProtectedProviderCustodyV1, ProtectedRootMountCustodyV1, SourceProviderSecurityError};

/// Carries one current nonauthorizing projection of protected provider custody.
pub struct RevalidatedProviderConfigurationV1 {
    provider: SourceProviderAuthorityV1,
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
    route_id: [u8; 16],
    route_generation: u64,
    route_digest: ObjectDigest,
    resource_namespace_digest: ObjectDigest,
    provider_hello_signer: SourceProviderSigningKeyV1,
    provider_outcome_signer: SourceProviderSigningKeyV1,
    valid_from_seconds: i64,
    valid_until_seconds: i64,
    proof_class_capabilities: u8,
    supports_recursive: bool,
    supports_kernel_coupled: bool,
    trust_history: Vec<ProtectedTrustHeadLinkV2>,
    historical_public_keys: Vec<HistoricalProviderVerificationKeyV1>,
}

/// Binds one historical verification key to its protected issuance context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalProviderVerificationKeyV1 {
    signer: SourceProviderSigningKeyV1,
    public_key: [u8; 32],
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
    state_effective_trust_generation: u64,
    state_effective_trust_digest: ObjectDigest,
    state_effective_revocation_generation: u64,
    state_effective_revocation_digest: ObjectDigest,
    valid_from_seconds: i64,
    valid_until_seconds: i64,
    state: SourceProviderKeyTrustStateV1,
    superseded_by_key_generation: u64,
    authority_valid_from_seconds: i64,
    authority_valid_until_seconds: i64,
    authority_state: SourceProviderAuthorityTrustStateV1,
    authority_state_effective_trust_generation: u64,
    authority_state_effective_trust_digest: ObjectDigest,
    authority_state_effective_revocation_generation: u64,
    authority_state_effective_revocation_digest: ObjectDigest,
}

impl core::fmt::Debug for RevalidatedProviderConfigurationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RevalidatedProviderConfigurationV1([protected projection])")
    }
}

impl RevalidatedProviderConfigurationV1 {
    /// Returns the exact non-secret configuration commitment used by migration custody.
    ///
    /// The commitment binds provider, trust, revocation, route, namespace,
    /// validity, capability, and current provider signer facts. It carries no
    /// signing or journal authority.
    #[must_use]
    pub fn migration_configuration_commitment_v1(&self) -> ObjectDigest {
        crate::migration::migration_configuration_commitment(self)
    }

    pub(crate) fn capture(
        custody: &mut ProtectedProviderCustodyV1,
        now_seconds: i64,
    ) -> Result<Self, SourceProviderSecurityError> {
        Self::capture_inner(custody.inner_mut(), now_seconds)
    }

    pub(crate) fn capture_root_mount(
        custody: &mut ProtectedRootMountCustodyV1,
        now_seconds: i64,
    ) -> Result<Self, SourceProviderSecurityError> {
        Self::capture_inner(custody.inner_mut(), now_seconds)
    }

    fn capture_inner(
        inner: &mut ProtectedCustodyV1,
        now_seconds: i64,
    ) -> Result<Self, SourceProviderSecurityError> {
        inner.revalidate_at(now_seconds)?;
        let current = inner.provider_authority();
        let trust = inner.trust();
        let route = inner.route();
        let provider = current.authority().clone();
        let authority_trust = trust
            .authorities()
            .iter()
            .find(|entry| {
                entry.authority() == &provider
                    && entry.state() == SourceProviderAuthorityTrustStateV1::Trusted
            })
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let hello = trust
            .keys()
            .iter()
            .find(|entry| entry.signer() == current.hello_signer())
            .filter(|entry| entry.state() == SourceProviderKeyTrustStateV1::Eligible)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let outcome = trust
            .keys()
            .iter()
            .find(|entry| entry.signer() == current.traffic_signer())
            .filter(|entry| entry.state() == SourceProviderKeyTrustStateV1::Eligible)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let valid_from_seconds = authority_trust
            .valid_from_seconds()
            .max(hello.valid_from_seconds())
            .max(outcome.valid_from_seconds());
        let valid_until_seconds = authority_trust
            .valid_until_seconds()
            .min(hello.valid_until_seconds())
            .min(outcome.valid_until_seconds());
        if now_seconds < valid_from_seconds || now_seconds >= valid_until_seconds {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let mut historical_public_keys = Vec::with_capacity(trust.keys().len());
        for entry in trust.keys() {
            let (
                issuance_trust_generation,
                issuance_trust_digest,
                issuance_revocation_generation,
                issuance_revocation_digest,
            ) = inner
                .trust_key_issuance(entry.signer())
                .ok_or(SourceProviderSecurityError::SessionContinuity)?
                .0;
            let (
                state_effective_trust_generation,
                state_effective_trust_digest,
                state_effective_revocation_generation,
                state_effective_revocation_digest,
            ) = inner
                .trust_key_issuance(entry.signer())
                .ok_or(SourceProviderSecurityError::SessionContinuity)?
                .1;
            let key_authority = trust
                .authorities()
                .iter()
                .find(|authority| {
                    authority.authority().authority_id() == entry.signer().authority_id()
                        && authority.authority().authority_generation()
                            == entry.signer().authority_generation()
                        && authority.authority().authority_digest()
                            == entry.signer().authority_digest()
                })
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let (
                authority_state_effective_trust_generation,
                authority_state_effective_trust_digest,
                authority_state_effective_revocation_generation,
                authority_state_effective_revocation_digest,
            ) = inner
                .trust_authority_state_head(key_authority.authority())
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            historical_public_keys.push(HistoricalProviderVerificationKeyV1 {
                signer: entry.signer().clone(),
                public_key: *entry.public_key(),
                trust_generation: issuance_trust_generation,
                trust_digest: issuance_trust_digest,
                revocation_generation: issuance_revocation_generation,
                revocation_digest: issuance_revocation_digest,
                state_effective_trust_generation,
                state_effective_trust_digest,
                state_effective_revocation_generation,
                state_effective_revocation_digest,
                valid_from_seconds: entry.valid_from_seconds(),
                valid_until_seconds: entry.valid_until_seconds(),
                state: entry.state(),
                superseded_by_key_generation: entry.superseded_by_key_generation(),
                authority_valid_from_seconds: key_authority.valid_from_seconds(),
                authority_valid_until_seconds: key_authority.valid_until_seconds(),
                authority_state: key_authority.state(),
                authority_state_effective_trust_generation,
                authority_state_effective_trust_digest,
                authority_state_effective_revocation_generation,
                authority_state_effective_revocation_digest,
            });
        }
        Ok(Self {
            provider,
            trust_generation: trust.trust_generation(),
            trust_digest: trust.trust_digest(),
            revocation_generation: trust.revocation_generation(),
            revocation_digest: trust.revocation_digest(),
            route_id: route.route_id(),
            route_generation: route.route_generation(),
            route_digest: route.route_digest(),
            resource_namespace_digest: route.resource_namespace_digest(),
            provider_hello_signer: current.hello_signer().clone(),
            provider_outcome_signer: current.traffic_signer().clone(),
            valid_from_seconds,
            valid_until_seconds,
            proof_class_capabilities: inner.manifest().proof_capabilities(),
            supports_recursive: inner.manifest().allow_recursive(),
            supports_kernel_coupled: inner.manifest().allow_kernel_coupled(),
            trust_history: inner.trust_history().to_vec(),
            historical_public_keys,
        })
    }

    /// Preserves immutable per-key issuance epochs across protected head advancement.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] if a complete signer identity is
    /// reused with another public key, authority validity, or key validity.
    pub fn reconcile_issuance_history(
        self,
        previous: &[HistoricalProviderVerificationKeyV1],
    ) -> Result<Self, SourceProviderSecurityError> {
        for entry in &self.historical_public_keys {
            if let Some(prior) = previous.iter().find(|prior| prior.signer == entry.signer) {
                if prior.public_key != entry.public_key
                    || prior.trust_generation != entry.trust_generation
                    || prior.trust_digest != entry.trust_digest
                    || prior.revocation_generation != entry.revocation_generation
                    || prior.revocation_digest != entry.revocation_digest
                    || prior.valid_from_seconds != entry.valid_from_seconds
                    || prior.valid_until_seconds != entry.valid_until_seconds
                    || prior.authority_valid_from_seconds != entry.authority_valid_from_seconds
                    || prior.authority_valid_until_seconds != entry.authority_valid_until_seconds
                    || !authenticated_state_transition(prior, entry, &self.trust_history)
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                // Revocation, supersession, and authority eligibility remain
                // refreshed from the newly authenticated protected snapshot.
            }
        }
        Ok(self)
    }

    /// Requires the newly protected trust history to retain a prior history exactly.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] if the retained history is not
    /// an exact prefix of the protected history.
    pub fn require_history_extension(
        self,
        previous: &[ProtectedTrustHeadLinkV2],
    ) -> Result<Self, SourceProviderSecurityError> {
        if previous.len() > self.trust_history.len()
            || self.trust_history[..previous.len()] != *previous
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        Ok(self)
    }

    /// Returns the protected current provider authority.
    #[must_use]
    pub const fn provider(&self) -> &SourceProviderAuthorityV1 {
        &self.provider
    }

    /// Returns the protected trust generation and digest.
    #[must_use]
    pub const fn trust_head(&self) -> (u64, ObjectDigest) {
        (self.trust_generation, self.trust_digest)
    }

    /// Returns the protected revocation generation and digest.
    #[must_use]
    pub const fn revocation_head(&self) -> (u64, ObjectDigest) {
        (self.revocation_generation, self.revocation_digest)
    }

    /// Returns the protected route identity, generation, and digest.
    #[must_use]
    pub const fn route_head(&self) -> ([u8; 16], u64, ObjectDigest) {
        (self.route_id, self.route_generation, self.route_digest)
    }

    /// Returns the protected resource-namespace digest.
    #[must_use]
    pub const fn resource_namespace_digest(&self) -> ObjectDigest {
        self.resource_namespace_digest
    }

    /// Returns the current provider hello signer reference.
    #[must_use]
    pub const fn provider_hello_signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.provider_hello_signer
    }

    /// Returns the current provider outcome signer reference.
    #[must_use]
    pub const fn provider_outcome_signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.provider_outcome_signer
    }

    /// Returns the common protected validity interval.
    #[must_use]
    pub const fn validity(&self) -> (i64, i64) {
        (self.valid_from_seconds, self.valid_until_seconds)
    }

    /// Returns the closed proof-class capability mask.
    #[must_use]
    pub const fn proof_class_capabilities(&self) -> u8 {
        self.proof_class_capabilities
    }

    /// Reports whether recursive source use is protected policy.
    #[must_use]
    pub const fn supports_recursive(&self) -> bool {
        self.supports_recursive
    }

    /// Reports whether kernel-coupled source use is protected policy.
    #[must_use]
    pub const fn supports_kernel_coupled(&self) -> bool {
        self.supports_kernel_coupled
    }

    /// Returns retained historical public verification keys, including tombstoned keys.
    ///
    /// Retention preserves equivocation evidence. Ordinary verification rejects
    /// every revoked key; the separate already-consumed cleanup verifier may
    /// authenticate an artifact only before its independently retained earliest
    /// deactivation head. A superseded key likewise verifies only artifacts
    /// before that authenticated head.
    #[must_use]
    pub fn historical_public_keys(&self) -> &[HistoricalProviderVerificationKeyV1] {
        &self.historical_public_keys
    }

    /// Returns the manifest-authenticated oldest-to-newest trust-head chain.
    #[must_use]
    pub fn trust_history(&self) -> &[ProtectedTrustHeadLinkV2] {
        &self.trust_history
    }

    /// Reports whether one exact historical head is authenticated by the protected chain.
    #[must_use]
    pub fn authenticates_head(
        &self,
        trust_generation: u64,
        trust_digest: ObjectDigest,
        revocation_generation: u64,
        revocation_digest: ObjectDigest,
    ) -> bool {
        self.trust_history.iter().any(|entry| {
            entry.head()
                == (
                    trust_generation,
                    trust_digest,
                    revocation_generation,
                    revocation_digest,
                )
        })
    }

    /// Reports whether one retained key was active at an authenticated historical head.
    ///
    /// The check is cryptographic-policy input only and grants no current
    /// request, signing, journal, effect, descriptor, or send authority.
    #[must_use]
    pub fn authenticates_historical_key_at(
        &self,
        trusted: &HistoricalProviderVerificationKeyV1,
        issued_seconds: i64,
        trust_generation: u64,
        trust_digest: ObjectDigest,
        revocation_generation: u64,
        revocation_digest: ObjectDigest,
    ) -> bool {
        if !self.historical_public_keys.contains(trusted) {
            return false;
        }
        historical_key_active_at(
            &self.trust_history,
            trusted,
            issued_seconds,
            trust_generation,
            trust_digest,
            revocation_generation,
            revocation_digest,
        )
    }

    /// Reports whether a now-revoked key was valid at one durable verification anchor.
    ///
    /// This narrow exception is only an input to already-consumed cleanup
    /// recovery. It never grants current request, use, activation, or signing
    /// authority, and requires the artifact head to precede every applicable
    /// authenticated earliest-deactivation head.
    #[must_use]
    pub(crate) fn authenticates_revoked_cleanup_key_at(
        &self,
        trusted: &HistoricalProviderVerificationKeyV1,
        verified_at_seconds: i64,
        trust_generation: u64,
        trust_digest: ObjectDigest,
        revocation_generation: u64,
        revocation_digest: ObjectDigest,
    ) -> bool {
        if !self.historical_public_keys.contains(trusted) {
            return false;
        }
        historical_cleanup_key_active_at(
            &self.trust_history,
            trusted,
            verified_at_seconds,
            trust_generation,
            trust_digest,
            revocation_generation,
            revocation_digest,
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn historical_key_active_at(
    history: &[ProtectedTrustHeadLinkV2],
    trusted: &HistoricalProviderVerificationKeyV1,
    issued_seconds: i64,
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
) -> bool {
    use aos_sandbox_source_provider_protocol::{
        SourceProviderAuthorityTrustStateV1 as AuthorityState,
        SourceProviderKeyTrustStateV1 as KeyState,
    };

    let artifact = (
        trust_generation,
        trust_digest,
        revocation_generation,
        revocation_digest,
    );
    let issuance = (
        trusted.trust_generation,
        trusted.trust_digest,
        trusted.revocation_generation,
        trusted.revocation_digest,
    );
    let issuance_index = history.iter().position(|head| head.head() == issuance);
    let artifact_index = history.iter().position(|head| head.head() == artifact);
    let Some((issuance_index, artifact_index)) = issuance_index.zip(artifact_index) else {
        return false;
    };
    if trusted.state == KeyState::Revoked || trusted.authority_state == AuthorityState::Revoked {
        return false;
    }
    let key_active = trusted.state == KeyState::Eligible
        || (trusted.state == KeyState::Superseded
            && history
                .iter()
                .position(|head| head.head() == trusted.state_effective_head())
                .is_some_and(|state_index| artifact_index < state_index));
    let authority_active = trusted.authority_state == AuthorityState::Trusted;
    issued_seconds
        >= trusted
            .valid_from_seconds
            .max(trusted.authority_valid_from_seconds)
        && issued_seconds
            < trusted
                .valid_until_seconds
                .min(trusted.authority_valid_until_seconds)
        && issuance_index <= artifact_index
        && key_active
        && authority_active
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn historical_cleanup_key_active_at(
    history: &[ProtectedTrustHeadLinkV2],
    trusted: &HistoricalProviderVerificationKeyV1,
    verified_at_seconds: i64,
    trust_generation: u64,
    trust_digest: ObjectDigest,
    revocation_generation: u64,
    revocation_digest: ObjectDigest,
) -> bool {
    use aos_sandbox_source_provider_protocol::{
        SourceProviderAuthorityTrustStateV1 as AuthorityState,
        SourceProviderKeyTrustStateV1 as KeyState,
    };

    let issuance = (
        trusted.trust_generation,
        trusted.trust_digest,
        trusted.revocation_generation,
        trusted.revocation_digest,
    );
    let artifact = (
        trust_generation,
        trust_digest,
        revocation_generation,
        revocation_digest,
    );
    let Some((issuance_index, artifact_index)) = history
        .iter()
        .position(|head| head.head() == issuance)
        .zip(history.iter().position(|head| head.head() == artifact))
    else {
        return false;
    };
    let key_deactivation_index = history
        .iter()
        .position(|head| head.head() == trusted.state_effective_head());
    let authority_deactivation_index = history
        .iter()
        .position(|head| head.head() == trusted.authority_state_effective_head());
    let key_was_active = match trusted.state {
        KeyState::Eligible => true,
        KeyState::Superseded | KeyState::Revoked => {
            key_deactivation_index.is_some_and(|deactivation| {
                issuance_index < deactivation && artifact_index < deactivation
            })
        }
    };
    let authority_was_active = match trusted.authority_state {
        AuthorityState::Trusted => true,
        AuthorityState::Revoked => authority_deactivation_index.is_some_and(|deactivation| {
            issuance_index < deactivation && artifact_index < deactivation
        }),
    };
    let currently_revoked =
        trusted.state == KeyState::Revoked || trusted.authority_state == AuthorityState::Revoked;
    currently_revoked
        && issuance_index <= artifact_index
        && key_was_active
        && authority_was_active
        && verified_at_seconds
            >= trusted
                .valid_from_seconds
                .max(trusted.authority_valid_from_seconds)
        && verified_at_seconds
            < trusted
                .valid_until_seconds
                .min(trusted.authority_valid_until_seconds)
}

fn authenticated_state_transition(
    prior: &HistoricalProviderVerificationKeyV1,
    next: &HistoricalProviderVerificationKeyV1,
    history: &[ProtectedTrustHeadLinkV2],
) -> bool {
    use aos_sandbox_source_provider_protocol::{
        SourceProviderAuthorityTrustStateV1 as AuthorityState,
        SourceProviderKeyTrustStateV1 as KeyState,
    };

    let (prior_key_state, prior_successor) = prior.state_and_successor();
    let (next_key_state, next_successor) = next.state_and_successor();
    let key_transition = match (prior_key_state, next_key_state) {
        (KeyState::Eligible, KeyState::Eligible) => {
            prior_successor == next_successor
                && prior.state_effective_head() == next.state_effective_head()
        }
        (KeyState::Eligible, KeyState::Superseded | KeyState::Revoked) => head_strictly_descends(
            history,
            prior.state_effective_head(),
            next.state_effective_head(),
        ),
        (KeyState::Superseded, KeyState::Superseded) => {
            prior_successor == next_successor
                && prior.state_effective_head() == next.state_effective_head()
        }
        (KeyState::Superseded, KeyState::Revoked) | (KeyState::Revoked, KeyState::Revoked) => {
            prior.state_effective_head() == next.state_effective_head()
        }
        _ => false,
    };
    let (_, _, prior_authority_state) = prior.authority_issuance();
    let (_, _, next_authority_state) = next.authority_issuance();
    let authority_transition = match (prior_authority_state, next_authority_state) {
        (AuthorityState::Trusted, AuthorityState::Trusted)
        | (AuthorityState::Revoked, AuthorityState::Revoked) => {
            prior.authority_state_effective_head() == next.authority_state_effective_head()
        }
        (AuthorityState::Trusted, AuthorityState::Revoked) => head_strictly_descends(
            history,
            prior.authority_state_effective_head(),
            next.authority_state_effective_head(),
        ),
        _ => false,
    };
    key_transition && authority_transition
}

fn head_strictly_descends(
    history: &[ProtectedTrustHeadLinkV2],
    earlier: (u64, ObjectDigest, u64, ObjectDigest),
    later: (u64, ObjectDigest, u64, ObjectDigest),
) -> bool {
    let earlier_index = history.iter().position(|entry| entry.head() == earlier);
    let later_index = history.iter().position(|entry| entry.head() == later);
    matches!((earlier_index, later_index), (Some(left), Some(right)) if left < right)
}

impl HistoricalProviderVerificationKeyV1 {
    /// Returns the complete signer identity.
    #[must_use]
    pub const fn signer(&self) -> &SourceProviderSigningKeyV1 {
        &self.signer
    }

    /// Returns the exact Ed25519 verification key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns the protected trust head at capture.
    #[must_use]
    pub const fn trust_head(&self) -> (u64, ObjectDigest) {
        (self.trust_generation, self.trust_digest)
    }

    /// Returns the protected revocation head at capture.
    #[must_use]
    pub const fn revocation_head(&self) -> (u64, ObjectDigest) {
        (self.revocation_generation, self.revocation_digest)
    }

    /// Returns the key validity interval.
    #[must_use]
    pub const fn validity(&self) -> (i64, i64) {
        (self.valid_from_seconds, self.valid_until_seconds)
    }

    /// Returns the historical trust state and successor generation.
    #[must_use]
    pub const fn state_and_successor(&self) -> (SourceProviderKeyTrustStateV1, u64) {
        (self.state, self.superseded_by_key_generation)
    }

    /// Returns the authenticated earliest head where the key ceased to be eligible.
    #[must_use]
    pub const fn state_effective_head(&self) -> (u64, ObjectDigest, u64, ObjectDigest) {
        (
            self.state_effective_trust_generation,
            self.state_effective_trust_digest,
            self.state_effective_revocation_generation,
            self.state_effective_revocation_digest,
        )
    }

    /// Returns the issuing authority's historical validity and trust state.
    #[must_use]
    pub const fn authority_issuance(&self) -> (i64, i64, SourceProviderAuthorityTrustStateV1) {
        (
            self.authority_valid_from_seconds,
            self.authority_valid_until_seconds,
            self.authority_state,
        )
    }

    /// Returns the authenticated head where the current authority state took effect.
    #[must_use]
    pub const fn authority_state_effective_head(&self) -> (u64, ObjectDigest, u64, ObjectDigest) {
        (
            self.authority_state_effective_trust_generation,
            self.authority_state_effective_trust_digest,
            self.authority_state_effective_revocation_generation,
            self.authority_state_effective_revocation_digest,
        )
    }
}
