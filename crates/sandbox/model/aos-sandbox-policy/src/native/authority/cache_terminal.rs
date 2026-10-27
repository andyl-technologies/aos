//! Rejoins ordinary Root gen1 with the actual fixed readonly Cache observation.
//!
//! Cache owns its complete native read and independent final mount post. This
//! finite Root receiver preserves the original gen1 precheck and positive-only
//! postcheck around that work. Returned failures keep their owning types; a
//! later final-mount refusal never replaces the first Cache or Root cause.

use aos_sandbox_broker::receiving::RootQ04OriginPurposeV1;
use aos_sandbox_cache::{
    CacheQ04ErrorV1, CacheResidencyProtectedJournalErrorV1, CacheResidencyRootReadOnlyPolicyHoldV1,
    CacheRootQ04TerminalObservationV1, Q04RootCacheTerminalRequestV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::{RootAuthorityErrorV1, RootAuthorityGen1LoanV1};

/// Preserves the actual Root or Cache failure at the terminal reader frontier.
#[derive(Debug, thiserror::Error)]
pub enum RootAuthorityCacheTerminalErrorV1 {
    /// The genuine gen1 precheck, its carrier admission or Root post refused.
    #[error(transparent)]
    Authority(#[from] RootAuthorityErrorV1),
    /// The actual fixed Cache reader retained its native or recipe refusal.
    #[error(transparent)]
    Cache(#[from] CacheQ04ErrorV1),
}

// Only a genuine gen1 receiver records this association after its original
// admission. The Arc compares the same opened Root allocation; nonce and cut
// bind this one actual flight/recipe without cloning another native writer.
struct RootAuthorityCacheTerminalAssociationV1 {
    instance: std::sync::Arc<crate::native::journal::PolicyJournalInstanceV1>,
    nonce: [u8; 16],
    cut: aos_sandbox_model::ObjectDigest,
    phase: aos_sandbox_protocol::cache_state::hold_state::q04_recipes::Q04CacheTerminalPhaseV1,
}

/// Retains the actual terminal readback and its independently owed final mount.
///
/// Error extraction transfers the real owning value once. An emptied slot is
/// explicitly absent, not replaced by another error or a successful post.
/// Positive readback DATA cannot authorize settlement, clearance or mutation.
pub struct RootAuthorityCacheTerminalOutcomeV1 {
    readback:
        Option<Result<CacheResidencyRootReadOnlyPolicyHoldV1, RootAuthorityCacheTerminalErrorV1>>,
    final_mount: Option<Result<(), CacheResidencyProtectedJournalErrorV1>>,
    association: Option<RootAuthorityCacheTerminalAssociationV1>,
    primary_failed: bool,
    final_failed: bool,
}

impl RootAuthorityCacheTerminalOutcomeV1 {
    fn new(
        readback: Result<CacheResidencyRootReadOnlyPolicyHoldV1, RootAuthorityCacheTerminalErrorV1>,
        final_mount: Result<(), CacheResidencyProtectedJournalErrorV1>,
        association: Option<RootAuthorityCacheTerminalAssociationV1>,
    ) -> Self {
        Self {
            primary_failed: readback.is_err(),
            final_failed: final_mount.is_err(),
            association,
            readback: Some(readback),
            final_mount: Some(final_mount),
        }
    }

    /// Measures additional same-frame Root and native Cache carrier bytes.
    ///
    /// The four-reader native/model/path geometry remains separately required.
    /// This passive supplier grants no finance, observation or selected route.
    ///
    /// # Errors
    /// Refuses checked carrier arithmetic overflow without observing a writer.
    pub fn receiving_demand_v1() -> Result<ResourceVector, RootAuthorityErrorV1> {
        let geometry = crate::native::PolicyNativeJournalErrorV1::geometry;
        let bytes = CacheRootQ04TerminalObservationV1::receiving_construction_bytes_v1()
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>().checked_mul(3)?))
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<RootAuthorityCacheTerminalAssociationV1>()
                        .checked_mul(2)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<RootAuthorityCacheTerminalErrorV1>().checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Option<Result<(), RootAuthorityErrorV1>>>()
                        .checked_mul(3)?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(geometry)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    /// Borrows only the actual positive readonly hold DATA.
    #[must_use]
    pub fn readback_v1(&self) -> Option<&CacheResidencyRootReadOnlyPolicyHoldV1> {
        self.readback
            .as_ref()
            .and_then(|result| result.as_ref().ok())
    }

    pub(in crate::native) fn require_same_terminal_original_v1(
        &self,
        gen1: &RootAuthorityGen1LoanV1<'_, '_, '_>,
        identity: &aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1,
        kind: crate::q04_data::Q04AcknowledgementKindV1,
    ) -> Result<&CacheResidencyRootReadOnlyPolicyHoldV1, RootAuthorityErrorV1> {
        use aos_sandbox_protocol::cache_state::hold_state::q04_recipes::Q04CacheTerminalPhaseV1 as Phase;
        let expected = match kind {
            crate::q04_data::Q04AcknowledgementKindV1::Settlement => Phase::Released,
            crate::q04_data::Q04AcknowledgementKindV1::Clearance => Phase::Cleared,
            _ => return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into()),
        };
        let association = self
            .association
            .as_ref()
            .ok_or(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut)?;
        if self.is_refused_v1()
            || !std::sync::Arc::ptr_eq(&association.instance, &gen1.current.owner.journal.instance)
            || association.nonce != gen1.current.owner.nonce_data_v1()?
            || association.cut != identity.digest()
            || association.phase != expected
            || !matches!(self.final_mount, Some(Ok(())))
        {
            return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into());
        }
        self.readback_v1()
            .ok_or_else(|| crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into())
    }

    /// Transfers this actual first Root/Cache error once to the enclosing owner.
    #[must_use]
    pub fn take_primary_error_once_v1(&mut self) -> Option<RootAuthorityCacheTerminalErrorV1> {
        if !matches!(self.readback, Some(Err(_))) {
            return None;
        }
        match self.readback.take() {
            Some(Err(error)) => Some(error),
            original => {
                self.readback = original;
                None
            }
        }
    }

    /// Transfers the actual independently owed final-mount error once.
    #[must_use]
    pub fn take_final_mount_error_once_v1(
        &mut self,
    ) -> Option<CacheResidencyProtectedJournalErrorV1> {
        if !matches!(self.final_mount, Some(Err(_))) {
            return None;
        }
        match self.final_mount.take() {
            Some(Err(error)) => Some(error),
            original => {
                self.final_mount = original;
                None
            }
        }
    }

    /// Reports a refused original outcome even after its owning error moved.
    #[must_use]
    pub const fn is_refused_v1(&self) -> bool {
        self.primary_failed || self.final_failed
    }
}

impl RootAuthorityGen1LoanV1<'_, '_, '_> {
    /// Observes terminal Cache history under this genuine ordinary gen1 loan.
    ///
    /// The existing public Q04 route uses ordinary startup and fixed writers.
    /// Selected Prelude admission remains closed; this method refuses that
    /// purpose rather than borrowing an absent selected reader invoice.
    ///
    /// It rechecks Root before native entry. Only a positive native readback
    /// enters the Root postcheck. Every entered Result path then consumes the
    /// Cache carrier's independent final mount post, even after Root refused.
    /// This preserves Result ordering without adding an unwinding guarantee.
    #[must_use]
    pub(in crate::native) fn replay_ordinary_terminal_cache_journals_v1(
        &self,
        request: &Q04RootCacheTerminalRequestV1<'_>,
    ) -> RootAuthorityCacheTerminalOutcomeV1 {
        let entry: Result<(), RootAuthorityErrorV1> = (|| {
            self.recheck()?;
            if self.current.owner.origin.purpose_v1() != RootQ04OriginPurposeV1::Ordinary {
                return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into());
            }
            self.current.owner.journal.admit_role_observation_v1(
                RootAuthorityCacheTerminalOutcomeV1::receiving_demand_v1()?,
            )?;
            Ok(())
        })();
        if let Err(error) = entry {
            return RootAuthorityCacheTerminalOutcomeV1::new(Err(error.into()), Ok(()), None);
        }

        let association = RootAuthorityCacheTerminalAssociationV1 {
            instance: std::sync::Arc::clone(&self.current.owner.journal.instance),
            nonce: self.current.owner.nonce,
            cut: request.identity.digest(),
            phase: request.phase,
        };
        let native = CacheRootQ04TerminalObservationV1::begin_v1(request);
        let root_post = if native.readback_v1().is_ok() {
            Some(self.recheck())
        } else {
            None
        };
        // Root refusal cannot suppress this independently owed native post.
        let outcome = native.finish_native_post_once_v1();
        let readback = match (outcome.readback, root_post) {
            (Err(error), _) => Err(error.into()),
            (Ok(readback), Some(Ok(()))) => Ok(readback),
            (Ok(_), Some(Err(error))) => Err(error.into()),
            // The private branch above records a post exactly when native
            // readback is positive. No caller supplies either discriminator.
            (Ok(_), None) => std::process::abort(),
        };
        RootAuthorityCacheTerminalOutcomeV1::new(readback, outcome.final_mount, Some(association))
    }
}

impl super::RootAuthorityQ04FlightOriginalV1<'_, '_, '_> {
    /// Observes terminal Cache state from this same earned Root history.
    ///
    /// Native History supplies the actual identity, Root5 and completed prefix;
    /// the original accepted flight supplies its independently admitted UID.
    /// No caller provides copied native parts or a phase-success capability.
    ///
    /// # Errors
    /// Preserves actual Root currentness, Claim and Cache-provenance failures,
    /// malformed prehold DATA, or an uncommitted release/settlement prefix.
    /// Entered Cache failures and independent final mount stay in the outcome.
    pub fn replay_original_terminal_cache_v1(
        &mut self,
        kind: crate::q04_data::Q04AcknowledgementKindV1,
        stage: &crate::q04_data::Q04RootStageRecipeV1,
        claim_packet: &[u8],
        prehold_packet: &[u8],
        controller_packet: &[u8],
        source_packet: &[u8],
    ) -> Result<RootAuthorityCacheTerminalOutcomeV1, RootAuthorityErrorV1> {
        use crate::q04_data::{
            PolicyQ04DataErrorV1 as DataError, Q04AcknowledgementKindV1 as Kind,
        };
        use aos_sandbox_protocol::cache_state::hold_state::q04_recipes::Q04CacheTerminalPhaseV1 as Phase;
        let phase = match kind {
            Kind::Settlement => Phase::Released,
            Kind::Clearance => Phase::Cleared,
            _ => return Err(DataError::ChangedCut.into()),
        };
        self.q04_history_v1()?;
        let cache_uid = self.identities_data_v1()?[3];
        self.q04_recheck_original_binding_prefix_v1(stage, source_packet)?;
        self.accept_historical_controller_readback_v1(controller_packet)?;
        let gen1 = self.completed_gen1_after_accepted_v1(controller_packet, source_packet)?;
        let history = self.q04_history_v1()?;
        let identity = history.identity();
        let claim = gen1.verify_claim(claim_packet, identity)?;
        let fields = claim.fields();
        let cache =
            gen1.original_cache_provenance(fields[12], fields[8], stage, identity, cache_uid)?;
        let prehold = crate::q04_data::Q04PreholdInputDataV1::decode(prehold_packet)?;
        let metadata = prehold.fields()[0];
        let release = history.phase_record_v1(5).ok_or(DataError::ChangedCut)?;
        let required = history
            .binding_prefix_end()?
            .checked_add(match kind {
                Kind::Settlement => 3,
                Kind::Clearance => 4,
                _ => return Err(DataError::ChangedCut.into()),
            })
            .ok_or(DataError::Bounds)?;
        if release.phase() != 5 || history.committed() < required {
            return Err(DataError::ChangedCut.into());
        }
        let request = Q04RootCacheTerminalRequestV1 {
            identity,
            phase,
            original_names: aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1::
                from_bytes(&metadata[272..320]).map_err(
                    aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from,
                )?,
            original_next: u64::from_be_bytes(crate::q04_data::fixed(metadata, 480)),
            held: cache.hold(),
            release_authorization: release.digest(),
        };
        Ok(gen1.replay_ordinary_terminal_cache_journals_v1(&request))
    }
}
