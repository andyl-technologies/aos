//! Retains current-token checks and one invocation's pending history inputs.
//!
//! These private carriers grant no ACL, root, epoch or publication authority.
//! Current authorization still decides those permissions after the owning history
//! walk and its actual physical, selected and Original inputs close together.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use terrane_format::auth::{self, IssuerKey, Verb};
use terrane_format::gc::publication::evidence::{PhysicalRegistration, RequiredControlPin};
use terrane_format::identity::Digest;
use terrane_format::provenance::VerifiedHistory;
use terrane_format::refs::RefRecord;

use super::{Guard, HistoryObservation, denied, invalid};
use crate::bucket::{
    BucketBinding,
    publication::{SelectedObservation, receipts::RecordRead},
};
use crate::store::LocalFs;
use crate::store::{Clock, NativeEffectClock, Store, StoreFailure};

mod store;

#[cfg(test)]
mod tests;

pub(in crate::guard) use store::CurrentHistoryStore;

fn unavailable() -> StoreFailure {
    StoreFailure::new(crate::store::StoreErrorKind::Unavailable { retry_after: None })
}

/// Retains genuine configured authentication inputs before current-policy I/O.
///
/// Each clone belongs to the same authorization invocation. This capability
/// checks token authenticity and current time only; it never authorizes a
/// request, substitutes a completed history, or starts a writer deadline.
#[derive(Clone)]
pub(crate) struct PendingCurrentReadCheck {
    inputs: Arc<CurrentTokenInputs>,
}

struct CurrentTokenInputs {
    clock: NativeEffectClock,
    keys: Vec<IssuerKey>,
    token: Vec<u8>,
    subject: String,
    reference: String,
    verb: Verb,
    paired_check: Option<crate::selected_bridge::OwnedFinalCheck>,
    paired_binding: Option<Arc<()>>,
}

impl PendingCurrentReadCheck {
    /// Captures actual configured inputs after genuine initial authentication.
    ///
    /// # Errors
    /// Preserves invalid token, retired issuer, expiry and unavailable retained
    /// clock failures. No repository permission is established by this check.
    pub(in crate::guard) fn capture<S: Store, C: Clock>(
        guard: &Guard<S, C>,
        reference: &str,
        token: &[u8],
        verb: Verb,
    ) -> Result<Self, StoreFailure> {
        let now = guard.now(reference, verb)?;
        let verified =
            auth::verify(token, &guard.keys, now).map_err(|_| denied(reference, verb))?;
        let clock = guard
            .clock
            .retain_native_clock()
            .map_err(super::time::retention_failure)?;
        let check = Self {
            inputs: Arc::new(CurrentTokenInputs {
                clock,
                keys: guard.keys.clone(),
                token: token.to_vec(),
                subject: verified.authority().subject.clone(),
                reference: reference.to_owned(),
                verb,
                paired_check: None,
                paired_binding: None,
            }),
        };
        check.recheck()?;
        Ok(check)
    }

    /// Requires this invocation's exact originally authenticated reference.
    ///
    /// # Errors
    /// Refuses a substituted reference or failed fresh authentication.
    pub(in crate::guard) fn check_reference(&self, reference: &str) -> Result<(), StoreFailure> {
        if reference != self.inputs.reference {
            return Err(invalid());
        }
        self.recheck()
    }

    /// Reauthenticates the exact token with actual configured keys at fresh time.
    ///
    /// # Errors
    /// Rejects unavailable time, retired or ambiguous issuer rows, invalid token
    /// signatures, expiry and a changed authenticated principal.
    pub(crate) fn recheck(&self) -> Result<(), StoreFailure> {
        let inputs = &self.inputs;
        if let Some(check) = &inputs.paired_check {
            check.recheck()?;
        }
        let refuse = || denied(&inputs.reference, inputs.verb);
        let now = inputs
            .clock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| refuse())?
            .as_secs();
        let verified = auth::verify(&inputs.token, &inputs.keys, now).map_err(|_| refuse())?;
        if verified.authority().subject != inputs.subject {
            return Err(refuse());
        }
        if let Some(check) = &inputs.paired_check {
            check.recheck()?;
        }
        Ok(())
    }

    /// Binds the genuine paired predicates before this fresh invocation is shared.
    ///
    /// # Errors
    /// Refuses an already shared or previously bound token capture and changed
    /// source current authority, signer window or original operation deadline.
    pub(in crate::guard) fn with_paired_transition(
        mut self,
        transition: &crate::selected_bridge::native_guard::disclosure::GuardTransition<'_>,
    ) -> Result<Self, StoreFailure> {
        self.recheck()?;
        let inputs = Arc::get_mut(&mut self.inputs).ok_or_else(invalid)?;
        if inputs.paired_check.is_some() {
            return Err(invalid());
        }
        inputs.paired_check = Some(transition.retained_check()?);
        inputs.paired_binding = Some(transition.read_binding());
        self.recheck()?;
        Ok(self)
    }

    /// Requires the exact closed paired purpose or genuine ordinary absence.
    ///
    /// # Errors
    /// Refuses a bare capture for paired work, another proof, paired evidence
    /// used by an ordinary close, or failed fresh predicates.
    pub(crate) fn check_paired_transition(
        &self,
        transition: Option<&crate::selected_bridge::native_guard::disclosure::GuardTransition<'_>>,
    ) -> Result<(), StoreFailure> {
        match transition {
            Some(transition) => {
                let binding = transition.read_binding();
                if !self
                    .inputs
                    .paired_binding
                    .as_ref()
                    .is_some_and(|actual| Arc::ptr_eq(actual, &binding))
                    || self.inputs.paired_check.is_none()
                {
                    return Err(invalid());
                }
            }
            None if self.inputs.paired_binding.is_some() || self.inputs.paired_check.is_some() => {
                return Err(invalid());
            }
            None => {}
        }
        self.recheck()
    }

    /// Requires the original authentication capture for this invocation.
    ///
    /// # Errors
    /// Refuses an independently captured check even when token bytes match.
    pub(crate) fn same_invocation(&self, other: &Self) -> Result<(), StoreFailure> {
        if !Arc::ptr_eq(&self.inputs, &other.inputs) {
            return Err(invalid());
        }
        self.recheck()
    }

    /// Retains the same genuine injected clock for the actual held Guard.
    ///
    /// # Errors
    /// Preserves failed retention or current token authentication.
    pub(in crate::guard) fn retained_clock(&self) -> Result<NativeEffectClock, StoreFailure> {
        self.recheck()?;
        self.inputs
            .clock
            .retain_native_clock()
            .map_err(super::time::retention_failure)
    }

    /// Requires the actual captured Guard to carry the same configured issuer rows.
    ///
    /// # Errors
    /// Refuses substituted issuer identifiers, public keys, retirement rows or
    /// a different configured inventory before native history I/O.
    pub(in crate::guard) fn check_configured_keys(
        &self,
        keys: &[IssuerKey],
    ) -> Result<(), StoreFailure> {
        let same = self.inputs.keys.len() == keys.len()
            && self.inputs.keys.iter().zip(keys).all(|(left, right)| {
                left.issuer == right.issuer
                    && left.key_id == right.key_id
                    && left.public_key == right.public_key
                    && left.retirement == right.retirement
            });
        if !same {
            return Err(invalid());
        }
        self.recheck()
    }

    /// Uses the production capture path for isolated native reader tests.
    ///
    /// # Errors
    /// Preserves every genuine authentication and retained-clock failure.
    #[cfg(test)]
    pub(crate) fn for_guard<S: Store, C: Clock>(
        guard: &Guard<S, C>,
        reference: &str,
        token: &[u8],
        verb: Verb,
    ) -> Result<Self, StoreFailure> {
        Self::capture(guard, reference, token, verb)
    }
}

/// Binds one current-history walk to its actual whole ref and held observation.
///
/// Borrowing this purpose retains no permission. A candidate or maintenance
/// observation cannot construct it, and a new authorization receives a new
/// purpose even when its immutable commit identity is unchanged.
pub(crate) struct CurrentPurpose<'history, 'held> {
    record: RefRecord,
    observation: HistoryObservation<'history>,
    selected: &'history SelectedObservation<'held>,
    current: PendingCurrentReadCheck,
}

impl<'history, 'held> CurrentPurpose<'history, 'held> {
    /// Binds only an actual current-purpose held observation and exact whole ref.
    ///
    /// # Errors
    /// Refuses missing or foreign held/resolver inputs, candidate or maintenance
    /// purposes, and failed fresh token authentication.
    pub(in crate::guard) async fn capture<F, B, V>(
        held: &crate::bucket::held::HeldBucket<'_, F, B, V, false>,
        selected: &'history SelectedObservation<'held>,
        reference: &str,
        record: &RefRecord,
        observation: HistoryObservation<'history>,
        current: PendingCurrentReadCheck,
    ) -> Result<Self, StoreFailure>
    where
        F: LocalFs + BucketBinding,
        B: Clock + BucketBinding,
        V: crate::store::ContentValidator + BucketBinding,
    {
        observation.same_current_scope(observation)?;
        current.recheck()?;
        if reference != current.inputs.reference {
            return Err(invalid());
        }
        if held
            .current_ref_from_observation(selected, reference)
            .await?
            .as_ref()
            != Some(record)
        {
            return Err(invalid());
        }
        let identity = observation.identity().ok_or_else(invalid)?;
        if identity.root() != selected.identity().root()
            || identity.physical_identity() != selected.identity().physical_identity()
            || !std::ptr::eq(
                identity.retained_namespace()?,
                selected.identity().retained_namespace()?,
            )
            || identity.writable()
        {
            return Err(invalid());
        }
        current.recheck()?;
        Ok(Self {
            record: record.clone(),
            observation,
            selected,
            current,
        })
    }

    /// Requires the exact current observation and requested immutable identity.
    ///
    /// # Errors
    /// Refuses changed authentication, a foreign observation or another commit.
    pub(in crate::guard) fn check(
        &self,
        view: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<(), StoreFailure> {
        self.current.recheck()?;
        self.observation.same_current_scope(observation)?;
        if view != self.record.commit {
            return Err(invalid());
        }
        Ok(())
    }

    /// Borrows the genuine token-only check for this current invocation.
    pub(in crate::guard) fn current(&self) -> &PendingCurrentReadCheck {
        &self.current
    }
}

/// Retains the complete semantic walk until the same current inputs close.
///
/// Only the owning disclosure walker supplies these fields. The value grants
/// no current ACL permission and cannot be consumed as candidate history.
pub(crate) struct PendingCurrentHistory<'scope, 'history, 'held> {
    /// The unchanged complete ancestor-first semantic walk awaiting promotion.
    pub(in crate::guard) history: Box<VerifiedHistory>,
    /// The original requested commit identity, never a candidate identity.
    pub(in crate::guard) requested: Digest,
    /// The actual held resolver observation used throughout the walk.
    pub(in crate::guard) observation: HistoryObservation<'history>,
    /// The same current invocation that will supply physical closing evidence.
    pub(in crate::guard) purpose: &'scope CurrentPurpose<'history, 'held>,
    /// The actual sealed data reader whose original recipes must close.
    pub(in crate::guard) reads: &'scope dyn crate::bucket::held::CurrentNodeReads,
    /// Every original contextual view preparation, still unpromoted.
    pub(in crate::guard) pending_uses: BTreeMap<Digest, super::history::completion::PendingViewUse>,
}

/// Pairs successful native physical closure with one exact current invocation.
///
/// Only the factory below initializes this carrier after a genuine physical
/// read projection. It supplies no candidate, mutation or ACL permission.
pub(crate) struct CheckedCurrentHistoryInputs<'scope, 'history, 'held> {
    purpose: &'scope CurrentPurpose<'history, 'held>,
    scope: &'scope dyn crate::bucket::held::CurrentNodeReads,
    pins: Vec<RequiredControlPin>,
    physical: crate::store::native_publication_effects::CurrentHistoryPhysicalInputs<'scope, 'held>,
}

impl<'scope, 'history, 'held> CheckedCurrentHistoryInputs<'scope, 'history, 'held> {
    /// Closes original DATA, selected and protected recipes before making proof.
    ///
    /// # Errors
    /// Refuses foreign scopes, missing controls, changed exact pins or original
    /// physical recipes, incomplete reads, authentication failure and unsupported
    /// native retention. A failed close never produces a completion carrier.
    pub(in crate::guard) async fn close<F: LocalFs + BucketBinding>(
        fs: &F,
        observed: &'scope SelectedObservation<'held>,
        purpose: &'scope CurrentPurpose<'history, 'held>,
        scope: &'scope dyn crate::bucket::held::CurrentNodeReads,
        controls: &[super::RetainedControls],
        original_reads: &[RecordRead],
    ) -> Result<Self, StoreFailure> {
        purpose.check(purpose.record.commit, purpose.observation)?;
        scope.check_holder(purpose.observation.identity().ok_or_else(invalid)?)?;
        scope.check_selection(observed)?;
        scope.check_current(purpose.current())?;
        if !std::ptr::eq(purpose.selected, observed) {
            return Err(invalid());
        }
        let pins = purpose
            .observation
            .resolver()
            .ok_or_else(invalid)?
            .control_pins()?;
        for pin in &pins {
            let PhysicalRegistration::Local(owner) = &pin.owner else {
                return Err(crate::store::StoreFailure::new(
                    crate::store::StoreErrorKind::Unsupported,
                ));
            };
            let record = controls
                .iter()
                .filter(|retained| {
                    retained.directory().as_os_str().as_encoded_bytes() == owner.control.as_slice()
                })
                .find_map(|retained| {
                    retained
                        .records()
                        .iter()
                        .find(|record| record.path() == retained.directory().join(&pin.key))
                })
                .ok_or_else(invalid)?;
            pin.check_record(record.bytes()).map_err(|_| invalid())?;
        }

        let payload_reads = scope.begin_closing()?;
        let physical = crate::store::native_publication_effects::close_current_history_inputs(
            fs,
            observed,
            controls,
            original_reads,
            payload_reads,
            purpose.current(),
        )
        .await?;
        let checked = Self {
            purpose,
            scope,
            pins,
            physical,
        };
        checked.check_reader_scope(scope)?;
        scope.complete_current_closing(&checked)?;
        Ok(checked)
    }

    /// Requires this proof's exact reader, invocation and unchanged consumed pins.
    ///
    /// # Errors
    /// Refuses a foreign reader, holder or selected observation, changed resolver
    /// pins and a failed genuine token or time recheck.
    pub(crate) fn check_reader_scope(
        &self,
        scope: &dyn crate::bucket::held::CurrentNodeReads,
    ) -> Result<(), StoreFailure> {
        self.purpose
            .check(self.purpose.record.commit, self.purpose.observation)?;
        if !std::ptr::addr_eq(self.scope, scope) {
            return Err(invalid());
        }
        if !std::ptr::eq(self.purpose.selected, self.physical.observed()) {
            return Err(invalid());
        }
        scope.check_holder(self.purpose.observation.identity().ok_or_else(invalid)?)?;
        scope.check_selection(self.physical.observed())?;
        scope.check_current(self.purpose.current())?;
        if self
            .purpose
            .observation
            .resolver()
            .ok_or_else(invalid)?
            .control_pins()?
            != self.pins
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Copies opaque configured Original contexts solely for physical prefetch.
    ///
    /// This input inventory grants no history completion or current permission.
    /// Each owning walker still revalidates every reached Original independently.
    ///
    /// # Errors
    /// Preserves unavailable synchronized Original configuration.
    pub(crate) fn original_history_control_contexts(
        &self,
    ) -> Result<Vec<super::OriginalCommitContext>, StoreFailure> {
        Ok(self
            .original_commits
            .read()
            .map_err(|_| unavailable())?
            .values()
            .cloned()
            .collect())
    }

    /// Preserves genuine Original state while installing one current read adapter.
    ///
    /// # Errors
    /// Refuses unavailable synchronized Original state rather than dropping it
    /// when the canonical reader is rebound to the same held invocation.
    pub(in crate::guard) fn current_history_guard<T, D>(
        &self,
        store: T,
        clock: D,
    ) -> Result<Guard<T, D>, StoreFailure> {
        let guard = self.read_configuration_adapter(store, clock);
        *guard.original_verifier.write().map_err(|_| unavailable())? = self
            .original_verifier
            .read()
            .map_err(|_| unavailable())?
            .clone();
        *guard
            .original_baselines
            .write()
            .map_err(|_| unavailable())? = self
            .original_baselines
            .read()
            .map_err(|_| unavailable())?
            .clone();
        *guard.original_commits.write().map_err(|_| unavailable())? = self
            .original_commits
            .read()
            .map_err(|_| unavailable())?
            .clone();
        Ok(guard)
    }

    /// Promotes the original semantic walk after its exact current inputs close.
    ///
    /// No awaited operation separates physical closing from this owning check.
    /// The caller still performs ordinary current ACL and request authorization.
    ///
    /// # Errors
    /// Refuses foreign purposes, changed current inputs or conflicting contextual
    /// preparations without promoting any pending view.
    pub(in crate::guard) fn promote_current_history<'scope, 'history, 'held>(
        &self,
        pending: PendingCurrentHistory<'scope, 'history, 'held>,
        checked: CheckedCurrentHistoryInputs<'scope, 'history, 'held>,
    ) -> Result<VerifiedHistory, StoreFailure> {
        if !std::ptr::eq(pending.purpose, checked.purpose) {
            return Err(invalid());
        }
        pending
            .purpose
            .check(pending.requested, pending.observation)?;
        checked.check_reader_scope(pending.reads)?;
        self.promote_prepared_view_inputs::<false, false>(
            pending.requested,
            pending.observation,
            pending.pending_uses,
            &pending.history,
        )?;
        Ok(*pending.history)
    }
}
