//! Binds one paired authorization to genuinely retained Guard-transition inputs.
//!
//! Only the destination import producer constructs this read purpose. Its
//! source-derived plans and physical controls explain an exact additive role
//! transition; they never grant actor permission or complete a history.

use std::{collections::BTreeMap, sync::Arc};

use super::{DisclosureSource, ImportPlan, check_transition, invalid, role_row};
use crate::bucket::held::{HeldBucket, HeldIdentity};
use crate::bucket::publication::{SelectedObservation, receipts::RecordRead};
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::{
    ConsumedResolver, Guard, HistoryObservation, OriginalAuthority, RetainedControls,
};
use crate::repository::local_authority::retention::Record;
use crate::selected_bridge::{OwnedFinalCheck, native_guard::SharedCheck};
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use terrane_format::auth::Verb;
use terrane_format::gc::publication::{PublicationState, evidence::GuardSnapshot};

/// Borrows the original observations and resolver without checking or granting rights.
pub(super) struct CaptureScope<'a, 'destination, 'source> {
    /// Borrows the actual destination selection retained by the paired producer.
    pub(super) destination: &'a SelectedObservation<'destination>,
    /// Borrows the original source selection captured before source authorization.
    pub(super) source: &'a SelectedObservation<'source>,
    /// Borrows this invocation's independently captured destination resolver.
    pub(super) resolver: &'a ConsumedResolver,
}

/// Borrows only original source recipes from a genuine selected observation.
///
/// This sealed, synchronous view erases the observation's callback lifetime;
/// implementations cannot construct a selection or confer authorization.
pub(crate) trait SourceReadScope: source_scope::Sealed {
    /// Borrows the original namespace identity and live exclusion.
    fn identity(&self) -> &HeldIdentity<'_>;

    /// Borrows the originally selected whole publication state.
    fn state(&self) -> &PublicationState;

    /// Returns the independently configured source owner.
    fn configured_operator_uid(&self) -> u32;

    /// Returns the original external control directory incarnation.
    fn control_identity(&self) -> (u64, u64);

    /// Borrows all original exact reads, including selected-chain absence.
    fn physical_reads(&self) -> &[RecordRead];
}

mod source_scope {
    /// Seals genuine observations while preserving thread-safe read scopes.
    #[cfg(feature = "send")]
    pub trait Sealed: Send + Sync {}

    /// Seals genuine observations for read scopes without thread-safe futures.
    #[cfg(not(feature = "send"))]
    pub trait Sealed {}

    impl Sealed for super::SelectedObservation<'_> {}
}

impl SourceReadScope for SelectedObservation<'_> {
    fn identity(&self) -> &HeldIdentity<'_> {
        self.identity()
    }

    fn state(&self) -> &PublicationState {
        self.state()
    }

    fn configured_operator_uid(&self) -> u32 {
        self.configured_operator_uid()
    }

    fn control_identity(&self) -> (u64, u64) {
        self.control_identity()
    }

    fn physical_reads(&self) -> &[RecordRead] {
        self.physical_reads()
    }
}

/// Retains actual baseline, source and control recipes for one fresh invocation.
pub(crate) struct GuardTransition<'a> {
    holder: &'a HeldIdentity<'a>,
    resolver: &'a ConsumedResolver,
    selected: PublicationState,
    old_guard: RecordRead,
    snapshot: Vec<u8>,
    plans: Vec<ImportPlan>,
    destination_controls: RetainedControls,
    source_controls: RetainedControls,
    source_selected: &'a dyn SourceReadScope,
    source_reads: Vec<RecordRead>,
    final_check: OwnedFinalCheck,
    read_binding: Arc<()>,
}

impl<'a> GuardTransition<'a> {
    /// Captures proof inputs without writing controls or granting current rights.
    ///
    /// # Errors
    /// Refuses unrelated role changes, substituted actual scopes, missing or
    /// contradictory import carriers, unsafe controls and source-current failures.
    pub(super) async fn capture<F, B, V, C, D>(
        concrete: &Guard<FileBucket<F, B, V>, C>,
        destination: &Guard<HeldBucket<'_, F, B, V, true>, D>,
        authority: &OriginalAuthority,
        scope: CaptureScope<'a, '_, '_>,
        source: &DisclosureSource<'_, F>,
        plans: &[ImportPlan],
        request: &super::DestinationRequest<'_>,
    ) -> Result<Self, StoreFailure>
    where
        F: LocalFs + BucketBinding + Sync,
        B: Clock + BucketBinding,
        V: ContentValidator + BucketBinding,
        C: Clock,
        D: Clock,
    {
        let CaptureScope {
            destination: observed,
            source: source_observed,
            resolver,
        } = scope;
        source.final_check.recheck()?;
        source.retained.revalidate(destination.store().fs()).await?;
        source_observed.revalidate().await?;
        observed.revalidate().await?;
        resolver.check_guard(destination)?;
        if source.requests.is_empty()
            || source.authority.root() != source_observed.identity().root()
            || source.authority.physical_identity()
                != source_observed.identity().physical_identity()
            || source.retained.owner() != source_observed.configured_operator_uid()
            || destination.configured_original_authority()? != *authority
        {
            return Err(invalid());
        }

        let old_guard = destination
            .store()
            .selected_guard_snapshot_record_retained(observed)
            .await?
            .ok_or_else(invalid)?;
        let previous = old_guard.bytes().ok_or_else(invalid)?;
        let snapshot = resolver.snapshot_bytes()?;
        check_transition(previous, &snapshot, plans)?;
        let previous = GuardSnapshot::decode(previous).map_err(|_| invalid())?;

        // Already installed additions must be the exact source-derived carrier,
        // independently reopened through the genuine native Original verifier.
        for trust in destination.retained_public_trust()? {
            if !trust
                .disclosure_roles
                .iter()
                .any(|role| !previous.disclosures.contains(&role_row(role)))
            {
                continue;
            }
            let bytes = trust.encode().map_err(crate::guard::retention_failure)?;
            let plan = plans
                .iter()
                .find(|plan| {
                    plan.trust
                        .encode()
                        .is_ok_and(|candidate| candidate == bytes)
                })
                .ok_or_else(invalid)?;
            let checked = concrete
                .load_original_import_held(authority, &plan.import, observed.identity())
                .await?;
            let borrowed = destination
                .load_original_import_held(authority, &plan.import, observed.identity())
                .await?;
            let actual = crate::repository::local_authority::public_trust::PublicTrustRecord {
                import_digest: plan.trust.import_digest,
                source_authority: plan.trust.source_authority,
                destination_authority: plan.trust.destination_authority,
                issuer_keys: borrowed.historical_keys()?.ok_or_else(invalid)?,
                disclosure_roles: borrowed
                    .historical_disclosure_roles()?
                    .ok_or_else(invalid)?,
            };
            if checked != borrowed
                || borrowed.retained_import_record()? != plan.import
                || actual.encode().map_err(crate::guard::retention_failure)? != bytes
            {
                return Err(invalid());
            }
        }
        resolver.check_guard(destination)?;
        if resolver.snapshot_bytes()? != snapshot {
            return Err(invalid());
        }

        let mut exclusion = concrete
            .hold_original_registration(authority, observed.identity())
            .await?;
        let decoded = GuardSnapshot::decode(&snapshot).map_err(|_| invalid())?;
        concrete
            .check_retained_trust_controls(authority, &mut exclusion, &decoded)
            .await?;
        let configured = ConsumedResolver::new(destination, authority)?;
        configured.registration(authority)?;
        let originals = destination.original_history_control_contexts()?;
        for original in &originals {
            configured.original(original)?;
        }
        let mut named = BTreeMap::new();
        for pin in configured.control_pins()? {
            if pin.owner != crate::guard::consumed_registration(authority) {
                return Err(invalid());
            }
            let bytes = exclusion.read_record(&pin.key).await?;
            pin.check_record(&bytes).map_err(|_| invalid())?;
            if named
                .get(&pin.key)
                .is_some_and(|previous| previous != &bytes)
            {
                return Err(invalid());
            }
            named.insert(pin.key, bytes);
        }
        let repository = authority
            .id()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        for row in decoded
            .disclosures
            .iter()
            .filter(|row| row.repository == repository)
        {
            let role = crate::repository::local_authority::public_trust::DisclosureRoleRecord {
                repository: row.repository.clone(),
                domain: row.domain.clone(),
                public_key: row.public_key,
                not_before: row.not_before,
                not_after: row.not_after,
            };
            let key = role.selector().map_err(crate::guard::retention_failure)?;
            let bytes = role.encode().map_err(crate::guard::retention_failure)?;
            if exclusion.read_record(&key).await? != bytes
                || named.get(&key).is_some_and(|previous| previous != &bytes)
            {
                return Err(invalid());
            }
            named.insert(key, bytes);
        }
        let destination_controls = exclusion
            .retain_named(&named.into_iter().collect::<Vec<_>>())
            .await?;
        // The retained duplicate, not a second acquired lock, stays with proof.
        drop(exclusion);

        let source_check = source.final_check.clone();
        let clock = destination
            .clock()
            .retain_native_clock()
            .map_err(crate::guard::retained_clock_failure)?;
        let started = request.started;
        let maximum = request.timing.maximum();
        let reference = request.reference.to_owned();
        let final_check = OwnedFinalCheck {
            check: SharedCheck::new(move || {
                source_check.recheck()?;
                if clock
                    .monotonic()
                    .checked_sub(started)
                    .is_none_or(|elapsed| elapsed > maximum)
                {
                    return Err(StoreFailure::with_source(
                        crate::guard::denied(&reference, Verb::Commit)
                            .kind()
                            .clone(),
                        crate::ref_advance::AdvanceError::Expired,
                    ));
                }
                Ok(())
            }),
        };
        let proof = Self {
            holder: observed.identity(),
            resolver,
            selected: observed.state().clone(),
            old_guard,
            snapshot,
            plans: plans.to_vec(),
            destination_controls,
            source_controls: source.retained.clone(),
            source_selected: source_observed,
            source_reads: source.selected_reads.clone(),
            final_check,
            read_binding: Arc::new(()),
        };
        proof.final_check.recheck()?;
        Ok(proof)
    }

    /// Requires the original holder and resolver and exact captured current bytes.
    ///
    /// # Errors
    /// Refuses a substituted purpose or changed source/deadline/current inputs.
    pub(crate) fn check_scope(
        &self,
        observation: HistoryObservation<'_>,
    ) -> Result<(), StoreFailure> {
        self.final_check.recheck()?;
        if !std::ptr::eq(observation.identity().ok_or_else(invalid)?, self.holder)
            || !std::ptr::eq(observation.resolver().ok_or_else(invalid)?, self.resolver)
            || !observation
                .paired_transition_purpose()
                .is_some_and(|proof| std::ptr::eq(proof, self))
            || self.resolver.snapshot_bytes()? != self.snapshot
        {
            return Err(invalid());
        }
        check_transition(
            self.old_guard.bytes().ok_or_else(invalid)?,
            &self.snapshot,
            &self.plans,
        )
    }

    /// Checks physical baseline recipes without adopting a fresh incarnation.
    ///
    /// # Errors
    /// Refuses changed whole selected state, original Guard data or controls.
    pub(crate) async fn check_selected<F: LocalFs + BucketBinding>(
        &self,
        fs: &F,
        selected: &SelectedObservation<'_>,
    ) -> Result<(), StoreFailure> {
        self.final_check.recheck()?;
        if selected.state() != &self.selected
            || selected.identity().root() != self.holder.root()
            || selected.identity().physical_identity() != self.holder.physical_identity()
            || !std::ptr::eq(
                selected.identity().retained_namespace()?,
                self.holder.retained_namespace()?,
            )
        {
            return Err(invalid());
        }
        self.old_guard.revalidate_retained(fs).await?;
        self.destination_controls.revalidate(fs).await?;
        self.source_controls.revalidate(fs).await?;
        // These original recipes include the selected chain and its first absent
        // successor. Closing them preserves the captured whole selection without
        // invoking an invariant callback or adopting a fresh incarnation.
        for read in self.source_selected.physical_reads() {
            read.revalidate_retained(fs).await?;
        }
        self.final_check.recheck()
    }

    /// Borrows the genuine destination read hold for Original and native closing.
    pub(crate) fn destination_controls(&self) -> &RetainedControls {
        &self.destination_controls
    }

    /// Borrows independently retained source authority and signer records.
    pub(crate) fn source_controls(&self) -> &RetainedControls {
        &self.source_controls
    }

    /// Borrows the exact source selected namespace whose recipes must close.
    pub(crate) fn source_selected(&self) -> &dyn SourceReadScope {
        self.source_selected
    }

    /// Borrows original source Guard and lineage preimages.
    pub(crate) fn source_reads(&self) -> &[RecordRead] {
        &self.source_reads
    }

    /// Borrows the original destination Guard recipe consumed by preflight.
    pub(crate) fn old_guard(&self) -> &RecordRead {
        &self.old_guard
    }

    /// Retains this proof's private invocation identity without granting rights.
    pub(crate) fn read_binding(&self) -> Arc<()> {
        Arc::clone(&self.read_binding)
    }

    /// Retains only the genuine source predicates and unchanged operation deadline.
    ///
    /// # Errors
    /// Preserves source current/signer refusal and the original deadline taxonomy.
    pub(crate) fn retained_check(&self) -> Result<OwnedFinalCheck, StoreFailure> {
        self.final_check.recheck()?;
        Ok(self.final_check.clone())
    }
}
