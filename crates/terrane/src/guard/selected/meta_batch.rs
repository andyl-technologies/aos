//! Retains native immutable staging controls beneath the actual candidate factory.
//!
//! This operation context limits effects; it grants no actor, selected lineage or
//! collector authority. Its factory uses genuine current requests, exact protected
//! reads and the same acquired Original exclusion retained by final publication.

use super::*;

/// Retains exact immutable-stage control inputs under the original held operation.
pub(crate) struct ImmutableEffectContext<'operation, 'held> {
    effect: GuardEffectContext,
    sources: Vec<&'operation SelectedObservation<'held>>,
    selected: terrane_core::gc::publication::PublicationState,
}

impl<'operation, 'held> ImmutableEffectContext<'operation, 'held> {
    /// Borrows the genuine selected/control evidence retained by this producer.
    pub(crate) fn effect_context(&self) -> &GuardEffectContext {
        &self.effect
    }

    /// Borrows other held namespace observations retained for native effects.
    pub(crate) fn sources(&self) -> &[&'operation SelectedObservation<'held>] {
        &self.sources
    }

    /// Refreshes the original actual retained clock and authenticated requests.
    ///
    /// # Errors
    /// Preserves deadline/token failures; this check alone grants no current ACL.
    pub(crate) fn recheck(&self) -> Result<(), StoreFailure> {
        self.effect.final_check.recheck()
    }

    /// Checks that own content publications changed no retained authority fields.
    ///
    /// # Errors
    /// Refuses changed backend/Guard/loss/branch/lineage association. A legitimate
    /// physical-loss repair ends this publication attempt before selected capture;
    /// it does not grant a same-loss or carried-lineage exemption.
    pub(crate) fn check_selection(
        &self,
        observed: &SelectedObservation<'_>,
    ) -> Result<(), StoreFailure> {
        self.recheck()?;
        let state = observed.state();
        if state.binding != self.selected.binding
            || state.guard != self.selected.guard
            || state.loss_generation != self.selected.loss_generation
            || state.branches != self.selected.branches
            || state.sources != self.selected.sources
            || state.burn_owners != self.selected.burn_owners
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Groups the independently configured Guard and its actual Original owner.
///
/// These borrows do not construct a control receipt or confer permission.
pub(super) struct ControlOwner<'guard, F: LocalFs, B, V, D> {
    /// The independently configured destination Guard.
    pub(super) concrete: &'guard Guard<FileBucket<F, B, V>, D>,
    /// The genuine factory-installed Original authority.
    pub(super) authority: &'guard OriginalAuthority,
}

/// Groups one actual held native selection and its consumed-input tracer.
pub(super) struct NativeSelection<'input, 'held, F: LocalFs, B, V, C, R> {
    /// The operation-local coordinator under the actual writable holder.
    pub(super) coordinator:
        &'input crate::ref_advance::Coordinator<HeldBucket<'held, F, B, V, true>, C, R>,
    /// The actual initial selected observation retained by that holder.
    pub(super) observed: &'input SelectedObservation<'held>,
    /// The same actual resolver recording this operation's consumed inputs.
    pub(super) consumed: &'input ConsumedResolver,
}

/// Groups the already admitted candidate and its original operation boundaries.
pub(super) struct CandidateRetention<'input, 'view> {
    /// The actual admitted candidate, with its ordinary token and publication target.
    pub(super) admitted: &'input crate::guard::AdmittedCommit,
    /// The genuine session publication target already checked by admission.
    pub(super) publication_reference: &'input str,
    /// The original candidate context established by signed preparation.
    pub(super) original: &'input crate::guard::OriginalCommitContext,
    /// The independently selected history tracked by this same operation.
    pub(super) history: crate::guard::HistoryObservation<'view>,
    /// The original commit deadline origin; grouping does not restart it.
    pub(super) started: std::time::Duration,
    /// The unchanged timing chosen by the actual coordinator.
    pub(super) timing: crate::ref_advance::CommitTiming,
    /// The initial protected selected preimages captured before staging.
    pub(super) selected_reads: &'input [SelectedControlRead],
}

/// Keeps the actual already-held control exclusion without a finalized lineage.
///
/// Only retain constructs this value from configured Original checks. Its field
/// is consumed by the late real completed-history capture; it contains no dummy
/// view, empty LineageUsedInputs or caller-supplied control record.
pub(super) struct EarlyControlInputs<'guard, F: LocalFs> {
    /// The same actual acquired Original exclusion, carried into late capture.
    pub(super) exclusion: crate::guard::ControlExclusion<'guard, F>,
}

/// Captures actual early requests and controls before native immutable staging.
///
/// The same exclusion is returned to the caller for final consumed-control
/// validation. Only the operation-local held Guard retains a clone; the long-lived
/// configured Guard must not retain this operation's acquired lock.
///
/// # Errors
/// Preserves ordinary admission/source/current/Original failures and refuses
/// a changed selected Guard, foreign local controls or unsupported retention.
pub(super) async fn retain<'operation, 'held, 'guard, F, B, V, C, R, D>(
    owner: ControlOwner<'guard, F, B, V, D>,
    selection: NativeSelection<'_, 'held, F, B, V, C, R>,
    candidate: CandidateRetention<'_, '_>,
) -> Result<
    (
        ImmutableEffectContext<'operation, 'held>,
        EarlyControlInputs<'guard, F>,
    ),
    crate::ref_advance::AdvanceError,
>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock + BucketBinding,
    R: LocalFs + BucketBinding,
{
    let ControlOwner {
        concrete,
        authority,
    } = owner;
    let NativeSelection {
        coordinator,
        observed,
        consumed,
    } = selection;
    let CandidateRetention {
        admitted,
        publication_reference,
        original,
        history,
        started,
        timing,
        selected_reads,
    } = candidate;

    coordinator
        .guard()
        .revalidate_original_context(original, history)
        .await?;
    coordinator
        .guard()
        .revalidate_admission_observed(admitted, history)
        .await?;
    history
        .record_candidate(
            coordinator.store(),
            admitted,
            coordinator.guard().config().min_chunk_size,
        )
        .await?;
    let mut requests = coordinator
        .guard()
        .capture_admission_authorizations_observed(admitted, history)
        .await?;
    requests.extend(
        coordinator
            .capture_source_authorizations_observed(admitted, history)
            .await?,
    );
    requests.push(
        coordinator
            .guard()
            .authorize_observed(
                publication_reference,
                &admitted.token,
                admitted.publication_verb,
                &[],
                &admitted.surface,
                history,
            )
            .await?,
    );
    for request in &requests {
        consumed.operation(request)?;
    }
    // Candidate consumption remains Pending here: only actual control pins,
    // configured snapshot and independently verified current requests are
    // retained. The post-upload signed-history Finish owns completed views.
    observed.revalidate().await?;
    let mut exclusion = concrete
        .hold_original_registration(authority, observed.identity())
        .await?;
    let snapshot = consumed.snapshot_bytes()?;
    if coordinator
        .store()
        .selected_guard_snapshot(observed)
        .await?
        .as_deref()
        != Some(snapshot.as_slice())
    {
        return Err(StoreFailure::new(StoreErrorKind::Denied {
            verb: "guard-install",
            pattern: authority.root().display().to_string(),
        })
        .into());
    }
    let pins = consumed.control_pins()?;
    let registration = crate::guard::consumed_registration(authority);
    for pin in &pins {
        if pin.owner != registration {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported).into());
        }
        let bytes = exclusion.read_record(&pin.key).await?;
        pin.check_record(&bytes).map_err(|_| invalid())?;
    }
    exclusion.revalidate().await?;
    observed.revalidate().await?;
    let retained = exclusion.retain_used(&pins).await?;
    let local = EarlyControlInputs { exclusion };
    coordinator.guard().retain_original_controls(&retained)?;
    let final_check = retain_final_check(coordinator.guard(), &requests, started, timing)?;
    let controls = vec![retained];
    let reads = selected_reads.to_vec();
    let sources = Vec::new();
    let state = observed.state();
    let context = ImmutableEffectContext {
        effect: GuardEffectContext {
            final_check,
            controls,
            selected_reads: reads,
            publication_original: Some(original.clone()),
        },
        sources,
        selected: state.clone(),
    };
    context.check_selection(observed)?;
    Ok((context, local))
}

/// Preserves every early Original control preimage while retaining later inputs.
///
/// The same acquired ControlExclusion stays live throughout. Added genuinely
/// consumed rows may extend the receipt; existing rows/ancestors may not refresh
/// their bytes, incarnation, protection or configured owner from a later read.
///
/// # Errors
/// Refuses a changed receipt binding, missing old record or changed old preimage.
pub(super) fn check_continuity(
    early: &crate::guard::RetainedControls,
    final_controls: &crate::guard::RetainedControls,
) -> Result<(), StoreFailure> {
    if early.directory() != final_controls.directory()
        || early.owner() != final_controls.owner()
        || early.identities() != final_controls.identities()
        || early.ancestors() != final_controls.ancestors()
    {
        return Err(invalid());
    }
    for previous in early.records() {
        let actual = final_controls
            .records()
            .iter()
            .find(|record| record.path() == previous.path())
            .ok_or_else(invalid)?;
        if actual.identity() != previous.identity() || actual.bytes() != previous.bytes() {
            return Err(invalid());
        }
    }
    Ok(())
}
