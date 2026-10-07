//! Dispatches cold preparation through the actual opened native binding.
//!
//! Each invocation restores its complete actual Original state on a held Guard.
//! The acyclic capture shares the FileBucket Arc and actual filesystem; public
//! arguments supply neither callbacks nor checked history/profile constructors.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use super::{OriginalState, PublicationClock, retain_clock, unavailable};
use crate::bucket::held::HeldIdentity;
use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::{
    AssociationView, BootstrapView, CommitRequest, Guard, OriginalAuthority, OriginalCommitContext,
    RegistrationView, RetainedBootstrap, RetainedControls, invalid,
};
use crate::ref_advance::{AdvanceError, CommitTiming, PublicationBinding, WriterSession};
use crate::store::{Clock, ContentValidator, LocalFs, Store, StoreFailure};
use terrane_core::gc::publication::evidence::{
    CheckedLineage, ControlKind, OriginalAssociation, OriginalBootstrap,
};

/// Owns request data and the parent's genuinely checked destination baseline.
pub(super) struct Preparation {
    source: String,
    reference: String,
    epoch: u64,
    baseline: RetainedBootstrap,
    request: CommitRequest,
    started: Duration,
    timing: CommitTiming,
}

#[cfg(feature = "send")]
type PreparationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<crate::guard::AdmittedCommit, AdvanceError>> + Send + 'a>>;
#[cfg(not(feature = "send"))]
type PreparationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<crate::guard::AdmittedCommit, AdvanceError>> + 'a>>;

/// Invokes only the closed actual factory with native Send requirements.
#[cfg(feature = "send")]
pub(super) type PreparationCheck = dyn for<'a> Fn(Preparation, &'a PublicationClock<'a>, OriginalState) -> PreparationFuture<'a>
    + Send
    + Sync;
/// Invokes the same actual factory without imposing Send on default futures.
#[cfg(not(feature = "send"))]
pub(super) type PreparationCheck =
    dyn for<'a> Fn(Preparation, &'a PublicationClock<'a>, OriginalState) -> PreparationFuture<'a>;

impl<S: Store, C: Clock> Guard<S, C> {
    /// Prepares native cold reuse without ordinary source admission fallback.
    ///
    /// A Guard without native dispatch retains its ordinary generic behavior.
    /// That separate lane never claims cold eligibility. For the native lane,
    /// missing context is Unsupported and requires separate full requalification.
    ///
    /// # Errors
    /// Preserves malformed/unsupported context, current denial, changed source,
    /// profile, Original or controls, signing, expiry and originating I/O failures.
    pub(crate) async fn prepare_cold_fork_native(
        &self,
        session: &WriterSession,
        source: &str,
        baseline: &RetainedBootstrap,
        request: CommitRequest,
        started: Duration,
        timing: CommitTiming,
    ) -> Result<crate::guard::AdmittedCommit, AdvanceError>
    where
        C: PublicationBinding,
    {
        let verifier = self
            .original_verifier
            .read()
            .map_err(|_| unavailable())?
            .clone();
        let Some(verifier) = verifier else {
            return self
                .admit_fork(source, session.reference(), session.epoch(), request)
                .await
                .map_err(Into::into);
        };
        let state = OriginalState {
            verifier: Some(verifier.clone()),
            baselines: self
                .original_baselines
                .read()
                .map_err(|_| unavailable())?
                .clone(),
            commits: self
                .original_commits
                .read()
                .map_err(|_| unavailable())?
                .clone(),
        };
        (verifier.preparation)(
            Preparation {
                source: source.to_owned(),
                reference: session.reference().to_owned(),
                epoch: session.epoch(),
                baseline: baseline.clone(),
                request,
                started,
                timing,
            },
            self.clock(),
            state,
        )
        .await
    }
}

/// Captures the actual bucket without a self-retaining installed verifier cycle.
pub(super) fn factory<F, B, V>(
    concrete: Arc<Guard<FileBucket<F, B, V>, ()>>,
    authority: OriginalAuthority,
) -> Arc<PreparationCheck>
where
    F: LocalFs + BucketBinding + 'static,
    B: Clock + BucketBinding + 'static,
    V: ContentValidator + BucketBinding + 'static,
{
    use crate::selected_bridge::native_guard::cold_fork::{self, ColdForkRequest};

    Arc::new(move |input, clock, state| {
        let concrete = Arc::clone(&concrete);
        let authority = authority.clone();
        Box::pin(async move {
            let clock = retain_clock(clock)?;
            let holder = crate::bucket::held::SingleHeld::acquire(concrete.store()).await?;
            let guard = concrete.held_guard(holder.destination(), clock)?;
            *guard.original_verifier.write().map_err(|_| unavailable())? = state.verifier;
            *guard
                .original_baselines
                .write()
                .map_err(|_| unavailable())? = state.baselines;
            *guard.original_commits.write().map_err(|_| unavailable())? = state.commits;
            let observed = guard.store().observe_publication().await?;
            let baseline = guard.original_bootstrap(&input.reference, input.epoch)?;
            if baseline != input.baseline || baseline.authority() != &authority {
                return Err(invalid().into());
            }
            let mut qualified = cold_fork::qualify_source(
                &concrete,
                &authority,
                &guard,
                &observed,
                ColdForkRequest {
                    source: &input.source,
                    token: &input.request.token,
                    surface: &input.request.surface,
                    started: input.started,
                    timing: input.timing,
                },
            )
            .await?;
            let admitted = guard
                .admit_qualified_cold_fork(
                    &mut qualified,
                    &input.reference,
                    input.epoch,
                    &baseline,
                    input.request,
                )
                .await?;
            qualified.revalidate(&guard).await?;
            Ok(admitted)
        })
    })
}

impl<F, B, V, C> Guard<FileBucket<F, B, V>, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Binds every reached local Original through the actual protected factory.
    ///
    /// Ancestors remain association inputs; none becomes a VerifiedCommit. The
    /// baseline adapter reproduces ordinary binding with the genuine held backend
    /// and retained control receipt, avoiding recursive lock acquisition.
    ///
    /// # Errors
    /// Rejects foreign controls, absent/conflicting rows, changed registration,
    /// protected baseline/association failures and originating storage errors.
    pub(crate) async fn bind_cold_originals(
        &self,
        authority: &OriginalAuthority,
        held: &HeldIdentity<'_>,
        retained: &RetainedControls,
        lineage: &CheckedLineage,
        records: &[Vec<u8>],
    ) -> Result<Vec<OriginalCommitContext>, StoreFailure> {
        if lineage.controls.len() != records.len() {
            return Err(invalid());
        }
        let mut baselines = Vec::new();
        let mut associations = Vec::new();
        for (pin, bytes) in lineage.controls.iter().zip(records) {
            match pin.kind {
                ControlKind::Bootstrap => {
                    baselines.push(OriginalBootstrap::decode(bytes).map_err(|_| invalid())?)
                }
                ControlKind::Association => {
                    associations.push(OriginalAssociation::decode(bytes).map_err(|_| invalid())?)
                }
                ControlKind::Registration => {}
                ControlKind::Import | ControlKind::ImportBinding | ControlKind::ImportTrust => {
                    return Err(crate::store::StoreFailure::new(
                        crate::store::StoreErrorKind::Unsupported,
                    ));
                }
            }
        }
        let namespace = crate::domain::DomainNamespace {
            root: authority.root().to_owned(),
            domain: authority.domain().to_owned(),
        };
        let mut checked = std::collections::BTreeMap::new();
        for view in &lineage.used.views {
            if checked.contains_key(&view.view) {
                continue;
            }
            let association = associations
                .iter()
                .find(|row| row.commit == view.view)
                .ok_or_else(invalid)?;
            let row = baselines
                .iter()
                .find(|row| {
                    row.original_id == association.original_id
                        && row.ref_name == association.ref_name
                        && row.epoch == association.epoch
                })
                .ok_or_else(invalid)?;
            let acl = row
                .acl
                .iter()
                .map(|grant| (grant.principal.clone(), grant.verbs))
                .collect::<Vec<_>>();
            let view = BootstrapView {
                id: &row.original_id,
                reference: &row.ref_name,
                epoch: row.epoch,
                acl: &acl,
            };
            if view.id != authority.id() {
                return Err(invalid());
            }
            let record = super::super::bootstrap_record(&view)?;
            let (root_identity, coordination_identity) = authority.physical_identity();
            let checked_authority = self
                .bind_original_records(
                    &namespace,
                    authority.control(),
                    RegistrationView {
                        id: authority.id(),
                        root: authority.root(),
                        domain: authority.domain(),
                        root_identity,
                        coordination_identity,
                        control: authority.control(),
                    },
                    &[record],
                    Some(held),
                    Some(retained),
                )
                .await?;
            let baseline = RetainedBootstrap {
                authority: checked_authority,
                reference: row.ref_name.clone(),
                epoch: row.epoch,
                acl,
            };
            let context = self
                .bind_original_commit_at(
                    &baseline,
                    AssociationView {
                        commit: &association.commit,
                        id: &association.original_id,
                        reference: &association.ref_name,
                        epoch: association.epoch,
                    },
                    Some(held),
                    Some(retained),
                )
                .await?;
            checked.insert(association.commit, context);
        }
        Ok(checked.into_values().collect())
    }
}
