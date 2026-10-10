//! Dispatches protected record checks through one captured actual FileBucket binding.
//!
//! Only the concrete native guard factory constructs this dispatcher. Its bucket
//! clone shares the existing inner Arc and filesystem instance; generic callers
//! supply untrusted decoded views, never callbacks or an authority constructor.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

#[cfg(not(feature = "send"))]
use std::rc::Rc as SetupGuard;
#[cfg(feature = "send")]
use std::sync::Arc as SetupGuard;

use super::{
    AssociationView, BootstrapView, OriginalAuthority, OriginalCommitContext, RetainedBootstrap,
    RetainedControls, invalid, unavailable,
};
use crate::bucket::held::{HeldIdentity, SingleHeld};
use crate::bucket::{BucketBinding, FileBucket};
use crate::domain::DomainNamespace;
use crate::guard::Guard;
use crate::ref_advance::{
    AdvanceError, Coordinator, FsRef, NativeTagRequest, PublicationClock, RetainedPublication,
    WriterSession,
};
use crate::store::{
    Clock, ContentValidator, LocalFs, NativeEffectClock, RefStore, StoreErrorKind, StoreFailure,
};
use terrane_core::refs::RefRecord;

#[cfg(unix)]
mod cold;
#[cfg(all(feature = "tokio", unix))]
mod current;
mod requalification;

// Retaining the actual injected clock does not strengthen generic Clock bounds.
fn retain_clock(clock: &PublicationClock<'_>) -> Result<NativeEffectClock, StoreFailure> {
    clock.retain_native_clock().map_err(|failure| {
        let kind = if failure.kind() == std::io::ErrorKind::Unsupported {
            StoreErrorKind::Unsupported
        } else {
            StoreErrorKind::Unavailable { retry_after: None }
        };
        StoreFailure::with_source(kind, failure)
    })
}

#[cfg(feature = "send")]
type CheckFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreFailure>> + Send + 'a>>;
#[cfg(not(feature = "send"))]
type CheckFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreFailure>> + 'a>>;

#[cfg(feature = "send")]
type BaselineCheck =
    dyn for<'a> Fn(BootstrapView<'a>) -> CheckFuture<'a, RetainedBootstrap> + Send + Sync;
#[cfg(not(feature = "send"))]
type BaselineCheck = dyn for<'a> Fn(BootstrapView<'a>) -> CheckFuture<'a, RetainedBootstrap>;

#[cfg(feature = "send")]
type CommitCheck = dyn for<'a> Fn(
        &'a RetainedBootstrap,
        AssociationView<'a>,
        Option<&'a HeldIdentity<'a>>,
        Option<&'a RetainedControls>,
    ) -> CheckFuture<'a, OriginalCommitContext>
    + Send
    + Sync;
#[cfg(not(feature = "send"))]
type CommitCheck = dyn for<'a> Fn(
    &'a RetainedBootstrap,
    AssociationView<'a>,
    Option<&'a HeldIdentity<'a>>,
    Option<&'a RetainedControls>,
) -> CheckFuture<'a, OriginalCommitContext>;

#[cfg(feature = "send")]
type PublicationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<RefRecord>, AdvanceError>> + Send + 'a>>;
#[cfg(not(feature = "send"))]
type PublicationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<RefRecord>, AdvanceError>> + 'a>>;

enum PublicationMode {
    Advance,
    Immutable,
}

struct OriginalState {
    verifier: Option<OriginalVerifier>,
    baselines: std::collections::BTreeMap<(String, u64), RetainedBootstrap>,
    commits: std::collections::BTreeMap<terrane_core::identity::Digest, OriginalCommitContext>,
}

#[cfg(feature = "send")]
type PublicationCheck = dyn for<'a> Fn(
        &'a mut WriterSession,
        RetainedPublication,
        &'a PublicationClock<'a>,
        OriginalState,
        PublicationMode,
    ) -> PublicationFuture<'a>
    + Send
    + Sync;
#[cfg(not(feature = "send"))]
type PublicationCheck = dyn for<'a> Fn(
    &'a mut WriterSession,
    RetainedPublication,
    &'a PublicationClock<'a>,
    OriginalState,
    PublicationMode,
) -> PublicationFuture<'a>;

#[cfg(feature = "send")]
type TagCheck = dyn for<'a> Fn(
        NativeTagRequest,
        &'a PublicationClock<'a>,
        OriginalState,
    ) -> Pin<Box<dyn Future<Output = Result<RefRecord, AdvanceError>> + Send + 'a>>
    + Send
    + Sync;
#[cfg(not(feature = "send"))]
type TagCheck =
    dyn for<'a> Fn(
        NativeTagRequest,
        &'a PublicationClock<'a>,
        OriginalState,
    ) -> Pin<Box<dyn Future<Output = Result<RefRecord, AdvanceError>> + 'a>>;

#[derive(Clone)]
pub(in crate::guard) struct OriginalVerifier {
    authority: OriginalAuthority,
    baseline: Arc<BaselineCheck>,
    commit: Arc<CommitCheck>,
    publication: Arc<PublicationCheck>,
    tag: Arc<TagCheck>,
    requalification: Arc<requalification::RequalificationCheck>,
    #[cfg(all(feature = "tokio", unix))]
    current: Arc<current::CurrentHistoryCheck>,
    #[cfg(unix)]
    preparation: Arc<cold::PreparationCheck>,
    retained: Option<RetainedControls>,
}

#[cfg(unix)]
impl<
    F: LocalFs + BucketBinding + 'static,
    B: Clock + BucketBinding + 'static,
    V: ContentValidator + BucketBinding + 'static,
    C,
> Guard<FileBucket<F, B, V>, C>
{
    /// Installs sealed checks capturing this exact native backend and protected authority.
    ///
    /// # Errors
    /// Rejects changed or unavailable physical registration, conflicting authority,
    /// or unavailable synchronized state. No caller-supplied callback is accepted.
    pub(crate) async fn install_original_verifier(
        &self,
        authority: &OriginalAuthority,
    ) -> Result<(), StoreFailure>
    where
        C: Clock,
    {
        // Setup retains its genuine clock without inventing a writer deadline.
        // No dummy clock can reach the initial checked effect context.
        let setup_clock = self.clock.retain_native_clock().map_err(|error| {
            let kind = if error.kind() == std::io::ErrorKind::Unsupported {
                StoreErrorKind::Unsupported
            } else {
                StoreErrorKind::Unavailable { retry_after: None }
            };
            StoreFailure::with_source(kind, error)
        })?;
        let namespace = DomainNamespace {
            root: authority.root.clone(),
            domain: authority.domain.clone(),
        };
        let authority = self
            .bind_original_authority(
                &namespace,
                &authority.control,
                super::RegistrationView {
                    id: &authority.id,
                    root: &authority.root,
                    domain: &authority.domain,
                    root_identity: authority.root_identity,
                    coordination_identity: authority.coordination_identity,
                    control: &authority.control,
                },
            )
            .await?;
        // FileBucket::clone shares its inner Arc. Cloning a separate Fs value
        // would not establish that the verifier observes this opened backend.
        let mut captured = Guard::new(
            self.store.clone(),
            (),
            self.keys.clone(),
            self.config.clone(),
        );
        captured.interpretation = self.interpretation;
        let concrete = Arc::new(captured);
        {
            let namespace = SingleHeld::acquire(&self.store).await?;
            let destination = namespace.destination();
            let observed = destination.observe_publication().await?;
            let mut setup = Guard::new(
                self.store.clone(),
                setup_clock,
                self.keys.clone(),
                self.config.clone(),
            );
            setup.interpretation = self.interpretation;
            crate::selected_bridge::native_guard::install_initial_guard(
                SetupGuard::new(setup),
                &authority,
                &destination,
                &observed,
            )
            .await?;
        }
        let baseline_guard = Arc::clone(&concrete);
        let baseline_authority = authority.clone();
        let baseline: Arc<BaselineCheck> = Arc::new(move |view| {
            let guard = Arc::clone(&baseline_guard);
            let authority = baseline_authority.clone();
            Box::pin(async move { guard.bind_original_bootstrap(&authority, view).await })
        });
        let publication_guard = Arc::clone(&concrete);
        let publication_authority = authority.clone();
        let publication: Arc<PublicationCheck> =
            Arc::new(move |session, publication, clock, state, mode| {
                let concrete = Arc::clone(&publication_guard);
                let publication_authority = publication_authority.clone();
                Box::pin(async move {
                    let clock = retain_clock(clock)?;
                    let RetainedPublication {
                        mut admitted,
                        original,
                        started,
                        reason,
                        timing,
                    } = publication;
                    let held = SingleHeld::acquire(concrete.store()).await?;
                    let destination = held.destination();
                    let selected = destination.observe_publication().await?;
                    let proof = destination.identity_proof();
                    let guard = concrete.held_guard(held.destination(), clock)?;
                    *guard.original_verifier.write().map_err(|_| unavailable())? = state.verifier;
                    *guard
                        .original_baselines
                        .write()
                        .map_err(|_| unavailable())? = state.baselines;
                    *guard.original_commits.write().map_err(|_| unavailable())? = state.commits;
                    let coordinator = Coordinator::new(guard, timing, FsRef(concrete.store().fs()));
                    let namespace = DomainNamespace {
                        root: publication_authority.root.clone(),
                        domain: publication_authority.domain.clone(),
                    };
                    let current_authority = concrete
                        .bind_original_records(
                            &namespace,
                            &publication_authority.control,
                            super::RegistrationView {
                                id: &publication_authority.id,
                                root: &publication_authority.root,
                                domain: &publication_authority.domain,
                                root_identity: publication_authority.root_identity,
                                coordination_identity: publication_authority.coordination_identity,
                                control: &publication_authority.control,
                            },
                            &[],
                            Some(&proof),
                            None,
                        )
                        .await?;
                    let consumed =
                        crate::guard::ConsumedResolver::new(&concrete, &current_authority)?;
                    consumed.registration(&current_authority)?;
                    let observation =
                        crate::guard::HistoryObservation::held(&proof).tracked(&consumed);
                    match mode {
                        PublicationMode::Advance => {
                            let mut publication = RetainedPublication {
                                admitted,
                                original,
                                started,
                                reason,
                                timing,
                            };
                            if publication.admitted.cold_fork.is_some() {
                                crate::selected_bridge::native_guard::cold_fork::publish(
                                    &concrete,
                                    &current_authority,
                                    &coordinator,
                                    &selected,
                                    session,
                                    &publication,
                                )
                                .await
                                .map(Some)
                            } else {
                                crate::selected_bridge::native_guard::publish_candidate(
                                    &concrete,
                                    &current_authority,
                                    &coordinator,
                                    &selected,
                                    &consumed,
                                    session,
                                    &mut publication,
                                )
                                .await
                                .map(Some)
                            }
                        }
                        PublicationMode::Immutable => {
                            // A marked attempt cannot become an ordinary losing
                            // traversal or silently lose its mandatory cold route.
                            if admitted.cold_fork.is_some() {
                                return Err(StoreFailure::new(StoreErrorKind::Unsupported).into());
                            }
                            coordinator
                                .guard()
                                .revalidate_original_context(&original, observation)
                                .await?;
                            let current = coordinator
                                .guard()
                                .authorize_observed(
                                    session.reference(),
                                    &admitted.token,
                                    admitted.publication_verb,
                                    &[],
                                    &admitted.surface,
                                    observation,
                                )
                                .await?;
                            if current.record() != admitted.observed_current.as_ref()
                                && !Coordinator::<
                                    FileBucket<F, B, V>,
                                    NativeEffectClock,
                                    FsRef<'_, F>,
                                >::may_rebase(
                                    session, current.record()
                                )
                            {
                                return coordinator.fence(session).await.map(Some);
                            }
                            // The signed first parent remains the historical
                            // base. Fresh held authorization independently binds
                            // this immutable attempt to the current whole head.
                            admitted.observed_current = current.record().cloned();
                            if coordinator.store().ref_get(session.reference()).await?
                                != admitted.observed_current
                            {
                                return coordinator.fence(session).await.map(Some);
                            }
                            coordinator
                                .publish_immutable_observed(&admitted, started, observation)
                                .await?;
                            Ok(None)
                        }
                    }
                })
            });
        let tag_guard = Arc::clone(&concrete);
        let tag_authority = authority.clone();
        let tag: Arc<TagCheck> = Arc::new(move |request, clock, state| {
            let concrete = Arc::clone(&tag_guard);
            let authority = tag_authority.clone();
            Box::pin(async move {
                let clock = retain_clock(clock)?;
                let held = SingleHeld::acquire(concrete.store()).await?;
                let destination = held.destination();
                let selected = destination.observe_publication().await?;
                let guard = concrete.held_guard(held.destination(), clock)?;
                *guard.original_verifier.write().map_err(|_| unavailable())? = state.verifier;
                *guard
                    .original_baselines
                    .write()
                    .map_err(|_| unavailable())? = state.baselines;
                *guard.original_commits.write().map_err(|_| unavailable())? = state.commits;
                let coordinator =
                    Coordinator::new(guard, request.timing, FsRef(concrete.store().fs()));
                crate::selected_bridge::native_guard::publish_tag(
                    &concrete,
                    &authority,
                    &coordinator,
                    &selected,
                    request,
                )
                .await
            })
        });
        let requalification = requalification::factory(Arc::clone(&concrete), authority.clone());
        #[cfg(all(feature = "tokio", unix))]
        let current = current::capture(Arc::clone(&concrete), authority.clone());
        let preparation = cold::factory(Arc::clone(&concrete), authority.clone());
        let commit_guard = concrete;
        let commit: Arc<CommitCheck> = Arc::new(move |baseline, view, held, retained| {
            let guard = Arc::clone(&commit_guard);
            Box::pin(async move {
                guard
                    .bind_original_commit_at(baseline, view, held, retained)
                    .await
            })
        });
        let mut installed = self.original_verifier.write().map_err(|_| unavailable())?;
        if installed
            .as_ref()
            .is_some_and(|old| old.authority != authority)
        {
            return Err(invalid());
        }
        *installed = Some(OriginalVerifier {
            authority,
            baseline,
            commit,
            publication,
            tag,
            requalification,
            #[cfg(all(feature = "tokio", unix))]
            current,
            preparation,
            retained: None,
        });
        Ok(())
    }
}

impl<S, C> Guard<S, C> {
    /// Borrows a held backend while preserving independently checked trust state.
    ///
    /// The adapter cannot outlive its exclusion. Every subsequent historical
    /// observation still rereads protected records using the matching proof.
    ///
    /// # Errors
    /// Reports unavailable synchronized state while copying checked trust evidence.
    pub(crate) fn held_guard<'a, F: LocalFs, B, V, D, const WRITABLE: bool>(
        &self,
        store: crate::bucket::held::HeldBucket<'a, F, B, V, WRITABLE>,
        clock: D,
    ) -> Result<Guard<crate::bucket::held::HeldBucket<'a, F, B, V, WRITABLE>, D>, StoreFailure>
    {
        let mut guard = Guard::new(store, clock, self.keys.clone(), self.config.clone());
        guard.interpretation = self.interpretation;
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

    /// Rereads the exact candidate association in the supplied observation scope.
    ///
    /// # Errors
    /// Rejects mismatched or unavailable protected evidence and preserves storage failures.
    pub(crate) async fn revalidate_original_context(
        &self,
        context: &OriginalCommitContext,
        observation: crate::guard::HistoryObservation<'_>,
    ) -> Result<(), StoreFailure> {
        let baseline = context.baseline();
        let view = AssociationView {
            commit: context.commit(),
            id: baseline.authority().id(),
            reference: baseline.reference(),
            epoch: baseline.epoch(),
        };
        let checked = match observation.identity() {
            Some(held) => {
                if self.original_verifier()?.retained.is_some() {
                    self.recheck_original_commit_observed(baseline, view, held)
                        .await?
                } else {
                    self.check_original_commit_held(baseline, view, held)
                        .await?
                }
            }
            None => self.check_original_commit(baseline, view).await?,
        };
        if &checked != context {
            return Err(invalid());
        }
        observation.record_original(&checked)?;
        Ok(())
    }

    /// Publishes under the actual native exclusion captured by the sealed factory.
    ///
    /// # Errors
    /// Rejects absent dispatch, invalid protected context, current authority denial,
    /// fencing, deadlines, and storage failures; uncertain CAS remains typed.
    pub(crate) async fn publish_retained_native(
        &self,
        session: &mut WriterSession,
        publication: RetainedPublication,
        clock: &PublicationClock<'_>,
    ) -> Result<RefRecord, AdvanceError> {
        self.publish_native_at(session, publication, clock, PublicationMode::Advance)
            .await?
            .ok_or_else(|| invalid().into())
    }

    /// Publishes a losing immutable candidate under the same native exclusion.
    ///
    /// # Errors
    /// Preserves protected evidence, current policy and storage failures before rebase.
    pub(crate) async fn publish_losing_native(
        &self,
        session: &mut WriterSession,
        publication: RetainedPublication,
        clock: &PublicationClock<'_>,
    ) -> Result<(), AdvanceError> {
        if self
            .publish_native_at(session, publication, clock, PublicationMode::Immutable)
            .await?
            .is_some()
        {
            return Err(invalid().into());
        }
        Ok(())
    }

    async fn publish_native_at(
        &self,
        session: &mut WriterSession,
        publication: RetainedPublication,
        clock: &PublicationClock<'_>,
        mode: PublicationMode,
    ) -> Result<Option<RefRecord>, AdvanceError> {
        let verifier = self.original_verifier()?;
        let state = OriginalState {
            verifier: self
                .original_verifier
                .read()
                .map_err(|_| unavailable())?
                .clone(),
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
        (verifier.publication)(session, publication, clock, state, mode).await
    }

    /// Rechecks the actual source under native exclusion through tag creation.
    ///
    /// # Errors
    /// Reports missing native dispatch, changed source authority, current Tag
    /// denial, existing destinations, and typed storage or indeterminate CAS failures.
    pub(crate) async fn publish_tag_native(
        &self,
        request: NativeTagRequest,
        clock: &PublicationClock<'_>,
    ) -> Result<RefRecord, AdvanceError> {
        let verifier = self.original_verifier()?;
        let state = OriginalState {
            verifier: self
                .original_verifier
                .read()
                .map_err(|_| unavailable())?
                .clone(),
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
        (verifier.tag)(request, clock, state).await
    }

    fn original_verifier(&self) -> Result<OriginalVerifier, StoreFailure> {
        self.original_verifier
            .read()
            .map_err(|_| unavailable())?
            .as_ref()
            .cloned()
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))
    }

    /// Checks and installs an exact protected baseline through the captured native binding.
    ///
    /// # Errors
    /// Rejects absent dispatch, malformed or conflicting protected records, changed
    /// physical binding, unavailable filesystem evidence, or poisoned internal state.
    pub(crate) async fn check_original_bootstrap(
        &self,
        view: BootstrapView<'_>,
    ) -> Result<RetainedBootstrap, StoreFailure> {
        let verifier = self.original_verifier()?;
        let checked = (verifier.baseline)(view).await?;
        let mut installed = self.original_baselines.write().map_err(|_| unavailable())?;
        let key = (checked.reference.clone(), checked.epoch);
        if installed.get(&key).is_some_and(|old| old != &checked) {
            return Err(invalid());
        }
        installed.insert(key, checked.clone());
        Ok(checked)
    }

    /// Checks and installs an exact immutable association through the captured native binding.
    ///
    /// # Errors
    /// Rejects absent dispatch, another authority, malformed or conflicting protected
    /// records, changed backend identity, unavailable evidence, or poisoned state.
    pub(crate) async fn check_original_commit(
        &self,
        baseline: &RetainedBootstrap,
        view: AssociationView<'_>,
    ) -> Result<OriginalCommitContext, StoreFailure> {
        self.check_original_commit_at(baseline, view, None).await
    }

    /// Checks protected association bytes under an actual writable held backend.
    ///
    /// Only the configuration lock is acquired; the borrowed identity keeps the
    /// independently acquired backend exclusion alive throughout validation.
    ///
    /// # Errors
    /// Rejects readonly or mismatched held namespaces, absent native dispatch,
    /// changed protected evidence, and underlying storage failures.
    pub(crate) async fn check_original_commit_held<'a>(
        &self,
        baseline: &'a RetainedBootstrap,
        view: AssociationView<'a>,
        held: &'a HeldIdentity<'a>,
    ) -> Result<OriginalCommitContext, StoreFailure> {
        if !held.writable() {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly));
        }
        self.check_original_commit_at(baseline, view, Some(held))
            .await
    }

    async fn check_original_commit_at<'a>(
        &self,
        baseline: &'a RetainedBootstrap,
        view: AssociationView<'a>,
        held: Option<&'a HeldIdentity<'a>>,
    ) -> Result<OriginalCommitContext, StoreFailure> {
        let verifier = self.original_verifier()?;
        if baseline.authority != verifier.authority {
            return Err(invalid());
        }
        let retained = held.and(verifier.retained.as_ref());
        let checked = (verifier.commit)(baseline, view, held, retained).await?;
        let mut installed = self.original_commits.write().map_err(|_| unavailable())?;
        if installed
            .get(&checked.commit)
            .is_some_and(|old| old != &checked)
        {
            return Err(invalid());
        }
        installed.insert(checked.commit, checked.clone());
        Ok(checked)
    }

    /// Retains genuine same-holder controls for subsequent observed Original checks.
    ///
    /// The native held factory independently checks the configured owner, exact
    /// records and selected association before supplying this physical receipt.
    /// This preserves exclusion only; it creates no Original or actor authority.
    ///
    /// # Errors
    /// Rejects missing dispatch, another control directory, incompatible retained
    /// owner/lock incarnations, or unavailable configuration synchronization.
    pub(crate) fn retain_original_controls(
        &self,
        retained: &RetainedControls,
    ) -> Result<(), StoreFailure> {
        let mut installed = self.original_verifier.write().map_err(|_| unavailable())?;
        let verifier = installed.as_mut().ok_or_else(invalid)?;
        if retained.directory() != verifier.authority.control()
            || verifier.retained.as_ref().is_some_and(|old| {
                old.directory() != retained.directory()
                    || old.owner() != retained.owner()
                    || old.identities() != retained.identities()
            })
        {
            return Err(invalid());
        }
        verifier.retained = Some(retained.clone());
        Ok(())
    }

    /// Rechecks an installed local Original under its actual writable holder.
    ///
    /// No authority is installed or supplemented. Its exact previously checked
    /// context must equal the fresh native binding before and after the await.
    /// Without retained controls, the ordinary configuration exclusion is acquired.
    ///
    /// # Errors
    /// Preserves readonly-holder refusal and rejects missing dispatch/context,
    /// changed backend, protected records or physical receipts and I/O failures.
    pub(crate) async fn recheck_original_commit_observed<'a>(
        &self,
        baseline: &'a RetainedBootstrap,
        view: AssociationView<'a>,
        held: &'a HeldIdentity<'a>,
    ) -> Result<OriginalCommitContext, StoreFailure> {
        if !held.writable() {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly));
        }
        let existing = self.original_commit(view.commit)?;
        let verifier = self.original_verifier()?;
        if baseline.authority != verifier.authority {
            return Err(invalid());
        }
        let checked =
            (verifier.commit)(baseline, view, Some(held), verifier.retained.as_ref()).await?;
        if existing != checked || self.original_commit(view.commit)? != checked {
            return Err(invalid());
        }
        Ok(checked)
    }
}
