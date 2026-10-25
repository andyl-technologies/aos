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
    invalid, unavailable,
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
use terrane_format::refs::RefRecord;

#[cfg(unix)]
mod cold;
#[cfg(all(feature = "tokio", unix))]
mod current;
#[cfg(all(feature = "tokio", unix))]
mod direct;
#[cfg(all(feature = "tokio", unix))]
mod held;
#[cfg(all(feature = "tokio", unix))]
mod overlay;
#[cfg(all(feature = "tokio", unix))]
mod read_configuration;
mod requalification;

#[cfg(test)]
mod recorded_adapter_tests;

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

#[cfg(unix)]
type RetainedHistoryControls = super::RetainedControls;
#[cfg(not(unix))]
type RetainedHistoryControls = ();

#[cfg(feature = "send")]
type CommitCheck = dyn for<'a> Fn(
        &'a RetainedBootstrap,
        AssociationView<'a>,
        Option<&'a HeldIdentity<'a>>,
        Option<&'a RetainedHistoryControls>,
    ) -> CheckFuture<'a, OriginalCommitContext>
    + Send
    + Sync;
#[cfg(not(feature = "send"))]
type CommitCheck = dyn for<'a> Fn(
    &'a RetainedBootstrap,
    AssociationView<'a>,
    Option<&'a HeldIdentity<'a>>,
    Option<&'a RetainedHistoryControls>,
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
    commits: std::collections::BTreeMap<terrane_format::identity::Digest, OriginalCommitContext>,
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

/// Owns genuine backend callbacks and retained inputs for protected Original checks.
#[derive(Clone)]
pub(in crate::guard) struct OriginalVerifier {
    authority: OriginalAuthority,
    /// Retains the independently installed disclosure roles for this authority.
    #[cfg(unix)]
    pub(in crate::guard::original) roles:
        Vec<crate::repository::local_authority::public_trust::DisclosureRoleRecord>,
    baseline: Arc<BaselineCheck>,
    commit: Arc<CommitCheck>,
    retained: Option<RetainedHistoryControls>,
    publication: Arc<PublicationCheck>,
    tag: Arc<TagCheck>,
    requalification: Arc<requalification::RequalificationCheck>,
    #[cfg(all(feature = "tokio", unix))]
    current: Arc<current::CurrentHistoryCheck>,
    #[cfg(all(feature = "tokio", unix))]
    held: Arc<held::HeldHistoryCheck>,
    #[cfg(all(feature = "tokio", unix))]
    direct: Arc<direct::DirectHistoryCheck>,
    #[cfg(all(feature = "tokio", unix))]
    overlay: Arc<overlay::OverlayHistoryCheck>,
    #[cfg(unix)]
    preparation: Arc<cold::PreparationCheck>,
    #[cfg(unix)]
    cold_candidates: cold::PendingColdForks,
    #[cfg(all(test, feature = "tokio", unix))]
    historical_lineage_reference: Option<String>,
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
        F: Sync,
        C: Clock,
    {
        self.configure_original_verifier(authority, true).await
    }

    /// Loads existing physical verification without installing a selected Guard.
    ///
    /// Only the native read-only factory uses this path, then independently
    /// requires an existing signed selected snapshot before returning a reader.
    ///
    /// # Errors
    /// Refuses unsafe physical bindings and incomplete or conflicting retained
    /// records. It never initializes selected authority or repairs missing state.
    pub(crate) async fn install_existing_original_verifier(
        &self,
        authority: &OriginalAuthority,
    ) -> Result<(), StoreFailure>
    where
        F: Sync,
        C: Clock,
    {
        self.configure_original_verifier(authority, false).await
    }

    /// Prepares physical checks for a private pending paired destination.
    ///
    /// This installs no selected Guard. Only the private recovery constructor
    /// uses this preparation; a pending coordinator is never returned as a
    /// repository or exposed for unrelated operations.
    ///
    /// # Errors
    /// Rejects unsafe physical bindings, malformed retained controls and
    /// conflicting original contexts exactly as ordinary native setup does.
    pub(crate) async fn prepare_paired_original_verifier(
        &self,
        authority: &OriginalAuthority,
    ) -> Result<(), StoreFailure>
    where
        F: Sync,
        C: Clock,
    {
        self.configure_original_verifier(authority, false).await
    }

    async fn configure_original_verifier(
        &self,
        authority: &OriginalAuthority,
        select_initial: bool,
    ) -> Result<(), StoreFailure>
    where
        F: Sync,
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
        let concrete = Arc::new(self.read_configuration_adapter(self.store.clone(), ()));
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
                    let proof = destination.identity_proof();
                    let guard = concrete.held_guard(held.destination(), clock)?;
                    *guard.original_verifier.write().map_err(|_| unavailable())? = state.verifier;
                    *guard
                        .original_baselines
                        .write()
                        .map_err(|_| unavailable())? = state.baselines;
                    *guard.original_commits.write().map_err(|_| unavailable())? = state.commits;
                    let coordinator = Coordinator::new(guard, timing, FsRef(concrete.store().fs()));
                    let selected = coordinator.store().observe_publication().await?;
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
                    // The held guard carries the independently captured public
                    // trust state. The dispatch capture deliberately has no
                    // verifier, avoiding a self-retaining Arc cycle.
                    let consumed = crate::guard::ConsumedResolver::new(
                        coordinator.guard(),
                        &current_authority,
                    )?;
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
        #[cfg(all(feature = "tokio", unix))]
        let held = held::capture(Arc::clone(&concrete), authority.clone());
        #[cfg(all(feature = "tokio", unix))]
        let direct = direct::capture(
            Arc::clone(&concrete),
            authority.clone(),
            setup_clock
                .retain_native_clock()
                .map_err(crate::guard::retained_clock_failure)?,
        );
        #[cfg(all(feature = "tokio", unix))]
        let overlay = overlay::capture(
            Arc::clone(&concrete),
            authority.clone(),
            setup_clock
                .retain_native_clock()
                .map_err(crate::guard::retained_clock_failure)?,
        );
        let cold_candidates = Arc::new(std::sync::RwLock::new(std::collections::BTreeMap::new()));
        let preparation = cold::factory(
            Arc::clone(&concrete),
            authority.clone(),
            Arc::clone(&cold_candidates),
        );
        let commit_guard = concrete;
        let commit_authority = authority.clone();
        let commit: Arc<CommitCheck> = Arc::new(move |baseline, view, held, retained| {
            let guard = Arc::clone(&commit_guard);
            let owner = commit_authority.clone();
            Box::pin(async move {
                if baseline.authority() == &owner {
                    guard
                        .bind_local_or_import_at(&owner, baseline, view, held, retained)
                        .await
                } else {
                    guard
                        .bind_imported_commit_at(&owner, baseline, view, held, retained)
                        .await
                }
            })
        });
        let mut roles = Vec::new();
        let uid = self.store.publication_operator_uid().ok_or_else(invalid)?;
        for path in self
            .store
            .fs()
            .read_dir(authority.control())
            .await
            .map_err(super::io_failure)?
        {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(invalid)?;
            if name.starts_with("disclosure-role-") {
                use crate::repository::local_authority::{
                    public_trust::DisclosureRoleRecord,
                    retention::{self, Record},
                };
                let role: DisclosureRoleRecord =
                    retention::read(self.store.fs(), authority.control(), uid, name)
                        .await
                        .map_err(super::import::retention_failure)?;
                if role.repository != super::hex(authority.id())
                    || role.domain != authority.domain()
                    || role.selector().map_err(|_| invalid())? != name
                {
                    return Err(invalid());
                }
                roles.push(role);
            }
        }
        roles.sort_by(|left, right| {
            (
                &left.repository,
                &left.domain,
                left.public_key,
                left.not_before,
            )
                .cmp(&(
                    &right.repository,
                    &right.domain,
                    right.public_key,
                    right.not_before,
                ))
        });

        {
            let mut installed = self.original_verifier.write().map_err(|_| unavailable())?;
            if installed
                .as_ref()
                .is_some_and(|old| old.authority != authority)
            {
                return Err(invalid());
            }

            *installed = Some(OriginalVerifier {
                authority: authority.clone(),
                roles,
                baseline,
                commit,
                retained: None,
                publication,
                tag,
                requalification,
                #[cfg(all(feature = "tokio", unix))]
                current,
                #[cfg(all(feature = "tokio", unix))]
                held,
                #[cfg(all(feature = "tokio", unix))]
                direct,
                #[cfg(all(feature = "tokio", unix))]
                overlay,
                preparation,
                cold_candidates,
                #[cfg(all(test, feature = "tokio", unix))]
                historical_lineage_reference: None,
            });
        }

        for path in self
            .store
            .fs()
            .read_dir(authority.control())
            .await
            .map_err(super::io_failure)?
        {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(invalid)?;
            if name.starts_with("import-")
                && !name.starts_with("import-binding-")
                && !name.starts_with("import-trust-")
            {
                use crate::repository::local_authority::retention::{self, ImportRecord};
                let import: ImportRecord =
                    retention::read(self.store.fs(), authority.control(), uid, name)
                        .await
                        .map_err(super::import::retention_failure)?;
                self.load_original_import(&authority, &import).await?;
            }
        }
        if !select_initial {
            return Ok(());
        }

        let setup = self.read_configuration_adapter(self.store.clone(), setup_clock);
        *setup.original_verifier.write().map_err(|_| unavailable())? = self
            .original_verifier
            .read()
            .map_err(|_| unavailable())?
            .clone();
        *setup.original_commits.write().map_err(|_| unavailable())? = self
            .original_commits
            .read()
            .map_err(|_| unavailable())?
            .clone();
        let namespace = SingleHeld::acquire(&self.store).await?;
        let destination = namespace.destination();
        let observed = destination.observe_publication().await?;
        crate::selected_bridge::native_guard::install_initial_guard(
            SetupGuard::new(setup),
            &authority,
            &destination,
            &observed,
        )
        .await?;
        Ok(())
    }
}

impl<S, C> Guard<S, C> {
    /// Chooses the older optional-field encoding for one native test reference.
    ///
    /// This changes only ordinary completed lineage serialization. Actual
    /// admission, history, configuration, Original, control and publication
    /// checks still run. Clearing the setting restores current encoding.
    ///
    /// # Errors
    /// Rejects a non-head reference, absent native dispatch or poisoned state.
    #[cfg(all(test, feature = "tokio", feature = "surface-sdk", unix))]
    pub(crate) fn historical_lineage_encoding_for_tests(
        &self,
        reference: Option<&str>,
    ) -> Result<(), StoreFailure> {
        if let Some(reference) = reference {
            let name = terrane_format::refs::RefName::parse(reference).map_err(|_| invalid())?;
            if name.class() != terrane_format::refs::RefClass::Heads {
                return Err(invalid());
            }
        }
        let mut installed = self.original_verifier.write().map_err(|_| unavailable())?;
        installed
            .as_mut()
            .ok_or_else(invalid)?
            .historical_lineage_reference = reference.map(str::to_owned);
        Ok(())
    }

    /// Reads only this held verifier's test compatibility encoding selection.
    ///
    /// # Errors
    /// Preserves poisoned synchronization; absent dispatch selects current encoding.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn omits_lineage_context_for_tests(
        &self,
        reference: &str,
    ) -> Result<bool, StoreFailure> {
        let installed = self.original_verifier.read().map_err(|_| unavailable())?;
        Ok(installed.as_ref().is_some_and(|verifier| {
            verifier.historical_lineage_reference.as_deref() == Some(reference)
        }))
    }

    /// Captures current read configuration and complete independently checked Original state.
    ///
    /// The replacement unit store and clock cannot read content or authorize an
    /// operation. The actual native worker still retains and refreshes every
    /// consumed physical control; this capture supplies no new qualification.
    /// Its existing closed native Original dispatcher remains available for
    /// protected-record rechecks under the actual retained control receipts.
    /// Known completed view selections share their existing synchronized carrier,
    /// so final ordinary comparisons observe the same installed selections.
    ///
    /// # Errors
    /// Preserves poisoned synchronization while capturing actual checked state.
    pub(crate) fn guard_carry_configuration_adapter(&self) -> Result<Guard<(), ()>, StoreFailure> {
        let guard = self.read_configuration_adapter((), ());
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

    /// Returns the actual physical binding captured by the native factory.
    ///
    /// This grants no current operation rights. Each producer rechecks the
    /// registration under its genuinely held backend and control exclusions.
    ///
    /// # Errors
    /// Rejects missing native dispatch or unavailable synchronized state.
    pub(crate) fn configured_original_authority(&self) -> Result<OriginalAuthority, StoreFailure> {
        self.original_verifier().map(|verifier| verifier.authority)
    }

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
                if !held.writable() {
                    self.recheck_original_commit_read_observed(baseline, view, held)
                        .await?
                } else if self.original_verifier()?.retained.is_some() {
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
        self.check_original_commit_at(baseline, view, None, false)
            .await
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
        self.check_original_commit_at(baseline, view, Some(held), false)
            .await
    }

    #[cfg(unix)]
    /// Retains existing Original exclusion for freshly checked local history reads.
    ///
    /// This physical receipt grants no history or actor authority. The captured
    /// native binder still checks backend identity and every canonical record.
    ///
    /// # Errors
    /// Refuses absent native dispatch, another configured control directory or
    /// incompatible already-retained receipt; the binder rechecks actual owner.
    pub(crate) fn retain_original_controls(
        &self,
        retained: &super::RetainedControls,
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

    /// Rechecks an installed original context under an actual held read observation.
    ///
    /// This validates protected records without installing or supplementing any
    /// authority. The existing context and native retention owner must match the
    /// freshly checked result exactly, including every imported control pin.
    ///
    /// # Errors
    /// Rejects missing dispatch or installed context, mismatched physical holders,
    /// changed protected records or context, and unavailable synchronization.
    pub(crate) async fn recheck_original_commit_read_observed<'a>(
        &self,
        baseline: &'a RetainedBootstrap,
        view: AssociationView<'a>,
        held: &'a HeldIdentity<'a>,
    ) -> Result<OriginalCommitContext, StoreFailure> {
        if held.writable() {
            return Err(invalid());
        }
        let existing = self.original_commit(view.commit)?;
        let verifier = self.original_verifier()?;
        if !existing.retained_by(&verifier.authority) {
            return Err(invalid());
        }
        let checked =
            (verifier.commit)(baseline, view, Some(held), verifier.retained.as_ref()).await?;
        if existing != checked || self.original_commit(view.commit)? != checked {
            return Err(invalid());
        }
        Ok(checked)
    }

    /// Installs a fully checked protected import during an explicit held transition.
    ///
    /// A same-original supplement may add retained trust only when the original
    /// commit, complete baseline and actual retention owner remain unchanged.
    /// Ordinary original checks retain exact context mismatch refusal.
    ///
    /// # Errors
    /// Rejects read-only or unrelated holders, invalid protected import or local
    /// originals, conflicting contexts and unavailable synchronization.
    #[cfg(unix)]
    pub(in crate::guard::original) async fn check_original_import_held<'a>(
        &self,
        baseline: &'a RetainedBootstrap,
        view: AssociationView<'a>,
        held: &'a HeldIdentity<'a>,
    ) -> Result<OriginalCommitContext, StoreFailure> {
        if !held.writable() {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly));
        }
        self.check_original_commit_at(baseline, view, Some(held), true)
            .await
    }

    async fn check_original_commit_at<'a>(
        &self,
        baseline: &'a RetainedBootstrap,
        view: AssociationView<'a>,
        held: Option<&'a HeldIdentity<'a>>,
        allow_local_supplement: bool,
    ) -> Result<OriginalCommitContext, StoreFailure> {
        let verifier = self.original_verifier()?;
        // Retained exclusions may be reused only with an actual held identity.
        let retained = held.and(verifier.retained.as_ref());
        let checked = (verifier.commit)(baseline, view, held, retained).await?;
        let mut installed = self.original_commits.write().map_err(|_| unavailable())?;
        if installed.get(&checked.commit).is_some_and(|old| {
            #[cfg(unix)]
            let supplements_local = old.imported.is_none()
                && checked
                    .imported
                    .as_ref()
                    .is_some_and(|imported| imported.supplements_local);
            #[cfg(not(unix))]
            let supplements_local = false;

            old != &checked
                && !(allow_local_supplement
                    && supplements_local
                    && old.commit == checked.commit
                    && old.baseline == checked.baseline
                    && old.retention_owner == checked.retention_owner)
        }) {
            return Err(invalid());
        }
        installed.insert(checked.commit, checked.clone());
        Ok(checked)
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
        if !existing.retained_by(&verifier.authority) {
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

#[cfg(unix)]
impl<F: LocalFs + BucketBinding, B: Clock + BucketBinding, V: ContentValidator + BucketBinding, C>
    Guard<FileBucket<F, B, V>, C>
{
    /// Copies checked Original state onto the same physical backend for a pending role transition.
    ///
    /// The candidate does not replace the serving Guard. Its disclosure-role
    /// delta must still be checked against protected records and selected by the
    /// owning native publisher before the actual Guard adopts it.
    ///
    /// # Errors
    /// Preserves poisoned synchronization while capturing existing checked state.
    pub(crate) fn disclosure_rotation_adapter(
        &self,
        clock: NativeEffectClock,
    ) -> Result<Guard<FileBucket<F, B, V>, NativeEffectClock>, StoreFailure> {
        let guard = self.read_configuration_adapter(self.store().clone(), clock);
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
}
