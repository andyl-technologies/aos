//! Separates signed preparation from protected retention and durable publication.
//!
//! Each prepared candidate carries its original deadline and exact administrative
//! baseline. Publication consumes only the matching protected commit association.
//! Rebase candidates return through this same boundary before any new uploads.

use super::coordinator::PendingAdvance;
use super::{AdvanceError, CommitRequest, Coordinator, FoldOutcome, WriterSession};
use crate::guard::{
    AssociationView, BootstrapView, JoinKind, JoinRequest, OriginalCommitContext, RebaseRequest,
    RetainedBootstrap,
};
use crate::store::{Clock, LocalFs, Store};
use terrane_format::identity::Digest;
use terrane_format::refs::{MergePolicy, RefClass, RefLogReason};

/// Reports an opt-in test boundary without changing publication inputs.
///
/// # Panics
/// Panics if enabled diagnostics cannot write to standard error.
#[cfg(test)]
fn trace_index_prepared(phase: &'static str) {
    if std::env::var_os("TERRANE_INDEX_REBUILD_TRACE").is_some() {
        eprintln!("index-prepared-subphase phase={phase}");
    }
}

/// Retains a signed candidate before any of its immutable content is published.
pub(crate) struct PreparedAdvance {
    pending: PendingAdvance,
    original: RetainedBootstrap,
    merge_base: Option<Digest>,
    losing_commit: Digest,
    join: Option<PreparedJoin>,
    excluded: Vec<Vec<u8>>,
}

/// Retains the original join operation for fresh recomputation after a conflict.
struct PreparedJoin {
    source: String,
    policies: Vec<MergePolicy>,
    kind: JoinKind,
}

impl PreparedAdvance {
    /// Returns ordinary work measured by this exact signed candidate preparation.
    pub(crate) fn index_work(&self) -> &crate::guard::IndexPublicationWork {
        &self.pending.admitted.index_work
    }

    /// Returns the exact signed immutable candidate requiring durable association.
    pub(crate) fn commit(&self) -> Digest {
        self.pending.admitted.commit.identity()
    }

    /// Returns the checked original baseline governing this candidate's ref and epoch.
    pub(crate) fn baseline(&self) -> &RetainedBootstrap {
        &self.original
    }

    /// Copies already signed immutable inputs for genuine historical test staging.
    ///
    /// This test-only observation constructs no admission, Original association,
    /// or selected publication result. The owning Repository retains the actual
    /// candidate association before returning these ordinary immutable values.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn historical_fixture_inputs(
        &self,
    ) -> (
        terrane_format::provenance::VerifiedCommit,
        Vec<crate::guard::StagedUpload>,
    ) {
        (
            self.pending.admitted.commit.clone(),
            self.pending.admitted.uploads.clone(),
        )
    }
}

/// Returns a completed publication or another signed candidate requiring retention.
pub(crate) enum PublicationStep {
    /// A whole authority record was durably acknowledged.
    Published(Box<FoldOutcome>),
    /// A conflict produced a newly signed candidate within the original deadline.
    Reprepare(Box<PreparedAdvance>),
}

impl<S: Store, C: Clock, F: LocalFs> Coordinator<S, C, F> {
    /// Uses already retained exact authority without offering a generic persistence bypass.
    pub(super) async fn publish_installed(
        &self,
        session: &mut WriterSession,
        prepared: PreparedAdvance,
    ) -> Result<FoldOutcome, AdvanceError>
    where
        C: super::PublicationBinding,
    {
        let context = self.guard().original_commit(&prepared.commit())?;
        match self.publish_prepared(session, prepared, context).await? {
            PublicationStep::Published(outcome) => Ok(*outcome),
            PublicationStep::Reprepare(_) => Err(crate::store::StoreFailure::new(
                crate::store::StoreErrorKind::Unsupported,
            )
            .into()),
        }
    }

    async fn checked_preparation_baseline(
        &self,
        session: &WriterSession,
    ) -> Result<RetainedBootstrap, AdvanceError> {
        let baseline = self
            .guard()
            .original_bootstrap(session.reference(), session.epoch())?;
        let checked = self
            .guard()
            .check_original_bootstrap(BootstrapView {
                id: baseline.authority().id(),
                reference: baseline.reference(),
                epoch: baseline.epoch(),
                acl: baseline.acl(),
            })
            .await?;
        if checked != baseline {
            return Err(crate::guard::invalid().into());
        }
        Ok(checked)
    }

    /// Starts a corrective session using namespace facts without index-serving proof.
    ///
    /// # Errors
    /// Preserves source, Original and current Commit denial; rejects absent or
    /// unsupported refs and exhausted epochs. Final repair qualification is separate.
    pub(crate) async fn begin_index_rebuild(
        &self,
        reference: &str,
        token: &[u8],
        surface: &str,
        purpose: &crate::guard::index_maintenance::Purpose,
    ) -> Result<WriterSession, AdvanceError> {
        let name = terrane_format::refs::RefName::parse(reference)
            .map_err(|_| AdvanceError::InvalidRefClass)?;
        if !matches!(
            name.class(),
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        ) {
            return Err(AdvanceError::InvalidRefClass);
        }
        let authorized = self
            .guard()
            .authorize_observed(
                reference,
                token,
                terrane_format::auth::Verb::Commit,
                &[],
                surface,
                crate::guard::HistoryObservation::default().maintenance(purpose),
            )
            .await?;
        let record = authorized
            .record()
            .cloned()
            .ok_or_else(crate::guard::invalid)?;
        if record.commit != purpose.source() {
            return Err(crate::guard::invalid().into());
        }
        let mut scopes = authorized.root_paths().to_vec();
        scopes.sort();
        scopes.dedup();
        let epoch = record
            .writer_epoch
            .checked_add(1)
            .ok_or(AdvanceError::Exhausted)?;
        Ok(WriterSession {
            reference: reference.to_owned(),
            epoch,
            record: Some(record),
            fenced: false,
            class: name.class(),
            scopes,
        })
    }

    /// Prepares an exact signed candidate without uploading content or advancing a ref.
    ///
    /// # Errors
    /// Rejects a fenced session, missing checked original baseline, stale single
    /// writer, failed current authorization, invalid candidate, or expired deadline.
    pub(crate) async fn prepare_advance(
        &self,
        session: &mut WriterSession,
        request: CommitRequest,
    ) -> Result<PreparedAdvance, AdvanceError> {
        self.prepare_advance_inner(session, request, None, None)
            .await
    }

    /// Preserves the original deadline across preparatory maintenance effects.
    ///
    /// # Errors
    /// Preserves ordinary preparation failures and rejects an expired original
    /// deadline before and after freshly qualifying the retained baseline.
    pub(crate) async fn prepare_advance_started(
        &self,
        session: &mut WriterSession,
        request: CommitRequest,
        started: std::time::Duration,
    ) -> Result<PreparedAdvance, AdvanceError> {
        self.prepare_advance_inner(session, request, None, Some(started))
            .await
    }

    /// Prepares one unchanged-owner candidate through the ordinary admission body.
    ///
    /// # Errors
    /// Preserves mandatory admission failures and refuses stale owner templates
    /// before losing/rebase admission can perform unrelated content work.
    #[cfg(unix)]
    pub(crate) async fn prepare_advance_with_existing_owner(
        &self,
        session: &mut WriterSession,
        mut request: CommitRequest,
        references: crate::guard::ExistingOwnerReferences,
    ) -> Result<PreparedAdvance, AdvanceError> {
        references.check_template(session, &request)?;
        request.reference_records = references.records();
        self.prepare_advance_inner(session, request, Some(references), None)
            .await
    }

    /// Prepares unchanged-owner evidence within the first replacement's deadline.
    ///
    /// # Errors
    /// Preserves existing-owner template and ordinary admission failures, and
    /// rejects expiration against the supplied original monotonic start.
    #[cfg(unix)]
    pub(crate) async fn prepare_advance_with_existing_owner_started(
        &self,
        session: &mut WriterSession,
        mut request: CommitRequest,
        references: crate::guard::ExistingOwnerReferences,
        started: std::time::Duration,
    ) -> Result<PreparedAdvance, AdvanceError> {
        self.check_time(started)?;
        references.check_template(session, &request)?;
        request.reference_records = references.records();
        self.prepare_advance_inner(session, request, Some(references), Some(started))
            .await
    }

    async fn prepare_advance_inner(
        &self,
        session: &mut WriterSession,
        request: CommitRequest,
        #[cfg(unix)] references: Option<crate::guard::ExistingOwnerReferences>,
        #[cfg(not(unix))] _references: Option<()>,
        original_started: Option<std::time::Duration>,
    ) -> Result<PreparedAdvance, AdvanceError> {
        if session.fenced {
            return Err(AdvanceError::Fenced {
                current: session.record.clone().map(Box::new),
            });
        }
        if let Some(started) = original_started {
            self.check_time(started)?;
        }

        #[cfg(test)]
        let mut trace = super::PhaseTrace::new(
            self.guard().clock(),
            session.reference(),
            None,
            None,
            "prepare-baseline-entry",
        );
        #[cfg(test)]
        trace_index_prepared("preparation-baseline-before");
        let original = self.checked_preparation_baseline(session).await?;
        #[cfg(test)]
        trace_index_prepared("preparation-baseline-after");
        #[cfg(test)]
        trace.mark("prepare-baseline-captured");
        let started = original_started.unwrap_or_else(|| self.guard().clock().monotonic());
        if original_started.is_some() {
            self.check_time(started)?;
        }

        #[cfg(test)]
        trace.mark("prepare-original-deadline-origin-captured");
        let current = self.store().ref_get(session.reference()).await?;
        let base = session.record.clone();
        let changed = current != base;
        #[cfg(unix)]
        if changed && references.is_some() {
            return self
                .fence(session)
                .await
                .and_then(|_| Err(crate::guard::invalid().into()));
        }
        if changed && !Self::may_rebase(session, current.as_ref()) {
            return self
                .fence(session)
                .await
                .and_then(|_| Err(crate::guard::invalid().into()));
        }
        let terminal_secret = request.terminal_secret;
        #[cfg(test)]
        trace_index_prepared("admission-before");
        let admitted = if changed {
            self.guard()
                .admit_losing(
                    session.reference(),
                    session.epoch(),
                    request,
                    base.clone().ok_or_else(crate::guard::invalid)?,
                )
                .await?
        } else {
            #[cfg(unix)]
            let maintenance = references
                .as_ref()
                .and_then(|references| references.maintenance_purpose());
            #[cfg(not(unix))]
            let maintenance: Option<&crate::guard::index_maintenance::Purpose> = None;
            if let Some(purpose) = maintenance {
                self.guard()
                    .admit_index_rebuild(session.reference(), session.epoch(), request, purpose)
                    .await?
            } else {
                self.guard()
                    .admit(session.reference(), session.epoch(), request)
                    .await?
            }
        };
        #[cfg(test)]
        trace_index_prepared("admission-after");
        #[cfg(unix)]
        let admitted = if let Some(references) = references {
            references.check_candidate(self.guard(), &admitted).await?;
            let mut admitted = admitted;
            admitted.existing_owner_references = Some(references);
            admitted
        } else {
            admitted
        };
        self.check_time(started)?;
        #[cfg(test)]
        trace.mark("prepare-admission-and-existing-owner-evidence-complete");
        let losing_commit = admitted.commit.identity();
        let merge_base = base.as_ref().map(|record| record.commit);
        Ok(PreparedAdvance {
            pending: PendingAdvance {
                admitted,
                started,
                reason: RefLogReason::Commit,
                terminal_secret,
                base,
                changed,
            },
            original,
            merge_base,
            losing_commit,
            join: None,
            excluded: Vec::new(),
        })
    }

    /// Prepares a new destination's fork without publishing its fresh authored commit.
    ///
    /// # Errors
    /// Rejects an existing or fenced destination, missing retained baseline,
    /// invalid source or destination authority, and failed canonical fork admission.
    pub(crate) async fn prepare_fork(
        &self,
        session: &mut WriterSession,
        source: &str,
        request: CommitRequest,
    ) -> Result<PreparedAdvance, AdvanceError>
    where
        C: super::PublicationBinding,
    {
        if session.class != RefClass::Heads {
            return Err(AdvanceError::InvalidRefClass);
        }
        if session.fenced || session.record.is_some() {
            return Err(AdvanceError::Fenced {
                current: session.record.clone().map(Box::new),
            });
        }
        let original = self.checked_preparation_baseline(session).await?;
        let started = self.guard().clock().monotonic();
        let terminal_secret = request.terminal_secret;
        #[cfg(unix)]
        let admitted = self
            .guard()
            .prepare_cold_fork_native(session, source, &original, request, started, self.timing)
            .await?;
        #[cfg(not(unix))]
        let admitted = self
            .guard()
            .prepare_cold_fork_native(session, source, request, started, self.timing)
            .await?;
        self.check_time(started)?;
        let losing_commit = admitted.commit.identity();

        Ok(PreparedAdvance {
            pending: PendingAdvance {
                admitted,
                started,
                reason: RefLogReason::Commit,
                terminal_secret,
                base: None,
                changed: false,
            },
            original,
            merge_base: None,
            losing_commit,
            join: None,
            excluded: Vec::new(),
        })
    }

    /// Prepares an independently recomputed merge or fold through the same retention boundary.
    ///
    /// # Errors
    /// Rejects a stale session, missing exact original baseline, invalid current
    /// source or destination authority, or failed canonical algebra admission.
    pub(crate) async fn prepare_join(
        &self,
        session: &mut WriterSession,
        request: JoinRequest<'_>,
    ) -> Result<(PreparedAdvance, Vec<Vec<u8>>), AdvanceError> {
        #[cfg(test)]
        let mut trace = super::PhaseTrace::new(
            self.guard().clock(),
            session.reference(),
            None,
            None,
            "prepare-join-entry",
        );
        if session.fenced || self.store().ref_get(session.reference()).await? != session.record {
            return self
                .fence(session)
                .await
                .and_then(|_| Err(crate::guard::invalid().into()));
        }
        let original = self.checked_preparation_baseline(session).await?;
        #[cfg(test)]
        trace.mark("prepare-join-current-baseline-checked");
        let started = self.guard().clock().monotonic();
        let join = PreparedJoin {
            source: request.source.to_owned(),
            policies: request.policies.to_vec(),
            kind: request.kind,
        };
        let reason = match request.kind {
            JoinKind::Merge => RefLogReason::Merge,
            JoinKind::Fold => RefLogReason::Fold,
        };
        let terminal_secret = request.request.terminal_secret;
        let base = session.record.clone();
        let merge_base = base.as_ref().map(|record| record.commit);
        #[cfg(test)]
        trace.mark("prepare-join-signing-start");
        let (admitted, excluded) = self
            .guard()
            .admit_join(session.reference(), session.epoch(), request)
            .await?;
        #[cfg(test)]
        trace.mark("prepare-join-signed-candidate");
        self.check_time(started)?;
        let losing_commit = admitted.commit.identity();

        Ok((
            PreparedAdvance {
                pending: PendingAdvance {
                    admitted,
                    started,
                    reason,
                    terminal_secret,
                    base,
                    changed: false,
                },
                original,
                merge_base,
                losing_commit,
                join: Some(join),
                excluded: excluded.clone(),
            },
            excluded,
        ))
    }

    /// Publishes only a candidate whose exact protected original association is installed.
    ///
    /// A rebase result must pass through protected association retention again.
    /// An indeterminate final CAS never enters this retry path.
    ///
    /// # Errors
    /// Rejects another candidate's association, changed session identity or baseline,
    /// missing installed retention, expired deadlines, current policy denial, fencing,
    /// and underlying storage failures.
    pub(crate) async fn publish_prepared(
        &self,
        session: &mut WriterSession,
        prepared: PreparedAdvance,
        context: OriginalCommitContext,
    ) -> Result<PublicationStep, AdvanceError>
    where
        C: super::PublicationBinding,
    {
        #[cfg(test)]
        let mut trace = super::PhaseTrace::new(
            self.guard().clock(),
            session.reference(),
            Some(prepared.commit()),
            Some(prepared.pending.started),
            "publish-prepared-entry",
        );
        self.check_time(prepared.pending.started)?;
        if context.commit() != &prepared.commit()
            || context.baseline() != prepared.baseline()
            || context.baseline().reference() != session.reference()
            || context.baseline().epoch() != session.epoch()
            || self.guard().original_commit(context.commit())? != context
        {
            return Err(crate::guard::invalid().into());
        }
        // Installed snapshots provide identity, not freshness. The sealed
        // native verifier rereads the exact protected bytes before effects.
        #[cfg(test)]
        trace_index_prepared("publication-original-before");
        let checked = self
            .guard()
            .check_original_commit(
                context.baseline(),
                AssociationView {
                    commit: context.commit(),
                    id: context.baseline().authority().id(),
                    reference: context.baseline().reference(),
                    epoch: context.baseline().epoch(),
                },
            )
            .await?;
        #[cfg(test)]
        trace_index_prepared("publication-original-after");
        if checked != context {
            return Err(crate::guard::invalid().into());
        }
        self.check_time(prepared.pending.started)?;

        #[cfg(test)]
        trace.mark("publish-prepared-original-retained-checked");
        let PreparedAdvance {
            pending,
            original,
            merge_base,
            losing_commit,
            join,
            excluded,
        } = prepared;
        let PendingAdvance {
            admitted,
            started,
            reason,
            terminal_secret,
            base,
            changed,
        } = pending;
        let changed = changed || admitted.expected != base;
        let contextual_overlay = !admitted.overlay_sources.is_empty();
        // Generic merge rebasing would discard ordered input Read obligations
        // and replace the signed overlay recipe. A stale operation must be
        // explicitly prepared again under its actual source and destination.
        if changed && contextual_overlay {
            return self
                .fence(session)
                .await
                .and_then(|_| Err(crate::guard::invalid().into()));
        }
        #[cfg(unix)]
        if changed && admitted.existing_owner_references.is_some() {
            return self
                .fence(session)
                .await
                .and_then(|_| Err(crate::guard::invalid().into()));
        }
        if changed && !Self::may_rebase(session, admitted.expected.as_ref()) {
            return self
                .fence(session)
                .await
                .and_then(|_| Err(crate::guard::invalid().into()));
        }
        #[cfg(unix)]
        let existing_owner = admitted.existing_owner_references.is_some();
        let source_authorization = admitted.source_authorization.clone();
        let token = admitted.token.clone();
        let surface = admitted.surface.clone();
        if changed {
            #[cfg(test)]
            trace_index_prepared("losing-publication-before");
            self.guard()
                .publish_losing_native(
                    session,
                    super::RetainedPublication {
                        admitted,
                        original: context,
                        started,
                        reason,
                        timing: self.timing,
                    },
                    self.guard().clock(),
                )
                .await?;
            #[cfg(test)]
            trace_index_prepared("losing-publication-after");
        } else {
            #[cfg(test)]
            trace_index_prepared("retained-publication-before");
            match self
                .guard()
                .publish_retained_native(
                    session,
                    super::RetainedPublication {
                        admitted,
                        original: context,
                        started,
                        reason,
                        timing: self.timing,
                    },
                    self.guard().clock(),
                )
                .await
            {
                Ok(record) => {
                    #[cfg(test)]
                    trace_index_prepared("retained-publication-after");
                    return Ok(PublicationStep::Published(Box::new(FoldOutcome {
                        record,
                        excluded,
                    })));
                }
                #[cfg(unix)]
                Err(error @ AdvanceError::Fenced { .. }) if existing_owner => return Err(error),
                Err(error @ AdvanceError::Fenced { .. }) if contextual_overlay => {
                    return Err(error);
                }
                Err(AdvanceError::Fenced { .. }) => {}
                Err(error) => return Err(error),
            }
        }

        #[cfg(test)]
        trace.mark("publish-prepared-losing-candidate-fenced");
        let merge_base = merge_base.ok_or_else(crate::guard::invalid)?;
        loop {
            self.check_time(started)?;
            let current = self.store().ref_get(session.reference()).await?;
            if !Self::may_rebase(session, current.as_ref()) {
                return self
                    .fence(session)
                    .await
                    .and_then(|_| Err(crate::guard::invalid().into()));
            }
            let current = current.ok_or_else(crate::guard::invalid)?;
            let rebase = RebaseRequest {
                base: merge_base,
                ours: current.clone(),
                theirs: losing_commit,
                terminal_secret,
                token: token.clone(),
                surface: surface.clone(),
            };
            // A fold must be recomputed as a fold against current authority.
            // Merging the losing result would retain stale exclusion decisions.
            let fold = join
                .as_ref()
                .filter(|join| matches!(join.kind, JoinKind::Fold));
            #[cfg(test)]
            trace.mark("reprepare-signing-start");
            let recomputed = if let Some(join) = fold {
                let request = CommitRequest {
                    commit: self
                        .guard()
                        .verified_tree(losing_commit)
                        .await?
                        .commit
                        .commit()
                        .clone(),
                    uploads: Vec::new(),
                    token: token.clone(),
                    terminal_secret,
                    surface: surface.clone(),
                    reference_records: Vec::new(),
                    disclosures: Vec::new(),
                };
                self.guard()
                    .admit_join(
                        session.reference(),
                        session.epoch(),
                        JoinRequest {
                            source: &join.source,
                            request,
                            policies: &join.policies,
                            kind: join.kind,
                        },
                    )
                    .await
            } else {
                self.guard()
                    .admit_rebase(session.reference(), session.epoch(), rebase)
                    .await
                    .map(|admitted| (admitted, Vec::new()))
            };
            #[cfg(test)]
            trace.mark("reprepare-signing-finished");
            let (mut admitted, excluded) = match recomputed {
                Ok(result) => result,
                Err(error) => {
                    if self.store().ref_get(session.reference()).await? != Some(current) {
                        continue;
                    }
                    return Err(error.into());
                }
            };
            if fold.is_some()
                && admitted
                    .source_authorization
                    .as_ref()
                    .map(|source| &source.record)
                    != source_authorization.as_ref().map(|source| &source.record)
            {
                return Err(crate::guard::invalid().into());
            }
            admitted.source_authorization = source_authorization.clone();
            session.record = Some(current.clone());
            session.fenced = false;
            self.check_time(started)?;
            return Ok(PublicationStep::Reprepare(Box::new(PreparedAdvance {
                pending: PendingAdvance {
                    admitted,
                    started,
                    reason: if join
                        .as_ref()
                        .is_some_and(|join| matches!(join.kind, JoinKind::Fold))
                    {
                        RefLogReason::Fold
                    } else {
                        RefLogReason::Merge
                    },
                    terminal_secret,
                    base: Some(current),
                    changed: false,
                },
                original,
                merge_base: Some(merge_base),
                losing_commit,
                join,
                excluded,
            })));
        }
    }
}

#[cfg(all(feature = "std", unix))]
impl<S: Store, C: Clock, F: LocalFs> Coordinator<S, C, F> {
    /// Prepares a contextual layer or authenticated overlay under the same deadline.
    ///
    /// # Errors
    /// Preserves current authority, Original baseline and source-history failures;
    /// refuses a changed destination rather than replacing another writer's head.
    pub(crate) async fn prepare_algebra(
        &self,
        session: &mut WriterSession,
        request: CommitRequest,
        operation: super::overlay::AlgebraPreparation<'_>,
    ) -> Result<PreparedAdvance, AdvanceError> {
        if session.fenced {
            return Err(AdvanceError::Fenced {
                current: session.record.clone().map(Box::new),
            });
        }
        let original = self.checked_preparation_baseline(session).await?;
        let started = self.guard().clock().monotonic();
        if self.store().ref_get(session.reference()).await? != session.record {
            return self
                .fence(session)
                .await
                .and_then(|_| Err(crate::guard::invalid().into()));
        }
        let terminal_secret = request.terminal_secret;
        let admitted = match operation {
            super::overlay::AlgebraPreparation::Layer => {
                self.guard()
                    .admit_overlay_layer(session.reference(), session.epoch(), request)
                    .await?
            }
            super::overlay::AlgebraPreparation::Overlay(inputs) => {
                self.guard()
                    .admit_overlay(session.reference(), session.epoch(), inputs, request)
                    .await?
            }
        };
        if admitted.expected != session.record {
            return self
                .fence(session)
                .await
                .and_then(|_| Err(crate::guard::invalid().into()));
        }
        self.check_time(started)?;
        let losing_commit = admitted.commit.identity();
        let base = session.record.clone();
        let merge_base = base.as_ref().map(|record| record.commit);
        Ok(PreparedAdvance {
            pending: PendingAdvance {
                admitted,
                started,
                reason: RefLogReason::Commit,
                terminal_secret,
                base,
                changed: false,
            },
            original,
            merge_base,
            losing_commit,
            join: None,
            excluded: Vec::new(),
        })
    }
}

#[cfg(all(feature = "std", unix))]
impl PreparedAdvance {
    /// Borrows the actual admitted immutable layer and its original deadline.
    pub(super) fn algebra_inputs(&self) -> (&crate::guard::AdmittedCommit, std::time::Duration) {
        (&self.pending.admitted, self.pending.started)
    }
}
