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
use terrane_core::identity::Digest;
use terrane_core::refs::{MergePolicy, RefClass, RefLogReason};

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
    /// Returns the exact signed immutable candidate requiring durable association.
    pub(crate) fn commit(&self) -> Digest {
        self.pending.admitted.commit.identity()
    }

    /// Returns the checked original baseline governing this candidate's ref and epoch.
    pub(crate) fn baseline(&self) -> &RetainedBootstrap {
        &self.original
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
        if session.fenced {
            return Err(AdvanceError::Fenced {
                current: session.record.clone().map(Box::new),
            });
        }
        let original = self.checked_preparation_baseline(session).await?;
        let started = self.guard().clock().monotonic();
        let current = self.store().ref_get(session.reference()).await?;
        let base = session.record.clone();
        let changed = current != base;
        if changed && !Self::may_rebase(session, current.as_ref()) {
            return self
                .fence(session)
                .await
                .and_then(|_| Err(crate::guard::invalid().into()));
        }
        let terminal_secret = request.terminal_secret;
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
            self.guard()
                .admit(session.reference(), session.epoch(), request)
                .await?
        };
        self.check_time(started)?;
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
    ) -> Result<PreparedAdvance, AdvanceError> {
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
        let admitted = self
            .guard()
            .admit_fork(source, session.reference(), session.epoch(), request)
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
        if changed && !Self::may_rebase(session, admitted.expected.as_ref()) {
            return self
                .fence(session)
                .await
                .and_then(|_| Err(crate::guard::invalid().into()));
        }
        let source_authorization = admitted.source_authorization.clone();
        let token = admitted.token.clone();
        let surface = admitted.surface.clone();
        if changed {
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
        } else {
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
                    return Ok(PublicationStep::Published(Box::new(FoldOutcome {
                        record,
                        excluded,
                    })));
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
