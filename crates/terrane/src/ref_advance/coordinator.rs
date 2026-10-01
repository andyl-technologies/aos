//! Publishes immutable objects before create-once reflogs and whole-record CAS.

use std::fmt;
use std::time::Duration;

use terrane_core::auth::Verb;
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::refs::{RefClass, RefLogReason, RefLogRecord, RefName, RefRecord};

use super::CommitRequest;
use crate::guard::{AdmittedCommit, Guard, HistoryObservation, JoinKind, JoinRequest};
use crate::store::{
    Clock, ContentUpload, LocalFs, MetaUpload, RefLogAppendOutcome, Store, StoreFailure,
};

/// Bounds a publication attempt strictly inside its store's garbage-collection grace window.
#[derive(Clone, Copy, Debug)]
pub struct CommitTiming {
    maximum: Duration,
}

impl CommitTiming {
    /// Returns the unchanged maximum duration retained by this publication.
    pub(crate) fn maximum(self) -> Duration {
        self.maximum
    }

    /// Validates the maximum commit duration and reserved safety margin.
    ///
    /// # Errors
    /// Rejects zero durations or a maximum that reaches the grace window minus its margin.
    pub fn new(maximum: Duration, grace: Duration, margin: Duration) -> Result<Self, AdvanceError> {
        if maximum.is_zero()
            || margin.is_zero()
            || grace
                .checked_sub(margin)
                .is_none_or(|limit| maximum >= limit)
        {
            return Err(AdvanceError::InvalidTiming);
        }
        Ok(Self { maximum })
    }
}

/// Reports publication, fencing, and duration failures without conflating CAS conflicts with transport errors.
#[derive(Debug)]
pub enum AdvanceError {
    /// Another writer superseded the exact record this session read.
    Fenced {
        /// Freshly reread authority value after the conflict.
        current: Option<Box<RefRecord>>,
    },
    /// Publication exceeded its permitted monotonic duration and must restart with new packs.
    Expired,
    /// The configured publication window is not strictly inside the grace window.
    InvalidTiming,
    /// The sequence or writer epoch cannot increase further.
    Exhausted,
    /// The operation does not apply to this ref class.
    InvalidRefClass,
    /// The underlying guard or store rejected an operation.
    Store(StoreFailure),
    /// The authority write failed after it may have crossed its linearization point.
    Indeterminate {
        /// Authority value observed after the failure, when a read was available.
        observed: Result<Option<Box<RefRecord>>, StoreFailure>,
        /// Storage failure whose durability outcome cannot be inferred.
        source: Box<StoreFailure>,
    },
}

impl fmt::Display for AdvanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fenced { .. } => formatter.write_str("writer session fenced"),
            Self::Expired => formatter.write_str("commit publication window expired"),
            Self::InvalidTiming => formatter.write_str("invalid commit publication window"),
            Self::Exhausted => formatter.write_str("ref counter exhausted"),
            Self::InvalidRefClass => {
                formatter.write_str("operation does not apply to this ref class")
            }
            Self::Store(source) => fmt::Display::fmt(source, formatter),
            Self::Indeterminate { .. } => {
                formatter.write_str("ref publication outcome indeterminate")
            }
        }
    }
}

impl std::error::Error for AdvanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(source) => Some(source),
            Self::Indeterminate { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl From<StoreFailure> for AdvanceError {
    fn from(value: StoreFailure) -> Self {
        Self::Store(value)
    }
}

/// Retains one incremented writer epoch and its exact last acknowledged authority record.
#[derive(Clone, Debug)]
pub struct WriterSession {
    pub(super) reference: String,
    pub(super) epoch: u64,
    pub(super) record: Option<RefRecord>,
    pub(super) fenced: bool,
    pub(super) class: RefClass,
    pub(super) scopes: Vec<Vec<u8>>,
}

/// Supplies canonical attestation data and the tagging capability's terminal signing key.
pub struct TagAnnotation {
    /// Canonical CBOR map carried by the signed snapshot envelope.
    pub attestation: Vec<u8>,
    /// Secret seed matching the authenticated capability's terminal public key.
    pub terminal_secret: [u8; 32],
}

/// Retains one admitted proposal and its original publication deadline.
pub(super) struct PendingAdvance {
    pub(super) admitted: AdmittedCommit,
    pub(super) started: Duration,
    pub(super) reason: RefLogReason,
    pub(super) terminal_secret: [u8; 32],
    pub(super) base: Option<RefRecord>,
    pub(super) changed: bool,
}

/// Reports the published parent record and deterministic fold exclusions.
pub struct FoldOutcome {
    /// Whole newly acknowledged parent authority record.
    pub record: RefRecord,
    /// Child-relative paths excluded by current destination Commit authority.
    pub excluded: Vec<Vec<u8>>,
}

impl WriterSession {
    /// Returns the canonical branch name bound to this session.
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Returns the fencing token selected before the session's first write.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the last complete record acknowledged by this session.
    pub fn record(&self) -> Option<&RefRecord> {
        self.record.as_ref()
    }

    /// Returns the canonical roots authorized when this session began.
    ///
    /// These scopes confer no authority; every actual mutation still requires
    /// independently checked current grants and root ACLs.
    pub fn scopes(&self) -> &[Vec<u8>] {
        &self.scopes
    }
}

/// Coordinates guarded local repository operations through the canonical store traits.
pub struct Coordinator<S, C, F> {
    fs: F,
    guard: Guard<S, C>,
    pub(super) timing: CommitTiming,
}

impl<S, C, F> Coordinator<S, C, F> {
    /// Creates an authority coordinator with validated garbage-collection timing.
    pub fn new(guard: Guard<S, C>, timing: CommitTiming, fs: F) -> Self {
        Self { guard, timing, fs }
    }

    /// Returns the repository's authorization enforcement point.
    pub fn guard(&self) -> &Guard<S, C> {
        &self.guard
    }

    pub(crate) fn fs(&self) -> &F {
        &self.fs
    }

    pub(crate) fn store(&self) -> &S {
        self.guard.store()
    }
}

impl<S: Store, C: Clock, F: LocalFs> Coordinator<S, C, F> {
    /// Creates an immutable tag from the exact currently authorized source head.
    ///
    /// # Errors
    /// Denies missing or changing source authority, non-tag destinations, existing
    /// names, expired publication windows, and unavailable storage. An uncertain
    /// final write returns the authoritative reread without claiming durability.
    /// An absent checked native publication binding reports Unsupported before effects.
    pub async fn tag(
        &self,
        source: &str,
        target: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<RefRecord, AdvanceError>
    where
        C: super::PublicationBinding,
    {
        self.publish_tag(source, target, token, surface, None).await
    }

    /// Creates an immutable tag with a terminal-key authenticated annotation.
    ///
    /// # Errors
    /// Returns tag publication errors and rejects malformed attestations or a
    /// signing key that does not match the authenticated source capability.
    pub async fn annotated_tag(
        &self,
        source: &str,
        target: &str,
        token: &[u8],
        surface: &str,
        annotation: &TagAnnotation,
    ) -> Result<RefRecord, AdvanceError>
    where
        C: super::PublicationBinding,
    {
        self.publish_tag(source, target, token, surface, Some(annotation))
            .await
    }

    async fn publish_tag(
        &self,
        source: &str,
        target: &str,
        token: &[u8],
        surface: &str,
        annotation: Option<&TagAnnotation>,
    ) -> Result<RefRecord, AdvanceError>
    where
        C: super::PublicationBinding,
    {
        let started = self.guard.clock().monotonic();
        let mut publication = self.guard.admit_tag(source, target, token, surface).await?;
        if let Some(annotation) = annotation {
            self.guard
                .annotate_tag(source, token, surface, &mut publication, annotation)?;
        }
        self.check_time(started)?;
        self.guard
            .publish_tag_native(
                super::NativeTagRequest {
                    source: source.to_owned(),
                    target: target.to_owned(),
                    token: token.to_vec(),
                    surface: surface.to_owned(),
                    publication,
                    started,
                    timing: self.timing,
                },
                self.guard.clock(),
            )
            .await
    }

    /// Starts a writer session with an epoch strictly above the current authority record.
    ///
    /// # Errors
    /// Denies unauthorized writers, non-branch names, unavailable current policy,
    /// and exhausted epoch counters.
    pub async fn begin(
        &self,
        reference: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<WriterSession, AdvanceError> {
        self.begin_with_paths(reference, token, &[], surface).await
    }

    /// Starts a writer session at selected actual root authorization units.
    ///
    /// Entry paths normalize to their containing graft roots. Session scope
    /// cannot authorize sibling mutations or replace canonical change checks.
    ///
    /// # Errors
    /// Rejects empty scopes, invalid paths, unauthorized roots, unmaterialized
    /// child roots, unsupported ref classes, and exhausted epoch counters.
    pub async fn begin_scoped(
        &self,
        reference: &str,
        token: &[u8],
        paths: &[Vec<u8>],
        surface: &str,
    ) -> Result<WriterSession, AdvanceError> {
        if paths.is_empty() {
            return Err(crate::guard::invalid().into());
        }
        self.begin_with_paths(reference, token, paths, surface)
            .await
    }

    async fn begin_with_paths(
        &self,
        reference: &str,
        token: &[u8],
        paths: &[Vec<u8>],
        surface: &str,
    ) -> Result<WriterSession, AdvanceError> {
        #[cfg(test)]
        let mut trace =
            super::PhaseTrace::new(self.guard.clock(), reference, None, None, "begin-entry");
        let name = RefName::parse(reference).map_err(|_| AdvanceError::InvalidRefClass)?;
        // Notes are opaque sidecars; only commit-pointer branches have sessions.
        if !matches!(
            name.class(),
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        ) {
            return Err(AdvanceError::InvalidRefClass);
        }
        let authorized = self
            .guard
            .authorize(reference, token, Verb::Commit, paths, surface)
            .await?;
        #[cfg(test)]
        trace.mark("begin-current-authorized");
        let record = authorized.record().cloned();
        let mut scopes = authorized.root_paths().to_vec();
        scopes.sort();
        scopes.dedup();
        if record.is_none() && scopes != [b"/".to_vec()] {
            return Err(crate::guard::invalid().into());
        }
        let epoch = record
            .as_ref()
            .map_or(0, |record| record.writer_epoch)
            .checked_add(1)
            .ok_or(AdvanceError::Exhausted)?;
        Ok(WriterSession {
            reference: reference.to_owned(),
            epoch,
            record,
            fenced: false,
            class: name.class(),
            scopes,
        })
    }

    /// Admits and publishes a commit, appends its exact reflog key, then swaps the whole previous record.
    ///
    /// # Errors
    /// Rejects failed current authorization or signature checks before publication.
    /// Failures before CAS leave the head unchanged. A final storage failure
    /// reports an indeterminate outcome and permanently fences the session;
    /// callers cannot infer a durable acknowledgement from a reread. A losing
    /// single-writer session cannot reuse its epoch. Missing retained original
    /// baseline or exact candidate association is refused before effects. A
    /// reprepare requires the repository retention loop and returns Unsupported
    /// through this legacy record-only entry point.
    pub async fn advance(
        &self,
        session: &mut WriterSession,
        request: CommitRequest,
    ) -> Result<RefRecord, AdvanceError>
    where
        C: super::PublicationBinding,
    {
        let prepared = self.prepare_advance(session, request).await?;
        self.publish_installed(session, prepared)
            .await
            .map(|outcome| outcome.record)
    }

    /// Checks monotone authority and home before admitting a multiwriter retry.
    pub(crate) fn may_rebase(session: &WriterSession, current: Option<&RefRecord>) -> bool {
        session.record.as_ref().is_some_and(|base| {
            current.is_some_and(|record| {
                record.home == base.home
                    && record.seq >= base.seq
                    && record.writer_epoch >= base.writer_epoch
                    && record.writer_epoch <= session.epoch
                    && record
                        .policy
                        .as_ref()
                        .is_some_and(|policy| policy.multi_writer == Some(true))
            })
        })
    }

    /// Creates a branch with a fresh signed commit over the unchanged source tree.
    ///
    /// # Errors
    /// Denies missing source Fork authority or destination Commit authority,
    /// an existing destination, invalid signing keys, absent protected candidate
    /// retention, and publication failures. Reprepare requires the repository loop.
    pub async fn fork(
        &self,
        source: &str,
        target: &str,
        request: CommitRequest,
    ) -> Result<RefRecord, AdvanceError>
    where
        C: super::PublicationBinding,
    {
        let mut session = self.begin(target, &request.token, &request.surface).await?;
        let prepared = self.prepare_fork(&mut session, source, request).await?;
        self.publish_installed(&mut session, prepared)
            .await
            .map(|outcome| outcome.record)
    }

    /// Advances a branch to an authenticated earlier commit without rewriting its history.
    ///
    /// # Errors
    /// Denies targets outside the current ancestry, missing current Commit or
    /// property-change authority, absent protected original context or native
    /// dispatch, fenced sessions, and publication failures.
    pub async fn rollback(
        &self,
        session: &mut WriterSession,
        target: terrane_core::identity::Digest,
        token: &[u8],
        surface: &str,
    ) -> Result<RefRecord, AdvanceError> {
        if session.fenced || self.store().ref_get(&session.reference).await? != session.record {
            return self.fence(session).await;
        }
        if !matches!(
            session.class,
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        ) {
            return Err(AdvanceError::InvalidRefClass);
        }
        let started = self.guard.clock().monotonic();
        let admitted = self
            .guard
            .admit_rollback(&session.reference, target, token, surface)
            .await?;
        self.publish(session, admitted, started, RefLogReason::Rollback)
            .await
    }

    /// Changes an existing ref policy through a current Admin-authorized ordinary advance.
    ///
    /// # Errors
    /// Denies missing current Admin authority, invalid policy combinations,
    /// tags or opaque Notes sidecars, absent protected original context or
    /// native dispatch, counter exhaustion, and durable publication failures.
    pub async fn set_policy(
        &self,
        reference: &str,
        policy: Option<terrane_core::refs::RefPolicy>,
        token: &[u8],
        surface: &str,
    ) -> Result<RefRecord, AdvanceError> {
        let name = RefName::parse(reference).map_err(|_| AdvanceError::InvalidRefClass)?;
        if !matches!(
            name.class(),
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        ) {
            return Err(AdvanceError::InvalidRefClass);
        }
        let started = self.guard.clock().monotonic();
        let admitted = self
            .guard
            .admit_policy(reference, policy, token, surface)
            .await?;
        let epoch = admitted
            .expected
            .as_ref()
            .ok_or_else(crate::guard::invalid)?
            .writer_epoch
            .checked_add(1)
            .ok_or(AdvanceError::Exhausted)?;
        let mut session = WriterSession {
            reference: reference.to_owned(),
            epoch,
            record: admitted.expected.clone(),
            fenced: false,
            class: name.class(),
            scopes: vec![b"/".to_vec()],
        };
        self.publish(&mut session, admitted, started, RefLogReason::Commit)
            .await
    }

    /// Merges a source ref using a verified DAG base and ordered current-policy inputs.
    ///
    /// The request supplies signing credentials and metadata. Its uploads must
    /// be empty; the guard recomputes the tree, recipe and receipt selections.
    ///
    /// # Errors
    /// Denies current source Read or destination Commit authority, rejects
    /// unrelated or ambiguous merge bases, absent protected candidate retention,
    /// and reports publication failures. Reprepare requires the repository loop.
    pub async fn merge(
        &self,
        session: &mut WriterSession,
        source: &str,
        request: CommitRequest,
        policies: &[terrane_core::refs::MergePolicy],
    ) -> Result<RefRecord, AdvanceError>
    where
        C: super::PublicationBinding,
    {
        self.join(
            session,
            JoinRequest {
                source,
                request,
                policies,
                kind: JoinKind::Merge,
            },
        )
        .await
        .map(|(record, _)| record)
    }

    /// Folds child changes from their authenticated fork point into the parent ref.
    ///
    /// The child remains available after publication. Retirement requires a
    /// separate authorized operation; exclusions are returned explicitly.
    ///
    /// # Errors
    /// Denies source Fork or destination Commit authority, invalid fork ancestry,
    /// nonempty caller uploads, unresolved error policies, absent protected
    /// candidate retention, and publication failures. Reprepare requires the repository loop.
    pub async fn fold(
        &self,
        session: &mut WriterSession,
        source: &str,
        request: CommitRequest,
        policies: &[terrane_core::refs::MergePolicy],
    ) -> Result<FoldOutcome, AdvanceError>
    where
        C: super::PublicationBinding,
    {
        let (record, excluded) = self
            .join(
                session,
                JoinRequest {
                    source,
                    request,
                    policies,
                    kind: JoinKind::Fold,
                },
            )
            .await?;
        Ok(FoldOutcome { record, excluded })
    }

    async fn join(
        &self,
        session: &mut WriterSession,
        request: JoinRequest<'_>,
    ) -> Result<(RefRecord, Vec<Vec<u8>>), AdvanceError>
    where
        C: super::PublicationBinding,
    {
        let (prepared, _) = self.prepare_join(session, request).await?;
        let outcome = self.publish_installed(session, prepared).await?;
        Ok((outcome.record, outcome.excluded))
    }

    pub(super) async fn publish(
        &self,
        session: &mut WriterSession,
        admitted: AdmittedCommit,
        started: Duration,
        reason: RefLogReason,
    ) -> Result<RefRecord, AdvanceError> {
        let clock = self
            .guard
            .clock()
            .retain_native_clock()
            .map_err(|failure| {
                let kind = if failure.kind() == std::io::ErrorKind::Unsupported {
                    crate::store::StoreErrorKind::Unsupported
                } else {
                    crate::store::StoreErrorKind::Unavailable { retry_after: None }
                };
                StoreFailure::with_source(kind, failure)
            })?;
        self.revalidate_source_observed(&admitted, HistoryObservation::default())
            .await?;
        let original = self.guard.original_commit(&admitted.commit.identity())?;
        self.guard
            .publish_retained_native(
                session,
                super::RetainedPublication {
                    admitted,
                    original,
                    started,
                    reason,
                    timing: self.timing,
                },
                &clock,
            )
            .await
    }

    /// Stages durable content and a candidate log before the final ref installation.
    ///
    /// The returned record is data, not a publication capability. A selected
    /// publication producer must independently bind the final current checks and
    /// consumed controls to its held observation before publishing that record.
    ///
    /// # Errors
    /// Propagates admission, protected-control, durability, expiry and fencing
    /// failures before the final ref installation.
    pub(crate) async fn stage_observed_ref(
        &self,
        session: &mut WriterSession,
        admitted: &mut AdmittedCommit,
        started: Duration,
        reason: RefLogReason,
        observation: super::PublicationObservation<'_>,
        retained_previous: Option<&RefRecord>,
    ) -> Result<RefRecord, AdvanceError> {
        #[cfg(test)]
        let mut trace = super::PhaseTrace::new(
            self.guard.clock(),
            session.reference(),
            Some(admitted.commit.identity()),
            Some(started),
            "stage-entry",
        );
        let super::PublicationObservation {
            history: observation,
            original,
        } = observation;
        if admitted.expected != session.record {
            return self.fence(session).await;
        }
        if let Some(original) = original {
            self.guard
                .revalidate_original_context(original, observation)
                .await?;
        }
        #[cfg(test)]
        trace.mark("stage-original-checked");
        let current = self
            .guard
            .authorize_observed(
                &session.reference,
                &admitted.token,
                admitted.publication_verb,
                &[],
                &admitted.surface,
                observation,
            )
            .await?;
        if current.record() != session.record.as_ref() {
            if Self::may_rebase(session, current.record()) {
                // Preserve this checked losing candidate under the same live
                // policy fence before returning it to ordered core merge.
                admitted.observed_current = current.record().cloned();
                self.publish_immutable_observed(admitted, started, observation)
                    .await?;
            }
            return self.fence(session).await;
        }
        #[cfg(test)]
        trace.mark("stage-immutable-start");
        self.publish_immutable_observed(admitted, started, observation)
            .await?;
        #[cfg(test)]
        trace.mark("stage-immutable-durable");

        // Capability expiry and current authority can change while immutable
        // content is becoming durable. Recheck before installing any log or
        // mutable ref; the exact-record CAS fences a concurrent later advance.
        let token = &admitted.token;
        let authorization = self
            .guard
            .authorize_observed(
                &session.reference,
                token,
                admitted.publication_verb,
                &[],
                &admitted.surface,
                observation,
            )
            .await?;
        if authorization.record() != session.record.as_ref() {
            return self.fence(session).await;
        }

        #[cfg(test)]
        trace.mark("stage-post-content-current-checked");
        self.revalidate_source_observed(admitted, observation)
            .await?;

        #[cfg(test)]
        trace.mark("stage-post-content-source-checked");
        let historical_previous = session.record.as_ref().or(retained_previous);
        let mut next = match historical_previous {
            Some(record) => record
                .advance(admitted.commit.identity(), session.epoch)
                .map_err(|_| AdvanceError::Exhausted)?,
            None => RefRecord::first(
                admitted.commit.identity(),
                session.epoch,
                self.guard.config().home.clone(),
            ),
        };
        if let Some(policy) = &admitted.policy_override {
            next.policy = policy.clone();
        }
        if next.policy.is_none() && admitted.commit.commit().profile_pair.conflicted == Some(true) {
            next.policy = Some(terrane_core::refs::RefPolicy::default());
        }
        if let Some(policy) = &mut next.policy {
            policy.conflicted = admitted.commit.commit().profile_pair.conflicted;
        }
        if matches!(
            session.class,
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        ) {
            loop {
                self.check_time(started)?;
                next.candidate_id = Some(self.candidate_id().await?);
                let log = RefLogRecord {
                    record: next.clone(),
                    previous_commit: historical_previous.map(|record| record.commit),
                    principal: admitted.principal.clone(),
                    reason,
                    timestamp: admitted.timestamp,
                    expected_previous: Some(session.record.clone()),
                    committed_previous: if session.record.is_none() {
                        retained_previous.cloned()
                    } else {
                        None
                    },
                };
                match self
                    .store()
                    .ref_log_append(&session.reference, next.seq, &log)
                    .await?
                {
                    RefLogAppendOutcome::Appended => break,
                    RefLogAppendOutcome::Exists => {
                        let current = self.store().ref_get(&session.reference).await?;
                        if current != session.record {
                            return self.fence(session).await;
                        }
                        // An abandoned proposal cannot occupy the successor
                        // sequence. A new secure selector restarts this attempt
                        // without extending the original publication deadline.
                    }
                }
            }
        }
        #[cfg(test)]
        trace.mark("stage-log-durable");
        self.check_time(started)?;
        self.guard
            .revalidate_admission_observed(admitted, observation)
            .await?;
        self.revalidate_source_observed(admitted, observation)
            .await?;
        if let Some(original) = original {
            self.guard
                .revalidate_original_context(original, observation)
                .await?;
        }
        let current = self
            .guard
            .authorize_observed(
                &session.reference,
                &admitted.token,
                admitted.publication_verb,
                &[],
                &admitted.surface,
                observation,
            )
            .await?;
        if current.record() != session.record.as_ref() {
            return self.fence(session).await;
        }
        self.check_time(started)?;
        #[cfg(test)]
        trace.mark("stage-final-current-original-source-checked");
        observation.finish()?;
        Ok(next)
    }

    /// Acknowledges a record after the actual checked selected publication.
    ///
    /// The sealed producer validates the exact successor before dispatch and
    /// calls this only after the selected slot and portable pointer are durable.
    /// Updating session bookkeeping cannot mint repository authority.
    pub(crate) fn acknowledge_selected(
        &self,
        session: &mut WriterSession,
        next: RefRecord,
    ) -> RefRecord {
        session.record = Some(next.clone());
        next
    }

    /// Preserves uncertainty after an unavailable selected publication dispatch.
    ///
    /// The session remains fenced and the actual authoritative reread retains
    /// its own error; a failed reread is never reported as an absent head.
    pub(crate) async fn selected_indeterminate(
        &self,
        session: &mut WriterSession,
        source: StoreFailure,
    ) -> AdvanceError {
        session.fenced = true;
        let observed = self
            .store()
            .ref_get(session.reference())
            .await
            .map(|record| record.map(Box::new));
        AdvanceError::Indeterminate {
            observed,
            source: Box::new(source),
        }
    }

    async fn revalidate_source_observed(
        &self,
        admitted: &AdmittedCommit,
        observation: HistoryObservation<'_>,
    ) -> Result<(), AdvanceError> {
        self.capture_source_authorizations_observed(admitted, observation)
            .await
            .map(|_| ())
    }

    /// Retains genuine source requests after checking their exact whole records.
    ///
    /// # Errors
    /// Rejects current source denial or changes and preserves storage failures.
    pub(crate) async fn capture_source_authorizations_observed(
        &self,
        admitted: &AdmittedCommit,
        observation: HistoryObservation<'_>,
    ) -> Result<Vec<crate::guard::AuthorizedRef>, AdvanceError> {
        let mut captured = Vec::new();
        if let Some(source) = &admitted.source_authorization {
            for path in &source.paths {
                let current = self
                    .guard
                    .authorize_observed(
                        &source.reference,
                        &admitted.token,
                        source.verb,
                        std::slice::from_ref(path),
                        &admitted.surface,
                        observation,
                    )
                    .await?;
                if current.record() != Some(&source.record) {
                    return Err(crate::guard::denied(&source.reference, source.verb).into());
                }
                captured.push(current);
            }
        }
        Ok(captured)
    }

    pub(crate) async fn publish_immutable_observed(
        &self,
        admitted: &AdmittedCommit,
        started: Duration,
        observation: HistoryObservation<'_>,
    ) -> Result<(), AdvanceError> {
        #[cfg(test)]
        let mut trace = super::PhaseTrace::new(
            self.guard.clock(),
            admitted
                .commit
                .commit()
                .profile_pair
                .commit_context
                .as_ref()
                .map_or("<missing-signed-context>", |context| context.reference()),
            Some(admitted.commit.identity()),
            Some(started),
            "immutable-entry",
        );
        self.check_time(started)?;
        self.revalidate_source_observed(admitted, observation)
            .await?;
        self.guard
            .revalidate_admission_observed(admitted, observation)
            .await?;
        #[cfg(test)]
        trace.mark("immutable-source-admission-checked");
        observation
            .record_candidate(self.store(), admitted, self.guard().config().min_chunk_size)
            .await?;
        #[cfg(test)]
        trace.mark("immutable-candidate-evidence-recorded");
        for upload in &admitted.uploads {
            self.store().put(upload.as_upload()?).await?;
            self.check_time(started)?;
        }
        #[cfg(test)]
        trace.mark("immutable-upload-bodies-durable");
        let encoded = admitted
            .commit
            .commit()
            .encode()
            .map_err(|_| AdvanceError::Store(crate::guard::invalid()))?;
        let identity = self
            .store()
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Commit,
                &encoded,
            )?))
            .await?;
        let expected_identity = TERRANE_V1
            .from_digest(IdentityKind::Commit, &admitted.commit.identity())
            .map_err(|_| AdvanceError::Store(crate::guard::invalid()))?;
        if identity != expected_identity {
            return Err(crate::guard::invalid().into());
        }
        self.check_time(started)?;

        Ok(())
    }

    async fn candidate_id(&self) -> Result<[u8; 32], AdvanceError> {
        let bytes = self.fs().random_bytes(32).await.map_err(|error| {
            AdvanceError::Store(StoreFailure::with_source(
                crate::store::StoreErrorKind::Unavailable { retry_after: None },
                error,
            ))
        })?;
        bytes.try_into().map_err(|_| crate::guard::invalid().into())
    }

    /// Checks the unchanged monotonic deadline for one publication attempt.
    ///
    /// # Errors
    /// Returns `Expired` for a reversed clock or an elapsed publication window.
    pub(crate) fn check_time(&self, started: Duration) -> Result<(), AdvanceError> {
        let elapsed = self
            .guard
            .clock()
            .monotonic()
            .checked_sub(started)
            .ok_or(AdvanceError::Expired)?;
        if elapsed > self.timing.maximum {
            Err(AdvanceError::Expired)
        } else {
            Ok(())
        }
    }

    /// Fences a session and returns the current complete authority observation.
    ///
    /// # Errors
    /// Returns the fenced outcome or preserves an unavailable current-record read.
    pub(crate) async fn fence(
        &self,
        session: &mut WriterSession,
    ) -> Result<RefRecord, AdvanceError> {
        session.fenced = true;
        let current = self.store().ref_get(&session.reference).await?;
        Err(AdvanceError::Fenced {
            current: current.map(Box::new),
        })
    }
}
