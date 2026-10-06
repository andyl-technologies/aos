//! Capture-first result publication through the original campaign actor.
//!
//! Replay objects remain protected until a durable actor root precedes the
//! committed producer journal. Failure retains the linear result and actual
//! accounting custody; dropping a diagnostic never authorizes their discharge.

use super::*;
use crate::executor_pool::CampaignActorPort;
use crate::stage_prepared_attempt_result;
use crucible_api::host_operational::HostOperationalError;
use crucible_campaign::CampaignRepositoryGcExclusionGuard;
use std::error::Error;
use std::fmt;

/// Retains the result and its authentic inventory fence on a failed handoff.
pub(crate) struct AdmittedPreparedResultFailure {
    source: Box<dyn Error + Send>,
    held: Option<RetainedResult>,
}

struct RetainedResult {
    _prepared: Box<PreparedAttemptResult>,
    _fence: Option<CampaignRepositoryGcExclusionGuard>,
    _actor: Arc<dyn Send + Sync>,
}

impl fmt::Debug for AdmittedPreparedResultFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedPreparedResultFailure")
            .field("source", &self.source)
            .field("result_retained", &self.held.is_some())
            .finish()
    }
}

impl fmt::Display for AdmittedPreparedResultFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "admitted capture publication handoff: {}",
            self.source
        )
    }
}

impl Error for AdmittedPreparedResultFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl Drop for AdmittedPreparedResultFailure {
    fn drop(&mut self) {
        if let Some(held) = self.held.take() {
            // A later recovery operation may reconcile a committed journal.
            // Until then, retain physical source authority and the real actor.
            let _quarantined_for_process_lifetime = Box::leak(Box::new(held));
        }
    }
}

/// Preserves the concrete failure of supervised replay capture publication.
#[derive(Debug)]
pub(crate) enum SemanticReplayCaptureBindingError {
    CaptureInputs(crate::FindingProductionReplayCaptureError),
    Store(crate::FindingReplayCaptureStoreError),
    Repository(crucible_campaign::CampaignRepositoryError),
    Semantic(PreparedSemanticResultCodecError),
}

impl fmt::Display for SemanticReplayCaptureBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaptureInputs(source) => write!(formatter, "replay capture inputs: {source}"),
            Self::Store(source) => write!(formatter, "replay capture storage: {source}"),
            Self::Repository(source) => write!(formatter, "replay capture publication: {source}"),
            Self::Semantic(source) => write!(formatter, "replay capture binding: {source}"),
        }
    }
}

impl Error for SemanticReplayCaptureBindingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CaptureInputs(source) => Some(source),
            Self::Store(source) => Some(source),
            Self::Repository(source) => Some(source),
            Self::Semantic(source) => Some(source),
        }
    }
}

/// Publishes and binds fresh replay captures while retaining the real GC fence.
///
/// A reproduction Service owns the result and native cleanup independently of
/// campaign execution staging. Its caller retains this returned fence through
/// complete semantic publication and never constructs another queued token.
///
/// # Errors
/// Returns capture, backend, or semantic binding errors before publication.
pub(crate) fn bind_admitted_semantic_replay_captures(
    store: &CampaignExecutorStore,
    result: &mut PreparedSemanticAttemptResult,
    guard: &crucible_linux_resource::host_supervision::HostOperationGuard,
) -> Result<Option<CampaignRepositoryGcExclusionGuard>, SemanticReplayCaptureBindingError> {
    let mut boundary = || {
        guard
            .wait_slice()
            .map(|_| ())
            .map_err(crate::FindingReplayCaptureStoreError::from)
    };
    boundary().map_err(SemanticReplayCaptureBindingError::Store)?;
    let Some(inputs) = result
        .production_replay_capture_inputs()
        .map_err(SemanticReplayCaptureBindingError::CaptureInputs)?
    else {
        return Ok(None);
    };
    let captures =
        crate::FindingReplayCaptureStore::prepare_set_with_boundary(inputs, &mut boundary)
            .map_err(SemanticReplayCaptureBindingError::Store)?;
    let publication = store
        .acquire_finding_replay_publication_guard()
        .map_err(SemanticReplayCaptureBindingError::Repository)?;
    let published = crate::FindingReplayCaptureStore::publish_set_with_boundary(
        &publication,
        &captures,
        &mut boundary,
    );
    let fence = publication.into_gc_exclusion();
    published.map_err(SemanticReplayCaptureBindingError::Store)?;
    let finding = result
        .prepare_bound_production_replay_finding(captures.references())
        .map_err(SemanticReplayCaptureBindingError::Semantic)?;
    result.commit_bound_production_replay_finding(finding);
    boundary().map_err(SemanticReplayCaptureBindingError::Store)?;
    Ok(Some(fence))
}

/// Stages capture roots before exposing a complete producer journal.
///
/// # Errors
/// Returns a failure owning the original result, actual actor custody, and
/// inventory exclusion. Such failures cannot discard publication authority.
pub(crate) fn stage_admitted_prepared_result<L, V>(
    actor: &CampaignActorPort<L, V>,
    store: &CampaignExecutorStore,
    namespace: &PreparedResultJournalNamespace,
    maximum_payload_bytes: usize,
    mut prepared: PreparedAttemptResult,
) -> Result<AttemptResultStageOutcome, AdmittedPreparedResultFailure>
where
    L: AssignmentLedger + Send + 'static,
    L::Error: Error + Send + 'static,
    V: AttemptAdmissionValidator + Send + Sync + 'static,
{
    let custody = actor.capacity_custody();
    let mut fence = None;
    macro_rules! retain_failure {
        ($source:expr, $prepared:expr) => {
            AdmittedPreparedResultFailure {
                source: Box::new($source),
                held: Some(RetainedResult {
                    _prepared: Box::new($prepared),
                    _fence: fence,
                    _actor: custody,
                }),
            }
        };
    }
    let guard = match prepared.queued().publication_guard() {
        Ok(guard) => guard,
        Err(source) => return Err(retain_failure!(source, prepared)),
    };
    macro_rules! publication_boundary {
        () => {
            if let Err(source) = guard.wait_slice() {
                return Err(retain_failure!(source, prepared));
            }
        };
    }
    let mut boundary = || {
        guard
            .wait_slice()
            .map(|_| ())
            .map_err(crate::FindingReplayCaptureStoreError::from)
    };
    publication_boundary!();
    let inputs = match prepared.production_replay_capture_inputs() {
        Ok(inputs) => inputs,
        Err(source) => return Err(retain_failure!(source, prepared)),
    };
    if let Some(inputs) = inputs {
        let captures = match crate::FindingReplayCaptureStore::prepare_set_with_boundary(
            inputs,
            &mut boundary,
        ) {
            Ok(captures) => captures,
            Err(source) => return Err(retain_failure!(source, prepared)),
        };
        let publication = match store.acquire_finding_replay_publication_guard() {
            Ok(publication) => publication,
            Err(source) => return Err(retain_failure!(source, prepared)),
        };
        let published = crate::FindingReplayCaptureStore::publish_set_with_boundary(
            &publication,
            &captures,
            &mut boundary,
        );
        fence = Some(publication.into_gc_exclusion());
        if let Err(source) = published {
            return Err(retain_failure!(source, prepared));
        }
        if let Err(source) = prepared.bind_production_replay_captures(captures.references()) {
            return Err(retain_failure!(source, prepared));
        }
    }

    publication_boundary!();
    prepared =
        match stage_prepared_attempt_result_journal(namespace, maximum_payload_bytes, prepared) {
            Ok((prepared, _)) => prepared,
            Err(failure) => return Err(retain_failure!(*failure.source, *failure.prepared)),
        };
    publication_boundary!();
    // Borrow a slot so actor unavailability cannot drop the linear token
    // captured by a callback that never ran.
    let mut slot = Some(prepared);
    let staged = actor.with_supervisor(|supervisor| {
        let prepared = slot.take().ok_or(HostOperationalError::Unavailable)?;
        Ok(stage_prepared_attempt_result(supervisor, prepared))
    });
    let outcome = match staged {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(failure)) => return Err(retain_failure!(failure.source, *failure.prepared)),
        Err(source) => {
            let Some(prepared) = slot.take() else {
                // A closure error after consuming the token is impossible in
                // the closed callback above. Retain the authentic actor/fence.
                let _held_for_process_lifetime = Box::leak(Box::new((custody, fence)));
                return Err(AdmittedPreparedResultFailure {
                    source: Box::new(source),
                    held: None,
                });
            };
            return Err(retain_failure!(source, prepared));
        }
    };
    match outcome {
        AttemptResultStageOutcome::Publish(staged) => {
            prepared = (*staged).into_prepared();
            publication_boundary!();
            let prepared = match prepared.commit_staged_journal() {
                Ok(prepared) => prepared,
                Err(failure) => return Err(retain_failure!(*failure.source, *failure.prepared)),
            };
            if let Err(source) = guard.wait_slice() {
                return Err(retain_failure!(source, prepared));
            }
            drop(fence);
            Ok(AttemptResultStageOutcome::Publish(Box::new(
                StagedAttemptResult { prepared },
            )))
        }
        finished @ AttemptResultStageOutcome::Finished { .. } => {
            drop(fence);
            Ok(finished)
        }
    }
}
