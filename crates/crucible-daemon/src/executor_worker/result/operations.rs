//! Staging, publication, recovery, and reconciliation for prepared results.

use super::*;

/// Installs the durable checkpoint root with a short supervisor CAS.
///
/// The consumed token is returned on every actor failure, so a ledger error
/// never forces QEMU execution or checkpoint capture to repeat.
///
/// # Errors
///
/// Returns [`CheckpointResultStagingError`] with the complete prepared token
/// when the operational ledger cannot safely establish the root.
pub fn stage_prepared_checkpoint_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    prepared: PreparedCheckpointResult,
) -> Result<CheckpointResultStageOutcome, CheckpointResultStagingError<LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let checkpoint = prepared.root();
    let stage = match supervisor.stage_checkpoint_publication(prepared.queued(), checkpoint) {
        Ok(stage) => stage,
        Err(source) => {
            return Err(CheckpointResultStagingError {
                prepared: Box::new(prepared),
                source,
            });
        }
    };
    match stage {
        CheckpointPublicationOutcome::Staged | CheckpointPublicationOutcome::AlreadyStaged => Ok(
            CheckpointResultStageOutcome::Publish(Box::new(StagedCheckpointResult { prepared })),
        ),
        CheckpointPublicationOutcome::AlreadyPaused | CheckpointPublicationOutcome::NotCurrent => {
            Ok(CheckpointResultStageOutcome::Finished {
                prepared: Box::new(prepared),
                checkpoint,
                outcome: stage,
            })
        }
    }
}

/// Publishes every exact-checkpoint child and its root outside actor ownership.
///
/// # Errors
///
/// Returns [`CheckpointResultPublicationError`] with the staged token when any
/// exact durable placement or authentication step fails.
pub fn publish_staged_checkpoint_result(
    store: &ExactCheckpointStore,
    staged: StagedCheckpointResult,
) -> Result<PublishedCheckpointResult, CheckpointResultPublicationError> {
    let publication = match store.publish_attempt_checkpoint(&staged.prepared.checkpoint) {
        Ok(publication) => publication,
        Err(source) => {
            return Err(CheckpointResultPublicationError {
                staged: Box::new(staged),
                source,
            });
        }
    };
    if let Err(source) = staged.prepared.checkpoint.retire_native_source() {
        return Err(CheckpointResultPublicationError {
            staged: Box::new(staged),
            source,
        });
    }
    Ok(PublishedCheckpointResult {
        queued: staged.prepared.queued,
        publication,
    })
}

/// Promotes one fully published checkpoint to durable paused state.
///
/// The worker/session owner must call this only after QEMU teardown has
/// attested physical process exit. Capacity is released by the successful or
/// idempotent paused-state transition, never merely by publishing bytes.
///
/// # Errors
///
/// Returns [`CheckpointResultReconcileError`] with the published token when
/// the operational ledger cannot safely reconcile the paused state.
pub fn reconcile_published_checkpoint_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    published: PublishedCheckpointResult,
) -> Result<CheckpointCompletionOutcome, CheckpointResultReconcileError<LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let checkpoint = published.root();
    match supervisor.complete_checkpoint(&published.queued, checkpoint) {
        Ok(outcome) => Ok(outcome),
        Err(source) => Err(CheckpointResultReconcileError {
            published: Box::new(published),
            source,
        }),
    }
}

/// Explicitly abandons one captured checkpoint without re-running the guest.
///
/// Cancellation removes any staged checkpoint root only after the worker has
/// physically returned. Partial immutable objects then become ordinary
/// collection candidates; no active capacity or linear result token is lost.
///
/// # Errors
///
/// Returns [`CheckpointResultAbortError`] with the complete phase token when
/// durable cancellation cannot be reconciled safely.
pub fn abort_checkpoint_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    token: CheckpointResultAbortToken,
) -> Result<CancellationOutcome, CheckpointResultAbortError<LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match supervisor.stage_and_reconcile_cancellation(token.queued()) {
        Ok(outcome) => Ok(outcome),
        Err(source) => Err(CheckpointResultAbortError { token, source }),
    }
}

/// Preflights one independently executed worker result outside supervision.
///
/// The caller first obtains [`QueuedAttempt`] with
/// [`LocalExecutorSupervisor::next_queued`], moves that value to a worker
/// thread, and later calls this function without borrowing the supervisor.
/// Repository closure traversal can therefore never block submission or
/// cancellation handling on the actor thread.
///
/// # Errors
///
/// Returns the linear worker token with either its classified worker failure or
/// its candidate when read-only preflight fails.
pub fn prepare_attempt_result<W>(
    store: &CampaignExecutorStore,
    checkpoints: &ExactCheckpointStore,
    work: AttemptWorkResult<W>,
) -> Result<PreparedAttemptWorkResult, AttemptResultPreparationError<W>> {
    let AttemptWorkResult { queued, result } = work;
    let product = match result {
        Ok(product) => product,
        Err(failure) => {
            return Err(AttemptResultPreparationError::Worker {
                queued: Box::new(queued),
                failure,
            });
        }
    };
    match product {
        AttemptExecutionProduct::PreparedSemantic(result) => prepare_pending_attempt_result(
            store,
            PendingAttemptResult {
                queued,
                result: *result,
            },
        )
        .map(|prepared| PreparedAttemptWorkResult::Observation(Box::new(prepared))),
        AttemptExecutionProduct::ExactCheckpoint(capture) => prepare_pending_checkpoint_result(
            checkpoints,
            PendingCheckpointResult {
                queued,
                checkpoint: *capture,
            },
        )
        .map(|prepared| PreparedAttemptWorkResult::ExactCheckpoint(Box::new(prepared))),
    }
}

/// Retries read-only preflight of an already-executed candidate.
///
/// # Errors
///
/// Returns the same candidate error with the linear pending token retained.
pub fn retry_pending_attempt_result<W>(
    store: &CampaignExecutorStore,
    pending: PendingAttemptResult,
) -> Result<PreparedAttemptResult, AttemptResultPreparationError<W>> {
    prepare_pending_attempt_result(store, pending)
}

/// Persists a preflighted semantic result before publication can be staged.
///
/// An existing journal must contain the exact same result and producer
/// execution. The returned token owns the per-attempt journal lock until
/// completion or cancellation becomes durable.
///
/// # Errors
///
/// Returns [`AttemptResultJournalError`] with the complete prepared token when
/// journal creation, reopening, authentication, or durability fails.
pub fn journal_prepared_attempt_result(
    namespace: &PreparedResultJournalNamespace,
    maximum_payload_bytes: usize,
    prepared: PreparedAttemptResult,
) -> Result<
    (
        PreparedAttemptResult,
        PreparedResultJournalCreateDisposition,
    ),
    AttemptResultJournalError,
> {
    let (prepared, disposition) =
        stage_prepared_attempt_result_journal(namespace, maximum_payload_bytes, prepared)?;
    Ok((prepared.commit_staged_journal()?, disposition))
}

pub(crate) fn stage_prepared_attempt_result_journal(
    namespace: &PreparedResultJournalNamespace,
    maximum_payload_bytes: usize,
    mut prepared: PreparedAttemptResult,
) -> Result<
    (
        PreparedAttemptResult,
        PreparedResultJournalCreateDisposition,
    ),
    AttemptResultJournalError,
> {
    let key = crate::AttemptExecutionKey::for_request(prepared.queued.request());
    let execution = prepared.queued.execution();
    let result = prepared.result().clone();
    let (journal, disposition) = match DirectoryPreparedResultJournal::prepare_staged(
        namespace,
        key,
        execution,
        maximum_payload_bytes,
        result,
    ) {
        Ok(created) => created,
        Err(source) => {
            return Err(AttemptResultJournalError {
                prepared: Box::new(prepared),
                source: Box::new(source),
            });
        }
    };
    prepared.result = PreparedAttemptResultOwner::Journal(Box::new(journal));
    Ok((prepared, disposition))
}

/// Reopens a complete producer journal before allowing fresh guest execution.
///
/// The fresh `queued` token remains the supervisor reconciliation authority;
/// the journal retains its separately authenticated producer execution ID.
/// Recovered semantic bytes are rechecked against immutable repository input
/// and authenticated scenario measurement definitions.
///
/// # Errors
///
/// Returns [`AttemptResultRecoveryError`] with the fresh execution token when
/// journal or semantic authentication fails.
pub fn recover_prepared_attempt_result(
    store: &CampaignExecutorStore,
    namespace: &PreparedResultJournalNamespace,
    maximum_payload_bytes: usize,
    queued: QueuedAttempt,
) -> Result<PreparedAttemptRecoveryOutcome, AttemptResultRecoveryError> {
    let key = crate::AttemptExecutionKey::for_request(queued.request());
    let journal = match DirectoryPreparedResultJournal::open_for_recovery(
        namespace,
        key,
        maximum_payload_bytes,
    ) {
        Ok(Some(journal)) => journal,
        Ok(None) => return Ok(PreparedAttemptRecoveryOutcome::Missing(Box::new(queued))),
        Err(source) => {
            return Err(AttemptResultRecoveryError {
                queued: Box::new(queued),
                source: Box::new(source.into()),
            });
        }
    };
    let observation = match journal.result().observation().observation().id() {
        Ok(observation) => observation,
        Err(source) => {
            return Err(AttemptResultRecoveryError {
                queued: Box::new(queued),
                source: Box::new(
                    AttemptResultPreparationFailure::Repository(CampaignRepositoryError::Codec(
                        source,
                    ))
                    .into(),
                ),
            });
        }
    };
    let finding_candidate = match journal.result().finding() {
        Some(finding) => match finding.id() {
            Ok(finding) => Some(finding),
            Err(source) => {
                return Err(AttemptResultRecoveryError {
                    queued: Box::new(queued),
                    source: Box::new(
                        AttemptResultPreparationFailure::Repository(
                            CampaignRepositoryError::Codec(source),
                        )
                        .into(),
                    ),
                });
            }
        },
        None => None,
    };
    if let Err(source) = validate_prepared_semantic_attempt_result(
        store,
        crate::AttemptExecutionKey::for_request(queued.request()),
        journal.result(),
    ) {
        return Err(AttemptResultRecoveryError {
            queued: Box::new(queued),
            source: Box::new(source.into()),
        });
    }
    if let Some(captures) = journal
        .result()
        .finding()
        .and_then(|finding| finding.bundle().replay_captures())
    {
        let guard = match store.acquire_finding_replay_publication_guard() {
            Ok(guard) => guard,
            Err(source) => {
                return Err(AttemptResultRecoveryError {
                    queued: Box::new(queued),
                    source: Box::new(crate::FindingReplayCaptureStoreError::from(source).into()),
                });
            }
        };
        let loaded = match crate::FindingReplayCaptureStore::load_set(&guard, captures) {
            Ok(loaded) => loaded,
            Err(source) => {
                return Err(AttemptResultRecoveryError {
                    queued: Box::new(queued),
                    source: Box::new(source.into()),
                });
            }
        };
        if let Err(source) = validate_recovered_finding_replay_captures(journal.result(), &loaded) {
            return Err(AttemptResultRecoveryError {
                queued: Box::new(queued),
                source,
            });
        }
    }

    Ok(PreparedAttemptRecoveryOutcome::Prepared(Box::new(
        PreparedAttemptResult {
            queued,
            result: PreparedAttemptResultOwner::Journal(Box::new(journal)),
            observation,
            finding_candidate,
        },
    )))
}

fn validate_recovered_finding_replay_captures(
    result: &PreparedSemanticAttemptResult,
    loaded: &[crate::LoadedFindingReplayCapture; 4],
) -> Result<(), Box<AttemptResultRecoveryFailure>> {
    let finding = result.finding().ok_or_else(|| {
        Box::new(AttemptResultRecoveryFailure::Preparation(
            AttemptResultPreparationFailure::Result(
                PreparedSemanticResultCodecError::Inconsistent {
                    component: "finding replay captures without finding",
                },
            ),
        ))
    })?;
    let limits = finding
        .production_replay_capture_limits()
        .map_err(AttemptResultPreparationFailure::Result)
        .map_err(AttemptResultRecoveryFailure::Preparation)
        .map_err(Box::new)?;
    let bindings = finding
        .production_replay_capture_bindings()
        .map_err(CampaignRepositoryError::Codec)
        .map_err(AttemptResultPreparationFailure::Repository)
        .map_err(AttemptResultRecoveryFailure::Preparation)
        .map_err(Box::new)?;

    for (capture, (reproduction, observed_signature)) in loaded.iter().zip(bindings) {
        let crate::LoadedFindingReplayCapture::Complete {
            bytes,
            content_hash,
        } = capture
        else {
            continue;
        };
        let capture = crate::FindingProductionReplayCapture::from_canonical_bytes(bytes, limits)
            .map_err(AttemptResultRecoveryFailure::ProductionReplay)
            .map_err(Box::new)?;
        if capture
            .content_hash(limits)
            .map_err(AttemptResultRecoveryFailure::ProductionReplay)
            .map_err(Box::new)?
            != *content_hash
        {
            return Err(Box::new(AttemptResultRecoveryFailure::ProductionReplay(
                crate::FindingProductionReplayCaptureError::CaptureBinding,
            )));
        }
        capture
            .validate_binding(reproduction, &observed_signature)
            .map_err(AttemptResultRecoveryFailure::ProductionReplay)
            .map_err(Box::new)?;
    }
    Ok(())
}

/// Retries no-write preparation of an already-captured exact checkpoint.
///
/// # Errors
///
/// Returns the same checkpoint error with the linear capture token retained.
pub fn retry_pending_checkpoint_result<W>(
    checkpoints: &ExactCheckpointStore,
    pending: PendingCheckpointResult,
) -> Result<PreparedCheckpointResult, AttemptResultPreparationError<W>> {
    prepare_pending_checkpoint_result(checkpoints, pending)
}

fn prepare_pending_attempt_result<W>(
    store: &CampaignExecutorStore,
    pending: PendingAttemptResult,
) -> Result<PreparedAttemptResult, AttemptResultPreparationError<W>> {
    let observation = match pending.candidate().observation().id() {
        Ok(observation) => observation,
        Err(error) => {
            return Err(AttemptResultPreparationError::Candidate {
                pending: Box::new(pending),
                source: Box::new(CampaignRepositoryError::Codec(error).into()),
            });
        }
    };
    let finding_candidate = match pending.finding() {
        Some(finding) => {
            if finding.bundle().observation() != observation {
                return Err(AttemptResultPreparationError::Candidate {
                    pending: Box::new(pending),
                    source: Box::new(
                        CampaignRepositoryError::Integrity {
                            reason: "prepared-finding-observation-mismatch",
                        }
                        .into(),
                    ),
                });
            }
            match finding.id() {
                Ok(candidate) => Some(candidate),
                Err(error) => {
                    return Err(AttemptResultPreparationError::Candidate {
                        pending: Box::new(pending),
                        source: Box::new(CampaignRepositoryError::Codec(error).into()),
                    });
                }
            }
        }
        None => None,
    };
    let result = pending.result.clone();
    let queued = pending.queued;
    if let Err(source) = validate_prepared_semantic_attempt_result(
        store,
        crate::AttemptExecutionKey::for_request(queued.request()),
        &result,
    ) {
        return Err(AttemptResultPreparationError::Candidate {
            pending: Box::new(PendingAttemptResult { queued, result }),
            source: Box::new(source),
        });
    }
    Ok(PreparedAttemptResult {
        queued,
        result: PreparedAttemptResultOwner::Volatile(Box::new(result)),
        observation,
        finding_candidate,
    })
}

/// Authenticates one prepared semantic result against its exact execution key.
///
/// # Errors
///
/// Returns an error when the key is not semantic, the observation differs from
/// the assigned attempt or lineage, or any scenario, measurement, or closure
/// dependency fails authentication.
pub(crate) fn validate_prepared_semantic_attempt_result(
    store: &CampaignExecutorStore,
    expected: crate::AttemptExecutionKey,
    result: &PreparedSemanticAttemptResult,
) -> Result<(), AttemptResultPreparationFailure> {
    if expected.scope() != crucible_campaign::AttemptExecutionScope::Semantic {
        return Err(CampaignRepositoryError::Integrity {
            reason: "prepared-result-nonsemantic-scope",
        }
        .into());
    }
    let lineage = store.load_lineage(expected.lineage())?;
    let observation = result.observation();
    if observation.observation().attempt() != expected.attempt() {
        return Err(CampaignRepositoryError::Integrity {
            reason: "prepared-result-attempt-mismatch",
        }
        .into());
    }
    if observation.child().scenario() != lineage.scenario()
        || observation.child().scenario_artifact() != lineage.scenario_content()
    {
        return Err(CampaignRepositoryError::Integrity {
            reason: "prepared-result-lineage-mismatch",
        }
        .into());
    }
    authenticate_prepared_measurements(store, &lineage, result)?;
    Ok(())
}

fn authenticate_prepared_measurements(
    store: &CampaignExecutorStore,
    lineage: &CampaignLineage,
    result: &PreparedSemanticAttemptResult,
) -> Result<(), AttemptResultPreparationFailure> {
    let artifact = store.load_scenario_artifact(lineage.scenario_content())?;
    let scenario = crate::decode_crucible_scenario_artifact(&artifact)?;
    result.verify_measurement_publications(&scenario)?;
    result.verify_terminal_fingerprints(&scenario)?;
    Ok(())
}

fn prepare_pending_checkpoint_result<W>(
    checkpoints: &ExactCheckpointStore,
    pending: PendingCheckpointResult,
) -> Result<PreparedCheckpointResult, AttemptResultPreparationError<W>> {
    if !pending.queued.checkpoint_request().is_requested() {
        return Err(AttemptResultPreparationError::Checkpoint {
            pending: Box::new(pending),
            source: Box::new(ExactCheckpointStoreError::InvalidRoot {
                reason: "execution returned an unsolicited exact checkpoint",
            }),
        });
    }
    let PendingCheckpointResult { queued, checkpoint } = pending;
    match checkpoint.into_state() {
        AttemptCheckpointResultState::Prepared(checkpoint) => {
            Ok(PreparedCheckpointResult::new(queued, *checkpoint))
        }
        AttemptCheckpointResultState::Captured(capture) => {
            match checkpoints.prepare_attempt_checkpoint(&capture) {
                Ok(checkpoint) => Ok(PreparedCheckpointResult::new(queued, checkpoint)),
                Err(source) => Err(AttemptResultPreparationError::Checkpoint {
                    pending: Box::new(PendingCheckpointResult {
                        queued,
                        checkpoint: (*capture).into(),
                    }),
                    source: Box::new(source),
                }),
            }
        }
    }
}

/// Reconciles a worker failure using only short supervisor operations.
///
/// # Errors
///
/// Returns the classified worker failure after requeue or durable stop, or a
/// supervisor error if operational reconciliation fails.
pub fn reconcile_attempt_failure<L, V, W>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    queued: QueuedAttempt,
    failure: AttemptWorkerFailure<W>,
) -> Result<(), AttemptWorkerReconcileError<W, LocalExecutorError<L::Error>>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            let failure = AttemptWorkerFailure::Retryable(error);
            if queued.cancellation().is_canceled() {
                let cancellation = supervisor.stage_and_reconcile_cancellation(&queued);
                let cancellation = match cancellation {
                    Ok(cancellation) => cancellation,
                    Err(source) => {
                        return Err(AttemptWorkerReconcileError::FailurePending {
                            queued: Box::new(queued),
                            failure,
                            source,
                        });
                    }
                };
                return Err(AttemptWorkerReconcileError::Stopped {
                    failure,
                    cancellation,
                });
            }
            supervisor.requeue(queued);
            Err(AttemptWorkerReconcileError::Worker(failure))
        }
        failure @ AttemptWorkerFailure::Canceled(_) => {
            let cancellation = supervisor.stage_and_reconcile_cancellation(&queued);
            let cancellation = match cancellation {
                Ok(cancellation) => cancellation,
                Err(source) => {
                    return Err(AttemptWorkerReconcileError::FailurePending {
                        queued: Box::new(queued),
                        failure,
                        source,
                    });
                }
            };
            Err(AttemptWorkerReconcileError::Stopped {
                failure,
                cancellation,
            })
        }
        failure @ AttemptWorkerFailure::Terminal(_) => {
            let terminal_failure = supervisor.stage_and_reconcile_terminal_failure(&queued);
            let terminal_failure = match terminal_failure {
                Ok(terminal_failure) => terminal_failure,
                Err(source) => {
                    return Err(AttemptWorkerReconcileError::FailurePending {
                        queued: Box::new(queued),
                        failure,
                        source,
                    });
                }
            };
            Err(AttemptWorkerReconcileError::TerminalStopped {
                failure,
                terminal_failure,
            })
        }
    }
}

/// Publishes a preflighted candidate without borrowing the supervisor actor.
///
/// # Errors
///
/// Returns [`AttemptResultPublicationError`] with the complete prepared bundle
/// when immutable storage is temporarily or stably unavailable.
pub fn publish_prepared_attempt_result(
    store: &CampaignExecutorStore,
    exact_authenticator: &dyn FindingExactCheckpointAuthenticator,
    staged: Box<StagedAttemptResult>,
) -> Result<PublishedAttemptResult, AttemptResultPublicationError> {
    if let Err(source) = publish_prepared_semantic_attempt_result(
        store,
        exact_authenticator,
        staged.prepared.result(),
    ) {
        return Err(AttemptResultPublicationError { staged, source });
    }
    let StagedAttemptResult { prepared } = *staged;
    Ok(PublishedAttemptResult {
        queued: prepared.queued,
        observation: prepared.observation,
        finding_candidate: prepared.finding_candidate,
        journal: prepared.result.into_journal(),
    })
}

/// Publishes a preflighted semantic closure in dependency order.
///
/// Callers must first complete [`validate_prepared_semantic_attempt_result`].
/// Packaged callers retain the staged publication owner while this function
/// writes; the synchronous standalone caller owns its private repository.
///
/// # Errors
///
/// Returns an error when raw evidence cannot derive its declared identity or
/// any trace, observation, or finding object cannot be published exactly.
pub(crate) fn publish_prepared_semantic_attempt_result(
    store: &CampaignExecutorStore,
    exact_authenticator: &dyn FindingExactCheckpointAuthenticator,
    result: &PreparedSemanticAttemptResult,
) -> Result<ObservationId, AttemptResultPublicationFailure> {
    for evidence in result.measurement_replay_evidence() {
        let expected = match evidence.id() {
            Ok(expected) => expected,
            Err(source) => return Err(AttemptResultPublicationFailure::Measurement(source)),
        };
        let bytes = match evidence.canonical_bytes() {
            Ok(bytes) => bytes,
            Err(source) => return Err(AttemptResultPublicationFailure::Measurement(source)),
        };
        store.publish_executor_trace_leaf(expected, evidence.schema_version(), &bytes)?;
    }
    let observation = store.publish_observation_candidate(result.observation())?;
    if let Some(finding) = result.finding() {
        finding.publish_for_executor(store, exact_authenticator)?;
    }
    Ok(observation)
}

/// Aborts a stably conflicting prepared publication before immutable writes.
///
/// # Errors
///
/// Returns [`AttemptResultStagingError`] with the linear prepared token when
/// durable cancellation cannot yet be reconciled.
pub fn abort_prepared_attempt_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    prepared: PreparedAttemptResult,
) -> Result<
    (CancellationOutcome, PreparedAttemptResult),
    AttemptResultStagingError<LocalExecutorError<L::Error>>,
>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match supervisor.stage_and_reconcile_cancellation(prepared.queued()) {
        Ok(outcome) => Ok((outcome, prepared)),
        Err(source) => Err(AttemptResultStagingError {
            prepared: Box::new(prepared),
            source,
        }),
    }
}

/// Aborts a stably failed staged publication without re-running the guest.
///
/// # Errors
///
/// Returns [`AttemptResultAbortError`] with the linear staged token when the
/// durable cancellation cannot yet be reconciled.
pub fn abort_staged_attempt_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    staged: Box<StagedAttemptResult>,
) -> Result<(CancellationOutcome, Box<StagedAttemptResult>), AttemptResultAbortError<L::Error>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match supervisor.stage_and_reconcile_cancellation(staged.prepared.queued()) {
        Ok(outcome) => Ok((outcome, staged)),
        Err(source) => Err(AttemptResultAbortError { staged, source }),
    }
}

/// Aborts a published result after stable completion reconciliation failure.
///
/// The immutable candidate remains content-addressed and may be collected when
/// its canceled publication root is no longer retained. This operation changes
/// only operational execution state and never fabricates campaign meaning.
///
/// # Errors
///
/// Returns [`PublishedAttemptResultAbortError`] with the linear published token
/// when durable cancellation cannot yet be reconciled.
pub fn abort_published_attempt_result<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    published: PublishedAttemptResult,
) -> Result<(CancellationOutcome, PublishedAttemptResult), PublishedAttemptResultAbortError<L::Error>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    match supervisor.stage_and_reconcile_cancellation(&published.queued) {
        Ok(outcome) => Ok((outcome, published)),
        Err(source) => Err(PublishedAttemptResultAbortError {
            published: Box::new(published),
            source,
        }),
    }
}

/// Reconciles one already-published result with a short supervisor operation.
///
/// # Errors
///
/// Returns [`AttemptWorkerReconcileError::CompletionPending`] when durable
/// completion validation or ledger reconciliation fails.
pub fn reconcile_published_attempt_result<L, V, W>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    published: PublishedAttemptResult,
) -> Result<
    AttemptWorkerReconcileOutcome,
    AttemptWorkerReconcileError<W, LocalExecutorError<L::Error>>,
>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let observation = published.observation;
    let completion = match supervisor.stage_and_reconcile_completion_with_finding_candidate(
        &published.queued,
        published.observation,
        published.finding_candidate,
    ) {
        Ok(completion) => completion,
        Err(source) => {
            return Err(AttemptWorkerReconcileError::CompletionPending {
                published: Box::new(published),
                source,
            });
        }
    };
    if let Err(source) = published.remove_journal() {
        return Err(AttemptWorkerReconcileError::JournalCleanupPending {
            published: Box::new(published),
            source: Box::new(source),
        });
    }
    Ok(AttemptWorkerReconcileOutcome::Reconciled {
        observation,
        completion,
    })
}
