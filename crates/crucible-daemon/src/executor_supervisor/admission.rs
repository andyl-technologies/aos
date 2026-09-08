//! Validated attempt admission and resume handling.

use super::*;

impl<L, V> LocalExecutorSupervisor<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    pub(super) fn submit(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        match self.preflight_submit(request)? {
            SubmitPreflight::Resolved(response) => return Ok(response),
            SubmitPreflight::NeedsValidation => {}
        }
        let validation = ValidatedSubmitAdmission::validate(self.validator.as_ref(), request);
        self.submit_after_validation(request, validation)
    }

    pub(super) fn resume(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
    ) -> Result<ResumeAttemptExecutionResponse, LocalExecutorError<L::Error>> {
        let assignment = request.assignment_request()?;
        let validation = self.validator.validate(&assignment);
        self.resume_after_validation(request, validation)
    }

    pub(crate) fn resume_after_validation(
        &mut self,
        request: &ResumeAttemptExecutionRequest,
        validation: Result<(), ExecutorRejection>,
    ) -> Result<ResumeAttemptExecutionResponse, LocalExecutorError<L::Error>> {
        let assignment = request.assignment_request()?;
        if request.daemon_epoch() != self.daemon_epoch {
            return ResumeAttemptExecutionResponse::new(
                request,
                ResumeAttemptExecutionDisposition::Rejected {
                    reason: ExecutorRejection::Unauthorized,
                },
            )
            .map_err(Into::into);
        }
        if request.prior_start_mode().execution_scope()
            != crucible_campaign::AttemptExecutionScope::Semantic
        {
            return ResumeAttemptExecutionResponse::new(
                request,
                ResumeAttemptExecutionDisposition::Rejected {
                    reason: ExecutorRejection::Incompatible,
                },
            )
            .map_err(Into::into);
        }
        if let Err(reason) = validation {
            return ResumeAttemptExecutionResponse::new(
                request,
                ResumeAttemptExecutionDisposition::Rejected { reason },
            )
            .map_err(Into::into);
        }
        if !self.capacity.supports(request.resources()) {
            return ResumeAttemptExecutionResponse::new(
                request,
                ResumeAttemptExecutionDisposition::Rejected {
                    reason: ExecutorRejection::Incompatible,
                },
            )
            .map_err(Into::into);
        }

        let key = AttemptExecutionKey::new(request.lineage(), request.attempt());
        let Some(current) = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?
        else {
            return ResumeAttemptExecutionResponse::new(
                request,
                ResumeAttemptExecutionDisposition::NotCurrent,
            )
            .map_err(Into::into);
        };
        let execution_basis = request.execution_basis_digest();
        let request_digest = request.request_digest();
        let resume_origin_matches = |origin: AttemptExecutionOrigin| {
            origin.resume_basis().is_some_and(|basis| {
                basis.prior_execution == request.prior_execution()
                    && basis.checkpoint == request.checkpoint()
            })
        };
        if current.origin().resume_basis().is_some_and(|basis| {
            basis.assignment == request.assignment() && basis.request_digest != request_digest
        }) {
            return ResumeAttemptExecutionResponse::new(
                request,
                ResumeAttemptExecutionDisposition::Rejected {
                    reason: ExecutorRejection::ConflictingAssignment,
                },
            )
            .map_err(Into::into);
        }

        if current.execution_basis() == execution_basis && resume_origin_matches(current.origin()) {
            match current {
                AttemptRuntimeState::Completed {
                    observation,
                    finding_candidate,
                    ..
                } => {
                    let finding_candidate = finding_candidate.candidate();
                    let (disposition, response_candidate) = match self
                        .validator
                        .validate_completion_artifacts(&assignment, observation, finding_candidate)
                    {
                        Ok(()) => (
                            ResumeAttemptExecutionDisposition::AlreadyCompleted { observation },
                            finding_candidate,
                        ),
                        Err(CompletionValidationFailure::UnavailableInput) => (
                            ResumeAttemptExecutionDisposition::Rejected {
                                reason: ExecutorRejection::UnavailableInput,
                            },
                            None,
                        ),
                        Err(CompletionValidationFailure::Unauthorized) => (
                            ResumeAttemptExecutionDisposition::Rejected {
                                reason: ExecutorRejection::Unauthorized,
                            },
                            None,
                        ),
                        Err(CompletionValidationFailure::Incompatible) => (
                            ResumeAttemptExecutionDisposition::Rejected {
                                reason: ExecutorRejection::Incompatible,
                            },
                            None,
                        ),
                    };
                    return match response_candidate {
                        Some(candidate) => {
                            ResumeAttemptExecutionResponse::new_with_finding_candidate(
                                request,
                                disposition,
                                candidate,
                            )
                        }
                        None => ResumeAttemptExecutionResponse::new(request, disposition),
                    }
                    .map_err(Into::into);
                }
                AttemptRuntimeState::Canceled { .. } => {
                    return ResumeAttemptExecutionResponse::new(
                        request,
                        ResumeAttemptExecutionDisposition::AlreadyCanceled,
                    )
                    .map_err(Into::into);
                }
                AttemptRuntimeState::TerminalFailure { .. } => {
                    return ResumeAttemptExecutionResponse::new(
                        request,
                        ResumeAttemptExecutionDisposition::Rejected {
                            reason: ExecutorRejection::TerminalFailure,
                        },
                    )
                    .map_err(Into::into);
                }
                AttemptRuntimeState::Running { execution, .. }
                | AttemptRuntimeState::CheckpointRequested { execution, .. }
                | AttemptRuntimeState::CheckpointPublishing { execution, .. }
                | AttemptRuntimeState::Publishing { execution, .. }
                    if current.daemon_epoch() == self.daemon_epoch
                        && self.active.contains_key(&execution) =>
                {
                    return ResumeAttemptExecutionResponse::new(
                        request,
                        ResumeAttemptExecutionDisposition::AlreadyRunning { execution },
                    )
                    .map_err(Into::into);
                }
                AttemptRuntimeState::Paused { .. } => {}
                AttemptRuntimeState::CheckpointPromoting { .. } => {
                    return ResumeAttemptExecutionResponse::new(
                        request,
                        ResumeAttemptExecutionDisposition::NotCurrent,
                    )
                    .map_err(Into::into);
                }
                AttemptRuntimeState::Running { .. }
                | AttemptRuntimeState::CheckpointRequested { .. }
                | AttemptRuntimeState::CheckpointPublishing { .. }
                | AttemptRuntimeState::Publishing { .. } => {
                    if !self.has_capacity(request.resources()) {
                        return ResumeAttemptExecutionResponse::new(
                            request,
                            ResumeAttemptExecutionDisposition::Rejected {
                                reason: ExecutorRejection::Backpressure,
                            },
                        )
                        .map_err(Into::into);
                    }
                    let execution = self.allocate_execution_id()?;
                    let origin = current
                        .origin()
                        .with_resume_basis(ExactCheckpointResumeBasis {
                            assignment: request.assignment(),
                            request_digest,
                            prior_execution: request.prior_execution(),
                            checkpoint: request.checkpoint(),
                        });
                    let next = match current {
                        AttemptRuntimeState::Running { .. } => AttemptRuntimeState::Running {
                            execution_basis,
                            origin,
                            daemon_epoch: self.daemon_epoch,
                            execution,
                        },
                        AttemptRuntimeState::CheckpointRequested { .. } => {
                            AttemptRuntimeState::CheckpointRequested {
                                execution_basis,
                                origin,
                                daemon_epoch: self.daemon_epoch,
                                execution,
                            }
                        }
                        AttemptRuntimeState::CheckpointPublishing { checkpoint, .. } => {
                            AttemptRuntimeState::CheckpointPublishing {
                                execution_basis,
                                origin,
                                daemon_epoch: self.daemon_epoch,
                                execution,
                                checkpoint,
                            }
                        }
                        AttemptRuntimeState::Publishing {
                            observation,
                            finding_candidate,
                            ..
                        } => AttemptRuntimeState::Publishing {
                            execution_basis,
                            origin,
                            daemon_epoch: self.daemon_epoch,
                            execution,
                            observation,
                            finding_candidate,
                        },
                        AttemptRuntimeState::Paused { .. }
                        | AttemptRuntimeState::CheckpointPromoting { .. }
                        | AttemptRuntimeState::Completed { .. }
                        | AttemptRuntimeState::Canceled { .. }
                        | AttemptRuntimeState::TerminalFailure { .. } => {
                            return Err(LocalExecutorError::LedgerInvariant {
                                reason: "resume recovery phase changed during classification",
                            });
                        }
                    };
                    let advance = self.advance_attempt(key, current, Some(next))?;
                    match next {
                        AttemptRuntimeState::CheckpointRequested { .. }
                        | AttemptRuntimeState::CheckpointPublishing { .. } => {
                            self.reserve_checkpoint_recovery(&assignment, execution, origin)?;
                        }
                        AttemptRuntimeState::Running { .. }
                        | AttemptRuntimeState::Publishing { .. } => {
                            self.reserve(&assignment, execution, origin)?;
                        }
                        AttemptRuntimeState::Paused { .. }
                        | AttemptRuntimeState::CheckpointPromoting { .. }
                        | AttemptRuntimeState::Completed { .. }
                        | AttemptRuntimeState::Canceled { .. }
                        | AttemptRuntimeState::TerminalFailure { .. } => {
                            return Err(LocalExecutorError::LedgerInvariant {
                                reason: "resume recovery produced a terminal phase",
                            });
                        }
                    }
                    if let AttemptAdvance::CommittedAfterError(error) = advance {
                        return Err(LocalExecutorError::Ledger(error));
                    }
                    return ResumeAttemptExecutionResponse::new(
                        request,
                        ResumeAttemptExecutionDisposition::Accepted { execution },
                    )
                    .map_err(Into::into);
                }
            }
        }

        let AttemptRuntimeState::Paused {
            execution: prior_execution,
            checkpoint,
            ..
        } = current
        else {
            return ResumeAttemptExecutionResponse::new(
                request,
                ResumeAttemptExecutionDisposition::NotCurrent,
            )
            .map_err(Into::into);
        };
        if current.execution_basis() != request.prior_execution_basis_digest()
            || prior_execution != request.prior_execution()
            || checkpoint != request.checkpoint()
        {
            return ResumeAttemptExecutionResponse::new(
                request,
                ResumeAttemptExecutionDisposition::NotCurrent,
            )
            .map_err(Into::into);
        }
        if !self.has_capacity(request.resources()) {
            return ResumeAttemptExecutionResponse::new(
                request,
                ResumeAttemptExecutionDisposition::Rejected {
                    reason: ExecutorRejection::Backpressure,
                },
            )
            .map_err(Into::into);
        }

        let execution = self.allocate_execution_id()?;
        let origin = current
            .origin()
            .with_resume_basis(ExactCheckpointResumeBasis {
                assignment: request.assignment(),
                request_digest,
                prior_execution,
                checkpoint,
            });
        let running = AttemptRuntimeState::Running {
            execution_basis,
            origin,
            daemon_epoch: self.daemon_epoch,
            execution,
        };
        let advance = self.advance_attempt(key, current, Some(running))?;
        self.reserve(&assignment, execution, origin)?;
        if let AttemptAdvance::CommittedAfterError(error) = advance {
            return Err(LocalExecutorError::Ledger(error));
        }
        ResumeAttemptExecutionResponse::new(
            request,
            ResumeAttemptExecutionDisposition::Accepted { execution },
        )
        .map_err(Into::into)
    }

    pub(super) fn assignment_response(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<Option<SubmitAttemptResponse>, LocalExecutorError<L::Error>> {
        let Some(record) = self
            .ledger
            .load_assignment(request.assignment())
            .map_err(LocalExecutorError::Ledger)?
        else {
            return Ok(None);
        };
        if record.request() == request {
            return Ok(Some(record.response().clone()));
        }
        self.response(
            request,
            SubmitAttemptDisposition::Rejected {
                reason: ExecutorRejection::ConflictingAssignment,
            },
        )
        .map(Some)
    }

    pub(super) fn submit_admitted(
        &mut self,
        request: &SubmitAttemptRequest,
        admission: ValidatedSubmitAdmission,
    ) -> Result<SubmitAttemptResponse, LocalExecutorError<L::Error>> {
        if !self.capacity.supports(request.resources()) {
            return self.persist_response(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Incompatible,
                },
            );
        }

        let key = AttemptExecutionKey::for_request(request);
        let execution_basis = request.execution_basis_digest();
        let mut prior = self
            .ledger
            .load_attempt(key)
            .map_err(LocalExecutorError::Ledger)?;
        if let Some(state) = prior
            && state.execution_basis() == execution_basis
            && matches!(
                state,
                AttemptRuntimeState::Running { .. }
                    | AttemptRuntimeState::CheckpointRequested { .. }
                    | AttemptRuntimeState::CheckpointPublishing { .. }
                    | AttemptRuntimeState::Publishing { .. }
            )
            && !(state.daemon_epoch() == self.daemon_epoch
                && self.active.contains_key(&state.execution()))
            && let Some(ExactCheckpointResumeBasis {
                prior_execution,
                checkpoint,
                ..
            }) = state.origin().resume_basis()
        {
            return self.persist_response(
                request,
                SubmitAttemptDisposition::AlreadyPaused {
                    execution: prior_execution,
                    checkpoint,
                },
            );
        }
        match prior {
            Some(AttemptRuntimeState::CheckpointRequested {
                execution_basis: current_basis,
                daemon_epoch,
                execution,
                ..
            })
            | Some(AttemptRuntimeState::CheckpointPublishing {
                execution_basis: current_basis,
                daemon_epoch,
                execution,
                ..
            }) if current_basis == execution_basis
                && daemon_epoch == self.daemon_epoch
                && self.active.contains_key(&execution) =>
            {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::AlreadyRunning { execution },
                );
            }
            Some(AttemptRuntimeState::Paused {
                execution_basis: current_basis,
                execution,
                checkpoint,
                ..
            }) if current_basis == execution_basis => {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::AlreadyPaused {
                        execution,
                        checkpoint,
                    },
                );
            }
            Some(AttemptRuntimeState::CheckpointPromoting {
                execution_basis: current_basis,
                ..
            }) if current_basis == execution_basis => {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::Rejected {
                        reason: ExecutorRejection::UnavailableInput,
                    },
                );
            }
            Some(
                requested @ AttemptRuntimeState::CheckpointRequested {
                    execution_basis: current_basis,
                    origin,
                    ..
                },
            ) if current_basis == execution_basis => {
                if !self.has_capacity(request.resources()) {
                    return self.persist_response(
                        request,
                        SubmitAttemptDisposition::Rejected {
                            reason: ExecutorRejection::Backpressure,
                        },
                    );
                }
                let recovery_execution = self.allocate_execution_id()?;
                let recovery = AttemptRuntimeState::CheckpointRequested {
                    execution_basis: current_basis,
                    origin,
                    daemon_epoch: self.daemon_epoch,
                    execution: recovery_execution,
                };
                let advance = self.advance_attempt(key, requested, Some(recovery))?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    self.reserve_checkpoint_recovery(request, recovery_execution, origin)?;
                    return Err(LocalExecutorError::Ledger(error));
                }
                let response = self.persist_response(
                    request,
                    SubmitAttemptDisposition::Accepted {
                        execution: recovery_execution,
                    },
                );
                self.reserve_checkpoint_recovery(request, recovery_execution, origin)?;
                return response;
            }
            Some(
                publishing @ AttemptRuntimeState::CheckpointPublishing {
                    execution_basis: current_basis,
                    origin,
                    checkpoint,
                    ..
                },
            ) if current_basis == execution_basis => {
                if !self.has_capacity(request.resources()) {
                    return self.persist_response(
                        request,
                        SubmitAttemptDisposition::Rejected {
                            reason: ExecutorRejection::Backpressure,
                        },
                    );
                }
                let recovery_execution = self.allocate_execution_id()?;
                let recovery = AttemptRuntimeState::CheckpointPublishing {
                    execution_basis: current_basis,
                    origin,
                    daemon_epoch: self.daemon_epoch,
                    execution: recovery_execution,
                    checkpoint,
                };
                let advance = self.advance_attempt(key, publishing, Some(recovery))?;
                if let AttemptAdvance::CommittedAfterError(error) = advance {
                    self.reserve_checkpoint_recovery(request, recovery_execution, origin)?;
                    return Err(LocalExecutorError::Ledger(error));
                }
                let response = self.persist_response(
                    request,
                    SubmitAttemptDisposition::Accepted {
                        execution: recovery_execution,
                    },
                );
                self.reserve_checkpoint_recovery(request, recovery_execution, origin)?;
                return response;
            }
            Some(AttemptRuntimeState::Publishing {
                execution_basis: current_basis,
                daemon_epoch,
                execution,
                ..
            }) if current_basis == execution_basis
                && daemon_epoch == self.daemon_epoch
                && self.active.contains_key(&execution) =>
            {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::AlreadyRunning { execution },
                );
            }
            Some(
                publishing @ AttemptRuntimeState::Publishing {
                    execution_basis: current_basis,
                    origin,
                    daemon_epoch,
                    execution,
                    observation,
                    finding_candidate,
                },
            ) if current_basis == execution_basis => {
                match self.validator.validate_completion_artifacts(
                    request,
                    observation,
                    finding_candidate,
                ) {
                    Ok(()) => {
                        let completed = AttemptRuntimeState::Completed {
                            execution_basis: current_basis,
                            origin,
                            daemon_epoch,
                            execution,
                            observation,
                            finding_candidate: CompletedFindingCandidate::pending(
                                finding_candidate,
                            ),
                        };
                        let advance = self.advance_attempt(key, publishing, Some(completed))?;
                        if let AttemptAdvance::CommittedAfterError(error) = advance {
                            return Err(LocalExecutorError::Ledger(error));
                        }
                        self.release_active_if_present(execution)?;
                        return self.persist_response_with_finding_candidate(
                            request,
                            SubmitAttemptDisposition::AlreadyCompleted { observation },
                            finding_candidate,
                        );
                    }
                    Err(CompletionValidationFailure::UnavailableInput) => {
                        if !self.has_capacity(request.resources()) {
                            return self.persist_response(
                                request,
                                SubmitAttemptDisposition::Rejected {
                                    reason: ExecutorRejection::Backpressure,
                                },
                            );
                        }
                        let recovery_execution = self.allocate_execution_id()?;
                        let recovery = AttemptRuntimeState::Publishing {
                            execution_basis: current_basis,
                            origin,
                            daemon_epoch: self.daemon_epoch,
                            execution: recovery_execution,
                            observation,
                            finding_candidate,
                        };
                        let advance = self.advance_attempt(key, publishing, Some(recovery))?;
                        if let AttemptAdvance::CommittedAfterError(error) = advance {
                            self.reserve(request, recovery_execution, origin)?;
                            return Err(LocalExecutorError::Ledger(error));
                        }
                        let response = self.persist_response(
                            request,
                            SubmitAttemptDisposition::Accepted {
                                execution: recovery_execution,
                            },
                        );
                        self.reserve(request, recovery_execution, origin)?;
                        return response;
                    }
                    Err(CompletionValidationFailure::Unauthorized) => {
                        return self.persist_response(
                            request,
                            SubmitAttemptDisposition::Rejected {
                                reason: ExecutorRejection::Unauthorized,
                            },
                        );
                    }
                    Err(CompletionValidationFailure::Incompatible) => {
                        return self.persist_response(
                            request,
                            SubmitAttemptDisposition::Rejected {
                                reason: ExecutorRejection::Incompatible,
                            },
                        );
                    }
                }
            }
            Some(AttemptRuntimeState::Completed {
                execution_basis: current_basis,
                observation,
                finding_candidate,
                ..
            }) if current_basis == execution_basis => {
                let finding_candidate = finding_candidate.candidate();
                match self.validator.validate_completion_artifacts(
                    request,
                    observation,
                    finding_candidate,
                ) {
                    Ok(()) => {
                        return self.persist_response_with_finding_candidate(
                            request,
                            SubmitAttemptDisposition::AlreadyCompleted { observation },
                            finding_candidate,
                        );
                    }
                    Err(CompletionValidationFailure::UnavailableInput) => {
                        return self.persist_response(
                            request,
                            SubmitAttemptDisposition::Rejected {
                                reason: ExecutorRejection::UnavailableInput,
                            },
                        );
                    }
                    Err(CompletionValidationFailure::Unauthorized) => {
                        return self.persist_response(
                            request,
                            SubmitAttemptDisposition::Rejected {
                                reason: ExecutorRejection::Unauthorized,
                            },
                        );
                    }
                    Err(CompletionValidationFailure::Incompatible) => {
                        let advance = self.advance_attempt_optional(key, prior, None)?;
                        if let AttemptAdvance::CommittedAfterError(error) = advance {
                            return Err(LocalExecutorError::Ledger(error));
                        }
                        prior = None;
                    }
                }
            }
            Some(AttemptRuntimeState::Running {
                execution_basis: current_basis,
                daemon_epoch,
                execution,
                ..
            })
            | Some(AttemptRuntimeState::Publishing {
                execution_basis: current_basis,
                daemon_epoch,
                execution,
                ..
            }) if daemon_epoch == self.daemon_epoch
                && current_basis == execution_basis
                && self.active.contains_key(&execution) =>
            {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::AlreadyRunning { execution },
                );
            }
            Some(AttemptRuntimeState::Running {
                execution_basis: current_basis,
                daemon_epoch,
                ..
            })
            | Some(AttemptRuntimeState::Publishing {
                execution_basis: current_basis,
                daemon_epoch,
                ..
            }) if daemon_epoch == self.daemon_epoch && current_basis != execution_basis => {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::Rejected {
                        reason: ExecutorRejection::Incompatible,
                    },
                );
            }
            Some(AttemptRuntimeState::CheckpointRequested {
                execution_basis: current_basis,
                daemon_epoch,
                ..
            })
            | Some(AttemptRuntimeState::CheckpointPublishing {
                execution_basis: current_basis,
                daemon_epoch,
                ..
            }) if daemon_epoch == self.daemon_epoch && current_basis != execution_basis => {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::Rejected {
                        reason: ExecutorRejection::Incompatible,
                    },
                );
            }
            Some(AttemptRuntimeState::TerminalFailure { .. }) => {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::Rejected {
                        reason: ExecutorRejection::TerminalFailure,
                    },
                );
            }
            Some(AttemptRuntimeState::CheckpointRequested { .. })
            | Some(AttemptRuntimeState::CheckpointPublishing { .. })
            | Some(AttemptRuntimeState::Paused { .. })
            | Some(AttemptRuntimeState::CheckpointPromoting { .. })
            | Some(AttemptRuntimeState::Completed { .. }) => {
                return self.persist_response(
                    request,
                    SubmitAttemptDisposition::Rejected {
                        reason: ExecutorRejection::Incompatible,
                    },
                );
            }
            Some(AttemptRuntimeState::Running { .. })
            | Some(AttemptRuntimeState::Publishing { .. })
            | Some(AttemptRuntimeState::Canceled { .. })
            | None => {}
        }

        if !self.has_capacity(request.resources()) {
            return self.persist_response(
                request,
                SubmitAttemptDisposition::Rejected {
                    reason: ExecutorRejection::Backpressure,
                },
            );
        }

        let execution = self.allocate_execution_id()?;
        let origin = if let AttemptStartMode::SelectedSavepoint {
            selection,
            request: capture_request,
            ..
        } = request.start_mode()
        {
            if let Some(state) = prior
                && state.execution_basis() == execution_basis
            {
                state.origin()
            } else {
                let source_attempt = admission.selected_source_attempt.ok_or(
                    LocalExecutorError::LedgerInvariant {
                        reason: "validated selected source attempt is absent",
                    },
                )?;
                let source_key = AttemptExecutionKey::new_scoped(
                    request.lineage(),
                    source_attempt,
                    AttemptExecutionScope::SavepointCapture {
                        request: capture_request,
                    },
                );
                let source_state = self
                    .ledger
                    .load_attempt(source_key)
                    .map_err(LocalExecutorError::Ledger)?;
                match source_state {
                    Some(AttemptRuntimeState::Paused {
                        execution: source_execution,
                        checkpoint: source_checkpoint,
                        ..
                    }) => AttemptExecutionOrigin::SelectedSavepoint {
                        certificate: selection,
                        request: capture_request,
                        source_attempt,
                        source_execution,
                        source_checkpoint,
                        resume: None,
                    },
                    None => AttemptExecutionOrigin::Initial,
                    Some(_) => {
                        return self.persist_response(
                            request,
                            SubmitAttemptDisposition::Rejected {
                                reason: ExecutorRejection::Incompatible,
                            },
                        );
                    }
                }
            }
        } else {
            AttemptExecutionOrigin::Initial
        };
        let capture_materialized_start = matches!(
            request.start_mode(),
            AttemptStartMode::CaptureMaterializedStart { .. }
                | AttemptStartMode::SavepointCapture { .. }
        );
        let initial_state = if capture_materialized_start {
            AttemptRuntimeState::CheckpointRequested {
                execution_basis,
                origin,
                daemon_epoch: self.daemon_epoch,
                execution,
            }
        } else {
            AttemptRuntimeState::Running {
                execution_basis,
                origin,
                daemon_epoch: self.daemon_epoch,
                execution,
            }
        };
        let advance = self.advance_attempt_optional(key, prior, Some(initial_state))?;
        if let AttemptAdvance::CommittedAfterError(error) = advance {
            if capture_materialized_start {
                self.reserve_checkpoint_recovery(request, execution, origin)?;
            } else {
                self.reserve(request, execution, origin)?;
            }
            return Err(LocalExecutorError::Ledger(error));
        }
        let response =
            self.persist_response(request, SubmitAttemptDisposition::Accepted { execution });
        // State is durable before response publication. Even when publication
        // is indeterminate, retain and run the prepared work so a response that
        // did become visible can never name an execution the daemon abandoned.
        if capture_materialized_start {
            self.reserve_checkpoint_recovery(request, execution, origin)?;
        } else {
            self.reserve(request, execution, origin)?;
        }
        response
    }
}
