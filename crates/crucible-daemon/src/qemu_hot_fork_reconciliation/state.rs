//! Monotonic admission, publication, and cleanup phases for one hot-fork child.

use super::*;

impl<B> QemuHotForkAttemptReconciliation<B>
where
    B: QemuHotForkReconciliationBackend,
{
    /// Begins ownership of one already-created exact child.
    pub fn new(attempt: QemuHotForkAttemptBasis, backend: B) -> Self {
        Self {
            attempt,
            backend: Some(backend),
            phase: QemuHotForkReconciliationPhase::AwaitingChildAdmission,
            child_admitted: false,
            terminal: None,
            publication: None,
            diagnostics_drained: false,
        }
    }

    pub(crate) fn from_reconciled_backend(
        attempt: QemuHotForkAttemptBasis,
        backend: B,
        terminal: Option<QemuHotForkChildObservation>,
        publication: Option<QemuHotForkPublicationDisposition>,
    ) -> Self {
        Self {
            attempt,
            backend: Some(backend),
            phase: QemuHotForkReconciliationPhase::Reconciled,
            child_admitted: true,
            terminal,
            publication,
            diagnostics_drained: true,
        }
    }

    /// Returns the exact supervisor reservation basis.
    #[must_use]
    pub const fn attempt(&self) -> QemuHotForkAttemptBasis {
        self.attempt
    }

    /// Returns the current monotonic phase.
    #[must_use]
    pub const fn phase(&self) -> QemuHotForkReconciliationPhase {
        self.phase
    }

    /// Returns the final parent-owned child status once observed.
    #[must_use]
    pub const fn terminal_observation(&self) -> Option<QemuHotForkChildObservation> {
        self.terminal
    }

    /// Returns the semantic publication disposition once reconciled.
    #[must_use]
    pub const fn publication(&self) -> Option<QemuHotForkPublicationDisposition> {
        self.publication
    }

    /// Authenticates the private child QMP channel before modeled execution.
    ///
    /// A failed handshake immediately quarantines the complete owner because
    /// the consumed private stream cannot be retried safely.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkAttemptReconciliationError::InvalidPhase`] unless
    /// the child awaits admission, or a backend error after quarantine.
    pub fn admit_child(&mut self) -> Result<(), QemuHotForkAttemptReconciliationError<B::Error>> {
        self.require_phase(
            "admit private child channel",
            QemuHotForkReconciliationPhase::AwaitingChildAdmission,
        )?;
        let drain = self.backend_mut()?.drain_child_diagnostics();
        if let Err(source) = drain {
            if let Some(backend) = self.backend.as_mut() {
                backend.quarantine();
            }
            self.phase = QemuHotForkReconciliationPhase::Quarantined;
            return Err(QemuHotForkAttemptReconciliationError::Operation {
                operation: "drain child diagnostics before admission",
                source,
            });
        }
        let admission = self.backend_mut()?.admit_child_channel();
        if let Err(source) = admission {
            if let Some(backend) = self.backend.as_mut() {
                backend.quarantine();
            }
            self.phase = QemuHotForkReconciliationPhase::Quarantined;
            return Err(QemuHotForkAttemptReconciliationError::Operation {
                operation: "admit private child channel",
                source,
            });
        }
        self.child_admitted = true;
        self.diagnostics_drained = false;
        self.phase = QemuHotForkReconciliationPhase::Live;
        Ok(())
    }

    /// Latches termination intent and signals the exact child pidfd.
    ///
    /// # Errors
    ///
    /// Returns an invalid-phase error after terminal reconciliation begins, or
    /// a backend error while retaining the latched termination phase for retry.
    pub fn request_termination(
        &mut self,
    ) -> Result<(), QemuHotForkAttemptReconciliationError<B::Error>> {
        match self.phase {
            QemuHotForkReconciliationPhase::AwaitingChildAdmission
            | QemuHotForkReconciliationPhase::Live
            | QemuHotForkReconciliationPhase::TerminationRequested => {}
            phase => {
                return Err(QemuHotForkAttemptReconciliationError::InvalidPhase {
                    operation: "request child termination",
                    phase,
                });
            }
        }
        self.phase = QemuHotForkReconciliationPhase::TerminationRequested;
        self.diagnostics_drained = false;
        self.backend_mut()?.terminate_child().map_err(|source| {
            QemuHotForkAttemptReconciliationError::Operation {
                operation: "request child termination",
                source,
            }
        })
    }

    /// Records the semantic outcome after target process cleanup.
    ///
    /// # Errors
    ///
    /// Returns an invalid-phase error unless operational cleanup is waiting for
    /// publication reconciliation.
    pub fn reconcile_publication(
        &mut self,
        disposition: QemuHotForkPublicationDisposition,
    ) -> Result<(), QemuHotForkAttemptReconciliationError<B::Error>> {
        self.require_phase(
            "reconcile semantic publication",
            QemuHotForkReconciliationPhase::AwaitingPublication,
        )?;
        if matches!(
            disposition,
            QemuHotForkPublicationDisposition::Observation(_)
                | QemuHotForkPublicationDisposition::ExactCheckpoint(_)
        ) && !self.child_admitted
        {
            return Err(QemuHotForkAttemptReconciliationError::ModeledResultWithoutAdmission);
        }
        self.publication = Some(disposition);
        self.phase = QemuHotForkReconciliationPhase::PublicationReconciled;
        Ok(())
    }

    /// Advances one worker-owned post-execution reconciliation subphase.
    ///
    /// The first call records the exact durable semantic disposition. Later
    /// calls require the same disposition and perform at most one backend
    /// operation through [`Self::reconcile_step`]. This is the direct adapter
    /// for [`crate::LocalAttemptWorker::reconcile_execution`].
    ///
    /// # Errors
    ///
    /// Returns a phase, admission, disposition, basis, or backend error while
    /// retaining the complete owner for exact retry or quarantine.
    pub fn reconcile_execution_disposition(
        &mut self,
        disposition: crate::AttemptExecutionDisposition,
    ) -> Result<
        crate::AttemptExecutionReconciliationStep,
        QemuHotForkAttemptReconciliationError<B::Error>,
    > {
        let publication = match disposition {
            crate::AttemptExecutionDisposition::Observation(observation) => {
                QemuHotForkPublicationDisposition::Observation(observation)
            }
            crate::AttemptExecutionDisposition::ExactCheckpoint(checkpoint) => {
                QemuHotForkPublicationDisposition::ExactCheckpoint(checkpoint)
            }
            crate::AttemptExecutionDisposition::Canceled => {
                QemuHotForkPublicationDisposition::Canceled
            }
            crate::AttemptExecutionDisposition::Failed => {
                QemuHotForkPublicationDisposition::TerminalFailure
            }
        };
        match self.publication {
            None => self.reconcile_publication(publication)?,
            Some(retained) if retained == publication => {}
            Some(_) => {
                return Err(QemuHotForkAttemptReconciliationError::PublicationDispositionMismatch);
            }
        }

        match self.reconcile_step()? {
            QemuHotForkReconciliationStep::Complete => {
                Ok(crate::AttemptExecutionReconciliationStep::Complete)
            }
            QemuHotForkReconciliationStep::Advanced(_)
            | QemuHotForkReconciliationStep::ChildDiagnosticsDrained
            | QemuHotForkReconciliationStep::ChildRunning
            | QemuHotForkReconciliationStep::AwaitingPublication => {
                Ok(crate::AttemptExecutionReconciliationStep::Progressed)
            }
        }
    }

    /// Performs at most one bounded reconciliation operation.
    ///
    /// The caller schedules subsequent calls without holding the executor
    /// supervisor actor. A live child alternates one nonblocking diagnostics
    /// drain with one parent-status query, so status cannot overtake stream
    /// service. Every destructive success advances the phase before returning,
    /// so retry never repeats an acknowledged release.
    ///
    /// # Errors
    ///
    /// Returns a typed backend error while retaining the same retryable phase,
    /// or a basis mismatch that requires caller-directed quarantine.
    pub fn reconcile_step(
        &mut self,
    ) -> Result<QemuHotForkReconciliationStep, QemuHotForkAttemptReconciliationError<B::Error>>
    {
        match self.phase {
            QemuHotForkReconciliationPhase::AwaitingChildAdmission
            | QemuHotForkReconciliationPhase::Live
            | QemuHotForkReconciliationPhase::TerminationRequested => {
                if !self.diagnostics_drained {
                    let drain = self.backend_mut()?.drain_child_diagnostics();
                    if let Err(source) = drain {
                        if let Some(backend) = self.backend.as_mut() {
                            backend.quarantine();
                        }
                        self.phase = QemuHotForkReconciliationPhase::Quarantined;
                        return Err(QemuHotForkAttemptReconciliationError::Operation {
                            operation: "drain branch-private child diagnostics",
                            source,
                        });
                    }
                    self.diagnostics_drained = true;
                    return Ok(QemuHotForkReconciliationStep::ChildDiagnosticsDrained);
                }
                self.diagnostics_drained = false;
                let observed = self.backend_mut()?.observe_child().map_err(|source| {
                    QemuHotForkAttemptReconciliationError::Operation {
                        operation: "query source-owned child status",
                        source,
                    }
                })?;
                let basis = self.backend_ref()?.child_basis();
                if observed.generation() != basis.generation()
                    || observed.process_id() != basis.process_id()
                {
                    return Err(QemuHotForkAttemptReconciliationError::ChildBasisMismatch);
                }
                if observed.disposition() == QemuHotForkChildDisposition::Running {
                    return Ok(QemuHotForkReconciliationStep::ChildRunning);
                }
                self.terminal = Some(observed);
                self.phase = QemuHotForkReconciliationPhase::ParentReaped;
                Ok(QemuHotForkReconciliationStep::Advanced(self.phase))
            }
            QemuHotForkReconciliationPhase::ParentReaped => {
                let complete =
                    self.backend_mut()?
                        .release_next_child_resource()
                        .map_err(|source| QemuHotForkAttemptReconciliationError::Operation {
                            operation: "release branch-private child resources",
                            source,
                        })?;
                if complete {
                    self.phase = QemuHotForkReconciliationPhase::ChildResourcesReleased;
                }
                Ok(QemuHotForkReconciliationStep::Advanced(self.phase))
            }
            QemuHotForkReconciliationPhase::ChildResourcesReleased => {
                self.backend_mut()?.release_target().map_err(|source| {
                    QemuHotForkAttemptReconciliationError::Operation {
                        operation: "release target process owner",
                        source,
                    }
                })?;
                self.phase = QemuHotForkReconciliationPhase::TargetReleased;
                Ok(QemuHotForkReconciliationStep::Advanced(self.phase))
            }
            QemuHotForkReconciliationPhase::TargetReleased => {
                self.phase = QemuHotForkReconciliationPhase::AwaitingPublication;
                Ok(QemuHotForkReconciliationStep::AwaitingPublication)
            }
            QemuHotForkReconciliationPhase::AwaitingPublication => {
                Ok(QemuHotForkReconciliationStep::AwaitingPublication)
            }
            QemuHotForkReconciliationPhase::PublicationReconciled => {
                let terminal = self
                    .terminal
                    .ok_or(QemuHotForkAttemptReconciliationError::ChildBasisMismatch)?;
                self.backend_mut()?
                    .release_source_status(terminal)
                    .map_err(|source| QemuHotForkAttemptReconciliationError::Operation {
                        operation: "release source-owned child status",
                        source,
                    })?;
                self.phase = QemuHotForkReconciliationPhase::SourceStatusReleased;
                Ok(QemuHotForkReconciliationStep::Advanced(self.phase))
            }
            QemuHotForkReconciliationPhase::SourceStatusReleased => {
                self.backend_mut()?
                    .release_process_contract()
                    .map_err(|source| QemuHotForkAttemptReconciliationError::Operation {
                        operation: "release child process contract",
                        source,
                    })?;
                self.phase = QemuHotForkReconciliationPhase::Reconciled;
                Ok(QemuHotForkReconciliationStep::Complete)
            }
            QemuHotForkReconciliationPhase::Reconciled => {
                Ok(QemuHotForkReconciliationStep::Complete)
            }
            QemuHotForkReconciliationPhase::Quarantined => {
                Err(QemuHotForkAttemptReconciliationError::InvalidPhase {
                    operation: "advance reconciliation",
                    phase: self.phase,
                })
            }
        }
    }

    /// Transfers every incomplete authority to fail-closed quarantine.
    pub fn quarantine(&mut self) {
        if self.phase == QemuHotForkReconciliationPhase::Reconciled
            || self.phase == QemuHotForkReconciliationPhase::Quarantined
        {
            return;
        }
        if let Some(backend) = self.backend.as_mut() {
            backend.quarantine();
        }
        self.phase = QemuHotForkReconciliationPhase::Quarantined;
    }

    /// Recovers the backend only after complete reconciliation.
    ///
    /// On an incomplete owner, returns the unchanged owner so no authority can
    /// escape the state machine.
    ///
    /// # Errors
    ///
    /// Returns the unchanged owner until its phase is
    /// [`QemuHotForkReconciliationPhase::Reconciled`].
    pub fn into_reconciled_backend(mut self) -> Result<B, Box<Self>> {
        if self.phase != QemuHotForkReconciliationPhase::Reconciled {
            return Err(Box::new(self));
        }
        match self.backend.take() {
            Some(backend) => Ok(backend),
            None => Err(Box::new(self)),
        }
    }

    pub(super) fn require_phase(
        &self,
        operation: &'static str,
        expected: QemuHotForkReconciliationPhase,
    ) -> Result<(), QemuHotForkAttemptReconciliationError<B::Error>> {
        if self.phase != expected {
            return Err(QemuHotForkAttemptReconciliationError::InvalidPhase {
                operation,
                phase: self.phase,
            });
        }
        Ok(())
    }

    pub(super) fn backend_ref(
        &self,
    ) -> Result<&B, QemuHotForkAttemptReconciliationError<B::Error>> {
        self.backend
            .as_ref()
            .ok_or(QemuHotForkAttemptReconciliationError::ChildBasisMismatch)
    }

    pub(super) fn backend_mut(
        &mut self,
    ) -> Result<&mut B, QemuHotForkAttemptReconciliationError<B::Error>> {
        self.backend
            .as_mut()
            .ok_or(QemuHotForkAttemptReconciliationError::ChildBasisMismatch)
    }
}

impl<B> Drop for QemuHotForkAttemptReconciliation<B>
where
    B: QemuHotForkReconciliationBackend,
{
    fn drop(&mut self) {
        if !matches!(
            self.phase,
            QemuHotForkReconciliationPhase::Reconciled
                | QemuHotForkReconciliationPhase::Quarantined
        ) && let Some(backend) = self.backend.as_mut()
        {
            backend.quarantine();
        }
    }
}
