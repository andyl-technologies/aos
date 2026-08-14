//! Atomic mirroring into canonical adapter state and a live backend.

use super::*;

/// One transaction mirrored into canonical adapter state and a live backend.
pub(super) struct MirroredFaultActionSink<'a, B> {
    state: &'a mut TransactionalFaultAdapters,
    backend: &'a mut B,
    prepared: Option<PreparedMirroredBatch>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedMirroredBatch {
    transaction: ContentHash,
    state_transaction: ContentHash,
    backend_transaction: ContentHash,
    state_before: TransactionalFaultAdapters,
}

impl<'a, B> MirroredFaultActionSink<'a, B>
where
    B: FaultActionSink,
{
    /// Couples canonical adapter state to one live production backend.
    #[must_use]
    pub(super) fn new(state: &'a mut TransactionalFaultAdapters, backend: &'a mut B) -> Self {
        Self {
            state,
            backend,
            prepared: None,
        }
    }

    fn abort_prepared(
        &mut self,
        prepared: &PreparedMirroredBatch,
    ) -> Result<(), FaultRuntimeError> {
        let state = self.state.abort_batch(prepared.state_transaction);
        let backend = self.backend.abort_batch(prepared.backend_transaction);
        if state.is_err() || backend.is_err() {
            *self.state = prepared.state_before.clone();
            return Err(FaultRuntimeError::AdapterTransactionRollback);
        }
        Ok(())
    }
}

impl<B> FaultActionSink for MirroredFaultActionSink<'_, B>
where
    B: FaultActionSink,
{
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        if self.prepared.is_some() {
            return Err(Box::new(RejectedActionBatch {
                error: FaultRuntimeError::AdapterTransactionPending,
                observations: Vec::new(),
                rejected_action: None,
            }));
        }
        let state_before = self.state.clone();
        let backend_batch = self.backend.prepare_batch(actions)?;
        let state_batch = match self.state.prepare_batch(actions) {
            Ok(batch) => batch,
            Err(error) => {
                if self.backend.abort_batch(backend_batch.transaction).is_err() {
                    return Err(Box::new(RejectedActionBatch {
                        error: FaultRuntimeError::AdapterTransactionRollback,
                        observations: error.observations,
                        rejected_action: error.rejected_action,
                    }));
                }
                return Err(error);
            }
        };
        let expected = actions
            .iter()
            .map(ResolvedBindingAction::id)
            .collect::<Vec<_>>();
        let backend_actions = backend_batch
            .results
            .iter()
            .map(|result| result.action)
            .collect::<Vec<_>>();
        let state_actions = state_batch
            .results
            .iter()
            .map(|result| result.action)
            .collect::<Vec<_>>();
        if backend_actions != expected || state_actions != expected {
            let prepared = PreparedMirroredBatch {
                transaction: ContentHash::default(),
                state_transaction: state_batch.transaction,
                backend_transaction: backend_batch.transaction,
                state_before,
            };
            let error = if self.abort_prepared(&prepared).is_ok() {
                FaultRuntimeError::IncompleteAdapterState
            } else {
                FaultRuntimeError::AdapterTransactionRollback
            };
            return Err(Box::new(RejectedActionBatch {
                error,
                observations: Vec::new(),
                rejected_action: None,
            }));
        }
        let transaction = mirrored_transaction_digest(
            state_batch.transaction,
            backend_batch.transaction,
            &expected,
        );
        self.prepared = Some(PreparedMirroredBatch {
            transaction,
            state_transaction: state_batch.transaction,
            backend_transaction: backend_batch.transaction,
            state_before,
        });
        Ok(PreparedActionBatch {
            transaction,
            results: backend_batch.results,
        })
    }

    fn abort_batch(&mut self, transaction: ContentHash) -> Result<(), FaultRuntimeError> {
        let prepared = self
            .prepared
            .take()
            .ok_or(FaultRuntimeError::UnknownAdapterTransaction)?;
        if prepared.transaction != transaction {
            self.prepared = Some(prepared);
            return Err(FaultRuntimeError::UnknownAdapterTransaction);
        }
        self.abort_prepared(&prepared)
    }

    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        let prepared = self.prepared.take().ok_or_else(|| {
            FaultActionCommitError::Rejected(Box::new(RejectedActionBatch {
                error: FaultRuntimeError::UnknownAdapterTransaction,
                observations: Vec::new(),
                rejected_action: None,
            }))
        })?;
        if prepared.transaction != transaction {
            self.prepared = Some(prepared);
            return Err(FaultActionCommitError::Rejected(Box::new(
                RejectedActionBatch {
                    error: FaultRuntimeError::UnknownAdapterTransaction,
                    observations: Vec::new(),
                    rejected_action: None,
                },
            )));
        }
        let backend = match self.backend.commit_batch(prepared.backend_transaction) {
            Ok(committed) => committed,
            Err(FaultActionCommitError::Rejected(error)) => {
                let state_abort = self.state.abort_batch(prepared.state_transaction);
                *self.state = prepared.state_before;
                if state_abort.is_err() {
                    return Err(FaultActionCommitError::Fatal(
                        FaultRuntimeError::AdapterTransactionRollback,
                    ));
                }
                return Err(FaultActionCommitError::Rejected(error));
            }
            Err(FaultActionCommitError::Fatal(error)) => {
                *self.state = prepared.state_before;
                return Err(FaultActionCommitError::Fatal(error));
            }
        };
        if self.state.commit_batch(prepared.state_transaction).is_err() {
            *self.state = prepared.state_before;
            return Err(FaultActionCommitError::Fatal(
                FaultRuntimeError::AdapterTransactionRollback,
            ));
        }
        Ok(PreparedActionBatch {
            transaction,
            results: backend.results,
        })
    }
}
