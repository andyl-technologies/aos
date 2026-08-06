//! Atomic routing across host-owned and live-QEMU fault adapters.
//!
//! A signal boundary can produce network, storage, and node actions together.
//! This sink prepares the complete batch before making any action visible,
//! commits live QEMU first, and commits the infallible host ledger only after
//! QEMU has acknowledged the architectural mutation. A QEMU rejection aborts
//! the still-hidden host transaction; ambiguous QEMU visibility is terminal.

use std::collections::{BTreeMap, BTreeSet};

use crucible::model::{
    ContentHash, FaultActionCommitError, FaultActionSink, FaultAdapter, FaultRuntimeError,
    HostFaultActionSink, PreparedActionBatch, PreparedActionResult, RejectedActionBatch,
    ResolvedBindingAction,
};

use crate::{QemuFaultActionSink, QemuNodeSet};

#[derive(Clone, Debug)]
struct PreparedProductionBatch {
    transaction: ContentHash,
    action_order: Vec<ContentHash>,
    host_transaction: Option<ContentHash>,
    qemu_transaction: Option<ContentHash>,
}

/// Production transaction sink spanning host devices and live patched QEMU.
pub struct ProductionFaultActionSink<'a> {
    host: &'a mut HostFaultActionSink,
    qemu: QemuFaultActionSink<'a>,
    prepared: Option<PreparedProductionBatch>,
}

impl<'a> ProductionFaultActionSink<'a> {
    /// Binds the host device state and live QEMU node set for one transaction.
    #[must_use]
    pub fn new(host: &'a mut HostFaultActionSink, nodes: &'a mut QemuNodeSet) -> Self {
        Self {
            host,
            qemu: QemuFaultActionSink::new(nodes),
            prepared: None,
        }
    }

    fn reject(error: FaultRuntimeError) -> Box<RejectedActionBatch> {
        Box::new(RejectedActionBatch {
            error,
            observations: Vec::new(),
            rejected_action: None,
        })
    }
}

impl FaultActionSink for ProductionFaultActionSink<'_> {
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        if self.prepared.is_some() {
            return Err(Self::reject(FaultRuntimeError::AdapterTransactionPending));
        }

        let mut host_actions = Vec::new();
        let mut qemu_actions = Vec::new();
        let mut seen = BTreeSet::new();
        for action in actions {
            if !seen.insert(action.id()) {
                return Err(Self::reject(FaultRuntimeError::DuplicateAdapterAction));
            }
            match action.effect.kind().descriptor().adapter {
                FaultAdapter::Network | FaultAdapter::Storage => host_actions.push(action.clone()),
                FaultAdapter::Node => qemu_actions.push(action.clone()),
            }
        }

        let host_batch = if host_actions.is_empty() {
            None
        } else {
            Some(self.host.prepare_batch(&host_actions)?)
        };
        let qemu_batch = if qemu_actions.is_empty() {
            None
        } else {
            match self.qemu.prepare_batch(&qemu_actions) {
                Ok(batch) => Some(batch),
                Err(error) => {
                    if let Some(host_batch) = &host_batch
                        && self.host.abort_batch(host_batch.transaction).is_err()
                    {
                        return Err(Self::reject(FaultRuntimeError::AdapterTransactionRollback));
                    }
                    return Err(error);
                }
            }
        };

        let action_order = actions
            .iter()
            .map(ResolvedBindingAction::id)
            .collect::<Vec<_>>();
        let mut material = Vec::with_capacity((action_order.len() + 2) * 32);
        for action in &action_order {
            material.extend_from_slice(&action.bytes);
        }
        for transaction in [
            host_batch.as_ref().map(|batch| batch.transaction),
            qemu_batch.as_ref().map(|batch| batch.transaction),
        ]
        .into_iter()
        .flatten()
        {
            material.extend_from_slice(&transaction.bytes);
        }
        let transaction = ContentHash::from_bytes(&material);
        let mut predicted = host_batch
            .iter()
            .chain(qemu_batch.iter())
            .flat_map(|batch| batch.results.iter().cloned())
            .map(|result| (result.action, result))
            .collect::<BTreeMap<_, _>>();
        let results = match reorder_results(&action_order, &mut predicted) {
            Ok(results) => results,
            Err(error) => {
                let qemu_abort = qemu_batch
                    .as_ref()
                    .map_or(Ok(()), |batch| self.qemu.abort_batch(batch.transaction));
                let host_abort = host_batch
                    .as_ref()
                    .map_or(Ok(()), |batch| self.host.abort_batch(batch.transaction));
                if qemu_abort.is_err() || host_abort.is_err() {
                    return Err(Self::reject(FaultRuntimeError::AdapterTransactionRollback));
                }
                return Err(Self::reject(error));
            }
        };

        self.prepared = Some(PreparedProductionBatch {
            transaction,
            action_order,
            host_transaction: host_batch.map(|batch| batch.transaction),
            qemu_transaction: qemu_batch.map(|batch| batch.transaction),
        });
        Ok(PreparedActionBatch {
            transaction,
            results,
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
        let qemu_result = prepared
            .qemu_transaction
            .map_or(Ok(()), |transaction| self.qemu.abort_batch(transaction));
        let host_result = prepared
            .host_transaction
            .map_or(Ok(()), |transaction| self.host.abort_batch(transaction));
        if qemu_result.is_err() || host_result.is_err() {
            return Err(FaultRuntimeError::AdapterTransactionRollback);
        }
        Ok(())
    }

    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        let prepared = self.prepared.take().ok_or_else(|| {
            FaultActionCommitError::Fatal(FaultRuntimeError::UnknownAdapterTransaction)
        })?;
        if prepared.transaction != transaction {
            self.prepared = Some(prepared);
            return Err(FaultActionCommitError::Fatal(
                FaultRuntimeError::UnknownAdapterTransaction,
            ));
        }

        let qemu_batch = match prepared.qemu_transaction {
            Some(qemu_transaction) => match self.qemu.commit_batch(qemu_transaction) {
                Ok(batch) => Some(batch),
                Err(FaultActionCommitError::Rejected(error)) => {
                    if let Some(host_transaction) = prepared.host_transaction
                        && self.host.abort_batch(host_transaction).is_err()
                    {
                        return Err(FaultActionCommitError::Fatal(
                            FaultRuntimeError::AdapterTransactionRollback,
                        ));
                    }
                    return Err(FaultActionCommitError::Rejected(error));
                }
                Err(FaultActionCommitError::Fatal(error)) => {
                    if let Some(host_transaction) = prepared.host_transaction {
                        let _ = self.host.abort_batch(host_transaction);
                    }
                    return Err(FaultActionCommitError::Fatal(error));
                }
            },
            None => None,
        };

        let host_batch = match prepared.host_transaction {
            Some(host_transaction) => match self.host.commit_batch(host_transaction) {
                Ok(batch) => Some(batch),
                Err(error) if qemu_batch.is_some() => {
                    let _ = error;
                    return Err(FaultActionCommitError::Fatal(
                        FaultRuntimeError::AdapterTransactionRollback,
                    ));
                }
                Err(error) => return Err(error),
            },
            None => None,
        };
        let mut committed = host_batch
            .iter()
            .chain(qemu_batch.iter())
            .flat_map(|batch| batch.results.iter().cloned())
            .map(|result| (result.action, result))
            .collect::<BTreeMap<_, _>>();
        let results = reorder_results(&prepared.action_order, &mut committed)
            .map_err(FaultActionCommitError::Fatal)?;
        Ok(PreparedActionBatch {
            transaction,
            results,
        })
    }
}

fn reorder_results(
    action_order: &[ContentHash],
    results: &mut BTreeMap<ContentHash, PreparedActionResult>,
) -> Result<Vec<PreparedActionResult>, FaultRuntimeError> {
    let ordered = action_order
        .iter()
        .map(|action| results.remove(action))
        .collect::<Option<Vec<_>>>()
        .ok_or(FaultRuntimeError::IncompleteAdapterState)?;
    if !results.is_empty() {
        return Err(FaultRuntimeError::IncompleteAdapterState);
    }
    Ok(ordered)
}
