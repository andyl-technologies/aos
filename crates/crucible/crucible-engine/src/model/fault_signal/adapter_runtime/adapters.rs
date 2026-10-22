//! Transactions spanning the network, storage, and node adapters.

use super::*;

impl TransactionalFaultAdapters {
    /// Creates the three production adapter transaction domains.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when a manifest names the wrong family.
    pub fn new(
        manifests: FaultAdapterManifests,
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, FaultRuntimeError> {
        Ok(Self {
            network: TransactionalAdapterRuntime::new(
                FaultAdapter::Network,
                manifests.network,
                resource_limits,
            )?,
            storage: TransactionalAdapterRuntime::new(
                FaultAdapter::Storage,
                manifests.storage,
                resource_limits,
            )?,
            node: TransactionalAdapterRuntime::new(
                FaultAdapter::Node,
                manifests.node,
                resource_limits,
            )?,
            prepared: None,
        })
    }

    /// Returns the committed runtime for one adapter family.
    #[must_use]
    pub const fn adapter(&self, adapter: FaultAdapter) -> &TransactionalAdapterRuntime {
        match adapter {
            FaultAdapter::Network => &self.network,
            FaultAdapter::Storage => &self.storage,
            FaultAdapter::Node => &self.node,
        }
    }

    /// Encodes all three committed adapter states for a fat checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] if an adapter has an in-flight transaction,
    /// its canonical state cannot be encoded, or the payload bound is exceeded.
    pub fn checkpoints(
        &self,
    ) -> Result<BTreeMap<FaultAdapter, AdapterCheckpointState>, FaultRuntimeError> {
        [
            FaultAdapter::Network,
            FaultAdapter::Storage,
            FaultAdapter::Node,
        ]
        .into_iter()
        .map(|adapter| Ok((adapter, self.adapter(adapter).checkpoint()?)))
        .collect()
    }

    /// Restores all three adapter transaction domains from a fat checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`FaultRuntimeError`] when a checkpoint family is missing or
    /// added, a payload is corrupt, or restored state exceeds a live manifest.
    pub fn restore(
        manifests: FaultAdapterManifests,
        mut checkpoints: BTreeMap<FaultAdapter, AdapterCheckpointState>,
        resource_limits: FaultResourceLimits,
    ) -> Result<Self, FaultRuntimeError> {
        let network = checkpoints
            .remove(&FaultAdapter::Network)
            .ok_or(FaultRuntimeError::IncompleteAdapterState)?;
        let storage = checkpoints
            .remove(&FaultAdapter::Storage)
            .ok_or(FaultRuntimeError::IncompleteAdapterState)?;
        let node = checkpoints
            .remove(&FaultAdapter::Node)
            .ok_or(FaultRuntimeError::IncompleteAdapterState)?;
        if !checkpoints.is_empty() {
            return Err(FaultRuntimeError::IncompleteAdapterState);
        }
        Ok(Self {
            network: TransactionalAdapterRuntime::restore(
                FaultAdapter::Network,
                manifests.network,
                &network,
                resource_limits,
            )?,
            storage: TransactionalAdapterRuntime::restore(
                FaultAdapter::Storage,
                manifests.storage,
                &storage,
                resource_limits,
            )?,
            node: TransactionalAdapterRuntime::restore(
                FaultAdapter::Node,
                manifests.node,
                &node,
                resource_limits,
            )?,
            prepared: None,
        })
    }

    fn adapter_mut(&mut self, adapter: FaultAdapter) -> &mut TransactionalAdapterRuntime {
        match adapter {
            FaultAdapter::Network => &mut self.network,
            FaultAdapter::Storage => &mut self.storage,
            FaultAdapter::Node => &mut self.node,
        }
    }

    fn abort_prepared(&mut self, prepared: &PreparedAdapterSet) -> Result<(), FaultRuntimeError> {
        for (adapter, transaction) in [
            (FaultAdapter::Network, prepared.network),
            (FaultAdapter::Storage, prepared.storage),
            (FaultAdapter::Node, prepared.node),
        ] {
            if let Some(transaction) = transaction {
                self.adapter_mut(adapter).abort_batch(transaction)?;
            }
        }
        Ok(())
    }
}

impl FaultActionSink for TransactionalFaultAdapters {
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
        let mut prepared = PreparedAdapterSet {
            transaction: ContentHash::default(),
            actions: actions.iter().map(ResolvedBindingAction::id).collect(),
            network: None,
            storage: None,
            node: None,
        };
        let mut by_action = std::collections::BTreeMap::new();
        for adapter in [
            FaultAdapter::Network,
            FaultAdapter::Storage,
            FaultAdapter::Node,
        ] {
            let subset = actions
                .iter()
                .filter(|action| action.effect.kind().descriptor().adapter == adapter)
                .cloned()
                .collect::<Vec<_>>();
            if subset.is_empty() {
                continue;
            }
            let batch = match self.adapter_mut(adapter).prepare_batch(&subset) {
                Ok(batch) => batch,
                Err(error) => {
                    if self.abort_prepared(&prepared).is_err() {
                        return Err(Box::new(RejectedActionBatch {
                            error: FaultRuntimeError::AdapterTransactionRollback,
                            observations: error.observations,
                            rejected_action: error.rejected_action,
                        }));
                    }
                    return Err(error);
                }
            };
            match adapter {
                FaultAdapter::Network => prepared.network = Some(batch.transaction),
                FaultAdapter::Storage => prepared.storage = Some(batch.transaction),
                FaultAdapter::Node => prepared.node = Some(batch.transaction),
            }
            for result in batch.results {
                by_action.insert(result.action, result);
            }
        }
        let results = match actions
            .iter()
            .map(|action| {
                by_action
                    .remove(&action.id())
                    .ok_or(FaultRuntimeError::IncompleteAdapterState)
            })
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(results) if by_action.is_empty() => results,
            Ok(_) | Err(_) => {
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
        };
        let transactions = [prepared.network, prepared.storage, prepared.node]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        prepared.transaction = transaction_digest(
            self.network.state_digest(),
            self.node.state_digest(),
            &transactions,
        );
        let transaction = prepared.transaction;
        self.prepared = Some(prepared);
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
        let mut by_action = BTreeMap::new();
        for (adapter, transaction) in [
            (FaultAdapter::Network, prepared.network),
            (FaultAdapter::Storage, prepared.storage),
            (FaultAdapter::Node, prepared.node),
        ] {
            if let Some(transaction) = transaction {
                let committed = self.adapter_mut(adapter).commit_batch(transaction)?;
                for result in committed.results {
                    by_action.insert(result.action, result);
                }
            }
        }
        let results = prepared
            .actions
            .iter()
            .map(|action| by_action.remove(action))
            .collect::<Option<Vec<_>>>()
            .ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ))?;
        if !by_action.is_empty() {
            return Err(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ));
        }
        Ok(PreparedActionBatch {
            transaction,
            results,
        })
    }
}
