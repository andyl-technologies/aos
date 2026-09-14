//! Cross-projection validation for compacted lifecycle replay.

use aos_sandbox_core::{ProjectId, ResourceId, Revision};

use super::{
    LifecycleAuthoritativeSemanticCommitV1, LifecycleAuxiliaryHistoryV1, LifecycleAuxiliaryKindV1,
    LifecycleAuxiliaryPayloadV1, LifecycleCoordinationRecordDigestV1, LifecycleModelError,
    LifecycleOperationV1, LifecycleProtectedCoordinationV1, LifecycleProtectedRetentionLedgerV1,
    LifecycleRetentionLedgerDigestV1, LifecycleSemanticCommitFactV1,
};

impl LifecycleAuxiliaryHistoryV1 {
    pub(super) fn record_is_materialization_required(
        &self,
        record: &super::LifecycleAuxiliaryRecordV1,
    ) -> bool {
        match record.payload() {
            LifecycleAuxiliaryPayloadV1::Operation(operation) => self
                .operations
                .operation_record(operation.operation_id())
                .is_some_and(|(current, digest)| {
                    current == operation && digest == record.operation_record()
                }),
            LifecycleAuxiliaryPayloadV1::Cancellation(cancellation) => self
                .operations
                .cancellations()
                .lookup(cancellation.request())
                .is_some_and(|outcome| outcome == *cancellation.outcome()),
            LifecycleAuxiliaryPayloadV1::BootInventory(boot) => self
                .operations
                .operation_record(boot.operation())
                .is_some_and(|(operation, digest)| {
                    operation.record_revision() == boot.operation_revision()
                        && digest == boot.operation_record()
                }),
            LifecycleAuxiliaryPayloadV1::SuspendObservation(observation) => self
                .operations
                .operation_record(observation.operation())
                .is_some_and(|(operation, digest)| {
                    operation.record_revision() == observation.operation_revision()
                        && digest == observation.operation_record()
                }),
            LifecycleAuxiliaryPayloadV1::Coordination(transaction) => {
                let record =
                    LifecycleProtectedCoordinationV1::from_authoritative(transaction.clone())
                        .record();
                self.operations.operations().any(|operation| {
                    operation.method_semantic_commit().is_some_and(|commit| {
                        commit
                            .evidence()
                            .coordination()
                            .is_some_and(|fact| fact.record() == record)
                            || matches!(
                                commit.facts(),
                                LifecycleSemanticCommitFactV1::CascadeDelete { cascade, .. }
                                    if cascade.coordination_record() == record
                            )
                    })
                })
            }
            LifecycleAuxiliaryPayloadV1::RetentionLedger(ledger) => {
                let record =
                    LifecycleProtectedRetentionLedgerV1::from_authoritative(ledger.clone())
                        .record();
                self.operations.operations().any(|operation| {
                    operation.method_semantic_commit().is_some_and(|commit| {
                        commit
                            .evidence()
                            .retention()
                            .is_some_and(|fact| fact.record() == record)
                            || match commit.facts() {
                                LifecycleSemanticCommitFactV1::Snapshot { retention, .. } => {
                                    retention.iter().any(|ack| ack.ledger() == record)
                                }
                                LifecycleSemanticCommitFactV1::DeleteSnapshot {
                                    retention_release,
                                    ..
                                } => {
                                    retention_release.predecessor_ledger() == record
                                        || retention_release.successor_ledger() == record
                                }
                                LifecycleSemanticCommitFactV1::DesiredState { .. }
                                | LifecycleSemanticCommitFactV1::CascadeDelete { .. } => false,
                            }
                    })
                })
            }
        }
    }

    pub(super) fn validate_materialized_method_join(
        &self,
        operation: &LifecycleOperationV1,
    ) -> Result<(), LifecycleModelError> {
        let Some(commit) = operation.method_semantic_commit() else {
            return Ok(());
        };
        let LifecycleSemanticCommitFactV1::DeleteSnapshot {
            tombstone,
            retention_release,
            ..
        } = commit.facts()
        else {
            return Ok(());
        };
        if tombstone.digest().as_bytes() == &[0; 32] {
            return Err(LifecycleModelError::InvalidTransition);
        }
        let operation_join_is_complete = self.records.values().any(|operation_member| {
            matches!(
                operation_member.payload(),
                LifecycleAuxiliaryPayloadV1::Operation(candidate) if candidate == operation
            ) && self.records.values().any(|successor_member| {
                let LifecycleAuxiliaryPayloadV1::RetentionLedger(successor) =
                    successor_member.payload()
                else {
                    return false;
                };
                if successor_member.project() != operation.project()
                    || successor_member.atomic_join() != operation_member.atomic_join()
                    || successor.revision() != retention_release.successor_revision()
                {
                    return false;
                }
                self.records.values().any(|predecessor_member| {
                    let LifecycleAuxiliaryPayloadV1::RetentionLedger(predecessor) =
                        predecessor_member.payload()
                    else {
                        return false;
                    };
                    if predecessor_member.project() != operation.project()
                        || predecessor_member.lineage() != successor_member.lineage()
                        || predecessor.revision() != retention_release.predecessor_revision()
                    {
                        return false;
                    }
                    let predecessor = LifecycleProtectedRetentionLedgerV1::from_authoritative(
                        predecessor.clone(),
                    );
                    let successor =
                        LifecycleProtectedRetentionLedgerV1::from_authoritative(successor.clone());
                    super::LifecycleSnapshotRetentionReleaseV1::from_protected_ledgers(
                        retention_release.snapshot(),
                        retention_release.holder(),
                        &predecessor,
                        &successor,
                    )
                    .is_ok_and(|derived| derived == *retention_release)
                })
            })
        });
        if operation_join_is_complete {
            Ok(())
        } else {
            Err(LifecycleModelError::InvalidTransition)
        }
    }

    pub(super) fn validate_terminal_auxiliaries(
        &self,
        operation: &LifecycleOperationV1,
    ) -> Result<(), LifecycleModelError> {
        if operation.terminal_result() != Some(super::LifecycleTerminalResultV1::Succeeded) {
            return Ok(());
        }
        let shares_operation_join = |record: &super::LifecycleAuxiliaryRecordV1| {
            self.records.values().any(|member| {
                member.project() == record.project()
                    && member.atomic_join() == record.atomic_join()
                    && matches!(
                        member.payload(),
                        LifecycleAuxiliaryPayloadV1::Operation(candidate) if candidate == operation
                    )
            })
        };
        let has_valid_boot = self.records.values().any(|record| {
            let LifecycleAuxiliaryPayloadV1::BootInventory(boot) = record.payload() else {
                return false;
            };
            let mut resources = Vec::new();
            if resources.try_reserve_exact(boot.resources().len()).is_err() {
                return false;
            }
            resources.extend_from_slice(boot.resources());
            shares_operation_join(record)
                && super::LifecycleBootInventoryV1::from_operation(
                    operation,
                    boot.step(),
                    boot.fence(),
                    boot.domains(),
                    resources,
                    boot.observed_at(),
                )
                .is_ok_and(|derived| derived == *boot && boot_fence_matches_commit(operation, boot))
        });
        if matches!(
            operation.intent().method(),
            super::LifecycleMethodV1::Start | super::LifecycleMethodV1::Resume
        ) && !has_valid_boot
        {
            return Err(LifecycleModelError::InvalidTransition);
        }
        if let super::LifecycleIntentV1::SuspendMemory { fence, .. } = operation.intent() {
            let observed = self.records.values().any(|record| {
                let LifecycleAuxiliaryPayloadV1::SuspendObservation(observation) = record.payload()
                else {
                    return false;
                };
                shares_operation_join(record)
                    && record.operation() == operation.operation_id()
                    && record.operation_revision() == operation.record_revision()
                    && observation.fence() == *fence
                    && super::LifecycleSuspendObservationV1::from_operation(
                        operation,
                        observation.fence(),
                        observation.observation(),
                        observation.observed_at(),
                    )
                    .is_ok_and(|derived| derived == *observation)
            });
            if !observed {
                return Err(LifecycleModelError::InvalidTransition);
            }
        }
        Ok(())
    }

    /// Resolves an exact authoritative coordination record to an opaque handle.
    #[must_use]
    pub fn protected_coordination(
        &self,
        project: ProjectId,
        lineage: ResourceId,
        revision: Revision,
        expected: LifecycleCoordinationRecordDigestV1,
    ) -> Option<LifecycleProtectedCoordinationV1> {
        let record = self.records.get(&(
            project,
            lineage,
            LifecycleAuxiliaryKindV1::Coordination,
            revision,
        ))?;
        let LifecycleAuxiliaryPayloadV1::Coordination(transaction) = record.payload() else {
            return None;
        };
        let protected = LifecycleProtectedCoordinationV1::from_authoritative(transaction.clone());
        (protected.record() == expected).then_some(protected)
    }

    /// Resolves an exact authoritative retention ledger to an opaque handle.
    #[must_use]
    pub fn protected_retention_ledger(
        &self,
        project: ProjectId,
        lineage: ResourceId,
        revision: Revision,
        expected: LifecycleRetentionLedgerDigestV1,
    ) -> Option<LifecycleProtectedRetentionLedgerV1> {
        let record = self.records.get(&(
            project,
            lineage,
            LifecycleAuxiliaryKindV1::RetentionLedger,
            revision,
        ))?;
        let LifecycleAuxiliaryPayloadV1::RetentionLedger(ledger) = record.payload() else {
            return None;
        };
        let protected = LifecycleProtectedRetentionLedgerV1::from_authoritative(ledger.clone());
        (protected.record() == expected).then_some(protected)
    }

    /// Rebinds decoded semantic facts to exact authoritative auxiliary records.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidTransition`] when a referenced
    /// coordination or retention revision is absent, orphaned, or divergent.
    pub fn authoritative_semantic_commit(
        &self,
        operation: &LifecycleOperationV1,
    ) -> Result<Option<LifecycleAuthoritativeSemanticCommitV1>, LifecycleModelError> {
        let Some(commit) = operation.method_semantic_commit() else {
            return Ok(None);
        };
        let project = operation.project();
        if let Some(fact) = commit.evidence().coordination() {
            let matches = self.records.values().any(|record| {
                record.project() == project
                    && self
                        .protected_coordination(
                            project,
                            record.lineage(),
                            record.revision(),
                            fact.record(),
                        )
                        .is_some_and(|protected| fact.is_bound_to(&protected))
            });
            if !matches {
                return Err(LifecycleModelError::InvalidTransition);
            }
        }
        if let Some(fact) = commit.evidence().retention() {
            let matches = self.records.values().any(|record| {
                record.project() == project
                    && self
                        .protected_retention_ledger(
                            project,
                            record.lineage(),
                            fact.revision(),
                            fact.record(),
                        )
                        .is_some_and(|protected| fact.is_bound_to(&protected))
            });
            if !matches {
                return Err(LifecycleModelError::InvalidTransition);
            }
        }
        let facts_match = match commit.facts() {
            LifecycleSemanticCommitFactV1::Snapshot { retention, .. } => {
                retention.iter().all(|acknowledgement| {
                    self.records.values().any(|record| {
                        record.project() == project
                            && self
                                .protected_retention_ledger(
                                    project,
                                    record.lineage(),
                                    acknowledgement.revision(),
                                    acknowledgement.ledger(),
                                )
                                .is_some_and(|protected| acknowledgement.is_bound_to(&protected))
                    })
                })
            }
            LifecycleSemanticCommitFactV1::DeleteSnapshot {
                retention_release, ..
            } => {
                let predecessor = self.records.values().find_map(|record| {
                    self.protected_retention_ledger(
                        project,
                        record.lineage(),
                        retention_release.predecessor_revision(),
                        retention_release.predecessor_ledger(),
                    )
                });
                let successor = self.records.values().find_map(|record| {
                    self.protected_retention_ledger(
                        project,
                        record.lineage(),
                        retention_release.successor_revision(),
                        retention_release.successor_ledger(),
                    )
                });
                predecessor
                    .zip(successor)
                    .is_some_and(|(predecessor, successor)| {
                        super::LifecycleSnapshotRetentionReleaseV1::from_protected_ledgers(
                            retention_release.snapshot(),
                            retention_release.holder(),
                            &predecessor,
                            &successor,
                        )
                        .is_ok_and(|derived| derived == *retention_release)
                    })
            }
            LifecycleSemanticCommitFactV1::CascadeDelete { cascade, .. } => self
                .records
                .values()
                .find_map(|record| {
                    self.protected_coordination(
                        project,
                        record.lineage(),
                        record.revision(),
                        cascade.coordination_record(),
                    )
                })
                .is_some_and(|protected| cascade.is_bound_to(&protected)),
            LifecycleSemanticCommitFactV1::DesiredState { .. } => true,
        };
        if !facts_match {
            return Err(LifecycleModelError::InvalidTransition);
        }
        Ok(Some(LifecycleAuthoritativeSemanticCommitV1::from_replay(
            commit.clone(),
        )))
    }
}

fn boot_fence_matches_commit(
    operation: &LifecycleOperationV1,
    boot: &super::LifecycleBootInventoryV1,
) -> bool {
    let sandbox = match operation.intent() {
        super::LifecycleIntentV1::Start { sandbox, .. }
        | super::LifecycleIntentV1::Resume { sandbox, .. } => *sandbox,
        _ => return false,
    };
    let Some(commit) = operation.method_semantic_commit() else {
        return false;
    };
    let cas = commit.facts().cas();
    let desired = boot.fence().desired();
    let exact_resources = commit
        .facts()
        .resources()
        .iter()
        .map(|resource| resource.resource())
        .eq(boot.resources().iter().copied());
    cas.resource() == super::LifecycleResourceV1::Sandbox(sandbox)
        && boot.fence().sandbox() == sandbox
        && desired.resource() == cas.resource()
        && desired.expected_generation() == cas.successor_generation()
        && exact_resources
        && commit.facts().resources().iter().any(|resource| {
            resource.resource() == cas.resource()
                && resource.successor_revision() == desired.resource_revision()
                && resource.successor_state() == desired.resource_state()
        })
}
