//! Original snapshot retention and coordination publication recipes.
//!
//! Native outcomes are parked before independent readback and debt observation.
//! These methods borrow the same Source owner and retain first causes in its
//! existing executor slots; they neither detach custody nor imply completion.

use super::*;

impl ProductionEffectExecutor {
    pub(super) fn ensure_snapshot_retention_ledger(
        &mut self,
        operation_id: OperationId,
    ) -> Result<(), EffectFailure> {
        let disposition = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (operation_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "snapshot operation is absent from protected custody".to_owned(),
                    )
                })?;
            let project = current.operation().project();
            let operation_lineage = lifecycle_plan_resource_id(operation_id, b"operation-lineage");
            let retention_lineage = lifecycle_plan_resource_id(operation_id, b"retention-lineage");
            let retention_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                project,
                retention_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if owner
                .current_retention_ledger(&retention_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .is_some()
            {
                AuxiliaryPublicationDisposition::Current
            } else {
                drop(current);
                let publication = owner
                    .publish_initial_retention_ledger(
                        &operation_key,
                        &retention_key,
                        lifecycle_plan_transaction_id(operation_id, b"retention-publication"),
                        lifecycle_plan_resource_id(operation_id, b"retention-atomic-join"),
                        operation_lineage,
                        retention_lineage,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                auxiliary_publication_disposition(publication)
            }
        };

        self.settle_auxiliary_publication(operation_id, disposition, "retention ledger")
    }

    pub(super) fn ensure_snapshot_coordination(
        &mut self,
        operation_id: OperationId,
    ) -> Result<(), EffectFailure> {
        if self.pending_snapshot_coordination.is_some() {
            return Err(self.retained_snapshot_coordination_failure());
        }

        let disposition = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (operation_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "snapshot operation is absent from protected custody".to_owned(),
                    )
                })?;
            let project = current.operation().project();
            let operation_lineage = lifecycle_plan_resource_id(operation_id, b"operation-lineage");
            let retention_lineage = lifecycle_plan_resource_id(operation_id, b"retention-lineage");
            let coordination_lineage =
                lifecycle_plan_resource_id(operation_id, b"coordination-lineage");
            let retention_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                project,
                retention_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let coordination_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                project,
                coordination_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if owner
                .current_coordination(&coordination_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .is_some()
            {
                Some(AuxiliaryPublicationDisposition::Current)
            } else {
                let selected_snapshot = matches!(
                    current.operation().intent(), LifecycleIntentV1::Snapshot { .. }
                );
                drop(current);
                if selected_snapshot {
                    let publication = owner.publish_snapshot_coordination_admission_v2(
                        &operation_key,
                        &retention_key,
                        &coordination_key,
                        lifecycle_plan_transaction_id(operation_id, b"coordination-publication"),
                        lifecycle_plan_resource_id(operation_id, b"coordination-atomic-join"),
                        operation_lineage,
                        coordination_lineage,
                        lifecycle_plan_resource_id(operation_id, b"coordination-transaction"),
                    );
                    match publication {
                        Err(error) => {
                            self.pending_snapshot_coordination =
                                Some(PendingSnapshotCoordinationV2 {
                                    operation_id,
                                    outcome: Err(error),
                                    readback_debt: None,
                                });
                        }
                        Ok((outcome, readback)) => {
                            let retained = self.pending_snapshot_coordination.insert(
                                PendingSnapshotCoordinationV2 {
                                    operation_id,
                                    outcome: Ok(outcome),
                                    readback_debt: None,
                                },
                            );
                            // Park native success/ambiguity first. The current handle
                            // remains local to this SAME Source owner loan.
                            match readback {
                                Ok(Some(current)) => drop(current),
                                Ok(None) => {
                                    if matches!(
                                        &retained.outcome,
                                        Ok(LifecycleProgressCommitOutcomeV1::Applied(_))
                                    ) {
                                        retained.readback_debt = Some(
                                            LifecycleProtectedJournalErrorV1::NonCanonicalRecord,
                                        );
                                    }
                                }
                                Err(error) => retained.readback_debt = Some(error),
                            }
                        }
                    }
                    None
                } else {
                    let publication = owner.publish_coordination_admission(
                        &operation_key,
                        &retention_key,
                        &coordination_key,
                        lifecycle_plan_transaction_id(operation_id, b"coordination-publication"),
                        lifecycle_plan_resource_id(operation_id, b"coordination-atomic-join"),
                        operation_lineage,
                        coordination_lineage,
                        lifecycle_plan_resource_id(operation_id, b"coordination-transaction"),
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    Some(auxiliary_publication_disposition(publication))
                }
            }
        };

        if let Some(retained) = &self.pending_snapshot_coordination {
            if matches!(
                &retained.outcome,
                Ok(LifecycleProgressCommitOutcomeV1::Applied(_))
            ) && retained.readback_debt.is_none()
            {
                // Every selected readback has succeeded and the owner loan ended.
                // Only this completed success retires its native result.
                self.pending_snapshot_coordination = None;
                return Ok(());
            }
            return Err(self.retained_snapshot_coordination_failure());
        }

        match disposition {
            Some(disposition) => {
                self.settle_auxiliary_publication(operation_id, disposition, "snapshot coordination")
            }
            None => Err(EffectFailure::Permanent(
                "snapshot coordination result is absent".to_owned(),
            )),
        }
    }

    fn retained_snapshot_coordination_failure(&self) -> EffectFailure {
        let Some(retained) = &self.pending_snapshot_coordination else {
            return EffectFailure::Permanent(
                "snapshot coordination custody is absent".to_owned(),
            );
        };
        match &retained.outcome {
            Err(error) => EffectFailure::Permanent(format!(
                "protected snapshot coordination {} failed: {error}",
                retained.operation_id,
            )),
            Ok(LifecycleProgressCommitOutcomeV1::OutcomeUnknown { cause, .. }) => {
                EffectFailure::Retryable(format!(
                    "protected snapshot coordination {} durability is unknown: {cause}",
                    retained.operation_id,
                ))
            }
            Ok(LifecycleProgressCommitOutcomeV1::Applied(_)) => match &retained.readback_debt {
                Some(error) => EffectFailure::Permanent(format!(
                    "protected snapshot coordination {} readback failed: {error}",
                    retained.operation_id,
                )),
                None => EffectFailure::Permanent(
                    "snapshot coordination result is already resident".to_owned(),
                ),
            },
        }
    }

    pub(super) fn settle_auxiliary_publication(
        &mut self,
        operation_id: OperationId,
        disposition: AuxiliaryPublicationDisposition,
        subject: &str,
    ) -> Result<(), EffectFailure> {
        match disposition {
            AuxiliaryPublicationDisposition::Current => Ok(()),
            AuxiliaryPublicationDisposition::OutcomeUnknown(pending) => {
                self.pending_source_commit = Some(PendingSourceCommit {
                    operation_id,
                    receipt: None,
                    pending,
                });
                Err(EffectFailure::Retryable(format!(
                    "protected {subject} durability is unknown"
                )))
            }
            AuxiliaryPublicationDisposition::Diverged(pending) => {
                self.pending_source_commit = Some(PendingSourceCommit {
                    operation_id,
                    receipt: None,
                    pending,
                });
                Err(EffectFailure::Permanent(format!(
                    "protected {subject} publication diverged"
                )))
            }
        }
    }

    pub(super) fn publish_snapshot_coordination_observation(
        &mut self,
        operation_id: OperationId,
        predecessor: aos_sandbox::lifecycle::LifecycleRecordDigestV1,
        observation: aos_sandbox::lifecycle::LifecycleEffectObservationV1,
    ) -> Result<(), EffectFailure> {
        let disposition = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (operation_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "snapshot operation is absent during coordination publication".to_owned(),
                    )
                })?;
            let operation_lineage = lifecycle_plan_resource_id(operation_id, b"operation-lineage");
            let coordination_lineage =
                lifecycle_plan_resource_id(operation_id, b"coordination-lineage");
            let coordination_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                current.operation().project(),
                coordination_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            drop(current);
            let publication = owner
                .publish_coordination_observation(
                    &operation_key,
                    &coordination_key,
                    lifecycle_progress_transaction_id(
                        operation_id,
                        predecessor.digest(),
                        b"coordination-observation",
                    ),
                    lifecycle_progress_resource_id(
                        operation_id,
                        predecessor.digest(),
                        b"coordination-observation",
                    ),
                    operation_lineage,
                    coordination_lineage,
                    observation,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            auxiliary_publication_disposition(publication)
        };
        self.settle_auxiliary_publication(operation_id, disposition, "snapshot coordination")
    }
}

pub(super) fn auxiliary_publication_disposition<Current>(
    publication: LifecycleCurrentAuxiliaryPublicationV1<Current>,
) -> AuxiliaryPublicationDisposition {
    match publication {
        LifecycleCurrentAuxiliaryPublicationV1::Current(_) => {
            AuxiliaryPublicationDisposition::Current
        }
        LifecycleCurrentAuxiliaryPublicationV1::OutcomeUnknown { pending, .. } => {
            AuxiliaryPublicationDisposition::OutcomeUnknown(pending)
        }
        LifecycleCurrentAuxiliaryPublicationV1::Diverged(pending) => {
            AuxiliaryPublicationDisposition::Diverged(pending)
        }
    }
}
