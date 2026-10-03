//! Partition-independent lookup of retained public logical cache pins.

use aos_sandbox_core::{AttachmentId, ObjectDescriptor, OperationId, ProjectId, ViewId};

use super::{
    CacheAuthorityPurposeV1, CachePinV1, CacheRecoveryInventoryV1, CacheRecoveryLimitsV1,
    CacheResidencyAuthorityRequestV1, CacheResidencyCommitOutcomeV1,
    CacheResidencyProtectedJournalErrorV1, CacheResidencyProtectedOwnerV1, PhysicalPartitionId,
    ProtectedDomainJournalErrorV1, ValidatedCacheResidencyPostcommitV1,
};
use crate::cache_residency::{
    CachePinId, CachePinKindV1, CachePinLedgerV1, CatalogPresenceV1,
    ValidatedPublicLogicalPinAcquisitionV1,
    protected_journal::LOGICAL_PIN_ACQUIRE_LIFETIME_SECONDS,
};
use crate::production_operation_compiler::{
    RecheckedCacheConsumerV1, recheck_cache_consumer_projection_v1,
};

#[cfg(target_os = "linux")]
#[derive(Default)]
pub(super) struct ResidentCachePinStateV1 {
    payload_budget: Option<crate::cache_residency::protected_journal::ResidentDomainPayloadBudgetV1>,
    prepared: Option<Result<crate::cache_residency::PreparedCacheResidencyTransactionV1, CacheResidencyProtectedJournalErrorV1>>,
    commit: Option<Result<CacheResidencyCommitOutcomeV1, crate::cache_residency::protected_journal::ResidentDomainCommitFailureV1>>,
    postcommit: Option<crate::cache_residency::CacheResidencyPostcommitCapabilityV1>,
    settlement: Option<Result<crate::cache_residency::CacheOwnerPinSettlementV1, crate::cache_residency::CacheOwnerPinSettlementErrorV1>>,
    validation_failure: Option<CacheResidencyProtectedJournalErrorV1>,
    postcheck: Option<CacheResidencyProtectedJournalErrorV1>,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
pub(super) struct ResidentCachePinMutationV1 {
    pub(super) operation: Option<OperationId>,
    authority: crate::cache_residency::protected_journal::ResidentPinAuthorityAppendV1,
    inventory: Option<Result<CacheRecoveryInventoryV1, CacheResidencyProtectedJournalErrorV1>>,
    state: ResidentCachePinStateV1,
    retained: Option<CachePinV1>,
    presence: Option<Result<crate::cache_residency::CacheOwnerPinPresenceV1, crate::cache_residency::CacheOwnerErrorV1>>,
    cold: Option<Result<crate::cache_residency::CacheResidencyColdRecoveryV1, CacheResidencyProtectedJournalErrorV1>>,
    reconciliation: Option<Result<crate::cache_residency::CacheOwnerPinReconciliationV1, crate::cache_residency::CacheOwnerPinSettlementErrorV1>>,
    pub(super) first_failure: Option<CacheResidencyProtectedJournalErrorV1>,
    pub(super) postcheck: Option<CacheResidencyProtectedJournalErrorV1>,
    pub(super) complete: bool,
}

#[cfg(target_os = "linux")]
impl ResidentCachePinMutationV1 {
    pub(super) fn for_operation(operation: OperationId) -> Self {
        Self {
            operation: Some(operation),
            ..Self::default()
        }
    }

    pub(super) fn set_payload_headroom(&mut self, maximum: usize) {
        self.state.payload_budget = Some(
            crate::cache_residency::protected_journal::ResidentDomainPayloadBudgetV1::new(maximum),
        );
    }

    pub(super) fn retained_payload_bytes(&self) -> usize {
        self.state.payload_budget.as_ref().map_or(0, |budget| budget.retained())
    }

    pub(super) fn release_completed_inventory(&mut self) {
        if self.complete {
            // Successful decoded DATA is replaceable after its original
            // bookends. Failed Results and all authority/commit owners stay.
            self.inventory = None;
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(cause) = self.authority.failure() {
            return Some(cause);
        }
        if let Some(Err(cause)) = self.inventory.as_ref() {
            return Some(cause);
        }
        if let Some(Err(cause)) = self.state.prepared.as_ref() {
            return Some(cause);
        }
        if let Some(Err(cause)) = self.state.commit.as_ref() {
            return Some(cause);
        }
        if let Some(Ok(CacheResidencyCommitOutcomeV1::ValidationUnknown { cause, .. })) = self.state.commit.as_ref() {
            return Some(cause);
        }
        if let Some(Err(cause)) = self.state.settlement.as_ref() {
            return Some(cause);
        }
        if let Some(Err(cause)) = self.presence.as_ref() {
            return Some(cause);
        }
        if let Some(Err(cause)) = self.cold.as_ref() {
            return Some(cause);
        }
        if let Some(Err(cause)) = self.reconciliation.as_ref() {
            return Some(cause);
        }
        if let Some(cause) = self.state.validation_failure.as_ref() {
            return Some(cause);
        }
        self.first_failure.as_ref()
            .or(self.state.postcheck.as_ref())
            .or(self.postcheck.as_ref())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }

    pub(super) fn cold_state_only(&self) -> bool {
        matches!(self.cold.as_ref(), Some(Ok(crate::cache_residency::CacheResidencyColdRecoveryV1::StateOnly)))
    }

    // The actual cold capability and full physical result stay in this slot
    // through the session's independent final currentness checks.
    pub(super) fn reconcile(
        &mut self,
        session: &mut crate::cache_residency::protected_journal::RetainedCacheAuthoritySessionV1<'_, '_, '_, '_>,
        state: &mut crate::Journal,
        transaction_id: [u8; 16],
        consumer: &RecheckedCacheConsumerV1,
        operation: OperationId,
        released_pin: Option<&CachePinV1>,
        source_journal: &crate::Journal,
        request: &crate::cli_model::DormantSandboxRequestKindV1,
        physical: &mut crate::cache_residency::DormantCacheOwnerV1,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let returned = session.while_current_records(&[], |_, _, _, validator, refresh| {
            let action = (|| {
                recheck_current_cache_consumer(source_journal, request, consumer)?;
                let journal = crate::cache_residency::CacheResidencyProtectedJournalV1::claim(state, validator)?;
                self.cold = Some(journal.recover_current_transaction_with_payload_budget(
                    transaction_id, self.state.payload_budget.as_mut(),
                ));
                refresh()?;

                let cold = match self.cold.as_ref() {
                    Some(Ok(crate::cache_residency::CacheResidencyColdRecoveryV1::StateOnly)) => {
                        self.complete = true;
                        return Ok(());
                    }
                    Some(Ok(crate::cache_residency::CacheResidencyColdRecoveryV1::ObservePending(cold)))
                    | Some(Ok(crate::cache_residency::CacheResidencyColdRecoveryV1::Terminal(cold))) => cold,
                    _ => return Err(ProtectedDomainJournalErrorV1::StaleAuthority),
                };
                let validated = cold.validate_borrowed(&journal)?;
                self.reconciliation = Some(match released_pin {
                    Some(pin) => validated.reconcile_cache_owner_pin_change(
                        physical, crate::cache_residency::CacheOwnerPinActionV1::Release, pin,
                    ),
                    None => validated.reconcile_public_logical_pin_acquisition(
                        physical, operation, consumer.object(), consumer.project(),
                        consumer.view(), consumer.attachment(),
                    ),
                });
                refresh()?;
                if !matches!(self.reconciliation.as_ref(), Some(Ok(_))) {
                    return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
                }
                self.complete = true;
                Ok(())
            })();
            if let Err(cause) = action {
                self.first_failure.get_or_insert(cause);
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
            }
            Ok(())
        });
        if let Err(cause) = returned {
            self.postcheck.get_or_insert(cause);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }

    fn capture_partition(
        &mut self,
        session: &mut crate::cache_residency::protected_journal::RetainedCacheAuthoritySessionV1<'_, '_, '_, '_>,
        state: &mut crate::Journal,
        partition: PhysicalPartitionId,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let returned = session.while_current_records(&[], |_, _, _, validator, refresh| {
            self.inventory = Some((|| {
                let projection = crate::cache_residency::CacheResidencyProtectedJournalV1::claim(
                    state, validator.clone(),
                )?.replay()?;
                let inventories = super::reconstruct_cache_history(projection.records(), &validator)?;
                inventories.into_iter().find(|inventory| inventory.global.node_quota.partition == partition)
                    .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)
            })());
            refresh()?;
            Ok(())
        });
        if let Err(cause) = returned {
            self.postcheck.get_or_insert(cause);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        if !matches!(self.inventory.as_ref(), Some(Ok(_))) {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl ResidentCachePinStateV1 {
    #[allow(clippy::too_many_arguments)]
    fn commit_pin_change(
        &mut self,
        session: &mut crate::cache_residency::protected_journal::RetainedCacheAuthoritySessionV1<'_, '_, '_, '_>,
        state: &mut crate::Journal,
        transaction_id: [u8; 16],
        purpose: CacheAuthorityPurposeV1,
        record_key: Vec<u8>,
        build: impl for<'session, 'authority, 'journal> FnOnce(
            &super::CacheResidencyAuthorizedControllerV1<'session, 'authority, 'journal>,
        ) -> Result<Vec<super::CacheResidencyControllerRecordV1<'session>>, CacheResidencyProtectedJournalErrorV1>,
        physical: &mut crate::cache_residency::DormantCacheOwnerV1,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let requests = [(purpose, record_key)];
        let returned = session.while_current_records_with_gate(
            &requests,
            |owner, capabilities, now, validator, refresh, gate| {
                let action = (|| {
                    let controller = super::CacheResidencyAuthorizedControllerV1 {
                        owner,
                        capabilities,
                        now,
                        transaction_kind: super::CacheResidencyTransactionKindV1::PinChange,
                    };
                    let records = build(&controller)?;
                    let mut journal = crate::cache_residency::CacheResidencyProtectedJournalV1::claim(
                        state, validator.clone(),
                    )?;
                    let successors = super::cache_controller_successors(records, &validator)?;
                    let budget = self.payload_budget.as_mut()
                        .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
                    self.prepared = Some(journal.plan_resident_with_cache_gate(
                        transaction_id,
                        super::CacheResidencyTransactionKindV1::PinChange,
                        successors,
                        gate.reborrow(),
                        budget,
                    ));
                    let Some(Ok(prepared)) = self.prepared.as_ref() else {
                        return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
                    };
                    refresh()?;

                    self.commit = Some(journal.commit_resident_prepared(prepared, gate.reborrow()));
                    let Some(Ok(CacheResidencyCommitOutcomeV1::Applied(applied))) = self.commit.as_mut() else {
                        return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
                    };
                    refresh()?;

                    self.postcommit = applied.take_postcommit();
                    let capability = self.postcommit.as_ref()
                        .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
                    let validated = match capability.validate_borrowed(&journal) {
                        Ok(validated) => validated,
                        Err(cause) => {
                            self.validation_failure = Some(cause);
                            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
                        }
                    };
                    self.settlement = Some(validated.settle_cache_owner_pin_change(physical));
                    refresh()?;
                    Ok(())
                })();
                if let Err(cause) = action {
                    self.validation_failure.get_or_insert(cause);
                    return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
                }
                Ok(())
            },
        );
        if let Err(cause) = returned {
            self.postcheck.get_or_insert(cause);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        if !matches!(self.settlement.as_ref(), Some(Ok(_))) {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }
}

/// Classifies a public acquisition without treating a no-op as a new pin event.
#[must_use = "physical owner state and protected commit outcomes require settlement"]
pub enum PublicLogicalPinAcquisitionCommitV1<R> {
    /// The sole retained pin already has this clock tick's maximum lease.
    Retained(CachePinV1),
    /// A new pin or renewal reached the protected commit path.
    Committed {
        /// Exact protected commit outcome, including ambiguous recovery custody.
        outcome: CacheResidencyCommitOutcomeV1,
        /// Current postcommit result, absent when protected authority is ambiguous.
        handoff: Option<R>,
    },
}

impl CacheResidencyProtectedOwnerV1 {
    /// Uses the same lookup and sealing policy under an already held owner cut.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn pin_existing_under_cut(
        session: &mut crate::cache_residency::protected_journal::RetainedCacheAuthoritySessionV1<'_, '_, '_, '_>,
        state: &mut crate::Journal,
        progress: &mut ResidentCachePinMutationV1,
        acquisition: &ValidatedPublicLogicalPinAcquisitionV1<'_, '_, '_, '_>,
        operation: OperationId,
        transaction_id: [u8; 16],
        source_journal: &crate::Journal,
        request: &crate::cli_model::DormantSandboxRequestKindV1,
        physical: &mut crate::cache_residency::DormantCacheOwnerV1,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        progress.capture_partition(session, state, acquisition.partition())?;
        let Some(Ok(inventory)) = progress.inventory.as_ref() else {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        };
        let (id, previous) = select_public_logical_pin_id(inventory, acquisition)?;
        let maximum_current_lease = session.current_unix_seconds()?
            .checked_add(LOGICAL_PIN_ACQUIRE_LIFETIME_SECONDS)
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if let Some(previous) = previous
            && previous.lease_valid_until >= maximum_current_lease
        {
            recheck_current_cache_consumer(source_journal, request, acquisition.consumer())?;
            let owner_id = crate::cache_residency::CacheOwnerPinIdV1::for_cache_pin(previous.partition, previous.id)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
            progress.retained = Some(previous);
            progress.presence = Some(physical.observe_pin(owner_id, acquisition.partition(), acquisition.object()));
            if !matches!(progress.presence.as_ref(), Some(Ok(crate::cache_residency::CacheOwnerPinPresenceV1::Present))) {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
            }
            session.while_current_records(&[], |_, _, _, _, refresh| { refresh()?; Ok(()) })?;
            progress.complete = true;
            return Ok(());
        }
        let budget = progress.state.payload_budget.as_mut()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let (record_key, valid_until) = session.issue_pin_acquire(
            acquisition, id, &mut progress.authority, budget,
        )?;
        let (sandbox, incarnation, assignment_epoch) = acquisition.runtime_fields();
        progress.state.commit_pin_change(
            session, state, transaction_id, CacheAuthorityPurposeV1::PinAcquire, record_key,
            |controller| {
                recheck_current_cache_consumer(source_journal, request, acquisition.consumer())?;
                let capability = controller.capability(0)
                    .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
                let pin = CachePinV1::from_verified(
                    controller.owner(), capability, id, acquisition.partition(),
                    acquisition.object().clone(), acquisition.project(), acquisition.view(),
                    acquisition.attachment(), sandbox, incarnation, CachePinKindV1::LogicalLease,
                    assignment_epoch, valid_until, controller.current_unix_seconds(),
                ).map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
                controller.seal_logical_pin_acquisition(inventory, pin, operation)
            }, physical,
        )?;
        progress.complete = true;
        Ok(())
    }

    /// Releases only the exact retained consumer pin through the same reducer.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn unpin_existing_under_cut(
        session: &mut crate::cache_residency::protected_journal::RetainedCacheAuthoritySessionV1<'_, '_, '_, '_>,
        state: &mut crate::Journal,
        progress: &mut ResidentCachePinMutationV1,
        consumer: &RecheckedCacheConsumerV1,
        pin: &CachePinV1,
        operation: OperationId,
        transaction_id: [u8; 16],
        source_journal: &crate::Journal,
        request: &crate::cli_model::DormantSandboxRequestKindV1,
        physical: &mut crate::cache_residency::DormantCacheOwnerV1,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        if consumer.acquisition_fence().is_some() || consumer.object() != &pin.object
            || consumer.project() != pin.project || consumer.view() != pin.view
            || consumer.attachment() != pin.attachment
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        progress.capture_partition(session, state, pin.partition)?;
        let Some(Ok(inventory)) = progress.inventory.as_ref() else {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        };
        let mut retained = inventory.reconstructed.iter()
            .filter(|payload| payload.plan.partition == pin.partition
                && payload.plan.descriptor == pin.object && payload.plan.project == pin.project)
            .flat_map(|payload| payload.pins.iter())
            .filter(|candidate| logical_pin_matches_consumer(
                candidate, pin.partition, &pin.object, pin.project, pin.view, pin.attachment,
            ));
        if retained.next() != Some(pin) || retained.next().is_some() {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
        }
        let budget = progress.state.payload_budget.as_mut()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        let record_key = session.issue_pin_drain(pin, &mut progress.authority, budget)?;
        progress.state.commit_pin_change(
            session, state, transaction_id, CacheAuthorityPurposeV1::PinDrain, record_key,
            |controller| {
                recheck_current_cache_consumer(source_journal, request, consumer)?;
                controller.seal_logical_pin_release(inventory, pin, operation)
            }, physical,
        )?;
        progress.complete = true;
        Ok(())
    }

    /// Commits one source-proven public logical pin acquisition or renewal.
    ///
    /// The caller must hold the authenticated View/index inputs. This method
    /// rechecks the same source journal and request inside the protected
    /// authority callback before sealing the pin. A new pin also
    /// requires physical owner admission from the postcommit callback before
    /// public completion; renewal must not acquire a second owner pin.
    ///
    /// # Errors
    ///
    /// Rejects an absent or nonresident catalog entry, incompatible renewal,
    /// exhausted pin identity, stale authority, or failed protected commit.
    pub fn commit_public_logical_pin_acquisition<R>(
        &mut self,
        transaction_id: [u8; 16],
        acquisition: &ValidatedPublicLogicalPinAcquisitionV1<'_, '_, '_, '_>,
        operation: OperationId,
        source_journal: &crate::Journal,
        request: &crate::cli_model::DormantSandboxRequestKindV1,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> Result<PublicLogicalPinAcquisitionCommitV1<R>, CacheResidencyProtectedJournalErrorV1> {
        let inventory = self.reconstructed_partition(acquisition.partition())?;
        let (id, previous) = select_public_logical_pin_id(&inventory, acquisition)?;
        let now = self.authority.current_unix_seconds()?;
        let maximum_current_lease = now
            .checked_add(LOGICAL_PIN_ACQUIRE_LIFETIME_SECONDS)
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if let Some(previous) = previous
            && previous.lease_valid_until >= maximum_current_lease
        {
            recheck_current_cache_consumer(source_journal, request, acquisition.consumer())?;
            let retained = self.retained_logical_pin(
                acquisition.partition(),
                acquisition.object(),
                acquisition.project(),
                acquisition.view(),
                acquisition.attachment(),
            )?;
            if retained.as_ref() != Some(&previous) {
                return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
            }
            return Ok(PublicLogicalPinAcquisitionCommitV1::Retained(previous));
        }
        let (record_key, valid_until) = self
            .authority
            .issue_logical_pin_acquire_record(acquisition, id)?;
        let authority_request =
            CacheResidencyAuthorityRequestV1::new(CacheAuthorityPurposeV1::PinAcquire, record_key)
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
        let (sandbox, incarnation, assignment_epoch) = acquisition.runtime_fields();

        let (outcome, handoff) = self.commit_authorized_pin_acquisition(
            transaction_id,
            vec![authority_request],
            |controller| {
                recheck_current_cache_consumer(source_journal, request, acquisition.consumer())?;
                let capability = controller
                    .capability(0)
                    .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
                let pin = CachePinV1::from_verified(
                    controller.owner(),
                    capability,
                    id,
                    acquisition.partition(),
                    acquisition.object().clone(),
                    acquisition.project(),
                    acquisition.view(),
                    acquisition.attachment(),
                    sandbox,
                    incarnation,
                    CachePinKindV1::LogicalLease,
                    assignment_epoch,
                    valid_until,
                    controller.current_unix_seconds(),
                )
                .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
                controller.seal_logical_pin_acquisition(&inventory, pin, operation)
            },
            handoff,
        )?;
        Ok(PublicLogicalPinAcquisitionCommitV1::Committed { outcome, handoff })
    }

    /// Commits one public logical-pin release under its exact protected drain record.
    ///
    /// The postcommit callback can turn a confirmed release into a physical
    /// Cache-owner admission. No public completion is implied by the journal
    /// commit alone; ambiguous outcomes retain their recovery state. The public
    /// consumer is rechecked against the same source journal while protected
    /// authority is held, including its current resource-version fence.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched consumer or pin, stale authority,
    /// invalid typed successor, or failed protected commit.
    pub fn commit_public_logical_pin_release<R>(
        &mut self,
        transaction_id: [u8; 16],
        consumer: &RecheckedCacheConsumerV1,
        pin: &CachePinV1,
        operation: OperationId,
        source_journal: &crate::Journal,
        request: &crate::cli_model::DormantSandboxRequestKindV1,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> Result<(CacheResidencyCommitOutcomeV1, Option<R>), CacheResidencyProtectedJournalErrorV1>
    {
        let authority_request = self.prepare_logical_pin_drain(consumer, pin)?;
        let inventory = self.reconstructed_partition(pin.partition)?;
        self.commit_authorized_pin_release(
            transaction_id,
            vec![authority_request],
            |controller| {
                recheck_current_cache_consumer(source_journal, request, consumer)?;
                controller.seal_logical_pin_release(&inventory, pin, operation)
            },
            handoff,
        )
    }

    /// Issues bounded drain authority for an exact retained public logical pin.
    ///
    /// The consumer was independently rechecked against desired state. The
    /// retained pin supplies the old physical partition and acquisition
    /// evidence; a changed View or attachment does not erase that obligation.
    /// This does not commit the release. The next protected transaction must
    /// select and verify the returned PinDrain record before sealing it.
    ///
    /// # Errors
    ///
    /// Returns an error unless the consumer is a release request for this
    /// exact protected pin, or when authority issuance cannot be confirmed.
    pub fn prepare_logical_pin_drain(
        &mut self,
        consumer: &RecheckedCacheConsumerV1,
        pin: &CachePinV1,
    ) -> Result<CacheResidencyAuthorityRequestV1, CacheResidencyProtectedJournalErrorV1> {
        if consumer.acquisition_fence().is_some()
            || consumer.object() != &pin.object
            || consumer.project() != pin.project
            || consumer.view() != pin.view
            || consumer.attachment() != pin.attachment
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
        }
        let retained = self.retained_logical_pin(
            pin.partition,
            consumer.object(),
            consumer.project(),
            consumer.view(),
            consumer.attachment(),
        )?;
        if retained.as_ref() != Some(pin) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
        }
        let record_key = self.authority.issue_logical_pin_drain_record(pin)?;
        CacheResidencyAuthorityRequestV1::new(CacheAuthorityPurposeV1::PinDrain, record_key)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord.into())
    }

    /// Reconstructs one exact partition beneath current protected Replay authority.
    ///
    /// This is retained state, not permission to acquire or drain a pin. A
    /// controller must still present the partition's current purpose-specific
    /// capability to the protected commit path.
    ///
    /// # Errors
    ///
    /// Returns an error when replay, currentness, or partition selection fails.
    pub fn reconstructed_partition(
        &mut self,
        partition: PhysicalPartitionId,
    ) -> Result<CacheRecoveryInventoryV1, CacheResidencyProtectedJournalErrorV1> {
        self.with_reconstructed_partitions(|inventories| {
            let inventory = inventories
                .into_iter()
                .find(|inventory| inventory.global.node_quota.partition == partition)
                .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
            Ok(inventory)
        })
    }

    /// Finds every retained partition pin for a public consumer and object.
    ///
    /// Public unpin requests carry no physical partition. This lookup scans
    /// every partition in one protected replay. A migrated consumer may have
    /// an old and a new physical obligation; unpin must drain each one rather
    /// than choosing an arbitrary partition. Historical state is not current
    /// drain or acquisition authority.
    ///
    /// # Errors
    ///
    /// Returns an error if protected replay or currentness fails, or if a
    /// partition contains more than one logical pin for this consumer/object.
    pub fn retained_consumer_logical_pins(
        &mut self,
        object: &ObjectDescriptor,
        project: ProjectId,
        view: ViewId,
        attachment: Option<AttachmentId>,
    ) -> Result<Vec<CachePinV1>, CacheResidencyProtectedJournalErrorV1> {
        self.with_reconstructed_partitions(|inventories| {
            let mut retained = Vec::new();
            for inventory in inventories {
                let mut partition_pin = None;
                for payload in inventory.reconstructed {
                    if &payload.plan.descriptor != object || payload.plan.project != project {
                        continue;
                    }
                    for pin in payload.pins {
                        if pin.partition != payload.plan.partition
                            || &pin.object != object
                            || pin.project != project
                            || pin.view != view
                            || pin.attachment != attachment
                            || pin.kind != CachePinKindV1::LogicalLease
                        {
                            continue;
                        }
                        if partition_pin.replace(pin).is_some() {
                            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
                        }
                    }
                }
                if let Some(pin) = partition_pin {
                    retained.push(pin);
                }
            }
            Ok(retained)
        })
    }

    /// Finds every retained release tombstone for a public consumer and object.
    ///
    /// A protected release removes the active logical pin before its physical
    /// owner effect necessarily settles. Public unpin recovery must inspect
    /// these tombstones across all partitions before reporting completion.
    ///
    /// # Errors
    ///
    /// Returns an error if protected replay or currentness fails, or a release
    /// tombstone escapes its reconstructed partition.
    pub fn released_consumer_logical_pins(
        &mut self,
        object: &ObjectDescriptor,
        project: ProjectId,
        view: ViewId,
        attachment: Option<AttachmentId>,
    ) -> Result<Vec<CachePinV1>, CacheResidencyProtectedJournalErrorV1> {
        self.with_reconstructed_partitions(|inventories| {
            let mut released = Vec::new();
            for inventory in inventories {
                for payload in inventory.reconstructed {
                    if &payload.plan.descriptor != object || payload.plan.project != project {
                        continue;
                    }
                    for tombstone in payload.released_pins {
                        let pin = tombstone.pin;
                        if pin.partition != payload.plan.partition {
                            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
                        }
                        if &pin.object == object
                            && pin.project == project
                            && pin.view == view
                            && pin.attachment == attachment
                            && pin.kind == CachePinKindV1::LogicalLease
                        {
                            released.push(pin);
                        }
                    }
                }
            }
            Ok(released)
        })
    }
}

pub(super) fn logical_pin_matches_consumer(
    candidate: &CachePinV1,
    partition: PhysicalPartitionId,
    object: &ObjectDescriptor,
    project: ProjectId,
    view: ViewId,
    attachment: Option<AttachmentId>,
) -> bool {
    candidate.partition == partition
        && &candidate.object == object
        && candidate.project == project
        && candidate.view == view
        && candidate.attachment == attachment
        && candidate.kind == CachePinKindV1::LogicalLease
}

// The project selector comes from the exact expected consumer, not the caller.
fn recheck_current_cache_consumer(
    source_journal: &crate::Journal,
    request: &crate::cli_model::DormantSandboxRequestKindV1,
    expected: &RecheckedCacheConsumerV1,
) -> Result<(), ProtectedDomainJournalErrorV1> {
    let current = recheck_cache_consumer_projection_v1(source_journal, expected.project(), request)
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    if current != *expected {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    Ok(())
}

fn select_public_logical_pin_id(
    inventory: &CacheRecoveryInventoryV1,
    acquisition: &ValidatedPublicLogicalPinAcquisitionV1<'_, '_, '_, '_>,
) -> Result<(CachePinId, Option<CachePinV1>), CacheResidencyProtectedJournalErrorV1> {
    if inventory.authority_poisoned
        || inventory.global.node_quota.partition != acquisition.partition()
    {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
    }
    let mut matching_catalogs = inventory.reconstructed.iter().filter(|payload| {
        payload.plan.partition == acquisition.partition()
            && payload.plan.project == acquisition.project()
            && &payload.plan.descriptor == acquisition.object()
            && payload
                .catalog
                .as_ref()
                .is_some_and(|entry| entry.presence == CatalogPresenceV1::Committed)
    });
    if matching_catalogs.next().is_none() || matching_catalogs.next().is_some() {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
    }

    let active = inventory
        .reconstructed
        .iter()
        .flat_map(|payload| payload.pins.iter().cloned());
    let released = inventory
        .reconstructed
        .iter()
        .flat_map(|payload| payload.released_pins.iter().cloned());
    let ledger = CachePinLedgerV1::replay(
        CacheRecoveryLimitsV1::default().maximum_records,
        inventory.global.pin_floor,
        active,
        released,
    )
    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
    if let Some(previous) = ledger.logical_consumer_pin(
        acquisition.partition(),
        acquisition.object(),
        acquisition.project(),
        acquisition.view(),
        acquisition.attachment(),
    ) {
        let (sandbox, incarnation, assignment_epoch) = acquisition.runtime_fields();
        if previous.sandbox != sandbox
            || previous.incarnation != incarnation
            || previous.assignment_epoch != assignment_epoch
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
        }
        return Ok((previous.id(), Some(previous.clone())));
    }
    ledger
        .next_pin_id()
        .map(|id| (id, None))
        .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord.into())
}
