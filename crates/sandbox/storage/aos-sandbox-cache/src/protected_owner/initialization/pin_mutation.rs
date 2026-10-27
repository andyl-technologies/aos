//! Owns retained native pin inventory, mutation and physical initialization.
//!
//! All effects remain under the same Cache Clock, Hold, authority and physical
//! originals. Exact C projection reads are supplied through the existing
//! finite Broker borrower at their original effect frontiers.

use super::*;

impl CacheResidentInitializationV1 {
    /// Borrows complete current partition DATA under the original clock and hold.
    ///
    /// The result grants neither pin authority nor a physical effect. Every
    /// partition, including release tombstones, remains available to selection.
    ///
    /// # Errors
    /// Retains replay failures and refuses changed or incomplete originals.
    #[cfg(target_os = "linux")]
    pub fn existing_pin_inventories(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
    ) -> Result<&[CacheRecoveryInventoryV1], CacheResidentUnavailableV1> {
        self.existing_pin_inventories_priced::<()>(owner, None, None)
    }

    /// Selects retained logical pins under this original's protected replay.
    ///
    /// The returned Native wrappers retain historical pin bindings only. Each
    /// release still requires the existing protected mutation and physical
    /// observation; this selection grants neither operation.
    ///
    /// # Errors
    /// Returns an error for unavailable original custody, duplicate partition
    /// pins, or a release tombstone outside its reconstructed partition.
    #[cfg(target_os = "linux")]
    pub fn existing_consumer_logical_pins_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        consumer: &aos_sandbox_protocol::public_api::cache_consumer::CacheConsumerDataV1,
    ) -> Result<(Vec<CachePinV1>, Vec<CachePinV1>), CacheResidencyProtectedJournalErrorV1> {
        let inventories = self.existing_pin_inventories(owner)
            .map_err(|_| CacheResidencyProtectedJournalErrorV1::StaleAuthority)?;
        let mut active = Vec::new();
        let mut released = Vec::new();
        for inventory in inventories {
            let mut partition_pin = None;
            for payload in &inventory.reconstructed {
                if &payload.plan.descriptor != consumer.object()
                    || payload.plan.project != consumer.project()
                {
                    continue;
                }
                for pin in &payload.pins {
                    if pin.partition != payload.plan.partition
                        || !pin_lookup::logical_pin_matches_consumer(
                            pin,
                            payload.plan.partition,
                            consumer.object(),
                            consumer.project(),
                            consumer.view(),
                            consumer.attachment(),
                        )
                    {
                        continue;
                    }
                    if partition_pin
                            .replace(CachePinV1::from_parsed_history_data_v1(pin.clone()))
                            .is_some()
                        {
                        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
                    }
                }
                for tombstone in &payload.released_pins {
                    if tombstone.pin.partition != payload.plan.partition {
                        return Err(CacheResidencyProtectedJournalErrorV1::NonCanonicalRecord);
                    }
                    if pin_lookup::logical_pin_matches_consumer(
                        &tombstone.pin,
                        payload.plan.partition,
                        consumer.object(),
                        consumer.project(),
                        consumer.view(),
                        consumer.attachment(),
                    ) {
                        released.push(CachePinV1::from_parsed_history_data_v1(
                            tombstone.pin.clone(),
                        ));
                    }
                }
            }
            if let Some(pin) = partition_pin {
                active.push(pin);
            }
        }
        Ok((active, released))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn existing_pin_inventories_priced<P>(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        baseline: Option<&baseline::CacheConstructionOriginalsV1>,
        receiving: Option<&baseline::CacheConstructionReceivingV1<'_, '_, '_, '_, P>>,
    ) -> Result<&[CacheRecoveryInventoryV1], CacheResidentUnavailableV1> {
        self.recheck(owner)?;
        self.complete = false;
        let clock = self.clock.as_ref().ok_or(CacheResidentUnavailableV1)?;
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };
        let hold = self.hold.as_mut().ok_or(CacheResidentUnavailableV1)?;
        let state = owner.state_journal.as_mut().ok_or(CacheResidentUnavailableV1)?;
        let returned = owner.authority.with_borrowed_mutable_authority_priced_v1(
            state, &mut hold.0, &guard,
            baseline.or_else(|| self.selected_baseline.as_ref().map(|selected| &selected.originals)),
            receiving,
            |session, state| session.while_current_records(&[], |_, _, _, validator, refresh| {
                self.pin_inventory = Some((|| {
                    let projection = CacheResidencyProtectedJournalV1::claim(state, validator.clone())?.replay()?;
                    reconstruct_cache_history(projection.records(), &validator)
                })());
                refresh()?;
                Ok(())
            }),
        );
        if let Err(cause) = returned {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Err(cause) = guard.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        drop(guard);
        if !matches!(self.pin_inventory.as_ref(), Some(Ok(_))) || self.postcheck.is_some() {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        self.recheck(owner)?;
        match self.pin_inventory.as_ref() {
            Some(Ok(inventories)) => Ok(inventories),
            _ => Err(CacheResidentUnavailableV1),
        }
    }

    /// Captures only a healthy, provisioned physical owner under these originals.
    ///
    /// All seven limits are derived from the complete protected partition set.
    /// Changed limits fence the existing owner; this route never drops or
    /// reopens it, initializes a missing manifest, or performs orphan recovery.
    ///
    /// # Errors
    /// Keeps returned fixed descriptors and the first typed capture failure.
    #[cfg(target_os = "linux")]
    pub fn prepare_existing_physical_owner(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        destination: &mut Option<crate::physical::DormantCacheOwnerV1>,
        node: aos_sandbox_model::NodeId,
        maximum_memory_bytes: u64,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.prepare_existing_physical_owner_priced::<()>(
            owner, destination, node, maximum_memory_bytes, None, None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(super) fn prepare_existing_physical_owner_priced<P>(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        destination: &mut Option<crate::physical::DormantCacheOwnerV1>,
        node: aos_sandbox_model::NodeId,
        maximum_memory_bytes: u64,
        baseline: Option<&baseline::CacheConstructionOriginalsV1>,
        receiving: Option<&baseline::CacheConstructionReceivingV1<'_, '_, '_, '_, P>>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if let Some(receiving) = receiving {
            let demand = crate::physical::ResidentCachePhysicalOpenV1::selected_preparation_demand_v1(
                maximum_memory_bytes,
            ).map_err(|cause| {
                self.first_failure.get_or_insert(InitializationCauseV1::Physical(cause));
                CacheResidentUnavailableV1
            })?;
            if let Err(cause) = receiving.require_physical_complete(demand) {
                self.first_failure.get_or_insert(cause);
                return Err(CacheResidentUnavailableV1);
            }
        }
        // Derive quotas from the complete selected inventory already retained
        // under the original clock/gate recipe, not another legacy full query.
        self.existing_pin_inventories_priced(owner, baseline, receiving)?;
        self.complete = false;
        let Some(clock) = self.clock.as_ref() else {
            self.first_failure.get_or_insert(InitializationCauseV1::Closed);
            return Err(CacheResidentUnavailableV1);
        };
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };
        let returned = (|| {
            let quotas = match self.pin_inventory.as_ref() {
                Some(Ok(inventories)) => inventories
                    .iter()
                    .map(|inventory| inventory.global.node_quota)
                    .collect::<Vec<_>>(),
                _ => return Err(InitializationCauseV1::Mutation),
            };
            if quotas.iter().any(|quota| quota.partition.node().as_bytes() != node.as_bytes()) {
                return Err(InitializationCauseV1::Physical(super::super::CacheOwnerErrorV1::InvalidLimits));
            }
            let limits = CacheOwnerLimitsV1::from_node_quotas(maximum_memory_bytes, quotas)?;
            if let Some(physical) = destination.as_ref() {
                if self.physical_limits != Some(limits) || physical.limits() != limits {
                    return Err(InitializationCauseV1::Physical(super::super::CacheOwnerErrorV1::InvalidLimits));
                }
                physical.held_snapshot()?;
                return Ok(());
            }
            if self.physical_limits.is_some() {
                return Err(InitializationCauseV1::Closed);
            }
            self.physical_limits = Some(limits);
            let opened = if let Some(receiving) = receiving {
                self.physical_open.open_selected_once(destination, limits, receiving)
            } else if self.selected_baseline.is_some() {
                return Err(InitializationCauseV1::Baseline);
            } else {
                self.physical_open.open_once(destination, limits)
            };
            if opened.is_err() {
                return Err(InitializationCauseV1::PhysicalOpen);
            }
            Ok(())
        })();
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }
        if let Err(cause) = guard.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        drop(guard);
        if self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        self.recheck(owner)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn with_pin_mutation(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut crate::physical::DormantCacheOwnerV1,
        operation: OperationId,
        action: impl for<'session, 'claim, 'journal, 'gate, 'clock> FnOnce(
            &mut crate::protected_journal::RetainedCacheAuthoritySessionV1<'claim, 'journal, 'gate, 'clock>,
            &mut Journal,
            &mut ResidentCachePinMutationV1,
            &mut crate::physical::DormantCacheOwnerV1,
        ) -> Result<(), CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.recheck(owner)?;
        if self.original_coverage.is_some_and(|observed| observed.is_some()) {
            // The first profile requires empty-owner audit before fencing;
            // this readback alone does not establish it. No pin action creates a new
            // protected or physical step after a read-only bookend succeeds.
            self.complete = false;
            self.first_failure.get_or_insert(InitializationCauseV1::UnsupportedTransition);
            return Err(CacheResidentUnavailableV1);
        }
        if self.mutations.iter().any(|progress| progress.operation != Some(operation) || !progress.complete) {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            self.complete = false;
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = false;
        let maximum = owner.state_journal.as_ref()
            .ok_or(CacheResidentUnavailableV1)?.limits().maximum_materialized_bytes;
        let retained = self.mutations.iter().try_fold(0_usize, |bytes, progress| {
            bytes.checked_add(progress.retained_payload_bytes())
        });
        let Some(headroom) = retained.and_then(|bytes| maximum.checked_sub(bytes)) else {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        };
        for progress in &mut self.mutations {
            progress.release_completed_inventory();
        }
        self.mutations.push(ResidentCachePinMutationV1::for_operation(operation));
        let progress = self.mutations.last_mut().ok_or(CacheResidentUnavailableV1)?;
        progress.set_payload_headroom(headroom);
        let clock = self.clock.as_ref().ok_or(CacheResidentUnavailableV1)?;
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };
        let returned = (|| {
            if owner.clock.as_ref().is_none_or(|current| !Arc::ptr_eq(clock, current)) {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
            }
            let hold = self.hold.as_mut().ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let state = owner.state_journal.as_mut().ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            owner.authority.with_borrowed_mutable_authority_v1(
                state, &mut hold.0, &guard,
                |session, state| {
                    let result = action(session, state, progress, physical);
                    if let Err(cause) = result {
                        progress.first_failure.get_or_insert(cause);
                        return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
                    }
                    Ok(())
                },
            )
        })();
        if let Err(cause) = returned {
            progress.postcheck.get_or_insert(cause);
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
        }
        if let Err(cause) = guard.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Err(cause) = physical.held_snapshot() {
            self.postcheck.get_or_insert(cause.into());
        }
        drop(guard);
        if self.first_failure.is_some() || self.postcheck.is_some() || !progress.complete {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        self.recheck(owner)?;
        if let Err(cause) = physical.finish_resident_pin_step() {
            self.complete = false;
            self.postcheck.get_or_insert(cause.into());
            return Err(CacheResidentUnavailableV1);
        }
        self.recheck(owner)
    }

    /// Releases completed operation DATA only after the same owners recheck.
    ///
    /// # Errors
    /// Refuses another operation, any unresolved leg or any changed original.
    #[cfg(target_os = "linux")]
    pub fn finish_existing_pin_operation(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut crate::physical::DormantCacheOwnerV1,
        operation: OperationId,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.recheck(owner)?;
        if self.mutations.iter().any(|progress| progress.operation != Some(operation) || !progress.complete) {
            return Err(CacheResidentUnavailableV1);
        }
        if let Err(cause) = physical.finish_resident_pin_operation() {
            self.postcheck.get_or_insert(cause.into());
            self.complete = false;
            return Err(CacheResidentUnavailableV1);
        }
        self.recheck(owner)?;

        // Both archives survive every fallible bookend. Only completed DATA
        // is released here; the original writers, clock and physical owner stay.
        physical.release_completed_resident_pin_data();
        self.mutations.clear();
        Ok(())
    }
}


impl CacheResidentInitializationV1 {
    /// Reconciles the original acquisition without selecting another partition.
    ///
    /// Returns `false` only for canonical state-only history; `true` requires
    /// actual protected-event and physical-manifest agreement.
    ///
    /// # Errors
    /// Retains the complete cold and physical results on ambiguity or failure.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_existing_public_pin(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut crate::DormantCacheOwnerV1,
        consumer: &aos_sandbox_protocol::public_api::cache_consumer::CacheConsumerDataV1,
        operation: OperationId,
        transaction_id: [u8; 16],
        consumer_reader: Option<&aos_sandbox_broker::controller_receiving::bank_launch::ControllerCacheConsumerReadBorrowV1<'_, impl Sized>>,
        request: &aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1,
    ) -> Result<bool, CacheResidentUnavailableV1> {
        if consumer.acquisition_fence().is_none() {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        }
        self.with_pin_mutation(owner, physical, operation, |session, state, progress, physical| {
            progress.reconcile(
                session, state, transaction_id, consumer, operation, None,
                consumer_reader, request, physical,
            )
        })?;
        Ok(self.mutations.last().is_some_and(|progress| !progress.cold_state_only()))
    }

    /// Reconciles one exact retained release tombstone under the same cut.
    ///
    /// # Errors
    /// Refuses foreign consumers, absent tombstones, state-only history or an
    /// unresolved physical release. Other partitions remain independent debt.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_existing_public_unpin(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut crate::DormantCacheOwnerV1,
        consumer: &aos_sandbox_protocol::public_api::cache_consumer::CacheConsumerDataV1,
        pin: &crate::CachePinV1,
        operation: OperationId,
        transaction_id: [u8; 16],
        consumer_reader: Option<&aos_sandbox_broker::controller_receiving::bank_launch::ControllerCacheConsumerReadBorrowV1<'_, impl Sized>>,
        request: &aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        let inventories = self.existing_pin_inventories(owner)?;
        let retained = inventories.iter().flat_map(|inventory| &inventory.reconstructed)
            .flat_map(|payload| &payload.released_pins)
            .any(|tombstone| &tombstone.pin == pin.historical_data_v1());
        if consumer.acquisition_fence().is_some() || !retained
            || !pin_lookup::logical_pin_matches_consumer(pin, pin.partition, consumer.object(), consumer.project(), consumer.view(), consumer.attachment())
        {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        }
        self.with_pin_mutation(owner, physical, operation, |session, state, progress, physical| {
            progress.reconcile(
                session, state, transaction_id, consumer, operation, Some(pin),
                consumer_reader, request, physical,
            )
        })?;
        if self.mutations.last().is_none_or(ResidentCachePinMutationV1::cold_state_only) {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            self.complete = false;
            return Err(CacheResidentUnavailableV1);
        }
        Ok(())
    }

    /// Pins one genuinely validated logical consumer without reopening writers.
    ///
    /// The actual acquisition proof, signed-source compiler inputs and current
    /// Controller request remain borrowed from the installed caller. Complete
    /// protected and physical results stay resident through final bookends.
    ///
    /// # Errors
    /// Permanently refuses changed originals, failed issuance, ambiguous
    /// protected append or incomplete physical settlement; no error is Drain.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn pin_existing_logical_consumer(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut crate::DormantCacheOwnerV1,
        acquisition: &crate::ValidatedPublicLogicalPinAcquisitionV1<'_, '_, '_, '_>,
        operation: OperationId,
        transaction_id: [u8; 16],
        consumer_reader: Option<&aos_sandbox_broker::controller_receiving::bank_launch::ControllerCacheConsumerReadBorrowV1<'_, impl Sized>>,
        request: &aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.with_pin_mutation(owner, physical, operation, |session, state, progress, physical| {
            CacheResidencyProtectedOwnerV1::pin_existing_under_cut(
                session, state, progress, acquisition, operation, transaction_id,
                consumer_reader, request, physical,
            )
        })
    }

    /// Releases one exact retained pin; the caller must select every partition.
    ///
    /// # Errors
    /// Keeps unresolved protected and physical results instead of permission to
    /// retry, release other pins or report consumer-wide completion.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn unpin_existing_logical_consumer(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut crate::DormantCacheOwnerV1,
        consumer: &aos_sandbox_protocol::public_api::cache_consumer::CacheConsumerDataV1,
        pin: &crate::CachePinV1,
        operation: OperationId,
        transaction_id: [u8; 16],
        consumer_reader: Option<&aos_sandbox_broker::controller_receiving::bank_launch::ControllerCacheConsumerReadBorrowV1<'_, impl Sized>>,
        request: &aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.with_pin_mutation(owner, physical, operation, |session, state, progress, physical| {
            CacheResidencyProtectedOwnerV1::unpin_existing_under_cut(
                session, state, progress, consumer, pin, operation, transaction_id,
                consumer_reader, request, physical,
            )
        })
    }
}
