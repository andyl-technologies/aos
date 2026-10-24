//! Conjoins current owning storage with independently named future phases.
//!
//! Current backing is observed from actual retained owners. Prospective rows
//! remain separate commitments and never substitute for a current allocation.
//! Both admissions use the same original installed memory/descriptor policy.

use super::*;

pub(super) fn observe(
    scope: &OriginalRestorationConstructionScope<'_>,
    policy: OriginalRestorationConstructionPolicy,
    storage: OriginalRestorationConstructionStorage,
) -> Result<usize, RuntimeError> {
    let mut requested = observed_current(scope, policy, storage)?;
    let final_construction = if let Some(window) = scope.window {
        window.final_construction
    } else {
        super::scope_storage::OriginalRestorationFinalConstructionData::quote(
            scope.inputs.archive,
            scope.inputs.activation,
            policy.maximum_requested_bytes,
        )?
    };
    requested = checked_sum(
        &[requested, final_construction.requested_bytes_data()?],
        policy.maximum_requested_bytes,
    )?;
    match scope.phase {
        OriginalRestorationConstructionPhase::ColdOwners => {
            for ticket in scope.inputs.tickets {
                requested = checked_sum(
                    &[
                        requested,
                        ticket
                            .native_restoration_construction_data()?
                            .source_cold_construction_requested_bytes_data(),
                    ],
                    policy.maximum_requested_bytes,
                )?;
            }
        }
        OriginalRestorationConstructionPhase::Transaction
        | OriginalRestorationConstructionPhase::Installed => {
            let window = scope.window.ok_or(RuntimeError::OwnerUnavailable)?;
            let coordinator = window
                .coordinator_construction
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            requested = checked_sum(
                &[requested, coordinator.requested_bytes_data()?],
                policy.maximum_requested_bytes,
            )?;
            if let Some(row) = window.coordinator17_construction.get() {
                requested = checked_sum(
                    &[requested, row.requested_bytes_data()?],
                    policy.maximum_requested_bytes,
                )?;
            }
            let common = window
                .common_construction
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            requested = checked_sum(
                &[
                    requested,
                    common.requested_bytes_data(),
                    common.counter_scratch_bytes_data(),
                ],
                policy.maximum_requested_bytes,
            )?;
            if let Some(candidate) = window.producer_publication.get() {
                requested = checked_sum(
                    &[requested, candidate.row.requested_bytes_data()],
                    policy.maximum_requested_bytes,
                )?;
            }
            {
                let capture = window
                    .restored_captures
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?;
                requested = checked_sum(
                    &[
                        requested,
                        capture.future_requested_bytes_data(policy.maximum_requested_bytes)?,
                    ],
                    policy.maximum_requested_bytes,
                )?;
            }
            for work in &window.producer_grant_work {
                if let Some((retained, transient, scratch)) = work.get() {
                    requested = checked_sum(
                        &[requested, retained, transient, scratch],
                        policy.maximum_requested_bytes,
                    )?;
                }
            }
            for ledger in &window.producer_executions {
                let ledger = ledger.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
                requested = checked_sum(
                    &[requested, ledger.future_requested_bytes_data()?],
                    policy.maximum_requested_bytes,
                )?;
            }
            for work in &window.initial_scheduling_work {
                if let Some((retained, transient, scratch)) = work.get() {
                    requested = checked_sum(
                        &[requested, retained, transient, scratch],
                        policy.maximum_requested_bytes,
                    )?;
                }
            }
            for ledger in &window.current_observations {
                let ledger = ledger.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
                requested = checked_sum(
                    &[requested, ledger.future_requested_bytes_data()?],
                    policy.maximum_requested_bytes,
                )?;
            }
            let rows = window
                .node_rows
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            for (index, row) in rows.iter().enumerate() {
                let validation = scope.inputs.tickets[index]
                    .native_restoration_construction_data()?
                    .original_archived_validation_construction_data()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                requested = checked_sum(
                    &[
                        requested,
                        validation.requested_bytes_data(),
                        validation.fixed_counter_scratch_bytes_data(),
                    ],
                    policy.maximum_requested_bytes,
                )?;
                if let Some(observation) = &row.source_observation {
                    // Every later reauthentication remains independently funded;
                    // completed World or Observe does not refund the old rows.
                    requested = checked_sum(
                        &[
                            requested,
                            observation.requested_peak_bytes_data(),
                            observation.counter_scratch_bytes_data(),
                        ],
                        policy.maximum_requested_bytes,
                    )?;
                }
                if let Some(suffix) = &row.restored_suffix {
                    // A separate full validation extent survives every phase;
                    // first-Observe credit is never reused for suffix inspection.
                    requested = checked_sum(
                        &[requested, suffix.requested_bytes_data()],
                        policy.maximum_requested_bytes,
                    )?;
                }
                let signer = row.signer.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
                let custody = row
                    .installed_custody
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                let activation = row
                    .source_activation
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                requested = checked_sum(
                    &[
                        requested,
                        signer.requested_peak_bytes_data(),
                        custody.requested_bytes_data(),
                        custody.counter_scratch_bytes_data(),
                        activation.requested_peak_bytes_data(),
                        activation.counter_scratch_bytes_data(),
                        signer.counter_scratch_bytes_data(),
                        // The target retains a distinct actual Value/canonical bank;
                        // Source's independent normalization has its own row above.
                        signer.mapping_normalization_requested_bytes_data(),
                        row.upload.retained_growth_bytes(),
                        row.upload.maximum_simultaneous_transient_bytes(),
                        row.upload.declared_counter_scratch_bytes(),
                        row.prepare_binding.retained_growth_bytes(),
                        row.prepare_binding.maximum_simultaneous_transient_bytes(),
                        row.prepare_binding.declared_counter_scratch_bytes(),
                        row.native_inputs.requested_input_suffix_bytes(),
                        row.native_commit.requested_bytes(),
                        row.host_currentness_bytes,
                        row.mapping_construction_bytes,
                    ],
                    policy.maximum_requested_bytes,
                )?;
            }
        }
    }
    Ok(requested)
}

pub(super) fn observed_current(
    scope: &OriginalRestorationConstructionScope<'_>,
    policy: OriginalRestorationConstructionPolicy,
    storage: OriginalRestorationConstructionStorage,
) -> Result<usize, RuntimeError> {
    let maximum = policy.maximum_requested_bytes;
    let installed = scope.phase == OriginalRestorationConstructionPhase::Installed;
    let runtime_bytes = if installed {
        scope
            .inputs
            .runtime
            .original_installed_restoration_retained_storage_precredit_data(
                scope.window.ok_or(RuntimeError::OwnerUnavailable)?,
                scope.inputs.archive,
                scope.plan,
                scope.inputs.activation,
                maximum,
            )?
    } else {
        scope
            .inputs
            .runtime
            .original_restoration_retained_storage_precredit_data(
                scope.inputs.archive,
                scope.plan,
                scope.inputs.activation,
                maximum,
            )?
    };
    let runtime_descriptors = if installed {
        scope
            .inputs
            .runtime
            .original_installed_restoration_descriptor_views_precredit_data(
                scope.window.ok_or(RuntimeError::OwnerUnavailable)?,
                scope.inputs.archive,
                scope.plan,
                scope.inputs.activation,
            )?
    } else {
        scope
            .inputs
            .runtime
            .original_restoration_descriptor_views_precredit_data(
                scope.inputs.archive,
                scope.plan,
                scope.inputs.activation,
            )?
    };
    let mut requested = checked_sum(
        &[
            policy.declared_observer_scratch_bytes,
            storage.retained_holder_bytes,
            crate::node_adapters::cnp::OriginalInitialLifecycleDiagnostics::requested_bytes(),
            storage.maximum_simultaneous_transient_bytes,
            runtime_bytes,
            scope.inputs.archive.inner.capture_owned_storage()?,
            NodeRuntime::capture_shared_allocation_storage::<CompleteOriginalRestorationWindow>(),
            NodeRuntime::capture_shared_allocation_storage::<
                super::transaction_group::OriginalRestorationTransactionGroup,
            >(),
        ],
        maximum,
    )?;
    let mut descriptors = checked_sum(
        &[
            storage.retained_descriptors,
            storage.maximum_simultaneous_transient_descriptors,
            runtime_descriptors,
            scope
                .inputs
                .archive
                .retained_descriptor_views_precredit_data()?,
            CnpSemanticLaunchGuard::original_initial_lifecycle_transient_descriptor_data(),
        ],
        policy.maximum_owned_descriptors,
    )?;
    for (index, source) in scope.inputs.sources.iter().enumerate() {
        requested = checked_sum(
            &[
                requested,
                source.original_initial_lifecycle_source_storage_data(maximum)?,
                scope.inputs.sdks[index].original_completed_initial_commitments_storage_data(
                    source,
                    &scope.inputs.launches[index],
                    scope.plan,
                )?,
            ],
            maximum,
        )?;
        descriptors = checked_sum(
            &[
                descriptors,
                source.original_initial_lifecycle_descriptor_views_precredit_data()?,
            ],
            policy.maximum_owned_descriptors,
        )?;
    }
    if let Some(window) = scope.window {
        if let Some(candidate) = window.producer_publication.get() {
            descriptors = checked_sum(
                &[
                    descriptors,
                    candidate
                        .row
                        .maximum_simultaneous_transient_descriptors_data(),
                ],
                policy.maximum_owned_descriptors,
            )?;
        }
        {
            let capture = window
                .restored_captures
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            requested = checked_sum(
                &[requested, capture.retained_requested_bytes_data(maximum)?],
                maximum,
            )?;
        }
        for ledger in &window.producer_executions {
            let ledger = ledger.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            requested = checked_sum(
                &[
                    requested,
                    ledger.charge_original_storage_data(scope.inputs.runtime, maximum)?,
                ],
                maximum,
            )?;
        }
        if let Some(target) = window.coordinator_target.get() {
            use crate::node_contract::runtime_owned_counter::OwnedStorage;
            requested = checked_sum(&[requested, target.owned_storage()?], maximum)?;
        }
        for slot in &window.observation_request_ids {
            if let Some(id) = slot.get() {
                requested = checked_sum(&[requested, id.allocated_capacity()], maximum)?;
            }
        }
        if let Some(ids) = window.activation_request_ids.get() {
            for id in ids {
                requested = checked_sum(&[requested, id.allocated_capacity()], maximum)?;
            }
        }
        let group = window
            .group_partial
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if let Some(group) = group.as_ref() {
            requested = checked_sum(&[requested, group.retained_storage_data(maximum)?], maximum)?;
        }
        if let Some(group) = window.group.get() {
            requested = checked_sum(&[requested, group.retained_storage_data(maximum)?], maximum)?;
        }
        drop(group);
        for (partial, complete) in window.targets_partial.iter().zip(&window.targets) {
            let target = partial.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
            if let Some(target) = target.as_ref() {
                requested = checked_sum(
                    &[
                        requested,
                        target.retained_requested_storage_precredit_data(maximum)?,
                    ],
                    maximum,
                )?;
            }
            if let Some(target) = complete.get() {
                requested = checked_sum(
                    &[
                        requested,
                        target.retained_requested_storage_precredit_data(maximum)?,
                    ],
                    maximum,
                )?;
            }
        }
        let partial = window
            .cold_partial
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if let Some(partial) = partial.as_ref() {
            requested = checked_sum(
                &[requested, partial.retained_storage_data(maximum)?],
                maximum,
            )?;
        }
        if let Some(cold) = window.cold.get() {
            requested = checked_sum(&[requested, cold.retained_storage_data(maximum)?], maximum)?;
        }
        let scope_owner = window
            .scope_partial
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if let Some(owner) = scope_owner.as_ref() {
            requested = checked_sum(&[requested, owner.retained_storage_data(maximum)?], maximum)?;
        }
        if let Some(owner) = window.complete_scope.get() {
            requested = checked_sum(&[requested, owner.retained_storage_data(maximum)?], maximum)?;
        }
        drop(scope_owner);
        let paused = window
            .paused_scheduler
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if let Some(scheduler) = paused.as_ref() {
            requested = checked_sum(
                &[
                    requested,
                    scheduler.original_retained_requested_storage_precredit_data(maximum)?,
                ],
                maximum,
            )?;
        }
        drop(paused);
        let coordinator = window
            .coordinator_owner
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        requested = checked_sum(
            &[requested, coordinator.retained_storage_data(maximum)?],
            maximum,
        )?;
        drop(coordinator);
        if let Some(activation) = window.activation_world.get() {
            let facts = activation.retained_requested_storage_data(maximum)?;
            requested = checked_sum(&[requested, facts.independent_bytes()], maximum)?;
            for root in facts.shared_allocations() {
                requested = checked_sum(&[requested, root.requested_bytes()], maximum)?;
            }
        }
        let partial_rows = window
            .node_rows_partial
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        for row in partial_rows
            .iter()
            .flatten()
            .chain(window.node_rows.get().into_iter().flatten())
        {
            requested = checked_sum(
                &[requested, row.retained_association_storage_data(maximum)?],
                maximum,
            )?;
        }
    }
    // Descriptor authority is independent; checked_sum above refuses excess.
    let _ = descriptors;
    Ok(requested)
}

pub(super) fn checked_sum(terms: &[usize], maximum: usize) -> Result<usize, RuntimeError> {
    terms.iter().try_fold(0usize, |sum, term| {
        sum.checked_add(*term)
            .filter(|sum| *sum <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    })
}
