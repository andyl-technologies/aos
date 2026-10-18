//! Counts the actual retained no-input Producer grant before action construction.
//!
//! The grant remains an original scheduler owner through every failed quote or
//! callback. These observations lend no mutable Runtime and authorize no effect.

use super::*;
use crate::node_scheduling::{ExactPermission, ExecutionAdmission};
use std::mem::size_of;

impl NodeRuntime {
    pub(crate) fn original_restored_producer_operation_limit_data(&self) -> usize {
        self.limits.maximum_operations
    }

    /// Prices ordinary scheduler/grant/Runtime owners before their constructors.
    ///
    /// The current installed scheduler must already exist. This observation
    /// creates no scheduler, owner clone, grant, request or execution authority.
    pub(crate) fn original_restored_producer_dispatch_construction_data(
        &self,
        world: &WorldActivation,
        node: &Id,
        operation: &Id,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        self.validate_activation(world)?;
        let snapshot = self.snapshots.get(node).ok_or(RuntimeError::UnknownNode)?;
        let route = &snapshot.route;
        let scheduler = self.scheduling_origin()?.retained()?;
        let (scheduler_retained, scheduler_transient) = scheduler
            .original_restored_producer_grant_construction_data(node, operation, maximum)?;
        let activation = world.retained_requested_storage_data(maximum)?;
        let mut activation_bytes = activation.independent_bytes();
        for allocation in activation.shared_allocations() {
            activation_bytes = activation_bytes
                .checked_add(allocation.requested_bytes())
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        let operation_copies = route
            .owners
            .len()
            .checked_add(11)
            .ok_or(RuntimeError::ResourceLimit)?;
        let operation_bytes = operation
            .allocated_capacity()
            .checked_mul(operation_copies)
            .ok_or(RuntimeError::ResourceLimit)?;
        let count = self
            .operations
            .len()
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        let nodes = Self::capture_protocol_tree_storage(
            1,
            count,
            size_of::<(Id, RetainedOperation)>(),
            std::mem::align_of::<(Id, RetainedOperation)>(),
            maximum,
        )?;
        let (failure_retained, failure_transient, failure_scratch) =
            self.current_observation_runtime_work_data(world, route, maximum)?;
        // World owners: ExactGrant; Begin local/Runtime/Node/Source admissions;
        // Poll local admission; receipt -> returned commit; retained commit;
        // final validated checkpoint. The actual shared roots are conservatively
        // repeated per view, without assuming identity permits a credit refund.
        // Route owners: returned token and the five admission copies above.
        // Operation strings: Begin argument/token/local+Runtime admissions/map
        // key, Node/Source/Poll admissions, receipt, commit local key and retained
        // commit, plus actual owner reservations. Reclaimed locals stay funded.
        let route_bytes = route
            .owned_storage()?
            .checked_mul(6)
            .ok_or(RuntimeError::ResourceLimit)?;
        let retained = activation_bytes
            .checked_mul(9)
            .and_then(|bytes| bytes.checked_add(route_bytes))
            .and_then(|bytes| bytes.checked_add(operation_bytes))
            .and_then(|bytes| bytes.checked_add(node.allocated_capacity().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(scheduler_retained))
            .and_then(|bytes| {
                bytes.checked_add(Self::capture_shared_allocation_storage::<
                    crate::node_admission::CompleteOriginalRestorationWindow,
                >())
            })
            .and_then(|bytes| bytes.checked_add(nodes))
            .and_then(|bytes| bytes.checked_add(failure_retained))
            .and_then(|bytes| {
                bytes.checked_add(
                    super::super::OriginalRuntimeOperationDispatch::SUFFIX_ACTION_ROW_REFUSAL.len(),
                )
            })
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        let transient = scheduler_transient
            .checked_add(failure_transient)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        let scratch = failure_scratch
            .checked_add(Self::original_restored_producer_grant_counter_scratch_data())
            .ok_or(RuntimeError::ResourceLimit)?;
        retained
            .checked_add(transient)
            .and_then(|bytes| bytes.checked_add(scratch))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok((retained, transient, scratch))
    }

    /// Checks the same real exact grant without cloning its request or owners.
    pub(crate) fn authenticate_restored_producer_grant_data(
        &self,
        grant: &ExecutionAdmission,
    ) -> Result<(), RuntimeError> {
        let ExecutionAdmission::Exact(exact) = grant else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        if exact.input_batch.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let (start, limit) = match &exact.permission {
            ExactPermission::Run {
                start,
                limit,
                boundary_policy: super::super::ExactBoundaryPolicy::HorizonPark,
            } => (*start, *limit),
            ExactPermission::Settlement { start, limit } if start.time_ps == limit.time_ps => {
                (*start, *limit)
            }
            _ => return Err(RuntimeError::UnsupportedFacet),
        };
        if start > limit {
            return Err(RuntimeError::InvalidReceipt);
        }
        self.validate_activation(&exact.activation)?;
        let snapshot = self
            .snapshots
            .get(&exact.node)
            .ok_or(RuntimeError::UnknownNode)?;
        let handle = self
            .nodes
            .get(&exact.node)
            .ok_or(RuntimeError::UnknownNode)?;
        snapshot.validate_current(handle.as_ref())?;
        self.validate_owners_available(&snapshot.route)?;
        if self.operations.contains_key(&exact.operation)
            || self.input_batches.contains_key(&exact.operation)
            || self.administrative_operation_used(&exact.operation)
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        if self.input_batches.values().any(|input| {
            input.committed
                && input.failure.is_none()
                && input.batch.node() == &exact.node
                && !input.batch.deliveries().is_empty()
                && !self.input_fully_consumed(&input.batch)
        }) {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    /// Observes the original exact grant's capacities and actual shared roots.
    ///
    /// Its inline slot is excluded, because the Window owns that slot. Shared
    /// activation allocations are conservatively charged per retained grant;
    /// equal records never justify discounting independent clone capacities.
    pub(crate) fn original_restored_producer_grant_requested_storage_data(
        &self,
        grant: &ExecutionAdmission,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let ExecutionAdmission::Exact(exact) = grant else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        if exact.input_batch.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        if !matches!(
            &exact.permission,
            ExactPermission::Run {
                boundary_policy: super::super::ExactBoundaryPolicy::HorizonPark,
                ..
            } | ExactPermission::Settlement { .. }
        ) {
            // Other variants can own additional heap, and are outside this
            // no-input construction row even after a failed selected attempt.
            return Err(RuntimeError::UnsupportedFacet);
        }
        // Raw ownership remains observable after dispatch, failure or revocation.
        // Live route/owner availability is checked only by the action issuer.
        let activation = exact.activation.retained_requested_storage_data(maximum)?;
        let mut requested = exact
            .node
            .allocated_capacity()
            .checked_add(exact.operation.allocated_capacity())
            .and_then(|bytes| bytes.checked_add(activation.independent_bytes()))
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        for allocation in activation.shared_allocations() {
            requested = requested
                .checked_add(allocation.requested_bytes())
                .filter(|bytes| *bytes <= maximum)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(requested)
    }

    pub(crate) fn original_restored_producer_grant_counter_scratch_data() -> usize {
        opaque_owner_counter_scratch_data()
            + crate::node_scheduling::CausalScheduler::original_restored_producer_grant_construction_counter_scratch_data()
            + size_of::<(usize, usize, usize)>()
            + size_of::<Result<(usize, usize, usize), RuntimeError>>()
            + size_of::<std::cell::Ref<'static, crate::node_scheduling::CausalScheduler>>()
            + size_of::<Result<std::cell::Ref<'static, crate::node_scheduling::CausalScheduler>, RuntimeError>>()
            + size_of::<&ExecutionAdmission>()
            + size_of::<&crate::node_scheduling::ExactGrant>()
            + size_of::<&ExactPermission>()
            + size_of::<(&crucible_node_contract::Position, &crucible_node_contract::Position)>()
            + size_of::<(crucible_node_contract::Position, crucible_node_contract::Position)>()
            + size_of::<Result<RetainedCoreOwnerStorage<'static>, RuntimeError>>()
            + size_of::<&RetainedCoreSharedAllocation>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Option<usize>>()
            + size_of::<Option<&NodeSnapshot>>()
            + size_of::<Result<&NodeSnapshot, RuntimeError>>()
            + size_of::<Option<&Box<dyn SimulationNode>>>()
            + size_of::<Result<&Box<dyn SimulationNode>, RuntimeError>>()
            + size_of::<&NodeRoute>()
    }
}

impl NodeRuntime {
    pub(crate) fn quote_original_restored_producer_execution_data(
        &self,
        grant: &ExecutionAdmission,
        launch: &crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        maximum: usize,
    ) -> Result<
        crate::node_admission::OriginalRestoredProducerExecutionConstructionData,
        RuntimeError,
    > {
        self.authenticate_restored_producer_grant_data(grant)?;
        let snapshot = self
            .snapshots
            .get(grant.node())
            .ok_or(RuntimeError::UnknownNode)?;
        let handle = self
            .nodes
            .get(grant.node())
            .ok_or(RuntimeError::UnknownNode)?;
        snapshot.validate_current(handle.as_ref())?;
        let row = handle.quote_original_restored_producer_execution(
            grant,
            launch,
            canonical_launch5,
            maximum,
        )?;
        snapshot.validate_current(handle.as_ref())?;
        self.validate_activation(grant.activation())?;
        Ok(row)
    }

    pub(crate) fn begin_original_restored_producer_admitted(
        &mut self,
        claim: &crate::node_admission::OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Result<BeginResult, RuntimeError> {
        claim.with_original_grant_data(|grant| {
            self.authenticate_restored_producer_grant_data(grant)?;
            let result = self.begin_with_inputs_and_producer_claim(
                grant.activation(),
                grant.node(),
                grant.operation().clone(),
                grant.request(),
                None,
                Some(claim),
            );
            if matches!(result, Err(_) | Ok(BeginResult::Refused(_)))
                && let Some(state) = &self.scheduler
                && let Some(mut scheduler) = state.borrow_if_initialized()?
            {
                scheduler
                    .reconcile_no_effect(grant)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
            }
            result
        })
    }
}

impl NodeRuntime {
    pub(crate) fn original_restored_producer_collect_storage_data<T>(
        entries: usize,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        construction_storage::collect_buffer_storage::<T>(entries, maximum)
    }
}

impl NodeRuntime {
    pub(crate) fn authenticate_original_restored_producer_phase_result_data(
        &self,
        token: &OperationToken,
        claim: &crate::node_admission::OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Result<(), RuntimeError> {
        use crate::node_admission::ProducerExecutionPhase;
        self.validate_token(token)?;
        let entry = self
            .operations
            .get(token.operation())
            .ok_or(RuntimeError::ForeignAuthority)?;
        claim.authenticate_runtime_data(self, &entry.admission, token.route())?;
        let result = match claim.phase_data() {
            ProducerExecutionPhase::Begin => matches!(entry.result, RetainedResult::Pending),
            ProducerExecutionPhase::Poll => matches!(entry.result, RetainedResult::Complete(_)),
            ProducerExecutionPhase::Publication => {
                matches!(entry.result, RetainedResult::Complete(_))
                    && entry.scheduling_commit.as_ref().is_some_and(|commit| {
                        commit.operation() == token.operation()
                            && commit.node() == &token.route.node
                            && commit.activation().same_authority(claim.world_data())
                    })
            }
            ProducerExecutionPhase::Retirement | ProducerExecutionPhase::Observation => {
                matches!(entry.result, RetainedResult::Acknowledged(_))
            }
        };
        if !result {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

impl NodeRuntime {
    pub(crate) fn original_restored_producer_scheduling_construction_data(
        &self,
        node: &Id,
        port: &Id,
        lane: &Id,
        maximum_newborn: usize,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        self.scheduling_origin()?
            .retained()?
            .original_restored_producer_publication_construction_data(
                node,
                port,
                lane,
                maximum_newborn,
                maximum,
            )
    }
}

impl NodeRuntime {
    pub(super) fn original_restored_producer_claim_required_data(
        &self,
        token: &OperationToken,
    ) -> bool {
        self.nodes
            .get(&token.route.node)
            .is_some_and(|node| node.requires_original_restored_producer_claim_data(token))
    }
}

impl NodeRuntime {
    /// Keeps generic completion APIs from spending a selected action's scopes.
    pub(super) fn authenticate_original_restored_producer_runtime_callback_data(
        &self,
        token: &OperationToken,
        claim: Option<&crate::node_admission::OriginalRestoredProducerExecutionClaim<'_>>,
        phase: crate::node_admission::ProducerExecutionPhase,
    ) -> Result<(), RuntimeError> {
        let selected = self.original_restored_producer_claim_required_data(token);
        match (selected, claim) {
            (false, None) => Ok(()),
            (true, Some(claim)) if claim.phase_data() == phase => {
                let original = self
                    .operations
                    .get(token.operation())
                    .ok_or(RuntimeError::ForeignAuthority)?;
                claim.authenticate_runtime_data(self, &original.admission, token.route())
            }
            _ => Err(RuntimeError::ForeignAuthority),
        }
    }
}

impl NodeRuntime {
    /// Applies the post-Retire proof before opening another scheduler grant.
    pub(crate) fn accept_original_restored_producer_checkpoint_data(
        &mut self,
        token: &OperationToken,
        claim: &crate::node_admission::OriginalRestoredProducerExecutionClaim<'_>,
    ) -> Result<(), RuntimePollFailure> {
        self.validate_token(token)
            .map_err(RuntimePollFailure::Admission)?;
        self.authenticate_original_restored_producer_runtime_callback_data(
            token,
            Some(claim),
            crate::node_admission::ProducerExecutionPhase::Observation,
        )
        .map_err(RuntimePollFailure::Admission)?;
        self.validate_owners_available(token.route())
            .map_err(RuntimePollFailure::Admission)?;
        {
            let entry =
                self.operations
                    .get(token.operation())
                    .ok_or(RuntimePollFailure::Admission(
                        RuntimeError::ForeignAuthority,
                    ))?;
            if !matches!(entry.result, RetainedResult::Acknowledged(_)) {
                return Err(RuntimePollFailure::Admission(
                    RuntimeError::OutstandingObligations,
                ));
            }
        }
        let coordinator_attempt = self.reserve_coordinator_attempt_data(
            crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentKind17::Observe,
            Some(token.operation()), Some(&token.route.node), None, 0,
        ).map_err(RuntimePollFailure::Admission)?;
        let result = (|| {
            let entry =
                self.operations
                    .get(token.operation())
                    .ok_or(RuntimePollFailure::Admission(
                        RuntimeError::ForeignAuthority,
                    ))?;
            let node = self
                .nodes
                .get_mut(&token.route.node)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
            let snapshot = self
                .snapshots
                .get(&token.route.node)
                .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
            snapshot
                .validate_current(node.as_ref())
                .map_err(RuntimePollFailure::Admission)?;
            let observation = node
                .observe_original_restored_producer_scheduling(&entry.admission, claim)
                .map_err(RuntimePollFailure::Native)?;
            snapshot
                .validate_current(node.as_ref())
                .map_err(RuntimePollFailure::Admission)?;
            if observation.node != token.route.node
                || observation.owners != token.route.owners
                || observation.bounds.len() > self.limits.maximum_nodes
                || !observation.publications.is_empty()
            {
                self.contain_roster(token.route());
                return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
            }
            let validated = crate::node_scheduling::ValidatedSchedulingObservation::new(
                claim.world_data().clone(),
                observation,
            );
            self.scheduler
                .as_mut()
                .ok_or(RuntimePollFailure::Admission(RuntimeError::NotActivated))?
                .borrow_mut()
                .map_err(RuntimePollFailure::Admission)?
                .accept_boundary_observation(validated)
                .map_err(|error| {
                    RuntimePollFailure::Admission(RuntimeError::SchedulerRefused(error.to_string()))
                })?;
            claim
                .retain_runtime_checkpoint_data(self)
                .map_err(RuntimePollFailure::Admission)
        })();
        self.finish_coordinator_attempt_data(coordinator_attempt,
            if result.is_ok() {
                crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentState17::Committed
            } else {
                crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentState17::Uncertain
            },
        ).map_err(RuntimePollFailure::Admission)?;
        result
    }
}
