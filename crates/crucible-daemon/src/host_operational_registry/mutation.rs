//! Serialized, durable reserve-before-apply operational mutation transactions.

use crucible_linux_resource::host_supervision::HostSupervisionError;
use crucible_linux_resource::ram_policy::HostRamPolicyError;
use crucible_protocol::ram_control::{RamControlConvergence, RamControlDisposition};

use super::*;

impl HostOperationalRegistry {
    pub(super) fn mutate(
        &self,
        request: HostOperationalRequest,
        digest: [u8; 32],
    ) -> Result<HostOperationalResponse, HostOperationalError> {
        let target = request.target();
        let key = match &request {
            HostOperationalRequest::UpdatePolicy {
                idempotency_key, ..
            }
            | HostOperationalRequest::AmendOuterCap {
                idempotency_key, ..
            } => *idempotency_key,
            _ => return Err(HostOperationalError::Unavailable),
        };
        // Placement and cap authorities serialize independently. A stalled
        // native policy apply must not prevent its separate outer watchdog
        // from accepting an amendment. Durable history locks cover only each
        // bounded prepare/commit, never native socket I/O.
        let owner = match target {
            HostOperationalTarget::Ram(target) => Some(self.node(target)?),
            _ => None,
        };
        let cap_owner = match target {
            HostOperationalTarget::OuterCap(target) => Some(
                self.shared
                    .state
                    .lock()
                    .map_err(unavailable)?
                    .caps
                    .get(&target)
                    .cloned()
                    .ok_or(HostOperationalError::Unavailable)?,
            ),
            _ => None,
        };
        let transaction = if let Some(owner) = &owner {
            owner.mutation.try_lock()
        } else if let Some(owner) = &cap_owner {
            owner.mutation.try_lock()
        } else {
            return Err(HostOperationalError::Unavailable);
        };
        let _transaction = match transaction {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                return Ok(refused(
                    &request,
                    digest,
                    HostOperationalDisposition::Unavailable,
                ));
            }
            Err(TryLockError::Poisoned(_)) => return Err(HostOperationalError::Unavailable),
        };
        let history = self
            .shared
            .history
            .as_ref()
            .ok_or(HostOperationalError::Unavailable)?;
        let mut journal = history.lock().map_err(unavailable)?;
        let index = target_digest(target);
        if let Some(mut original) = journal.lookup(index, key, digest)? {
            match &mut original {
                HostOperationalResponse::PolicyUpdate { disposition, .. }
                | HostOperationalResponse::OuterCapAmendment { disposition, .. } => {
                    if *disposition == HostOperationalDisposition::Accepted {
                        *disposition = HostOperationalDisposition::Replayed;
                    }
                }
                _ => return Err(HostOperationalError::Unavailable),
            }
            return Ok(original);
        }
        if owner.as_ref().is_some_and(|owner| {
            owner
                .state
                .lock()
                .map(|status| status.remaining_unique_update_capacity == 0)
                .unwrap_or(true)
        }) {
            return Ok(refused(
                &request,
                digest,
                HostOperationalDisposition::HistoryCapacityRefused,
            ));
        }
        if !journal.prepare(index, key, digest)? {
            return Ok(refused(
                &request,
                digest,
                HostOperationalDisposition::HistoryCapacityRefused,
            ));
        }
        // A durable intent is charged even for a typed refusal. Reusing its key
        // must replay the same decision instead of becoming a later success.
        if let Some(owner) = &owner {
            let mut status = owner.state.lock().map_err(unavailable)?;
            status.remaining_unique_update_capacity -= 1;
            status.history_disk_bytes = status
                .history_disk_bytes
                .checked_add(history::RECORD_CHARGE)
                .ok_or(HostOperationalError::Unavailable)?;
        }
        drop(journal);
        let result = match &request {
            HostOperationalRequest::UpdatePolicy {
                target,
                expected_policy_revision,
                policy,
                reservation_amendment,
                ..
            } => self.apply_policy(
                *target,
                *expected_policy_revision,
                **policy,
                *reservation_amendment,
                digest,
            ),
            HostOperationalRequest::AmendOuterCap {
                target,
                expected_cap_revision,
                allowance,
                ..
            } => self.apply_cap(*target, *expected_cap_revision, *allowance, digest),
            _ => Err(HostOperationalError::Unavailable),
        };
        let response = match result {
            Ok(response) => response,
            Err(error) => {
                self.quarantine(target)?;
                return Err(error);
            }
        };
        let committed = history
            .lock()
            .map_err(unavailable)
            .and_then(|journal| journal.commit(index, key, digest, &response));
        if let Err(error) = committed {
            self.quarantine(target)?;
            return Err(error);
        }
        Ok(response)
    }

    fn apply_policy(
        &self,
        target: HostRamTarget,
        expected_revision: u64,
        policy: HostRamPolicy,
        reservation: Option<HostReservationAmendment>,
        digest: [u8; 32],
    ) -> Result<HostOperationalResponse, HostOperationalError> {
        let owner = self.node(target)?;
        let previous = owner.state.lock().map_err(unavailable)?.clone();
        let refusal = |disposition| HostOperationalResponse::PolicyUpdate {
            request_digest: digest,
            target,
            disposition,
            policy_revision: previous.policy_revision,
            reservation_revision: previous.reservation_revision,
            transition: None,
            accepted_policy: None,
        };
        if previous.policy_revision != expected_revision {
            return Ok(refusal(HostOperationalDisposition::RevisionConflict));
        }
        let cap = owner.supervisor.outer_cap_status().map_err(unavailable)?;
        if cap.state != HostOperationState::Running {
            return Ok(refusal(HostOperationalDisposition::Terminal));
        }
        let requested_resources =
            reservation.map_or(previous.admitted_resources, |amendment| amendment.requested);
        // Metadata and staging have explicit mandatory floors. Unqualified
        // process/device headroom is owned capacity, not a measured minimum;
        // shrinking its complete resident/backing allocation requires proof.
        if reservation.is_some()
            && !owner.qualification.bounded_execution_peak
            && (requested_resources.resident_peak_bytes
                < previous.admitted_resources.resident_peak_bytes
                || requested_resources.backing_peak_bytes
                    < previous.admitted_resources.backing_peak_bytes)
        {
            return Ok(refusal(HostOperationalDisposition::Unsupported));
        }
        // The live backend seals its root budget, spill catalog and source
        // scratch at startup. A new host reservation cannot grant native
        // capacity until that backend supports the matching physical change.
        if requested_resources != previous.admitted_resources {
            return Ok(refusal(HostOperationalDisposition::Unsupported));
        }
        if u64::from(policy.maximum_paging_io_in_flight)
            > owner.capabilities.maximum_paging_io_slots
        {
            return Ok(refusal(HostOperationalDisposition::Unsupported));
        }
        if previous.transition.is_some() {
            return Ok(refusal(HostOperationalDisposition::AdmissionRefused));
        }
        if reservation.is_some() {
            let previous_subsets = previous
                .admitted_resources
                .metadata_bytes
                .checked_add(previous.admitted_resources.staging_bytes)
                .ok_or(HostOperationalError::Unavailable)?;
            let retained_floor = owner
                .capabilities
                .compulsory_resident_bytes
                .saturating_sub(previous_subsets);
            let minimum = owner
                .capabilities
                .minimum_execution_peak_bytes
                .checked_add(retained_floor)
                .and_then(|bytes| bytes.checked_add(requested_resources.metadata_bytes))
                .and_then(|bytes| bytes.checked_add(requested_resources.staging_bytes));
            if minimum.is_none_or(|bytes| bytes > requested_resources.resident_peak_bytes) {
                return Ok(refusal(HostOperationalDisposition::AdmissionRefused));
            }
        }
        if let Err(error) = policy.validate_update(
            previous.requested_policy,
            owner.capabilities,
            requested_resources,
            cap.allowance.is_some(),
        ) {
            let disposition = match error {
                HostRamPolicyError::Unsupported => HostOperationalDisposition::Unsupported,
                HostRamPolicyError::CapacityRefused => HostOperationalDisposition::AdmissionRefused,
                _ => HostOperationalDisposition::Unsupported,
            };
            return Ok(refusal(disposition));
        }
        let revision = previous
            .policy_revision
            .checked_add(1)
            .ok_or(HostOperationalError::Unavailable)?;
        let placement_changes = placement_changed(previous.requested_policy, policy);
        let mut client = match owner.client.try_lock() {
            Ok(client) => client,
            Err(TryLockError::WouldBlock) => {
                return Ok(refusal(HostOperationalDisposition::Unavailable));
            }
            Err(TryLockError::Poisoned(_)) => return Err(HostOperationalError::Unavailable),
        };
        if (placement_changes || reservation.is_some()) && client.is_none() {
            return Ok(refusal(HostOperationalDisposition::Unsupported));
        }
        let transition = if let Some(amendment) = reservation {
            match self.admission()?.begin_transition(target, amendment) {
                Ok(transition) => Some(transition),
                Err(_) => return Ok(refusal(HostOperationalDisposition::AdmissionRefused)),
            }
        } else {
            None
        };
        let reservation_revision = transition.map_or(previous.reservation_revision, |transition| {
            transition.reservation_revision
        });
        if let Some(transition) = transition {
            *owner.pending.lock().map_err(unavailable)? = Some(transition);
            let mut status = owner.state.lock().map_err(unavailable)?;
            status.admitted_resources = transition.held_peak;
            status.reservation_revision = transition.reservation_revision;
            status.transition = Some(transition.transition_id);
        }
        let reply = if let Some(client) = client.as_mut() {
            Some(
                client
                    .apply(
                        expected_revision,
                        revision,
                        reservation_revision,
                        policy,
                        requested_resources,
                    )
                    .map_err(unavailable)?,
            )
        } else {
            None
        };
        if let Some(reply) = &reply {
            if reply.disposition != RamControlDisposition::Accepted {
                if transition.is_some() {
                    return Err(HostOperationalError::Unavailable);
                }
                return Ok(refusal(wire_disposition(reply.disposition)));
            }
            if reply.requested_policy_revision != revision
                || reply.reservation_revision != reservation_revision
            {
                return Err(HostOperationalError::Unavailable);
            }
        }
        let (budget_revision, _) = owner.supervisor.budgets().map_err(unavailable)?;
        owner
            .supervisor
            .update_budgets(budget_revision, policy.latency)
            .map_err(unavailable)?;
        let mut status = owner.state.lock().map_err(unavailable)?;
        status.policy_revision = revision;
        status.requested_policy = policy;
        status.accepted_unique_update_count = status
            .accepted_unique_update_count
            .checked_add(1)
            .ok_or(HostOperationalError::Unavailable)?;
        status.observation_sequence = status
            .observation_sequence
            .checked_add(1)
            .ok_or(HostOperationalError::Unavailable)?;
        if let Some(reply) = reply {
            observe_reply(&mut status, reply, policy, revision)?;
        } else {
            // Budget-only application is actual live watchdog application; it
            // neither establishes paging nor invents physical measurements.
            status.applied_policy = policy;
        }
        Ok(HostOperationalResponse::PolicyUpdate {
            request_digest: digest,
            target,
            disposition: HostOperationalDisposition::Accepted,
            policy_revision: revision,
            reservation_revision: status.reservation_revision,
            transition: status.transition,
            accepted_policy: Some(Box::new(policy)),
        })
    }

    fn apply_cap(
        &self,
        target: HostOuterCapTarget,
        expected_revision: u64,
        allowance: Option<Duration>,
        digest: [u8; 32],
    ) -> Result<HostOperationalResponse, HostOperationalError> {
        let (cap, owners) = {
            let state = self.shared.state.lock().map_err(unavailable)?;
            let cap = state
                .caps
                .get(&target)
                .cloned()
                .ok_or(HostOperationalError::Unavailable)?;
            let owners: Vec<_> = state
                .nodes
                .values()
                .filter(|owner| owner.cap == target)
                .cloned()
                .collect();
            (cap, owners)
        };
        // Reserve each transport before mutating the shared cap. A busy native
        // apply yields a durable refusal rather than an unpropagated extension.
        // Every actual exchange retains its finite cleanup allowance.
        let mut clients = Vec::with_capacity(owners.len());
        for owner in &owners {
            match owner.client.try_lock() {
                Ok(client) => clients.push(client),
                Err(TryLockError::WouldBlock) => {
                    return Ok(HostOperationalResponse::OuterCapAmendment {
                        request_digest: digest,
                        target,
                        disposition: HostOperationalDisposition::Unavailable,
                        accepted_cap_revision: None,
                        accepted_allowance: None,
                    });
                }
                Err(TryLockError::Poisoned(_)) => return Err(HostOperationalError::Unavailable),
            }
        }
        let broadcast = cap
            .supervisor
            .begin(crucible_linux_resource::host_supervision::HostOperationClass::Cleanup)
            .map_err(unavailable)?;
        match cap.supervisor.amend_outer_cap(expected_revision, allowance) {
            Ok(revision) => {
                let binding = cap.supervisor.outer_cap_binding().map_err(unavailable)?;
                for client in &mut clients {
                    if let Some(client) = client.as_mut() {
                        let reply = client
                            .sync_outer_cap_under(binding, &broadcast)
                            .map_err(unavailable)?;
                        if reply.disposition != RamControlDisposition::Accepted {
                            return Err(HostOperationalError::Unavailable);
                        }
                    }
                }
                broadcast.complete().map_err(unavailable)?;
                Ok(HostOperationalResponse::OuterCapAmendment {
                    request_digest: digest,
                    target,
                    disposition: HostOperationalDisposition::Accepted,
                    accepted_cap_revision: Some(revision),
                    accepted_allowance: Some(allowance),
                })
            }
            Err(error) => {
                let disposition = match error {
                    HostSupervisionError::RevisionConflict { .. } => {
                        HostOperationalDisposition::RevisionConflict
                    }
                    HostSupervisionError::Terminal { .. } => HostOperationalDisposition::Terminal,
                    HostSupervisionError::UnboundedInfrastructure { .. }
                    | HostSupervisionError::InvalidBudget => {
                        HostOperationalDisposition::Unsupported
                    }
                    _ => return Err(HostOperationalError::Unavailable),
                };
                Ok(HostOperationalResponse::OuterCapAmendment {
                    request_digest: digest,
                    target,
                    disposition,
                    accepted_cap_revision: None,
                    accepted_allowance: None,
                })
            }
        }
    }

    fn quarantine(&self, target: HostOperationalTarget) -> Result<(), HostOperationalError> {
        match target {
            HostOperationalTarget::Owner(_) => return Err(HostOperationalError::Unavailable),
            HostOperationalTarget::Ram(target) => {
                let owner = self.node(target)?;
                owner.supervisor.cancel().map_err(unavailable)?;
                owner.state.lock().map_err(unavailable)?.convergence =
                    HostRamConvergence::Quarantined;
            }
            HostOperationalTarget::OuterCap(target) => {
                let cap = self
                    .shared
                    .state
                    .lock()
                    .map_err(unavailable)?
                    .caps
                    .get(&target)
                    .cloned()
                    .ok_or(HostOperationalError::Unavailable)?;
                cap.supervisor.cancel().map_err(unavailable)?;
            }
        }
        Ok(())
    }
}

pub(super) fn refused(
    request: &HostOperationalRequest,
    digest: [u8; 32],
    disposition: HostOperationalDisposition,
) -> HostOperationalResponse {
    match request {
        HostOperationalRequest::UpdatePolicy {
            target,
            expected_policy_revision,
            ..
        } => HostOperationalResponse::PolicyUpdate {
            request_digest: digest,
            target: *target,
            disposition,
            policy_revision: *expected_policy_revision,
            reservation_revision: 0,
            transition: None,
            accepted_policy: None,
        },
        HostOperationalRequest::AmendOuterCap { target, .. } => {
            HostOperationalResponse::OuterCapAmendment {
                request_digest: digest,
                target: *target,
                disposition,
                accepted_cap_revision: None,
                accepted_allowance: None,
            }
        }
        _ => unreachable!("only mutating requests enter mutation admission"),
    }
}

fn target_digest(target: HostOperationalTarget) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.host-control.owner.v1\0");
    match target {
        HostOperationalTarget::Owner(target) => {
            hasher.update(&[2]);
            hasher.update(&target.daemon_epoch);
            hasher.update(&target.owner_id);
        }
        HostOperationalTarget::Ram(target) => {
            hasher.update(&[0]);
            hasher.update(&target.daemon_epoch);
            hasher.update(&target.owner_id);
            hasher.update(&target.node_id);
            hasher.update(&target.owner_generation.to_be_bytes());
            hasher.update(&target.arena_generation.to_be_bytes());
            hasher.update(&[u8::from(target.retained_template)]);
        }
        HostOperationalTarget::OuterCap(target) => {
            hasher.update(&[1]);
            hasher.update(&target.daemon_epoch);
            match target.owner {
                HostOuterCapOwner::Execution(owner) => {
                    hasher.update(&[0]);
                    hasher.update(&owner);
                }
                HostOuterCapOwner::Service(owner) => {
                    hasher.update(&[1]);
                    hasher.update(&owner);
                }
            }
            hasher.update(&target.owner_generation.to_be_bytes());
            hasher.update(&target.cap_id);
        }
    }
    *hasher.finalize().as_bytes()
}

fn placement_changed(mut before: HostRamPolicy, after: HostRamPolicy) -> bool {
    before.latency = after.latency;
    before != after
}

fn wire_disposition(disposition: RamControlDisposition) -> HostOperationalDisposition {
    match disposition {
        RamControlDisposition::Accepted => HostOperationalDisposition::Accepted,
        RamControlDisposition::RevisionConflict => HostOperationalDisposition::RevisionConflict,
        RamControlDisposition::NotCurrent => HostOperationalDisposition::NotCurrent,
        RamControlDisposition::Unsupported => HostOperationalDisposition::Unsupported,
        RamControlDisposition::AdmissionRefused => HostOperationalDisposition::AdmissionRefused,
        RamControlDisposition::Unavailable => HostOperationalDisposition::Unavailable,
        RamControlDisposition::Canceled => HostOperationalDisposition::Terminal,
    }
}

pub(super) fn observe_reply(
    status: &mut HostRamStatus,
    reply: RamControlReply,
    policy: HostRamPolicy,
    revision: u64,
) -> Result<(), HostOperationalError> {
    if reply.applied_policy_revision > revision {
        return Err(HostOperationalError::Unavailable);
    }
    if reply.applied_policy_revision == revision {
        status.applied_policy = policy;
    }
    status.effective_resident_target_bytes = reply.effective_resident_target_bytes;
    status.effective_floor_bytes = reply.effective_floor_bytes;
    status.measurements_available = reply.measurements_available;
    status.activity = reply.activity;
    status.private_resident_bytes = reply.private_resident_bytes;
    status.shared_resident_bytes_observed = reply.shared_resident_bytes_observed;
    status.preserved_backing_bytes = reply.preserved_backing_bytes;
    status.private_dirty_bytes = reply.private_dirty_bytes;
    status.writeback_pending_bytes = reply.writeback_pending_bytes;
    status.convergence = match reply.convergence {
        RamControlConvergence::Stable => HostRamConvergence::Stable,
        RamControlConvergence::Applying => HostRamConvergence::Applying,
        RamControlConvergence::Evicting => HostRamConvergence::Evicting,
        RamControlConvergence::Prefetching => HostRamConvergence::Prefetching,
        RamControlConvergence::Blocked => HostRamConvergence::Blocked,
        RamControlConvergence::Failed => HostRamConvergence::Failed,
        RamControlConvergence::Quarantined => HostRamConvergence::Quarantined,
    };
    status.limitation_reasons = [
        (1, "compulsory-floor"),
        (2, "pinned-borrower"),
        (4, "backing-capacity"),
        (8, "io-capacity"),
        (16, "execution-peak"),
        (32, "host-pressure"),
    ]
    .into_iter()
    .filter(|(bit, _)| reply.limitation_reasons & bit != 0)
    .map(|(_, name)| name.to_owned())
    .collect();
    Ok(())
}
