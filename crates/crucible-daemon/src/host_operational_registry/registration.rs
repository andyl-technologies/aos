//! Prepublication admission and native convergence for exact RAM owners.
//!
//! Registration binds the granted resource vector and original supervisor to
//! one controller incarnation. It publishes only after the native initial
//! policy applies, while preserving the independently established capability
//! certificate and immutable outer authority.

use super::*;

impl HostOperationalRegistry {
    /// Publishes behavior only after the scoped immutable receipt proves this incarnation.
    pub(crate) fn register_with_qualification(
        &self,
        target: HostRamTarget,
        policy: HostRamPolicy,
        resources: HostResourceVector,
        supervisor: HostOperationSupervisor,
        client: Option<RamControlClient>,
        qualification: HostRamQualification,
    ) -> Result<(), RamControlError> {
        let registration =
            self.native_registration(target, policy, resources, supervisor, client, qualification)?;
        self.register_node(registration)
            .map_err(|_| RamControlError::AuthorityMismatch)
    }

    pub(super) fn native_registration(
        &self,
        target: HostRamTarget,
        policy: HostRamPolicy,
        resources: HostResourceVector,
        supervisor: HostOperationSupervisor,
        mut client: Option<RamControlClient>,
        qualification: HostRamQualification,
    ) -> Result<NativeRamRegistration, RamControlError> {
        let observation = client
            .as_mut()
            .ok_or(RamControlError::AuthorityMismatch)?
            .status()?;
        let logical = observation.logical_ram_bytes;
        if logical == 0 {
            return Err(RamControlError::AuthorityMismatch);
        }
        let services = self
            .bootstrap_limits()
            .ok_or(RamControlError::AuthorityMismatch)?
            .host_service_resident_bytes();
        let floor = resources
            .metadata_bytes
            .checked_add(resources.staging_bytes)
            .and_then(|bytes| bytes.checked_add(services))
            .ok_or(RamControlError::InvalidFrame)?;
        let qualified_placement = qualification.backend == HostRamBackend::PausedPager
            && qualification.authenticated_pages
            && qualification.evidence.is_some();
        let capabilities = HostRamCapabilities {
            logical_ram_bytes: logical,
            compulsory_resident_bytes: floor,
            minimum_execution_peak_bytes: logical,
            maximum_paging_io_slots: 1,
            dynamic_residency: qualified_placement,
            disk_oriented: false,
            resident_required: false,
        };
        Ok(NativeRamRegistration {
            #[cfg(test)]
            native_resident_initial: false,
            target,
            policy,
            resources,
            capabilities,
            qualification,
            supervisor,
            client,
        })
    }
}

impl HostOperationalRegistry {
    /// Registers an admitted node with independently established qualification.
    ///
    /// Qualification must come from deployment evidence, never socket presence
    /// or an operator boolean. Full RAM is the minimum execution peak whenever
    /// fault-safe reclamation has not been independently qualified.
    ///
    /// # Errors
    /// Refuses reused targets, invalid policy/admission, mismatched live handles,
    /// unqualified capability claims, and unavailable controller authority.
    pub(super) fn register_node(
        &self,
        registration: NativeRamRegistration,
    ) -> Result<(), HostOperationalError> {
        let NativeRamRegistration {
            #[cfg(test)]
            native_resident_initial,
            target,
            policy,
            resources,
            capabilities,
            qualification,
            supervisor,
            mut client,
        } = registration;
        let _transaction = self.shared.mutation.try_lock().map_err(unavailable)?;
        if target.owner_generation == 0
            || target.arena_generation == 0
            || client
                .as_ref()
                .is_some_and(|value| value.target() != target)
        {
            return Err(HostOperationalError::Unavailable);
        }
        self.admit_node(target, resources)?;
        // The public canonical codec validates the closed qualification matrix.
        codec::validate_response(&HostOperationalResponse::Capabilities {
            target,
            capabilities,
            qualification,
        })?;
        let finite_outer = supervisor
            .outer_cap_status()
            .map_err(unavailable)?
            .allowance
            .is_some();
        #[cfg(test)]
        if native_resident_initial {
            native_initial::validate_entitlement(policy, capabilities, resources, finite_outer)?;
        } else {
            policy
                .validate_update(policy, capabilities, resources, finite_outer)
                .map_err(unavailable)?;
        }
        #[cfg(not(test))]
        policy
            .validate_update(policy, capabilities, resources, finite_outer)
            .map_err(unavailable)?;
        let (_, budgets) = supervisor.budgets().map_err(unavailable)?;
        if budgets != policy.latency {
            return Err(HostOperationalError::Unavailable);
        }
        // RAM process generations select an already admitted assignment or
        // service cap. A node cannot manufacture a second outer authority.
        let cap = {
            let state = self.shared.state.lock().map_err(unavailable)?;
            let mut matching = state.caps.iter().filter(|(cap, owner)| {
                let owner_id = match cap.owner {
                    HostOuterCapOwner::Execution(id) | HostOuterCapOwner::Service(id) => id,
                };
                cap.daemon_epoch == target.daemon_epoch
                    && owner_id == target.owner_id
                    && cap.cap_id == supervisor.cap_id()
                    && owner.supervisor.shares_outer_cap(&supervisor)
            });
            let cap = *matching.next().ok_or(HostOperationalError::Unavailable)?.0;
            if matching.next().is_some() {
                return Err(HostOperationalError::Unavailable);
            }
            cap
        };
        let cap_owner = self
            .shared
            .state
            .lock()
            .map_err(unavailable)?
            .caps
            .get(&cap)
            .cloned()
            .ok_or(HostOperationalError::Unavailable)?;
        // Registration and amendment serialize on the same original authority.
        // The native startup binding may have been sampled before an amendment;
        // synchronize it before publication so no new owner misses the fanout.
        let _cap_transaction = cap_owner.mutation.try_lock().map_err(unavailable)?;
        if let Some(client) = client.as_mut() {
            let binding = supervisor.outer_cap_binding().map_err(unavailable)?;
            let reply = client.sync_outer_cap(binding).map_err(unavailable)?;
            if reply.disposition != crucible_protocol::ram_control::RamControlDisposition::Accepted
            {
                return Err(HostOperationalError::Unavailable);
            }
        }
        let mut status = HostRamStatus {
            target,
            observation_sequence: 1,
            policy_revision: 0,
            applied_policy_revision: 0,
            reservation_revision: 0,
            requested_policy: policy,
            applied_policy: policy,
            placement_receipt: None,
            effective_resident_target_bytes: policy.resident_target_bytes,
            effective_floor_bytes: capabilities.compulsory_resident_bytes,
            limitation_reasons: Vec::new(),
            measurements_available: false,
            activity: None,
            private_resident_bytes: 0,
            shared_resident_bytes_observed: 0,
            preserved_backing_bytes: 0,
            private_dirty_bytes: 0,
            writeback_pending_bytes: 0,
            convergence: HostRamConvergence::Stable,
            accepted_unique_update_count: 0,
            remaining_unique_update_capacity: MAX_UNIQUE_UPDATES,
            history_disk_bytes: 0,
            transition: None,
            admitted_resources: resources,
            outer_caps: Vec::new(),
            outstanding_operations: Vec::new(),
        };
        if let Some(client) = client.as_mut() {
            let setup = supervisor
                .begin(crucible_linux_resource::host_supervision::HostOperationClass::Setup)
                .map_err(unavailable)?;
            let mut reply = client
                .apply(0, 1, 0, policy, resources)
                .map_err(unavailable)?;
            if reply.disposition != crucible_protocol::ram_control::RamControlDisposition::Accepted
                || reply.requested_policy_revision != 1
            {
                supervisor.cancel().map_err(unavailable)?;
                return Err(HostOperationalError::Unavailable);
            }
            while reply.applied_policy_revision != 1 {
                setup.wait_for_change().map_err(unavailable)?;
                reply = client.status().map_err(unavailable)?;
                if reply.requested_policy_revision != 1 || reply.applied_policy_revision > 1 {
                    return Err(HostOperationalError::Unavailable);
                }
            }
            #[cfg(test)]
            if native_resident_initial {
                native_initial::validate_receipt(&reply)?;
            }
            status.policy_revision = 1;
            mutation::observe_reply(&mut status, reply, policy, 1)?;
            setup.complete().map_err(unavailable)?;
        }
        let mut state = self.shared.state.lock().map_err(unavailable)?;
        if state.nodes.len() + state.retired.len() >= MAX_OWNERS
            || state.nodes.contains_key(&target)
            || state.retired.contains(&target)
        {
            return Err(HostOperationalError::Unavailable);
        }
        state.nodes.insert(
            target,
            Arc::new(Owner {
                mutation: Mutex::new(()),
                supervisor,
                cap,
                capabilities,
                qualification,
                state: Mutex::new(status),
                client: Mutex::new(client),
                pending: Mutex::new(None),
                retirement: Mutex::new(None),
                cancellation_failure: Mutex::new(None),
            }),
        );
        Ok(())
    }
}
