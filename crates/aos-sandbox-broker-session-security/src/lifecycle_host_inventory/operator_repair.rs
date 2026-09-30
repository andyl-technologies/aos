//! Drives original Repair on the actual retained Storage session.
//!
//! Ordinary Inventory completes before the serial operator hold. Original
//! archives provide only authenticated historical DATA after hold or commit;
//! they never manufacture currentness, release, or a second effect identity.

use aos_sandbox::controller::{
    OperatorStorageRepairBridgeV1, OperatorStorageRepairErrorV1,
    OperatorStorageRepairTerminalV1,
};
use aos_sandbox::resource_inventory::ResourceInventoryServiceIdentity;
use aos_sandbox_protocol::operator_storage_repair_transport_v3::OperatorStorageRepairResultV3;

use super::*;

fn repair_inventory_failure(error: LifecyclePhase6ErrorV1) -> EffectFailure {
    EffectFailure::Retryable(format!(
        "original Repair Inventory remains unresolved: {error}"
    ))
}

fn repair_bridge_failure(error: OperatorStorageRepairErrorV1) -> EffectFailure {
    // A binding conflict or missing role after admission must not enter generic
    // Permanent completion and release original sent/held custody as failure.
    EffectFailure::Retryable(format!(
        "original Repair custody remains unresolved: {error}"
    ))
}

impl DormantStorageLifecycleInventoryOwnerV1 {
    /// Drives only the original Repair attempt and its authenticated history.
    ///
    /// Terminal Inventory finishes on the ordinary serial broker before the
    /// facade opens the operator hold socket. Once hold custody exists, only
    /// original historical packets may be reauthenticated: no ordinary socket
    /// request can wait behind that same Storage actor's retained hold.
    ///
    /// # Errors
    ///
    /// Retains unresolved original custody on unavailable history, role,
    /// transport, physical proof, exact terminal CAS or owner settlement.
    pub(crate) fn reconcile_operator_storage_repair(
        &mut self,
        bridge: &mut OperatorStorageRepairBridgeV1<'_>,
        operation: OperationId,
        completion_wall_seconds: i64,
    ) -> Result<OperatorStorageRepairTerminalV1, EffectFailure> {
        let service = self
            .operator_repair_service_identity()
            .map_err(repair_inventory_failure)?;
        let mut progress = bridge
            .progress_snapshot(operation)
            .map_err(repair_bridge_failure)?;
        let admission = self
            .operator_repair_inventory_history(
                progress.admission_request_id,
                Some(&progress.admission_packet),
            )
            .map_err(repair_inventory_failure)?;

        if progress.terminal_hold_sent || progress.terminal_committed {
            let before_id = progress.before_request_id.ok_or_else(|| {
                EffectFailure::Retryable(
                    "held Repair lost its original before challenge".to_owned(),
                )
            })?;
            let after_id = progress.after_request_id.ok_or_else(|| {
                EffectFailure::Retryable(
                    "held Repair lost its original after challenge".to_owned(),
                )
            })?;
            let terminal_id = progress.terminal_request_id.ok_or_else(|| {
                EffectFailure::Retryable(
                    "held Repair lost its original Terminal challenge".to_owned(),
                )
            })?;

            let before = self
                .operator_repair_inventory_history(before_id, progress.before_packet.as_deref())
                .map_err(repair_inventory_failure)?;
            let after = self
                .operator_repair_inventory_history(after_id, progress.after_packet.as_deref())
                .map_err(repair_inventory_failure)?;
            let terminal = self
                .operator_repair_inventory_history(terminal_id, progress.terminal_packet.as_deref())
                .map_err(repair_inventory_failure)?;
            return bridge
                .complete_terminal(
                    operation, &admission, &before, &after, &terminal, &service,
                    completion_wall_seconds,
                )
                .map_err(repair_bridge_failure);
        }

        let before = self.original_operator_repair_inventory(
            progress.before_request_id,
            progress.before_packet.as_deref(),
            |request| bridge.reserve_before_query(operation, request),
        )?;
        if progress.prepared_probe.is_none() {
            bridge
                .prepare(operation, &before, &service)
                .map_err(repair_bridge_failure)?;
        }

        if progress.owner_pair.is_none() {
            match bridge
                .execute_or_recover(operation, &service)
                .map_err(repair_bridge_failure)?
            {
                OperatorStorageRepairResultV3::Complete(_, _) => {}
                OperatorStorageRepairResultV3::Pending => {
                    return Err(EffectFailure::Retryable(
                        "original Repair owner outcome is pending".to_owned(),
                    ));
                }
                OperatorStorageRepairResultV3::Prepared(_) => {
                    return Err(EffectFailure::Retryable(
                        "Repair Execute returned a different stage".to_owned(),
                    ));
                }
            }
            progress = bridge
                .progress_snapshot(operation)
                .map_err(repair_bridge_failure)?;
        }

        let (evidence, receipt) = progress.owner_pair.as_ref().ok_or_else(|| {
            EffectFailure::Retryable("original Repair owner pair is unavailable".to_owned())
        })?;
        let after = self.original_operator_repair_inventory(
            progress.after_request_id,
            progress.after_packet.as_deref(),
            |request| bridge.reserve_after_query(operation, evidence, receipt, request),
        )?;
        if !progress.proof_sealed {
            bridge
                .seal_proof(operation, &before, &after)
                .map_err(repair_bridge_failure)?;
        }

        let terminal = self.original_operator_repair_inventory(
            progress.terminal_request_id,
            progress.terminal_packet.as_deref(),
            |request| bridge.reserve_terminal_query(operation, request),
        )?;

        // Completion is sampled after the serial observations, not before
        // Repair's physical work. It never changes the original effect grant
        // or deadline; Core retains this timestamp with the first hold request.
        let completion = crate::controller_ownership::sample_ownership_clock()
            .map_err(|_| {
                EffectFailure::Retryable("Repair completion clock is unavailable".to_owned())
            })?;
        if completion.wall_seconds() < completion_wall_seconds {
            return Err(EffectFailure::Retryable(
                "Repair completion clock moved backward".to_owned(),
            ));
        }

        // No ordinary Inventory call occurs after this boundary. Core owns the
        // same operator socket through hold, exact six-row CAS, ACK and release.
        bridge
            .complete_terminal(
                operation, &admission, &before, &after, &terminal, &service,
                completion.wall_seconds(),
            )
            .map_err(repair_bridge_failure)
    }

    fn original_operator_repair_inventory(
        &mut self,
        request_id: Option<[u8; 16]>,
        packet: Option<&[u8]>,
        reserve: impl FnOnce([u8; 16]) -> Result<(), OperatorStorageRepairErrorV1>,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, EffectFailure> {
        if let Some(request_id) = request_id {
            match self.operator_repair_inventory_history(request_id, packet) {
                Ok(outcome) => return Ok(outcome),
                Err(_) if packet.is_none() => {
                    // A selected challenge owns its request forever. Only its
                    // retained in-process exchange may advance; failed/cold
                    // recovery does not authorize another request identity.
                    return self
                        .recover_challenged_operator_repair_inventory_observation(request_id)
                        .map(|(outcome, _)| outcome)
                        .map_err(repair_inventory_failure);
                }
                Err(error) => return Err(repair_inventory_failure(error)),
            }
        }

        if packet.is_some() {
            return Err(EffectFailure::Retryable(
                "Repair packet has no original challenge".to_owned(),
            ));
        }
        self.challenged_operator_repair_inventory_observation(|request| {
            reserve(request).map_err(|_| BrokerSessionSecurityError::Currentness)
        })
        .map(|(outcome, _)| outcome)
        .map_err(repair_inventory_failure)
    }

    /// Rejoins the existing fixed Storage policy to this actual session peer.
    ///
    /// The policy matches the existing ControllerPeerVerifier Storage role;
    /// retained cgroup and live pidfd membership, not the pathname alone, prove
    /// that the nominated operator record subject belongs to that same role.
    ///
    /// # Errors
    ///
    /// Rejects unavailable actual session custody, non-root credentials,
    /// non-leader or departed peers, and unavailable exact Storage cgroup.
    pub(crate) fn operator_repair_service_identity(
        &mut self,
    ) -> Result<ResourceInventoryServiceIdentity, LifecyclePhase6ErrorV1> {
        let descriptor = self
            .0
            .session
            .retain_authenticated_peer_pidfd()
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let peer = aos_sandbox_linux::pidfd::PidFd::from_owned(descriptor)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let descriptor = rustix::fs::open(
            "/sys/fs/cgroup",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let root = aos_sandbox_linux::cgroup::CgroupV2Root::from_owned(descriptor)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let cgroup = root
            .resolve(std::path::Path::new(
                "aos.slice/aos-control.slice/aos-storaged.service",
            ))
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;

        let info = cgroup
            .verify_exact_membership(&peer)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let credentials = info
            .credentials()
            .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
        if info.pid() != info.thread_group_id()
            || credentials.real_user_id() != 0
            || credentials.real_group_id() != 0
            || credentials.effective_user_id() != 0
            || credentials.effective_group_id() != 0
            || credentials.saved_user_id() != 0
            || credentials.saved_group_id() != 0
            || credentials.filesystem_user_id() != 0
            || credentials.filesystem_group_id() != 0
        {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }

        Ok(ResourceInventoryServiceIdentity { uid: 0, gid: 0, cgroup })
    }

    /// Reauthenticates only retained original Repair Inventory history.
    ///
    /// No broker request is sent, and the returned outcome is historical DATA,
    /// not a currentness owner or a restored operator hold.
    ///
    /// # Errors
    ///
    /// Rejects absent, foreign, ambiguous or substituted history, unavailable
    /// protected floor/checkpoint/pins, or changed actual session/peer custody.
    pub(crate) fn operator_repair_inventory_history(
        &mut self,
        request_id: [u8; 16],
        packet: Option<&[u8]>,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, LifecyclePhase6ErrorV1> {
        self.0
            .session
            .operator_repair_inventory_history(request_id, packet)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)
    }
}
