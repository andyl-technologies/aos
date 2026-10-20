//! Associates protected Launch and Stop history with fresh native census DATA.
//!
//! The optional AOSHNS04 bytes live inside CompositeStopRecord's existing JSON
//! execution authentication. Old omitted fields keep their original MAC bytes.
//! A completed Launch without a Host Stop row has a distinct comparison shape.
//! Neither historical shape restores an old native owner; only the genuine
//! fresh inventory can establish ownership or absence for a new cleanup.

use aos_sandbox_protocol::host_stopped_namespace::{
    HOST_STOPPED_NAMESPACE_BYTES_V4, HostStoppedNamespaceDataV4,
};

use super::*;

/// Retains immutable historical DATA without restoring the old native owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HistoricalNamespaceCandidateV7 {
    scope: Option<HostStoppedNamespaceDataV4>,
    launch: Option<aos_sandbox_protocol::host_stopped_namespace::HostLaunchNamespaceDataV1>,
    target: transition::CompositeStopTarget,
    phase: Option<transition::CompositeStopPhase>,
    cleanup: Option<CleanupLineageCandidateV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CleanupLineageCandidateV1 {
    subject: aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupSubjectDataV1,
    child: ([u8; 16], [u8; 32], [u8; 32]),
    chain: [u8; 32],
}

impl HistoricalNamespaceCandidateV7 {
    pub(crate) fn require_completed_resident_stop_v1(
        &self,
        scope: &HostStoppedNamespaceDataV4,
    ) -> Result<()> {
        if self.scope.as_ref() != Some(scope)
            || self.launch.is_some()
            || self.cleanup.is_some()
            || !matches!(self.phase, Some(transition::CompositeStopPhase::Complete { .. }))
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn stopped_scope_v1(&self) -> Result<&HostStoppedNamespaceDataV4> {
        self.scope.as_ref().ok_or_else(refused)
    }

    pub(crate) fn launch_only_scope_v1(
        &self,
    ) -> Option<&aos_sandbox_protocol::host_stopped_namespace::HostLaunchNamespaceDataV1> {
        self.launch.as_ref()
    }

    pub(crate) fn dispatched_observation_scope_v1(
        &self,
    ) -> Option<aos_sandbox_protocol::host_stopped_namespace::HostLaunchNamespaceDataV1> {
        use aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupOriginDataV1;

        if let Some(scope) = self.launch {
            return Some(scope);
        }
        let cleanup = self.cleanup.as_ref()?;
        if cleanup.subject.origin_v1() != HostStopCleanupOriginDataV1::DispatchedBeforeHost
            || matches!(
                self.phase,
                Some(transition::CompositeStopPhase::Complete { .. })
            )
        {
            return None;
        }
        Some(self.scope.as_ref()?.launch_scope_v1())
    }

    pub(crate) fn require_cleanup_subject_v2(
        &self,
        subject: &aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupSubjectDataV1,
    ) -> Result<()> {
        use aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupOriginDataV1 as Origin;
        let matches = match subject.origin_v1() {
            Origin::ProtectedPending => {
                self.launch.is_none()
                    && self.scope.as_ref() == Some(subject.historical_scope_v1())
                    && self.cleanup.as_ref().is_none_or(|cleanup| {
                        cleanup.subject.origin_v1() == Origin::ProtectedPending
                    })
            }
            Origin::DispatchedBeforeHost => {
                self.launch.as_ref() == Some(&subject.historical_scope_v1().launch_scope_v1())
                    || (self.scope.as_ref() == Some(subject.historical_scope_v1())
                        && self.cleanup.as_ref().is_some_and(|cleanup| {
                            cleanup.subject.origin_v1() == Origin::DispatchedBeforeHost
                        }))
            }
        };
        if matches { Ok(()) } else { Err(refused()) }
    }

    pub(crate) fn fresh_launch_stop_target_v1(&self) -> Result<transition::CompositeStopTarget> {
        if self.launch.is_none() || self.scope.is_some() || self.phase.is_some() {
            return Err(refused());
        }
        Ok(self.target.clone())
    }

    pub(crate) fn require_cleanup_child_data_v1(
        &self,
        subject: &aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupSubjectDataV1,
        child: ([u8; 16], [u8; 32], [u8; 32]),
    ) -> Result<()> {
        if self.cleanup.as_ref().is_none_or(|actual| actual.subject != *subject || actual.child != child) {
            return Err(refused());
        }
        Ok(())
    }

    /// Projects only a genuine protected Complete cleanup leaf into new DATA.
    ///
    /// The caller must still join both equal protected snapshots and the actual
    /// complete native census; this passive projection supplies no native grant.
    pub(crate) fn cleanup_lineage_data_v1(&self,
        observation: aos_sandbox_protocol::host_inventory_absence::HostInventoryAbsenceDataV5,
    ) -> Result<Option<aos_sandbox_protocol::host_cleanup_lineage::HostCleanupLineageDataV1>> {
        let Some(cleanup) = &self.cleanup else {
            return Ok(None);
        };
        if !matches!(
            self.phase,
            Some(transition::CompositeStopPhase::Complete { .. })
        ) {
            return Err(refused());
        }
        aos_sandbox_protocol::host_cleanup_lineage::HostCleanupLineageDataV1::from_data_v1(
            cleanup.subject, cleanup.child, observation, cleanup.chain).map(Some).map_err(Into::into)
    }

    /// Compares present roles with the immutable MAC-protected old target.
    ///
    /// # Errors
    /// Refuses foreign role identities, total absence or a completed Stop with
    /// contradictory live residue. The caller supplies actual native ownership.
    pub(crate) fn require_present_target_v1(
        &self,
        payload: &aos_systemd_client::PostUnrefUnitObservation,
        guardian: &aos_systemd_client::PostUnrefUnitObservation,
    ) -> Result<()> {
        use aos_systemd_client::{ExactUnitRole, PostUnrefUnitObservation};
        use transition::StopUnitTarget;

        if matches!(
            self.phase,
            Some(transition::CompositeStopPhase::Complete { .. })
        ) {
            return Err(refused());
        }

        let mut present = false;
        for (target, observed, role) in [
            (self.target.payload(), payload, ExactUnitRole::Payload),
            (self.target.guardian(), guardian, ExactUnitRole::Guardian),
        ] {
            if let PostUnrefUnitObservation::Present(observed) = observed {
                let StopUnitTarget::Exact {
                    binding: Some(binding),
                    invocation,
                } = target
                else {
                    return Err(refused());
                };
                if observed.role != role
                    || observed.binding != Some(binding)
                    || observed.invocation_id != Some(invocation)
                {
                    return Err(refused());
                }
                present = true;
            }
        }
        if !present {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn present_phase_v8(
        &self,
        payload: &aos_systemd_client::PostUnrefUnitObservation,
        guardian: &aos_systemd_client::PostUnrefUnitObservation,
    ) -> Result<aos_sandbox_protocol::host_stop_cleanup_candidate::HostStopCleanupSavedPhaseDataV1>
    {
        use aos_sandbox_protocol::host_stop_cleanup_candidate::HostStopCleanupSavedPhaseDataV1 as Phase;
        use transition::{CompositeStopPhase, StopProgress};
        self.require_present_target_v1(payload, guardian)?;
        Ok(match self.phase.as_ref().ok_or_else(refused)? {
            CompositeStopPhase::StopAuthorized => Phase::Authorized,
            CompositeStopPhase::StopEffectIssued { progress } => match progress {
                StopProgress::PayloadPending => Phase::PayloadPending,
                StopProgress::GuardianPending => Phase::GuardianPending,
                StopProgress::PayloadAwaitingAbsence => Phase::PayloadAwaitingAbsence,
                StopProgress::GuardianAwaitingAbsence => Phase::GuardianAwaitingAbsence,
            },
            CompositeStopPhase::Complete { .. } => return Err(refused()),
        })
    }

    /// Compares the saved phase after the actual census proved total absence.
    pub(crate) fn absent_phase_v7(
        &self,
        observation: u64,
    ) -> Result<aos_sandbox_protocol::host_recovered_namespace::HostRecoveryStopPhaseDataV7> {
        use aos_sandbox_protocol::host_recovered_namespace::HostRecoveryStopPhaseDataV7 as Phase;
        if self.cleanup.is_some() || self.scope.is_none() {
            return Err(refused());
        }
        use transition::{
            AuthorityFreshness, CompositeStopPhase, StopDecision, StopDecisionInput, StopProgress,
            UnitObservation, decide_composite_stop,
        };
        let phase = self.phase.as_ref().ok_or_else(refused)?;
        if matches!(phase, CompositeStopPhase::StopAuthorized) {
            // An unissued authorization is not renewed or fed into the effect
            // reducer. The read grant records only the fresh census's absence.
            return if observation != 0 {
                Ok(Phase::AuthorizedAbsent)
            } else {
                Err(refused())
            };
        }

        let decision = decide_composite_stop(StopDecisionInput {
            target: &self.target,
            phase,
            freshness: AuthorityFreshness::Expired,
            payload: UnitObservation::Absent,
            guardian: UnitObservation::Absent,
            observation_sequence: observation,
        });
        if !matches!(
            decision,
            StopDecision::HistoricalComplete
                | StopDecision::Persist(CompositeStopPhase::Complete { .. })
        ) {
            return Err(refused());
        }
        // The decision is comparison only. No phase, counter or receipt is
        // written under the RuntimeInventory read grant.
        Ok(match phase {
            CompositeStopPhase::Complete { .. } => Phase::Complete,
            CompositeStopPhase::StopEffectIssued { progress } => match progress {
                StopProgress::PayloadPending => Phase::PayloadPending,
                StopProgress::GuardianPending => Phase::GuardianPending,
                StopProgress::PayloadAwaitingAbsence => Phase::PayloadAwaitingAbsence,
                StopProgress::GuardianAwaitingAbsence => Phase::GuardianAwaitingAbsence,
            },
            CompositeStopPhase::StopAuthorized => return Err(refused()),
        })
    }
}

pub(super) fn receiving_bytes_v6() -> Option<usize> {
    let width = HOST_STOPPED_NAMESPACE_BYTES_V4;
    // Three State-model overlaps plus two canonical authentication encodings
    // and their allocation overlaps. JSON's decimal byte+comma width is four.
    width
        .checked_mul(2)?
        .checked_mul(3)?
        .checked_add(width.checked_mul(4)?.checked_mul(4)?)?
        .checked_add(std::mem::size_of::<HostStoppedNamespaceDataV4>().checked_mul(3)?)
}

impl HostState {
    /// Selects restrictive comparison geometry, never a native or semantic grant.
    pub(crate) fn native_inventory_pending_incarnation_data_v8(&self) -> Option<[u8; 16]> {
        if self.fences.len() != 1 {
            return None;
        }
        let current = self.fences.values().next()?;
        let request = self.requests.get(&current.witness_request_id)?;
        match &request.execution {
            DurableExecution::CompositeStop(record) => (!matches!(
                record.phase,
                transition::CompositeStopPhase::Complete { .. }
            ))
            .then_some(request.fence.incarnation_id),
            _ => self.requests.values().find_map(|row| {
                let DurableExecution::GuardianLaunch(record) = &row.execution else {
                    return None;
                };
                record.launch_namespace_history_v1.as_ref()?;
                matches!(
                    record.phase,
                    transition::GuardianLaunchPhase::Complete { .. }
                )
                .then_some(row.fence.incarnation_id)
            }),
        }
    }

    /// Selects the exact authenticated historical Stop census candidate.
    ///
    /// The caller prepays the complete traversal and joins the same protected
    /// snapshot to the actual native census. This method creates no native proof.
    ///
    /// # Errors
    /// Refuses missing association or unrelated
    /// runtime history, or a scope differing from its original Launch/Stop.
    pub(crate) fn historical_namespace_candidate_v7(
        &self,
        authority: &HostAuthorityV1,
    ) -> Result<HistoricalNamespaceCandidateV7> {
        let chains = self.validate_authenticated_cleanup_chains_v1(authority)?;
        if self.fences.len() != 1 || !self.fuse_worker_launches.is_empty() {
            return Err(refused());
        }
        let current = self.fences.values().next().ok_or_else(refused)?;
        let stop = self
            .requests
            .get(&current.witness_request_id)
            .ok_or_else(refused)?;
        let DurableExecution::CompositeStop(record) = &stop.execution else {
            return self.launch_ready_candidate_v1();
        };
        let scope = HostStoppedNamespaceDataV4::decode_v4(
            record.namespace_history_v6.as_deref().ok_or_else(refused)?,
        )?;
        let dispatched = record.cleanup_parent_v1.as_ref().is_some_and(|link|link.subject_v1().is_ok_and(|subject|
            subject.origin_v1() == aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupOriginDataV1::DispatchedBeforeHost));
        if dispatched {
            self.require_dispatched_namespace_history_v1(scope, stop, &chains)?;
        } else {
            let root = self.requests.get(&scope.stop_v4().0).ok_or_else(refused)?;
            self.require_stopped_namespace_history_v6(scope, root, stop, &chains)?;
            let effect = authority.open_effect(&root.request_id, &root.effect)?;
            if effect.host_boot_id() != scope.boot_v4() {
                return Err(refused());
            }
        }
        Ok(HistoricalNamespaceCandidateV7 {
            scope: Some(scope),
            launch: None,
            target: record.target.clone(),
            phase: Some(record.phase.clone()),
            cleanup: record
                .cleanup_parent_v1
                .as_ref()
                .map(|link| -> Result<CleanupLineageCandidateV1> {
                    Ok(CleanupLineageCandidateV1 {
                        subject: link.subject_v1()?,
                        child: link.request_identity_v1()?,
                        chain: chains.commitment_v1(&stop.request_id)?,
                    })
                })
                .transpose()?,
        })
    }

    fn require_dispatched_namespace_history_v1(
        &self,
        scope: HostStoppedNamespaceDataV4,
        leaf: &RequestRecord,
        chains: &VerifiedCleanupChainsV1,
    ) -> Result<()> {
        let launch = self
            .requests
            .get(&scope.launch_v4().0)
            .ok_or_else(refused)?;
        let target = completed_launch_target_v1(launch, &scope.launch_scope_v1())?;
        let DurableExecution::CompositeStop(record) = &leaf.execution else {
            return Err(refused());
        };
        if record.target != target || self.requests.contains_key(&scope.stop_v4().0)
            || self.requests.values().any(|row| {
                (row.receipt.is_none() && row.request_id != leaf.request_id && !chains.is_superseded_v1(&row.request_id))
                    || row.fence.sandbox_id != *scope.fence_v4().sandbox_id()
                    || row.fence.incarnation_id != *scope.fence_v4().incarnation_id()
                    || row.fence.assignment_epoch != scope.fence_v4().assignment_epoch()
                    || row.fence.assignment_digest != *scope.fence_v4().assignment_digest()
                    || (row.action == HostAction::Launch.code() && row.request_id != launch.request_id)
                    || (row.action == HostAction::Stop.code()
                        && !matches!(&row.execution, DurableExecution::CompositeStop(child)
                            if child.cleanup_parent_v1.as_ref().is_some_and(|link|
                                link.subject_v1().is_ok_and(|subject|subject.historical_scope_v1() == &scope
                                    && subject.origin_v1() == aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupOriginDataV1::DispatchedBeforeHost))))
            })
        { return Err(refused()); }
        Ok(())
    }

    fn launch_ready_candidate_v1(&self) -> Result<HistoricalNamespaceCandidateV7> {
        let current = self.fences.values().next().ok_or_else(refused)?;
        let mut launches = self
            .requests
            .values()
            .filter(|row| row.action == HostAction::Launch.code());
        let launch = launches.next().ok_or_else(refused)?;
        if launches.next().is_some()
            || self.requests.values().any(|row| {
                row.receipt.is_none()
                    || row.action == HostAction::Stop.code()
                    || row.fence.sandbox_id != launch.fence.sandbox_id
                    || row.fence.incarnation_id != launch.fence.incarnation_id
                    || row.fence.assignment_epoch != launch.fence.assignment_epoch
                    || row.fence.assignment_digest != launch.fence.assignment_digest
            })
            || current.sandbox_id != launch.fence.sandbox_id
            || current.incarnation_id != launch.fence.incarnation_id
            || current.assignment_epoch != launch.fence.assignment_epoch
            || current.assignment_digest != launch.fence.assignment_digest
            || current.desired_generation != launch.fence.desired_generation
        {
            return Err(refused());
        }
        let DurableExecution::GuardianLaunch(record) = &launch.execution else {
            return Err(refused());
        };
        let scope =
            aos_sandbox_protocol::host_stopped_namespace::HostLaunchNamespaceDataV1::decode_v1(
                record
                    .launch_namespace_history_v1
                    .as_deref()
                    .ok_or_else(refused)?,
            )?;
        let target = completed_launch_target_v1(launch, &scope)?;
        Ok(HistoricalNamespaceCandidateV7 {
            scope: None,
            launch: Some(scope),
            target,
            phase: None,
            cleanup: None,
        })
    }

    fn require_stopped_namespace_history_v6(
        &self,
        scope: HostStoppedNamespaceDataV4,
        stop: &RequestRecord,
        leaf: &RequestRecord,
        chains: &VerifiedCleanupChainsV1,
    ) -> Result<()> {
        let launch = self
            .requests
            .get(&scope.launch_v4().0)
            .ok_or_else(refused)?;
        let old = scope.fence_v4();
        let DurableExecution::GuardianLaunch(original) = &launch.execution else {
            return Err(refused());
        };
        let transition::GuardianLaunchPhase::Complete { worker_proof, .. } = &original.phase else {
            return Err(refused());
        };
        if &worker_proof.host_boot_id != scope.boot_v4()
            || scope.stop_v4().0 != stop.request_id
            || stop.action != HostAction::Stop.code()
            || launch.action != HostAction::Launch.code()
            || launch.receipt.is_none()
            || launch.fence.sandbox_id != *old.sandbox_id()
            || launch.fence.incarnation_id != *old.incarnation_id()
            || launch.fence.assignment_epoch != old.assignment_epoch()
            || launch.fence.desired_generation != old.desired_generation()
            || launch.fence.assignment_digest != *old.assignment_digest()
            || self.requests.values().any(|request| {
                (request.receipt.is_none() && request.request_id != leaf.request_id
                    && !chains.is_superseded_v1(&request.request_id))
                    || request.fence.sandbox_id != *old.sandbox_id()
                    || request.fence.incarnation_id != *old.incarnation_id()
                    || (request.action == HostAction::Launch.code()
                        && request.request_id != launch.request_id)
                    || (request.action == HostAction::Stop.code()
                        && request.request_id != stop.request_id
                        && !matches!(&request.execution, DurableExecution::CompositeStop(child)
                            if child.cleanup_parent_v1.as_ref().is_some_and(|link|
                                link.subject_v1().is_ok_and(|subject| subject.historical_scope_v1() == &scope))))
            })
        {
            return Err(refused());
        }
        Ok(())
    }
}

pub(super) fn completed_launch_target_v1(
    launch: &RequestRecord,
    scope: &aos_sandbox_protocol::host_stopped_namespace::HostLaunchNamespaceDataV1,
) -> Result<transition::CompositeStopTarget> {
    let DurableExecution::GuardianLaunch(record) = &launch.execution else {
        return Err(refused());
    };
    let transition::GuardianLaunchPhase::Complete {
        guardian_invocation,
        payload_invocation,
        worker_proof,
        ..
    } = &record.phase
    else {
        return Err(refused());
    };
    let fence = scope.fence_v1();
    if launch.action != HostAction::Launch.code()
        || launch.receipt.is_none()
        || scope.launch_v1().0 != launch.request_id
        || record.launch_namespace_history_v1.as_deref() != Some(scope.encode_v1().as_slice())
        || &worker_proof.host_boot_id != scope.boot_v1()
        || launch.fence.sandbox_id != *fence.sandbox_id()
        || launch.fence.incarnation_id != *fence.incarnation_id()
        || launch.fence.assignment_epoch != fence.assignment_epoch()
        || launch.fence.desired_generation != fence.desired_generation()
        || launch.fence.assignment_digest != *fence.assignment_digest()
    {
        return Err(refused());
    }
    let binding = launch.execution.guardian_binding().ok_or_else(refused)?;
    Ok(transition::CompositeStopTarget::GuardianComposite {
        source_launch_request_id: launch.request_id,
        incarnation_id: *fence.incarnation_id(),
        launch_binding: binding,
        payload: transition::StopUnitTarget::Exact {
            binding: Some(binding),
            invocation: *payload_invocation,
        },
        guardian: transition::StopUnitTarget::Exact {
            binding: Some(binding),
            invocation: *guardian_invocation,
        },
    })
}

fn refused() -> HostError {
    HostError::Fence(
        "Host historical namespace lacks its exact completed Launch and protected Stop association",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_history_preserves_old_canonical_execution_bytes() {
        let execution = DurableExecution::composite_stop_fixture();
        assert_eq!(
            serde_json::to_string(&execution).unwrap(),
            r#"{"kind":"composite_stop","state":{"target":{"shape":"absent"},"phase":{"phase":"stop_authorized"}}}"#
        );
    }

    fn pending_candidate() -> HistoricalNamespaceCandidateV7 {
        use transition::{CompositeStopPhase, CompositeStopTarget, StopUnitTarget};

        // Canonical AOSHNS04 test DATA; no validated-fence constructor or native
        // owner is exposed merely to build this passive comparison fixture.
        let mut bytes = [0; HOST_STOPPED_NAMESPACE_BYTES_V4];
        let runtime = aos_sandbox_protocol::semantics::host::runtime_handle_v1(&[3; 16], 4, &[6; 32]);
        let parts: [&[u8]; 15] = [b"AOSHNS04", &[1; 16], &[2; 16], &[3; 16],
            &4_u64.to_le_bytes(), &5_u64.to_le_bytes(), &[6; 32], &[7; 32], &runtime,
            &[8; 16], &[9; 32], &[10; 32], &[11; 16], &[12; 32], &[13; 32]];
        let mut offset = 0;
        for part in parts {
            bytes[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        }
        let scope = HostStoppedNamespaceDataV4::decode_v4(&bytes).unwrap();
        HistoricalNamespaceCandidateV7 {
            scope: Some(scope),
            launch: None,
            cleanup: None,
            target: CompositeStopTarget::GuardianComposite {
                source_launch_request_id: [8; 16],
                incarnation_id: [3; 16],
                launch_binding: [14; 32],
                payload: StopUnitTarget::Exact {
                    binding: Some([14; 32]),
                    invocation: [15; 16],
                },
                guardian: StopUnitTarget::Exact {
                    binding: Some([14; 32]),
                    invocation: [16; 16],
                },
            },
            phase: Some(CompositeStopPhase::StopAuthorized),
        }
    }

    #[test]
    fn cleanup_leaf_has_only_distinct_complete_lineage_projection() {
        use aos_sandbox_protocol::host_inventory_absence::HostInventoryAbsenceDataV5;
        use aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupSubjectDataV1;
        let mut candidate = pending_candidate();
        let subject = HostStopCleanupSubjectDataV1::from_data_v1(
            candidate.scope.unwrap(),
            [30; 16],
            [31; 16],
            [32; 32],
            [33; 16],
            [34; 32],
            1000,
        )
        .unwrap();
        candidate.cleanup = Some(CleanupLineageCandidateV1 {
            subject,
            child: ([31; 16], [35; 32], [36; 32]),
            chain: [37; 32],
        });
        let observation =
            HostInventoryAbsenceDataV5::from_data_v5([38; 16], [39; 16], [40; 16], 41, 42).unwrap();

        assert!(candidate.cleanup_lineage_data_v1(observation).is_err());
        assert!(candidate.absent_phase_v7(42).is_err());
        candidate.phase = Some(transition::CompositeStopPhase::Complete {
            observation_sequence: 42,
        });
        let lineage = candidate
            .cleanup_lineage_data_v1(observation)
            .unwrap()
            .unwrap();
        assert_eq!(
            Some(lineage.subject_v1().historical_scope_v1()),
            candidate.scope.as_ref()
        );
        assert_eq!(lineage.child_v1(), ([31; 16], [35; 32], [36; 32]));
        assert!(candidate.absent_phase_v7(42).is_err());
    }

    #[test]
    fn dispatched_child_preserves_launch_observation_until_its_own_completion() {
        use aos_sandbox_protocol::host_inventory_absence::HostInventoryAbsenceDataV5;
        use aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupSubjectDataV1;

        let mut candidate = pending_candidate();
        let scope = *candidate.stopped_scope_v1().unwrap();
        let subject = HostStopCleanupSubjectDataV1::from_dispatched_data_v2(
            scope.launch_scope_v1(),
            scope.stop_v4(),
            [30; 16],
            [31; 16],
            [32; 32],
            [33; 16],
            [34; 32],
            1000,
        )
        .unwrap();
        candidate.cleanup = Some(CleanupLineageCandidateV1 {
            subject,
            child: ([31; 16], [35; 32], [36; 32]),
            chain: [37; 32],
        });

        assert_eq!(
            candidate.dispatched_observation_scope_v1(),
            Some(scope.launch_scope_v1())
        );
        assert!(candidate.require_cleanup_subject_v2(&subject).is_ok());
        let protected_pending = HostStopCleanupSubjectDataV1::from_data_v1(
            scope, [30; 16], [31; 16], [32; 32], [33; 16], [34; 32], 1000,
        )
        .unwrap();
        assert!(
            candidate
                .require_cleanup_subject_v2(&protected_pending)
                .is_err()
        );
        assert!(candidate.absent_phase_v7(42).is_err());

        let absence =
            HostInventoryAbsenceDataV5::from_data_v5([38; 16], [39; 16], [40; 16], 41, 42).unwrap();
        assert!(candidate.cleanup_lineage_data_v1(absence).is_err());
        candidate.phase = Some(transition::CompositeStopPhase::Complete {
            observation_sequence: 42,
        });

        assert!(candidate.dispatched_observation_scope_v1().is_none());
        assert_eq!(
            candidate
                .cleanup_lineage_data_v1(absence)
                .unwrap()
                .unwrap()
                .subject_v1(),
            &subject
        );
        assert!(candidate.absent_phase_v7(42).is_err());
    }

    #[test]
    fn passive_present_comparison_requires_exact_old_target_and_never_calls_complete_present_absent() {
        use aos_systemd_client::{ExactUnitObservation, ExactUnitRole, ExactUnitState, PostUnrefUnitObservation};
        let candidate = pending_candidate();
        let observation = ExactUnitObservation {
            role: ExactUnitRole::Payload, object_path: "/payload".try_into().unwrap(),
            binding: Some([14; 32]), invocation_id: Some([15; 16]),
            active_state: "active".to_owned(), sub_state: "running".to_owned(),
            state: ExactUnitState::ActiveRunning,
            cgroup: Some(aos_systemd_client::SandboxUnitName::from_incarnation([3; 16]).cgroup_path()),
            main_pid: std::num::NonZeroU32::new(17),
        };
        let absent = PostUnrefUnitObservation::Absent;
        let present = PostUnrefUnitObservation::Present(observation.clone());
        assert_eq!(candidate.present_phase_v8(&present, &absent).unwrap(),
            aos_sandbox_protocol::host_stop_cleanup_candidate::HostStopCleanupSavedPhaseDataV1::Authorized);
        assert!(candidate.present_phase_v8(&absent, &absent).is_err());
        for change in 0..3 {
            let mut changed = observation.clone();
            match change {
                0 => changed.binding = Some([20; 32]),
                1 => changed.invocation_id = Some([21; 16]),
                _ => changed.role = ExactUnitRole::Guardian,
            }
            assert!(
                candidate
                    .present_phase_v8(&PostUnrefUnitObservation::Present(changed), &absent)
                    .is_err()
            );
        }
        let mut completed = candidate.clone();
        completed.phase = Some(transition::CompositeStopPhase::Complete {
            observation_sequence: 1,
        });
        assert!(completed.present_phase_v8(&present, &absent).is_err());
        let mut foreign = candidate;
        foreign.target = transition::CompositeStopTarget::Absent;
        assert!(foreign.present_phase_v8(&present, &absent).is_err());
    }
}
