//! Authenticates finite Stop cleanup ancestry without changing old records.
//!
//! Every link is covered by the existing CompositeStop execution MAC. A child
//! names one exact immutable parent; only a fully authenticated acyclic chain
//! permits ignoring superseded Pending ancestors. No link grants a new effect.

use super::*;
use aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupSubjectDataV1;
use sha2::{Digest as _, Sha256};

const CHAIN_DOMAIN: &[u8] = b"aos.host.stop-cleanup-chain.v1\0";
const RECORD_DOMAIN: &[u8] = b"aos.host.stop-cleanup-parent.v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CleanupParentDataV1 {
    version: u8,
    parent: [u8; 16],
    parent_digest: [u8; 32],
    subject: Vec<u8>,
    session: [u8; 32],
    signed: [u8; 32],
}

impl CleanupParentDataV1 {
    #[cfg(test)]
    pub(super) fn dispatched_fixture_v1(
        parent: &RequestRecord,
        subject: HostStopCleanupSubjectDataV1,
    ) -> Self {
        Self {
            version: 2,
            parent: parent.request_id,
            parent_digest: record_digest_v1(parent).unwrap(),
            subject: subject.encode_v1().to_vec(),
            session: [201; 32],
            signed: [202; 32],
        }
    }
    pub(super) fn parent_id_v1(&self) -> [u8; 16] {
        self.parent
    }
    pub(super) fn dynamic_bytes_v1(&self) -> usize {
        self.subject.capacity()
    }

    pub(super) fn validate_format_v1(&self) -> bool {
        self.subject_v1().is_ok_and(|subject| match (self.version, subject.origin_v1()) {
            (1, aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupOriginDataV1::ProtectedPending)
            | (2, aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupOriginDataV1::DispatchedBeforeHost) => true,
            _ => false,
        })
            && self.parent != [0; 16]
            && self.parent_digest != [0; 32]
            && self.session != [0; 32]
            && self.signed != [0; 32]
            && HostStopCleanupSubjectDataV1::decode_v1(&self.subject).is_ok()
    }

    pub(crate) fn subject_v1(&self) -> Result<HostStopCleanupSubjectDataV1> {
        HostStopCleanupSubjectDataV1::decode_v1(&self.subject).map_err(Into::into)
    }

    pub(crate) fn request_identity_v1(&self) -> Result<([u8; 16], [u8; 32], [u8; 32])> {
        Ok((
            *self.subject_v1()?.cleanup_request_v1(),
            self.session,
            self.signed,
        ))
    }
}

pub(super) struct CleanupAdmissionV1<'borrow, 'native> {
    pub(super) ownership: &'borrow crate::broker::HostCleanupNativeOwnershipV1<'native>,
    pub(super) request: &'borrow aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
}

pub(crate) struct VerifiedCleanupChainsV1 {
    children: BTreeMap<[u8; 16], [u8; 16]>,
    commitments: BTreeMap<[u8; 16], [u8; 32]>,
}

impl VerifiedCleanupChainsV1 {
    pub(crate) fn is_superseded_v1(&self, id: &[u8; 16]) -> bool {
        self.children.contains_key(id)
    }

    pub(crate) fn commitment_v1(&self, leaf: &[u8; 16]) -> Result<[u8; 32]> {
        if self.is_superseded_v1(leaf) {
            return Err(refused());
        }
        self.commitments.get(leaf).copied().ok_or_else(refused)
    }
}

struct CanonicalRecordHashV1(Sha256);

impl std::io::Write for CanonicalRecordHashV1 {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn record_digest_v1(record: &RequestRecord) -> Result<[u8; 32]> {
    let mut writer = CanonicalRecordHashV1(Sha256::new().chain_update(RECORD_DOMAIN));
    // The exact existing serde record schema supplies the bytes. Streaming
    // avoids a second owned record encoding or parser/archive.
    serde_json::to_writer(&mut writer, record).map_err(|_| refused())?;
    Ok(writer.0.finalize().into())
}

impl HostState {
    /// Admits only a fresh native-proven child of the current authenticated Stop.
    ///
    /// # Errors
    /// Refuses replay, a completed/foreign parent, changed history/ownership or
    /// inconsistent fresh subject. Ordinary Stop cannot select this exception.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_cleanup_stop_v1(
        &mut self,
        runtime: &aos_sandbox_protocol::ValidatedRuntimeRequest,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        request_digest: [u8; 32],
        ownership: &crate::broker::HostCleanupNativeOwnershipV1<'_>,
        sealed_fence: Vec<u8>,
        admitted: &VerifiedBrokerAdmission,
        sealed_effect: Vec<u8>,
        authority: &HostAuthorityV1,
    ) -> Result<Admission> {
        let subject = runtime.host_stop_cleanup_v1().ok_or_else(refused)?;
        let id = request.request_id();
        if self.requests.contains_key(&id)
            || runtime.header().request_id() != &id
            || admitted.effect.host_boot_id() != subject.current_boot_v1()
            || admitted.effect.request_id() != &id
            || admitted.effect.transport_request_digest().as_bytes() != &request_digest
            || <[u8; 32]>::from(Sha256::digest(request.exact_body())) != request_digest
        {
            return Err(refused());
        }
        subject.require_request_data_v1(
            &id,
            runtime.fence(),
            request.deadline_boottime_nanoseconds(),
        )?;
        let candidate = self.historical_namespace_candidate_v7(authority)?;
        candidate.require_cleanup_subject_v2(subject)?;
        ownership.require_current_target_v1(&candidate, request)?;
        let parent_id = match candidate.launch_only_scope_v1() {
            Some(scope) => scope.launch_v1().0,
            None => {
                self.fences
                    .get(runtime.fence().sandbox_id())
                    .ok_or_else(refused)?
                    .witness_request_id
            }
        };
        let parent = self.requests.get(&parent_id).ok_or_else(refused)?;
        // Native full-ownership/absence and both protected reads matched before
        // the effect-bearing target/progress are cloned into the new child.
        let mut execution = match candidate.launch_only_scope_v1() {
            Some(scope) => {
                if self
                    .requests
                    .contains_key(&subject.historical_scope_v1().stop_v4().0)
                {
                    return Err(refused());
                }
                historical_namespace::completed_launch_target_v1(parent, scope)?;
                transition::CompositeStopRecord {
                    target: candidate.fresh_launch_stop_target_v1()?,
                    phase: transition::CompositeStopPhase::StopAuthorized,
                    namespace_history_v6: Some(subject.historical_scope_v1().encode_v4().to_vec()),
                    cleanup_parent_v1: None,
                }
            }
            None => {
                let DurableExecution::CompositeStop(parent_stop) = &parent.execution else {
                    return Err(refused());
                };
                if parent.receipt.is_some()
                    || matches!(
                        parent_stop.phase,
                        transition::CompositeStopPhase::Complete { .. }
                    )
                {
                    return Err(refused());
                }
                parent_stop.clone()
            }
        };
        execution.cleanup_parent_v1 = Some(CleanupParentDataV1 {
            version: match subject.origin_v1() {
                aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupOriginDataV1::ProtectedPending => 1,
                aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupOriginDataV1::DispatchedBeforeHost => 2,
            },
            parent: parent_id,
            parent_digest: record_digest_v1(parent)?,
            subject: subject.encode_v1().to_vec(),
            session: request.session_binding(),
            signed: request.signed_request_digest(),
        });
        self.admit_specialized_execution_engine_v1(
            HostAction::Stop,
            runtime.fence(),
            id,
            request_digest,
            DurableExecution::CompositeStop(execution),
            sealed_fence,
            admitted,
            sealed_effect,
            authority,
            Some(CleanupAdmissionV1 { ownership, request }),
        )
    }

    pub(super) fn validate_cleanup_chains_v1(&self) -> Result<VerifiedCleanupChainsV1> {
        let mut result = VerifiedCleanupChainsV1 {
            children: BTreeMap::new(),
            commitments: BTreeMap::new(),
        };
        for (child_id, child) in &self.requests {
            let DurableExecution::CompositeStop(child_stop) = &child.execution else {
                continue;
            };
            let Some(link) = child_stop.cleanup_parent_v1.as_ref() else {
                continue;
            };
            let subject = link.subject_v1()?;
            let parent = self.requests.get(&link.parent).ok_or_else(refused)?;
            match &parent.execution {
                DurableExecution::GuardianLaunch(_) => {
                    if link.version != 2
                        || link.parent != subject.historical_scope_v1().launch_v4().0
                        || self
                            .requests
                            .contains_key(&subject.historical_scope_v1().stop_v4().0)
                        || child_stop.target
                            != historical_namespace::completed_launch_target_v1(
                                parent,
                                &subject.historical_scope_v1().launch_scope_v1(),
                            )?
                    {
                        return Err(refused());
                    }
                }
                DurableExecution::CompositeStop(parent_stop) => {
                    if parent.action != HostAction::Stop.code()
                        || parent.receipt.is_some()
                        || child_stop.target != parent_stop.target
                        || child_stop.namespace_history_v6 != parent_stop.namespace_history_v6
                        || phase_order(&child_stop.phase) < phase_order(&parent_stop.phase)
                    {
                        return Err(refused());
                    }
                    if let Some(parent_link) = parent_stop.cleanup_parent_v1.as_ref() {
                        let parent_subject = parent_link.subject_v1()?;
                        if parent_subject.historical_scope_v1() != subject.historical_scope_v1()
                            || parent_subject.origin_v1() != subject.origin_v1()
                        {
                            return Err(refused());
                        }
                    } else if link.version != 1
                        || parent.request_id != subject.historical_scope_v1().stop_v4().0
                    {
                        return Err(refused());
                    }
                }
                _ => return Err(refused()),
            }
            let old = subject.historical_scope_v1().fence_v4();
            if !link.validate_format_v1()
                || child_id != subject.cleanup_request_v1()
                || child.action != HostAction::Stop.code()
                || *child_id == link.parent
                || child_stop.namespace_history_v6.as_deref()
                    != Some(subject.historical_scope_v1().encode_v4().as_slice())
                || child.fence.sandbox_id != parent.fence.sandbox_id
                || child.fence.incarnation_id != parent.fence.incarnation_id
                || child.fence.assignment_epoch != parent.fence.assignment_epoch
                || child.fence.assignment_digest != parent.fence.assignment_digest
                || child.fence.sandbox_id != *old.sandbox_id()
                || child.fence.incarnation_id != *old.incarnation_id()
                || child.fence.assignment_epoch != old.assignment_epoch()
                || child.fence.assignment_digest != *old.assignment_digest()
                || child.fence.desired_generation < old.desired_generation()
                || record_digest_v1(parent)? != link.parent_digest
                || result.children.insert(link.parent, *child_id).is_some()
            {
                return Err(refused());
            }
            parent.fence.validate_successor(&child.fence)?;
        }
        if result.children.is_empty() {
            return Ok(result);
        }

        let mut seen = BTreeSet::new();
        for (root_id, root) in &self.requests {
            let child_link = match &root.execution {
                DurableExecution::CompositeStop(stop) => stop.cleanup_parent_v1.is_some(),
                _ => false,
            };
            if child_link {
                continue;
            }
            let mut current = *root_id;
            let mut commitment: [u8; 32] = Sha256::new()
                .chain_update(CHAIN_DOMAIN)
                .chain_update(record_digest_v1(root)?)
                .finalize()
                .into();
            // Every node is visited once globally. The installed finite State
            // row limit bounds the walk; there is no new unchecked counter.
            for _ in 0..=self.requests.len() {
                if !seen.insert(current) {
                    return Err(refused());
                }
                result.commitments.insert(current, commitment);
                let Some(child) = result.children.get(&current).copied() else {
                    break;
                };
                let record = self.requests.get(&child).ok_or_else(refused)?;
                commitment = Sha256::new()
                    .chain_update(CHAIN_DOMAIN)
                    .chain_update(commitment)
                    .chain_update(record_digest_v1(record)?)
                    .finalize()
                    .into();
                current = child;
            }
        }
        if seen.len() != self.requests.len() {
            return Err(refused());
        }
        Ok(result)
    }

    pub(super) fn require_not_superseded_cleanup_v1(&self, id: &[u8; 16]) -> Result<()> {
        // This refusal-only gate cannot grant an ancestor exception. Positive
        // admission separately authenticates the entire chain first.
        if self
            .requests
            .values()
            .any(|request| match &request.execution {
                DurableExecution::CompositeStop(stop) => stop
                    .cleanup_parent_v1
                    .as_ref()
                    .is_some_and(|link| &link.parent == id),
                _ => false,
            })
        {
            return Err(refused());
        }
        Ok(())
    }
}

fn refused() -> HostError {
    HostError::Fence(
        "Host cleanup chain has a missing, changed, cyclic, sibling or superseded target",
    )
}

fn phase_order(phase: &transition::CompositeStopPhase) -> u8 {
    use transition::{CompositeStopPhase as Phase, StopProgress};
    match phase {
        Phase::StopAuthorized => 0,
        Phase::StopEffectIssued {
            progress: StopProgress::PayloadPending,
        } => 1,
        Phase::StopEffectIssued {
            progress: StopProgress::PayloadAwaitingAbsence,
        } => 2,
        Phase::StopEffectIssued {
            progress: StopProgress::GuardianPending,
        } => 3,
        Phase::StopEffectIssued {
            progress: StopProgress::GuardianAwaitingAbsence,
        } => 4,
        Phase::Complete { .. } => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transition::{
        CompositeStopPhase as Phase, CompositeStopRecord, CompositeStopTarget, StopProgress,
        StopUnitTarget,
    };

    fn old_scope() -> aos_sandbox_protocol::host_stopped_namespace::HostStoppedNamespaceDataV4 {
        let runtime =
            aos_sandbox_protocol::semantics::host::runtime_handle_v1(&[3; 16], 4, &[6; 32]);
        let mut bytes = [0; 328];
        let mut offset = 0;
        for part in [
            b"AOSHNS04".as_slice(),
            &[1; 16],
            &[2; 16],
            &[3; 16],
            &4_u64.to_le_bytes(),
            &5_u64.to_le_bytes(),
            &[6; 32],
            &[7; 32],
            &runtime,
            &[8; 16],
            &[9; 32],
            &[10; 32],
            &[11; 16],
            &[12; 32],
            &[13; 32],
        ] {
            bytes[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        }
        aos_sandbox_protocol::host_stopped_namespace::HostStoppedNamespaceDataV4::decode_v4(&bytes)
            .unwrap()
    }

    fn root() -> HostState {
        let scope = old_scope();
        let id = scope.stop_v4().0;
        let fence = DurableFence {
            witness_request_id: id,
            sandbox_id: [2; 16],
            incarnation_id: [3; 16],
            assignment_epoch: 4,
            desired_generation: 5,
            assignment_digest: [6; 32],
            authorization: vec![1],
            base_authorization: None,
        };
        let record = RequestRecord {
            request_id: id,
            request_digest: [30; 32],
            fence: fence.clone(),
            action: HostAction::Stop.code(),
            execution: DurableExecution::CompositeStop(CompositeStopRecord {
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
                phase: Phase::StopEffectIssued {
                    progress: StopProgress::PayloadPending,
                },
                namespace_history_v6: Some(scope.encode_v4().to_vec()),
                cleanup_parent_v1: None,
            }),
            execution_authentication: vec![31],
            effect: vec![32],
            receipt: None,
        };
        let mut state = HostState::default();
        state.fences.insert(fence.sandbox_id, fence);
        state.requests.insert(id, record);
        state
    }

    // These specimens exercise only structural chain validation. Their dummy
    // MACs cannot pass validate_authenticated and confer no effect permission.
    fn child(state: &mut HostState, parent: [u8; 16], id: [u8; 16]) {
        let old = state.requests.get(&parent).unwrap();
        let digest = record_digest_v1(old).unwrap();
        let mut next = old.clone();
        next.request_id = id;
        next.fence.witness_request_id = id;
        let subject = HostStopCleanupSubjectDataV1::from_data_v1(
            old_scope(),
            [40; 16],
            id,
            [41; 32],
            [42; 16],
            [43; 32],
            1000,
        )
        .unwrap();
        let DurableExecution::CompositeStop(stop) = &mut next.execution else {
            unreachable!();
        };
        stop.cleanup_parent_v1 = Some(CleanupParentDataV1 {
            version: 1,
            parent,
            parent_digest: digest,
            subject: subject.encode_v1().to_vec(),
            session: [44; 32],
            signed: [45; 32],
        });
        state
            .fences
            .insert(next.fence.sandbox_id, next.fence.clone());
        state.requests.insert(id, next);
    }

    #[test]
    fn verified_finite_chain_keeps_ancestors_immutable_and_only_leaf_current() {
        let mut state = root();
        let original = state.requests[&[11; 16]].clone();
        child(&mut state, [11; 16], [50; 16]);
        let intermediate = state.requests[&[50; 16]].clone();
        child(&mut state, [50; 16], [51; 16]);

        let verified = state.validate_cleanup_chains_v1().unwrap();
        assert!(verified.is_superseded_v1(&[11; 16]));
        assert!(verified.is_superseded_v1(&[50; 16]));
        assert!(!verified.is_superseded_v1(&[51; 16]));
        assert!(verified.commitment_v1(&[11; 16]).is_err());
        assert_ne!(verified.commitment_v1(&[51; 16]).unwrap(), [0; 32]);
        assert!(state.require_not_superseded_cleanup_v1(&[11; 16]).is_err());
        assert_eq!(state.requests[&[11; 16]], original);
        assert_eq!(state.requests[&[50; 16]], intermediate);
    }

    #[test]
    fn sibling_missing_changed_parent_and_progress_regression_are_refused() {
        let mut state = root();
        child(&mut state, [11; 16], [50; 16]);
        child(&mut state, [11; 16], [51; 16]);
        assert!(state.validate_cleanup_chains_v1().is_err());
        state.requests.remove(&[51; 16]);
        assert!(state.validate_cleanup_chains_v1().is_ok());

        let mut missing = state.clone();
        missing.requests.remove(&[11; 16]);
        assert!(missing.validate_cleanup_chains_v1().is_err());

        let mut changed = state.clone();
        changed.requests.get_mut(&[11; 16]).unwrap().effect.push(9);
        assert!(changed.validate_cleanup_chains_v1().is_err());

        let DurableExecution::CompositeStop(stop) =
            &mut state.requests.get_mut(&[50; 16]).unwrap().execution
        else {
            unreachable!();
        };
        stop.phase = Phase::StopAuthorized;
        assert!(state.validate_cleanup_chains_v1().is_err());
    }

    #[test]
    fn foreign_target_and_cycle_cannot_become_an_ancestor_exception() {
        let mut state = root();
        child(&mut state, [11; 16], [50; 16]);
        let mut foreign = state.clone();
        let DurableExecution::CompositeStop(stop) =
            &mut foreign.requests.get_mut(&[50; 16]).unwrap().execution
        else {
            unreachable!();
        };
        stop.target = CompositeStopTarget::Absent;
        assert!(foreign.validate_cleanup_chains_v1().is_err());

        let DurableExecution::CompositeStop(stop) =
            &mut state.requests.get_mut(&[50; 16]).unwrap().execution
        else {
            unreachable!();
        };
        stop.cleanup_parent_v1.as_mut().unwrap().parent = [50; 16];
        assert!(state.validate_cleanup_chains_v1().is_err());
    }

    #[test]
    fn dispatched_origin_cannot_relabel_an_existing_protected_pending_root() {
        let mut state = root();
        child(&mut state, [11; 16], [50; 16]);
        let DurableExecution::CompositeStop(stop) =
            &mut state.requests.get_mut(&[50; 16]).unwrap().execution
        else {
            unreachable!()
        };
        let link = stop.cleanup_parent_v1.as_mut().unwrap();
        link.version = 2;
        assert!(!link.validate_format_v1());
        let subject = HostStopCleanupSubjectDataV1::from_dispatched_data_v2(
            old_scope().launch_scope_v1(),
            old_scope().stop_v4(),
            [40; 16],
            [50; 16],
            [41; 32],
            [42; 16],
            [43; 32],
            1000,
        )
        .unwrap();
        link.subject = subject.encode_v1().to_vec();
        assert!(link.validate_format_v1());
        assert!(state.validate_cleanup_chains_v1().is_err());
    }
}
