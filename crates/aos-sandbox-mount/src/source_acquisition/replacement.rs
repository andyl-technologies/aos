//! Authenticated idle SourceProvider session replacement for AOSMSA02.
//!
//! Replacement preserves stable scope, Inventory floor, observation ordinal,
//! projection, and holder-wide acquisition sequence. Only session-scoped
//! request/response heads reset to one, and cached reconciliation is invalidated.

use aos_sandbox::journal::ProtectedJournalAuthority;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::mount_source_acquisition_state::{
    MountSourceAcquisitionStateError, prepare_dead_replacement_v2,
    validate_provider_session_successor_v2,
};
use aos_sandbox_source_provider_security::{
    CurrentRootMountSourceProviderSessionV1, DeadProviderExecutionV1, ProviderExecutionDeathKindV2,
};

use super::format::{
    MutationTagV2, death_digest, materialized_record as record_bytes, provider_head_key,
    provider_session_key, put_record, state_error,
};
use super::model::*;
use super::reservation::{sealed_attempt, sealed_head, sealed_row};
use super::security::session_from_projection;
use super::transition::{MutationIdentityV2, commit_mutation, next_revision, record_ref, seal};
use super::{
    FixedMountSourceAcquisitionOwnerV2, SourceAcquisitionTableV2, install_and_retire_kind2_table,
};
use crate::Result;

impl FixedMountSourceAcquisitionOwnerV2<'_> {
    /// Joins a fresh authenticated carrier to the protected predecessor head.
    ///
    /// A pending request refuses here: only the Broker's absent-runtime entry
    /// can perform cold kind5 abandonment without losing opaque custody. An idle
    /// barrier preserves its predecessor until signed terminal settlement.
    ///
    /// # Errors
    ///
    /// Rejects multiple scopes, changed protected state, unproven predecessor
    /// death, or an invalid successor projection.
    #[doc(hidden)]
    pub fn establish_startup_provider_successor_v2(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    ) -> Result<()> {
        self.require_no_original_native_flight()?;
        // A live owner cannot abandon pending requests without retaining their
        // opaque custody. Only the Broker's absent-runtime kind5 entry may use
        // cold scheduling derivation.
        if self
            .runtime
            .table
            .provider_heads
            .values()
            .any(|head| head.pending_attempt.is_some())
        {
            return Err(state_error(
                "pending startup replacement requires the fresh-cold kind5 entry",
            ));
        }
        if self
            .runtime
            .table
            .provider_heads
            .values()
            .any(|head| head.recovery_barrier.is_some())
        {
            return self.establish_kind2_barrier_idle_successor_v4(root);
        }
        root.with_current_session(|session| {
            self.with_source_acquisition_authority(|table, authority| {
                authority.with_authority(|journal| {
                    let mut heads = table.provider_heads.values();
                    let Some(head) = heads.next().cloned() else {
                        return Ok(());
                    };
                    if heads.next().is_some() {
                        return Err(state_error(
                            "startup provider successor has multiple protected scopes",
                        ));
                    }
                    let predecessor = table
                        .provider_sessions
                        .get(&head.current_session_id)
                        .filter(|value| value.record_digest == head.current_session_record_digest)
                        .ok_or_else(|| {
                            state_error("startup provider predecessor session is absent")
                        })?;
                    if session
                        .current_session_id_v2()
                        .map_err(|_| state_error("startup Provider session is stale"))?
                        .as_bytes()
                        == &predecessor.session_binding
                    {
                        return Ok(());
                    }
                    table.replace_idle_provider_session_v2(
                        journal,
                        session,
                        head.scope.holder_authority_id,
                        head.scope.provider_authority_id,
                    )
                })
            })
        })
        .map_err(|_| state_error("Root-Mount successor handshake is not current"))?
        .ok_or_else(|| state_error("Root-Mount successor handshake is pending"))?
    }

    fn establish_kind2_barrier_idle_successor_v4(
        &mut self,
        root: &mut aos_sandbox_source_provider_security::RootMountSourceProviderOwnerV1,
    ) -> Result<()> {
        let mut writer = self
            .protected
            .root_local_recovery_authority_v4()
            .map_err(|error| state_error(&error.to_string()))?;
        let table = &mut self.runtime.table;
        // Cold local metadata is installed under this actual owner before its
        // floor can disappear. No historical live plan is reconstructed.
        install_and_retire_kind2_table(table, &mut writer, None)?;
        root.with_current_session(|session| {
            let mut heads = table.provider_heads.values();
            let head = heads
                .next()
                .cloned()
                .ok_or_else(|| state_error("kind2 Head is absent"))?;
            if heads.next().is_some() {
                return Err(state_error("kind2 successor has multiple scopes"));
            }
            let predecessor = table
                .provider_sessions
                .get(&head.current_session_id)
                .filter(|value| value.record_digest == head.current_session_record_digest)
                .cloned()
                .ok_or_else(|| state_error("kind2 predecessor Session is absent"))?;
            if session
                .current_session_id_v2()
                .map_err(|_| state_error("kind2 Session is stale"))?
                .as_bytes()
                == &predecessor.session_binding
            {
                return Ok(());
            }
            let guard = writer.security_view();
            let death = session
                .try_prove_mount_provider_execution_dead_v2(
                    guard,
                    &guard.snapshot()?,
                    &provider_session_key(predecessor.session_id),
                    &record_bytes(StoredRecordV2::ProviderSession {
                        value: predecessor.clone(),
                    })?,
                )
                .map_err(|_| state_error("kind2 predecessor liveness is indeterminate"))?;
            let (plan, successor, expected_head) = table.prepare_barrier_idle_session_v4(
                guard,
                session,
                death,
                head.scope.holder_authority_id,
                head.scope.provider_authority_id,
            )?;
            let readback = session
                .with_barrier_idle_replacement_v4(&mut writer, plan, |projection, writer| {
                    let mut actual =
                        session_from_projection(projection, Some(predecessor.session_id))?;
                    actual.barrier_idle_replacement = successor.barrier_idle_replacement.clone();
                    actual.record_digest = [0; 32];
                    let actual = match seal(StoredRecordV2::ProviderSession { value: actual })? {
                        StoredRecordV2::ProviderSession { value } => value,
                        _ => return Err(state_error("kind2 sealed Session changed kind")),
                    };
                    if actual != successor {
                        return Err(state_error("kind2 current plan projection changed"));
                    }
                    let prepared = writer.prepare_barrier_idle_replacement(actual)?;
                    let readback = writer
                        .commit_barrier_idle_replacement(prepared)
                        .map_err(crate::MountError::from)?;
                    let current = writer.current_source_state()?;
                    if current.provider_heads.get(&(
                        head.scope.holder_authority_id,
                        head.scope.provider_authority_id,
                    )) != Some(&expected_head)
                    {
                        return Err(state_error(
                            "kind2 protected Head differs from actual owner proposal",
                        ));
                    }
                    Ok(readback)
                })
                .map_err(|_| state_error("kind2 current plan consumption failed"))??;
            // Revalidate live custody after CAS and before the trusted owner's
            // installation/DELETE sequence. A failure retains the local floor.
            if session
                .current_session_id_v2()
                .map_err(|_| state_error("kind2 post-CAS custody is stale"))?
                .as_bytes()
                != &successor.session_binding
            {
                return Err(state_error(
                    "kind2 installed Session is not current custody",
                ));
            }
            install_and_retire_kind2_table(table, &mut writer, Some(readback))
        })
        .map_err(|_| state_error("kind2 Root custody is stale"))?
        .ok_or_else(|| state_error("kind2 Root handshake is pending"))?
    }
}

impl SourceAcquisitionTableV2 {
    /// Replaces an idle recovery carrier without releasing its barrier.
    ///
    /// # Errors
    ///
    /// Rejects a changed protected head, indeterminate predecessor execution,
    /// an unrelated recovery root, or a successor that rolls back authority.
    #[doc(hidden)]
    pub(crate) fn replace_barrier_idle_session_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        live_successor: &mut CurrentRootMountSourceProviderSessionV1,
        predecessor_death: Option<DeadProviderExecutionV1>,
        holder_authority_id: [u8; 16],
        provider_authority_id: [u8; 16],
    ) -> Result<()> {
        let (_, successor, next_head) = self.prepare_barrier_idle_session_v4(
            journal,
            live_successor,
            predecessor_death,
            holder_authority_id,
            provider_authority_id,
        )?;
        commit_mutation(
            self,
            journal,
            MutationIdentityV2 {
                tag: MutationTagV2::BarrierIdleReplacement,
                holder_id: holder_authority_id,
                provider_id: provider_authority_id,
                next_holder_sequence_revision: self
                    .holder_sequences
                    .get(&holder_authority_id)
                    .map_or(0, |value| value.revision),
                next_head_revision: next_head.revision,
                acquisition_id: None,
                next_row_revision: None,
                attempt_id: None,
                next_attempt_revision: None,
                session_id: Some(successor.session_id),
            },
            vec![
                StoredRecordV2::ProviderSession { value: successor },
                StoredRecordV2::ProviderHead { value: next_head },
            ],
        )
    }

    fn prepare_barrier_idle_session_v4(
        &self,
        journal: &ProtectedJournalAuthority<'_>,
        live_successor: &mut CurrentRootMountSourceProviderSessionV1,
        predecessor_death: Option<DeadProviderExecutionV1>,
        holder_authority_id: [u8; 16],
        provider_authority_id: [u8; 16],
    ) -> Result<(
        aos_sandbox_source_provider_security::CurrentMountProviderSessionPlanV2,
        SourceProviderSessionV2,
        SourceProviderHeadV2,
    )> {
        let identity = (holder_authority_id, provider_authority_id);
        let current_head = self
            .provider_heads
            .get(&identity)
            .filter(|head| {
                head.pending_attempt.is_none()
                    && head.next_request_sequence == head.next_response_sequence
                    && head
                        .recovery_barrier
                        .as_ref()
                        .is_some_and(|barrier| barrier.recovery_inventory_tail.is_none())
            })
            .cloned()
            .ok_or_else(|| state_error("barrier-idle predecessor head is absent"))?;
        let barrier = current_head
            .recovery_barrier
            .as_ref()
            .ok_or_else(|| state_error("barrier-idle recovery barrier is absent"))?;
        let root = self
            .provider_attempts
            .get(&barrier.root_attempt.id)
            .filter(|attempt| {
                attempt.revision == barrier.root_attempt.revision
                    && attempt.record_digest == barrier.root_attempt.record_digest
                    && matches!(
                        attempt.state,
                        ProviderAttemptStateV2::AbandonedIndeterminate {
                            resolution: None,
                            ..
                        }
                    )
                    && matches!(attempt.owner, ProviderQueryOwnerV2::Acquire { .. })
                    && attempt.method == ProviderMethodV2::Acquire
            })
            .ok_or_else(|| state_error("barrier-idle native root is not abandoned"))?;
        let ProviderQueryOwnerV2::Acquire { acquisition_id } = root.owner else {
            return Err(state_error("barrier-idle recovery root is not Acquire"));
        };
        if self.acquisitions.get(&acquisition_id).is_none_or(|row| {
            row.phase != SourceAcquisitionPhaseV2::PendingQuery
                || row.acquire_lineage.root != barrier.root_attempt
                || row.acquire_lineage.tail != barrier.root_attempt
                || !matches!(
                    row.recovery,
                    AcquisitionRecoveryV2::InventoryRequired { root_attempt }
                        if root_attempt == barrier.root_attempt
                )
        }) {
            return Err(state_error(
                "barrier-idle acquisition is not the native root",
            ));
        }
        let predecessor = self
            .provider_sessions
            .get(&current_head.current_session_id)
            .filter(|session| session.record_digest == current_head.current_session_record_digest)
            .cloned()
            .ok_or_else(|| state_error("barrier-idle predecessor session is absent"))?;
        let (protected_death, predecessor_observation) = match predecessor_death {
            Some(death) => {
                let (protected, durable) = durable_death_for_predecessor(&predecessor, death)?;
                (
                    Some(protected),
                    BarrierIdlePredecessorObservationV2::Dead { execution: durable },
                )
            }
            None => (None, BarrierIdlePredecessorObservationV2::Live),
        };
        let plan = live_successor
            .barrier_idle_replacement_mount_provider_session_plan_v2(
                journal,
                journal.snapshot()?,
                provider_head_key(holder_authority_id, provider_authority_id),
                record_bytes(StoredRecordV2::ProviderHead {
                    value: current_head.clone(),
                })?,
                provider_session_key(predecessor.session_id),
                record_bytes(StoredRecordV2::ProviderSession {
                    value: predecessor.clone(),
                })?,
                ObjectDigest::from_bytes(predecessor.session_id),
                ObjectDigest::from_bytes(predecessor.session_binding),
                protected_death,
                current_head.next_request_sequence,
                current_head.next_response_sequence,
            )
            .map_err(|_| state_error("barrier-idle successor planning failed"))?;
        let mut successor = session_from_projection(plan.session(), Some(predecessor.session_id))?;
        validate_successor(&predecessor, &successor, &self.provider_sessions)?;
        let replacement_count = barrier
            .replacement_count
            .checked_add(1)
            .ok_or_else(|| state_error("barrier-idle replacement count is exhausted"))?;
        successor.barrier_idle_replacement = Some(BarrierIdleReplacementWitnessV2 {
            root_attempt: barrier.root_attempt,
            predecessor_head: Box::new(current_head.clone()),
            replacement_count,
            predecessor_observation,
        });
        successor.record_digest = [0; 32];
        let successor = match seal(StoredRecordV2::ProviderSession { value: successor })? {
            StoredRecordV2::ProviderSession { value } => value,
            _ => return Err(state_error("sealed barrier-idle successor changed kind")),
        };

        let mut next_head = current_head.clone();
        next_head.revision = next_revision(current_head.revision)?;
        next_head.holder_authority_generation = successor.root_mount_authority_generation;
        next_head.holder_authority_digest = successor.root_mount_authority_digest;
        next_head.provider_authority_generation = successor.provider_authority_generation;
        next_head.provider_authority_digest = successor.provider_authority_digest;
        next_head.current_session_id = successor.session_id;
        next_head.current_session_record_digest = successor.record_digest;
        next_head.next_request_sequence = 1;
        next_head.next_response_sequence = 1;
        next_head.last_reconciliation = None;
        next_head.recovery_barrier = Some(RecoveryBarrierV2 {
            required_session_id: successor.session_id,
            replacement_count,
            ..barrier.clone()
        });
        next_head.record_digest = [0; 32];
        let next_head = sealed_head(next_head)?;
        Ok((plan, successor, next_head))
    }

    /// Supersedes one exact pending attempt for provider-owned backend recovery.
    #[doc(hidden)]
    pub(crate) fn replace_backend_recovery_session_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        live_successor: &mut CurrentRootMountSourceProviderSessionV1,
        attempt_id: [u8; 32],
    ) -> Result<([u8; 32], u64, [u8; 32], ProviderMethodV2)> {
        let current_attempt = self
            .provider_attempts
            .get(&attempt_id)
            .filter(|attempt| matches!(attempt.state, ProviderAttemptStateV2::Reserved))
            .cloned()
            .ok_or_else(|| state_error("backend recovery attempt is not reserved"))?;
        let identity = (
            current_attempt.scope.holder_authority_id,
            current_attempt.scope.provider_authority_id,
        );
        let current_head = self
            .provider_heads
            .get(&identity)
            .filter(|head| head.pending_attempt.map(|value| value.id) == Some(attempt_id))
            .cloned()
            .ok_or_else(|| state_error("backend recovery head is not pending"))?;
        let predecessor = self
            .provider_sessions
            .get(&current_head.current_session_id)
            .filter(|session| session.record_digest == current_head.current_session_record_digest)
            .cloned()
            .ok_or_else(|| state_error("backend recovery predecessor session is absent"))?;
        let plan = live_successor
            .recovery_replacement_mount_provider_session_plan_v2(
                journal,
                journal.snapshot()?,
                provider_head_key(identity.0, identity.1),
                record_bytes(StoredRecordV2::ProviderHead {
                    value: current_head.clone(),
                })?,
                provider_session_key(predecessor.session_id),
                record_bytes(StoredRecordV2::ProviderSession {
                    value: predecessor.clone(),
                })?,
                ObjectDigest::from_bytes(predecessor.session_id),
                ObjectDigest::from_bytes(predecessor.session_binding),
                current_head.next_request_sequence,
                current_head.next_response_sequence,
            )
            .map_err(|_| state_error("protected backend recovery replacement planning failed"))?;
        let successor = session_from_projection(plan.session(), Some(predecessor.session_id))?;
        validate_successor(&predecessor, &successor, &self.provider_sessions)?;

        let mut next_attempt = current_attempt.clone();
        next_attempt.revision = next_revision(current_attempt.revision)?;
        next_attempt.state = ProviderAttemptStateV2::SupersededIndeterminate {
            successor_session_id: successor.session_id,
            recovery_root_attempt_id: current_attempt.lineage_root_attempt_id,
            outcome_may_exist: true,
        };
        next_attempt.record_digest = [0; 32];
        let next_attempt = sealed_attempt(next_attempt)?;
        let next_attempt_ref = record_ref(&StoredRecordV2::ProviderQueryAttempt {
            value: next_attempt.clone(),
        })?;
        let acquisition_id = current_attempt.owner.owner_id();
        let mut next_row = self
            .acquisitions
            .get(&acquisition_id)
            .cloned()
            .ok_or_else(|| state_error("backend recovery owner row is absent"))?;
        next_row.revision = next_revision(next_row.revision)?;
        match current_attempt.method {
            ProviderMethodV2::Acquire => {
                if next_row.acquire_lineage.root.id == current_attempt.attempt_id {
                    next_row.acquire_lineage.root = next_attempt_ref;
                }
                next_row.acquire_lineage.tail = next_attempt_ref;
            }
            ProviderMethodV2::Release => {
                next_row
                    .release_lineage
                    .as_mut()
                    .ok_or_else(|| state_error("backend recovery Release lineage is absent"))?
                    .tail = next_attempt_ref;
            }
            ProviderMethodV2::Inventory => {
                return Err(state_error(
                    "backend recovery attempt has no acquisition owner",
                ));
            }
        }
        next_row.recovery = AcquisitionRecoveryV2::Ready;
        next_row.record_digest = [0; 32];
        let next_row = sealed_row(next_row)?;

        let mut next_head = current_head.clone();
        next_head.revision = next_revision(current_head.revision)?;
        next_head.holder_authority_generation = successor.root_mount_authority_generation;
        next_head.holder_authority_digest = successor.root_mount_authority_digest;
        next_head.provider_authority_generation = successor.provider_authority_generation;
        next_head.provider_authority_digest = successor.provider_authority_digest;
        next_head.current_session_id = successor.session_id;
        next_head.current_session_record_digest = successor.record_digest;
        next_head.next_request_sequence = 1;
        next_head.next_response_sequence = 1;
        next_head.pending_attempt = None;
        next_head.recovery_barrier = None;
        next_head.last_reconciliation = None;
        next_head.record_digest = [0; 32];
        let next_head = sealed_head(next_head)?;
        commit_mutation(
            self,
            journal,
            MutationIdentityV2 {
                tag: MutationTagV2::BackendRecoveryReplacement,
                holder_id: identity.0,
                provider_id: identity.1,
                next_holder_sequence_revision: self
                    .holder_sequences
                    .get(&identity.0)
                    .map_or(0, |value| value.revision),
                next_head_revision: next_head.revision,
                acquisition_id: Some(acquisition_id),
                next_row_revision: Some(next_row.revision),
                attempt_id: Some(next_attempt.attempt_id),
                next_attempt_revision: Some(next_attempt.revision),
                session_id: Some(successor.session_id),
            },
            vec![
                StoredRecordV2::ProviderQueryAttempt {
                    value: next_attempt,
                },
                StoredRecordV2::ProviderSession { value: successor },
                StoredRecordV2::Acquisition {
                    value: next_row.clone(),
                },
                StoredRecordV2::ProviderHead { value: next_head },
            ],
        )?;
        Ok((
            acquisition_id,
            next_row.revision,
            next_row.record_digest,
            current_attempt.method,
        ))
    }

    /// Supersedes one exact pending Inventory under a proven successor session.
    #[doc(hidden)]
    pub(crate) fn replace_inventory_recovery_session_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        live_successor: &mut CurrentRootMountSourceProviderSessionV1,
        attempt_id: [u8; 32],
    ) -> Result<([u8; 16], [u8; 16], Option<[u8; 32]>, [u8; 32])> {
        let current_attempt = self
            .provider_attempts
            .get(&attempt_id)
            .filter(|attempt| {
                attempt.method == ProviderMethodV2::Inventory
                    && attempt.owner == ProviderQueryOwnerV2::Inventory
                    && matches!(attempt.state, ProviderAttemptStateV2::Reserved)
            })
            .cloned()
            .ok_or_else(|| state_error("Inventory recovery attempt is not reserved"))?;
        let identity = (
            current_attempt.scope.holder_authority_id,
            current_attempt.scope.provider_authority_id,
        );
        let current_head = self
            .provider_heads
            .get(&identity)
            .filter(|head| head.pending_attempt.map(|value| value.id) == Some(attempt_id))
            .cloned()
            .ok_or_else(|| state_error("Inventory recovery head is not pending"))?;
        let predecessor = self
            .provider_sessions
            .get(&current_head.current_session_id)
            .filter(|session| session.record_digest == current_head.current_session_record_digest)
            .cloned()
            .ok_or_else(|| state_error("Inventory recovery predecessor session is absent"))?;
        let plan = live_successor
            .recovery_replacement_mount_provider_session_plan_v2(
                journal,
                journal.snapshot()?,
                provider_head_key(identity.0, identity.1),
                record_bytes(StoredRecordV2::ProviderHead {
                    value: current_head.clone(),
                })?,
                provider_session_key(predecessor.session_id),
                record_bytes(StoredRecordV2::ProviderSession {
                    value: predecessor.clone(),
                })?,
                ObjectDigest::from_bytes(predecessor.session_id),
                ObjectDigest::from_bytes(predecessor.session_binding),
                current_head.next_request_sequence,
                current_head.next_response_sequence,
            )
            .map_err(|_| state_error("protected Inventory recovery planning failed"))?;
        let successor = session_from_projection(plan.session(), Some(predecessor.session_id))?;
        validate_successor(&predecessor, &successor, &self.provider_sessions)?;

        let mut next_attempt = current_attempt.clone();
        next_attempt.revision = next_revision(current_attempt.revision)?;
        next_attempt.state = ProviderAttemptStateV2::SupersededIndeterminate {
            successor_session_id: successor.session_id,
            recovery_root_attempt_id: current_attempt.lineage_root_attempt_id,
            outcome_may_exist: true,
        };
        next_attempt.record_digest = [0; 32];
        let next_attempt = sealed_attempt(next_attempt)?;
        let next_attempt_ref = record_ref(&StoredRecordV2::ProviderQueryAttempt {
            value: next_attempt.clone(),
        })?;
        let mut next_head = current_head.clone();
        next_head.revision = next_revision(current_head.revision)?;
        next_head.holder_authority_generation = successor.root_mount_authority_generation;
        next_head.holder_authority_digest = successor.root_mount_authority_digest;
        next_head.provider_authority_generation = successor.provider_authority_generation;
        next_head.provider_authority_digest = successor.provider_authority_digest;
        next_head.current_session_id = successor.session_id;
        next_head.current_session_record_digest = successor.record_digest;
        next_head.next_request_sequence = 1;
        next_head.next_response_sequence = 1;
        next_head.pending_attempt = None;
        next_head.last_reconciliation = None;
        let recovery_root_attempt_id = current_head
            .recovery_barrier
            .as_ref()
            .map(|barrier| barrier.root_attempt.id);
        if let Some(barrier) = next_head.recovery_barrier.as_mut() {
            barrier.required_session_id = successor.session_id;
            barrier.recovery_inventory_tail = Some(next_attempt_ref);
            barrier.replacement_count = barrier
                .replacement_count
                .checked_add(1)
                .ok_or_else(|| state_error("Inventory replacement count is exhausted"))?;
        } else {
            next_head.last_inventory_attempt = Some(next_attempt_ref);
        }
        next_head.record_digest = [0; 32];
        let next_head = sealed_head(next_head)?;
        commit_mutation(
            self,
            journal,
            MutationIdentityV2 {
                tag: MutationTagV2::BackendRecoveryReplacement,
                holder_id: identity.0,
                provider_id: identity.1,
                next_holder_sequence_revision: self
                    .holder_sequences
                    .get(&identity.0)
                    .map_or(0, |value| value.revision),
                next_head_revision: next_head.revision,
                acquisition_id: None,
                next_row_revision: None,
                attempt_id: Some(next_attempt.attempt_id),
                next_attempt_revision: Some(next_attempt.revision),
                session_id: Some(successor.session_id),
            },
            vec![
                StoredRecordV2::ProviderQueryAttempt {
                    value: next_attempt,
                },
                StoredRecordV2::ProviderSession { value: successor },
                StoredRecordV2::ProviderHead { value: next_head },
            ],
        )?;
        Ok((
            identity.0,
            identity.1,
            recovery_root_attempt_id,
            current_attempt.signed_request_digest,
        ))
    }

    /// Replaces one idle provider session under fresh protected authentication.
    ///
    /// # Errors
    ///
    /// Returns an error for an outstanding attempt/recovery barrier, stale
    /// protected records, changed stable scope, generation rollback or
    /// equal-generation equivocation, reused session identity, or commit failure.
    #[doc(hidden)]
    pub(crate) fn replace_idle_provider_session_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        live_successor: &mut CurrentRootMountSourceProviderSessionV1,
        holder_authority_id: [u8; 16],
        provider_authority_id: [u8; 16],
    ) -> Result<()> {
        let identity = (holder_authority_id, provider_authority_id);
        let current_head = self
            .provider_heads
            .get(&identity)
            .filter(|head| {
                head.pending_attempt.is_none()
                    && head.recovery_barrier.is_none()
                    && head.next_request_sequence == head.next_response_sequence
            })
            .cloned()
            .ok_or_else(|| state_error("provider session replacement requires an idle head"))?;
        let predecessor = self
            .provider_sessions
            .get(&current_head.current_session_id)
            .filter(|session| session.record_digest == current_head.current_session_record_digest)
            .cloned()
            .ok_or_else(|| state_error("provider session replacement predecessor is absent"))?;
        let head_record = record_bytes(StoredRecordV2::ProviderHead {
            value: current_head.clone(),
        })?;
        let predecessor_record = record_bytes(StoredRecordV2::ProviderSession {
            value: predecessor.clone(),
        })?;
        let plan = live_successor
            .replacement_mount_provider_session_plan_v2(
                journal,
                journal.snapshot()?,
                provider_head_key(holder_authority_id, provider_authority_id),
                head_record,
                provider_session_key(predecessor.session_id),
                predecessor_record,
                ObjectDigest::from_bytes(predecessor.session_id),
                ObjectDigest::from_bytes(predecessor.session_binding),
                current_head.next_request_sequence,
                current_head.next_response_sequence,
            )
            .map_err(|_| state_error("protected provider replacement planning failed"))?;
        let successor = session_from_projection(plan.session(), Some(predecessor.session_id))?;
        validate_successor(&predecessor, &successor, &self.provider_sessions)?;
        let mut next_head = current_head.clone();
        next_head.revision = next_revision(current_head.revision)?;
        next_head.holder_authority_generation = successor.root_mount_authority_generation;
        next_head.holder_authority_digest = successor.root_mount_authority_digest;
        next_head.provider_authority_generation = successor.provider_authority_generation;
        next_head.provider_authority_digest = successor.provider_authority_digest;
        next_head.current_session_id = successor.session_id;
        next_head.current_session_record_digest = successor.record_digest;
        next_head.next_request_sequence = 1;
        next_head.next_response_sequence = 1;
        next_head.last_reconciliation = None;
        next_head.record_digest = [0; 32];
        let next_head = sealed_head(next_head)?;
        commit_mutation(
            self,
            journal,
            MutationIdentityV2 {
                tag: MutationTagV2::IdleReplacement,
                holder_id: holder_authority_id,
                provider_id: provider_authority_id,
                next_holder_sequence_revision: self
                    .holder_sequences
                    .get(&holder_authority_id)
                    .map_or(0, |value| value.revision),
                next_head_revision: next_head.revision,
                acquisition_id: None,
                next_row_revision: None,
                attempt_id: None,
                next_attempt_revision: None,
                session_id: Some(successor.session_id),
            },
            vec![
                StoredRecordV2::ProviderSession { value: successor },
                StoredRecordV2::ProviderHead { value: next_head },
            ],
        )
    }

    /// Suspends one indeterminate request and installs a proven successor session.
    ///
    /// The move-only death proof is consumed by the protected session planner.
    /// The same transaction abandons the exact Reserved attempt, installs the
    /// immutable successor session, creates or advances the recovery barrier,
    /// and marks an acquisition owner as requiring recovery Inventory.
    ///
    /// # Errors
    ///
    /// Returns an error unless the proof names the exact current provider
    /// execution and Reserved attempt, the successor monotonically extends the
    /// stable scope, and all replacement records validate and commit atomically.
    #[doc(hidden)]
    pub(crate) fn suspend_dead_attempt_and_replace_session_v2(
        &mut self,
        journal: &mut ProtectedJournalAuthority<'_>,
        live_successor: &mut CurrentRootMountSourceProviderSessionV1,
        predecessor_death: DeadProviderExecutionV1,
        holder_authority_id: [u8; 16],
        provider_authority_id: [u8; 16],
    ) -> Result<()> {
        let (_, identity, records) = self.prepare_dead_replacement_v4(
            journal,
            live_successor,
            predecessor_death,
            holder_authority_id,
            provider_authority_id,
        )?;
        commit_mutation(self, journal, identity, records)
    }

    pub(super) fn prepare_dead_replacement_v4(
        &self,
        journal: &ProtectedJournalAuthority<'_>,
        live_successor: &mut CurrentRootMountSourceProviderSessionV1,
        predecessor_death: DeadProviderExecutionV1,
        holder_authority_id: [u8; 16],
        provider_authority_id: [u8; 16],
    ) -> Result<(
        aos_sandbox_source_provider_security::CurrentMountProviderSessionPlanV2,
        MutationIdentityV2,
        Vec<StoredRecordV2>,
    )> {
        let identity = (holder_authority_id, provider_authority_id);
        let current_head = self
            .provider_heads
            .get(&identity)
            .cloned()
            .ok_or_else(|| state_error("dead provider replacement head is absent"))?;
        let current_attempt_ref = current_head
            .pending_attempt
            .ok_or_else(|| state_error("dead provider replacement has no Reserved attempt"))?;
        self.provider_attempts
            .get(&current_attempt_ref.id)
            .filter(|attempt| {
                attempt.revision == current_attempt_ref.revision
                    && attempt.record_digest == current_attempt_ref.record_digest
                    && attempt.session_id == current_head.current_session_id
                    && matches!(&attempt.state, ProviderAttemptStateV2::Reserved)
            })
            .ok_or_else(|| state_error("dead provider replacement attempt is not current"))?;
        let predecessor = self
            .provider_sessions
            .get(&current_head.current_session_id)
            .filter(|session| session.record_digest == current_head.current_session_record_digest)
            .cloned()
            .ok_or_else(|| state_error("dead provider predecessor session is absent"))?;
        let head_record = record_bytes(StoredRecordV2::ProviderHead {
            value: current_head.clone(),
        })?;
        let predecessor_record = record_bytes(StoredRecordV2::ProviderSession {
            value: predecessor.clone(),
        })?;
        let (protected_death, durable_death) =
            durable_death_for_predecessor(&predecessor, predecessor_death)?;
        let plan = live_successor
            .dead_replacement_mount_provider_session_plan_v2(
                journal,
                journal.snapshot()?,
                provider_head_key(holder_authority_id, provider_authority_id),
                head_record,
                provider_session_key(predecessor.session_id),
                predecessor_record,
                ObjectDigest::from_bytes(predecessor.session_id),
                ObjectDigest::from_bytes(predecessor.session_binding),
                protected_death,
                current_head.next_request_sequence,
                current_head.next_response_sequence,
            )
            .map_err(|_| state_error("protected dead-provider replacement planning failed"))?;
        let successor = session_from_projection(plan.session(), Some(predecessor.session_id))?;
        let records = prepare_dead_replacement_v2(&self.state(), successor, durable_death)
            .map_err(protocol_state_error)?;
        let Some(StoredRecordV2::ProviderQueryAttempt { value: attempt }) = records.first() else {
            return Err(state_error("dead replacement proposal lacks its Attempt"));
        };
        let Some(StoredRecordV2::ProviderHead { value: head }) = records.last() else {
            return Err(state_error("dead replacement proposal lacks its Head"));
        };
        let row = records.iter().find_map(|record| match record {
            StoredRecordV2::Acquisition { value } => Some(value),
            _ => None,
        });
        let identity = MutationIdentityV2 {
            tag: MutationTagV2::DeadReplacement,
            holder_id: holder_authority_id,
            provider_id: provider_authority_id,
            next_holder_sequence_revision: self
                .holder_sequences
                .get(&holder_authority_id)
                .map_or(0, |value| value.revision),
            next_head_revision: head.revision,
            acquisition_id: row.map(|row| row.acquisition_id),
            next_row_revision: row.map(|row| row.revision),
            attempt_id: Some(attempt.attempt_id),
            next_attempt_revision: Some(attempt.revision),
            session_id: Some(head.current_session_id),
        };
        Ok((plan, identity, records))
    }
}

fn durable_death_for_predecessor(
    predecessor: &SourceProviderSessionV2,
    proof: DeadProviderExecutionV1,
) -> Result<(
    aos_sandbox_source_provider_security::DeadProviderExecutionProjectionV2,
    DeadProviderExecutionProjectionV2,
)> {
    let protected = proof.into_durable_projection();
    let (old_boot, old_pid, old_start, old_instance) = protected.old_execution();
    let (observed_boot, _) = protected.observation();
    let execution_digest = protected.process_execution_digest();
    if (old_boot, old_pid, old_start, old_instance)
        != (
            predecessor.kernel_boot_id,
            predecessor.provider_execution.pid,
            predecessor.provider_execution.start_time_ticks,
            predecessor.provider_process_instance,
        )
        || execution_digest.as_bytes() != &predecessor.provider_execution.process_execution_digest
    {
        return Err(state_error(
            "provider death projection changes the retained execution",
        ));
    }
    let proof_kind = match protected.kind() {
        ProviderExecutionDeathKindV2::PidfdExited => DeadProviderExecutionProofKindV2::PidfdExited,
        ProviderExecutionDeathKindV2::BootReplaced => {
            DeadProviderExecutionProofKindV2::BootReplaced
        }
    };
    let mut durable = DeadProviderExecutionProjectionV2 {
        proof_kind,
        old_session_id: predecessor.session_id,
        old_session_record_digest: predecessor.record_digest,
        node_id: predecessor.node_id,
        old_kernel_boot_id: predecessor.kernel_boot_id,
        provider_process_instance: predecessor.provider_process_instance,
        process_execution_digest: *execution_digest.as_bytes(),
        observed_kernel_boot_id: observed_boot,
        death_evidence_digest: [0; 32],
    };
    durable.death_evidence_digest = death_digest(&durable)?;
    Ok((protected, durable))
}

fn protocol_state_error(error: MountSourceAcquisitionStateError) -> crate::MountError {
    let MountSourceAcquisitionStateError::Invalid(reason) = error;
    state_error(reason)
}

fn validate_successor(
    predecessor: &SourceProviderSessionV2,
    successor: &SourceProviderSessionV2,
    sessions: &std::collections::BTreeMap<[u8; 32], SourceProviderSessionV2>,
) -> Result<()> {
    validate_provider_session_successor_v2(predecessor, successor, sessions)
        .map_err(protocol_state_error)
}
