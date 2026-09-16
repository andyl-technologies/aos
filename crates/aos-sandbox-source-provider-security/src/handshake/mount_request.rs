//! Move-only Root Mount authorization for canonical Acquire-v2 traffic.
//!
//! This module is the dormant Mount-facing custody seam. It signs only one
//! fully validated Acquire-v2 request bound to the current authenticated
//! session, and returns a one-shot outcome verifier for that exact attempt.
//! It exposes neither a signing key nor a generic signing/verifying oracle.

use std::collections::BTreeSet;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    AcquireSourceRequestV1, AcquireSourceResponseV1, InventorySourceRequestV1,
    InventorySourceResponseV1, NormalizedAcquisitionIntentV2, ProviderCatalogFloorV1,
    ReleaseSourceRequestV1, ReleaseSourceResponseV1, SignedSourceExportLeaseV1,
    SignedSourceProviderInventoryV1, SignedSourceProviderReceiptV1, SignedSourceProviderRequestV1,
    SignedSourceProviderStatusV1, SignedSourceReleaseReceiptV1,
    SourceProviderAuthorityTrustStateV1, SourceProviderAuthorityV1, SourceProviderDescriptorRole,
    SourceProviderKeyTrustStateV1, SourceProviderKeyUsageV1, SourceProviderMethod,
    SourceProviderSigningKeyV1, SourceProviderStatus, SourceProviderVerificationContextV1,
    SourceSelectionFloorV1, decode_acquire_request, decode_acquire_response,
    decode_inventory_response, decode_release_response, digest_acquire_request,
    digest_inventory_request, digest_provider_proof, digest_release_request,
    digest_signed_export_lease, digest_signed_request, encode_acquire_request,
    encode_acquire_response, encode_inventory_request, encode_inventory_response,
    encode_release_request, encode_release_response, provider_resource_commitment_v1,
    response_result_digest_v1, sign_request, verify_acquire, verify_hello, verify_inventory,
    verify_provider_receipt_and_lease, verify_release_receipt, verify_request,
    verify_response_status,
};
use sha2::{Digest as _, Sha256};

use super::CurrentRootMountSourceProviderSessionV1;
use crate::SourceProviderSecurityError;
use crate::carrier::CarrierFailureV1;

#[path = "mount_request/historical.rs"]
mod historical;
#[path = "mount_request/model.rs"]
mod model;
#[path = "mount_request/outcome.rs"]
mod outcome;
#[path = "mount_request/projection.rs"]
mod projection;
#[path = "mount_request/recovery.rs"]
mod recovery;

pub use model::*;
use model::{HistoricalMountAcquisitionLineageV2, historical_acquisition_commitment};
use projection::*;

impl CurrentRootMountSourceProviderSessionV1 {
    /// Returns the fixed holder/provider identities and current validity ceiling.
    ///
    /// The values are projections of freshly revalidated protected custody and
    /// cannot select or replace either authority.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session when its
    /// protected custody, peer execution, or trusted time is no longer current.
    #[doc(hidden)]
    pub fn current_authority_scope_v2(
        &mut self,
    ) -> Result<([u8; 16], [u8; 16], i64), SourceProviderSecurityError> {
        self.revalidate()?;
        let now = super::current_unix_seconds()?;
        let projection =
            capture_session_projection(self, now).map_err(|error| self.poison(error))?;
        Ok((
            projection.authority_trust[0].authority.authority_id(),
            projection.authority_trust[1].authority.authority_id(),
            projection.current_valid_until_seconds,
        ))
    }

    /// Returns the exact current session identifier after protected revalidation.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session when its
    /// protected custody, peer execution, or trusted time is no longer current.
    #[doc(hidden)]
    pub fn current_session_id_v2(&mut self) -> Result<ObjectDigest, SourceProviderSecurityError> {
        self.revalidate()?;
        let now = super::current_unix_seconds()?;
        let projection =
            capture_session_projection(self, now).map_err(|error| self.poison(error))?;
        Ok(ObjectDigest::from_bytes(projection.session_id))
    }

    /// Proves one exact protected Mount session's provider execution is dead.
    ///
    /// The full AOSMSA02 process digest is derived inside security from the
    /// retained process facts and is carried into the move-only death proof.
    /// No pidfd, reusable liveness authority, or caller-supplied digest escapes.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session unless
    /// the exact protected session record is current and kernel observation
    /// proves exit, PID reuse, or a changed boot identity.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_mount_provider_execution_dead_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: &aos_sandbox::ProtectedJournalSnapshot,
        retained_session_key: &[u8],
        retained_session_record: &[u8],
        old_boot_id: [u8; 16],
        old_provider_process_id: u32,
        old_provider_tgid: u32,
        old_provider_parent_pid: u32,
        old_provider_start_time_ticks: u64,
        old_provider_cgroup_id: u64,
        old_provider_credentials: [u32; 8],
        old_provider_process_instance: [u8; 16],
    ) -> Result<crate::DeadProviderExecutionV1, SourceProviderSecurityError> {
        self.revalidate()?;
        let execution_digest = mount_provider_execution_digest(
            old_provider_process_id,
            old_provider_tgid,
            old_provider_parent_pid,
            old_provider_start_time_ticks,
            old_provider_cgroup_id,
            old_provider_credentials,
        );
        let state = validated_mount_state(journal).map_err(|error| self.poison(error))?;
        let retained = match aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(
            retained_session_key,
            retained_session_record,
        ) {
            Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::ProviderSession { value }) => value,
            _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
        };
        if retained_session_key.is_empty()
            || retained_session_record.is_empty()
            || old_boot_id == [0; 16]
            || old_provider_process_id == 0
            || old_provider_start_time_ticks == 0
            || old_provider_process_instance == [0; 16]
            || retained.kernel_boot_id != old_boot_id
            || retained.provider_process_instance != old_provider_process_instance
            || retained.provider_execution.pid != old_provider_process_id
            || retained.provider_execution.tgid != old_provider_tgid
            || retained.provider_execution.ppid != old_provider_parent_pid
            || retained.provider_execution.start_time_ticks != old_provider_start_time_ticks
            || retained.provider_execution.cgroup_id != old_provider_cgroup_id
            || [
                retained.provider_execution.real_uid,
                retained.provider_execution.effective_uid,
                retained.provider_execution.saved_uid,
                retained.provider_execution.filesystem_uid,
                retained.provider_execution.real_gid,
                retained.provider_execution.effective_gid,
                retained.provider_execution.saved_gid,
                retained.provider_execution.filesystem_gid,
            ] != old_provider_credentials
            || retained.provider_execution.process_execution_digest != *execution_digest.as_bytes()
            || state.provider_sessions.get(&retained.session_id) != Some(&retained)
            || journal
                .validate_mount_source_acquisition_snapshot(journal_snapshot)
                .is_err()
            || journal.get(retained_session_key).ok().flatten() != Some(retained_session_record)
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        crate::DeadProviderExecutionV1::establish_from_current_custody(
            old_boot_id,
            old_provider_process_id,
            old_provider_start_time_ticks,
            old_provider_process_instance,
            execution_digest,
        )
        .map_err(|error| self.poison(error))
    }

    /// Captures the first move-only session plan from proven absent Mount state.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session unless
    /// the namespace-40 snapshot is current and the exact provider-head key is
    /// absent. Bootstrap sequences are fixed at one.
    pub fn initial_mount_provider_session_plan_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        head_key: Vec<u8>,
    ) -> Result<CurrentMountProviderSessionPlanV2, SourceProviderSecurityError> {
        self.revalidate()?;
        let now = super::current_unix_seconds()?;
        let session = capture_session_projection(self, now).map_err(|error| self.poison(error))?;
        let expected_head_key =
            aos_sandbox_protocol::mount_source_acquisition_state::provider_head_key(
                session.authority_trust[0].authority.authority_id(),
                session.authority_trust[1].authority.authority_id(),
            );
        let state = validated_mount_state(journal).map_err(|error| self.poison(error))?;
        if head_key != expected_head_key
            || state.provider_heads.contains_key(&(
                session.authority_trust[0].authority.authority_id(),
                session.authority_trust[1].authority.authority_id(),
            ))
            || journal
                .validate_mount_source_acquisition_snapshot(&journal_snapshot)
                .is_err()
            || journal.get(&head_key).ok().flatten().is_some()
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let head_record = Vec::new();
        let freshness_digest = mount_plan_freshness_digest(
            session.signed_hellos(),
            1,
            1,
            &head_key,
            &head_record,
            None,
            None,
        );
        Ok(CurrentMountProviderSessionPlanV2 {
            session,
            current_request_sequence: 1,
            current_response_sequence: 1,
            freshness_digest,
            journal_snapshot,
            head_key,
            head_record,
            predecessor_session_key: None,
            predecessor_session_record: None,
            predecessor_death_commitment: None,
        })
    }

    /// Captures a move-only current-session plan from the protected Mount head.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session unless
    /// the namespace-40 snapshot and exact provider-head value are current and
    /// contain the supplied nonzero request/response sequence heads.
    pub fn current_mount_provider_session_plan_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        head_key: Vec<u8>,
        head_record: Vec<u8>,
        current_request_sequence: u64,
        current_response_sequence: u64,
    ) -> Result<CurrentMountProviderSessionPlanV2, SourceProviderSecurityError> {
        self.revalidate()?;
        let now = super::current_unix_seconds()?;
        let session = capture_session_projection(self, now).map_err(|error| self.poison(error))?;
        let state = validated_mount_state(journal).map_err(|error| self.poison(error))?;
        let identity = (
            session.authority_trust[0].authority.authority_id(),
            session.authority_trust[1].authority.authority_id(),
        );
        let retained_head = state.provider_heads.get(&identity);
        let retained_session =
            retained_head.and_then(|head| state.provider_sessions.get(&head.current_session_id));
        let expected_head_key =
            aos_sandbox_protocol::mount_source_acquisition_state::provider_head_key(
                identity.0, identity.1,
            );
        if current_request_sequence == 0
            || current_response_sequence == 0
            || head_key != expected_head_key
            || retained_head.is_none_or(|head| {
                head.next_request_sequence != current_request_sequence
                    || head.next_response_sequence != current_response_sequence
                    || head.pending_attempt.is_some()
                    || head.scope.route_id != session.route_id
                    || head.scope.resource_namespace_digest
                        != *session.resource_namespace_digest.as_bytes()
            })
            || retained_session
                .is_none_or(|stored| !stored_mount_session_matches_projection(stored, &session))
            || journal
                .validate_mount_source_acquisition_snapshot(&journal_snapshot)
                .is_err()
            || journal.get(&head_key).ok().flatten() != Some(head_record.as_slice())
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let freshness_digest = mount_plan_freshness_digest(
            session.signed_hellos(),
            current_request_sequence,
            current_response_sequence,
            &head_key,
            &head_record,
            None,
            None,
        );
        Ok(CurrentMountProviderSessionPlanV2 {
            session,
            current_request_sequence,
            current_response_sequence,
            freshness_digest,
            journal_snapshot,
            head_key,
            head_record,
            predecessor_session_key: None,
            predecessor_session_record: None,
            predecessor_death_commitment: None,
        })
    }

    /// Captures an idle successor-session plan while authenticating the old head.
    ///
    /// The old session sequences remain committed in the predecessor head. The
    /// authenticated successor session starts its independent transcript at
    /// request and response sequence one.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session unless
    /// both protected records are current, name the supplied idle predecessor
    /// and sequence heads exactly, and the live session has a distinct binding.
    #[allow(clippy::too_many_arguments)]
    pub fn replacement_mount_provider_session_plan_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        head_key: Vec<u8>,
        head_record: Vec<u8>,
        predecessor_session_key: Vec<u8>,
        predecessor_session_record: Vec<u8>,
        predecessor_session_id: ObjectDigest,
        predecessor_session_binding: ObjectDigest,
        predecessor_request_sequence: u64,
        predecessor_response_sequence: u64,
    ) -> Result<CurrentMountProviderSessionPlanV2, SourceProviderSecurityError> {
        self.replacement_mount_provider_session_plan_inner(
            journal,
            journal_snapshot,
            head_key,
            head_record,
            predecessor_session_key,
            predecessor_session_record,
            predecessor_session_id,
            predecessor_session_binding,
            None,
            false,
            predecessor_request_sequence,
            predecessor_response_sequence,
        )
    }

    /// Captures a crash-recovery successor plan under consumed death evidence.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session unless
    /// the protected records are current, the death projection exactly names
    /// their old execution, and the live session has a distinct binding.
    #[allow(clippy::too_many_arguments)]
    pub fn dead_replacement_mount_provider_session_plan_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        head_key: Vec<u8>,
        head_record: Vec<u8>,
        predecessor_session_key: Vec<u8>,
        predecessor_session_record: Vec<u8>,
        predecessor_session_id: ObjectDigest,
        predecessor_session_binding: ObjectDigest,
        predecessor_death: crate::DeadProviderExecutionProjectionV2,
        predecessor_request_sequence: u64,
        predecessor_response_sequence: u64,
    ) -> Result<CurrentMountProviderSessionPlanV2, SourceProviderSecurityError> {
        self.replacement_mount_provider_session_plan_inner(
            journal,
            journal_snapshot,
            head_key,
            head_record,
            predecessor_session_key,
            predecessor_session_record,
            predecessor_session_id,
            predecessor_session_binding,
            Some(predecessor_death),
            false,
            predecessor_request_sequence,
            predecessor_response_sequence,
        )
    }

    /// Captures a successor plan for an exact backend-recovery pending attempt.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn recovery_replacement_mount_provider_session_plan_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        head_key: Vec<u8>,
        head_record: Vec<u8>,
        predecessor_session_key: Vec<u8>,
        predecessor_session_record: Vec<u8>,
        predecessor_session_id: ObjectDigest,
        predecessor_session_binding: ObjectDigest,
        predecessor_request_sequence: u64,
        predecessor_response_sequence: u64,
    ) -> Result<CurrentMountProviderSessionPlanV2, SourceProviderSecurityError> {
        self.replacement_mount_provider_session_plan_inner(
            journal,
            journal_snapshot,
            head_key,
            head_record,
            predecessor_session_key,
            predecessor_session_record,
            predecessor_session_id,
            predecessor_session_binding,
            None,
            true,
            predecessor_request_sequence,
            predecessor_response_sequence,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn replacement_mount_provider_session_plan_inner(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        head_key: Vec<u8>,
        head_record: Vec<u8>,
        predecessor_session_key: Vec<u8>,
        predecessor_session_record: Vec<u8>,
        predecessor_session_id: ObjectDigest,
        predecessor_session_binding: ObjectDigest,
        predecessor_death: Option<crate::DeadProviderExecutionProjectionV2>,
        recovery_supersession: bool,
        predecessor_request_sequence: u64,
        predecessor_response_sequence: u64,
    ) -> Result<CurrentMountProviderSessionPlanV2, SourceProviderSecurityError> {
        self.revalidate()?;
        let now = super::current_unix_seconds()?;
        let session = capture_session_projection(self, now).map_err(|error| self.poison(error))?;
        let state = validated_mount_state(journal).map_err(|error| self.poison(error))?;
        let predecessor_id = *predecessor_session_id.as_bytes();
        let retained_head = state.provider_heads.get(&(
            session.authority_trust[0].authority.authority_id(),
            session.authority_trust[1].authority.authority_id(),
        ));
        let retained_session = state.provider_sessions.get(&predecessor_id);
        let expected_head_key =
            aos_sandbox_protocol::mount_source_acquisition_state::provider_head_key(
                session.authority_trust[0].authority.authority_id(),
                session.authority_trust[1].authority.authority_id(),
            );
        let expected_session_key =
            aos_sandbox_protocol::mount_source_acquisition_state::provider_session_key(
                predecessor_id,
            );
        let death_commitment = predecessor_death.as_ref().map(|death| death.commitment());
        let death_matches = predecessor_death.as_ref().is_none_or(|death| {
            retained_session
                .is_some_and(|stored| predecessor_death_matches_session(death, stored, now))
        });
        let predecessor_state_matches = retained_head.is_some_and(|head| {
            if predecessor_death.is_some() || recovery_supersession {
                head.pending_attempt.is_some()
            } else {
                head.pending_attempt.is_none() && head.recovery_barrier.is_none()
            }
        });
        if predecessor_request_sequence == 0
            || predecessor_response_sequence == 0
            || !death_matches
            || !predecessor_state_matches
            || predecessor_session_binding == session.session_binding
            || head_key != expected_head_key
            || predecessor_session_key != expected_session_key
            || retained_head.is_none_or(|head| {
                head.current_session_id != predecessor_id
                    || head.next_request_sequence != predecessor_request_sequence
                    || head.next_response_sequence != predecessor_response_sequence
            })
            || retained_session.is_none_or(|stored| {
                stored.session_binding != *predecessor_session_binding.as_bytes()
                    || stored.session_id != predecessor_id
            })
            || journal
                .validate_mount_source_acquisition_snapshot(&journal_snapshot)
                .is_err()
            || journal.get(&head_key).ok().flatten() != Some(head_record.as_slice())
            || journal.get(&predecessor_session_key).ok().flatten()
                != Some(predecessor_session_record.as_slice())
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let freshness_digest = mount_plan_freshness_digest(
            session.signed_hellos(),
            1,
            1,
            &head_key,
            &head_record,
            Some((&predecessor_session_key, &predecessor_session_record)),
            death_commitment,
        );
        Ok(CurrentMountProviderSessionPlanV2 {
            session,
            current_request_sequence: 1,
            current_response_sequence: 1,
            freshness_digest,
            journal_snapshot,
            head_key,
            head_record,
            predecessor_session_key: Some(predecessor_session_key),
            predecessor_session_record: Some(predecessor_session_record),
            predecessor_death_commitment: death_commitment,
        })
    }

    fn consume_current_mount_plan(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        plan: CurrentMountProviderSessionPlanV2,
    ) -> Result<(MountProviderSessionProjectionV2, u64, u64), SourceProviderSecurityError> {
        self.revalidate()?;
        let expected_freshness = mount_plan_freshness_digest(
            plan.session.signed_hellos(),
            plan.current_request_sequence,
            plan.current_response_sequence,
            &plan.head_key,
            &plan.head_record,
            plan.predecessor_session_key
                .as_deref()
                .zip(plan.predecessor_session_record.as_deref()),
            plan.predecessor_death_commitment,
        );
        if plan.freshness_digest != expected_freshness
            || plan.session.signed_hellos()
                != (
                    self.session
                        .signed_root_mount_hello()
                        .to_canonical_bytes()
                        .as_slice(),
                    self.session
                        .signed_provider_hello()
                        .to_canonical_bytes()
                        .as_slice(),
                )
            || journal
                .validate_mount_source_acquisition_snapshot(&plan.journal_snapshot)
                .is_err()
            || if plan.head_record.is_empty() {
                journal.get(&plan.head_key).ok().flatten().is_some()
            } else {
                journal.get(&plan.head_key).ok().flatten() != Some(plan.head_record.as_slice())
            }
            || match (
                plan.predecessor_session_key.as_deref(),
                plan.predecessor_session_record.as_deref(),
            ) {
                (None, None) => false,
                (Some(key), Some(record)) => journal.get(key).ok().flatten() != Some(record),
                _ => true,
            }
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        Ok((
            plan.session,
            plan.current_request_sequence,
            plan.current_response_sequence,
        ))
    }

    /// Sends one exact custody-prepared request after protected reservation.
    ///
    /// # Errors
    ///
    /// Returns [`MountProviderRequestSendRecoveryV2`] with the exact reservation
    /// for stale custody, a session mismatch, or any carrier failure. A
    /// successful atomic send never recreates retry authority.
    pub fn send_reserved_mount_request_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        reservation: ReservedMountProviderRequestV2,
    ) -> Result<SentMountProviderRequestV2, MountProviderRequestSendRecoveryV2> {
        if self.revalidate().is_err() {
            return Err(MountProviderRequestSendRecoveryV2 { reservation });
        }
        let prepared_signed_request = match SignedSourceProviderRequestV1::from_canonical_bytes(
            &reservation.prepared.signed_request,
        ) {
            Ok(request) => request,
            Err(_) => {
                self.poison(SourceProviderSecurityError::SessionContinuity);
                return Err(MountProviderRequestSendRecoveryV2 { reservation });
            }
        };
        if reservation.prepared.projection.session_binding != self.session.binding()
            || reservation.prepared.outcome.session_binding != self.session.binding()
            || reservation.prepared.projection.signed_request_digest
                != digest_signed_request(&prepared_signed_request)
            || self.carrier.socket().peer().credentials().pid().get() == 0
        {
            self.poison(SourceProviderSecurityError::SessionContinuity);
            return Err(MountProviderRequestSendRecoveryV2 { reservation });
        }
        // The opaque protected snapshot and exact records are retained until
        // the final pre-send currentness check, so no reservation witness can
        // be reused after the namespace advances.
        let journal_current = reservation.attempt_key.len() == 75
            && reservation.head_key.len() == 66
            && !reservation.attempt_record.is_empty()
            && !reservation.head_record.is_empty()
            && journal
                .validate_mount_source_acquisition_snapshot(&reservation.reservation_snapshot)
                .is_ok()
            && journal.get(&reservation.attempt_key).ok().flatten()
                == Some(reservation.attempt_record.as_slice())
            && journal.get(&reservation.head_key).ok().flatten()
                == Some(reservation.head_record.as_slice());
        if !journal_current {
            self.poison(SourceProviderSecurityError::SessionContinuity);
            return Err(MountProviderRequestSendRecoveryV2 { reservation });
        }
        if let Err(failure) = self.carrier.send(&reservation.prepared.signed_request) {
            if let CarrierFailureV1::Fatal(error) = failure {
                self.poison(error);
            }
            return Err(MountProviderRequestSendRecoveryV2 { reservation });
        }
        // A successful sequenced-packet send is atomic. Outcome receive checks
        // currentness again; bytes accepted by the kernel never recreate send
        // authority.
        let ReservedMountProviderRequestV2 { prepared, .. } = reservation;
        Ok(SentMountProviderRequestV2 {
            projection: prepared.projection,
            outcome: prepared.outcome,
        })
    }

    /// Retries one exact retained send reservation without rebuilding its request.
    ///
    /// # Errors
    ///
    /// Returns the same recovery custody when protected currentness, exact
    /// journal readback, or the atomic carrier send is still unavailable.
    pub fn retry_reserved_mount_request_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        recovery: MountProviderRequestSendRecoveryV2,
    ) -> Result<SentMountProviderRequestV2, MountProviderRequestSendRecoveryV2> {
        self.send_reserved_mount_request_v2(journal, recovery.reservation)
    }

    /// Authorizes one exact protected catalog and retained-selection floor.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session for a
    /// stale custody/session, a noncurrent publication, a lowered catalog
    /// floor, or selection evidence outside the validated Mount graph.
    pub fn authorize_mount_acquire_verification_floor_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        catalog_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        current_catalog: crate::ProtectedCurrentCatalogPublicationV1,
        selection_acquisition_key: Option<Vec<u8>>,
    ) -> Result<AuthorizedMountAcquireVerificationFloorV2, SourceProviderSecurityError> {
        use aos_sandbox_protocol::mount_source_acquisition_state::{
            ProviderMethodV2, StoredRecordV2, decode_mount_source_state_record_v2,
            protocol_selection_floor_v2,
        };

        self.revalidate()?;
        let now = super::current_unix_seconds()?;
        let session = capture_session_projection(self, now).map_err(|error| self.poison(error))?;
        let graph = validated_mount_state(journal).map_err(|error| self.poison(error))?;
        if !current_catalog.validate_current(catalog_journal) {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let publication = &current_catalog.publication;
        let provider = &session.authority_trust[1].authority;
        let (catalog_generation, _) = publication.catalog_head();
        let (minimum_catalog_generation, minimum_catalog_digest) = publication.catalog_floor();
        let (
            _,
            publication_trust_generation,
            publication_trust_digest,
            publication_revocation_generation,
            publication_revocation_digest,
        ) = publication.issuance();
        if publication.provider() != provider
            || publication.resource_namespace_digest() != session.resource_namespace_digest
            || publication.catalog_floor().0 > catalog_generation
            || publication_trust_generation != session.trust_generation
            || publication_trust_digest != session.trust_digest
            || publication_revocation_generation != session.revocation_generation
            || publication_revocation_digest != session.revocation_digest
            || journal
                .validate_mount_source_acquisition_snapshot(&journal_snapshot)
                .is_err()
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let catalog = ProviderCatalogFloorV1::new(
            provider.authority_id(),
            session.resource_namespace_digest,
            minimum_catalog_generation,
            minimum_catalog_digest,
        )
        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let scope = (
            session.authority_trust[0].authority.authority_id(),
            provider.authority_id(),
        );
        if graph.provider_attempts.values().any(|attempt| {
            if attempt.method != ProviderMethodV2::Acquire
                || (
                    attempt.scope.holder_authority_id,
                    attempt.scope.provider_authority_id,
                ) != scope
            {
                return false;
            }
            attempt
                .acquire_verification_floor
                .as_ref()
                .is_none_or(|floor| {
                    floor.catalog.minimum_catalog_generation > minimum_catalog_generation
                        || (floor.catalog.minimum_catalog_generation == minimum_catalog_generation
                            && floor.catalog.minimum_catalog_digest
                                != *minimum_catalog_digest.as_bytes())
                })
        }) {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }

        let selection = match selection_acquisition_key {
            Some(key) => {
                let record = journal
                    .get(&key)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?
                    .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                let row = match decode_mount_source_state_record_v2(&key, record) {
                    Ok(StoredRecordV2::Acquisition { value }) => value,
                    _ => {
                        return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                    }
                };
                let evidence = row
                    .evidence
                    .as_ref()
                    .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                let historical = &evidence.historical_lease_signer;
                let selection = protocol_selection_floor_v2(&historical.selection_floor)
                    .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
                if graph.acquisitions.get(&row.acquisition_id) != Some(&row)
                    || row.scope.holder_authority_id != scope.0
                    || row.scope.provider_authority_id != scope.1
                    || historical.selection_floor_digest != *selection.digest().as_bytes()
                    || selection.acquisition_id().as_bytes()
                        != &row.provider_acquisition.acquisition_id
                    || selection.resource().catalog_generation() < minimum_catalog_generation
                    || (selection.resource().catalog_generation() == minimum_catalog_generation
                        && selection.resource().catalog_digest() != minimum_catalog_digest)
                {
                    return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
                }
                Some(selection)
            }
            None => None,
        };
        self.revalidate()?;
        if journal
            .validate_mount_source_acquisition_snapshot(&journal_snapshot)
            .is_err()
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        Ok(AuthorizedMountAcquireVerificationFloorV2 {
            catalog,
            selection,
            current_catalog,
            session_binding: session.session_binding,
            trust_generation: session.trust_generation,
            trust_digest: session.trust_digest,
            revocation_generation: session.revocation_generation,
            revocation_digest: session.revocation_digest,
            journal_snapshot,
        })
    }

    /// Authorizes and signs one exact Acquire-v2 request from current Root Mount custody.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session for a
    /// stale custody/session, a non-v2 or mismatched request, a noncanonical
    /// normalized intent, a stale protected floor authorization, a noncurrent
    /// key, or signing failure.
    pub fn prepare_acquire_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        catalog_journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        plan: CurrentMountProviderSessionPlanV2,
        request: AcquireSourceRequestV1,
        normalized_intent: NormalizedAcquisitionIntentV2,
        floor_authorization: AuthorizedMountAcquireVerificationFloorV2,
    ) -> Result<PreparedMountProviderRequestV2, SourceProviderSecurityError> {
        let (session_projection, expected_request_sequence, expected_response_sequence) =
            self.consume_current_mount_plan(journal, plan)?;
        if journal
            .validate_mount_source_acquisition_snapshot(&floor_authorization.journal_snapshot)
            .is_err()
            || floor_authorization.session_binding != session_projection.session_binding
            || floor_authorization.trust_generation != session_projection.trust_generation
            || floor_authorization.trust_digest != session_projection.trust_digest
            || floor_authorization.revocation_generation != session_projection.revocation_generation
            || floor_authorization.revocation_digest != session_projection.revocation_digest
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        if !floor_authorization
            .current_catalog
            .validate_current(catalog_journal)
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let AuthorizedMountAcquireVerificationFloorV2 {
            catalog: catalog_floor,
            selection: selection_floor,
            current_catalog,
            ..
        } = floor_authorization;
        let current_catalog_head_commitment = current_catalog.projection.head_commitment();
        let now = super::current_unix_seconds()?;
        let session_binding = self.session.binding();
        let signer_set_commitment = self.session.signer_set_commitment();
        let provider_process_instance = self.session.provider_hello().process_instance();
        let kernel_boot_id = session_projection.root_boot_id;
        let trusted_clock_evidence_digest = session_projection.trusted_clock_evidence_digest;
        let material = (|| {
            let inner = self.custody.inner_mut();
            inner.revalidate_at(now)?;
            let holder = inner.root_authority().authority().clone();
            let provider = inner.provider_authority().authority().clone();
            let trust_generation = inner.trust().trust_generation();
            let trust_digest = inner.trust().trust_digest();
            let revocation_generation = inner.trust().revocation_generation();
            let revocation_digest = inner.trust().revocation_digest();
            let expected_intent = NormalizedAcquisitionIntentV2::from_acquire_request(
                &request,
                provider.clone(),
                holder.clone(),
                request.node_id(),
                request.boot_id(),
                inner.route().route_id(),
                inner.route().route_generation(),
                inner.route().route_digest(),
                inner.route().resource_namespace_digest(),
                revocation_generation,
                revocation_digest,
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            if request.session_binding() != session_binding
                || request.sequence() != expected_request_sequence
                || request.deadline_seconds() <= now
                || expected_response_sequence == 0
                || normalized_intent != expected_intent
                || catalog_floor.provider_authority_id() != provider.authority_id()
                || catalog_floor.resource_namespace_digest()
                    != inner.route().resource_namespace_digest()
                || selection_floor.as_ref().is_some_and(|floor| {
                    floor.acquisition_id() != request.acquisition_id()
                        || floor.provider_authority_id() != provider.authority_id()
                        || floor.route_id() != inner.route().route_id()
                        || floor.resource().resource_namespace_digest()
                            != inner.route().resource_namespace_digest()
                })
            {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            let signer = inner.root_authority().traffic_signer().clone();
            let signed_request = sign_request(
                SourceProviderMethod::Acquire,
                encode_acquire_request(&request),
                signer,
                inner.outcome_key().signing_key(),
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            inner.revalidate_at(super::current_unix_seconds()?)?;
            let provider_key = inner
                .trust()
                .keys()
                .iter()
                .find(|entry| {
                    entry.signer() == inner.provider_authority().traffic_signer()
                        && entry.state()
                            == aos_sandbox_source_provider_protocol::SourceProviderKeyTrustStateV1::Eligible
                })
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            Ok::<_, SourceProviderSecurityError>((
                holder,
                provider,
                trust_generation,
                trust_digest,
                revocation_generation,
                revocation_digest,
                signed_request,
                *provider_key.public_key(),
                provider_key.signer().clone(),
            ))
        })();
        let (
            holder,
            provider,
            trust_generation,
            trust_digest,
            revocation_generation,
            revocation_digest,
            signed_request,
            provider_outcome_public_key,
            provider_outcome_signer,
        ) = material.map_err(|error| self.poison(error))?;
        let typed_request_digest = digest_acquire_request(&request);
        let signed_request_digest = digest_signed_request(&signed_request);
        let normalized_intent_digest = normalized_intent.digest();
        let projection = MountProviderRequestProjectionV2 {
            method: SourceProviderMethod::Acquire,
            session: session_projection,
            provider: provider.clone(),
            holder: holder.clone(),
            session_binding,
            signer_set_commitment,
            trust_generation,
            trust_digest,
            revocation_generation,
            revocation_digest,
            provider_process_instance,
            request_id: request.request_id(),
            request_sequence: request.sequence(),
            expected_response_sequence,
            acquisition_id: Some(request.acquisition_id()),
            acquisition_sequence: Some(request.acquisition_sequence()),
            normalized_intent: Some(normalized_intent.to_canonical_bytes()),
            normalized_intent_digest: Some(normalized_intent_digest),
            typed_request_digest,
            signed_request_digest,
            deadline_seconds: request.deadline_seconds(),
            catalog_floor: Some(catalog_floor.clone()),
            selection_floor: selection_floor.clone(),
            current_catalog_head_commitment: Some(current_catalog_head_commitment),
            inventory_correlations: None,
        };
        let outcome = AuthorizedMountProviderOutcomeV2 {
            signed_request: signed_request.clone(),
            method: SourceProviderMethod::Acquire,
            provider,
            holder,
            provider_outcome_public_key,
            provider_outcome_signer,
            session_binding,
            provider_process_instance,
            request_id: request.request_id(),
            typed_request_digest,
            signed_request_digest,
            expected_response_sequence,
            request_sequence: request.sequence(),
            mount_session_id: None,
            mount_attempt_id: None,
            kernel_boot_id,
            trusted_clock_evidence_digest,
            verification_anchor: None,
            acquisition_id: Some(request.acquisition_id()),
            acquisition_sequence: Some(request.acquisition_sequence()),
            lease_id: None,
            lease_digest: None,
            deadline_seconds: request.deadline_seconds(),
            catalog_floor: Some(catalog_floor),
            selection_floor,
            current_catalog_head_commitment: Some(current_catalog_head_commitment),
            deadline_policy: OutcomeDeadlinePolicyV2::Fresh,
            cleanup_only_current_policy: false,
            inventory_correlations: None,
            recovered_inventory_terminal_rows: None,
            historical_session: None,
        };
        Ok(PreparedMountProviderRequestV2 {
            signed_request: signed_request.to_canonical_bytes(),
            projection,
            outcome,
        })
    }

    /// Authorizes and signs one exact Release request for a retained v2 acquisition.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session when
    /// custody is stale or any session, holder, acquisition, lease, deadline,
    /// or response-sequence field is inconsistent.
    pub fn prepare_release_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        plan: CurrentMountProviderSessionPlanV2,
        request: ReleaseSourceRequestV1,
        acquisition_sequence: u64,
    ) -> Result<PreparedMountProviderRequestV2, SourceProviderSecurityError> {
        let (session_projection, expected_request_sequence, expected_response_sequence) =
            self.consume_current_mount_plan(journal, plan)?;
        if request.sequence() != expected_request_sequence {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        if request.acquisition_id()
            != aos_sandbox_source_provider_protocol::source_acquisition_id_v2(
                request.holder_authority_id(),
                request.holder_generation(),
                request.holder_authority_digest(),
                acquisition_sequence,
            )
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let typed_request_digest = digest_release_request(&request);
        self.authorize_non_acquire_v2(
            SourceProviderMethod::Release,
            encode_release_request(&request),
            request.session_binding(),
            request.sequence(),
            request.request_id(),
            request.holder_authority_id(),
            request.holder_generation(),
            request.holder_authority_digest(),
            request.deadline_seconds(),
            expected_response_sequence,
            Some((request.acquisition_id(), acquisition_sequence)),
            Some((request.lease_id(), request.lease_digest())),
            typed_request_digest,
            session_projection,
        )
    }

    /// Authorizes Release of an exact predecessor-holder acquisition mapping.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session unless
    /// the move-only historical authorization remains current, the request is
    /// signed by the live successor holder, and acquisition/lease identities
    /// exactly match the retained predecessor lineage.
    pub fn prepare_historical_release_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        plan: CurrentMountProviderSessionPlanV2,
        request: ReleaseSourceRequestV1,
        historical: HistoricalMountReleaseAuthorizationV2,
    ) -> Result<PreparedMountProviderRequestV2, SourceProviderSecurityError> {
        if !historical.revalidate(journal, self.session.binding()) {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let (acquisition_id, acquisition_sequence) = historical.acquisition_identity();
        let (lease_id, lease_digest) = historical.lease_identity();
        let (_, current_holder) = historical.holder_transition();
        let (session_projection, expected_request_sequence, expected_response_sequence) =
            self.consume_current_mount_plan(journal, plan)?;
        if request.sequence() != expected_request_sequence
            || request.acquisition_id() != acquisition_id
            || request.lease_id() != lease_id
            || request.lease_digest() != lease_digest
            || request.holder_authority_id() != current_holder.authority_id()
            || request.holder_generation() != current_holder.authority_generation()
            || request.holder_authority_digest() != current_holder.authority_digest()
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let typed_request_digest = digest_release_request(&request);
        self.authorize_non_acquire_v2(
            SourceProviderMethod::Release,
            encode_release_request(&request),
            request.session_binding(),
            request.sequence(),
            request.request_id(),
            request.holder_authority_id(),
            request.holder_generation(),
            request.holder_authority_digest(),
            request.deadline_seconds(),
            expected_response_sequence,
            Some((acquisition_id, acquisition_sequence)),
            Some((lease_id, lease_digest)),
            typed_request_digest,
            session_projection,
        )
    }

    /// Authorizes and signs one exact Inventory request for the current holder.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session when
    /// custody is stale or any session, holder, deadline, or sequence field is
    /// inconsistent.
    pub fn prepare_inventory_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        plan: CurrentMountProviderSessionPlanV2,
        request: InventorySourceRequestV1,
        correlations: aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationSetV2,
    ) -> Result<PreparedMountProviderRequestV2, SourceProviderSecurityError> {
        let expected = self.current_inventory_correlations_v2(journal)?;
        if correlations != expected {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        self.prepare_inventory_with_correlations_v2(journal, plan, request, correlations)
    }

    fn prepare_inventory_with_correlations_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        plan: CurrentMountProviderSessionPlanV2,
        request: InventorySourceRequestV1,
        correlations: aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationSetV2,
    ) -> Result<PreparedMountProviderRequestV2, SourceProviderSecurityError> {
        let (session_projection, expected_request_sequence, expected_response_sequence) =
            self.consume_current_mount_plan(journal, plan)?;
        if request.sequence() != expected_request_sequence {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let typed_request_digest = digest_inventory_request(&request);
        let mut prepared = self.authorize_non_acquire_v2(
            SourceProviderMethod::Inventory,
            encode_inventory_request(&request),
            request.session_binding(),
            request.sequence(),
            request.request_id(),
            request.holder_authority_id(),
            request.holder_generation(),
            request.holder_authority_digest(),
            request.deadline_seconds(),
            expected_response_sequence,
            None,
            None,
            typed_request_digest,
            session_projection,
        )?;
        prepared.projection.inventory_correlations = Some(correlations.clone());
        prepared.outcome.inventory_correlations = Some(correlations);
        Ok(prepared)
    }

    /// Authorizes Inventory and binds predecessor-holder correlations to its outcome.
    ///
    /// Each move-only authorization is consumed before signing and can affect
    /// only the exact Inventory outcome verifier returned with this request.
    /// It cannot authorize Acquire, Release, or session replacement.
    ///
    /// # Errors
    ///
    /// Returns [`SourceProviderSecurityError`] and poisons the session unless
    /// every historical lineage is current, unique, and belongs to the live
    /// provider and authenticated successor holder.
    pub fn prepare_historical_inventory_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        plan: CurrentMountProviderSessionPlanV2,
        request: InventorySourceRequestV1,
        correlations: aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationSetV2,
        historical: Vec<HistoricalMountInventoryAuthorizationV2>,
    ) -> Result<PreparedMountProviderRequestV2, SourceProviderSecurityError> {
        if historical.is_empty()
            || historical.len() > aos_sandbox_source_provider_protocol::MAXIMUM_INVENTORY_ENTRIES
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let current_session_binding = self.session.binding();
        let mut acquisition_ids = BTreeSet::new();
        let mut lease_ids = BTreeSet::new();
        let mut expected_entries = self.current_inventory_correlations_v2(journal)?.entries;
        for authorization in historical {
            let lineage = authorization.lineage;
            let current_holder = self.custody.inner().root_authority().authority();
            let provider = self.custody.inner().provider_authority().authority();
            if !lineage.revalidate(journal, current_session_binding)
                || &lineage.current_holder != current_holder
                || lineage.provider_authority_id != provider.authority_id()
                || !acquisition_ids.insert(lineage.acquisition_id)
                || !lease_ids.insert(lineage.lease_id)
            {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            let acquisition = match aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(
                &lineage.acquisition_key,
                &lineage.acquisition_record,
            ) {
                Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::Acquisition { value }) => value,
                _ => return Err(self.poison(SourceProviderSecurityError::SessionContinuity)),
            };
            expected_entries.push(
                aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationV2 {
                    mount_acquisition_id: acquisition.acquisition_id,
                    provider_acquisition: acquisition.provider_acquisition,
                    lease_id: Some(lineage.lease_id),
                    signed_lease_digest: Some(*lineage.lease_digest.as_bytes()),
                    acquisition_record:
                        aos_sandbox_protocol::mount_source_acquisition_state::RecordRefV2 {
                            id: acquisition.acquisition_id,
                            revision: acquisition.revision,
                            record_digest: acquisition.record_digest,
                        },
                    expectation: lineage.inventory_expectation,
                },
            );
        }
        expected_entries.sort_by_key(|entry| entry.provider_acquisition.acquisition_id);
        let expected =
            aos_sandbox_protocol::mount_source_acquisition_state::inventory_correlation_set_v2(
                expected_entries,
            )
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        if correlations != expected {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        self.prepare_inventory_with_correlations_v2(journal, plan, request, correlations)
    }

    fn current_inventory_correlations_v2(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    ) -> Result<
        aos_sandbox_protocol::mount_source_acquisition_state::InventoryCorrelationSetV2,
        SourceProviderSecurityError,
    > {
        self.revalidate()?;
        let holder = self.custody.inner().root_authority().authority().clone();
        let provider = self
            .custody
            .inner()
            .provider_authority()
            .authority()
            .clone();
        let graph = validated_mount_state(journal).map_err(|error| self.poison(error))?;
        let mut entries = graph
            .acquisitions
            .values()
            .filter(|row| {
                row.scope.holder_authority_id == holder.authority_id()
                    && row.scope.provider_authority_id == provider.authority_id()
                    && row.provider_acquisition.holder_authority_generation
                        == holder.authority_generation()
                    && row.provider_acquisition.holder_authority_digest
                        == *holder.authority_digest().as_bytes()
            })
            .filter_map(
                aos_sandbox_protocol::mount_source_acquisition_state::inventory_correlation_for_row_v2,
            )
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.provider_acquisition.acquisition_id);
        aos_sandbox_protocol::mount_source_acquisition_state::inventory_correlation_set_v2(entries)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_non_acquire_v2(
        &mut self,
        method: SourceProviderMethod,
        subject: Vec<u8>,
        session_binding: ObjectDigest,
        request_sequence: u64,
        request_id: [u8; 16],
        holder_authority_id: [u8; 16],
        holder_generation: u64,
        holder_authority_digest: ObjectDigest,
        deadline_seconds: i64,
        expected_response_sequence: u64,
        acquisition: Option<(ObjectDigest, u64)>,
        lease: Option<([u8; 16], ObjectDigest)>,
        typed_request_digest: ObjectDigest,
        session_projection: MountProviderSessionProjectionV2,
    ) -> Result<PreparedMountProviderRequestV2, SourceProviderSecurityError> {
        self.revalidate()?;
        let now = super::current_unix_seconds()?;
        let current_session_binding = self.session.binding();
        let signer_set_commitment = self.session.signer_set_commitment();
        let provider_process_instance = self.session.provider_hello().process_instance();
        let kernel_boot_id = session_projection.root_boot_id;
        let trusted_clock_evidence_digest = session_projection.trusted_clock_evidence_digest;
        let material = (|| {
            let inner = self.custody.inner_mut();
            inner.revalidate_at(now)?;
            let holder = inner.root_authority().authority().clone();
            let provider = inner.provider_authority().authority().clone();
            if session_binding != current_session_binding
                || request_sequence == 0
                || request_id == [0; 16]
                || holder_authority_id != holder.authority_id()
                || holder_generation != holder.authority_generation()
                || holder_authority_digest != holder.authority_digest()
                || deadline_seconds <= now
                || expected_response_sequence == 0
                || !matches!(
                    (method, acquisition, lease),
                    (SourceProviderMethod::Release, Some(_), Some(_))
                        | (SourceProviderMethod::Inventory, None, None)
                )
            {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            let trust_generation = inner.trust().trust_generation();
            let trust_digest = inner.trust().trust_digest();
            let revocation_generation = inner.trust().revocation_generation();
            let revocation_digest = inner.trust().revocation_digest();
            let signed_request = sign_request(
                method,
                subject,
                inner.root_authority().traffic_signer().clone(),
                inner.outcome_key().signing_key(),
            )
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            inner.revalidate_at(super::current_unix_seconds()?)?;
            let provider_key = inner
                .trust()
                .keys()
                .iter()
                .find(|entry| {
                    entry.signer() == inner.provider_authority().traffic_signer()
                        && entry.state()
                            == aos_sandbox_source_provider_protocol::SourceProviderKeyTrustStateV1::Eligible
                })
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            Ok::<_, SourceProviderSecurityError>((
                holder,
                provider,
                trust_generation,
                trust_digest,
                revocation_generation,
                revocation_digest,
                signed_request,
                *provider_key.public_key(),
                provider_key.signer().clone(),
            ))
        })();
        let (
            holder,
            provider,
            trust_generation,
            trust_digest,
            revocation_generation,
            revocation_digest,
            signed_request,
            provider_outcome_public_key,
            provider_outcome_signer,
        ) = material.map_err(|error| self.poison(error))?;
        let signed_request_digest = digest_signed_request(&signed_request);
        let (acquisition_id, acquisition_sequence) = acquisition.unzip();
        let (lease_id, lease_digest) = lease.unzip();
        Ok(PreparedMountProviderRequestV2 {
            projection: MountProviderRequestProjectionV2 {
                method,
                session: session_projection,
                provider: provider.clone(),
                holder: holder.clone(),
                session_binding,
                signer_set_commitment,
                trust_generation,
                trust_digest,
                revocation_generation,
                revocation_digest,
                provider_process_instance,
                request_id,
                request_sequence,
                expected_response_sequence,
                acquisition_id,
                acquisition_sequence,
                normalized_intent: None,
                normalized_intent_digest: None,
                typed_request_digest,
                signed_request_digest,
                deadline_seconds,
                catalog_floor: None,
                selection_floor: None,
                current_catalog_head_commitment: None,
                inventory_correlations: None,
            },
            outcome: AuthorizedMountProviderOutcomeV2 {
                signed_request: signed_request.clone(),
                method,
                provider,
                holder,
                provider_outcome_public_key,
                provider_outcome_signer,
                session_binding,
                provider_process_instance,
                request_id,
                typed_request_digest,
                signed_request_digest,
                expected_response_sequence,
                request_sequence,
                mount_session_id: None,
                mount_attempt_id: None,
                kernel_boot_id,
                trusted_clock_evidence_digest,
                verification_anchor: None,
                acquisition_id,
                acquisition_sequence,
                lease_id,
                lease_digest,
                deadline_seconds,
                catalog_floor: None,
                selection_floor: None,
                current_catalog_head_commitment: None,
                deadline_policy: OutcomeDeadlinePolicyV2::Fresh,
                cleanup_only_current_policy: false,
                inventory_correlations: None,
                recovered_inventory_terminal_rows: None,
                historical_session: None,
            },
            signed_request: signed_request.to_canonical_bytes(),
        })
    }
}

fn predecessor_death_matches_session(
    death: &crate::DeadProviderExecutionProjectionV2,
    predecessor_session: &aos_sandbox_protocol::mount_source_acquisition_state::SourceProviderSessionV2,
    now_seconds: i64,
) -> bool {
    let (old_boot_id, old_process_id, old_start_time_ticks, old_process_instance) =
        death.old_execution();
    let (observed_boot_id, observed_at_seconds) = death.observation();
    observed_at_seconds > 0
        && observed_at_seconds <= now_seconds
        && observed_boot_id != [0; 16]
        && death.matches(
            old_boot_id,
            old_process_id,
            old_start_time_ticks,
            old_process_instance,
        )
        && predecessor_session.kernel_boot_id == old_boot_id
        && predecessor_session.provider_process_instance == old_process_instance
        && predecessor_session.provider_execution.pid == old_process_id
        && predecessor_session.provider_execution.start_time_ticks == old_start_time_ticks
        && predecessor_session
            .provider_execution
            .process_execution_digest
            == *death.process_execution_digest().as_bytes()
}
