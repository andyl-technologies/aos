//! Genuine original Root1 preparation, signing and store-first carrier checks.
//!
//! The private signer requires the named held writer's exact readback and the
//! retained original native guard. No historical bytes reconstruct hot custody.

use aos_sandbox::{MountOriginalNativeJournalAuthorityV5, OriginalRootProtectedReadbackV5};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1 as Kind, NativeHeldOwnerV1, NativeHeldScopeV1,
    NativeHeldSectionTagV1 as Tag,
    frame::{
        NativeHeldSectionV1, NativeHeldSignerV1, PreparedNativeHeldControlV1,
        SignedNativeHeldControlV1,
    },
    native_held_flight_digest_v1,
    witness::NativeHeldOwnerWitnessV1,
};
use ed25519_dalek::Signer as _;

use super::*;

impl CurrentRootMountSourceProviderSessionV1 {
    /// Rechecks original preparation immediately before coupled v5 admission.
    ///
    /// # Errors
    /// Rejects stale original planning, sender, clock, cookie or fixed writer.
    #[doc(hidden)]
    pub fn revalidate_original_native_preparation_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        prepared: &PreparedMountProviderRequestV2,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, ()).run(|owner, _| {
            let guard = prepared
                .native_currentness
                .as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            writer
                .validate_original_planning_snapshot(guard.original_planning_snapshot())
                .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            owner.require_native_acquire_currentness_v3(guard)
        })
    }

    /// Sends the same original Acquire after Root1's successful atomic send.
    ///
    /// The actual reservation records Root1's accepted send. Both IO boundaries
    /// recheck original sender/cut/deadline. This compatibility wrapper returns
    /// custody on ordinary error but cannot restore caller ownership on unwind.
    ///
    /// # Errors
    /// Returns the SAME reserved custody on currentness or atomic send failure.
    /// A post-send failure poisons the Session, retaining possible-send debt.
    #[doc(hidden)]
    pub fn send_original_native_acquire_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        persisted: &OriginalRootProtectedReadbackV5,
        signed: &SignedNativeHeldControlV1,
        reservation: ReservedMountProviderRequestV2,
    ) -> Result<SentMountProviderRequestV2, MountProviderRequestSendRecoveryV2> {
        let mut reservation = reservation;
        let signed_request = match self.send_original_native_borrowed_v5(
            writer,
            persisted,
            signed,
            &reservation,
        ) {
            Ok(Some(request)) => request,
            Ok(None) | Err(_) => return Err(MountProviderRequestSendRecoveryV2 { reservation }),
        };
        if native_catalog::custody::park_native_outcome_v5(
            &mut reservation.prepared,
            &signed_request,
        )
        .is_err()
        {
            self.poison(SourceProviderSecurityError::SessionContinuity);
            return Err(MountProviderRequestSendRecoveryV2 { reservation });
        }

        let ReservedMountProviderRequestV2 { prepared, .. } = reservation;
        Ok(SentMountProviderRequestV2 {
            projection: prepared.projection,
            outcome: prepared.outcome,
        })
    }

    /// Sends while retaining Reserved across every actual carrier boundary.
    ///
    /// # Errors
    /// Keeps the same reservation or Sent output on refusal and unwind. Only a
    /// fully rechecked Retryable result permits reuse of the reservation.
    #[doc(hidden)]
    pub fn send_original_native_acquire_retaining_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        persisted: &OriginalRootProtectedReadbackV5,
        signed: &SignedNativeHeldControlV1,
        reservation: &mut Option<ReservedMountProviderRequestV2>,
        sent: &mut Option<SentMountProviderRequestV2>,
    ) -> Result<bool, SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, reservation).run(|owner, reservation| {
            if sent.is_some() {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            let reserved = reservation.as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let Some(request) = owner.send_original_native_borrowed_v5(
                writer,
                persisted,
                signed,
                reserved,
            )? else {
                return Ok(false);
            };
            let reserved = reservation.as_mut()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            native_catalog::custody::park_native_outcome_v5(&mut reserved.prepared, &request)?;

            *sent = reservation.take().map(|reserved| {
                let ReservedMountProviderRequestV2 { prepared, .. } = reserved;
                SentMountProviderRequestV2 {
                    projection: prepared.projection,
                    outcome: prepared.outcome,
                }
            });
            Ok(true)
        })
    }

    fn send_original_native_borrowed_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        persisted: &OriginalRootProtectedReadbackV5,
        signed: &SignedNativeHeldControlV1,
        reservation: &ReservedMountProviderRequestV2,
    ) -> Result<Option<SignedSourceProviderRequestV1>, SourceProviderSecurityError> {
        use native_catalog::custody::OriginalSendStateV5 as Send;
        OriginalBoundaryV5::new(self, reservation).run(|owner, reservation| {
            let reservation = *reservation;
            if reservation.original_failed.get()
                || reservation.root1_send.get() != Send::Accepted
                || !matches!(reservation.acquire_send.get(), Send::Unattempted | Send::Retryable)
                || persisted.graph().sidecars().get(&persisted.attempt()).is_none_or(|row| {
                    row.suffix().phase() != 1
                        || row.suffix().control(Kind::RootPrepared) != Some(signed)
                })
            {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            owner.require_original_root1_v5(writer, persisted, reservation)?;
            let retryable_this_call = core::cell::Cell::new(false);
            let result = owner.send_borrowed_mount_request_with_attempt_v5(
                writer,
                reservation,
                || reservation.acquire_send.set(Send::Attempted),
                |owner, reservation, boundary| {
                    retryable_this_call.set(boundary == ProviderSendBoundaryV6::Retryable);
                    reservation.acquire_send.set(match boundary {
                        ProviderSendBoundaryV6::Accepted => Send::Accepted,
                        ProviderSendBoundaryV6::Retryable => Send::Retryable,
                    });
                    owner.require_original_root1_v5(writer, persisted, reservation)
                },
            );
            match result {
                Ok(request) => Ok(Some(request)),
                Err(_) if retryable_this_call.get()
                    && reservation.acquire_send.get() == Send::Retryable
                    && owner.revalidate().is_ok() => Ok(None),
                Err(error) => Err(error),
            }
        })
    }

    /// Retries exact original Acquire bytes without reconstructing custody.
    ///
    /// # Errors
    /// Returns unchanged recovery custody on unavailable currentness or send.
    #[doc(hidden)]
    pub fn retry_original_native_acquire_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        persisted: &OriginalRootProtectedReadbackV5,
        signed: &SignedNativeHeldControlV1,
        recovery: MountProviderRequestSendRecoveryV2,
    ) -> Result<SentMountProviderRequestV2, MountProviderRequestSendRecoveryV2> {
        self.send_original_native_acquire_v5(writer, persisted, signed, recovery.reservation)
    }

    /// Derives unsigned Root1 from genuine original custody and prospective rows.
    ///
    /// This produces DATA only. The real writer must atomically admit/read it
    /// back, and trusted Mount must install its actual table before signing.
    ///
    /// # Errors
    /// Rejects changed planning/cookie/clock/role, owners or original request.
    #[doc(hidden)]
    pub fn prepare_original_root_assertion_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        prepared: &PreparedMountProviderRequestV2,
        owners: &aos_sandbox::JournalTransaction,
    ) -> Result<PreparedNativeHeldControlV1, SourceProviderSecurityError> {
        let mut retained = None;
        self.prepare_original_root_assertion_retaining_v5(writer, prepared, owners, &mut retained)?;
        retained.ok_or(SourceProviderSecurityError::SessionContinuity)
    }

    /// Parks original unsigned Root1 before its post-preparation currentness checks.
    ///
    /// # Errors
    /// Retains any output and revokes the actual Session on refusal or unwind.
    #[doc(hidden)]
    pub fn prepare_original_root_assertion_retaining_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        prepared: &PreparedMountProviderRequestV2,
        owners: &aos_sandbox::JournalTransaction,
        root1_slot: &mut Option<PreparedNativeHeldControlV1>,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, ()).run(|owner, _| {
            if root1_slot.is_some() {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            let guard = prepared
                .native_currentness
                .as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            writer
                .validate_original_planning_snapshot(guard.original_planning_snapshot())
                .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            owner.require_native_acquire_currentness_v3(guard)?;
            let attempt = owners
                .records()
                .iter()
                .filter_map(|record| {
                    if record.namespace() != aos_sandbox::RecordNamespace::MountSourceAcquisition {
                        return None;
                    }
                    match aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(
                        record.key(),
                        record.value()?,
                    ) {
                        Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::ProviderQueryAttempt { value }) => Some(value),
                        _ => None,
                    }
                })
                .next()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            if attempt.signed_request != prepared.signed_request
                || prepared.projection.session_binding != owner.session.binding()
            {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }
            let (_, captured, sequence) = writer
                .prospective_original_admission_cut(owners, attempt.attempt_id)
                .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            let witness = NativeHeldOwnerWitnessV1::Root(
                guard.original_root_witness(captured.witnesses().clone(), sequence)?,
            )
            .to_canonical_bytes()
            .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            let request = prepared.projection.signed_request_digest;
            let session = owner.session.binding();
            let mount_attempt = ObjectDigest::from_bytes(attempt.attempt_id);
            let acquisition = prepared
                .projection
                .acquisition_id
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let scope = NativeHeldScopeV1 {
                flight: native_held_flight_digest_v1(request, mount_attempt, session),
                original_source_session: session,
                mount_attempt,
                provider_attempt: ObjectDigest::from_bytes([0; 32]),
                provider_acquisition: acquisition,
                original_root_request: request,
                original_native_request: ObjectDigest::from_bytes([0; 32]),
            };
            let signer = owner
                .custody
                .inner()
                .root_authority()
                .traffic_signer()
                .clone();
            *root1_slot = Some(PreparedNativeHeldControlV1::new(
                Kind::RootPrepared,
                scope,
                ObjectDigest::from_bytes([0; 32]),
                vec![
                    NativeHeldSectionV1::new(Tag::Witness, witness)
                        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
                ],
                NativeHeldSignerV1::SourceProvider(signer),
            )
            .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?);
            owner.require_native_acquire_currentness_v3(guard)?;
            writer
                .validate_original_planning_snapshot(guard.original_planning_snapshot())
                .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            Ok(())
        })
    }

    /// Confirms original reservation through the fully validated named v5 view.
    ///
    /// # Errors
    /// Returns the SAME preparation on any exact readback/currentness failure.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn confirm_original_native_reservation_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        prepared: PreparedMountProviderRequestV2,
        attempt_key: Vec<u8>,
        attempt_record: Vec<u8>,
        head_key: Vec<u8>,
        head_record: Vec<u8>,
    ) -> Result<
        ReservedMountProviderRequestV2,
        (PreparedMountProviderRequestV2, SourceProviderSecurityError),
    > {
        self.confirm_native_acquire_reservation_with_view(
            writer,
            prepared,
            attempt_key,
            attempt_record,
            head_key,
            head_record,
        )
    }

    /// Confirms and parks the actual reservation without consuming preparation early.
    ///
    /// # Errors
    /// Retains preparation and any occupied output on exact readback failure or unwind.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn confirm_original_native_reservation_retaining_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        prepared: &mut Option<PreparedMountProviderRequestV2>,
        attempt_key: Vec<u8>,
        attempt_record: Vec<u8>,
        head_key: Vec<u8>,
        head_record: Vec<u8>,
        reserved: &mut Option<ReservedMountProviderRequestV2>,
    ) -> Result<(), SourceProviderSecurityError> {
        self.confirm_native_reservation_retaining_with_view_v5(
            writer,
            prepared,
            attempt_key,
            attempt_record,
            head_key,
            head_record,
            reserved,
        )
    }

    fn require_original_root1_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        readback: &OriginalRootProtectedReadbackV5,
        reservation: &ReservedMountProviderRequestV2,
    ) -> Result<(), SourceProviderSecurityError> {
        writer
            .validate_readback(readback)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        self.revalidate_native_acquire_reservation_with_view(writer, reservation)?;
        let floor = readback
            .floor()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let prepared = floor.original_prepared();
        let projection = &reservation.prepared.projection;
        if readback.attempt() != floor.request().owner_id
            || prepared.scope().original_source_session != self.session.binding()
            || prepared.scope().original_root_request != projection.signed_request_digest
            || prepared.scope().provider_acquisition
                != projection
                    .acquisition_id
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        self.require_current_root_mount_record_role_v5(prepared.signer())
    }

    /// Checks the exact current RootMountRecord pin and protected secret role.
    ///
    /// # Errors
    ///
    /// Rejects stale protected authority, an ineligible or differently scoped
    /// signer, or a public-key mismatch with the role-selected signing secret.
    pub(in crate::handshake::mount_request) fn require_current_root_mount_record_role_v5(
        &mut self,
        expected: &NativeHeldSignerV1,
    ) -> Result<(), SourceProviderSecurityError> {
        let now = super::current_unix_seconds()?;
        let inner = self.custody.inner_mut();
        inner.revalidate_at(now)?;
        inner
            .root_authority()
            .validate_at(now)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let signer = inner.root_authority().traffic_signer();
        let key = inner
            .trust()
            .keys()
            .iter()
            .find(|entry| {
                entry.signer() == signer && entry.state() == SourceProviderKeyTrustStateV1::Eligible
            })
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if signer.usage() != SourceProviderKeyUsageV1::RootMountRecord
            || expected != &NativeHeldSignerV1::SourceProvider(signer.clone())
            || *key.public_key() != inner.outcome_key().signing_key().verifying_key().to_bytes()
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        Ok(())
    }

    /// Signs exact admitted Root1 once under genuine current RootRecord custody.
    ///
    /// Trusted Mount installs/compares its actual table BEFORE this call. Stored
    /// Session RootRecord slot1 differs from protected secret manifest slot2;
    /// the role APIs above select and compare the exact current pin and secret.
    ///
    /// # Errors
    /// Returns any already signed bytes with a post-sign failure so the owning
    /// flight retains them; neither a retry nor ambiguity may re-sign or remint.
    #[doc(hidden)]
    pub fn sign_original_root1_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        admission: &OriginalRootProtectedReadbackV5,
        reservation: &ReservedMountProviderRequestV2,
    ) -> Result<
        SignedNativeHeldControlV1,
        (
            Option<SignedNativeHeldControlV1>,
            SourceProviderSecurityError,
        ),
    > {
        let mut signed = None;
        match self.sign_original_root1_retaining_v5(writer, admission, reservation, &mut signed) {
            Ok(()) => signed.ok_or((None, SourceProviderSecurityError::SessionContinuity)),
            Err(error) => Err((signed, error)),
        }
    }

    /// Signs once and parks the actual Root1 before any post-sign check.
    ///
    /// # Errors
    /// Retains signed bytes and fail-stops the same reservation and Session on
    /// any refusal or unwind. Signature attempts are never renewed.
    #[doc(hidden)]
    pub fn sign_original_root1_retaining_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        admission: &OriginalRootProtectedReadbackV5,
        reservation: &ReservedMountProviderRequestV2,
        signed_slot: &mut Option<SignedNativeHeldControlV1>,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, reservation).run(|owner, reservation| {
            let reservation = *reservation;
            if reservation.original_failed.get()
                || reservation.root1_signature_attempted.get()
                || signed_slot.is_some()
            {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            owner.require_original_root1_v5(writer, admission, reservation)?;
            let floor = admission.floor()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let sidecar = admission.graph().sidecars().get(&admission.attempt())
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let NativeHeldOwnerWitnessV1::Root(witness) =
                NativeHeldOwnerWitnessV1::from_canonical_bytes(
                    NativeHeldOwnerV1::Root,
                    floor.original_prepared().section(Tag::Witness)
                        .ok_or(SourceProviderSecurityError::SessionContinuity)?,
                ).map_err(|_| SourceProviderSecurityError::SessionContinuity)?
            else {
                return Err(SourceProviderSecurityError::SessionContinuity);
            };
            if sidecar.suffix().phase() != 0
                || witness.journal_sequence != admission.sequence()
                || witness.local_socket_cookie != owner.carrier.socket().peer().socket_cookie().get()
                || witness.planning_sequence != reservation.prepared.native_currentness
                    .as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?
                    .original_planning_snapshot().sequence()
            {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }
            let root1 = floor.original_prepared().clone();
            let message = root1.signature_message();
            reservation.root1_signature_attempted.set(true);
            let signature = owner
                .custody
                .inner()
                .outcome_key()
                .signing_key()
                .sign(&message)
                .to_bytes();
            *signed_slot = Some(root1.with_signature(signature));

            owner.require_original_root1_v5(writer, admission, reservation)
        })
    }

    /// Advances only the reservation snapshot after exact original Root1 storage.
    ///
    /// # Errors
    /// Rejects stale readback, different Root1/P/C/T/H/Session or original guard.
    /// The retained planning snapshot is never changed or revalidated as current.
    #[doc(hidden)]
    pub fn advance_original_root1_reservation_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        persisted: &OriginalRootProtectedReadbackV5,
        reservation: &mut ReservedMountProviderRequestV2,
        signed: &SignedNativeHeldControlV1,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, reservation).run(|owner, reservation| {
            let reservation = &mut **reservation;
            writer
                .validate_readback(persisted)
                .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            let floor = persisted
                .floor()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            let sidecar = persisted
                .graph()
                .sidecars()
                .get(&persisted.attempt())
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            if sidecar.suffix().phase() != 1
                || sidecar.suffix().control(Kind::RootPrepared) != Some(signed)
                || signed.prepared() != floor.original_prepared()
            {
                return Err(owner.poison(SourceProviderSecurityError::SessionContinuity));
            }
            let snapshot = writer
                .snapshot()
                .map_err(|_| owner.poison(SourceProviderSecurityError::SessionContinuity))?;
            reservation
                .prepared
                .validate_protected_reservation(
                    writer,
                    &snapshot,
                    &reservation.attempt_key,
                    &reservation.attempt_record,
                    &reservation.head_key,
                    &reservation.head_record,
                )
                .map_err(|error| owner.poison(error))?;
            let guard = reservation
                .prepared
                .native_currentness
                .as_ref()
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            owner.require_native_acquire_currentness_v3(guard)?;
            reservation.reservation_snapshot = snapshot;
            owner.require_original_root1_v5(writer, persisted, reservation)
        })
    }

    /// Sends stored Root1 before the original Acquire on the SAME carrier.
    ///
    /// # Errors
    /// Returns false for WouldBlock, retaining exact bytes and caller progress;
    /// fatal/changed currentness poisons the original Session without renewal.
    #[doc(hidden)]
    pub fn send_original_root1_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        persisted: &OriginalRootProtectedReadbackV5,
        reservation: &ReservedMountProviderRequestV2,
        signed: &SignedNativeHeldControlV1,
    ) -> Result<bool, (bool, SourceProviderSecurityError)> {
        use native_catalog::custody::OriginalSendStateV5 as Send;
        OriginalBoundaryV5::new(self, reservation).run(|owner, reservation| {
            let reservation = *reservation;
            if reservation.original_failed.get()
                || !matches!(reservation.root1_send.get(), Send::Unattempted | Send::Retryable)
            {
                return Err((false, SourceProviderSecurityError::SessionContinuity));
            }
            owner.require_original_root1_v5(writer, persisted, reservation)
                .map_err(|error| (false, owner.poison(error)))?;
            let sidecar = persisted.graph().sidecars().get(&persisted.attempt())
                .ok_or((false, SourceProviderSecurityError::SessionContinuity))?;
            if sidecar.suffix().phase() != 1
                || sidecar.suffix().control(Kind::RootPrepared) != Some(signed)
            {
                return Err((false, owner.poison(SourceProviderSecurityError::SessionContinuity)));
            }
            let bytes = signed.to_canonical_bytes();
            reservation.root1_send.set(Send::Attempted);
            let sent = match owner.carrier.send(&bytes) {
                Ok(()) => {
                    reservation.root1_send.set(Send::Accepted);
                    true
                }
                Err(CarrierFailureV1::Retryable) => {
                    reservation.root1_send.set(Send::Retryable);
                    false
                }
                Err(CarrierFailureV1::Fatal(error)) => return Err((true, owner.poison(error))),
            };
            owner.require_original_root1_v5(writer, persisted, reservation)
                .map_err(|error| (sent, owner.poison(error)))?;
            Ok(sent)
        })
    }
}
