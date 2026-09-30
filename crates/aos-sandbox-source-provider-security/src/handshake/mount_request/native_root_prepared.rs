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
        let guard = prepared
            .native_currentness
            .as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        writer
            .validate_original_planning_snapshot(guard.original_planning_snapshot())
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        self.require_native_acquire_currentness_v3(guard)
    }

    /// Sends the same original Acquire after Root1's successful atomic send.
    ///
    /// Trusted Mount owns the Root1 progress bit. Both IO boundaries recheck
    /// original sender/cut/deadline while retaining the same reservation.
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
        let matches = persisted
            .graph()
            .sidecars()
            .get(&persisted.attempt())
            .is_some_and(|r| {
                r.suffix().phase() == 1 && r.suffix().control(Kind::RootPrepared) == Some(signed)
            });
        if !matches
            || self
                .require_original_root1_v5(writer, persisted, &reservation)
                .is_err()
        {
            self.poison(SourceProviderSecurityError::SessionContinuity);
            return Err(MountProviderRequestSendRecoveryV2 { reservation });
        }
        self.send_reserved_mount_request_with_view(writer, reservation, |owner, retained| {
            owner.require_original_root1_v5(writer, persisted, retained)
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
        let guard = prepared
            .native_currentness
            .as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        writer
            .validate_original_planning_snapshot(guard.original_planning_snapshot())
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        self.require_native_acquire_currentness_v3(guard)?;
        let attempt = owners.records().iter().filter_map(|record| {
            if record.namespace() != aos_sandbox::RecordNamespace::MountSourceAcquisition { return None; }
            match aos_sandbox_protocol::mount_source_acquisition_state::decode_mount_source_state_record_v2(record.key(), record.value()?) {
                Ok(aos_sandbox_protocol::mount_source_acquisition_state::StoredRecordV2::ProviderQueryAttempt { value }) => Some(value),
                _ => None,
            }
        }).next().ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if attempt.signed_request != prepared.signed_request
            || prepared.projection.session_binding != self.session.binding()
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let (_, captured, sequence) = writer
            .prospective_original_admission_cut(owners, attempt.attempt_id)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let witness = NativeHeldOwnerWitnessV1::Root(
            guard.original_root_witness(captured.witnesses().clone(), sequence),
        )
        .to_canonical_bytes()
        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let request = prepared.projection.signed_request_digest;
        let session = self.session.binding();
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
        let signer = self
            .custody
            .inner()
            .root_authority()
            .traffic_signer()
            .clone();
        let root1 = PreparedNativeHeldControlV1::new(
            Kind::RootPrepared,
            scope,
            ObjectDigest::from_bytes([0; 32]),
            vec![
                NativeHeldSectionV1::new(Tag::Witness, witness)
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?,
            ],
            NativeHeldSignerV1::SourceProvider(signer),
        )
        .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        self.require_native_acquire_currentness_v3(guard)?;
        writer
            .validate_original_planning_snapshot(guard.original_planning_snapshot())
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        Ok(root1)
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
        self.require_original_root1_v5(writer, admission, reservation)
            .map_err(|error| (None, self.poison(error)))?;
        let floor = admission
            .floor()
            .ok_or((None, SourceProviderSecurityError::SessionContinuity))?;
        let sidecar = admission
            .graph()
            .sidecars()
            .get(&admission.attempt())
            .ok_or((None, SourceProviderSecurityError::SessionContinuity))?;
        let NativeHeldOwnerWitnessV1::Root(witness) =
            NativeHeldOwnerWitnessV1::from_canonical_bytes(
                NativeHeldOwnerV1::Root,
                floor
                    .original_prepared()
                    .section(Tag::Witness)
                    .ok_or((None, SourceProviderSecurityError::SessionContinuity))?,
            )
            .map_err(|_| (None, SourceProviderSecurityError::SessionContinuity))?
        else {
            return Err((None, SourceProviderSecurityError::SessionContinuity));
        };
        if sidecar.suffix().phase() != 0
            || witness.journal_sequence != admission.sequence()
            || witness.local_socket_cookie != self.carrier.socket().peer().socket_cookie().get()
            || witness.planning_sequence
                != reservation
                    .prepared
                    .native_currentness
                    .as_ref()
                    .ok_or((None, SourceProviderSecurityError::SessionContinuity))?
                    .original_planning_snapshot()
                    .sequence()
        {
            return Err((
                None,
                self.poison(SourceProviderSecurityError::SessionContinuity),
            ));
        }
        let root1 = floor.original_prepared().clone();
        let signature = self
            .custody
            .inner()
            .outcome_key()
            .signing_key()
            .sign(&root1.signature_message())
            .to_bytes();
        let signed = root1.with_signature(signature);
        if let Err(error) = self.require_original_root1_v5(writer, admission, reservation) {
            return Err((Some(signed), self.poison(error)));
        }
        Ok(signed)
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
        writer
            .validate_readback(persisted)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
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
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let snapshot = writer
            .snapshot()
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
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
            .map_err(|error| self.poison(error))?;
        let guard = reservation
            .prepared
            .native_currentness
            .as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        self.require_native_acquire_currentness_v3(guard)?;
        reservation.reservation_snapshot = snapshot;
        self.require_original_root1_v5(writer, persisted, reservation)
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
        self.require_original_root1_v5(writer, persisted, reservation)
            .map_err(|error| (false, self.poison(error)))?;
        let sidecar = persisted
            .graph()
            .sidecars()
            .get(&persisted.attempt())
            .ok_or((false, SourceProviderSecurityError::SessionContinuity))?;
        if sidecar.suffix().phase() != 1
            || sidecar.suffix().control(Kind::RootPrepared) != Some(signed)
        {
            return Err((
                false,
                self.poison(SourceProviderSecurityError::SessionContinuity),
            ));
        }
        let sent = match self.carrier.send(&signed.to_canonical_bytes()) {
            Ok(()) => true,
            Err(CarrierFailureV1::Retryable) => false,
            Err(CarrierFailureV1::Fatal(error)) => return Err((true, self.poison(error))),
        };
        self.require_original_root1_v5(writer, persisted, reservation)
            .map_err(|error| (sent, self.poison(error)))?;
        Ok(sent)
    }
}
