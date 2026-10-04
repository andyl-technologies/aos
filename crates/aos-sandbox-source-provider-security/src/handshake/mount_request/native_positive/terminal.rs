//! Same-owner original Source7 reception and once-only local Root13 delivery.
//!
//! The parent owns Held, Complete, its physical FD and the original clock. This
//! child adds no authority: it retains the terminal packet, actual native cause,
//! preparation and signature while the parent rechecks the genuine originals.

use aos_sandbox_source_provider_protocol::native_held_completion::assertion::NativeHeldSettlementV1;
use ed25519_dalek::Signer as _;

use super::*;
use crate::carrier::OriginalRootAcceptedCarrierFailureV5;

#[derive(Clone, Copy)]
enum FirstFailure {
    Receive,
    Security,
    Send,
    OwnerPost,
    ClockPost,
}

pub(super) struct OriginalTerminalProgressV5 {
    record: Option<RetainedSourceProviderRecordV5>,
    receive_failure: Option<OriginalRootAcceptedCarrierFailureV5>,
    control: Option<SignedNativeHeldControlV1>,
    settlement: Option<NativeHeldSettlementV1>,
    unsigned: Option<PreparedNativeHeldControlV1>,
    signing_preparation: Option<PreparedNativeHeldControlV1>,
    signature_message: Option<Vec<u8>>,
    signature_attempted: bool,
    signature: Option<[u8; 64]>,
    signed: Option<SignedNativeHeldControlV1>,
    send_attempted: bool,
    payload: Option<Vec<u8>>,
    send_result: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    first: Option<FirstFailure>,
    failure: Option<SourceProviderSecurityError>,
    debt: Option<SourceProviderSecurityError>,
    owner_post: Option<Result<(), SourceProviderSecurityError>>,
    clock_post: Option<Result<(), SourceProviderSecurityError>>,
}

impl OriginalTerminalProgressV5 {
    pub(super) fn new() -> Self {
        Self {
            record: None,
            receive_failure: None,
            control: None,
            settlement: None,
            unsigned: None,
            signing_preparation: None,
            signature_message: None,
            signature_attempted: false,
            signature: None,
            signed: None,
            send_attempted: false,
            payload: None,
            send_result: None,
            first: None,
            failure: None,
            debt: None,
            owner_post: None,
            clock_post: None,
        }
    }

    fn retain_failure(&mut self, cause: SourceProviderSecurityError) {
        if self.first.is_none() {
            self.failure = Some(cause);
            self.first = Some(FirstFailure::Security);
        } else if self.debt.is_none() {
            self.debt = Some(cause);
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            FirstFailure::Receive => self.receive_failure.as_ref().map(|cause| cause as &dyn std::error::Error),
            FirstFailure::Security => self.failure.as_ref().map(|cause| cause as &dyn std::error::Error),
            FirstFailure::Send => self.send_result.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            FirstFailure::OwnerPost => self.owner_post.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            FirstFailure::ClockPost => self.clock_post.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
        }
    }
}

impl OriginalNativeReceivedOutcomeV5 {
    /// Borrows the actual first terminal receive, verification or send cause.
    ///
    /// This performs no observation and lends neither a descriptor nor a key.
    #[doc(hidden)]
    #[must_use]
    pub fn original_terminal_failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.positive.terminal.failure()
    }

    /// Borrows later terminal observation debt without replacing the first cause.
    #[doc(hidden)]
    #[must_use]
    pub fn original_terminal_postcheck_debt_v5(&self) -> Option<&SourceProviderSecurityError> {
        let terminal = &self.positive.terminal;
        let owner = terminal.owner_post.as_ref().and_then(|result| result.as_ref().err());
        let clock = terminal.clock_post.as_ref().and_then(|result| result.as_ref().err());
        match terminal.first {
            Some(FirstFailure::OwnerPost) => clock.or(terminal.debt.as_ref()),
            Some(FirstFailure::ClockPost) => terminal.debt.as_ref(),
            _ => terminal.debt.as_ref().or(owner).or(clock),
        }
    }

    /// Borrows the actual independent terminal-owner post observation Result.
    ///
    /// No observation or retry occurs; a caller can retain earlier native
    /// chronology while lending this separately owned later refusal.
    #[doc(hidden)]
    #[must_use]
    pub fn original_terminal_owner_post_v5(
        &self,
    ) -> Option<&Result<(), SourceProviderSecurityError>> {
        self.positive.terminal.owner_post.as_ref()
    }

    /// Borrows the separate SAME original paired-clock post observation Result.
    ///
    /// The clock observation is attempted even when the owner observation
    /// returned Err. This loan performs no freshness check or authority action.
    #[doc(hidden)]
    #[must_use]
    pub fn original_terminal_clock_post_v5(
        &self,
    ) -> Option<&Result<(), SourceProviderSecurityError>> {
        self.positive.terminal.clock_post.as_ref()
    }

    /// Borrows the actual terminal Security refusal without another observation.
    ///
    /// A caller whose earlier native Journal cause is already resident can lend
    /// this as later debt; this method does not choose global error chronology.
    #[doc(hidden)]
    #[must_use]
    pub fn original_terminal_security_failure_v5(&self) -> Option<&SourceProviderSecurityError> {
        self.positive.terminal.failure.as_ref()
    }

    /// Borrows retained Source7 DATA, not proof of authentication or settlement.
    #[doc(hidden)]
    #[must_use]
    pub fn original_provider_settled_v5(&self) -> Option<&SignedNativeHeldControlV1> {
        self.positive.terminal.control.as_ref()
    }

    /// Borrows the original local unsigned Root13 preparation.
    #[doc(hidden)]
    #[must_use]
    pub fn original_unsigned_terminal_v5(&self) -> Option<&PreparedNativeHeldControlV1> {
        self.positive.terminal.unsigned.as_ref()
    }

    /// Borrows the once-created signed Root13 even after a failed postcheck.
    #[doc(hidden)]
    #[must_use]
    pub fn original_signed_terminal_v5(&self) -> Option<&SignedNativeHeldControlV1> {
        self.positive.terminal.signed.as_ref()
    }
}

impl CurrentRootMountSourceProviderSessionV1 {
    // Negative post observation uses the SAME original Complete and clock
    // engine even if the owner check ended the Session. No positive admission
    // or failed-owner accessor is used to construct another currentness claim.
    fn observe_original_terminal_clock_v5(
        &mut self,
        retained: &OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        let complete = retained.positive.complete.as_ref()
            .and_then(RetainedSourceProviderRecordV5::bound)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let (_, expires) = retained.positive.reply.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?.receipt().receipt().validity();
        self.require_original_positive_effect_clock_v5(&retained.original, &complete.payload, expires)
    }

    fn capture_original_terminal_posts_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        readback: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        let terminal = &retained.positive.terminal;
        if matches!(terminal.owner_post, Some(Err(_)))
            || matches!(terminal.clock_post, Some(Err(_)))
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }

        // Only prior unit Ok values can be replaced. Each actual new Result
        // is resident before the next observation; no Err is erased or reset.
        let owner_post = self.require_original_terminal_owner_v5(writer, readback, authorization, retained);
        retained.positive.terminal.owner_post = Some(owner_post);
        if matches!(retained.positive.terminal.owner_post, Some(Err(_))) {
            retained.positive.terminal.first.get_or_insert(FirstFailure::OwnerPost);
        }

        // This call is unconditional: an owner Err cannot skip the independent
        // Complete/Storage-expiry-narrowed original paired-clock observation.
        let clock_post = self.observe_original_terminal_clock_v5(retained);
        retained.positive.terminal.clock_post = Some(clock_post);
        if matches!(retained.positive.terminal.clock_post, Some(Err(_))) {
            retained.positive.terminal.first.get_or_insert(FirstFailure::ClockPost);
        }
        if matches!(retained.positive.terminal.owner_post, Some(Err(_)))
            || matches!(retained.positive.terminal.clock_post, Some(Err(_)))
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        Ok(())
    }

    /// Observes and parks terminal-owner and original-clock posts independently.
    ///
    /// # Errors
    /// Keeps both actual Results and ends the same Session after both attempts.
    /// Earlier native/action causes are never replaced by a post refusal.
    #[doc(hidden)]
    pub fn observe_original_terminal_posts_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        readback: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let result = owner.capture_original_terminal_posts_v5(writer, readback, authorization, retained);
            owner.finish_original_terminal_v5(retained, result)
        })
    }

    fn finish_original_terminal_v5<T>(
        &mut self,
        retained: &mut OriginalNativeReceivedOutcomeV5,
        result: Result<T, SourceProviderSecurityError>,
    ) -> Result<T, SourceProviderSecurityError> {
        match result {
            Ok(value) => Ok(value),
            Err(cause) => {
                // A receive/send slot may already own the actual earlier
                // cause. Its coarse returned status is not observation debt.
                if retained.positive.terminal.first.is_none() {
                    retained.positive.terminal.retain_failure(cause);
                }
                retained.failed.set(true);
                Err(self.poison(SourceProviderSecurityError::SessionContinuity))
            }
        }
    }

    fn require_original_terminal_owner_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        readback: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        if !matches!(retained.positive.send_result, Some(Ok(())))
            || !retained.positive.send_attempted
            || retained.positive.first_failure.is_some()
            || retained.positive.postcheck_failure.is_some()
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let phase = readback.graph().sidecars().get(&readback.attempt())
            .ok_or(SourceProviderSecurityError::SessionContinuity)?.suffix().phase();
        match phase {
            5 => self.require_stored_original_accepted_v5(writer, readback, authorization, retained)?,
            6 | 7 => self.require_original_positive_owner_for_v5(
                writer, readback, authorization, retained, OriginalPositivePurposeV5::Terminal,
            )?,
            _ => return Err(SourceProviderSecurityError::SessionContinuity),
        }
        if retained.positive.terminal.control.is_some() {
            self.require_original_provider_settled_v5(authorization, retained)?;
        }
        if phase >= 6 {
            self.require_original_terminal_cut_v5(readback, retained)?;
        }
        // Terminal packet/cut checks follow the shared slow observations. This
        // SAME paired original clock is last before the caller's native effect.
        let complete = retained.original_complete_record_v5()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let (_, expires) = retained.positive.reply.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?.receipt().receipt().validity();
        self.require_original_positive_effect_clock_v5(&retained.original, &complete.payload, expires)
    }

    fn require_original_provider_settled_v5(
        &mut self,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        self.require_native_outcome_authorization_v3(authorization)?;
        let record = retained.positive.terminal.record.as_ref()
            .and_then(RetainedSourceProviderRecordV5::bound)
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        record.execution.revalidate(self.carrier.socket().peer())?;
        let control = retained.positive.terminal.control.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let held = retained.positive.held.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let settlement = retained.positive.terminal.settlement.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let disposition = retained.positive.disposition.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if !record.descriptors.is_empty()
            || !record.execution.has_same_execution(&self.provider_execution)
            || record.payload.len() > MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1
            || record.payload != control.to_canonical_bytes()
            || control.kind() != Kind::ProviderSettled
            || control.scope() != held.scope()
            || settlement.disposition != NativeHeldDispositionV1::Accepted
            || settlement.root_disposition != disposition.digest()
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        settlement.validate_for_kind(Kind::ProviderSettled)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        control.verify_signature_claim(
            &NativeHeldSignerV1::SourceProvider(authorization.provider_outcome_signer.clone()),
            &authorization.provider_outcome_public_key,
        ).map_err(|_| SourceProviderSecurityError::SessionContinuity)?;

        let NativeHeldOwnerWitnessV1::Provider(witness) = NativeHeldOwnerWitnessV1::from_canonical_bytes(
            NativeHeldOwnerV1::Provider,
            control.section(Tag::Witness).ok_or(SourceProviderSecurityError::SessionContinuity)?,
        ).map_err(|_| SourceProviderSecurityError::SessionContinuity)? else {
            return Err(SourceProviderSecurityError::SessionContinuity);
        };
        let original = retained.positive.witness.as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        if witness.root_local_cookie != original.root_local_cookie
            || witness.storage_local_cookie != original.storage_local_cookie
            || witness.authority != original.authority
            || witness.native_namespace != original.native_namespace
            || witness.catalog_head != original.catalog_head
            || witness.catalog_floor != original.catalog_floor
            || witness.head_commitment != original.head_commitment
            || witness.publication != original.publication
            || witness.selected_manifest != original.selected_manifest
            || witness.backend_manifest != original.backend_manifest
            || witness.verifier_manifest != original.verifier_manifest
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        // Source's changed record/sequence witnesses are signed assertions, not
        // Root measurements of its phase8, current floor, Spent or retirement.
        Ok(())
    }

    fn require_original_terminal_cut_v5(
        &mut self,
        readback: &OriginalRootProtectedReadbackV5,
        retained: &OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        let sidecar = readback.graph().sidecars().get(&readback.attempt())
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let terminal = &retained.positive.terminal;
        let control = terminal.control.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let unsigned = terminal.unsigned.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let cut = retained.positive.cut.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let captured = cut.reconstruct(readback.graph().legacy(), readback.attempt())
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let NativeHeldOwnerWitnessV1::Root(witness) = NativeHeldOwnerWitnessV1::from_canonical_bytes(
            NativeHeldOwnerV1::Root,
            unsigned.section(Tag::Witness).ok_or(SourceProviderSecurityError::SessionContinuity)?,
        ).map_err(|_| SourceProviderSecurityError::SessionContinuity)? else {
            return Err(SourceProviderSecurityError::SessionContinuity);
        };
        let expected = NativeHeldOwnerWitnessV1::Root(
            retained.original.original_root_witness(captured.witnesses().clone(), witness.journal_sequence)?,
        ).to_canonical_bytes().map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let exact = match sidecar.suffix().phase() {
            6 => sidecar.suffix().prepared() == Some(unsigned)
                && readback.sequence() == witness.journal_sequence
                && readback.floor().is_some(),
            7 => terminal.signed.as_ref().is_some_and(|signed| {
                signed.prepared() == unsigned
                    && sidecar.suffix().prepared().is_none()
                    && sidecar.suffix().control(Kind::RootTerminalRecorded) == Some(signed)
                    && readback.floor().is_none()
                    && original_root_remaining_v5(readback.graph(), readback.attempt())
                        .is_ok_and(|remaining| remaining == 0)
            }),
            _ => false,
        };
        if !exact || sidecar.suffix().control(Kind::ProviderSettled) != Some(control)
            || sidecar.settlement() != terminal.settlement.as_ref()
            || sidecar.terminal_verifier().is_some()
            || unsigned.predecessor() != control.digest()
            || unsigned.section(Tag::Witness) != Some(expected.as_slice())
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        self.require_current_root_mount_record_role_v5(unsigned.signer())
    }

    /// Receives original Source7 only after the actual once Root4 native success.
    ///
    /// # Errors
    /// Retains whole fatal native/binding results and unexpected FDs before
    /// refusing; only nonconsuming backpressure can retry after real bookends.
    #[doc(hidden)]
    pub fn receive_original_provider_settled_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase5: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<bool, SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let mut attempted = false;
            let result = (|| {
                owner.require_original_terminal_owner_v5(writer, phase5, authorization, retained)?;
                if retained.positive.terminal.record.is_some() {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                let terminal = &mut retained.positive.terminal;
                attempted = true;
                match owner.carrier.receive_original_provider_settled_retaining_v5(
                    &mut terminal.record, &mut terminal.receive_failure,
                ) {
                    Ok(true) => {}
                    Ok(false) | Err(CarrierFailureV1::Retryable) => {
                        return Ok(false);
                    }
                    Err(CarrierFailureV1::Fatal(cause)) => {
                        if terminal.receive_failure.is_some() {
                            terminal.first = Some(FirstFailure::Receive);
                        }
                        return Err(cause);
                    }
                }
                let terminal = &mut retained.positive.terminal;
                let record = terminal.record.as_ref().and_then(RetainedSourceProviderRecordV5::bound)
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                if !record.descriptors.is_empty() {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                terminal.control = Some(SignedNativeHeldControlV1::from_canonical_bytes(&record.payload)
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?);
                terminal.settlement = Some(NativeHeldSettlementV1::from_canonical_bytes(
                    terminal.control.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?
                        .section(Tag::Settlement).ok_or(SourceProviderSecurityError::SessionContinuity)?,
                ).map_err(|_| SourceProviderSecurityError::SessionContinuity)?);
                Ok(true)
            })();
            if !attempted {
                return owner.finish_original_terminal_v5(retained, result);
            }

            // Park the actual canonical/action refusal before independently
            // observing the owner and clock. A native slot already owns fatal
            // receive/binding errors; their returned coarse status is not debt.
            let action = match result {
                Ok(ready) => Ok(ready),
                Err(cause) => {
                    if retained.positive.terminal.first.is_none() {
                        retained.positive.terminal.retain_failure(cause);
                    }
                    Err(SourceProviderSecurityError::SessionContinuity)
                }
            };
            let posts = owner.capture_original_terminal_posts_v5(writer, phase5, authorization, retained);
            let result = match action {
                Err(cause) => Err(cause),
                Ok(ready) => posts.map(|()| {
                    if !ready {
                        owner.carrier.finish_original_receive_backpressure_v5();
                    }
                    ready
                }),
            };
            owner.finish_original_terminal_v5(retained, result)
        })
    }

    /// Rechecks the genuine original owners and actual phase5/6/7 cut.
    ///
    /// # Errors
    /// Retains first refusal and ends the SAME Session on any changed original.
    #[doc(hidden)]
    pub fn revalidate_original_terminal_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        readback: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let result = owner.require_original_terminal_owner_v5(writer, readback, authorization, retained);
            owner.finish_original_terminal_v5(retained, result)
        })
    }

    /// Prepares unsigned Root13 from actual phase5 companions and signed Source7.
    ///
    /// # Errors
    /// Rejects occupied custody, stale originals or a different full-TX sequence.
    #[doc(hidden)]
    pub fn prepare_original_root_terminal_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase5: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
        transaction: [u8; 16],
        successor_sequence: u64,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let result = (|| {
                owner.require_original_terminal_owner_v5(writer, phase5, authorization, retained)?;
                if retained.positive.terminal.unsigned.is_some()
                    || phase5.sequence().checked_add(5) != Some(successor_sequence)
                    || phase5.graph().sidecars().get(&phase5.attempt())
                        .is_none_or(|sidecar| sidecar.suffix().phase() != 5)
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                let cut = retained.positive.cut.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let captured = cut.reconstruct(phase5.graph().legacy(), phase5.attempt())
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
                // Transaction identity is the deterministic owner TX; it does
                // not substitute for the actual captured companion witnesses.
                if transaction == [0; 16] {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                let witness = NativeHeldOwnerWitnessV1::Root(
                    retained.original.original_root_witness(captured.witnesses().clone(), successor_sequence)?,
                ).to_canonical_bytes().map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
                let terminal = &mut retained.positive.terminal;
                let control = terminal.control.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let settlement = terminal.settlement.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let signer = retained.positive.signed.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?.prepared().signer().clone();
                let sections = vec![
                    NativeHeldSectionV1::new(Tag::Witness, witness),
                    NativeHeldSectionV1::new(Tag::Settlement,
                        settlement.to_canonical_bytes().map_err(|_| SourceProviderSecurityError::SessionContinuity)?.to_vec()),
                ].into_iter().collect::<Result<Vec<_>, _>>()
                    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
                terminal.unsigned = Some(PreparedNativeHeldControlV1::new(
                    Kind::RootTerminalRecorded, *control.scope(), control.digest(), sections, signer,
                ).map_err(|_| SourceProviderSecurityError::SessionContinuity)?);
                owner.require_original_terminal_owner_v5(writer, phase5, authorization, retained)
            })();
            owner.finish_original_terminal_v5(retained, result)
        })
    }

    /// Signs the same physically stored unsigned phase6 Root13 once.
    ///
    /// # Errors
    /// Prearms before any observation; refusal/unwind permanently ends signing.
    #[doc(hidden)]
    pub fn sign_original_root_terminal_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase6: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<(), SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let result = (|| {
                let terminal = &mut retained.positive.terminal;
                if terminal.signature_attempted || terminal.first.is_some() {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                terminal.signature_attempted = true;
                owner.require_original_terminal_owner_v5(writer, phase6, authorization, retained)?;
                if phase6.graph().sidecars().get(&phase6.attempt())
                    .is_none_or(|sidecar| sidecar.suffix().phase() != 6)
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                let terminal = &mut retained.positive.terminal;
                terminal.signing_preparation = Some(terminal.unsigned.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?.clone());
                terminal.signature_message = Some(terminal.signing_preparation.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?.signature_message());
                owner.require_original_terminal_owner_v5(writer, phase6, authorization, retained)?;
                let terminal = &mut retained.positive.terminal;
                let message = terminal.signature_message.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let signature = owner.custody.inner().outcome_key().signing_key()
                    .sign(message).to_bytes();
                terminal.signature = Some(signature);
                if let Some(unsigned) = terminal.signing_preparation.take() {
                    terminal.signed = Some(unsigned.with_signature(signature));
                }
                owner.capture_original_terminal_posts_v5(writer, phase6, authorization, retained)
            })();
            owner.finish_original_terminal_v5(retained, result)
        })
    }

    /// Sends physically stored Root13 once, reporting local transmission only.
    ///
    /// # Errors
    /// Even EAGAIN/EINTR ends this purpose. Actual native cause and later debt
    /// stay resident; successful reentry only observes the same phase7 endpoint.
    #[doc(hidden)]
    pub fn send_original_root_terminal_v5(
        &mut self,
        writer: &MountOriginalNativeJournalAuthorityV5<'_>,
        phase7: &OriginalRootProtectedReadbackV5,
        authorization: &AuthorizedMountProviderOutcomeV2,
        retained: &mut OriginalNativeReceivedOutcomeV5,
    ) -> Result<bool, SourceProviderSecurityError> {
        OriginalBoundaryV5::new(self, retained).run(|owner, retained| {
            let retained = &mut **retained;
            let result = (|| {
                let terminal = &mut retained.positive.terminal;
                if terminal.first.is_some()
                    || (terminal.send_attempted && !matches!(terminal.send_result, Some(Ok(()))))
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                let already_sent = terminal.send_attempted;
                terminal.send_attempted = true;
                if !already_sent {
                    terminal.payload = Some(terminal.signed.as_ref()
                        .ok_or(SourceProviderSecurityError::SessionContinuity)?.to_canonical_bytes());
                }
                let terminal = &mut retained.positive.terminal;
                let payload = terminal.payload.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?;
                let signed = terminal.signed.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?;
                if phase7.graph().sidecars().get(&phase7.attempt())
                    .is_none_or(|sidecar| sidecar.suffix().phase() != 7)
                    || payload.len() > MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1
                    || *payload != signed.to_canonical_bytes()
                {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                // Serialization/equality and all payload admission are complete
                // before the final original owner/paired-clock validation.
                owner.require_original_terminal_owner_v5(writer, phase7, authorization, retained)?;
                if already_sent {
                    return Ok(true);
                }
                // No observation follows the final SAME-clock sample before
                // this native effect. The exact returned Result is parked first.
                let terminal = &mut retained.positive.terminal;
                let payload = terminal.payload.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?;
                terminal.send_result = Some(owner.carrier.send_original_root_terminal_retaining_v5(payload));
                if !matches!(terminal.send_result, Some(Ok(()))) {
                    terminal.first = Some(FirstFailure::Send);
                }
                let _posts = owner.capture_original_terminal_posts_v5(writer, phase7, authorization, retained);
                if retained.positive.terminal.first.is_some() {
                    return Err(SourceProviderSecurityError::SessionContinuity);
                }
                Ok(true)
            })();
            owner.finish_original_terminal_v5(retained, result)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_terminal_has_no_packet_key_owner_or_effect_permission() {
        let terminal = OriginalTerminalProgressV5::new();

        assert!(terminal.record.is_none());
        assert!(terminal.control.is_none());
        assert!(terminal.unsigned.is_none());
        assert!(!terminal.signature_attempted);
        assert!(!terminal.send_attempted);
        assert!(terminal.failure().is_none());
    }

    #[test]
    fn later_debt_does_not_replace_original_security_cause() {
        let mut terminal = OriginalTerminalProgressV5::new();
        terminal.retain_failure(SourceProviderSecurityError::DirectoryPath);
        let original = terminal.failure.as_ref().unwrap() as *const _;

        terminal.retain_failure(SourceProviderSecurityError::SessionContinuity);

        assert_eq!(terminal.failure.as_ref().unwrap() as *const _, original);
        assert!(terminal.debt.is_some());
    }
}
