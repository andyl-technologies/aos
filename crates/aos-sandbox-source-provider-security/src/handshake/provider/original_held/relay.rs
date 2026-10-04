//! Once-only relay5 signing and dispatch on the original Held Session.
//!
//! Unsigned phase7 and signed phase7 are distinct protected cuts. Every new
//! crossing retains its actual preparation, signature, samples and first cause;
//! dispatch still grants no remote acknowledgement, settlement or release.

use super::*;
use aos_sandbox_source_provider_ledger::ledger::native_held_completion::SourceNativeHeldStepV1;

#[derive(Clone, Copy, Eq, PartialEq)]
enum RelayStageV5 {
    Unstarted,
    Ready,
    Checking,
    Signed,
    Sent,
    Closed,
}

#[derive(Clone, Copy)]
enum RelayFirstFailureV5 {
    Validation,
    Sample(usize),
    Storage,
    Postcheck(usize),
}

pub(super) struct OriginalProviderRelayV5 {
    stage: RelayStageV5,
    attempted: bool,
    prepared: Option<PreparedNativeHeldControlV1>,
    message: Option<Vec<u8>>,
    detached: Option<[u8; 64]>,
    signed: Option<SignedNativeHeldControlV1>,
    samples: [Option<Result<RawPairedClockSample, SourceProviderSecurityError>>; 2],
    first: Option<RelayFirstFailureV5>,
    cause: Option<OriginalHeldCauseV5>,
    storage_cause: Option<OriginalHeldCauseV5>,
    postchecks: [Option<Result<(), OriginalHeldCauseV5>>; 3],
    transport_staged: bool,
}

impl OriginalProviderRelayV5 {
    // The whole-parent gate ends before this disjoint immutable DATA loan.
    pub(super) fn control(&self) -> Option<&SignedNativeHeldControlV1> {
        self.signed.as_ref()
    }

    pub(super) fn pending() -> Self {
        Self {
            stage: RelayStageV5::Unstarted,
            attempted: false,
            prepared: None,
            message: None,
            detached: None,
            signed: None,
            samples: std::array::from_fn(|_| None),
            first: None,
            cause: None,
            storage_cause: None,
            postchecks: std::array::from_fn(|_| None),
            transport_staged: false,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let first: Option<&(dyn std::error::Error + 'static)> = match self.first {
            Some(RelayFirstFailureV5::Validation) => self.cause.as_ref().map(|cause| cause as _),
            Some(RelayFirstFailureV5::Sample(index)) => self.samples[index].as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(RelayFirstFailureV5::Storage) => self.storage_cause.as_ref().map(|cause| cause as _),
            Some(RelayFirstFailureV5::Postcheck(index)) => self.postchecks[index].as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            None => None,
        };
        first
    }

    fn retain_failure(&mut self, cause: OriginalHeldCauseV5) {
        if self.first.is_none() {
            self.cause = Some(cause);
            self.first = Some(RelayFirstFailureV5::Validation);
        }
    }

    fn retain_postcheck(&mut self, index: usize, result: Result<(), OriginalHeldCauseV5>) {
        self.postchecks[index] = Some(result);
        if self.first.is_none() && self.postchecks[index].as_ref().is_some_and(Result::is_err) {
            self.first = Some(RelayFirstFailureV5::Postcheck(index));
        }
    }

    fn sample(
        &mut self,
        index: usize,
        initial: RawPairedClockSample,
        deadline: u64,
        validity: (i64, i64),
    ) -> Result<(), OriginalHeldCauseV5> {
        self.samples[index] = Some(super::super::super::original_kernel_clock());
        let Some(Ok(later)) = &self.samples[index] else {
            if self.first.is_none() {
                self.first = Some(RelayFirstFailureV5::Sample(index));
            }
            return Err(SourceProviderSecurityError::SessionContinuity.into());
        };
        validate_original_held_clock_sample_v5(initial, *later, deadline, validity)
    }

    fn binding_purpose<'control>(
        &'control self,
        crossing: RelayCrossingV5<'control>,
        held3: &'control SignedNativeHeldControlV1,
        root4: &'control SignedNativeHeldControlV1,
        complete: &'control [u8],
    ) -> Result<OriginalHeldBindingPurposeV5<'control>, OriginalHeldCauseV5> {
        if matches!(crossing, RelayCrossingV5::Sign(_) | RelayCrossingV5::Preparation) {
            let relay = self.prepared.as_ref()
                .or_else(|| self.signed.as_ref().map(SignedNativeHeldControlV1::prepared))
                .or_else(|| match crossing {
                    RelayCrossingV5::Sign(prepared) => Some(prepared),
                    _ => None,
                })
                .ok_or(SourceProviderSecurityError::SessionContinuity)?;
            Ok(OriginalHeldBindingPurposeV5::RelayPreparation(held3, complete, root4, relay))
        } else {
            let relay = self.signed.as_ref().ok_or(SourceProviderSecurityError::SessionContinuity)?;
            Ok(OriginalHeldBindingPurposeV5::RelayDelivery(held3, complete, root4, relay))
        }
    }
}

#[derive(Clone, Copy)]
enum RelayCrossingV5<'prepared> {
    Sign(&'prepared PreparedNativeHeldControlV1),
    Preparation,
    Delivery,
    Send,
}

// The owner and new purpose are fenced before any delegate or allocation. An
// unfinished observation, including a caught unwind, never reopens the purpose.
struct RelayBoundaryV5<'owner> {
    session: &'owner mut CurrentProviderIngressSessionV1,
    signatures: &'owner mut OriginalProviderHeldSignaturesV5,
    completed: bool,
}

impl Drop for RelayBoundaryV5<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.signatures.relay.stage = RelayStageV5::Closed;
            self.session.close_original_held_after_failure_v5();
        }
    }
}

impl OriginalProviderHeldSignaturesV5 {
    /// Borrows relay5 DATA only after this same owner completed its signing.
    #[must_use]
    pub fn original_relay(&self) -> Option<&SignedNativeHeldControlV1> {
        if self.failure().is_some() || !matches!(self.relay.stage, RelayStageV5::Signed | RelayStageV5::Sent) {
            None
        } else {
            self.relay.signed.as_ref()
        }
    }

    /// Observes local relay dispatch, not a remote ACK or settlement.
    #[must_use]
    pub fn original_relay_sent(&self) -> bool {
        self.failure().is_none() && self.relay.stage == RelayStageV5::Sent
    }

    /// Reports that the actual first relay cause resides in the Storage child.
    ///
    /// The upper owner borrows that whole owning error rather than substituting
    /// this diagnostic marker or a later Session/clock postcheck debt.
    #[must_use]
    #[doc(hidden)]
    pub fn original_relay_storage_failed(&self) -> bool {
        matches!(self.relay.first, Some(RelayFirstFailureV5::Storage))
    }
}

impl CurrentProviderIngressSessionV1 {
    /// Arms the relay purpose after the genuine same-owner Root4 admission.
    ///
    /// The already consumed Held signing disposition remains ended. No new
    /// Session, signing epoch, currentness permit or transport is constructed.
    #[doc(hidden)]
    pub fn begin_original_relay_v5(&mut self, signatures: &mut OriginalProviderHeldSignaturesV5) -> bool {
        if signatures.relay.stage != RelayStageV5::Unstarted
            || signatures.root_accepted().is_none()
            || !signatures.delivery_complete()
            || self.failure_disposition != CurrentSessionFailureDispositionV5::OriginalHeldEnded
        {
            signatures.relay.retain_failure(SourceProviderSecurityError::SessionContinuity.into());
            signatures.relay.stage = RelayStageV5::Closed;
            self.close_original_held_after_failure_v5();
            return false;
        }
        signatures.relay.stage = RelayStageV5::Ready;
        true
    }

    /// Signs canonical relay5 once from the actual unsigned phase7 readback.
    ///
    /// Both once-only latches are consumed before basis validation or crypto.
    /// All returned DATA and errors remain in the same original reservoir.
    #[doc(hidden)]
    pub fn sign_original_relay_v5(
        &mut self,
        journal: &SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &OriginalSourceProtectedReadbackV5,
        root: &CurrentRootPreparedCarrierV1,
        acquire: &CurrentProviderRequestV1,
        physical: &crate::ProviderSourceRootHandoffV1,
        lease: &SignedSourceExportLeaseV1,
        archive: &crate::ProtectedOriginalConfigurationArchiveV5,
        selected: &crate::ProtectedOriginalSelectedInputV1,
        storage: &mut crate::OriginalStorageOfferTransportV5,
        complete: &[u8],
        prepared: &PreparedNativeHeldControlV1,
        initial: RawPairedClockSample,
        deadline: u64,
        validity: (i64, i64),
        signatures: &mut OriginalProviderHeldSignaturesV5,
    ) -> bool {
        self.observe_original_relay_v5(
            journal, readback, root, acquire, physical, lease, archive, selected,
            storage, complete, initial, deadline, validity, signatures,
            RelayCrossingV5::Sign(prepared),
        )
    }

    /// Rechecks only the exact unsigned or signed relay cut named by its step.
    ///
    /// The closed step is DATA; the opaque current readback and same owner still
    /// supply the actual basis. Every other step is refused without an effect.
    #[doc(hidden)]
    pub fn revalidate_original_relay_v5(
        &mut self,
        journal: &SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &OriginalSourceProtectedReadbackV5,
        root: &CurrentRootPreparedCarrierV1,
        acquire: &CurrentProviderRequestV1,
        physical: &crate::ProviderSourceRootHandoffV1,
        lease: &SignedSourceExportLeaseV1,
        archive: &crate::ProtectedOriginalConfigurationArchiveV5,
        selected: &crate::ProtectedOriginalSelectedInputV1,
        storage: &mut crate::OriginalStorageOfferTransportV5,
        complete: &[u8],
        step: SourceNativeHeldStepV1,
        initial: RawPairedClockSample,
        deadline: u64,
        validity: (i64, i64),
        signatures: &mut OriginalProviderHeldSignaturesV5,
    ) -> bool {
        let crossing = match step {
            SourceNativeHeldStepV1::RootDispositionPrepared => RelayCrossingV5::Preparation,
            SourceNativeHeldStepV1::RelayStored => RelayCrossingV5::Delivery,
            _ => {
                signatures.relay.retain_failure(SourceProviderSecurityError::SessionContinuity.into());
                signatures.relay.stage = RelayStageV5::Closed;
                self.close_original_held_after_failure_v5();
                return false;
            }
        };
        self.observe_original_relay_v5(
            journal, readback, root, acquire, physical, lease, archive, selected,
            storage, complete, initial, deadline, validity, signatures, crossing,
        )
    }

    /// Dispatches the stored relay5 once on the same offered Storage transport.
    ///
    /// A nonconsuming readiness observation may remain pending. Any dispatched
    /// error is permanently closed and retained; success is not a remote ACK.
    #[doc(hidden)]
    pub fn send_original_relay_v5(
        &mut self,
        journal: &SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &OriginalSourceProtectedReadbackV5,
        root: &CurrentRootPreparedCarrierV1,
        acquire: &CurrentProviderRequestV1,
        physical: &crate::ProviderSourceRootHandoffV1,
        lease: &SignedSourceExportLeaseV1,
        archive: &crate::ProtectedOriginalConfigurationArchiveV5,
        selected: &crate::ProtectedOriginalSelectedInputV1,
        storage: &mut crate::OriginalStorageOfferTransportV5,
        complete: &[u8],
        initial: RawPairedClockSample,
        deadline: u64,
        validity: (i64, i64),
        signatures: &mut OriginalProviderHeldSignaturesV5,
    ) -> bool {
        self.observe_original_relay_v5(
            journal, readback, root, acquire, physical, lease, archive, selected,
            storage, complete, initial, deadline, validity, signatures, RelayCrossingV5::Send,
        )
    }

    fn observe_original_relay_v5(
        &mut self,
        journal: &SourceOriginalNativeJournalAuthorityV5<'_, '_>,
        readback: &OriginalSourceProtectedReadbackV5,
        root: &CurrentRootPreparedCarrierV1,
        acquire: &CurrentProviderRequestV1,
        physical: &crate::ProviderSourceRootHandoffV1,
        lease: &SignedSourceExportLeaseV1,
        archive: &crate::ProtectedOriginalConfigurationArchiveV5,
        selected: &crate::ProtectedOriginalSelectedInputV1,
        storage: &mut crate::OriginalStorageOfferTransportV5,
        complete: &[u8],
        initial: RawPairedClockSample,
        deadline: u64,
        validity: (i64, i64),
        signatures: &mut OriginalProviderHeldSignaturesV5,
        crossing: RelayCrossingV5<'_>,
    ) -> bool {
        let previous = signatures.relay.stage;
        let signing = matches!(crossing, RelayCrossingV5::Sign(_));
        let available = signatures.root_accepted().is_some()
            && self.failure_disposition == CurrentSessionFailureDispositionV5::OriginalHeldEnded
            && if signing {
                previous == RelayStageV5::Ready && !signatures.relay.attempted
            } else {
                matches!(previous, RelayStageV5::Signed | RelayStageV5::Sent)
            };
        if !available {
            // A terminal reentry must not overwrite the sample or postcheck
            // Result named by this same resident first-cause tag.
            signatures.relay.retain_failure(SourceProviderSecurityError::SessionContinuity.into());
            signatures.relay.stage = RelayStageV5::Closed;
            self.close_original_held_after_failure_v5();
            return false;
        }
        if signing {
            signatures.relay.attempted = true;
        }
        signatures.relay.stage = RelayStageV5::Checking;
        let mut boundary = RelayBoundaryV5 { session: self, signatures, completed: false };
        // The public genuine gate above ended before these disjoint loans. Raw
        // Root4 DATA never bypasses its debt/Received admission predicate.
        let held3 = boundary.signatures.signed.as_ref();
        let root4_owner = &boundary.signatures.root_accepted;
        let child = &mut boundary.signatures.relay;
        let action = (|| {
            if signing {
                let RelayCrossingV5::Sign(prepared) = crossing else {
                    return Err(SourceProviderSecurityError::SessionContinuity.into());
                };
                let aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1::Acquire(verified)
                    = acquire.verified() else {
                    return Err(SourceProviderSecurityError::SessionContinuity.into());
                };
                journal.claim_original_relay_signing_v5(
                    readback, verified.request().acquisition_id(),
                    held3.ok_or(SourceProviderSecurityError::SessionContinuity)?,
                    root4_owner.control().ok_or(SourceProviderSecurityError::SessionContinuity)?,
                    prepared,
                )?;
                // The fixed typed codec and complete actual all-eight/NEXT
                // basis are checked before copying this <=8192 preparation.
                // The original Source preparation remains resident as well.
                child.prepared = Some(prepared.clone());
            }
            root4_owner.revalidate_execution(boundary.session.carrier.socket().peer())?;
            boundary.session.require_original_held_bindings_v5(
                journal, readback, root, acquire, physical, lease, archive, selected,
                storage, child.binding_purpose(
                    crossing, held3.ok_or(SourceProviderSecurityError::SessionContinuity)?,
                    root4_owner.control().ok_or(SourceProviderSecurityError::SessionContinuity)?, complete,
                )?, initial, deadline, validity,
            )?;
            if signing {
                child.message = Some(child.prepared.as_ref()
                    .ok_or(SourceProviderSecurityError::SessionContinuity)?.signature_message());
            }
            child.sample(0, initial, deadline, validity)?;
            match crossing {
                RelayCrossingV5::Sign(_) => {
                    child.detached = Some(boundary.session.custody.inner().outcome_key()
                        .signing_key().sign(child.message.as_ref()
                            .ok_or(SourceProviderSecurityError::SessionContinuity)?).to_bytes());
                    if let (Some(prepared), Some(raw)) = (child.prepared.take(), child.detached) {
                        child.signed = Some(prepared.with_signature(raw));
                    }
                    Ok(true)
                }
                RelayCrossingV5::Send => {
                    if !child.transport_staged {
                        let staged = storage.stage_original_relay_v5(child.signed.as_ref()
                            .ok_or(SourceProviderSecurityError::SessionContinuity)?);
                        if storage.failure().is_some() {
                            // Staging can retain an actual native sample Err
                            // before returning a coarse boundary error. Keep
                            // that original lower cause ahead of upper debt.
                            if let Err(cause) = staged {
                                child.cause = Some(cause.into());
                            }
                            child.storage_cause = Some(OriginalHeldCauseV5::StorageRelay);
                            child.first = Some(RelayFirstFailureV5::Storage);
                            return Ok(false);
                        }
                        staged?;
                        child.transport_staged = true;
                    }
                    let sent = storage.advance_original_relay_v5();
                    if storage.failure().is_some() {
                        // The native owning Err stays in Storage, not a cloned
                        // proxy. Source records this marker before upper debt.
                        child.storage_cause = Some(OriginalHeldCauseV5::StorageRelay);
                        child.first = Some(RelayFirstFailureV5::Storage);
                        return Ok(false);
                    }
                    Ok(sent)
                }
                RelayCrossingV5::Preparation | RelayCrossingV5::Delivery => Ok(true),
            }
        })();
        let progressed = match action {
            Ok(progressed) => progressed,
            Err(cause) => {
                child.retain_failure(cause);
                false
            }
        };
        let execution = root4_owner.revalidate_execution(boundary.session.carrier.socket().peer())
            .map_err(OriginalHeldCauseV5::from);
        child.retain_postcheck(0, execution);
        let bindings = (|| {
            boundary.session.require_original_held_bindings_v5(
                journal, readback, root, acquire, physical, lease, archive, selected,
                storage, child.binding_purpose(
                    crossing, held3.ok_or(SourceProviderSecurityError::SessionContinuity)?,
                    root4_owner.control().ok_or(SourceProviderSecurityError::SessionContinuity)?, complete,
                )?, initial, deadline, validity,
            )
        })();
        child.retain_postcheck(1, bindings);
        let clock = child.sample(1, initial, deadline, validity);
        child.retain_postcheck(2, clock);
        if child.failure().is_some() {
            return false;
        }
        child.stage = if matches!(crossing, RelayCrossingV5::Send) && progressed {
            RelayStageV5::Sent
        } else if signing {
            RelayStageV5::Signed
        } else {
            previous
        };
        boundary.completed = true;
        progressed
    }
}

#[cfg(test)]
mod tests {
    //! UNRUN empty reservoir/diagnostic DATA only; no live Session is created.

    use super::*;

    #[test]
    fn empty_relay_cannot_supply_signed_data_or_delivery() {
        let signatures = OriginalProviderHeldSignaturesV5::pending(false);

        assert!(signatures.original_relay().is_none());
        assert!(!signatures.original_relay_sent());
        assert!(!signatures.original_relay_storage_failed());
        assert!(signatures.relay.stage == RelayStageV5::Unstarted);
        assert!(!signatures.relay.attempted);
    }

    #[test]
    fn first_validation_cause_precedes_postcheck_debt() {
        let mut relay = OriginalProviderRelayV5::pending();
        relay.retain_failure(aos_sandbox::JournalError::InvalidTransaction.into());
        relay.retain_postcheck(0, Err(SourceProviderSecurityError::SessionContinuity.into()));

        assert!(matches!(relay.failure().and_then(|cause| cause.downcast_ref::<OriginalHeldCauseV5>()),
            Some(OriginalHeldCauseV5::Journal(aos_sandbox::JournalError::InvalidTransaction))));
    }
}
