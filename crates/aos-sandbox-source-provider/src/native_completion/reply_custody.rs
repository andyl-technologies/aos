//! One owner-local native completion retained beyond its single wire handoff.
//!
//! Reservation identity is comparison data, not live authority. Only the
//! original observation received by the native executor supplies the Storage
//! endpoint, verifier owner, original descriptor and unchanged clock anchor.
//! Neither successful send nor carrier failure establishes Root acknowledgement
//! or Storage writer fencing, so neither releases this slot.

use aos_sandbox_source_provider_protocol::{
    SignedSourceProviderRequestV1, decode_acquire_request, digest_signed_request,
};
use aos_sandbox_source_provider_security::CommittedProviderOutcomeV1;

use super::*;
use crate::backend::ObservedBackendAcquisitionV1;

/// Identifies the original admission without supplying any admission authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeReplyIdentity {
    pub(crate) acquisition: ObjectDigest,
    pub(crate) attempt: ObjectDigest,
    pub(crate) session: ObjectDigest,
    pub(crate) signed_request: ObjectDigest,
}

/// Names one exact internal cut without granting admission or replay authority.
#[derive(Clone, Copy)]
pub(crate) enum NativeReplyPhase {
    Requested,
    Prepared,
}

/// Compares an internal reauthentication to its original slot and durable cut.
#[derive(Clone, Copy)]
pub(crate) struct NativeReplyReauthentication {
    pub(crate) identity: NativeReplyIdentity,
    pub(crate) phase: NativeReplyPhase,
}

impl NativeReplyReauthentication {
    pub(crate) fn require_record(
        &self,
        record: &NativeAcquireCompletionRecordV2,
        original_signed_bytes: &[u8],
    ) -> Result<(), ProviderLedgerError> {
        let expected = match self.phase {
            NativeReplyPhase::Requested => NativeAcquireCompletionStateV2::Requested,
            NativeReplyPhase::Prepared => NativeAcquireCompletionStateV2::Prepared,
        };
        record
            .validate_canonical_artifacts()
            .map_err(crate::transaction::map_pure_ledger_error)?;
        let original = record
            .canonical_request
            .as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?
            .request()
            .signed_root_request();
        if record.state != expected
            || record.acquisition_id != self.identity.acquisition
            || record.attempt_digest != self.identity.attempt
            || record.session_binding != self.identity.session
            || record.root_request_digest != self.identity.signed_request
            || original.to_canonical_bytes().as_slice() != original_signed_bytes
            || record.original_clock.is_none()
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        Ok(())
    }
}

#[derive(Default)]
enum SendState {
    #[default]
    Uncompleted,
    Unattempted,
    Attempted,
}

/// Holds at most one original; cold recovery cannot reconstruct these fields.
#[derive(Default)]
pub(crate) struct NativeReplyCustody {
    identity: Option<NativeReplyIdentity>,
    observed: Option<ObservedBackendAcquisitionV1>,
    committed: Option<CommittedProviderOutcomeV1>,
    send: SendState,
}

impl NativeReplyCustody {
    pub(crate) fn require_candidate_available(
        &self,
        native: bool,
    ) -> Result<(), ProviderLedgerError> {
        if native {
            self.require_empty()?;
        }
        Ok(())
    }

    pub(crate) fn require_empty(&self) -> Result<(), ProviderLedgerError> {
        if self.identity.is_some() {
            return Err(ProviderLedgerError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn reserve(
        &mut self,
        identity: NativeReplyIdentity,
    ) -> Result<(), ProviderLedgerError> {
        self.require_empty()?;
        self.identity = Some(identity);
        Ok(())
    }

    pub(crate) fn require_reserved(
        &self,
        identity: NativeReplyIdentity,
    ) -> Result<(), ProviderLedgerError> {
        if self.identity != Some(identity)
            || self.observed.is_some()
            || self.committed.is_some()
            || !matches!(self.send, SendState::Uncompleted)
        {
            return Err(ProviderLedgerError::Unavailable);
        }
        Ok(())
    }

    // The executor checks the empty reserved slot before dispatch. Installing
    // before any subsequent validation ensures failure cannot drop the origin.
    pub(crate) fn retain_observed(&mut self, observed: ObservedBackendAcquisitionV1) {
        self.observed = Some(observed);
    }

    pub(crate) fn lend_observed(
        &mut self,
    ) -> Result<ObservedBackendAcquisitionV1, ProviderLedgerError> {
        self.observed.take().ok_or(ProviderLedgerError::Unavailable)
    }

    // Only the completion wrapper lends this field, under an exclusive ledger
    // borrow; it restores the same object on every Result path, without a CAS
    // failure that could itself discard the lent original.
    pub(crate) fn restore_observed(&mut self, observed: ObservedBackendAcquisitionV1) {
        self.observed = Some(observed);
    }

    pub(crate) fn retain_committed(&mut self, committed: CommittedProviderOutcomeV1) {
        self.committed = Some(committed);
        self.send = SendState::Unattempted;
    }

    pub(crate) fn matches_request(&self, signed: &SignedSourceProviderRequestV1) -> bool {
        self.identity
            .is_some_and(|identity| identity.signed_request == digest_signed_request(signed))
    }

    pub(crate) fn begin_send(
        &mut self,
        identity: NativeReplyIdentity,
        session: ObjectDigest,
    ) -> Result<(&ObservedBackendAcquisitionV1, &CommittedProviderOutcomeV1), ProviderLedgerError>
    {
        if self.identity != Some(identity) || !matches!(self.send, SendState::Unattempted) {
            return Err(ProviderLedgerError::Unavailable);
        }
        // One attempted handoff is consumed even if a pre-send check fails.
        // A retry would need genuine disposition, which this seam does not add.
        self.send = SendState::Attempted;
        let observed = self
            .observed
            .as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?;
        let committed = self
            .committed
            .as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?;
        if committed.session_binding() != session
            || identity.session != session
            || observed.native.is_none()
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        Ok((observed, committed))
    }
}

impl NativeReplyIdentity {
    pub(crate) fn for_request(
        signed: &SignedSourceProviderRequestV1,
        attempt: ObjectDigest,
    ) -> Result<Self, ProviderLedgerError> {
        let request = decode_acquire_request(signed.subject())
            .map_err(|_| ProviderLedgerError::Equivocation)?;
        Ok(Self {
            acquisition: request.acquisition_id(),
            attempt,
            session: request.session_binding(),
            signed_request: digest_signed_request(signed),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(byte: u8) -> NativeReplyIdentity {
        NativeReplyIdentity {
            acquisition: ObjectDigest::from_bytes([byte; 32]),
            attempt: ObjectDigest::from_bytes([byte + 1; 32]),
            session: ObjectDigest::from_bytes([byte + 2; 32]),
            signed_request: ObjectDigest::from_bytes([byte + 3; 32]),
        }
    }

    fn signed_root(record: &NativeAcquireCompletionRecordV2) -> Vec<u8> {
        record
            .canonical_request
            .as_ref()
            .unwrap()
            .request()
            .signed_root_request()
            .to_canonical_bytes()
    }

    fn cut(
        record: &NativeAcquireCompletionRecordV2,
        phase: NativeReplyPhase,
    ) -> NativeReplyReauthentication {
        NativeReplyReauthentication {
            identity: NativeReplyIdentity::for_request(
                record
                    .canonical_request
                    .as_ref()
                    .unwrap()
                    .request()
                    .signed_root_request(),
                record.attempt_digest,
            )
            .unwrap(),
            phase,
        }
    }

    #[test]
    fn requested_and_prepared_internal_cuts_refuse_phase_substitution() {
        // These are the existing canonical signed DATA records, not live
        // endpoint/observation tokens or an installed bridge qualification.
        let requested =
            super::super::fixture_requested([1; 32], 500, ObjectDigest::from_bytes([2; 32]));
        let prepared = super::super::fixture_prepared(&requested);
        let active = prepared
            .advance(NativeAcquireCompletionStateV2::Active)
            .unwrap();
        let cleanup = prepared
            .advance(NativeAcquireCompletionStateV2::CleanupRequired)
            .unwrap();
        let original = signed_root(&requested);
        let requested_cut = cut(&requested, NativeReplyPhase::Requested);
        let prepared_cut = cut(&prepared, NativeReplyPhase::Prepared);

        assert!(requested_cut.require_record(&requested, &original).is_ok());
        assert!(prepared_cut.require_record(&prepared, &original).is_ok());
        assert!(requested_cut.require_record(&prepared, &original).is_err());
        assert!(prepared_cut.require_record(&requested, &original).is_err());
        for record in [&active, &cleanup] {
            assert!(requested_cut.require_record(record, &original).is_err());
            assert!(prepared_cut.require_record(record, &original).is_err());
        }
    }

    #[test]
    fn internal_cut_requires_full_original_identity_bytes_clock_and_artifacts() {
        let requested =
            super::super::fixture_requested([1; 32], 500, ObjectDigest::from_bytes([2; 32]));
        let prepared = super::super::fixture_prepared(&requested);
        let original = signed_root(&requested);
        let expected = cut(&prepared, NativeReplyPhase::Prepared);
        let different = ObjectDigest::from_bytes([99; 32]);
        let mutations = [
            NativeReplyIdentity {
                acquisition: different,
                ..expected.identity
            },
            NativeReplyIdentity {
                attempt: different,
                ..expected.identity
            },
            NativeReplyIdentity {
                session: different,
                ..expected.identity
            },
            NativeReplyIdentity {
                signed_request: different,
                ..expected.identity
            },
        ];

        for identity in mutations {
            let changed = NativeReplyReauthentication {
                identity,
                ..expected
            };
            assert!(changed.require_record(&prepared, &original).is_err());
        }
        let foreign = super::super::fixture_requested([3; 32], 501, different);
        assert!(
            expected
                .require_record(&prepared, &signed_root(&foreign))
                .is_err()
        );
        let mut changed = prepared.clone();
        changed.receipt_digest = different;
        assert!(expected.require_record(&changed, &original).is_err());
        let mut no_clock = prepared.clone();
        no_clock.original_clock = None;
        assert!(expected.require_record(&no_clock, &original).is_err());

        let mut slot = NativeReplyCustody::default();
        slot.reserve(expected.identity).unwrap();
        assert!(slot.require_reserved(expected.identity).is_ok());
        assert!(slot.require_reserved(mutations[0]).is_err());
        assert!(slot.require_empty().is_err());
        assert!(
            slot.begin_send(expected.identity, expected.identity.session)
                .is_err()
        );
    }

    #[test]
    fn reservation_is_bounded_and_never_substitutes_for_a_live_observation() {
        let mut slot = NativeReplyCustody::default();
        slot.reserve(identity(1)).unwrap();

        assert!(slot.reserve(identity(5)).is_err());
        assert!(slot.require_reserved(identity(5)).is_err());
        assert!(slot.begin_send(identity(1), identity(1).session).is_err());
        assert!(slot.lend_observed().is_err());
        assert_eq!(slot.identity, Some(identity(1)));
        assert!(slot.require_empty().is_err());
    }

    #[test]
    fn cold_slot_has_no_observation_or_reconstructed_send_authority() {
        let mut slot = NativeReplyCustody::default();

        assert!(slot.begin_send(identity(1), identity(1).session).is_err());
        assert!(slot.lend_observed().is_err());
        assert!(slot.require_empty().is_ok());
    }
}
