//! Bounded hot Storage6 continuation on the originally offered Source child.
//!
//! Existing AOSNSI02 reducers own the durable phase2 -> 3 -> 3 -> 4 grammar.
//! This child owns only resident crossings and their negative outcomes. A
//! locally sent kind6 is not Source receipt, retirement, release or Drain.

use aos_sandbox::journal::{CommitResult, JournalError, JournalTransaction};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::seqpacket::{
    ReceivedRecord, RetainedSeqpacketReceiveErrorV1,
    RetainedSeqpacketSendErrorV1, SeqpacketSocket,
};
use aos_sandbox_source_provider_protocol::native_held_completion::{
    MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1, NativeHeldControlKindV1 as Kind,
    NativeHeldOwnerV1 as Owner, NativeHeldSectionTagV1 as Tag,
    assertion::NativeHeldSettlementV1,
    frame::{NativeHeldSectionV1, NativeHeldSignerV1, PreparedNativeHeldControlV1, SignedNativeHeldControlV1},
    suffix::NativeHeldCompletionSuffixV1,
    witness::{NativeHeldByteWitnessV1, NativeHeldOwnerWitnessV1,
        NativeHeldRecordFamilyV1 as Family, StorageNativeHeldWitnessV1,
        native_held_record_byte_digest_v1},
};

use super::*;
use super::original_held_measurement::{
    OriginalHeldMeasurementErrorV3 as Error, OriginalHeldRecordV1,
    OriginalHeldCarrierReadV1, OriginalHeldSigningReadV1, OriginalHeldSigningPurposeV1,
};
use crate::live_export_request_trust::{AuthenticatedStorageNativeRequestV2, StorageLiveExportRequestTrustV1};
use crate::native_issuance::{
    StorageNativeIssuanceErrorV1,
    held_completion::{StorageHeldIssuanceRowV2, StorageHeldStepV1 as Step,
        MAXIMUM_STORAGE_HELD_ISSUANCE_VALUE_BYTES_V2},
};
use crate::peer::ProviderLiveExportPeerVerifier;
use crate::storage_zfs_hold_key::StorageZfsHoldKeyV1;

/// Resident actual outcomes, not a synthetic successful native receipt.
#[derive(Default)]
pub(crate) struct OriginalHeldAppendOutcomeV1 {
    pub(crate) preflight: Option<Result<(), JournalError>>,
    pub(crate) commit: Option<Result<CommitResult, JournalError>>,
    pub(crate) readback: Option<Result<u64, StorageNativeIssuanceErrorV1>>,
    pub(crate) attempted: bool,
    pub(crate) failure: Option<OriginalHeldAppendFailureV1>,
    pub(crate) clocks: [Option<Result<(), Error>>; 4],
}

#[derive(Clone, Copy)]
pub(crate) enum OriginalHeldAppendFailureV1 {
    Preflight,
    Commit,
    Readback,
    Clock(usize),
}

impl OriginalHeldAppendOutcomeV1 {
    pub(crate) fn first_cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.failure? {
            OriginalHeldAppendFailureV1::Preflight => self.preflight.as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            OriginalHeldAppendFailureV1::Commit => self.commit.as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            OriginalHeldAppendFailureV1::Readback => self.readback.as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            OriginalHeldAppendFailureV1::Clock(index) => self.clocks[index].as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
        }
    }

    pub(crate) fn check_clock(
        &mut self, index: usize, clock: &OriginalHeldAppendClockLoanV1<'_, '_, '_>,
    ) -> Result<(), StorageNativeIssuanceErrorV1> {
        if self.clocks.get(index).is_none_or(Option::is_some) {
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        self.clocks[index] = Some(clock.check());
        if self.clocks[index].as_ref().is_some_and(Result::is_err) {
            if self.failure.is_none() {
                self.failure = Some(OriginalHeldAppendFailureV1::Clock(index));
            }
            return Err(StorageNativeIssuanceErrorV1::Conflict);
        }
        Ok(())
    }
}

/// Borrows the genuine resident first pair, original cutoff and verified request.
pub(crate) struct OriginalHeldAppendClockLoanV1<'owner, 'request, 'trust> {
    original: &'owner super::original_held_measurement::ResidentOriginalV3,
    authenticated: &'request AuthenticatedStorageNativeRequestV2<'trust>,
}

impl<'owner, 'request, 'trust> OriginalHeldAppendClockLoanV1<'owner, 'request, 'trust> {
    pub(super) fn from_original(
        original: &'owner super::original_held_measurement::ResidentOriginalV3,
        authenticated: &'request AuthenticatedStorageNativeRequestV2<'trust>,
    ) -> Self {
        Self { original, authenticated }
    }

    fn check(&self) -> Result<(), Error> {
        self.authenticated.recheck()?;
        validate_original_clock(self.authenticated.request(),
            self.original.first.ok_or(Error::Closed)?,
            trusted_paired_clock_sample()?, self.original.cutoff.ok_or(Error::Closed)?)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SettlementPhaseV1 {
    Vacant,
    Receiving,
    Received,
    RelayStored,
    Prepared,
    Signing,
    Signed,
    Stored,
    Sending,
    Sent,
    Failed,
}

#[derive(Clone, Copy)]
enum SettlementFirstCauseV1 {
    Append(usize),
    Receive,
    Send,
    Other,
}

/// A fixed subordinate reservoir; no field is authority or a supplied FD.
pub(crate) struct OriginalHeldSettlementV1 {
    phase: SettlementPhaseV1,
    pub(super) appends: [OriginalHeldAppendOutcomeV1; 6],
    pub(super) signing_attempted: [bool; 2],
    receive: Option<Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>>,
    pending_record: Option<ReceivedRecord>,
    record: Option<OriginalHeldRecordV1>,
    relay: Option<SignedNativeHeldControlV1>,
    rows: [Option<StorageHeldIssuanceRowV2>; 3],
    transactions: [Option<JournalTransaction>; 3],
    readbacks: [Option<u64>; 3],
    control: Option<SignedNativeHeldControlV1>,
    packet: Option<Vec<u8>>,
    send: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    first: Option<SettlementFirstCauseV1>,
    failure: Option<Error>,
    postcheck_debt: Option<Error>,
    inventory: Option<OriginalHeldInventoryV1>,
}

impl Default for OriginalHeldSettlementV1 {
    fn default() -> Self {
        Self {
            phase: SettlementPhaseV1::Vacant,
            appends: std::array::from_fn(|_| OriginalHeldAppendOutcomeV1::default()),
            signing_attempted: [false; 2],
            receive: None,
            pending_record: None,
            record: None,
            relay: None,
            rows: [None, None, None],
            transactions: [None, None, None],
            readbacks: [None, None, None],
            control: None,
            packet: None,
            send: None,
            first: None,
            failure: None,
            postcheck_debt: None,
            inventory: None,
        }
    }
}

impl OriginalHeldSettlementV1 {
    pub(super) fn first_cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            SettlementFirstCauseV1::Append(index) => self.appends[index].first_cause(),
            SettlementFirstCauseV1::Receive => self.receive.as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            SettlementFirstCauseV1::Send => self.send.as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            SettlementFirstCauseV1::Other => self.failure.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
        }
    }

    pub(super) fn note_append_failure(&mut self, index: usize) {
        if self.first.is_none() && self.appends[index].first_cause().is_some() {
            self.first = Some(SettlementFirstCauseV1::Append(index));
        }
    }

    pub(super) fn retain_failure(&mut self, cause: Error) {
        self.phase = SettlementPhaseV1::Failed;
        if self.first.is_none() {
            self.first = Some(SettlementFirstCauseV1::Other);
            self.failure = Some(cause);
        } else if self.postcheck_debt.is_none() && !matches!(cause, Error::Closed) {
            self.postcheck_debt = Some(cause);
        }
    }

    pub(super) fn retain_postcheck_debt(&mut self, check: Result<(), Error>) {
        if let Err(cause) = check {
            if self.postcheck_debt.is_none() {
                self.postcheck_debt = Some(cause);
            }
        }
    }

    fn begin_receive(&mut self) -> Result<(), Error> {
        let inventory = self.inventory.as_ref().ok_or(Error::Closed)?;
        if self.phase != SettlementPhaseV1::Vacant
            || inventory.retained_data == 0
            || inventory.transient_data == 0
            || inventory.additional_fd_peak == 0
            || inventory.physical_rechecks > super::original_held_measurement::MAXIMUM_ORIGINAL_RECHECKS
        {
            return Err(Error::Closed);
        }
        self.phase = SettlementPhaseV1::Receiving;
        Ok(())
    }

    // Native errors remain first even when the final owner/clock bookend fails.
    fn finish_native_check(&mut self, check: Result<(), Error>) -> Result<(), Error> {
        match check {
            Ok(()) if self.first.is_none() => Ok(()),
            Ok(()) => Err(Error::Closed),
            Err(cause) if self.first.is_some() => {
                if self.postcheck_debt.is_none() {
                    self.postcheck_debt = Some(cause);
                }
                Err(Error::Closed)
            }
            Err(cause) => Err(cause),
        }
    }
}

/// Canonical DATA bounds, not allocator, kernel-memory or live-funding proof.
pub(super) struct OriginalHeldInventoryV1 {
    pub(super) retained_data: usize,
    pub(super) transient_data: usize,
    pub(super) additional_fd_peak: usize,
    pub(super) physical_rechecks: usize,
}

impl OriginalHeldSettlementV1 {
    pub(super) fn prepare_inventory(&mut self, shared_transient: usize) -> Result<usize, Error> {
        if self.inventory.is_some() || self.phase != SettlementPhaseV1::Vacant {
            return Err(Error::Closed);
        }
        let row = MAXIMUM_STORAGE_HELD_ISSUANCE_VALUE_BYTES_V2;
        let request = aos_sandbox_source_provider_protocol::MAXIMUM_SIGNED_STORAGE_NATIVE_ACQUIRE_REQUEST_BYTES_V2;
        let reply = aos_sandbox_source_provider_protocol::STORAGE_NATIVE_ACQUIRE_REPLY_BYTES_V3;
        let control = MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1;
        // Six retained rows and their PUT copies include nested request/reply
        // and archive bytes. Raw/parsed carrier request, resident original
        // request and cutoff copies, remaining raw/parsed controls, original
        // reply bodies and signature inputs are charged separately.
        // The pre-existing physical reader/worker reservoir is not counted as
        // proof of process-wide FD, heap or kernel-memory funding here.
        let retained = row.checked_mul(6)
            .and_then(|n| n.checked_add((row + 48 + 7).checked_mul(6)?))
            .and_then(|n| n.checked_add(request.checked_mul(4)?))
            .and_then(|n| n.checked_add(control.checked_mul(16)?))
            .and_then(|n| n.checked_add(reply.checked_mul(2)?))
            .and_then(|n| n.checked_add(std::mem::size_of::<Self>()))
            .ok_or(Error::Bound)?;
        // One canonical row/readback encoding and one native control signature
        // input coexist with the bounded shared replay/append working set.
        let transient = shared_transient.checked_add(row)
            .and_then(|n| n.checked_add(control.checked_mul(2)?))
            .ok_or(Error::Bound)?;
        // recvmsg has a fixed 512-byte ancillary buffer; both peek and consume
        // may park raw FD words before rejection. Alias and subject pins count,
        // even though the authorized message profile is zero-FD.
        let additional_fd_peak = (512 / std::mem::size_of::<i32>()) * 2 + 3;
        // Six old physical probes plus eleven fixed continuation bookends.
        // Poll-only EINTR does not add a worker probe.
        let physical_rechecks = 6 + 11;
        if physical_rechecks > super::original_held_measurement::MAXIMUM_ORIGINAL_RECHECKS {
            return Err(Error::Bound);
        }
        let reservation = retained.checked_add(transient).ok_or(Error::Bound)?;
        self.inventory = Some(OriginalHeldInventoryV1 {
            retained_data: retained, transient_data: transient,
            additional_fd_peak, physical_rechecks,
        });
        Ok(reservation)
    }
}

impl StorageBrokerRuntime {
    pub(super) fn settle_original_held_native(
        &mut self,
        index: usize,
        authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
        trust: &StorageLiveExportRequestTrustV1,
        verifier: &ProviderLiveExportPeerVerifier,
        key: &StorageZfsHoldKeyV1,
        child: &mut SeqpacketSocket,
        execution: Option<aos_sandbox_linux::pidfd::PidFdInfo>,
        records: &[Option<OriginalHeldRecordV1>; 2],
        stored: &StorageHeldIssuanceRowV2,
        state: &mut OriginalHeldSettlementV1,
    ) -> Result<(), Error> {
        state.begin_receive()?;
        self.check_original_held_current(index, authenticated, trust, verifier, key,
            carrier_read(child, execution, records), Some(stored), None)?;
        let cutoff = self.original_measurements.originals[index].cutoff.ok_or(Error::Closed)?;
        crate::zfs_hold_transport::wait_original_record(child.as_fd()?, cutoff)?;

        // Once the syscall is dispatched, every returned class is fatal; no
        // EAGAIN/EINTR branch can rearm or repeat this receive.
        state.receive = Some(child.receive_retaining(MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1));
        if state.receive.as_ref().is_some_and(Result::is_err) {
            state.first = Some(SettlementFirstCauseV1::Receive);
            let check = self.check_original_held_current(index, authenticated, trust, verifier, key,
                carrier_read(child, execution, records), Some(stored), None);
            state.finish_native_check(check)?;
            return Err(Error::Closed);
        }
        state.pending_record = match state.receive.take() {
            Some(Ok(record)) => Some(record),
            _ => return Err(Error::Closed),
        };
        let record = state.pending_record.take().ok_or(Error::Closed)?;
        match child.bind_received_retaining(record) {
            Ok(bound) => {
                let (bytes, subject, _) = bound.into_parts();
                state.record = Some(OriginalHeldRecordV1 { bytes, subject });
            }
            Err((cause, record)) => {
                state.pending_record = Some(record);
                return Err(Error::HeldBinding(cause));
            }
        }
        self.check_original_held_current(index, authenticated, trust, verifier, key,
            carrier_read(child, execution, records), Some(stored), state.record.as_ref())?;
        state.relay = Some(SignedNativeHeldControlV1::from_canonical_bytes(
            &state.record.as_ref().ok_or(Error::Closed)?.bytes)?);
        let relay = state.relay.as_ref().ok_or(Error::Closed)?;
        trust.verify_held_archive(relay, key.verifier())?;
        if relay.kind() != Kind::ProviderRelay
            || relay.scope() != stored.suffix().control(Kind::StorageHeld).ok_or(Error::Closed)?.scope()
        {
            return Err(Error::Closed);
        }
        state.phase = SettlementPhaseV1::Received;

        let request = authenticated.request();
        let mut controls = stored.suffix().controls().to_vec();
        controls.push(relay.clone());
        state.rows[0] = Some(StorageHeldIssuanceRowV2::new(request.clone(),
            self.original_measurements.originals[index].reply.as_ref().ok_or(Error::Closed)?
                .acceptance().acceptance().clone(), None,
            NativeHeldCompletionSuffixV1::new(Owner::Storage, 3, relay.scope().flight, None, controls)?)?);
        self.check_original_held_current(index, authenticated, trust, verifier, key,
            carrier_read(child, execution, records), Some(stored), state.record.as_ref())?;
        self.store_original_settlement_row(state, 0, Step::RootDispositionRecorded, index, authenticated)?;
        state.phase = SettlementPhaseV1::RelayStored;
        self.check_original_held_current(index, authenticated, trust, verifier, key,
            carrier_read(child, execution, records), state.rows[0].as_ref(), state.record.as_ref())?;

        let before = state.rows[0].as_ref().ok_or(Error::Closed)?;
        let assertion = before.settlement()?.ok_or(Error::Closed)?;
        let relay = state.relay.as_ref().ok_or(Error::Closed)?;
        let (trust_sequence, generation, file) = trust.held_trust_cut()?;
        let witness = NativeHeldOwnerWitnessV1::Storage(StorageNativeHeldWitnessV1 {
            local_socket_cookie: child.peer().socket_cookie().get(),
            primary_sequence: self.coordinator.native_metadata_readback_cut(
                Path::new("/var/lib/aos/sandbox-storage")).map_err(StorageRuntimeError::Admission)?.0,
            workspace_sequence: self.workspaces.as_ref().ok_or(Error::Closed)?
                .native_metadata_readback_cut(Path::new("/var/lib/aos/sandbox-storage"))
                .map_err(StorageRuntimeError::WorkspaceCatalog)?.journal_sequence(),
            request_trust_sequence: trust_sequence,
            issuance_sequence: state.readbacks[0].ok_or(Error::Closed)?,
            request_trust_generation: generation,
            request_trust_file: file,
            issuance: NativeHeldByteWitnessV1::new(Family::StorageIssuance,
                before.key().to_vec(), native_held_record_byte_digest_v1(
                    Family::StorageIssuance, &before.key(), &before.to_canonical_bytes()?)?)?,
        });
        let settlement = NativeHeldSettlementV1 {
            disposition: assertion.disposition,
            root_disposition: assertion.root_disposition,
            storage_settlement: assertion.digest()?,
            provider_settlement: ObjectDigest::from_bytes([0; 32]),
        };
        let prepared = PreparedNativeHeldControlV1::new(Kind::StorageSettled,
            *relay.scope(), relay.digest(), vec![
                NativeHeldSectionV1::new(Tag::Witness, witness.to_canonical_bytes()?)?,
                NativeHeldSectionV1::new(Tag::Settlement, settlement.to_canonical_bytes()?.to_vec())?,
            ], NativeHeldSignerV1::Storage(key.verifier().projection().0))?;
        state.rows[1] = Some(StorageHeldIssuanceRowV2::new(request.clone(),
            self.original_measurements.originals[index].reply.as_ref().ok_or(Error::Closed)?
                .acceptance().acceptance().clone(), None,
            NativeHeldCompletionSuffixV1::new(Owner::Storage, 3, relay.scope().flight,
                Some(prepared), before.suffix().controls().to_vec())?)?);
        self.check_original_held_current(index, authenticated, trust, verifier, key,
            carrier_read(child, execution, records), state.rows[0].as_ref(), state.record.as_ref())?;
        self.store_original_settlement_row(state, 1, Step::SettlementPrepared, index, authenticated)?;
        state.phase = SettlementPhaseV1::Prepared;
        self.check_original_held_current(index, authenticated, trust, verifier, key,
            carrier_read(child, execution, records), state.rows[1].as_ref(), state.record.as_ref())?;

        // Parent attempt is spent before key recheck/clone/message preparation;
        // the loan's own unused bit is spent later, inside the unchanged key recipe.
        if state.signing_attempted[1] {
            return Err(Error::Closed);
        }
        state.signing_attempted[1] = true;
        state.phase = SettlementPhaseV1::Signing;
        let mut signing = self.stored_original_signing_loan(index, authenticated, trust,
            OriginalHeldSigningReadV1 {
                original: carrier_read(child, execution, records), prepared: state.rows[1].as_ref(),
                before_sequence: state.readbacks[0], prepared_sequence: state.readbacks[1],
                relay_record: state.record.as_ref(), purpose: OriginalHeldSigningPurposeV1::Settlement,
            }, verifier)?;
        let signed = key.sign_stored_original_held_control(&mut signing);
        drop(signing);
        state.control = Some(signed?);
        state.phase = SettlementPhaseV1::Signed;
        self.check_original_held_current(index, authenticated, trust, verifier, key,
            carrier_read(child, execution, records), state.rows[1].as_ref(), state.record.as_ref())?;
        trust.verify_held_archive(state.control.as_ref().ok_or(Error::Closed)?, key.verifier())?;
        let original = &self.original_measurements.originals[index];
        let reply = original.reply.as_ref().ok_or(Error::Closed)?;
        let before = state.rows[0].as_ref().ok_or(Error::Closed)?;
        let mut controls = before.suffix().controls().to_vec();
        controls.push(state.control.as_ref().ok_or(Error::Closed)?.clone());
        state.rows[2] = Some(StorageHeldIssuanceRowV2::new(request.clone(),
            reply.acceptance().acceptance().clone(), None,
            NativeHeldCompletionSuffixV1::new(Owner::Storage, 4, before.suffix().flight(), None, controls)?)?);
        self.check_original_held_current(index, authenticated, trust, verifier, key,
            carrier_read(child, execution, records), state.rows[1].as_ref(), state.record.as_ref())?;
        self.store_original_settlement_row(state, 2, Step::SettlementStored, index, authenticated)?;
        state.phase = SettlementPhaseV1::Stored;
        self.check_original_held_current(index, authenticated, trust, verifier, key,
            carrier_read(child, execution, records), state.rows[2].as_ref(), state.record.as_ref())?;
        state.packet = Some(state.control.as_ref().ok_or(Error::Closed)?.to_canonical_bytes());
        if state.packet.as_ref().is_none_or(|packet| packet.len() > MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1) {
            return Err(Error::Bound);
        }
        self.check_original_held_current(index, authenticated, trust, verifier, key,
            carrier_read(child, execution, records), state.rows[2].as_ref(), state.record.as_ref())?;
        state.phase = SettlementPhaseV1::Sending;
        state.send = Some(child.send_retaining(state.packet.as_deref().ok_or(Error::Closed)?));
        if state.send.as_ref().is_some_and(Result::is_err) {
            state.first = Some(SettlementFirstCauseV1::Send);
        }
        let check = self.check_original_held_current(index, authenticated, trust, verifier, key,
            carrier_read(child, execution, records), state.rows[2].as_ref(), state.record.as_ref());
        state.finish_native_check(check)?;
        state.phase = SettlementPhaseV1::Sent;
        Ok(())
    }

    fn store_original_settlement_row(
        &mut self, state: &mut OriginalHeldSettlementV1, slot: usize, step: Step,
        index: usize, authenticated: &AuthenticatedStorageNativeRequestV2<'_>,
    ) -> Result<(), Error> {
        let clock = OriginalHeldAppendClockLoanV1::from_original(
            &self.original_measurements.originals[index], authenticated);
        let result = self.native_issuance.as_mut().ok_or(Error::Closed)?
            .store_original_held_row_retaining(state.rows[slot].as_ref().ok_or(Error::Closed)?,
                step, &mut state.transactions[slot], &mut state.appends[slot + 3], &clock);
        state.note_append_failure(slot + 3);
        if state.appends[slot + 3].first_cause().is_some() {
            return Err(Error::Closed);
        }
        state.readbacks[slot] = Some(result?);
        Ok(())
    }
}

fn carrier_read<'owner>(
    child: &'owner SeqpacketSocket,
    execution: Option<aos_sandbox_linux::pidfd::PidFdInfo>,
    records: &'owner [Option<OriginalHeldRecordV1>; 2],
) -> OriginalHeldCarrierReadV1<'owner> {
    OriginalHeldCarrierReadV1 { child: Some(child), execution, records }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_signing_attempt_stays_spent_after_failure() {
        let mut state = OriginalHeldSettlementV1::default();
        state.signing_attempted[1] = true;
        state.retain_failure(Error::Closed);
        assert!(state.signing_attempted[1]);
        assert!(state.begin_receive().is_err());
    }

    #[test]
    fn a_spent_receive_cannot_be_rearmed_from_data() {
        let mut state = OriginalHeldSettlementV1::default();
        state.inventory = Some(OriginalHeldInventoryV1 {
            retained_data: 1, transient_data: 1, additional_fd_peak: 1, physical_rechecks: 17,
        });
        assert!(state.begin_receive().is_ok());
        assert!(state.begin_receive().is_err());
    }

    #[test]
    fn later_debt_does_not_replace_the_first_concrete_failure() {
        let mut state = OriginalHeldSettlementV1::default();
        state.retain_failure(Error::Bound);
        state.retain_failure(Error::Closed);
        assert!(state.first_cause().is_some());
        assert!(matches!(state.failure, Some(Error::Bound)));
    }
}
