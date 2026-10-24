//! Borrows the same copied receipt and Ready framing across live stage intervals.
//!
//! The constructor splits actual resident fields before borrowing slices. Its
//! negative return keeps the mutable body borrower until the caller parks the
//! real primary, so no partial, native owner or copied recipe is discarded.

use super::super::initial_bundle::RootInitialBundleOwnershipOriginalV1;
use super::super::initial_ready::RootInitialReadyOriginalV1;
use super::super::initial_source_exchange::RootInitialSourceExchangeOriginalV1;
use super::super::owned::RootCurrentAcceptedOriginalsV1;
use super::super::writers::RootCurrentWritersOriginalV1;
use super::*;
use aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes;

/// Borrows Initial's same prepared Controller body and immutable original recipes.
///
/// Only the genuine owned Current constructs this borrower. Its private fields
/// retain the real producer, stage reservoirs, rooted reader and copied receipt;
/// supplied receipt/bundle DATA cannot construct or substitute it.
pub struct RootInitialControllerReadonlyPreparedBorrowV1<'scope, 'startup, 'inputs> {
    pub(super) state: &'scope mut RootInitialControllerReadonlyBodyV1,
    pub(super) purpose: RootControllerPurposeBorrowV1<'scope>,
    pub(super) receipt: InputsReadyNativeReceiptDataV1<'scope>,
    pub(super) bundle: ReadyBundleDataV1<'scope>,
    pub(super) open: &'scope RootInitialOpenPreparedOriginalV1,
    pub(super) ready: &'scope RootInitialReadyOriginalV1,
    pub(super) cache: &'scope RootInitialCacheProofOriginalV1,
    pub(super) source: &'scope RootInitialSourceExchangeOriginalV1,
    pub(super) ownership: &'scope RootInitialBundleOwnershipOriginalV1,
    pub(super) policy_data: &'scope RootCurrentPolicyInputDataV1<'inputs>,
    pub(super) writers: &'scope RootCurrentWritersOriginalV1,
    pub(super) originals: &'scope RootCurrentAcceptedOriginalsV1<'startup>,
}

impl RootInitialControllerReadonlyOriginalV1 {
    pub(in crate::native::root_current) fn borrow_prepared_once_v1<'scope, 'startup, 'inputs>(
        &'scope mut self,
        writers: &'scope RootCurrentWritersOriginalV1,
        open: &'scope RootInitialOpenPreparedOriginalV1,
        ready: &'scope RootInitialReadyOriginalV1,
        cache: &'scope RootInitialCacheProofOriginalV1,
        source: &'scope RootInitialSourceExchangeOriginalV1,
        ownership: &'scope RootInitialBundleOwnershipOriginalV1,
        policy_data: &'scope RootCurrentPolicyInputDataV1<'inputs>,
        originals: &'scope RootCurrentAcceptedOriginalsV1<'startup>,
    ) -> Result<RootInitialControllerReadonlyPreparedBorrowV1<'scope, 'startup, 'inputs>, E> {
        let prepared = RootInitialControllerReadonlyPreparedBorrowV1::prepare_inner(
            &mut self.body,
            &mut self.receipt,
            writers,
            open,
            ready,
            cache,
            source,
            ownership,
            policy_data,
            originals,
            RootControllerPurposeBorrowV1::Initial,
        );
        match prepared {
            Ok(prepared) => Ok(prepared),
            Err((error, state)) => {
                state.primary.get_or_insert(Err(error));
                Err(E::Incomplete)
            }
        }
    }

    pub(in crate::native::root_current) fn borrow_reserved_prepared_once_v1<'scope, 'startup, 'inputs>(
        &'scope mut self,
        writers: &'scope RootCurrentWritersOriginalV1,
        open: &'scope RootInitialOpenPreparedOriginalV1,
        ready: &'scope RootInitialReadyOriginalV1,
        cache: &'scope RootInitialCacheProofOriginalV1,
        source: &'scope RootInitialSourceExchangeOriginalV1,
        ownership: &'scope RootInitialBundleOwnershipOriginalV1,
        policy_data: &'scope RootCurrentPolicyInputDataV1<'inputs>,
        originals: &'scope RootCurrentAcceptedOriginalsV1<'startup>,
        authorization: &'scope super::super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1,
        received: &'scope super::super::use_tail::reserved::RootUseReservedReceivedOriginalV1,
    ) -> Result<RootInitialControllerReadonlyPreparedBorrowV1<'scope, 'startup, 'inputs>, E> {
        let prepared = RootInitialControllerReadonlyPreparedBorrowV1::prepare_inner(
            &mut self.body,
            &mut self.receipt,
            writers,
            open,
            ready,
            cache,
            source,
            ownership,
            policy_data,
            originals,
            RootControllerPurposeBorrowV1::Reserved {
                authorization,
                received,
            },
        );
        match prepared {
            Ok(prepared) => Ok(prepared),
            Err((error, state)) => {
                state.primary.get_or_insert(Err(error));
                Err(E::Incomplete)
            }
        }
    }
}

impl<'scope, 'startup, 'inputs>
    RootInitialControllerReadonlyPreparedBorrowV1<'scope, 'startup, 'inputs>
{
    fn prepare_inner(
        state: &'scope mut RootInitialControllerReadonlyBodyV1,
        copied_receipt: &'scope mut [u8; INPUTS_READY_RECEIPT_BYTES_V1],
        writers: &'scope RootCurrentWritersOriginalV1,
        open: &'scope RootInitialOpenPreparedOriginalV1,
        ready: &'scope RootInitialReadyOriginalV1,
        cache: &'scope RootInitialCacheProofOriginalV1,
        source: &'scope RootInitialSourceExchangeOriginalV1,
        ownership: &'scope RootInitialBundleOwnershipOriginalV1,
        policy_data: &'scope RootCurrentPolicyInputDataV1<'inputs>,
        originals: &'scope RootCurrentAcceptedOriginalsV1<'startup>,
        purpose: RootControllerPurposeBorrowV1<'scope>,
    ) -> Result<Self, (E, &'scope mut RootInitialControllerReadonlyBodyV1)> {
        // This is the ordinary `?` conversion with the actual body borrower
        // returned on failure. It creates no runtime closure or native adapter.
        macro_rules! retain_body {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => return Err((E::from(error), state)),
                }
            };
        }

        if !state.body_entered || state.primary.is_some() || state.mount_entered || state.closed {
            state.closed = true;
            return Err((E::Incomplete, state));
        }
        state.mount_entered = true;
        if state.suffix_segments != purpose.segments_v1() {
            state.closed = true;
            return Err((E::Incomplete, state));
        }
        if !matches!(purpose, RootControllerPurposeBorrowV1::Initial | RootControllerPurposeBorrowV1::Reserved { .. }) {
            state.tail_preparation = Some(purpose.require_preparation_v1(open));
            retain_body!(positive(&state.tail_preparation));
        }
        retain_body!(positive(&state.peer_arm));
        retain_body!(cache.require_complete_v1());
        retain_body!(source.require_complete_v1().map_err(|_| E::Incomplete));
        if let RootControllerPurposeBorrowV1::Signed { received, admitted, input, .. } = purpose {
            retain_body!(state.signed_suffix.prepare_once(retain_body!(open.body_v1()).open.lane, received, admitted, input));
        }
        state.receipt_copy = Some(
            cache
                .controller_receipt_v1(open, ready)
                .map_err(E::from)
                .and_then(|receipt| {
                    receipt
                        .encode(open.body_v1()?.open.lane)
                        .map_err(|_| E::Incomplete)
                })
                .map(|bytes| *copied_receipt = bytes),
        );
        retain_body!(positive(&state.receipt_copy));
        let body = retain_body!(open.body_v1());
        state.purpose_root_nonce = Some(body.root_nonce);
        // The mutable receipt loan ends here. Every later phase borrows the
        // SAME copied immutable bytes; there is no self-reference or reparse.
        let copied_receipt: &'scope [u8; INPUTS_READY_RECEIPT_BYTES_V1] = copied_receipt;
        let receipt = match InputsReadyNativeReceiptDataV1::decode(copied_receipt, body.open.lane) {
            Ok(receipt) => {
                state.receipt_decoding = Some(Ok(()));
                receipt
            }
            Err(cause) => {
                state.receipt_decoding = Some(Err(cause));
                return Err((E::Incomplete, state));
            }
        };
        let key = retain_body!(
            KeyV1::new(body.open.lane, OwnerV1::Controller, 3).map_err(|_| E::Incomplete)
        );
        let phase = retain_body!(PhaseV1::new(OwnerV1::Controller, 2).map_err(|_| E::Incomplete));
        state.expected = Some(super::body::prepare_readonly_pair(
            key,
            phase,
            receipt.record,
            &receipt.latest_head,
        ));
        let expected = retain_body!(positive(&state.expected));
        state.coordinates = Some((|| {
            let bytes = encoded_transaction_append_bytes(expected)
                .map_err(|error| ReadError::from(Mechanical::from(error)))?;
            let next = receipt
                .after_next
                .checked_sub(4)
                .filter(|next| *next != 0)
                .ok_or(ReadError::ProtectedBoundary)?;
            let end = receipt
                .after_end
                .checked_sub(bytes)
                .ok_or(ReadError::ProtectedBoundary)?;
            Ok((next, end))
        })());
        retain_body!(positive(&state.coordinates));
        let raw = retain_body!(ready.raw_ready_bytes_v1());
        let bundle = retain_body!(
            ReadyBundleDataV1::borrow_field_framing_data_v1(raw).map_err(|_| E::Incomplete)
        );
        state.storage_width = Some(
            super::super::storage_inventory::RootCurrentStorageInventoryV1::encoded_width_v1(
                bundle,
            ),
        );
        retain_body!(positive(&state.storage_width));
        state.compiler_root_width = Some(policy_data.encoded_width_v1().map_err(ReadError::from));
        retain_body!(positive(&state.compiler_root_width));
        state.history_geometry = Some(
            ControllerHistoryGeometryV1::from_bundle(bundle, receipt).map_err(ReadError::from),
        );
        retain_body!(positive(&state.history_geometry));
        let (authority, policy) =
            retain_body!(writers.opened_pair_view_v1().map_err(|_| E::Incomplete));
        state.before.observe_once_v1(authority, policy);
        retain_body!(state.before.require_complete_v1());
        state.before_readback = Some(purpose.readback_v1(open, authority, policy));
        retain_body!(positive(&state.before_readback));
        state.before_sample = Some(state.before_clock.observe_once(None));
        state.before_cutoff = Some(super::super::initial_cache::require_clock(
            open,
            source,
            &state.before_sample,
        ));
        retain_body!(positive(&state.before_cutoff));
        state.expected_end = Some(retain_body!(purpose.after_end_v1(body.open.lane, receipt, state)));
        state
            .reader
            .prepare_current_mount_once_v1(body.controller_uid, receipt.names.directory());
        if state.reader.failure().is_some() {
            return Err((E::Incomplete, state));
        }
        Ok(Self {
            state,
            purpose,
            receipt,
            bundle,
            open,
            ready,
            cache,
            source,
            ownership,
            policy_data,
            writers,
            originals,
        })
    }

    /// Borrows the first retained cause from this same prepared Controller body.
    ///
    /// This passive view permits the actual caller to preserve an earlier body
    /// failure before attempting a later upper exclusion. It observes no native
    /// state and constructs neither an admission nor a completion.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.state.failure_v1()
    }

    /// Repeats the actual fixed-stage receiver check after the original mount.
    ///
    /// # Errors
    /// Retains genuine predecessor, same-Initial or live fixed-stage refusal.
    pub fn admit_named_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let predecessor = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.state
                    .receiving
                    .park_named_predecessor_refusal_v1(error);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        self.state
            .admit_named_once_v1(self.open, predecessor, exclusion)
    }

    /// Parks an actual upper lock/borrow refusal as a nonissuing marker.
    pub fn refuse_named_entry_once_v1(&mut self) {
        self.state.refuse_named_entry_once_v1();
    }

    /// Opens the same bound files after the reached live named admission.
    ///
    /// # Errors
    /// Retains the original opening, captured names, metadata or exact-end refusal.
    pub fn prepare_files_once_v1(&mut self) -> Result<(), E> {
        self.state.prepare_files_once_v1(self.receipt)
    }

    /// Pays the captured native pass and its two exact expected-transaction copies.
    ///
    /// # Errors
    /// Retains genuine predecessor, same-Initial, quote, debit or service refusal.
    pub fn admit_native_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let predecessor = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.state.native_predecessor.get_or_insert(error);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        let mut predecessor = predecessor;
        if !matches!(self.purpose, RootControllerPurposeBorrowV1::Initial | RootControllerPurposeBorrowV1::Reserved { .. }) {
            self.state.tail_native = Some(self.purpose.require_stage_v1(self.open).and_then(|()| {
                if self.purpose.same_financial_v1(predecessor.split_initial_v1().1) { Ok(()) }
                else { Err(super::tail_purpose::TailPurposeErrorV1::Boundary) }
            }));
            if positive(&self.state.tail_native).is_err() {
                // The predecessor still lends the SAME Initial; park the typed
                // cause before latching its nonissuing returned marker.
                predecessor.split_initial_v1().0.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        }
        self.state
            .begin_native_once_v1(self.open, predecessor, startup, exclusion)
    }

    /// Allocates the same expected copies and audits the same captured file once.
    ///
    /// # Errors
    /// Retains native-stage, recipe, full native Audit or bank-history refusal.
    pub fn audit_native_once_v1(&mut self) -> Result<(), E> {
        self.state.audit_native_once_v1(self.bundle)?;
        let state = self.state.reader.current_audit_original_v1().native_data_v1()
            .and_then(|native| native.state()).ok_or(E::Incomplete)?;
        match self.purpose {
            RootControllerPurposeBorrowV1::Outcome { received, admitted, signed, input, .. } => {
                self.state.outcome_suffix.observe_once(state, self.bundle.lane, signed, admitted, received,
                    input.recorded_receipt_v1(self.bundle.lane).map_err(|_| E::Incomplete)?)?;
            }
            RootControllerPurposeBorrowV1::Closed { reserved, outcome, input, .. } => {
                self.state.closed_suffix.observe_once(state, self.bundle.lane, reserved, outcome, input)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Pays the audited semantic peak and genuine model/compiler/Storage receivers.
    ///
    /// # Errors
    /// Retains genuine predecessor, same-Initial, quote, debit or service refusal.
    pub fn admit_semantic_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let predecessor = match self
            .originals
            .peer
            .borrow_current_writers_predecessor_v1(initial)
        {
            Ok(predecessor) => predecessor,
            Err(error) => {
                self.state.semantic_predecessor.get_or_insert(error);
                initial.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        };
        let mut predecessor = predecessor;
        if !matches!(self.purpose, RootControllerPurposeBorrowV1::Initial | RootControllerPurposeBorrowV1::Reserved { .. }) {
            self.state.tail_semantic = Some(self.purpose.require_stage_v1(self.open).and_then(|()| {
                if self.purpose.same_financial_v1(predecessor.split_initial_v1().1) { Ok(()) }
                else { Err(super::tail_purpose::TailPurposeErrorV1::Boundary) }
            }));
            if positive(&self.state.tail_semantic).is_err() {
                // The predecessor still lends the SAME Initial; park the typed
                // cause before latching its nonissuing returned marker.
                predecessor.split_initial_v1().0.latch_root_refusal_v1();
                return Err(RootObservationErrorV1::Service);
            }
        }
        self.state
            .begin_semantic_once_v1(self.open, predecessor, startup, exclusion)
    }
}

impl RootInitialControllerReadonlyOriginalV1 {
    pub(in crate::native::root_current) fn borrow_signed_prepared_once_v1<'scope, 'startup, 'inputs>(
        &'scope mut self,
        writers: &'scope RootCurrentWritersOriginalV1,
        open: &'scope RootInitialOpenPreparedOriginalV1,
        ready: &'scope RootInitialReadyOriginalV1,
        cache: &'scope RootInitialCacheProofOriginalV1,
        source: &'scope RootInitialSourceExchangeOriginalV1,
        ownership: &'scope RootInitialBundleOwnershipOriginalV1,
        policy_data: &'scope RootCurrentPolicyInputDataV1<'inputs>,
        originals: &'scope RootCurrentAcceptedOriginalsV1<'startup>,
        authorization: &'scope super::purpose::RootInitialUseAuthorizedOriginalV1,
        reserved: &'scope super::purpose::RootUseReservedOriginalV1,
        admitted: &'scope super::purpose::RootUseAdmittedOriginalV1,
        input: &'scope super::purpose::RootSignedInputOriginalV1,
    ) -> Result<RootInitialControllerReadonlyPreparedBorrowV1<'scope, 'startup, 'inputs>, E> {
        let received = match reserved.received_original_v1() {
            Ok(received) => received,
            Err(_) => { self.body.primary.get_or_insert(Err(E::Incomplete)); return Err(E::Incomplete); }
        };
        match RootInitialControllerReadonlyPreparedBorrowV1::prepare_inner(
            &mut self.body, &mut self.receipt, writers, open, ready, cache, source,
            ownership, policy_data, originals,
            RootControllerPurposeBorrowV1::Signed { authorization, reserved, received, admitted, input },
        ) {
            Ok(prepared) => Ok(prepared),
            Err((error, state)) => { state.primary.get_or_insert(Err(error)); Err(E::Incomplete) }
        }
    }

    pub(in crate::native::root_current) fn borrow_outcome_prepared_once_v1<'scope, 'startup, 'inputs>(
        &'scope mut self,
        writers: &'scope RootCurrentWritersOriginalV1,
        open: &'scope RootInitialOpenPreparedOriginalV1,
        ready: &'scope RootInitialReadyOriginalV1,
        cache: &'scope RootInitialCacheProofOriginalV1,
        source: &'scope RootInitialSourceExchangeOriginalV1,
        ownership: &'scope RootInitialBundleOwnershipOriginalV1,
        policy_data: &'scope RootCurrentPolicyInputDataV1<'inputs>,
        originals: &'scope RootCurrentAcceptedOriginalsV1<'startup>,
        authorization: &'scope super::purpose::RootInitialUseAuthorizedOriginalV1,
        reserved: &'scope super::purpose::RootUseReservedOriginalV1,
        admitted: &'scope super::purpose::RootUseAdmittedOriginalV1,
        signed: &'scope super::purpose::RootSignedBoundOriginalV1,
        input: &'scope super::purpose::RootOutcomeInputOriginalV1,
    ) -> Result<RootInitialControllerReadonlyPreparedBorrowV1<'scope, 'startup, 'inputs>, E> {
        let received = match reserved.received_original_v1() {
            Ok(received) => received,
            Err(_) => { self.body.primary.get_or_insert(Err(E::Incomplete)); return Err(E::Incomplete); }
        };
        match RootInitialControllerReadonlyPreparedBorrowV1::prepare_inner(
            &mut self.body, &mut self.receipt, writers, open, ready, cache, source,
            ownership, policy_data, originals,
            RootControllerPurposeBorrowV1::Outcome { authorization, reserved, received, admitted, signed, input },
        ) {
            Ok(prepared) => Ok(prepared),
            Err((error, state)) => { state.primary.get_or_insert(Err(error)); Err(E::Incomplete) }
        }
    }

    pub(in crate::native::root_current) fn borrow_closed_prepared_once_v1<'scope, 'startup, 'inputs>(
        &'scope mut self,
        writers: &'scope RootCurrentWritersOriginalV1,
        open: &'scope RootInitialOpenPreparedOriginalV1,
        ready: &'scope RootInitialReadyOriginalV1,
        cache: &'scope RootInitialCacheProofOriginalV1,
        source: &'scope RootInitialSourceExchangeOriginalV1,
        ownership: &'scope RootInitialBundleOwnershipOriginalV1,
        policy_data: &'scope RootCurrentPolicyInputDataV1<'inputs>,
        originals: &'scope RootCurrentAcceptedOriginalsV1<'startup>,
        authorization: &'scope super::purpose::RootInitialUseAuthorizedOriginalV1,
        reserved: &'scope super::purpose::RootUseReservedOriginalV1,
        signed: &'scope super::purpose::RootSignedBoundOriginalV1,
        outcome: &'scope super::purpose::RootUseOutcomeOriginalV1,
        input: &'scope super::purpose::RootReleaseInputOriginalV1,
    ) -> Result<RootInitialControllerReadonlyPreparedBorrowV1<'scope, 'startup, 'inputs>, E> {
        let received = match reserved.received_original_v1() {
            Ok(received) => received,
            Err(_) => { self.body.primary.get_or_insert(Err(E::Incomplete)); return Err(E::Incomplete); }
        };
        match RootInitialControllerReadonlyPreparedBorrowV1::prepare_inner(
            &mut self.body, &mut self.receipt, writers, open, ready, cache, source,
            ownership, policy_data, originals,
            RootControllerPurposeBorrowV1::Closed { authorization, reserved, received, signed, outcome, input },
        ) {
            Ok(prepared) => Ok(prepared),
            Err((error, state)) => { state.primary.get_or_insert(Err(error)); Err(E::Incomplete) }
        }
    }

}
