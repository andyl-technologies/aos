//! Encodes the original Root3 body and exact unsigned plan-transfer frame.
//!
//! Hashes and receipts are passive comparisons. Actual stages and the closed
//! append gate retain the genuine financial/currentness authority separately.

use super::super::super::{
    initial_cache::RootInitialCacheProofOriginalV1,
    initial_open::RootInitialOpenPreparedOriginalV1, initial_ready::RootInitialReadyOriginalV1,
    initial_source_exchange::RootInitialSourceExchangeOriginalV1,
    initial_use_authorized::RootInitialUseAuthorizedOriginalV1,
};
use super::super::reserved::RootUseReservedOriginalV1;
use super::*;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
    continuation::{ContinuationKindV1, UseAdmissionTransferDataV1},
    transport::{FRAME_HEADER_BYTES, FrameCoordinatesV1, FrameKindV1},
    use_authorized::source_current_reply_commitment_v1,
    use_reserved::use_current_proofs_commitment_v1,
};
use sha2::{Digest as _, Sha256};

impl RootUseAdmittedOriginalV1 {
    pub(in crate::native::root_current) fn prepare_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &RootInitialUseAuthorizedOriginalV1,
        reserved: &RootUseReservedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
    ) -> Result<(), E> {
        self.fixed.require_complete_v1()?;
        positive(&self.append_arm)?;
        if self.primary.is_some() || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        let result = self.prepare_inner(open, authorization, reserved, source, cache);
        self.primary = Some(result);
        positive(&self.primary).map(|_| ())
    }

    fn prepare_inner(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &RootInitialUseAuthorizedOriginalV1,
        reserved: &RootUseReservedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
    ) -> Result<(), E> {
        reserved.require_complete_v1()?;
        source.require_use_complete_for_v1(open, authorization, reserved)?;
        cache.require_use_complete_for_v1(open, authorization, reserved)?;
        self.body = Some((|| {
            let lane = open.body_v1()?.open.lane;
            let receipt = reserved.completed_receipt_v1(lane)?;
            let held = receipt.body(lane).map_err(|_| E::Incomplete)?;
            let plan = reserved
                .completed_controller_v1()?
                .prospective_use_plan_v1()?
                .preparation_data_v1();
            Ok(UseAdmittedBodyDataV1 {
                use_reserved: record_checksum(receipt.record, lane, OwnerV1::Controller, 5, 4)?,
                current_proofs: use_current_proofs_commitment_v1(
                    cache.use_current_proofs_payload_v1()?,
                ),
                source_current: source_current_reply_commitment_v1(source.verified_packet_v1()?),
                cache_current: Sha256::digest(cache.verified_packet_v1()?).into(),
                use_claim: aos_sandbox_protocol::domain_ledger::resource_bank::Claim::decode(
                    held.claim,
                )
                .map_err(|_| E::Incomplete)?
                .native_fields()
                .id,
                unsigned_plan: Sha256::digest(plan.canonical_plan()).into(),
                signing_statement: Sha256::digest(plan.signing_request().canonical_statement())
                    .into(),
            })
        })());
        let body = *positive(&self.body).map_err(|_| E::Incomplete)?;
        self.encoded = Some(body.encode());
        let root_body = open.body_v1()?;
        let previous = record_checksum(
            authorization.completed_receipt_v1()?.record,
            root_body.open.lane,
            OwnerV1::Root,
            2,
            2,
        )?;
        self.pair
            .prepare_once_v1(
                KeyV1::new(root_body.open.lane, OwnerV1::Root, 3).map_err(|_| E::Incomplete)?,
                PhaseV1::new(OwnerV1::Root, 3).map_err(|_| E::Incomplete)?,
                previous,
                root_body.open.seed,
                positive(&self.encoded).map_err(|_| E::Incomplete)?,
            )
            .map_err(|_| E::Incomplete)?;

        self.pair.prepare_use_admitted_cut_once_v1(open)?;
        Ok(())
    }

    pub(in crate::native::root_current) fn frame_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
        reserved: &RootUseReservedOriginalV1,
    ) -> Result<(), E> {
        positive(&self.primary)?;
        positive(&self.append_live)?;
        if self.framing.is_some() || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.framing = Some(self.make_frame(open, ready, reserved));
        positive(&self.framing).map(|_| ())
    }

    fn make_frame(
        &mut self,
        root: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
        reserved: &RootUseReservedOriginalV1,
    ) -> Result<(), HistoryErrorV1> {
        let body = root.body_v1().map_err(|_| HistoryErrorV1::Correlation)?;
        let readback = positive(&self.pair.readback).map_err(|_| HistoryErrorV1::Correlation)?;
        let committed = positive(&self.pair.append).map_err(|_| HistoryErrorV1::Correlation)?;
        let receipt = ContinuationNativeReceiptDataV1 {
            record: &self.pair.record,
            latest_head: readback.head,
            names: self
                .append_posts
                .authority_names_v1()
                .map_err(|_| HistoryErrorV1::Correlation)?,
            after_next: readback.next,
            after_end: committed.durable_bytes,
        };
        receipt.encode_into(
            body.open.lane,
            ContinuationKindV1::UseAdmitted,
            &mut self.receipt,
        )?;
        let prepared = reserved
            .completed_controller_v1()
            .map_err(|_| HistoryErrorV1::Correlation)?
            .prospective_use_plan_v1()
            .map_err(|_| HistoryErrorV1::Correlation)?
            .preparation_data_v1();
        let transfer = UseAdmissionTransferDataV1 {
            receipt: &self.receipt,
            plan: prepared.canonical_plan(),
            statement: prepared.signing_request().canonical_statement(),
        };
        self.frame_length = Some(transfer.encoded_bytes(body.open.lane).and_then(|bytes| {
            bytes
                .checked_add(FRAME_HEADER_BYTES)
                .ok_or(HistoryErrorV1::Extent)
        }));
        let length = *positive(&self.frame_length).map_err(|_| HistoryErrorV1::Extent)?;
        self.allocation = Some(self.frame.try_reserve_exact(length));
        positive(&self.allocation).map_err(|_| HistoryErrorV1::Extent)?;
        self.frame.resize(length, 0);
        transfer.encode_into(body.open.lane, &mut self.frame[FRAME_HEADER_BYTES..])?;
        let sequence = u64::from(
            ready
                .original_transfer_index_v1()
                .map_err(|_| HistoryErrorV1::Correlation)?
                .count(),
        )
        .checked_add(9)
        .ok_or(HistoryErrorV1::Extent)?;
        let header = FrameCoordinatesV1 {
            kind: FrameKindV1::UseAdmitted,
            lane: body.open.lane,
            sequence,
            root_nonce: body.root_nonce,
            controller_nonce: body.open.controller_nonce,
        }
        .encode_header(&self.frame[FRAME_HEADER_BYTES..])?;
        self.frame[..FRAME_HEADER_BYTES].copy_from_slice(&header);
        Ok(())
    }
}

fn record_checksum(
    record: &[u8],
    lane: [u8; 16],
    owner: OwnerV1,
    revision: u64,
    phase: u8,
) -> Result<[u8; 32], E> {
    let key = KeyV1::new(lane, owner, revision)?;
    let phase = PhaseV1::new(owner, phase)?;
    Ok(RecordEnvelopeV1::decode(record, key, phase)?.checksum())
}
