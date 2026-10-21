//! Executes actual Root4 preparation, shared append and same-handler transfer.

use super::super::super::{
    initial_ready::RootInitialReadyOriginalV1,
    initial_source_exchange::RootInitialSourceExchangeOriginalV1,
    owned::RootCurrentAcceptedOriginalsV1, writers::RootCurrentWritersOriginalV1,
};
use super::*;
use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    continuation::ContinuationKindV1,
    transport::{FrameCoordinatesV1, FrameKindV1},
};
use sha2::{Digest as _, Sha256};
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

impl RootSignedBoundOriginalV1 {
    pub(in crate::native::root_current) fn prepare_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        admitted: &RootUseAdmittedOriginalV1,
    ) -> Result<(), E> {
        positive(&self.append_arm)?;
        self.received.require_complete_v1()?;
        self.controller
            .as_ref()
            .ok_or(E::Incomplete)?
            .require_complete_v1()?;
        if self.primary.is_some() || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.primary = Some((|| {
            let bundle = self.received.input.received_bundle_v1()?;
            self.body = Some((|| {
                Ok(SignedBoundBodyDataV1 {
                    bundle: bundle.commitment()?,
                    bundle_bytes: u64::try_from(bundle.encoded_bytes()?)
                        .map_err(|_| HistoryErrorV1::Extent)?,
                    request_id: self
                        .received
                        .verification
                        .request_id_v1()
                        .map_err(|_| HistoryErrorV1::Correlation)?,
                    request_body: Sha256::digest(bundle.request_body).into(),
                    plan: Sha256::digest(bundle.plan).into(),
                    signature: Sha256::digest(bundle.signature).into(),
                })
            })());
            self.encoded = Some(positive(&self.body)?.encode());
            let body = open.body_v1()?;
            let previous = admitted
                .completed_receipt_v1()?
                .record_data(body.open.lane, ContinuationKindV1::UseAdmitted)?
                .checksum();
            self.pair.prepare_once_v1(
                KeyV1::new(body.open.lane, OwnerV1::Root, 4)?,
                PhaseV1::new(OwnerV1::Root, 4)?,
                previous,
                body.open.seed,
                positive(&self.encoded)?,
            )?;
            self.pair.prepare_signed_cut_once_v1(open)?;
            Ok(())
        })());
        positive(&self.primary).map(|_| ())
    }

    pub(in crate::native::root_current) fn append_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        admitted: &RootUseAdmittedOriginalV1,
        reserved: &RootUseReservedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        writers: &mut RootCurrentWritersOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        original: &UnixStream,
    ) -> Result<(), E> {
        positive(&self.primary)?;
        let result = match writers.opened_pair_v1() {
            Ok(pair) => match pair.authority_and_policy_v1() {
                Ok((authority, policy)) => self
                    .pair
                    .append_signed_once_v1(
                        authority,
                        policy,
                        open,
                        admitted,
                        reserved,
                        source,
                        &self.received,
                        originals,
                        original.as_fd(),
                    )
                    .map_err(E::from),
                Err(error) => Err(E::Root(error)),
            },
            Err(error) => Err(E::Root(error)),
        };
        self.primary = Some(result);
        positive(&self.primary).map(|_| ())
    }

    pub(in crate::native::root_current) fn observe_append_posts_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        reserved: &RootUseReservedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        writers: &mut RootCurrentWritersOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
    ) {
        if !matches!(self.append_arm, Some(Ok(()))) {
            return;
        }
        self.append_posts
            .observe_once_v1(writers, open, &originals.peer, &originals.stream);
        self.append_live = Some((|| {
            self.append_posts.require_complete_v1()?;
            super::received::require_live(open, reserved, source, self.append_posts.sample_v1()?)
        })());
    }

    pub(in crate::native::root_current) fn frame_after_posts_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
    ) -> Result<(), E> {
        positive(&self.primary)?;
        positive(&self.append_live)?;
        if self.framing.is_some() || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.framing = Some(self.frame_once_v1(open, ready));
        positive(&self.framing).map(|_| ())
    }
    pub(in crate::native::root_current) fn frame_once_v1(
        &mut self,
        root: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
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
            ContinuationKindV1::SignedBound,
            &mut self.frame[FRAME_HEADER_BYTES..],
        )?;
        let sequence = 11_u64
            .checked_add(u64::from(
                ready
                    .original_transfer_index_v1()
                    .map_err(|_| HistoryErrorV1::Correlation)?
                    .count(),
            ))
            .and_then(|value| {
                value.checked_add(u64::from(self.received.input.index_data_v1().ok()?.count()))
            })
            .ok_or(HistoryErrorV1::Extent)?;
        let header = FrameCoordinatesV1 {
            kind: FrameKindV1::SignedBound,
            lane: body.open.lane,
            sequence,
            root_nonce: body.root_nonce,
            controller_nonce: body.open.controller_nonce,
        }
        .encode_header(&self.frame[FRAME_HEADER_BYTES..])?;
        self.frame[..FRAME_HEADER_BYTES].copy_from_slice(&header);
        Ok(())
    }

    pub(in crate::native::root_current) fn send_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        reserved: &RootUseReservedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        writers: &mut RootCurrentWritersOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        original: &UnixStream,
    ) -> Result<(), E> {
        positive(&self.framing)?;
        positive(&self.send_arm)?;
        if self.sent.is_some() || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.sent = Some(self.send.run_once(
            &mut &*original,
            &mut self.frame,
            source.original_cutoff_v1()?,
            DeadlineStreamDirectionV1::Write,
        ));
        self.send_posts
            .observe_once_v1(writers, open, &originals.peer, &originals.stream);
        match writers.opened_pair_view_v1() {
            Ok((authority, policy)) => {
                self.send_readback = Some(self.pair.readback_pair_v1(authority, policy));
                self.send_metadata = Some(authority.read_view().metadata());
            }
            Err(error) => self.send_readback = Some(Err(RootInitialOpenErrorV1::Root(error))),
        }
        self.send_live = Some((|| {
            self.send_posts.require_complete_v1()?;
            super::received::require_live(open, reserved, source, self.send_posts.sample_v1()?)?;
            positive(&self.send_readback)?;
            self.pair.require_end_v1(&self.send_metadata)?;
            Ok(())
        })());
        self.complete = self.send.completed_exact()
            && matches!(self.send_live, Some(Ok(())))
            && self.failure_v1().is_none();
        self.require_complete_v1()
    }
}
