//! Produces Root's second history pair from its complete live current cut.
//!
//! The actual accepted flight, fixed writers and completed Source, Cache,
//! Inventory, Ownership and Controller reads remain resident. The unsigned
//! receiving proposal is derived by the shared complete recipe; it is not a
//! Controller grant. The same native append and independent post engines serve
//! RootOpen and this transition. No signing key enters this owner.

use std::error::Error as StdError;
use std::fs::Metadata;
use std::io;
use std::os::unix::net::UnixStream;

use aos_sandbox_model::ResourceVector;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HEAD_BYTES, HistoryErrorV1, KeyV1, LatestHeadV1, OwnerV1, PhaseV1,
    RecordCoordinatesV1, RecordEnvelopeV1,
    root_open::RootHelloDataV1,
    transport::{FRAME_HEADER_BYTES, FrameCoordinatesV1, FrameKindV1},
    use_authorized::{UseAuthorizedBodyDataV1, UseAuthorizedNativeReceiptDataV1,
        USE_AUTHORIZED_BODY_BYTES_V1, USE_AUTHORIZED_RECORD_BYTES_V1,
        USE_AUTHORIZED_FRAME_BYTES_V1, current_proofs_commitment_v1,
        source_current_reply_commitment_v1},
};
use crate::controller_resource_reservation::CreateStorageCacheCurrentExtentsDataV1;
use crate::journal::{Journal, JournalError};
use crate::journal::broker_session_receiving::{StorageCreateUseSecurityShapeDataV1,
    StorageSessionGeometryRefusalV1, storage_create_use_receiving_demand_v1};
use crate::journal::create_storage_history::HistoryPairReadbackV1;
use crate::normal_root::RootPolicyAcceptedFlightV1;
use crate::policy_compiler::bounded_stream_io::{FixedDeadlineStreamIoV1, DeadlineStreamDirectionV1};
use crate::policy_compiler::root_current_writers::RootCreateStorageCurrentWritersV1;

use super::{RootCreateStorageCurrentErrorV1 as Error,
    bundle_ownership::RootCurrentBundleOwnershipStateV1,
    cache_current::RootCurrentCacheProofStateV1,
    controller_readonly::RootCurrentControllerReadonlyStateV1,
    ready::RootCurrentReadyStateV1,
    root_open::{RootCurrentOpenStateV1, RootCurrentHistoryPostsV1},
    source_current::RootCurrentSourceExchangeStateV1};

type Readback = HistoryPairReadbackV1<USE_AUTHORIZED_RECORD_BYTES_V1>;

pub(crate) struct RootCurrentUseAuthorizedStateV1 {
    receiving: Option<Result<ResourceVector, StorageSessionGeometryRefusalV1>>,
    source_extent: Option<Result<crate::journal::ProtectedJournalPreopenReplayExtentV1, JournalError>>,
    body: Option<Result<UseAuthorizedBodyDataV1, Error>>,
    body_encoding: Option<Result<[u8; USE_AUTHORIZED_BODY_BYTES_V1], HistoryErrorV1>>,
    pair: super::history_pair::RootCurrentHistoryPairV1<USE_AUTHORIZED_RECORD_BYTES_V1>,
    primary: Option<Result<(), Error>>,
    append_posts: RootCurrentHistoryPostsV1,
    append_live: Option<Result<(), JournalError>>,
    hello: [u8; 612],
    frame: [u8; USE_AUTHORIZED_FRAME_BYTES_V1],
    framing: Option<Result<(), HistoryErrorV1>>,
    send: FixedDeadlineStreamIoV1<USE_AUTHORIZED_FRAME_BYTES_V1>,
    sent: Option<Result<(), HistoryErrorV1>>,
    send_posts: RootCurrentHistoryPostsV1,
    send_readback: Option<Result<Readback, JournalError>>,
    send_native_end: Option<io::Result<Metadata>>,
    send_live: Option<Result<(), JournalError>>,
    complete: bool,
    closed: bool,
}

impl RootCurrentUseAuthorizedStateV1 {
    pub(super) fn new() -> Self {
        Self { receiving: None, source_extent: None, body: None, body_encoding: None,
            pair: super::history_pair::RootCurrentHistoryPairV1::new(), primary: None, append_posts: Default::default(),
            append_live: None, hello: [0; 612], frame: [0; USE_AUTHORIZED_FRAME_BYTES_V1],
            framing: None, send: Default::default(), sent: None,
            send_posts: Default::default(), send_readback: None, send_native_end: None,
            send_live: None, complete: false, closed: false }
    }

    pub(super) fn produce_once(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        original: &UnixStream,
        root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1,
        source: &RootCurrentSourceExchangeStateV1,
        cache: &RootCurrentCacheProofStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1,
        readonly: &RootCurrentControllerReadonlyStateV1,
        private: StorageCreateUseSecurityShapeDataV1,
    ) -> Result<(), Error> {
        if self.primary.is_some() || self.closed {
            self.closed = true;
            return Err(Error::Original);
        }
        self.append_posts.arm_once(flight)?;
        self.primary = Some(self.produce_inner(flight, writers, original, root,
            ready, source, cache, ownership, readonly, private));
        let origin = root.original_clock_origin_v1().ok();
        let body = root.completed_body().ok();
        self.append_posts.observe_once(flight, writers, body.as_ref(),
            origin.map(|pair| pair.0), origin.map(|pair| pair.1));
        self.append_live = Some(self.append_posts.require_complete()
            .and_then(|()| self.append_posts.sample())
            .and_then(|sample| require_live(root, source, readonly, sample)));
        positive(&self.primary).map_err(|_| Error::History)?;
        positive(&self.append_live).map_err(|_| Error::History)?;

        self.framing = Some(self.frame_once(root, ready, cache));
        positive(&self.framing).map_err(|_| Error::History)?;
        self.send_posts.arm_once(flight)?;
        self.sent = Some(self.send.run_once(&mut &*original, &mut self.frame,
            source.original_cutoff_v1()?, DeadlineStreamDirectionV1::Write));
        // A failed write still owes these posts. No returned Error unwinds the
        // actual accepted socket, append outcomes or partial write progress.
        self.send_posts.observe_once(flight, writers, body.as_ref(),
            origin.map(|pair| pair.0), origin.map(|pair| pair.1));
        match writers.authority_and_policy() {
            Ok((authority, policy)) => {
                self.send_readback = Some(self.pair.readback_pair(authority, policy));
                self.send_native_end = Some(authority.held_native_receiving_metadata_v1().0);
            }
            Err(error) => self.send_readback = Some(Err(error)),
        }
        self.send_live = Some((|| {
            self.send_posts.require_complete()?;
            require_live(root, source, readonly, self.send_posts.sample()?)?;
            positive(&self.send_readback)?;
            self.pair.require_end(&self.send_native_end)
        })());
        self.complete = self.send.completed_exact() && self.failure().is_none()
            && matches!(self.send_live, Some(Ok(())));
        self.require_complete_v1()
    }

    fn produce_inner(
        &mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        source: &RootCurrentSourceExchangeStateV1, cache: &RootCurrentCacheProofStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1,
        readonly: &RootCurrentControllerReadonlyStateV1,
        private: StorageCreateUseSecurityShapeDataV1,
    ) -> Result<(), Error> {
        readonly.require_complete_v1()?;
        source.require_complete_v1()?;
        cache.require_complete_v1()?;
        ownership.require_complete_v1()?;
        let extents = CreateStorageCacheCurrentExtentsDataV1::from_current_snapshot_v1(
            &cache.verified_body_v1()?.snapshot).map_err(|_| Error::History)?;
        // The completed independent Source proof compares its actual native
        // end with the SAME signed Held receipt's source_after_end. This copy
        // sizes Source release; it supplies no read or release authority.
        self.source_extent = Some(crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
            crate::source_domain::source_domain_journal_limits(), source.fields_v1()?.source_end));
        let source_extent = positive(&self.source_extent).map_err(|_| Error::History)?;
        self.receiving = Some(storage_create_use_receiving_demand_v1(
            readonly.prospective_session_extent_v1()?,
            readonly.prospective_use_plan_v1()?.request_shape_bytes_v1(),
            readonly.actual_controller_extent_v1()?, source_extent, extents.extents_v1(), private));
        let receiving = *positive(&self.receiving).map_err(|_| Error::History)?;
        self.body = Some((|| {
            let root_body = root.completed_body()?;
            let inputs = cache.controller_receipt_v1(root, ready)?;
            let input = inputs.body(root_body.open.lane).map_err(|_| Error::History)?;
            let root_record = RecordEnvelopeV1::decode(root.committed_record()?,
                KeyV1::new(root_body.open.lane, OwnerV1::Root, 1).map_err(|_| Error::History)?,
                PhaseV1::new(OwnerV1::Root, 1).map_err(|_| Error::History)?)
                .map_err(|_| Error::History)?;
            let input_record = RecordEnvelopeV1::decode(inputs.record,
                KeyV1::new(root_body.open.lane, OwnerV1::Controller, 3).map_err(|_| Error::History)?,
                PhaseV1::new(OwnerV1::Controller, 2).map_err(|_| Error::History)?)
                .map_err(|_| Error::History)?;
            let lease = ownership.completed_response_v1()?.value().ok_or(Error::History)?;
            Ok(UseAuthorizedBodyDataV1 { association: input.association,
                root_nonce: root_body.root_nonce, root_open: root_record.checksum(),
                ready: root_body.open.ready, inputs_ready: input_record.checksum(),
                current_proofs: current_proofs_commitment_v1(cache.current_proofs_payload_v1()?),
                source_current: source_current_reply_commitment_v1(source.verified_packet_v1()?),
                assignment: *ownership.completed_manifest_v1()?.digest().as_bytes(),
                ownership_lease: *lease.digest().as_bytes(), receiving })
        })());
        let body = *positive(&self.body).map_err(|_| Error::History)?;
        self.body_encoding = Some(body.encode());
        let lane = root.completed_body()?.open.lane;
        let key = KeyV1::new(lane, OwnerV1::Root, 2).map_err(|_| Error::History)?;
        let phase = PhaseV1::new(OwnerV1::Root, 2).map_err(|_| Error::History)?;
        self.pair.prepare_once(key, phase, body.root_open, body.association.seed,
            positive(&self.body_encoding).map_err(|_| Error::History)?)
            .map_err(|_| Error::History)?;
        let purpose = super::root_open::RootCurrentHistoryPurposeV1::UseAuthorized { root, readonly, source, cache };
        self.pair.prepare_cut_once(root, purpose).map_err(|_| Error::History)?;
        let (authority, policy) = writers.authority_and_policy().map_err(|_| Error::Writers)?;
        self.pair.append_once(flight, original, authority, policy, root, purpose)
            .map_err(|_| Error::History)
    }

    fn frame_once(&mut self, root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1, cache: &RootCurrentCacheProofStateV1)
        -> Result<(), HistoryErrorV1>
    {
        ready.original_hello_frame_v1(root, &mut self.hello)?;
        let root_body = root.completed_body().map_err(|_| HistoryErrorV1::Correlation)?;
        let hello = RootHelloDataV1::decode(&self.hello, root_body.open)?;
        let receipt = self.receipt_data().map_err(|_| HistoryErrorV1::Correlation)?;
        receipt.require_originals(&hello, cache.controller_receipt_v1(root, ready)
            .map_err(|_| HistoryErrorV1::Correlation)?)?;
        let encoded = receipt.encode(root_body.open.lane)?;
        let sequence = u64::from(ready.original_transfer_index_v1()
            .map_err(|_| HistoryErrorV1::Correlation)?.count())
            .checked_add(5).ok_or(HistoryErrorV1::Extent)?;
        let header = FrameCoordinatesV1 { kind: FrameKindV1::UseAuthorized,
            lane: root_body.open.lane, sequence, root_nonce: root_body.root_nonce,
            controller_nonce: root_body.open.controller_nonce }.encode_header(&encoded)?;
        self.frame[..FRAME_HEADER_BYTES].copy_from_slice(&header);
        self.frame[FRAME_HEADER_BYTES..].copy_from_slice(&encoded);
        Ok(())
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if self.complete && !self.closed && self.failure().is_none() { Ok(()) }
        else { Err(Error::History) }
    }

    pub(crate) fn completed_body_v1(&self) -> Result<&UseAuthorizedBodyDataV1, Error> {
        self.require_complete_v1()?;
        positive(&self.body).map_err(|_| Error::History)
    }

    pub(super) fn completed_receipt_v1(&self) -> Result<UseAuthorizedNativeReceiptDataV1<'_>, Error> {
        self.require_complete_v1()?;
        self.receipt_data()
    }

    fn receipt_data(&self) -> Result<UseAuthorizedNativeReceiptDataV1<'_>, Error> {
        positive(&self.body).map_err(|_| Error::History)?;
        let observed = positive(&self.pair.readback).map_err(|_| Error::History)?;
        let committed = positive(&self.pair.append).map_err(|_| Error::History)?;
        Ok(UseAuthorizedNativeReceiptDataV1 { record: &self.pair.record,
            latest_head: observed.head, names: self.append_posts.authority_names_v1()
                .map_err(|_| Error::History)?, after_next: observed.next,
            after_end: committed.durable_bytes })
    }

    pub(super) fn readback_current_v1(&self, authority: &Journal, policy: &Journal)
        -> Result<Readback, JournalError>
    {
        self.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        self.pair.readback_current_v1(authority, policy)
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.source_extent).or_else(|| cause(&self.receiving)).or_else(|| cause(&self.body)).or_else(|| cause(&self.body_encoding))
            .or_else(|| self.pair.failure()).or_else(|| cause(&self.primary))
            .or_else(|| self.append_posts.failure()).or_else(|| cause(&self.append_live))
            .or_else(|| cause(&self.framing)).or_else(|| self.send.failure())
            .or_else(|| cause(&self.sent)).or_else(|| self.send_posts.failure())
            .or_else(|| cause(&self.send_readback)).or_else(|| cause(&self.send_native_end))
            .or_else(|| cause(&self.send_live))
    }
}

fn require_live(root: &RootCurrentOpenStateV1, source: &RootCurrentSourceExchangeStateV1,
    readonly: &RootCurrentControllerReadonlyStateV1, sample: aos_sandbox_model::RawPairedClockSample)
    -> Result<(), JournalError>
{
    root.require_clock(sample)?;
    readonly.require_live_at_v1(sample)?;
    if sample.boottime_nanoseconds() >= source.original_cutoff_v1()
        .map_err(|_| JournalError::ProtectedBoundary)? { return Err(JournalError::ProtectedBoundary); }
    Ok(())
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<E: StdError + 'static, T>(slot: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
