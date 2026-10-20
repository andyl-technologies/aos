//! Retains Source17's same-view tree, released hold, signature and native clocks.
//!
//! The actual Source connection supplies its checked original receiving loan,
//! exact suffix and authenticated Root stream. Query and reply fields are DATA;
//! they neither establish Controller currentness nor authorize a journal append.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_core::{ProjectId, RawPairedClockSample};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
    source_current::{SourceCurrentQueryDataV1, SourceCurrentReplyDataV1, SourceCurrentReplyFieldsV1,
        SOURCE_CURRENT_QUERY_BYTES_V1, SOURCE_CURRENT_BODY_BYTES_V1, SOURCE_CURRENT_PACKET_BYTES_V1,
        SOURCE_CURRENT_SIGNATURE_DOMAIN_V1},
};
use ed25519_dalek::{Signer as _, SigningKey};

use crate::signer::SourceReadonlyReceivingContextV1;
type SourceCurrentTreeOriginalsV1 =
    aos_sandbox_ledger_replay::replay::tree_lineage::retained::SourceCurrentTreeOriginalsV1<
        aos_sandbox_protocol::domain_ledger::DomainLedgerDataError,
    >;
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use super::super::readonly_native::SourceReadonlyNativeOriginalV1 as ReadOnlyProtectedJournal;
use aos_sandbox_core::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::source_policy_hold::{
    SourceDomainPolicyHoldV1, SourceDomainPolicyV8PendingSettlementV1,
};
use crate::signer::clock::SourceClockOriginalV1 as RetainedKernelPairedClockAttemptV1;

#[derive(Clone, Copy)]
enum First { Query, Clock(usize), ClockBinding(usize), Suffix, Pair, Hold, Pending,
    HoldBinding, Tree, Fields, Body, Packet, Closed }

pub(super) struct SourceCurrentCutOriginalsV1 {
    query: [u8; SOURCE_CURRENT_QUERY_BYTES_V1],
    query_result: Option<Result<(), HistoryErrorV1>>,
    bracket: super::clock_bracket::SourceReadonlyClockBracketV1,
    suffix: Option<Result<(), JournalError>>,
    pair: Option<Result<(), JournalError>>,
    hold: Option<Result<Option<SourceDomainPolicyHoldV1>, JournalError>>,
    pending: Option<Result<Option<SourceDomainPolicyV8PendingSettlementV1>, JournalError>>,
    hold_binding: Option<Result<(), JournalError>>,
    ancestry_binding: Option<Result<(), JournalError>>,
    tree: SourceCurrentTreeOriginalsV1,
    fields: Option<Result<SourceCurrentReplyFieldsV1, HistoryErrorV1>>,
    body: Option<Result<[u8; SOURCE_CURRENT_BODY_BYTES_V1], HistoryErrorV1>>,
    signed: [u8; SOURCE_CURRENT_SIGNATURE_DOMAIN_V1.len() + SOURCE_CURRENT_BODY_BYTES_V1],
    signature: Option<[u8; 64]>,
    packet: Option<Result<[u8; SOURCE_CURRENT_PACKET_BYTES_V1], HistoryErrorV1>>,
    first: Option<First>,
    closed: Option<JournalError>,
    observed: bool,
}

impl SourceCurrentCutOriginalsV1 {
    pub(super) fn new(query: [u8; SOURCE_CURRENT_QUERY_BYTES_V1]) -> Self {
        Self {
            query, query_result: None,
            bracket: Default::default(),
            suffix: None, pair: None, hold: None, pending: None, hold_binding: None, ancestry_binding: None,
            tree: SourceCurrentTreeOriginalsV1::new(), fields: None, body: None,
            signed: [0; SOURCE_CURRENT_SIGNATURE_DOMAIN_V1.len() + SOURCE_CURRENT_BODY_BYTES_V1],
            signature: None, packet: None, first: None, closed: None, observed: false,
        }
    }

    pub(super) fn begin_once(&mut self) -> Result<(), ()> {
        if self.query_result.is_some() { return self.close(); }
        self.query_result = Some(SourceCurrentQueryDataV1::decode(&self.query).map(|_| ()));
        if !matches!(self.query_result, Some(Ok(()))) { self.mark(First::Query); return Err(()); }
        self.observe_clock(0)
    }

    pub(super) fn observe_once(&mut self, readback: &mut ReadOnlyProtectedJournal,
        receiving: &SourceReadonlyReceivingContextV1<'_, '_>, generation: u64, key: &SigningKey,
    ) -> Result<(), ()> {
        if self.observed || self.first.is_some() || !self.bracket.bound_is_positive(0) {
            return self.close();
        }
        self.observed = true;
        let query_bytes = self.query;
        let query = SourceCurrentQueryDataV1::decode(&query_bytes).map_err(|_| ())?;
        let root = query.root_body().map_err(|_| ())?;
        let receipt = query.source_receipt().map_err(|_| ())?;
        let source = receipt.body(root.open.lane).map_err(|_| ())?;
        self.suffix = Some(receiving.require_current_query_complete_v1(
            query.digest_v1().map_err(|_| ())?, receipt.source_after_end));
        if !matches!(self.suffix, Some(Ok(()))) { self.mark(First::Suffix); return Err(()); }

        let names = readback.physical_names_v1().map_err(|_| ())?;
        let journal = readback.journal_mut();
        self.pair = Some((|| {
            let record = KeyV1::new(root.open.lane, OwnerV1::Source, 1)
                .map_err(|_| JournalError::ProtectedBoundary)?.encode();
            let latest = KeyV1::new(root.open.lane, OwnerV1::Source, 0)
                .map_err(|_| JournalError::ProtectedBoundary)?.encode();
            if names != receipt.source_names || journal.snapshot_sequence() != receipt.source_after_next
                || journal.get(RecordNamespace::CreateStorageHistory, &record) != Some(receipt.record.as_slice())
                || journal.get(RecordNamespace::CreateStorageHistory, &latest) != Some(receipt.latest_head.as_slice()) {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        if !matches!(self.pair, Some(Ok(()))) { self.mark(First::Pair); return Err(()); }
        self.hold = Some(journal.source_domain_policy_hold_v1());
        if !matches!(self.hold, Some(Ok(Some(_)))) { self.close_at(First::Hold); return Err(()); }
        // This exact parser refuses an uncleared Q04 marker as well as V8.
        self.pending = Some(journal.source_domain_policy_v8_pending_settlement_v1());
        if !matches!(self.pending, Some(Ok(None))) { self.close_at(First::Pending); return Err(()); }
        let hold = self.hold.as_ref().and_then(|value| value.as_ref().ok()).and_then(|hold| *hold).ok_or(())?;
        self.hold_binding = Some(if !hold.is_held() && hold.operation().as_bytes() == &source.operation
            && hold.sandbox().as_bytes() == &source.sandbox { Ok(()) }
            else { Err(JournalError::ProtectedBoundary) });
        if !matches!(self.hold_binding, Some(Ok(()))) { self.mark(First::HoldBinding); return Err(()); }
        if self.tree.observe_once(journal.all_records(), ProjectId::from_bytes(source.project)).is_err() {
            self.mark(First::Tree); return Err(());
        }
        let tree = self.tree.value().ok_or(())?;
        self.ancestry_binding = Some(if hold.ancestry() == tree.tree_head { Ok(()) }
            else { Err(JournalError::ProtectedBoundary) });
        if !matches!(self.ancestry_binding, Some(Ok(()))) { self.mark(First::HoldBinding); return Err(()); }
        self.observe_clock(1)?;
        let clock = self.bracket.sample(1).ok_or(())?;
        self.fields = Some((|| {
            let held = RecordEnvelopeV1::decode(receipt.record,
                KeyV1::new(root.open.lane, OwnerV1::Source, 1)?, PhaseV1::new(OwnerV1::Source, 1)?)?;
            let fields = SourceCurrentReplyFieldsV1 {
                signer_generation: generation, query_digest: query.digest_v1()?,
                boot: clock.host_boot_id(), wall_seconds: clock.wall_seconds(),
                boottime_nanoseconds: clock.boottime_nanoseconds(), source_names: names,
                source_next: journal.snapshot_sequence(), source_end: receipt.source_after_end,
                held_head: held.checksum(), project: source.project, sandbox: source.sandbox,
                ancestry_record_revision: tree.revision, tree_generation: tree.generation,
                tree_commitment: *tree.commitment.as_bytes(), tree_head: *tree.tree_head.as_bytes(),
                lineage_head: *tree.lineage_head.as_bytes(), released_operation: *hold.operation().as_bytes(),
                released_sandbox: *hold.sandbox().as_bytes(), controller_source: *hold.controller_source().as_bytes(),
                released_ancestry: *hold.ancestry().as_bytes(), cut_binding: *hold.binding().as_bytes(),
                released_epoch: hold.epoch(), released_record_digest: *hold.record_digest()
                    .map_err(|_| HistoryErrorV1::Correlation)?.as_bytes(),
            };
            fields.require_query(query, generation)?;
            Ok(fields)
        })());
        if !matches!(self.fields, Some(Ok(_))) { self.mark(First::Fields); return Err(()); }
        self.body = Some(self.fields.as_ref().and_then(|fields| fields.as_ref().ok())
            .copied().ok_or(HistoryErrorV1::Correlation).and_then(SourceCurrentReplyFieldsV1::encode_body));
        let Some(Ok(body)) = &self.body else { self.mark(First::Body); return Err(()); };
        self.signed[..SOURCE_CURRENT_SIGNATURE_DOMAIN_V1.len()].copy_from_slice(SOURCE_CURRENT_SIGNATURE_DOMAIN_V1);
        self.signed[SOURCE_CURRENT_SIGNATURE_DOMAIN_V1.len()..].copy_from_slice(body);
        self.signature = Some(key.sign(&self.signed).to_bytes());
        self.packet = Some(SourceCurrentReplyDataV1 {
            fields: *self.fields.as_ref().and_then(|fields| fields.as_ref().ok()).ok_or(())?,
            signature: self.signature.ok_or(())?,
        }.encode());
        if !matches!(self.packet, Some(Ok(_))) { self.mark(First::Packet); return Err(()); }
        Ok(())
    }

    pub(super) fn post_once(&mut self, index: usize) -> Result<(), ()> {
        if index >= 3 || self.bracket.has_sample(index + 2)
            || index > 0 && !self.bracket.has_sample(index + 1) { return self.close(); }
        // A failed primary enters only this one owed independent post. The
        // connection never advances to response/shutdown after refusal.
        self.observe_clock(index + 2)
    }

    fn observe_clock(&mut self, index: usize) -> Result<(), ()> {
        if self.bracket.has_sample(index) { return self.close(); }
        let bounds = (|| {
            let query = SourceCurrentQueryDataV1::decode(&self.query)?;
            let root = query.root_body()?;
            let source = query.source_receipt()?.body(root.open.lane)?;
            Ok(super::clock_bracket::SourceReadonlyClockBoundsV1 { boot: root.boot,
                other_boot: source.boot, started: root.started.max(source.started),
                cutoff: root.cutoff.min(source.cutoff) })
        })();
        let result = self.bracket.observe_once(index, bounds);
        if result.is_err() {
            match self.bracket.selected() {
                Some(super::clock_bracket::ClockFailureV1::Native(index)) => self.mark(First::Clock(index)),
                _ => self.mark(First::ClockBinding(index)),
            }
        }
        result
    }

    fn mark(&mut self, first: First) { self.first.get_or_insert(first); }

    fn close_at(&mut self, first: First) {
        self.closed.get_or_insert(JournalError::ProtectedBoundary);
        self.mark(first);
    }

    fn close(&mut self) -> Result<(), ()> { self.close_at(First::Closed); Err(()) }

    pub(super) fn packet(&self) -> Option<&[u8]> {
        if self.first.is_some() || !self.bracket.bound_is_positive(2) { return None; }
        self.packet.as_ref()?.as_ref().ok().map(|packet| packet.as_slice())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Query => self.query_result.as_ref()?.as_ref().err().map(|error| error as _),
            First::Clock(_) => self.bracket.failure(),
            First::ClockBinding(_) => self.bracket.failure(),
            First::Suffix => self.suffix.as_ref()?.as_ref().err().map(|error| error as _),
            First::Pair => self.pair.as_ref()?.as_ref().err().map(|error| error as _),
            First::Hold => self.hold.as_ref()?.as_ref().err().map(|error| error as _).or_else(|| self.closed.as_ref().map(|error| error as _)),
            First::Pending => self.pending.as_ref()?.as_ref().err().map(|error| error as _).or_else(|| self.closed.as_ref().map(|error| error as _)),
            First::HoldBinding => self.hold_binding.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)
                .or_else(|| self.ancestry_binding.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)),
            First::Tree => self.tree.failure().or_else(|| self.closed.as_ref().map(|error| error as _)),
            First::Fields => self.fields.as_ref()?.as_ref().err().map(|error| error as _),
            First::Body => self.body.as_ref()?.as_ref().err().map(|error| error as _),
            First::Packet => self.packet.as_ref()?.as_ref().err().map(|error| error as _),
            First::Closed => self.closed.as_ref().map(|error| error as _),
        }
    }

    pub(super) fn fixed_obligations_v1() -> Option<(usize, usize, usize)> {
        let bytes = size_of::<Self>().checked_mul(2)?
            .checked_add(RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?.checked_mul(5)?)?
            .checked_add(SourceCurrentTreeOriginalsV1::receiving_fixed_bytes_v1()?)?;
        let cells = 20_usize.checked_add(10)?
            .checked_add(RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()?.checked_mul(5)?)?
            .checked_add(SourceCurrentTreeOriginalsV1::receiving_fixed_cells_v1()?)?;
        Some((bytes, cells, 2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_query_stops_before_native_clock_and_cannot_replace_its_first_cause() {
        let mut original = SourceCurrentCutOriginalsV1::new([0; SOURCE_CURRENT_QUERY_BYTES_V1]);
        assert!(original.begin_once().is_err());
        let first = original.failure().unwrap().downcast_ref::<HistoryErrorV1>().unwrap() as *const HistoryErrorV1;
        assert!(original.bracket.samples.iter().all(Option::is_none));
        assert!(original.packet().is_none());
        assert!(original.begin_once().is_err());
        assert_eq!(original.failure().unwrap().downcast_ref::<HistoryErrorV1>().unwrap() as *const HistoryErrorV1, first);
        assert!(original.bracket.samples.iter().all(Option::is_none));
    }
}
