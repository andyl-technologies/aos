//! Signs the independently replayed Delete pending cut under the same Source F.
//!
//! A Controller native position is never supplied. Native64 comes only from
//! the same complete paid readonly parser, and the current Tree/lineage uses
//! the existing canonical full structural fold without an empty-tree shortcut.

use std::{error::Error, mem::size_of};
use aos_sandbox_model::ProjectId;
use aos_sandbox_protocol::domain_ledger::delete_root::source_current::*;
use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1;
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use ed25519_dalek::{Signer as _, SigningKey};
use super::clock_bracket::{SourceReadonlyClockBracketV1, SourceReadonlyClockBoundsV1};
use super::super::readonly_native::SourceReadonlyNativeOriginalV1;

#[derive(Debug, thiserror::Error)]
enum ReplyErrorV1 {
    #[error(transparent)] Data(#[from] SourceDeleteCurrentDataErrorV1),
    #[error(transparent)] Native(#[from] JournalError),
    #[error(transparent)] Hierarchy(#[from] aos_sandbox_protocol::domain_ledger::DomainLedgerDataError),
    #[error(transparent)] Tree(#[from] aos_sandbox_ledger_replay::hierarchy::codec::HierarchyCodecError),
}

use aos_sandbox_ledger_replay::delete_pending::{
    DeleteSourceTreeDataV1 as TreeDataV1, DeleteSourceTreeDataErrorV1,
    source_delete_tree_data_v1,
};

impl From<DeleteSourceTreeDataErrorV1> for ReplyErrorV1 {
    fn from(cause: DeleteSourceTreeDataErrorV1) -> Self {
        match cause {
            DeleteSourceTreeDataErrorV1::Hierarchy(cause) => Self::Hierarchy(cause),
            DeleteSourceTreeDataErrorV1::Tree(cause) => Self::Tree(cause),
            DeleteSourceTreeDataErrorV1::Data(cause) => Self::Data(cause),
        }
    }
}

#[derive(Clone, Copy)]
enum FirstV1 { Query, Clock, Attachment, Native, Tree, Fields, Body, Packet, Closed }

pub(super) struct SourceDeletePendingCutOriginalsV1 {
    query: [u8; SOURCE_DELETE_CURRENT_QUERY_BYTES_V1],
    purpose: SourceDeleteCurrentPurposeDataV3,
    query_result: Option<Result<SourceDeleteCurrentQueryDataV1, SourceDeleteCurrentDataErrorV1>>,
    bracket: SourceReadonlyClockBracketV1,
    attachment: Option<Result<(), JournalError>>,
    native: Option<Result<[u8; 64], SourceDeleteCurrentDataErrorV1>>,
    tree: Option<Result<TreeDataV1, ReplyErrorV1>>,
    fields: Option<Result<SourceDeleteCurrentReplyFieldsV1, ReplyErrorV1>>,
    body: Option<Result<[u8; SOURCE_DELETE_CURRENT_BODY_BYTES_V1], SourceDeleteCurrentDataErrorV1>>,
    signed: [u8; SOURCE_DELETE_CURRENT_SIGNATURE_MESSAGE_MAXIMUM_BYTES_V3],
    signature: Option<[u8; 64]>,
    packet: Option<Result<[u8; SOURCE_DELETE_CURRENT_PACKET_BYTES_V1], SourceDeleteCurrentDataErrorV1>>,
    first: Option<FirstV1>,
    closed: Option<JournalError>,
    observed: bool,
}

impl SourceDeletePendingCutOriginalsV1 {
    pub(super) fn new(query: [u8; SOURCE_DELETE_CURRENT_QUERY_BYTES_V1], purpose: SourceDeleteCurrentPurposeDataV3) -> Self {
        Self { query, purpose, query_result: None, bracket: Default::default(), attachment: None, native: None,
            tree: None, fields: None, body: None,
            signed: [0; SOURCE_DELETE_CURRENT_SIGNATURE_MESSAGE_MAXIMUM_BYTES_V3],
            signature: None, packet: None, first: None, closed: None, observed: false }
    }

    pub(super) fn begin_once(&mut self, opening: &mut SourceReadonlyNativeOriginalV1,
        receiving: &mut crate::signer::SourceReadonlyReceivingContextV1<'_, '_>,
    ) -> Result<(), ()> {
        if self.query_result.is_some() { return self.close(); }
        self.query_result = Some(SourceDeleteCurrentQueryDataV1::decode_for_purpose_v3(&self.query, self.purpose));
        let Some(Ok(query)) = self.query_result.as_ref() else { self.mark(FirstV1::Query); return Err(()); };
        let query = *query;
        self.observe_clock(0)?;
        self.attachment = Some((|| {
            receiving.attach_delete_project_once(ProjectId::from_bytes(query.project))?;
            opening.attach_delete_pending_once(query, self.purpose)
        })());
        if !matches!(self.attachment, Some(Ok(()))) { self.mark(FirstV1::Attachment); return Err(()); }
        Ok(())
    }

    pub(super) fn observe_once(&mut self, readback: &mut SourceReadonlyNativeOriginalV1,
        generation: u64, key: &SigningKey,
    ) -> Result<(), ()> {
        if self.observed || self.first.is_some() || !self.bracket.bound_is_positive(0) { return self.close(); }
        self.observed = true;
        let query = self.query_result.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(())?;
        self.native = Some(readback.delete_pending_native_data_v1(query, self.purpose));
        if !matches!(self.native, Some(Ok(_))) { self.mark(FirstV1::Native); return Err(()); }
        self.tree = Some(source_delete_tree_data_v1(readback.all_records(),
            ProjectId::from_bytes(query.project)).map_err(ReplyErrorV1::from));
        if !matches!(self.tree, Some(Ok(_))) { self.mark(FirstV1::Tree); return Err(()); }
        self.observe_clock(1)?;
        self.fields = Some((|| {
            let native = self.native.as_ref().and_then(|result| result.as_ref().ok()).copied()
                .ok_or(SourceDeleteCurrentDataErrorV1::Native)?;
            let tree = self.tree.as_ref().and_then(|result| result.as_ref().ok()).copied()
                .ok_or(SourceDeleteCurrentDataErrorV1::Tree)?;
            let clock = self.bracket.sample(1).ok_or(SourceDeleteCurrentDataErrorV1::Clock)?;
            let fields = SourceDeleteCurrentReplyFieldsV1 { generation, query: query.digest_for_purpose_v3(self.purpose)?,
                boot: clock.host_boot_id(), wall_seconds: clock.wall_seconds(), boottime_nanoseconds: clock.boottime_nanoseconds(),
                names: readback.physical_names_v1()?, next: readback.snapshot_sequence(),
                end: u64::from_be_bytes(native[56..64].try_into().map_err(|_| SourceDeleteCurrentDataErrorV1::Native)?),
                pending_native: native, batch: query.batch, project: query.project, operation: query.operation,
                tree_generation: tree.generation, tree_commitment: tree.commitment, tree_head: tree.head, lineage_head: tree.lineage };
            fields.require_query_for_purpose_v3(query, generation, self.purpose)?;
            Ok(fields)
        })());
        let Some(Ok(fields)) = self.fields.as_ref() else { self.mark(FirstV1::Fields); return Err(()); };
        self.body = Some(fields.encode_body_for_purpose_v3(self.purpose));
        let Some(Ok(body)) = self.body.as_ref() else { self.mark(FirstV1::Body); return Err(()); };
        let domain = self.purpose.signature_domain_v3();
        let signed = &mut self.signed[..domain.len() + SOURCE_DELETE_CURRENT_BODY_BYTES_V1];
        signed[..domain.len()].copy_from_slice(domain);
        signed[domain.len()..].copy_from_slice(body);
        self.signature = Some(key.sign(signed).to_bytes());
        self.packet = Some(SourceDeleteCurrentReplyDataV1 { fields: *fields,
            signature: self.signature.ok_or(())? }.encode_for_purpose_v3(self.purpose));
        if !matches!(self.packet, Some(Ok(_))) { self.mark(FirstV1::Packet); return Err(()); }
        Ok(())
    }

    pub(super) fn post_once(&mut self, index: usize) -> Result<(), ()> {
        if index >= 3 || self.bracket.has_sample(index + 2)
            || index > 0 && !self.bracket.has_sample(index + 1) { return self.close(); }
        self.observe_clock(index + 2)
    }

    fn observe_clock(&mut self, index: usize) -> Result<(), ()> {
        let bounds = self.query_result.as_ref().and_then(|result| result.as_ref().ok())
            .map(|query| SourceReadonlyClockBoundsV1 { boot: query.boot, other_boot: query.boot,
                started: query.started, cutoff: query.cutoff }).ok_or(HistoryErrorV1::Correlation);
        let result = self.bracket.observe_once(index, bounds);
        if result.is_err() { self.mark(FirstV1::Clock); }
        result
    }

    pub(super) fn packet(&self) -> Option<&[u8]> {
        if self.first.is_some() || !self.bracket.bound_is_positive(2) { return None; }
        self.packet.as_ref()?.as_ref().ok().map(|packet| packet.as_slice())
    }

    pub(super) fn fixed_obligations_v1() -> Option<(usize, usize, usize)> {
        let clock = crate::signer::clock::SourceClockOriginalV1::dominant_requested_bytes_v1()?.checked_mul(5)?;
        let model = aos_sandbox_ledger_replay::replay::tree_lineage::retained::SourceCurrentTreeOriginalsV1::<
            aos_sandbox_protocol::domain_ledger::DomainLedgerDataError>::receiving_fixed_bytes_v1()?;
        Some((size_of::<Self>().checked_mul(2)?.checked_add(clock)?.checked_add(model)?, 0,
            2 * crate::signer::clock::SourceClockOriginalV1::MAXIMUM_RETAINED_FILES_V1))
    }

    fn mark(&mut self, first: FirstV1) { self.first.get_or_insert(first); }
    fn close(&mut self) -> Result<(), ()> { self.closed.get_or_insert(JournalError::ProtectedBoundary); self.mark(FirstV1::Closed); Err(()) }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            FirstV1::Query => error(&self.query_result),
            FirstV1::Clock => self.bracket.failure(),
            FirstV1::Attachment => error(&self.attachment),
            FirstV1::Native => error(&self.native),
            FirstV1::Tree => error(&self.tree),
            FirstV1::Fields => error(&self.fields),
            FirstV1::Body => error(&self.body),
            FirstV1::Packet => error(&self.packet),
            FirstV1::Closed => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
