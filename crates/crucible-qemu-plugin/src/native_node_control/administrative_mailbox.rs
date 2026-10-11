//! Bounded original datagrams for the administrative native controller lane.
//!
//! This owner receives no modeled-work permission. It retains every consumed
//! byte before decoding, and preserves kernel custody when credit or framing
//! bounds prevent complete retention. Query and ACK are request classes, not
//! authority: their reducers must authenticate the original retained objects.
//! Modeled commands remain immutable inbox material until RR owner admission.
//!
//! ```text
//! NativeAdminInbox01 snapshot:
//! magic[8], edition:u16be, scope[32], next_cursor:u64be,
//! failed:u8, socket_device:u64be, socket_inode:u64be,
//! maximum_records:u64be, maximum_bytes:u64be, retained_bytes:u64be,
//! record_count:u32be, records(cursor:u64be, class:u8,
//! reply_reserved:u8, request_len:u32be, reply_len:u32be, original bytes)
//! ```

use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

#[cfg(test)]
use crucible_protocol::node_control::NativePreparation;
use crucible_protocol::node_control::{
    NODE_CONTROL_HEADER_BYTES, NODE_CONTROL_MAX_BODY_BYTES, NativeChannel, NativeChannelError,
    NativeFrame, decode_frame_for_edition, encode_frame_for_edition,
};
use thiserror::Error;

const MAXIMUM_PACKET_BYTES: usize = NODE_CONTROL_HEADER_BYTES + NODE_CONTROL_MAX_BODY_BYTES;
const MAXIMUM_RECORDS: usize = 1024;
const MAXIMUM_MAILBOX_BYTES: usize = 16 * 1024 * 1024;
const RECORD_METADATA_BYTES: usize = 32;

/// Classifies original requests without granting execution or ACK authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum NativeAdministrativeClass {
    /// Reads an already retained original object; never resamples native state.
    ReadOriginal = 1,
    /// Requests acknowledgement; the actual original journal must validate it.
    AcknowledgeOriginal = 2,
    /// Retains modeled work pending separate original RR owner admission.
    Modeled = 3,
    /// Retains invalid original bytes and closes further inbox admission.
    Invalid = 4,
    /// Retains original launch material pending installed source-pin verification.
    Preparation = 5,
}

/// Reports a bounded nonsemantic receive step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeAdministrativeReceive {
    /// No datagram is available without waiting.
    Empty,
    /// Credit is exhausted; the complete datagram remains unread.
    Backpressure,
    /// Original bytes have native custody under this local cursor.
    Retained(u64, NativeAdministrativeClass),
}

/// Refuses ambiguous transport/control material while retaining original custody.
#[derive(Debug, Error)]
pub(crate) enum NativeAdministrativeError {
    #[error("native administrative mailbox credit is invalid")]
    Credit,
    #[error("native administrative request is foreign or conflicting")]
    Conflict,
    #[error("native administrative original packet exceeds the framing limit")]
    Oversized,
    #[error("native administrative original packet is malformed")]
    Malformed,
    #[error("native administrative transport failed")]
    Transport(#[from] NativeChannelError),
    #[error("native administrative allocation failed")]
    Allocation,
}

struct OriginalRecord {
    class: NativeAdministrativeClass,
    request: Vec<u8>,
    reply_reserved: bool,
    reply_storage: Vec<u8>,
    reply: Option<Vec<u8>>,
}

/// Holds pre-effect credit for one original administrative reply.
///
/// Dropping the handle does not refund the reservation. The mailbox retains the
/// obligation so a lost handler reply cannot authorize another native effect.
/// Recovery may return another handle to that same reservation. The authenticated
/// original journal, rather than this byte-credit handle, decides whether an ACK
/// effect is new or already complete and returns its unchanged cached result.
pub(crate) struct NativeAdministrativeReplyCredit {
    owner: Arc<()>,
    cursor: u64,
}

impl NativeAdministrativeReplyCredit {
    /// Returns the retained original record's local cursor, never effect authority.
    pub(crate) fn cursor(&self) -> u64 {
        self.cursor
    }
}

/// Owns the sole prepared endpoint and all consumed original datagrams.
///
/// The installed reader holds this owner behind the original-journal mutex.
/// A native cut uses a nonblocking lock attempt under BQL. The socket is not
/// exposed as a second receiver, and no method releases a modeled writer gate.
pub(crate) struct NativeAdministrativeMailbox {
    channel: NativeChannel,
    scope: [u8; 32],
    socket_identity: (u64, u64),
    owner: Arc<()>,
    records: BTreeMap<u64, OriginalRecord>,
    next_cursor: u64,
    retained_bytes: usize,
    maximum_records: usize,
    maximum_bytes: usize,
    failed: bool,
}

impl NativeAdministrativeMailbox {
    pub(crate) fn descriptor(&self) -> i32 {
        self.channel.prepared_descriptor().as_raw_fd()
    }
    /// Takes sole prepared socket custody with finite immutable-history credit.
    ///
    /// Preparation/channel authentication belongs to the installed native
    /// factory. Reproducing portable preparation fields establishes no authority.
    /// All fallible checks borrow the caller's original endpoint. Refusal leaves
    /// that endpoint and every unread datagram in the caller's custody.
    ///
    /// # Errors
    /// Refuses invalid original preparation or zero/out-of-profile credit.
    #[cfg(test)]
    pub(crate) fn from_prepared(
        prepared_channel: &mut Option<NativeChannel>,
        preparation: &NativePreparation,
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<Self, NativeAdministrativeError> {
        let channel = prepared_channel
            .as_ref()
            .ok_or(NativeAdministrativeError::Conflict)?;
        encode_frame_for_edition(
            channel.edition(),
            &NativeFrame::Prepare(Box::new(preparation.clone())),
        )
        .map_err(|error| NativeAdministrativeError::Transport(error.into()))?;
        let scope = preparation
            .scope
            .identity_digest()
            .map_err(|error| NativeAdministrativeError::Transport(error.into()))?;
        Self::from_pinned_endpoint(prepared_channel, scope, maximum_records, maximum_bytes)
    }

    /// Retains the first launch datagram before preparation decoding.
    ///
    /// The installed source factory must verify this scope against its authentic
    /// original launch pin and validate the retained complete preparation before
    /// registration. This raw constructor conveys no native authority.
    ///
    /// # Errors
    /// Refuses missing/zero scope, invalid credit or socket metadata failure,
    /// leaving the actual endpoint and all unread material with the caller.
    pub(crate) fn from_pinned_endpoint(
        prepared_channel: &mut Option<NativeChannel>,
        scope: [u8; 32],
        maximum_records: usize,
        maximum_bytes: usize,
    ) -> Result<Self, NativeAdministrativeError> {
        let channel = prepared_channel
            .as_ref()
            .ok_or(NativeAdministrativeError::Conflict)?;
        if scope == [0; 32] {
            return Err(NativeAdministrativeError::Conflict);
        }
        if maximum_records == 0
            || maximum_records > MAXIMUM_RECORDS
            || maximum_bytes <= RECORD_METADATA_BYTES
            || maximum_bytes > MAXIMUM_MAILBOX_BYTES
        {
            return Err(NativeAdministrativeError::Credit);
        }
        // The duplicate exists only for an actual fstat through safe owned-FD
        // APIs. It is closed before any receive and never becomes another reader.
        let descriptor = channel
            .prepared_descriptor()
            .try_clone_to_owned()
            .map_err(|error| NativeAdministrativeError::Transport(error.into()))?;
        let metadata = std::fs::File::from(descriptor)
            .metadata()
            .map_err(|error| NativeAdministrativeError::Transport(error.into()))?;
        let socket_identity = (metadata.dev(), metadata.ino());
        let channel = prepared_channel
            .take()
            .ok_or(NativeAdministrativeError::Conflict)?;
        Ok(Self {
            channel,
            scope,
            socket_identity,
            owner: Arc::new(()),
            records: BTreeMap::new(),
            next_cursor: 1,
            retained_bytes: 0,
            maximum_records,
            maximum_bytes,
            failed: false,
        })
    }

    /// Retains at most one whole original datagram without waiting or dispatch.
    ///
    /// Linux's length peek avoids copying an oversized packet or consuming its
    /// prefix. Complete request and maximum reply credit is reserved before the
    /// actual receive. A consumed ACK never waits for new response credit.
    ///
    /// # Errors
    /// Refuses malformed/oversized packets, allocation or transport failure.
    /// Consumed invalid bytes remain in the first original record. Oversized
    /// bytes remain in the socket. A refusal closes further admission.
    pub(crate) fn receive(
        &mut self,
    ) -> Result<NativeAdministrativeReceive, NativeAdministrativeError> {
        if self.failed {
            return Err(NativeAdministrativeError::Conflict);
        }
        let descriptor = self.channel.prepared_descriptor().as_raw_fd();
        let mut preview = [0_u8; 1];
        // SAFETY: the sole owned channel retains this descriptor. The one-byte
        // output buffer is valid; MSG_TRUNC reports the complete datagram length
        // without copying its body. No bytes are dequeued by MSG_PEEK.
        let observed = unsafe {
            libc::recv(
                descriptor,
                preview.as_mut_ptr().cast(),
                preview.len(),
                libc::MSG_PEEK | libc::MSG_TRUNC | libc::MSG_DONTWAIT,
            )
        };
        if observed < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                return Ok(NativeAdministrativeReceive::Empty);
            }
            self.failed = true;
            return Err(NativeAdministrativeError::Transport(error.into()));
        }
        let length = usize::try_from(observed).map_err(|_| NativeAdministrativeError::Oversized)?;
        if length > MAXIMUM_PACKET_BYTES {
            self.failed = true;
            return Err(NativeAdministrativeError::Oversized);
        }
        let required = length
            .checked_add(RECORD_METADATA_BYTES)
            .and_then(|length| length.checked_add(MAXIMUM_PACKET_BYTES))
            .and_then(|length| self.retained_bytes.checked_add(length));
        let Some(required) = required.filter(|required| *required <= self.maximum_bytes) else {
            return Ok(NativeAdministrativeReceive::Backpressure);
        };
        let Some(next) = self.next_cursor.checked_add(1) else {
            return Ok(NativeAdministrativeReceive::Backpressure);
        };
        if self.records.len() >= self.maximum_records {
            return Ok(NativeAdministrativeReceive::Backpressure);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| NativeAdministrativeError::Allocation)?;
        bytes.resize(length, 0);
        let mut reply_storage = Vec::new();
        reply_storage
            .try_reserve_exact(MAXIMUM_PACKET_BYTES)
            .map_err(|_| NativeAdministrativeError::Allocation)?;

        // Allocate the record node and both byte stores before consuming any
        // packet. Decode may only inspect an original already owned by this
        // ledger; byte credit is backed by the actual retained reply buffer.
        let cursor = self.next_cursor;
        self.records.insert(
            cursor,
            OriginalRecord {
                class: NativeAdministrativeClass::Invalid,
                request: bytes,
                reply_reserved: true,
                reply_storage,
                reply: None,
            },
        );
        self.retained_bytes = required;
        self.next_cursor = next;
        let record = self
            .records
            .get_mut(&cursor)
            .ok_or(NativeAdministrativeError::Conflict)?;
        // SAFETY: the prepared endpoint has one receiver and remains live. This
        // bounded vector covers the exact peeked datagram; MSG_TRUNC detects any
        // violated sole-receiver/packet-identity invariant without out-of-bounds
        // access. A nonblocking receive performs no native modeled transition.
        let received = unsafe {
            libc::recv(
                descriptor,
                record.request.as_mut_ptr().cast(),
                record.request.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        if received < 0 {
            // No observed packet identity exists for this failed receive.
            record.request.clear();
            self.failed = true;
            return Err(NativeAdministrativeError::Transport(
                std::io::Error::last_os_error().into(),
            ));
        }
        let class = if received != observed {
            NativeAdministrativeClass::Invalid
        } else {
            classify(self.channel.edition(), self.scope, &record.request)
        };
        record.class = class;
        if class == NativeAdministrativeClass::Invalid {
            self.failed = true;
            return Err(NativeAdministrativeError::Malformed);
        }
        Ok(NativeAdministrativeReceive::Retained(cursor, class))
    }

    /// Recovers pre-dequeue reply credit before an authenticated administrative effect.
    ///
    /// # Errors
    /// Refuses unknown, modeled/invalid or already completed requests and an
    /// exhausted allowance. Reservations survive token drop and lost replies.
    /// A recovered reservation is not a one-shot native effect permit.
    pub(crate) fn reserve_reply(
        &mut self,
        cursor: u64,
    ) -> Result<NativeAdministrativeReplyCredit, NativeAdministrativeError> {
        let record = self
            .records
            .get_mut(&cursor)
            .ok_or(NativeAdministrativeError::Conflict)?;
        if self.failed
            || matches!(
                record.class,
                NativeAdministrativeClass::Modeled | NativeAdministrativeClass::Invalid
            )
            || record.reply.is_some()
        {
            return Err(NativeAdministrativeError::Conflict);
        }
        if !record.reply_reserved {
            return Err(NativeAdministrativeError::Conflict);
        }
        Ok(NativeAdministrativeReplyCredit {
            owner: Arc::clone(&self.owner),
            cursor,
        })
    }

    pub(crate) fn reserve_construction_reply(
        &mut self,
        cursor: u64,
    ) -> Result<NativeAdministrativeReplyCredit, NativeAdministrativeError> {
        let frame = self.decode_original(cursor)?;
        if matches!(
            frame,
            NativeFrame::Initialize(_)
                | NativeFrame::EffectCompute(_)
                | NativeFrame::ContinuePrefix(_)
        ) {
            let record = self
                .records
                .get(&cursor)
                .ok_or(NativeAdministrativeError::Conflict)?;
            if self.failed || !record.reply_reserved || record.reply.is_some() {
                return Err(NativeAdministrativeError::Conflict);
            }
            return Ok(NativeAdministrativeReplyCredit {
                owner: Arc::clone(&self.owner),
                cursor,
            });
        }
        self.reserve_reply(cursor)
    }

    /// Retains the original authenticated reply before attempting publication.
    ///
    /// The original-object reducer supplies the reply; this mailbox validates
    /// reservation custody and bytes, never ACK authority or native closure.
    ///
    /// # Errors
    /// Refuses foreign credit, encoding failure, or a changed historical reply.
    pub(crate) fn retain_reply(
        &mut self,
        credit: NativeAdministrativeReplyCredit,
        reply: &NativeFrame,
    ) -> Result<(), NativeAdministrativeError> {
        if !self.owns_credit(&credit) {
            return Err(NativeAdministrativeError::Conflict);
        }
        let bytes = encode_frame_for_edition(self.channel.edition(), reply)
            .map_err(|error| NativeAdministrativeError::Transport(error.into()))?;
        let record = self
            .records
            .get_mut(&credit.cursor)
            .ok_or(NativeAdministrativeError::Conflict)?;
        if !record.reply_reserved || bytes.len() > MAXIMUM_PACKET_BYTES {
            return Err(NativeAdministrativeError::Conflict);
        }
        let original = decode_frame_for_edition(self.channel.edition(), &record.request)
            .map_err(|error| NativeAdministrativeError::Transport(error.into()))?;
        if !reply_matches(&original, reply, self.scope) {
            return Err(NativeAdministrativeError::Conflict);
        }
        if let Some(original) = &record.reply {
            if original != &bytes {
                self.failed = true;
                return Err(NativeAdministrativeError::Conflict);
            }
        } else {
            record.reply_storage.extend_from_slice(&bytes);
            record.reply = Some(std::mem::take(&mut record.reply_storage));
        }
        Ok(())
    }

    /// Retains or compares one historical query reply under its original reservation.
    ///
    /// Cached reply recovery uses the same pre-dequeue storage and never reserves
    /// a replacement credit. This operation accepts only administrative queries;
    /// it cannot admit a construction command or native effect.
    ///
    /// # Errors
    /// Refuses an unknown/non-query original, changed reply or transport failure.
    pub(crate) fn reply_administration(
        &mut self,
        cursor: u64,
        reply: &NativeFrame,
    ) -> Result<bool, NativeAdministrativeError> {
        if self.failed
            || !matches!(
                self.decode_original(cursor)?,
                NativeFrame::QueryAdministration { .. }
            )
            || !matches!(reply, NativeFrame::AdministrationFacts(_))
        {
            return Err(NativeAdministrativeError::Conflict);
        }
        let credit = NativeAdministrativeReplyCredit {
            owner: Arc::clone(&self.owner),
            cursor,
        };
        self.retain_reply(credit, reply)?;
        self.send_reply(cursor)
    }

    /// Returns immutable original wire bytes without decoding or native dispatch.
    pub(crate) fn original(&self, cursor: u64) -> Option<&[u8]> {
        self.records
            .get(&cursor)
            .map(|record| record.request.as_slice())
    }

    /// Returns actual retained socket correlation data, not a native authority seal.
    pub(crate) fn socket_identity(&self) -> (u64, u64) {
        self.socket_identity
    }

    /// Checks original reply-custody identity without authorizing a native effect.
    pub(crate) fn owns_credit(&self, credit: &NativeAdministrativeReplyCredit) -> bool {
        Arc::ptr_eq(&credit.owner, &self.owner)
            && self
                .records
                .get(&credit.cursor)
                .is_some_and(|record| record.reply_reserved)
    }

    /// Revalidates actual pre-dequeue reply storage without moving its credit.
    ///
    /// # Errors
    /// Refuses foreign credit, missing backing or an already retained reply.
    pub(crate) fn validate_unpublished_credit(
        &self,
        credit: &NativeAdministrativeReplyCredit,
    ) -> Result<(), NativeAdministrativeError> {
        if self.failed || !self.owns_credit(credit) {
            return Err(NativeAdministrativeError::Conflict);
        }
        let record = self
            .records
            .get(&credit.cursor)
            .ok_or(NativeAdministrativeError::Conflict)?;
        if record.reply.is_some() || record.reply_storage.capacity() < MAXIMUM_PACKET_BYTES {
            return Err(NativeAdministrativeError::Conflict);
        }
        Ok(())
    }

    /// Decodes the immutable original record under its pinned transport edition.
    ///
    /// # Errors
    /// Refuses absent records or invalid original bytes without receiving again.
    pub(crate) fn decode_original(
        &self,
        cursor: u64,
    ) -> Result<NativeFrame, NativeAdministrativeError> {
        let original = self
            .original(cursor)
            .ok_or(NativeAdministrativeError::Conflict)?;
        decode_frame_for_edition(self.channel.edition(), original)
            .map_err(|error| NativeAdministrativeError::Transport(error.into()))
    }

    /// Publishes only the retained original reply; backpressure leaves it intact.
    ///
    /// # Errors
    /// Refuses unknown/uncompleted records, malformed history or transport errors.
    pub(crate) fn send_reply(&self, cursor: u64) -> Result<bool, NativeAdministrativeError> {
        let bytes = self
            .records
            .get(&cursor)
            .and_then(|record| record.reply.as_ref())
            .ok_or(NativeAdministrativeError::Conflict)?;
        let reply = decode_frame_for_edition(self.channel.edition(), bytes)
            .map_err(|error| NativeAdministrativeError::Transport(error.into()))?;
        Ok(self.channel.send(&reply)?)
    }

    /// Encodes complete original mailbox material within caller capture credit.
    ///
    /// This includes actual socket device/inode correlation and original credit.
    /// Socket unread bytes and whole native source identities remain separate
    /// obligations. This data-only image cannot certify complete readiness.
    ///
    /// # Errors
    /// Refuses inadequate caller credit or allocation failure before copying.
    pub(crate) fn snapshot(
        &self,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, NativeAdministrativeError> {
        let length = self
            .records
            .values()
            .try_fold(95_usize, |length, record| {
                length
                    .checked_add(18)?
                    .checked_add(record.request.len())?
                    .checked_add(record.reply.as_ref().map_or(0, Vec::len))
            })
            .filter(|length| *length <= maximum_bytes)
            .ok_or(NativeAdministrativeError::Credit)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| NativeAdministrativeError::Allocation)?;
        bytes.extend_from_slice(b"CNAINB01");
        bytes.extend_from_slice(&(self.channel.edition().version()).to_be_bytes());
        bytes.extend_from_slice(&self.scope);
        bytes.extend_from_slice(&self.next_cursor.to_be_bytes());
        bytes.push(u8::from(self.failed));
        bytes.extend_from_slice(&self.socket_identity.0.to_be_bytes());
        bytes.extend_from_slice(&self.socket_identity.1.to_be_bytes());
        bytes.extend_from_slice(&(self.maximum_records as u64).to_be_bytes());
        bytes.extend_from_slice(&(self.maximum_bytes as u64).to_be_bytes());
        bytes.extend_from_slice(&(self.retained_bytes as u64).to_be_bytes());
        bytes.extend_from_slice(&(self.records.len() as u32).to_be_bytes());
        for (cursor, record) in &self.records {
            bytes.extend_from_slice(&cursor.to_be_bytes());
            bytes.push(record.class as u8);
            bytes.push(u8::from(record.reply_reserved));
            bytes.extend_from_slice(&(record.request.len() as u32).to_be_bytes());
            let reply = record.reply.as_deref().unwrap_or(&[]);
            bytes.extend_from_slice(&(reply.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&record.request);
            bytes.extend_from_slice(reply);
        }
        Ok(bytes)
    }
}

fn reply_matches(original: &NativeFrame, reply: &NativeFrame, scope: [u8; 32]) -> bool {
    match (original, reply) {
        (
            NativeFrame::QueryAdministration {
                prepared_scope_hash,
                administration_commitment,
            },
            NativeFrame::AdministrationFacts(facts),
        ) => {
            *prepared_scope_hash == scope
                && facts.prepared_scope_hash == scope
                && facts.role_commitment == *administration_commitment
        }
        (NativeFrame::QueryCpuPark(_), NativeFrame::CpuPark(facts)) => {
            facts.prepared_scope_hash == scope
        }
        (
            NativeFrame::QueryPreparationSuccessor(query),
            NativeFrame::PreparationSuccessorChunk(chunk),
        ) => {
            chunk.facts.prepared_scope_hash == scope
                && chunk.facts.initialization_sequence == query.initialization_sequence
                && chunk.facts.original_cut_digest == query.original_cut_digest
                && chunk.offset == query.offset
        }
        (NativeFrame::QueryTimers(query), NativeFrame::TimerChunk(chunk)) => {
            chunk.prepared_scope_hash == scope
                && chunk.sequence == query.sequence
                && chunk.offset == query.offset
        }
        (NativeFrame::QueryWriters(query), NativeFrame::WriterChunk(chunk)) => {
            chunk.prepared_scope_hash == scope
                && chunk.sequence == query.sequence
                && chunk.offset == query.offset
        }
        (NativeFrame::QueryPhaseTimers(query), NativeFrame::PhaseTimerChunk(chunk)) => {
            chunk.prepared_scope_hash == scope
                && chunk.sequence == query.sequence
                && chunk.offset == query.offset
        }
        (NativeFrame::QueryInitialization(query), NativeFrame::InitializationCut(cut)) => {
            cut.prepared_scope_hash == scope
                && cut.initialization_commitment == query.initialization_commitment
        }
        (NativeFrame::Initialize(command), NativeFrame::InitializationStopped(receipt)) => {
            receipt.prepared_scope_hash == scope
                && receipt.sequence == command.sequence
                && receipt.initialization_commitment == command.initialization_commitment
                && receipt.original_cut_digest == command.original_cut_digest
                && receipt.realize_request_digest == command.realize_request_digest
        }
        (NativeFrame::EffectCompute(original), NativeFrame::EffectProgress(progress)) => {
            // Source-result custody authenticates the native cut before this
            // publication step. The mailbox additionally checks the complete
            // original command/grant and retains byte-identical reply history.
            progress.scope == scope && progress.validate_against(original).is_ok()
        }
        (
            NativeFrame::QueryPrefixPreparation {
                scope: original_scope,
                prefix_preparation,
            },
            NativeFrame::PrefixPreparationFacts(reply),
        ) => {
            let bytes = reply.canonical_bytes();
            *original_scope == scope
                && bytes[16..48] == scope
                && bytes[520..552] == *prefix_preparation
        }
        (
            NativeFrame::AcknowledgePrefixPreparation(original),
            NativeFrame::PrefixPreparationAcknowledged(reply),
        ) => original.scope == scope && original == reply,
        (NativeFrame::AcknowledgePrefix(original), NativeFrame::PrefixAcknowledged(reply)) => {
            original.scope == scope && original == reply
        }
        (NativeFrame::ContinuePrefix(original), NativeFrame::PrefixProgress(reply)) => {
            reply.scope == scope
                && reply.prefix_preparation == original.acknowledgement.prefix_preparation
                && reply.grant_digest == original.acknowledgement.grant_digest
                && reply.command_digest == original.acknowledgement.command_digest
                && reply.sequence == original.acknowledgement.sequence
                && reply.previous_cut_id == original.acknowledgement.cut_id
                && reply.acknowledgement_sequence
                    == original.acknowledgement.acknowledgement_sequence
        }
        (NativeFrame::Acknowledge(original), NativeFrame::Acknowledged(reply)) => original == reply,
        (
            NativeFrame::AcknowledgeInitialization(original),
            NativeFrame::InitializationAcknowledged(reply),
        ) => original == reply,
        (_, NativeFrame::SourceFault(facts)) => facts.prepared_scope_hash == scope,
        _ => false,
    }
}

fn classify(
    edition: crucible_protocol::node_control::NativeControlEdition,
    scope: [u8; 32],
    bytes: &[u8],
) -> NativeAdministrativeClass {
    let Ok(frame) = decode_frame_for_edition(edition, bytes) else {
        return NativeAdministrativeClass::Invalid;
    };
    match frame {
        NativeFrame::PreparePrefix(plan)
            if plan
                .original_effect
                .original_root
                .administration
                .phase
                .initialization
                .preparation
                .scope
                .identity_digest()
                == Ok(scope) =>
        {
            NativeAdministrativeClass::Preparation
        }
        NativeFrame::PrepareEffect(plan)
            if plan
                .original_root
                .administration
                .phase
                .initialization
                .preparation
                .scope
                .identity_digest()
                == Ok(scope) =>
        {
            NativeAdministrativeClass::Preparation
        }
        NativeFrame::EffectCompute(compute)
            if compute.command.scope.identity_digest() == Ok(scope) =>
        {
            NativeAdministrativeClass::Modeled
        }
        NativeFrame::PrepareFixedMicrovm(plan)
            if plan
                .administration
                .phase
                .initialization
                .preparation
                .scope
                .identity_digest()
                == Ok(scope) =>
        {
            NativeAdministrativeClass::Preparation
        }
        NativeFrame::PrepareAdministration(plan)
            if plan
                .phase
                .initialization
                .preparation
                .scope
                .identity_digest()
                == Ok(scope) =>
        {
            NativeAdministrativeClass::Preparation
        }
        NativeFrame::QueryAdministration {
            prepared_scope_hash,
            ..
        } if prepared_scope_hash == scope => NativeAdministrativeClass::ReadOriginal,
        NativeFrame::Prepare(plan) if plan.scope.identity_digest() == Ok(scope) => {
            NativeAdministrativeClass::Preparation
        }
        NativeFrame::PrepareInitialization(plan)
            if plan.preparation.scope.identity_digest() == Ok(scope) =>
        {
            NativeAdministrativeClass::Preparation
        }
        NativeFrame::PreparePhase(plan)
            if plan.initialization.preparation.scope.identity_digest() == Ok(scope) =>
        {
            NativeAdministrativeClass::Preparation
        }
        NativeFrame::QueryCpuPark(actual) if actual == scope => {
            NativeAdministrativeClass::ReadOriginal
        }
        NativeFrame::QueryPreparationSuccessor(query) if query.prepared_scope_hash == scope => {
            NativeAdministrativeClass::ReadOriginal
        }
        NativeFrame::QueryTimers(query) if query.prepared_scope_hash == scope => {
            NativeAdministrativeClass::ReadOriginal
        }
        NativeFrame::QueryWriters(query) if query.prepared_scope_hash == scope => {
            NativeAdministrativeClass::ReadOriginal
        }
        NativeFrame::QueryPhaseTimers(query) if query.prepared_scope_hash == scope => {
            NativeAdministrativeClass::ReadOriginal
        }
        NativeFrame::QueryInitialization(query) if query.prepared_scope_hash == scope => {
            NativeAdministrativeClass::ReadOriginal
        }
        NativeFrame::QueryPrefixPreparation {
            scope: original_scope,
            ..
        } if original_scope == scope => NativeAdministrativeClass::ReadOriginal,
        NativeFrame::AcknowledgePrefixPreparation(ack) if ack.scope == scope => {
            NativeAdministrativeClass::AcknowledgeOriginal
        }
        NativeFrame::AcknowledgePrefix(acknowledgement) if acknowledgement.scope == scope => {
            NativeAdministrativeClass::AcknowledgeOriginal
        }
        NativeFrame::ContinuePrefix(continuation)
            if continuation.acknowledgement.scope == scope =>
        {
            NativeAdministrativeClass::Modeled
        }
        NativeFrame::Acknowledge(_) | NativeFrame::AcknowledgeInitialization(_) => {
            NativeAdministrativeClass::AcknowledgeOriginal
        }
        NativeFrame::Command(command) if command.scope.identity_digest() == Ok(scope) => {
            NativeAdministrativeClass::Modeled
        }
        NativeFrame::Initialize(command) if command.prepared_scope_hash == scope => {
            NativeAdministrativeClass::Modeled
        }
        _ => NativeAdministrativeClass::Invalid,
    }
}

#[cfg(test)]
#[path = "administrative_mailbox_tests.rs"]
mod tests;
