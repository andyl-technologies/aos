//! Quotes the closed held-proof plan before its owned buffers are constructed.
//!
//! This predicts requested storage from actual closed Blob field rosters and
//! compiled layouts. It is a conservative bound, never an observed capacity,
//! allocator measurement, Source whole-node allowance or restoration permit.
//! Actual retained facts must be reconciled before the first SDK/model effect.

use super::restore_input_quote::{shared_header_storage, tree_storage};
use super::*;
use crate::client::DeadlineStream;
use crate::reference_packet::service::complete_restore::{
    PacketNative5CompleteRestoreSelection, maximum_complete_restore_held_evidence_bytes,
};
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use crate::transport::original_frames::OriginalFrameReservation;
use std::cell::{Cell, RefCell};
use std::mem::{align_of, size_of};

pub(crate) struct OriginalRestoreHeldProofAllocationQuote {
    actor: Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    codec: Rc<Native5CodecOwner>,
    bank: Rc<RefCell<OriginalFrameReservation>>,
    maximum_frames: usize,
    requested_bytes: usize,
    prebuilding: Cell<bool>,
}

impl OriginalRestoreHeldProofAllocationQuote {
    pub(super) const fn requested_bytes(&self) -> usize {
        self.requested_bytes
    }

    fn authenticate_connection<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        if connection.role != EndpointRole::Provider
            || !Rc::ptr_eq(&self.actor, &connection.protocol_owner)
            || connection
                .native5_codec
                .as_ref()
                .is_none_or(|codec| !Rc::ptr_eq(codec, &self.codec))
            || connection
                .original_frames
                .as_ref()
                .is_none_or(|bank| !Rc::ptr_eq(bank, &self.bank))
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn retain_original<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<Self, ProviderError> {
        self.authenticate_connection(connection)?;
        if self.prebuilding.get() {
            return Err(refused());
        }
        Ok(Self {
            actor: Rc::clone(&self.actor),
            codec: Rc::clone(&self.codec),
            bank: Rc::clone(&self.bank),
            maximum_frames: self.maximum_frames,
            requested_bytes: self.requested_bytes,
            prebuilding: Cell::new(false),
        })
    }

    pub(super) fn begin_original_prebuild<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        frames: usize,
    ) -> Result<(), ProviderError> {
        self.authenticate_connection(connection)?;
        if frames < 3 || frames > self.maximum_frames || self.prebuilding.replace(true) {
            return Err(refused());
        }
        Ok(())
    }

    /// Checks actual prebuilt storage under the same retained data quote.
    ///
    /// This does not replace the Source's actual simultaneous node/stack/allocator
    /// issuer. The native consumer must separately retain that real conjunction.
    pub(crate) fn authenticate_reconciled_plan<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        actual: &RetainedProtocolMetadataFacts,
    ) -> Result<(), ProviderError> {
        self.authenticate_connection(connection)?;
        if !self.prebuilding.get() || requested_facts(actual)? > self.requested_bytes {
            return Err(credit());
        }
        Ok(())
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(super) fn quote_original_restore_held_proof_allocation(
        &self,
    ) -> Result<OriginalRestoreHeldProofAllocationQuote, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Provider
            || self.original_native5_complete_restore_selection()?
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            return Err(refused());
        }
        let mut incoming = self.guard.incoming_requests();
        let original = incoming.next().ok_or_else(refused)?;
        if incoming.next().is_some() {
            return Err(refused());
        }
        self.guard
            .authenticate_incoming_complete_restore(original)?;
        let projection = self.original_selected_restore_transfer_projection_data(original)?;
        if projection.phase() != crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreTransferPhase::Prepare {
            return Err(refused());
        }
        // Exhaustive scope coverage keeps this closed plan coupled to Envelope.
        // The future Blob scope is null; the retained Commit copy is separately
        // bounded as a complete wire object, including every original field.
        let Envelope {
            protocol,
            message,
            session_id,
            incarnation_id,
            node_id: _,
            execution_owner_id: _,
            capture_owner_id: _,
            request_id,
            operation_id: _,
            sequence: _,
            method,
            body: _,
            extensions: _,
        } = original;
        if protocol != "CNP/1"
            || *message != MessageKind::Request
            || *method != Method::Begin
            || session_id.0.as_ref() != Some(self.authority.session_id())
            || incarnation_id.0.as_ref() != Some(self.authority.incarnation_id())
            || request_id.0.is_none()
        {
            return Err(refused());
        }
        let maximum_frame = allowance(self.authority.limits().frame_bytes.get())?;
        let chunk = allowance(self.authority.limits().blob_chunk_bytes.get())?.min(4096);
        if maximum_frame == 0 || maximum_frame > 65_536 || chunk == 0 {
            return Err(credit());
        }
        let held = maximum_complete_restore_held_evidence_bytes()?;
        let chunks = held.div_ceil(chunk);
        let frames = add(chunks, 2)?;
        if frames > allowance(self.authority.limits().requests.get())? {
            return Err(credit());
        }
        let bank = self.original_frames.as_ref().ok_or_else(refused)?;
        let codec = self.native5_codec.as_ref().ok_or_else(refused)?;
        let mut observer = MetadataObserver::new();
        use crate::retained_metadata::aliases::MetadataSharedKind;
        observer.shared_original(
            MetadataSharedKind::ProtocolOwner,
            self.protocol_owner.as_ref(),
        )?;
        observer.shared_original(MetadataSharedKind::FrameBank, bank.as_ref())?;
        bank.try_borrow()
            .map_err(|_| ProviderError::Conflict("held proof quote bank borrowed"))?
            .observe_owned11_metadata(&mut observer)?;
        let prior_roots = requested_facts(&observer.finish())?;

        let requested_bytes =
            held_proof_geometry(maximum_frame, chunk, prior_roots, size_of::<Self>(), held)?.1;
        Ok(OriginalRestoreHeldProofAllocationQuote {
            actor: Rc::clone(&self.protocol_owner),
            codec: Rc::clone(codec),
            bank: Rc::clone(bank),
            maximum_frames: frames,
            requested_bytes,
            prebuilding: Cell::new(false),
        })
    }
}

fn requested_facts(facts: &RetainedProtocolMetadataFacts) -> Result<usize, ProviderError> {
    sum(&[
        facts.string_capacity_bytes,
        facts.vector_capacity_bytes,
        facts.boxed_value_bytes,
        facts.shared_value_bytes,
        tree_storage(
            facts.tree_containers,
            facts.tree_entries,
            facts.maximum_tree_key_value_bytes,
            facts.maximum_tree_entry_alignment.max(1),
        )?,
        shared_header_storage(
            facts.shared_backing_views,
            facts.maximum_shared_value_alignment.max(1),
        )?,
    ])
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(credit)
}
fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(credit)
}
fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |total, value| add(total, *value))
}
fn refused() -> ProviderError {
    ProviderError::Correlation("original held proof allocation source changed")
}
fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("original held proof requested storage")
}

fn maximum_closed_key_bytes() -> usize {
    [
        "protocol",
        "message",
        "session_id",
        "incarnation_id",
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "request_id",
        "operation_id",
        "sequence",
        "method",
        "body",
        "extensions",
        "transfer_id",
        "content",
        "hash",
        "length",
        "media_type",
        "algorithm",
        "domain",
        "digest",
        "offset",
        "bytes",
    ]
    .into_iter()
    .map(str::len)
    .max()
    .unwrap_or(0)
}

/// Projects the exact closed proof banks without fabricating a frame owner.
pub(super) fn held_proof_geometry(
    maximum_frame: usize,
    chunk: usize,
    prior_roots: usize,
    connection_header_bytes: usize,
    maximum_held_evidence: usize,
) -> Result<(usize, usize), ProviderError> {
    if maximum_frame == 0
        || maximum_frame > 65_536
        || chunk == 0
        || chunk > 4096
        || maximum_held_evidence == 0
    {
        return Err(credit());
    }
    let chunks = maximum_held_evidence.div_ceil(chunk);
    let frames = add(chunks, 2)?;
    // Final Blob body has exactly5/3/3 object containers and9/4/2 entries
    // for Begin/Chunk/Finish. Envelope extensions are included. A staged
    // correlation owns a second deep body copy and its own Id map key.
    let containers = sum(&[5, mul(chunks, 3)?, 3])?;
    let entries = sum(&[9, mul(chunks, 4)?, 2])?;
    let body_tree = tree_storage(
        mul(2, containers)?,
        mul(2, entries)?,
        size_of::<String>() + size_of::<serde_json::Value>(),
        align_of::<String>().max(align_of::<serde_json::Value>()),
    )?;
    let staging_tree = tree_storage(
        1,
        frames,
        size_of::<Id>() + size_of::<Envelope>(),
        align_of::<Id>().max(align_of::<Envelope>()),
    )?;
    // These are predictive UTF-8 bounds, not reported actual capacities.
    // Canonical input bytes bound the sum of cloned key/value String lengths.
    // Success ACK bodies are closed; one malformed raw ACK may additionally
    // own an arbitrary negotiated JSON object and is charged separately.
    let frame_strings = mul(mul(frames, maximum_frame)?, 4)?;
    let vectors = sum(&[
        mul(add(frames, 1)?, size_of::<Envelope>())?,
        mul(frames, size_of::<Vec<u8>>())?,
        mul(frames, size_of::<Option<usize>>())?,
        mul(frames, size_of::<ReceivedFrame>())?,
        mul(frames, size_of::<ResponseBody>())?,
        // Canonical Vec growth and one simultaneous escaped String scratch.
        mul(mul(frames, maximum_frame.max(128))?, 4)?,
    ])?;
    let ack_trees = tree_storage(
        mul(frames, 8)?,
        mul(frames, 32)?,
        size_of::<String>() + size_of::<serde_json::Value>(),
        align_of::<String>().max(align_of::<serde_json::Value>()),
    )?;
    // The retained exact Commit and at most one malformed ACK/parse scratch
    // can use the negotiated JSON byte budget. Each node consumes at least
    // one wire byte; this broad inverse bound is deliberately not a claim
    // that a wire ceiling equals an observed heap capacity.
    let open_json = tree_storage(
        mul(maximum_frame, 2)?,
        mul(maximum_frame, 2)?,
        size_of::<String>() + size_of::<serde_json::Value>(),
        align_of::<String>().max(align_of::<serde_json::Value>()),
    )?;
    // Canonical writer's actual temporary BTreeMap<Vec<u16>,(&str,&Value)>
    // visits at most the13 envelope keys plus9 body/content/hash entries.
    let sorted = tree_storage(
        6,
        22,
        size_of::<Vec<u16>>() + size_of::<(&str, &serde_json::Value)>(),
        align_of::<Vec<u16>>().max(align_of::<(&str, &serde_json::Value)>()),
    )?;
    let scratch = sum(&[
        open_json,
        sorted,
        mul(maximum_frame.max(128), 8)?,
        mul(22, mul(4, maximum_closed_key_bytes())?)?,
        size_of::<crate::session::OriginalRestoreProofRegistration>(),
        size_of::<PreparedOriginalRestoreHeldProof<DeadlineStream>>(),
        connection_header_bytes,
    ])?;
    let requested_bytes = sum(&[
        prior_roots,
        frame_strings,
        vectors,
        body_tree,
        staging_tree,
        ack_trees,
        scratch,
    ])?;
    if requested_bytes > 512 * 1024 * 1024 {
        return Err(credit());
    }

    Ok((frames, requested_bytes))
}

#[path = "restore_proof_quote/settled.rs"]
mod settled_history;
