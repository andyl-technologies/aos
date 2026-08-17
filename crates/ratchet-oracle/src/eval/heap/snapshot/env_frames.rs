//! Captured-environment frame-table serializer (RFC-0007 doc 31 §1 step 3,
//! increment 2).
//!
//! A closure's captured [`EvalEnv`] is a parent-linked chain of
//! `Arc<EvalFrame>` slot arrays allocated outside the flat arena, so the dumped
//! reservation lanes do not carry it — and it cannot be rebuilt from IR without
//! re-forcing, which is the work the snapshot exists to skip. This module
//! serializes the frame graph as a dense, deduplicated table:
//!
//! - **Capture** walks every live worker closure's environment, deduplicates
//!   frames by `Arc` identity (sharing is the point: the measured prelude shows
//!   741 distinct frames behind 1,031 references), and assigns each distinct
//!   frame a dense id such that a frame's in-table parent always has a smaller
//!   id. Each frame serializes as its parent link plus its address-free
//!   Candidate-C slot value words.
//! - **Rebuild** reconstructs the shared `Arc<EvalFrame>` DAG bottom-up
//!   (parents first, enforced by the id order), re-sharing parents so restored
//!   closures that captured one frame keep capturing one frame.
//!
//! Closure payloads (increment 3) reference frames by table id; `with`-scope
//! and scoped-global stacks hold no frames (they are value stacks serialized
//! with each closure), so the table is fed by lexical environments alone.
//!
//! # Wire format
//!
//! Each frame's opaque bytes inside its [`FramePayload`] segment
//! (little-endian):
//!
//! ```text
//! frame: parent(u32; 0xffff_ffff = none) | slot_count(u32) | slot_word(u64)*
//! ```
//!
//! Slot words are address-free Candidate-C value words that resolve unchanged
//! once the restored reservation re-registers the image's domain. Raw interned
//! symbol ids inside those values are valid in-process only (see the step-3
//! spec's cross-process boundary note).

use std::collections::HashMap;
use std::sync::Arc;

use ratchet_value::heap::FramePayload;

use crate::eval::env::{EvalEnv, EvalFrame};
use crate::value::Value;
use crate::value::compressed::CompressedValueWord;

use super::super::{EvalHeap, FlatClosurePayload};
use super::EvalHeapSnapshotError;

/// The `parent` wire word of a frame with no serialized parent link.
const FRAME_PARENT_NONE: u32 = u32::MAX;

/// Byte width of one serialized Candidate-C slot value word.
const SLOT_WORD_LEN: usize = 8;

/// A captured, deduplicated environment frame table.
///
/// Produced by [`EvalHeap::capture_env_frame_table`]; closure capture
/// (increment 3) translates each closure's `Arc<EvalFrame>` references into
/// dense table ids through [`CapturedFrameTable::frame_id`].
#[derive(Debug)]
pub(crate) struct CapturedFrameTable {
    /// Dense-id-ordered frame payloads (`payloads[i].index == i`).
    payloads: Vec<FramePayload>,
    /// `Arc` identity of each captured frame, keyed to its dense id.
    ids: HashMap<*const EvalFrame, u32>,
}

impl CapturedFrameTable {
    /// Captures the deduplicated frame table for `envs`.
    ///
    /// Walks each environment's captured frame view outermost-to-innermost,
    /// deduplicating by `Arc` identity. A frame's parent link serializes as the
    /// parent's table id when the parent is itself referenced by some
    /// environment view, and as *none* otherwise (an out-of-view ancestor is
    /// unreachable through every captured view, so dropping the link preserves
    /// each view's observable chain).
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::EnvFrameUnreadable`] when a frame's
    /// slots cannot be snapshotted (an invalid slot encoding, unreachable
    /// through [`EvalFrame::set`]).
    pub(crate) fn capture_from_envs<'a>(
        envs: impl Iterator<Item = &'a EvalEnv>,
    ) -> Result<Self, EvalHeapSnapshotError> {
        // Pass 1: collect the distinct frames in first-encounter order, keyed
        // by `Arc` identity, retaining one clone of each for slot reads.
        let mut membership: HashMap<*const EvalFrame, usize> = HashMap::new();
        let mut frames: Vec<Arc<EvalFrame>> = Vec::new();
        for env in envs {
            for frame in env.frames().iter() {
                membership.entry(Arc::as_ptr(frame)).or_insert_with(|| {
                    frames.push(Arc::clone(frame));
                    frames.len() - 1
                });
            }
        }

        // Pass 2: assign dense ids parent-before-child. For each frame in
        // first-encounter order, walk its unassigned in-table ancestors and
        // assign them top-down, so every serialized parent id is smaller than
        // its child's id (the rebuild-order invariant).
        let mut ids: HashMap<*const EvalFrame, u32> = HashMap::with_capacity(frames.len());
        let mut order: Vec<Arc<EvalFrame>> = Vec::with_capacity(frames.len());
        for frame in &frames {
            let mut chain: Vec<&Arc<EvalFrame>> = Vec::new();
            let mut cursor = Some(frame);
            while let Some(current) = cursor {
                let key = Arc::as_ptr(current);
                if ids.contains_key(&key) || !membership.contains_key(&key) {
                    break;
                }
                chain.push(current);
                cursor = current.parent();
            }
            for current in chain.into_iter().rev() {
                let id = order.len() as u32;
                ids.insert(Arc::as_ptr(current), id);
                order.push(Arc::clone(current));
            }
        }

        let mut payloads = Vec::with_capacity(order.len());
        for (id, frame) in order.iter().enumerate() {
            let parent = frame
                .parent()
                .and_then(|parent| ids.get(&Arc::as_ptr(parent)).copied())
                .unwrap_or(FRAME_PARENT_NONE);
            let slots = frame
                .slot_values()
                .map_err(EvalHeapSnapshotError::EnvFrameUnreadable)?;
            let mut frame_bytes = Vec::with_capacity(8 + slots.len() * SLOT_WORD_LEN);
            frame_bytes.extend_from_slice(&parent.to_le_bytes());
            frame_bytes.extend_from_slice(&(slots.len() as u32).to_le_bytes());
            for value in &slots {
                frame_bytes.extend_from_slice(&value.word().raw().to_le_bytes());
            }
            payloads.push(FramePayload {
                index: id as u32,
                frame_bytes,
            });
        }
        Ok(Self { payloads, ids })
    }

    /// Returns the dense table id of a captured frame, by `Arc` identity.
    pub(crate) fn frame_id(&self, frame: &Arc<EvalFrame>) -> Option<u32> {
        self.ids.get(&Arc::as_ptr(frame)).copied()
    }

    /// Returns the number of distinct captured frames.
    pub(crate) fn len(&self) -> usize {
        self.payloads.len()
    }

    /// Consumes the table into its wire payload segments.
    pub(crate) fn into_payloads(self) -> Vec<FramePayload> {
        self.payloads
    }
}

/// A rebuilt shared `Arc<EvalFrame>` graph, indexed by dense frame id.
///
/// Restored closure payloads (increment 3) resolve their environment frame
/// references through [`RestoredFrameTable::frame`].
#[derive(Debug)]
pub(crate) struct RestoredFrameTable {
    frames: Vec<Arc<EvalFrame>>,
}

impl RestoredFrameTable {
    /// Rebuilds the shared frame graph from its wire payload segments.
    ///
    /// The segments must be dense (`payloads[i].index == i` — which also rules
    /// out duplicate ids) and parent-before-child (`parent < index`), the
    /// order capture guarantees; the table rebuilds bottom-up so every child
    /// links the already-rebuilt shared parent `Arc`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::MalformedFramePayload`] when a segment
    /// is out of dense order, its bytes are truncated or trailing, its parent
    /// id is not smaller than its own, or a slot word is not a valid
    /// Candidate-C value word, and
    /// [`EvalHeapSnapshotError::EnvFrameUnreadable`] when a rebuilt frame's
    /// slot storage cannot be allocated or written.
    pub(crate) fn rebuild(payloads: &[FramePayload]) -> Result<Self, EvalHeapSnapshotError> {
        let mut frames: Vec<Arc<EvalFrame>> = Vec::with_capacity(payloads.len());
        for (position, payload) in payloads.iter().enumerate() {
            let malformed = || EvalHeapSnapshotError::MalformedFramePayload {
                index: payload.index,
            };
            if payload.index as usize != position {
                return Err(malformed());
            }
            let bytes = &payload.frame_bytes;
            if bytes.len() < 8 {
                return Err(malformed());
            }
            let parent_id = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| malformed())?);
            let slot_count =
                u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| malformed())?) as usize;
            // Exact-length check before any allocation: `slot_count` is
            // untrusted and must not drive a speculative reservation.
            let expected = slot_count
                .checked_mul(SLOT_WORD_LEN)
                .and_then(|words| words.checked_add(8))
                .ok_or_else(malformed)?;
            if bytes.len() != expected {
                return Err(malformed());
            }
            let parent = if parent_id == FRAME_PARENT_NONE {
                None
            } else {
                // Parent-before-child: the parent must already be rebuilt.
                if parent_id as usize >= position {
                    return Err(malformed());
                }
                frames.get(parent_id as usize).cloned()
            };
            let frame = EvalFrame::new_linked(slot_count, parent)
                .map_err(EvalHeapSnapshotError::EnvFrameUnreadable)?;
            for (slot, chunk) in bytes[8..].chunks_exact(SLOT_WORD_LEN).enumerate() {
                let raw = u64::from_le_bytes(chunk.try_into().map_err(|_| malformed())?);
                let word = CompressedValueWord::from_raw(raw).map_err(|_| malformed())?;
                frame
                    .set(slot as u32, Value::from_word(word))
                    .map_err(EvalHeapSnapshotError::EnvFrameUnreadable)?;
            }
            frames.push(frame);
        }
        Ok(Self { frames })
    }

    /// Returns the rebuilt shared frame with dense id `id`.
    pub(crate) fn frame(&self, id: u32) -> Option<&Arc<EvalFrame>> {
        self.frames.get(id as usize)
    }

    /// Returns the number of rebuilt frames.
    pub(crate) fn len(&self) -> usize {
        self.frames.len()
    }
}

impl EvalHeap {
    /// Captures the deduplicated env-frame table of every live worker closure.
    ///
    /// Walks the lexical environment of each thunk and lambda in the flat
    /// closure store (primops and retired slots capture no environment) and
    /// dedups frames by `Arc` identity. This is the capture half of the step-3
    /// closure serializer; closure payload capture (increment 3) consumes the
    /// returned table's ids.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::EnvFrameUnreadable`] when a captured
    /// frame's slots cannot be snapshotted.
    pub(crate) fn capture_env_frame_table(
        &self,
    ) -> Result<CapturedFrameTable, EvalHeapSnapshotError> {
        CapturedFrameTable::capture_from_envs(self.flat_closures.iter().filter_map(|object| {
            match object.object().payload() {
                FlatClosurePayload::Thunk(thunk) => thunk.env(),
                FlatClosurePayload::SharedThunk(thunk) => thunk.env(),
                FlatClosurePayload::Lambda(lambda) => Some(lambda.env()),
                FlatClosurePayload::Primop(_) | FlatClosurePayload::Retired(_) => None,
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a linked child frame holding `values`, for graph fixtures.
    fn frame_with_values(parent: Option<Arc<EvalFrame>>, values: &[Value]) -> Arc<EvalFrame> {
        let frame = EvalFrame::new_linked(values.len(), parent).expect("frame allocates");
        for (slot, value) in values.iter().enumerate() {
            frame.set(slot as u32, *value).expect("slot writes");
        }
        frame
    }

    /// Reads every slot of a rebuilt frame back as raw value words.
    fn slot_words(frame: &EvalFrame) -> Vec<u64> {
        frame
            .slot_values()
            .expect("slots read")
            .iter()
            .map(|value| value.word().raw())
            .collect()
    }

    #[test]
    fn capture_dedups_shared_parents_and_round_trips_the_dag() {
        // A shared outer frame with two child frames: the diamond the dedup
        // exists for. env1 = [a, b1], env2 = [a, b2].
        let a = frame_with_values(None, &[Value::int(1), Value::bool(true)]);
        let b1 = frame_with_values(Some(Arc::clone(&a)), &[Value::int(10)]);
        let b2 = frame_with_values(Some(Arc::clone(&a)), &[Value::null()]);
        let env1 = EvalEnv::capture(&[Arc::clone(&a), Arc::clone(&b1)]).expect("env1 captures");
        let env2 = EvalEnv::capture(&[Arc::clone(&a), Arc::clone(&b2)]).expect("env2 captures");

        let table = CapturedFrameTable::capture_from_envs([&env1, &env2].into_iter())
            .expect("frame table captures");
        // Four frame references dedup to three distinct frames.
        assert_eq!(table.len(), 3);
        let id_a = table.frame_id(&a).expect("a is captured");
        let id_b1 = table.frame_id(&b1).expect("b1 is captured");
        let id_b2 = table.frame_id(&b2).expect("b2 is captured");
        assert!(id_a < id_b1, "parent is assigned before its child");
        assert!(id_a < id_b2, "parent is assigned before its child");

        let payloads = table.into_payloads();
        let restored = RestoredFrameTable::rebuild(&payloads).expect("frame table rebuilds");
        assert_eq!(restored.len(), 3);

        let restored_a = restored.frame(id_a).expect("a rebuilds");
        let restored_b1 = restored.frame(id_b1).expect("b1 rebuilds");
        let restored_b2 = restored.frame(id_b2).expect("b2 rebuilds");
        assert_eq!(slot_words(restored_a), slot_words(&a));
        assert_eq!(slot_words(restored_b1), slot_words(&b1));
        assert_eq!(slot_words(restored_b2), slot_words(&b2));
        // The rebuilt children re-share one parent `Arc` — the identity the
        // dedup preserves across the round trip.
        let parent_b1 = restored_b1.parent().expect("b1 keeps its parent link");
        let parent_b2 = restored_b2.parent().expect("b2 keeps its parent link");
        assert!(Arc::ptr_eq(parent_b1, restored_a));
        assert!(Arc::ptr_eq(parent_b1, parent_b2));
    }

    #[test]
    fn capture_drops_out_of_view_ancestor_links() {
        // `hidden` is an ancestor no environment view reaches: the captured
        // view of env = [visible] has length 1, so the chain walk never leaves
        // `visible`. Its serialized parent link must be none.
        let hidden = frame_with_values(None, &[Value::int(7)]);
        let visible = frame_with_values(Some(hidden), &[Value::int(8)]);
        let env = EvalEnv::capture(&[Arc::clone(&visible)]).expect("env captures");

        let table = CapturedFrameTable::capture_from_envs(std::iter::once(&env)).expect("captures");
        assert_eq!(table.len(), 1, "the out-of-view ancestor is not captured");
        let payloads = table.into_payloads();
        let restored = RestoredFrameTable::rebuild(&payloads).expect("rebuilds");
        assert!(
            restored
                .frame(0)
                .expect("frame rebuilds")
                .parent()
                .is_none(),
            "an out-of-view ancestor link does not survive capture"
        );
    }

    #[test]
    fn rebuild_refuses_a_non_dense_or_out_of_order_table() {
        let env =
            EvalEnv::capture(&[frame_with_values(None, &[Value::int(3)])]).expect("env captures");
        let payloads = CapturedFrameTable::capture_from_envs(std::iter::once(&env))
            .expect("captures")
            .into_payloads();

        // A gap in the dense id space refuses.
        let mut sparse = payloads.clone();
        sparse[0].index = 5;
        assert!(matches!(
            RestoredFrameTable::rebuild(&sparse),
            Err(EvalHeapSnapshotError::MalformedFramePayload { index: 5 })
        ));

        // A parent id at or above the frame's own id refuses (cycle guard).
        let mut self_parent = payloads.clone();
        self_parent[0].frame_bytes[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            RestoredFrameTable::rebuild(&self_parent),
            Err(EvalHeapSnapshotError::MalformedFramePayload { index: 0 })
        ));
    }

    #[test]
    fn rebuild_refuses_truncated_trailing_or_invalid_slot_bytes() {
        let env =
            EvalEnv::capture(&[frame_with_values(None, &[Value::int(3)])]).expect("env captures");
        let payloads = CapturedFrameTable::capture_from_envs(std::iter::once(&env))
            .expect("captures")
            .into_payloads();

        // Truncated below the fixed header.
        let mut truncated = payloads.clone();
        truncated[0].frame_bytes.truncate(6);
        assert!(matches!(
            RestoredFrameTable::rebuild(&truncated),
            Err(EvalHeapSnapshotError::MalformedFramePayload { .. })
        ));

        // Trailing bytes beyond the declared slot run.
        let mut trailing = payloads.clone();
        trailing[0].frame_bytes.push(0);
        assert!(matches!(
            RestoredFrameTable::rebuild(&trailing),
            Err(EvalHeapSnapshotError::MalformedFramePayload { .. })
        ));

        // A slot-count that overstates the byte run (an untrusted-length lie).
        let mut overstated = payloads.clone();
        overstated[0].frame_bytes[4..8].copy_from_slice(&1000u32.to_le_bytes());
        assert!(matches!(
            RestoredFrameTable::rebuild(&overstated),
            Err(EvalHeapSnapshotError::MalformedFramePayload { .. })
        ));

        // A slot word that is not a valid Candidate-C encoding.
        let mut invalid_word = payloads;
        let last = invalid_word[0].frame_bytes.len();
        invalid_word[0].frame_bytes[last - 8..].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            RestoredFrameTable::rebuild(&invalid_word),
            Err(EvalHeapSnapshotError::MalformedFramePayload { .. })
        ));
    }
}
