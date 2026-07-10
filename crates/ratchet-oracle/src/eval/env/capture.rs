//! Flat and linked lexical-environment captures.

use std::ops::Index;
use std::sync::Arc;

use super::{EvalEnvError, EvalFrame, capture_stats};
use crate::eval::module::EvalNodeRef;
use crate::compile::FLAT_CAPTURE_MAX_SLOTS;
use crate::heap::flat::FlatValueTailHandle;
use crate::value::Value;

/// A compact handle to values named by one flat capture plan.
#[derive(Clone, Debug)]
pub(crate) struct EvalFlatCapture {
    allocation_site: EvalNodeRef,
    frame_count: usize,
    owner: Value,
    tail: FlatValueTailHandle,
}

impl EvalFlatCapture {
    /// Creates a handle to values inlined in `owner`'s flat object.
    pub(crate) fn inline(
        allocation_site: EvalNodeRef,
        frame_count: usize,
        owner: Value,
        tail: FlatValueTailHandle,
    ) -> Self {
        Self {
            allocation_site,
            frame_count,
            owner,
            tail,
        }
    }

    /// Returns the module-qualified allocation site that owns the plan.
    pub(crate) const fn allocation_site(&self) -> EvalNodeRef {
        self.allocation_site
    }

    /// Returns the conceptual frame depth at the allocation site.
    pub(crate) const fn frame_count(&self) -> usize {
        self.frame_count
    }

    /// Returns the number of values in the canonical capture order.
    pub(crate) fn len(&self) -> usize {
        self.tail.len()
    }

    /// Returns whether no lexical value is captured.
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the flat closure that owns the inline values.
    pub(crate) const fn inline_owner(&self) -> Value {
        self.owner
    }

    /// Returns the prevalidated coordinate of the owning closure's value tail.
    pub(crate) const fn tail_handle(&self) -> FlatValueTailHandle {
        self.tail
    }

    /// Returns whether two capture handles name the same inline value run.
    fn raw_eq(&self, other: &Self) -> bool {
        self.allocation_site == other.allocation_site
            && self.frame_count == other.frame_count
            && self.owner.raw_eq(other.owner)
            && self.tail == other.tail
    }
}

/// Stack-owned capture values awaiting one flat closure allocation.
#[derive(Debug)]
pub(crate) struct EvalFlatCaptureBuffer {
    allocation_site: EvalNodeRef,
    frame_count: usize,
    values: [Value; FLAT_CAPTURE_MAX_SLOTS],
    len: usize,
    ready: bool,
}

impl EvalFlatCaptureBuffer {
    /// Creates an empty buffer for one allocation site.
    pub(crate) fn new(allocation_site: EvalNodeRef, frame_count: usize) -> Self {
        Self {
            allocation_site,
            frame_count,
            values: [Value::null(); FLAT_CAPTURE_MAX_SLOTS],
            len: 0,
            ready: true,
        }
    }

    /// Reserves a placeholder run for a closure allocated during assembly.
    pub(crate) fn pending(
        allocation_site: EvalNodeRef,
        frame_count: usize,
        values: usize,
    ) -> Result<Self, EvalEnvError> {
        if values > FLAT_CAPTURE_MAX_SLOTS {
            return Err(EvalEnvError::CaptureAllocationFailed { frames: values });
        }
        Ok(Self {
            allocation_site,
            frame_count,
            values: [Value::null(); FLAT_CAPTURE_MAX_SLOTS],
            len: values,
            ready: false,
        })
    }

    /// Appends one value in canonical plan order.
    pub(crate) fn push(&mut self, value: Value) -> Result<(), EvalEnvError> {
        let Some(slot) = self.values.get_mut(self.len) else {
            return Err(EvalEnvError::CaptureAllocationFailed {
                frames: self.len.saturating_add(1),
            });
        };
        *slot = value;
        self.len += 1;
        Ok(())
    }

    /// Records the completed capture and returns the initialized value run.
    pub(crate) fn finish(self) -> Self {
        debug_assert!(self.ready, "only initialized captures may be published");
        capture_stats::note_flat_env_capture(self.len);
        self
    }

    /// Returns the module-qualified allocation site.
    pub(crate) const fn allocation_site(&self) -> EvalNodeRef {
        self.allocation_site
    }

    /// Returns the conceptual frame count at allocation.
    pub(crate) const fn frame_count(&self) -> usize {
        self.frame_count
    }

    /// Returns values in canonical plan order.
    pub(crate) fn values(&self) -> &[Value] {
        &self.values[..self.len]
    }

    /// Returns whether the value run is ready for immediate publication.
    pub(crate) const fn is_ready(&self) -> bool {
        self.ready
    }
}

/// Storage for the conservative suffix of one captured environment.
#[derive(Clone, Debug)]
enum EvalEnvStorage {
    /// Production persistent chain: capture clones one head pointer.
    Chain {
        head: Option<Arc<EvalFrame>>,
        frames: usize,
    },
    /// Compatibility fallback for independently constructed, unlinked frames.
    Array(Arc<[Arc<EvalFrame>]>),
}

impl Default for EvalEnvStorage {
    fn default() -> Self {
        Self::Chain {
            head: None,
            frames: 0,
        }
    }
}

impl EvalEnvStorage {
    fn capture_linked(frames: &[Arc<EvalFrame>]) -> Self {
        Self::Chain {
            head: frames.last().cloned(),
            frames: frames.len(),
        }
    }

    fn capture(frames: &[Arc<EvalFrame>]) -> Result<Self, EvalEnvError> {
        if frames_are_linked(frames) {
            return Ok(Self::capture_linked(frames));
        }

        capture_stats::note_env_capture(frames.len());
        let mut captured = Vec::new();
        captured.try_reserve_exact(frames.len()).map_err(|_| {
            EvalEnvError::CaptureAllocationFailed {
                frames: frames.len(),
            }
        })?;
        captured.extend_from_slice(frames);
        Ok(Self::Array(captured.into()))
    }

    fn len(&self) -> usize {
        match self {
            Self::Chain { frames, .. } => *frames,
            Self::Array(frames) => frames.len(),
        }
    }

    fn frames(&self) -> EvalEnvFrames<'_> {
        match self {
            Self::Chain { head, frames } => EvalEnvFrames::chain(head.as_ref(), *frames),
            Self::Array(frames) => EvalEnvFrames::array(frames),
        }
    }

    /// Returns whether two storage snapshots share the same captured backing.
    fn raw_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Chain {
                    head: left,
                    frames: left_frames,
                },
                Self::Chain {
                    head: right,
                    frames: right_frames,
                },
            ) => {
                left_frames == right_frames
                    && match (left, right) {
                        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                        (None, None) => true,
                        _ => false,
                    }
            }
            (Self::Array(left), Self::Array(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

fn frames_are_linked(frames: &[Arc<EvalFrame>]) -> bool {
    frames.windows(2).all(|pair| {
        pair[1]
            .parent()
            .is_some_and(|parent| Arc::ptr_eq(parent, &pair[0]))
    })
}

/// A captured lexical environment.
///
/// Conservative captures retain one persistent frame-chain head. Flat sites
/// retain only the statically selected values. A compatibility array is used
/// only when tests or external callers supply independently built frames that
/// do not carry production parent links.
#[derive(Clone, Debug, Default)]
pub struct EvalEnv {
    storage: EvalEnvStorage,
    flat_base: Option<EvalFlatCapture>,
}

impl EvalEnv {
    /// Returns whether two snapshots share the same lexical and flat backing.
    pub(crate) fn raw_eq(&self, other: &Self) -> bool {
        self.storage.raw_eq(&other.storage)
            && match (&self.flat_base, &other.flat_base) {
                (Some(left), Some(right)) => left.raw_eq(right),
                (None, None) => true,
                _ => false,
            }
    }

    /// Captures the active frame stack.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::CaptureAllocationFailed`] only for the
    /// compatibility array fallback.
    pub fn capture(frames: &[Arc<EvalFrame>]) -> Result<Self, EvalEnvError> {
        Ok(Self {
            storage: EvalEnvStorage::capture(frames)?,
            flat_base: None,
        })
    }

    /// Captures the evaluator-owned linked active stack without rescanning its
    /// parent-pointer invariant at every closure allocation.
    pub(crate) fn capture_linked_with_flat_base(
        frames: &[Arc<EvalFrame>],
        flat_base: Option<EvalFlatCapture>,
    ) -> Self {
        Self {
            storage: EvalEnvStorage::capture_linked(frames),
            flat_base,
        }
    }

    /// Creates an environment referring to values in its owning flat object.
    pub(crate) fn inline_flat(
        allocation_site: EvalNodeRef,
        frame_count: usize,
        owner: Value,
        tail: FlatValueTailHandle,
    ) -> Self {
        Self {
            storage: EvalEnvStorage::default(),
            flat_base: Some(EvalFlatCapture::inline(
                allocation_site,
                frame_count,
                owner,
                tail,
            )),
        }
    }

    /// Returns the captured shared frames, ordered outermost to innermost.
    pub fn frames(&self) -> EvalEnvFrames<'_> {
        self.storage.frames()
    }

    /// Returns the inherited flat captured-value base, when present.
    pub(crate) const fn flat_base(&self) -> Option<&EvalFlatCapture> {
        self.flat_base.as_ref()
    }

    /// Returns the conceptual frame count seen by lowered lexical coordinates.
    pub fn frame_count(&self) -> usize {
        self.flat_base
            .as_ref()
            .map_or(0, EvalFlatCapture::frame_count)
            .saturating_add(self.storage.len())
    }

    /// Returns whether the environment captures no lexical values or frames.
    pub fn is_empty(&self) -> bool {
        self.storage.len() == 0
            && self
                .flat_base
                .as_ref()
                .is_none_or(EvalFlatCapture::is_empty)
    }
}

/// A borrowed outermost-to-innermost view of captured shared frames.
#[derive(Clone, Copy, Debug)]
pub struct EvalEnvFrames<'a> {
    source: EvalEnvFramesSource<'a>,
    len: usize,
}

#[derive(Clone, Copy, Debug)]
enum EvalEnvFramesSource<'a> {
    Chain(Option<&'a Arc<EvalFrame>>),
    Array(&'a [Arc<EvalFrame>]),
}

impl<'a> EvalEnvFrames<'a> {
    const fn chain(head: Option<&'a Arc<EvalFrame>>, len: usize) -> Self {
        Self {
            source: EvalEnvFramesSource::Chain(head),
            len,
        }
    }

    const fn array(frames: &'a [Arc<EvalFrame>]) -> Self {
        Self {
            source: EvalEnvFramesSource::Array(frames),
            len: frames.len(),
        }
    }

    /// Returns the number of shared frames in the view.
    pub const fn len(self) -> usize {
        self.len
    }

    /// Returns whether the view contains no shared frames.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Returns the outermost-indexed frame, when present.
    pub fn get(self, index: usize) -> Option<&'a Arc<EvalFrame>> {
        if index >= self.len {
            return None;
        }
        match self.source {
            EvalEnvFramesSource::Array(frames) => frames.get(index),
            EvalEnvFramesSource::Chain(mut frame) => {
                for _ in 0..self.len.saturating_sub(index + 1) {
                    frame = frame?.parent();
                }
                frame
            }
        }
    }

    /// Returns the innermost shared frame, when present.
    pub fn last(self) -> Option<&'a Arc<EvalFrame>> {
        self.len.checked_sub(1).and_then(|index| self.get(index))
    }

    /// Iterates from the outermost frame to the innermost frame.
    pub fn iter(self) -> impl Iterator<Item = &'a Arc<EvalFrame>> {
        (0..self.len).filter_map(move |index| self.get(index))
    }
}

impl Index<usize> for EvalEnvFrames<'_> {
    type Output = Arc<EvalFrame>;

    fn index(&self, index: usize) -> &Self::Output {
        match self.get(index) {
            Some(frame) => frame,
            None => panic!("captured environment frame index {index} is out of bounds"),
        }
    }
}
