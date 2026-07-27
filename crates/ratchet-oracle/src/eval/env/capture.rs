//! Flat and linked lexical-environment captures.

use std::ops::Index;
use std::sync::Arc;

use super::{EvalEnvError, EvalFrame, capture_stats};
use crate::compile::FLAT_CAPTURE_MAX_SLOTS;
use crate::eval::module::EvalNodeRef;
use crate::heap::flat::FlatValueTailHandle;
use crate::value::Value;

const FLAT_CAPTURE_SITE_NODE_BITS: u32 = 20;
const FLAT_CAPTURE_SITE_NODE_MASK: u32 = (1 << FLAT_CAPTURE_SITE_NODE_BITS) - 1;
const FLAT_CAPTURE_SITE_MODULE_MAX: u32 = (1 << (u32::BITS - FLAT_CAPTURE_SITE_NODE_BITS)) - 1;

/// A checked module-qualified capture site packed into one word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EvalFlatCaptureSite(u32);

impl EvalFlatCaptureSite {
    /// Packs a site admitted by the flat-capture optimization.
    fn new(site: EvalNodeRef) -> Option<Self> {
        let module = site.module().as_u32();
        let node = site.id().as_u32();
        if module > FLAT_CAPTURE_SITE_MODULE_MAX || node > FLAT_CAPTURE_SITE_NODE_MASK {
            return None;
        }
        Some(Self((module << FLAT_CAPTURE_SITE_NODE_BITS) | node))
    }

    /// Reconstructs the exact module-qualified site.
    const fn node_ref(self) -> EvalNodeRef {
        EvalNodeRef::new(
            crate::eval::module::EvalModuleId::new(self.0 >> FLAT_CAPTURE_SITE_NODE_BITS),
            crate::compile::IrId::new(self.0 & FLAT_CAPTURE_SITE_NODE_MASK),
        )
    }
}

/// A compact handle to values named by one flat capture plan.
#[derive(Clone, Debug)]
pub(crate) struct EvalFlatCapture {
    allocation_site: EvalFlatCaptureSite,
    tail: FlatValueTailHandle,
    frame_count: u16,
    linked_frame_count: u16,
}

impl EvalFlatCapture {
    /// Creates a handle to values inlined in one flat closure object.
    pub(crate) fn inline(
        allocation_site: EvalNodeRef,
        frame_count: usize,
        tail: FlatValueTailHandle,
    ) -> Result<Self, EvalEnvError> {
        let allocation_site = EvalFlatCaptureSite::new(allocation_site).ok_or(
            EvalEnvError::CompactCaptureSiteUnsupported {
                module: allocation_site.module().as_u32(),
                node: allocation_site.id().as_u32(),
            },
        )?;
        let frame_count =
            u16::try_from(frame_count).map_err(|_| EvalEnvError::CaptureAllocationFailed {
                frames: frame_count,
            })?;
        Ok(Self {
            allocation_site,
            tail,
            frame_count,
            linked_frame_count: 0,
        })
    }

    /// Records the conservative linked suffix stored beside this flat prefix.
    fn with_linked_frame_count(mut self, frames: usize) -> Result<Self, EvalEnvError> {
        self.linked_frame_count =
            u16::try_from(frames).map_err(|_| EvalEnvError::CaptureAllocationFailed { frames })?;
        Ok(self)
    }

    /// Returns the conservative linked suffix stored beside this flat prefix.
    const fn linked_frame_count(&self) -> usize {
        self.linked_frame_count as usize
    }

    /// Returns whether a conceptual depth fits the compact capture metadata.
    pub(crate) const fn supports_frame_count(frame_count: usize) -> bool {
        frame_count <= u16::MAX as usize
    }

    /// Returns whether a module-qualified site fits compact capture metadata.
    pub(crate) fn supports_allocation_site(site: EvalNodeRef) -> bool {
        EvalFlatCaptureSite::new(site).is_some()
    }

    /// Returns the module-qualified allocation site that owns the plan.
    pub(crate) const fn allocation_site(&self) -> EvalNodeRef {
        self.allocation_site.node_ref()
    }

    /// Returns the conceptual frame depth at the allocation site.
    pub(crate) const fn frame_count(&self) -> usize {
        self.frame_count as usize
    }

    /// Returns the number of values in the canonical capture order.
    pub(crate) const fn len(&self) -> usize {
        self.tail.len()
    }

    /// Returns whether no lexical value is captured.
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the prevalidated coordinate of the owning closure's value tail.
    pub(crate) const fn tail_handle(&self) -> FlatValueTailHandle {
        self.tail
    }

    /// Returns whether two capture handles name the same inline value run.
    fn raw_eq(&self, other: &Self) -> bool {
        self.allocation_site == other.allocation_site
            && self.frame_count == other.frame_count
            && self.linked_frame_count == other.linked_frame_count
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
    /// No conservative frames or flat prefix are captured.
    Empty,
    /// Production persistent chain: capture clones one non-empty head pointer.
    Chain { head: Arc<EvalFrame>, frames: u32 },
    /// Compatibility fallback for independently constructed, unlinked frames.
    ///
    /// The vector is kept behind a thin [`Arc`] rather than an unsized
    /// `Arc<[Arc<EvalFrame>]>`: this compatibility-only variant must not widen
    /// the production [`EvalEnvStorage`] enum carried by every closure.
    Array(Arc<Vec<Arc<EvalFrame>>>),
    /// A statically selected flat prefix without conservative frames.
    Flat(EvalFlatCapture),
    /// A production chain following a statically selected flat prefix.
    ChainFlat {
        head: Arc<EvalFrame>,
        flat: EvalFlatCapture,
    },
    /// A compatibility frame array following a statically selected flat prefix.
    ArrayFlat {
        frames: Arc<Vec<Arc<EvalFrame>>>,
        flat: EvalFlatCapture,
    },
}

impl Default for EvalEnvStorage {
    fn default() -> Self {
        Self::Empty
    }
}

impl EvalEnvStorage {
    /// Returns the stable telemetry name for this storage representation.
    const fn class(&self) -> &'static str {
        match self {
            Self::Empty => "Empty",
            Self::Chain { .. } => "Chain",
            Self::Array(_) => "Array",
            Self::Flat(_) => "Flat",
            Self::ChainFlat { .. } => "ChainFlat",
            Self::ArrayFlat { .. } => "ArrayFlat",
        }
    }

    fn linked(head: Option<Arc<EvalFrame>>, frames: usize) -> Result<Self, EvalEnvError> {
        debug_assert_eq!(head.is_some(), frames != 0);
        let frames =
            u32::try_from(frames).map_err(|_| EvalEnvError::CaptureAllocationFailed { frames })?;
        match head {
            Some(head) => Ok(Self::Chain { head, frames }),
            None => Ok(Self::Empty),
        }
    }

    fn capture_linked(frames: &[Arc<EvalFrame>]) -> Result<Self, EvalEnvError> {
        Self::linked(frames.last().cloned(), frames.len())
    }

    fn capture(frames: &[Arc<EvalFrame>]) -> Result<Self, EvalEnvError> {
        if frames_are_linked(frames) {
            return Self::capture_linked(frames);
        }

        capture_stats::note_env_capture(frames.len());
        let mut captured = Vec::new();
        captured.try_reserve_exact(frames.len()).map_err(|_| {
            EvalEnvError::CaptureAllocationFailed {
                frames: frames.len(),
            }
        })?;
        captured.extend_from_slice(frames);
        Ok(Self::Array(Arc::new(captured)))
    }

    fn with_flat_base(self, flat: Option<EvalFlatCapture>) -> Result<Self, EvalEnvError> {
        let Some(flat) = flat else {
            return Ok(self);
        };
        Ok(match self {
            Self::Empty => Self::Flat(flat),
            Self::Chain { head, frames } => Self::ChainFlat {
                head,
                flat: flat.with_linked_frame_count(frames as usize)?,
            },
            Self::Array(frames) => Self::ArrayFlat { frames, flat },
            storage @ (Self::Flat(_) | Self::ChainFlat { .. } | Self::ArrayFlat { .. }) => {
                debug_assert!(false, "flat base attached twice");
                storage
            }
        })
    }

    fn len(&self) -> usize {
        match self {
            Self::Empty | Self::Flat(_) => 0,
            Self::Chain { frames, .. } => *frames as usize,
            Self::ChainFlat { flat, .. } => flat.linked_frame_count(),
            Self::Array(frames) | Self::ArrayFlat { frames, .. } => frames.len(),
        }
    }

    fn frames(&self) -> EvalEnvFrames<'_> {
        match self {
            Self::Empty | Self::Flat(_) => EvalEnvFrames::chain(None, 0),
            Self::Chain { head, frames } => EvalEnvFrames::chain(Some(head), *frames as usize),
            Self::ChainFlat { head, flat } => {
                EvalEnvFrames::chain(Some(head), flat.linked_frame_count())
            }
            Self::Array(frames) | Self::ArrayFlat { frames, .. } => {
                EvalEnvFrames::array(frames.as_slice())
            }
        }
    }

    const fn flat_base(&self) -> Option<&EvalFlatCapture> {
        match self {
            Self::Flat(flat) | Self::ChainFlat { flat, .. } | Self::ArrayFlat { flat, .. } => {
                Some(flat)
            }
            Self::Empty | Self::Chain { .. } | Self::Array(_) => None,
        }
    }

    fn linked_parts(&self) -> Option<(Option<&Arc<EvalFrame>>, usize)> {
        match self {
            Self::Empty | Self::Flat(_) => Some((None, 0)),
            Self::Chain { head, frames } => Some((Some(head), *frames as usize)),
            Self::ChainFlat { head, flat } => Some((Some(head), flat.linked_frame_count())),
            Self::Array(_) | Self::ArrayFlat { .. } => None,
        }
    }

    /// Returns whether two storage snapshots share the same captured backing.
    fn raw_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Empty, Self::Empty) => true,
            (
                Self::Chain {
                    head: left,
                    frames: left_frames,
                },
                Self::Chain {
                    head: right,
                    frames: right_frames,
                },
            ) => left_frames == right_frames && Arc::ptr_eq(left, right),
            (Self::Array(left), Self::Array(right)) => Arc::ptr_eq(left, right),
            (Self::Flat(left), Self::Flat(right)) => left.raw_eq(right),
            (
                Self::ChainFlat {
                    head: left_head,
                    flat: left_flat,
                },
                Self::ChainFlat {
                    head: right_head,
                    flat: right_flat,
                },
            ) => Arc::ptr_eq(left_head, right_head) && left_flat.raw_eq(right_flat),
            (
                Self::ArrayFlat {
                    frames: left_frames,
                    flat: left_flat,
                },
                Self::ArrayFlat {
                    frames: right_frames,
                    flat: right_flat,
                },
            ) => Arc::ptr_eq(left_frames, right_frames) && left_flat.raw_eq(right_flat),
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
}

impl EvalEnv {
    /// Returns the storage representation used by this capture.
    pub(crate) const fn storage_class(&self) -> &'static str {
        self.storage.class()
    }

    /// Returns whether two snapshots share the same lexical and flat backing.
    pub(crate) fn raw_eq(&self, other: &Self) -> bool {
        self.storage.raw_eq(&other.storage)
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
        })
    }

    /// Captures frames plus an inherited flat lexical prefix.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::CaptureAllocationFailed`] only for the
    /// compatibility array fallback.
    pub(crate) fn capture_with_flat_base(
        frames: &[Arc<EvalFrame>],
        flat_base: Option<EvalFlatCapture>,
    ) -> Result<Self, EvalEnvError> {
        Ok(Self {
            storage: EvalEnvStorage::capture(frames)?.with_flat_base(flat_base)?,
        })
    }

    /// Rebuilds a captured environment from restored shared frames and an
    /// optional flat capture (RFC-0007 doc 31 §1 heap-image closure restore).
    ///
    /// Storage selection mirrors [`EvalEnv::capture`]: frames whose rebuilt
    /// parent links form the production chain re-capture as a chain head;
    /// unlinked frames fall back to the compatibility array.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::CaptureAllocationFailed`] only for the
    /// compatibility array fallback.
    #[cfg(feature = "candidate_c_value")]
    pub(crate) fn restore_parts(
        frames: &[Arc<EvalFrame>],
        flat_base: Option<EvalFlatCapture>,
    ) -> Result<Self, EvalEnvError> {
        Ok(Self {
            storage: EvalEnvStorage::capture(frames)?.with_flat_base(flat_base)?,
        })
    }

    /// Captures a known linked active environment from its innermost head.
    pub(crate) fn capture_linked_head_with_flat_base(
        head: Option<Arc<EvalFrame>>,
        frames: usize,
        flat_base: Option<EvalFlatCapture>,
    ) -> Result<Self, EvalEnvError> {
        Ok(Self {
            storage: EvalEnvStorage::linked(head, frames)?.with_flat_base(flat_base)?,
        })
    }

    /// Captures a linked frame slice for tests that construct a flat prefix.
    #[cfg(test)]
    pub(crate) fn capture_linked_with_flat_base(
        frames: &[Arc<EvalFrame>],
        flat_base: Option<EvalFlatCapture>,
    ) -> Result<Self, EvalEnvError> {
        Ok(Self {
            storage: EvalEnvStorage::capture_linked(frames)?.with_flat_base(flat_base)?,
        })
    }

    /// Returns the persistent-chain head and frame count when storage is linked.
    pub(crate) fn linked_parts(&self) -> Option<(Option<&Arc<EvalFrame>>, usize)> {
        self.storage.linked_parts()
    }

    /// Creates an environment referring to values in its owning flat object.
    pub(crate) fn inline_flat(
        allocation_site: EvalNodeRef,
        frame_count: usize,
        tail: FlatValueTailHandle,
    ) -> Result<Self, EvalEnvError> {
        Ok(Self {
            storage: EvalEnvStorage::Flat(EvalFlatCapture::inline(
                allocation_site,
                frame_count,
                tail,
            )?),
        })
    }

    /// Returns the captured shared frames, ordered outermost to innermost.
    pub fn frames(&self) -> EvalEnvFrames<'_> {
        self.storage.frames()
    }

    /// Returns the inherited flat captured-value base, when present.
    pub(crate) const fn flat_base(&self) -> Option<&EvalFlatCapture> {
        self.storage.flat_base()
    }

    /// Returns the conceptual frame count seen by lowered lexical coordinates.
    pub fn frame_count(&self) -> usize {
        self.storage
            .flat_base()
            .map_or(0, EvalFlatCapture::frame_count)
            .saturating_add(self.storage.len())
    }

    /// Returns whether the environment captures no lexical values or frames.
    pub fn is_empty(&self) -> bool {
        self.storage.len() == 0
            && self
                .storage
                .flat_base()
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
    ///
    /// For an [`EvalEnvFramesSource::Chain`] view this walks parent links from
    /// the innermost head, so it is `O(len - index)` in the distance from the
    /// innermost frame. Prefer [`EvalEnvFrames::iter`] or
    /// [`EvalEnvFrames::clone_into`] when a full traversal is needed — both are
    /// single-pass `O(len)` rather than the `O(len^2)` incurred by repeated
    /// `get` calls across every index.
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
    ///
    /// This is `O(1)` for both storage sources: the chain head is already the
    /// innermost frame, so no parent links are walked.
    pub fn last(self) -> Option<&'a Arc<EvalFrame>> {
        self.len.checked_sub(1).and_then(|index| self.get(index))
    }

    /// Iterates from the outermost frame to the innermost frame.
    ///
    /// The traversal is single-pass `O(len)`. A chain-backed view cannot yield
    /// outermost-first lazily — parent links run innermost-first — so it walks
    /// the chain once into a temporary buffer and drains it in reverse. An
    /// array-backed view borrows its slice directly with no allocation.
    ///
    /// The chain walk is bounded to exactly `len` frames from the innermost
    /// head. The head's chain may extend past the captured window to
    /// out-of-view ancestors; those are never yielded, matching the windowed
    /// semantics of [`EvalEnvFrames::get`].
    pub fn iter(self) -> EvalEnvFramesIter<'a> {
        match self.source {
            EvalEnvFramesSource::Array(frames) => EvalEnvFramesIter {
                inner: EvalEnvFramesIterInner::Array(frames.iter()),
            },
            EvalEnvFramesSource::Chain(head) => {
                let mut collected: Vec<&'a Arc<EvalFrame>> = Vec::with_capacity(self.len);
                let mut node = head;
                for _ in 0..self.len {
                    let Some(frame) = node else { break };
                    collected.push(frame);
                    node = frame.parent();
                }
                collected.reverse();
                EvalEnvFramesIter {
                    inner: EvalEnvFramesIterInner::Chain(collected.into_iter()),
                }
            }
        }
    }

    /// Clones every frame outermost-first, appending onto `out` in a single
    /// `O(len)` pass.
    ///
    /// `out` must already reserve capacity for `self.len()` additional frames;
    /// this method performs no allocation of its own, so the caller keeps the
    /// fallible [`Vec::try_reserve_exact`] reservation that drives the
    /// capture-allocation error path. A chain-backed view is walked once from
    /// the innermost head — pushing innermost-first, bounded to exactly `len`
    /// frames so out-of-view ancestors past the captured window are excluded —
    /// then the freshly appended suffix is reversed in place so the final order
    /// is outermost-first, matching [`EvalEnvFrames::iter`]. An array-backed
    /// view is copied directly.
    pub fn clone_into(self, out: &mut Vec<Arc<EvalFrame>>) {
        match self.source {
            EvalEnvFramesSource::Array(frames) => out.extend_from_slice(frames),
            EvalEnvFramesSource::Chain(head) => {
                let start = out.len();
                let mut node = head;
                for _ in 0..self.len {
                    let Some(frame) = node else { break };
                    out.push(Arc::clone(frame));
                    node = frame.parent();
                }
                out[start..].reverse();
            }
        }
    }
}

/// Outermost-to-innermost iterator over an [`EvalEnvFrames`] view.
///
/// Yielded by [`EvalEnvFrames::iter`]. Construction is single-pass `O(len)`:
/// an array-backed view borrows its slice, while a chain-backed view walks its
/// parent links once into a temporary buffer that is then drained in reverse.
#[derive(Debug)]
pub struct EvalEnvFramesIter<'a> {
    inner: EvalEnvFramesIterInner<'a>,
}

#[derive(Debug)]
enum EvalEnvFramesIterInner<'a> {
    Array(std::slice::Iter<'a, Arc<EvalFrame>>),
    Chain(std::vec::IntoIter<&'a Arc<EvalFrame>>),
}

impl<'a> Iterator for EvalEnvFramesIter<'a> {
    type Item = &'a Arc<EvalFrame>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            EvalEnvFramesIterInner::Array(frames) => frames.next(),
            EvalEnvFramesIterInner::Chain(frames) => frames.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.inner {
            EvalEnvFramesIterInner::Array(frames) => frames.size_hint(),
            EvalEnvFramesIterInner::Chain(frames) => frames.size_hint(),
        }
    }
}

impl ExactSizeIterator for EvalEnvFramesIter<'_> {}

impl Index<usize> for EvalEnvFrames<'_> {
    type Output = Arc<EvalFrame>;

    fn index(&self, index: usize) -> &Self::Output {
        match self.get(index) {
            Some(frame) => frame,
            None => panic!("captured environment frame index {index} is out of bounds"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds `depth` production frames linked innermost-to-outermost via
    /// parent pointers, returned outermost-first (the capture-slice order).
    fn linked_chain(depth: usize) -> Vec<Arc<EvalFrame>> {
        let mut frames: Vec<Arc<EvalFrame>> = Vec::with_capacity(depth);
        let mut parent: Option<Arc<EvalFrame>> = None;
        for _ in 0..depth {
            let frame = EvalFrame::new_linked(1, parent.clone()).expect("frame allocation");
            parent = Some(Arc::clone(&frame));
            frames.push(frame);
        }
        frames
    }

    /// A deep chain-backed view must iterate identically, element-for-element,
    /// to the equivalent array-backed view over the same outermost-first slice.
    #[test]
    fn deep_chain_iter_matches_array_view_order() {
        let frames = linked_chain(64);
        assert!(frames_are_linked(&frames));

        let chain = EvalEnvStorage::capture_linked(&frames).expect("linked capture succeeds");
        let chain_view = chain.frames();
        let array_view = EvalEnvFrames::array(&frames);

        assert!(matches!(chain_view.source, EvalEnvFramesSource::Chain(_)));
        assert_eq!(chain_view.len(), array_view.len());

        let chain_iter: Vec<&Arc<EvalFrame>> = chain_view.iter().collect();
        let array_iter: Vec<&Arc<EvalFrame>> = array_view.iter().collect();
        assert_eq!(chain_iter.len(), frames.len());
        for (from_chain, expected) in chain_iter.iter().zip(frames.iter()) {
            assert!(Arc::ptr_eq(from_chain, expected));
        }
        for (from_chain, from_array) in chain_iter.iter().zip(array_iter.iter()) {
            assert!(Arc::ptr_eq(from_chain, from_array));
        }
    }

    /// `clone_into` (the single-pass helper behind `clone_env_frames`) must
    /// clone a deep chain outermost-first, matching both the source slice and
    /// the array-backed clone element-for-element by `Arc` identity.
    #[test]
    fn deep_chain_clone_into_matches_array_view_order() {
        let frames = linked_chain(64);

        let chain = EvalEnvStorage::capture_linked(&frames).expect("linked capture succeeds");
        let chain_view = chain.frames();
        let array_view = EvalEnvFrames::array(&frames);

        let mut from_chain = Vec::new();
        from_chain
            .try_reserve_exact(chain_view.len())
            .expect("reserve chain clone");
        chain_view.clone_into(&mut from_chain);

        let mut from_array = Vec::new();
        from_array
            .try_reserve_exact(array_view.len())
            .expect("reserve array clone");
        array_view.clone_into(&mut from_array);

        assert_eq!(from_chain.len(), frames.len());
        assert_eq!(from_array.len(), frames.len());
        for (cloned, expected) in from_chain.iter().zip(frames.iter()) {
            assert!(Arc::ptr_eq(cloned, expected));
        }
        for (cloned, expected) in from_array.iter().zip(frames.iter()) {
            assert!(Arc::ptr_eq(cloned, expected));
        }
    }

    /// `get` and `Index` on a chain view resolve every position to the same
    /// frame the array view resolves, across the full depth.
    #[test]
    fn deep_chain_indexed_access_matches_array_view() {
        let frames = linked_chain(64);
        let chain = EvalEnvStorage::capture_linked(&frames).expect("linked capture succeeds");
        let chain_view = chain.frames();
        let array_view = EvalEnvFrames::array(&frames);

        for index in 0..frames.len() {
            let chained = chain_view.get(index).expect("chain frame present");
            let arrayed = array_view.get(index).expect("array frame present");
            assert!(Arc::ptr_eq(chained, arrayed));
            assert!(Arc::ptr_eq(&chain_view[index], &frames[index]));
        }
        assert!(chain_view.get(frames.len()).is_none());
        assert!(Arc::ptr_eq(
            chain_view.last().expect("innermost present"),
            frames.last().expect("innermost source"),
        ));
    }

    /// A chain head may extend past the captured window to out-of-view
    /// ancestors; `iter`, `clone_into`, and `get` must all honor `len` and
    /// never surface those ancestors.
    #[test]
    fn chain_window_excludes_out_of_view_ancestors() {
        // Build a depth-4 chain but capture only the innermost two frames, so
        // the head's parent links reach two ancestors outside the window.
        let full = linked_chain(4);
        let head = full.last().expect("innermost frame");
        let chain = EvalEnvStorage::Chain {
            head: Arc::clone(head),
            frames: 2,
        };
        let view = chain.frames();
        assert_eq!(view.len(), 2);

        let window: Vec<&Arc<EvalFrame>> = view.iter().collect();
        assert_eq!(window.len(), 2, "iter yields only the captured window");
        // Outermost-first: the window is [full[2], full[3]].
        assert!(Arc::ptr_eq(window[0], &full[2]));
        assert!(Arc::ptr_eq(window[1], &full[3]));

        let mut cloned = Vec::new();
        cloned.try_reserve_exact(view.len()).expect("reserve");
        view.clone_into(&mut cloned);
        assert_eq!(
            cloned.len(),
            2,
            "clone_into yields only the captured window"
        );
        assert!(Arc::ptr_eq(&cloned[0], &full[2]));
        assert!(Arc::ptr_eq(&cloned[1], &full[3]));

        // `get` is likewise windowed: index 0 is the outermost in-view frame,
        // and out-of-view ancestors are unreachable.
        assert!(Arc::ptr_eq(view.get(0).expect("in view"), &full[2]));
        assert!(Arc::ptr_eq(view.get(1).expect("in view"), &full[3]));
        assert!(view.get(2).is_none());
    }
}
