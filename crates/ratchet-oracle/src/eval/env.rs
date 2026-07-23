//! Lexical and dynamic environment captures for the tree-walk evaluator.
//!
//! The tree-walk oracle stores active lexical frames as shared slot arrays so
//! thunks can capture the frame graph at allocation time. Slots are filled after
//! the frame is pushed, which supports Nix's self-visible `let` bindings and
//! lets recursive thunks blackhole through the ordinary thunk state machine.
//! Dynamic `with` scopes and scoped-import globals are captured alongside
//! lexical frames so escaping thunks and closures preserve the same runtime
//! lookup chain.
//!
//! # Sync-safety and the frame publication protocol
//!
//! Frames are shared through [`Arc`] and each slot is stored as an
//! [`AtomicValueCell`] (a tag word plus a payload word, both atomic), so
//! `EvalFrame` is [`Send`] and [`Sync`] and a shared demand graph can hand
//! frames to parallel forcing workers without data-race UB. Slot reads and
//! writes may interleave freely on the constructing thread: `let`/`rec`
//! binding assembly writes slots incrementally, reads slots back while
//! assembling attrset entries, and `__overrides` rewrites already-written
//! slots.
//!
//! Cross-thread visibility relies on the graph publication discipline rather
//! than per-slot locking: a frame's slots are mutated only by the thread that
//! constructs the enclosing binding form, and every hand-off of a capturing
//! value to another worker must pass through a synchronizing publication (a
//! parallel thunk cell publish, a scheduler queue, or another release/acquire
//! edge). Under that discipline a remote reader always observes a fully
//! written tag/payload pair; the per-slot release-on-tag / acquire-on-tag
//! ordering then guarantees the payload matches the tag it reads.

use std::ops::Deref;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use thiserror::Error;

use super::module::{EvalModuleId, EvalNodeRef};
use crate::compile::IrId;
use crate::value::{HeapObject, Value, ValueTag};

mod apply_probe;
mod capture;
mod depth_probe;
mod frame_probe;

#[cfg(test)]
pub(crate) use apply_probe::env_apply_histogram;
pub(crate) use apply_probe::{emit_env_apply_histogram_report, note_env_install};
pub use capture::{EvalEnv, EvalEnvFrames};
pub(crate) use capture::{EvalFlatCapture, EvalFlatCaptureBuffer};
pub(crate) use depth_probe::{
    emit_depth_report, enabled as depth_probe_enabled, note_capture_depth, note_install_depth,
};
pub(crate) use frame_probe::emit_frame_probe_report;

/// Process-wide environment capture/allocation counters (RFC-0007 doc 30 FV-0).
///
/// The flat-value campaign's §11.1 reproducibility fix: the capture-copy and
/// small-environment-allocation figures previously quoted only from session
/// profiles become stock-build counters here. The counters are process-wide
/// relaxed atomics because [`EvalEnv::capture`] and [`EvalFrame::new`] have no
/// evaluator handle to thread a per-eval counter through; each `TreeWalk`
/// snapshots them at construction and reports the delta at stats time, so a
/// serial evaluation sees exactly its own capture mass (concurrent evaluators
/// in one process fold into whichever snapshot window they overlap).
pub(crate) mod capture_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    static ENV_CAPTURES: AtomicU64 = AtomicU64::new(0);
    static ENV_CAPTURE_FRAME_HANDLES: AtomicU64 = AtomicU64::new(0);
    static FLAT_ENV_CAPTURES: AtomicU64 = AtomicU64::new(0);
    static FLAT_ENV_CAPTURE_VALUES: AtomicU64 = AtomicU64::new(0);
    static WITH_ENV_CAPTURES: AtomicU64 = AtomicU64::new(0);
    static WITH_ENV_CAPTURE_SCOPES: AtomicU64 = AtomicU64::new(0);
    static SCOPED_GLOBAL_ENV_CAPTURES: AtomicU64 = AtomicU64::new(0);
    static SCOPED_GLOBAL_ENV_CAPTURE_SCOPES: AtomicU64 = AtomicU64::new(0);
    static ENV_FRAME_ALLOCS: AtomicU64 = AtomicU64::new(0);
    static ENV_FRAME_SLOT_BYTES: AtomicU64 = AtomicU64::new(0);
    static ENV_FRAMES_RECYCLABLE: AtomicU64 = AtomicU64::new(0);

    /// A point-in-time reading of the process-wide capture counters.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct EnvCaptureStats {
        /// Lexical frame-array copies performed by [`super::EvalEnv::capture`].
        pub(crate) env_captures: u64,
        /// Frame handles copied across all lexical captures (8 bytes each).
        pub(crate) env_capture_frame_handles: u64,
        /// Flat capture-plan environments materialized.
        pub(crate) flat_env_captures: u64,
        /// Values copied across all flat capture-plan environments.
        pub(crate) flat_env_capture_values: u64,
        /// `with`-scope stack copies performed by [`super::EvalWithEnv::capture`].
        pub(crate) with_env_captures: u64,
        /// Scope entries copied across all `with`-stack captures.
        pub(crate) with_env_capture_scopes: u64,
        /// Scoped-import global stack copies.
        pub(crate) scoped_global_env_captures: u64,
        /// Scope values copied across all scoped-global captures.
        pub(crate) scoped_global_env_capture_scopes: u64,
        /// Lexical frames allocated by [`super::EvalFrame::new`].
        pub(crate) env_frame_allocs: u64,
        /// Slot-storage bytes allocated across all frame allocations.
        pub(crate) env_frame_slot_bytes: u64,
        /// Frames popped from the active stack with no surviving capture
        /// (`Arc` strong count 1 at pop) — the population a frame pool could
        /// recycle without semantic risk.
        pub(crate) env_frames_recyclable: u64,
    }

    impl EnvCaptureStats {
        /// Returns the counter movement since `baseline` (saturating).
        pub(crate) fn delta_since(self, baseline: Self) -> Self {
            Self {
                env_captures: self.env_captures.saturating_sub(baseline.env_captures),
                env_capture_frame_handles: self
                    .env_capture_frame_handles
                    .saturating_sub(baseline.env_capture_frame_handles),
                flat_env_captures: self
                    .flat_env_captures
                    .saturating_sub(baseline.flat_env_captures),
                flat_env_capture_values: self
                    .flat_env_capture_values
                    .saturating_sub(baseline.flat_env_capture_values),
                with_env_captures: self
                    .with_env_captures
                    .saturating_sub(baseline.with_env_captures),
                with_env_capture_scopes: self
                    .with_env_capture_scopes
                    .saturating_sub(baseline.with_env_capture_scopes),
                scoped_global_env_captures: self
                    .scoped_global_env_captures
                    .saturating_sub(baseline.scoped_global_env_captures),
                scoped_global_env_capture_scopes: self
                    .scoped_global_env_capture_scopes
                    .saturating_sub(baseline.scoped_global_env_capture_scopes),
                env_frame_allocs: self
                    .env_frame_allocs
                    .saturating_sub(baseline.env_frame_allocs),
                env_frame_slot_bytes: self
                    .env_frame_slot_bytes
                    .saturating_sub(baseline.env_frame_slot_bytes),
                env_frames_recyclable: self
                    .env_frames_recyclable
                    .saturating_sub(baseline.env_frames_recyclable),
            }
        }
    }

    /// Reads all counters with relaxed ordering.
    pub(crate) fn snapshot() -> EnvCaptureStats {
        EnvCaptureStats {
            env_captures: ENV_CAPTURES.load(Ordering::Relaxed),
            env_capture_frame_handles: ENV_CAPTURE_FRAME_HANDLES.load(Ordering::Relaxed),
            flat_env_captures: FLAT_ENV_CAPTURES.load(Ordering::Relaxed),
            flat_env_capture_values: FLAT_ENV_CAPTURE_VALUES.load(Ordering::Relaxed),
            with_env_captures: WITH_ENV_CAPTURES.load(Ordering::Relaxed),
            with_env_capture_scopes: WITH_ENV_CAPTURE_SCOPES.load(Ordering::Relaxed),
            scoped_global_env_captures: SCOPED_GLOBAL_ENV_CAPTURES.load(Ordering::Relaxed),
            scoped_global_env_capture_scopes: SCOPED_GLOBAL_ENV_CAPTURE_SCOPES
                .load(Ordering::Relaxed),
            env_frame_allocs: ENV_FRAME_ALLOCS.load(Ordering::Relaxed),
            env_frame_slot_bytes: ENV_FRAME_SLOT_BYTES.load(Ordering::Relaxed),
            env_frames_recyclable: ENV_FRAMES_RECYCLABLE.load(Ordering::Relaxed),
        }
    }

    /// Records one lexical frame-array copy of `frames` handles.
    pub(super) fn note_env_capture(frames: usize) {
        ENV_CAPTURES.fetch_add(1, Ordering::Relaxed);
        ENV_CAPTURE_FRAME_HANDLES.fetch_add(frames as u64, Ordering::Relaxed);
    }

    /// Records one flat capture and its copied-value count.
    pub(super) fn note_flat_env_capture(values: usize) {
        FLAT_ENV_CAPTURES.fetch_add(1, Ordering::Relaxed);
        FLAT_ENV_CAPTURE_VALUES.fetch_add(values as u64, Ordering::Relaxed);
    }

    /// Records one `with`-scope stack copy of `scopes` entries.
    pub(crate) fn note_with_env_capture(scopes: usize) {
        WITH_ENV_CAPTURES.fetch_add(1, Ordering::Relaxed);
        WITH_ENV_CAPTURE_SCOPES.fetch_add(scopes as u64, Ordering::Relaxed);
    }

    /// Records one scoped-global stack copy of `scopes` values.
    pub(crate) fn note_scoped_global_env_capture(scopes: usize) {
        SCOPED_GLOBAL_ENV_CAPTURES.fetch_add(1, Ordering::Relaxed);
        SCOPED_GLOBAL_ENV_CAPTURE_SCOPES.fetch_add(scopes as u64, Ordering::Relaxed);
    }

    /// Records one lexical frame allocation of `slot_bytes` slot storage.
    pub(super) fn note_env_frame_alloc(slot_bytes: usize) {
        ENV_FRAME_ALLOCS.fetch_add(1, Ordering::Relaxed);
        ENV_FRAME_SLOT_BYTES.fetch_add(slot_bytes as u64, Ordering::Relaxed);
    }

    /// Records one frame popped with no surviving capture (pool-recyclable).
    pub(crate) fn note_env_frame_recyclable() {
        ENV_FRAMES_RECYCLABLE.fetch_add(1, Ordering::Relaxed);
    }
}

/// One immutable node in a persistent environment stack.
#[derive(Debug)]
struct PersistentEnvNode<T> {
    value: T,
    parent: Option<Arc<Self>>,
    len: usize,
    values: OnceLock<Box<[T]>>,
}

/// A persistent stack whose captures clone only the innermost node pointer.
#[derive(Clone, Debug)]
struct PersistentEnvStack<T> {
    head: Option<Arc<PersistentEnvNode<T>>>,
}

impl<T> Default for PersistentEnvStack<T> {
    fn default() -> Self {
        Self { head: None }
    }
}

impl<T> PersistentEnvStack<T> {
    /// Returns whether two snapshots share the same persistent head.
    fn raw_eq(&self, other: &Self) -> bool {
        match (&self.head, &other.head) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            (None, None) => true,
            _ => false,
        }
    }
}

impl<T: Copy> PersistentEnvStack<T> {
    fn from_slice(values: &[T]) -> Self {
        let mut stack = Self::default();
        for value in values.iter().copied() {
            stack.push(value);
        }
        stack
    }

    fn push(&mut self, value: T) {
        let parent = self.head.take();
        let len = parent.as_ref().map_or(1, |parent| parent.len + 1);
        self.head = Some(Arc::new(PersistentEnvNode {
            value,
            parent,
            len,
            values: OnceLock::new(),
        }));
    }

    fn pop(&mut self) -> Option<T> {
        let head = self.head.take()?;
        let value = head.value;
        self.head = head.parent.clone();
        Some(value)
    }

    fn as_slice(&self) -> &[T] {
        let Some(head) = self.head.as_ref() else {
            return &[];
        };
        head.values.get_or_init(|| {
            let mut values = Vec::with_capacity(head.len);
            let mut cursor = Some(head);
            while let Some(node) = cursor {
                values.push(node.value);
                cursor = node.parent.as_ref();
            }
            values.reverse();
            values.into_boxed_slice()
        })
    }

    fn replace(&mut self, index: usize, value: T) -> bool {
        let mut values = self.as_slice().to_vec();
        let Some(slot) = values.get_mut(index) else {
            return false;
        };
        *slot = value;
        *self = Self::from_slice(&values);
        true
    }
}

/// A captured dynamic `with` scope stack.
#[derive(Clone, Debug, Default)]
pub struct EvalWithEnv {
    scopes: PersistentEnvStack<EvalWithScope>,
}

impl EvalWithEnv {
    /// Returns the shared empty dynamic-scope capture.
    pub(crate) const fn empty_ref() -> &'static Self {
        &EMPTY_WITH_ENV
    }

    /// Returns whether two captures share the same persistent stack.
    pub(crate) fn raw_eq(&self, other: &Self) -> bool {
        self.scopes.raw_eq(&other.scopes)
    }

    /// Captures the active `with` scope stack.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::WithCaptureAllocationFailed`] if the snapshot
    /// scope list cannot be reserved.
    pub fn capture(scopes: &[EvalWithScope]) -> Result<Self, EvalEnvError> {
        capture_stats::note_with_env_capture(scopes.len());
        Ok(Self {
            scopes: PersistentEnvStack::from_slice(scopes),
        })
    }

    /// Captures another persistent stack by cloning its head pointer.
    ///
    /// The capture counter is recorded by the caller under the stats flag
    /// (RFC-0007 §P1 ledger lever 4), so the default hot path takes no atomic.
    pub(crate) fn capture_persistent(scopes: &Self) -> Self {
        scopes.clone()
    }

    /// Returns the captured `with` scopes, ordered outermost to innermost.
    pub fn scopes(&self) -> &[EvalWithScope] {
        self.scopes.as_slice()
    }

    /// Pushes one active scope while preserving the prior stack as its parent.
    pub(crate) fn push(&mut self, scope: EvalWithScope) {
        self.scopes.push(scope);
    }

    /// Removes and returns the innermost active scope.
    pub(crate) fn pop(&mut self) -> Option<EvalWithScope> {
        self.scopes.pop()
    }

    /// Rebuilds the stack with one relocated scope value.
    pub(crate) fn replace_value(&mut self, index: usize, value: Value) -> bool {
        let Some(scope) = self.scopes().get(index).copied() else {
            return false;
        };
        self.scopes.replace(
            index,
            EvalWithScope::new(scope.module(), scope.scope(), value),
        )
    }
}

impl Deref for EvalWithEnv {
    type Target = [EvalWithScope];

    fn deref(&self) -> &Self::Target {
        self.scopes()
    }
}

impl From<Vec<EvalWithScope>> for EvalWithEnv {
    fn from(scopes: Vec<EvalWithScope>) -> Self {
        Self {
            scopes: PersistentEnvStack::from_slice(&scopes),
        }
    }
}

/// A captured scoped-import global scope stack.
#[derive(Clone, Debug, Default)]
pub struct EvalScopedGlobalEnv {
    scopes: PersistentEnvStack<Value>,
}

impl EvalScopedGlobalEnv {
    /// Returns the shared empty scoped-global capture.
    pub(crate) const fn empty_ref() -> &'static Self {
        &EMPTY_SCOPED_GLOBAL_ENV
    }

    /// Returns whether two captures share the same persistent stack.
    pub(crate) fn raw_eq(&self, other: &Self) -> bool {
        self.scopes.raw_eq(&other.scopes)
    }

    /// Captures the active scoped-import global scope stack.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::ScopedGlobalCaptureAllocationFailed`] if the
    /// snapshot scope list cannot be reserved.
    pub fn capture(scopes: &[Value]) -> Result<Self, EvalEnvError> {
        capture_stats::note_scoped_global_env_capture(scopes.len());
        Ok(Self {
            scopes: PersistentEnvStack::from_slice(scopes),
        })
    }

    /// Captures another persistent stack by cloning its head pointer.
    ///
    /// The capture counter is recorded by the caller under the stats flag
    /// (RFC-0007 §P1 ledger lever 4), so the default hot path takes no atomic.
    pub(crate) fn capture_persistent(scopes: &Self) -> Self {
        scopes.clone()
    }

    /// Returns the captured scoped-import globals, ordered outermost to innermost.
    pub fn scopes(&self) -> &[Value] {
        self.scopes.as_slice()
    }

    /// Pushes one active global while preserving the prior stack as its parent.
    pub(crate) fn push(&mut self, value: Value) {
        self.scopes.push(value);
    }

    /// Rebuilds the stack with one relocated global value.
    pub(crate) fn replace_value(&mut self, index: usize, value: Value) -> bool {
        self.scopes.replace(index, value)
    }
}

static EMPTY_WITH_ENV: EvalWithEnv = EvalWithEnv {
    scopes: PersistentEnvStack { head: None },
};

static EMPTY_SCOPED_GLOBAL_ENV: EvalScopedGlobalEnv = EvalScopedGlobalEnv {
    scopes: PersistentEnvStack { head: None },
};

impl Deref for EvalScopedGlobalEnv {
    type Target = [Value];

    fn deref(&self) -> &Self::Target {
        self.scopes()
    }
}

impl From<Vec<Value>> for EvalScopedGlobalEnv {
    fn from(scopes: Vec<Value>) -> Self {
        Self {
            scopes: PersistentEnvStack::from_slice(&scopes),
        }
    }
}

/// One active dynamic `with` scope.
#[derive(Clone, Copy, Debug)]
pub struct EvalWithScope {
    scope: EvalNodeRef,
    value: Value,
}

impl EvalWithScope {
    /// Creates an active `with` scope entry.
    pub const fn new(module: EvalModuleId, scope: IrId, value: Value) -> Self {
        Self {
            scope: EvalNodeRef::new(module, scope),
            value,
        }
    }

    /// Returns the module-qualified lowered scrutinee node for this scope.
    pub const fn scope_ref(&self) -> EvalNodeRef {
        self.scope
    }

    /// Returns the module that owns this scope's lowered scrutinee node.
    pub const fn module(&self) -> EvalModuleId {
        self.scope.module()
    }

    /// Returns the lowered scrutinee node for this scope.
    pub const fn scope(&self) -> IrId {
        self.scope.id()
    }

    /// Returns the lazy attrset value for this scope.
    pub const fn value(&self) -> Value {
        self.value
    }
}

/// The tag word stored by an empty [`AtomicValueCell`].
///
/// No [`ValueTag`] encodes to this word, so an empty cell can never be
/// confused with a stored value.
const ATOMIC_VALUE_CELL_EMPTY_TAG: u64 = u64::MAX;

const TAG_INT: u64 = ValueTag::Int as u64;
const TAG_FLOAT: u64 = ValueTag::Float as u64;
const TAG_BOOL: u64 = ValueTag::Bool as u64;
const TAG_NULL: u64 = ValueTag::Null as u64;
const TAG_STRING: u64 = ValueTag::String as u64;
const TAG_PATH: u64 = ValueTag::Path as u64;
const TAG_LIST: u64 = ValueTag::List as u64;
const TAG_ATTRS: u64 = ValueTag::Attrs as u64;
const TAG_LAMBDA: u64 = ValueTag::Lambda as u64;
const TAG_PRIMOP: u64 = ValueTag::Primop as u64;
const TAG_EXTERNAL: u64 = ValueTag::External as u64;
const TAG_THUNK: u64 = ValueTag::Thunk as u64;

/// A [`Value`]-sized cell published through a pair of atomic words.
///
/// The cell replaces `Cell<Value>`-style interior mutability in graph-shared
/// structures so those structures are [`Sync`] without locks. A store writes
/// the payload word first and then the tag word with release ordering; a load
/// reads the tag word with acquire ordering and then the payload word. When a
/// reader synchronizes with the writer (same thread, or a release/acquire
/// publication edge established by the enclosing structure), the pair it
/// decodes is exactly the pair that was stored.
///
/// The cell is *not* a lock-free register for arbitrary concurrent writers:
/// racing writers or a reader racing an in-progress rewrite can observe a
/// mixed tag/payload pair. Owning structures must guarantee that all writes
/// happen-before any cross-thread read (see the module docs).
#[cfg(not(feature = "candidate_c_value"))]
#[derive(Debug)]
pub(crate) struct AtomicValueCell {
    tag: AtomicU64,
    payload: AtomicU64,
}

#[cfg(not(feature = "candidate_c_value"))]
impl AtomicValueCell {
    /// Creates an empty cell.
    pub(crate) const fn empty() -> Self {
        Self {
            tag: AtomicU64::new(ATOMIC_VALUE_CELL_EMPTY_TAG),
            payload: AtomicU64::new(0),
        }
    }

    /// Creates a cell holding `value`.
    pub(crate) fn filled(value: Value) -> Self {
        Self {
            tag: AtomicU64::new(value.tag() as u64),
            payload: AtomicU64::new(value.relocation_sensitive_identity_bits()),
        }
    }

    /// Stores `value`, publishing the payload before the tag.
    pub(crate) fn store(&self, value: Value) {
        self.payload.store(
            value.relocation_sensitive_identity_bits(),
            Ordering::Relaxed,
        );
        self.tag.store(value.tag() as u64, Ordering::Release);
    }

    /// Clears the cell back to empty.
    pub(crate) fn clear(&self) {
        self.tag
            .store(ATOMIC_VALUE_CELL_EMPTY_TAG, Ordering::Release);
    }

    /// Loads the stored value, or `None` if the cell is empty.
    ///
    /// # Errors
    ///
    /// Returns [`AtomicValueCellError::InvalidEncoding`] if the stored words do
    /// not decode into a valid runtime value. This is unreachable through
    /// [`AtomicValueCell::store`], which only accepts well-formed values.
    pub(crate) fn load(&self) -> Result<Option<Value>, AtomicValueCellError> {
        let tag = self.tag.load(Ordering::Acquire);
        if tag == ATOMIC_VALUE_CELL_EMPTY_TAG {
            return Ok(None);
        }
        let payload = self.payload.load(Ordering::Relaxed);
        decode_value(tag, payload).map(Some)
    }
}

/// A [`Value`]-sized cell published through a single atomic word.
///
/// On the Candidate-C carrier a [`Value`] is one 8-byte word, so the cell
/// collapses to a single [`AtomicU64`]: a store/load is a lone atomic and the
/// two-word tearing protocol disappears. [`ATOMIC_VALUE_CELL_EMPTY_TAG`]
/// (`u64::MAX`, whose high-byte kind `0xff` is not a valid Candidate-C kind) is
/// reused as the empty sentinel word.
#[cfg(feature = "candidate_c_value")]
#[derive(Debug)]
pub(crate) struct AtomicValueCell {
    word: AtomicU64,
}

#[cfg(feature = "candidate_c_value")]
impl AtomicValueCell {
    /// Creates an empty cell.
    pub(crate) const fn empty() -> Self {
        Self {
            word: AtomicU64::new(ATOMIC_VALUE_CELL_EMPTY_TAG),
        }
    }

    /// Creates a cell holding `value`.
    pub(crate) fn filled(value: Value) -> Self {
        Self {
            word: AtomicU64::new(value.word().raw()),
        }
    }

    /// Stores `value` with release ordering.
    pub(crate) fn store(&self, value: Value) {
        self.word.store(value.word().raw(), Ordering::Release);
    }

    /// Clears the cell back to empty.
    pub(crate) fn clear(&self) {
        self.word
            .store(ATOMIC_VALUE_CELL_EMPTY_TAG, Ordering::Release);
    }

    /// Loads the stored value, or `None` if the cell is empty.
    ///
    /// # Errors
    ///
    /// Returns [`AtomicValueCellError::InvalidEncoding`] if the stored word is
    /// not a valid Candidate-C value word. This is unreachable through
    /// [`AtomicValueCell::store`], which only accepts well-formed values.
    #[allow(unsafe_code)]
    pub(crate) fn load(&self) -> Result<Option<Value>, AtomicValueCellError> {
        let word = self.word.load(Ordering::Acquire);
        if word == ATOMIC_VALUE_CELL_EMPTY_TAG {
            return Ok(None);
        }
        // SAFETY: this private atomic is initialized and subsequently written
        // only by `filled`/`store`, both of which copy an already-validated
        // `Value` word intact. The single AtomicU64 load cannot tear, and the
        // only other encoding admitted by `clear` was handled above.
        Ok(Some(unsafe { Value::from_validated_raw_unchecked(word) }))
    }
}

/// Rebuilds a [`Value`] from its raw tag and payload words.
#[cfg(not(feature = "candidate_c_value"))]
fn decode_value(tag: u64, payload: u64) -> Result<Value, AtomicValueCellError> {
    match tag {
        TAG_INT => Ok(Value::int(payload as i64)),
        TAG_FLOAT => Ok(Value::float(f64::from_bits(payload))),
        TAG_BOOL if payload <= 1 => Ok(Value::bool(payload != 0)),
        TAG_NULL if payload == 0 => Ok(Value::null()),
        TAG_STRING | TAG_PATH | TAG_LIST | TAG_ATTRS | TAG_LAMBDA | TAG_PRIMOP | TAG_EXTERNAL
        | TAG_THUNK => {
            let value_tag = match tag {
                TAG_STRING => ValueTag::String,
                TAG_PATH => ValueTag::Path,
                TAG_LIST => ValueTag::List,
                TAG_ATTRS => ValueTag::Attrs,
                TAG_LAMBDA => ValueTag::Lambda,
                TAG_PRIMOP => ValueTag::Primop,
                TAG_EXTERNAL => ValueTag::External,
                _ => ValueTag::Thunk,
            };
            let ptr = NonNull::new(payload as *mut HeapObject)
                .ok_or(AtomicValueCellError::InvalidEncoding { tag, payload })?;
            Value::heap(value_tag, ptr)
                .map_err(|_| AtomicValueCellError::InvalidEncoding { tag, payload })
        }
        _ => Err(AtomicValueCellError::InvalidEncoding { tag, payload }),
    }
}

/// An [`AtomicValueCell`] held words that do not decode into a runtime value.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum AtomicValueCellError {
    /// The stored tag/payload pair is not a valid value encoding.
    #[error("atomic value cell holds invalid encoding: tag {tag:#x}, payload {payload:#x}")]
    InvalidEncoding {
        /// The raw tag word.
        tag: u64,
        /// The raw payload word.
        payload: u64,
    },
}

/// The number of slots an [`EvalFrame`] stores inline before spilling to the
/// heap.
///
/// Capture statistics show lexical frames average roughly one slot, so the
/// fixed cost of a separate slot allocation dominates the payload. Storing up
/// to this many slots inline in the frame struct removes the second heap
/// allocation (the boxed slot slice) for that dominant class; only larger
/// frames pay for a heap spill. The inline array widens every `EvalFrame` by
/// one `[AtomicValueCell; INLINE_SLOT_CAPACITY]` even when heap-backed, which
/// trades a few struct bytes for eliminating an allocation on the common path.
const INLINE_SLOT_CAPACITY: usize = 2;

/// Backing storage for one frame's runtime slots.
///
/// Small frames (at most [`INLINE_SLOT_CAPACITY`] slots) keep their cells
/// inline in the frame struct; larger frames spill to a boxed slice. Both
/// variants expose their live cells through [`FrameSlots::as_slice`], so slot
/// access above this type is representation-agnostic.
#[derive(Debug)]
enum FrameSlots {
    /// Up to [`INLINE_SLOT_CAPACITY`] cells stored inline. `len` names how many
    /// leading cells are live; any trailing cells are inert null padding that
    /// [`FrameSlots::as_slice`] never exposes.
    Inline {
        /// The inline cell array; only the first `len` entries are live.
        cells: [AtomicValueCell; INLINE_SLOT_CAPACITY],
        /// The number of live leading cells (at most [`INLINE_SLOT_CAPACITY`]).
        len: u8,
    },
    /// Slot counts above [`INLINE_SLOT_CAPACITY`] spill to a boxed slice.
    Heap(Box<[AtomicValueCell]>),
}

impl FrameSlots {
    /// Borrows the frame's live slot cells as a slice.
    #[inline]
    fn as_slice(&self) -> &[AtomicValueCell] {
        match self {
            FrameSlots::Inline { cells, len } => &cells[..*len as usize],
            FrameSlots::Heap(slots) => slots,
        }
    }
}

/// One lexical frame's runtime slots.
///
/// Slots are initialized to `null` and rewritten through [`EvalFrame::set`]
/// while the constructing thread assembles the binding form. Reads may
/// interleave with writes on that thread; cross-thread readers rely on the
/// publication discipline described in the module docs.
#[derive(Debug)]
pub struct EvalFrame {
    slots: FrameSlots,
    /// The next outer shared frame in the persistent capture chain.
    parent: Option<Arc<EvalFrame>>,
    /// Emulates the historical `RefCell` shared-borrow guard for tests that
    /// exercise the borrow-conflict error path of GC root writebacks. The
    /// counter only exists in test builds; production code cannot observe a
    /// borrow conflict.
    #[cfg(test)]
    test_borrows: std::sync::atomic::AtomicUsize,
}

impl EvalFrame {
    /// Creates a frame with `slot_count` null-initialized slots.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::FrameAllocationFailed`] if the slot vector
    /// cannot be reserved.
    pub fn new(slot_count: usize) -> Result<Arc<Self>, EvalEnvError> {
        Self::new_linked(slot_count, None)
    }

    /// Creates a production frame linked to the active outer frame.
    pub(crate) fn new_linked(
        slot_count: usize,
        parent: Option<Arc<EvalFrame>>,
    ) -> Result<Arc<Self>, EvalEnvError> {
        // The gauge measures logical slot payload bytes regardless of inline
        // or heap placement: an inline frame still holds these bytes, just
        // within the frame struct rather than a separate allocation.
        capture_stats::note_env_frame_alloc(
            slot_count.saturating_mul(std::mem::size_of::<AtomicValueCell>()),
        );
        // FV-6 frame-arena ceiling probe (RFC-0007): time the allocation in
        // context only when `AOS_NIX_FRAME_PROBE=1`, so a normal eval pays
        // nothing.
        if frame_probe::should_time() {
            let start = std::time::Instant::now();
            let frame = Self::alloc(slot_count, parent);
            frame_probe::note_alloc(start.elapsed().as_nanos() as u64, slot_count);
            return frame;
        }
        Self::alloc(slot_count, parent)
    }

    /// Allocates a linked frame with `slot_count` null-initialized slots.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::FrameAllocationFailed`] if a heap-backed slot
    /// vector cannot be reserved.
    fn alloc(slot_count: usize, parent: Option<Arc<EvalFrame>>) -> Result<Arc<Self>, EvalEnvError> {
        let slots = if slot_count <= INLINE_SLOT_CAPACITY {
            // Small frames — the dominant class — store their cells inline; the
            // trailing cells past `slot_count` are inert null padding.
            let cells = std::array::from_fn(|_| AtomicValueCell::filled(Value::null()));
            FrameSlots::Inline {
                cells,
                len: slot_count as u8,
            }
        } else {
            let mut slots = Vec::new();
            slots
                .try_reserve_exact(slot_count)
                .map_err(|_| EvalEnvError::FrameAllocationFailed { slots: slot_count })?;
            for _ in 0..slot_count {
                slots.push(AtomicValueCell::filled(Value::null()));
            }
            FrameSlots::Heap(slots.into_boxed_slice())
        };
        Ok(Arc::new(Self {
            slots,
            parent,
            #[cfg(test)]
            test_borrows: std::sync::atomic::AtomicUsize::new(0),
        }))
    }

    /// Returns the next outer frame in the persistent capture chain.
    pub(crate) const fn parent(&self) -> Option<&Arc<EvalFrame>> {
        self.parent.as_ref()
    }

    /// Reads a slot value.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::SlotOutOfBounds`] if `slot` is outside this
    /// frame. Returns [`EvalEnvError::SlotEncodingInvalid`] if the slot's
    /// atomic words do not decode into a runtime value, which is unreachable
    /// through [`EvalFrame::set`].
    pub fn get(&self, slot: u32) -> Result<Value, EvalEnvError> {
        let Some(cell) = self.slots.as_slice().get(slot as usize) else {
            return Err(EvalEnvError::SlotOutOfBounds {
                slot,
                slots: self.slots.as_slice().len(),
            });
        };
        match cell.load() {
            Ok(Some(value)) => Ok(value),
            Ok(None) | Err(AtomicValueCellError::InvalidEncoding { .. }) => {
                Err(EvalEnvError::SlotEncodingInvalid { slot })
            }
        }
    }

    /// Writes a slot value.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::BorrowConflict`] if a test currently holds the
    /// frame's slots borrowed (test builds only). Returns
    /// [`EvalEnvError::SlotOutOfBounds`] if `slot` is outside this frame.
    pub fn set(&self, slot: u32, value: Value) -> Result<(), EvalEnvError> {
        self.check_test_borrow()?;
        let Some(cell) = self.slots.as_slice().get(slot as usize) else {
            return Err(EvalEnvError::SlotOutOfBounds {
                slot,
                slots: self.slots.as_slice().len(),
            });
        };
        cell.store(value);
        Ok(())
    }

    /// Validates that a slot can be written without changing its value.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::BorrowConflict`] if a test currently holds the
    /// frame's slots borrowed (test builds only). Returns
    /// [`EvalEnvError::SlotOutOfBounds`] if `slot` is outside this frame.
    pub(crate) fn validate_set(&self, slot: u32) -> Result<(), EvalEnvError> {
        self.check_test_borrow()?;
        if slot as usize >= self.slots.as_slice().len() {
            return Err(EvalEnvError::SlotOutOfBounds {
                slot,
                slots: self.slots.as_slice().len(),
            });
        }
        Ok(())
    }

    /// Returns a copied snapshot of every slot in this frame.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::SlotEncodingInvalid`] if a slot's atomic words
    /// do not decode into a runtime value, which is unreachable through
    /// [`EvalFrame::set`]. Returns
    /// [`EvalEnvError::FrameSnapshotAllocationFailed`] if the copied slot
    /// vector cannot reserve storage.
    pub fn slot_values(&self) -> Result<Vec<Value>, EvalEnvError> {
        let slots = self.slots.as_slice();
        let mut snapshot = Vec::new();
        snapshot
            .try_reserve_exact(slots.len())
            .map_err(|_| EvalEnvError::FrameSnapshotAllocationFailed { slots: slots.len() })?;
        for (slot, cell) in slots.iter().enumerate() {
            match cell.load() {
                Ok(Some(value)) => snapshot.push(value),
                Ok(None) | Err(AtomicValueCellError::InvalidEncoding { .. }) => {
                    return Err(EvalEnvError::SlotEncodingInvalid { slot: slot as u32 });
                }
            }
        }
        Ok(snapshot)
    }

    /// Rejects mutation while a test holds the frame's slots borrowed.
    #[cfg(test)]
    fn check_test_borrow(&self) -> Result<(), EvalEnvError> {
        if self.test_borrows.load(Ordering::Acquire) > 0 {
            return Err(EvalEnvError::BorrowConflict);
        }
        Ok(())
    }

    /// Production builds have no borrow guard; mutation is always admitted.
    #[cfg(not(test))]
    #[inline]
    const fn check_test_borrow(&self) -> Result<(), EvalEnvError> {
        Ok(())
    }

    /// Borrows frame slots for tests that need to hold a borrow open.
    ///
    /// The returned guard snapshots the slot values and, while alive, makes
    /// [`EvalFrame::set`] and [`EvalFrame::validate_set`] report
    /// [`EvalEnvError::BorrowConflict`], mirroring the historical `RefCell`
    /// shared borrow.
    #[cfg(test)]
    pub(crate) fn borrow_slots_for_test(
        &self,
    ) -> Result<EvalFrameSlotsTestBorrow<'_>, EvalEnvError> {
        let values = self.slot_values()?;
        self.test_borrows.fetch_add(1, Ordering::AcqRel);
        Ok(EvalFrameSlotsTestBorrow {
            frame: self,
            values,
        })
    }
}

/// A held test borrow of one frame's slots.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct EvalFrameSlotsTestBorrow<'a> {
    frame: &'a EvalFrame,
    values: Vec<Value>,
}

#[cfg(test)]
impl std::ops::Deref for EvalFrameSlotsTestBorrow<'_> {
    type Target = [Value];

    fn deref(&self) -> &[Value] {
        &self.values
    }
}

#[cfg(test)]
impl Drop for EvalFrameSlotsTestBorrow<'_> {
    fn drop(&mut self) {
        self.frame.test_borrows.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A lexical environment operation failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EvalEnvError {
    /// A frame's slot vector could not be allocated.
    #[error("failed to reserve {slots} environment slots")]
    FrameAllocationFailed {
        /// The requested number of frame slots.
        slots: usize,
    },
    /// A frame slot snapshot could not be allocated.
    #[error("failed to reserve {slots} frame snapshot slots")]
    FrameSnapshotAllocationFailed {
        /// The requested number of copied frame slots.
        slots: usize,
    },
    /// A captured frame list could not be allocated.
    #[error("failed to reserve {frames} captured environment frames")]
    CaptureAllocationFailed {
        /// The requested number of captured frames.
        frames: usize,
    },
    /// A captured `with` scope list could not be allocated.
    #[error("failed to reserve {scopes} captured with scopes")]
    WithCaptureAllocationFailed {
        /// The requested number of captured `with` scopes.
        scopes: usize,
    },
    /// A captured scoped-import global scope list could not be allocated.
    #[error("failed to reserve {scopes} captured scoped-import globals")]
    ScopedGlobalCaptureAllocationFailed {
        /// The requested number of captured scoped-import global scopes.
        scopes: usize,
    },
    /// A frame was already borrowed in an incompatible mode.
    #[error("environment frame borrow conflict")]
    BorrowConflict,
    /// A slot index was outside the frame.
    #[error("environment slot {slot} out of bounds for {slots} slots")]
    SlotOutOfBounds {
        /// The requested slot.
        slot: u32,
        /// The number of slots available in the frame.
        slots: usize,
    },
    /// A frame slot's atomic words did not decode into a runtime value.
    #[error("environment slot {slot} holds an invalid value encoding")]
    SlotEncodingInvalid {
        /// The slot whose stored words failed to decode.
        slot: u32,
    },
}

#[cfg(test)]
mod tests;
