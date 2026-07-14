//! Suspended/active evaluation environment wrappers and telemetry
//! (split from tree_walk.rs under the §2 file-size cap).
use std::collections::TryReserveError;

use super::*;

#[derive(Clone, Copy, Debug)]
pub(crate) struct AttrUpdateTelemetryState {
    pub(crate) override_chain_depth: usize,
    // Active update projection reads the left heap value metadata; this field is
    // still used by the test-only telemetry wrapper that synthesizes chains.
    #[allow(dead_code)]
    pub(crate) projected_repr: AttrSetReprKind,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct AttrUpdateMergeProjection {
    pub(crate) left_repr: AttrSetReprKind,
    pub(crate) override_chain_depth: usize,
    pub(crate) decision: AttrSetReprDecision,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(super) enum AttrUpdateTelemetryDispatchError {
    #[error("flat attrset operand normalization failed: {0}")]
    Flat(#[from] AttrError),
    #[error("HAMT operand normalization failed: {0}")]
    Hamt(#[from] HamtError),
    #[error("representation-dispatched update failed: {0}")]
    Repr(#[from] AttrSetReprValueError),
}

pub(crate) type AttrUpdateTelemetryNodeKey = (u32, u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ActivePrimopArgFrame {
    pub(crate) start: usize,
    pub(crate) len: usize,
}

#[derive(Debug)]
pub(crate) struct SuspendedTreeWalkEnv {
    pub(crate) env: ActiveEvalEnv,
    pub(crate) with_scopes: EvalWithEnv,
    pub(crate) scoped_globals: EvalScopedGlobalEnv,
}

impl SuspendedTreeWalkEnv {
    pub(crate) fn new(
        env: ActiveEvalEnv,
        with_scopes: EvalWithEnv,
        scoped_globals: EvalScopedGlobalEnv,
    ) -> Self {
        Self {
            env,
            with_scopes,
            scoped_globals,
        }
    }
}

/// The active lexical frame stack, split into a shared immutable base and a
/// mutable inner tail (RFC-0007 §P1 stage B).
///
/// `base` is the outer captured suffix installed when a closure body begins; it
/// is an `Arc<[_]>` so installing it (`clone_env_frames` + `swap_env_frames`)
/// shares every frame with a single refcount bump instead of copying the whole
/// stack. `tail` holds frames pushed while that body runs — the lambda argument
/// frame plus any `let`/`with` scopes — and is the only part mutated by
/// [`ActiveFrameStack::push`]/[`ActiveFrameStack::pop`]. The conceptual stack is
/// `base` followed by `tail`, ordered outermost-first (innermost last), so an
/// index of `0` is the outermost frame.
#[derive(Clone, Debug, Default)]
pub(crate) struct ActiveFrameStack {
    base: Arc<[Arc<EvalFrame>]>,
    tail: Vec<Arc<EvalFrame>>,
}

impl ActiveFrameStack {
    /// Creates an empty stack.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Creates a stack whose entire contents are a shared immutable base.
    pub(crate) fn from_base(base: Arc<[Arc<EvalFrame>]>) -> Self {
        Self {
            base,
            tail: Vec::new(),
        }
    }

    /// Returns the total number of frames across the base and tail.
    pub(crate) fn len(&self) -> usize {
        self.base.len() + self.tail.len()
    }

    /// Returns whether the stack holds no frames.
    pub(crate) fn is_empty(&self) -> bool {
        self.base.is_empty() && self.tail.is_empty()
    }

    /// Returns the innermost (most recently pushed) frame, if any.
    pub(crate) fn innermost(&self) -> Option<&Arc<EvalFrame>> {
        self.tail.last().or_else(|| self.base.last())
    }

    /// Returns the frame at an outermost-relative index (`0` = outermost).
    pub(crate) fn get(&self, index: usize) -> Option<&Arc<EvalFrame>> {
        let base_len = self.base.len();
        if index < base_len {
            self.base.get(index)
        } else {
            self.tail.get(index - base_len)
        }
    }

    /// Returns the frame at a depth measured from the innermost (`0` =
    /// innermost), or `None` when `depth` reaches past the outermost frame.
    pub(crate) fn get_from_inner(&self, depth: usize) -> Option<&Arc<EvalFrame>> {
        let index = self.len().checked_sub(depth + 1)?;
        self.get(index)
    }

    /// Reserves capacity for one additional pushed frame.
    ///
    /// # Errors
    ///
    /// Returns [`TryReserveError`] if the tail buffer cannot grow.
    pub(crate) fn reserve_one(&mut self) -> Result<(), TryReserveError> {
        self.tail.try_reserve_exact(1)
    }

    /// Pushes a frame onto the mutable tail.
    pub(crate) fn push(&mut self, frame: Arc<EvalFrame>) {
        self.tail.push(frame);
    }

    /// Pops the innermost frame, if any.
    ///
    /// Under the evaluator's balanced push/pop bracketing a body never pops
    /// below the base it was installed with, so this normally drains the tail.
    /// The base-materializing branch keeps the shared `Arc` immutable and is a
    /// pure correctness fallback that production does not reach.
    pub(crate) fn pop(&mut self) -> Option<Arc<EvalFrame>> {
        if let Some(frame) = self.tail.pop() {
            return Some(frame);
        }
        if self.base.is_empty() {
            return None;
        }
        let mut owned: Vec<Arc<EvalFrame>> = Vec::with_capacity(self.base.len());
        owned.extend(self.base.iter().cloned());
        self.base = Arc::from(Vec::new());
        self.tail = owned;
        self.tail.pop()
    }

    /// Iterates every frame outermost-first (base then tail).
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Arc<EvalFrame>> {
        self.base.iter().chain(self.tail.iter())
    }

    /// Returns the shared immutable base slice.
    pub(crate) fn base_slice(&self) -> &[Arc<EvalFrame>] {
        &self.base
    }

    /// Returns the mutable tail slice.
    pub(crate) fn tail_slice(&self) -> &[Arc<EvalFrame>] {
        &self.tail
    }
}

#[cfg(test)]
impl std::ops::Index<usize> for ActiveFrameStack {
    type Output = Arc<EvalFrame>;

    fn index(&self, index: usize) -> &Self::Output {
        match self.get(index) {
            Some(frame) => frame,
            None => panic!("active frame stack index {index} is out of bounds"),
        }
    }
}

/// The active lexical environment split at an optional flat captured prefix.
///
/// `frames` contains only the live shared-frame suffix introduced inside the
/// flat prefix (or the complete stack when `flat_base` is absent). Lowered IR
/// still sees `flat_base.frame_count() + frames.len()` conceptual frames.
#[derive(Clone, Debug, Default)]
pub(crate) struct ActiveEvalEnv {
    pub(crate) frames: ActiveFrameStack,
    pub(crate) flat_base: Option<EvalFlatCapture>,
}

impl ActiveEvalEnv {
    pub(crate) fn from_frames(frames: Vec<Arc<EvalFrame>>) -> Self {
        Self {
            frames: ActiveFrameStack::from_base(Arc::from(frames)),
            flat_base: None,
        }
    }

    pub(crate) fn frame_count(&self) -> usize {
        self.flat_base
            .as_ref()
            .map_or(0, EvalFlatCapture::frame_count)
            .saturating_add(self.frames.len())
    }
}

impl From<Vec<Arc<EvalFrame>>> for ActiveEvalEnv {
    fn from(frames: Vec<Arc<EvalFrame>>) -> Self {
        Self::from_frames(frames)
    }
}

#[cfg(test)]
impl std::ops::Index<usize> for ActiveEvalEnv {
    type Output = Arc<EvalFrame>;

    fn index(&self, index: usize) -> &Self::Output {
        match self.frames.get(index) {
            Some(frame) => frame,
            None => panic!("active environment frame index {index} is out of bounds"),
        }
    }
}

/// A borrowed view of either an active or captured composed lexical env.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EvalEnvRef<'a> {
    pub(crate) frames: EvalEnvFramesRef<'a>,
    pub(crate) flat_base: Option<&'a EvalFlatCapture>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum EvalEnvFramesRef<'a> {
    /// The live active stack, borrowed as its split base and tail slices.
    Active {
        base: &'a [Arc<EvalFrame>],
        tail: &'a [Arc<EvalFrame>],
    },
    Captured(EvalEnvFrames<'a>),
}

impl<'a> EvalEnvFramesRef<'a> {
    pub(crate) fn len(self) -> usize {
        match self {
            Self::Active { base, tail } => base.len() + tail.len(),
            Self::Captured(frames) => frames.len(),
        }
    }

    pub(crate) fn is_empty(self) -> bool {
        self.len() == 0
    }

    pub(crate) fn get(self, index: usize) -> Option<&'a Arc<EvalFrame>> {
        match self {
            Self::Active { base, tail } => {
                if index < base.len() {
                    base.get(index)
                } else {
                    tail.get(index - base.len())
                }
            }
            Self::Captured(frames) => frames.get(index),
        }
    }
}

impl EvalEnvRef<'_> {
    pub(crate) fn frame_count(self) -> usize {
        self.flat_base
            .map_or(0, EvalFlatCapture::frame_count)
            .saturating_add(self.frames.len())
    }

    pub(crate) fn is_empty(self) -> bool {
        self.frames.is_empty() && self.flat_base.is_none_or(EvalFlatCapture::is_empty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> Arc<EvalFrame> {
        EvalFrame::new(1).expect("frame allocation")
    }

    /// The split stack indexes outermost-first (base then tail), reports the
    /// combined length, and resolves innermost-relative depths.
    #[test]
    fn active_frame_stack_base_tail_ordering() {
        let f0 = frame();
        let f1 = frame();
        let f2 = frame();
        let base: Arc<[Arc<EvalFrame>]> = Arc::from(vec![Arc::clone(&f0), Arc::clone(&f1)]);
        let mut stack = ActiveFrameStack::from_base(base);
        assert_eq!(stack.len(), 2);
        stack.push(Arc::clone(&f2));
        assert_eq!(stack.len(), 3);
        assert!(!stack.is_empty());

        assert!(Arc::ptr_eq(stack.get(0).expect("outermost"), &f0));
        assert!(Arc::ptr_eq(stack.get(1).expect("middle"), &f1));
        assert!(Arc::ptr_eq(stack.get(2).expect("innermost"), &f2));
        assert!(stack.get(3).is_none());

        assert!(Arc::ptr_eq(stack.innermost().expect("innermost"), &f2));
        assert!(Arc::ptr_eq(stack.get_from_inner(0).expect("depth 0"), &f2));
        assert!(Arc::ptr_eq(stack.get_from_inner(2).expect("depth 2"), &f0));
        assert!(stack.get_from_inner(3).is_none());

        let collected: Vec<&Arc<EvalFrame>> = stack.iter().collect();
        assert_eq!(collected.len(), 3);
        assert!(Arc::ptr_eq(collected[0], &f0));
        assert!(Arc::ptr_eq(collected[1], &f1));
        assert!(Arc::ptr_eq(collected[2], &f2));

        // Pop removes only the tail; the shared base stays intact.
        assert!(Arc::ptr_eq(&stack.pop().expect("pop tail"), &f2));
        assert_eq!(stack.len(), 2);
        assert!(Arc::ptr_eq(stack.get(0).expect("outermost"), &f0));
    }

    /// Popping with an empty tail materializes the base into an owned tail
    /// rather than mutating the shared `Arc`.
    #[test]
    fn active_frame_stack_pop_materializes_base_fallback() {
        let f0 = frame();
        let f1 = frame();
        let base: Arc<[Arc<EvalFrame>]> = Arc::from(vec![Arc::clone(&f0), Arc::clone(&f1)]);
        let shared = Arc::clone(&base);
        let mut stack = ActiveFrameStack::from_base(base);

        assert!(Arc::ptr_eq(&stack.pop().expect("pop base fallback"), &f1));
        assert_eq!(stack.len(), 1);
        assert!(Arc::ptr_eq(stack.get(0).expect("survivor"), &f0));
        // The original shared base slice is untouched by the fallback.
        assert_eq!(shared.len(), 2);
        assert!(Arc::ptr_eq(&shared[1], &f1));
    }

    /// An empty stack reports empty and yields nothing.
    #[test]
    fn active_frame_stack_empty() {
        let mut stack = ActiveFrameStack::new();
        assert!(stack.is_empty());
        assert_eq!(stack.len(), 0);
        assert!(stack.innermost().is_none());
        assert!(stack.get(0).is_none());
        assert!(stack.pop().is_none());
        assert_eq!(stack.iter().count(), 0);
    }
}
