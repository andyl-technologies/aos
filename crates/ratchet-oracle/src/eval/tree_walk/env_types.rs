//! Suspended/active evaluation environment wrappers and telemetry
//! (split from tree_walk.rs under the §2 file-size cap).
use super::*;

/// Inline capacity for the active lexical frame suffix.
///
/// Captured-environment telemetry shows an average installed depth of 0.15,
/// and every lambda application adds exactly one call frame. Keeping the first
/// two frames inline therefore removes the per-call `Vec` allocation from the
/// dominant serial path while retaining a spill path for arbitrary Nix scope
/// depth.
pub(crate) const ACTIVE_ENV_INLINE_FRAMES: usize = 2;

/// The active lexical suffix, inline for the overwhelmingly common shallow case.
pub(crate) type ActiveEvalFrames = smallvec::SmallVec<[Arc<EvalFrame>; ACTIVE_ENV_INLINE_FRAMES]>;

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

/// The active lexical environment split at an optional flat captured prefix.
///
/// `frames` contains only the live shared-frame suffix introduced inside the
/// flat prefix (or the complete stack when `flat_base` is absent). Lowered IR
/// still sees `flat_base.frame_count() + frames.len()` conceptual frames.
#[derive(Clone, Debug, Default)]
pub(crate) struct ActiveEvalEnv {
    pub(crate) frames: ActiveEvalFrames,
    pub(crate) flat_base: Option<EvalFlatCapture>,
}

impl ActiveEvalEnv {
    pub(crate) fn from_frames(frames: Vec<Arc<EvalFrame>>) -> Self {
        Self {
            frames: ActiveEvalFrames::from_vec(frames),
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
        &self.frames[index]
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
    Active(&'a [Arc<EvalFrame>]),
    Captured(EvalEnvFrames<'a>),
}

impl<'a> EvalEnvFramesRef<'a> {
    pub(crate) fn len(self) -> usize {
        match self {
            Self::Active(frames) => frames.len(),
            Self::Captured(frames) => frames.len(),
        }
    }

    pub(crate) fn is_empty(self) -> bool {
        self.len() == 0
    }

    pub(crate) fn get(self, index: usize) -> Option<&'a Arc<EvalFrame>> {
        match self {
            Self::Active(frames) => frames.get(index),
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
