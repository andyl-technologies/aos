//! Bounded proof-only shadows for native recursive evaluator continuations.
//!
//! This module never collects or mutates heap storage. When the nested
//! nonmoving proof selects a completion ordinal, it records active recursive
//! entry edges and publishes explicitly declared native-local [`Value`]s to the
//! proof root set. Missing continuation permits are retained as uncovered
//! active edges, so the proof fails closed while the first instrumentation
//! slice is intentionally incomplete.
//!
//! Without the `collection_poll_probe` feature, this module retains only an
//! inline facade whose portals call their evaluator operations directly. The
//! storage-bearing shadow, panic guards, counters, and reports are not compiled.

#[cfg(feature = "collection_poll_probe")]
use std::panic::Location;
#[cfg(feature = "collection_poll_probe")]
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use super::*;

#[cfg(feature = "collection_poll_probe")]
const FRAME_CAP: usize = 480;
#[cfg(feature = "collection_poll_probe")]
const ROOT_CAP: usize = 4096;
#[cfg(feature = "collection_poll_probe")]
const PRIMOP_CONTEXT_CAP: usize = 64;
#[cfg(feature = "collection_poll_probe")]
pub(super) const STORAGE_CAP_BYTES: usize = 64 * 1024;
#[cfg(feature = "collection_poll_probe")]
pub(super) const COMBINED_DIAGNOSTIC_CAP_BYTES: usize = 128 * 1024;

/// A recursive evaluator portal tracked by the native-continuation census.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeContinuationEdge {
    EvalNode,
    ForceValue,
    ApplyLambda,
}

#[cfg(feature = "collection_poll_probe")]
impl NativeContinuationEdge {
    const ALL: [Self; 3] = [Self::EvalNode, Self::ForceValue, Self::ApplyLambda];

    const fn name(self) -> &'static str {
        match self {
            Self::EvalNode => "eval_node",
            Self::ForceValue => "force_value",
            Self::ApplyLambda => "apply_lambda",
        }
    }
}

/// A source-independent semantic class for one native continuation site.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "collection_poll_probe")]
enum NativeContinuationSiteClass {
    Unknown,
    Int,
    Float,
    Bool,
    Null,
    Str,
    Path,
    SearchPath,
    Uri,
    LocalVar,
    UpvalVar,
    GlobalVar,
    BuiltinAttr,
    List,
    AttrSet,
    Lambda,
    FormalSet,
    Formal,
    Apply,
    Select,
    HasAttr,
    Let,
    With,
    Assert,
    If,
    BinOp,
    UnaryOp,
    Interp,
    ThunkAlloc,
    PrimOp,
}

#[cfg(feature = "collection_poll_probe")]
impl NativeContinuationSiteClass {
    const ALL: [Self; 30] = [
        Self::Unknown,
        Self::Int,
        Self::Float,
        Self::Bool,
        Self::Null,
        Self::Str,
        Self::Path,
        Self::SearchPath,
        Self::Uri,
        Self::LocalVar,
        Self::UpvalVar,
        Self::GlobalVar,
        Self::BuiltinAttr,
        Self::List,
        Self::AttrSet,
        Self::Lambda,
        Self::FormalSet,
        Self::Formal,
        Self::Apply,
        Self::Select,
        Self::HasAttr,
        Self::Let,
        Self::With,
        Self::Assert,
        Self::If,
        Self::BinOp,
        Self::UnaryOp,
        Self::Interp,
        Self::ThunkAlloc,
        Self::PrimOp,
    ];

    const fn from_ir_kind(kind: IrKind) -> Self {
        match kind {
            IrKind::Int => Self::Int,
            IrKind::Float => Self::Float,
            IrKind::Bool => Self::Bool,
            IrKind::Null => Self::Null,
            IrKind::Str => Self::Str,
            IrKind::Path => Self::Path,
            IrKind::SearchPath => Self::SearchPath,
            IrKind::Uri => Self::Uri,
            IrKind::LocalVar => Self::LocalVar,
            IrKind::UpvalVar => Self::UpvalVar,
            IrKind::GlobalVar => Self::GlobalVar,
            IrKind::BuiltinAttr => Self::BuiltinAttr,
            IrKind::List => Self::List,
            IrKind::AttrSet => Self::AttrSet,
            IrKind::Lambda => Self::Lambda,
            IrKind::FormalSet => Self::FormalSet,
            IrKind::Formal => Self::Formal,
            IrKind::Apply => Self::Apply,
            IrKind::Select => Self::Select,
            IrKind::HasAttr => Self::HasAttr,
            IrKind::Let => Self::Let,
            IrKind::With => Self::With,
            IrKind::Assert => Self::Assert,
            IrKind::If => Self::If,
            IrKind::BinOp => Self::BinOp,
            IrKind::UnaryOp => Self::UnaryOp,
            IrKind::Interp => Self::Interp,
            IrKind::ThunkAlloc => Self::ThunkAlloc,
            IrKind::PrimOp => Self::PrimOp,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Int => "int",
            Self::Float => "float",
            Self::Bool => "bool",
            Self::Null => "null",
            Self::Str => "str",
            Self::Path => "path",
            Self::SearchPath => "search_path",
            Self::Uri => "uri",
            Self::LocalVar => "local_var",
            Self::UpvalVar => "upval_var",
            Self::GlobalVar => "global_var",
            Self::BuiltinAttr => "builtin_attr",
            Self::List => "list",
            Self::AttrSet => "attr_set",
            Self::Lambda => "lambda",
            Self::FormalSet => "formal_set",
            Self::Formal => "formal",
            Self::Apply => "apply",
            Self::Select => "select",
            Self::HasAttr => "has_attr",
            Self::Let => "let",
            Self::With => "with",
            Self::Assert => "assert",
            Self::If => "if",
            Self::BinOp => "bin_op",
            Self::UnaryOp => "unary_op",
            Self::Interp => "interp",
            Self::ThunkAlloc => "thunk_alloc",
            Self::PrimOp => "prim_op",
        }
    }
}

/// A manually declared proof or diagnostic continuation in the bounded census.
///
/// A kind does not itself grant coverage. Proof wrappers open covered frames
/// with an expected child, while diagnostic wrappers open uncovered zero-root
/// frames that cannot authorize a child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeContinuationKind {
    FoldCanary,
    CanaryPublish,
    CanaryCompletion,
    NodeThunkBody,
    ForceNodeResult,
    ApplyLambdaPortal,
    LambdaBody,
    LetBody,
    InterpChild,
    InterpolationHookForce,
    InterpolationOutPathForce,
    LazyDemandForce,
    CallableForce,
    IfCondition,
    IfBranch,
    BinaryLhs,
    BinaryRhs,
    BinaryPipeLeft,
    BinaryPipeRight,
    SelectReceiver,
    SelectDynamicAttr,
    SelectDefault,
    SelectStaticDefault,
    /// Marks one direct recursive child evaluation owned by a primop.
    PrimOpEvalChild,
    /// Marks one direct force leaf owned by a primop.
    PrimOpForceLeaf,
    /// Evaluates the attribute-set argument of `getAttr`.
    GetAttrArgumentEval,
    /// Evaluates the list argument of `map`.
    MapListArgumentEval,
    /// Evaluates one direct strict-unary builtin argument.
    StrictUnaryArgumentEval,
    /// Forces one derivation attribute while retaining the remaining entries.
    DerivationAttributeForce,
    /// Forces one derivation argument while retaining the remaining arguments.
    DerivationArgumentForce,
    /// Forces one string-concatenation element while retaining the source slice.
    ConcatStringElementForce,
    /// Forces the `outPath` selected while serializing an attribute set.
    JsonOutPathForce,
    /// Marks the conditional force leaf for a lazy `foldl'` initial value.
    LazyFoldlInitialForceLeaf,
    /// Marks the force leaf after consuming an already-suspended demanded value.
    DemandedConsumedForceLeaf,
    /// Marks the first unconditional force leaf for a demanded value.
    DemandedPrimaryForceLeaf,
    /// Marks the retry force leaf after the first demanded force suspends again.
    DemandedRetryForceLeaf,
}

#[cfg(feature = "collection_poll_probe")]
impl NativeContinuationKind {
    const fn name(self) -> &'static str {
        match self {
            Self::FoldCanary => "fold_canary",
            Self::CanaryPublish => "canary_publish",
            Self::CanaryCompletion => "canary_completion",
            Self::NodeThunkBody => "node_thunk_body",
            Self::ForceNodeResult => "force_node_result",
            Self::ApplyLambdaPortal => "apply_lambda_portal",
            Self::LambdaBody => "lambda_body",
            Self::LetBody => "let_body",
            Self::InterpChild => "interp_child",
            Self::InterpolationHookForce => "interpolation_hook_force",
            Self::InterpolationOutPathForce => "interpolation_out_path_force",
            Self::LazyDemandForce => "lazy_demand_force",
            Self::CallableForce => "callable_force",
            Self::IfCondition => "if_condition",
            Self::IfBranch => "if_branch",
            Self::BinaryLhs => "binary_lhs",
            Self::BinaryRhs => "binary_rhs",
            Self::BinaryPipeLeft => "binary_pipe_left",
            Self::BinaryPipeRight => "binary_pipe_right",
            Self::SelectReceiver => "select_receiver",
            Self::SelectDynamicAttr => "select_dynamic_attr",
            Self::SelectDefault => "select_default",
            Self::SelectStaticDefault => "select_static_default",
            Self::PrimOpEvalChild => "primop_eval_child",
            Self::PrimOpForceLeaf => "primop_force_leaf",
            Self::GetAttrArgumentEval => "get_attr_argument_eval",
            Self::MapListArgumentEval => "map_list_argument_eval",
            Self::StrictUnaryArgumentEval => "strict_unary_argument_eval",
            Self::DerivationAttributeForce => "derivation_attribute_force",
            Self::DerivationArgumentForce => "derivation_argument_force",
            Self::ConcatStringElementForce => "concat_string_element_force",
            Self::JsonOutPathForce => "json_out_path_force",
            Self::LazyFoldlInitialForceLeaf => "lazy_foldl_initial_force_leaf",
            Self::DemandedConsumedForceLeaf => "demanded_consumed_force_leaf",
            Self::DemandedPrimaryForceLeaf => "demanded_primary_force_leaf",
            Self::DemandedRetryForceLeaf => "demanded_retry_force_leaf",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "collection_poll_probe")]
enum NativeContinuationFrameKind {
    Edge(NativeContinuationEdge),
    Semantic(NativeContinuationKind),
}

/// The direct primop dispatch path that owns recursive child transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativePrimOpContextMode {
    CachedDirect,
    ResolvedInlineDirect,
    ResolvedHeapDirect,
}

#[cfg(feature = "collection_poll_probe")]
impl NativePrimOpContextMode {
    const fn name(self) -> &'static str {
        match self {
            Self::CachedDirect => "cached_direct",
            Self::ResolvedInlineDirect => "resolved_inline_direct",
            Self::ResolvedHeapDirect => "resolved_heap_direct",
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[cfg(feature = "collection_poll_probe")]
struct NativePrimOpContext {
    mode: NativePrimOpContextMode,
    module: EvalModuleId,
    site: IrId,
    symbol: Symbol,
    next_child_sequence: u32,
}

#[cfg(feature = "collection_poll_probe")]
impl NativeContinuationFrameKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Edge(edge) => edge.name(),
            Self::Semantic(kind) => kind.name(),
        }
    }
}

/// Opaque LIFO coordinate for one active shadow frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "collection_poll_probe")]
pub(super) struct NativeContinuationToken {
    depth: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug)]
#[cfg(feature = "collection_poll_probe")]
struct NativeContinuationFrame {
    token: NativeContinuationToken,
    kind: NativeContinuationFrameKind,
    site_class: NativeContinuationSiteClass,
    module: EvalModuleId,
    site: IrId,
    root_start: usize,
    root_len: usize,
    expected_child: Option<NativeContinuationEdge>,
    child_consumed: bool,
    covered: bool,
    caller_location: Option<&'static Location<'static>>,
}

/// Read-only reconciliation state captured at one selected completion.
#[derive(Clone, Copy, Debug, Default)]
#[cfg(feature = "collection_poll_probe")]
pub(super) struct NativeContinuationSnapshot {
    pub(super) active_frames: usize,
    pub(super) active_overflow_frames: usize,
    pub(super) active_roots: usize,
    pub(super) covered_frames: usize,
    pub(super) uncovered_active: usize,
    pub(super) uncovered_entries: u64,
    pub(super) imbalances: u64,
    pub(super) overflows: u64,
    pub(super) active_primop_contexts: usize,
    pub(super) primop_context_coalesced_entries: u64,
    pub(super) primop_context_overflows: u64,
    pub(super) primop_context_module_mismatches: u64,
    pub(super) modeled_storage_bytes: usize,
    pub(super) storage_cap_bytes: usize,
}

#[cfg(feature = "collection_poll_probe")]
impl NativeContinuationSnapshot {
    /// Returns whether every active continuation is explicitly represented.
    pub(super) const fn reconciled(self) -> bool {
        self.uncovered_active == 0
            && self.active_overflow_frames == 0
            && self.imbalances == 0
            && self.primop_context_overflows == 0
            && self.primop_context_module_mismatches == 0
            && self.modeled_storage_bytes <= self.storage_cap_bytes
    }
}

/// Per-evaluator bounded native-continuation census and root stack.
#[derive(Debug)]
#[cfg(feature = "collection_poll_probe")]
pub(super) struct NativeContinuationShadow {
    frames: Vec<NativeContinuationFrame>,
    roots: Vec<Value>,
    next_generation: u64,
    uncovered_entries: u64,
    imbalances: u64,
    overflows: u64,
    active_overflow_frames: usize,
    primop_contexts: Vec<NativePrimOpContext>,
    primop_context_coalesced_entries: u64,
    primop_context_overflows: u64,
    primop_context_module_mismatches: u64,
}

#[cfg(feature = "collection_poll_probe")]
impl NativeContinuationShadow {
    /// Enables the shadow for either root-completeness consumer.
    pub(super) fn from_env() -> Option<Self> {
        let proof_requested = std::env::var("AOS_NIX_NESTED_NONMOVING_PROOF_ORDINAL")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|ordinal| *ordinal != 0)
            .is_some();
        #[cfg(feature = "nested_nonmoving_retirement_probe")]
        let retirement_requested =
            std::env::var("AOS_NIX_NESTED_NONMOVING_RETIREMENT_REPORT_ORDINAL")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|ordinal| *ordinal != 0)
                .is_some();
        #[cfg(feature = "nested_nonmoving_retirement_probe")]
        let rotating_rollover_requested =
            std::env::var("AOS_NIX_ROTATING_ROLLOVER_PROBE").is_ok_and(|value| value == "1");
        #[cfg(not(feature = "nested_nonmoving_retirement_probe"))]
        let retirement_requested = false;
        #[cfg(not(feature = "nested_nonmoving_retirement_probe"))]
        let rotating_rollover_requested = false;
        (proof_requested || retirement_requested || rotating_rollover_requested).then(Self::new)
    }

    const fn new() -> Self {
        Self {
            frames: Vec::new(),
            roots: Vec::new(),
            next_generation: 0,
            uncovered_entries: 0,
            imbalances: 0,
            overflows: 0,
            active_overflow_frames: 0,
            primop_contexts: Vec::new(),
            primop_context_coalesced_entries: 0,
            primop_context_overflows: 0,
            primop_context_module_mismatches: 0,
        }
    }

    pub(super) fn roots(&self) -> &[Value] {
        &self.roots
    }

    pub(super) fn modeled_storage_bytes(&self) -> usize {
        self.frames
            .capacity()
            .saturating_mul(std::mem::size_of::<NativeContinuationFrame>())
            .saturating_add(
                self.roots
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Value>()),
            )
            .saturating_add(
                self.primop_contexts
                    .capacity()
                    .saturating_mul(std::mem::size_of::<NativePrimOpContext>()),
            )
    }

    pub(super) fn snapshot(&self) -> NativeContinuationSnapshot {
        let covered_frames = self.frames.iter().filter(|frame| frame.covered).count();
        NativeContinuationSnapshot {
            active_frames: self.frames.len(),
            active_overflow_frames: self.active_overflow_frames,
            active_roots: self.roots.len(),
            covered_frames,
            uncovered_active: self.frames.len().saturating_sub(covered_frames),
            uncovered_entries: self.uncovered_entries,
            imbalances: self.imbalances,
            overflows: self.overflows,
            active_primop_contexts: self.primop_contexts.len(),
            primop_context_coalesced_entries: self.primop_context_coalesced_entries,
            primop_context_overflows: self.primop_context_overflows,
            primop_context_module_mismatches: self.primop_context_module_mismatches,
            modeled_storage_bytes: self.modeled_storage_bytes(),
            storage_cap_bytes: STORAGE_CAP_BYTES,
        }
    }

    fn begin(
        &mut self,
        kind: NativeContinuationFrameKind,
        module: EvalModuleId,
        site: IrId,
        site_class: NativeContinuationSiteClass,
        roots: &[Value],
        expected_child: Option<NativeContinuationEdge>,
        covered: bool,
    ) -> Option<NativeContinuationToken> {
        let root_end = match self.roots.len().checked_add(roots.len()) {
            Some(end) if end <= ROOT_CAP && self.frames.len() < FRAME_CAP => end,
            _ => {
                self.note_overflow();
                return None;
            }
        };
        let generation = match self.next_generation.checked_add(1) {
            Some(generation) => generation,
            None => {
                self.note_overflow();
                return None;
            }
        };
        if self.frames.try_reserve_exact(1).is_err()
            || self.roots.try_reserve_exact(roots.len()).is_err()
        {
            self.note_overflow();
            return None;
        }
        let token = NativeContinuationToken {
            depth: self.frames.len(),
            generation,
        };
        let root_start = self.roots.len();
        self.roots.extend_from_slice(roots);
        debug_assert_eq!(self.roots.len(), root_end);
        self.frames.push(NativeContinuationFrame {
            token,
            kind,
            site_class,
            module,
            site,
            root_start,
            root_len: roots.len(),
            expected_child,
            child_consumed: false,
            covered,
            caller_location: None,
        });
        self.next_generation = generation;
        Some(token)
    }

    fn note_overflow(&mut self) {
        self.overflows = self.overflows.saturating_add(1);
        self.active_overflow_frames = self.active_overflow_frames.saturating_add(1);
    }

    fn finish_overflow(&mut self) {
        if self.active_overflow_frames == 0 {
            self.imbalances = self.imbalances.saturating_add(1);
            return;
        }
        self.active_overflow_frames -= 1;
    }

    fn begin_edge(
        &mut self,
        edge: NativeContinuationEdge,
        module: EvalModuleId,
        site: IrId,
        site_class: NativeContinuationSiteClass,
    ) -> Option<NativeContinuationToken> {
        self.begin_edge_at(edge, module, site, site_class, None)
    }

    fn begin_edge_at(
        &mut self,
        edge: NativeContinuationEdge,
        module: EvalModuleId,
        site: IrId,
        site_class: NativeContinuationSiteClass,
        caller_location: Option<&'static Location<'static>>,
    ) -> Option<NativeContinuationToken> {
        let permitted = self.frames.last_mut().is_some_and(|parent| {
            if parent.covered && parent.expected_child == Some(edge) && !parent.child_consumed {
                parent.child_consumed = true;
                true
            } else {
                false
            }
        });
        let covered = permitted && site_class != NativeContinuationSiteClass::Unknown;
        if !covered {
            self.uncovered_entries = self.uncovered_entries.saturating_add(1);
        }
        let token = self.begin(
            NativeContinuationFrameKind::Edge(edge),
            module,
            site,
            site_class,
            &[],
            None,
            covered,
        );
        if token.is_some()
            && let Some(frame) = self.frames.last_mut()
        {
            frame.caller_location = caller_location;
        }
        token
    }

    /// Returns whether an edge is an unmarked child of direct primop dispatch.
    ///
    /// Explicit diagnostic portals remain the immediate parent of their edge,
    /// so this structural fallback does not double-count them.
    fn edge_needs_primop_child_marker(&mut self, edge: NativeContinuationEdge) -> bool {
        let parent = self.frames.last().copied();
        if parent.is_some_and(|parent| {
            matches!(parent.kind, NativeContinuationFrameKind::Semantic(_)) && !parent.covered
        }) {
            return false;
        }
        let context_active = if let Some(context) = self.primop_contexts.last_mut() {
            let child_sequence = context.next_child_sequence;
            context.next_child_sequence = context.next_child_sequence.saturating_add(1);
            let _ = (
                context.mode,
                context.module,
                context.site,
                context.symbol,
                child_sequence,
            );
            true
        } else {
            false
        };
        let Some(parent) = parent else {
            return context_active;
        };
        if !context_active
            && !matches!(
                (parent.kind, parent.site_class),
                (
                    NativeContinuationFrameKind::Edge(NativeContinuationEdge::EvalNode),
                    NativeContinuationSiteClass::PrimOp,
                )
            )
        {
            return false;
        }
        matches!(
            edge,
            NativeContinuationEdge::EvalNode | NativeContinuationEdge::ForceValue
        ) && (!parent.covered || parent.expected_child != Some(edge) || parent.child_consumed)
    }

    fn begin_primop_context(
        &mut self,
        mode: NativePrimOpContextMode,
        module: EvalModuleId,
        site: IrId,
        symbol: Symbol,
    ) -> Option<usize> {
        if self.primop_contexts.len() >= PRIMOP_CONTEXT_CAP {
            self.primop_context_coalesced_entries =
                self.primop_context_coalesced_entries.saturating_add(1);
            return None;
        }
        if self.primop_contexts.try_reserve_exact(1).is_err() {
            self.primop_context_overflows = self.primop_context_overflows.saturating_add(1);
            return None;
        }
        let depth = self.primop_contexts.len();
        self.primop_contexts.push(NativePrimOpContext {
            mode,
            module,
            site,
            symbol,
            next_child_sequence: 0,
        });
        Some(depth)
    }

    fn finish_primop_context(&mut self, depth: Option<usize>, module: EvalModuleId) {
        let Some(depth) = depth else {
            return;
        };
        if depth != self.primop_contexts.len().saturating_sub(1) {
            self.imbalances = self.imbalances.saturating_add(1);
            return;
        }
        if self
            .primop_contexts
            .last()
            .is_some_and(|context| context.module != module)
        {
            self.primop_context_module_mismatches =
                self.primop_context_module_mismatches.saturating_add(1);
        }
        let _ = self.primop_contexts.pop();
    }

    fn finish(&mut self, token: NativeContinuationToken) {
        let Some(frame) = self.frames.last().copied() else {
            self.imbalances = self.imbalances.saturating_add(1);
            return;
        };
        if frame.token != token
            || frame.token.depth != self.frames.len().saturating_sub(1)
            || frame.root_start.saturating_add(frame.root_len) != self.roots.len()
        {
            self.imbalances = self.imbalances.saturating_add(1);
            return;
        }
        self.roots.truncate(frame.root_start);
        let _ = self.frames.pop();
    }

    fn active_frame_records(
        &self,
    ) -> impl Iterator<
        Item = (
            usize,
            &'static str,
            &'static str,
            u32,
            u32,
            usize,
            bool,
            &'static str,
            u32,
            u32,
        ),
    > + '_ {
        self.frames.iter().enumerate().map(|(depth, frame)| {
            (
                depth,
                frame.kind.name(),
                frame.site_class.name(),
                frame.module.as_u32(),
                frame.site.as_u32(),
                frame.root_len,
                frame.covered,
                frame
                    .caller_location
                    .map_or("none", |location| location.file()),
                frame.caller_location.map_or(0, |location| location.line()),
                frame
                    .caller_location
                    .map_or(0, |location| location.column()),
            )
        })
    }

    fn selected_class_counts(
        &self,
        edge: NativeContinuationEdge,
        class: NativeContinuationSiteClass,
    ) -> (usize, usize) {
        let mut covered = 0usize;
        let mut uncovered = 0usize;
        for frame in &self.frames {
            if frame.kind == NativeContinuationFrameKind::Edge(edge) && frame.site_class == class {
                if frame.covered {
                    covered = covered.saturating_add(1);
                } else {
                    uncovered = uncovered.saturating_add(1);
                }
            }
        }
        (covered, uncovered)
    }

    pub(super) fn emit_selected_active_frames(&self, ordinal: u64) {
        for (depth, context) in self.primop_contexts.iter().enumerate() {
            eprintln!(
                "aos_nix_native_continuation_selected_primop_context ordinal={} depth={} \
                 mode={} module={} site={} symbol={} child_sequence={}",
                ordinal,
                depth,
                context.mode.name(),
                context.module.as_u32(),
                context.site.as_u32(),
                context.symbol.as_u32(),
                context.next_child_sequence,
            );
        }
        for (
            depth,
            kind,
            class,
            module,
            site,
            roots,
            covered,
            caller_file,
            caller_line,
            caller_column,
        ) in self.active_frame_records()
        {
            eprintln!(
                "aos_nix_native_continuation_selected_frame ordinal={} depth={} kind={} \
                 class={} module={} site={} roots={} covered={} caller_file={} caller_line={} \
                 caller_column={}",
                ordinal,
                depth,
                kind,
                class,
                module,
                site,
                roots,
                covered,
                caller_file,
                caller_line,
                caller_column,
            );
        }
        for edge in NativeContinuationEdge::ALL {
            for class in NativeContinuationSiteClass::ALL {
                let (covered, uncovered) = self.selected_class_counts(edge, class);
                if covered != 0 || uncovered != 0 {
                    eprintln!(
                        "aos_nix_native_continuation_selected_class ordinal={} edge={} class={} \
                         covered={} uncovered={}",
                        ordinal,
                        edge.name(),
                        class.name(),
                        covered,
                        uncovered,
                    );
                }
            }
        }
    }
}

#[cfg(feature = "collection_poll_probe")]
impl TreeWalk {
    fn native_continuation_site_class(&self, site: IrId) -> NativeContinuationSiteClass {
        self.current_ir()
            .arena
            .node(site)
            .map_or(NativeContinuationSiteClass::Unknown, |node| {
                NativeContinuationSiteClass::from_ir_kind(node.kind)
            })
    }

    /// Returns whether the nested proof requested native-continuation census data.
    pub(super) fn native_continuation_shadow_enabled(&self) -> bool {
        self.native_continuation_shadow.is_some()
    }

    /// Opens one central recursive-entry census frame.
    pub(super) fn begin_native_continuation_edge(
        &mut self,
        edge: NativeContinuationEdge,
        site: IrId,
    ) -> Option<NativeContinuationToken> {
        self.native_continuation_shadow.as_ref()?;
        let site_class = self.native_continuation_site_class(site);
        self.native_continuation_shadow
            .as_mut()
            .and_then(|shadow| shadow.begin_edge(edge, self.current_module, site, site_class))
    }

    /// Opens one central recursive-entry frame with its exact Rust caller.
    fn begin_native_continuation_edge_at(
        &mut self,
        edge: NativeContinuationEdge,
        site: IrId,
        caller_location: &'static Location<'static>,
    ) -> Option<NativeContinuationToken> {
        self.native_continuation_shadow.as_ref()?;
        let site_class = self.native_continuation_site_class(site);
        self.native_continuation_shadow.as_mut().and_then(|shadow| {
            shadow.begin_edge_at(
                edge,
                self.current_module,
                site,
                site_class,
                Some(caller_location),
            )
        })
    }

    /// Returns whether a central recursive entry is an unmarked primop child.
    fn native_continuation_edge_needs_primop_child_marker(
        &mut self,
        edge: NativeContinuationEdge,
    ) -> bool {
        let Some(shadow) = self.native_continuation_shadow.as_mut() else {
            return false;
        };
        shadow.edge_needs_primop_child_marker(edge)
    }

    /// Closes one central recursive-entry census frame.
    pub(super) fn finish_native_continuation_edge(
        &mut self,
        token: Option<NativeContinuationToken>,
    ) {
        let Some(shadow) = self.native_continuation_shadow.as_mut() else {
            return;
        };
        if let Some(token) = token {
            shadow.finish(token);
        } else {
            shadow.finish_overflow();
        }
    }

    /// Runs one central recursive evaluator entry with panic-safe census cleanup.
    #[inline]
    pub(super) fn with_native_continuation_edge<T>(
        &mut self,
        edge: NativeContinuationEdge,
        site: IrId,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        if self.native_continuation_shadow.is_none() {
            return body(self);
        }
        let token = self.begin_native_continuation_edge(edge, site);
        let result = catch_unwind(AssertUnwindSafe(|| body(self)));
        self.finish_native_continuation_edge(token);
        match result {
            Ok(result) => result,
            Err(payload) => resume_unwind(payload),
        }
    }

    /// Runs one central recursive entry while retaining its outward Rust caller.
    #[inline]
    fn with_native_continuation_edge_at<T>(
        &mut self,
        edge: NativeContinuationEdge,
        site: IrId,
        caller_location: &'static Location<'static>,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        if self.native_continuation_shadow.is_none() {
            return body(self);
        }
        let token = self.begin_native_continuation_edge_at(edge, site, caller_location);
        let result = catch_unwind(AssertUnwindSafe(|| body(self)));
        self.finish_native_continuation_edge(token);
        match result {
            Ok(result) => result,
            Err(payload) => resume_unwind(payload),
        }
    }

    /// Runs one proof-only semantic continuation with explicit nonmoving roots.
    #[inline]
    pub(super) fn with_nonmoving_native_continuation<T>(
        &mut self,
        kind: NativeContinuationKind,
        site: IrId,
        roots: &[Value],
        expected_child: Option<NativeContinuationEdge>,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        if self.native_continuation_shadow.is_none() {
            return body(self);
        }
        let site_class = self.native_continuation_site_class(site);
        let token = self.native_continuation_shadow.as_mut().and_then(|shadow| {
            shadow.begin(
                NativeContinuationFrameKind::Semantic(kind),
                self.current_module,
                site,
                site_class,
                roots,
                expected_child,
                true,
            )
        });
        let result = catch_unwind(AssertUnwindSafe(|| body(self)));
        self.finish_native_continuation_edge(token);
        match result {
            Ok(result) => result,
            Err(payload) => resume_unwind(payload),
        }
    }

    /// Runs one semantic continuation with a bounded, explicitly built root manifest.
    ///
    /// Manifest admission failure executes `body` without a semantic parent,
    /// leaving its recursive edge uncovered and preserving evaluator behavior.
    #[inline]
    pub(super) fn with_bounded_native_root_manifest<T>(
        &mut self,
        kind: NativeContinuationKind,
        site: IrId,
        root_count: usize,
        expected_child: NativeContinuationEdge,
        build_roots: impl FnOnce(&mut Vec<Value>),
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        if self.native_continuation_shadow.is_none() || root_count > ROOT_CAP {
            return body(self);
        }
        let mut roots = Vec::new();
        if roots.try_reserve_exact(root_count).is_err() {
            return body(self);
        }
        build_roots(&mut roots);
        if roots.len() != root_count {
            return body(self);
        }
        self.with_nonmoving_native_continuation(kind, site, &roots, Some(expected_child), body)
    }

    /// Runs one diagnostic-only semantic marker that cannot authorize a child.
    #[inline]
    pub(super) fn with_uncovered_native_continuation_marker<T>(
        &mut self,
        kind: NativeContinuationKind,
        site: IrId,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        if self.native_continuation_shadow.is_none() {
            return body(self);
        }
        let site_class = self.native_continuation_site_class(site);
        let token = self.native_continuation_shadow.as_mut().and_then(|shadow| {
            shadow.begin(
                NativeContinuationFrameKind::Semantic(kind),
                self.current_module,
                site,
                site_class,
                &[],
                None,
                false,
            )
        });
        let result = catch_unwind(AssertUnwindSafe(|| body(self)));
        self.finish_native_continuation_edge(token);
        match result {
            Ok(result) => result,
            Err(payload) => resume_unwind(payload),
        }
    }

    /// Runs one central edge and diagnoses an unmarked primop child transition.
    #[inline]
    pub(super) fn with_attributed_native_continuation_edge<T>(
        &mut self,
        edge: NativeContinuationEdge,
        fallback_kind: NativeContinuationKind,
        site: IrId,
        caller_location: &'static Location<'static>,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        if self.native_continuation_edge_needs_primop_child_marker(edge) {
            return self.with_uncovered_native_continuation_marker(fallback_kind, site, |eval| {
                eval.with_native_continuation_edge_at(edge, site, caller_location, body)
            });
        }
        self.with_native_continuation_edge_at(edge, site, caller_location, body)
    }

    /// Runs one direct primop dispatch with a balanced diagnostic control record.
    #[inline]
    pub(super) fn with_native_primop_context<T>(
        &mut self,
        mode: NativePrimOpContextMode,
        site: IrId,
        symbol: Symbol,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        let Some(shadow) = self.native_continuation_shadow.as_mut() else {
            return body(self);
        };
        let token = shadow.begin_primop_context(mode, self.current_module, site, symbol);
        let result = catch_unwind(AssertUnwindSafe(|| body(self)));
        let module = self.current_module;
        if let Some(shadow) = self.native_continuation_shadow.as_mut() {
            shadow.finish_primop_context(token, module);
        }
        match result {
            Ok(result) => result,
            Err(payload) => resume_unwind(payload),
        }
    }

    /// Evaluates one direct primop child under an uncovered diagnostic marker.
    ///
    /// # Errors
    ///
    /// Returns the recursive evaluator error for `site`.
    #[inline]
    #[track_caller]
    pub(super) fn eval_uncovered_primop_child(
        &mut self,
        site: IrId,
    ) -> Result<Value, TreeWalkError> {
        let caller_location = Location::caller();
        self.with_uncovered_native_continuation_marker(
            NativeContinuationKind::PrimOpEvalChild,
            site,
            |eval| eval.eval_node_from_caller(site, caller_location),
        )
    }

    /// Forces one direct primop leaf under an uncovered diagnostic marker.
    ///
    /// # Errors
    ///
    /// Returns the recursive force error for `value`.
    #[inline]
    #[track_caller]
    pub(super) fn force_uncovered_primop_leaf(
        &mut self,
        site: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        let caller_location = Location::caller();
        self.with_uncovered_native_continuation_marker(
            NativeContinuationKind::PrimOpForceLeaf,
            site,
            |eval| eval.force_value_from_caller(site, span, value, caller_location),
        )
    }

    pub(super) fn native_continuation_snapshot(&self) -> NativeContinuationSnapshot {
        self.native_continuation_shadow
            .as_ref()
            .map_or_else(NativeContinuationSnapshot::default, |shadow| {
                shadow.snapshot()
            })
    }
}

#[cfg(not(feature = "collection_poll_probe"))]
impl TreeWalk {
    /// Returns `false` because native-continuation storage is absent.
    #[inline]
    pub(super) const fn native_continuation_shadow_enabled(&self) -> bool {
        false
    }

    /// Runs a recursive evaluator entry directly when the proof probe is absent.
    #[inline]
    pub(super) fn with_native_continuation_edge<T>(
        &mut self,
        _edge: NativeContinuationEdge,
        _site: IrId,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        body(self)
    }

    /// Runs a semantic continuation directly when the proof probe is absent.
    #[inline]
    pub(super) fn with_nonmoving_native_continuation<T>(
        &mut self,
        _kind: NativeContinuationKind,
        _site: IrId,
        _roots: &[Value],
        _expected_child: Option<NativeContinuationEdge>,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        body(self)
    }

    /// Runs one recursive entry directly when root-manifest storage is absent.
    #[inline]
    pub(super) fn with_bounded_native_root_manifest<T>(
        &mut self,
        _kind: NativeContinuationKind,
        _site: IrId,
        _root_count: usize,
        _expected_child: NativeContinuationEdge,
        _build_roots: impl FnOnce(&mut Vec<Value>),
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        body(self)
    }

    /// Runs a diagnostic continuation directly when the proof probe is absent.
    #[inline]
    pub(super) fn with_uncovered_native_continuation_marker<T>(
        &mut self,
        _kind: NativeContinuationKind,
        _site: IrId,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        body(self)
    }

    /// Runs one central recursive entry directly when the proof probe is absent.
    #[inline]
    pub(super) fn with_attributed_native_continuation_edge<T>(
        &mut self,
        _edge: NativeContinuationEdge,
        _fallback_kind: NativeContinuationKind,
        _site: IrId,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        body(self)
    }

    /// Runs one direct primop dispatch when the proof probe is absent.
    #[inline]
    pub(super) fn with_native_primop_context<T>(
        &mut self,
        _mode: NativePrimOpContextMode,
        _site: IrId,
        _symbol: Symbol,
        body: impl FnOnce(&mut Self) -> Result<T, TreeWalkError>,
    ) -> Result<T, TreeWalkError> {
        body(self)
    }

    /// Evaluates one direct primop child without probe instrumentation.
    ///
    /// # Errors
    ///
    /// Returns the recursive evaluator error for `site`.
    #[inline]
    pub(super) fn eval_uncovered_primop_child(
        &mut self,
        site: IrId,
    ) -> Result<Value, TreeWalkError> {
        self.eval_node(site)
    }

    /// Forces one direct primop leaf without probe instrumentation.
    ///
    /// # Errors
    ///
    /// Returns the recursive force error for `value`.
    #[inline]
    pub(super) fn force_uncovered_primop_leaf(
        &mut self,
        site: IrId,
        span: Span,
        value: Value,
    ) -> Result<Value, TreeWalkError> {
        self.force_value(site, span, value)
    }
}

#[cfg(all(test, not(feature = "collection_poll_probe")))]
mod feature_off_tests {
    use super::*;

    #[test]
    fn feature_off_facade_takes_direct_paths_without_shadow_state() {
        let ir = aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str("null").expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers");
        let mut evaluator = TreeWalk::new(&ir);
        assert!(!evaluator.native_continuation_shadow_enabled());
        assert!(
            evaluator
                .eval_uncovered_primop_child(ir.root)
                .expect("direct child evaluates")
                .raw_eq(Value::null())
        );
        let span = evaluator.node(ir.root).unwrap().span;
        assert!(
            evaluator
                .force_uncovered_primop_leaf(ir.root, span, Value::null())
                .expect("direct value forces")
                .raw_eq(Value::null())
        );
    }
}

#[cfg(all(test, feature = "collection_poll_probe"))]
mod tests {
    use super::*;
    use crate::eval::heap::EvalThunk;

    #[test]
    fn writeback_portal_owns_the_only_native_value_copies_and_balances_all_exits() {
        let ir = aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str("null").expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.native_continuation_shadow = Some(NativeContinuationShadow::new());
        let span = evaluator.node(ir.root).expect("root exists").span;

        let mut success_roots = [Value::int(1), Value::int(2)];
        let observed = evaluator
            .with_writeback_native_continuation(
                NativeContinuationKind::ForceNodeResult,
                ir.root,
                span,
                &mut success_roots,
                NativeContinuationEdge::ForceValue,
                |eval, slots| {
                    eval.with_native_continuation_edge(
                        NativeContinuationEdge::ForceValue,
                        ir.root,
                        |eval| {
                            let snapshot = eval.native_continuation_snapshot();
                            assert_eq!(snapshot.active_roots, 0);
                            assert_eq!(eval.transient_value_stack_roots().len(), 2);
                            assert!(eval.set_current_transient_value_stack_root(
                                slots.start,
                                Value::int(11),
                            ));
                            let second = slots
                                .start
                                .checked_add(1)
                                .expect("two-slot test range cannot overflow");
                            assert!(
                                eval.set_current_transient_value_stack_root(second, Value::int(22))
                            );
                            Ok(eval
                                .current_transient_value_stack_root(slots.start)
                                .expect("updated slot remains live"))
                        },
                    )
                },
            )
            .expect("writeback portal succeeds");
        assert!(observed.raw_eq(Value::int(11)));
        assert!(success_roots[0].raw_eq(Value::int(11)));
        assert!(success_roots[1].raw_eq(Value::int(22)));
        assert!(evaluator.transient_value_stack_roots().is_empty());
        assert_eq!(evaluator.native_continuation_snapshot().active_frames, 0);

        let mut error_roots = [Value::int(3)];
        let error =
            evaluator.with_writeback_native_continuation(
                NativeContinuationKind::ForceNodeResult,
                ir.root,
                span,
                &mut error_roots,
                NativeContinuationEdge::ForceValue,
                |eval, slots| {
                    eval.with_native_continuation_edge(
                        NativeContinuationEdge::ForceValue,
                        ir.root,
                        |eval| {
                            assert!(eval.set_current_transient_value_stack_root(
                                slots.start,
                                Value::int(33),
                            ));
                            eval.node(IrId::new(u32::MAX)).map(|_| ())
                        },
                    )
                },
            );
        assert!(error.is_err());
        assert!(error_roots[0].raw_eq(Value::int(33)));
        assert!(evaluator.transient_value_stack_roots().is_empty());
        assert_eq!(evaluator.native_continuation_snapshot().active_frames, 0);

        let mut panic_roots = [Value::int(4)];
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), TreeWalkError> = evaluator.with_writeback_native_continuation(
                NativeContinuationKind::ForceNodeResult,
                ir.root,
                span,
                &mut panic_roots,
                NativeContinuationEdge::ForceValue,
                |eval, slots| {
                    eval.with_native_continuation_edge(
                        NativeContinuationEdge::ForceValue,
                        ir.root,
                        |eval| {
                            assert!(eval.set_current_transient_value_stack_root(
                                slots.start,
                                Value::int(44),
                            ));
                            panic!("injected writeback-portal panic");
                        },
                    )
                },
            );
        }));
        assert!(outcome.is_err());
        assert!(panic_roots[0].raw_eq(Value::int(44)));
        assert!(evaluator.transient_value_stack_roots().is_empty());
        let snapshot = evaluator.native_continuation_snapshot();
        assert_eq!(snapshot.active_frames, 0);
        assert_eq!(snapshot.active_roots, 0);
        assert_eq!(snapshot.imbalances, 0);
    }

    #[test]
    fn terminal_writeback_portal_reloads_without_a_read_only_shadow_copy() {
        let ir = aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str("null").expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.native_continuation_shadow = Some(NativeContinuationShadow::new());
        let span = evaluator.node(ir.root).expect("root exists").span;
        let replacement = evaluator
            .heap
            .alloc_string(NixString::from_bytes(b"relocated".to_vec()))
            .expect("replacement allocates");
        let mut roots = [Value::null()];

        let observed = evaluator
            .with_terminal_writeback_native_continuation(
                NativeContinuationKind::CanaryCompletion,
                ir.root,
                span,
                &mut roots,
                |eval, slots| {
                    let snapshot = eval.native_continuation_snapshot();
                    assert_eq!(snapshot.active_frames, 1);
                    assert_eq!(snapshot.active_roots, 0);
                    assert_eq!(eval.transient_value_stack_roots().len(), 1);
                    assert!(eval.set_current_transient_value_stack_root(slots.start, replacement));
                    eval.current_transient_value_stack_root(slots.start)
                        .ok_or_else(|| {
                            TreeWalkError::new(
                                TreeWalkErrorKind::SafepointRootStackLengthOverflow { id: ir.root },
                                span,
                            )
                        })
                },
            )
            .expect("terminal portal succeeds");

        assert!(observed.raw_eq(replacement));
        assert!(roots[0].raw_eq(replacement));
        assert!(evaluator.transient_value_stack_roots().is_empty());
        let snapshot = evaluator.native_continuation_snapshot();
        assert_eq!(snapshot.active_frames, 0);
        assert_eq!(snapshot.active_roots, 0);
        assert_eq!(snapshot.imbalances, 0);
    }

    #[test]
    fn missing_permit_is_retained_as_uncovered() {
        let mut shadow = NativeContinuationShadow::new();
        let token = shadow
            .begin_edge(
                NativeContinuationEdge::EvalNode,
                EvalModuleId::ROOT,
                IrId::new(7),
                NativeContinuationSiteClass::Int,
            )
            .unwrap_or_else(|| panic!("bounded edge frame should fit"));
        let snapshot = shadow.snapshot();
        assert_eq!(snapshot.uncovered_active, 1);
        assert_eq!(snapshot.uncovered_entries, 1);
        assert!(!snapshot.reconciled());
        shadow.finish(token);
        let after = shadow.snapshot();
        assert_eq!(after.active_frames, 0);
        assert_eq!(after.uncovered_entries, 1);
        assert!(after.reconciled());
    }

    #[test]
    fn matching_one_shot_permit_covers_exactly_one_child() {
        let mut shadow = NativeContinuationShadow::new();
        let parent = shadow
            .begin(
                NativeContinuationFrameKind::Semantic(NativeContinuationKind::FoldCanary),
                EvalModuleId::ROOT,
                IrId::new(1),
                NativeContinuationSiteClass::Let,
                &[Value::int(1)],
                Some(NativeContinuationEdge::EvalNode),
                true,
            )
            .unwrap_or_else(|| panic!("bounded parent frame should fit"));
        let child = shadow
            .begin_edge(
                NativeContinuationEdge::EvalNode,
                EvalModuleId::ROOT,
                IrId::new(2),
                NativeContinuationSiteClass::Int,
            )
            .unwrap_or_else(|| panic!("bounded child frame should fit"));
        assert_eq!(shadow.snapshot().uncovered_active, 0);
        shadow.finish(child);
        let second = shadow
            .begin_edge(
                NativeContinuationEdge::EvalNode,
                EvalModuleId::ROOT,
                IrId::new(3),
                NativeContinuationSiteClass::Int,
            )
            .unwrap_or_else(|| panic!("bounded second frame should fit"));
        assert_eq!(shadow.snapshot().uncovered_active, 1);
        shadow.finish(second);
        shadow.finish(parent);
    }

    #[test]
    fn overflow_fails_closed_without_partial_push() {
        let mut shadow = NativeContinuationShadow::new();
        let roots = vec![Value::null(); ROOT_CAP + 1];
        assert!(
            shadow
                .begin(
                    NativeContinuationFrameKind::Semantic(NativeContinuationKind::CanaryPublish,),
                    EvalModuleId::ROOT,
                    IrId::new(1),
                    NativeContinuationSiteClass::AttrSet,
                    &roots,
                    None,
                    true,
                )
                .is_none()
        );
        let snapshot = shadow.snapshot();
        assert_eq!(snapshot.active_frames, 0);
        assert_eq!(snapshot.active_overflow_frames, 1);
        assert_eq!(snapshot.active_roots, 0);
        assert_eq!(snapshot.overflows, 1);
        assert!(!snapshot.reconciled());
        shadow.finish_overflow();
        let after = shadow.snapshot();
        assert_eq!(after.active_overflow_frames, 0);
        assert_eq!(after.overflows, 1);
        assert!(after.reconciled());
    }

    #[test]
    fn active_overflow_balances_only_at_its_matching_finish() {
        let mut shadow = NativeContinuationShadow::new();
        let roots = vec![Value::null(); ROOT_CAP + 1];
        assert!(shadow
            .begin(
                NativeContinuationFrameKind::Semantic(NativeContinuationKind::CanaryCompletion,),
                EvalModuleId::ROOT,
                IrId::new(9),
                NativeContinuationSiteClass::PrimOp,
                &roots,
                None,
                true,
            )
            .is_none());
        assert_eq!(shadow.snapshot().active_overflow_frames, 1);
        assert!(!shadow.snapshot().reconciled());
        shadow.finish_overflow();
        assert_eq!(shadow.snapshot().active_overflow_frames, 0);
        assert!(shadow.snapshot().reconciled());
    }

    #[test]
    fn disabled_shadow_does_not_finish_an_overflow() {
        let ir = aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str("null").expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.native_continuation_shadow = None;
        evaluator.finish_native_continuation_edge(None);
        assert_eq!(evaluator.native_continuation_snapshot().imbalances, 0);
    }

    #[test]
    fn selected_frame_records_observe_the_active_stack() {
        let mut shadow = NativeContinuationShadow::new();
        let parent = shadow
            .begin(
                NativeContinuationFrameKind::Semantic(NativeContinuationKind::FoldCanary),
                EvalModuleId::ROOT,
                IrId::new(11),
                NativeContinuationSiteClass::Let,
                &[Value::int(1)],
                Some(NativeContinuationEdge::ForceValue),
                true,
            )
            .unwrap_or_else(|| panic!("bounded parent frame should fit"));
        let child = shadow
            .begin_edge(
                NativeContinuationEdge::ForceValue,
                EvalModuleId::ROOT,
                IrId::new(12),
                NativeContinuationSiteClass::LocalVar,
            )
            .unwrap_or_else(|| panic!("bounded child frame should fit"));
        let records = shadow.active_frame_records().collect::<Vec<_>>();
        assert_eq!(
            records,
            vec![
                (0, "fold_canary", "let", 0, 11, 1, true, "none", 0, 0),
                (1, "force_value", "local_var", 0, 12, 0, true, "none", 0, 0,),
            ]
        );
        assert_eq!(
            shadow.selected_class_counts(
                NativeContinuationEdge::ForceValue,
                NativeContinuationSiteClass::LocalVar,
            ),
            (1, 0),
        );
        shadow.finish(child);
        shadow.finish(parent);
    }

    #[test]
    fn caller_locations_remain_distinct_across_explicit_wrapper_propagation() {
        fn first_location() -> &'static Location<'static> {
            Location::caller()
        }
        fn second_location() -> &'static Location<'static> {
            Location::caller()
        }

        let first = first_location();
        let second = second_location();
        assert_ne!(first.line(), second.line());

        let mut shadow = NativeContinuationShadow::new();
        let first_token = shadow
            .begin_edge_at(
                NativeContinuationEdge::EvalNode,
                EvalModuleId::ROOT,
                IrId::new(1),
                NativeContinuationSiteClass::Int,
                Some(first),
            )
            .unwrap_or_else(|| panic!("first caller frame should fit"));
        let first_record = shadow
            .active_frame_records()
            .next()
            .unwrap_or_else(|| panic!("first caller frame should be active"));
        assert_eq!(first_record.7, file!());
        assert_eq!(first_record.8, first.line());
        shadow.finish(first_token);

        let second_token = shadow
            .begin_edge_at(
                NativeContinuationEdge::ForceValue,
                EvalModuleId::ROOT,
                IrId::new(2),
                NativeContinuationSiteClass::Int,
                Some(second),
            )
            .unwrap_or_else(|| panic!("second caller frame should fit"));
        let second_record = shadow
            .active_frame_records()
            .next()
            .unwrap_or_else(|| panic!("second caller frame should be active"));
        assert_eq!(second_record.7, file!());
        assert_eq!(second_record.8, second.line());
        assert_ne!(first_record.8, second_record.8);
        shadow.finish(second_token);
    }

    #[test]
    fn bounded_root_manifest_balances_success_error_and_panic() {
        let ir = aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str("null").expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.native_continuation_shadow = Some(NativeContinuationShadow::new());

        evaluator
            .with_bounded_native_root_manifest(
                NativeContinuationKind::DerivationArgumentForce,
                ir.root,
                2,
                NativeContinuationEdge::EvalNode,
                |roots| roots.extend_from_slice(&[Value::int(1), Value::int(2)]),
                |eval| {
                    eval.with_native_continuation_edge(
                        NativeContinuationEdge::EvalNode,
                        ir.root,
                        |eval| {
                            let snapshot = eval.native_continuation_snapshot();
                            assert_eq!(snapshot.active_frames, 2);
                            assert_eq!(snapshot.covered_frames, 2);
                            assert_eq!(snapshot.active_roots, 2);
                            Ok(())
                        },
                    )
                },
            )
            .expect("bounded manifest success returns");

        assert!(
            evaluator
                .with_bounded_native_root_manifest(
                    NativeContinuationKind::DerivationArgumentForce,
                    ir.root,
                    1,
                    NativeContinuationEdge::EvalNode,
                    |roots| roots.push(Value::null()),
                    |eval| eval.eval_node_from_caller(IrId::new(u32::MAX), Location::caller()),
                )
                .is_err()
        );

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), TreeWalkError> = evaluator.with_bounded_native_root_manifest(
                NativeContinuationKind::DerivationArgumentForce,
                ir.root,
                1,
                NativeContinuationEdge::EvalNode,
                |roots| roots.push(Value::null()),
                |_| panic!("injected manifest panic"),
            );
        }));
        assert!(outcome.is_err());
        let snapshot = evaluator.native_continuation_snapshot();
        assert_eq!(snapshot.active_frames, 0);
        assert_eq!(snapshot.active_roots, 0);
        assert_eq!(snapshot.imbalances, 0);
    }

    #[test]
    fn bounded_root_manifest_declines_caps_and_incomplete_builds() {
        let ir = aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str("null").expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.native_continuation_shadow = Some(NativeContinuationShadow::new());
        let cap_builder_called = std::cell::Cell::new(false);

        evaluator
            .with_bounded_native_root_manifest(
                NativeContinuationKind::DerivationAttributeForce,
                ir.root,
                ROOT_CAP.saturating_add(1),
                NativeContinuationEdge::ForceValue,
                |_| cap_builder_called.set(true),
                |eval| {
                    assert_eq!(eval.native_continuation_snapshot().active_frames, 0);
                    Ok(())
                },
            )
            .expect("cap decline preserves body result");
        assert!(!cap_builder_called.get());

        evaluator
            .with_bounded_native_root_manifest(
                NativeContinuationKind::DerivationAttributeForce,
                ir.root,
                2,
                NativeContinuationEdge::ForceValue,
                |roots| roots.push(Value::null()),
                |eval| {
                    assert_eq!(eval.native_continuation_snapshot().active_frames, 0);
                    Ok(())
                },
            )
            .expect("incomplete manifest preserves body result");
        assert_eq!(evaluator.native_continuation_snapshot().active_roots, 0);
    }

    #[test]
    fn generic_transition_batch_covers_expected_edges_and_retains_roots() {
        let mut shadow = NativeContinuationShadow::new();
        let node_parent = shadow
            .begin(
                NativeContinuationFrameKind::Semantic(NativeContinuationKind::NodeThunkBody),
                EvalModuleId::ROOT,
                IrId::new(20),
                NativeContinuationSiteClass::LocalVar,
                &[],
                Some(NativeContinuationEdge::EvalNode),
                true,
            )
            .unwrap_or_else(|| panic!("bounded node parent should fit"));
        let node_child = shadow
            .begin_edge(
                NativeContinuationEdge::EvalNode,
                EvalModuleId::ROOT,
                IrId::new(20),
                NativeContinuationSiteClass::LocalVar,
            )
            .unwrap_or_else(|| panic!("bounded node child should fit"));
        let force_parent = shadow
            .begin(
                NativeContinuationFrameKind::Semantic(NativeContinuationKind::ForceNodeResult),
                EvalModuleId::ROOT,
                IrId::new(21),
                NativeContinuationSiteClass::UpvalVar,
                &[Value::int(1)],
                Some(NativeContinuationEdge::ForceValue),
                true,
            )
            .unwrap_or_else(|| panic!("bounded force parent should fit"));
        let force_child = shadow
            .begin_edge(
                NativeContinuationEdge::ForceValue,
                EvalModuleId::ROOT,
                IrId::new(21),
                NativeContinuationSiteClass::UpvalVar,
            )
            .unwrap_or_else(|| panic!("bounded force child should fit"));
        let apply_parent = shadow
            .begin(
                NativeContinuationFrameKind::Semantic(NativeContinuationKind::ApplyLambdaPortal),
                EvalModuleId::ROOT,
                IrId::new(22),
                NativeContinuationSiteClass::Apply,
                &[Value::int(2), Value::int(3)],
                Some(NativeContinuationEdge::ApplyLambda),
                true,
            )
            .unwrap_or_else(|| panic!("bounded apply parent should fit"));
        let apply_child = shadow
            .begin_edge(
                NativeContinuationEdge::ApplyLambda,
                EvalModuleId::ROOT,
                IrId::new(22),
                NativeContinuationSiteClass::Apply,
            )
            .unwrap_or_else(|| panic!("bounded apply child should fit"));

        let records = shadow.active_frame_records().collect::<Vec<_>>();
        assert_eq!(records[0].1, "node_thunk_body");
        assert_eq!(records[2].1, "force_node_result");
        assert_eq!(records[2].5, 1);
        assert_eq!(records[4].1, "apply_lambda_portal");
        assert_eq!(records[4].5, 2);
        let snapshot = shadow.snapshot();
        assert_eq!(snapshot.active_frames, 6);
        assert_eq!(snapshot.active_roots, 3);
        assert_eq!(snapshot.covered_frames, 6);
        assert_eq!(snapshot.uncovered_active, 0);

        shadow.finish(apply_child);
        shadow.finish(apply_parent);
        shadow.finish(force_child);
        shadow.finish(force_parent);
        shadow.finish(node_child);
        shadow.finish(node_parent);
        let after = shadow.snapshot();
        assert_eq!(after.active_frames, 0);
        assert_eq!(after.active_roots, 0);
        assert_eq!(after.imbalances, 0);
    }

    #[test]
    fn second_transition_batch_covers_only_its_declared_child_and_roots() {
        let cases = [
            (
                NativeContinuationKind::LambdaBody,
                "lambda_body",
                NativeContinuationEdge::EvalNode,
                0,
            ),
            (
                NativeContinuationKind::LetBody,
                "let_body",
                NativeContinuationEdge::EvalNode,
                0,
            ),
            (
                NativeContinuationKind::InterpChild,
                "interp_child",
                NativeContinuationEdge::EvalNode,
                0,
            ),
            (
                NativeContinuationKind::InterpolationHookForce,
                "interpolation_hook_force",
                NativeContinuationEdge::ForceValue,
                1,
            ),
            (
                NativeContinuationKind::InterpolationOutPathForce,
                "interpolation_out_path_force",
                NativeContinuationEdge::ForceValue,
                0,
            ),
            (
                NativeContinuationKind::LazyDemandForce,
                "lazy_demand_force",
                NativeContinuationEdge::ForceValue,
                0,
            ),
            (
                NativeContinuationKind::CallableForce,
                "callable_force",
                NativeContinuationEdge::ForceValue,
                0,
            ),
        ];
        let mut shadow = NativeContinuationShadow::new();
        for (index, (kind, name, edge, root_len)) in cases.into_iter().enumerate() {
            let roots = [Value::int(index as i64)];
            let roots = &roots[..root_len];
            let site = IrId::new(index as u32 + 30);
            let parent = shadow
                .begin(
                    NativeContinuationFrameKind::Semantic(kind),
                    EvalModuleId::ROOT,
                    site,
                    NativeContinuationSiteClass::PrimOp,
                    roots,
                    Some(edge),
                    true,
                )
                .unwrap_or_else(|| panic!("bounded second-batch parent should fit"));
            let child = shadow
                .begin_edge(
                    edge,
                    EvalModuleId::ROOT,
                    site,
                    NativeContinuationSiteClass::PrimOp,
                )
                .unwrap_or_else(|| panic!("bounded second-batch child should fit"));
            let records = shadow.active_frame_records().collect::<Vec<_>>();
            assert_eq!(records[0].1, name);
            assert_eq!(records[0].5, root_len);
            assert!(records[0].6);
            assert!(records[1].6);
            assert_eq!(shadow.snapshot().uncovered_active, 0);
            shadow.finish(child);
            shadow.finish(parent);
        }
        let snapshot = shadow.snapshot();
        assert_eq!(snapshot.active_frames, 0);
        assert_eq!(snapshot.active_roots, 0);
        assert_eq!(snapshot.imbalances, 0);
    }

    #[test]
    fn third_transition_covered_kinds_authorize_but_diagnostic_marker_never_does() {
        let mut shadow = NativeContinuationShadow::new();
        let covered_cases = [
            NativeContinuationKind::IfCondition,
            NativeContinuationKind::IfBranch,
            NativeContinuationKind::BinaryLhs,
            NativeContinuationKind::SelectReceiver,
        ];
        for (index, kind) in covered_cases.into_iter().enumerate() {
            let site = IrId::new(index as u32 + 40);
            let parent = shadow
                .begin(
                    NativeContinuationFrameKind::Semantic(kind),
                    EvalModuleId::ROOT,
                    site,
                    NativeContinuationSiteClass::If,
                    &[],
                    Some(NativeContinuationEdge::EvalNode),
                    true,
                )
                .unwrap_or_else(|| panic!("bounded covered parent should fit"));
            let child = shadow
                .begin_edge(
                    NativeContinuationEdge::EvalNode,
                    EvalModuleId::ROOT,
                    site,
                    NativeContinuationSiteClass::Int,
                )
                .unwrap_or_else(|| panic!("bounded covered child should fit"));
            assert_eq!(shadow.snapshot().uncovered_active, 0);
            shadow.finish(child);
            shadow.finish(parent);
        }

        let diagnostic_cases = [
            (NativeContinuationKind::BinaryRhs, "binary_rhs"),
            (NativeContinuationKind::BinaryPipeLeft, "binary_pipe_left"),
            (NativeContinuationKind::BinaryPipeRight, "binary_pipe_right"),
            (
                NativeContinuationKind::SelectDynamicAttr,
                "select_dynamic_attr",
            ),
            (NativeContinuationKind::SelectDefault, "select_default"),
            (
                NativeContinuationKind::SelectStaticDefault,
                "select_static_default",
            ),
            (NativeContinuationKind::PrimOpEvalChild, "primop_eval_child"),
            (NativeContinuationKind::PrimOpForceLeaf, "primop_force_leaf"),
            (
                NativeContinuationKind::LazyFoldlInitialForceLeaf,
                "lazy_foldl_initial_force_leaf",
            ),
            (
                NativeContinuationKind::DemandedConsumedForceLeaf,
                "demanded_consumed_force_leaf",
            ),
            (
                NativeContinuationKind::DemandedPrimaryForceLeaf,
                "demanded_primary_force_leaf",
            ),
            (
                NativeContinuationKind::DemandedRetryForceLeaf,
                "demanded_retry_force_leaf",
            ),
        ];
        for (index, (kind, name)) in diagnostic_cases.into_iter().enumerate() {
            let site = IrId::new(index as u32 + 50);
            let parent = shadow
                .begin(
                    NativeContinuationFrameKind::Semantic(kind),
                    EvalModuleId::ROOT,
                    site,
                    NativeContinuationSiteClass::BinOp,
                    &[],
                    Some(NativeContinuationEdge::EvalNode),
                    false,
                )
                .unwrap_or_else(|| panic!("bounded diagnostic parent should fit"));
            let child = shadow
                .begin_edge(
                    NativeContinuationEdge::EvalNode,
                    EvalModuleId::ROOT,
                    site,
                    NativeContinuationSiteClass::Int,
                )
                .unwrap_or_else(|| panic!("bounded diagnostic child should fit"));
            let records = shadow.active_frame_records().collect::<Vec<_>>();
            assert_eq!(records[0].1, name);
            assert!(!records[0].6);
            assert!(!records[1].6);
            assert_eq!(shadow.snapshot().uncovered_active, 2);
            shadow.finish(child);
            shadow.finish(parent);
        }
        assert_eq!(shadow.snapshot().active_frames, 0);
    }

    #[test]
    fn diagnostic_marker_balances_success_error_and_panic() {
        let ir = aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str("null").expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.native_continuation_shadow = Some(NativeContinuationShadow::new());

        evaluator
            .with_uncovered_native_continuation_marker(
                NativeContinuationKind::PrimOpEvalChild,
                ir.root,
                |_| Ok(()),
            )
            .expect("diagnostic success returns");
        assert_eq!(evaluator.native_continuation_snapshot().active_frames, 0);

        assert!(
            evaluator
                .eval_uncovered_primop_child(IrId::new(u32::MAX))
                .is_err()
        );
        assert_eq!(evaluator.native_continuation_snapshot().active_frames, 0);

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), TreeWalkError> = evaluator.with_uncovered_native_continuation_marker(
                NativeContinuationKind::PrimOpForceLeaf,
                ir.root,
                |_| panic!("injected diagnostic panic"),
            );
        }));
        assert!(outcome.is_err());
        let snapshot = evaluator.native_continuation_snapshot();
        assert_eq!(snapshot.active_frames, 0);
        assert_eq!(snapshot.active_roots, 0);
        assert_eq!(snapshot.imbalances, 0);
    }

    #[test]
    fn fallback_marker_wraps_only_edges_without_an_existing_portal() {
        let ir = aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str("null").expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.native_continuation_shadow = Some(NativeContinuationShadow::new());

        evaluator
            .with_native_primop_context(
                NativePrimOpContextMode::ResolvedInlineDirect,
                ir.root,
                Symbol::new(7),
                |eval| {
                    eval.with_attributed_native_continuation_edge(
                        NativeContinuationEdge::EvalNode,
                        NativeContinuationKind::PrimOpEvalChild,
                        ir.root,
                        Location::caller(),
                        |eval| {
                            let records = eval
                                .native_continuation_shadow
                                .as_ref()
                                .expect("shadow remains enabled")
                                .active_frame_records()
                                .collect::<Vec<_>>();
                            assert_eq!(records.len(), 2);
                            assert_eq!(records[0].1, "primop_eval_child");
                            assert_eq!(records[1].1, "eval_node");
                            assert!(!records[0].6);
                            assert!(!records[1].6);
                            Ok(())
                        },
                    )
                },
            )
            .expect("fallback edge balances");

        evaluator
            .with_native_primop_context(
                NativePrimOpContextMode::CachedDirect,
                ir.root,
                Symbol::new(8),
                |eval| {
                    eval.with_uncovered_native_continuation_marker(
                        NativeContinuationKind::PrimOpEvalChild,
                        ir.root,
                        |eval| {
                            eval.with_attributed_native_continuation_edge(
                                NativeContinuationEdge::EvalNode,
                                NativeContinuationKind::PrimOpEvalChild,
                                ir.root,
                                Location::caller(),
                                |eval| {
                                    let records = eval
                                        .native_continuation_shadow
                                        .as_ref()
                                        .expect("shadow remains enabled")
                                        .active_frame_records()
                                        .collect::<Vec<_>>();
                                    assert_eq!(records.len(), 2);
                                    assert_eq!(records[0].1, "primop_eval_child");
                                    assert_eq!(records[1].1, "eval_node");
                                    Ok(())
                                },
                            )
                        },
                    )
                },
            )
            .expect("existing diagnostic portal is not duplicated");

        let snapshot = evaluator.native_continuation_snapshot();
        assert_eq!(snapshot.active_frames, 0);
        assert_eq!(snapshot.imbalances, 0);
        assert!(
            evaluator
                .native_continuation_shadow
                .as_ref()
                .expect("shadow remains enabled")
                .primop_contexts
                .is_empty()
        );
    }

    #[test]
    fn proof_permit_bypasses_the_diagnostic_fallback() {
        let ir = aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str("null").expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.native_continuation_shadow = Some(NativeContinuationShadow::new());

        evaluator
            .with_nonmoving_native_continuation(
                NativeContinuationKind::IfBranch,
                ir.root,
                &[],
                Some(NativeContinuationEdge::EvalNode),
                |eval| {
                    eval.with_attributed_native_continuation_edge(
                        NativeContinuationEdge::EvalNode,
                        NativeContinuationKind::PrimOpEvalChild,
                        ir.root,
                        Location::caller(),
                        |eval| {
                            let records = eval
                                .native_continuation_shadow
                                .as_ref()
                                .expect("shadow remains enabled")
                                .active_frame_records()
                                .collect::<Vec<_>>();
                            assert_eq!(records.len(), 2);
                            assert_eq!(records[0].1, "if_branch");
                            assert_eq!(records[1].1, "eval_node");
                            assert!(records[0].6);
                            assert!(records[1].6);
                            Ok(())
                        },
                    )
                },
            )
            .expect("covered edge balances");

        assert_eq!(
            evaluator.native_continuation_snapshot().uncovered_entries,
            0
        );
    }

    #[test]
    fn disabled_diagnostic_portals_take_the_direct_path() {
        let ir = aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str("null").expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers");
        let mut evaluator = TreeWalk::new(&ir);
        assert!(!evaluator.native_continuation_shadow_enabled());
        assert!(
            evaluator
                .eval_uncovered_primop_child(ir.root)
                .expect("direct child evaluates")
                .raw_eq(Value::null())
        );
        let span = evaluator.node(ir.root).unwrap().span;
        assert!(
            evaluator
                .force_uncovered_primop_leaf(ir.root, span, Value::null())
                .expect("direct value forces")
                .raw_eq(Value::null())
        );
        assert_eq!(evaluator.native_continuation_snapshot().active_frames, 0);
    }

    #[test]
    fn representative_lowered_ir_kinds_have_stable_site_classes() {
        let cases = [
            ("1", NativeContinuationSiteClass::Int),
            ("x: x", NativeContinuationSiteClass::Lambda),
            ("let x = 1; in x", NativeContinuationSiteClass::Let),
            ("(x: x) 1", NativeContinuationSiteClass::Apply),
            ("{}.missing or null", NativeContinuationSiteClass::Select),
        ];
        for (source, expected) in cases {
            let ir = aos_nix_dialect::nix_lower(
                crate::compile::resolve(crate::syntax::parse_str(source).expect("source parses"))
                    .expect("source resolves"),
            )
            .expect("source lowers");
            let evaluator = TreeWalk::new(&ir);
            assert_eq!(
                evaluator.native_continuation_site_class(ir.root),
                expected,
                "source {source:?}",
            );
        }
    }

    #[test]
    fn unknown_site_class_is_reportable_and_fails_coverage() {
        let ir = aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str("null").expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers");
        let evaluator = TreeWalk::new(&ir);
        let class = evaluator.native_continuation_site_class(IrId::new(u32::MAX));
        assert_eq!(class, NativeContinuationSiteClass::Unknown);

        let mut shadow = NativeContinuationShadow::new();
        let parent = shadow
            .begin(
                NativeContinuationFrameKind::Semantic(NativeContinuationKind::FoldCanary),
                EvalModuleId::ROOT,
                ir.root,
                NativeContinuationSiteClass::Null,
                &[],
                Some(NativeContinuationEdge::EvalNode),
                true,
            )
            .unwrap_or_else(|| panic!("bounded parent frame should fit"));
        let child = shadow
            .begin_edge(
                NativeContinuationEdge::EvalNode,
                EvalModuleId::ROOT,
                IrId::new(u32::MAX),
                class,
            )
            .unwrap_or_else(|| panic!("bounded child frame should fit"));
        let records = shadow.active_frame_records().collect::<Vec<_>>();
        assert_eq!(records[1].2, "unknown");
        assert!(!records[1].6);
        assert_eq!(
            shadow.selected_class_counts(
                NativeContinuationEdge::EvalNode,
                NativeContinuationSiteClass::Unknown,
            ),
            (0, 1),
        );
        assert_eq!(shadow.snapshot().uncovered_active, 1);
        shadow.finish(child);
        shadow.finish(parent);
    }

    #[test]
    fn configured_frame_and_root_caps_fit_the_shadow_storage_cap() {
        let maximum_modeled_storage = FRAME_CAP
            .saturating_mul(std::mem::size_of::<NativeContinuationFrame>())
            .saturating_add(ROOT_CAP.saturating_mul(std::mem::size_of::<Value>()))
            .saturating_add(
                PRIMOP_CONTEXT_CAP.saturating_mul(std::mem::size_of::<NativePrimOpContext>()),
            );
        assert!(maximum_modeled_storage <= STORAGE_CAP_BYTES);
    }

    #[test]
    fn primop_context_cap_coalesces_without_reporting_allocation_overflow() {
        let mut shadow = NativeContinuationShadow::new();
        let mut tokens = Vec::new();
        for index in 0..PRIMOP_CONTEXT_CAP {
            tokens.push(shadow.begin_primop_context(
                NativePrimOpContextMode::CachedDirect,
                EvalModuleId::ROOT,
                IrId::new(index as u32),
                Symbol::new(index as u32),
            ));
        }
        assert!(
            shadow
                .begin_primop_context(
                    NativePrimOpContextMode::CachedDirect,
                    EvalModuleId::ROOT,
                    IrId::new(PRIMOP_CONTEXT_CAP as u32),
                    Symbol::new(PRIMOP_CONTEXT_CAP as u32),
                )
                .is_none()
        );
        let snapshot = shadow.snapshot();
        assert_eq!(snapshot.primop_context_coalesced_entries, 1);
        assert_eq!(snapshot.primop_context_overflows, 0);
        for token in tokens.into_iter().rev() {
            shadow.finish_primop_context(token, EvalModuleId::ROOT);
        }
        assert_eq!(shadow.snapshot().active_primop_contexts, 0);
    }

    #[test]
    fn semantic_roots_enter_the_nested_nonmoving_inventory() {
        let ir = aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str("null").expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.native_continuation_shadow = Some(NativeContinuationShadow::new());
        let value = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(ir.root))
            .expect("test thunk allocates");
        evaluator
            .with_nonmoving_native_continuation(
                NativeContinuationKind::CanaryPublish,
                ir.root,
                &[value],
                None,
                |eval| {
                    let (_, inventory) = eval
                        .nested_nonmoving_root_set(Value::null())
                        .expect("nested root inventory builds");
                    assert_eq!(inventory.native_shadow_values, 1);
                    Ok(())
                },
            )
            .expect("shadowed inventory builds");
        let snapshot = evaluator.native_continuation_snapshot();
        assert_eq!(snapshot.active_frames, 0);
        assert_eq!(snapshot.active_roots, 0);
    }

    #[test]
    fn panic_restores_semantic_frame_and_roots() {
        let ir = aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str("null").expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.native_continuation_shadow = Some(NativeContinuationShadow::new());
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), TreeWalkError> = evaluator.with_nonmoving_native_continuation(
                NativeContinuationKind::FoldCanary,
                ir.root,
                &[Value::null()],
                None,
                |_| panic!("injected continuation panic"),
            );
        }));
        assert!(outcome.is_err());
        let snapshot = evaluator.native_continuation_snapshot();
        assert_eq!(snapshot.active_frames, 0);
        assert_eq!(snapshot.active_roots, 0);
        assert_eq!(snapshot.imbalances, 0);
    }

    #[test]
    fn panic_restores_edge_frame() {
        let ir = aos_nix_dialect::nix_lower(
            crate::compile::resolve(crate::syntax::parse_str("null").expect("source parses"))
                .expect("source resolves"),
        )
        .expect("source lowers");
        let mut evaluator = TreeWalk::new(&ir);
        evaluator.native_continuation_shadow = Some(NativeContinuationShadow::new());
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), TreeWalkError> = evaluator.with_native_continuation_edge(
                NativeContinuationEdge::EvalNode,
                ir.root,
                |_| panic!("injected edge panic"),
            );
        }));
        assert!(outcome.is_err());
        let snapshot = evaluator.native_continuation_snapshot();
        assert_eq!(snapshot.active_frames, 0);
        assert_eq!(snapshot.active_roots, 0);
        assert_eq!(snapshot.imbalances, 0);
    }
}
