//! Per-expression analysis facts attached to lowered IR.
//!
//! Whole-program optimization passes refine these facts over time. Until a
//! proof exists, every node carries conservative facts: unknown strictness,
//! many-use cardinality, and escaping allocation behavior.
//!
//! # Demand fact semantics
//!
//! Strictness facts are *relative to the node's nearest enclosing execution
//! unit*: the module root, the body of a `ThunkAlloc`, or the body of a
//! lambda. A demand proof on a node says "whenever that unit executes, this
//! node is evaluated", not "this node is evaluated whenever the module root
//! is". Consumers that act on a node's facts do so at the moment the node is
//! itself evaluated, so the relative reading is the one they need.
//!
//! The demand lattice is ordered `Unknown < Demanded < DemandedBeforeEffect`.
//! Only [`Strictness::DemandedBeforeEffect`] licenses eager lowering
//! ([`BindingLowering::Eager`] / [`BindingLowering::Scalar`]): evaluating a
//! binding at its allocation site is observationally invisible only when the
//! lazy program would have forced it before any observable event —
//! `throw`, `abort`, a failed `assert`, `trace` output, or divergence — could
//! occur (soundness rule S2). [`Strictness::Demanded`] proves S1 only
//! ("forced on every normally-completing path") and is consumed as a fan-out
//! hint and by passes that need existence-of-demand, never as an eager
//! license.

use crate::scope::Upvalue;
use crate::syntax::Symbol;

use super::IrId;

/// Whether evaluating an enclosing expression is known to demand this node.
///
/// Levels are relative to the node's nearest enclosing execution unit (module
/// root, thunk body, or lambda body); see the module documentation for the
/// exact reading and the soundness rules each level carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Strictness {
    /// The node is not proven to be demanded, so lazy lowering must be kept.
    #[default]
    Unknown,
    /// The node is proven to be evaluated on every normally-completing path
    /// of its enclosing execution unit (S1), but possibly only after another
    /// observable event may occur. Licenses fan-out hints, never eagerness.
    Demanded,
    /// The node is proven to be evaluated before any observable event of its
    /// enclosing execution unit can occur (S1 + S2). This is the only level
    /// that licenses eager lowering.
    DemandedBeforeEffect,
}

impl Strictness {
    /// Returns whether any positive demand proof exists (S1).
    pub const fn is_demanded(self) -> bool {
        !matches!(self, Self::Unknown)
    }

    /// Returns whether the proof licenses eager evaluation (S1 + S2).
    pub const fn is_demanded_before_effect(self) -> bool {
        matches!(self, Self::DemandedBeforeEffect)
    }
}

/// How often a lowered binding or expression is known to be entered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Cardinality {
    /// The node is proven unused.
    Absent,
    /// The node is proven to be entered at most once.
    Once,
    /// The node may be entered more than once.
    #[default]
    Many,
}

/// Whether a value allocated by this node is known to stay frame-local.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Escape {
    /// The value is proven not to escape its allocating frame.
    NoEscape,
    /// The value may escape its allocating frame.
    #[default]
    Escapes,
}

/// When a lambda call demands an argument or one of its formal values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LambdaDemand {
    /// The call itself demands the value at the recorded level.
    Unconditional(Strictness),
    /// The call demands the value only when its result reaches WHNF.
    IfResultForced(Strictness),
}

impl LambdaDemand {
    /// Returns the demand licensed at a call site with the given result demand.
    pub fn at_call(self, result: Strictness) -> Strictness {
        match self {
            Self::Unconditional(level) => level,
            Self::IfResultForced(level) => level.min(result),
        }
    }
}

/// A statically described set of attribute keys demanded through a formal alias.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum LambdaAttrKeys {
    /// Exactly these keys are demanded.
    Only(Box<[Symbol]>),
    /// Every key except these keys is demanded.
    AllExcept(Box<[Symbol]>),
}

impl LambdaAttrKeys {
    /// Returns whether the key belongs to this demand set.
    pub fn contains(&self, key: Symbol) -> bool {
        match self {
            Self::Only(keys) => keys.contains(&key),
            Self::AllExcept(keys) => !keys.contains(&key),
        }
    }

    /// Returns the symbols carried by this key-set encoding.
    pub fn symbols(&self) -> &[Symbol] {
        match self {
            Self::Only(keys) | Self::AllExcept(keys) => keys,
        }
    }

    /// Replaces the symbols carried by this key-set encoding.
    pub fn replace_symbols(&mut self, symbols: Box<[Symbol]>) {
        match self {
            Self::Only(keys) | Self::AllExcept(keys) => *keys = symbols,
        }
    }
}

/// Demand and escape facts for one formal-set slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LambdaFormalSummary {
    /// The value demand transferred to the caller's matching attribute.
    pub demand: LambdaDemand,
    /// Whether references through this formal slot can publish the value.
    pub escape: Escape,
}

/// Demand transferred through an `@` alias into derivation attribute assembly.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LambdaAttrValueSummary {
    /// The actual argument keys covered by this summary.
    pub keys: LambdaAttrKeys,
    /// The demand transferred to values stored under the covered keys.
    pub demand: LambdaDemand,
    /// Whether the aggregate alias can publish covered values.
    pub escape: Escape,
}

/// Persisted call-site facts for one lambda parameter frame.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LambdaCallSummary {
    /// The lambda's pattern node, used as the runtime closure lookup key.
    pub pattern: IrId,
    /// Demand placed on the whole argument value.
    pub argument_demand: LambdaDemand,
    /// Whether the whole argument can escape through the call.
    pub argument_escape: Escape,
    /// Per-slot demand and escape facts in formal-pattern order.
    pub formals: Box<[LambdaFormalSummary]>,
    /// Attribute-value demand transferred through a formal-set `@` alias.
    pub attr_values: Box<[LambdaAttrValueSummary]>,
}

/// Per-expression optimization facts attached to one IR node.
///
/// The default is intentionally conservative: unproven strictness keeps lazy
/// thunks, unproven cardinality keeps full update/blackhole machinery, and
/// unproven escape behavior keeps heap allocation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ExprFacts {
    /// Whether this node is proven demanded, and at which effect rank.
    pub strictness: Strictness,
    /// Whether this node is absent, single-entry, or many-entry.
    pub cardinality: Cardinality,
    /// Whether this node's allocation is proven frame-local.
    pub escape: Escape,
}

impl ExprFacts {
    /// Returns the conservative fact record used before analysis has proven more.
    pub const fn conservative() -> Self {
        Self {
            strictness: Strictness::Unknown,
            cardinality: Cardinality::Many,
            escape: Escape::Escapes,
        }
    }

    /// Returns the binding-lowering strategy licensed by these facts.
    ///
    /// Eager execution is licensed only by [`Strictness::DemandedBeforeEffect`]
    /// (S2: no observable event can be reordered by evaluating at the
    /// allocation site). Scalar replacement additionally requires a no-escape
    /// proof. [`Strictness::Demanded`] fails closed to a lazy thunk: it proves
    /// the binding is forced, not that forcing it early is invisible.
    pub const fn binding_lowering(self) -> BindingLowering {
        match (self.strictness, self.escape) {
            (Strictness::DemandedBeforeEffect, Escape::NoEscape) => BindingLowering::Scalar,
            (Strictness::DemandedBeforeEffect, Escape::Escapes) => BindingLowering::Eager,
            (Strictness::Unknown | Strictness::Demanded, _) => BindingLowering::Thunk,
        }
    }

    /// Returns whether this node is staged Strict+NoEscape for JIT tiers.
    ///
    /// A node that is both proven demanded before any observable event
    /// (S1 + S2) and frame-local may be lowered by a compiling tier as an
    /// eager, unboxed temporary: no thunk cell, no heap publication. This is
    /// a staging fact only — no current tier consumes it; the tier-1/tier-2
    /// lowering seams read it when their unboxed-temporary lowering lands.
    pub const fn jit_strict_no_escape_stage(self) -> bool {
        self.strictness.is_demanded_before_effect() && matches!(self.escape, Escape::NoEscape)
    }

    /// Returns the thunk-sharing mode licensed by these facts.
    ///
    /// Single-entry thunks are only safe when the cardinality proof says the
    /// thunk is entered at most once and the escape proof keeps it frame-local.
    /// A proof of absence licenses omitting the thunk entirely unless another
    /// fact contradicts it by proving the binding demanded at any level.
    pub const fn thunk_sharing(self) -> ThunkSharing {
        match (self.cardinality, self.strictness, self.escape) {
            (Cardinality::Absent, Strictness::Unknown, _) => ThunkSharing::Omit,
            (
                Cardinality::Absent,
                Strictness::Demanded | Strictness::DemandedBeforeEffect,
                _,
            )
            | (Cardinality::Once | Cardinality::Many, _, Escape::Escapes)
            | (Cardinality::Many, _, Escape::NoEscape) => ThunkSharing::Update,
            (Cardinality::Once, _, Escape::NoEscape) => ThunkSharing::SingleEntry,
        }
    }
}

/// Strategy for lowering one binding-position expression.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum BindingLowering {
    /// Allocate a lazy thunk and force it on demand.
    #[default]
    Thunk,
    /// Evaluate eagerly and pass the WHNF value directly.
    Eager,
    /// Evaluate eagerly and keep a non-escaping result out of the heap.
    Scalar,
}

/// Sharing/update machinery required for a thunk-like binding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ThunkSharing {
    /// Keep normal update and blackhole state for sharing and cycle detection.
    #[default]
    Update,
    /// Use a single-entry representation for a frame-local used-once thunk.
    SingleEntry,
    /// Omit code and storage for a proven-absent binding.
    Omit,
}

/// The free-variable capture plan computed for one allocation site.
///
/// A capture plan is produced for every lambda construction and thunk
/// allocation node. It names the value representation a runtime may use for
/// the site's captured lexical environment (the FV-5 flat-capture campaign's
/// input fact):
///
/// - [`CapturePlan::Flat`] proves the site's body reads at most the listed
///   `(depth, slot)` coordinates from the environment active at the
///   allocation site, so a consumer may copy exactly those slots instead of
///   retaining the whole shared frame chain. Coordinates are relative to the
///   allocation-site environment: depth 0 is its innermost frame.
/// - [`CapturePlan::SharedChain`] keeps the conservative whole-chain capture,
///   with the reason the flat plan was declined.
///
/// The plan covers only the lexical frame chain. Dynamic `with` scopes and
/// scoped-import globals are separate captures and are unaffected, except
/// that a body probing dynamic scope declines the flat plan entirely (its
/// probes fall back to lexically captured frames through the resolver's
/// chain metadata).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CapturePlan {
    /// Capture exactly these environment coordinates.
    Flat(Box<[Upvalue]>),
    /// Keep capturing the whole shared frame chain.
    SharedChain(SharedChainReason),
}

/// A lexical read rewritten to one slot of its owning flat closure.
///
/// The capture analysis attaches this fact to local/upvalue nodes whose
/// coordinate crosses the frames introduced inside a flat-planned lambda or
/// thunk. At runtime, matching [`Self::site`] against the active flat capture
/// licenses a single indexed load from [`Self::index`]; a mismatch retains
/// the ordinary lexical-coordinate fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlatCaptureAccess {
    /// The lambda or thunk allocation site whose plan owns the slot.
    pub site: IrId,
    /// The zero-based index into that site's [`CapturePlan::Flat`] slots.
    pub index: u16,
}

/// Why a capture plan fell back to the shared frame chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SharedChainReason {
    /// The free-variable set exceeded the flat-capture width cap.
    TooManyFreeVars,
    /// The body probes dynamic (`with`) scope.
    DynamicScope,
    /// A free-variable coordinate did not fit the plan encoding.
    CoordinateOverflow,
}

/// Per-node analysis facts for one lowered IR artifact.
///
/// Entries are indexed by [`IrId`] and are expected to stay in one-to-one order
/// with the node arena. Alongside the per-node [`ExprFacts`] records the table
/// carries three per-node bits and three sparse side tables:
///
/// - a `tryEval` barrier bit: nodes that root the argument subtree of a
///   `builtins.tryEval` application. No transform in the current pipeline
///   consumes the bit; it is persisted for future relocation passes (S4:
///   computations must not be moved across a `tryEval` catch boundary).
/// - an eager-assembly bit ([`Self::assembly_eager`]): binding-value thunk
///   allocations that a frame assembler may evaluate directly to WHNF.
/// - a structural-totality bit ([`Self::structurally_total`]): nodes whose
///   forced evaluation cannot produce an observable event.
/// - a capture plan ([`Self::capture_plan`]): the free-variable capture plan
///   for lambda construction and thunk allocation sites (FV-5 input).
/// - a flat-capture access ([`Self::flat_capture_access`]): the constant
///   capture index for a lexical read owned by a flat-planned site.
/// - a lambda call summary ([`Self::lambda_call_summary`]): sparse demand and
///   escape facts transferred from a closure's module to its caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrFacts {
    nodes: Box<[ExprFacts]>,
    try_eval_barriers: Box<[bool]>,
    assembly_eager: Box<[bool]>,
    structurally_total: Box<[bool]>,
    capture_plans: Box<[Option<CapturePlan>]>,
    flat_capture_accesses: Box<[Option<FlatCaptureAccess>]>,
    lambda_call_summaries: Box<[LambdaCallSummary]>,
}

impl IrFacts {
    /// Creates a conservative fact table with one entry per IR node.
    pub fn conservative(node_count: usize) -> Self {
        Self {
            nodes: vec![ExprFacts::conservative(); node_count].into_boxed_slice(),
            try_eval_barriers: vec![false; node_count].into_boxed_slice(),
            assembly_eager: vec![false; node_count].into_boxed_slice(),
            structurally_total: vec![false; node_count].into_boxed_slice(),
            capture_plans: vec![None; node_count].into_boxed_slice(),
            flat_capture_accesses: vec![None; node_count].into_boxed_slice(),
            lambda_call_summaries: Box::new([]),
        }
    }

    /// Returns the number of per-node fact records.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns whether the fact table is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns all fact records in IR node order.
    pub fn as_slice(&self) -> &[ExprFacts] {
        &self.nodes
    }

    /// Returns one fact record by node id.
    pub fn get(&self, id: IrId) -> Option<ExprFacts> {
        self.nodes.get(id.index()).copied()
    }

    /// Returns mutable access to one fact record by node id.
    pub fn get_mut(&mut self, id: IrId) -> Option<&mut ExprFacts> {
        self.nodes.get_mut(id.index())
    }

    /// Returns whether `id` roots the argument subtree of a `tryEval` call.
    pub fn try_eval_barrier(&self, id: IrId) -> bool {
        self.try_eval_barriers
            .get(id.index())
            .copied()
            .unwrap_or(false)
    }

    /// Marks `id` as rooting the argument subtree of a `tryEval` call.
    ///
    /// Out-of-range ids are ignored; the barrier table always mirrors the
    /// node-fact table length.
    pub fn set_try_eval_barrier(&mut self, id: IrId, barrier: bool) {
        if let Some(slot) = self.try_eval_barriers.get_mut(id.index()) {
            *slot = barrier;
        }
    }

    /// Returns all `tryEval` barrier bits in IR node order.
    pub fn try_eval_barriers(&self) -> &[bool] {
        &self.try_eval_barriers
    }

    /// Returns whether `id` carries the eager-assembly license.
    ///
    /// The bit is a per-frame assembly plan entry produced by the strictness
    /// analysis for binding-value `ThunkAlloc` nodes of attrset literals that
    /// flow into a derivation boundary (`builtins.derivationStrict` /
    /// `builtins.derivation`). It licenses an order-sensitive frame assembler
    /// to evaluate the binding body directly to WHNF into its slot instead of
    /// allocating lazy storage, under the assembler's existing contract:
    /// bindings are populated in source order and dynamic-key or shape
    /// validation has already completed.
    ///
    /// The producer only sets the bit where that schedule is proven
    /// observation-equivalent to lazy assembly (soundness rules S2 + S3):
    ///
    /// - values whose bodies are structurally *total* (incapable of throwing,
    ///   diverging, or emitting trace output), which every derivation
    ///   boundary forces; evaluating them at any point of the assembly is
    ///   silent, so their relative order never matters; and
    /// - at most one non-total value: the `name` binding of a literal that is
    ///   the syntactically direct `derivationStrict` argument, whose force is
    ///   the serializer's first observable-event opportunity.
    ///
    /// Note the bit is deliberately not folded into [`Strictness`]: a total
    /// value late in the serializer's sorted force order is only
    /// [`Strictness::Demanded`] (an earlier attribute's failure can precede
    /// its force), yet eager evaluation of it is still invisible because its
    /// body cannot produce events.
    pub fn assembly_eager(&self, id: IrId) -> bool {
        self.assembly_eager.get(id.index()).copied().unwrap_or(false)
    }

    /// Marks `id` as carrying the eager-assembly license.
    ///
    /// Out-of-range ids are ignored; the bit table always mirrors the
    /// node-fact table length.
    pub fn set_assembly_eager(&mut self, id: IrId, eager: bool) {
        if let Some(slot) = self.assembly_eager.get_mut(id.index()) {
            *slot = eager;
        }
    }

    /// Returns all eager-assembly bits in IR node order.
    pub fn assembly_eager_bits(&self) -> &[bool] {
        &self.assembly_eager
    }

    /// Returns whether forcing this node is structurally total.
    ///
    /// Total nodes cannot throw, diverge, trace, or otherwise emit an
    /// observable event. Cross-module call planning combines this proof with
    /// positive demand before evaluating an argument binding during assembly.
    pub fn structurally_total(&self, id: IrId) -> bool {
        self.structurally_total
            .get(id.index())
            .copied()
            .unwrap_or(false)
    }

    /// Marks a node as structurally total.
    pub fn set_structurally_total(&mut self, id: IrId, total: bool) {
        if let Some(slot) = self.structurally_total.get_mut(id.index()) {
            *slot = total;
        }
    }

    /// Returns all structural-totality bits in IR node order.
    pub fn structurally_total_bits(&self) -> &[bool] {
        &self.structurally_total
    }

    /// Returns the capture plan computed for an allocation site, if any.
    ///
    /// Only lambda construction and thunk allocation nodes carry plans; every
    /// other node (and out-of-range ids) returns `None`. A missing plan on an
    /// allocation site means the capture analysis has not run (or declined
    /// the whole module) and consumers must keep the shared-chain capture.
    pub fn capture_plan(&self, id: IrId) -> Option<&CapturePlan> {
        self.capture_plans.get(id.index())?.as_ref()
    }

    /// Installs the capture plan for an allocation site.
    ///
    /// Out-of-range ids are ignored; the plan table always mirrors the
    /// node-fact table length.
    pub fn set_capture_plan(&mut self, id: IrId, plan: Option<CapturePlan>) {
        if let Some(slot) = self.capture_plans.get_mut(id.index()) {
            *slot = plan;
        }
    }

    /// Returns all capture plans in IR node order.
    pub fn capture_plans(&self) -> &[Option<CapturePlan>] {
        &self.capture_plans
    }

    /// Returns the constant flat-capture access for a lexical read, if any.
    ///
    /// A missing fact means the read is frame-local, belongs to a
    /// shared-chain site, has an ambiguous shared IR context, or analysis has
    /// not run. Consumers must retain coordinate lookup for those cases.
    #[inline]
    pub fn flat_capture_access(&self, id: IrId) -> Option<FlatCaptureAccess> {
        self.flat_capture_accesses.get(id.index()).copied().flatten()
    }

    /// Installs the constant flat-capture access for one lexical read.
    ///
    /// Out-of-range ids are ignored; the access table always mirrors the
    /// node-fact table length.
    pub fn set_flat_capture_access(&mut self, id: IrId, access: Option<FlatCaptureAccess>) {
        if let Some(slot) = self.flat_capture_accesses.get_mut(id.index()) {
            *slot = access;
        }
    }

    /// Returns all flat-capture accesses in IR node order.
    pub fn flat_capture_accesses(&self) -> &[Option<FlatCaptureAccess>] {
        &self.flat_capture_accesses
    }

    /// Returns the call summary keyed by a runtime lambda's pattern node.
    pub fn lambda_call_summary(&self, pattern: IrId) -> Option<&LambdaCallSummary> {
        self.lambda_call_summaries
            .binary_search_by_key(&pattern.as_u32(), |summary| summary.pattern.as_u32())
            .ok()
            .and_then(|index| self.lambda_call_summaries.get(index))
    }

    /// Replaces the sparse lambda call-summary table.
    ///
    /// Entries are sorted by pattern id so runtime closure lookup is logarithmic.
    pub fn set_lambda_call_summaries(&mut self, mut summaries: Vec<LambdaCallSummary>) {
        summaries.sort_unstable_by_key(|summary| summary.pattern.as_u32());
        self.lambda_call_summaries = summaries.into_boxed_slice();
    }

    /// Returns all lambda call summaries in pattern-id order.
    pub fn lambda_call_summaries(&self) -> &[LambdaCallSummary] {
        &self.lambda_call_summaries
    }

    /// Returns mutable access to persisted lambda call summaries.
    pub fn lambda_call_summaries_mut(&mut self) -> &mut [LambdaCallSummary] {
        &mut self.lambda_call_summaries
    }
}
