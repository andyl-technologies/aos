//! Runtime allocation strategy dispatch for evaluator heap objects.
//!
//! The tree-walk oracle allocates through this layer instead of naming a heap
//! backend directly. Today the installed worker strategy is the Tier-A one-shot
//! bump arena, with a separate permanent-shared bump arena for hash-consed
//! values. Later Phase-3 work can install the precise generational collector
//! behind the same worker `aos_alloc_*` entry-point surface.

use std::mem;

use crate::heap::arena::{
    ArenaAllocation, ArenaError, ArenaMemoryAdviceReport, ArenaRegionMark, ArenaRegionPopReport,
    ArenaStats, BumpArena, HeapObjectKind,
};
use crate::heap::{HeapMemoryBudget, HeapMemoryBudgetResponse, HeapMemorySample, MemoryAdviceKind};

/// The installed runtime allocation strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocatorTier {
    /// One-shot CLI evaluation backed by a never-free bump arena.
    TierAOneShot,
    /// Hash-consed shared values backed by a non-collected permanent arena.
    PermanentShared,
}

/// A centralized allocation entry point that forms an allocation safepoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocationEntryPoint {
    /// The `aos_alloc_thunk` helper.
    AosAllocThunk,
    /// The `aos_alloc_lambda` helper.
    AosAllocLambda,
    /// The `aos_alloc_attrs` helper.
    AosAllocAttrs,
    /// The `aos_alloc_cons` helper.
    AosAllocCons,
    /// The `aos_alloc_list` helper.
    AosAllocList,
    /// The `aos_alloc_string` helper.
    AosAllocString,
    /// The `aos_alloc_raw` helper.
    AosAllocRaw,
}

/// Worker allocator position captured for a future lexical region pop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RuntimeAllocatorRegionMark {
    arena: ArenaRegionMark,
    safepoints: AllocationSafepointState,
}

impl RuntimeAllocatorRegionMark {
    const fn new(arena: ArenaRegionMark, safepoints: AllocationSafepointState) -> Self {
        Self { arena, safepoints }
    }

    /// Returns the raw arena marker captured with this runtime mark.
    pub(crate) const fn arena(self) -> ArenaRegionMark {
        self.arena
    }

    const fn safepoints(self) -> AllocationSafepointState {
        self.safepoints
    }
}

/// Frozen allocation entry points registered by future native runtimes.
pub const RUNTIME_ALLOCATION_ENTRYPOINTS: &[RuntimeAllocationEntryPoint] = &[
    RuntimeAllocationEntryPoint::AosAllocAttrs,
    RuntimeAllocationEntryPoint::AosAllocCons,
    RuntimeAllocationEntryPoint::AosAllocLambda,
    RuntimeAllocationEntryPoint::AosAllocList,
    RuntimeAllocationEntryPoint::AosAllocRaw,
    RuntimeAllocationEntryPoint::AosAllocString,
    RuntimeAllocationEntryPoint::AosAllocThunk,
];

const ALLOC_ATTRS_PARAMETERS: &[RuntimeAllocationAbiParameter] = &[
    RuntimeAllocationAbiParameter::new("rt", RuntimeAllocationAbiParameterKind::RuntimeContext),
    RuntimeAllocationAbiParameter::new("shape", RuntimeAllocationAbiParameterKind::ShapeId),
    RuntimeAllocationAbiParameter::new("slots", RuntimeAllocationAbiParameterKind::U32),
];
const ALLOC_CONS_PARAMETERS: &[RuntimeAllocationAbiParameter] = &[
    RuntimeAllocationAbiParameter::new("rt", RuntimeAllocationAbiParameterKind::RuntimeContext),
    RuntimeAllocationAbiParameter::new("head", RuntimeAllocationAbiParameterKind::Value),
    RuntimeAllocationAbiParameter::new("tail", RuntimeAllocationAbiParameterKind::ListPointer),
];
const ALLOC_LAMBDA_PARAMETERS: &[RuntimeAllocationAbiParameter] = &[
    RuntimeAllocationAbiParameter::new("rt", RuntimeAllocationAbiParameterKind::RuntimeContext),
    RuntimeAllocationAbiParameter::new("code_ptr", RuntimeAllocationAbiParameterKind::CodePointer),
    RuntimeAllocationAbiParameter::new("env", RuntimeAllocationAbiParameterKind::EnvPointer),
];
const ALLOC_LIST_PARAMETERS: &[RuntimeAllocationAbiParameter] = &[
    RuntimeAllocationAbiParameter::new("rt", RuntimeAllocationAbiParameterKind::RuntimeContext),
    RuntimeAllocationAbiParameter::new("len", RuntimeAllocationAbiParameterKind::Usize),
];
const ALLOC_RAW_PARAMETERS: &[RuntimeAllocationAbiParameter] = &[
    RuntimeAllocationAbiParameter::new("rt", RuntimeAllocationAbiParameterKind::RuntimeContext),
    RuntimeAllocationAbiParameter::new("size", RuntimeAllocationAbiParameterKind::Usize),
    RuntimeAllocationAbiParameter::new("align", RuntimeAllocationAbiParameterKind::Usize),
    RuntimeAllocationAbiParameter::new("type_tag", RuntimeAllocationAbiParameterKind::TypeTag),
];
const ALLOC_STRING_PARAMETERS: &[RuntimeAllocationAbiParameter] = &[
    RuntimeAllocationAbiParameter::new("rt", RuntimeAllocationAbiParameterKind::RuntimeContext),
    RuntimeAllocationAbiParameter::new("len", RuntimeAllocationAbiParameterKind::Usize),
];
const ALLOC_THUNK_PARAMETERS: &[RuntimeAllocationAbiParameter] = &[
    RuntimeAllocationAbiParameter::new("rt", RuntimeAllocationAbiParameterKind::RuntimeContext),
    RuntimeAllocationAbiParameter::new("code_ptr", RuntimeAllocationAbiParameterKind::CodePointer),
    RuntimeAllocationAbiParameter::new("env", RuntimeAllocationAbiParameterKind::EnvPointer),
];

/// Frozen allocation-helper ABI signatures for future native runtimes.
pub const RUNTIME_ALLOCATION_ABI_SIGNATURES: &[RuntimeAllocationAbiSignature] = &[
    RuntimeAllocationAbiSignature::new(
        RuntimeAllocationEntryPoint::AosAllocAttrs,
        ALLOC_ATTRS_PARAMETERS,
        RuntimeAllocationAbiReturnKind::AttrsPointer,
    ),
    RuntimeAllocationAbiSignature::new(
        RuntimeAllocationEntryPoint::AosAllocCons,
        ALLOC_CONS_PARAMETERS,
        RuntimeAllocationAbiReturnKind::ListPointer,
    ),
    RuntimeAllocationAbiSignature::new(
        RuntimeAllocationEntryPoint::AosAllocLambda,
        ALLOC_LAMBDA_PARAMETERS,
        RuntimeAllocationAbiReturnKind::LambdaPointer,
    ),
    RuntimeAllocationAbiSignature::new(
        RuntimeAllocationEntryPoint::AosAllocList,
        ALLOC_LIST_PARAMETERS,
        RuntimeAllocationAbiReturnKind::ListPointer,
    ),
    RuntimeAllocationAbiSignature::new(
        RuntimeAllocationEntryPoint::AosAllocRaw,
        ALLOC_RAW_PARAMETERS,
        RuntimeAllocationAbiReturnKind::RawPointer,
    ),
    RuntimeAllocationAbiSignature::new(
        RuntimeAllocationEntryPoint::AosAllocString,
        ALLOC_STRING_PARAMETERS,
        RuntimeAllocationAbiReturnKind::StringHeaderPointer,
    ),
    RuntimeAllocationAbiSignature::new(
        RuntimeAllocationEntryPoint::AosAllocThunk,
        ALLOC_THUNK_PARAMETERS,
        RuntimeAllocationAbiReturnKind::ThunkPointer,
    ),
];

/// Returns the frozen allocation entry-point inventory.
pub const fn runtime_allocation_entrypoints() -> &'static [RuntimeAllocationEntryPoint] {
    RUNTIME_ALLOCATION_ENTRYPOINTS
}

/// Returns the frozen allocation-helper ABI signature inventory.
pub const fn runtime_allocation_abi_signatures() -> &'static [RuntimeAllocationAbiSignature] {
    RUNTIME_ALLOCATION_ABI_SIGNATURES
}

impl RuntimeAllocationEntryPoint {
    /// Returns the stable runtime symbol name for this allocation entry point.
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::AosAllocThunk => "aos_alloc_thunk",
            Self::AosAllocLambda => "aos_alloc_lambda",
            Self::AosAllocAttrs => "aos_alloc_attrs",
            Self::AosAllocCons => "aos_alloc_cons",
            Self::AosAllocList => "aos_alloc_list",
            Self::AosAllocString => "aos_alloc_string",
            Self::AosAllocRaw => "aos_alloc_raw",
        }
    }

    /// Returns the allocation entry point for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        match symbol_name {
            "aos_alloc_thunk" => Some(Self::AosAllocThunk),
            "aos_alloc_lambda" => Some(Self::AosAllocLambda),
            "aos_alloc_attrs" => Some(Self::AosAllocAttrs),
            "aos_alloc_cons" => Some(Self::AosAllocCons),
            "aos_alloc_list" => Some(Self::AosAllocList),
            "aos_alloc_string" => Some(Self::AosAllocString),
            "aos_alloc_raw" => Some(Self::AosAllocRaw),
            _ => None,
        }
    }

    /// Returns the frozen ABI signature for this allocation entry point.
    pub const fn abi_signature(self) -> RuntimeAllocationAbiSignature {
        match self {
            Self::AosAllocThunk => RuntimeAllocationAbiSignature::new(
                self,
                ALLOC_THUNK_PARAMETERS,
                RuntimeAllocationAbiReturnKind::ThunkPointer,
            ),
            Self::AosAllocLambda => RuntimeAllocationAbiSignature::new(
                self,
                ALLOC_LAMBDA_PARAMETERS,
                RuntimeAllocationAbiReturnKind::LambdaPointer,
            ),
            Self::AosAllocAttrs => RuntimeAllocationAbiSignature::new(
                self,
                ALLOC_ATTRS_PARAMETERS,
                RuntimeAllocationAbiReturnKind::AttrsPointer,
            ),
            Self::AosAllocCons => RuntimeAllocationAbiSignature::new(
                self,
                ALLOC_CONS_PARAMETERS,
                RuntimeAllocationAbiReturnKind::ListPointer,
            ),
            Self::AosAllocList => RuntimeAllocationAbiSignature::new(
                self,
                ALLOC_LIST_PARAMETERS,
                RuntimeAllocationAbiReturnKind::ListPointer,
            ),
            Self::AosAllocString => RuntimeAllocationAbiSignature::new(
                self,
                ALLOC_STRING_PARAMETERS,
                RuntimeAllocationAbiReturnKind::StringHeaderPointer,
            ),
            Self::AosAllocRaw => RuntimeAllocationAbiSignature::new(
                self,
                ALLOC_RAW_PARAMETERS,
                RuntimeAllocationAbiReturnKind::RawPointer,
            ),
        }
    }
}

/// A frozen allocation-helper ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationAbiSignature {
    entrypoint: RuntimeAllocationEntryPoint,
    parameters: &'static [RuntimeAllocationAbiParameter],
    return_kind: RuntimeAllocationAbiReturnKind,
}

impl RuntimeAllocationAbiSignature {
    const fn new(
        entrypoint: RuntimeAllocationEntryPoint,
        parameters: &'static [RuntimeAllocationAbiParameter],
        return_kind: RuntimeAllocationAbiReturnKind,
    ) -> Self {
        Self {
            entrypoint,
            parameters,
            return_kind,
        }
    }

    /// Returns the allocation ABI signature for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        RuntimeAllocationEntryPoint::from_symbol_name(symbol_name)
            .map(RuntimeAllocationEntryPoint::abi_signature)
    }

    /// Returns the allocation entry point served by this signature.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this signature.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the ordered ABI parameters for this signature.
    pub const fn parameters(self) -> &'static [RuntimeAllocationAbiParameter] {
        self.parameters
    }

    /// Returns the ABI result kind produced by this signature.
    pub const fn return_kind(self) -> RuntimeAllocationAbiReturnKind {
        self.return_kind
    }
}

/// A parameter accepted by a frozen allocation-helper ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationAbiParameter {
    name: &'static str,
    kind: RuntimeAllocationAbiParameterKind,
}

impl RuntimeAllocationAbiParameter {
    const fn new(name: &'static str, kind: RuntimeAllocationAbiParameterKind) -> Self {
        Self { name, kind }
    }

    /// Returns the stable ABI parameter name.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the machine-level kind carried by this parameter.
    pub const fn kind(self) -> RuntimeAllocationAbiParameterKind {
        self.kind
    }
}

/// A machine-level parameter kind accepted by allocation-helper symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocationAbiParameterKind {
    /// The evaluator runtime context that owns the installed allocator strategy.
    RuntimeContext,
    /// A pointer to native code for a thunk or lambda body.
    CodePointer,
    /// A pointer to a captured environment frame.
    EnvPointer,
    /// A by-value runtime value word pair.
    Value,
    /// A pointer to a runtime list object.
    ListPointer,
    /// A hidden-class shape identifier.
    ShapeId,
    /// A target-pointer-sized unsigned integer.
    Usize,
    /// A runtime-specific raw allocation type tag.
    TypeTag,
    /// A 32-bit unsigned integer.
    U32,
}

/// The success-path machine-level result kind returned by allocation-helper symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocationAbiReturnKind {
    /// A pointer to a thunk object.
    ThunkPointer,
    /// A pointer to a lambda closure object.
    LambdaPointer,
    /// A pointer to an attrset object.
    AttrsPointer,
    /// A pointer to a list object.
    ListPointer,
    /// A pointer to a string header object.
    StringHeaderPointer,
    /// A pointer to raw heap storage.
    RawPointer,
}

/// GC-stress polling policy evaluated at allocation safepoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcStressPolicy {
    mode: GcStressPolicyMode,
}

impl Default for GcStressPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

impl GcStressPolicy {
    /// Creates a policy that never requests a GC-stress collector poll.
    pub const fn disabled() -> Self {
        Self {
            mode: GcStressPolicyMode::Disabled,
        }
    }

    /// Creates a policy that requests a GC-stress collector poll at every
    /// allocation safepoint.
    pub const fn every_safepoint() -> Self {
        Self {
            mode: GcStressPolicyMode::EverySafepoint,
        }
    }

    /// Creates a policy that requests a GC-stress collector poll every `period`
    /// allocation safepoints.
    ///
    /// The cadence is evaluated against the allocator's lifetime safepoint
    /// sequence, not the policy-installation epoch.
    ///
    /// # Errors
    ///
    /// Returns [`GcStressPolicyError::ZeroPeriod`] when `period` is zero.
    pub const fn every_n_safepoints(period: u64) -> Result<Self, GcStressPolicyError> {
        if period == 0 {
            return Err(GcStressPolicyError::ZeroPeriod);
        }
        Ok(Self {
            mode: GcStressPolicyMode::EveryNSafepoints { period },
        })
    }

    /// Returns whether this policy never requests a GC-stress collector poll.
    pub const fn is_disabled(self) -> bool {
        matches!(self.mode, GcStressPolicyMode::Disabled)
    }

    const fn poll_reason_for(self, sequence: u64) -> Option<AllocationGcPollReason> {
        match self.mode {
            GcStressPolicyMode::Disabled => None,
            _ if sequence == u64::MAX => Some(AllocationGcPollReason::GcStressSequenceSaturated),
            GcStressPolicyMode::EverySafepoint => {
                Some(AllocationGcPollReason::GcStressEverySafepoint)
            }
            GcStressPolicyMode::EveryNSafepoints { period } => {
                if sequence % period == 0 {
                    Some(AllocationGcPollReason::GcStressEveryNSafepoints { period })
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GcStressPolicyMode {
    Disabled,
    EverySafepoint,
    EveryNSafepoints { period: u64 },
}

/// A GC-stress policy configuration failure.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum GcStressPolicyError {
    /// Periodic GC-stress polling needs a non-zero period.
    #[error("GC-stress safepoint period cannot be zero")]
    ZeroPeriod,
}

/// The reason an allocation safepoint requested a collector poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationGcPollReason {
    /// GC-stress mode requested a collector poll at every safepoint.
    GcStressEverySafepoint,
    /// GC-stress mode requested a collector poll at a periodic safepoint.
    GcStressEveryNSafepoints {
        /// The configured safepoint period.
        period: u64,
    },
    /// GC-stress mode requested a collector poll because the safepoint sequence
    /// saturated.
    GcStressSequenceSaturated,
}

/// A collector poll requested by an allocation safepoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocationCollectorPoll {
    sequence: u64,
    tier: RuntimeAllocatorTier,
    entrypoint: RuntimeAllocationEntryPoint,
    reason: AllocationGcPollReason,
    stats_after: ArenaStats,
}

impl AllocationCollectorPoll {
    const fn new(safepoint: AllocationSafepoint, reason: AllocationGcPollReason) -> Self {
        Self {
            sequence: safepoint.sequence,
            tier: safepoint.tier,
            entrypoint: safepoint.entrypoint,
            reason,
            stats_after: safepoint.stats_after,
        }
    }

    /// Returns the allocation safepoint sequence that requested the poll.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the allocation tier that requested the poll.
    pub const fn tier(self) -> RuntimeAllocatorTier {
        self.tier
    }

    /// Returns the allocation entry point that requested the poll.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.entrypoint
    }

    /// Returns why the collector poll was requested.
    pub const fn reason(self) -> AllocationGcPollReason {
        self.reason
    }

    /// Returns allocator accounting after the safepoint allocation completed.
    pub const fn stats_after(self) -> ArenaStats {
        self.stats_after
    }
}

/// A high-water memory-budget decision made at an allocation safepoint.
///
/// The current runtime does not have a live RSS sampler, so allocation
/// safepoints use post-allocation mapped arena bytes as the resident-memory
/// proxy and accept caller-supplied cheap-reclaim capacity for dead arena pages
/// and cold hash-consed values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocationMemoryBudgetDecision {
    sequence: u64,
    tier: RuntimeAllocatorTier,
    entrypoint: RuntimeAllocationEntryPoint,
    budget: HeapMemoryBudget,
    sample: HeapMemorySample,
    stats_after: ArenaStats,
    response: HeapMemoryBudgetResponse,
}

impl AllocationMemoryBudgetDecision {
    const fn new(
        safepoint: AllocationSafepoint,
        budget: HeapMemoryBudget,
        sample: HeapMemorySample,
    ) -> Self {
        Self {
            sequence: safepoint.sequence,
            tier: safepoint.tier,
            entrypoint: safepoint.entrypoint,
            budget,
            sample,
            stats_after: safepoint.stats_after,
            response: budget.classify(sample),
        }
    }

    /// Returns the allocation safepoint sequence that produced this decision.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the allocation tier sampled by this decision.
    pub const fn tier(self) -> RuntimeAllocatorTier {
        self.tier
    }

    /// Returns the allocation entry point sampled by this decision.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.entrypoint
    }

    /// Returns the budget used to classify memory pressure.
    pub const fn budget(self) -> HeapMemoryBudget {
        self.budget
    }

    /// Returns the memory sample classified by the budget policy.
    pub const fn sample(self) -> HeapMemorySample {
        self.sample
    }

    /// Returns allocator accounting captured after the safepoint allocation.
    pub const fn stats_after(self) -> ArenaStats {
        self.stats_after
    }

    /// Returns the high-water budget response selected for this safepoint.
    pub const fn response(self) -> HeapMemoryBudgetResponse {
        self.response
    }

    /// Returns whether the response asks runtime code to do more than continue.
    pub const fn requires_runtime_action(self) -> bool {
        match self.response {
            HeapMemoryBudgetResponse::ContinueTierA { .. } => false,
            HeapMemoryBudgetResponse::SpillCold { .. }
            | HeapMemoryBudgetResponse::InstallTierB { .. } => true,
        }
    }

    /// Returns whether the response asks the runtime to install Tier B.
    pub const fn requests_tier_b(self) -> bool {
        matches!(self.response, HeapMemoryBudgetResponse::InstallTierB { .. })
    }
}

/// Metadata captured at one allocation safepoint.
///
/// The current tree-walk runtime records safepoints and GC-stress poll intent
/// only. It does not yet invoke a collector, build a root set, or run GC stress
/// collection from this event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocationSafepoint {
    sequence: u64,
    tier: RuntimeAllocatorTier,
    entrypoint: RuntimeAllocationEntryPoint,
    kind: HeapObjectKind,
    requested_size: usize,
    reserved_size: usize,
    stats_after: ArenaStats,
    gc_poll_reason: Option<AllocationGcPollReason>,
}

impl AllocationSafepoint {
    const fn new(
        sequence: u64,
        tier: RuntimeAllocatorTier,
        entrypoint: RuntimeAllocationEntryPoint,
        allocation: ArenaAllocation,
        stats_after: ArenaStats,
        gc_poll_reason: Option<AllocationGcPollReason>,
    ) -> Self {
        Self {
            sequence,
            tier,
            entrypoint,
            kind: allocation.kind,
            requested_size: allocation.requested_size,
            reserved_size: allocation.reserved_size,
            stats_after,
            gc_poll_reason,
        }
    }

    /// Returns the monotonic safepoint sequence number for this allocator.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the allocation tier that produced this safepoint.
    pub const fn tier(self) -> RuntimeAllocatorTier {
        self.tier
    }

    /// Returns the centralized allocation entry point.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.entrypoint
    }

    /// Returns the logical heap-object kind requested by the caller.
    pub const fn kind(self) -> HeapObjectKind {
        self.kind
    }

    /// Returns the caller-requested allocation size in bytes.
    pub const fn requested_size(self) -> usize {
        self.requested_size
    }

    /// Returns the word-rounded bump distance in bytes.
    pub const fn reserved_size(self) -> usize {
        self.reserved_size
    }

    /// Returns the full arena accounting snapshot after this allocation.
    pub const fn stats_after(self) -> ArenaStats {
        self.stats_after
    }

    /// Returns why this safepoint requested a collector poll.
    pub const fn gc_poll_reason(self) -> Option<AllocationGcPollReason> {
        self.gc_poll_reason
    }

    /// Returns the typed collector poll requested by this safepoint.
    pub const fn collector_poll(self) -> Option<AllocationCollectorPoll> {
        match self.gc_poll_reason {
            Some(reason) => Some(AllocationCollectorPoll::new(self, reason)),
            None => None,
        }
    }

    /// Builds the high-water budget sample for this safepoint.
    ///
    /// The active runtime does not have live RSS sampling yet, so the sample uses
    /// post-allocation mapped arena bytes as its resident-memory proxy. The
    /// caller supplies cheap-reclaim estimates for dead arena pages and cold
    /// hash-consed values.
    pub const fn memory_budget_sample(
        self,
        dead_arena_bytes: usize,
        cold_hash_consed_bytes: usize,
    ) -> HeapMemorySample {
        HeapMemorySample::new(
            self.heap_mapped_bytes_after(),
            dead_arena_bytes,
            cold_hash_consed_bytes,
        )
    }

    /// Classifies this safepoint against a high-water memory budget.
    pub const fn classify_memory_budget(
        self,
        budget: HeapMemoryBudget,
        dead_arena_bytes: usize,
        cold_hash_consed_bytes: usize,
    ) -> AllocationMemoryBudgetDecision {
        let sample = self.memory_budget_sample(dead_arena_bytes, cold_hash_consed_bytes);
        AllocationMemoryBudgetDecision::new(self, budget, sample)
    }

    /// Returns heap chunks owned after this allocation completed.
    pub const fn heap_chunks_after(self) -> usize {
        self.stats_after.chunks
    }

    /// Returns heap bytes reserved after this allocation completed.
    pub const fn heap_reserved_bytes_after(self) -> usize {
        self.stats_after.reserved_bytes
    }

    /// Returns page-rounded mapped bytes after this allocation completed.
    pub const fn heap_mapped_bytes_after(self) -> usize {
        self.stats_after.mapped_bytes
    }

    /// Returns heap bytes consumed after this allocation completed.
    pub const fn heap_used_bytes_after(self) -> usize {
        self.stats_after.used_bytes
    }
}

/// Allocation-safepoint accounting for one allocator domain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocationSafepointState {
    count: u64,
    last: Option<AllocationSafepoint>,
}

impl AllocationSafepointState {
    /// Returns how many allocation safepoints have been recorded.
    pub const fn count(self) -> u64 {
        self.count
    }

    /// Returns the most recent allocation safepoint.
    pub const fn last(self) -> Option<AllocationSafepoint> {
        self.last
    }

    /// Returns the collector poll requested by the most recent safepoint.
    pub const fn last_safepoint_collector_poll(self) -> Option<AllocationCollectorPoll> {
        match self.last {
            Some(safepoint) => safepoint.collector_poll(),
            None => None,
        }
    }

    /// Classifies the most recent safepoint against a high-water memory budget.
    pub const fn last_memory_budget_decision(
        self,
        budget: HeapMemoryBudget,
        dead_arena_bytes: usize,
        cold_hash_consed_bytes: usize,
    ) -> Option<AllocationMemoryBudgetDecision> {
        match self.last {
            Some(safepoint) => Some(safepoint.classify_memory_budget(
                budget,
                dead_arena_bytes,
                cold_hash_consed_bytes,
            )),
            None => None,
        }
    }

    fn record(
        &mut self,
        tier: RuntimeAllocatorTier,
        entrypoint: RuntimeAllocationEntryPoint,
        allocation: ArenaAllocation,
        stats_after: ArenaStats,
        gc_stress_policy: GcStressPolicy,
    ) {
        let sequence = self.count.saturating_add(1);
        self.count = sequence;
        let gc_poll_reason = gc_stress_policy.poll_reason_for(sequence);
        self.last = Some(AllocationSafepoint::new(
            sequence,
            tier,
            entrypoint,
            allocation,
            stats_after,
            gc_poll_reason,
        ));
    }
}

/// Routes heap allocations through the active runtime allocation strategy.
#[derive(Debug)]
pub struct RuntimeAllocator {
    backend: RuntimeAllocatorBackend,
    safepoints: AllocationSafepointState,
    gc_stress_policy: GcStressPolicy,
}

impl Default for RuntimeAllocator {
    fn default() -> Self {
        Self::tier_a_one_shot()
    }
}

impl RuntimeAllocator {
    /// Creates a runtime allocator backed by the Tier-A one-shot arena.
    pub fn tier_a_one_shot() -> Self {
        Self {
            backend: RuntimeAllocatorBackend::TierAOneShot(BumpArena::new()),
            safepoints: AllocationSafepointState::default(),
            gc_stress_policy: GcStressPolicy::disabled(),
        }
    }

    /// Creates a Tier-A runtime allocator with an explicit first chunk size.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError::InvalidChunkSize`] when `chunk_bytes` is zero, or
    /// [`ArenaError::SizeOverflow`] if rounding the chunk size overflows.
    pub fn tier_a_with_initial_chunk_bytes(chunk_bytes: usize) -> Result<Self, ArenaError> {
        Ok(Self {
            backend: RuntimeAllocatorBackend::TierAOneShot(BumpArena::with_initial_chunk_bytes(
                chunk_bytes,
            )?),
            safepoints: AllocationSafepointState::default(),
            gc_stress_policy: GcStressPolicy::disabled(),
        })
    }

    /// Returns this allocator with a GC-stress polling policy installed.
    pub fn with_gc_stress_policy(mut self, policy: GcStressPolicy) -> Self {
        self.gc_stress_policy = policy;
        self
    }

    /// Installs a GC-stress polling policy for later allocation safepoints.
    ///
    /// Periodic policies use this allocator's lifetime safepoint sequence, so
    /// installing a policy does not reset the cadence.
    pub fn set_gc_stress_policy(&mut self, policy: GcStressPolicy) {
        self.gc_stress_policy = policy;
    }

    /// Returns the installed GC-stress polling policy.
    pub const fn gc_stress_policy(&self) -> GcStressPolicy {
        self.gc_stress_policy
    }

    /// Returns the installed allocation tier.
    pub fn tier(&self) -> RuntimeAllocatorTier {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(_) => RuntimeAllocatorTier::TierAOneShot,
        }
    }

    /// Returns current allocation accounting for the installed strategy.
    pub fn stats(&self) -> ArenaStats {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => arena.stats(),
        }
    }

    /// Advises unused bytes at the end of chunks owned by this allocator.
    pub fn advise_unused_tail(&self, kind: MemoryAdviceKind) -> ArenaMemoryAdviceReport {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => arena.advise_unused_tail(kind),
        }
    }

    /// Returns unused-tail bytes this allocator can lower to page advice.
    pub fn supported_unused_tail_advice_bytes(&self) -> usize {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => {
                arena.supported_unused_tail_advice_bytes()
            }
        }
    }

    /// Captures the current worker allocator position for lexical reclamation.
    pub(crate) fn region_mark(&self) -> RuntimeAllocatorRegionMark {
        match &self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => {
                RuntimeAllocatorRegionMark::new(arena.region_mark(), self.safepoints)
            }
        }
    }

    /// Restores the worker allocator to a previously captured region marker.
    ///
    /// The caller must first validate and invalidate any typed heap records for
    /// allocations above the marker. Successful pops also roll allocation
    /// safepoint accounting back to the marker so later collector polls cannot
    /// describe reclaimed allocations.
    #[allow(unsafe_code)]
    pub(crate) fn pop_caller_validated_region(
        &mut self,
        mark: RuntimeAllocatorRegionMark,
        _reclaimed_records: usize,
    ) -> Result<ArenaRegionPopReport, ArenaError> {
        // SAFETY: `EvalHeap::pop_worker_region_if_disconnected` is the only
        // caller. It validates that `mark` belongs to the current heap and
        // allocator lifetime, is the innermost active marker, reclaims only
        // worker-domain suffix records, and has no retained precise edges into
        // that suffix before reaching this allocator boundary.
        let report = unsafe { self.arena_mut().pop_region_to_mark(mark.arena()) }?;
        self.safepoints = mark.safepoints();
        Ok(report)
    }

    /// Returns allocation-safepoint accounting for this allocator domain.
    pub const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.safepoints
    }

    /// Drops the installed worker arena and replaces it with an empty arena.
    ///
    /// The returned accounting describes the dropped arena. The installed
    /// GC-stress policy is preserved for the next worker lifetime, while
    /// allocation-safepoint accounting is reset with the new empty arena. Any
    /// allocation handles returned before the reset must be considered dead by
    /// the caller; [`EvalHeap::reset_worker_allocator_if_idle`](crate::eval::heap::EvalHeap::reset_worker_allocator_if_idle)
    /// is the typed side-table admission boundary for evaluator-owned values.
    pub(crate) fn reset_to_empty(&mut self) -> ArenaStats {
        let previous = mem::replace(
            &mut self.backend,
            RuntimeAllocatorBackend::TierAOneShot(BumpArena::new()),
        );
        let stats = match &previous {
            RuntimeAllocatorBackend::TierAOneShot(arena) => arena.stats(),
        };
        drop(previous);
        self.safepoints = AllocationSafepointState::default();
        stats
    }

    /// Allocates a thunk-sized heap object through `aos_alloc_thunk`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_thunk(&mut self) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena_mut().aos_alloc_thunk()?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocThunk, allocation);
        Ok(allocation)
    }

    /// Allocates a lambda-sized heap object through `aos_alloc_lambda`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_lambda(&mut self) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena_mut().aos_alloc_lambda()?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocLambda, allocation);
        Ok(allocation)
    }

    /// Allocates an attribute-set heap object through `aos_alloc_attrs`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_attrs(
        &mut self,
        shape: u32,
        slots: u32,
    ) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena_mut().aos_alloc_attrs(shape, slots)?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocAttrs, allocation);
        Ok(allocation)
    }

    /// Allocates a cons-cell heap object through `aos_alloc_cons`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_cons(&mut self) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena_mut().aos_alloc_cons()?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocCons, allocation);
        Ok(allocation)
    }

    /// Allocates a contiguous list heap object through `aos_alloc_list`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_list(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena_mut().aos_alloc_list(len)?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocList, allocation);
        Ok(allocation)
    }

    /// Allocates a string heap object through `aos_alloc_string`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_string(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena_mut().aos_alloc_string(len)?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocString, allocation);
        Ok(allocation)
    }

    /// Allocates raw heap storage through `aos_alloc_raw`.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if the active allocation strategy cannot reserve
    /// the requested object.
    pub fn aos_alloc_raw(
        &mut self,
        size: usize,
        align: usize,
        type_tag: u32,
    ) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena_mut().aos_alloc_raw(size, align, type_tag)?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocRaw, allocation);
        Ok(allocation)
    }

    fn arena_mut(&mut self) -> &mut BumpArena {
        match &mut self.backend {
            RuntimeAllocatorBackend::TierAOneShot(arena) => arena,
        }
    }

    fn record_allocation_safepoint(
        &mut self,
        entrypoint: RuntimeAllocationEntryPoint,
        allocation: ArenaAllocation,
    ) {
        let tier = self.tier();
        let stats = self.stats();
        let gc_stress_policy = self.gc_stress_policy;
        self.safepoints
            .record(tier, entrypoint, allocation, stats, gc_stress_policy);
    }
}

#[derive(Debug)]
enum RuntimeAllocatorBackend {
    TierAOneShot(BumpArena),
}

/// Allocates reusable hash-consed values in permanent shared storage.
#[derive(Debug)]
pub(crate) struct PermanentSharedAllocator {
    arena: BumpArena,
    safepoints: AllocationSafepointState,
    gc_stress_policy: GcStressPolicy,
}

impl Default for PermanentSharedAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl PermanentSharedAllocator {
    /// Creates a permanent-shared allocator.
    pub(crate) fn new() -> Self {
        Self {
            arena: BumpArena::new(),
            safepoints: AllocationSafepointState::default(),
            gc_stress_policy: GcStressPolicy::disabled(),
        }
    }

    /// Creates a permanent-shared allocator with an explicit first chunk size.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError::InvalidChunkSize`] when `chunk_bytes` is zero, or
    /// [`ArenaError::SizeOverflow`] if rounding the chunk size overflows.
    pub(crate) fn with_initial_chunk_bytes(chunk_bytes: usize) -> Result<Self, ArenaError> {
        Ok(Self {
            arena: BumpArena::with_initial_chunk_bytes(chunk_bytes)?,
            safepoints: AllocationSafepointState::default(),
            gc_stress_policy: GcStressPolicy::disabled(),
        })
    }

    /// Installs a GC-stress polling policy for later allocation safepoints.
    ///
    /// Periodic policies use this allocator's lifetime safepoint sequence, so
    /// installing a policy does not reset the cadence.
    pub(crate) fn set_gc_stress_policy(&mut self, policy: GcStressPolicy) {
        self.gc_stress_policy = policy;
    }

    /// Returns the installed GC-stress polling policy.
    pub(crate) const fn gc_stress_policy(&self) -> GcStressPolicy {
        self.gc_stress_policy
    }

    /// Returns the allocator tier for permanent shared storage.
    pub(crate) const fn tier(&self) -> RuntimeAllocatorTier {
        RuntimeAllocatorTier::PermanentShared
    }

    /// Returns current permanent shared allocation accounting.
    pub(crate) fn stats(&self) -> ArenaStats {
        self.arena.stats()
    }

    /// Advises unused bytes at the end of permanent shared arena chunks.
    pub(crate) fn advise_unused_tail(&self, kind: MemoryAdviceKind) -> ArenaMemoryAdviceReport {
        self.arena.advise_unused_tail(kind)
    }

    /// Returns unused-tail bytes this allocator can lower to page advice.
    pub(crate) fn supported_unused_tail_advice_bytes(&self) -> usize {
        self.arena.supported_unused_tail_advice_bytes()
    }

    /// Returns allocation-safepoint accounting for permanent shared storage.
    pub(crate) const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.safepoints
    }

    /// Allocates a permanent-shared attribute-set heap object.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if permanent storage cannot reserve the object.
    pub(crate) fn aos_alloc_attrs(
        &mut self,
        shape: u32,
        slots: u32,
    ) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena.aos_alloc_attrs(shape, slots)?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocAttrs, allocation);
        Ok(allocation)
    }

    /// Allocates a permanent-shared contiguous list heap object.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if permanent storage cannot reserve the object.
    pub(crate) fn aos_alloc_list(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena.aos_alloc_list(len)?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocList, allocation);
        Ok(allocation)
    }

    /// Allocates a permanent-shared string or path heap object.
    ///
    /// # Errors
    ///
    /// Returns [`ArenaError`] if permanent storage cannot reserve the object.
    pub(crate) fn aos_alloc_string(&mut self, len: usize) -> Result<ArenaAllocation, ArenaError> {
        let allocation = self.arena.aos_alloc_string(len)?;
        self.record_allocation_safepoint(RuntimeAllocationEntryPoint::AosAllocString, allocation);
        Ok(allocation)
    }

    fn record_allocation_safepoint(
        &mut self,
        entrypoint: RuntimeAllocationEntryPoint,
        allocation: ArenaAllocation,
    ) {
        let tier = self.tier();
        let stats = self.stats();
        let gc_stress_policy = self.gc_stress_policy;
        self.safepoints
            .record(tier, entrypoint, allocation, stats, gc_stress_policy);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::compile::{RuntimeHelperRole, runtime_helper_symbols};
    use crate::heap::arena::HeapObjectKind;

    use super::*;

    fn assert_last_safepoint(
        state: AllocationSafepointState,
        sequence: u64,
        tier: RuntimeAllocatorTier,
        entrypoint: RuntimeAllocationEntryPoint,
        allocation: ArenaAllocation,
        stats: ArenaStats,
    ) {
        assert_eq!(state.count(), sequence);
        let event = state.last().expect("safepoint records");
        assert_eq!(event.sequence(), sequence);
        assert_eq!(event.tier(), tier);
        assert_eq!(event.entrypoint(), entrypoint);
        assert_eq!(event.kind(), allocation.kind);
        assert_eq!(event.requested_size(), allocation.requested_size);
        assert_eq!(event.reserved_size(), allocation.reserved_size);
        assert_eq!(event.stats_after(), stats);
        assert_eq!(event.heap_chunks_after(), stats.chunks);
        assert_eq!(event.heap_used_bytes_after(), stats.used_bytes);
        assert_eq!(event.heap_reserved_bytes_after(), stats.reserved_bytes);
        assert_eq!(event.heap_mapped_bytes_after(), stats.mapped_bytes);
        assert_eq!(event.gc_poll_reason(), None);
        assert_eq!(event.collector_poll(), None);
        assert_eq!(state.last_safepoint_collector_poll(), None);
    }

    fn memory_budget(bytes: usize) -> HeapMemoryBudget {
        HeapMemoryBudget::new(bytes).expect("budget is non-zero")
    }

    #[test]
    fn tier_a_allocator_routes_every_entrypoint() {
        let mut allocator =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(512).expect("allocator creates");

        assert_eq!(allocator.tier(), RuntimeAllocatorTier::TierAOneShot);
        assert!(allocator.gc_stress_policy().is_disabled());
        assert_eq!(
            allocator.allocation_safepoints(),
            AllocationSafepointState::default()
        );
        let allocation = allocator.aos_alloc_thunk().expect("thunk allocates");
        assert_eq!(allocation.kind, HeapObjectKind::Thunk);
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            1,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocThunk,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_lambda().expect("lambda allocates");
        assert_eq!(allocation.kind, HeapObjectKind::Lambda);
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            2,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocLambda,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_attrs(7, 2).expect("attrs allocates");
        assert_eq!(
            allocation.kind,
            HeapObjectKind::Attrs { shape: 7, slots: 2 }
        );
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            3,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocAttrs,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_cons().expect("cons allocates");
        assert_eq!(allocation.kind, HeapObjectKind::Cons);
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            4,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocCons,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_list(3).expect("list allocates");
        assert_eq!(allocation.kind, HeapObjectKind::List { len: 3 });
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            5,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocList,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_string(5).expect("string allocates");
        assert_eq!(allocation.kind, HeapObjectKind::String { len: 5 });
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            6,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocString,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator
            .aos_alloc_raw(8, 8, 0x7261_7770)
            .expect("raw allocates");
        assert_eq!(
            allocation.kind,
            HeapObjectKind::Raw {
                type_tag: 0x7261_7770,
            }
        );
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            7,
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocRaw,
            allocation,
            allocator.stats(),
        );

        let stats = allocator.stats();
        assert_eq!(stats.chunks, 1);
        assert!(stats.used_bytes > 0);
    }

    #[test]
    fn permanent_shared_allocator_routes_only_reusable_value_shapes() {
        let mut allocator =
            PermanentSharedAllocator::with_initial_chunk_bytes(256).expect("allocator creates");

        assert_eq!(allocator.tier(), RuntimeAllocatorTier::PermanentShared);
        assert!(allocator.gc_stress_policy().is_disabled());
        assert_eq!(allocator.stats(), ArenaStats::default());
        assert_eq!(
            allocator.allocation_safepoints(),
            AllocationSafepointState::default()
        );
        let allocation = allocator.aos_alloc_attrs(7, 2).expect("attrs allocates");
        assert_eq!(
            allocation.kind,
            HeapObjectKind::Attrs { shape: 7, slots: 2 }
        );
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            1,
            RuntimeAllocatorTier::PermanentShared,
            RuntimeAllocationEntryPoint::AosAllocAttrs,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_list(3).expect("list allocates");
        assert_eq!(allocation.kind, HeapObjectKind::List { len: 3 });
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            2,
            RuntimeAllocatorTier::PermanentShared,
            RuntimeAllocationEntryPoint::AosAllocList,
            allocation,
            allocator.stats(),
        );

        let allocation = allocator.aos_alloc_string(5).expect("string allocates");
        assert_eq!(allocation.kind, HeapObjectKind::String { len: 5 });
        assert_last_safepoint(
            allocator.allocation_safepoints(),
            3,
            RuntimeAllocatorTier::PermanentShared,
            RuntimeAllocationEntryPoint::AosAllocString,
            allocation,
            allocator.stats(),
        );

        let stats = allocator.stats();
        assert_eq!(stats.chunks, 1);
        assert!(stats.used_bytes > 0);
    }

    #[test]
    fn allocation_safepoint_classifies_high_water_memory_budget() {
        let mut allocator =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(128).expect("allocator creates");
        allocator.aos_alloc_thunk().expect("thunk allocates");
        let state = allocator.allocation_safepoints();
        let safepoint = state.last().expect("safepoint records");
        let mapped_bytes = safepoint.heap_mapped_bytes_after();
        assert!(mapped_bytes > 1);

        let loose_budget = memory_budget(mapped_bytes.checked_mul(2).expect("budget doubles"));
        let continue_decision = safepoint.classify_memory_budget(loose_budget, 0, 0);
        assert_eq!(continue_decision.sequence(), safepoint.sequence());
        assert_eq!(continue_decision.tier(), RuntimeAllocatorTier::TierAOneShot);
        assert_eq!(
            continue_decision.entrypoint(),
            RuntimeAllocationEntryPoint::AosAllocThunk
        );
        assert_eq!(continue_decision.budget(), loose_budget);
        assert_eq!(
            continue_decision.sample(),
            HeapMemorySample::new(mapped_bytes, 0, 0)
        );
        assert_eq!(continue_decision.stats_after(), safepoint.stats_after());
        assert_eq!(
            continue_decision.response(),
            HeapMemoryBudgetResponse::ContinueTierA {
                headroom_bytes: loose_budget.soft_limit_bytes() - mapped_bytes,
                projected_resident_bytes: mapped_bytes,
            }
        );
        assert!(!continue_decision.requires_runtime_action());
        assert!(!continue_decision.requests_tier_b());

        let spill_budget = memory_budget(mapped_bytes);
        let spill_reclaim_bytes = mapped_bytes - spill_budget.soft_limit_bytes();
        let spill_decision = state
            .last_memory_budget_decision(spill_budget, spill_reclaim_bytes, 0)
            .expect("last safepoint classifies");
        assert_eq!(
            spill_decision.sample(),
            HeapMemorySample::new(mapped_bytes, spill_reclaim_bytes, 0)
        );
        assert_eq!(
            spill_decision.response(),
            HeapMemoryBudgetResponse::SpillCold {
                desired_reclaim_bytes: spill_reclaim_bytes,
                available_reclaim_bytes: spill_reclaim_bytes,
                projected_resident_bytes: spill_budget.soft_limit_bytes(),
            }
        );
        assert!(spill_decision.requires_runtime_action());
        assert!(!spill_decision.requests_tier_b());

        let tier_b_budget = memory_budget(mapped_bytes / 2);
        let tier_b_decision = safepoint.classify_memory_budget(tier_b_budget, 0, 0);
        assert_eq!(
            tier_b_decision.response(),
            HeapMemoryBudgetResponse::InstallTierB {
                desired_reclaim_bytes: mapped_bytes - tier_b_budget.soft_limit_bytes(),
                available_reclaim_bytes: 0,
                projected_resident_bytes: mapped_bytes,
                over_budget_bytes: mapped_bytes - tier_b_budget.max_resident_bytes(),
            }
        );
        assert!(tier_b_decision.requires_runtime_action());
        assert!(tier_b_decision.requests_tier_b());

        assert_eq!(
            AllocationSafepointState::default().last_memory_budget_decision(loose_budget, 0, 0),
            None
        );
    }

    #[test]
    fn runtime_allocators_report_unused_tail_advice() {
        let mut worker =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(65536).expect("worker creates");
        worker.aos_alloc_thunk().expect("worker allocates");
        let worker_supported_tail_advice_bytes = worker.supported_unused_tail_advice_bytes();

        let worker_report = worker.advise_unused_tail(MemoryAdviceKind::Dead);

        assert_eq!(worker_report.kind(), MemoryAdviceKind::Dead);
        assert_eq!(worker_report.chunks(), 1);
        assert!(worker_report.requested_bytes() > 0);
        #[cfg(target_os = "linux")]
        assert!(worker_supported_tail_advice_bytes > 0);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(worker_supported_tail_advice_bytes, 0);
        assert!(worker_supported_tail_advice_bytes <= worker_report.requested_bytes());
        assert_eq!(
            worker_report.applied()
                + worker_report.unsupported()
                + worker_report.empty_ranges()
                + worker_report.rejected(),
            1
        );

        let mut permanent =
            PermanentSharedAllocator::with_initial_chunk_bytes(65536).expect("permanent creates");
        permanent
            .aos_alloc_string(1)
            .expect("permanent string allocates");
        let permanent_supported_tail_advice_bytes = permanent.supported_unused_tail_advice_bytes();

        let permanent_report = permanent.advise_unused_tail(MemoryAdviceKind::Dead);

        assert_eq!(permanent_report.kind(), MemoryAdviceKind::Dead);
        assert_eq!(permanent_report.chunks(), 1);
        assert!(permanent_report.requested_bytes() > 0);
        #[cfg(target_os = "linux")]
        assert!(permanent_supported_tail_advice_bytes > 0);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(permanent_supported_tail_advice_bytes, 0);
        assert!(permanent_supported_tail_advice_bytes <= permanent_report.requested_bytes());
        assert_eq!(
            permanent_report.applied()
                + permanent_report.unsupported()
                + permanent_report.empty_ranges()
                + permanent_report.rejected(),
            1
        );
    }

    #[test]
    fn worker_allocator_reset_drops_worker_chunks_without_touching_permanent_storage() {
        let mut worker =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(128).expect("worker creates");
        let mut permanent =
            PermanentSharedAllocator::with_initial_chunk_bytes(128).expect("permanent creates");
        worker.set_gc_stress_policy(GcStressPolicy::every_safepoint());
        worker.aos_alloc_thunk().expect("worker allocates");
        permanent
            .aos_alloc_string(5)
            .expect("permanent string allocates");
        let worker_stats_before = worker.stats();
        let permanent_stats_before = permanent.stats();
        let permanent_safepoints_before = permanent.allocation_safepoints();

        let dropped_worker_stats = worker.reset_to_empty();

        assert_eq!(dropped_worker_stats, worker_stats_before);
        assert_eq!(worker.stats(), ArenaStats::default());
        assert_eq!(
            worker.allocation_safepoints(),
            AllocationSafepointState::default()
        );
        assert_eq!(worker.gc_stress_policy(), GcStressPolicy::every_safepoint());
        assert_eq!(permanent.stats(), permanent_stats_before);
        assert_eq!(
            permanent.allocation_safepoints(),
            permanent_safepoints_before
        );

        permanent
            .aos_alloc_string(7)
            .expect("permanent allocator remains usable after worker reset");
        assert_eq!(permanent.allocation_safepoints().count(), 2);
        assert!(permanent.stats().used_bytes > permanent_stats_before.used_bytes);
    }

    #[test]
    fn runtime_abi_declares_allocator_entrypoint_names() {
        let allocation_symbols = runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() == RuntimeHelperRole::Allocation)
            .map(|symbol| symbol.name())
            .collect::<BTreeSet<_>>();
        let runtime_entrypoint_symbols = runtime_allocation_entrypoints()
            .iter()
            .copied()
            .map(RuntimeAllocationEntryPoint::symbol_name)
            .collect::<BTreeSet<_>>();
        let runtime_signature_symbols = runtime_allocation_abi_signatures()
            .iter()
            .copied()
            .map(RuntimeAllocationAbiSignature::symbol_name)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            allocation_symbols,
            BTreeSet::from([
                "aos_alloc_attrs",
                "aos_alloc_cons",
                "aos_alloc_lambda",
                "aos_alloc_list",
                "aos_alloc_raw",
                "aos_alloc_string",
                "aos_alloc_thunk",
            ])
        );
        assert_eq!(runtime_entrypoint_symbols, allocation_symbols);
        assert_eq!(runtime_signature_symbols, allocation_symbols);
    }

    #[test]
    fn allocation_entrypoint_symbols_round_trip() {
        assert_eq!(
            runtime_allocation_entrypoints(),
            [
                RuntimeAllocationEntryPoint::AosAllocAttrs,
                RuntimeAllocationEntryPoint::AosAllocCons,
                RuntimeAllocationEntryPoint::AosAllocLambda,
                RuntimeAllocationEntryPoint::AosAllocList,
                RuntimeAllocationEntryPoint::AosAllocRaw,
                RuntimeAllocationEntryPoint::AosAllocString,
                RuntimeAllocationEntryPoint::AosAllocThunk,
            ]
        );

        for entrypoint in runtime_allocation_entrypoints() {
            assert_eq!(
                RuntimeAllocationEntryPoint::from_symbol_name(entrypoint.symbol_name()),
                Some(*entrypoint)
            );
            assert_eq!(
                RuntimeAllocationAbiSignature::from_symbol_name(entrypoint.symbol_name()),
                Some(entrypoint.abi_signature())
            );
        }
        for symbol in runtime_helper_symbols()
            .iter()
            .copied()
            .filter(|symbol| symbol.role() != RuntimeHelperRole::Allocation)
        {
            assert_eq!(
                RuntimeAllocationEntryPoint::from_symbol_name(symbol.name()),
                None,
                "{} is not an allocation entry point",
                symbol.name()
            );
            assert_eq!(
                RuntimeAllocationAbiSignature::from_symbol_name(symbol.name()),
                None,
                "{} has no allocation ABI signature",
                symbol.name()
            );
        }
        assert_eq!(
            RuntimeAllocationEntryPoint::from_symbol_name("nix.builtin.derivationStrict"),
            None
        );
        assert_eq!(
            RuntimeAllocationAbiSignature::from_symbol_name("nix.builtin.derivationStrict"),
            None
        );
    }

    #[test]
    fn allocation_abi_signatures_pin_runtime_parameters() {
        fn assert_signature(
            entrypoint: RuntimeAllocationEntryPoint,
            parameters: &[RuntimeAllocationAbiParameter],
            return_kind: RuntimeAllocationAbiReturnKind,
        ) {
            let signature = entrypoint.abi_signature();
            assert_eq!(signature.entrypoint(), entrypoint);
            assert_eq!(signature.parameters(), parameters);
            assert_eq!(signature.return_kind(), return_kind);
        }

        assert_eq!(
            runtime_allocation_abi_signatures()
                .iter()
                .copied()
                .map(RuntimeAllocationAbiSignature::entrypoint)
                .collect::<Vec<_>>(),
            runtime_allocation_entrypoints()
        );

        for signature in runtime_allocation_abi_signatures().iter().copied() {
            assert_eq!(signature.entrypoint().abi_signature(), signature);
            assert_eq!(
                signature.symbol_name(),
                signature.entrypoint().symbol_name()
            );
            assert_eq!(
                signature.parameters().first().copied(),
                Some(RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                )),
                "{} takes the runtime context first",
                signature.symbol_name()
            );
        }

        assert_signature(
            RuntimeAllocationEntryPoint::AosAllocThunk,
            &[
                RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                ),
                RuntimeAllocationAbiParameter::new(
                    "code_ptr",
                    RuntimeAllocationAbiParameterKind::CodePointer,
                ),
                RuntimeAllocationAbiParameter::new(
                    "env",
                    RuntimeAllocationAbiParameterKind::EnvPointer,
                ),
            ],
            RuntimeAllocationAbiReturnKind::ThunkPointer,
        );
        assert_signature(
            RuntimeAllocationEntryPoint::AosAllocLambda,
            &[
                RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                ),
                RuntimeAllocationAbiParameter::new(
                    "code_ptr",
                    RuntimeAllocationAbiParameterKind::CodePointer,
                ),
                RuntimeAllocationAbiParameter::new(
                    "env",
                    RuntimeAllocationAbiParameterKind::EnvPointer,
                ),
            ],
            RuntimeAllocationAbiReturnKind::LambdaPointer,
        );
        assert_signature(
            RuntimeAllocationEntryPoint::AosAllocAttrs,
            [
                RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                ),
                RuntimeAllocationAbiParameter::new(
                    "shape",
                    RuntimeAllocationAbiParameterKind::ShapeId,
                ),
                RuntimeAllocationAbiParameter::new("slots", RuntimeAllocationAbiParameterKind::U32),
            ]
            .as_slice(),
            RuntimeAllocationAbiReturnKind::AttrsPointer,
        );
        assert_signature(
            RuntimeAllocationEntryPoint::AosAllocCons,
            &[
                RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                ),
                RuntimeAllocationAbiParameter::new(
                    "head",
                    RuntimeAllocationAbiParameterKind::Value,
                ),
                RuntimeAllocationAbiParameter::new(
                    "tail",
                    RuntimeAllocationAbiParameterKind::ListPointer,
                ),
            ],
            RuntimeAllocationAbiReturnKind::ListPointer,
        );
        assert_signature(
            RuntimeAllocationEntryPoint::AosAllocList,
            [
                RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                ),
                RuntimeAllocationAbiParameter::new("len", RuntimeAllocationAbiParameterKind::Usize),
            ]
            .as_slice(),
            RuntimeAllocationAbiReturnKind::ListPointer,
        );
        assert_signature(
            RuntimeAllocationEntryPoint::AosAllocString,
            [
                RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                ),
                RuntimeAllocationAbiParameter::new("len", RuntimeAllocationAbiParameterKind::Usize),
            ]
            .as_slice(),
            RuntimeAllocationAbiReturnKind::StringHeaderPointer,
        );
        assert_signature(
            RuntimeAllocationEntryPoint::AosAllocRaw,
            &[
                RuntimeAllocationAbiParameter::new(
                    "rt",
                    RuntimeAllocationAbiParameterKind::RuntimeContext,
                ),
                RuntimeAllocationAbiParameter::new(
                    "size",
                    RuntimeAllocationAbiParameterKind::Usize,
                ),
                RuntimeAllocationAbiParameter::new(
                    "align",
                    RuntimeAllocationAbiParameterKind::Usize,
                ),
                RuntimeAllocationAbiParameter::new(
                    "type_tag",
                    RuntimeAllocationAbiParameterKind::TypeTag,
                ),
            ],
            RuntimeAllocationAbiReturnKind::RawPointer,
        );
    }

    #[test]
    fn invalid_tier_a_chunk_size_is_rejected() {
        let error = RuntimeAllocator::tier_a_with_initial_chunk_bytes(0)
            .expect_err("zero-sized chunks are invalid");

        assert_eq!(error, ArenaError::InvalidChunkSize { chunk_bytes: 0 });
    }

    #[test]
    fn gc_stress_period_rejects_zero() {
        assert_eq!(
            GcStressPolicy::every_n_safepoints(0),
            Err(GcStressPolicyError::ZeroPeriod)
        );
    }

    #[test]
    fn gc_stress_every_safepoint_records_poll_reason() {
        let mut allocator =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(128).expect("allocator creates");
        allocator.set_gc_stress_policy(GcStressPolicy::every_safepoint());

        allocator.aos_alloc_thunk().expect("thunk allocates");

        let event = allocator
            .allocation_safepoints()
            .last()
            .expect("safepoint records");
        assert_eq!(event.sequence(), 1);
        assert_eq!(
            event.gc_poll_reason(),
            Some(AllocationGcPollReason::GcStressEverySafepoint)
        );
        let poll = event.collector_poll().expect("poll request records");
        assert_eq!(poll.sequence(), event.sequence());
        assert_eq!(poll.tier(), RuntimeAllocatorTier::TierAOneShot);
        assert_eq!(
            poll.entrypoint(),
            RuntimeAllocationEntryPoint::AosAllocThunk
        );
        assert_eq!(
            poll.reason(),
            AllocationGcPollReason::GcStressEverySafepoint
        );
        assert_eq!(poll.stats_after(), event.stats_after());
        assert_eq!(
            allocator
                .allocation_safepoints()
                .last_safepoint_collector_poll(),
            Some(poll)
        );
    }

    #[test]
    fn gc_stress_periodic_policy_records_poll_on_matching_sequences() {
        let mut allocator = RuntimeAllocator::tier_a_with_initial_chunk_bytes(128)
            .expect("allocator creates")
            .with_gc_stress_policy(
                GcStressPolicy::every_n_safepoints(2).expect("period is non-zero"),
            );

        allocator.aos_alloc_thunk().expect("first allocation");
        assert_eq!(
            allocator
                .allocation_safepoints()
                .last()
                .expect("first safepoint")
                .gc_poll_reason(),
            None
        );

        allocator.aos_alloc_lambda().expect("second allocation");
        assert_eq!(
            allocator
                .allocation_safepoints()
                .last()
                .expect("second safepoint")
                .gc_poll_reason(),
            Some(AllocationGcPollReason::GcStressEveryNSafepoints { period: 2 })
        );

        allocator.aos_alloc_cons().expect("third allocation");
        assert_eq!(
            allocator
                .allocation_safepoints()
                .last()
                .expect("third safepoint")
                .gc_poll_reason(),
            None
        );
    }

    #[test]
    fn periodic_gc_stress_uses_allocator_lifetime_sequence() {
        let mut allocator =
            RuntimeAllocator::tier_a_with_initial_chunk_bytes(128).expect("allocator creates");
        allocator.aos_alloc_thunk().expect("first allocation");

        allocator.set_gc_stress_policy(
            GcStressPolicy::every_n_safepoints(2).expect("period is non-zero"),
        );
        allocator.aos_alloc_lambda().expect("second allocation");

        let event = allocator
            .allocation_safepoints()
            .last()
            .expect("second safepoint");
        assert_eq!(event.sequence(), 2);
        assert_eq!(
            event.gc_poll_reason(),
            Some(AllocationGcPollReason::GcStressEveryNSafepoints { period: 2 })
        );
    }

    #[test]
    fn enabled_gc_stress_polls_when_safepoint_sequence_saturates() {
        let mut arena = BumpArena::with_initial_chunk_bytes(64).expect("arena creates");
        let allocation = arena.aos_alloc_thunk().expect("thunk allocates");
        let mut state = AllocationSafepointState {
            count: u64::MAX - 1,
            last: None,
        };
        let policy = GcStressPolicy::every_n_safepoints(2).expect("period is non-zero");

        state.record(
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocThunk,
            allocation,
            arena.stats(),
            policy,
        );
        let event = state.last().expect("saturated safepoint records");
        assert_eq!(event.sequence(), u64::MAX);
        assert_eq!(
            event.gc_poll_reason(),
            Some(AllocationGcPollReason::GcStressSequenceSaturated)
        );
        assert_eq!(
            event.collector_poll().expect("poll records").reason(),
            AllocationGcPollReason::GcStressSequenceSaturated
        );

        state.record(
            RuntimeAllocatorTier::TierAOneShot,
            RuntimeAllocationEntryPoint::AosAllocThunk,
            allocation,
            arena.stats(),
            policy,
        );
        let event = state.last().expect("post-saturation safepoint records");
        assert_eq!(event.sequence(), u64::MAX);
        assert_eq!(
            event.gc_poll_reason(),
            Some(AllocationGcPollReason::GcStressSequenceSaturated)
        );
        assert_eq!(
            state
                .last_safepoint_collector_poll()
                .expect("poll records")
                .sequence(),
            u64::MAX
        );
    }

    #[test]
    fn permanent_shared_allocations_can_record_gc_stress_poll_reason() {
        let mut allocator =
            PermanentSharedAllocator::with_initial_chunk_bytes(128).expect("allocator creates");
        allocator.set_gc_stress_policy(GcStressPolicy::every_safepoint());

        allocator.aos_alloc_string(5).expect("string allocates");

        let event = allocator
            .allocation_safepoints()
            .last()
            .expect("safepoint records");
        assert_eq!(event.tier(), RuntimeAllocatorTier::PermanentShared);
        assert_eq!(
            event.gc_poll_reason(),
            Some(AllocationGcPollReason::GcStressEverySafepoint)
        );
        let poll = allocator
            .allocation_safepoints()
            .last_safepoint_collector_poll()
            .expect("permanent poll records");
        assert_eq!(poll.sequence(), event.sequence());
        assert_eq!(poll.tier(), RuntimeAllocatorTier::PermanentShared);
        assert_eq!(
            poll.entrypoint(),
            RuntimeAllocationEntryPoint::AosAllocString
        );
        assert_eq!(
            poll.reason(),
            AllocationGcPollReason::GcStressEverySafepoint
        );
        assert_eq!(poll.stats_after(), event.stats_after());
    }
}
