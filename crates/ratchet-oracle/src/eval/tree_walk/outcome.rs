//! Evaluation outcome, derivation, statistics, trace, IFD-realization, and warning types.

use std::ptr::NonNull;

use thiserror::Error;

use super::*;
use crate::cache::ImpureInputTraceSource;
use crate::compile::EffectClass;
use crate::eval::heap::{
    AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    AllocationCollectorPollObjectBodyWriteReport, AllocationCollectorPollObjectByteCopyPlan,
    AllocationCollectorPollObjectGenerationWritePlan,
    AllocationCollectorPollObjectGenerationWriteReport, EvalHeapError, EvalHeapMemoryAdviceReport,
    EvalHeapMemoryBudgetDecision, EvalHeapTierBAdmissionPlan, EvalHeapTierBAdmissionReport,
    EvalRootSource,
};
use crate::heap::{ArenaStats, HeapGeneration};
use crate::value::HeapObject;

mod memo_stats;
pub use memo_stats::{MemoEconomicsStats, MemoTierEvents};

#[cfg(test)]
mod destination_object_generation_binding_tests;
#[cfg(test)]
mod forwarding_destination_binding_tests;
#[cfg(test)]
mod heap_field_writeback_destination_binding_tests;
#[cfg(test)]
mod live_remembered_set_merge_tests;
#[cfg(test)]
mod object_generation_write_plan_tests;
#[cfg(test)]
mod root_writeback_destination_binding_tests;

type IfdRealizerCallback =
    dyn for<'a> Fn(IfdRealization<'a>) -> Result<(), IfdRealizationError> + Send + Sync;

const BOUNDARY_MINOR_GC_ROOT_REFERENCE_VALUES_TABLE: &str =
    "boundary minor-GC root reference values";
const BOUNDARY_MINOR_GC_OBJECT_BYTE_COPY_APPLICATIONS_TABLE: &str =
    "boundary minor-GC object byte-copy applications";
const BOUNDARY_MINOR_GC_OBJECT_SOURCE_BYTES_TABLE: &str = "boundary minor-GC object source bytes";
const BOUNDARY_MINOR_GC_OBJECT_DESTINATION_BYTES_TABLE: &str =
    "boundary minor-GC object destination bytes";
const BOUNDARY_MINOR_GC_OBJECT_BYTE_COPY_BUFFERS_TABLE: &str =
    "boundary minor-GC object byte-copy buffers";
const BOUNDARY_MINOR_GC_SOURCE_OBJECT_BYTES_TABLE: &str =
    "boundary minor-GC source object byte refs";
const BOUNDARY_MINOR_GC_NURSERY_DESTINATION_STORAGE_BYTES_TABLE: &str =
    "boundary minor-GC nursery destination storage bytes";
const BOUNDARY_MINOR_GC_OLD_DESTINATION_STORAGE_BYTES_TABLE: &str =
    "boundary minor-GC old destination storage bytes";
const BOUNDARY_MINOR_GC_DESTINATION_STORAGE_LAYOUTS_TABLE: &str =
    "boundary minor-GC destination storage layouts";
const BOUNDARY_MINOR_GC_LIVE_DESTINATION_OBJECT_BYTES_TABLE: &str =
    "boundary minor-GC live destination object bytes";
const BOUNDARY_MINOR_GC_LIVE_OBJECT_GENERATIONS_TABLE: &str =
    "boundary minor-GC live object generations";
const BOUNDARY_MINOR_GC_DESTINATION_OBJECT_GENERATION_BINDINGS_TABLE: &str =
    "boundary minor-GC destination object-generation bindings";
const BOUNDARY_MINOR_GC_OBJECT_GENERATION_WRITES_TABLE: &str =
    "boundary minor-GC object-generation writes";
const BOUNDARY_MINOR_GC_OBJECT_GENERATION_WRITE_BYTES_TABLE: &str =
    "boundary minor-GC object-generation write bytes";
const BOUNDARY_MINOR_GC_OBJECT_BODY_GENERATION_PREFLIGHT_REQUESTS_TABLE: &str =
    "boundary minor-GC object body/generation preflight requests";
const BOUNDARY_MINOR_GC_FORWARDING_DESTINATION_BINDINGS_TABLE: &str =
    "boundary minor-GC forwarding destination bindings";
const BOUNDARY_MINOR_GC_FORWARDING_HEADER_WRITES_TABLE: &str =
    "boundary minor-GC forwarding-header writes";
const BOUNDARY_MINOR_GC_FORWARDING_HEADER_WRITE_BYTES_TABLE: &str =
    "boundary minor-GC forwarding-header write bytes";
const BOUNDARY_MINOR_GC_ROOT_WRITEBACK_DESTINATION_BINDINGS_TABLE: &str =
    "boundary minor-GC root writeback destination bindings";
const BOUNDARY_MINOR_GC_ROOT_WRITEBACK_WRITES_TABLE: &str =
    "boundary minor-GC root writeback writes";
const BOUNDARY_MINOR_GC_ROOT_WRITEBACK_WRITE_BYTES_TABLE: &str =
    "boundary minor-GC root writeback write bytes";
const BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE: &str =
    "boundary minor-GC heap-field writeback destination bindings";
const BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE: &str =
    "boundary minor-GC heap-field writeback writes";
const BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITE_BYTES_TABLE: &str =
    "boundary minor-GC heap-field writeback write bytes";
const BOUNDARY_MINOR_GC_REFERENCE_WRITEBACK_WRITES_TABLE: &str =
    "boundary minor-GC reference writeback writes";
const BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE: &str =
    "boundary minor-GC forwarding slot buffer";
const BOUNDARY_MINOR_GC_REFERENCE_BUFFER_TABLE: &str = "boundary minor-GC reference buffer";
const BOUNDARY_MINOR_GC_ROOT_WRITEBACK_SLOTS_TABLE: &str = "boundary minor-GC root writeback slots";
const BOUNDARY_MINOR_GC_ROOT_VALUE_WRITEBACK_SLOTS_TABLE: &str =
    "boundary minor-GC root value writeback slots";
const BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_SLOTS_TABLE: &str =
    "boundary minor-GC heap-field writeback slots";
const BOUNDARY_MINOR_GC_LIVE_ROOT_WRITEBACK_SLOTS_TABLE: &str =
    "boundary minor-GC live root writeback slots";
const BOUNDARY_MINOR_GC_LIVE_ROOT_VALUE_WRITEBACK_SLOTS_TABLE: &str =
    "boundary minor-GC live root value writeback slots";
const BOUNDARY_MINOR_GC_LIVE_HEAP_FIELD_WRITEBACK_SLOTS_TABLE: &str =
    "boundary minor-GC live heap-field writeback slots";

/// Metadata for a requested Tier-B heap transition.
///
mod tier_b_transition;
pub use tier_b_transition::*;

mod boundary_binding_fns;
mod boundary_commit_applications;
mod boundary_commit_types;
mod boundary_dry_run;
mod boundary_heap_field_fns;
mod boundary_live_installs;
mod boundary_merge_fns;
mod boundary_object_plan_fns;
mod boundary_root_reference_fns;
mod boundary_root_writeback_types;
mod boundary_scan_types;
mod boundary_writeback_reports;
mod eval_outcome;
mod eval_outcome_boundary_ops;
mod eval_outcome_dry_run_ops;
mod eval_stats;

pub(crate) use boundary_binding_fns::*;
pub use boundary_commit_applications::*;
pub use boundary_commit_types::*;
pub use boundary_dry_run::*;
pub(crate) use boundary_heap_field_fns::*;
pub use boundary_live_installs::*;
pub(crate) use boundary_merge_fns::*;
pub(crate) use boundary_object_plan_fns::*;
pub(crate) use boundary_root_reference_fns::*;
pub use boundary_root_writeback_types::*;
pub use boundary_scan_types::*;
pub use boundary_writeback_reports::*;
pub use eval_outcome::*;
pub use eval_stats::*;

/// Counts for an ABI forwarding-header write plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport {
    headers: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    payload_bytes: usize,
}

impl EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport {
    fn record(&mut self, write: &EvalGcStressBoundaryMinorGcForwardingHeaderWrite) {
        self.headers = self.headers.saturating_add(1);
        self.payload_bytes = self
            .payload_bytes
            .saturating_add(write.destination_bytes().len());
        match write.request().action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery = self.copied_to_nursery.saturating_add(1);
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old = self.promoted_to_old.saturating_add(1);
            }
        }
    }

    /// Returns how many object headers would receive forwarding metadata.
    pub const fn headers(self) -> usize {
        self.headers
    }

    /// Returns how many planned header writes point to next-nursery objects.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns how many planned header writes point to promoted old objects.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns the total destination payload bytes covered by the plan.
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

/// One validated forwarding-header write input.
///
/// This is an immutable write plan for a future ABI object-header writer. It
/// proves that an installed live forwarding cell still matches an installed
/// forwarding-destination binding and carries the destination payload metadata
/// needed by the eventual writer, but it does not mutate object headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcForwardingHeaderWrite {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    generation: HeapGeneration,
    forwarded_value: ResolvedValueGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcForwardingHeaderWrite {
    fn from_binding(
        binding: &EvalGcStressBoundaryMinorGcForwardingDestinationBinding,
    ) -> Result<Self, EvalHeapError> {
        Ok(Self {
            source: binding.source(),
            destination: binding.destination(),
            generation: binding.generation(),
            forwarded_value: binding.forwarded_value(),
            request: binding.request(),
            destination_bytes: clone_boundary_destination_storage_bytes(
                BOUNDARY_MINOR_GC_FORWARDING_HEADER_WRITE_BYTES_TABLE,
                binding.destination_bytes(),
            )?,
        })
    }

    /// Returns the from-space object whose ABI header would be written.
    pub const fn source(&self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination object address carried by the forwarding value.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns the destination generation carried by the forwarding value.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the forwarding value that would be written into the header.
    pub const fn forwarded_value(&self) -> ResolvedValueGeneration {
        self.forwarded_value
    }

    /// Returns the object-copy request associated with this header write.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the installed destination payload bytes covered by this write.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}

/// A validated forwarding-header write plan.
///
/// The plan is derived from installed live forwarding cells and installed
/// forwarding-destination bindings. It is a checked input set for a future
/// unsafe ABI header writer; creating it does not write headers, copy object
/// bodies, or change evaluator heap records.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcForwardingHeaderWritePlan {
    report: EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport,
    writes: Vec<EvalGcStressBoundaryMinorGcForwardingHeaderWrite>,
}

impl EvalGcStressBoundaryMinorGcForwardingHeaderWritePlan {
    fn new(writes: Vec<EvalGcStressBoundaryMinorGcForwardingHeaderWrite>) -> Self {
        let mut report = EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport::default();
        for write in &writes {
            report.record(write);
        }
        Self { report, writes }
    }

    /// Returns whether this plan has no header writes.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Returns how many header writes are planned.
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Returns aggregate counts for the plan.
    pub const fn report(&self) -> EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport {
        self.report
    }

    /// Returns the planned forwarding-header writes.
    pub fn writes(&self) -> &[EvalGcStressBoundaryMinorGcForwardingHeaderWrite] {
        &self.writes
    }
}

/// A derivation recorded during tree-walk evaluation.
///
/// Recorded derivations include their ATerm bytes when byte materialization is
/// possible during evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalDerivation {
    pub(crate) absolute_path: String,
    pub(crate) aterm_bytes: Option<Vec<u8>>,
}

impl EvalDerivation {
    pub(crate) fn new(absolute_path: String, aterm_bytes: Option<Vec<u8>>) -> Self {
        Self {
            absolute_path,
            aterm_bytes,
        }
    }

    /// Returns the absolute `/nix/store` path of the `.drv`.
    pub fn absolute_path(&self) -> &str {
        &self.absolute_path
    }

    /// Returns the serialized `.drv` ATerm bytes when they are statically known.
    pub fn aterm_bytes(&self) -> Option<&[u8]> {
        self.aterm_bytes.as_deref()
    }
}

/// User-facing trace output emitted by `builtins.trace`-style builtins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalTraceOutput {
    pub(crate) kind: EvalTraceKind,
    pub(crate) message: Vec<u8>,
}

impl EvalTraceOutput {
    /// Creates a trace output record.
    pub(crate) fn new(kind: EvalTraceKind, message: Vec<u8>) -> Self {
        Self { kind, message }
    }

    /// Returns the builtin family that emitted this output.
    pub const fn kind(&self) -> EvalTraceKind {
        self.kind
    }

    /// Returns the rendered trace message bytes without the `trace: ` prefix.
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}

/// The trace-like builtin that produced user-facing output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvalTraceKind {
    /// Output from `builtins.trace`.
    Trace,
    /// Output from `builtins.traceVerbose`.
    TraceVerbose,
}

/// A request to realize a derivation output needed during evaluation.
///
/// Import-from-derivation (IFD) is the one point where evaluation must pause for
/// the build layer. The tree-walk evaluator does not build by itself; callers
/// may install an [`IfdRealizer`] that realizes the requested derivation output
/// and returns once the filesystem path can be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IfdRealization<'a> {
    pub(crate) path: &'a [u8],
    pub(crate) drv_path: &'a [u8],
    pub(crate) output_name: Option<&'a [u8]>,
    pub(crate) context_kind: ContextKind,
    pub(crate) op: &'static str,
}

impl<'a> IfdRealization<'a> {
    /// Returns the filesystem path that triggered the IFD demand.
    pub const fn path(&self) -> &'a [u8] {
        self.path
    }

    /// Returns the derivation path whose output must be realized.
    pub const fn drv_path(&self) -> &'a [u8] {
        self.drv_path
    }

    /// Returns the requested output name for single-output contexts.
    pub const fn output_name(&self) -> Option<&'a [u8]> {
        self.output_name
    }

    /// Returns the string-context kind that caused the IFD demand.
    pub const fn context_kind(&self) -> ContextKind {
        self.context_kind
    }

    /// Returns the filesystem-reading builtin that triggered the demand.
    pub const fn op(&self) -> &'static str {
        self.op
    }

    /// Returns the dialect effect member for this realization boundary.
    pub const fn effect(&self) -> EffectClass {
        aos_nix_dialect::NIX_EFFECT_IFD
    }
}

/// A failure reported by an import-from-derivation realizer.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct IfdRealizationError {
    pub(crate) message: String,
}

impl IfdRealizationError {
    /// Creates a realization error from a user-facing message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the realizer failure message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Detailed context for an import-from-derivation evaluator error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IfdErrorDetail {
    pub(crate) path: Box<[u8]>,
    pub(crate) drv_path: Box<[u8]>,
    pub(crate) output_name: Option<Box<[u8]>>,
    pub(crate) context_kind: ContextKind,
    pub(crate) message: Option<String>,
}

impl IfdErrorDetail {
    pub(crate) fn new(
        path: Vec<u8>,
        drv_path: Vec<u8>,
        output_name: Option<Vec<u8>>,
        context_kind: ContextKind,
        message: Option<String>,
    ) -> Self {
        Self {
            path: path.into_boxed_slice(),
            drv_path: drv_path.into_boxed_slice(),
            output_name: output_name.map(Vec::into_boxed_slice),
            context_kind,
            message,
        }
    }

    /// Returns the filesystem path that triggered the IFD demand.
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// Returns the derivation path recorded in the string context.
    pub fn drv_path(&self) -> &[u8] {
        &self.drv_path
    }

    /// Returns the requested output name for single-output contexts.
    pub fn output_name(&self) -> Option<&[u8]> {
        self.output_name.as_deref()
    }

    /// Returns the context kind that caused the IFD demand.
    pub const fn context_kind(&self) -> ContextKind {
        self.context_kind
    }

    /// Returns the realizer diagnostic, if the realizer failed.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for IfdErrorDetail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "path {:?}, derivation {:?}, output {:?}, context {:?}",
            self.path,
            self.drv_path,
            self.output_name.as_deref(),
            self.context_kind
        )?;
        if let Some(message) = &self.message {
            write!(formatter, ": {message}")?;
        }
        Ok(())
    }
}

/// Callback used to realize derivation outputs at IFD boundaries.
#[derive(Clone)]
pub struct IfdRealizer {
    realize: Arc<IfdRealizerCallback>,
}

impl IfdRealizer {
    /// Creates an IFD realizer from a callback.
    pub fn new<F>(realize: F) -> Self
    where
        F: for<'a> Fn(IfdRealization<'a>) -> Result<(), IfdRealizationError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            realize: Arc::new(realize),
        }
    }

    pub(crate) fn realize(&self, request: IfdRealization<'_>) -> Result<(), IfdRealizationError> {
        (self.realize)(request)
    }
}

impl fmt::Debug for IfdRealizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IfdRealizer")
            .finish_non_exhaustive()
    }
}

/// User-facing warning output emitted by `builtins.warn`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalWarningOutput {
    pub(crate) message: Vec<u8>,
}

impl EvalWarningOutput {
    /// Creates a warning output record.
    pub(crate) fn new(message: Vec<u8>) -> Self {
        Self { message }
    }

    /// Returns the warning message bytes without the `evaluation warning: ` prefix.
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}
