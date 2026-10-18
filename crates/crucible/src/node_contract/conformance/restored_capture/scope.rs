//! Binds current restored capture to the actual admitted administrative attempt.
//!
//! The scope borrows real current owners. It is never constructed from a saved
//! checkpoint, archive reference, row or successful callback. It does not use
//! the original-only collecting capture scope or Host preparation path.

use super::*;
use crate::node_adapters::cnp::PacketCompleteSemanticSource;
use crate::node_contract::{
    HostSchedulingContinuationLimits, HostSchedulingSource, NodeRuntime,
    OriginalLineageRuntimeRecord, OriginalLineageWorldCapture, PreparedRestoredHost17Capture,
};
use crate::node_scheduling::{InputPayload, SchedulingSnapshot};
use crate::node_state::{
    NativeArchiveRecord, RestoredArchive17ValidationConstructionData,
    RestoredArchive17ValidationPrewalkData, RestoredArchive17ValidationStep,
};
use crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch;
use crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentCheckpoint17;

/// Borrows genuine current collecting custody for the selected restored codec.
///
/// Its private constructor follows full Window admission. The actual Runtime
/// remains exclusively borrowed by the caller throughout native capture and
/// persistence; neither this scope nor its metadata loans recreate authority.
pub struct RestoredCollectingCaptureScope17<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    graph: &'a crate::node_admission::ConformanceGraph,
    host: &'a HostSchedulingSource,
    world: &'a WorldActivation,
    capture_id: Id,
    slot: usize,
    runtime: *const NodeRuntime,
    launches: &'a [PacketNative5SourceLaunch; 3],
    encoded_launches: [&'a [u8]; 3],
}

impl<'a> RestoredCollectingCaptureScope17<'a> {
    pub(crate) fn same_graph_data(
        &self,
        graph: &Rc<crate::node_admission::ConformanceGraph>,
    ) -> bool {
        std::ptr::eq(self.graph, graph.as_ref())
    }

    pub(super) fn new(
        window: &'a CompleteOriginalRestorationWindow,
        graph: &'a crate::node_admission::ConformanceGraph,
        host: &'a HostSchedulingSource,
        world: &'a WorldActivation,
        capture_id: Id,
        slot: usize,
        runtime: &NodeRuntime,
        launches: &'a [PacketNative5SourceLaunch; 3],
        encoded_launches: [&'a [u8]; 3],
    ) -> Result<Self, RuntimeError> {
        let scope = Self {
            window,
            graph,
            host,
            world,
            capture_id,
            slot,
            runtime,
            launches,
            encoded_launches,
        };
        scope.authenticate_runtime_data(runtime)?;
        Ok(scope)
    }

    /// Borrows the actual opaque collecting plan without ordinary conversion.
    pub fn plan_data(&self) -> &InstalledConformancePlan {
        self.graph.plan()
    }

    /// Borrows the current World, independently of immutable first ancestry.
    pub fn world_data(&self) -> &WorldActivation {
        self.world
    }

    /// Borrows the actual current Host metadata owner without capture delegation.
    pub fn host_data(&self) -> &HostSchedulingSource {
        self.host
    }

    /// Borrows the capture identity retained in the real Window's admitted slot.
    pub fn capture_id_data(&self) -> &Id {
        &self.capture_id
    }

    /// Rechecks current registered members while no native mutable loan is held.
    ///
    /// # Errors
    /// Refuses revoked or foreign plan/Host/Window custody, a changed actual
    /// attempt, unfinished whole observation or missing current activation.
    pub fn authenticate_current_data(&self) -> Result<(), RuntimeError> {
        self.graph
            .authenticate_current_scope()
            .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
        self.host
            .authenticate_current()
            .map_err(|error| RuntimeError::SchedulerRefused(error.reason))?;
        self.window
            .authenticate_restored_capture_archive_identity_data(
                self.graph.plan(),
                self.world,
                self.slot,
                &self.capture_id,
                self.runtime,
            )?;
        self.window
            .authenticate_restored_host17_phase_data(self.slot)?;
        self.window
            .authenticate_restored_terminal17_phase_data(self.slot)
    }

    /// Borrows this current member's actual synchronous launch operands.
    ///
    /// The loan neither reconstructs a launch nor authorizes Capture. The
    /// selected Source effect still authenticates its admitted construction
    /// row's exact launch identity and complete canonical-byte digest.
    ///
    /// # Errors
    /// Refuses stale scope custody or a Source outside this Window's roster.
    pub(crate) fn original_source_launch_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(&PacketNative5SourceLaunch, &[u8]), RuntimeError> {
        self.authenticate_current_data()?;
        let selected = self.window.original_installed_source_index_data(source)?;
        let launch = self
            .launches
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let encoded = self
            .encoded_launches
            .get(selected)
            .copied()
            .ok_or(RuntimeError::ForeignAuthority)?;
        self.authenticate_current_data()?;
        Ok((launch, encoded))
    }

    /// Borrows this Source's admitted imported-closure geometry before effects.
    ///
    /// The eight counts describe objects, body bytes, reference backing, edge
    /// occurrences, adjacency backing, largest body, largest returned row, and
    /// largest row plus hash work. They come from the same retained Source row;
    /// no closure walk, object body, read owner or native permission is created.
    ///
    /// # Errors
    /// Refuses stale Scope/Window/World custody, a foreign Source, unadmitted or
    /// advanced attempt state, a started member, or a failed/reentrant writer.
    pub(crate) fn original_source_imported_closure_storage_data(
        &self,
        source: &PacketCompleteSemanticSource,
    ) -> Result<(usize, usize, usize, usize, usize, usize, usize, usize), RuntimeError> {
        self.authenticate_current_data()?;
        let storage = self
            .window
            .original_restored_capture_imported_closure_storage_data(
                self.graph.plan(),
                self.world,
                self.slot,
                &self.capture_id,
                self.runtime,
                source,
            )?;
        // The Window's ledger loan is released before currentness callbacks.
        self.authenticate_current_data()?;
        Ok(storage)
    }

    /// Commits fixed Host counter work before its independently observed quote.
    ///
    /// # Errors
    /// Refuses foreign or stale owners, an occupied phase or exceeded policy.
    pub(crate) fn retain_host_prewalk_data(
        &self,
        runtime: &NodeRuntime,
    ) -> Result<(), RuntimeError> {
        self.authenticate_runtime_data(runtime)?;
        self.window
            .retain_restored_host17_prewalk_data(self.slot, runtime, self.world, self.host)
    }

    /// Retains genuine Host constructor geometry beside the actual checkpoints.
    ///
    /// # Errors
    /// Refuses unobserved prewalk credit, changed owners or unsupported limits.
    pub(crate) fn quote_host_data(
        &self,
        runtime: &NodeRuntime,
        limits: HostSchedulingContinuationLimits,
    ) -> Result<(), RuntimeError> {
        self.authenticate_runtime_data(runtime)?;
        self.window
            .quote_restored_host17_data(self.slot, runtime, self.world, self.host, limits)
    }

    /// Constructs into retained Host owners after complete row admission.
    ///
    /// # Errors
    /// Refuses unobserved constructor credit, stale owners or failed construction.
    pub(crate) fn construct_host_data(&self, runtime: &NodeRuntime) -> Result<(), RuntimeError> {
        self.authenticate_runtime_data(runtime)?;
        self.window
            .construct_restored_host17_data(self.slot, runtime, self.world, self.host)
    }

    /// Retains the actual same-source capsule for the later mutable writer loan.
    ///
    /// # Errors
    /// Refuses unobserved construction, another live owner or failed preparation.
    pub(crate) fn prepare_host_data(&self, runtime: &NodeRuntime) -> Result<(), RuntimeError> {
        self.authenticate_runtime_data(runtime)?;
        self.window.prepare_restored_host17_data(
            self.slot,
            &self.graph.graph,
            runtime,
            self.world,
            self.host,
        )
    }

    /// Lends actual retained checkpoints and the genuine prepared Host once.
    ///
    /// The callback independently joins complete object references and bytes.
    /// It releases each private Source/SDK/native loan and performs the real
    /// full owner observation before authenticating the next scope. Return from
    /// this lender does not replace that observation or automatically reenter it.
    ///
    /// # Errors
    /// Refuses another Runtime, incomplete preparation, repeated writer use,
    /// changed checkpoint custody, stale current owners or callback failure.
    pub(crate) fn with_prepared_checkpoint_data<R>(
        &self,
        runtime: &mut NodeRuntime,
        inspect: impl FnOnce(
            &mut NodeRuntime,
            &OriginalLineageRuntimeRecord,
            &SchedulingSnapshot,
            &InputPayload,
            &InputPayload,
            &CoordinatorCommitmentCheckpoint17,
            &InputPayload,
            &Rc<PreparedRestoredHost17Capture>,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.authenticate_runtime_data(runtime)?;
        self.window.with_restored_host17_checkpoint_data(
            self.slot, self.graph, runtime, self.world, self.host, inspect,
        )
    }

    /// Compares the same retained Window while holding genuine current scope custody.
    pub(crate) fn same_window_data(&self, window: &CompleteOriginalRestorationWindow) -> bool {
        std::ptr::eq(self.window, window)
    }

    /// Retains real terminal prewalk and next-ledger-bank credit after all owners.
    ///
    /// # Errors
    /// Refuses incomplete real outputs, stale scope, repeated stages or policy excess.
    pub(crate) fn retain_terminal_validation_prewalk_data(
        &self,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        archive: &NativeArchiveRecord,
        prewalk: RestoredArchive17ValidationPrewalkData,
    ) -> Result<(), RuntimeError> {
        self.authenticate_runtime_data(runtime)?;
        self.window.retain_terminal_validation_prewalk_data(
            self.slot, self, runtime, capture, archive, prewalk,
        )
    }

    /// Appends the actual pending numeric phase after its bank was fully observed.
    ///
    /// # Errors
    /// Refuses unobserved credit, stale custody, reuse or failed bank allocation.
    pub(crate) fn append_terminal_validation_phase_data(
        &self,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        archive: &NativeArchiveRecord,
    ) -> Result<(), RuntimeError> {
        self.authenticate_runtime_data(runtime)?;
        self.window
            .append_terminal_validation_phase_data(self.slot, self, runtime, capture, archive)
    }

    /// Retains a complete real constructor row including all prior live cache work.
    ///
    /// # Errors
    /// Refuses missing prewalk admission, changed geometry or policy excess.
    pub(crate) fn retain_terminal_validation_row_data(
        &self,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        archive: &NativeArchiveRecord,
        row: RestoredArchive17ValidationConstructionData,
    ) -> Result<(), RuntimeError> {
        self.authenticate_runtime_data(runtime)?;
        self.window
            .retain_terminal_validation_row_data(self.slot, self, runtime, capture, archive, row)
    }

    /// Starts one actual pure constructor after genuine full row observation.
    ///
    /// # Errors
    /// Refuses another step, stale output custody, reuse or pending observation.
    pub(crate) fn begin_terminal_validation_constructor_data(
        &self,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        archive: &NativeArchiveRecord,
        step: RestoredArchive17ValidationStep,
    ) -> Result<(), RuntimeError> {
        self.authenticate_runtime_data(runtime)?;
        self.window.begin_terminal_validation_constructor_data(
            self.slot, self, runtime, capture, archive, step,
        )
    }

    /// Retains a constructor's genuine completed-cache census and spent step.
    ///
    /// # Errors
    /// Refuses stale custody, another step, reuse or actual retained cache excess.
    pub(crate) fn finish_terminal_validation_stage_data(
        &self,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        archive: &NativeArchiveRecord,
        step: RestoredArchive17ValidationStep,
        actual_cache_retained: usize,
    ) -> Result<(), RuntimeError> {
        self.authenticate_runtime_data(runtime)?;
        self.window.finish_terminal_validation_stage_data(
            self.slot,
            self,
            runtime,
            capture,
            archive,
            step,
            actual_cache_retained,
        )
    }

    /// Requires the completed terminal conjunction before the actual final signer.
    ///
    /// # Errors
    /// Refuses stale complete-output custody, unfinished stages or pending census.
    pub(crate) fn require_terminal_validation_completed_data(
        &self,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        archive: &NativeArchiveRecord,
    ) -> Result<(), RuntimeError> {
        self.authenticate_runtime_data(runtime)?;
        self.window
            .require_terminal_validation_completed_data(self.slot, self, runtime, capture, archive)
    }

    /// Names the scope and borrowed member-operand controls before their loan.
    pub(crate) const fn launch_operand_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<&PacketCompleteSemanticSource>()
            + size_of::<&[PacketNative5SourceLaunch; 3]>()
            + size_of::<[&[u8]; 3]>()
            + size_of::<Option<&PacketNative5SourceLaunch>>()
            + size_of::<Option<&&[u8]>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(&PacketNative5SourceLaunch, &[u8]), RuntimeError>>()
            + size_of::<usize>()
            + size_of::<&mut NodeRuntime>()
            + size_of::<&OriginalLineageRuntimeRecord>()
            + size_of::<&SchedulingSnapshot>()
            + size_of::<&CoordinatorCommitmentCheckpoint17>()
            + size_of::<[&InputPayload; 3]>()
            + size_of::<&Rc<PreparedRestoredHost17Capture>>()
            + size_of::<&OriginalLineageWorldCapture>()
            + size_of::<&NativeArchiveRecord>()
            + size_of::<RestoredArchive17ValidationPrewalkData>()
            + size_of::<RestoredArchive17ValidationConstructionData>()
            + size_of::<RestoredArchive17ValidationStep>()
            + size_of::<(usize, usize, usize, usize, usize, usize, usize, usize)>()
            + size_of::<
                Result<(usize, usize, usize, usize, usize, usize, usize, usize), RuntimeError>,
            >()
    }

    pub(crate) fn authenticate_runtime_data(
        &self,
        runtime: &NodeRuntime,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(runtime, self.runtime) {
            return Err(RuntimeError::ForeignAuthority);
        }
        runtime.validate_activation(self.world)?;
        runtime.authenticate_host_scheduling_source(self.host)?;
        self.authenticate_current_data()
    }
}
