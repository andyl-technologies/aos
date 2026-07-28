//! Direct native CFGs for validated mixed-machine demand regions.
//!
//! This first executable slice recognizes the validated
//! `ApplyGuarded -> Force -> Update -> Return` corridor and emits it as one
//! Cranelift function. Runtime inspection is represented by prevalidated,
//! caller-owned decision records: generated code does not interpret mixed
//! operations, dispatch per thunk, or call generic evaluator callbacks.
//!
//! The decision ABI is intentionally narrower than the eventual evaluator
//! adapter. A real adapter must derive decisions before transferring a claim
//! and retain the exact work-identity proof while native code is active.

use std::{
    marker::PhantomData,
    mem::{self, offset_of},
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};

use cranelift_codegen::{
    Context,
    cursor::{Cursor, CursorPosition, FuncCursor},
    ir::{
        AbiParam, Block, Function, InstBuilder, MemFlags, Signature, UserFuncName, Value,
        condcodes::IntCC, types,
    },
    isa::CallConv,
    settings,
    verifier::verify_function,
};
use cranelift_jit::JITModule;
use cranelift_module::{Linkage, Module};
use ratchet_core::mixed_machine::{
    MixedBlockId, MixedEntryKind, MixedFunctionId, MixedModuleKey, MixedModulePlan, MixedOp,
    MixedStatepointId, MixedStatepointMode, MixedTerminator, MixedValueId, MixedValueType,
};
use thiserror::Error;

use super::{JitCraneliftModuleSetupError, module_setup::native_jit_builder};

macro_rules! field_offset {
    ($container:ty, $field:ident) => {
        offset_of!($container, $field) as i32
    };
}

const MIXED_SUPERBLOCK_BACKEND_VERSION: u32 = 7;
const MIXED_SUPERBLOCK_FUNCTION_NAMESPACE: u32 = 12;
const MIXED_SUPERBLOCK_SYMBOL: &str = "aos.mixed.superblock.v1";
const DECLINED_TARGET: u32 = u32::MAX;

const STATUS_COMPLETE: u32 = 1;
const STATUS_SIDE_EXIT: u32 = 2;
const STATUS_INVALID_ACTIVATION: u32 = 3;
const GENERAL_VALUE_SLOT_CAP: u32 = 512;

static NEXT_EXECUTABLE_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Canonical identity of one directly compiled mixed-machine plan.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct JitMixedSuperblockCacheKey {
    plan: MixedModuleKey,
    canonical_plan: Box<[u8]>,
    backend_version: u32,
    cranelift_version: &'static str,
}

impl JitMixedSuperblockCacheKey {
    fn new(plan: &MixedModulePlan) -> Self {
        Self {
            plan: plan.key(),
            canonical_plan: plan.canonical_bytes().into_boxed_slice(),
            backend_version: MIXED_SUPERBLOCK_BACKEND_VERSION,
            cranelift_version: cranelift_codegen::VERSION,
        }
    }

    /// Returns the validated mixed-plan identity.
    pub const fn plan(&self) -> MixedModuleKey {
        self.plan
    }

    /// Returns the exact canonical plan bytes covered by the cache identity.
    pub fn canonical_plan(&self) -> &[u8] {
        &self.canonical_plan
    }

    /// Returns the direct-superblock backend format version.
    pub const fn backend_version(&self) -> u32 {
        self.backend_version
    }

    /// Returns the Cranelift code-generator version in the identity.
    pub const fn cranelift_version(&self) -> &'static str {
        self.cranelift_version
    }
}

/// A prevalidated exact guarded-call decision consumed by native code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct JitMixedSuperblockCallDecision {
    callable: u64,
    target_ordinal: u32,
    frame: u32,
}

impl JitMixedSuperblockCallDecision {
    /// Creates a successful decision for one zero-based guarded target.
    pub const fn target(callable: u64, target_ordinal: u32, frame: u32) -> Self {
        Self {
            callable,
            target_ordinal,
            frame,
        }
    }

    /// Creates a decision that selects the plan's guarded-call side exit.
    pub const fn declined(callable: u64) -> Self {
        Self {
            callable,
            target_ordinal: DECLINED_TARGET,
            frame: 0,
        }
    }
}

/// A prevalidated force transition selected before native ownership transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum JitMixedSuperblockForceAction {
    /// The subject was already ready; `result` is its WHNF value.
    Ready = 0,
    /// Exact Node work was claimed.
    Node = 1,
    /// Exact Apply work was claimed.
    Apply = 2,
    /// Exact `GenListElemAtAddOne` work was claimed.
    GenListElemAtAddOne = 3,
    /// No exact force guard matched.
    Declined = 4,
}

/// One force transition consumed by native code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct JitMixedSuperblockForceDecision {
    subject: u64,
    result: u64,
    token: u64,
    frame: u32,
    action: JitMixedSuperblockForceAction,
}

impl JitMixedSuperblockForceDecision {
    /// Creates an already-ready transition.
    pub const fn ready(subject: u64, result: u64) -> Self {
        Self {
            subject,
            result,
            token: 0,
            frame: 0,
            action: JitMixedSuperblockForceAction::Ready,
        }
    }

    /// Creates an exact claimed-work transition.
    pub const fn claimed(
        subject: u64,
        action: JitMixedSuperblockForceAction,
        frame: u32,
        token: u64,
    ) -> Self {
        Self {
            subject,
            result: 0,
            token,
            frame,
            action,
        }
    }

    /// Creates a transition that selects the plan's force side exit.
    pub const fn declined(subject: u64) -> Self {
        Self {
            subject,
            result: 0,
            token: 0,
            frame: 0,
            action: JitMixedSuperblockForceAction::Declined,
        }
    }
}

/// One update published by a successful native force corridor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct JitMixedSuperblockPublishedUpdate {
    token: u64,
    value: u64,
    published: u32,
    padding: u32,
}

impl JitMixedSuperblockPublishedUpdate {
    /// Returns the caller-defined update token.
    pub const fn token(self) -> u64 {
        self.token
    }

    /// Returns the value published by the matching update edge.
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Returns whether the record was published.
    pub const fn is_published(self) -> bool {
        self.published != 0
    }
}

#[repr(C)]
struct RawActivation {
    argument: u64,
    entry_frame: u32,
    frame_stride: u32,
    frames: *const u64,
    frame_count: u32,
    call_count: u32,
    calls: *const JitMixedSuperblockCallDecision,
    call_cursor: u32,
    force_count: u32,
    forces: *const JitMixedSuperblockForceDecision,
    force_cursor: u32,
    update_capacity: u32,
    updates: *mut JitMixedSuperblockPublishedUpdate,
    published_updates: u32,
    status: u32,
    side_exit: u32,
    padding: u32,
    result: u64,
    value_slots: *mut u64,
    value_capacity: u32,
    live_value_count: u32,
    resume_requested: u32,
    resume_statepoint: u32,
    resume_has_result: u32,
    resume_padding: u32,
    resume_result: u64,
    executable_token: u64,
}

/// Validated caller-owned storage for one native superblock activation.
pub struct JitMixedSuperblockActivation<'storage> {
    raw: RawActivation,
    updates: &'storage mut [JitMixedSuperblockPublishedUpdate],
    value_slots: Option<&'storage mut [u64]>,
    _storage: PhantomData<&'storage mut [u64]>,
}

/// A malformed native activation buffer.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum JitMixedSuperblockActivationError {
    /// A frame stride of zero cannot address frame locals.
    #[error("mixed-superblock frame stride must be nonzero")]
    ZeroFrameStride,
    /// Frame storage is not an exact multiple of its stride.
    #[error("mixed-superblock frame storage is not divisible by its stride")]
    PartialFrame,
    /// A storage length exceeds the fixed `u32` ABI.
    #[error("mixed-superblock {storage} storage exceeds u32::MAX entries")]
    StorageTooLarge {
        /// Name of the oversized storage family.
        storage: &'static str,
    },
}

impl<'storage> JitMixedSuperblockActivation<'storage> {
    /// Creates one activation over fixed caller-owned decision and update buffers.
    ///
    /// # Errors
    ///
    /// Returns [`JitMixedSuperblockActivationError`] when frame geometry is
    /// invalid or any buffer length exceeds the fixed-width native ABI.
    pub fn new(
        argument: u64,
        entry_frame: u32,
        frames: &'storage [u64],
        frame_stride: u32,
        calls: &'storage [JitMixedSuperblockCallDecision],
        forces: &'storage [JitMixedSuperblockForceDecision],
        updates: &'storage mut [JitMixedSuperblockPublishedUpdate],
    ) -> Result<Self, JitMixedSuperblockActivationError> {
        Self::new_inner(
            argument,
            entry_frame,
            frames,
            frame_stride,
            calls,
            forces,
            updates,
            None,
        )
    }

    /// Creates one activation with caller-owned writable statepoint slots.
    ///
    /// The slot slice is indexed by [`MixedValueId`]. Generated general-CFG
    /// code clears it on entry, stores all activation values there, and clears
    /// every slot absent from a side exit's exact `live_values` set before
    /// returning control. A caller may rewrite the declared live slots before
    /// resuming the artifact. Execution rejects a slice whose length differs
    /// from the compiled plan's exact `value_slots` bound.
    ///
    /// # Errors
    ///
    /// Returns [`JitMixedSuperblockActivationError`] when frame geometry is
    /// invalid or any buffer length exceeds the fixed-width native ABI.
    #[allow(clippy::too_many_arguments)]
    pub fn new_resumable(
        argument: u64,
        entry_frame: u32,
        frames: &'storage [u64],
        frame_stride: u32,
        calls: &'storage [JitMixedSuperblockCallDecision],
        forces: &'storage [JitMixedSuperblockForceDecision],
        updates: &'storage mut [JitMixedSuperblockPublishedUpdate],
        value_slots: &'storage mut [u64],
    ) -> Result<Self, JitMixedSuperblockActivationError> {
        Self::new_inner(
            argument,
            entry_frame,
            frames,
            frame_stride,
            calls,
            forces,
            updates,
            Some(value_slots),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        argument: u64,
        entry_frame: u32,
        frames: &'storage [u64],
        frame_stride: u32,
        calls: &'storage [JitMixedSuperblockCallDecision],
        forces: &'storage [JitMixedSuperblockForceDecision],
        updates: &'storage mut [JitMixedSuperblockPublishedUpdate],
        mut value_slots: Option<&'storage mut [u64]>,
    ) -> Result<Self, JitMixedSuperblockActivationError> {
        if frame_stride == 0 {
            return Err(JitMixedSuperblockActivationError::ZeroFrameStride);
        }
        if !frames.len().is_multiple_of(frame_stride as usize) {
            return Err(JitMixedSuperblockActivationError::PartialFrame);
        }
        let frame_count = narrow_len("frame", frames.len() / frame_stride as usize)?;
        let call_count = narrow_len("call decision", calls.len())?;
        let force_count = narrow_len("force decision", forces.len())?;
        let update_capacity = narrow_len("update", updates.len())?;
        let value_capacity = narrow_len(
            "statepoint value",
            value_slots.as_ref().map_or(0, |slots| slots.len()),
        )?;
        let update_pointer = updates.as_mut_ptr();
        let value_pointer = value_slots
            .as_deref_mut()
            .map_or(std::ptr::null_mut(), <[u64]>::as_mut_ptr);
        Ok(Self {
            raw: RawActivation {
                argument,
                entry_frame,
                frame_stride,
                frames: frames.as_ptr(),
                frame_count,
                call_count,
                calls: calls.as_ptr(),
                call_cursor: 0,
                force_count,
                forces: forces.as_ptr(),
                force_cursor: 0,
                update_capacity,
                updates: update_pointer,
                published_updates: 0,
                status: 0,
                side_exit: u32::MAX,
                padding: 0,
                result: 0,
                value_slots: value_pointer,
                value_capacity,
                live_value_count: 0,
                resume_requested: 0,
                resume_statepoint: u32::MAX,
                resume_has_result: 0,
                resume_padding: 0,
                resume_result: 0,
                executable_token: 0,
            },
            updates,
            value_slots,
            _storage: PhantomData,
        })
    }

    /// Returns the number of call decisions consumed by generated code.
    pub const fn consumed_calls(&self) -> u32 {
        self.raw.call_cursor
    }

    /// Returns the number of force decisions consumed by generated code.
    pub const fn consumed_forces(&self) -> u32 {
        self.raw.force_cursor
    }

    /// Returns the published update records.
    pub fn published_updates(&self) -> &[JitMixedSuperblockPublishedUpdate] {
        let len = self.raw.published_updates.min(self.raw.update_capacity) as usize;
        &self.updates[..len]
    }

    /// Returns the indexed writable value slots used by resumable statepoints.
    ///
    /// After [`JitMixedSuperblockOutcome::SideExit`], slots absent from the
    /// selected statepoint's declared live set contain zero.
    pub fn value_slots_mut(&mut self) -> Option<&mut [u64]> {
        self.value_slots.as_deref_mut()
    }

    /// Returns the number of exact live values declared by the latest side exit.
    pub const fn live_value_count(&self) -> u32 {
        self.raw.live_value_count
    }
}

fn narrow_len(storage: &'static str, len: usize) -> Result<u32, JitMixedSuperblockActivationError> {
    u32::try_from(len).map_err(|_| JitMixedSuperblockActivationError::StorageTooLarge { storage })
}

/// Result returned by one direct native activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JitMixedSuperblockOutcome {
    /// The outer entry completed with one opaque one-word value.
    Complete(u64),
    /// A prevalidated decision selected one plan statepoint.
    SideExit(MixedStatepointId),
    /// Activation geometry or decision provenance was invalid.
    InvalidActivation,
}

/// A verified, address-free direct mixed-superblock artifact.
pub struct JitMixedSuperblockArtifact {
    cache_key: JitMixedSuperblockCacheKey,
    function: Function,
    resumable: bool,
    value_slots: u32,
    reachable_statepoints: Box<[bool]>,
    resumable_statepoints: Box<[bool]>,
}

impl JitMixedSuperblockArtifact {
    /// Returns the complete content and backend cache identity.
    pub const fn cache_key(&self) -> &JitMixedSuperblockCacheKey {
        &self.cache_key
    }

    /// Returns the verified Cranelift function.
    pub const fn function(&self) -> &Function {
        &self.function
    }
}

/// A failure while admitting, lowering, or finalizing a mixed superblock.
#[derive(Debug, Error)]
pub enum JitMixedSuperblockCompileError {
    /// The requested outer entry does not exist.
    #[error("mixed-superblock entry {entry} does not exist")]
    InvalidEntry {
        /// Requested entry-table index.
        entry: usize,
    },
    /// The validated plan is outside the first direct corridor grammar.
    #[error("mixed-superblock plan is outside slice-A grammar: {reason}")]
    UnsupportedPlan {
        /// Exact failed admission condition.
        reason: &'static str,
    },
    /// Cranelift rejected the generated function.
    #[error("mixed-superblock CLIF verification failed: {message}")]
    Verification {
        /// Cranelift verifier diagnostic.
        message: String,
    },
    /// The process exhausted unique activation-owner tokens.
    #[error("mixed-superblock executable token space is exhausted")]
    ExecutableTokenExhausted,
    /// Executable module construction or finalization failed.
    #[error(transparent)]
    Module(#[from] JitCraneliftModuleSetupError),
}

/// One finalized direct superblock and its owning executable module.
pub struct JitMixedSuperblockExecutable {
    artifact: JitMixedSuperblockCacheKey,
    module: JITModule,
    code: NonNull<u8>,
    statepoints: Box<[JitMixedSuperblockStatepoint]>,
    required_value_slots: Option<u32>,
    executable_token: u64,
}

#[derive(Clone, Debug)]
struct JitMixedSuperblockStatepoint {
    live_values: Box<[MixedValueId]>,
    result: Option<MixedValueId>,
    result_type: Option<MixedValueType>,
    reachable: bool,
    resumable: bool,
}

impl JitMixedSuperblockExecutable {
    /// Returns the exact source/backend cache identity.
    pub const fn cache_key(&self) -> &JitMixedSuperblockCacheKey {
        &self.artifact
    }

    /// Executes one validated activation through the generated CFG.
    ///
    /// This boundary represents invalid activation state as
    /// [`JitMixedSuperblockOutcome::InvalidActivation`]. Construction and
    /// finalization failures are returned by [`compile_mixed_superblock`].
    pub fn run(
        &self,
        activation: &mut JitMixedSuperblockActivation<'_>,
    ) -> JitMixedSuperblockOutcome {
        if activation.raw.status != 0
            || activation.raw.executable_token != 0
            || !self.has_exact_value_slab(activation)
        {
            return JitMixedSuperblockOutcome::InvalidActivation;
        }
        activation.raw.executable_token = self.executable_token;
        activation.raw.resume_requested = 0;
        self.invoke(activation)
    }

    /// Resumes the latest side exit after caller-owned roots were rewritten.
    ///
    /// `result` must be present exactly when the selected statepoint declares a
    /// result slot. Generated code reloads every continuation value from the
    /// writable activation slots, so a relocation or test mutation performed
    /// while native code was suspended is observed after resumption.
    pub fn resume(
        &self,
        activation: &mut JitMixedSuperblockActivation<'_>,
        result: Option<u64>,
    ) -> JitMixedSuperblockOutcome {
        if activation.raw.status != STATUS_SIDE_EXIT {
            return JitMixedSuperblockOutcome::InvalidActivation;
        }
        if activation.raw.executable_token != self.executable_token
            || !self.has_exact_value_slab(activation)
            || activation.raw.side_exit != activation.raw.resume_statepoint
        {
            return JitMixedSuperblockOutcome::InvalidActivation;
        }
        let Some(statepoint) = self.statepoints.get(activation.raw.side_exit as usize) else {
            return JitMixedSuperblockOutcome::InvalidActivation;
        };
        let result_matches = match (result, statepoint.result_type) {
            (None, None) => true,
            (Some(raw), Some(expected)) => resume_result_matches_type(raw, expected),
            _ => false,
        };
        if !statepoint.resumable
            || statepoint.result.is_some() != result.is_some()
            || !result_matches
        {
            return JitMixedSuperblockOutcome::InvalidActivation;
        }
        activation.raw.resume_requested = 1;
        activation.raw.resume_has_result = u32::from(result.is_some());
        activation.raw.resume_result = result.unwrap_or(0);
        self.invoke(activation)
    }

    /// Returns the exact writable value-slot identities for one side exit.
    pub fn statepoint_live_values(&self, statepoint: MixedStatepointId) -> Option<&[MixedValueId]> {
        self.statepoints
            .get(statepoint.as_u32() as usize)
            .filter(|metadata| metadata.resumable)
            .map(|metadata| metadata.live_values.as_ref())
    }

    /// Returns the declared result type that an oracle must satisfy on resume.
    ///
    /// Baseline-carrier callers must validate their opaque one-word adapter
    /// encoding against this contract before calling [`Self::resume`].
    pub fn statepoint_result_type(&self, statepoint: MixedStatepointId) -> Option<MixedValueType> {
        self.statepoints
            .get(statepoint.as_u32() as usize)
            .filter(|metadata| metadata.resumable)
            .and_then(|metadata| metadata.result_type)
    }

    /// Returns whether the compiled artifact can resume this statepoint.
    pub fn statepoint_is_resumable(&self, statepoint: MixedStatepointId) -> bool {
        self.statepoints
            .get(statepoint.as_u32() as usize)
            .is_some_and(|metadata| metadata.resumable)
    }

    fn has_exact_value_slab(&self, activation: &JitMixedSuperblockActivation<'_>) -> bool {
        self.required_value_slots
            .is_none_or(|required| activation.raw.value_capacity == required)
    }

    fn invoke(
        &self,
        activation: &mut JitMixedSuperblockActivation<'_>,
    ) -> JitMixedSuperblockOutcome {
        type Entry = unsafe extern "C" fn(*mut RawActivation) -> u32;
        // SAFETY: `compile_mixed_superblock` finalized `code` from the exact
        // signature used below, `module` keeps its executable allocation live,
        // and the activation wrapper keeps every embedded buffer live.
        let entry = unsafe { mem::transmute::<*mut u8, Entry>(self.code.as_ptr()) };
        // SAFETY: The activation's private raw record satisfies the generated
        // pointer, length, alignment, and mutability contract.
        let status = unsafe { entry(&mut activation.raw) };
        self.outcome_from_status(activation, status)
    }

    fn outcome_from_status(
        &self,
        activation: &mut JitMixedSuperblockActivation<'_>,
        status: u32,
    ) -> JitMixedSuperblockOutcome {
        if status != activation.raw.status {
            activation.raw.status = STATUS_INVALID_ACTIVATION;
            return JitMixedSuperblockOutcome::InvalidActivation;
        }
        match status {
            STATUS_COMPLETE => JitMixedSuperblockOutcome::Complete(activation.raw.result),
            STATUS_SIDE_EXIT => {
                let Some(statepoint) = self.statepoints.get(activation.raw.side_exit as usize)
                else {
                    activation.raw.status = STATUS_INVALID_ACTIVATION;
                    return JitMixedSuperblockOutcome::InvalidActivation;
                };
                if !statepoint.reachable {
                    activation.raw.status = STATUS_INVALID_ACTIVATION;
                    return JitMixedSuperblockOutcome::InvalidActivation;
                }
                if statepoint.resumable
                    && activation.raw.resume_statepoint != activation.raw.side_exit
                {
                    activation.raw.status = STATUS_INVALID_ACTIVATION;
                    return JitMixedSuperblockOutcome::InvalidActivation;
                }
                JitMixedSuperblockOutcome::SideExit(MixedStatepointId::new(
                    activation.raw.side_exit,
                ))
            }
            _ => JitMixedSuperblockOutcome::InvalidActivation,
        }
    }
}

#[cfg(not(feature = "candidate_c_value"))]
fn resume_result_matches_type(_raw: u64, expected: MixedValueType) -> bool {
    // The baseline superblock proving ABI carries one opaque test/adaptor word,
    // not the production two-word `Value`. Its caller owns the documented type
    // check until a production adapter replaces this substrate.
    !matches!(
        expected,
        MixedValueType::VirtualThunk | MixedValueType::VirtualClosure
    )
}

#[cfg(feature = "candidate_c_value")]
fn resume_result_matches_type(raw: u64, expected: MixedValueType) -> bool {
    use ratchet_value::value::{ValueTag, compressed::CompressedValueWord};

    let Ok(word) = CompressedValueWord::from_raw(raw) else {
        return false;
    };
    match expected {
        MixedValueType::Value => true,
        MixedValueType::Int => word.semantic_tag() == ValueTag::Int,
        MixedValueType::Bool => word.semantic_tag() == ValueTag::Bool,
        MixedValueType::Null => word.semantic_tag() == ValueTag::Null,
        MixedValueType::VirtualThunk | MixedValueType::VirtualClosure => false,
    }
}

impl Drop for JitMixedSuperblockExecutable {
    fn drop(&mut self) {
        // Read the owner so dead-code analysis cannot mistake it for inert
        // metadata; dropping the JIT module releases the code after this point.
        let _ = &self.module;
    }
}

/// Compiles one admitted validated mixed-machine entry as a direct native CFG.
///
/// # Errors
///
/// Returns [`JitMixedSuperblockCompileError`] when the entry is absent, the
/// plan is outside the slice-A corridor grammar, Cranelift verification fails,
/// or executable module setup/finalization fails.
pub fn compile_mixed_superblock(
    plan: &MixedModulePlan,
    entry: usize,
) -> Result<JitMixedSuperblockExecutable, JitMixedSuperblockCompileError> {
    let artifact = lower_mixed_superblock(plan, entry)?;
    let cache_key = artifact.cache_key.clone();
    let artifact_resumable = artifact.resumable;
    let required_value_slots = artifact_resumable.then_some(artifact.value_slots);
    let reachable_statepoints = artifact.reachable_statepoints;
    let resumable_statepoints = artifact.resumable_statepoints;
    let mut module = JITModule::new(native_jit_builder()?);
    let function = artifact.function;
    let function_id = module
        .declare_function(
            MIXED_SUPERBLOCK_SYMBOL,
            Linkage::Export,
            &function.signature,
        )
        .map_err(
            |source| JitCraneliftModuleSetupError::DeclareArtifactFunction {
                symbol_name: MIXED_SUPERBLOCK_SYMBOL.to_owned(),
                source,
            },
        )?;
    let mut context = Context::for_function(function);
    module
        .define_function(function_id, &mut context)
        .map_err(
            |source| JitCraneliftModuleSetupError::DefineArtifactFunction {
                symbol_name: MIXED_SUPERBLOCK_SYMBOL.to_owned(),
                source,
            },
        )?;
    module.finalize_definitions().map_err(|source| {
        JitCraneliftModuleSetupError::FinalizeDefinitions {
            symbol_name: MIXED_SUPERBLOCK_SYMBOL.to_owned(),
            source,
        }
    })?;
    let code =
        NonNull::new(module.get_finalized_function(function_id) as *mut u8).ok_or_else(|| {
            JitCraneliftModuleSetupError::FinalizedFunctionPointerNull {
                symbol_name: MIXED_SUPERBLOCK_SYMBOL.to_owned(),
            }
        })?;
    let statepoints = plan
        .statepoints()
        .iter()
        .enumerate()
        .map(|(index, statepoint)| JitMixedSuperblockStatepoint {
            live_values: statepoint.live_values.clone(),
            result: statepoint.result,
            result_type: statepoint.result_type,
            reachable: reachable_statepoints.get(index).copied().unwrap_or(false),
            resumable: resumable_statepoints.get(index).copied().unwrap_or(false),
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    Ok(JitMixedSuperblockExecutable {
        artifact: cache_key,
        module,
        code,
        statepoints,
        required_value_slots,
        executable_token: NEXT_EXECUTABLE_TOKEN
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |token| {
                token.checked_add(1)
            })
            .map_err(|_| JitMixedSuperblockCompileError::ExecutableTokenExhausted)?,
    })
}

#[derive(Clone, Copy)]
enum ClaimedResult {
    FrameLocal(u32),
    Constant(u64),
}

#[derive(Clone, Copy)]
enum AdmittedCallResult {
    Argument,
    FrameLocal(u32),
    Constant(u64),
}

#[derive(Clone, Copy)]
enum AdmittedEntryOperand {
    Parameter,
    FrameLocal(u32),
    Constant(u64),
}

struct AdmittedCorridor {
    entry_callable: AdmittedEntryOperand,
    entry_argument: AdmittedEntryOperand,
    call_results: Vec<AdmittedCallResult>,
    call_fallback: MixedStatepointId,
    force: Option<AdmittedForceCorridor>,
}

struct AdmittedForceCorridor {
    force_fallback: MixedStatepointId,
    node: ClaimedResult,
    apply: ClaimedResult,
    gen_list: ClaimedResult,
}

fn lower_mixed_superblock(
    plan: &MixedModulePlan,
    entry: usize,
) -> Result<JitMixedSuperblockArtifact, JitMixedSuperblockCompileError> {
    let corridor = match admit_corridor(plan, entry) {
        Ok(corridor) => corridor,
        Err(JitMixedSuperblockCompileError::UnsupportedPlan { .. }) => {
            return lower_general_mixed_cfg(plan, entry);
        }
        Err(error) => return Err(error),
    };
    let mut reachable_statepoints = vec![false; plan.statepoints().len()];
    reachable_statepoints[corridor.call_fallback.as_u32() as usize] = true;
    if let Some(force) = corridor.force.as_ref() {
        reachable_statepoints[force.force_fallback.as_u32() as usize] = true;
    }
    let mut signature = Signature::new(CallConv::SystemV);
    signature.params.push(AbiParam::new(types::I64));
    signature.returns.push(AbiParam::new(types::I32));
    let mut function = Function::with_name_signature(
        UserFuncName::user(MIXED_SUPERBLOCK_FUNCTION_NAMESPACE, entry as u32),
        signature,
    );
    let entry_block = function.dfg.make_block();
    function.dfg.append_block_param(entry_block, types::I64);
    let call_ready = function.dfg.make_block();
    let force_ready = function.dfg.make_block();
    function.dfg.append_block_param(force_ready, types::I64);
    let force_node = function.dfg.make_block();
    let force_apply = function.dfg.make_block();
    let force_gen_list = function.dfg.make_block();
    let complete = function.dfg.make_block();
    let side_exit = function.dfg.make_block();
    let invalid = function.dfg.make_block();
    function.dfg.append_block_param(complete, types::I64);
    function.dfg.append_block_param(side_exit, types::I32);
    function.layout.append_block(entry_block);

    let activation = {
        let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(entry_block);
        let activation = cursor.func.dfg.block_params(entry_block)[0];
        let nonnull = cursor.ins().icmp_imm(IntCC::NotEqual, activation, 0);
        cursor.ins().brif(nonnull, call_ready, &[], invalid, &[]);
        activation
    };

    function.layout.append_block(call_ready);
    {
        let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(call_ready);
        let parameter = load_i64(
            &mut cursor,
            activation,
            field_offset!(RawActivation, argument),
        );
        let entry_frame = load_i32(
            &mut cursor,
            activation,
            field_offset!(RawActivation, entry_frame),
        );
        let callable = emit_entry_operand(
            &mut cursor,
            activation,
            parameter,
            entry_frame,
            corridor.entry_callable,
            invalid,
        );
        let Some(callable) = callable else {
            unreachable!("admitted entry operand always emits a continuation");
        };
        let argument = emit_entry_operand(
            &mut cursor,
            activation,
            parameter,
            entry_frame,
            corridor.entry_argument,
            invalid,
        );
        let Some(argument) = argument else {
            unreachable!("admitted entry operand always emits a continuation");
        };
        let decision = emit_next_call_decision(&mut cursor, activation, invalid);
        let Some(decision) = decision else {
            unreachable!("decision load always emits a continuation");
        };
        let observed = load_i64(
            &mut cursor,
            decision,
            field_offset!(JitMixedSuperblockCallDecision, callable),
        );
        let same_callable = cursor.ins().icmp(IntCC::Equal, observed, callable);
        let target_check = cursor.func.dfg.make_block();
        cursor
            .ins()
            .brif(same_callable, target_check, &[], invalid, &[]);
        cursor.func.layout.append_block(target_check);
        cursor.set_position(CursorPosition::After(target_check));
        let ordinal = load_i32(
            &mut cursor,
            decision,
            field_offset!(JitMixedSuperblockCallDecision, target_ordinal),
        );
        let frame = load_i32(
            &mut cursor,
            decision,
            field_offset!(JitMixedSuperblockCallDecision, frame),
        );
        let call_continuation = if corridor.force.is_some() {
            force_ready
        } else {
            complete
        };
        emit_call_target_dispatch(
            &mut cursor,
            activation,
            ordinal,
            frame,
            argument,
            &corridor.call_results,
            call_continuation,
            side_exit,
            invalid,
            corridor.call_fallback,
        );
    }

    if let Some(force) = corridor.force.as_ref() {
        function.layout.append_block(force_ready);
        let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(force_ready);
        let call_result = cursor.func.dfg.block_params(force_ready)[0];
        let decision = emit_next_force_decision(&mut cursor, activation, invalid);
        let Some(decision) = decision else {
            unreachable!("decision load always emits a continuation");
        };
        let observed = load_i64(
            &mut cursor,
            decision,
            field_offset!(JitMixedSuperblockForceDecision, subject),
        );
        let same_subject = cursor.ins().icmp(IntCC::Equal, observed, call_result);
        let action_block = cursor.func.dfg.make_block();
        cursor
            .ins()
            .brif(same_subject, action_block, &[], invalid, &[]);
        cursor.func.layout.append_block(action_block);
        cursor.set_position(CursorPosition::After(action_block));
        let action = load_i32(
            &mut cursor,
            decision,
            field_offset!(JitMixedSuperblockForceDecision, action),
        );
        let ready = cursor.ins().icmp_imm(
            IntCC::Equal,
            action,
            JitMixedSuperblockForceAction::Ready as i64,
        );
        let not_ready = cursor.func.dfg.make_block();
        let ready_result = load_i64(
            &mut cursor,
            decision,
            field_offset!(JitMixedSuperblockForceDecision, result),
        );
        cursor
            .ins()
            .brif(ready, complete, &[ready_result.into()], not_ready, &[]);
        cursor.func.layout.append_block(not_ready);
        cursor.set_position(CursorPosition::After(not_ready));
        emit_force_action_dispatch(
            &mut cursor,
            action,
            force_node,
            force_apply,
            force_gen_list,
            side_exit,
            invalid,
            force.force_fallback,
        );

        append_claimed_block(
            &mut function,
            force_node,
            activation,
            force.node,
            complete,
            invalid,
        );
        append_claimed_block(
            &mut function,
            force_apply,
            activation,
            force.apply,
            complete,
            invalid,
        );
        append_claimed_block(
            &mut function,
            force_gen_list,
            activation,
            force.gen_list,
            complete,
            invalid,
        );
    }

    function.layout.append_block(complete);
    {
        let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(complete);
        let result = cursor.func.dfg.block_params(complete)[0];
        store_i64(
            &mut cursor,
            activation,
            field_offset!(RawActivation, result),
            result,
        );
        store_status(&mut cursor, activation, STATUS_COMPLETE);
        let status = cursor.ins().iconst(types::I32, i64::from(STATUS_COMPLETE));
        cursor.ins().return_(&[status]);
    }

    function.layout.append_block(side_exit);
    {
        let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(side_exit);
        let statepoint = cursor.func.dfg.block_params(side_exit)[0];
        store_i32(
            &mut cursor,
            activation,
            field_offset!(RawActivation, side_exit),
            statepoint,
        );
        store_status(&mut cursor, activation, STATUS_SIDE_EXIT);
        let status = cursor.ins().iconst(types::I32, i64::from(STATUS_SIDE_EXIT));
        cursor.ins().return_(&[status]);
    }

    function.layout.append_block(invalid);
    {
        let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(invalid);
        store_status(&mut cursor, activation, STATUS_INVALID_ACTIVATION);
        let status = cursor
            .ins()
            .iconst(types::I32, i64::from(STATUS_INVALID_ACTIVATION));
        cursor.ins().return_(&[status]);
    }

    let flags = settings::Flags::new(settings::builder());
    verify_function(&function, &flags).map_err(|errors| {
        JitMixedSuperblockCompileError::Verification {
            message: errors.to_string(),
        }
    })?;
    Ok(JitMixedSuperblockArtifact {
        cache_key: JitMixedSuperblockCacheKey::new(plan),
        function,
        resumable: false,
        value_slots: 0,
        resumable_statepoints: vec![false; plan.statepoints().len()].into_boxed_slice(),
        reachable_statepoints: reachable_statepoints.into_boxed_slice(),
    })
}

/// Lowers the first table-generic, resumable subset of a mixed plan.
///
/// Runtime Apply, Force, and Materialize terminators leave through their exact
/// statepoints. Pure control resumes in a fresh native invocation over the
/// caller-owned value-slot slab; no native stack or SSA value survives the
/// boundary.
fn lower_general_mixed_cfg(
    plan: &MixedModulePlan,
    entry: usize,
) -> Result<JitMixedSuperblockArtifact, JitMixedSuperblockCompileError> {
    let entry = plan
        .entries()
        .get(entry)
        .ok_or(JitMixedSuperblockCompileError::InvalidEntry { entry })?;
    if entry.kind != MixedEntryKind::ForceWhnf {
        return unsupported("general entry is not ForceWhnf");
    }
    let mixed_function = function(plan, entry.function)?;
    let block_start = mixed_function.blocks.start() as usize;
    let block_end = block_start
        .checked_add(mixed_function.blocks.len() as usize)
        .ok_or_else(|| unsupported_error("general function block range overflows"))?;
    let block_range = block_start..block_end;
    let mut reachable_statepoints = vec![false; plan.statepoints().len()];
    for block_index in block_range.clone() {
        let statepoint = match &plan.blocks()[block_index].terminator {
            MixedTerminator::Force { fallback, .. }
            | MixedTerminator::ApplyGuarded { fallback, .. } => Some(*fallback),
            MixedTerminator::Materialize { statepoint } => Some(*statepoint),
            _ => None,
        };
        if let Some(statepoint) = statepoint {
            reachable_statepoints[statepoint.as_u32() as usize] = true;
        }
    }
    let function_end = mixed_function
        .blocks
        .start()
        .saturating_add(mixed_function.blocks.len());
    let resumable_statepoints = plan
        .statepoints()
        .iter()
        .enumerate()
        .map(|(index, statepoint)| {
            let resume = statepoint.resume.as_u32();
            reachable_statepoints[index]
                && matches!(statepoint.mode, MixedStatepointMode::Resume)
                && resume >= mixed_function.blocks.start()
                && resume < function_end
        })
        .collect::<Vec<_>>();
    if plan
        .statepoints()
        .iter()
        .zip(&resumable_statepoints)
        .any(|(statepoint, resumable)| {
            *resumable
                && matches!(
                    statepoint.result_type,
                    Some(MixedValueType::VirtualThunk | MixedValueType::VirtualClosure)
                )
        })
    {
        return unsupported("general resume result has an unsupported virtual type");
    }
    if plan.bounds().value_slots > GENERAL_VALUE_SLOT_CAP {
        return unsupported("general value-slot bound exceeds the generated-code cap");
    }
    let semantic_blocks = block_range
        .clone()
        .map(|_| None)
        .collect::<Vec<Option<Block>>>();
    let mut signature = Signature::new(CallConv::SystemV);
    signature.params.push(AbiParam::new(types::I64));
    signature.returns.push(AbiParam::new(types::I32));
    let mut generated = Function::with_name_signature(
        UserFuncName::user(MIXED_SUPERBLOCK_FUNCTION_NAMESPACE, entry.function.as_u32()),
        signature,
    );
    let native_entry = generated.dfg.make_block();
    generated.dfg.append_block_param(native_entry, types::I64);
    let storage_ready = generated.dfg.make_block();
    let initial = generated.dfg.make_block();
    let resume_dispatch = generated.dfg.make_block();
    let complete = generated.dfg.make_block();
    let invalid = generated.dfg.make_block();
    generated.dfg.append_block_param(complete, types::I64);
    generated.layout.append_block(native_entry);

    let activation = {
        let mut cursor = FuncCursor::new(&mut generated).at_first_insertion_point(native_entry);
        let activation = cursor.func.dfg.block_params(native_entry)[0];
        let nonnull = cursor.ins().icmp_imm(IntCC::NotEqual, activation, 0);
        cursor.ins().brif(nonnull, storage_ready, &[], invalid, &[]);
        activation
    };

    generated.layout.append_block(storage_ready);
    {
        let mut cursor = FuncCursor::new(&mut generated).at_first_insertion_point(storage_ready);
        let slots = load_i64(
            &mut cursor,
            activation,
            field_offset!(RawActivation, value_slots),
        );
        let slots_nonnull = cursor.ins().icmp_imm(IntCC::NotEqual, slots, 0);
        let capacity = load_i32(
            &mut cursor,
            activation,
            field_offset!(RawActivation, value_capacity),
        );
        let capacity_ok = cursor.ins().icmp_imm(
            IntCC::UnsignedGreaterThanOrEqual,
            capacity,
            i64::from(plan.bounds().value_slots),
        );
        let storage_ok = cursor.ins().band(slots_nonnull, capacity_ok);
        let choose_entry = cursor.func.dfg.make_block();
        cursor
            .ins()
            .brif(storage_ok, choose_entry, &[], invalid, &[]);
        cursor.func.layout.append_block(choose_entry);
        cursor.set_position(CursorPosition::After(choose_entry));
        let resume_requested = load_i32(
            &mut cursor,
            activation,
            field_offset!(RawActivation, resume_requested),
        );
        let resume = cursor.ins().icmp_imm(IntCC::NotEqual, resume_requested, 0);
        cursor
            .ins()
            .brif(resume, resume_dispatch, &[], initial, &[]);
    }

    let mut semantic_blocks = semantic_blocks;
    for slot in &mut semantic_blocks {
        *slot = Some(generated.dfg.make_block());
    }
    let semantic_block = |id: MixedBlockId| -> Result<Block, JitMixedSuperblockCompileError> {
        let index = id
            .as_u32()
            .checked_sub(block_range.start as u32)
            .ok_or_else(|| unsupported_error("general block precedes function range"))?
            as usize;
        semantic_blocks
            .get(index)
            .and_then(|block| *block)
            .ok_or_else(|| unsupported_error("general block leaves function range"))
    };

    generated.layout.append_block(initial);
    {
        let mut cursor = FuncCursor::new(&mut generated).at_first_insertion_point(initial);
        clear_general_value_slots(&mut cursor, activation, plan.bounds().value_slots)?;
        let argument = load_i64(
            &mut cursor,
            activation,
            field_offset!(RawActivation, argument),
        );
        store_general_value_slot(&mut cursor, activation, mixed_function.parameter, argument)?;
        store_i32_imm(
            &mut cursor,
            activation,
            field_offset!(RawActivation, resume_requested),
            0,
        );
        cursor
            .ins()
            .jump(semantic_block(mixed_function.entry)?, &[]);
    }

    generated.layout.append_block(resume_dispatch);
    {
        let mut cursor = FuncCursor::new(&mut generated).at_first_insertion_point(resume_dispatch);
        let requested = load_i32(
            &mut cursor,
            activation,
            field_offset!(RawActivation, resume_statepoint),
        );
        for (statepoint_index, statepoint) in plan.statepoints().iter().enumerate() {
            let resume = statepoint.resume.as_u32();
            let function_end = mixed_function
                .blocks
                .start()
                .saturating_add(mixed_function.blocks.len());
            if !matches!(statepoint.mode, MixedStatepointMode::Resume)
                || resume < mixed_function.blocks.start()
                || resume >= function_end
            {
                continue;
            }
            let matched = cursor.func.dfg.make_block();
            let next = cursor.func.dfg.make_block();
            let exact = cursor.ins().icmp_imm(
                IntCC::Equal,
                requested,
                i64::try_from(statepoint_index).unwrap_or(i64::MAX),
            );
            cursor.ins().brif(exact, matched, &[], next, &[]);
            cursor.func.layout.append_block(matched);
            cursor.set_position(CursorPosition::After(matched));
            let has_result = load_i32(
                &mut cursor,
                activation,
                field_offset!(RawActivation, resume_has_result),
            );
            let result_shape_ok = cursor.ins().icmp_imm(
                IntCC::Equal,
                has_result,
                i64::from(u32::from(statepoint.result.is_some())),
            );
            let install_result = cursor.func.dfg.make_block();
            cursor
                .ins()
                .brif(result_shape_ok, install_result, &[], invalid, &[]);
            cursor.func.layout.append_block(install_result);
            cursor.set_position(CursorPosition::After(install_result));
            if let Some(result_slot) = statepoint.result {
                let result = load_i64(
                    &mut cursor,
                    activation,
                    field_offset!(RawActivation, resume_result),
                );
                store_general_value_slot(&mut cursor, activation, result_slot, result)?;
            }
            store_i32_imm(
                &mut cursor,
                activation,
                field_offset!(RawActivation, resume_requested),
                0,
            );
            cursor.ins().jump(semantic_block(statepoint.resume)?, &[]);
            cursor.func.layout.append_block(next);
            cursor.set_position(CursorPosition::After(next));
        }
        cursor.ins().jump(invalid, &[]);
    }

    for block_index in block_range.clone() {
        let block_id = MixedBlockId::new(block_index as u32);
        let native_block = semantic_block(block_id)?;
        generated.layout.append_block(native_block);
        let mut cursor = FuncCursor::new(&mut generated).at_first_insertion_point(native_block);
        for operation in operations(plan, &plan.blocks()[block_index])? {
            emit_general_operation(&mut cursor, activation, invalid, *operation)?;
        }
        match &plan.blocks()[block_index].terminator {
            MixedTerminator::Jump { target } => {
                cursor.ins().jump(semantic_block(*target)?, &[]);
            }
            MixedTerminator::Branch {
                condition,
                when_true,
                when_false,
            } => {
                let condition = load_general_value_slot(&mut cursor, activation, *condition)?;
                let is_true = cursor.ins().icmp_imm(
                    IntCC::Equal,
                    condition,
                    encode_boolean_constant(true) as i64,
                );
                cursor.ins().brif(
                    is_true,
                    semantic_block(*when_true)?,
                    &[],
                    semantic_block(*when_false)?,
                    &[],
                );
            }
            MixedTerminator::Force { fallback, .. }
            | MixedTerminator::ApplyGuarded { fallback, .. } => {
                emit_general_side_exit(&mut cursor, activation, plan, *fallback)?;
            }
            MixedTerminator::Return { value } => {
                let value = load_general_value_slot(&mut cursor, activation, *value)?;
                cursor.ins().jump(complete, &[value.into()]);
            }
            MixedTerminator::Materialize { statepoint } => {
                emit_general_side_exit(&mut cursor, activation, plan, *statepoint)?;
            }
            MixedTerminator::Update { .. } => {
                return unsupported("general CFG does not own force-update publication");
            }
        }
    }

    generated.layout.append_block(complete);
    {
        let mut cursor = FuncCursor::new(&mut generated).at_first_insertion_point(complete);
        let result = cursor.func.dfg.block_params(complete)[0];
        store_i64(
            &mut cursor,
            activation,
            field_offset!(RawActivation, result),
            result,
        );
        store_i32_imm(
            &mut cursor,
            activation,
            field_offset!(RawActivation, live_value_count),
            0,
        );
        store_status(&mut cursor, activation, STATUS_COMPLETE);
        let status = cursor.ins().iconst(types::I32, i64::from(STATUS_COMPLETE));
        cursor.ins().return_(&[status]);
    }

    generated.layout.append_block(invalid);
    {
        let mut cursor = FuncCursor::new(&mut generated).at_first_insertion_point(invalid);
        store_status(&mut cursor, activation, STATUS_INVALID_ACTIVATION);
        let status = cursor
            .ins()
            .iconst(types::I32, i64::from(STATUS_INVALID_ACTIVATION));
        cursor.ins().return_(&[status]);
    }

    let flags = settings::Flags::new(settings::builder());
    verify_function(&generated, &flags).map_err(|errors| {
        JitMixedSuperblockCompileError::Verification {
            message: errors.to_string(),
        }
    })?;
    Ok(JitMixedSuperblockArtifact {
        cache_key: JitMixedSuperblockCacheKey::new(plan),
        function: generated,
        resumable: true,
        value_slots: plan.bounds().value_slots,
        reachable_statepoints: reachable_statepoints.into_boxed_slice(),
        resumable_statepoints: resumable_statepoints.into_boxed_slice(),
    })
}

fn emit_general_operation(
    cursor: &mut FuncCursor<'_>,
    activation: Value,
    invalid: Block,
    operation: MixedOp,
) -> Result<(), JitMixedSuperblockCompileError> {
    let (destination, value) = match operation {
        MixedOp::ConstInt { destination, value } => {
            let value = encode_integer_constant(value)
                .ok_or_else(|| unsupported_error("general integer is not inline-representable"))?;
            (destination, cursor.ins().iconst(types::I64, value as i64))
        }
        MixedOp::ConstBool { destination, value } => (
            destination,
            cursor
                .ins()
                .iconst(types::I64, encode_boolean_constant(value) as i64),
        ),
        MixedOp::ConstNull { destination } => (
            destination,
            cursor
                .ins()
                .iconst(types::I64, encode_null_constant() as i64),
        ),
        MixedOp::Move {
            destination,
            source,
        } => (
            destination,
            load_general_value_slot(cursor, activation, source)?,
        ),
        MixedOp::LoadLocal { destination, slot } => {
            let frame = load_i32(
                cursor,
                activation,
                field_offset!(RawActivation, entry_frame),
            );
            let Some(value) = emit_frame_load(cursor, activation, frame, slot, invalid) else {
                return unsupported("general local load did not emit a value");
            };
            (destination, value)
        }
        MixedOp::LoadUpvalue { .. } => {
            return unsupported("general CFG lacks parent-frame coordinates");
        }
        MixedOp::VirtualThunk { .. } | MixedOp::VirtualClosure { .. } => {
            return unsupported("general CFG lacks virtual materialization recipes");
        }
        MixedOp::AddInt { .. } | MixedOp::LessThanInt { .. } => {
            return unsupported("general CFG scalar arithmetic is not carrier-generic yet");
        }
    };
    store_general_value_slot(cursor, activation, destination, value)?;
    Ok(())
}

fn emit_general_side_exit(
    cursor: &mut FuncCursor<'_>,
    activation: Value,
    plan: &MixedModulePlan,
    statepoint_id: MixedStatepointId,
) -> Result<(), JitMixedSuperblockCompileError> {
    let statepoint = plan
        .statepoints()
        .get(statepoint_id.as_u32() as usize)
        .ok_or_else(|| unsupported_error("general statepoint is absent"))?;
    for slot in 0..plan.bounds().value_slots {
        let value = MixedValueId::new(slot);
        if statepoint.live_values.binary_search(&value).is_err() {
            let zero = cursor.ins().iconst(types::I64, 0);
            store_general_value_slot(cursor, activation, value, zero)?;
        }
    }
    store_i32_imm(
        cursor,
        activation,
        field_offset!(RawActivation, live_value_count),
        statepoint.live_values.len() as u32,
    );
    store_i32_imm(
        cursor,
        activation,
        field_offset!(RawActivation, side_exit),
        statepoint_id.as_u32(),
    );
    store_i32_imm(
        cursor,
        activation,
        field_offset!(RawActivation, resume_statepoint),
        statepoint_id.as_u32(),
    );
    store_i32_imm(
        cursor,
        activation,
        field_offset!(RawActivation, resume_requested),
        0,
    );
    store_status(cursor, activation, STATUS_SIDE_EXIT);
    let status = cursor.ins().iconst(types::I32, i64::from(STATUS_SIDE_EXIT));
    cursor.ins().return_(&[status]);
    Ok(())
}

fn clear_general_value_slots(
    cursor: &mut FuncCursor<'_>,
    activation: Value,
    count: u32,
) -> Result<(), JitMixedSuperblockCompileError> {
    for slot in 0..count {
        let zero = cursor.ins().iconst(types::I64, 0);
        store_general_value_slot(cursor, activation, MixedValueId::new(slot), zero)?;
    }
    Ok(())
}

fn load_general_value_slot(
    cursor: &mut FuncCursor<'_>,
    activation: Value,
    slot: MixedValueId,
) -> Result<Value, JitMixedSuperblockCompileError> {
    let base = load_i64(
        cursor,
        activation,
        field_offset!(RawActivation, value_slots),
    );
    let offset = general_value_slot_offset(slot)?;
    Ok(cursor
        .ins()
        .load(types::I64, MemFlags::trusted(), base, offset))
}

fn store_general_value_slot(
    cursor: &mut FuncCursor<'_>,
    activation: Value,
    slot: MixedValueId,
    value: Value,
) -> Result<(), JitMixedSuperblockCompileError> {
    let base = load_i64(
        cursor,
        activation,
        field_offset!(RawActivation, value_slots),
    );
    let offset = general_value_slot_offset(slot)?;
    cursor.ins().store(MemFlags::trusted(), value, base, offset);
    Ok(())
}

fn general_value_slot_offset(slot: MixedValueId) -> Result<i32, JitMixedSuperblockCompileError> {
    let bytes = slot
        .as_u32()
        .checked_mul(u64::BITS / 8)
        .ok_or_else(|| unsupported_error("general value-slot byte offset overflows u32"))?;
    i32::try_from(bytes)
        .map_err(|_| unsupported_error("general value-slot byte offset exceeds i32"))
}

fn store_i32_imm(cursor: &mut FuncCursor<'_>, base: Value, offset: i32, value: u32) {
    let value = cursor.ins().iconst(types::I32, i64::from(value));
    store_i32(cursor, base, offset, value);
}

#[allow(clippy::too_many_arguments)]
fn emit_call_target_dispatch(
    cursor: &mut FuncCursor<'_>,
    activation: Value,
    ordinal: Value,
    frame: Value,
    argument: Value,
    results: &[AdmittedCallResult],
    continuation: Block,
    side_exit: Block,
    invalid: Block,
    fallback: MixedStatepointId,
) {
    for (target, result) in results.iter().copied().enumerate() {
        let matched = cursor.func.dfg.make_block();
        let next = cursor.func.dfg.make_block();
        let exact = cursor.ins().icmp_imm(
            IntCC::Equal,
            ordinal,
            i64::try_from(target).unwrap_or(i64::MAX),
        );
        cursor.ins().brif(exact, matched, &[], next, &[]);
        cursor.func.layout.append_block(matched);
        cursor.set_position(CursorPosition::After(matched));
        let value = match result {
            AdmittedCallResult::Argument => argument,
            AdmittedCallResult::FrameLocal(slot) => {
                let Some(value) = emit_frame_load(cursor, activation, frame, slot, invalid) else {
                    unreachable!("frame load always emits a continuation");
                };
                value
            }
            AdmittedCallResult::Constant(value) => cursor.ins().iconst(types::I64, value as i64),
        };
        cursor.ins().jump(continuation, &[value.into()]);
        cursor.func.layout.append_block(next);
        cursor.set_position(CursorPosition::After(next));
    }
    let declined = cursor
        .ins()
        .icmp_imm(IntCC::Equal, ordinal, i64::from(DECLINED_TARGET));
    let statepoint = cursor
        .ins()
        .iconst(types::I32, i64::from(fallback.as_u32()));
    cursor
        .ins()
        .brif(declined, side_exit, &[statepoint.into()], invalid, &[]);
}

fn admit_corridor(
    plan: &MixedModulePlan,
    entry: usize,
) -> Result<AdmittedCorridor, JitMixedSuperblockCompileError> {
    let entry = plan
        .entries()
        .get(entry)
        .ok_or(JitMixedSuperblockCompileError::InvalidEntry { entry })?;
    if entry.kind != MixedEntryKind::ForceWhnf {
        return unsupported("entry is not ForceWhnf");
    }
    if plan.operations().iter().any(|operation| {
        matches!(
            operation,
            MixedOp::VirtualThunk { .. } | MixedOp::VirtualClosure { .. }
        )
    }) {
        return unsupported("plan constructs virtual objects");
    }
    if plan
        .blocks()
        .iter()
        .any(|block| matches!(block.terminator, MixedTerminator::Materialize { .. }))
    {
        return unsupported("plan contains a generic materialization terminator");
    }
    let entry_function = function(plan, entry.function)?;
    let apply_block = block(plan, entry_function.entry)?;
    let apply_operations = operations(plan, apply_block)?;
    let MixedTerminator::ApplyGuarded {
        function: callable,
        argument: apply_argument,
        result: call_result,
        targets,
        continuation,
        fallback: call_fallback,
    } = &apply_block.terminator
    else {
        return unsupported("entry block does not end in ApplyGuarded");
    };
    if targets.len() == 0 {
        return unsupported("guarded application is not the direct entry shape");
    }
    let Some((entry_callable, callable_operation)) =
        admit_entry_operand(apply_operations, *callable, entry_function.parameter)
    else {
        return unsupported("guarded callable is not a direct scalar operand");
    };
    let Some((entry_argument, argument_operation)) =
        admit_entry_operand(apply_operations, *apply_argument, entry_function.parameter)
    else {
        return unsupported("guarded argument is not a direct scalar operand");
    };
    if callable_operation == argument_operation
        || usize::from(callable_operation.is_some())
            .saturating_add(usize::from(argument_operation.is_some()))
            != apply_operations.len()
    {
        return unsupported("guarded entry operations are not one-use scalar operands");
    }
    let target_start = targets.start() as usize;
    let target_end = target_start
        .checked_add(targets.len() as usize)
        .ok_or_else(|| unsupported_error("guarded target range overflows"))?;
    let guarded_targets = plan
        .call_targets()
        .get(target_start..target_end)
        .ok_or_else(|| unsupported_error("guarded target range is absent"))?;
    let mut call_results = Vec::with_capacity(guarded_targets.len());
    for target in guarded_targets {
        let callee = function(plan, target.function)?;
        if target.argument_destination != callee.parameter {
            return unsupported("callee argument mapping is not direct");
        }
        let callee_block = block(plan, callee.entry)?;
        let result = match (operations(plan, callee_block)?, &callee_block.terminator) {
            ([], MixedTerminator::Return { value }) if *value == callee.parameter => {
                AdmittedCallResult::Argument
            }
            ([MixedOp::LoadLocal { destination, slot }], MixedTerminator::Return { value })
                if destination == value =>
            {
                AdmittedCallResult::FrameLocal(*slot)
            }
            (
                [MixedOp::ConstInt { destination, value }],
                MixedTerminator::Return {
                    value: return_value,
                },
            ) if destination == return_value => {
                let Some(value) = encode_integer_constant(*value) else {
                    return unsupported("guarded callee integer is not inline-representable");
                };
                AdmittedCallResult::Constant(value)
            }
            _ => return unsupported("guarded callee is not a direct scalar return"),
        };
        call_results.push(result);
    }
    let force = admit_force_corridor(plan, *continuation, *call_result)?;
    Ok(AdmittedCorridor {
        entry_callable,
        entry_argument,
        call_results,
        call_fallback: *call_fallback,
        force,
    })
}

fn admit_force_corridor(
    plan: &MixedModulePlan,
    continuation: MixedBlockId,
    call_result: MixedValueId,
) -> Result<Option<AdmittedForceCorridor>, JitMixedSuperblockCompileError> {
    let force_block = block(plan, continuation)?;
    if !operations(plan, force_block)?.is_empty() {
        return unsupported("guarded continuation contains pure operations");
    }
    if matches!(
        force_block.terminator,
        MixedTerminator::Return { value } if value == call_result
    ) {
        return Ok(None);
    }
    if plan.bounds().update_depth == 0 {
        return unsupported("force corridor reserves no update record");
    }
    let MixedTerminator::Force {
        subject,
        result: force_result,
        ready,
        node,
        apply,
        gen_list,
        fallback: force_fallback,
        ..
    } = &force_block.terminator
    else {
        return unsupported("guarded continuation is not a direct return or Force");
    };
    if *subject != call_result {
        return unsupported("force subject is not the guarded-call result");
    }
    let ready_block = block(plan, *ready)?;
    if !operations(plan, ready_block)?.is_empty()
        || !matches!(
            ready_block.terminator,
            MixedTerminator::Return { value } if value == *force_result
        )
    {
        return unsupported("ready force edge does not return its result");
    }
    Ok(Some(AdmittedForceCorridor {
        force_fallback: *force_fallback,
        node: admit_claimed_result(plan, *node, *force_result, *ready)?,
        apply: admit_claimed_result(plan, *apply, *force_result, *ready)?,
        gen_list: admit_claimed_result(plan, *gen_list, *force_result, *ready)?,
    }))
}

fn admit_entry_operand(
    operations: &[MixedOp],
    value: MixedValueId,
    parameter: MixedValueId,
) -> Option<(AdmittedEntryOperand, Option<usize>)> {
    if value == parameter {
        return Some((AdmittedEntryOperand::Parameter, None));
    }
    operations
        .iter()
        .enumerate()
        .find_map(|(index, operation)| match *operation {
            MixedOp::LoadLocal { destination, slot } if destination == value => {
                Some((AdmittedEntryOperand::FrameLocal(slot), Some(index)))
            }
            MixedOp::ConstInt {
                destination,
                value: constant,
            } if destination == value => encode_integer_constant(constant)
                .map(|constant| (AdmittedEntryOperand::Constant(constant), Some(index))),
            _ => None,
        })
}

fn admit_claimed_result(
    plan: &MixedModulePlan,
    block_id: MixedBlockId,
    force_result: MixedValueId,
    ready: MixedBlockId,
) -> Result<ClaimedResult, JitMixedSuperblockCompileError> {
    let block = block(plan, block_id)?;
    let value =
        match operations(plan, block)? {
            [MixedOp::LoadLocal { destination, slot }] => {
                (*destination, ClaimedResult::FrameLocal(*slot))
            }
            [MixedOp::ConstInt { destination, value }] => (
                *destination,
                ClaimedResult::Constant(encode_integer_constant(*value).ok_or_else(|| {
                    unsupported_error("claimed integer is not inline-representable")
                })?),
            ),
            _ => return unsupported("claimed force edge has unsupported operations"),
        };
    let MixedTerminator::Update {
        value: update_value,
        result,
        next,
    } = block.terminator
    else {
        return unsupported("claimed force edge does not publish Update");
    };
    if update_value != value.0 || result != force_result || next != ready {
        return unsupported("claimed update does not rejoin the ready return");
    }
    Ok(value.1)
}

fn function(
    plan: &MixedModulePlan,
    id: MixedFunctionId,
) -> Result<&ratchet_core::mixed_machine::MixedFunction, JitMixedSuperblockCompileError> {
    plan.functions()
        .get(id.as_u32() as usize)
        .ok_or_else(|| unsupported_error("function id is absent"))
}

fn block(
    plan: &MixedModulePlan,
    id: MixedBlockId,
) -> Result<&ratchet_core::mixed_machine::MixedBlock, JitMixedSuperblockCompileError> {
    plan.blocks()
        .get(id.as_u32() as usize)
        .ok_or_else(|| unsupported_error("block id is absent"))
}

fn operations<'plan>(
    plan: &'plan MixedModulePlan,
    block: &ratchet_core::mixed_machine::MixedBlock,
) -> Result<&'plan [MixedOp], JitMixedSuperblockCompileError> {
    let start = block.operations.start() as usize;
    let end = start
        .checked_add(block.operations.len() as usize)
        .ok_or_else(|| unsupported_error("operation range overflows"))?;
    plan.operations()
        .get(start..end)
        .ok_or_else(|| unsupported_error("operation range is absent"))
}

fn unsupported<T>(reason: &'static str) -> Result<T, JitMixedSuperblockCompileError> {
    Err(unsupported_error(reason))
}

const fn unsupported_error(reason: &'static str) -> JitMixedSuperblockCompileError {
    JitMixedSuperblockCompileError::UnsupportedPlan { reason }
}

fn encode_integer_constant(value: i64) -> Option<u64> {
    #[cfg(feature = "candidate_c_value")]
    {
        let value = i32::try_from(value).ok()?;
        Some(ratchet_value::value::Value::int(i64::from(value)).transient_identity_bits())
    }
    #[cfg(not(feature = "candidate_c_value"))]
    {
        Some(value as u64)
    }
}

fn encode_boolean_constant(value: bool) -> u64 {
    #[cfg(feature = "candidate_c_value")]
    {
        ratchet_value::value::Value::bool(value).transient_identity_bits()
    }
    #[cfg(not(feature = "candidate_c_value"))]
    {
        u64::from(value)
    }
}

fn encode_null_constant() -> u64 {
    #[cfg(feature = "candidate_c_value")]
    {
        ratchet_value::value::Value::null().transient_identity_bits()
    }
    #[cfg(not(feature = "candidate_c_value"))]
    {
        0
    }
}

fn emit_entry_operand(
    cursor: &mut FuncCursor<'_>,
    activation: Value,
    parameter: Value,
    frame: Value,
    operand: AdmittedEntryOperand,
    invalid: Block,
) -> Option<Value> {
    match operand {
        AdmittedEntryOperand::Parameter => Some(parameter),
        AdmittedEntryOperand::FrameLocal(slot) => {
            emit_frame_load(cursor, activation, frame, slot, invalid)
        }
        AdmittedEntryOperand::Constant(value) => {
            Some(cursor.ins().iconst(types::I64, value as i64))
        }
    }
}

fn emit_frame_load(
    cursor: &mut FuncCursor<'_>,
    activation: Value,
    frame: Value,
    slot: u32,
    invalid: Block,
) -> Option<Value> {
    let frame_count = load_i32(
        cursor,
        activation,
        field_offset!(RawActivation, frame_count),
    );
    let valid_frame = cursor
        .ins()
        .icmp(IntCC::UnsignedLessThan, frame, frame_count);
    let check_slot = cursor.func.dfg.make_block();
    cursor
        .ins()
        .brif(valid_frame, check_slot, &[], invalid, &[]);
    cursor.func.layout.append_block(check_slot);
    cursor.set_position(CursorPosition::After(check_slot));
    let stride = load_i32(
        cursor,
        activation,
        field_offset!(RawActivation, frame_stride),
    );
    let valid_slot = cursor
        .ins()
        .icmp_imm(IntCC::UnsignedGreaterThan, stride, i64::from(slot));
    let load = cursor.func.dfg.make_block();
    cursor.ins().brif(valid_slot, load, &[], invalid, &[]);
    cursor.func.layout.append_block(load);
    cursor.set_position(CursorPosition::After(load));
    let frame64 = cursor.ins().uextend(types::I64, frame);
    let stride64 = cursor.ins().uextend(types::I64, stride);
    let frame_base = cursor.ins().imul(frame64, stride64);
    let index = cursor.ins().iadd_imm(frame_base, i64::from(slot));
    let byte_offset = cursor.ins().ishl_imm(index, 3);
    let frames = load_i64(cursor, activation, field_offset!(RawActivation, frames));
    let address = cursor.ins().iadd(frames, byte_offset);
    Some(
        cursor
            .ins()
            .load(types::I64, MemFlags::trusted(), address, 0),
    )
}

fn emit_next_call_decision(
    cursor: &mut FuncCursor<'_>,
    activation: Value,
    invalid: Block,
) -> Option<Value> {
    emit_next_record(
        cursor,
        activation,
        field_offset!(RawActivation, call_cursor),
        field_offset!(RawActivation, call_count),
        field_offset!(RawActivation, calls),
        std::mem::size_of::<JitMixedSuperblockCallDecision>() as i64,
        invalid,
    )
}

fn emit_next_force_decision(
    cursor: &mut FuncCursor<'_>,
    activation: Value,
    invalid: Block,
) -> Option<Value> {
    emit_next_record(
        cursor,
        activation,
        field_offset!(RawActivation, force_cursor),
        field_offset!(RawActivation, force_count),
        field_offset!(RawActivation, forces),
        std::mem::size_of::<JitMixedSuperblockForceDecision>() as i64,
        invalid,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_next_record(
    cursor: &mut FuncCursor<'_>,
    activation: Value,
    cursor_offset: i32,
    count_offset: i32,
    records_offset: i32,
    record_size: i64,
    invalid: Block,
) -> Option<Value> {
    let index = load_i32(cursor, activation, cursor_offset);
    let count = load_i32(cursor, activation, count_offset);
    let available = cursor.ins().icmp(IntCC::UnsignedLessThan, index, count);
    let load = cursor.func.dfg.make_block();
    cursor.ins().brif(available, load, &[], invalid, &[]);
    cursor.func.layout.append_block(load);
    cursor.set_position(CursorPosition::After(load));
    let next = cursor.ins().iadd_imm(index, 1);
    store_i32(cursor, activation, cursor_offset, next);
    let base = load_i64(cursor, activation, records_offset);
    let index64 = cursor.ins().uextend(types::I64, index);
    let byte_offset = cursor.ins().imul_imm(index64, record_size);
    Some(cursor.ins().iadd(base, byte_offset))
}

#[allow(clippy::too_many_arguments)]
fn emit_force_action_dispatch(
    cursor: &mut FuncCursor<'_>,
    action: Value,
    node: Block,
    apply: Block,
    gen_list: Block,
    side_exit: Block,
    invalid: Block,
    fallback: MixedStatepointId,
) {
    let is_node = cursor.ins().icmp_imm(
        IntCC::Equal,
        action,
        JitMixedSuperblockForceAction::Node as i64,
    );
    let check_apply = cursor.func.dfg.make_block();
    cursor.ins().brif(is_node, node, &[], check_apply, &[]);
    cursor.func.layout.append_block(check_apply);
    cursor.set_position(CursorPosition::After(check_apply));
    let is_apply = cursor.ins().icmp_imm(
        IntCC::Equal,
        action,
        JitMixedSuperblockForceAction::Apply as i64,
    );
    let check_gen = cursor.func.dfg.make_block();
    cursor.ins().brif(is_apply, apply, &[], check_gen, &[]);
    cursor.func.layout.append_block(check_gen);
    cursor.set_position(CursorPosition::After(check_gen));
    let is_gen = cursor.ins().icmp_imm(
        IntCC::Equal,
        action,
        JitMixedSuperblockForceAction::GenListElemAtAddOne as i64,
    );
    let check_declined = cursor.func.dfg.make_block();
    cursor
        .ins()
        .brif(is_gen, gen_list, &[], check_declined, &[]);
    cursor.func.layout.append_block(check_declined);
    cursor.set_position(CursorPosition::After(check_declined));
    let declined = cursor.ins().icmp_imm(
        IntCC::Equal,
        action,
        JitMixedSuperblockForceAction::Declined as i64,
    );
    let statepoint = cursor
        .ins()
        .iconst(types::I32, i64::from(fallback.as_u32()));
    cursor
        .ins()
        .brif(declined, side_exit, &[statepoint.into()], invalid, &[]);
}

fn append_claimed_block(
    function: &mut Function,
    block: Block,
    activation: Value,
    result: ClaimedResult,
    complete: Block,
    invalid: Block,
) {
    function.layout.append_block(block);
    let mut cursor = FuncCursor::new(function).at_first_insertion_point(block);
    let decision = emit_current_force_decision(&mut cursor, activation, invalid);
    let Some(decision) = decision else {
        unreachable!("current decision always emits a continuation");
    };
    let value = match result {
        ClaimedResult::FrameLocal(slot) => {
            let frame = load_i32(
                &mut cursor,
                decision,
                field_offset!(JitMixedSuperblockForceDecision, frame),
            );
            let Some(value) = emit_frame_load(&mut cursor, activation, frame, slot, invalid) else {
                unreachable!("frame load always emits a continuation");
            };
            value
        }
        ClaimedResult::Constant(value) => cursor.ins().iconst(types::I64, value as i64),
    };
    emit_publish_update(&mut cursor, activation, decision, value, invalid);
    cursor.ins().jump(complete, &[value.into()]);
}

fn emit_current_force_decision(
    cursor: &mut FuncCursor<'_>,
    activation: Value,
    invalid: Block,
) -> Option<Value> {
    let next = load_i32(
        cursor,
        activation,
        field_offset!(RawActivation, force_cursor),
    );
    let has_current = cursor.ins().icmp_imm(IntCC::NotEqual, next, 0);
    let load = cursor.func.dfg.make_block();
    cursor.ins().brif(has_current, load, &[], invalid, &[]);
    cursor.func.layout.append_block(load);
    cursor.set_position(CursorPosition::After(load));
    let index = cursor.ins().iadd_imm(next, -1);
    let base = load_i64(cursor, activation, field_offset!(RawActivation, forces));
    let index64 = cursor.ins().uextend(types::I64, index);
    let byte_offset = cursor.ins().imul_imm(
        index64,
        std::mem::size_of::<JitMixedSuperblockForceDecision>() as i64,
    );
    Some(cursor.ins().iadd(base, byte_offset))
}

fn emit_publish_update(
    cursor: &mut FuncCursor<'_>,
    activation: Value,
    decision: Value,
    value: Value,
    invalid: Block,
) {
    let index = load_i32(
        cursor,
        activation,
        field_offset!(RawActivation, published_updates),
    );
    let capacity = load_i32(
        cursor,
        activation,
        field_offset!(RawActivation, update_capacity),
    );
    let available = cursor.ins().icmp(IntCC::UnsignedLessThan, index, capacity);
    let publish = cursor.func.dfg.make_block();
    cursor.ins().brif(available, publish, &[], invalid, &[]);
    cursor.func.layout.append_block(publish);
    cursor.set_position(CursorPosition::After(publish));
    let updates = load_i64(cursor, activation, field_offset!(RawActivation, updates));
    let index64 = cursor.ins().uextend(types::I64, index);
    let byte_offset = cursor.ins().imul_imm(
        index64,
        std::mem::size_of::<JitMixedSuperblockPublishedUpdate>() as i64,
    );
    let record = cursor.ins().iadd(updates, byte_offset);
    let token = load_i64(
        cursor,
        decision,
        field_offset!(JitMixedSuperblockForceDecision, token),
    );
    store_i64(
        cursor,
        record,
        field_offset!(JitMixedSuperblockPublishedUpdate, token),
        token,
    );
    store_i64(
        cursor,
        record,
        field_offset!(JitMixedSuperblockPublishedUpdate, value),
        value,
    );
    let published = cursor.ins().iconst(types::I32, 1);
    store_i32(
        cursor,
        record,
        field_offset!(JitMixedSuperblockPublishedUpdate, published),
        published,
    );
    let next = cursor.ins().iadd_imm(index, 1);
    store_i32(
        cursor,
        activation,
        field_offset!(RawActivation, published_updates),
        next,
    );
}

fn load_i64(cursor: &mut FuncCursor<'_>, base: Value, offset: i32) -> Value {
    cursor
        .ins()
        .load(types::I64, MemFlags::trusted(), base, offset)
}

fn load_i32(cursor: &mut FuncCursor<'_>, base: Value, offset: i32) -> Value {
    cursor
        .ins()
        .load(types::I32, MemFlags::trusted(), base, offset)
}

fn store_i64(cursor: &mut FuncCursor<'_>, base: Value, offset: i32, value: Value) {
    cursor.ins().store(MemFlags::trusted(), value, base, offset);
}

fn store_i32(cursor: &mut FuncCursor<'_>, base: Value, offset: i32, value: Value) {
    cursor.ins().store(MemFlags::trusted(), value, base, offset);
}

fn store_status(cursor: &mut FuncCursor<'_>, activation: Value, status: u32) {
    let status = cursor.ins().iconst(types::I32, i64::from(status));
    store_i32(
        cursor,
        activation,
        field_offset!(RawActivation, status),
        status,
    );
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, hint::black_box};

    use cranelift_codegen::ir::Opcode;
    use ratchet_core::{
        FrameId, Ir, IrData, IrId, lower,
        mixed_machine::{
            MixedBlock, MixedCallTarget, MixedCallable, MixedCodeIdentity, MixedEntry,
            MixedExecutablePlan, MixedExecutionOutcome, MixedExecutionRunner, MixedForceAction,
            MixedForceGuards, MixedForceShape, MixedFunction, MixedMachineRuntime,
            MixedOracleCallTargetBlock, MixedOracleNodeLowerOutcome, MixedOraclePlanLowerOutcome,
            MixedPlanBounds, MixedSource, MixedStatepoint, MixedStatepointMode,
            MixedStatepointReason, MixedTableRange, MixedValueType, lower_mixed_oracle_node,
            lower_mixed_oracle_ready_call_plan,
        },
        resolve,
        stg::{StgCodeKey, StgLowerOutcome, StgModuleId, lower_stg_code_block},
        syntax::{Span, parse_str},
    };

    use super::*;

    const DEFAULT_SUPERBLOCK_PROBE_ITERATIONS: u64 = 5_000_000;
    const EXPECTED_PROBE_VALUE: u64 = 40;
    const EXPECTED_PROBE_TOKEN: u64 = 99;

    #[derive(Default)]
    struct ReferenceRuntime {
        published: Vec<(u64, u64)>,
    }

    impl MixedMachineRuntime for ReferenceRuntime {
        type Value = u64;
        type Frame = u32;
        type ForceTarget = u64;
        type UpdateToken = u64;
        type Error = Infallible;

        fn integer(&mut self, value: i64) -> Result<Self::Value, Self::Error> {
            Ok(value as u64)
        }

        fn boolean(&mut self, value: bool) -> Self::Value {
            u64::from(value)
        }

        fn null(&mut self) -> Self::Value {
            0
        }

        fn load_local(
            &mut self,
            frame: Self::Frame,
            slot: u32,
        ) -> Result<Self::Value, Self::Error> {
            Ok(match (frame, slot) {
                (0, 0) => 9,
                (1, 0) => 40,
                _ => 0,
            })
        }

        fn load_upvalue(
            &mut self,
            frame: Self::Frame,
            depth: u32,
            slot: u32,
        ) -> Result<Self::Value, Self::Error> {
            self.load_local(frame.saturating_sub(depth), slot)
        }

        fn add_integer(
            &mut self,
            left: Self::Value,
            right: Self::Value,
        ) -> Result<Self::Value, Self::Error> {
            Ok(left.wrapping_add(right))
        }

        fn integer_less_than(
            &mut self,
            left: Self::Value,
            right: Self::Value,
        ) -> Result<Self::Value, Self::Error> {
            Ok(u64::from(left < right))
        }

        fn decode_boolean(&mut self, value: Self::Value) -> Result<bool, Self::Error> {
            Ok(value != 0)
        }

        fn begin_force(
            &mut self,
            subject: Self::Value,
            guards: MixedForceGuards,
        ) -> Result<
            MixedForceAction<Self::Value, Self::Frame, Self::ForceTarget, Self::UpdateToken>,
            Self::Error,
        > {
            Ok(MixedForceAction::Claimed {
                target: subject,
                shape: MixedForceShape::Node,
                work: guards.node,
                frame: 1,
                update: 99,
            })
        }

        fn inspect_callable(
            &mut self,
            callable: Self::Value,
        ) -> Result<MixedCallable<Self::Frame>, Self::Error> {
            Ok(MixedCallable::Materialized {
                code: code(callable as u32),
                frame: 0,
            })
        }

        fn publish_update(
            &mut self,
            _target: &Self::ForceTarget,
            token: &Self::UpdateToken,
            value: Self::Value,
        ) -> Result<(), Self::Error> {
            self.published.push((*token, value));
            Ok(())
        }

        fn abort_update(&mut self, _target: Self::ForceTarget, _token: Self::UpdateToken) {}
    }

    #[test]
    fn direct_native_corridor_matches_reference_runner() {
        let plan = corridor_plan(41);
        let executable =
            MixedExecutablePlan::new(&plan).expect("fixture is executable by the reference runner");
        let mut runner = MixedExecutionRunner::<ReferenceRuntime>::new(executable, 0, 8, 0, 2)
            .expect("reference runner allocates");
        let mut reference = ReferenceRuntime::default();
        let MixedExecutionOutcome::Complete(reference_value) =
            runner.run(&mut reference).expect("reference executes")
        else {
            panic!("reference must complete");
        };

        let native = compile_mixed_superblock(&plan, 0).expect("direct corridor compiles");
        let frames = [9, 40];
        let calls = [JitMixedSuperblockCallDecision::target(8, 0, 0)];
        let forces = [JitMixedSuperblockForceDecision::claimed(
            9,
            JitMixedSuperblockForceAction::Node,
            1,
            99,
        )];
        let mut updates = [JitMixedSuperblockPublishedUpdate::default()];
        let mut activation =
            JitMixedSuperblockActivation::new(8, 0, &frames, 1, &calls, &forces, &mut updates)
                .expect("activation validates");

        assert_eq!(
            native.run(&mut activation),
            JitMixedSuperblockOutcome::Complete(reference_value)
        );
        assert_eq!(activation.consumed_calls(), 1);
        assert_eq!(activation.consumed_forces(), 1);
        assert_eq!(reference.published, vec![(99, reference_value)]);
        assert_eq!(
            activation.published_updates(),
            &[JitMixedSuperblockPublishedUpdate {
                token: 99,
                value: reference_value,
                published: 1,
                padding: 0,
            }]
        );
        assert_eq!(
            native.run(&mut activation),
            JitMixedSuperblockOutcome::InvalidActivation
        );
        assert_eq!(
            native.resume(&mut activation, None),
            JitMixedSuperblockOutcome::InvalidActivation
        );
    }

    #[test]
    fn generated_guard_decline_returns_the_exact_statepoint() {
        let plan = corridor_plan(41);
        let native = compile_mixed_superblock(&plan, 0).expect("direct corridor compiles");
        let frames = [9, 40];
        let calls = [JitMixedSuperblockCallDecision::declined(8)];
        let mut updates = [JitMixedSuperblockPublishedUpdate::default()];
        let mut activation =
            JitMixedSuperblockActivation::new(8, 0, &frames, 1, &calls, &[], &mut updates)
                .expect("activation validates");

        assert_eq!(
            native.run(&mut activation),
            JitMixedSuperblockOutcome::SideExit(MixedStatepointId::new(0))
        );
        assert!(!native.statepoint_is_resumable(MixedStatepointId::new(0)));
        assert_eq!(
            native.statepoint_live_values(MixedStatepointId::new(0)),
            None
        );
        assert_eq!(
            native.statepoint_result_type(MixedStatepointId::new(0)),
            None
        );
        assert_eq!(
            native.resume(&mut activation, Some(0)),
            JitMixedSuperblockOutcome::InvalidActivation
        );
        assert_eq!(
            native.run(&mut activation),
            JitMixedSuperblockOutcome::InvalidActivation
        );
        assert_eq!(activation.consumed_calls(), 1);
        assert_eq!(activation.consumed_forces(), 0);
        assert!(activation.published_updates().is_empty());
    }

    #[test]
    fn general_statepoint_resume_observes_caller_rewritten_spill() {
        let plan = resumable_move_plan();
        let native = compile_mixed_superblock(&plan, 0).expect("general CFG compiles");
        let mut updates = [];
        let mut value_slots = [u64::MAX; 4];
        let mut activation = JitMixedSuperblockActivation::new_resumable(
            17,
            0,
            &[],
            1,
            &[],
            &[],
            &mut updates,
            &mut value_slots,
        )
        .expect("resumable activation validates");

        assert_eq!(
            native.run(&mut activation),
            JitMixedSuperblockOutcome::SideExit(MixedStatepointId::new(0))
        );
        assert_eq!(
            native.statepoint_live_values(MixedStatepointId::new(0)),
            Some(&[MixedValueId::new(1)][..])
        );
        assert_eq!(activation.live_value_count(), 1);
        let suspended_slots = activation
            .value_slots_mut()
            .expect("resumable activation owns value slots")
            .to_vec();
        assert_eq!(
            native.run(&mut activation),
            JitMixedSuperblockOutcome::InvalidActivation
        );
        assert_eq!(
            activation
                .value_slots_mut()
                .expect("suspended slots remain owned"),
            suspended_slots
        );
        let slots = activation
            .value_slots_mut()
            .expect("resumable activation owns value slots");
        assert_eq!(slots, &[0, 17, 0, 0]);
        slots[1] = 99;

        assert_eq!(
            native.resume(&mut activation, None),
            JitMixedSuperblockOutcome::Complete(99)
        );
        assert_eq!(activation.live_value_count(), 0);
        assert_eq!(
            native.resume(&mut activation, None),
            JitMixedSuperblockOutcome::InvalidActivation
        );
        assert_eq!(
            native.run(&mut activation),
            JitMixedSuperblockOutcome::InvalidActivation
        );
    }

    #[test]
    fn general_resume_executes_branches_and_jumps() {
        let plan = resumable_branch_plan();
        let native = compile_mixed_superblock(&plan, 0).expect("general branch CFG compiles");
        assert_eq!(
            native.statepoint_result_type(MixedStatepointId::new(0)),
            Some(MixedValueType::Bool)
        );
        assert!(native.statepoint_is_resumable(MixedStatepointId::new(0)));

        for (condition, expected) in [(true, 41), (false, 42)] {
            let mut updates = [];
            let mut value_slots = [u64::MAX; 5];
            let mut activation = JitMixedSuperblockActivation::new_resumable(
                0,
                0,
                &[],
                1,
                &[],
                &[],
                &mut updates,
                &mut value_slots,
            )
            .expect("resumable activation validates");
            assert_eq!(
                native.run(&mut activation),
                JitMixedSuperblockOutcome::SideExit(MixedStatepointId::new(0))
            );
            assert_eq!(activation.live_value_count(), 0);
            assert!(
                activation
                    .value_slots_mut()
                    .expect("value slots exist")
                    .iter()
                    .all(|value| *value == 0),
                "no undeclared Value may cross the side exit"
            );
            assert_eq!(
                native.resume(&mut activation, Some(encode_boolean_constant(condition))),
                JitMixedSuperblockOutcome::Complete(
                    encode_integer_constant(expected).expect("fixture integer is representable")
                )
            );
        }
    }

    #[test]
    fn general_resume_rejects_missing_or_unexpected_oracle_results() {
        let no_result_plan = resumable_move_plan();
        let no_result = compile_mixed_superblock(&no_result_plan, 0).expect("move CFG compiles");
        let mut updates = [];
        let mut value_slots = [0; 4];
        let mut activation = JitMixedSuperblockActivation::new_resumable(
            17,
            0,
            &[],
            1,
            &[],
            &[],
            &mut updates,
            &mut value_slots,
        )
        .expect("activation validates");
        assert!(matches!(
            no_result.run(&mut activation),
            JitMixedSuperblockOutcome::SideExit(_)
        ));
        assert_eq!(
            no_result.resume(&mut activation, Some(1)),
            JitMixedSuperblockOutcome::InvalidActivation
        );

        let result_plan = resumable_branch_plan();
        let result = compile_mixed_superblock(&result_plan, 0).expect("branch CFG compiles");
        let mut result_updates = [];
        let mut result_slots = [0; 5];
        let mut result_activation = JitMixedSuperblockActivation::new_resumable(
            0,
            0,
            &[],
            1,
            &[],
            &[],
            &mut result_updates,
            &mut result_slots,
        )
        .expect("activation validates");
        assert!(matches!(
            result.run(&mut result_activation),
            JitMixedSuperblockOutcome::SideExit(_)
        ));
        assert_eq!(
            result.resume(&mut result_activation, None),
            JitMixedSuperblockOutcome::InvalidActivation
        );
    }

    #[test]
    fn general_execution_requires_the_exact_compiled_value_slab() {
        let plan = resumable_move_plan();
        let native = compile_mixed_superblock(&plan, 0).expect("general CFG compiles");

        for mut slots in [vec![0; 3], vec![0; 5]] {
            let slot_count = slots.len();
            let mut updates = [];
            let mut activation = JitMixedSuperblockActivation::new_resumable(
                17,
                0,
                &[],
                1,
                &[],
                &[],
                &mut updates,
                &mut slots,
            )
            .expect("storage geometry itself is valid");
            assert_eq!(
                native.run(&mut activation),
                JitMixedSuperblockOutcome::InvalidActivation
            );
            assert_eq!(
                activation.value_slots_mut().expect("slots remain present"),
                vec![0; slot_count]
            );
        }
    }

    #[test]
    fn malformed_native_side_exit_is_never_wrapped_as_a_statepoint() {
        let plan = resumable_move_plan();
        let native = compile_mixed_superblock(&plan, 0).expect("general CFG compiles");
        let mut updates = [];
        let mut slots = [0; 4];
        let mut activation = JitMixedSuperblockActivation::new_resumable(
            17,
            0,
            &[],
            1,
            &[],
            &[],
            &mut updates,
            &mut slots,
        )
        .expect("activation validates");
        assert!(matches!(
            native.run(&mut activation),
            JitMixedSuperblockOutcome::SideExit(_)
        ));

        activation.raw.resume_statepoint = 1;
        assert_eq!(
            native.resume(&mut activation, None),
            JitMixedSuperblockOutcome::InvalidActivation
        );
        activation.raw.resume_statepoint = 0;
        activation.raw.side_exit = u32::MAX;
        assert_eq!(
            native.outcome_from_status(&mut activation, STATUS_SIDE_EXIT),
            JitMixedSuperblockOutcome::InvalidActivation
        );
        assert_eq!(activation.raw.status, STATUS_INVALID_ACTIVATION);
    }

    #[test]
    fn suspended_activation_rejects_a_different_executable() {
        let first_plan = resumable_move_plan_with_bound_and_key(4, 31);
        let second_plan = resumable_move_plan_with_bound_and_key(4, 41);
        let first = compile_mixed_superblock(&first_plan, 0).expect("first CFG compiles");
        let second = compile_mixed_superblock(&second_plan, 0).expect("second CFG compiles");
        let mut updates = [];
        let mut slots = [0; 4];
        let mut activation = JitMixedSuperblockActivation::new_resumable(
            17,
            0,
            &[],
            1,
            &[],
            &[],
            &mut updates,
            &mut slots,
        )
        .expect("activation validates");

        assert!(matches!(
            first.run(&mut activation),
            JitMixedSuperblockOutcome::SideExit(_)
        ));
        assert_eq!(
            second.resume(&mut activation, None),
            JitMixedSuperblockOutcome::InvalidActivation
        );
        assert_eq!(
            first.resume(&mut activation, None),
            JitMixedSuperblockOutcome::Complete(17)
        );
    }

    #[test]
    fn resumable_metadata_is_scoped_to_the_compiled_entry_function() {
        let plan = multi_function_statepoint_plan();
        let native = compile_mixed_superblock(&plan, 0).expect("selected function compiles");

        assert!(native.statepoint_is_resumable(MixedStatepointId::new(0)));
        assert!(!native.statepoint_is_resumable(MixedStatepointId::new(1)));
        assert_eq!(
            native.statepoint_live_values(MixedStatepointId::new(1)),
            None
        );
    }

    #[test]
    fn general_lowering_rejects_pathological_value_slot_bounds() {
        let plan =
            resumable_move_plan_with_bound_and_key(GENERAL_VALUE_SLOT_CAP.saturating_add(1), 51);
        assert!(matches!(
            compile_mixed_superblock(&plan, 0),
            Err(JitMixedSuperblockCompileError::UnsupportedPlan {
                reason: "general value-slot bound exceeds the generated-code cap"
            })
        ));
        assert!(matches!(
            general_value_slot_offset(MixedValueId::new(u32::MAX)),
            Err(JitMixedSuperblockCompileError::UnsupportedPlan {
                reason: "general value-slot byte offset overflows u32"
            })
        ));
    }

    #[test]
    fn general_resume_can_cross_consecutive_exact_statepoints() {
        let plan = consecutive_statepoint_plan();
        let native = compile_mixed_superblock(&plan, 0).expect("general CFG compiles");
        let mut updates = [];
        let mut slots = [u64::MAX; 4];
        let mut activation = JitMixedSuperblockActivation::new_resumable(
            17,
            0,
            &[],
            1,
            &[],
            &[],
            &mut updates,
            &mut slots,
        )
        .expect("activation validates");

        assert_eq!(
            native.run(&mut activation),
            JitMixedSuperblockOutcome::SideExit(MixedStatepointId::new(0))
        );
        activation.value_slots_mut().expect("slots exist")[1] = 23;
        assert_eq!(
            native.resume(&mut activation, None),
            JitMixedSuperblockOutcome::SideExit(MixedStatepointId::new(1))
        );
        assert_eq!(
            activation.value_slots_mut().expect("slots exist"),
            &[0, 23, 0, 0]
        );
        activation.value_slots_mut().expect("slots exist")[1] = 29;
        assert_eq!(
            native.resume(&mut activation, None),
            JitMixedSuperblockOutcome::Complete(29)
        );
    }

    #[cfg(feature = "candidate_c_value")]
    #[test]
    fn candidate_c_resume_rejects_malformed_and_wrong_typed_words() {
        use ratchet_value::value::compressed::CompressedValueWord;

        let plan = resumable_branch_plan();
        let native = compile_mixed_superblock(&plan, 0).expect("general CFG compiles");
        let mut updates = [];
        let mut slots = [0; 5];
        let mut activation = JitMixedSuperblockActivation::new_resumable(
            0,
            0,
            &[],
            1,
            &[],
            &[],
            &mut updates,
            &mut slots,
        )
        .expect("activation validates");
        assert!(matches!(
            native.run(&mut activation),
            JitMixedSuperblockOutcome::SideExit(_)
        ));

        assert_eq!(
            native.resume(&mut activation, Some((0x02_u64 << 32) | 2)),
            JitMixedSuperblockOutcome::InvalidActivation
        );
        assert_eq!(
            native.resume(
                &mut activation,
                Some(CompressedValueWord::inline_int(1).expect("inline").raw())
            ),
            JitMixedSuperblockOutcome::InvalidActivation
        );
        assert_eq!(
            native.resume(
                &mut activation,
                Some(CompressedValueWord::boolean(true).raw())
            ),
            JitMixedSuperblockOutcome::Complete(
                encode_integer_constant(41).expect("fixture integer is representable")
            )
        );
    }

    #[test]
    fn virtual_resume_results_are_never_accepted_by_the_proving_abi() {
        assert!(!resume_result_matches_type(0, MixedValueType::VirtualThunk));
        assert!(!resume_result_matches_type(
            0,
            MixedValueType::VirtualClosure
        ));
    }

    #[test]
    fn direct_native_corridor_accepts_every_exact_guarded_target() {
        let plan = corridor_plan_with_targets(41, 2);
        let native = compile_mixed_superblock(&plan, 0).expect("polymorphic corridor compiles");
        let frames = [9, 40];
        let calls = [JitMixedSuperblockCallDecision::target(8, 1, 0)];
        let value = encode_integer_constant(55).expect("fixture integer is representable");
        let forces = [JitMixedSuperblockForceDecision::ready(value, value)];
        let mut updates = [JitMixedSuperblockPublishedUpdate::default()];
        let mut activation =
            JitMixedSuperblockActivation::new(8, 0, &frames, 1, &calls, &forces, &mut updates)
                .expect("activation validates");

        assert_eq!(
            native.run(&mut activation),
            JitMixedSuperblockOutcome::Complete(value)
        );
        assert_eq!(activation.consumed_calls(), 1);
        assert_eq!(activation.consumed_forces(), 1);
    }

    #[test]
    fn source_backed_literal_target_runs_through_the_native_corridor() {
        let plan = real_literal_corridor_plan();
        let native = compile_mixed_superblock(&plan, 0).expect("real scalar corridor compiles");
        let frames = [8];
        let calls = [JitMixedSuperblockCallDecision::target(8, 0, 0)];
        let value = encode_integer_constant(42).expect("fixture integer is representable");
        let mut updates = [JitMixedSuperblockPublishedUpdate::default()];
        let mut activation =
            JitMixedSuperblockActivation::new(777, 0, &frames, 1, &calls, &[], &mut updates)
                .expect("activation validates");

        assert_eq!(
            native.run(&mut activation),
            JitMixedSuperblockOutcome::Complete(value)
        );
        assert_eq!(activation.consumed_calls(), 1);
        assert_eq!(activation.consumed_forces(), 0);
    }

    #[test]
    fn artifact_contains_no_calls_or_interpreter_dispatch() {
        let artifact =
            lower_mixed_superblock(&corridor_plan(41), 0).expect("direct corridor lowers");
        assert!(
            artifact
                .function()
                .layout
                .blocks()
                .flat_map(|block| artifact.function().layout.block_insts(block))
                .all(|inst| artifact.function().dfg.insts[inst].opcode() != Opcode::Call)
        );
    }

    #[test]
    fn canonical_cache_key_distinguishes_plan_bytes() {
        let first = lower_mixed_superblock(&corridor_plan(41), 0).expect("first corridor lowers");
        let second = lower_mixed_superblock(&corridor_plan(42), 0).expect("second corridor lowers");
        assert_ne!(first.cache_key(), second.cache_key());
        assert_eq!(
            first.cache_key().backend_version(),
            MIXED_SUPERBLOCK_BACKEND_VERSION
        );
    }

    #[test]
    #[ignore = "PMU probe; run explicitly on a pinned Linux performance host"]
    fn pmu_callback_free_mixed_superblock_corridor() {
        let iterations = superblock_probe_iterations();
        let native =
            compile_mixed_superblock(&corridor_plan(41), 0).expect("direct corridor compiles");
        let frames = [9, EXPECTED_PROBE_VALUE];
        let calls = [JitMixedSuperblockCallDecision::target(8, 0, 0)];
        let forces = [JitMixedSuperblockForceDecision::claimed(
            9,
            JitMixedSuperblockForceAction::Node,
            1,
            EXPECTED_PROBE_TOKEN,
        )];
        let mut updates = [JitMixedSuperblockPublishedUpdate::default()];
        let mut activation =
            JitMixedSuperblockActivation::new(8, 0, &frames, 1, &calls, &forces, &mut updates)
                .expect("activation validates");
        let mut checksum = 0;

        for iteration in 0..iterations {
            reset_probe_activation(&mut activation);
            let outcome = black_box(native.run(black_box(&mut activation)));
            let JitMixedSuperblockOutcome::Complete(value) = outcome else {
                panic!("native PMU probe must complete");
            };
            let [update] = activation.published_updates() else {
                panic!("native PMU probe must publish exactly one update");
            };
            assert_eq!(value, EXPECTED_PROBE_VALUE);
            assert_eq!(update.token(), EXPECTED_PROBE_TOKEN);
            assert_eq!(update.value(), EXPECTED_PROBE_VALUE);
            assert!(update.is_published());
            checksum = probe_checksum(checksum, iteration, value, update.token());
        }

        black_box(checksum);
        eprintln!(
            "aos_mixed_superblock_pmu_probe iterations={iterations} checksum={checksum:#018x}"
        );
    }

    #[test]
    #[ignore = "PMU baseline; run explicitly on a pinned Linux performance host"]
    fn pmu_mixed_superblock_activation_reset_checksum_baseline() {
        let iterations = superblock_probe_iterations();
        let frames = [9, EXPECTED_PROBE_VALUE];
        let calls = [JitMixedSuperblockCallDecision::target(8, 0, 0)];
        let forces = [JitMixedSuperblockForceDecision::claimed(
            9,
            JitMixedSuperblockForceAction::Node,
            1,
            EXPECTED_PROBE_TOKEN,
        )];
        let mut updates = [JitMixedSuperblockPublishedUpdate::default()];
        let mut activation =
            JitMixedSuperblockActivation::new(8, 0, &frames, 1, &calls, &forces, &mut updates)
                .expect("activation validates");
        let mut checksum = 0;

        for iteration in 0..iterations {
            reset_probe_activation(black_box(&mut activation));
            black_box(&activation.raw);
            let value = black_box(EXPECTED_PROBE_VALUE);
            let token = black_box(EXPECTED_PROBE_TOKEN);
            assert_eq!(value, EXPECTED_PROBE_VALUE);
            assert_eq!(token, EXPECTED_PROBE_TOKEN);
            checksum = probe_checksum(checksum, iteration, value, token);
        }

        black_box(checksum);
        eprintln!(
            "aos_mixed_superblock_pmu_baseline iterations={iterations} checksum={checksum:#018x}"
        );
    }

    fn superblock_probe_iterations() -> u64 {
        std::env::var("AOS_MIXED_SUPERBLOCK_PROBE_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|iterations| *iterations != 0)
            .unwrap_or(DEFAULT_SUPERBLOCK_PROBE_ITERATIONS)
    }

    fn reset_probe_activation(activation: &mut JitMixedSuperblockActivation<'_>) {
        activation.raw.call_cursor = 0;
        activation.raw.force_cursor = 0;
        activation.raw.published_updates = 0;
        activation.raw.status = 0;
        activation.raw.side_exit = u32::MAX;
        activation.raw.result = 0;
        activation.raw.executable_token = 0;
    }

    fn probe_checksum(checksum: u64, iteration: u64, value: u64, token: u64) -> u64 {
        black_box(
            checksum.rotate_left(9)
                ^ iteration.wrapping_mul(0x9e37_79b9_7f4a_7c15)
                ^ value.rotate_left(17)
                ^ token,
        )
    }

    fn source(id: u32) -> MixedSource {
        MixedSource::new([3; 32], IrId::new(id), Span::new(id, id + 1))
    }

    fn code(id: u32) -> MixedCodeIdentity {
        MixedCodeIdentity::new(
            [3; 32],
            IrId::new(id),
            IrId::new(id + 1),
            Some(FrameId::new(id)),
            [id as u8; 32],
        )
    }

    fn lowered(source: &str) -> Ir {
        lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
            .expect("IR lowers")
    }

    fn real_literal_corridor_plan() -> MixedModulePlan {
        let entry_ir = lowered("f: f 1");
        let entry_lambda = *entry_ir.arena.node(entry_ir.root).expect("lambda exists");
        let IrData::Lambda {
            body: entry_body, ..
        } = entry_lambda.data
        else {
            panic!("lambda payload expected");
        };
        let MixedOracleNodeLowerOutcome::Lowered(entry) = lower_mixed_oracle_node(
            &entry_ir,
            StgModuleId::new(7),
            [7; 32],
            entry_ir.root,
            entry_body,
            [9; 32],
        )
        .expect("entry lowering succeeds") else {
            panic!("real application entry must lower");
        };

        let target_ir = lowered("x: 42");
        let target_lambda = *target_ir.arena.node(target_ir.root).expect("lambda exists");
        let IrData::Lambda {
            body: target_body,
            frame: target_frame,
            ..
        } = target_lambda.data
        else {
            panic!("lambda payload expected");
        };
        let target_key = StgCodeKey::new(StgModuleId::new(8), target_body, target_frame);
        let StgLowerOutcome::Lowered(target_code) =
            lower_stg_code_block(&target_ir, target_key).expect("target lowering succeeds")
        else {
            panic!("literal target must lower");
        };
        let target = MixedOracleCallTargetBlock::new(
            MixedCodeIdentity::new([8; 32], target_ir.root, target_body, target_frame, [5; 32]),
            target_code,
        );
        let MixedOraclePlanLowerOutcome::Lowered(plan) = lower_mixed_oracle_ready_call_plan(
            MixedModuleKey::new([7; 32], [6; 32], 1),
            MixedPlanBounds::new(16, 1, 1),
            &entry,
            &[target],
        )
        .expect("real corridor translation succeeds") else {
            panic!("real corridor must lower");
        };
        plan
    }

    fn resumable_move_plan() -> MixedModulePlan {
        resumable_move_plan_with_bound_and_key(4, 31)
    }

    fn resumable_move_plan_with_bound_and_key(value_slots: u32, key_byte: u8) -> MixedModulePlan {
        MixedModulePlan::new(
            MixedModuleKey::new([key_byte; 32], [key_byte.wrapping_add(1); 32], 1),
            MixedPlanBounds::new(value_slots, 1, 1),
            vec![MixedEntry {
                kind: MixedEntryKind::ForceWhnf,
                source: source(100),
                function: MixedFunctionId::new(0),
                frame: None,
                capture_layout_digest: [0; 32],
            }],
            vec![MixedFunction {
                source: source(100),
                parameter: MixedValueId::new(0),
                parameter_type: MixedValueType::Value,
                return_type: MixedValueType::Value,
                entry: MixedBlockId::new(0),
                blocks: MixedTableRange::new(0, 2),
            }],
            vec![
                MixedBlock {
                    source: source(100),
                    operations: MixedTableRange::new(0, 1),
                    terminator: MixedTerminator::Materialize {
                        statepoint: MixedStatepointId::new(0),
                    },
                },
                MixedBlock {
                    source: source(101),
                    operations: MixedTableRange::new(1, 0),
                    terminator: MixedTerminator::Return {
                        value: MixedValueId::new(1),
                    },
                },
            ],
            vec![MixedOp::Move {
                destination: MixedValueId::new(1),
                source: MixedValueId::new(0),
            }],
            vec![],
            vec![MixedStatepoint {
                source: source(102),
                resume: MixedBlockId::new(1),
                live_values: Box::new([MixedValueId::new(1)]),
                live_virtuals: Box::new([]),
                result: None,
                result_type: None,
                mode: MixedStatepointMode::Resume,
                reason: MixedStatepointReason::Unsupported,
            }],
        )
        .expect("resumable move fixture validates")
    }

    fn consecutive_statepoint_plan() -> MixedModulePlan {
        MixedModulePlan::new(
            MixedModuleKey::new([35; 32], [36; 32], 1),
            MixedPlanBounds::new(4, 1, 1),
            vec![MixedEntry {
                kind: MixedEntryKind::ForceWhnf,
                source: source(120),
                function: MixedFunctionId::new(0),
                frame: None,
                capture_layout_digest: [0; 32],
            }],
            vec![MixedFunction {
                source: source(120),
                parameter: MixedValueId::new(0),
                parameter_type: MixedValueType::Value,
                return_type: MixedValueType::Value,
                entry: MixedBlockId::new(0),
                blocks: MixedTableRange::new(0, 3),
            }],
            vec![
                MixedBlock {
                    source: source(120),
                    operations: MixedTableRange::new(0, 1),
                    terminator: MixedTerminator::Materialize {
                        statepoint: MixedStatepointId::new(0),
                    },
                },
                MixedBlock {
                    source: source(121),
                    operations: MixedTableRange::new(1, 0),
                    terminator: MixedTerminator::Materialize {
                        statepoint: MixedStatepointId::new(1),
                    },
                },
                MixedBlock {
                    source: source(122),
                    operations: MixedTableRange::new(1, 0),
                    terminator: MixedTerminator::Return {
                        value: MixedValueId::new(1),
                    },
                },
            ],
            vec![MixedOp::Move {
                destination: MixedValueId::new(1),
                source: MixedValueId::new(0),
            }],
            vec![],
            vec![
                MixedStatepoint {
                    source: source(123),
                    resume: MixedBlockId::new(1),
                    live_values: Box::new([MixedValueId::new(1)]),
                    live_virtuals: Box::new([]),
                    result: None,
                    result_type: None,
                    mode: MixedStatepointMode::Resume,
                    reason: MixedStatepointReason::Unsupported,
                },
                MixedStatepoint {
                    source: source(124),
                    resume: MixedBlockId::new(2),
                    live_values: Box::new([MixedValueId::new(1)]),
                    live_virtuals: Box::new([]),
                    result: None,
                    result_type: None,
                    mode: MixedStatepointMode::Resume,
                    reason: MixedStatepointReason::Unsupported,
                },
            ],
        )
        .expect("consecutive statepoint fixture validates")
    }

    fn multi_function_statepoint_plan() -> MixedModulePlan {
        MixedModulePlan::new(
            MixedModuleKey::new([61; 32], [62; 32], 1),
            MixedPlanBounds::new(4, 1, 1),
            vec![MixedEntry {
                kind: MixedEntryKind::ForceWhnf,
                source: source(130),
                function: MixedFunctionId::new(0),
                frame: None,
                capture_layout_digest: [0; 32],
            }],
            vec![
                MixedFunction {
                    source: source(130),
                    parameter: MixedValueId::new(0),
                    parameter_type: MixedValueType::Value,
                    return_type: MixedValueType::Value,
                    entry: MixedBlockId::new(0),
                    blocks: MixedTableRange::new(0, 2),
                },
                MixedFunction {
                    source: source(132),
                    parameter: MixedValueId::new(2),
                    parameter_type: MixedValueType::Value,
                    return_type: MixedValueType::Value,
                    entry: MixedBlockId::new(2),
                    blocks: MixedTableRange::new(2, 2),
                },
            ],
            vec![
                MixedBlock {
                    source: source(130),
                    operations: MixedTableRange::new(0, 0),
                    terminator: MixedTerminator::ApplyGuarded {
                        function: MixedValueId::new(0),
                        argument: MixedValueId::new(0),
                        result: MixedValueId::new(1),
                        targets: MixedTableRange::new(0, 1),
                        continuation: MixedBlockId::new(1),
                        fallback: MixedStatepointId::new(0),
                    },
                },
                MixedBlock {
                    source: source(131),
                    operations: MixedTableRange::new(0, 0),
                    terminator: MixedTerminator::Return {
                        value: MixedValueId::new(1),
                    },
                },
                MixedBlock {
                    source: source(132),
                    operations: MixedTableRange::new(0, 0),
                    terminator: MixedTerminator::Materialize {
                        statepoint: MixedStatepointId::new(1),
                    },
                },
                MixedBlock {
                    source: source(133),
                    operations: MixedTableRange::new(0, 0),
                    terminator: MixedTerminator::Return {
                        value: MixedValueId::new(2),
                    },
                },
            ],
            vec![],
            vec![MixedCallTarget {
                code: code(136),
                function: MixedFunctionId::new(1),
                argument_destination: MixedValueId::new(2),
            }],
            vec![
                MixedStatepoint {
                    source: source(134),
                    resume: MixedBlockId::new(1),
                    live_values: Box::new([]),
                    live_virtuals: Box::new([]),
                    result: Some(MixedValueId::new(1)),
                    result_type: Some(MixedValueType::Value),
                    mode: MixedStatepointMode::Resume,
                    reason: MixedStatepointReason::Unsupported,
                },
                MixedStatepoint {
                    source: source(135),
                    resume: MixedBlockId::new(3),
                    live_values: Box::new([MixedValueId::new(2)]),
                    live_virtuals: Box::new([]),
                    result: None,
                    result_type: None,
                    mode: MixedStatepointMode::Resume,
                    reason: MixedStatepointReason::Unsupported,
                },
            ],
        )
        .expect("multi-function statepoint fixture validates")
    }

    fn resumable_branch_plan() -> MixedModulePlan {
        MixedModulePlan::new(
            MixedModuleKey::new([33; 32], [34; 32], 1),
            MixedPlanBounds::new(5, 1, 1),
            vec![MixedEntry {
                kind: MixedEntryKind::ForceWhnf,
                source: source(110),
                function: MixedFunctionId::new(0),
                frame: None,
                capture_layout_digest: [0; 32],
            }],
            vec![MixedFunction {
                source: source(110),
                parameter: MixedValueId::new(0),
                parameter_type: MixedValueType::Value,
                return_type: MixedValueType::Value,
                entry: MixedBlockId::new(0),
                blocks: MixedTableRange::new(0, 6),
            }],
            vec![
                MixedBlock {
                    source: source(110),
                    operations: MixedTableRange::new(0, 0),
                    terminator: MixedTerminator::Materialize {
                        statepoint: MixedStatepointId::new(0),
                    },
                },
                MixedBlock {
                    source: source(111),
                    operations: MixedTableRange::new(0, 0),
                    terminator: MixedTerminator::Branch {
                        condition: MixedValueId::new(1),
                        when_true: MixedBlockId::new(2),
                        when_false: MixedBlockId::new(3),
                    },
                },
                MixedBlock {
                    source: source(112),
                    operations: MixedTableRange::new(0, 1),
                    terminator: MixedTerminator::Jump {
                        target: MixedBlockId::new(4),
                    },
                },
                MixedBlock {
                    source: source(113),
                    operations: MixedTableRange::new(1, 1),
                    terminator: MixedTerminator::Jump {
                        target: MixedBlockId::new(5),
                    },
                },
                MixedBlock {
                    source: source(114),
                    operations: MixedTableRange::new(2, 0),
                    terminator: MixedTerminator::Return {
                        value: MixedValueId::new(2),
                    },
                },
                MixedBlock {
                    source: source(115),
                    operations: MixedTableRange::new(2, 0),
                    terminator: MixedTerminator::Return {
                        value: MixedValueId::new(3),
                    },
                },
            ],
            vec![
                MixedOp::ConstInt {
                    destination: MixedValueId::new(2),
                    value: 41,
                },
                MixedOp::ConstInt {
                    destination: MixedValueId::new(3),
                    value: 42,
                },
            ],
            vec![],
            vec![MixedStatepoint {
                source: source(116),
                resume: MixedBlockId::new(1),
                live_values: Box::new([]),
                live_virtuals: Box::new([]),
                result: Some(MixedValueId::new(1)),
                result_type: Some(MixedValueType::Bool),
                mode: MixedStatepointMode::Resume,
                reason: MixedStatepointReason::Unsupported,
            }],
        )
        .expect("resumable branch fixture validates")
    }

    fn corridor_plan(apply_value: i64) -> MixedModulePlan {
        corridor_plan_with_targets(apply_value, 1)
    }

    fn corridor_plan_with_targets(apply_value: i64, target_count: u32) -> MixedModulePlan {
        let mut functions = vec![MixedFunction {
            source: source(0),
            parameter: MixedValueId::new(0),
            parameter_type: MixedValueType::Value,
            return_type: MixedValueType::Value,
            entry: MixedBlockId::new(0),
            blocks: MixedTableRange::new(0, 6),
        }];
        let mut target_blocks = Vec::with_capacity(target_count as usize);
        let mut call_targets = Vec::with_capacity(target_count as usize);
        let mut operations = vec![
            MixedOp::LoadLocal {
                destination: MixedValueId::new(1),
                slot: 0,
            },
            MixedOp::LoadLocal {
                destination: MixedValueId::new(4),
                slot: 0,
            },
            MixedOp::ConstInt {
                destination: MixedValueId::new(5),
                value: apply_value,
            },
            MixedOp::ConstInt {
                destination: MixedValueId::new(6),
                value: 42,
            },
        ];
        for target in 0..target_count {
            let parameter = MixedValueId::new(7 + target);
            let block = MixedBlockId::new(6 + target);
            functions.push(MixedFunction {
                source: source(10 + target),
                parameter,
                parameter_type: MixedValueType::Value,
                return_type: MixedValueType::Value,
                entry: block,
                blocks: MixedTableRange::new(block.as_u32(), 1),
            });
            let (operation_range, return_value) = if target == 0 {
                (MixedTableRange::new(operations.len() as u32, 0), parameter)
            } else {
                let destination = MixedValueId::new(7 + target_count + target - 1);
                let start = operations.len() as u32;
                operations.push(MixedOp::ConstInt {
                    destination,
                    value: 55,
                });
                (MixedTableRange::new(start, 1), destination)
            };
            target_blocks.push(MixedBlock {
                source: source(10 + target),
                operations: operation_range,
                terminator: MixedTerminator::Return {
                    value: return_value,
                },
            });
            call_targets.push(MixedCallTarget {
                code: code(8 + target),
                function: MixedFunctionId::new(1 + target),
                argument_destination: parameter,
            });
        }
        let mut blocks = vec![
            MixedBlock {
                source: source(0),
                operations: MixedTableRange::new(0, 1),
                terminator: MixedTerminator::ApplyGuarded {
                    function: MixedValueId::new(0),
                    argument: MixedValueId::new(1),
                    result: MixedValueId::new(2),
                    targets: MixedTableRange::new(0, target_count),
                    continuation: MixedBlockId::new(1),
                    fallback: MixedStatepointId::new(0),
                },
            },
            MixedBlock {
                source: source(1),
                operations: MixedTableRange::new(1, 0),
                terminator: MixedTerminator::Force {
                    subject: MixedValueId::new(2),
                    result: MixedValueId::new(3),
                    result_type: MixedValueType::Value,
                    guards: MixedForceGuards::new(code(30), code(31), code(32)),
                    ready: MixedBlockId::new(2),
                    node: MixedBlockId::new(3),
                    apply: MixedBlockId::new(4),
                    gen_list: MixedBlockId::new(5),
                    fallback: MixedStatepointId::new(1),
                },
            },
            MixedBlock {
                source: source(2),
                operations: MixedTableRange::new(1, 0),
                terminator: MixedTerminator::Return {
                    value: MixedValueId::new(3),
                },
            },
            claimed_block(3, 1, 1, MixedValueId::new(4)),
            claimed_block(4, 2, 1, MixedValueId::new(5)),
            claimed_block(5, 3, 1, MixedValueId::new(6)),
        ];
        blocks.extend(target_blocks);
        MixedModulePlan::new(
            MixedModuleKey::new([3; 32], [4; 32], 1),
            MixedPlanBounds::new(7 + target_count.saturating_mul(2), 2, 2),
            vec![MixedEntry {
                kind: MixedEntryKind::ForceWhnf,
                source: source(0),
                function: MixedFunctionId::new(0),
                frame: None,
                capture_layout_digest: [0; 32],
            }],
            functions,
            blocks,
            operations,
            call_targets,
            vec![
                statepoint(20, 1, 2, MixedStatepointReason::UnknownCall),
                statepoint(21, 2, 3, MixedStatepointReason::UnsupportedForce),
            ],
        )
        .expect("corridor fixture validates")
    }

    fn claimed_block(
        source_id: u32,
        operation_start: u32,
        operation_len: u32,
        value: MixedValueId,
    ) -> MixedBlock {
        MixedBlock {
            source: source(source_id),
            operations: MixedTableRange::new(operation_start, operation_len),
            terminator: MixedTerminator::Update {
                value,
                result: MixedValueId::new(3),
                next: MixedBlockId::new(2),
            },
        }
    }

    fn statepoint(
        source_id: u32,
        resume: u32,
        result: u32,
        reason: MixedStatepointReason,
    ) -> MixedStatepoint {
        let live_values: Box<[MixedValueId]> = match result {
            2 => Box::new([MixedValueId::new(0), MixedValueId::new(1)]),
            3 => Box::new([MixedValueId::new(2)]),
            _ => Box::new([]),
        };
        MixedStatepoint {
            source: source(source_id),
            resume: MixedBlockId::new(resume),
            live_values,
            live_virtuals: Box::new([]),
            result: Some(MixedValueId::new(result)),
            result_type: Some(MixedValueType::Value),
            mode: MixedStatepointMode::Resume,
            reason,
        }
    }
}
