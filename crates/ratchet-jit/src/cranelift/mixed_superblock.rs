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
    MixedStatepointId, MixedTerminator, MixedValueId,
};
use thiserror::Error;

use super::{JitCraneliftModuleSetupError, module_setup::native_jit_builder};

macro_rules! field_offset {
    ($container:ty, $field:ident) => {
        offset_of!($container, $field) as i32
    };
}

const MIXED_SUPERBLOCK_BACKEND_VERSION: u32 = 1;
const MIXED_SUPERBLOCK_FUNCTION_NAMESPACE: u32 = 12;
const MIXED_SUPERBLOCK_SYMBOL: &str = "aos.mixed.superblock.v1";
const DECLINED_TARGET: u32 = u32::MAX;

const STATUS_COMPLETE: u32 = 1;
const STATUS_SIDE_EXIT: u32 = 2;
const STATUS_INVALID_ACTIVATION: u32 = 3;

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
}

/// Validated caller-owned storage for one native superblock activation.
pub struct JitMixedSuperblockActivation<'storage> {
    raw: RawActivation,
    updates: &'storage mut [JitMixedSuperblockPublishedUpdate],
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
        let update_pointer = updates.as_mut_ptr();
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
            },
            updates,
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
    /// Executable module construction or finalization failed.
    #[error(transparent)]
    Module(#[from] JitCraneliftModuleSetupError),
}

/// One finalized direct superblock and its owning executable module.
pub struct JitMixedSuperblockExecutable {
    artifact: JitMixedSuperblockCacheKey,
    module: JITModule,
    code: NonNull<u8>,
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
        type Entry = unsafe extern "C" fn(*mut RawActivation) -> u32;
        // SAFETY: `compile_mixed_superblock` finalized `code` from the exact
        // signature used below, `module` keeps its executable allocation live,
        // and the activation wrapper keeps every embedded buffer live.
        let entry = unsafe { mem::transmute::<*mut u8, Entry>(self.code.as_ptr()) };
        // SAFETY: The activation's private raw record satisfies the generated
        // pointer, length, alignment, and mutability contract.
        let status = unsafe { entry(&mut activation.raw) };
        match status {
            STATUS_COMPLETE => JitMixedSuperblockOutcome::Complete(activation.raw.result),
            STATUS_SIDE_EXIT => JitMixedSuperblockOutcome::SideExit(MixedStatepointId::new(
                activation.raw.side_exit,
            )),
            _ => JitMixedSuperblockOutcome::InvalidActivation,
        }
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
    Ok(JitMixedSuperblockExecutable {
        artifact: cache_key,
        module,
        code,
    })
}

#[derive(Clone, Copy)]
enum ClaimedResult {
    FrameLocal(u32),
    Constant(u64),
}

#[derive(Clone, Copy)]
struct AdmittedCorridor {
    entry_local: u32,
    call_fallback: MixedStatepointId,
    force_fallback: MixedStatepointId,
    node: ClaimedResult,
    apply: ClaimedResult,
    gen_list: ClaimedResult,
}

fn lower_mixed_superblock(
    plan: &MixedModulePlan,
    entry: usize,
) -> Result<JitMixedSuperblockArtifact, JitMixedSuperblockCompileError> {
    let corridor = admit_corridor(plan, entry)?;
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
    let (callable, argument) = {
        let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(call_ready);
        let callable = load_i64(
            &mut cursor,
            activation,
            field_offset!(RawActivation, argument),
        );
        let entry_frame = load_i32(
            &mut cursor,
            activation,
            field_offset!(RawActivation, entry_frame),
        );
        let argument = emit_frame_load(
            &mut cursor,
            activation,
            entry_frame,
            corridor.entry_local,
            invalid,
        );
        let Some(argument) = argument else {
            unreachable!("frame load always emits a continuation");
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
        let exact_target = cursor.ins().icmp_imm(IntCC::Equal, ordinal, 0);
        let call_declined = cursor.func.dfg.make_block();
        cursor
            .ins()
            .brif(exact_target, force_ready, &[], call_declined, &[]);
        cursor.func.layout.append_block(call_declined);
        cursor.set_position(CursorPosition::After(call_declined));
        let declined = cursor
            .ins()
            .icmp_imm(IntCC::Equal, ordinal, i64::from(DECLINED_TARGET));
        let fallback = cursor
            .ins()
            .iconst(types::I32, i64::from(corridor.call_fallback.as_u32()));
        cursor
            .ins()
            .brif(declined, side_exit, &[fallback.into()], invalid, &[]);
        (callable, argument)
    };
    let _ = callable;

    function.layout.append_block(force_ready);
    {
        let mut cursor = FuncCursor::new(&mut function).at_first_insertion_point(force_ready);
        let decision = emit_next_force_decision(&mut cursor, activation, invalid);
        let Some(decision) = decision else {
            unreachable!("decision load always emits a continuation");
        };
        let observed = load_i64(
            &mut cursor,
            decision,
            field_offset!(JitMixedSuperblockForceDecision, subject),
        );
        let same_subject = cursor.ins().icmp(IntCC::Equal, observed, argument);
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
            corridor.force_fallback,
        );
    }

    append_claimed_block(
        &mut function,
        force_node,
        activation,
        corridor.node,
        complete,
        invalid,
    );
    append_claimed_block(
        &mut function,
        force_apply,
        activation,
        corridor.apply,
        complete,
        invalid,
    );
    append_claimed_block(
        &mut function,
        force_gen_list,
        activation,
        corridor.gen_list,
        complete,
        invalid,
    );

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
    })
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
    if plan.bounds().update_depth == 0 {
        return unsupported("plan reserves no update record");
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
    let [
        MixedOp::LoadLocal {
            destination: argument,
            slot: entry_local,
        },
    ] = apply_operations
    else {
        return unsupported("entry block is not one direct local load");
    };
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
    if *callable != entry_function.parameter || apply_argument != argument || targets.len() != 1 {
        return unsupported("guarded application is not the one-target entry shape");
    }
    let target_index = targets.start() as usize;
    let target = plan
        .call_targets()
        .get(target_index)
        .ok_or_else(|| unsupported_error("guarded target is absent"))?;
    let callee = function(plan, target.function)?;
    if target.argument_destination != callee.parameter {
        return unsupported("callee argument mapping is not direct");
    }
    let callee_block = block(plan, callee.entry)?;
    if !operations(plan, callee_block)?.is_empty()
        || !matches!(
            callee_block.terminator,
            MixedTerminator::Return { value } if value == callee.parameter
        )
    {
        return unsupported("guarded callee is not a direct parameter return");
    }
    let force_block = block(plan, *continuation)?;
    if !operations(plan, force_block)?.is_empty() {
        return unsupported("force continuation contains pure operations");
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
        return unsupported("guarded continuation does not end in Force");
    };
    if subject != call_result {
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
    Ok(AdmittedCorridor {
        entry_local: *entry_local,
        call_fallback: *call_fallback,
        force_fallback: *force_fallback,
        node: admit_claimed_result(plan, *node, *force_result, *ready)?,
        apply: admit_claimed_result(plan, *apply, *force_result, *ready)?,
        gen_list: admit_claimed_result(plan, *gen_list, *force_result, *ready)?,
    })
}

fn admit_claimed_result(
    plan: &MixedModulePlan,
    block_id: MixedBlockId,
    force_result: MixedValueId,
    ready: MixedBlockId,
) -> Result<ClaimedResult, JitMixedSuperblockCompileError> {
    let block = block(plan, block_id)?;
    let value = match operations(plan, block)? {
        [MixedOp::LoadLocal { destination, slot }] => {
            (*destination, ClaimedResult::FrameLocal(*slot))
        }
        [MixedOp::ConstInt { destination, value }] => {
            (*destination, ClaimedResult::Constant(*value as u64))
        }
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
        FrameId, IrId,
        mixed_machine::{
            MixedBlock, MixedCallTarget, MixedCallable, MixedCodeIdentity, MixedEntry,
            MixedExecutablePlan, MixedExecutionOutcome, MixedExecutionRunner, MixedForceAction,
            MixedForceGuards, MixedForceShape, MixedFunction, MixedMachineRuntime, MixedPlanBounds,
            MixedSource, MixedStatepoint, MixedStatepointMode, MixedStatepointReason,
            MixedTableRange, MixedValueType,
        },
        syntax::Span,
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
        assert_eq!(activation.consumed_calls(), 1);
        assert_eq!(activation.consumed_forces(), 0);
        assert!(activation.published_updates().is_empty());
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

    fn corridor_plan(apply_value: i64) -> MixedModulePlan {
        MixedModulePlan::new(
            MixedModuleKey::new([3; 32], [4; 32], 1),
            MixedPlanBounds::new(8, 2, 2),
            vec![MixedEntry {
                kind: MixedEntryKind::ForceWhnf,
                source: source(0),
                function: MixedFunctionId::new(0),
                frame: None,
                capture_layout_digest: [0; 32],
            }],
            vec![
                MixedFunction {
                    source: source(0),
                    parameter: MixedValueId::new(0),
                    parameter_type: MixedValueType::Value,
                    return_type: MixedValueType::Value,
                    entry: MixedBlockId::new(0),
                    blocks: MixedTableRange::new(0, 6),
                },
                MixedFunction {
                    source: source(10),
                    parameter: MixedValueId::new(7),
                    parameter_type: MixedValueType::Value,
                    return_type: MixedValueType::Value,
                    entry: MixedBlockId::new(6),
                    blocks: MixedTableRange::new(6, 1),
                },
            ],
            vec![
                MixedBlock {
                    source: source(0),
                    operations: MixedTableRange::new(0, 1),
                    terminator: MixedTerminator::ApplyGuarded {
                        function: MixedValueId::new(0),
                        argument: MixedValueId::new(1),
                        result: MixedValueId::new(2),
                        targets: MixedTableRange::new(0, 1),
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
                MixedBlock {
                    source: source(10),
                    operations: MixedTableRange::new(4, 0),
                    terminator: MixedTerminator::Return {
                        value: MixedValueId::new(7),
                    },
                },
            ],
            vec![
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
            ],
            vec![MixedCallTarget {
                code: code(8),
                function: MixedFunctionId::new(1),
                argument_destination: MixedValueId::new(7),
            }],
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
