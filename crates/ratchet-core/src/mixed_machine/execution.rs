//! Narrow executable backend for validated mixed-machine plans.
//!
//! Version 2 plans describe typed control flow, but deliberately do not own
//! evaluator force leases, lexical frames, or callable inspection. This module
//! makes that backend boundary explicit through [`MixedMachineRuntime`].
//! Execution is admitted only when every transition can complete without
//! allocating a Promise or closure record inside the runner. Virtual object
//! operations and generic materialization remain rejected until the plan
//! format carries complete materialization recipes.

use std::error::Error;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use thiserror::Error;

use super::{
    MixedBlockId, MixedCallTarget, MixedCodeIdentity, MixedForceGuards, MixedForceShape,
    MixedFunctionId, MixedModulePlan, MixedOp, MixedStatepoint, MixedStatepointId,
    MixedStatepointMode, MixedTerminator, MixedValueId,
};

/// A pre-claim force decision supplied by the evaluator backend.
#[derive(Debug)]
pub enum MixedForceAction<Value, Frame, ForceTarget, UpdateToken> {
    /// The subject was already in weak head normal form.
    Ready(Value),
    /// The backend atomically claimed supported work for fused execution.
    Claimed {
        /// Exact runtime thunk identity that owns the transferred claim.
        target: ForceTarget,
        /// Runtime thunk family selecting the statically validated successor.
        shape: MixedForceShape,
        /// Exact runtime-observed work identity selected before the claim.
        work: MixedCodeIdentity,
        /// Lexical or synthetic payload frame installed while evaluating work.
        frame: Frame,
        /// Owned update token published by the matching update transition.
        update: UpdateToken,
    },
    /// The backend declined before making an observable force-state change.
    Declined,
}

/// Runtime callable information used by an exact guarded application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixedCallable<Frame> {
    /// A materialized closure with an exact code and capture-layout identity.
    Materialized {
        /// Runtime-observed closure identity.
        code: MixedCodeIdentity,
        /// Captured lexical frame installed for the direct call.
        frame: Frame,
    },
    /// An allocation-free virtual closure already naming its plan function.
    ///
    /// Executable v3 admission currently rejects producers of this variant,
    /// but the variant fixes the guarded-call ABI without pretending that a
    /// virtual closure has a materialized [`MixedCodeIdentity`].
    Virtual {
        /// Direct plan function represented by the virtual closure.
        function: MixedFunctionId,
        /// Captured virtual lexical frame.
        frame: Frame,
    },
    /// The value is not an admitted exact unary closure.
    Declined,
}

/// Evaluator operations required by the narrow mixed-machine executor.
///
/// Force and callable methods are runtime inspection/ownership operations,
/// not semantic callbacks: successful claims transfer an update token and a
/// frame to the runner, which then executes the plan's blocks directly.
///
/// `Value` and `Frame` must remain valid across every backend call. An adapter
/// backed by relocatable pointers must either use stable handles or admit this
/// executor only while moving collection is disabled. The current API does not
/// claim to be a moving-GC root-registration contract.
pub trait MixedMachineRuntime {
    /// Encoded or decoded value stored in the fixed activation slab.
    type Value: Copy;
    /// Runtime or virtual lexical-frame handle.
    type Frame: Copy;
    /// Stable identity of the exact thunk cell owning a claimed force.
    ///
    /// This handle is carried unchanged from claim through publication or
    /// abort. A moving-heap adapter must therefore use a stable handle or
    /// update it through its own root protocol before the runner resumes.
    type ForceTarget;
    /// Owned force-update token.
    type UpdateToken;
    /// Backend failure.
    type Error: Error + 'static;

    /// Constructs an integer value.
    ///
    /// # Errors
    ///
    /// Returns an error when the runtime cannot represent the integer.
    fn integer(&mut self, value: i64) -> Result<Self::Value, Self::Error>;

    /// Constructs a Boolean value.
    fn boolean(&mut self, value: bool) -> Self::Value;

    /// Constructs the null value.
    fn null(&mut self) -> Self::Value;

    /// Copies one local from the currently installed lexical frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame or local slot is invalid.
    fn load_local(&mut self, frame: Self::Frame, slot: u32) -> Result<Self::Value, Self::Error>;

    /// Copies one local from an enclosing lexical frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame chain, depth, or local slot is invalid.
    fn load_upvalue(
        &mut self,
        frame: Self::Frame,
        depth: u32,
        slot: u32,
    ) -> Result<Self::Value, Self::Error>;

    /// Adds two values proven statically to be decoded integers.
    ///
    /// # Errors
    ///
    /// Returns an error if runtime representation checks or arithmetic fail.
    fn add_integer(
        &mut self,
        left: Self::Value,
        right: Self::Value,
    ) -> Result<Self::Value, Self::Error>;

    /// Compares two values proven statically to be decoded integers.
    ///
    /// # Errors
    ///
    /// Returns an error if runtime representation checks fail.
    fn integer_less_than(
        &mut self,
        left: Self::Value,
        right: Self::Value,
    ) -> Result<Self::Value, Self::Error>;

    /// Decodes one value proven statically to be Boolean.
    ///
    /// # Errors
    ///
    /// Returns an error if the runtime value violates its validated type.
    fn decode_boolean(&mut self, value: Self::Value) -> Result<bool, Self::Error>;

    /// Inspects or atomically claims a force subject before entering a branch.
    ///
    /// # Errors
    ///
    /// Returns an error when runtime force-state inspection fails before a
    /// claim is transferred to the runner.
    #[allow(clippy::type_complexity)]
    fn begin_force(
        &mut self,
        subject: Self::Value,
        guards: MixedForceGuards,
    ) -> Result<
        MixedForceAction<Self::Value, Self::Frame, Self::ForceTarget, Self::UpdateToken>,
        Self::Error,
    >;

    /// Inspects a potential exact unary closure without entering its body.
    ///
    /// # Errors
    ///
    /// Returns an error when runtime closure metadata cannot be inspected.
    fn inspect_callable(
        &mut self,
        callable: Self::Value,
    ) -> Result<MixedCallable<Self::Frame>, Self::Error>;

    /// Publishes one successfully completed claimed force.
    ///
    /// # Errors
    ///
    /// Returns an error when the evaluator rejects publication. The runner
    /// then aborts this token and every outer token in reverse order.
    fn publish_update(
        &mut self,
        target: &Self::ForceTarget,
        token: &Self::UpdateToken,
        value: Self::Value,
    ) -> Result<(), Self::Error>;

    /// Aborts one claimed force during runtime-error cleanup.
    fn abort_update(&mut self, target: Self::ForceTarget, token: Self::UpdateToken);
}

/// Reports why a validated v3 plan cannot enter the narrow executable subset.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MixedExecutionAdmissionError {
    /// Virtual objects lack complete capture and materialization recipes in v3.
    #[error("mixed operation {operation} constructs an unrepresentable virtual object")]
    VirtualObject {
        /// Operation-table index.
        operation: usize,
    },
    /// Generic materialization lacks an exact oracle action in v3.
    #[error("mixed block {block} uses a materialization statepoint without an oracle action")]
    GenericMaterialization {
        /// Block-table index.
        block: usize,
    },
}

/// A validated plan admitted to the narrow executable runtime contract.
#[derive(Clone, Copy, Debug)]
pub struct MixedExecutablePlan<'plan> {
    plan: &'plan MixedModulePlan,
}

impl<'plan> MixedExecutablePlan<'plan> {
    /// Checks that every operation has executable v3 runtime semantics.
    ///
    /// # Errors
    ///
    /// Returns [`MixedExecutionAdmissionError`] for virtual object producers
    /// or generic materialization statepoints, whose recipes are absent in v3.
    pub fn new(plan: &'plan MixedModulePlan) -> Result<Self, MixedExecutionAdmissionError> {
        for (operation, item) in plan.operations().iter().enumerate() {
            if matches!(
                item,
                MixedOp::VirtualThunk { .. } | MixedOp::VirtualClosure { .. }
            ) {
                return Err(MixedExecutionAdmissionError::VirtualObject { operation });
            }
        }
        for (block, item) in plan.blocks().iter().enumerate() {
            if matches!(item.terminator, MixedTerminator::Materialize { .. }) {
                return Err(MixedExecutionAdmissionError::GenericMaterialization { block });
            }
        }
        Ok(Self { plan })
    }

    /// Returns the underlying fully validated plan.
    pub const fn plan(self) -> &'plan MixedModulePlan {
        self.plan
    }
}

/// Distinguishes a semantic statepoint from a bounded-runner capacity exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixedExecutionSideExitCause {
    /// Runtime force or call guards selected the plan's semantic fallback.
    Guard,
    /// The fixed activation slab had no free direct-call frame.
    CallCapacity,
}

/// Describes one suspended pre-claim materializing exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixedExecutionSideExit {
    statepoint: MixedStatepointId,
    cause: MixedExecutionSideExitCause,
}

impl MixedExecutionSideExit {
    /// Returns the exact statepoint whose live-set contract is suspended.
    pub const fn statepoint(self) -> MixedStatepointId {
        self.statepoint
    }

    /// Returns why the runner selected the statepoint.
    pub const fn cause(self) -> MixedExecutionSideExitCause {
        self.cause
    }
}

/// Result of running until completion or an explicit oracle boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixedExecutionOutcome<Value> {
    /// The outer mixed entry returned a value.
    Complete(Value),
    /// Execution stopped before observable unsupported semantic work.
    SideExit(MixedExecutionSideExit),
    /// Claimed work was rolled back before the semantic oracle re-enters an outer entry.
    Restart {
        /// Entry-table index that must be evaluated through the oracle.
        entry: u32,
        /// Guard boundary that requested the rollback.
        statepoint: MixedStatepointId,
    },
}

/// Counts concrete transitions driven by one runner activation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MixedExecutionStats {
    /// Basic blocks entered.
    pub blocks: u64,
    /// Pure typed operations executed.
    pub operations: u64,
    /// Force subjects already ready.
    pub ready_forces: u64,
    /// Runtime thunks claimed by shape.
    pub claimed_forces: [u64; 3],
    /// Claimed updates published.
    pub updates: u64,
    /// Exact guarded calls entered without an oracle call.
    pub direct_calls: u64,
    /// Direct call or outer returns completed.
    pub returns: u64,
    /// Explicit side exits selected.
    pub side_exits: u64,
}

/// Reports the fixed storage reserved before mixed execution begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixedExecutionStorage {
    /// Value slots across every preallocated call activation.
    pub value_slots: usize,
    /// Direct-call activation records.
    pub call_frames: usize,
    /// Force-update records.
    pub update_tokens: usize,
    /// Bytes reserved by the three hot runner buffers.
    pub reserved_bytes: usize,
}

/// Reports runtime failures and impossible validated-plan invariants.
#[derive(Debug, Error)]
pub enum MixedExecutionError<RuntimeError: Error + 'static> {
    /// The selected entry does not exist.
    #[error("mixed execution entry {entry} is outside the entry table")]
    InvalidEntry {
        /// Requested entry-table index.
        entry: usize,
    },
    /// The requested fixed call capacity is zero or overflows the slot slab.
    #[error("mixed execution call capacity {capacity} cannot size the activation slab")]
    InvalidCallCapacity {
        /// Requested activation count.
        capacity: usize,
    },
    /// Execution was requested while an oracle statepoint remained suspended.
    #[error("mixed execution must resume its suspended statepoint first")]
    Suspended,
    /// Execution was requested after completion or failure made it terminal.
    #[error("mixed execution activation is already terminal")]
    Terminal,
    /// Workspace reuse was requested before the current activation terminated.
    #[error("mixed execution workspace still owns an active activation")]
    Active,
    /// A resume value disagreed with the statepoint result contract.
    #[error("mixed execution statepoint resume value presence is invalid")]
    InvalidResumeValue,
    /// A runtime operation failed.
    #[error("mixed execution runtime failed")]
    Runtime(#[source] RuntimeError),
    /// Validated SSA state was absent at execution time.
    #[error("mixed execution read undefined value slot {value:?}")]
    UndefinedValue {
        /// Missing plan-local value slot.
        value: MixedValueId,
    },
    /// Runtime update ownership disagreed with the validated LIFO contract.
    #[error("mixed execution update ownership is unbalanced")]
    UpdateOwnership,
    /// The runtime claimed work that did not match the terminator's exact guard.
    #[error("mixed execution runtime claimed a mismatched force-work identity")]
    ForceIdentityMismatch,
    /// A runtime virtual callable named no target in its guarded population.
    #[error("mixed execution virtual callable target is outside the guarded population")]
    VirtualCallTarget,
}

#[derive(Clone, Copy, Debug)]
struct ReturnTarget {
    block: MixedBlockId,
    result: MixedValueId,
}

#[derive(Clone, Copy, Debug)]
struct Activation<Frame> {
    block: MixedBlockId,
    frame: Frame,
    return_target: Option<ReturnTarget>,
}

#[derive(Debug)]
struct OwnedUpdate<Frame, ForceTarget, UpdateToken> {
    activation: usize,
    previous_frame: Frame,
    target: ForceTarget,
    token: UpdateToken,
}

/// Fixed-slab executor for one admitted mixed-machine entry.
///
/// Construction allocates all value slots and call records. Running does not
/// allocate Promise records, closure records, lexical frames, or call slabs.
pub struct MixedExecutionRunner<'plan, Runtime: MixedMachineRuntime> {
    executable: MixedExecutablePlan<'plan>,
    slots: Box<[Option<Runtime::Value>]>,
    activations: Box<[Activation<Runtime::Frame>]>,
    updates: Box<[Option<OwnedUpdate<Runtime::Frame, Runtime::ForceTarget, Runtime::UpdateToken>>]>,
    slot_count: usize,
    activation_depth: usize,
    update_depth: usize,
    suspended: Option<MixedExecutionSideExit>,
    terminal: bool,
    stats: MixedExecutionStats,
}

impl<'plan, Runtime: MixedMachineRuntime> MixedExecutionRunner<'plan, Runtime> {
    /// Creates a preallocated activation for one guarded outer entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the entry is absent, call capacity is zero, or
    /// sizing the fixed value slab overflows addressable memory.
    pub fn new(
        executable: MixedExecutablePlan<'plan>,
        entry: usize,
        argument: Runtime::Value,
        frame: Runtime::Frame,
        call_capacity: usize,
    ) -> Result<Self, MixedExecutionError<Runtime::Error>> {
        let plan = executable.plan();
        let Some(entry_data) = plan.entries().get(entry).copied() else {
            return Err(MixedExecutionError::InvalidEntry { entry });
        };
        if call_capacity == 0 {
            return Err(MixedExecutionError::InvalidCallCapacity {
                capacity: call_capacity,
            });
        }
        let slot_count = plan.bounds().value_slots as usize;
        let Some(total_slots) = slot_count.checked_mul(call_capacity) else {
            return Err(MixedExecutionError::InvalidCallCapacity {
                capacity: call_capacity,
            });
        };
        let mut slots = Vec::new();
        if slots.try_reserve_exact(total_slots).is_err() {
            return Err(MixedExecutionError::InvalidCallCapacity {
                capacity: call_capacity,
            });
        }
        slots.resize(total_slots, None);
        let function = plan.functions()[entry_data.function.as_u32() as usize];
        let initial_activation = Activation {
            block: function.entry,
            frame,
            return_target: None,
        };
        let mut activations = Vec::new();
        if activations.try_reserve_exact(call_capacity).is_err() {
            return Err(MixedExecutionError::InvalidCallCapacity {
                capacity: call_capacity,
            });
        }
        activations.resize(call_capacity, initial_activation);
        let mut updates = Vec::new();
        if updates
            .try_reserve_exact(plan.bounds().update_depth as usize)
            .is_err()
        {
            return Err(MixedExecutionError::InvalidCallCapacity {
                capacity: call_capacity,
            });
        }
        updates.resize_with(plan.bounds().update_depth as usize, || None);
        slots[function.parameter.as_u32() as usize] = Some(argument);
        Ok(Self {
            executable,
            slots: slots.into_boxed_slice(),
            activations: activations.into_boxed_slice(),
            updates: updates.into_boxed_slice(),
            slot_count,
            activation_depth: 1,
            update_depth: 0,
            suspended: None,
            terminal: false,
            stats: MixedExecutionStats::default(),
        })
    }

    /// Returns concrete transition counts accumulated by this activation.
    pub const fn stats(&self) -> MixedExecutionStats {
        self.stats
    }

    /// Returns fixed runner storage available without hot-path growth.
    pub fn storage(&self) -> MixedExecutionStorage {
        let slot_bytes = self
            .slots
            .len()
            .saturating_mul(std::mem::size_of::<Option<Runtime::Value>>());
        let call_bytes = self
            .activations
            .len()
            .saturating_mul(std::mem::size_of::<Activation<Runtime::Frame>>());
        let update_bytes = self.updates.len().saturating_mul(std::mem::size_of::<
            Option<OwnedUpdate<Runtime::Frame, Runtime::ForceTarget, Runtime::UpdateToken>>,
        >());
        MixedExecutionStorage {
            value_slots: self.slots.len(),
            call_frames: self.activations.len(),
            update_tokens: self.updates.len(),
            reserved_bytes: slot_bytes
                .saturating_add(call_bytes)
                .saturating_add(update_bytes),
        }
    }

    /// Reuses the fixed slabs for another entry without allocating.
    ///
    /// The plan and all storage bounds remain unchanged. Every value slot and
    /// activation record is cleared before the new argument is installed.
    ///
    /// # Errors
    ///
    /// Returns [`MixedExecutionError::Active`] until the preceding activation
    /// completes or fails, or [`MixedExecutionError::InvalidEntry`] when
    /// `entry` is outside the immutable plan.
    pub fn restart(
        &mut self,
        entry: usize,
        argument: Runtime::Value,
        frame: Runtime::Frame,
    ) -> Result<(), MixedExecutionError<Runtime::Error>> {
        if !self.terminal {
            return Err(MixedExecutionError::Active);
        }
        let Some(entry_data) = self.executable.plan().entries().get(entry).copied() else {
            return Err(MixedExecutionError::InvalidEntry { entry });
        };
        if self.update_depth != 0 {
            return Err(MixedExecutionError::UpdateOwnership);
        }
        self.slots.fill(None);
        let function = self.executable.plan().functions()[entry_data.function.as_u32() as usize];
        self.slots[function.parameter.as_u32() as usize] = Some(argument);
        self.activations[0] = Activation {
            block: function.entry,
            frame,
            return_target: None,
        };
        self.activation_depth = 1;
        self.suspended = None;
        self.terminal = false;
        self.stats = MixedExecutionStats::default();
        Ok(())
    }

    /// Returns metadata for the currently suspended statepoint.
    pub fn suspended_statepoint(&self) -> Option<&MixedStatepoint> {
        let exit = self.suspended?;
        self.executable
            .plan()
            .statepoints()
            .get(exit.statepoint.as_u32() as usize)
    }

    /// Copies one live value from the current suspended activation.
    pub fn suspended_value(&self, value: MixedValueId) -> Option<Runtime::Value> {
        self.suspended?;
        self.read_slot(value).ok()
    }

    /// Supplies the oracle result and resumes the statepoint's local block.
    ///
    /// # Errors
    ///
    /// Returns an error when no statepoint is suspended or result presence
    /// disagrees with the validated statepoint contract.
    pub fn resume(
        &mut self,
        result: Option<Runtime::Value>,
    ) -> Result<(), MixedExecutionError<Runtime::Error>> {
        let Some(exit) = self.suspended.take() else {
            return Err(MixedExecutionError::InvalidResumeValue);
        };
        let statepoint = &self.executable.plan().statepoints()[exit.statepoint.as_u32() as usize];
        match (statepoint.result, result) {
            (Some(destination), Some(value)) => self.write_slot(destination, value),
            (None, None) => {}
            _ => {
                self.suspended = Some(exit);
                return Err(MixedExecutionError::InvalidResumeValue);
            }
        }
        self.current_activation_mut()?.block = statepoint.resume;
        Ok(())
    }

    /// Executes typed blocks until the outer return or a pre-claim side exit.
    ///
    /// # Errors
    ///
    /// Returns runtime backend failures or an internal ownership error. On a
    /// runtime failure, every outstanding update is aborted in reverse order.
    ///
    /// # Panics
    ///
    /// Resumes a panic raised by the runtime backend after first aborting every
    /// outstanding update in reverse order.
    pub fn run(
        &mut self,
        runtime: &mut Runtime,
    ) -> Result<MixedExecutionOutcome<Runtime::Value>, MixedExecutionError<Runtime::Error>> {
        if self.suspended.is_some() {
            return Err(MixedExecutionError::Suspended);
        }
        if self.terminal {
            return Err(MixedExecutionError::Terminal);
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| self.run_inner(runtime)));
        match outcome {
            Ok(result) => {
                if result.is_err() {
                    self.abort_updates(runtime);
                    self.terminal = true;
                } else if matches!(
                    &result,
                    Ok(MixedExecutionOutcome::Complete(_) | MixedExecutionOutcome::Restart { .. })
                ) {
                    self.terminal = true;
                }
                result
            }
            Err(payload) => {
                self.abort_updates(runtime);
                self.terminal = true;
                resume_unwind(payload)
            }
        }
    }

    fn run_inner(
        &mut self,
        runtime: &mut Runtime,
    ) -> Result<MixedExecutionOutcome<Runtime::Value>, MixedExecutionError<Runtime::Error>> {
        loop {
            let activation_index = self.activation_depth.saturating_sub(1);
            let activation = self.activations[activation_index];
            let block = &self.executable.plan().blocks()[activation.block.as_u32() as usize];
            self.stats.blocks = self.stats.blocks.saturating_add(1);
            let operation_start = block.operations.start() as usize;
            let operation_end = operation_start.saturating_add(block.operations.len() as usize);
            for operation_index in operation_start..operation_end {
                let operation = self.executable.plan().operations()[operation_index];
                self.execute_operation(runtime, activation.frame, operation)?;
                self.stats.operations = self.stats.operations.saturating_add(1);
            }
            match &block.terminator {
                MixedTerminator::Jump { target } => self.set_block(*target),
                MixedTerminator::Branch {
                    condition,
                    when_true,
                    when_false,
                } => {
                    let value = self.read_slot(*condition)?;
                    let branch = runtime
                        .decode_boolean(value)
                        .map_err(MixedExecutionError::Runtime)?;
                    self.set_block(if branch { *when_true } else { *when_false });
                }
                MixedTerminator::Force {
                    subject,
                    result,
                    guards,
                    ready,
                    node,
                    apply,
                    gen_list,
                    fallback,
                    ..
                } => {
                    let subject_value = self.read_slot(*subject)?;
                    match runtime
                        .begin_force(subject_value, *guards)
                        .map_err(MixedExecutionError::Runtime)?
                    {
                        MixedForceAction::Ready(value) => {
                            self.write_slot(*result, value);
                            self.stats.ready_forces = self.stats.ready_forces.saturating_add(1);
                            self.set_block(*ready);
                        }
                        MixedForceAction::Claimed {
                            target: force_target,
                            shape,
                            work,
                            frame,
                            update,
                        } => {
                            if work != guards.for_shape(shape) {
                                runtime.abort_update(force_target, update);
                                return Err(MixedExecutionError::ForceIdentityMismatch);
                            }
                            let successor = match shape {
                                MixedForceShape::Node => *node,
                                MixedForceShape::Apply => *apply,
                                MixedForceShape::GenListElemAtAddOne => *gen_list,
                            };
                            let shape_index = match shape {
                                MixedForceShape::Node => 0,
                                MixedForceShape::Apply => 1,
                                MixedForceShape::GenListElemAtAddOne => 2,
                            };
                            self.stats.claimed_forces[shape_index] =
                                self.stats.claimed_forces[shape_index].saturating_add(1);
                            if self.update_depth == self.updates.len() {
                                runtime.abort_update(force_target, update);
                                return Err(MixedExecutionError::UpdateOwnership);
                            }
                            let previous_frame = self.activations[activation_index].frame;
                            self.updates[self.update_depth] = Some(OwnedUpdate {
                                activation: activation_index,
                                previous_frame,
                                target: force_target,
                                token: update,
                            });
                            self.update_depth = self.update_depth.saturating_add(1);
                            self.activations[activation_index].frame = frame;
                            self.set_block(successor);
                        }
                        MixedForceAction::Declined => {
                            return self.guard_exit(
                                runtime,
                                *fallback,
                                MixedExecutionSideExitCause::Guard,
                            );
                        }
                    }
                }
                MixedTerminator::ApplyGuarded {
                    function,
                    argument,
                    result,
                    targets,
                    continuation,
                    fallback,
                } => {
                    let callable = self.read_slot(*function)?;
                    let argument_value = self.read_slot(*argument)?;
                    let target_start = targets.start() as usize;
                    let target_end = target_start.saturating_add(targets.len() as usize);
                    let population =
                        &self.executable.plan().call_targets()[target_start..target_end];
                    let inspected = runtime
                        .inspect_callable(callable)
                        .map_err(MixedExecutionError::Runtime)?;
                    let selected = match inspected {
                        MixedCallable::Materialized { code, frame } => population
                            .iter()
                            .find(|target| target.code == code)
                            .copied()
                            .map(|target| (target, frame)),
                        MixedCallable::Virtual { function, frame } => {
                            let Some(target) = population
                                .iter()
                                .find(|target| target.function == function)
                                .copied()
                            else {
                                return Err(MixedExecutionError::VirtualCallTarget);
                            };
                            Some((target, frame))
                        }
                        MixedCallable::Declined => None,
                    };
                    let Some((target, frame)) = selected else {
                        return self.guard_exit(
                            runtime,
                            *fallback,
                            MixedExecutionSideExitCause::Guard,
                        );
                    };
                    if self.activation_depth == self.activations.len() {
                        return self.guard_exit(
                            runtime,
                            *fallback,
                            MixedExecutionSideExitCause::CallCapacity,
                        );
                    }
                    self.enter_call(
                        target,
                        argument_value,
                        frame,
                        ReturnTarget {
                            block: *continuation,
                            result: *result,
                        },
                    );
                    self.stats.direct_calls = self.stats.direct_calls.saturating_add(1);
                }
                MixedTerminator::Update {
                    value,
                    result,
                    next,
                } => {
                    let value = self.read_slot(*value)?;
                    let Some(update_index) = self.update_depth.checked_sub(1) else {
                        return Err(MixedExecutionError::UpdateOwnership);
                    };
                    let pending = self.updates[update_index]
                        .as_ref()
                        .ok_or(MixedExecutionError::UpdateOwnership)?;
                    if pending.activation != activation_index {
                        return Err(MixedExecutionError::UpdateOwnership);
                    }
                    runtime
                        .publish_update(&pending.target, &pending.token, value)
                        .map_err(MixedExecutionError::Runtime)?;
                    let pending = self.updates[update_index]
                        .take()
                        .ok_or(MixedExecutionError::UpdateOwnership)?;
                    self.update_depth = update_index;
                    self.activations[activation_index].frame = pending.previous_frame;
                    self.write_slot(*result, value);
                    self.set_block(*next);
                    self.stats.updates = self.stats.updates.saturating_add(1);
                }
                MixedTerminator::Return { value } => {
                    let value = self.read_slot(*value)?;
                    self.stats.returns = self.stats.returns.saturating_add(1);
                    if self.activation_depth == 1 {
                        if self.update_depth != 0 {
                            return Err(MixedExecutionError::UpdateOwnership);
                        }
                        return Ok(MixedExecutionOutcome::Complete(value));
                    }
                    let callee_index = self.activation_depth.saturating_sub(1);
                    let callee = self.activations[callee_index];
                    self.activation_depth = callee_index;
                    let Some(return_target) = callee.return_target else {
                        return Err(MixedExecutionError::UpdateOwnership);
                    };
                    self.write_slot(return_target.result, value);
                    self.set_block(return_target.block);
                }
                MixedTerminator::Materialize { .. } => {
                    return Err(MixedExecutionError::UpdateOwnership);
                }
            }
        }
    }

    fn execute_operation(
        &mut self,
        runtime: &mut Runtime,
        frame: Runtime::Frame,
        operation: MixedOp,
    ) -> Result<(), MixedExecutionError<Runtime::Error>> {
        let (destination, value) = match operation {
            MixedOp::ConstInt { destination, value } => (
                destination,
                runtime
                    .integer(value)
                    .map_err(MixedExecutionError::Runtime)?,
            ),
            MixedOp::ConstBool { destination, value } => (destination, runtime.boolean(value)),
            MixedOp::ConstNull { destination } => (destination, runtime.null()),
            MixedOp::Move {
                destination,
                source,
            } => (destination, self.read_slot(source)?),
            MixedOp::LoadLocal { destination, slot } => (
                destination,
                runtime
                    .load_local(frame, slot)
                    .map_err(MixedExecutionError::Runtime)?,
            ),
            MixedOp::LoadUpvalue {
                destination,
                depth,
                slot,
            } => (
                destination,
                runtime
                    .load_upvalue(frame, depth, slot)
                    .map_err(MixedExecutionError::Runtime)?,
            ),
            MixedOp::AddInt {
                destination,
                left,
                right,
            } => (
                destination,
                runtime
                    .add_integer(self.read_slot(left)?, self.read_slot(right)?)
                    .map_err(MixedExecutionError::Runtime)?,
            ),
            MixedOp::LessThanInt {
                destination,
                left,
                right,
            } => (
                destination,
                runtime
                    .integer_less_than(self.read_slot(left)?, self.read_slot(right)?)
                    .map_err(MixedExecutionError::Runtime)?,
            ),
            MixedOp::VirtualThunk { .. } | MixedOp::VirtualClosure { .. } => {
                return Err(MixedExecutionError::UpdateOwnership);
            }
        };
        self.write_slot(destination, value);
        Ok(())
    }

    fn enter_call(
        &mut self,
        target: MixedCallTarget,
        argument: Runtime::Value,
        frame: Runtime::Frame,
        return_target: ReturnTarget,
    ) {
        let depth = self.activation_depth;
        let start = depth.saturating_mul(self.slot_count);
        let end = start.saturating_add(self.slot_count);
        self.slots[start..end].fill(None);
        let function = self.executable.plan().functions()[target.function.as_u32() as usize];
        self.slots[start + target.argument_destination.as_u32() as usize] = Some(argument);
        self.activations[depth] = Activation {
            block: function.entry,
            frame,
            return_target: Some(return_target),
        };
        self.activation_depth = self.activation_depth.saturating_add(1);
    }

    fn side_exit(
        &mut self,
        statepoint: MixedStatepointId,
        cause: MixedExecutionSideExitCause,
    ) -> MixedExecutionOutcome<Runtime::Value> {
        let exit = MixedExecutionSideExit { statepoint, cause };
        self.suspended = Some(exit);
        self.stats.side_exits = self.stats.side_exits.saturating_add(1);
        MixedExecutionOutcome::SideExit(exit)
    }

    fn guard_exit(
        &mut self,
        runtime: &mut Runtime,
        statepoint: MixedStatepointId,
        cause: MixedExecutionSideExitCause,
    ) -> Result<MixedExecutionOutcome<Runtime::Value>, MixedExecutionError<Runtime::Error>> {
        let mode = self.executable.plan().statepoints()[statepoint.as_u32() as usize].mode;
        if let MixedStatepointMode::RestartEntry { entry } = mode {
            self.abort_updates(runtime);
            self.stats.side_exits = self.stats.side_exits.saturating_add(1);
            return Ok(MixedExecutionOutcome::Restart { entry, statepoint });
        }
        Ok(self.side_exit(statepoint, cause))
    }

    fn read_slot(
        &self,
        value: MixedValueId,
    ) -> Result<Runtime::Value, MixedExecutionError<Runtime::Error>> {
        let depth = self.activation_depth.saturating_sub(1);
        let index = depth
            .saturating_mul(self.slot_count)
            .saturating_add(value.as_u32() as usize);
        self.slots[index].ok_or(MixedExecutionError::UndefinedValue { value })
    }

    fn write_slot(&mut self, value: MixedValueId, runtime_value: Runtime::Value) {
        let depth = self.activation_depth.saturating_sub(1);
        let index = depth
            .saturating_mul(self.slot_count)
            .saturating_add(value.as_u32() as usize);
        self.slots[index] = Some(runtime_value);
    }

    fn set_block(&mut self, block: MixedBlockId) {
        let index = self.activation_depth.saturating_sub(1);
        if let Some(activation) = self.activations.get_mut(index) {
            activation.block = block;
        }
    }

    fn current_activation_mut(
        &mut self,
    ) -> Result<&mut Activation<Runtime::Frame>, MixedExecutionError<Runtime::Error>> {
        if self.activation_depth == 0 {
            return Err(MixedExecutionError::UpdateOwnership);
        }
        let index = self.activation_depth.saturating_sub(1);
        self.activations
            .get_mut(index)
            .ok_or(MixedExecutionError::UpdateOwnership)
    }

    fn abort_updates(&mut self, runtime: &mut Runtime) {
        while let Some(index) = self.update_depth.checked_sub(1) {
            let Some(update) = self.updates[index].take() else {
                self.update_depth = index;
                continue;
            };
            self.update_depth = index;
            if let Some(activation) = self.activations.get_mut(update.activation) {
                activation.frame = update.previous_frame;
            }
            runtime.abort_update(update.target, update.token);
        }
    }
}

#[cfg(test)]
mod tests;
