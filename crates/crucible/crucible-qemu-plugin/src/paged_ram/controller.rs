//! SPDX-License-Identifier: GPL-2.0-or-later
//! Owns real pre-CPU resource admission and live independent paging supervision.
//!
//! The startup report precedes dense RAM metadata allocation. Its scratch comes
//! from the original staging entitlement; the authenticated host grant can only
//! reclassify metadata/staging within the same retained complete resource peaks.
//! Policy application changes the actual arena owner and the live operation
//! roster together. No guest clock, replay token or QEMU lock is used by dispatch.

use super::supervision::OperationalStart;
use crate::ram_error::RamError;
use std::fs::File;
use std::io;
use std::os::fd::BorrowedFd;
use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crucible_qemu_protocol::ram_control::*;
use crucible_ram::RegionDescriptor;

use super::control::PagerControl;
use super::engine::PausedPagingOwner;
use super::source::{
    ObservationOperationError, SourceOperation, SourceOperationClass, SourceOperationFactory,
};
use crate::PluginArgs;

mod actor;
mod prebirth;
pub(crate) use prebirth::InstallerControlRequests;
pub(super) use prebirth::configured_shared_allocation_layout;

mod admission;
mod aliases;
mod capture;
pub(crate) use capture::work::{CheckpointWorkAdmission, HeldCheckpointWork};
pub(crate) use capture::{CheckpointPagerOwner, retain_pager_owner};
mod fault_actor;
mod fork;
pub(crate) use admission::{
    admit_native_inventory, admitted_spill_quota, complete_native_admission,
};
use aliases::DescriptorAlias;
pub(crate) use aliases::{disarm_inherited_aliases, retain_source_alias};
pub(crate) use fork::{
    PreparedChildControl, disarm_parent_control, final_seal, prepare_child, prepare_fork,
    rebind_child, resume_parent,
};

const MAX_OPERATIONS: usize = 64;

static CONTROLLER: Mutex<Option<Arc<LivePagerController>>> = Mutex::new(None);

fn controller() -> Result<Option<Arc<LivePagerController>>, RamError> {
    CONTROLLER
        .lock()
        .map(|current| current.clone())
        .map_err(|_| RamError::Invariant("RAM controller publication poisoned"))
}

type NativeOwnerInventory = extern "C" fn(*mut u64, *mut u64, *mut u64) -> c_int;

type NativeGrant = extern "C" fn(u64, u64, *mut u64) -> c_int;
type ChildRuntimeReady = extern "C" fn() -> c_int;

struct Inventory {
    report: RamControlInventoryReport,
    regions: Vec<RamControlInventoryRegion>,
    grant: Option<(RamControlResources, u64)>,
    operation: Option<Arc<dyn SourceOperation>>,
}

struct State {
    resources: RamControlResources,
    budgets: [RamControlBudget; RAM_CONTROL_BUDGET_COUNT],
    outer: Option<RamControlOuterCap>,
    outer_expired: bool,
    aliases: [Option<DescriptorAlias>; 3],
    inventory: Option<Inventory>,
    owner: Option<Arc<PausedPagingOwner>>,
    requested_revision: u64,
    applied_revision: u64,
    reservation_revision: u64,
    observation_sequence: u64,
    policy: Option<RamControlPolicy>,
    failed: bool,
    fork_preparing: bool,
    policy_applying: bool,
    child_bootstrap: bool,
    checkpoint: capture::CheckpointAdmission,
}

/// Retains real control, budget and arena authority until process disposition.
struct LivePagerController {
    target: RamControlTarget,
    session: [u8; 32],
    fault_actor_test_entitlement: Option<[u8; 32]>,
    state: Arc<Mutex<State>>,
    canceled: Arc<AtomicBool>,
    operations: Arc<capture::work::OperationRegistry>,
    native_grant: NativeGrant,
    child_runtime_ready: ChildRuntimeReady,
    spill: Mutex<Option<File>>,
    spill_quota: u64,
    actor: Mutex<actor::ActorState>,
}

/// Returns only the admitted independent operation factory.
///
/// # Errors
/// Refuses a missing managed controller or poisoned publication.
pub(crate) fn operation_factory() -> Result<Arc<dyn SourceOperationFactory>, RamError> {
    Ok(controller()?.ok_or("RAM controller unavailable")?)
}

/// Returns the retained actual arena owner without guest locks or backing I/O.
///
/// # Errors
/// Refuses unavailable or poisoned operational admission.
pub(crate) fn current_owner() -> Result<Option<Arc<PausedPagingOwner>>, RamError> {
    let Some(controller) = controller()? else {
        return Ok(None);
    };
    let owner = controller
        .state
        .lock()
        .map_err(|_| RamError::Invariant("RAM controller poisoned"))?
        .owner
        .clone();
    Ok(owner)
}

/// Retains only the installed pager owner bound to this genuine runtime.
///
/// # Errors
/// Refuses absent/replaced controller, native actor identity or paging ownership.
pub(crate) fn registered_current_owner(
    id: u64,
    userdata: *mut c_void,
) -> Result<Arc<PausedPagingOwner>, RamError> {
    let controller = controller()?.ok_or("fingerprint controller absent")?;
    let actor = controller
        .actor
        .try_lock()
        .map_err(|_| "fingerprint actor relation busy")?;
    if !actor.matches_runtime(id, userdata) {
        return Err(RamError::Invariant(
            "fingerprint runtime allocation changed",
        ));
    }
    drop(actor);
    let owner = controller
        .state
        .try_lock()
        .map_err(|_| "fingerprint owner relation busy")?
        .owner
        .clone()
        .ok_or("fingerprint paging owner absent")?;
    if Arc::as_ptr(&owner.operations).cast::<()>() != Arc::as_ptr(&controller).cast::<()>() {
        return Err(RamError::Invariant("fingerprint controller owner changed"));
    }
    Ok(owner)
}

/// Returns allocation requests for the fixed controller and initial pager bodies.
///
/// This is layout information only; the installer Source must independently
/// issue the prebirth purpose before any allocation or descriptor effect.
///
/// # Errors
/// Returns an error when the configured layout requests cannot be represented.
pub(crate) fn installer_control_requests() -> Result<InstallerControlRequests, RamError> {
    prebirth::required_control_requests()
}

/// Starts actual independent dispatch before native machine inventory admission.
///
/// # Errors
/// Refuses incomplete launch resources/timing, unavailable native ownership
/// APIs, duplicate setup, invalid Unix streams or failed worker creation.
pub(crate) fn install(
    args: &PluginArgs,
    plugin_id: u64,
    setup: &crate::PluginSetupCompletion,
    userdata: *mut c_void,
) -> Result<(), RamError> {
    let Some(control) = args.ram_control() else {
        return Ok(());
    };
    let control_alias = DescriptorAlias::capture(control.descriptor)?;
    let resources = args
        .ram_resources()
        .ok_or("RAM control lacks admitted resources")?;
    let spill_alias = DescriptorAlias::capture(
        args.ram_spill_descriptor()
            .ok_or("RAM spill descriptor missing")?,
    )?;
    let spill_quota = args
        .ram_spill_quota()
        .ok_or("RAM control lacks admitted spill quota")?;
    let spill_descriptor = args
        .ram_spill_descriptor()
        .ok_or("RAM control lacks private disk backing")?;
    // SAFETY: launch retains this admitted private file descriptor while duplicated.
    let borrowed = unsafe { BorrowedFd::borrow_raw(spill_descriptor) };
    let spill = File::from(borrowed.try_clone_to_owned()?);
    let budgets = args
        .ram_initial_budgets()
        .ok_or("RAM control lacks initial live budget roster")?;
    let outer = args
        .ram_outer_cap()
        .ok_or("RAM control lacks original-start outer binding")?;
    outer.validate()?;
    validate_infrastructure(&budgets, Some(outer))?;
    // Actual seven-row Source admission precedes the configured controller
    // allocation. Native exclusively owns the RAM endpoint and sole worker.
    setup.require_installer_control_purpose()?;
    let actor = actor::ActorState::new(plugin_id, userdata)?;
    // SAFETY: the grant callback lends one scalar output within this process.
    let native_grant = unsafe {
        std::mem::transmute::<*mut c_void, NativeGrant>(symbol(
            b"qemu_plugin_crucible_ram_admission_grant_v1\0",
        )?)
    };
    // SAFETY: readiness is a lock-free scalar from the paired native runtime.
    let child_runtime_ready = unsafe {
        std::mem::transmute::<*mut c_void, ChildRuntimeReady>(symbol(
            b"qemu_plugin_crucible_ram_child_runtime_ready_v1\0",
        )?)
    };
    let controller = Arc::new(LivePagerController {
        target: control.target,
        session: control.session,
        fault_actor_test_entitlement: control.fault_actor_test_entitlement,
        state: Arc::new(Mutex::new(State {
            resources,
            budgets,
            outer: Some(outer),
            outer_expired: false,
            aliases: [Some(control_alias), Some(spill_alias), None],
            inventory: None,
            owner: None,
            requested_revision: 0,
            applied_revision: 0,
            reservation_revision: 0,
            observation_sequence: 0,
            policy: None,
            failed: false,
            fork_preparing: false,
            policy_applying: false,
            child_bootstrap: false,
            checkpoint: capture::CheckpointAdmission::default(),
        })),
        canceled: Arc::new(AtomicBool::new(false)),
        operations: Arc::new(capture::work::OperationRegistry::default()),
        native_grant,
        child_runtime_ready,
        spill: Mutex::new(Some(spill)),
        spill_quota,
        actor: Mutex::new(actor),
    });
    {
        let mut current = CONTROLLER
            .lock()
            .map_err(|_| RamError::Invariant("RAM controller publication poisoned"))?;
        if current.is_some() {
            return Err(RamError::Invariant("RAM controller already installed"));
        }
        *current = Some(controller.clone());
    }
    actor::install(&controller, setup, control.descriptor)?;
    Ok(())
}

fn remaining_allowance_ns(allowance_ns: u64, elapsed: Duration) -> Option<Duration> {
    if allowance_ns == 0 || allowance_ns > RAM_CONTROL_MAX_ALLOWANCE_NS {
        return None;
    }
    Duration::from_nanos(allowance_ns)
        .checked_sub(elapsed)
        .filter(|remaining| !remaining.is_zero())
}

fn validate_infrastructure(
    budgets: &[RamControlBudget; RAM_CONTROL_BUDGET_COUNT],
    outer: Option<RamControlOuterCap>,
) -> Result<(), RamError> {
    for index in [0, 2, 3, 5, 6, 10, 13] {
        let budget = budgets[index];
        if budget.poll_ns == 0
            || (budget.total_ns.is_none()
                && budget.progress_ns.is_none()
                && (index == 13
                    || !outer.is_some_and(|cap| {
                        cap.allowance_ns.is_some() && cap.state == RamControlOuterState::Running
                    })))
        {
            return Err(RamError::Invariant(
                "RAM infrastructure requires finite initial allowances",
            ));
        }
    }
    Ok(())
}

impl LivePagerController {
    fn mark_failed(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.failed = true;
        }
    }

    fn reply(&self, state: &mut State, disposition: RamControlDisposition) -> RamControlReply {
        if state.outer.is_some_and(|cap| outer_remaining(cap).is_err()) {
            state.outer_expired = true;
        }
        let observation = state
            .owner
            .as_ref()
            .map(|owner| owner.status_snapshot(state.policy, state.requested_revision));
        let observation_unavailable = observation.as_ref().is_some_and(Result::is_err);
        let observation = observation.and_then(Result::ok);
        let completed = observation
            .as_ref()
            .and_then(|snapshot| snapshot.placement_receipt);
        let authority = observation.as_ref().map(|snapshot| &snapshot.authority);
        let failed = state.failed
            || authority.is_some_and(|snapshot| snapshot.failed)
            || state
                .owner
                .as_ref()
                .is_some_and(|owner| owner.operational_failure().is_some());
        if !failed
            && !state.policy_applying
            && !state.outer_expired
            && !self.canceled.load(Ordering::Acquire)
            && completed.is_some_and(|receipt| {
                receipt.policy_revision == state.requested_revision
                    && state
                        .policy
                        .is_some_and(|policy| policy.mode == receipt.mode)
            })
        {
            state.applied_revision = state.requested_revision;
        }
        state.observation_sequence = state.observation_sequence.saturating_add(1);
        let report = state.inventory.as_ref().map(|inventory| inventory.report);
        let logical = report.map_or(0, |report| report.logical_bytes);
        let floor = authority
            .as_ref()
            .map_or(logical, |snapshot| snapshot.permanent_resident_bytes);
        let requested_target = state
            .policy
            .map_or(logical, |policy| policy.resident_target_bytes);
        // A strict resident guarantee covers the complete logical inventory,
        // independently of its advisory target and current lock observation.
        let mode_target = if state
            .policy
            .is_some_and(|policy| policy.mode == RamControlMode::ResidentRequired)
        {
            logical
        } else {
            requested_target
        };
        let effective_target = mode_target.max(floor);
        let mut limitations = 0;
        if requested_target < floor {
            limitations |= RAM_LIMIT_COMPULSORY_FLOOR;
        }
        // Removal is confined to paused boundaries. A low residency target
        // therefore never reduces the full-RAM execution peak reservation.
        if logical != 0
            && requested_target < logical
            && state
                .policy
                .is_some_and(|policy| policy.mode != RamControlMode::ResidentRequired)
        {
            limitations |= RAM_LIMIT_EXECUTION_PEAK;
        }
        let activity = state.owner.as_ref().map(|owner| {
            let statistics = owner.statistics();
            RamControlActivity {
                successful_missing_installs: statistics.missing_installs,
                successful_missing_read_installs: statistics.successful_missing_read_installs,
                successful_missing_write_installs: statistics.successful_missing_write_installs,
                write_protect_transitions: statistics.write_transitions,
                preservation_reads: statistics.preserved_reads,
                preservation_writes: statistics.preserved_writes,
                physical_discards: statistics.physical_discards,
                prefetched_pages: statistics.prefetched_pages,
            }
        });
        let mut reply = RamControlReply {
            performance: state.owner.as_ref().and_then(|owner| {
                owner
                    .performance(
                        crucible_qemu_protocol::ram_control::RamControlPerformanceAction::Observe,
                    )
                    .ok()
                    .flatten()
            }),
            operation_failure: state
                .owner
                .as_ref()
                .and_then(|owner| owner.operational_failure().map(|failure| failure.to_wire())),
            placement_receipt: completed
                .filter(|receipt| receipt.policy_revision == state.applied_revision),
            fault_actor: state
                .owner
                .as_ref()
                .and_then(|owner| owner.fault_actor_report().ok().flatten()),
            kernel_probe: state.owner.as_ref().and_then(|owner| owner.kernel_probe()),
            activity,
            disposition: if observation_unavailable
                && disposition == RamControlDisposition::Accepted
            {
                RamControlDisposition::Unavailable
            } else {
                disposition
            },
            logical_ram_bytes: logical,
            inventory: report,
            inventory_region: None,
            requested_policy_revision: state.requested_revision,
            applied_policy_revision: state.applied_revision,
            reservation_revision: state.reservation_revision,
            observation_sequence: state.observation_sequence,
            effective_resident_target_bytes: effective_target,
            effective_floor_bytes: floor,
            limitation_reasons: limitations,
            // Live lock coverage and completed activity are separate evidence.
            // Neither supplies all five fresh physical page classifications.
            measurements_available: false,
            resident_observation: observation
                .as_ref()
                .and_then(|snapshot| snapshot.resident_observation)
                .filter(|observation| {
                    observation.policy_revision == state.applied_revision
                        && !failed
                        && !state.outer_expired
                        && !state.fork_preparing
                        && !state.child_bootstrap
                        && !self.canceled.load(Ordering::Acquire)
                }),
            private_resident_bytes: 0,
            shared_resident_bytes_observed: 0,
            preserved_backing_bytes: 0,
            private_dirty_bytes: 0,
            writeback_pending_bytes: 0,
            convergence: if failed || state.outer_expired {
                RamControlConvergence::Failed
            } else if observation_unavailable
                || state.fork_preparing
                || state.child_bootstrap
                || state.checkpoint.is_held()
                || self.canceled.load(Ordering::Acquire)
            {
                RamControlConvergence::Blocked
            } else if state.policy_applying || state.requested_revision != state.applied_revision {
                RamControlConvergence::Applying
            } else {
                observation
                    .as_ref()
                    .map_or(RamControlConvergence::Blocked, |snapshot| {
                        snapshot.convergence
                    })
            },
        };
        // The same retained outer original bounds this read-only snapshot too.
        // Observation never starts or renews an operation to obtain status.
        if state
            .outer
            .is_some_and(|cap| outer_remaining_for::<true>(cap).is_err())
        {
            state.outer_expired = true;
            reply.convergence = RamControlConvergence::Failed;
            reply.resident_observation = None;
        }
        reply
    }

    fn unavailable(&self) -> RamControlReply {
        RamControlReply {
            performance: None,
            placement_receipt: None,
            operation_failure: None,
            fault_actor: None,
            kernel_probe: None,
            activity: None,
            disposition: RamControlDisposition::Unavailable,
            logical_ram_bytes: 0,
            inventory: None,
            inventory_region: None,
            requested_policy_revision: 0,
            applied_policy_revision: 0,
            reservation_revision: 0,
            observation_sequence: 0,
            effective_resident_target_bytes: 0,
            effective_floor_bytes: 0,
            limitation_reasons: 0,
            measurements_available: false,
            resident_observation: None,
            private_resident_bytes: 0,
            shared_resident_bytes_observed: 0,
            preserved_backing_bytes: 0,
            private_dirty_bytes: 0,
            writeback_pending_bytes: 0,
            convergence: RamControlConvergence::Blocked,
        }
    }
}

impl PagerControl for LivePagerController {
    fn identity(&self) -> RamControlTarget {
        self.target
    }

    fn apply(
        &self,
        expected: u64,
        revision: u64,
        reservation: u64,
        policy: RamControlPolicy,
        resources: RamControlResources,
    ) -> RamControlReply {
        let Ok(mut state) = self.state.try_lock() else {
            return self.unavailable();
        };
        if state.outer.is_some_and(|cap| outer_remaining(cap).is_err()) {
            state.outer_expired = true;
        }
        if state.failed || state.outer_expired || self.canceled.load(Ordering::Acquire) {
            return self.reply(&mut state, RamControlDisposition::AdmissionRefused);
        }
        if state.fork_preparing
            || state.policy_applying
            || state.checkpoint_producer_held(&self.state, &self.operations)
        {
            return self.reply(&mut state, RamControlDisposition::Unavailable);
        }
        // Child adoption can complete the initial policy before its host
        // registrar retries the same authenticated tuple. Replay only the
        // recorded success; no owner work, budget publication or new token runs.
        if expected.checked_add(1) == Some(revision)
            && state.requested_revision == revision
            && state.applied_revision == revision
            && state.reservation_revision == reservation
            && state.resources == resources
            && state.policy == Some(policy)
            && state.budgets == policy.budgets
        {
            return self.reply(&mut state, RamControlDisposition::Accepted);
        }
        // A staged child can acknowledge its already installed configuration,
        // but arbitrary operational placement must wait for actual native
        // coordinator and descriptor reconstruction. Polling never advances it.
        if state.child_bootstrap {
            if (self.child_runtime_ready)() != 1 {
                return self.reply(&mut state, RamControlDisposition::Unavailable);
            }
            state.child_bootstrap = false;
        }
        if state.applied_revision != expected
            || state.requested_revision != expected
            || expected.checked_add(1) != Some(revision)
        {
            return self.reply(&mut state, RamControlDisposition::RevisionConflict);
        }
        if validate_infrastructure(&policy.budgets, state.outer).is_err() {
            return self.reply(&mut state, RamControlDisposition::AdmissionRefused);
        }
        let Some(owner) = state.owner.clone() else {
            return self.reply(&mut state, RamControlDisposition::Unavailable);
        };
        if resources.resident_peak_bytes != state.resources.resident_peak_bytes
            || resources.backing_peak_bytes != state.resources.backing_peak_bytes
            || resources.cpu_slots != state.resources.cpu_slots
            || resources.task_slots != state.resources.task_slots
            || resources.file_descriptors != state.resources.file_descriptors
            || !(state.reservation_revision.checked_add(1) == Some(reservation)
                || (resources == state.resources && reservation == state.reservation_revision))
        {
            return self.reply(&mut state, RamControlDisposition::AdmissionRefused);
        }
        if owner.admit_resource_policy(&policy, &resources).is_err() {
            return self.reply(&mut state, RamControlDisposition::Unsupported);
        }

        // Publish the requested roster before scheduling: the engine's original
        // operation token must observe these budgets. Exclusive admission keeps
        // another Apply or fork from overtaking the effectful transition.
        state.policy_applying = true;
        state.budgets = policy.budgets;
        state.policy = Some(policy);
        state.requested_revision = revision;
        drop(state);
        let applied = owner.apply_resource_policy(&policy, &resources, revision);

        // Scheduling enters the same live budget factory. Holding state across
        // that call would deadlock; publication instead checks retained authority
        // after the effect, and uncertain failures quarantine the owner.
        let Ok(mut state) = self.state.lock() else {
            return self.unavailable();
        };
        let current = state.policy_applying
            && state.requested_revision == revision
            && state.applied_revision == expected
            && state
                .owner
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &owner));
        state.policy_applying = false;
        if !current || applied.is_err() {
            state.failed = true;
            return self.reply(&mut state, RamControlDisposition::Unavailable);
        }
        state.resources = resources;
        if policy.mode == RamControlMode::Managed {
            state.applied_revision = revision;
        }
        state.reservation_revision = reservation;
        self.reply(&mut state, RamControlDisposition::Accepted)
    }

    fn status(&self) -> RamControlReply {
        let Ok(mut state) = self.state.try_lock() else {
            return self.unavailable();
        };
        self.reply(&mut state, RamControlDisposition::Accepted)
    }

    fn performance(
        &self,
        action: crucible_qemu_protocol::ram_control::RamControlPerformanceAction,
    ) -> RamControlReply {
        use crucible_qemu_protocol::ram_control::RamControlPerformanceAction;
        let (owner, mut dispatch) = {
            let Ok(mut state) = self.state.try_lock() else {
                return self.unavailable();
            };
            if state.fork_preparing
                || state.policy_applying
                || state.checkpoint_producer_held(&self.state, &self.operations)
            {
                return self.reply(&mut state, RamControlDisposition::Unavailable);
            }
            // Reading or closing an existing diagnostic interval remains possible
            // after failure. It neither revives paging nor admits new storage.
            if action == RamControlPerformanceAction::Start {
                if state.outer.is_some_and(|cap| outer_remaining(cap).is_err()) {
                    state.outer_expired = true;
                }
                if state.failed
                    || state.outer_expired
                    || self.canceled.load(Ordering::Acquire)
                    || (state.child_bootstrap && (self.child_runtime_ready)() != 1)
                {
                    return self.reply(&mut state, RamControlDisposition::Unavailable);
                }
            }
            let Some(owner) = state.owner.as_ref().cloned() else {
                return self.reply(&mut state, RamControlDisposition::Unavailable);
            };
            let Ok(dispatch) = capture::work::PerformanceDispatch::begin(self.operations.clone())
            else {
                return self.reply(&mut state, RamControlDisposition::Unavailable);
            };
            (owner, dispatch)
        };
        let result = owner.performance(action);
        if result.is_ok() {
            dispatch.settle();
        }
        let Ok(mut state) = self.state.try_lock() else {
            return self.unavailable();
        };
        if !state
            .owner
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &owner))
        {
            return self.unavailable();
        }
        let mut reply = self.reply(
            &mut state,
            if result.is_ok() {
                RamControlDisposition::Accepted
            } else {
                RamControlDisposition::AdmissionRefused
            },
        );
        reply.performance = result.ok().flatten();
        reply
    }

    fn inventory_region(&self, generation: u64, ordinal: u32) -> RamControlReply {
        let Ok(mut state) = self.state.try_lock() else {
            return self.unavailable();
        };
        let region = state
            .inventory
            .as_ref()
            .filter(|inventory| inventory.report.topology_generation == generation)
            .and_then(|inventory| inventory.regions.get(ordinal as usize))
            .copied();
        let mut reply = self.reply(
            &mut state,
            if region.is_some() {
                RamControlDisposition::Accepted
            } else {
                RamControlDisposition::NotCurrent
            },
        );
        reply.inventory_region = region;
        reply
    }

    fn grant_inventory(
        &self,
        generation: u64,
        grant: RamControlResources,
        spill_quota: u64,
    ) -> RamControlReply {
        let Ok(mut state) = self.state.try_lock() else {
            return self.unavailable();
        };
        let initial = state.resources;
        let Some(inventory) = state.inventory.as_ref() else {
            return self.reply(&mut state, RamControlDisposition::Unavailable);
        };
        let minimum_metadata = inventory
            .report
            .native_metadata_bytes
            .checked_add(inventory.report.rust_metadata_required_bytes);
        let minimum_scratch = inventory.report.native_scratch_bytes;
        let minimum_spill = inventory
            .regions
            .iter()
            .try_fold(0_u64, |total, region| {
                let padded = region
                    .logical_length
                    .checked_add(super::PAGE_BYTES as u64 - 1)?
                    / super::PAGE_BYTES as u64
                    * super::PAGE_BYTES as u64;
                total.checked_add(padded)
            })
            .and_then(|padded| padded.checked_mul(2));
        let valid = inventory.report.rust_metadata_required_bytes > 0
            && minimum_spill.is_some_and(|minimum| spill_quota == minimum)
            && spill_quota > 0
            && spill_quota <= grant.backing_peak_bytes
            && spill_quota >= inventory.report.logical_bytes
            && generation == inventory.report.topology_generation
            && inventory.grant.is_none()
            && !inventory.report.granted
            && state.applied_revision == 0
            && grant.resident_peak_bytes == initial.resident_peak_bytes
            && grant.backing_peak_bytes == initial.backing_peak_bytes
            && grant.paging_io_slots == initial.paging_io_slots
            && grant.cpu_slots == initial.cpu_slots
            && grant.task_slots == initial.task_slots
            && grant.file_descriptors == initial.file_descriptors
            && grant.metadata_bytes >= initial.metadata_bytes
            && minimum_metadata.is_some_and(|minimum| grant.metadata_bytes >= minimum)
            && grant.staging_bytes >= initial.staging_bytes
            && grant.staging_bytes >= minimum_scratch
            && inventory
                .report
                .owner_resources
                .existing_tasks
                .checked_add(inventory.report.owner_resources.prospective_tasks)
                .is_some_and(|tasks| tasks <= grant.task_slots)
            && inventory
                .report
                .owner_resources
                .existing_file_descriptors
                .checked_add(
                    inventory
                        .report
                        .owner_resources
                        .prospective_file_descriptors,
                )
                .is_some_and(|fds| fds <= grant.file_descriptors)
            && grant
                .metadata_bytes
                .checked_add(grant.staging_bytes)
                .is_some_and(|bytes| bytes <= grant.resident_peak_bytes);
        if !valid {
            return self.reply(&mut state, RamControlDisposition::AdmissionRefused);
        }
        if let Some(inventory) = state.inventory.as_mut() {
            inventory.grant = Some((grant, spill_quota));
        }
        self.reply(&mut state, RamControlDisposition::Accepted)
    }

    fn sync_outer_cap(&self, cap: RamControlOuterCap) -> RamControlReply {
        let Ok(mut state) = self.state.try_lock() else {
            return self.unavailable();
        };
        let Some(current) = state.outer else {
            return self.reply(&mut state, RamControlDisposition::AdmissionRefused);
        };
        if current.cap_id != cap.cap_id
            || current.original_monotonic_ns != cap.original_monotonic_ns
            || cap.validate().is_err()
        {
            return self.reply(&mut state, RamControlDisposition::NotCurrent);
        }
        if cap == current {
            return self.reply(&mut state, RamControlDisposition::Accepted);
        }
        if cap.revision == current.revision
            && cap.allowance_ns == current.allowance_ns
            && current.state == RamControlOuterState::Running
            && cap.state != RamControlOuterState::Running
        {
            state.outer = Some(cap);
            state.outer_expired = true;
            return self.reply(&mut state, RamControlDisposition::Accepted);
        }
        if current.revision.checked_add(1) != Some(cap.revision) {
            return self.reply(&mut state, RamControlDisposition::NotCurrent);
        }
        if outer_remaining(current).is_err() {
            state.outer_expired = true;
        }
        if state.outer_expired || current.state != RamControlOuterState::Running {
            return self.reply(&mut state, RamControlDisposition::AdmissionRefused);
        }
        if validate_infrastructure(&state.budgets, Some(cap)).is_err()
            && cap.state == RamControlOuterState::Running
        {
            return self.reply(&mut state, RamControlDisposition::AdmissionRefused);
        }
        state.outer = Some(cap);
        if cap.state != RamControlOuterState::Running || outer_remaining(cap).is_err() {
            state.outer_expired = true;
        }
        self.reply(&mut state, RamControlDisposition::Accepted)
    }

    fn test_fault_actor(
        &self,
        entitlement: [u8; 32],
        worker_generation: u64,
        action: RamControlFaultActorAction,
    ) -> RamControlReply {
        self.dispatch_fault_actor_test(entitlement, worker_generation, action)
    }

    fn cancel(&self, generation: u64) -> RamControlReply {
        let Ok(mut state) = self.state.try_lock() else {
            return self.unavailable();
        };
        if generation != self.target.arena_generation {
            return self.reply(&mut state, RamControlDisposition::NotCurrent);
        }
        self.canceled.store(true, Ordering::Release);
        self.reply(&mut state, RamControlDisposition::Canceled)
    }
}

fn outer_remaining(cap: RamControlOuterCap) -> io::Result<Option<Duration>> {
    outer_remaining_for::<false>(cap).map_err(ObservationOperationError::into_io)
}

fn outer_remaining_for<const BORROWED: bool>(
    cap: RamControlOuterCap,
) -> Result<Option<Duration>, ObservationOperationError> {
    if cap.state != RamControlOuterState::Running {
        return Err(ObservationOperationError::static_error::<BORROWED>(
            if cap.state == RamControlOuterState::Canceled {
                io::ErrorKind::Interrupted
            } else {
                io::ErrorKind::TimedOut
            },
            "RAM outer cap terminal",
        ));
    }
    let Some(allowance) = cap.allowance_ns else {
        return Ok(None);
    };
    let deadline = cap
        .original_monotonic_ns
        .checked_add(allowance)
        .ok_or_else(|| {
            ObservationOperationError::static_error::<BORROWED>(
                io::ErrorKind::Other,
                "RAM outer deadline overflow",
            )
        })?;
    let remaining = deadline
        .checked_sub(super::supervision::monotonic_ns_for::<BORROWED>()?)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| {
            ObservationOperationError::static_error::<BORROWED>(
                io::ErrorKind::TimedOut,
                "RAM original-start cap expired",
            )
        })?;
    Ok(Some(Duration::from_nanos(remaining)))
}

struct LiveOperation {
    state: Arc<Mutex<State>>,
    canceled: Arc<AtomicBool>,
    operations: Arc<capture::work::OperationRegistry>,
    class: usize,
    started: OperationalStart,
    progress: Mutex<OperationProgress>,
    terminal: AtomicU8,
    tracked: bool,
    admitted: AtomicBool,
}

struct OperationProgress {
    completed_units: u64,
    last_completed: OperationalStart,
}

impl LivePagerController {
    // The same admission orders both ordinary boxed operations and a native
    // record's caller-funded inline operation against the policy cut.
    fn begin_inline<const BORROWED: bool>(
        &self,
        class: SourceOperationClass,
    ) -> Result<LiveOperation, ObservationOperationError> {
        let class = match class {
            SourceOperationClass::ControlSetup => 0,
            SourceOperationClass::Cleanup => 13,
            SourceOperationClass::PageIn => 2,
            SourceOperationClass::Writeback => 3,
            SourceOperationClass::FingerprintInitialization => 4,
            SourceOperationClass::FingerprintUpdate => 5,
            SourceOperationClass::Quiescence => 6,
            SourceOperationClass::ForkRearm => 10,
        };
        {
            let mut state = self.state.lock().map_err(|_| {
                ObservationOperationError::static_error::<BORROWED>(
                    io::ErrorKind::Other,
                    "RAM operation admission poisoned",
                )
            })?;
            if class != 0
                && class != 13
                && state.checkpoint_producer_held(&self.state, &self.operations)
            {
                return Err(if BORROWED {
                    ObservationOperationError::Static {
                        kind: io::ErrorKind::WouldBlock,
                        message: "checkpoint retains operation admission",
                    }
                } else {
                    ObservationOperationError::Io(io::Error::from_raw_os_error(libc::EBUSY))
                });
            }
            // The same lock orders this actual token admission against the
            // checkpoint policy cut. Already admitted work may still settle.
            self.operations
                .capacity
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < MAX_OPERATIONS).then_some(count + 1)
                })
                .map_err(|_| {
                    ObservationOperationError::static_error::<BORROWED>(
                        io::ErrorKind::Other,
                        "RAM operation slots exhausted",
                    )
                })?;
            if class != 0 && class != 13 {
                self.operations.start();
            }
        }
        let started = OperationalStart::begin();
        let operation = LiveOperation {
            state: self.state.clone(),
            canceled: self.canceled.clone(),
            operations: self.operations.clone(),
            class,
            started,
            progress: Mutex::new(OperationProgress {
                completed_units: 0,
                last_completed: started,
            }),
            terminal: AtomicU8::new(0),
            tracked: class != 0 && class != 13,
            admitted: AtomicBool::new(false),
        };
        // A borrowed record stores this actual clock and owner before its
        // first fallible supervision cut. The ordinary boxed factory preserves
        // its historical initial check before returning the operation.
        if !BORROWED {
            operation
                .wait_slice()
                .map_err(ObservationOperationError::Io)?;
        }
        Ok(operation)
    }
}

impl SourceOperationFactory for LivePagerController {
    fn begin(&self, class: SourceOperationClass) -> io::Result<Box<dyn SourceOperation>> {
        let operation = self
            .begin_inline::<false>(class)
            .map_err(ObservationOperationError::into_io)?;
        Ok(Box::new(operation))
    }
}

impl LiveOperation {
    fn progress_for_observation(
        &self,
        completed_units: u64,
    ) -> Result<(), ObservationOperationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ObservationOperationError::Static {
                kind: io::ErrorKind::Other,
                message: "fingerprint progress ownership poisoned",
            })?;
        self.current_slice_for::<true>(&mut state)?;
        let mut progress = self
            .progress
            .lock()
            .map_err(|_| ObservationOperationError::Static {
                kind: io::ErrorKind::Other,
                message: "fingerprint progress counter poisoned",
            })?;
        if completed_units <= progress.completed_units {
            return Err(ObservationOperationError::Static {
                kind: io::ErrorKind::InvalidInput,
                message: "fingerprint completed units did not increase",
            });
        }
        progress.completed_units = completed_units;
        progress.last_completed = OperationalStart::begin();
        Ok(())
    }

    fn current_slice(&self, state: &mut State) -> io::Result<Duration> {
        self.current_slice_for::<false>(state)
            .map_err(ObservationOperationError::into_io)
    }

    fn current_slice_for<const BORROWED: bool>(
        &self,
        state: &mut State,
    ) -> Result<Duration, ObservationOperationError> {
        match self.terminal.load(Ordering::Acquire) {
            0 => {}
            2 => {
                return Err(ObservationOperationError::static_error::<BORROWED>(
                    io::ErrorKind::TimedOut,
                    "RAM operation already expired",
                ));
            }
            3 => {
                return Err(ObservationOperationError::static_error::<BORROWED>(
                    io::ErrorKind::Interrupted,
                    "RAM operation already canceled",
                ));
            }
            _ => {
                return Err(ObservationOperationError::static_error::<BORROWED>(
                    io::ErrorKind::Other,
                    "RAM operation already disposed",
                ));
            }
        }
        if self.class != 0 && self.class != 13 && self.canceled.load(Ordering::Acquire) {
            self.terminal.store(3, Ordering::Release);
            return Err(ObservationOperationError::static_error::<BORROWED>(
                io::ErrorKind::Interrupted,
                "RAM operation canceled",
            ));
        }
        // Failed guest-work authority still permits the bounded independent
        // control reader to report failure and dispose its retained endpoint.
        if state.failed && self.class != 13 {
            self.terminal.store(4, Ordering::Release);
            return Err(ObservationOperationError::static_error::<BORROWED>(
                io::ErrorKind::Other,
                "RAM authority failed",
            ));
        }
        let outer = if self.class == 13 {
            None
        } else if let Some(cap) = state.outer {
            if state.outer_expired {
                self.terminal.store(2, Ordering::Release);
                return Err(ObservationOperationError::static_error::<BORROWED>(
                    io::ErrorKind::TimedOut,
                    "RAM original-start cap already terminal",
                ));
            }
            match outer_remaining_for::<BORROWED>(cap) {
                Ok(remaining) => remaining,
                Err(error) => {
                    state.outer_expired = true;
                    self.terminal.store(2, Ordering::Release);
                    return Err(error);
                }
            }
        } else {
            None
        };
        let budget = state.budgets[self.class];
        let progress_elapsed = self
            .progress
            .lock()
            .map_err(|_| {
                ObservationOperationError::static_error::<BORROWED>(
                    io::ErrorKind::Other,
                    "RAM work progress poisoned",
                )
            })?
            .last_completed
            .elapsed();
        let mut slice = Duration::from_nanos(budget.poll_ns);
        if let Some(remaining) = outer {
            slice = slice.min(remaining);
        }
        for (allowance, elapsed) in [
            (budget.total_ns, self.started.elapsed()),
            (budget.progress_ns, progress_elapsed),
        ]
        .into_iter()
        .filter_map(|(allowance, elapsed)| allowance.map(|allowance| (allowance, elapsed)))
        {
            let remaining = remaining_allowance_ns(allowance, elapsed).ok_or_else(|| {
                self.terminal.store(2, Ordering::Release);
                ObservationOperationError::static_error::<BORROWED>(
                    io::ErrorKind::TimedOut,
                    "RAM operation allowance expired",
                )
            })?;
            slice = slice.min(remaining);
        }
        if slice.is_zero() {
            return Err(ObservationOperationError::static_error::<BORROWED>(
                io::ErrorKind::TimedOut,
                "RAM polling allowance expired",
            ));
        }
        self.admitted.store(true, Ordering::Release);
        Ok(slice)
    }
}

impl SourceOperation for LiveOperation {
    fn retain_checkpoint_work(
        self: Arc<Self>,
        admission: &mut CheckpointWorkAdmission<'_>,
    ) -> Result<HeldCheckpointWork, RamError> {
        admission.retain(self)
    }

    fn matches_checkpoint_work(&self, admission: &CheckpointWorkAdmission<'_>) -> bool {
        admission.matches(self)
    }

    fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ObservationOperationError::Static {
                kind: io::ErrorKind::Other,
                message: "RAM budget ownership poisoned",
            })?;
        self.current_slice_for::<true>(&mut state)
    }

    fn complete_observation(&self) -> Result<(), ObservationOperationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ObservationOperationError::Static {
                kind: io::ErrorKind::Other,
                message: "RAM budget ownership poisoned",
            })?;
        self.current_slice_for::<true>(&mut state)?;
        if self
            .terminal
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ObservationOperationError::Static {
                kind: io::ErrorKind::Other,
                message: "RAM operation already completed",
            });
        }
        if self.tracked {
            self.operations.finish(false);
        }
        Ok(())
    }

    fn wait_slice(&self) -> io::Result<Duration> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("RAM budget ownership poisoned"))?;
        self.current_slice(&mut state)
    }

    fn progress(&self, cumulative_completed_units: u64) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("RAM budget ownership poisoned"))?;
        self.current_slice(&mut state)?;
        let mut progress = self
            .progress
            .lock()
            .map_err(|_| io::Error::other("RAM work progress poisoned"))?;
        if cumulative_completed_units <= progress.completed_units {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RAM completed work must strictly increase",
            ));
        }
        progress.completed_units = cumulative_completed_units;
        progress.last_completed = OperationalStart::begin();
        Ok(())
    }

    fn complete(&self) -> io::Result<()> {
        // Completion shares the same short operational lock as policy updates
        // and cancellation. No allowance can change between check and commit.
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("RAM budget ownership poisoned"))?;
        self.current_slice(&mut state)?;
        if self
            .terminal
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(io::Error::other("RAM operation already completed"));
        }
        if self.tracked {
            self.operations.finish(false);
        }
        Ok(())
    }
}

impl Drop for LiveOperation {
    fn drop(&mut self) {
        if self.tracked && self.terminal.load(Ordering::Acquire) != 1 {
            self.operations
                .finish(self.admitted.load(Ordering::Acquire));
        }
        self.operations.capacity.fetch_sub(1, Ordering::AcqRel);
    }
}

fn symbol(name: &'static [u8]) -> Result<*mut c_void, RamError> {
    // SAFETY: callers provide static NUL-terminated names from matching native ABI.
    let pointer = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr().cast()) };
    if pointer.is_null() {
        Err(RamError::MissingSymbol(name))
    } else {
        Ok(pointer)
    }
}

#[cfg(test)]
mod tests;
