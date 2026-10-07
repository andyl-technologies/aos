//! Bounded, revisioned operational supervision shared by host components.
//!
//! Host clocks and revisions never become guest time or semantic identities.
//! Each guard retains its original start and meaningful-progress coordinate.
//! Policy updates and outer-cap amendments wake all waiting guards. Completing
//! work checks deadlines under the same lock as amendment and cancellation.
//! Persistent control owners must journal requests before calling mutation
//! methods and retain uncertain ownership after a failed durable commit.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use self::deadline::{OperationDecision, decide_operation, operation_status_from_decision};

mod deadline;

/// Number of classes in the fixed operational budget roster.
pub const HOST_OPERATION_CLASS_COUNT: usize = 14;

/// Maximum concurrently owned operations in one execution supervisor.
pub const MAX_HOST_OPERATIONS: usize = 12;

// Keep two representable records available for finite control and containment
// while paging or checkpoint work has consumed its entire admitted inventory.
const MAX_HOST_WORK_OPERATIONS: usize = MAX_HOST_OPERATIONS - 2;

static NEXT_CAP_ID: AtomicU64 = AtomicU64::new(1);

/// One host operation whose completion cannot change guest virtual time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum HostOperationClass {
    /// Plugin and control transport setup.
    Setup = 0,
    /// One deterministic guest execution boundary.
    Quantum = 1,
    /// Authentication and installation of one missing page generation.
    PageIn = 2,
    /// Preservation of one selected dirty page generation.
    Writeback = 3,
    /// Construction of a complete initial RAM tree.
    FingerprintInitialization = 4,
    /// Update of a coherent incremental RAM tree.
    FingerprintUpdate = 5,
    /// Establishment of a coherent pause boundary.
    Quiescence = 6,
    /// Capture of an immutable exact closure.
    CheckpointCapture = 7,
    /// Durable publication of an exact closure.
    CheckpointPublication = 8,
    /// Authentication and installation of restored state.
    Restore = 9,
    /// Fork placement, repair, and readiness barriers.
    ForkRearm = 10,
    /// Copy of authenticated missing closure objects.
    Transfer = 11,
    /// Preparation of locally retained executable state.
    Preparation = 12,
    /// Cancellation, disposition, and reap under retained ownership.
    Cleanup = 13,
}

impl HostOperationClass {
    /// Returns the canonical class roster in wire order.
    pub const ALL: [Self; HOST_OPERATION_CLASS_COUNT] = [
        Self::Setup,
        Self::Quantum,
        Self::PageIn,
        Self::Writeback,
        Self::FingerprintInitialization,
        Self::FingerprintUpdate,
        Self::Quiescence,
        Self::CheckpointCapture,
        Self::CheckpointPublication,
        Self::Restore,
        Self::ForkRearm,
        Self::Transfer,
        Self::Preparation,
        Self::Cleanup,
    ];
}

/// Polling, lack-of-progress, and total allowances for one operation class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostOperationBudget {
    /// Maximum polling slice; expiration only yields to operational control.
    pub poll_interval: Duration,
    /// Maximum time since meaningful completion progress, when configured.
    pub progress_timeout: Option<Duration>,
    /// Maximum time since original operation entry, when configured.
    pub total_timeout: Option<Duration>,
}

impl HostOperationBudget {
    /// Returns a finite infrastructure budget with independent short polling.
    pub const fn finite(total: Duration) -> Self {
        Self {
            poll_interval: Duration::from_millis(10),
            progress_timeout: None,
            total_timeout: Some(total),
        }
    }

    /// Returns an unlimited guest quantum with responsive host polling.
    pub const fn unlimited_quantum() -> Self {
        Self {
            poll_interval: Duration::from_millis(10),
            progress_timeout: None,
            total_timeout: None,
        }
    }

    fn validate(
        self,
        class: HostOperationClass,
        finite_outer: bool,
    ) -> Result<(), HostSupervisionError> {
        if self.poll_interval.is_zero()
            || self
                .progress_timeout
                .is_some_and(|duration| duration.is_zero())
            || self
                .total_timeout
                .is_some_and(|duration| duration.is_zero())
            || host_now().checked_add(self.poll_interval).is_none()
            || self
                .progress_timeout
                .is_some_and(|duration| host_now().checked_add(duration).is_none())
            || self
                .total_timeout
                .is_some_and(|duration| host_now().checked_add(duration).is_none())
        {
            return Err(HostSupervisionError::InvalidBudget);
        }
        if class != HostOperationClass::Quantum
            && self.progress_timeout.is_none()
            && self.total_timeout.is_none()
            && (!finite_outer || class == HostOperationClass::Cleanup)
        {
            return Err(HostSupervisionError::UnboundedInfrastructure { class });
        }
        Ok(())
    }
}

/// Fixed operation-class budget roster, excluded from modeled configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostOperationBudgets {
    /// One budget for each class in canonical class order.
    pub classes: [HostOperationBudget; HOST_OPERATION_CLASS_COUNT],
}

impl Default for HostOperationBudgets {
    fn default() -> Self {
        let mut classes =
            [HostOperationBudget::finite(Duration::from_secs(30)); HOST_OPERATION_CLASS_COUNT];
        classes[HostOperationClass::Quantum as usize] = HostOperationBudget::unlimited_quantum();
        Self { classes }
    }
}

impl HostOperationBudgets {
    /// Returns the budget for a class.
    pub const fn get(&self, class: HostOperationClass) -> HostOperationBudget {
        self.classes[class as usize]
    }

    /// Validates finite infrastructure and independent cleanup bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for zero allowances or an infrastructure class without
    /// a finite class allowance or applicable finite outer cap.
    pub fn validate(&self, finite_outer: bool) -> Result<(), HostSupervisionError> {
        for class in HostOperationClass::ALL {
            self.get(class).validate(class, finite_outer)?;
        }
        Ok(())
    }
}

/// Terminal operational disposition; no variant is a guest outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostOperationState {
    /// Work remains under live operational ownership.
    Running,
    /// Authenticated work completed before its applicable deadline.
    Completed,
    /// A host allowance elapsed.
    Expired,
    /// Sticky operational cancellation stopped continuation.
    Canceled,
}

/// Source of an operation's effective limiting deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostDeadlineSource {
    /// Lack-of-progress allowance from the named class policy revision.
    Progress(u64),
    /// Total allowance from the named class policy revision.
    Total(u64),
    /// Original-start outer cap at the named revision.
    Outer {
        /// Exact independently registered operational cap identity.
        cap_id: [u8; 32],
        /// Current original-start cap revision.
        revision: u64,
    },
}

/// Closed kind of meaningful completed work used by operational evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HostProgressKind {
    /// One validated finite protocol or ownership phase.
    ValidatedPhase = 0,
    /// A validated deterministic execution boundary.
    GuestBoundary = 1,
    /// One authenticated installed page generation.
    AuthenticatedPage = 2,
    /// One safely preserved dirty page generation.
    PreservedPage = 3,
    /// One required logical leaf or subtree.
    MerkleLeaf = 4,
    /// One required authenticated or durably published closure object.
    DurableObject = 5,
    /// One authenticated fork placement or repair barrier.
    ForkBarrier = 6,
}

/// Coherent effective deadline including every tied limiting source.
#[derive(Debug, PartialEq, Eq)]
pub struct HostEffectiveDeadline {
    /// Remaining operational allowance; zero means elapsed.
    pub remaining: Duration,
    /// Bounded sources whose allowance equals the earliest deadline.
    pub sources: Vec<HostDeadlineSource>,
}

/// Coherent operational status of one original-start operation.
#[derive(Debug, PartialEq, Eq)]
pub struct HostOperationStatus {
    /// Nonreused operation identity within this supervisor incarnation.
    pub operation_id: u64,
    /// Fixed operation class.
    pub class: HostOperationClass,
    /// Policy revision at operation entry.
    pub started_policy_revision: u64,
    /// Latest live policy revision used for deadline evaluation.
    pub applied_policy_revision: u64,
    /// Monotonic count of completed required work, excluding retries.
    pub completed_work_units: u64,
    /// Required units remaining in the selected operation's work inventory.
    pub outstanding_work_units: u64,
    /// Meaning of the monotonic completed and required work units.
    pub progress_kind: HostProgressKind,
    /// Current operational disposition.
    pub state: HostOperationState,
    /// Earliest deadline, or no deadline for explicitly unlimited execution.
    pub effective_deadline: Option<HostEffectiveDeadline>,
}

/// Revisioned original-start outer-cap status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostOuterCapStatus {
    /// Current nonreused operational revision.
    pub revision: u64,
    /// Allowance measured from the supervisor's immutable original start.
    pub allowance: Option<Duration>,
    /// Remaining allowance, with zero meaning elapsed and none unbounded.
    pub remaining: Option<Duration>,
    /// Sticky cap disposition.
    pub state: HostOperationState,
}

/// Session-local original cap binding in the shared kernel monotonic clock.
///
/// A binding is valid only for the authenticated local Unix session. Its
/// absolute origin is never copied into guest state or another host's clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostOuterCapBinding {
    /// Exact existing original-start outer authority.
    pub cap_id: [u8; 32],
    /// Conservatively sampled immutable CLOCK_MONOTONIC origin in nanoseconds.
    pub original_monotonic_ns: u64,
    /// Current independent cap revision.
    pub revision: u64,
    /// Allowance measured from the immutable origin, or deliberate unboundedness.
    pub allowance: Option<Duration>,
    /// Sticky terminal disposition observed with this revision.
    pub state: HostOperationState,
}

/// Typed operational refusal or failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HostSupervisionError {
    /// A configured duration was zero.
    #[error("invalid host operation budget")]
    InvalidBudget,
    /// An infrastructure phase lost its last finite applicable allowance.
    #[error("unbounded host infrastructure phase {class:?}")]
    UnboundedInfrastructure {
        /// Class that lacks a finite bound.
        class: HostOperationClass,
    },
    /// The caller used a stale policy or cap revision.
    #[error("host policy revision conflict: current {current}")]
    RevisionConflict {
        /// Current revision to use for a separately authorized new request.
        current: u64,
    },
    /// Terminal work cannot be resumed by an amendment.
    #[error("host operation is terminal: {state:?}")]
    Terminal {
        /// Sticky terminal disposition.
        state: HostOperationState,
    },
    /// An operation deadline expired.
    #[error("host operation {operation_id} ({class:?}) expired")]
    DeadlineExpired {
        /// Original operation identity.
        operation_id: u64,
        /// Operation class.
        class: HostOperationClass,
    },
    /// Maximum simultaneous operations was reached.
    #[error("host operation capacity exhausted")]
    CapacityExhausted,
    /// A revision or identity would wrap.
    #[error("host supervision identity exhausted")]
    IdentityExhausted,
    /// A supposedly monotonic meaningful-progress count decreased.
    #[error("host operation progress regressed")]
    ProgressRegressed,
    /// Synchronization ownership is uncertain after a panic.
    #[error("host supervision ownership is poisoned")]
    Unavailable,
}

#[derive(Debug)]
struct Operation {
    class: HostOperationClass,
    control: bool,
    started: Duration,
    last_progress: Duration,
    started_revision: u64,
    completed: u64,
    required: u64,
    state: HostOperationState,
}

#[derive(Debug)]
struct SupervisionState {
    cap_id: [u8; 32],
    budgets: HostOperationBudgets,
    policy_revision: u64,
    cap_revision: u64,
    cap_allowance: Option<Duration>,
    cap_state: HostOperationState,
    next_operation: u64,
    operations: BTreeMap<u64, Operation>,
}

#[derive(Debug)]
struct Shared {
    started: Instant,
    original_monotonic_ns: u64,
    cap_id: [u8; 32],
    state: Mutex<SupervisionState>,
    changed: Arc<Condvar>,
    outer: Arc<Mutex<OuterAuthority>>,
    budget_owner: u64,
}

#[derive(Debug)]
struct OuterAuthority {
    root_wakeup: Arc<Condvar>,
    revision: u64,
    allowance: Option<Duration>,
    state: HostOperationState,
    next_owner: u64,
    rosters: BTreeMap<u64, (HostOperationBudgets, Option<Weak<Shared>>)>,
}

/// Clone-shared runtime supervision with independently wakeable host control.
#[derive(Clone, Debug)]
pub struct HostOperationSupervisor {
    shared: Arc<Shared>,
}

impl PartialEq for HostOperationSupervisor {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }
}

impl Eq for HostOperationSupervisor {}

impl HostOperationSupervisor {
    /// Starts operational supervision with immutable elapsed-time coordinates.
    ///
    /// # Errors
    ///
    /// Returns an error if a class loses its finite infrastructure bound or a
    /// present outer allowance is zero.
    pub fn new(
        budgets: HostOperationBudgets,
        outer: Option<Duration>,
    ) -> Result<Self, HostSupervisionError> {
        if outer.is_some_and(|duration| {
            duration.is_zero() || host_now().checked_add(duration).is_none()
        }) {
            return Err(HostSupervisionError::InvalidBudget);
        }
        budgets.validate(outer.is_some())?;
        let ordinal = NEXT_CAP_ID
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |ordinal| {
                ordinal.checked_add(1)
            })
            .map_err(|_| HostSupervisionError::IdentityExhausted)?;
        let mut cap_id = [0; 32];
        cap_id[24..].copy_from_slice(&ordinal.to_be_bytes());
        let changed = Arc::new(Condvar::new());
        // Sampling before the Instant origin cannot extend the native cap.
        let original_monotonic_ns = kernel_monotonic_ns()?;
        Ok(Self {
            shared: Arc::new(Shared {
                started: host_now(),
                original_monotonic_ns,
                cap_id,
                state: Mutex::new(SupervisionState {
                    cap_id,
                    budgets,
                    policy_revision: 0,
                    cap_revision: 0,
                    cap_allowance: outer,
                    cap_state: HostOperationState::Running,
                    next_operation: 0,
                    operations: BTreeMap::new(),
                }),
                changed: Arc::clone(&changed),
                budget_owner: 0,
                outer: Arc::new(Mutex::new(OuterAuthority {
                    root_wakeup: changed,
                    revision: 0,
                    allowance: outer,
                    state: HostOperationState::Running,
                    next_owner: 0,
                    rosters: BTreeMap::from([(0, (budgets, None))]),
                })),
            }),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, SupervisionState>, HostSupervisionError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let mut outer = self
            .shared
            .outer
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if outer.state == HostOperationState::Running
            && outer
                .allowance
                .is_some_and(|allowance| self.elapsed() >= allowance)
        {
            outer.state = HostOperationState::Expired;
        }
        state.cap_revision = outer.revision;
        state.cap_allowance = outer.allowance;
        state.cap_state = outer.state;
        drop(outer);
        Ok(state)
    }

    /// Creates an independent node budget roster under the same original outer cap.
    ///
    /// Operations and policy revisions remain local to this owner. Cap start,
    /// identity, amendment revision, terminal disposition, and wakeups are shared.
    ///
    /// # Errors
    /// Refuses invalid finite bounds, terminal authority, owner-capacity
    /// exhaustion, or uncertain synchronization.
    pub fn new_budget_owner(
        &self,
        budgets: HostOperationBudgets,
    ) -> Result<Self, HostSupervisionError> {
        let state = self.lock()?;
        if state.cap_state != HostOperationState::Running {
            return Err(HostSupervisionError::Terminal {
                state: state.cap_state,
            });
        }
        budgets.validate(state.cap_allowance.is_some())?;
        let mut outer = self
            .shared
            .outer
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if outer.state == HostOperationState::Running
            && outer
                .allowance
                .is_some_and(|allowance| self.elapsed() >= allowance)
        {
            outer.state = HostOperationState::Expired;
        }
        if outer.state != HostOperationState::Running {
            return Err(HostSupervisionError::Terminal { state: outer.state });
        }
        budgets.validate(outer.allowance.is_some())?;
        outer
            .rosters
            .retain(|_, (_, owner)| owner.as_ref().is_none_or(|owner| owner.strong_count() != 0));
        if outer.rosters.len() >= 4096 {
            return Err(HostSupervisionError::CapacityExhausted);
        }
        let owner_id = outer
            .next_owner
            .checked_add(1)
            .ok_or(HostSupervisionError::IdentityExhausted)?;
        let shared = Arc::new(Shared {
            started: self.shared.started,
            original_monotonic_ns: self.shared.original_monotonic_ns,
            cap_id: self.shared.cap_id,
            state: Mutex::new(SupervisionState {
                cap_id: state.cap_id,
                budgets,
                policy_revision: 0,
                cap_revision: outer.revision,
                cap_allowance: outer.allowance,
                cap_state: outer.state,
                next_operation: 0,
                operations: BTreeMap::new(),
            }),
            changed: Arc::new(Condvar::new()),
            outer: Arc::clone(&self.shared.outer),
            budget_owner: owner_id,
        });
        outer.next_owner = owner_id;
        outer
            .rosters
            .insert(owner_id, (budgets, Some(Arc::downgrade(&shared))));
        Ok(Self { shared })
    }

    /// Reports whether two budget owners share the exact original outer authority.
    #[must_use]
    pub fn shares_outer_cap(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared.outer, &other.shared.outer)
    }

    fn notify_owners(&self) -> Result<(), HostSupervisionError> {
        let outer = self
            .shared
            .outer
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        outer.root_wakeup.notify_all();
        self.shared.changed.notify_all();
        for (_, owner) in outer.rosters.values() {
            if let Some(owner) = owner.as_ref().and_then(Weak::upgrade) {
                owner.changed.notify_all();
            }
        }
        Ok(())
    }

    fn elapsed(&self) -> Duration {
        host_now().saturating_duration_since(self.shared.started)
    }

    /// Begins one bounded operation under the current live class policy.
    ///
    /// # Errors
    ///
    /// Returns an error for terminal execution, an unbounded infrastructure
    /// phase, exhausted operation capacity, or uncertain synchronization.
    pub fn begin(
        &self,
        class: HostOperationClass,
    ) -> Result<HostOperationGuard, HostSupervisionError> {
        self.begin_work(class, 1)
    }

    /// Begins one operation with an explicit required-work inventory.
    ///
    /// # Errors
    ///
    /// Returns the same ownership, finite-bound, and capacity errors as
    /// [`Self::begin`], and refuses an empty work inventory.
    pub fn begin_work(
        &self,
        class: HostOperationClass,
        required_work_units: u64,
    ) -> Result<HostOperationGuard, HostSupervisionError> {
        self.begin_admitted(
            class,
            required_work_units,
            class == HostOperationClass::Cleanup,
        )
    }

    /// Begins an independent control exchange using reserved operation records.
    ///
    /// Setup retains its live class budget and original outer cap. Cleanup
    /// retains its finite class budget, including after outer-cap expiry.
    /// Work saturation cannot consume the two reserved control records.
    ///
    /// # Errors
    ///
    /// Refuses classes other than setup and cleanup, a terminal setup owner,
    /// exhausted control records, invalid bounds, or uncertain synchronization.
    pub fn begin_control(
        &self,
        class: HostOperationClass,
    ) -> Result<HostOperationGuard, HostSupervisionError> {
        if !matches!(
            class,
            HostOperationClass::Setup | HostOperationClass::Cleanup
        ) {
            return Err(HostSupervisionError::InvalidBudget);
        }
        self.begin_admitted(class, 1, true)
    }

    fn begin_admitted(
        &self,
        class: HostOperationClass,
        required_work_units: u64,
        control: bool,
    ) -> Result<HostOperationGuard, HostSupervisionError> {
        if required_work_units == 0 {
            return Err(HostSupervisionError::InvalidBudget);
        }
        let mut state = self.lock()?;
        let elapsed = self.elapsed();
        refresh_cap(&mut state, elapsed);
        if class != HostOperationClass::Cleanup && state.cap_state != HostOperationState::Running {
            return Err(HostSupervisionError::Terminal {
                state: state.cap_state,
            });
        }
        state
            .budgets
            .get(class)
            .validate(class, state.cap_allowance.is_some())?;
        let work_operations = state
            .operations
            .values()
            .filter(|operation| !operation.control)
            .count();
        if state.operations.len() >= MAX_HOST_OPERATIONS
            || (!control && work_operations >= MAX_HOST_WORK_OPERATIONS)
        {
            return Err(HostSupervisionError::CapacityExhausted);
        }
        let id = state
            .next_operation
            .checked_add(1)
            .ok_or(HostSupervisionError::IdentityExhausted)?;
        let revision = state.policy_revision;
        state.next_operation = id;
        state.operations.insert(
            id,
            Operation {
                class,
                control,
                started: elapsed,
                last_progress: elapsed,
                started_revision: revision,
                completed: 0,
                required: required_work_units,
                state: HostOperationState::Running,
            },
        );
        Ok(HostOperationGuard {
            supervisor: self.clone(),
            id,
        })
    }

    /// Returns this supervisor's exact nonreused operational cap identity.
    pub fn cap_id(&self) -> [u8; 32] {
        self.shared.cap_id
    }

    /// Applies class budgets to current operations without resetting their clocks.
    ///
    /// # Errors
    ///
    /// Returns an error for stale revision, invalid finite bounds, identity
    /// exhaustion, or uncertain synchronization.
    pub fn update_budgets(
        &self,
        expected_revision: u64,
        budgets: HostOperationBudgets,
    ) -> Result<u64, HostSupervisionError> {
        let mut state = self.lock()?;
        let mut outer = self
            .shared
            .outer
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        state.cap_allowance = outer.allowance;
        state.cap_state = outer.state;
        refresh_cap(&mut state, self.elapsed());
        outer.state = state.cap_state;
        if state.policy_revision != expected_revision {
            return Err(HostSupervisionError::RevisionConflict {
                current: state.policy_revision,
            });
        }
        budgets.validate(
            state.cap_allowance.is_some() && state.cap_state == HostOperationState::Running,
        )?;
        let revision = state
            .policy_revision
            .checked_add(1)
            .ok_or(HostSupervisionError::IdentityExhausted)?;
        state.budgets = budgets;
        state.policy_revision = revision;
        outer
            .rosters
            .get_mut(&self.shared.budget_owner)
            .ok_or(HostSupervisionError::Unavailable)?
            .0 = budgets;
        drop(outer);
        drop(state);
        self.notify_owners()?;
        Ok(revision)
    }

    /// Amends the outer allowance from its original start with expiry precedence.
    ///
    /// Authentication, exact owner generations, and durable bounded idempotency
    /// belong to the caller's operational control transaction. This primitive
    /// cannot revive elapsed or canceled authority even before a watcher runs.
    ///
    /// # Errors
    ///
    /// Returns an error for stale revision, terminal authority, loss of a finite
    /// infrastructure bound, invalid allowance, or uncertain synchronization.
    pub fn amend_outer_cap(
        &self,
        expected_revision: u64,
        allowance: Option<Duration>,
    ) -> Result<u64, HostSupervisionError> {
        let mut state = self.lock()?;
        let mut outer = self
            .shared
            .outer
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        state.cap_revision = outer.revision;
        state.cap_allowance = outer.allowance;
        state.cap_state = outer.state;
        refresh_cap(&mut state, self.elapsed());
        outer.state = state.cap_state;
        if state.cap_state != HostOperationState::Running {
            return Err(HostSupervisionError::Terminal {
                state: state.cap_state,
            });
        }
        if state.cap_revision != expected_revision {
            return Err(HostSupervisionError::RevisionConflict {
                current: state.cap_revision,
            });
        }
        if allowance.is_some_and(|duration| {
            duration.is_zero() || host_now().checked_add(duration).is_none()
        }) {
            return Err(HostSupervisionError::InvalidBudget);
        }
        for (budgets, _) in outer.rosters.values() {
            budgets.validate(allowance.is_some())?;
        }
        let revision = state
            .cap_revision
            .checked_add(1)
            .ok_or(HostSupervisionError::IdentityExhausted)?;
        state.cap_allowance = allowance;
        state.cap_revision = revision;
        refresh_cap(&mut state, self.elapsed());
        outer.allowance = state.cap_allowance;
        outer.revision = state.cap_revision;
        outer.state = state.cap_state;
        drop(outer);
        drop(state);
        self.notify_owners()?;
        Ok(revision)
    }

    /// Returns coherent cap status and atomically records an elapsed cap.
    ///
    /// # Errors
    ///
    /// Returns an error when synchronization ownership is uncertain.
    pub fn outer_cap_status(&self) -> Result<HostOuterCapStatus, HostSupervisionError> {
        self.status_snapshot().map(|(cap, _)| cap)
    }

    /// Returns coherent status for every bounded outstanding operation.
    ///
    /// # Errors
    ///
    /// Returns an error when synchronization ownership is uncertain.
    pub fn operation_statuses(&self) -> Result<Vec<HostOperationStatus>, HostSupervisionError> {
        self.status_snapshot().map(|(_, operations)| operations)
    }

    /// Supervises active work across all budget owners without charging idle time.
    ///
    /// This method creates no operation and therefore imposes no class deadline
    /// on an idle retained service. Policy changes and cancellation wake the
    /// bounded wait; outstanding work keeps its original operation clocks.
    ///
    /// # Errors
    /// Reports expired or canceled authority, an expired active operation, or
    /// uncertain synchronization.
    pub fn wait_for_active_work_change(&self) -> Result<(), HostSupervisionError> {
        self.check_active_work()?;
        let state = self.lock()?;
        let waited = self
            .shared
            .changed
            .wait_timeout(state, Duration::from_millis(10))
            .map_err(|_| HostSupervisionError::Unavailable)?;
        drop(waited);
        self.check_active_work()
    }

    fn check_active_work(&self) -> Result<(), HostSupervisionError> {
        let owners: Vec<Self> = self
            .shared
            .outer
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?
            .rosters
            .values()
            .filter_map(|(_, owner)| owner.as_ref().and_then(Weak::upgrade))
            .map(|shared| Self { shared })
            .collect();
        let cap = self.outer_cap_status()?;
        if cap.state != HostOperationState::Running {
            return Err(HostSupervisionError::Terminal { state: cap.state });
        }
        for status in self.operation_statuses()? {
            if status.state != HostOperationState::Completed {
                require_running(&status)?;
            }
        }
        for owner in owners {
            if owner == *self {
                continue;
            }
            for status in owner.operation_statuses()? {
                if status.state != HostOperationState::Completed {
                    require_running(&status)?;
                }
            }
        }
        Ok(())
    }

    /// Observes all local operations and their shared cap at one atomic boundary.
    ///
    /// # Errors
    /// Returns an error when either operational ownership lock is uncertain.
    pub fn status_snapshot(
        &self,
    ) -> Result<(HostOuterCapStatus, Vec<HostOperationStatus>), HostSupervisionError> {
        self.status_snapshot_with_elapsed(usize::MAX)
            .map(|(cap, _, operations)| (cap, operations))
    }

    /// Observes at most `maximum` operations without allocating a larger roster.
    ///
    /// Callers reserve the concrete status, identity and three-source deadline
    /// storage before calling. The ownership lock covers the count check and
    /// construction, so concurrent admissions cannot enlarge that snapshot.
    ///
    /// # Errors
    /// Refuses an oversized roster or uncertain ownership before allocation.
    pub fn status_snapshot_bounded(
        &self,
        maximum: usize,
    ) -> Result<(HostOuterCapStatus, Vec<HostOperationStatus>), HostSupervisionError> {
        self.status_snapshot_with_elapsed(maximum)
            .map(|(cap, _, operations)| (cap, operations))
    }

    /// Observes a session-local cap binding without resetting its original origin.
    ///
    /// Native receivers use the same host kernel clock, so transit delay cannot
    /// extend an allowance. Bindings must not cross hosts or Unix sessions.
    ///
    /// # Errors
    /// Refuses uncertain operational ownership or invalid active-operation status.
    pub fn outer_cap_binding(&self) -> Result<HostOuterCapBinding, HostSupervisionError> {
        let (status, _, _) = self.status_snapshot_with_elapsed(usize::MAX)?;
        Ok(HostOuterCapBinding {
            cap_id: self.shared.cap_id,
            original_monotonic_ns: self.shared.original_monotonic_ns,
            revision: status.revision,
            allowance: status.allowance,
            state: status.state,
        })
    }

    fn status_snapshot_with_elapsed(
        &self,
        maximum: usize,
    ) -> Result<(HostOuterCapStatus, Duration, Vec<HostOperationStatus>), HostSupervisionError>
    {
        let mut state = self.lock()?;
        let mut outer = self
            .shared
            .outer
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let elapsed = self.elapsed();
        state.cap_revision = outer.revision;
        state.cap_allowance = outer.allowance;
        state.cap_state = outer.state;
        refresh_cap(&mut state, elapsed);
        outer.state = state.cap_state;
        let cap = HostOuterCapStatus {
            revision: state.cap_revision,
            allowance: state.cap_allowance,
            remaining: state
                .cap_allowance
                .map(|allowance| allowance.saturating_sub(elapsed)),
            state: state.cap_state,
        };
        let count = state.operations.len();
        if count > maximum {
            return Err(HostSupervisionError::CapacityExhausted);
        }
        let mut ids = Vec::new();
        ids.try_reserve_exact(count)
            .map_err(|_| HostSupervisionError::CapacityExhausted)?;
        ids.extend(state.operations.keys().copied());
        let mut operations = Vec::new();
        operations
            .try_reserve_exact(count)
            .map_err(|_| HostSupervisionError::CapacityExhausted)?;
        for id in ids {
            operations.push(evaluate_operation(&mut state, id, elapsed)?);
        }
        Ok((cap, elapsed, operations))
    }

    /// Returns the current budget revision and fixed roster atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when synchronization ownership is uncertain.
    pub fn budgets(&self) -> Result<(u64, HostOperationBudgets), HostSupervisionError> {
        let state = self.lock()?;
        Ok((state.policy_revision, state.budgets))
    }

    /// Publishes sticky cancellation and wakes every live operation.
    ///
    /// # Errors
    ///
    /// Returns an error when synchronization ownership is uncertain.
    pub fn cancel(&self) -> Result<(), HostSupervisionError> {
        let mut state = self.lock()?;
        let mut outer = self
            .shared
            .outer
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        if outer.state == HostOperationState::Running {
            outer.state = if outer
                .allowance
                .is_some_and(|allowance| self.elapsed() >= allowance)
            {
                HostOperationState::Expired
            } else {
                HostOperationState::Canceled
            };
        }
        state.cap_state = outer.state;
        drop(outer);
        drop(state);
        self.notify_owners()?;
        Ok(())
    }

    /// Completes the outer owner, giving elapsed time precedence over completion.
    ///
    /// # Errors
    ///
    /// Returns terminal failure when expiry or cancellation wins completion.
    pub fn complete(&self) -> Result<(), HostSupervisionError> {
        let mut state = self.lock()?;
        let mut outer = self
            .shared
            .outer
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        state.cap_state = outer.state;
        state.cap_allowance = outer.allowance;
        refresh_cap(&mut state, self.elapsed());
        outer.state = state.cap_state;
        if state.cap_state != HostOperationState::Running {
            return Err(HostSupervisionError::Terminal {
                state: state.cap_state,
            });
        }
        state.cap_state = HostOperationState::Completed;
        outer.state = state.cap_state;
        drop(outer);
        drop(state);
        self.notify_owners()?;
        Ok(())
    }

    fn operation_status(&self, id: u64) -> Result<HostOperationStatus, HostSupervisionError> {
        let mut state = self.lock()?;
        self.evaluate(&mut state, id)
    }

    fn evaluate(
        &self,
        state: &mut SupervisionState,
        id: u64,
    ) -> Result<HostOperationStatus, HostSupervisionError> {
        let mut outer = self
            .shared
            .outer
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        state.cap_revision = outer.revision;
        state.cap_allowance = outer.allowance;
        state.cap_state = outer.state;
        let status = evaluate_operation(state, id, self.elapsed())?;
        outer.state = state.cap_state;
        Ok(status)
    }

    fn evaluate_decision(
        &self,
        state: &mut SupervisionState,
        id: u64,
    ) -> Result<OperationDecision, HostSupervisionError> {
        let mut outer = self
            .shared
            .outer
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        state.cap_revision = outer.revision;
        state.cap_allowance = outer.allowance;
        state.cap_state = outer.state;
        let decision = evaluate_operation_decision(state, id, self.elapsed())?;
        outer.state = state.cap_state;
        Ok(decision)
    }
}

/// Owned operation guard with live deadline recomputation and wakeable polling.
#[derive(Debug)]
pub struct HostOperationGuard {
    supervisor: HostOperationSupervisor,
    id: u64,
}

impl HostOperationGuard {
    /// Returns coherent live operation status.
    ///
    /// # Errors
    ///
    /// Returns an error when operational ownership is uncertain.
    pub fn status(&self) -> Result<HostOperationStatus, HostSupervisionError> {
        self.supervisor.operation_status(self.id)
    }

    /// Returns a responsive wait slice capped by every current applicable budget.
    ///
    /// # Errors
    ///
    /// Returns typed expiration or cancellation instead of a guest failure.
    pub fn wait_slice(&self) -> Result<Duration, HostSupervisionError> {
        let mut state = self.supervisor.lock()?;
        let decision = self.supervisor.evaluate_decision(&mut state, self.id)?;
        decision.require_running(self.id)?;
        let poll = state.budgets.get(decision.class).poll_interval;
        Ok(decision
            .deadline
            .map_or(poll, |deadline| poll.min(deadline.remaining)))
    }

    /// Waits for a poll slice or a policy/cancellation wakeup, then reevaluates.
    ///
    /// # Errors
    ///
    /// Returns typed operational failure when a live allowance expires.
    pub fn wait_for_change(&self) -> Result<(), HostSupervisionError> {
        let mut state = self.supervisor.lock()?;
        let decision = self.supervisor.evaluate_decision(&mut state, self.id)?;
        decision.require_running(self.id)?;
        let poll = state.budgets.get(decision.class).poll_interval;
        let slice = decision
            .deadline
            .map_or(poll, |deadline| poll.min(deadline.remaining));
        let waited = self
            .supervisor
            .shared
            .changed
            .wait_timeout(state, slice)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        drop(waited);
        let mut state = self.supervisor.lock()?;
        self.supervisor
            .evaluate_decision(&mut state, self.id)?
            .require_running(self.id)
    }

    /// Records a strictly increasing count of completed required work units.
    ///
    /// Repeated counts, retries, page traffic, and heartbeats do not renew time.
    ///
    /// # Errors
    ///
    /// Returns an error for regressing counts or terminal operations.
    pub fn progress(&self, completed_work_units: u64) -> Result<(), HostSupervisionError> {
        let mut state = self.supervisor.lock()?;
        let elapsed = self.supervisor.elapsed();
        self.supervisor
            .evaluate_decision(&mut state, self.id)?
            .require_running(self.id)?;
        let operation = state
            .operations
            .get_mut(&self.id)
            .ok_or(HostSupervisionError::Unavailable)?;
        if completed_work_units < operation.completed {
            return Err(HostSupervisionError::ProgressRegressed);
        }
        if completed_work_units > operation.required {
            return Err(HostSupervisionError::InvalidBudget);
        }
        if completed_work_units > operation.completed {
            operation.completed = completed_work_units;
            operation.last_progress = elapsed;
        }
        Ok(())
    }

    /// Completes required work after reevaluating all live deadlines.
    ///
    /// # Errors
    ///
    /// Returns failure when expiration or sticky cancellation wins completion.
    pub fn complete(&self) -> Result<HostOperationStatus, HostSupervisionError> {
        let mut state = self.supervisor.lock()?;
        self.supervisor
            .evaluate_decision(&mut state, self.id)?
            .require_running(self.id)?;
        let operation = state
            .operations
            .get_mut(&self.id)
            .ok_or(HostSupervisionError::Unavailable)?;
        operation.completed = operation.required;
        operation.state = HostOperationState::Completed;
        drop(state);
        self.status()
    }
}

impl Drop for HostOperationGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.supervisor.lock() {
            state.operations.remove(&self.id);
        }
    }
}

fn require_running(status: &HostOperationStatus) -> Result<(), HostSupervisionError> {
    match status.state {
        HostOperationState::Running => Ok(()),
        HostOperationState::Expired => Err(HostSupervisionError::DeadlineExpired {
            operation_id: status.operation_id,
            class: status.class,
        }),
        state => Err(HostSupervisionError::Terminal { state }),
    }
}

fn refresh_cap(state: &mut SupervisionState, elapsed: Duration) {
    if state.cap_state == HostOperationState::Running
        && state
            .cap_allowance
            .is_some_and(|allowance| elapsed >= allowance)
    {
        state.cap_state = HostOperationState::Expired;
    }
}

fn evaluate_operation(
    state: &mut SupervisionState,
    id: u64,
    elapsed: Duration,
) -> Result<HostOperationStatus, HostSupervisionError> {
    refresh_cap(state, elapsed);
    let operation = state
        .operations
        .get(&id)
        .ok_or(HostSupervisionError::Unavailable)?;
    let decision = decide_operation(state, operation, elapsed);
    let status = operation_status_from_decision(state, id, operation, decision);
    if let Some(operation) = state.operations.get_mut(&id) {
        operation.state = decision.state;
    }
    Ok(status)
}

fn evaluate_operation_decision(
    state: &mut SupervisionState,
    id: u64,
    elapsed: Duration,
) -> Result<OperationDecision, HostSupervisionError> {
    refresh_cap(state, elapsed);
    let operation = state
        .operations
        .get(&id)
        .ok_or(HostSupervisionError::Unavailable)?;
    let decision = decide_operation(state, operation, elapsed);
    if let Some(operation) = state.operations.get_mut(&id) {
        operation.state = decision.state;
    }
    Ok(decision)
}

fn progress_kind(class: HostOperationClass) -> HostProgressKind {
    match class {
        HostOperationClass::Quantum => HostProgressKind::GuestBoundary,
        HostOperationClass::PageIn => HostProgressKind::AuthenticatedPage,
        HostOperationClass::Writeback => HostProgressKind::PreservedPage,
        HostOperationClass::FingerprintInitialization | HostOperationClass::FingerprintUpdate => {
            HostProgressKind::MerkleLeaf
        }
        HostOperationClass::CheckpointPublication | HostOperationClass::Transfer => {
            HostProgressKind::DurableObject
        }
        HostOperationClass::ForkRearm => HostProgressKind::ForkBarrier,
        _ => HostProgressKind::ValidatedPhase,
    }
}

// Host monotonic time bounds waiting only and never enters guest identities.
// crucible-lint: allow clippy-disallowed-method -- operational supervision cannot define modeled time.
#[allow(clippy::disallowed_methods)]
fn host_now() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod tests;

fn kernel_monotonic_ns() -> Result<u64, HostSupervisionError> {
    let value = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let seconds = u64::try_from(value.tv_sec).map_err(|_| HostSupervisionError::Unavailable)?;
    let nanoseconds =
        u64::try_from(value.tv_nsec).map_err(|_| HostSupervisionError::Unavailable)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(nanoseconds))
        .ok_or(HostSupervisionError::IdentityExhausted)
}
