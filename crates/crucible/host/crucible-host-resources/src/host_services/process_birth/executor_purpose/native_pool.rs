//! Issues disjoint node reservations beneath one authentic normal native pool.
//!
//! Inputs describe a selected World; only the retained Main subdivision and a
//! real entered Preparation can issue claims. The preallocated ledger keeps
//! all attempted assignments and descriptor windows through refusal or Drop.
//! Assignments return only after the containing producer certifies actual closure.

// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use super::{
    AuthenticatedNativeSubdivision, AuthenticatedSourceHostPurpose, HostOperationGuard,
    HostResourceVector, HostServiceLease, ServiceBirthError,
};

mod ledger;
mod node;
mod refusal;
mod window;
mod world_return;
mod worker_admission;
use super::world_admission::{borrow_world_control, observe_world_attempt};
use ledger::{NodeSlot, PoolLedger, WorldSlot};
use refusal::{RefusalPostcut, RetainedClaim};
pub(super) use refusal::PreparedRefusal;

pub use world_return::NativePoolReturnError;

#[cfg(test)]
pub(super) use world_return::tests::check_real_kernel_world_return;

impl PoolState {
    fn verify_return_custody(
        &self,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        cleanup.verify_operation_class(crate::host_supervision::HostOperationClass::Cleanup)?;
        self.root.owner.family.check_retained_custody()?;
        self.root
            .owner
            .host_descriptors
            .try_lock()
            .map_err(|_| {
                ServiceBirthError::policy("native return descriptor custody is uncertain")
            })?
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native return descriptor owner is absent"))?
            .check()?;
        cleanup.verify_operation_class(crate::host_supervision::HostOperationClass::Cleanup)?;
        Ok(())
    }
}

/// Names a selected operational owner and authenticated immutable World input.
///
/// These copied coordinates grant no resources; a pool verifies and retains
/// the actual Main and Preparation independently when accepting a selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeWorldIdentity {
    /// Actual already admitted execution or retained Service owner.
    pub owner: [u8; 32],
    /// Actual admitted operational allocation epoch, not a checkpoint digest.
    pub selection: [u8; 32],
}

/// Describes one prospective two-incarnation node reservation, not credit.
#[derive(Clone, Copy, Debug)]
pub struct NativeNodeReservation {
    /// Exact node identity, strictly ordered within the selected request.
    pub node: [u8; 32],
    /// Complete disjoint native family vector, including both retained shares.
    pub resources: HostResourceVector,
    /// Main-table landing peak retained for the initial Source host controls.
    pub source_host_descriptors: u64,
    /// Separate Main-table landing peak retained for Target host controls.
    pub target_host_descriptors: u64,
}

/// Retains the actual once-published normal pool and its checked ledger.
///
/// Cloning this facade shares the same ledger, root debit and absolute end.
#[derive(Clone)]
pub struct AuthenticatedNativePoolPurpose {
    held: Arc<PoolState>,
}

struct PoolState {
    root: AuthenticatedNativeSubdivision,
    _original: Arc<HostOperationGuard>,
    ledger: Mutex<PoolLedger>,
    selection: Mutex<Vec<NativeNodeReservation>>,
    capacity: usize,
}

/// Owns one occupied World assignment without duplicating its native bank.
#[must_use = "retain the World claim until every actual member is physically retired"]
pub struct AuthenticatedNativeWorldClaim {
    held: Option<Arc<PoolState>>,
    epoch: u64,
    original: Arc<HostOperationGuard>,
    initial_custody: Option<NativeWorldBirthCustody>,
    returned: bool,
}

/// Holds both genuinely issued birth holders until their first owner receives them.
struct NativeWorldBirthCustody {
    cleanup: AuthenticatedNativeWorldCleanupLoan,
    controls: AuthenticatedNativeWorldControlLease,
}

/// Reports whether an exact World has returned or still owns its paid body.
///
/// Pending body custody is an accounting observation, not a cleanup grant or a
/// failed admission. Every issued native member must already have returned
/// consistently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeWorldReturn {
    /// Retains the same World and its complete remaining containing-body debit.
    PendingBody,
    /// Records the actual descriptor/ledger return of this exact assignment.
    Returned,
}

/// Retains the selected containing-body charge through actual owner destruction.
///
/// This move-only holder comes from the already admitted World. A production
/// cleanup cell keeps it after every contained body is destroyed; scalar byte
/// counts or dropping the holder cannot return its assignment.
#[must_use = "return this holder only after the actual containing owners are destroyed"]
pub struct AuthenticatedNativeWorldControlLease {
    held: Arc<PoolState>,
    epoch: u64,
    closed: bool,
}

/// Lends cleanup of the exact admitted World without duplicating its debit.
///
/// Only that actual World claim can construct this value. The original Main
/// and World Preparation remain in the ledger; no copied identity can issue it.
pub struct AuthenticatedNativeWorldCleanupLoan {
    held: Arc<PoolState>,
    epoch: u64,
}

/// Owns one checked node family beneath its exact retained World and Main.
///
/// This is funding custody only. It supplies no Source, guest, actor, callback,
/// CPU-phase or native readiness authority. It has no scalar constructor.
#[must_use = "retain the node claim through actual process/controller/window retirement"]
pub struct AuthenticatedNativeNodeClaim {
    held: Option<Arc<PoolState>>,
    world_epoch: u64,
    assignment_epoch: u64,
    node_index: usize,
    _original: Arc<HostOperationGuard>,
    target_window: Mutex<Option<AuthenticatedNativeNodeHostWindow>>,
}

/// Retains one node's disjoint landing within the same actual Main table.
///
/// This holder names an already reserved Source or Target window. No descriptor
/// is opened by taking it, and Drop cannot certify that its aliases returned.
#[must_use = "retain the landing holder through actual descriptor closure"]
pub struct AuthenticatedNativeNodeHostWindow {
    held: Option<Arc<PoolState>>,
    world_epoch: u64,
    assignment_epoch: u64,
    node_index: usize,
    role: WindowRole,
    closed: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum WindowRole {
    Source,
    Target,
}

/// Preserves the first refusal, independent postcut and any issued custody.
///
/// Issuers prepay a private carrier before any child publication. Refusal moves
/// the actual owner into that carrier without allocating after the failed cut.
#[derive(Debug, thiserror::Error)]
#[error("native subdivision refused: {cause}; independent original: {after:?}")]
pub struct NativePoolRefusal {
    #[source]
    cause: ServiceBirthError,
    after: RefusalPostcut,
    _retained: RetainedClaim,
}

pub(super) fn missing_node_window(
    after: Option<ServiceBirthError>,
) -> Result<(), NativePoolRefusal> {
    Err(NativePoolRefusal {
        cause: ServiceBirthError::policy("Target host needs its consumed node claim"),
        after: after.into(),
        _retained: RetainedClaim::empty(),
    })
}

pub(super) fn finish_dispatcher(
    result: Result<(super::AuthenticatedTargetDispatcherPurpose, PreparedRefusal), ServiceBirthError>,
    after: Option<ServiceBirthError>,
) -> Result<super::AuthenticatedTargetDispatcherPurpose, NativePoolRefusal> {
    match (result, after) {
        (Ok((purpose, _prepared)), None) => Ok(purpose),
        (Err(cause), after) => Err(NativePoolRefusal {
            cause,
            after: after.into(),
            _retained: RetainedClaim::empty(),
        }),
        (Ok((purpose, prepared)), Some(after)) => Err(NativePoolRefusal {
            cause: ServiceBirthError::policy("Target dispatcher postcut refused"),
            after: Some(after).into(),
            _retained: RetainedClaim::dispatcher(purpose, prepared),
        }),
    }
}

pub(super) fn finish_source(
    result: Result<(AuthenticatedSourceHostPurpose, PreparedRefusal), ServiceBirthError>,
    after: Option<ServiceBirthError>,
) -> Result<AuthenticatedSourceHostPurpose, NativePoolRefusal> {
    match (result, after) {
        (Ok((source, _prepared)), None) => Ok(source),
        (Err(cause), after) => Err(NativePoolRefusal {
            cause,
            after: after.into(),
            _retained: RetainedClaim::empty(),
        }),
        (Ok((source, prepared)), Some(after)) => Err(NativePoolRefusal {
            cause: ServiceBirthError::policy("Source host postcut refused"),
            after: Some(after).into(),
            _retained: RetainedClaim::source(source, prepared),
        }),
    }
}

/// Keeps an initiating refusal distinct from the unconditional post-observation.
pub(super) fn finish_root(
    result: Result<(AuthenticatedNativePoolPurpose, PreparedRefusal), ServiceBirthError>,
    after: Option<ServiceBirthError>,
) -> Result<AuthenticatedNativePoolPurpose, NativePoolRefusal> {
    match (result, after) {
        (Ok((pool, _prepared)), None) => Ok(pool),
        (Err(cause), after) => Err(NativePoolRefusal {
            cause,
            after: after.into(),
            _retained: RetainedClaim::empty(),
        }),
        (Ok((pool, prepared)), Some(after)) => Err(NativePoolRefusal {
            cause: ServiceBirthError::policy("native pool postcut refused"),
            after: Some(after).into(),
            _retained: RetainedClaim::pool(pool, prepared),
        }),
    }
}

impl std::fmt::Debug for AuthenticatedNativePoolPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticatedNativePoolPurpose { .. }")
    }
}

impl std::fmt::Debug for AuthenticatedNativeWorldClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedNativeWorldClaim")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AuthenticatedNativeNodeClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedNativeNodeClaim")
            .field("world_epoch", &self.world_epoch)
            .field("assignment_epoch", &self.assignment_epoch)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AuthenticatedNativeNodeHostWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedNativeNodeHostWindow")
            .field("world_epoch", &self.world_epoch)
            .field("assignment_epoch", &self.assignment_epoch)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// Pure requested geometry; it cannot publish a Main or child purpose.
pub(super) struct PoolLayout {
    capacity: usize,
    controls: u64,
    shared_descriptors: u64,
}

/// Rejects impossible control geometry before root limit/census effects.
pub(super) fn checked_layout(
    ceiling: HostResourceVector,
    consumer_control_bytes: u64,
    consumer_file_descriptors: u64,
) -> Result<PoolLayout, ServiceBirthError> {
    super::validate_request(ceiling)?;
    // Every node requires a positive CPU share; concurrent World/node
    // counts therefore cannot exceed the already assigned aggregate CPU.
    // This capacity is independent of worker count and private actor width.
    let capacity = usize::try_from(ceiling.cpu_slots)
        .map_err(|_| ServiceBirthError::policy("native pool capacity overflows"))?;
    let controls = structure_bytes(capacity)?
        .checked_add(consumer_control_bytes)
        .ok_or_else(|| ServiceBirthError::policy("native containing control extent overflows"))?;
    super::checked_assignment(
        HostResourceVector::default(),
        HostResourceVector {
            resident_peak_bytes: controls,
            metadata_bytes: controls,
            file_descriptors: consumer_file_descriptors,
            ..HostResourceVector::default()
        },
        ceiling,
    )?;
    if consumer_file_descriptors == 0 {
        return Err(ServiceBirthError::policy(
            "shared Main descriptor geometry is absent",
        ));
    }
    Ok(PoolLayout {
        capacity,
        controls,
        shared_descriptors: consumer_file_descriptors,
    })
}

impl AuthenticatedNativePoolPurpose {
    pub(super) fn publish(
        root: AuthenticatedNativeSubdivision,
        layout: PoolLayout,
        original: &Arc<HostOperationGuard>,
    ) -> Result<Self, ServiceBirthError> {
        root.check()?;
        let ledger = PoolLedger::new(
            root.bounds(),
            layout.capacity,
            layout.controls,
            layout.shared_descriptors,
        )?;
        let mut selection = Vec::new();
        selection.try_reserve_exact(layout.capacity).map_err(|_| {
            ServiceBirthError::policy("native selection scratch allocation refused")
        })?;
        let pool = Self {
            held: Arc::new(PoolState {
                root,
                _original: Arc::clone(original),
                ledger: Mutex::new(ledger),
                selection: Mutex::new(selection),
                capacity: layout.capacity,
            }),
        };
        pool.held.root.check()?;
        Ok(pool)
    }

    /// Matches the same already-issued pool allocation without granting work.
    #[must_use]
    pub fn same_pool(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.held, &other.held)
    }

    /// Reports the fixed already-paid node capacity independently of workers.
    #[must_use]
    pub fn node_capacity(&self) -> usize {
        self.held.capacity
    }

    /// Matches the actual once-admitted Main, never a copied owner coordinate.
    #[must_use]
    pub fn belongs_to_main(&self, main: &Arc<super::AuthenticatedNativeSlotPurpose>) -> bool {
        Arc::ptr_eq(&self.held.root.owner, main)
    }

    /// Observes physical return of a genuine preexisting loan in this same pool.
    ///
    /// This checks the actual pool Arc before reading its monotonic publication
    /// ledger. Absence proves return only because the sole row-removal cut
    /// follows irreversible assignment consumption. It issues no new work,
    /// return, Cleanup, or never-born assertion and does not erase prior reports.
    ///
    /// # Errors
    /// Refuses a foreign loan/pool, an unissued epoch or uncertain ledger.
    pub fn observe_world_returned(
        &self,
        loan: &AuthenticatedNativeWorldCleanupLoan,
    ) -> Result<bool, ServiceBirthError> {
        if !Arc::ptr_eq(&self.held, &loan.held) {
            return Err(ServiceBirthError::policy(
                "native return loan belongs to another pool",
            ));
        }
        self.held
            .ledger
            .try_lock()
            .map_err(|_| ServiceBirthError::policy("native World return ledger is uncertain"))?
            .observe_world_returned(loan.epoch)
    }

    /// Debits permanent worker bodies from this same Main pool before birth.
    ///
    /// This once-only standing assignment remains occupied for Main lifetime;
    /// World/window return cannot refund it. The returned facade retains the
    /// existing original bank and issues no Source, CPU or process authority.
    ///
    /// # Errors
    /// Refuses stale Main, occupied admission locks, zero/repeated assignment,
    /// or exhausted concurrent pool geometry. The actual initial Preparation
    /// remains unchanged. Initiating and postcheck refusals stay independent;
    /// a post refusal retains the attempted permanent debit.
    pub fn reserve_worker_controls(&self, bytes: u64) -> Result<Self, NativePoolRefusal> {
        worker_admission::admit_worker_controls(&self.held.ledger, bytes, || {
            self.held.root.check_worker_admission()
        })?;
        Ok(self.clone())
    }

    /// Checks the retained Main without entering another operation or claim.
    ///
    /// # Errors
    /// Refuses a changed, expired or canceled authenticated Main owner.
    pub fn verify_retained_main(&self) -> Result<(), ServiceBirthError> {
        self.held.root.check()
    }

    /// Enters actual native Preparation beneath this same unchanged Main.
    ///
    /// The producer prices its real guard/control storage in the containing
    /// peak before this call. No clock, budget owner or Source is manufactured.
    ///
    /// # Errors
    /// Refuses expired/changed Main or its genuine operation admission.
    pub fn begin_native_preparation(&self) -> Result<HostOperationGuard, ServiceBirthError> {
        self.held.root.begin_world_preparation()
    }

    /// Snapshots selected node geometry into constructor-prepaid bounded storage.
    ///
    /// The real producer visits its immutable admitted partition without a new
    /// request Vec. Snapshot access is nonblocking, including reentry. These
    /// inert rows are sorted canonically and pass the same aggregate admission.
    /// `consumer_control_bytes` prices the actual selected containing bodies;
    /// it is retained with this World through final member/control closure.
    ///
    /// # Errors
    /// Refuses concurrent snapshot access, excess rows, producer refusal or the
    /// actual Original independently before/after every attempted snapshot.
    /// The one infallible entry callback runs only at checked assignment
    /// publication; snapshot refusal cannot consume the caller's nominal proof.
    pub fn claim_world_from(
        &self,
        identity: NativeWorldIdentity,
        consumer_control_bytes: u64,
        original: &Arc<HostOperationGuard>,
        entered: impl FnOnce(),
        populate: impl FnOnce(
            &mut dyn FnMut(NativeNodeReservation) -> Result<(), ServiceBirthError>,
        ) -> Result<(), ServiceBirthError>,
    ) -> Result<AuthenticatedNativeWorldClaim, NativePoolRefusal> {
        let snapshot = (|| {
            self.held.root.verify_world_preparation(original)?;
            let mut rows = self.held.selection.try_lock().map_err(|_| {
                ServiceBirthError::policy("native selection snapshot is occupied or uncertain")
            })?;
            rows.clear();
            populate(&mut |row| {
                if rows.len() >= self.held.capacity {
                    return Err(ServiceBirthError::policy(
                        "native selection exceeds its prepaid capacity",
                    ));
                }
                rows.push(row);
                Ok(())
            })?;
            rows.sort_unstable_by_key(|row| row.node);
            Ok(rows)
        })();
        match snapshot {
            Ok(rows) => {
                self.claim_world(identity, &rows, consumer_control_bytes, original, entered)
            }
            Err(cause) => Err(NativePoolRefusal {
                cause,
                after: self.held.root.verify_world_preparation(original).err().into(),
                _retained: RetainedClaim::empty(),
            }),
        }
    }

    /// Occupies all selected node vectors before a child holder or effect.
    ///
    /// The request must use actual admitted owner/basis facts and include the
    /// complete simultaneous family/outside classification at its caller.
    /// That producer join is required; these coordinates are not authority.
    ///
    /// # Errors
    /// Refuses stale/foreign Original, duplicate World or node selection,
    /// exhausted aggregate axes/control storage/tables, or a failed postcut.
    /// Every committed partial assignment and both initial holders remain
    /// retained in the same pool, including descriptor or independent post refusal.
    fn claim_world(
        &self,
        identity: NativeWorldIdentity,
        nodes: &[NativeNodeReservation],
        consumer_control_bytes: u64,
        original: &Arc<HostOperationGuard>,
        entered: impl FnOnce(),
    ) -> Result<AuthenticatedNativeWorldClaim, NativePoolRefusal> {
        let mut born = None;
        let mut assignment_refused = false;
        let (result, after) = observe_world_attempt(
            || self.held.root.verify_world_preparation(original),
            || {
                let prepared = PreparedRefusal::reserve(&self.held.root.owner)?;
                let mut ledger = borrow_world_control(
                    &self.held.ledger,
                    "native World assignment ledger is busy or uncertain",
                )?;
                let (epoch, peak, tables) = match ledger.assign_source(
                    identity,
                    nodes,
                    consumer_control_bytes,
                    original,
                    entered,
                ) {
                    Ok(assigned) => assigned,
                    Err(cause) => {
                        // assign checks all fallible arithmetic before its
                        // publication cut. A failed snapshot callback never
                        // reaches this cut; no descriptor window has run.
                        assignment_refused = true;
                        return Err(cause);
                    }
                };
                // Assignment already marked the body issued under this same
                // ledger borrow. Save both actual holders before descriptor
                // effects or any independent post can refuse.
                let claim = AuthenticatedNativeWorldClaim {
                    held: Some(Arc::clone(&self.held)),
                    epoch,
                    original: Arc::clone(original),
                    initial_custody: Some(NativeWorldBirthCustody {
                        cleanup: AuthenticatedNativeWorldCleanupLoan {
                            held: Arc::clone(&self.held),
                            epoch,
                        },
                        controls: AuthenticatedNativeWorldControlLease {
                            held: Arc::clone(&self.held),
                            epoch,
                            closed: false,
                        },
                    }),
                    returned: false,
                };
                born = Some((claim, prepared));

                let window = borrow_world_control(
                    &self.held.root.owner.host_descriptors,
                    "World descriptor owner is busy or uncertain",
                )?
                .as_mut()
                .ok_or_else(|| ServiceBirthError::policy("Main descriptor owner is absent"))?
                .reserve_pool_windows(peak, tables, original)?;
                ledger.bind_window(epoch, window)?;
                Ok(())
            },
        );
        let assignment_refused = assignment_refused && after.is_none();
        match (result, after) {
            (Ok(()), None) => born
                .map(|(claim, _prepared)| claim)
                .ok_or_else(|| NativePoolRefusal {
                    cause: ServiceBirthError::policy("native World publication is absent"),
                    after: None.into(),
                    _retained: RetainedClaim::empty(),
                }),
            (result, after) => Err(NativePoolRefusal {
                cause: result
                    .err()
                    .unwrap_or_else(|| ServiceBirthError::policy("native World postcut refused")),
                after: RefusalPostcut::world_attempt(after, assignment_refused),
                _retained: born.map_or_else(RetainedClaim::empty, |(claim, prepared)| {
                    RetainedClaim::world(claim, prepared)
                }),
            }),
        }
    }
}

impl AuthenticatedNativeWorldClaim {
    /// Moves this World's two original birth holders without issuing or relocking.
    ///
    /// Both holders were published beneath the same assignment ledger borrow,
    /// before any descriptor effect or independent post could refuse. Their
    /// saved containing-body charge remains occupied through actual destruction.
    ///
    /// # Errors
    /// Refuses a second move of the same pair; no replacement pair is created.
    pub fn take_initial_custody(
        &mut self,
    ) -> Result<
        (
            AuthenticatedNativeWorldCleanupLoan,
            AuthenticatedNativeWorldControlLease,
        ),
        ServiceBirthError,
    > {
        let custody = self.initial_custody.take().ok_or_else(|| {
            ServiceBirthError::policy("native World birth custody is already delivered")
        })?;
        Ok((custody.cleanup, custody.controls))
    }

    /// Matches an existing cleanup loan to this exact retained assignment.
    #[must_use]
    pub fn matches_cleanup_loan(&self, loan: &AuthenticatedNativeWorldCleanupLoan) -> bool {
        self.epoch == loan.epoch
            && self
                .held
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, &loan.held))
    }

    /// Reports the current unconsumed member count for exact before-birth storage.
    ///
    /// # Errors
    /// Refuses stale/lost World custody or uncertain selection state.
    pub fn unissued_node_count(&self) -> Result<usize, ServiceBirthError> {
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native World custody is absent"))?;
        held.root.check()?;
        held.ledger
            .lock()
            .map_err(|_| ServiceBirthError::policy("native World selection is uncertain"))?
            .unissued_node_count(self.epoch)
    }

    /// Observes the next unconsumed row without allocating or entering a node.
    ///
    /// # Errors
    /// Refuses lost/stale World custody, changed Main or uncertain selection.
    pub fn next_node(&self) -> Result<Option<NativeNodeReservation>, ServiceBirthError> {
        let held = self
            .held
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("native World custody is absent"))?;
        held.root.check()?;
        held.ledger
            .lock()
            .map_err(|_| ServiceBirthError::policy("native World selection is uncertain"))?
            .next_node(self.epoch)
    }

    /// Saves one issued member in its prepaid caller slot before the postcut.
    ///
    /// The destination is custody, not a diagnostic. Prefix refusal leaves it
    /// unchanged; a negative independent post retains the actual node there.
    ///
    /// # Errors
    /// Refuses an occupied destination, stale member/window, wrong Original or
    /// independent post. No failed observation removes a saved actual holder.
    pub fn take_node_into(
        &self,
        node: [u8; 32],
        destination: &mut Option<AuthenticatedNativeNodeClaim>,
    ) -> Result<(), NativePoolRefusal> {
        let result = (|| {
            if destination.is_some() {
                return Err(ServiceBirthError::policy(
                    "native node destination is occupied",
                ));
            }
            let held = self
                .held
                .as_ref()
                .ok_or_else(|| ServiceBirthError::policy("native World custody is absent"))?;
            held.root.verify_native_preparation(&self.original)?;
            let mut ledger = held
                .ledger
                .lock()
                .map_err(|_| ServiceBirthError::policy("native pool ledger is uncertain"))?;
            let (node_index, assignment_epoch) = ledger.take_node(self.epoch, node)?;
            *destination = Some(AuthenticatedNativeNodeClaim {
                held: Some(Arc::clone(held)),
                world_epoch: self.epoch,
                assignment_epoch,
                node_index,
                _original: Arc::clone(&self.original),
                target_window: Mutex::new(None),
            });
            Ok(())
        })();
        let after = postcut(self.held.as_ref(), &self.original);
        match (result, after) {
            (Ok(()), None) => Ok(()),
            (result, after) => Err(NativePoolRefusal {
                cause: result
                    .err()
                    .unwrap_or_else(|| ServiceBirthError::policy("native node postcut refused")),
                after: after.into(),
                _retained: RetainedClaim::empty(),
            }),
        }
    }
}

fn postcut(
    held: Option<&Arc<PoolState>>,
    original: &Arc<HostOperationGuard>,
) -> Option<ServiceBirthError> {
    match held {
        Some(held) => held.root.verify_native_preparation(original).err(),
        None => original.wait_slice().map_err(ServiceBirthError::from).err(),
    }
}

fn structure_bytes(capacity: usize) -> Result<u64, ServiceBirthError> {
    let (arc, _) = std::alloc::Layout::new::<(
        std::sync::atomic::AtomicUsize,
        std::sync::atomic::AtomicUsize,
    )>()
    .extend(std::alloc::Layout::new::<PoolState>())
    .map_err(|_| ServiceBirthError::policy("native pool layout overflows"))?;
    let worlds = std::alloc::Layout::array::<Option<WorldSlot>>(capacity)
        .map_err(|_| ServiceBirthError::policy("native World array layout overflows"))?;
    let selection = std::alloc::Layout::array::<NativeNodeReservation>(capacity)
        .map_err(|_| ServiceBirthError::policy("native selection scratch layout overflows"))?;
    let nodes = std::alloc::Layout::array::<Option<NodeSlot>>(capacity)
        .map_err(|_| ServiceBirthError::policy("native node array layout overflows"))?;
    let (cleanup, _) = std::alloc::Layout::new::<(
        std::sync::atomic::AtomicUsize,
        std::sync::atomic::AtomicUsize,
    )>()
    .extend(std::alloc::Layout::new::<HostOperationGuard>())
    .map_err(|_| ServiceBirthError::policy("native World Cleanup layout overflows"))?;
    let cleanups = cleanup
        .pad_to_align()
        .size()
        .checked_mul(capacity)
        .ok_or_else(|| ServiceBirthError::policy("native World Cleanup peak overflows"))?;
    arc.pad_to_align()
        .size()
        .checked_add(cleanups)
        .and_then(|bytes| bytes.checked_add(worlds.size()))
        .and_then(|bytes| bytes.checked_add(nodes.size()))
        .and_then(|bytes| bytes.checked_add(selection.size()))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| ServiceBirthError::policy("native pool control extent overflows"))
}

impl AuthenticatedNativeWorldControlLease {
    /// Matches this open containing-body lease to its genuine World loan.
    ///
    /// This structural observation enters no operation and attests neither
    /// physical return nor absence of native effects. Both original holders
    /// must still follow their independent cleanup and accounting cuts.
    ///
    /// # Errors
    /// Refuses a closed lease or a different actual pool allocation or epoch.
    pub fn verify_world_loan(
        &self,
        loan: &AuthenticatedNativeWorldCleanupLoan,
    ) -> Result<(), ServiceBirthError> {
        if self.closed || self.epoch != loan.epoch || !Arc::ptr_eq(&self.held, &loan.held) {
            return Err(ServiceBirthError::policy(
                "World body lease is foreign or closed",
            ));
        }
        Ok(())
    }

    /// Authenticates the same open containing-body lease and never-born World.
    ///
    /// This observation releases nothing. The actual owner must still be
    /// destroyed before closing this lease and returning its World assignment.
    ///
    /// # Errors
    /// Refuses closed, foreign, stale, attempted or uncertain custody.
    pub fn verify_unborn_world(
        &self,
        loan: &AuthenticatedNativeWorldCleanupLoan,
    ) -> Result<(), ServiceBirthError> {
        self.verify_world_loan(loan)?;
        loan.verify_never_born()
    }

    /// Records destruction of the real containing owner before assignment return.
    ///
    /// The prepaid cleanup cell destroys its actual containing owner outside
    /// the queue lock. A canonically proven never-born constructor instead
    /// consumes its same pending body before this call. Neither path returns
    /// native role, operation, descriptor or Source permission.
    ///
    /// # Errors
    /// Refuses stale or uncertain custody; the same holder remains retryable.
    pub fn close_after_owner_destruction(&mut self) -> Result<(), ServiceBirthError> {
        if self.closed {
            return Ok(());
        }
        self.held
            .ledger
            .lock()
            .map_err(|_| ServiceBirthError::policy("native World body return is uncertain"))?
            .close_consumer(self.epoch)?;
        self.closed = true;
        Ok(())
    }
}

impl AuthenticatedNativeWorldCleanupLoan {
    /// Observes that no member constructor was ever entered for this World.
    ///
    /// The ledger marks entry before issuing any node holder and never clears
    /// that fact at physical return. This factual observation grants no work;
    /// the caller still destroys its actual Pending Box before returning the
    /// separate containing-body lease or cleanup reservation.
    ///
    /// # Errors
    /// Refuses stale/uncertain state or any attempted node construction.
    pub fn verify_never_born(&self) -> Result<(), ServiceBirthError> {
        self.held
            .ledger
            .lock()
            .map_err(|_| ServiceBirthError::policy("native World no-birth ledger is uncertain"))?
            .verify_never_born(self.epoch)
    }

    /// Enters once and reuses this World's original-bounded Cleanup.
    ///
    /// # Errors
    /// Refuses stale ownership, the saved first admission failure or the same
    /// Cleanup's cancellation/expiry; no retry receives a fresh clock.
    pub fn retained_cleanup(&self) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
        self.held
            .ledger
            .lock()
            .map_err(|_| ServiceBirthError::policy("native World Cleanup ledger is uncertain"))?
            .retained_cleanup(self.epoch)
    }
}

#[cfg(test)]
mod refusal_tests;
