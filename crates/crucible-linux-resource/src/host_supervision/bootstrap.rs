//! Preserves original supervision coordinates before heap publication.
//!
//! Standalone service construction begins its original preparation on the
//! stack. Its fixed publisher requires the already charged original accounts;
//! publication moves the same cap, operation, clock and sticky disposition.
//! The private service constructor retains those accounts through every alias
//! from this lane. This API does not fund arbitrary supervisor consumers.

use std::alloc::Layout;
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use std::sync::atomic::AtomicUsize;

use super::*;
use crate::host_services::{AdmittedHostServiceBootstrap, HostServiceBootstrap};

/// Unpublished original supervisor and its first preparation operation.
///
/// Construction and polling allocate no heap storage. The original clocks,
/// cap identity, policy and operation coordinates survive publication without
/// renewal. This token is intended for the bounded private standalone service
/// constructor, whose original accounts outlive all published aliases.
#[derive(Debug)]
pub struct HostSupervisionBootstrap {
    started: Instant,
    #[cfg(feature = "private-measurement-domain")]
    measurement_origin: Option<crate::measurement_origin::MeasurementInvocationOrigin>,
    original_monotonic_ns: u64,
    state: SupervisionState,
    preparation: Operation,
}

impl HostSupervisionBootstrap {
    /// Starts the original finite roster and first preparation without a heap.
    ///
    /// # Errors
    /// Preserves standalone roster-before-outer validation, original identity
    /// exhaustion, monotonic-clock refusal and original preparation failure.
    pub fn new(
        budgets: HostOperationBudgets,
        outer: Option<Duration>,
    ) -> Result<Self, HostSupervisionError> {
        budgets.validate(false)?;
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
        let original_monotonic_ns = kernel_monotonic_ns()?;
        let started = host_now();
        let mut state = SupervisionState {
            cap_id,
            budgets,
            policy_revision: 0,
            cap_revision: 0,
            cap_allowance: outer,
            cap_state: HostOperationState::Running,
            next_operation: 0,
            operations: BTreeMap::new(),
        };

        refresh_cap(&mut state, host_now().saturating_duration_since(started));
        state.budgets.validate(false)?;
        refresh_cap(&mut state, host_now().saturating_duration_since(started));
        let elapsed = host_now().saturating_duration_since(started);
        refresh_cap(&mut state, elapsed);
        if state.cap_state != HostOperationState::Running {
            return Err(HostSupervisionError::Terminal {
                state: state.cap_state,
            });
        }
        state
            .budgets
            .get(HostOperationClass::Preparation)
            .validate(
                HostOperationClass::Preparation,
                state.cap_allowance.is_some(),
            )?;
        state.next_operation = 1;
        Ok(Self {
            started,
            #[cfg(feature = "private-measurement-domain")]
            measurement_origin: None,
            original_monotonic_ns,
            state,
            preparation: Operation {
                class: HostOperationClass::Preparation,
                control: false,
                started: elapsed,
                last_progress: elapsed,
                started_revision: 0,
                completed: 0,
                required: 1,
                state: HostOperationState::Running,
                startup_cancellation: None,
            },
        })
    }

    /// Consumes the authenticated private invocation without renewing its clocks.
    ///
    /// The original init interval includes admission and loader work. The same
    /// descriptor-owning token moves into the existing outer owner at publication.
    /// Its expanded control/body and all prepublication work must already belong
    /// to the authenticated whole operator contract; this method issues no credit.
    ///
    /// # Errors
    /// Refuses invalid class budgets, exhausted identity, original clock refusal
    /// or a preparation budget already spent since the original init start.
    #[cfg(feature = "private-measurement-domain")]
    pub fn from_measurement_origin(
        origin: crate::measurement_origin::MeasurementInvocationOrigin,
        budgets: HostOperationBudgets,
    ) -> Result<Self, HostSupervisionError> {
        budgets.validate(false)?;
        let (started, clock) = origin
            .supervision_coordinates()
            .map_err(|_| HostSupervisionError::Unavailable)?;
        budgets.validate(true)?;
        let ordinal = NEXT_CAP_ID
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |ordinal| {
                ordinal.checked_add(1)
            })
            .map_err(|_| HostSupervisionError::IdentityExhausted)?;
        let mut cap_id = [0; 32];
        cap_id[24..].copy_from_slice(&ordinal.to_be_bytes());
        let mut bootstrap = Self {
            started,
            measurement_origin: Some(origin),
            original_monotonic_ns: clock.start_ns,
            state: SupervisionState {
                cap_id,
                budgets,
                policy_revision: 0,
                cap_revision: 0,
                cap_allowance: Some(clock.span()),
                cap_state: HostOperationState::Running,
                next_operation: 1,
                operations: BTreeMap::new(),
            },
            preparation: Operation {
                class: HostOperationClass::Preparation,
                control: false,
                // Admission and loader time belong to this original phase too.
                started: Duration::ZERO,
                last_progress: Duration::ZERO,
                started_revision: 0,
                completed: 0,
                required: 1,
                state: HostOperationState::Running,
                startup_cancellation: None,
            },
        };
        bootstrap.wait_slice()?;
        Ok(bootstrap)
    }

    fn elapsed(&self) -> Duration {
        let elapsed = host_now().saturating_duration_since(self.started);
        #[cfg(feature = "private-measurement-domain")]
        if let Some(origin) = self.measurement_origin.as_ref() {
            return match origin.supervision_coordinates() {
                Ok((_, clock)) => elapsed.max(clock.elapsed()),
                Err(_) => Duration::MAX,
            };
        }
        elapsed
    }

    #[cfg(all(test, feature = "private-measurement-domain"))]
    pub(crate) fn original_measurement_start_for_test(&self) -> u64 {
        self.original_monotonic_ns
    }

    /// Checks the original preparation and returns its current polling slice.
    ///
    /// # Errors
    /// Returns the original expiration or sticky terminal disposition.
    pub fn wait_slice(&mut self) -> Result<Duration, HostSupervisionError> {
        let before = self.elapsed();
        refresh_cap(&mut self.state, before);
        let elapsed = self.elapsed();
        refresh_cap(&mut self.state, elapsed);
        let decision = decide_operation(&self.state, &self.preparation, elapsed);
        self.preparation.state = decision.state;
        decision.require_running(1)?;
        let poll = self
            .state
            .budgets
            .get(HostOperationClass::Preparation)
            .poll_interval;
        Ok(decision
            .deadline
            .map_or(poll, |deadline| poll.min(deadline.remaining)))
    }

    /// Publishes the original supervisor and preparation under precharged accounts.
    ///
    /// The caller keeps `accounts` alive through these fixed allocations, then
    /// moves its unchanged counters into their final controls. Both controls
    /// must outlive every supervisor and guard alias from this bounded service
    /// lane, including constructor cleanup and retained namespace quarantine.
    /// No callback runs between structural admission and publication.
    ///
    /// # Errors
    /// Refuses insufficient structural credit, layout overflow, or unavailable
    /// unpublished operation ownership. It never creates a replacement origin.
    pub fn publish(
        self,
        accounts: &AdmittedHostServiceBootstrap,
    ) -> Result<(HostOperationSupervisor, HostOperationGuard), HostSupervisionError> {
        #[cfg(feature = "private-measurement-domain")]
        let measurement_clock = if let Some(origin) = self.measurement_origin.as_ref() {
            let (_, clock) = origin
                .supervision_coordinates()
                .map_err(|_| HostSupervisionError::Unavailable)?;
            decide_operation(&self.state, &self.preparation, self.elapsed()).require_running(1)?;
            Some(clock)
        } else {
            None
        };
        let minimum = Self::structure_bytes()?
            .checked_add(
                HostServiceBootstrap::control_bytes()
                    .map_err(|_| HostSupervisionError::CapacityExhausted)?,
            )
            .ok_or(HostSupervisionError::CapacityExhausted)?;
        if accounts.structural_bytes() < minimum {
            return Err(HostSupervisionError::CapacityExhausted);
        }
        let changed = Arc::new(Condvar::new());
        let supervisor = HostOperationSupervisor {
            shared: Arc::new(Shared {
                started: self.started,
                #[cfg(feature = "private-measurement-domain")]
                measurement_clock,
                original_monotonic_ns: self.original_monotonic_ns,
                cap_id: self.state.cap_id,
                changed: Arc::clone(&changed),
                outer: Arc::new(Mutex::new(OuterAuthority {
                    #[cfg(feature = "private-measurement-domain")]
                    measurement_origin: self.measurement_origin,
                    root_wakeup: changed,
                    revision: self.state.cap_revision,
                    allowance: self.state.cap_allowance,
                    state: self.state.cap_state,
                    next_owner: 0,
                    rosters: BTreeMap::from([(0, (self.state.budgets, None))]),
                })),
                state: Mutex::new(self.state),
                budget_owner: 0,
            }),
        };
        supervisor
            .shared
            .state
            .lock()
            .map_err(|_| HostSupervisionError::Unavailable)?
            .operations
            .insert(1, self.preparation);
        let preparation = HostOperationGuard {
            supervisor: supervisor.clone(),
            id: 1,
        };
        // Publication itself allocates the original controls and tree nodes.
        // Private invocation admission rechecks the SAME returned preparation
        // after that work; no new clock or operation can renew its allowance.
        #[cfg(feature = "private-measurement-domain")]
        if measurement_clock.is_some() {
            preparation.wait_slice()?;
        }
        Ok((supervisor, preparation))
    }

    /// Returns the bounded lane's supervision heap-control and report extent.
    ///
    /// One root roster and at most twelve operation records are reachable.
    /// Their pinned standard-library tree can retain two leaves and one root;
    /// at most one three-source owned completion report per record overlaps.
    /// This excludes the two original capacity controls and caller/service
    /// bodies, which the fixed caller separately includes before publication.
    /// Stack frames, native allocator overhead and returned provider errors
    /// require separate caller accounting; this is not a full process bound.
    ///
    /// # Errors
    /// Refuses layout or byte-count overflow on the compilation target.
    pub fn structure_bytes() -> Result<u64, HostSupervisionError> {
        let extents = [
            arc_bytes::<Condvar>()?,
            arc_bytes::<Mutex<OuterAuthority>>()?,
            arc_bytes::<Shared>()?,
            std::mem::size_of::<TreeLeaf<u64, (HostOperationBudgets, Option<Weak<Shared>>)>>(),
            std::mem::size_of::<TreeLeaf<u64, Operation>>()
                .checked_mul(2)
                .ok_or(HostSupervisionError::CapacityExhausted)?,
            std::mem::size_of::<TreeInternal<u64, Operation>>(),
            MAX_HOST_OPERATIONS
                .checked_mul(3)
                .and_then(|count| count.checked_mul(std::mem::size_of::<HostDeadlineSource>()))
                .ok_or(HostSupervisionError::CapacityExhausted)?,
        ];
        let bytes = extents
            .into_iter()
            .try_fold(0usize, |bytes, extent| bytes.checked_add(extent))
            .ok_or(HostSupervisionError::CapacityExhausted)?;
        u64::try_from(bytes).map_err(|_| HostSupervisionError::CapacityExhausted)
    }
}

fn arc_bytes<T>() -> Result<usize, HostSupervisionError> {
    Layout::new::<(AtomicUsize, AtomicUsize)>()
        .extend(Layout::new::<T>())
        .map(|(layout, _)| layout.pad_to_align().size())
        .map_err(|_| HostSupervisionError::CapacityExhausted)
}

// These fields match the pinned standard library's B-tree node representation.
// Allocation probes verify both monomorphizations against its actual requests.
// A toolchain update must retain those checks before this bound is accepted.
#[expect(dead_code, reason = "only the node allocation layout is used")]
struct TreeLeaf<K, V> {
    parent: Option<NonNull<TreeInternal<K, V>>>,
    parent_idx: MaybeUninit<u16>,
    len: u16,
    keys: [MaybeUninit<K>; 11],
    vals: [MaybeUninit<V>; 11],
}

#[repr(C)]
struct TreeInternal<K, V> {
    leaf: TreeLeaf<K, V>,
    edges: [NonNull<TreeLeaf<K, V>>; 12],
}

#[cfg(test)]
mod tests;
