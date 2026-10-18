//! Defers supervisor heap controls until its actual containing payer is admitted.
//!
//! Preparation captures one immutable original start and unique identity without
//! publishing a roster, wakeup, cancellation object or operation. Publication
//! consumes that same prepared value; delay cannot renew its lifetime.

use super::*;

/// Owns one original supervisor start before its shared controls are allocated.
///
/// This value is not cloneable and grants no resource, work or cleanup credit.
/// Its caller must admit the genuine containing owner before calling publish.
#[must_use = "retain the original start or consume it after the actual payer is admitted"]
pub struct PreparedHostOperationSupervisor {
    budgets: HostOperationBudgets,
    outer: Option<Duration>,
    started: Instant,
    original_monotonic_ns: u64,
    cap_id: [u8; 32],
}

impl HostOperationSupervisor {
    /// Captures one supervisor start without allocating its shared controls.
    ///
    /// The validation and identity-exhaustion order matches ordinary new. Both
    /// time coordinates are captured once and remain private to the owner.
    ///
    /// # Errors
    /// Returns the original invalid-budget, identity-exhaustion or monotonic
    /// coordinate refusal before shared control allocation.
    pub fn prepare(
        budgets: HostOperationBudgets,
        outer: Option<Duration>,
    ) -> Result<PreparedHostOperationSupervisor, HostSupervisionError> {
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
        // Sampling before the Instant origin cannot extend the native cap.
        let original_monotonic_ns = kernel_monotonic_ns()?;
        Ok(PreparedHostOperationSupervisor {
            budgets,
            outer,
            started: host_now(),
            original_monotonic_ns,
            cap_id,
        })
    }
}

impl PreparedHostOperationSupervisor {
    /// Returns the reserved logical identity without publishing any authority.
    #[must_use]
    pub const fn cap_id(&self) -> [u8; 32] {
        self.cap_id
    }

    /// Allocates shared controls using the SAME original start and identity.
    ///
    /// This operation creates no containing resource debit. The caller must
    /// retain its independently admitted payer through physical control return.
    ///
    /// # Errors
    /// Returns the actual shared-roster publication refusal. It never captures
    /// another origin, retries allocation or substitutes a new identity.
    pub fn publish(self) -> Result<HostOperationSupervisor, HostSupervisionError> {
        let changed = Arc::new(Condvar::new());
        HostOperationSupervisor::publish(
            self.budgets,
            self.outer,
            self.started,
            self.original_monotonic_ns,
            self.cap_id,
            changed,
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delayed_publication_keeps_both_origins_and_the_already_expired_cap() {
        let mut prepared = HostOperationSupervisor::prepare(
            HostOperationBudgets::default(),
            Some(Duration::from_millis(1)),
        )
        .unwrap();
        // Backdate the private, unpublished origin to model delayed publication.
        prepared.started = host_now() - Duration::from_secs(1);
        let started = prepared.started;
        let monotonic = prepared.original_monotonic_ns;
        let identity = prepared.cap_id();

        let supervisor = prepared.publish().unwrap();

        assert_eq!(supervisor.shared.started, started);
        assert_eq!(supervisor.shared.original_monotonic_ns, monotonic);
        assert_eq!(supervisor.cap_id(), identity);
        assert!(matches!(
            supervisor.outer_cap_status().unwrap().state,
            HostOperationState::Expired
        ));
        assert!(matches!(
            supervisor.begin(HostOperationClass::Setup),
            Err(HostSupervisionError::Terminal {
                state: HostOperationState::Expired
            })
        ));
    }

    #[test]
    fn reversed_publication_preserves_each_reserved_identity_and_live_roster() {
        let first =
            HostOperationSupervisor::prepare(HostOperationBudgets::default(), None).unwrap();
        let second =
            HostOperationSupervisor::prepare(HostOperationBudgets::default(), None).unwrap();
        let first_id = first.cap_id();
        let second_id = second.cap_id();
        assert_ne!(first_id, second_id);

        let second = second.publish().unwrap();
        let first = first.publish().unwrap();
        let operation = first.begin(HostOperationClass::Preparation).unwrap();

        assert_eq!(first.cap_id(), first_id);
        assert_eq!(second.cap_id(), second_id);
        assert!(!first.shares_outer_cap(&second));
        assert_eq!(first.outer_cap_binding().unwrap().cap_id, first_id);
        assert_eq!(first.status_snapshot().unwrap().1.len(), 1);
        assert!(second.status_snapshot().unwrap().1.is_empty());
        operation.complete().unwrap();
    }

    #[test]
    fn immediate_and_prepared_construction_keep_the_same_budget_refusals() {
        let budgets = HostOperationBudgets::default();
        assert!(matches!(
            HostOperationSupervisor::prepare(budgets, Some(Duration::ZERO)),
            Err(HostSupervisionError::InvalidBudget)
        ));
        assert!(matches!(
            HostOperationSupervisor::new(budgets, Some(Duration::ZERO)),
            Err(HostSupervisionError::InvalidBudget)
        ));

        let immediate = HostOperationSupervisor::new(budgets, None).unwrap();
        let prepared = HostOperationSupervisor::prepare(budgets, None)
            .unwrap()
            .publish()
            .unwrap();
        assert_eq!(immediate.status_snapshot().unwrap().0.allowance, None);
        assert_eq!(prepared.status_snapshot().unwrap().0.allowance, None);
        assert!(immediate.status_snapshot().unwrap().1.is_empty());
        assert!(prepared.status_snapshot().unwrap().1.is_empty());
    }

    #[test]
    fn exact_guard_owner_rejects_a_foreign_roster_under_the_same_outer_cap() {
        let original = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let alias = original.clone();
        let foreign = original
            .new_budget_owner(HostOperationBudgets::default())
            .unwrap();
        let operation = original.begin(HostOperationClass::Restore).unwrap();

        assert!(operation.belongs_to_supervisor(&alias));
        assert!(operation.shares_outer_cap(&foreign));
        assert!(!operation.belongs_to_supervisor(&foreign));
        operation
            .verify_operation_class(HostOperationClass::Restore)
            .unwrap();
        operation.complete().unwrap();
    }
}
