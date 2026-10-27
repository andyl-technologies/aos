//! Bounded, tenant-aware admission for Git pack publication work.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_channel::oneshot;

use super::RpcError;

const BODY_CONCURRENCY: usize = 4;
const BODY_CONCURRENCY_PER_TENANT: usize = 2;
const VALIDATION_CONCURRENCY: usize = 1;
const MAX_QUEUED_OPERATIONS: usize = 32;

/// Separates bounded body retention from exclusive pack parsing.
pub(super) struct PackAdmission {
    bodies: Arc<FairAdmission>,
    validation: Arc<FairAdmission>,
}

impl PackAdmission {
    /// Creates the process-wide production admission policy.
    pub(super) fn production() -> Self {
        Self::new(
            BODY_CONCURRENCY,
            BODY_CONCURRENCY_PER_TENANT,
            VALIDATION_CONCURRENCY,
            MAX_QUEUED_OPERATIONS,
        )
    }

    fn new(
        body_capacity: usize,
        body_capacity_per_tenant: usize,
        validation_capacity: usize,
        queue_capacity: usize,
    ) -> Self {
        Self {
            bodies: FairAdmission::new(body_capacity, body_capacity_per_tenant, queue_capacity),
            validation: FairAdmission::new(
                validation_capacity,
                validation_capacity,
                queue_capacity,
            ),
        }
    }

    /// Reserves one bounded body slot for `tenant`.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::ResourceExhausted`] when the wait queue is full, or
    /// [`RpcError::Unavailable`] if admission shuts down while waiting.
    pub(super) async fn admit_body(&self, tenant: &str) -> Result<AdmissionPermit, RpcError> {
        self.bodies.acquire(tenant).await
    }

    /// Reserves exclusive pack-validation capacity for `tenant`.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::ResourceExhausted`] when the wait queue is full, or
    /// [`RpcError::Unavailable`] if admission shuts down while waiting.
    pub(super) async fn admit_validation(&self, tenant: &str) -> Result<AdmissionPermit, RpcError> {
        self.validation.acquire(tenant).await
    }
}

/// Runs a complete admitted operation within one total deadline.
///
/// # Errors
///
/// Returns the operation's error, or [`RpcError::Unavailable`] when the
/// deadline expires before the operation completes.
pub(super) async fn run_with_deadline<F, T>(duration: Duration, operation: F) -> Result<T, RpcError>
where
    F: Future<Output = Result<T, RpcError>>,
{
    let timeout = aos_hub_model::clock::sleep(duration);
    futures_util::pin_mut!(operation, timeout);

    match futures_util::future::select(operation, timeout).await {
        futures_util::future::Either::Left((result, _)) => result,
        futures_util::future::Either::Right(((), _)) => Err(RpcError::Unavailable(
            "Git pack publication timed out".into(),
        )),
    }
}

struct FairAdmission {
    capacity: usize,
    capacity_per_tenant: usize,
    queue_capacity: usize,
    state: Mutex<AdmissionState>,
}

#[derive(Default)]
struct AdmissionState {
    active: usize,
    active_by_tenant: HashMap<String, usize>,
    waiters: VecDeque<Waiter>,
    last_granted_tenant: Option<String>,
}

struct Waiter {
    tenant: String,
    ready: oneshot::Sender<AdmissionPermit>,
}

/// Releases one admission slot when dropped.
pub(super) struct AdmissionPermit {
    admission: Arc<FairAdmission>,
    tenant: String,
    active: bool,
}

impl FairAdmission {
    fn new(capacity: usize, capacity_per_tenant: usize, queue_capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            capacity_per_tenant,
            queue_capacity,
            state: Mutex::new(AdmissionState::default()),
        })
    }

    async fn acquire(self: &Arc<Self>, tenant: &str) -> Result<AdmissionPermit, RpcError> {
        let receiver = {
            let mut state = lock_state(&self.state);
            prune_cancelled(&mut state);

            if can_admit(self, &state, tenant) && state.waiters.is_empty() {
                record_grant(&mut state, tenant);
                return Ok(AdmissionPermit {
                    admission: Arc::clone(self),
                    tenant: tenant.to_owned(),
                    active: true,
                });
            }
            if state.waiters.len() >= self.queue_capacity {
                return Err(RpcError::ResourceExhausted(
                    "Git pack publication queue is full".into(),
                ));
            }

            let (ready, receiver) = oneshot::channel();
            state.waiters.push_back(Waiter {
                tenant: tenant.to_owned(),
                ready,
            });
            dispatch(self, &mut state);
            receiver
        };

        receiver
            .await
            .map_err(|_| RpcError::Unavailable("Git pack publication admission closed".into()))
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        let mut state = lock_state(&self.admission.state);
        state.active = state.active.saturating_sub(1);
        decrement_tenant(&mut state, &self.tenant);
        dispatch(&self.admission, &mut state);
    }
}

fn lock_state(mutex: &Mutex<AdmissionState>) -> MutexGuard<'_, AdmissionState> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn can_admit(admission: &FairAdmission, state: &AdmissionState, tenant: &str) -> bool {
    state.active < admission.capacity
        && state.active_by_tenant.get(tenant).copied().unwrap_or(0) < admission.capacity_per_tenant
}

fn record_grant(state: &mut AdmissionState, tenant: &str) {
    state.active += 1;
    *state.active_by_tenant.entry(tenant.to_owned()).or_default() += 1;
    state.last_granted_tenant = Some(tenant.to_owned());
}

fn decrement_tenant(state: &mut AdmissionState, tenant: &str) {
    let Some(active) = state.active_by_tenant.get_mut(tenant) else {
        return;
    };
    *active = active.saturating_sub(1);
    if *active == 0 {
        state.active_by_tenant.remove(tenant);
    }
}

fn prune_cancelled(state: &mut AdmissionState) {
    state.waiters.retain(|waiter| !waiter.ready.is_canceled());
}

fn dispatch(admission: &Arc<FairAdmission>, state: &mut AdmissionState) {
    prune_cancelled(state);
    while state.active < admission.capacity {
        let preferred = state.waiters.iter().position(|waiter| {
            can_admit(admission, state, &waiter.tenant)
                && state.last_granted_tenant.as_deref() != Some(waiter.tenant.as_str())
        });
        let fallback = state
            .waiters
            .iter()
            .position(|waiter| can_admit(admission, state, &waiter.tenant));
        let Some(index) = preferred.or(fallback) else {
            break;
        };
        let Some(waiter) = state.waiters.remove(index) else {
            break;
        };

        record_grant(state, &waiter.tenant);
        let permit = AdmissionPermit {
            admission: Arc::clone(admission),
            tenant: waiter.tenant.clone(),
            active: true,
        };
        if let Err(mut permit) = waiter.ready.send(permit) {
            state.active = state.active.saturating_sub(1);
            decrement_tenant(state, &waiter.tenant);
            permit.active = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn body_admission_reserves_capacity_for_another_tenant() {
        let admission = PackAdmission::new(3, 2, 1, 8);
        let _a1 = admission.admit_body("a").await.unwrap();
        let _a2 = admission.admit_body("a").await.unwrap();
        let queued_a1 = admission.admit_body("a");
        let queued_a2 = admission.admit_body("a");
        let b = admission.admit_body("b");
        futures_util::pin_mut!(queued_a1, queued_a2, b);

        assert!(futures_util::poll!(&mut queued_a1).is_pending());
        assert!(futures_util::poll!(&mut queued_a2).is_pending());
        assert!(futures_util::poll!(&mut b).is_ready());
    }

    #[tokio::test]
    async fn validation_queue_rotates_between_tenants() {
        let admission = PackAdmission::new(4, 2, 1, 8);
        let active = admission.admit_validation("a").await.unwrap();
        let next_a = admission.admit_validation("a");
        let next_b = admission.admit_validation("b");
        futures_util::pin_mut!(next_a, next_b);
        assert!(futures_util::poll!(&mut next_a).is_pending());
        assert!(futures_util::poll!(&mut next_b).is_pending());

        drop(active);
        let b_permit = next_b.await.unwrap();
        assert!(futures_util::poll!(&mut next_a).is_pending());
        drop(b_permit);
        assert!(next_a.await.is_ok());
    }

    #[tokio::test]
    async fn cancelled_waiter_does_not_consume_a_permit() {
        let admission = PackAdmission::new(1, 1, 1, 2);
        let active = admission.admit_body("a").await.unwrap();
        let mut cancelled = Box::pin(admission.admit_body("b"));
        assert!(futures_util::poll!(&mut cancelled).is_pending());
        drop(cancelled);

        drop(active);
        assert!(admission.admit_body("c").await.is_ok());
    }

    #[tokio::test]
    async fn queue_rejects_work_beyond_its_bound() {
        let admission = PackAdmission::new(1, 1, 1, 1);
        let _active = admission.admit_body("a").await.unwrap();
        let queued = admission.admit_body("b");
        futures_util::pin_mut!(queued);
        assert!(futures_util::poll!(&mut queued).is_pending());

        assert!(matches!(
            admission.admit_body("c").await,
            Err(RpcError::ResourceExhausted(_))
        ));
    }

    #[tokio::test]
    async fn slow_placement_work_does_not_hold_validation_admission() {
        let admission = PackAdmission::new(2, 1, 1, 4);
        let _slow_body = admission.admit_body("a").await.unwrap();
        let validation = admission.admit_validation("a").await.unwrap();
        drop(validation);

        let _other_body = admission.admit_body("b").await.unwrap();
        assert!(admission.admit_validation("b").await.is_ok());
    }

    #[tokio::test]
    async fn failed_validation_releases_both_admissions() {
        let admission = PackAdmission::new(1, 1, 1, 2);
        let result: Result<(), ()> = async {
            let _body = admission.admit_body("a").await.map_err(|_| ())?;
            let _validation = admission.admit_validation("a").await.map_err(|_| ())?;
            Err(())
        }
        .await;
        assert!(result.is_err());

        let _next_body = admission.admit_body("b").await.unwrap();
        assert!(admission.admit_validation("b").await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_includes_time_spent_waiting_for_admission() {
        let operation = run_with_deadline(Duration::from_secs(5), async {
            futures_util::future::pending::<()>().await;
            Ok(())
        });
        tokio::pin!(operation);
        assert!(futures_util::poll!(&mut operation).is_pending());

        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(matches!(operation.await, Err(RpcError::Unavailable(_))));
    }
}
