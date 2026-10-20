//! One real request reservation beneath the installed common scheduling policy.
//!
//! Only configured callers use this helper. Their actual current lease, floor,
//! cohort and original cutoff remain the admission checks. A transferred Copy
//! permit is already an owner and must not pass through this acquisition again.

use anyhow::{ensure, Result};

use super::Policy;
use crate::direct_upload::provider_capacity::{self, Class, Permit};

/// Reserves one configured request while checking its original authority.
///
/// # Errors
/// Refuses an incompatible active pool, stale original or bounded wait failure.
pub(crate) async fn acquire(
    policy: &Policy,
    class: Class,
    fresh: &dyn Fn() -> Result<()>,
) -> Result<Permit> {
    provider_capacity::configure(policy.maximum_provider_requests)?;
    provider_capacity::acquire_class_checked(1, class, &|| fresh()).await
}

#[cfg(test)]
mod tests;

/// Checks a real one-request outer owner without reserving another pool slot.
///
/// The caller keeps the borrowed permit through the entire provider response.
/// Copy's atomic two-request owner and transferred source tickets use their own
/// custody path and cannot masquerade as this one-request verification owner.
///
/// # Errors
/// Refuses another active pool, a non-single request owner or stale authority.
pub(crate) fn validate_held(
    policy: &Policy,
    permit: &Permit,
    fresh: &dyn Fn() -> Result<()>,
) -> Result<()> {
    fresh()?;
    provider_capacity::configure(policy.maximum_provider_requests)?;
    ensure!(
        permit.count == 1
            && provider_capacity::POOL
                .with(|current| std::rc::Rc::ptr_eq(&current.borrow(), &permit.pool)),
        "configured request outer capacity differs"
    );
    fresh()
}
