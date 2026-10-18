//! Drives the genuine Target owner still retained in its original Main role.
//!
//! A return stores only an original selector and safe monomorphized callbacks.
//! It neither allocates nor extracts a second Pending Box. Actual Loop body
//! destruction is checked by the containing role before each Target operation.

use std::any::Any;
use std::error::Error;

use super::prepared_service::PreparedSourceSelector;

/// Operates only on the existing saved Target and its actual Source checkout.
///
/// Implementations retain typed failures in their same preborn allocation.
/// They cannot issue another Target, World loan, operation or resource budget.
pub(crate) trait TargetConstructionPostBody: Send + 'static {
    /// Retries actual aggregate and Target loan obligations before metadata handback.
    fn retry_after_body(&mut self) -> bool;

    /// Observes the irreversible journal of those same owned obligations.
    fn is_physically_returned(&self) -> bool;

    /// Borrows the original Source selection retained from the actual checkout.
    fn source_selector(&self) -> &PreparedSourceSelector;

    /// Borrows the actual unchanged first cause from this same retained owner.
    fn first_failure(&self) -> Option<&(dyn Error + 'static)>;
}

pub(super) struct TargetReturn {
    selector: PreparedSourceSelector,
    retry: fn(&mut (dyn Any + Send)) -> bool,
    returned: fn(&(dyn Any + Send)) -> bool,
    physically_returned: bool,
}

impl TargetReturn {
    pub(super) fn new<T: TargetConstructionPostBody>(selector: PreparedSourceSelector) -> Self {
        Self {
            selector,
            retry: retry::<T>,
            returned: returned::<T>,
            physically_returned: false,
        }
    }

    pub(super) fn is_physically_returned(&self) -> bool {
        self.physically_returned
    }

    pub(super) fn retry_after_body(&mut self) -> bool {
        if self.physically_returned {
            return true;
        }
        self.physically_returned = self
            .selector
            .with_erased_after_body(|owner| {
                if (self.returned)(owner) {
                    true
                } else {
                    let _attempted = (self.retry)(owner);
                    (self.returned)(owner)
                }
            })
            .unwrap_or(false);
        self.physically_returned
    }
}

fn retry<T: TargetConstructionPostBody>(owner: &mut (dyn Any + Send)) -> bool {
    owner
        .downcast_mut::<T>()
        .is_some_and(TargetConstructionPostBody::retry_after_body)
}

fn returned<T: TargetConstructionPostBody>(owner: &(dyn Any + Send)) -> bool {
    owner
        .downcast_ref::<T>()
        .is_some_and(TargetConstructionPostBody::is_physically_returned)
}
