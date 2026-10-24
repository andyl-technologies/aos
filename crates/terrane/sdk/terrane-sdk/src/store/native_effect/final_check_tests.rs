//! Supplies typed clock checks for retained-effect unit mechanics only.
//!
//! The module is a test-only descendant of selected_bridge, so it can initialize
//! its private owned callback without a production callback constructor. It
//! checks the actual retained clock; it supplies no actor or physical authority.

#[cfg(not(feature = "send"))]
use std::rc::Rc as Shared;
#[cfg(feature = "send")]
use std::sync::Arc as Shared;
use std::time::Duration;

use super::OwnedFinalCheck;
use crate::store::{Clock, NativeEffectClock, StoreErrorKind, StoreFailure};

/// Creates a test-only deadline check from the exact retained clock state.
///
/// The callback refuses elapsed deadlines and backward monotonic time using
/// the coordinator's strict `elapsed > maximum` boundary. Its deliberately
/// test-specific denial does not define production deadline error mapping or
/// establish that a request was authenticated.
pub(crate) fn deadline_check(
    clock: NativeEffectClock,
    started: Duration,
    maximum: Duration,
) -> OwnedFinalCheck {
    OwnedFinalCheck {
        check: Shared::new(move || {
            let elapsed = clock.monotonic().checked_sub(started);
            if elapsed.is_none_or(|elapsed| elapsed > maximum) {
                return Err(StoreFailure::new(StoreErrorKind::Denied {
                    verb: "test-deadline",
                    pattern: "/retained-effect-mechanics".to_owned(),
                }));
            }
            Ok(())
        }),
    }
}
