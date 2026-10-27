//! Bounds native lineage reclamation while preserving its original custody.
//!
//! Expiration reports unresolved reclamation. It never releases the owning
//! native driver, replaces its command journal or invents a stopped boundary.

use std::time::Duration;

use crate::{
    ProviderError,
    reference_lineage::{NativeLineageDevice, transport::ExchangeBudget},
};

pub(super) fn quarantine(
    native: &mut NativeLineageDevice,
    timeout: Duration,
) -> Result<bool, ProviderError> {
    let budget = ExchangeBudget::after(timeout)
        .map_err(|_| ProviderError::ResourceExhausted("lineage source quarantine deadline"))?;
    loop {
        if native.poll_quarantine()? {
            return Ok(true);
        }
        if budget.is_expired() {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
