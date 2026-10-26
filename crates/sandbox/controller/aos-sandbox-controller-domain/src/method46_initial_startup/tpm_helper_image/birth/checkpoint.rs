//! Captures Source-paid checkpoint staging before the first native NV request.
//!
//! Security derives the canonical checkpoint from its resident approved request.
//! The same Source owns the native prefix and fixed journal encoder; comparison
//! DATA grants no publication or TPM authority.

use super::*;

impl Method46InitialTpmHelperDrivingLoanV1<'_> {
    /// Captures the fixed checkpoint stage as an exact canonical prefix once.
    ///
    /// The Source prepays before encoding or opening the existing stage. This
    /// read-only step must complete before any NV request; a conflicting prefix
    /// cannot be discovered only after the first Extend. No file is created,
    /// written, truncated, renamed or removed by this method.
    ///
    /// # Errors
    /// Refuses failed/ended Source, reentry, missing original locks, insufficient
    /// funding, changed native main, unsafe stage or a nonmatching prefix. Every
    /// reached native failure and the independent main post remain resident.
    pub fn capture_initial_checkpoint_stage_once_v1(
        &mut self,
        checkpoint: [u8; 156],
    ) -> Result<(), Method46InitialStartupClosedV1> {
        require_current(self.startup)?;
        let action = (|| {
            let body = self.startup.body.as_ref().ok_or(self.startup.closed)?;
            let mut writer = body
                .main_writer
                .try_borrow_mut()
                .map_err(|_| self.startup.closed)?;
            let demand = writer.quote_initial_checkpoint_once();
            self.startup.fund_additional(demand)?;
            writer
                .capture_initial_checkpoint_once(checkpoint)
                .map_err(|_| self.startup.closed)
        })();
        let after = require_current(self.startup);
        if action.is_err() || after.is_err() {
            Err(self.startup.fail(First::MainWriter))
        } else {
            Ok(())
        }
    }
}
