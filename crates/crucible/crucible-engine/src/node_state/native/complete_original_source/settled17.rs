//! Moves completed current17 cold owners through the actual Source birth.
//!
//! No decoder is called through a ticket or a fresh Source. The exact signed
//! validation occurrence supplies all retained owners before the Rc is created.

use super::*;

impl CompleteOriginalRestorationSource {
    pub(crate) fn take_restored_decoded_collection_into_data(
        &self,
        output: &mut Option<super::super::RetainedCold17Collection>,
    ) -> Result<(), RuntimeError> {
        self.inner.authenticate_birth()?;
        self.inner.host.restored_data()?;
        if output.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut original = self
            .inner
            .restored_collection
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        original
            .as_ref()
            .ok_or(RuntimeError::OutstandingObligations)?
            .authenticate_completed_data(&self.inner.archive)?;
        *output = original.take();
        self.inner.authenticate_birth()
    }
}

#[path = "settled17/prebirth_loan.rs"]
mod prebirth_loan;

#[path = "settled17/model18_construction.rs"]
mod model18_construction;
