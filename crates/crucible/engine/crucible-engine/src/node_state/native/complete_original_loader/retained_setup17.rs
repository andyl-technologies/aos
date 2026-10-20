//! Observes the actual selected complete-load record before Source17 construction.
//!
//! The ordinary record observer remains closed to complete-load receipts. This
//! distinct view requires the genuine private receipt and exact index/directory
//! identities; receipt data are inline and cannot recreate that live admission.

use super::*;

impl NativeArchiveRecord {
    /// Counts this actual complete-load record and all retained record backing.
    ///
    /// The existing concrete manifest/index/directory census includes this
    /// record's inline root. The complete-load receipt owns no independent heap.
    /// This reads metadata only: no file, hash, validator or native callback runs.
    ///
    /// # Errors
    /// Refuses absent or foreign selected-load custody, changed private backing
    /// identities, unsupported actual metadata or checked extent overflow.
    pub fn original_complete_load_retained_requested_storage_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        let Self {
            complete_load: _,
            index: _,
            manifest: _,
            directory: _,
            limits: _,
        } = self;
        self.authenticate_complete_load_admission()?;
        let original = self
            .complete_load
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let CompleteLoadAdmission {
            process: _,
            thread: _,
            index: _,
            directory: _,
            maximum: _,
        } = original;
        let bytes = self.capture_owned_storage()?;
        self.authenticate_complete_load_admission()?;
        Ok(bytes)
    }

    /// Names the fixed receipt/record/result views of the raw selected-load census.
    ///
    /// The enclosing complete Source/archive observer supplies its existing
    /// concrete record/index traversal scratch independently of this loan.
    pub fn original_complete_load_retained_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<&CompleteLoadAdmission>()
            + std::mem::size_of::<Option<&CompleteLoadAdmission>>()
            + std::mem::size_of::<Result<usize, RuntimeError>>()
            + std::mem::size_of::<Result<(), RuntimeError>>()
            + std::mem::size_of::<usize>()
    }
}
