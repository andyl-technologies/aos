//! Walks actual complete current17 common custody without legacy phase shortcuts.
//!
//! The actual17 caller supplies the original process/thread/read fence. This
//! observer adds every generic base operation/input map to installed custody;
//! the separate old Initial15 observer keeps its existing refusal unchanged.

use std::mem::size_of;

use crate::node_adapters::cnp::semantic::{
    retained_storage::{Counter, common},
    state::SemanticRuntimeCustody,
};
use crate::node_contract::RuntimeError;

/// Separates the same actual current17 common owner's requested storage axes.
///
/// The visitor performs no allocation or serialization. Its retained sum is an
/// owner observation, while fixed traversal/return views remain an independent
/// scratch term. Neither term creates a Source or Capture permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CnpRestoredNode17RawStorageData {
    retained: usize,
    scratch: usize,
}

impl CnpRestoredNode17RawStorageData {
    pub(crate) const fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }
    pub(crate) const fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        0
    }
    pub(crate) const fn declared_counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }
}

impl SemanticRuntimeCustody {
    /// Counts complete actual custody for the independently selected17 caller.
    ///
    /// This raw observer does not establish currentness, eligibility or release
    /// authority. The caller retains the same Node/native loan and independently
    /// authenticates its actual17 action before using the observation in a row.
    ///
    /// # Errors
    /// Refuses absent installed custody, unsupported retained common children,
    /// unresolved owner layouts, checked overflow or the independent maximum.
    pub(in crate::node_adapters::cnp::semantic) fn retained_current17_runtime_storage_data(
        &self,
        maximum: usize,
    ) -> Result<CnpRestoredNode17RawStorageData, RuntimeError> {
        if self.installed_restoration.is_none() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut counter = Counter::new(maximum);
        counter
            .add(size_of::<Self>())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        // The defining common walk includes every base field and both actual
        // maps, including failed originals, typed requests, contexts and bytes.
        // It calls no Source policy, transport, native effect or old phase guard.
        common::runtime(self, &mut counter).map_err(|_| RuntimeError::UnsupportedFacet)?;
        let retained = counter
            .finish()
            .complete_requested_bytes()
            .map_err(|_| RuntimeError::UnsupportedFacet)?;
        let scratch = size_of::<Counter>()
            + size_of::<CnpRestoredNode17RawStorageData>()
            + size_of::<Result<CnpRestoredNode17RawStorageData, RuntimeError>>()
            + size_of::<&SemanticRuntimeCustody>()
            + crate::node_contract::opaque_owner_counter_scratch_data()
            // The installed custody owns an Initial15 association and no
            // settled17 family bank. Price the actual retained type.
            + crate::node_contract::OriginalInstalledRestorationNodeAssociation::counter_scratch_data();
        retained
            .checked_add(scratch)
            .filter(|bytes| *bytes <= maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(CnpRestoredNode17RawStorageData { retained, scratch })
    }
}
