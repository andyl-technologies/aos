//! Reads original directory publishers without calling erased store callbacks.

use super::*;
use crate::node_qualification::{QualificationError, RetainedMetadataCounter as Counter};
use crucible_store::content_store::DirectoryBlobBackend;

impl StoredWorldActivationPublisher {
    pub(crate) fn charge_original_directory_storage_data<T: MutableRefBackend + ?Sized>(
        &self,
        expected_blobs: &Arc<DirectoryBlobBackend>,
        expected_refs: &Arc<T>,
        counter: &mut Counter,
    ) -> Result<(), QualificationError> {
        let Self {
            blobs,
            refs,
            reference,
            prepared,
        } = self;
        // Concrete aliases come from the same closed construction. Comparing
        // data addresses ignores vtable duplication and invokes no backend.
        if !std::ptr::addr_eq(Arc::as_ptr(blobs), Arc::as_ptr(expected_blobs))
            || !std::ptr::addr_eq(Arc::as_ptr(refs), Arc::as_ptr(expected_refs))
        {
            return Err(QualificationError::Refused(
                "unknown Clock publisher storage owner",
            ));
        }
        counter.add(reference.retained_requested_storage_data())?;
        if let Some(prepared) = prepared {
            prepared.charge_original_storage_data(counter)?;
        }
        Ok(())
    }
}
