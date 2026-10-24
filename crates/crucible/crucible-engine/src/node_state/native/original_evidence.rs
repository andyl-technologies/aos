//! Verifies source-retained original archive objects without granting restoration.

use super::*;

impl NativeArchiveRecord {
    /// Verifies a retained core object's bytes and its signed direct dependencies.
    ///
    /// The reference must occur in this original authenticated index. No path,
    /// digest-only match, external URI or caller-selected dependency inventory is
    /// accepted. The returned references are data; they authorize no source
    /// adoption, capture, fresh owner construction or native operation.
    ///
    /// # Errors
    /// Refuses changed bytes, unavailable retained storage, unsupported bounds or
    /// an oversized original dependency list. Returns `None` when the complete
    /// reference does not belong to this record's signed core object inventory.
    pub fn verify_retained_evidence_data(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
        maximum_dependencies: usize,
    ) -> Result<Option<Vec<ContentRef>>, StateError> {
        let Some(object) = self
            .index
            .objects
            .iter()
            .find(|object| &object.reference == reference)
        else {
            return Ok(None);
        };
        if maximum_bytes == 0
            || reference.length.get() > maximum_bytes as u64
            || object.dependencies.len() > maximum_dependencies
        {
            return Err(limit("original evidence verification bounds"));
        }
        // This is the same no-follow, length-bounded and full-reference checked
        // reader as normal archive admission, not a portable report decoder.
        self.object_bytes(reference, maximum_bytes)?;
        let mut dependencies = Vec::new();
        dependencies
            .try_reserve_exact(object.dependencies.len())
            .map_err(|_| limit("original evidence dependency reservation"))?;
        dependencies.extend(object.dependencies.iter().cloned());
        Ok(Some(dependencies))
    }

    /// Counts this retained record's requested backing under the native layout.
    ///
    /// The existing owner walk counts the actual manifest, immutable index and
    /// directory handle headers. Conservatively counting another view retains
    /// its real obligations; byte equality never deduplicates independent heaps.
    /// Kernel storage and allocator implementation overhead remain outside this
    /// requested-layout row and are not granted by this observer.
    ///
    /// # Errors
    /// Refuses checked size overflow or unsupported retained field accounting.
    pub fn retained_record_requested_storage_data(
        &self,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        let Self {
            complete_load,
            index: _,
            manifest: _,
            directory: _,
            limits: _,
        } = self;
        if complete_load.is_some() {
            return Err(crate::node_contract::RuntimeError::UnsupportedFacet);
        }
        self.capture_owned_storage()
    }
}
