//! Lends actual original parent bodies from the completed three-Source roster.
//!
//! Early metadata comes from the genuine Window's retained Source rows. Late
//! bodies come from actual completed Source custody. Neither callback turns a
//! ContentRef into an intrinsic leaf or interprets numeric credit as authority.

use super::*;
use crucible::node_contract::{RestoredCollectingCaptureScope17, RuntimeError};
use crucible::node_state::ImportedClosureGeometry17;

/// Names the real Source lender and the enclosing fixed adapter controls.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<ImportedClosureGeometry17>()
        + size_of::<Result<ImportedClosureGeometry17, StateError>>()
        + size_of::<Option<StateError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<(&ContentRef, &[u8], &[ContentRef])>()
        + size_of::<&mut dyn FnMut(&ContentRef, &[u8], &[ContentRef]) -> Result<(), StateError>>()
        + size_of::<
            std::slice::Iter<'_, Rc<crucible::node_adapters::cnp::PacketCompleteSemanticSource>>,
        >()
        + crucible::node_state::imported_closure17_counter_scratch_data()
}

impl PacketCompleteCaptureFactory {
    pub(super) fn imported17_geometry(
        &self,
        scope: &RestoredCollectingCaptureScope17<'_>,
        completed: bool,
    ) -> Result<ImportedClosureGeometry17, StateError> {
        self.authenticate_storage_origin()?;
        scope.authenticate_current_data().map_err(error)?;
        let mut rows = [(0, 0, 0, 0, 0, 0, 0, 0); 3];
        for (source, row) in self.authority.roster().sources.iter().zip(&mut rows) {
            *row = if completed {
                source
                    .original_capture17_completed_imported_closure_storage_data()
                    .map_err(error)?
            } else {
                scope
                    .original_source_imported_closure_storage_data(source)
                    .map_err(error)?
            };
        }
        scope.authenticate_current_data().map_err(error)?;
        Ok(rows)
    }

    pub(super) fn visit_imported17_objects(
        &self,
        scope: &RestoredCollectingCaptureScope17<'_>,
        inspect: &mut dyn FnMut(&ContentRef, &[u8], &[ContentRef]) -> Result<(), StateError>,
    ) -> Result<(), StateError> {
        self.authenticate_storage_origin()?;
        scope.authenticate_current_data().map_err(error)?;
        for source in &self.authority.roster().sources {
            let mut failure = None;
            let result = source.visit_original_capture17_imported_objects_data(
                |reference, bytes, dependencies| match inspect(reference, bytes, dependencies) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        failure = Some(error);
                        Err(RuntimeError::ForeignAuthority)
                    }
                },
            );
            if let Some(error) = failure {
                return Err(error);
            }
            result.map_err(error)?;
        }
        scope.authenticate_current_data().map_err(error)
    }
}
