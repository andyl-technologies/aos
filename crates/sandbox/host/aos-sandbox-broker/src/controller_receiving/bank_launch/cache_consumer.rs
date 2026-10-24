//! Lends finite Cache projection comparisons from the actual Controller writer.
//!
//! The paired fixed opening remains the only native owner constructor. Every
//! lookup repeats its native-uncertainty gate. Returned DATA grant no Cache effect.

use aos_sandbox_model::{ProjectId, RecordNamespace};
use aos_sandbox_protocol::public_api::cache_consumer::{
    CacheAcquisitionFenceDataV1, CacheConsumerComparisonDataV1, CacheConsumerComparisonErrorV1,
    CacheConsumerDataV1,
};
use aos_sandbox_protocol::public_api::projection::{
    PublicProjectionKindV1, PublicProjectionRecordV1, PublicProjectionResourceV1,
    decode_checked_public_projection_v1, projection_key,
};
use aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1;

use super::coordinator::ControllerCoordinatorWriterV1;
use CacheConsumerComparisonErrorV1::Rejected;

/// Borrows the same genuine Controller native owner for a finite Cache read.
///
/// The non-Clone handle owns no files, allocation, credit or authority.
pub struct ControllerCacheConsumerReadBorrowV1<'writer, P> {
    writer: &'writer ControllerCoordinatorWriterV1<P>,
}

impl<P> ControllerCoordinatorWriterV1<P> {
    /// Borrows this actual Controller for ordered Cache consumer comparisons.
    ///
    /// Construction performs no read. Each projection read checks actual native
    /// uncertainty, including within a healthy entered Controller stage.
    #[must_use]
    pub fn borrow_cache_consumer_read_v1(&self) -> ControllerCacheConsumerReadBorrowV1<'_, P> {
        ControllerCacheConsumerReadBorrowV1 { writer: self }
    }
}

impl<P> ControllerCacheConsumerReadBorrowV1<'_, P> {
    /// Rechecks the requested consumer at the existing ordered native frontiers.
    ///
    /// # Errors
    /// Rejects malformed requests, native uncertainty, invalid canonical
    /// projections and current desired-state comparison mismatches.
    pub fn recheck_v1(
        &self,
        project: ProjectId,
        request: &DormantSandboxRequestKindV1,
    ) -> Result<CacheConsumerDataV1, CacheConsumerComparisonErrorV1> {
        let (comparison, object) = CacheConsumerComparisonDataV1::from_request(project, request)?;
        let fence = self.compare_projection_v1(&comparison)?;
        comparison.finish_consumer_data_v1(object, fence)
    }

    /// Compares current projections before compiling a Cache mutation intent.
    ///
    /// # Errors
    /// Preserves malformed identities and rejected native, canonical-projection
    /// or current desired-state comparisons. No effect permission is produced.
    pub fn compare_projection_v1(
        &self,
        comparison: &CacheConsumerComparisonDataV1<'_>,
    ) -> Result<Option<CacheAcquisitionFenceDataV1>, CacheConsumerComparisonErrorV1> {
        let view = {
            let record = self.load_projection(
                PublicProjectionKindV1::FilesystemView,
                comparison.view_id_data_v1(),
            )?;
            let PublicProjectionResourceV1::FilesystemView(view) = record.resource() else {
                return Err(Rejected);
            };
            view.clone()
        };
        comparison.compare_view_data_v1(&view)?;
        let runtime = if let Some(id) = comparison.attachment_id_data_v1()? {
            let attachment = {
                let record = self.load_projection(PublicProjectionKindV1::Attachment, id)?;
                let PublicProjectionResourceV1::Attachment(attachment) = record.resource() else {
                    return Err(Rejected);
                };
                attachment.clone()
            };
            let sandbox = {
                let record = self.load_projection(
                    PublicProjectionKindV1::Sandbox,
                    comparison.sandbox_id_data_v1(&attachment)?,
                )?;
                let PublicProjectionResourceV1::Sandbox(sandbox) = record.resource() else {
                    return Err(Rejected);
                };
                sandbox.clone()
            };
            comparison.compare_attached_runtime_data_v1(&view, &attachment, &sandbox)?
        } else {
            comparison.compare_unattached_resource_data_v1(&view)?;
            None
        };
        // Match the old owning scope: both attached clones are gone before
        // Release returns or the View descriptor allocates/converts.
        comparison.finish_projection_data_v1(&view, runtime)
    }

    fn load_projection(
        &self,
        kind: PublicProjectionKindV1,
        id: [u8; 16],
    ) -> Result<PublicProjectionRecordV1, CacheConsumerComparisonErrorV1> {
        // Match Journal::ensure_healthy, not the stricter idle-loan gate:
        // existing semantic checks run within a healthy entered C stage.
        if self.writer.has_native_uncertainty_v1() {
            return Err(Rejected);
        }
        let key = projection_key(kind, id);
        let value = self
            .writer
            .historical_view()
            .get(RecordNamespace::DesiredState, &key)
            .ok_or(Rejected)?;
        decode_checked_public_projection_v1(&key, value).map_err(|_| Rejected)
    }
}
