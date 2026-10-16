//! Copies the same original Report into its pre-Child Source return bank.
//!
//! The outer13 marker supplies only a full reference. The actual original SDK
//! content loan authenticates the same retained proof bytes before copying;
//! full native14 cold validation separately joins its typed and raw owner.

use super::*;
use crucible_node_provider::reference_packet::service::native_snapshot::PacketNativeOwned13SnapshotPlan;

impl OriginalCompleteCaptureExecution {
    pub(super) fn retain_original_allocation_report(
        &mut self, plan: &PacketNativeOwned13SnapshotPlan<'_>,
        scope: &CnpSemanticRealizationScope<'_>, maximum: usize,
    ) -> Result<(), OperationFailure> {
        if !self.allocation_selected || self.allocation.is_some()
            || self.allocation_bank.capacity() < allocation_report_capacity()
            || !self.allocation_bank.is_empty()
        {
            return Err(refused("original Report return bank is absent or spent"));
        }
        let decode = NodeRuntime::capture_selected_json_decode_storage(
            plan.allocation_reference_bytes(), size_of::<ContentRef>(),
            NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(), maximum,
        ).map_err(unknown)?;
        let admitted = self.dependency_plan.as_ref()
            .ok_or_else(|| refused("original Report phase has no pre-effect dependency plan"))?
            .maximum_lookup_scratch_data();
        let phase = allocation_reference_phase_storage_data(maximum)?;
        if decode > phase || phase > admitted {
            return Err(refused("original Report decoder exceeds its pre-effect phase credit"));
        }
        retained_values::sum([self.retained_storage(maximum)?, phase], maximum)?;
        let reference: ContentRef = serde_json::from_slice(plan.allocation_reference_bytes()).map_err(unknown)?;
        // Install both owners before the next fallible SDK loan or hash check.
        self.allocation = Some(InputPayload { reference, bytes: std::mem::take(&mut self.allocation_bank) });
        let report = self.allocation.as_ref().ok_or_else(|| refused("original Report slot absent"))?;
        let body = scope.controller.original_capture_allocation_body_data(&report.reference).map_err(unknown)?;
        plan.authenticate_allocation_bytes(body).map_err(unknown)?;
        if body.len() > allocation_report_capacity() || body.len() > report.bytes.capacity() {
            return Err(refused("original Report exceeds its pre-Child bank"));
        }
        self.retained_storage(maximum)?;
        self.allocation.as_mut().ok_or_else(|| refused("original Report slot lost"))?.bytes.extend_from_slice(body);
        Ok(())
    }
}

// This closed serializer describes future reference fields only. It is not a
// fabricated ContentRef/report and creates no content identity or permission.
#[derive(serde::Serialize)]
struct AllocationReferenceProjection<'a> {
    hash: AllocationHashProjection<'a>,
    length: U64,
    media_type: &'static str,
}

#[derive(serde::Serialize)]
struct AllocationHashProjection<'a> {
    algorithm: &'static str,
    digest: &'a str,
    domain: &'static str,
}

pub(super) fn allocation_reference_phase_storage_data(maximum: usize) -> Result<usize, OperationFailure> {
    use super::super::archive_owner::CompleteNativeSnapshotClass;
    let projection = AllocationReferenceProjection {
        hash: AllocationHashProjection {
            algorithm: "blake3-256", digest: "0000000000000000000000000000000000000000000000000000000000000000",
            domain: "cnp.blob.v1",
        },
        length: U64::new(u64::try_from(allocation_report_capacity()).map_err(unknown)?),
        media_type: crucible_node_provider::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,
    };
    retained_values::sum([
        NodeRuntime::capture_future_decode_storage(&projection, maximum).map_err(unknown)?,
        size_of::<AllocationReferenceProjection<'_>>(),
        size_of::<ContentRef>(),
        size_of::<blake3::Hasher>(),
        size_of::<blake3::Hash>(),
        super::super::archive_owner::snapshot_parser_known_storage_for_class(CompleteNativeSnapshotClass::StartupCapture14, maximum)?,
    ], maximum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_report_reference_phase_dominates_actual_reference_decode() -> Result<(), OperationFailure> {
        let body = vec![b'a'; allocation_report_capacity()];
        let reference = canonical::content_ref(&body,
            crucible_node_provider::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA).map_err(unknown)?;
        let value = serde_json::to_value(&reference).map_err(unknown)?;
        let bytes = canonical::canonical_json(&value).map_err(unknown)?;
        let actual = NodeRuntime::capture_selected_json_decode_storage(&bytes, size_of::<ContentRef>(),
            NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(), usize::MAX).map_err(unknown)?;
        let bound = allocation_reference_phase_storage_data(usize::MAX)?;
        assert!(actual <= bound);
        assert_eq!(allocation_reference_phase_storage_data(bound)?, bound);
        assert!(allocation_reference_phase_storage_data(bound - 1).is_err());
        Ok(())
    }
}
