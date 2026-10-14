//! Counts borrowed archive-validation owners before vendor reconstruction.
//!
//! The verified content closure is intentionally excluded because a source's
//! fixed-owner reconstruction plan counts it once. Borrowed graph/source owners
//! and factory-specific banks remain separately admitted by their owning layer.

use super::{CompleteOriginalArchiveValidation, StateError};
use crate::node_contract::{NodeRuntime, RuntimeOriginalCaptureJournal};

impl CompleteOriginalArchiveValidation<'_> {
    /// Counts retained core validation owners, excluding verified object content.
    ///
    /// The count includes actual Runtime7 and scheduling container capacities,
    /// the administrative journal's independent owned strings and vectors, and
    /// the archive's manifest, index and backing-owner allocations. Shared archive
    /// owners are conservatively charged per view; portable equality never earns
    /// an allocation discount. This observer allocates nothing and grants no
    /// source, capture, restoration or readiness authority.
    ///
    /// The caller adds its own retained factory/source banks before reconstructing
    /// any typed protocol graph. This is a requested-layout accounting input,
    /// not an allocator-resident-byte or complete process-stack measurement.
    ///
    /// # Errors
    /// Refuses arithmetic overflow in the existing core capacity walkers.
    pub fn retained_allocation_bytes_excluding_content(&self) -> Result<usize, StateError> {
        let runtime = NodeRuntime::capture_runtime_record_storage(self.runtime)
            .map_err(super::super::schema)?;
        let scheduling = NodeRuntime::capture_scheduling_record_storage(self.scheduling)
            .map_err(super::super::schema)?;
        let administrative = NodeRuntime::capture_admin_storage(self.administrative)
            .map_err(super::super::schema)?;
        let archive = self
            .archive
            .capture_owned_storage()
            .map_err(super::super::schema)?;
        [
            runtime,
            scheduling,
            administrative,
            std::mem::size_of::<RuntimeOriginalCaptureJournal>(),
            archive,
        ]
        .into_iter()
        .try_fold(0usize, |total, next| {
            total
                .checked_add(next)
                .ok_or_else(|| super::refused("complete archive validation storage overflow"))
        })
    }
}

impl CompleteOriginalArchiveValidation<'_> {
    /// Decodes one bounded Host2 record before any native protocol reconstruction.
    ///
    /// The caller supplies its actual other retained banks, excluding the core
    /// validation owners and content counted here. Requested DOM, typed, parser,
    /// canonical validation and common-record reconstruction storage use the same
    /// closed Host2 walker as complete source adoption. The returned record is
    /// inert historical data; it cannot construct a host ticket or target source.
    ///
    /// # Errors
    /// Refuses absent content, finite-budget overflow, malformed Host2 data or a
    /// record whose unchanged Runtime7/scheduler differs from this archive scope.
    pub fn decode_host_continuation_data(
        &self,
        reference: &crucible_node_contract::ContentRef,
        lineage: crate::node_contract::OriginalInputLineageLimits,
        additional_retained_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<crate::node_contract::HostSchedulingContinuationRecord, StateError> {
        use crate::node_contract::{
            HostSchedulingContinuationLimits, HostSchedulingContinuationRecord,
            HostSchedulingRuntimeRecord,
        };
        let maximum_total_bytes = maximum_total_bytes
            .min(self.archive.limits.state.maximum_total_content_bytes)
            .min(self.archive.limits.native.maximum_total_record_bytes);
        let bytes = self
            .content
            .get(reference)
            .ok_or_else(|| super::refused("complete archived Host2 body absent"))?;
        if bytes.len() > self.archive.limits.state.maximum_record_bytes
            || bytes.len() > self.archive.limits.native.maximum_record_bytes
        {
            return Err(super::refused(
                "archived Host2 exceeds selected record credit",
            ));
        }
        reference.verify(bytes).map_err(super::super::schema)?;
        let limits = HostSchedulingContinuationLimits {
            maximum_record_bytes: bytes.len(),
            lineage,
        };
        let decode = super::core_decode_credit::preflight(bytes, maximum_total_bytes)
            .map_err(super::super::schema)?;
        let validation = super::core_decode_credit::validation_storage(&decode, limits)
            .map_err(super::super::schema)?;
        let common_reconstruction = decode
            .value_containers
            .checked_add(decode.parser_strings)
            .and_then(|total| total.checked_add(decode.canonical_temporaries))
            .ok_or_else(|| super::refused("archived Host2 reconstruction credit overflow"))?;
        let retained = self
            .retained_allocation_bytes_excluding_content()?
            .checked_add(
                self.content
                    .capture_owned_storage()
                    .map_err(super::super::schema)?,
            )
            .and_then(|total| total.checked_add(additional_retained_bytes))
            .ok_or_else(|| super::refused("archived Host2 coexisting owner credit overflow"))?;
        let peak = decode
            .total()
            .map_err(super::super::schema)?
            .checked_add(validation)
            .and_then(|total| total.checked_add(common_reconstruction))
            .and_then(|total| total.checked_add(retained))
            .and_then(|total| total.checked_add(super::core_decode_credit::scanner_storage()))
            .and_then(|total| {
                total.checked_add(std::mem::size_of::<HostSchedulingContinuationRecord>())
            })
            .ok_or_else(|| super::refused("archived Host2 requested peak overflow"))?;
        if peak > maximum_total_bytes {
            return Err(super::refused(
                "archived Host2 exceeds remaining reconstruction credit",
            ));
        }
        let record = HostSchedulingContinuationRecord::decode(bytes, limits)
            .map_err(super::super::schema)?;
        let HostSchedulingRuntimeRecord::OriginalLineage(runtime) = &record.runtime else {
            return Err(super::refused(
                "complete archive contains a legacy host runtime",
            ));
        };
        if &**runtime != self.runtime || &record.scheduling != self.scheduling {
            return Err(super::refused(
                "archived Host2 differs from the original common scope",
            ));
        }
        Ok(record)
    }

    /// Counts one already decoded Host2 data owner using actual capacities.
    ///
    /// This permits an external source factory to include that same owner before
    /// reconstructing its fixed native protocol group. It creates no snapshot,
    /// ticket, native owner or restoration permission.
    ///
    /// # Errors
    /// Refuses arithmetic overflow in the closed actual-capacity walker.
    pub fn host_continuation_retained_allocation_bytes(
        record: &crate::node_contract::HostSchedulingContinuationRecord,
    ) -> Result<usize, StateError> {
        std::mem::size_of::<crate::node_contract::HostSchedulingContinuationRecord>()
            .checked_add(
                NodeRuntime::capture_host_record_storage(record).map_err(super::super::schema)?,
            )
            .ok_or_else(|| super::refused("archived Host2 retained storage overflow"))
    }
}
