//! Counts borrowed archive-validation owners before vendor reconstruction.
//!
//! The verified content closure is intentionally excluded because a source's
//! fixed-owner reconstruction plan counts it once. Borrowed graph/source owners
//! and factory-specific banks remain separately admitted by their owning layer.

use super::{CompleteOriginalArchiveValidation, StateError};
use crate::node_contract::{NodeRuntime, RuntimeOriginalCaptureJournal};

impl CompleteOriginalArchiveValidation<'_> {
    /// Counts this context's actual verified content owner without copying it.
    ///
    /// The native factory joins this separate content row with actual live or
    /// historical owners before cold copies. The private Core validation origin
    /// is authenticated on both sides; no decoder DTO selects another closure.
    /// This is requested-layout data, not allocation or restoration authority.
    ///
    /// # Errors
    /// Refuses foreign/stale validation origin or checked content-layout overflow.
    pub fn retained_verified_content_allocation_bytes(&self) -> Result<usize, StateError> {
        self.original_write_runtime_data()?;
        let bytes = self
            .content
            .capture_owned_storage()
            .map_err(super::super::schema)?;
        self.original_write_runtime_data()?;
        Ok(bytes)
    }

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
            // These actual explicit fixed views remain live throughout the
            // same admitted cold callback; the rows own no child heap/FD.
            std::mem::size_of::<Self>(),
            std::mem::size_of::<std::cell::RefCell<[Option<super::CompleteOriginalNativeRestorationData>; 4]>>(),
            std::mem::size_of::<std::cell::RefMut<'_, [Option<super::CompleteOriginalNativeRestorationData>; 4]>>(),
            std::mem::size_of::<super::CompleteOriginalNativeRestorationData>(),
            std::mem::size_of::<super::ValidatedCompleteNativeRestorationData<'_>>(),
            crucible_node_transport::reference_packet::service::complete_restore::transfer::complete_restore_selected_owner_construction_counter_scratch_data(),
            super::CompleteOriginalNativeRestorationData::reference_counter_scratch_data(),
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
        reference: &crucible_node_format::ContentRef,
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
        // This full-reference lookup borrows immutable, already authenticated
        // closure bytes; no allocating hash is needed before storage admission.
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

impl CompleteOriginalArchiveValidation<'_> {
    /// Validates the original Host2 settlement and decodes its unchanged record.
    ///
    /// The native factory supplies the same signed administrative owner row.
    /// Complete Runtime7 and the host journal are compared to their exact
    /// canonical producer encodings before Host2 reconstruction. All dynamic
    /// comparison and decoder storage is admitted alongside the actual caller
    /// owners and verified content; historical data constructs no live source.
    ///
    /// # Errors
    /// Refuses another attempt, owner, snapshot, operation, runtime or journal,
    /// a noncanonical producer body, missing content or insufficient storage.
    pub fn decode_original_host_capture_data(
        &self,
        owner: &super::NativeOwnerState,
        attempt: &crate::node_contract::OriginalCaptureAttemptRecord,
        settled: &crate::node_contract::OriginalCaptureOwnerRecord,
        additional_retained_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<crate::node_contract::HostSchedulingContinuationRecord, StateError> {
        use crate::node_contract::OriginalCaptureOwnerState;

        // Both original-write and selected-load purposes come from the private
        // Core origin. Merely possessing public archive/runtime DTOs is not one.
        self.original_write_runtime_data()?;
        let OriginalCaptureOwnerState::Settled { snapshot, journal } = &settled.state else {
            return Err(super::refused(
                "complete host administrative row is unsettled",
            ));
        };
        if self.administrative.attempts.as_slice() != std::slice::from_ref(attempt)
            || attempt.capture_id != self.archive.manifest().capture_id
            || attempt.source_activation != self.runtime.source_activation
            || attempt.cut != self.runtime.capture_cut
            || attempt.ordinal != self.runtime.capture_ordinal
            || !attempt.owners.contains(settled)
            || settled.owner.owner != owner.owner
            || settled.participants != owner.participants
            || snapshot != &owner.state
            || !owner.evidence.contains(journal.as_ref())
            || journal.media_type
                != "application/vnd.crucible.host-scheduling-capture-journal+json;version=2"
        {
            return Err(super::refused(
                "complete host settlement differs from original attempt",
            ));
        }
        self.authenticate_original_encoding_data(
            self.runtime,
            &attempt.source_runtime,
            additional_retained_bytes,
            maximum_total_bytes,
        )?;
        let expected = OriginalHostJournalData {
            schema: "source-owned.host-scheduling-capture-journal/2",
            capture_id: &attempt.capture_id,
            operation: &settled.operation,
            owner: &settled.owner,
            participants: &settled.participants,
            cut: attempt.cut,
            ordinal: attempt.ordinal,
            runtime: &attempt.source_runtime,
            snapshot,
            transition: "one original unchanged-cut common snapshot; no native operation, input or acknowledgement submitted",
        };
        let additional = additional_retained_bytes
            .checked_add(std::mem::size_of::<OriginalHostJournalData<'_>>())
            .ok_or_else(|| super::refused("complete host journal comparison storage overflow"))?;
        self.authenticate_original_encoding_data(
            &expected,
            journal,
            additional,
            maximum_total_bytes,
        )?;
        let record = self.decode_host_continuation_data(
            snapshot,
            self.lineage_limits(),
            additional_retained_bytes,
            maximum_total_bytes,
        )?;
        self.original_write_runtime_data()?;
        Ok(record)
    }

    fn authenticate_original_encoding_data(
        &self,
        expected: &impl serde::Serialize,
        reference: &crucible_node_format::ContentRef,
        additional_retained_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<(), StateError> {
        use crucible_node_format::canonical;

        let maximum = maximum_total_bytes
            .min(self.archive.limits.state.maximum_total_content_bytes)
            .min(self.archive.limits.native.maximum_total_record_bytes);
        let bytes = self
            .content
            .get(reference)
            .ok_or_else(|| super::refused("complete original producer body absent"))?;
        // This full-reference lookup borrows immutable, already authenticated
        // closure bytes; no allocating hash is needed before storage admission.
        if bytes.len() > self.archive.limits.state.maximum_record_bytes {
            return Err(super::refused(
                "complete original producer record exceeds credit",
            ));
        }
        let retained = self
            .retained_allocation_bytes_excluding_content()?
            .checked_add(
                self.content
                    .capture_owned_storage()
                    .map_err(super::super::schema)?,
            )
            .and_then(|total| total.checked_add(additional_retained_bytes))
            // Closed U64 format scratch precedes both counting serializers.
            .and_then(|total| total.checked_add(20))
            .filter(|total| *total <= maximum)
            .ok_or_else(|| {
                super::refused("complete original comparison retained storage exhausted")
            })?;
        let value = NodeRuntime::capture_serialization_storage(expected, maximum)
            .map_err(super::super::schema)?;
        let encoded = NodeRuntime::capture_encoded_output_storage(expected, maximum)
            .map_err(super::super::schema)?;
        retained
            .checked_add(value)
            .and_then(|total| total.checked_add(encoded))
            .filter(|total| *total <= maximum)
            .ok_or_else(|| {
                super::refused("complete original comparison transient storage exhausted")
            })?;

        let value = serde_json::to_value(expected).map_err(super::super::schema)?;
        let canonical = canonical::canonical_json(&value).map_err(super::super::schema)?;
        if canonical != bytes {
            return Err(super::refused("complete original producer body differs"));
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct OriginalHostJournalData<'a> {
    schema: &'static str,
    capture_id: &'a crucible_node_format::Id,
    operation: &'a crucible_node_format::Id,
    owner: &'a crate::node_contract::OwnerIdentity,
    participants: &'a [crucible_node_format::Id],
    cut: crucible_node_format::Position,
    ordinal: crucible_node_format::U64,
    runtime: &'a crucible_node_format::ContentRef,
    snapshot: &'a crucible_node_format::ContentRef,
    transition: &'static str,
}
