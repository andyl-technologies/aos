//! Aggregates the original Observe report's actual requested publication phases.
//!
//! The shared source body retains upper native preparation, typed observation,
//! capture-owner and final-counter queries at their original lexical slots.
//! Numeric layouts and metadata facts confer no Source or construction right.

use super::super::report_startup::PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY;
use crate::ProviderError;
use crate::profile::requested_storage::requested_metadata_backing_storage_data;
use crate::profile::serialization_storage::RetainedProtocolMetadataFacts;
use crucible_node_format::ContentRef;
use std::mem::{align_of, size_of};

/// Describes separately bounded requested storage for one compiled publisher.
///
/// Values describe a closed prospective shape. They prove no Source admission,
/// native currentness, actual capacities or physical allocator peak.
pub struct PacketNativeReportStartupStorageData {
    /// Counts independent retained publication owners.
    pub retained_growth_bytes: usize,
    /// Bounds the largest original receive, encoding or ACK phase.
    pub maximum_simultaneous_transient_bytes: usize,
    /// Names the independently admitted defining counter window.
    pub declared_counter_scratch_bytes: usize,
}

impl PacketNativeReportStartupStorageData {
    /// Returns the exact required raw report capacity shared by both families.
    pub const fn raw_report_capacity(&self) -> usize {
        PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY
    }

    /// Returns the bound for every independent new retained owner.
    pub const fn retained_growth_bytes(&self) -> usize {
        self.retained_growth_bytes
    }

    /// Returns a conservative sum covering the complete simultaneous phase.
    pub const fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.maximum_simultaneous_transient_bytes
    }

    /// Returns the declared counter and fixed compiled schema-generation window.
    pub const fn declared_counter_scratch_bytes(&self) -> usize {
        self.declared_counter_scratch_bytes
    }
}

/// Reports the actual key and value components of the private reply cache.
///
/// Components match tree<K,V>: its arithmetic adds key and value widths before
/// applying their maximum alignment. Tuple padding is not substituted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportCacheTreeLayoutData {
    /// Reports the actual cache key header width.
    pub key_bytes: usize,
    /// Reports the actual independently typed cache value header width.
    pub value_bytes: usize,
    /// Reports the actual key alignment.
    pub key_alignment: usize,
    /// Reports the actual value alignment.
    pub value_alignment: usize,
}

/// Applies the original two-tree population and requested-layout arithmetic.
///
/// # Errors
/// Preserves population overflow, invalid alignment and requested-layout errors.
pub fn cache_tree_backing_data(layout: &ReportCacheTreeLayoutData) -> Result<usize, ProviderError> {
    let mut trees = RetainedProtocolMetadataFacts::default();
    let content_entries = 4;
    // tree<K,V> validates the record width before advancing its record prefix.
    size_of::<ContentRef>()
        .checked_add(size_of::<Vec<u8>>())
        .ok_or_else(crate::profile::metadata_population::overflow)?;
    crate::profile::metadata_population::record_unprofiled_data(&mut trees)?;
    crate::source_birth_metadata_tree_population!(trees, content_entries, ContentRef, Vec<u8>)?;
    let cache_entries = 1;
    layout
        .key_bytes
        .checked_add(layout.value_bytes)
        .ok_or_else(crate::profile::metadata_population::overflow)?;
    crate::profile::metadata_population::record_unprofiled_data(&mut trees)?;
    crate::source_birth_metadata_tree_population!(@layout trees, cache_entries,
        layout.key_bytes, layout.value_bytes, layout.key_alignment, layout.value_alignment)?;
    requested_metadata_backing_storage_data(&trees)
}

/// Names the new nested cache-layout and population helper windows.
///
/// The macro adds no report-call frame. Existing report, observer, scalar and
/// result terms remain independently present in the upper defining counter.
pub const AGGREGATION_COUNTER_SCRATCH_DATA: usize = size_of::<ReportCacheTreeLayoutData>() // supplier initializer
    + size_of::<ReportCacheTreeLayoutData>() // supplier return
    + size_of::<ReportCacheTreeLayoutData>() // retained macro binding
    + size_of::<&ReportCacheTreeLayoutData>() // actual helper loan
    + size_of::<&ReportCacheTreeLayoutData>() // lower helper input
    + size_of::<RetainedProtocolMetadataFacts>() // independent helper population
    + size_of::<&mut RetainedProtocolMetadataFacts>() // record/population family
    + size_of::<&RetainedProtocolMetadataFacts>() // requested-backing input
    + size_of::<Result<usize, ProviderError>>() // helper return
    + size_of::<usize>() // content entry-count binding
    + size_of::<usize>(); // cache entry-count binding

/// Expands the sole original aggregation body around concrete upper query slots.
///
/// Slots are source expressions, not runtime callbacks or native authority.
/// The owner observation slot must perform the original single-binding guard
/// before observing that actual typed binding; facts are consumed only there.
#[macro_export]
macro_rules! source_birth_original_report_body {
    (
        shapes = $shapes:ident,
        initial_receive = $initial_receive:ident,
        typed_query_requested_bytes = $typed_query_requested_bytes:ident,
        maximum = $maximum:expr,
        objects = $objects:ident,
        prefix = $prefix:ident,
        preparation = $preparation:ident,
        prefix_lifetime = $prefix_lifetime:ident,
        prefix_stage = $prefix_stage:expr,
        lifetime_stage = $lifetime_stage:expr,
        cache_layout = $cache_layout:expr,
        layout = $layout:expr,
        capture_owner = $capture_owner:expr,
        owner_binding = $owner_binding:ident,
        observation = { $($observation:tt)* },
        owner_facts = $owner_facts:expr,
        counter = $counter:expr $(,)?
    ) => {{
        use $crate::profile::reference_packet::service::capture_allocation::*;
        use $crate::profile::reference_packet::service::native_startup::original_report::{self, sum, mul};
        use $crate::profile::reference_packet::service::native_startup::packet_prefix::frames::OriginalContinuationContentExtent;
        use $crate::profile::reference_packet::service::report_startup::PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY;

        let raw = $shapes.raw.maximum_encoded_bytes.min(65_536);
        // The existing producer rejects larger encoded records. Its complete
        // pre-rejection DOM/canonical work remains charged below at the full shape.
        let $objects = [
            OriginalContinuationContentExtent {
                maximum_payload_bytes: raw,
                media_type: "application/json",
            },
            OriginalContinuationContentExtent {
                maximum_payload_bytes: $shapes.wrapper.maximum_encoded_bytes,
                media_type: "application/json",
            },
            OriginalContinuationContentExtent {
                maximum_payload_bytes: PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
                media_type: PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,
            },
        ];
        let ($prefix, $preparation) = $prefix_stage?;
        // authenticate_tuple selected the actual OriginalObserve12 constructor.
        // Its incoming query returns before reply/control/prefix construction. Keep
        // every original/failed owner below; the complete old prefix peak is merely
        // partitioned so returning work is not also described as permanent growth.

        let $prefix_lifetime = $lifetime_stage?;

        let cache_layout = $cache_layout;
        let new_tree_backing = original_report::cache_tree_backing_data(&cache_layout)?;
        let content_bytes = sum(&[
            raw,
            $shapes.receipt.maximum_encoded_bytes,
            $shapes.wrapper.maximum_encoded_bytes,
            PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
        ])?;
        let layout = $layout;
        let cache_bytes = sum(&[
            raw,
            $shapes.wrapper.maximum_encoded_bytes,
            PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
            $shapes.terminal.dom_and_canonical_scratch_bytes,
            mul(3, layout.content_entry_bytes)?,
        ])?;
        let reference_children = |media: &str| {
            sum(&[
                "blake3-256".len(),
                "cnp.blob.v1".len(),
                2 * blake3::OUT_LEN,
                media.len(),
            ])
        };
        let content_references = sum(&[
            mul(3, reference_children("application/json")?)?,
            reference_children(PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA)?,
        ])?;
        let completed_owner = sum(&[
            $capture_owner,
            $shapes.original.dom_and_canonical_scratch_bytes,
            layout.capture_report_bytes,
            $shapes.report.dom_and_canonical_scratch_bytes,
            PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY,
            reference_children(PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA)?,
        ])?;

        $($observation)*
        let identity =
            $crate::profile::serialization_storage::actual_serialization_storage_data(
                $owner_binding,
                $owner_facts,
                $maximum,
            )?;
        // The real selected dispatcher hashes this same immutable binding while
        // comparing the request, producing receipt5 and building ObservationBatch.
        let binding_identity_transient = sum(&[
            mul(3, identity.requested_total()?)?,
            mul(
                3,
                "blake3-256".len() + "cnp.owner-binding.v1".len() + 2 * blake3::OUT_LEN,
            )?,
        ])?;
        let retained = sum(&[
            $prefix_lifetime.retained_requested_bytes,
            $prefix.source_owner_requested_bytes,
            content_bytes,
            content_references,
            cache_bytes,
            completed_owner,
            new_tree_backing,
            // Independent policy definition refs belong to this publication class.
            mul(2, layout.content_ref_bytes)?,
            mul(2, reference_children("application/json")?)?,
        ])?;
        let encoding = sum(&[
            // Endpoint::step holds the SAME returned Box<RequestBody> and its
            // Observe hash/children until selected_report returns. This actual
            // restricted query row, including the unchanged SDK observer's possible
            // empty Extensions root, survives receive and overlaps all encoding;
            // only its returning raw/parser work belongs in the other max arm.
            $typed_query_requested_bytes,
            binding_identity_transient,
            $prefix_lifetime.encoding_work_requested_bytes()?,
            $prefix.declared_counter_scratch_bytes,
            $shapes.original.requested_total()?,
            $shapes.raw.requested_total()?,
            $shapes.receipt.requested_total()?,
            $shapes.wrapper.requested_total()?,
            $shapes.report.requested_total()?,
            $shapes.terminal.requested_total()?,
            // The receipt constructor owns a complete original clone and independent
            // scope strings. Charging its full DOM shape plus actual typed header
            // dominates those scalar children without manufacturing a receipt DTO.
            layout.produced_receipt_bytes,
            128, // Id::new grammar bound of the independently retained activation witness.
            $shapes.receipt.dom_and_canonical_scratch_bytes,
            layout.observation_batch_bytes,
            layout.observe_result_bytes,
            $shapes.terminal.dom_and_canonical_scratch_bytes,
            // Each of the four new content references is independently generated,
            // verified and cloned into a content key/evidence/typed wrapper owner.
            mul(4, content_references)?,
            layout.hasher_bytes,
        ])?;
        // ACK receipt starts only after the actual transform/dispatch/prepare
        // stack returns. The returned typed Observe query survives through publish;
        // preserve it and both defining counter windows in this distinct arm.
        let acknowledgement = sum(&[
            $typed_query_requested_bytes,
            $prefix_lifetime.acknowledgement_work_requested_bytes()?,
            $prefix.declared_counter_scratch_bytes,
        ])?;
        Ok(original_report::PacketNativeReportStartupStorageData {
            retained_growth_bytes: retained,
            // The full untrusted query is still funded at the negotiated raw cap.
            // It cannot overlap later encoding: receive_original_report_query has
            // returned before publish_original_capture_allocation_observe begins.
            // Original/containment remain funded above; the returned typed Box and
            // Observe children are explicitly carried in encoding, not maxed away.
            maximum_simultaneous_transient_bytes: $initial_receive.max(encoding).max(acknowledgement),
            declared_counter_scratch_bytes: $counter,
        })
    }};
}

/// Adds the original aggregation operands without admitting storage.
///
/// # Errors
/// Refuses checked overflow with the original report-storage error.
#[doc(hidden)]
pub fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, next| {
        total.checked_add(*next).ok_or_else(exhausted)
    })
}

/// Multiplies an original aggregation population by its actual component width.
///
/// # Errors
/// Refuses checked overflow with the original report-storage error.
#[doc(hidden)]
pub fn mul(count: usize, slot: usize) -> Result<usize, ProviderError> {
    count.checked_mul(slot).ok_or_else(exhausted)
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("compiled native report startup storage")
}
