//! Defines selected original-Observe allocation data without issuing capture rights.
//!
//! ```text
//! {"schema":"source-owned.packet-native-capture-record/12",
//!  "native":{...original receipt5...},"allocation":{...full report reference...}}
//! ```
//!
//! The native endpoint retains the actual completed quote and its currency owner.
//! Source independently authenticates the exact original Observe exchange, current
//! model boundary and whole-world allocation before a Core Capture ticket is used.
//! Serialized counts, a decoded record or a matching hash cannot replace those owners.

use crucible_source_birth_data::profile::reference_packet::service::capture_allocation::CaptureAllocationContractValue;

pub use crucible_source_birth_data::profile::reference_packet::service::capture_allocation::{
    MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES, NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN,
    PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE, PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,
    PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD, PACKET_NATIVE_CAPTURE_ALLOCATION_REPORT,
    capture_allocation_contract, capture_allocation_record_schema, capture_allocation_schema,
};

use super::{PacketNative5ProtocolMetadataBirthFacts, PacketNative5ProtocolMetadataLimits};
use crate::{
    ProviderError,
    envelope::{MessageKind, Method},
    reference_packet::control::PacketNative5Record,
};
use crucible_node_format::{ContentRef, HashRef, Id, Position, U64, Validate, canonical};
use serde::{Deserialize, Serialize};

/// Binds a report to the actual request and native semantic boundary.
///
/// These fields are portable correlation data. The native retained owner and
/// Source's original controller/kernel association independently prove currency.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeCaptureAllocationScope {
    /// Names the process that performed the actual native walk.
    pub native_pid: U64,
    /// Names the exact assigned original Observe request.
    pub observe_request: Id,
    /// Retains its actual incoming connection sequence.
    pub observe_sequence: U64,
    /// Commits its complete canonical Envelope in the separate Observe domain.
    pub observe_hash: HashRef,
    /// Names the current original session.
    pub session: Id,
    /// Names the current original native incarnation.
    pub incarnation: Id,
    /// Names the independently selected logical node.
    pub node: Id,
    /// Names the same execution and capture owner.
    pub owner: Id,
    /// Retains the installed binding, rather than a caller-selected subset.
    pub binding_hash: HashRef,
    /// Retains the complete active world identity.
    pub world: HashRef,
    /// Names the original live activation without reactivating it.
    pub activation: Id,
    /// Retains the current world generation.
    pub world_generation: U64,
    /// Retains the independently selected owner generation.
    pub owner_generation: U64,
    /// Reports the actual local native cursor, distinct from an administrative cut.
    pub model_cursor: Position,
    /// Counts Control originals immediately before this Observe is registered.
    pub control_originals_before: U64,
    /// Counts complete endpoint exchanges before publishing this Observe proof.
    pub endpoint_records_before: U64,
    /// Retains the next provider sequence before preparing its proof windows.
    pub provider_next_sequence_before: U64,
}

/// Reports actual physical storage in one same-owner protocol reservation.
///
/// All fields describe independently retained banks. Current encoded extent is
/// measured without binding or copying a future Capture owner into the bank.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeCaptureProtocolAllocation {
    /// Reports the actual original encoded Vec capacity, including spare bytes.
    pub encoded_capacity: U64,
    /// Reports actual literal and descriptor backing, excluding the encoded Vec.
    pub literal_and_descriptor_bytes: U64,
    /// Reports the exact current complete protocol encoding extent.
    pub current_encoded_bytes: U64,
}

/// Names independent future retained allocations through the first Capture.
///
/// Every component is a requested-layout bound from the closed actual producer.
/// A selected byte ceiling or metadata-row ceiling is never an actual allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeCaptureRetainedGrowth {
    /// Includes the actual report, native receipt, cached reply and Observe proof.
    pub observe_publication_bytes: U64,
    /// Includes the restricted next Capture raw, parsed, typed and correlation owners.
    pub capture_request_bytes: U64,
    /// Includes pending Capture/control/protocol copy and original publication owners.
    pub capture_publication_bytes: U64,
    /// Includes fourth-Poll request, confirmation, original and completed suffix owners.
    pub after_confirmation_bytes: U64,
}

/// Names coexisting transient phases without claiming allocator or stack residency.
///
/// The native producer admits each complete phase. It may not count only an
/// output Vec while omitting simultaneous DOM, canonical, base64 or input copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeCaptureTransients {
    /// Includes report/receipt construction and its complete original proof suffix.
    pub observe_encoding_bytes: U64,
    /// Includes model and Control borrowed-view vectors, DOMs and canonical banks.
    pub model_control_encoding_bytes: U64,
    /// Includes raw-before compact encoding, metadata and complete outer snapshot copies.
    pub native_before_encoding_bytes: U64,
    /// Includes complete native-after encoding, confirmation and acknowledgement copies.
    pub native_after_encoding_bytes: U64,
    /// Includes known quote observer/identity-roster and serializer scratch layouts.
    pub quote_scratch_bytes: U64,
}

/// Retains measured native owners and prospective first-Capture storage data.
///
/// Actual aliases are deduplicated only by the producer's same-process typed
/// identity roster. No process pointer, private type layout or identity roster
/// crosses the wire. Source must retain this exact report's original exchange.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeCaptureAllocationReport {
    /// Selects exactly the allocation-report12 data grammar.
    pub schema: String,
    /// Binds the actual original Observe and current semantic scope.
    pub scope: PacketNativeCaptureAllocationScope,
    /// Reports the actual native-before reservation storage.
    pub before: PacketNativeCaptureProtocolAllocation,
    /// Reports the independent actual native-after reservation storage.
    pub after: PacketNativeCaptureProtocolAllocation,
    /// Retains actual metadata/alias bank allocation facts from this same endpoint.
    pub metadata_banks: PacketNative5ProtocolMetadataBirthFacts,
    /// Sums actual current native requested storage, including inline owning roots.
    pub retained_requested_bytes: U64,
    /// Counts actual strong shared-owner edges traversed by the typed producer.
    pub shared_edges: U64,
    /// Counts distinct actual shared payloads whose child storage was walked once.
    pub unique_roots: U64,
    /// Names separately bounded future retained storage, with no lifetime refunds.
    pub growth: PacketNativeCaptureRetainedGrowth,
    /// Names complete prospective transient phases.
    pub transients: PacketNativeCaptureTransients,
}

impl PacketNativeCaptureAllocationReport {
    /// Checks closed report data and computes its conservative requested peak.
    ///
    /// This arithmetic grants no storage, ticket, currency or capture authority.
    /// It sums all retained growth, the largest complete transient phase and
    /// separately declared quote scratch; Source adds its actual other owners.
    ///
    /// # Errors
    /// Refuses another schema/domain, invalid scalar syntax, inconsistent physical
    /// extents or shared counts, and any checked requested-storage overflow.
    pub fn requested_peak_data(&self) -> Result<U64, ProviderError> {
        self.validate_data()?;
        self.sum_data()
    }

    /// Checks report syntax and internal arithmetic without checking live currency.
    ///
    /// # Errors
    /// Refuses malformed correlation, another report edition, encoded extents
    /// exceeding their actual bank capacity, impossible alias counts or overflow.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        let scope = &self.scope;
        if self.schema != PACKET_NATIVE_CAPTURE_ALLOCATION_REPORT
            || scope.native_pid.get() == 0
            || scope.observe_sequence.get() == 0
            || scope.provider_next_sequence_before.get() == 0
            || scope.observe_hash.domain != NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN
            || self.unique_roots.get() == 0
            || self.unique_roots > self.shared_edges
            || self.retained_requested_bytes.get() == 0
            || self.before.current_encoded_bytes > self.before.encoded_capacity
            || self.after.current_encoded_bytes > self.after.encoded_capacity
        {
            return Err(invalid());
        }
        for id in [
            &scope.observe_request,
            &scope.session,
            &scope.incarnation,
            &scope.node,
            &scope.owner,
            &scope.activation,
        ] {
            id.validate()?;
        }
        for hash in [&scope.observe_hash, &scope.binding_hash, &scope.world] {
            hash.validate()?;
        }
        scope.model_cursor.validate()?;
        self.metadata_banks
            .validate_data(&PacketNative5ProtocolMetadataLimits {
                native_before_rows: self.metadata_banks.before.selected_rows,
                native_after_rows: self.metadata_banks.after.selected_rows,
            })?;
        let mut bank_bytes = 0u64;
        for value in [
            self.before.encoded_capacity,
            self.before.literal_and_descriptor_bytes,
            self.after.encoded_capacity,
            self.after.literal_and_descriptor_bytes,
            self.metadata_banks.before.record_bytes,
            self.metadata_banks.before.alias_row_bytes,
            self.metadata_banks.before.alias_lookup_bytes,
            self.metadata_banks.after.record_bytes,
            self.metadata_banks.after.alias_row_bytes,
            self.metadata_banks.after.alias_lookup_bytes,
        ] {
            bank_bytes = bank_bytes.checked_add(value.get()).ok_or_else(invalid)?;
        }
        if bank_bytes > self.retained_requested_bytes.get() {
            return Err(invalid());
        }
        self.sum_data()?;
        Ok(())
    }

    fn sum_data(&self) -> Result<U64, ProviderError> {
        requested_sum(
            self.retained_requested_bytes,
            &self.growth,
            &self.transients,
        )
    }
}

fn requested_sum(
    retained: U64,
    growth: &PacketNativeCaptureRetainedGrowth,
    transient: &PacketNativeCaptureTransients,
) -> Result<U64, ProviderError> {
    let phase = [
        transient.observe_encoding_bytes,
        transient.model_control_encoding_bytes,
        transient.native_before_encoding_bytes,
        transient.native_after_encoding_bytes,
    ]
    .into_iter()
    .map(U64::get)
    .max()
    .ok_or_else(invalid)?;
    [
        retained.get(),
        growth.observe_publication_bytes.get(),
        growth.capture_request_bytes.get(),
        growth.capture_publication_bytes.get(),
        growth.after_confirmation_bytes.get(),
        transient.quote_scratch_bytes.get(),
        phase,
    ]
    .into_iter()
    .try_fold(0u64, |sum, next| sum.checked_add(next).ok_or_else(invalid))
    .map(U64::new)
}

/// Retains the selected Observe receipt and its separate allocation report.
///
/// The nested original receipt5 remains unchanged. Only the new selected Observe
/// uses this wrapper; other native method records keep their original grammar.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeCaptureAllocationRecord {
    /// Selects exactly the distinct original Observe record12 wrapper.
    pub schema: String,
    /// Retains the full original native receipt and underlying model proof ref.
    pub native: PacketNative5Record,
    /// Names the exact original report body, including its media type and length.
    pub allocation: ContentRef,
}

impl PacketNativeCaptureAllocationRecord {
    /// Checks the selected wrapper's nonexecuting Observe shape as data.
    ///
    /// # Errors
    /// Refuses another edition/method, a non-original request, report media type,
    /// empty or oversized report, invalid reference, or nonempty envelope extensions.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        let original = &self.native.original;
        if self.schema != PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD
            || self.native.schema != "source-owned.packet-receipt/5"
            || original.message != MessageKind::Request
            || original.method != Method::Observe
            || !original.extensions.is_empty()
            || self.allocation.media_type != PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA
            || self.allocation.length.get() == 0
            || self.allocation.length.get() > MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES as u64
        {
            return Err(invalid());
        }
        original.validate()?;
        self.allocation.validate()?;
        Ok(())
    }
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("native original Observe allocation report data")
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- closed inert schema and arithmetic controls.
#[expect(
    clippy::unwrap_used,
    reason = "closed data controls intentionally panic on mismatch"
)]
mod tests {
    use super::*;

    #[test]
    fn requested_sum_charges_all_retained_growth_and_one_complete_phase() {
        let growth = PacketNativeCaptureRetainedGrowth {
            observe_publication_bytes: U64::new(2),
            capture_request_bytes: U64::new(3),
            capture_publication_bytes: U64::new(5),
            after_confirmation_bytes: U64::new(7),
        };
        let transient = PacketNativeCaptureTransients {
            observe_encoding_bytes: U64::new(11),
            model_control_encoding_bytes: U64::new(13),
            native_before_encoding_bytes: U64::new(19),
            native_after_encoding_bytes: U64::new(17),
            quote_scratch_bytes: U64::new(23),
        };

        assert_eq!(
            requested_sum(U64::new(29), &growth, &transient).unwrap(),
            U64::new(88)
        );
        assert!(requested_sum(U64::new(u64::MAX), &growth, &transient).is_err());
    }

    #[test]
    fn contract_registers_distinct_full_report_and_record_definitions() {
        let report = capture_allocation_schema().unwrap();
        let record = capture_allocation_record_schema().unwrap();
        let definition = capture_allocation_contract().unwrap();

        assert_ne!(report.id, record.id);
        assert_eq!(report.version, 12);
        assert_eq!(record.version, 12);
        assert_eq!(report.definition, record.definition);
        report.definition.verify(&definition).unwrap();
        assert_eq!(
            canonical::canonical_json(
                &canonical::parse_json(&definition, definition.len()).unwrap()
            )
            .unwrap(),
            definition
        );
    }

    #[test]
    fn report_components_refuse_unknown_fields_and_unknown_selection() {
        let fields = serde_json::json!({
            "observe_encoding_bytes":"1", "model_control_encoding_bytes":"2",
            "native_before_encoding_bytes":"3", "native_after_encoding_bytes":"4",
            "quote_scratch_bytes":"5"
        });
        let mut extended = fields.clone();
        extended
            .as_object_mut()
            .unwrap()
            .insert("permission".into(), serde_json::json!(true));

        assert!(serde_json::from_value::<PacketNativeCaptureTransients>(fields).is_ok());
        assert!(serde_json::from_value::<PacketNativeCaptureTransients>(extended).is_err());
        assert!(
            serde_json::from_value::<PacketNative5CaptureAllocationSelection>(serde_json::json!(
                "other"
            ))
            .is_err()
        );
        assert_eq!(
            serde_json::to_string(&PacketNative5CaptureAllocationSelection::OriginalObserve12)
                .unwrap(),
            "\"original_observe12\""
        );
    }
}

impl crate::retained_metadata::ObserveMetadata for PacketNative5CaptureAllocationSelection {
    fn observe_metadata(
        &self,
        _: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        match self {
            Self::OriginalObserve12 => Ok(()),
        }
    }
}

// One borrowed compiled roster drives BOTH the existing canonical definition
// and its prospective DOM/canonical counter. No schema bytes or field values
// are regenerated independently in the admission calculation.

pub(crate) fn capture_allocation_contract_storage_data(
    maximum: usize,
) -> Result<
    crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
    ProviderError,
> {
    // This unit struct and its borrowed literals own no heap/Bytes formatter.
    crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
        &CaptureAllocationContractValue,
        crate::retained_metadata::RetainedProtocolMetadataFacts::default(),
        maximum,
    )
}

mod borrowed_report;
pub use borrowed_report::{
    PacketNativeCaptureAllocationReportView, original_capture_allocation_native_bytes_data,
    original_capture_allocation_report_counter_scratch_data,
};

pub(crate) use borrowed_report::original_capture_allocation_reference_matches_data;

pub use crucible_source_birth_data::profile::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection;
