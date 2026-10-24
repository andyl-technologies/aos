//! Reads the complete report and compares its canonical raw body without copies.
//!
//! Capacity rows describe the independent typed report. The raw bank is a
//! separate retained owner; correspondence is checked after both are installed.

use super::super::typed::{
    Fields, HistoricalType, Ledger, historical_struct, invalid, plain_string, unsigned,
};
use crate::{
    ProviderError,
    reference_packet::service::{
        PacketNative5ProtocolMetadataBankFacts, PacketNative5ProtocolMetadataBirthFacts,
        capture_allocation::*,
    },
};
use crucible_node_format::{HashRef, Id, Position, U64};

historical_struct!(PacketNativeCaptureAllocationScope {
    native_pid: U64,
    observe_request: Id,
    observe_sequence: U64,
    observe_hash: HashRef,
    session: Id,
    incarnation: Id,
    node: Id,
    owner: Id,
    binding_hash: HashRef,
    world: HashRef,
    activation: Id,
    world_generation: U64,
    owner_generation: U64,
    model_cursor: Position,
    control_originals_before: U64,
    endpoint_records_before: U64,
    provider_next_sequence_before: U64,
});

historical_struct!(PacketNativeCaptureProtocolAllocation {
    encoded_capacity: U64,
    literal_and_descriptor_bytes: U64,
    current_encoded_bytes: U64,
});

historical_struct!(PacketNativeCaptureRetainedGrowth {
    observe_publication_bytes: U64,
    capture_request_bytes: U64,
    capture_publication_bytes: U64,
    after_confirmation_bytes: U64,
});

historical_struct!(PacketNativeCaptureTransients {
    observe_encoding_bytes: U64,
    model_control_encoding_bytes: U64,
    native_before_encoding_bytes: U64,
    native_after_encoding_bytes: U64,
    quote_scratch_bytes: U64,
});

historical_struct!(PacketNative5ProtocolMetadataBankFacts {
    selected_rows: U64,
    record_capacity: U64,
    record_bytes: U64,
    alias_row_capacity: U64,
    alias_lookup_capacity: U64,
    alias_row_bytes: U64,
    alias_lookup_bytes: U64,
});

historical_struct!(PacketNative5ProtocolMetadataBirthFacts {
    before: PacketNative5ProtocolMetadataBankFacts,
    after: PacketNative5ProtocolMetadataBankFacts,
});

historical_struct!(PacketNativeCaptureAllocationReport {
    schema: String,
    scope: PacketNativeCaptureAllocationScope,
    before: PacketNativeCaptureProtocolAllocation,
    after: PacketNativeCaptureProtocolAllocation,
    metadata_banks: PacketNative5ProtocolMetadataBirthFacts,
    retained_requested_bytes: U64,
    shared_edges: U64,
    unique_roots: U64,
    growth: PacketNativeCaptureRetainedGrowth,
    transients: PacketNativeCaptureTransients,
});

fn quoted_u64(bytes: &[u8], original: U64) -> Result<(), ProviderError> {
    if unsigned(plain_string(bytes)?.as_bytes())? != original.get() {
        return Err(invalid());
    }
    Ok(())
}

fn scalar(bytes: &[u8], original: &impl serde::Serialize) -> Result<(), ProviderError> {
    super::super::correspondence::scalar(bytes, original)
}

fn protocol(
    bytes: &[u8],
    original: &PacketNativeCaptureProtocolAllocation,
) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    quoted_u64(
        fields.named("current_encoded_bytes")?,
        original.current_encoded_bytes,
    )?;
    quoted_u64(fields.named("encoded_capacity")?, original.encoded_capacity)?;
    quoted_u64(
        fields.named("literal_and_descriptor_bytes")?,
        original.literal_and_descriptor_bytes,
    )?;
    fields.finish()
}

fn growth(bytes: &[u8], original: &PacketNativeCaptureRetainedGrowth) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    quoted_u64(
        fields.named("after_confirmation_bytes")?,
        original.after_confirmation_bytes,
    )?;
    quoted_u64(
        fields.named("capture_publication_bytes")?,
        original.capture_publication_bytes,
    )?;
    quoted_u64(
        fields.named("capture_request_bytes")?,
        original.capture_request_bytes,
    )?;
    quoted_u64(
        fields.named("observe_publication_bytes")?,
        original.observe_publication_bytes,
    )?;
    fields.finish()
}

fn transients(bytes: &[u8], original: &PacketNativeCaptureTransients) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    quoted_u64(
        fields.named("model_control_encoding_bytes")?,
        original.model_control_encoding_bytes,
    )?;
    quoted_u64(
        fields.named("native_after_encoding_bytes")?,
        original.native_after_encoding_bytes,
    )?;
    quoted_u64(
        fields.named("native_before_encoding_bytes")?,
        original.native_before_encoding_bytes,
    )?;
    quoted_u64(
        fields.named("observe_encoding_bytes")?,
        original.observe_encoding_bytes,
    )?;
    quoted_u64(
        fields.named("quote_scratch_bytes")?,
        original.quote_scratch_bytes,
    )?;
    fields.finish()
}

fn bank(
    bytes: &[u8],
    original: &PacketNative5ProtocolMetadataBankFacts,
) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    quoted_u64(
        fields.named("alias_lookup_bytes")?,
        original.alias_lookup_bytes,
    )?;
    quoted_u64(
        fields.named("alias_lookup_capacity")?,
        original.alias_lookup_capacity,
    )?;
    quoted_u64(fields.named("alias_row_bytes")?, original.alias_row_bytes)?;
    quoted_u64(
        fields.named("alias_row_capacity")?,
        original.alias_row_capacity,
    )?;
    quoted_u64(fields.named("record_bytes")?, original.record_bytes)?;
    quoted_u64(fields.named("record_capacity")?, original.record_capacity)?;
    quoted_u64(fields.named("selected_rows")?, original.selected_rows)?;
    fields.finish()
}

fn birth(
    bytes: &[u8],
    original: &PacketNative5ProtocolMetadataBirthFacts,
) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    bank(fields.named("after")?, &original.after)?;
    bank(fields.named("before")?, &original.before)?;
    fields.finish()
}

fn hash(bytes: &[u8], original: &HashRef) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    scalar(fields.named("algorithm")?, &original.algorithm)?;
    scalar(fields.named("digest")?, &original.digest)?;
    scalar(fields.named("domain")?, &original.domain)?;
    fields.finish()
}

fn position(bytes: &[u8], original: &Position) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    quoted_u64(fields.named("microstep")?, original.microstep)?;
    scalar(fields.named("phase")?, &original.phase)?;
    quoted_u64(fields.named("time_ps")?, original.time_ps)?;
    fields.finish()
}

fn scope(bytes: &[u8], original: &PacketNativeCaptureAllocationScope) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    scalar(fields.named("activation")?, &original.activation)?;
    hash(fields.named("binding_hash")?, &original.binding_hash)?;
    quoted_u64(
        fields.named("control_originals_before")?,
        original.control_originals_before,
    )?;
    quoted_u64(
        fields.named("endpoint_records_before")?,
        original.endpoint_records_before,
    )?;
    scalar(fields.named("incarnation")?, &original.incarnation)?;
    position(fields.named("model_cursor")?, &original.model_cursor)?;
    quoted_u64(fields.named("native_pid")?, original.native_pid)?;
    scalar(fields.named("node")?, &original.node)?;
    hash(fields.named("observe_hash")?, &original.observe_hash)?;
    scalar(fields.named("observe_request")?, &original.observe_request)?;
    quoted_u64(fields.named("observe_sequence")?, original.observe_sequence)?;
    scalar(fields.named("owner")?, &original.owner)?;
    quoted_u64(fields.named("owner_generation")?, original.owner_generation)?;
    quoted_u64(
        fields.named("provider_next_sequence_before")?,
        original.provider_next_sequence_before,
    )?;
    scalar(fields.named("session")?, &original.session)?;
    hash(fields.named("world")?, &original.world)?;
    quoted_u64(fields.named("world_generation")?, original.world_generation)?;
    fields.finish()
}

pub(super) fn authenticate_canonical_report(
    bytes: &[u8],
    original: &PacketNativeCaptureAllocationReport,
) -> Result<(), ProviderError> {
    let mut fields = Fields::object(bytes)?;
    protocol(fields.named("after")?, &original.after)?;
    protocol(fields.named("before")?, &original.before)?;
    growth(fields.named("growth")?, &original.growth)?;
    birth(fields.named("metadata_banks")?, &original.metadata_banks)?;
    quoted_u64(
        fields.named("retained_requested_bytes")?,
        original.retained_requested_bytes,
    )?;
    scalar(fields.named("schema")?, &original.schema)?;
    scope(fields.named("scope")?, &original.scope)?;
    quoted_u64(fields.named("shared_edges")?, original.shared_edges)?;
    transients(fields.named("transients")?, &original.transients)?;
    quoted_u64(fields.named("unique_roots")?, original.unique_roots)?;
    fields.finish()
}

// crucible-lint: allow panic-shortcut -- closed report correspondence controls assert exact data/refusal observations.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "canonical report data and refusal assertions"
)]
mod tests {
    use super::*;
    use crucible_node_format::{Phase, canonical};

    fn report() -> PacketNativeCaptureAllocationReport {
        let id = || Id::new("original").unwrap();
        let hash = |domain: &str| HashRef {
            algorithm: "blake3-256".into(),
            domain: domain.into(),
            digest: "0".repeat(64),
        };
        let (row_bytes, lookup_bytes) =
            crate::retained_metadata::aliases::original_metadata_alias_layouts();
        let bank = PacketNative5ProtocolMetadataBankFacts {
            selected_rows: U64::new(1),
            record_capacity: U64::new(1),
            record_bytes: U64::new(
                u64::try_from(std::mem::size_of::<
                    crate::retained_metadata::records::MetadataCapacityRecord,
                >())
                .unwrap(),
            ),
            alias_row_capacity: U64::new(1),
            alias_lookup_capacity: U64::new(1),
            alias_row_bytes: U64::new(u64::try_from(row_bytes).unwrap()),
            alias_lookup_bytes: U64::new(u64::try_from(lookup_bytes).unwrap()),
        };
        let protocol = PacketNativeCaptureProtocolAllocation {
            encoded_capacity: U64::new(512),
            literal_and_descriptor_bytes: U64::new(256),
            current_encoded_bytes: U64::new(128),
        };
        PacketNativeCaptureAllocationReport {
            schema: PACKET_NATIVE_CAPTURE_ALLOCATION_REPORT.into(),
            scope: PacketNativeCaptureAllocationScope {
                native_pid: U64::new(1),
                observe_request: id(),
                observe_sequence: U64::new(u64::MAX),
                observe_hash: hash(NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN),
                session: id(),
                incarnation: id(),
                node: id(),
                owner: id(),
                binding_hash: hash("binding"),
                world: hash("world"),
                activation: id(),
                world_generation: U64::new(u64::MAX),
                owner_generation: U64::new(0),
                model_cursor: Position::new(U64::new(4), U64::new(2), Phase::Reaction),
                control_originals_before: U64::new(7),
                endpoint_records_before: U64::new(9),
                provider_next_sequence_before: U64::new(11),
            },
            before: protocol,
            after: protocol,
            metadata_banks: PacketNative5ProtocolMetadataBirthFacts {
                before: bank,
                after: bank,
            },
            retained_requested_bytes: U64::new(4096),
            shared_edges: U64::new(5),
            unique_roots: U64::new(3),
            growth: PacketNativeCaptureRetainedGrowth {
                observe_publication_bytes: U64::new(1),
                capture_request_bytes: U64::new(2),
                capture_publication_bytes: U64::new(3),
                after_confirmation_bytes: U64::new(4),
            },
            transients: PacketNativeCaptureTransients {
                observe_encoding_bytes: U64::new(1),
                model_control_encoding_bytes: U64::new(2),
                native_before_encoding_bytes: U64::new(3),
                native_after_encoding_bytes: U64::new(4),
                quote_scratch_bytes: U64::new(5),
            },
        }
    }

    #[test]
    fn canonical_report_comparator_matches_real_writer_and_rejects_changed_nested_owner_data() {
        let original = report();
        original.validate_data().unwrap();
        let bytes = canonical::canonical_json(&serde_json::to_value(&original).unwrap()).unwrap();

        authenticate_canonical_report(&bytes, &original).unwrap();
        let mut changed = original.clone();
        changed.scope.owner_generation = U64::new(1);
        assert!(authenticate_canonical_report(&bytes, &changed).is_err());
        changed = original.clone();
        changed.metadata_banks.after.alias_lookup_bytes = U64::new(33);
        assert!(authenticate_canonical_report(&bytes, &changed).is_err());
        changed = original.clone();
        changed.scope.model_cursor.phase = Phase::Delivery;
        assert!(authenticate_canonical_report(&bytes, &changed).is_err());
    }

    #[test]
    fn canonical_report_comparator_rejects_duplicate_unknown_and_noncanonical_u64_fields() {
        let original = report();
        original.validate_data().unwrap();
        let bytes = canonical::canonical_json(&serde_json::to_value(&original).unwrap()).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let duplicate = text.replacen("\"schema\":", "\"schema\":\"duplicate\",\"schema\":", 1);
        assert!(authenticate_canonical_report(duplicate.as_bytes(), &original).is_err());
        let mut unknown = bytes.clone();
        unknown.pop();
        unknown.extend_from_slice(b",\"unknown\":null}");
        assert!(authenticate_canonical_report(&unknown, &original).is_err());
        let leading_zero = text.replacen("\"native_pid\":\"1\"", "\"native_pid\":\"01\"", 1);
        assert_ne!(leading_zero, text);
        assert!(authenticate_canonical_report(leading_zero.as_bytes(), &original).is_err());
        assert!(quoted_u64(b"1", U64::new(1)).is_err());
        assert!(quoted_u64(b"\"18446744073709551616\"", U64::new(0)).is_err());
    }
}
