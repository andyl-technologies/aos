//! Defines the separately selected full Capture-allocation outer snapshot.
//!
//! ```text
//! {"capture":{},"capture_request":{},"control":{},"control_reference":{},
//!  "endpoint":["source-owned.packet-native-endpoint-state/13",...13 old fields...,
//!    ["source-private.native-capture-allocation-owner-reference/13",REPORT_REF]],
//!  "protocol":["source-private.native-before-protocol/13",BEFORE_REF,CAPACITY,COMPACT],
//!  "schema":"source-owned.packet-native-continuation/13"}
//! ```
//!
//! Report bytes remain in the actual inner native-state14 fourth owner and the
//! original Observe proof. This marker establishes a checked data join, never a
//! replacement for full inner alias/currency, Control/model and Source validation.

use super::*;
use crate::reference_packet::service::capture_allocation::{
    MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES, PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,
};

const SCHEMA: &str = "source-owned.packet-native-continuation/13";
const BEFORE_TAG: &str = "source-private.native-before-protocol/13";
const ENDPOINT_TAG: &str = "source-owned.packet-native-endpoint-state/13";
const OWNER_MARKER: &str = "source-private.native-capture-allocation-owner-reference/13";

// A single canonical closed definition is used by both the owning declaration
// producer and the allocation-free installed-schema comparison. It contains no
// process-private layout, pointer, clock or original issuer material.
const CONTRACT_BYTES: &[u8] = include_bytes!("startup_capture_contract13.json");

/// Checks the entire installed schema against the actual compiled definition.
///
/// This is a DATA comparison. The caller separately authenticates the original
/// policy/source roots and startup admission before using an installed schema.
///
/// # Errors
/// Refuses any changed identity, revision, extension, full reference or bytes.
pub(crate) fn authenticate_native_owned13_snapshot_schema_data(
    schema: &SchemaRef,
) -> Result<(), ProviderError> {
    let reference = &schema.definition;
    if schema.id.as_str() != SCHEMA
        || schema.version != 13
        || !schema.extensions.is_empty()
        || reference.media_type != "application/json"
        || reference.length.get() != CONTRACT_BYTES.len() as u64
        || reference.hash.algorithm != "blake3-256"
        || reference.hash.domain != "cnp.blob.v1"
    {
        return Err(invalid());
    }
    let mut hasher = blob_hasher(CONTRACT_BYTES.len())?;
    hasher.update(CONTRACT_BYTES);
    let hash = hasher.finalize();
    let digest = reference.hash.digest.as_bytes();
    if digest.len() != 64 {
        return Err(invalid());
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // The exact 64-byte gate above proves the two-byte view has no remainder.
    let (pairs, _) = digest.as_chunks::<2>();
    for (byte, pair) in hash.as_bytes().iter().zip(pairs) {
        if pair[0] != HEX[usize::from(byte >> 4)] || pair[1] != HEX[usize::from(byte & 15)] {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Names the full fixed requested headers of the schema DATA comparator.
///
/// The borrowed reference, hash return, framing scalars and iterator views are
/// paid before the complete schema comparison. These DATA grant no authority.
pub(crate) const fn native_owned13_snapshot_schema_counter_scratch_data() -> usize {
    std::mem::size_of::<blake3::Hasher>()
        + std::mem::size_of::<Result<blake3::Hasher, ProviderError>>()
        + std::mem::size_of::<blake3::Hash>()
        + std::mem::size_of::<&crucible_node_format::ContentRef>()
        + std::mem::size_of::<[u8; 4]>()
        + std::mem::size_of::<[u8; 8]>()
        + std::mem::size_of::<Result<u64, std::num::TryFromIntError>>()
        + std::mem::size_of::<Result<(), ProviderError>>()
        + std::mem::size_of::<&SchemaRef>()
        + std::mem::size_of::<&[u8]>()
        + std::mem::size_of::<(&u8, &[u8])>()
        // Retain the original counter terms and pay the actual array view,
        // returned split tuple, typed pair and replacement iterator separately.
        + std::mem::size_of::<&[[u8; 2]]>()
        + std::mem::size_of::<(&[[u8; 2]], &[u8])>()
        + std::mem::size_of::<(&u8, &[u8; 2])>()
        + std::mem::size_of::<Option<(&u8, &[u8; 2])>>()
        + std::mem::size_of::<std::slice::Iter<'static, u8>>()
        + std::mem::size_of::<std::slice::Iter<'static, [u8; 2]>>()
        + std::mem::size_of::<
            std::iter::Zip<std::slice::Iter<'static, u8>, std::slice::Iter<'static, [u8; 2]>>,
        >()
}

/// Returns the complete definition for the selected allocation-owning snapshot.
///
/// # Errors
/// Reports canonical definition encoding failure.
pub fn native_owned13_snapshot_contract() -> Result<Vec<u8>, ProviderError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(CONTRACT_BYTES.len()).map_err(|_| {
        ProviderError::ResourceExhausted("native startup snapshot definition storage")
    })?;
    bytes.extend_from_slice(CONTRACT_BYTES);
    Ok(bytes)
}

/// Returns the exact schema reference of the complete allocation-owning edition.
///
/// # Errors
/// Reports invalid schema identifier or canonical definition encoding failure.
pub fn native_owned13_snapshot_schema() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(SCHEMA)?,
        version: 13,
        definition: canonical::content_ref(
            &native_owned13_snapshot_contract()?,
            "application/json",
        )?,
        extensions: Default::default(),
    })
}

/// Borrows exact outer13 framing and its explicit original Report dependency.
///
/// This allocation-free framing/hash plan does not perform owning cold decoding
/// or prove Source, actor, currentness or adoption authority.
pub struct PacketNativeOwned13SnapshotPlan<'a> {
    capture: &'a [u8],
    capture_request: &'a [u8],
    control: &'a [u8],
    control_reference: &'a [u8],
    endpoint: PacketNativeOwned11EndpointPlan<'a>,
    before: PacketNativeBeforeProtocolPlan<'a>,
    report_reference: &'a [u8],
    report_length: usize,
}

impl<'a> PacketNativeOwned13SnapshotPlan<'a> {
    /// Checks closed framing, raw-before identity and exact Report reference grammar.
    ///
    /// # Errors
    /// Refuses another edition/tag, missing/extra fields, malformed reference,
    /// exceeded bounds, changed raw before or embedded Control bytes.
    pub fn validate(
        input: &'a [u8],
        maximum_input: usize,
        maximum_before_capacity: usize,
    ) -> Result<Self, ProviderError> {
        if input.len() > maximum_input {
            return Err(invalid());
        }
        let mut fields = Fields::object(input)?;
        let capture = fields.named("capture")?;
        let capture_request = fields.named("capture_request")?;
        let control = fields.named("control")?;
        let control_reference = fields.named("control_reference")?;
        let mut endpoint_fields = Fields::array(fields.named("endpoint")?)?;
        let endpoint = PacketNativeOwned11EndpointPlan::read_original_fields_at_context(
            &mut endpoint_fields,
            ENDPOINT_TAG,
            "same-original-native-protocol-service-context/14",
        )?;
        let mut marker = Fields::array(required(&mut endpoint_fields)?)?;
        if plain_string(required(&mut marker)?)? != OWNER_MARKER {
            return Err(invalid());
        }
        let report_reference = required(&mut marker)?;
        marker.finish()?;
        endpoint_fields.finish()?;
        let report_length = report_reference_data(report_reference)?;
        let before = PacketNativeBeforeProtocolPlan::validate_edition(
            fields.named("protocol")?,
            maximum_input,
            maximum_before_capacity,
            BEFORE_TAG,
        )?;
        authenticate_startup_inner_tag(&before)?;
        if plain_string(fields.named("schema")?)? != SCHEMA {
            return Err(invalid());
        }
        fields.finish()?;
        if capture.first() != Some(&b'{')
            || capture_request.first() != Some(&b'{')
            || control.first() != Some(&b'{')
        {
            return Err(invalid());
        }
        authenticate_blob(control_reference, control)?;
        let mut control_fields = Fields::object(control)?;
        for key in [
            "administrative_cut",
            "captured_process",
            "control",
            "local_cursor",
            "model",
        ] {
            control_fields.named(key)?;
        }
        if plain_string(control_fields.named("schema")?)?
            != "source-owned.packet-native-control-state/6"
        {
            return Err(invalid());
        }
        control_fields.finish()?;
        Ok(Self {
            capture,
            capture_request,
            control,
            control_reference,
            endpoint,
            before,
            report_reference,
            report_length,
        })
    }

    /// Borrows the complete original Capture arguments.
    pub fn capture_arguments_bytes(&self) -> &'a [u8] {
        self.capture
    }
    /// Borrows the full original incoming Capture Envelope.
    pub fn capture_request_bytes(&self) -> &'a [u8] {
        self.capture_request
    }
    /// Borrows the exact embedded complete Control6 bytes.
    pub fn control_bytes(&self) -> &'a [u8] {
        self.control
    }
    /// Borrows its full separately returned Control reference.
    pub fn control_reference_bytes(&self) -> &'a [u8] {
        self.control_reference
    }
    /// Borrows all thirteen original endpoint fields for full typed validation.
    pub fn endpoint(&self) -> &PacketNativeOwned11EndpointPlan<'a> {
        &self.endpoint
    }
    /// Borrows the independently verified exact original native-state14 bytes.
    pub fn before(&self) -> &PacketNativeBeforeProtocolPlan<'a> {
        &self.before
    }
    /// Borrows the exact full reference of the original Observe Report dependency.
    pub fn allocation_reference_bytes(&self) -> &'a [u8] {
        self.report_reference
    }

    /// Checks complete supplied original Report bytes against the declared reference.
    ///
    /// # Errors
    /// Refuses changed length/hash bytes. Typed canonical Report and genuine
    /// original producer/currency/inner-owner correspondence remain separate.
    pub fn authenticate_allocation_bytes(&self, bytes: &[u8]) -> Result<(), ProviderError> {
        if bytes.len() != self.report_length {
            return Err(invalid());
        }
        let digest = reference_digest(self.report_reference)?;
        let mut hasher = blob_hasher(bytes.len())?;
        hasher.update(bytes);
        if hasher.finalize().to_hex().as_str() != digest {
            return Err(invalid());
        }
        Ok(())
    }
}

fn reference_digest(input: &[u8]) -> Result<&str, ProviderError> {
    let mut reference = Fields::object(input)?;
    let mut hash = Fields::object(reference.named("hash")?)?;
    if plain_string(hash.named("algorithm")?)? != "blake3-256" {
        return Err(invalid());
    }
    let digest = plain_string(hash.named("digest")?)?;
    if digest.len() != 2 * blake3::OUT_LEN
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || plain_string(hash.named("domain")?)? != "cnp.blob.v1"
    {
        return Err(invalid());
    }
    hash.finish()?;
    reference.named("length")?;
    if plain_string(reference.named("media_type")?)? != PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA {
        return Err(invalid());
    }
    reference.finish()?;
    Ok(digest)
}

fn report_reference_data(input: &[u8]) -> Result<usize, ProviderError> {
    reference_digest(input)?;
    let mut fields = Fields::object(input)?;
    fields.named("hash")?;
    let length = usize::try_from(unsigned(plain_string(fields.named("length")?)?.as_bytes())?)
        .map_err(|_| invalid())?;
    fields.named("media_type")?;
    fields.finish()?;
    if length == 0 || length > MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES {
        return Err(invalid());
    }
    Ok(length)
}

/// Returns known actual parser headers and declared fixed scratch for outer13.
///
/// This data substitutes the actual outer13 root size into the same bounded
/// Fields/compact/hash implementation. It excludes compiler/recursive frames,
/// decoded native/Control/model owners and the complete factory transient peak.
pub fn packet_native_owned13_snapshot_validation_layouts()
-> PacketNativeOwned11SnapshotValidationLayouts {
    let mut layouts = packet_native_owned11_snapshot_validation_layouts();
    layouts.plan_header_bytes = std::mem::size_of::<PacketNativeOwned13SnapshotPlan<'static>>();
    layouts.plan_header_alignment =
        std::mem::align_of::<PacketNativeOwned13SnapshotPlan<'static>>();
    layouts.raw_chunk_array_bytes = layouts
        .raw_chunk_array_bytes
        .saturating_add(INNER_STARTUP_PREFIX.len());
    layouts
}

// This exact prefix is emitted by the owning SDK14 serializer. The full raw
// body has already been hash-checked by the compact plan; the complete typed
// startup codec remains a separate mandatory validation before any rights.
const INNER_STARTUP_PREFIX: &[u8] =
    b"[\"source-private.cnp-protocol/11\",[\"source-private.native-state/14\",";

fn authenticate_startup_inner_tag(
    before: &PacketNativeBeforeProtocolPlan<'_>,
) -> Result<(), ProviderError> {
    if before.encoded_length() < INNER_STARTUP_PREFIX.len() {
        return Err(invalid());
    }
    let mut prefix = [0u8; INNER_STARTUP_PREFIX.len()];
    before.bytes.copy_range(0, &mut prefix)?;
    if prefix != INNER_STARTUP_PREFIX {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
    use crucible_node_format::ContentRef;
    use serde_json::{Value, json};

    // These are framing-only data controls, intentionally not a fabricated
    // native-state14/Control6 positive or Source/SDK owner. Full cold codecs
    // must reject the dummy model; this plan verifies raw bytes and joins only.
    fn framing_data() -> Result<(Value, Vec<u8>, Vec<u8>, ContentRef), ProviderError> {
        let before = br#"["source-private.cnp-protocol/11",["source-private.native-state/14",null,null,null,null],[],[]]"#.to_vec();
        let before_reference = canonical::content_ref(&before, "application/json")?;
        let report = br#"{"original":"report framing data"}"#.to_vec();
        let report_reference =
            canonical::content_ref(&report, PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA)?;
        let control = json!({
            "administrative_cut":{}, "captured_process":"1", "control":{},
            "local_cursor":{}, "model":{}, "schema":"source-owned.packet-native-control-state/6"
        });
        let control_reference =
            canonical::content_ref(&canonical::canonical_json(&control)?, "application/json")?;
        let value = json!({
            "capture":{}, "capture_request":{}, "control":control,
            "control_reference":control_reference,
            "endpoint":[ENDPOINT_TAG,{},null,null,null,{},
                "same-original-native-protocol-service-context/14",[],0,[],0,1,0,true,
                [OWNER_MARKER,report_reference]],
            "protocol":[BEFORE_TAG,before_reference,before.len()+17,
                serde_json::to_value(BorrowedCompactBytes::new(&before)).map_err(crucible_node_format::ContractError::from)?],
            "schema":SCHEMA
        });
        Ok((value, before, report, report_reference))
    }

    #[test]
    fn outer13_framing_preserves_raw_before_and_exact_original_report_reference()
    -> Result<(), ProviderError> {
        let (value, before, report, reference) = framing_data()?;
        let encoded = canonical::canonical_json(&value)?;
        let plan =
            PacketNativeOwned13SnapshotPlan::validate(&encoded, encoded.len(), before.len() + 17)?;
        plan.before().authenticate_original_bytes(&before)?;
        plan.authenticate_allocation_bytes(&report)?;
        let decoded: ContentRef = serde_json::from_slice(plan.allocation_reference_bytes())
            .map_err(crucible_node_format::ContractError::from)?;
        assert_eq!(decoded, reference);
        assert_eq!(plan.before().original_capacity(), before.len() + 17);
        assert!(
            PacketNativeOwned11SnapshotPlan::validate(&encoded, encoded.len(), before.len() + 17)
                .is_err()
        );
        assert!(
            super::super::capture_allocation::PacketNativeOwned12SnapshotPlan::validate(
                &encoded,
                encoded.len(),
                before.len() + 17
            )
            .is_err()
        );
        let mut changed = report;
        changed[1] ^= 1;
        assert!(plan.authenticate_allocation_bytes(&changed).is_err());
        Ok(())
    }

    #[test]
    fn outer13_refuses_wrong_endpoint_before_control_and_report_editions()
    -> Result<(), ProviderError> {
        let (original, before, _, _) = framing_data()?;
        for field in [0usize, 1, 2, 3, 4] {
            let mut value = original.clone();
            match field {
                0 => {
                    value["schema"] =
                        Value::String("source-owned.packet-native-continuation/11".into())
                }
                1 => {
                    value["endpoint"][0] =
                        Value::String("source-owned.packet-native-endpoint-state/11".into())
                }
                2 => {
                    value["protocol"][0] =
                        Value::String("source-private.native-before-protocol/11".into())
                }
                3 => {
                    value["control"]["schema"] =
                        Value::String("source-owned.packet-native-control-state/5".into());
                    value["control_reference"] = serde_json::to_value(canonical::content_ref(
                        &canonical::canonical_json(&value["control"])?,
                        "application/json",
                    )?)
                    .map_err(crucible_node_format::ContractError::from)?;
                }
                _ => {
                    value["endpoint"][14][1]["media_type"] =
                        Value::String("application/json".into())
                }
            }
            let encoded = canonical::canonical_json(&value)?;
            assert!(
                PacketNativeOwned13SnapshotPlan::validate(
                    &encoded,
                    encoded.len(),
                    before.len() + 17
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn outer13_refuses_inner12_even_when_raw_full_reference_is_recomputed()
    -> Result<(), ProviderError> {
        let (mut value, _, _, _) = framing_data()?;
        let old = br#"["source-private.cnp-protocol/11",["source-private.native-state/12",null,null,null,null],[],[]]"#;
        value["protocol"][1] =
            serde_json::to_value(canonical::content_ref(old, "application/json")?)
                .map_err(crucible_node_format::ContractError::from)?;
        value["protocol"][2] = Value::from(old.len() + 17);
        value["protocol"][3] = serde_json::to_value(BorrowedCompactBytes::new(old))
            .map_err(crucible_node_format::ContractError::from)?;
        let encoded = canonical::canonical_json(&value)?;
        assert!(
            PacketNativeOwned13SnapshotPlan::validate(&encoded, encoded.len(), old.len() + 17)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn startup_snapshot_schema_gate_matches_actual_canonical_producer_and_rejects_every_fullref_axis()
    -> Result<(), ProviderError> {
        let bytes = native_owned13_snapshot_contract()?;
        let parsed = canonical::parse_json(&bytes, bytes.len())?;
        assert_eq!(canonical::canonical_json(&parsed)?, bytes);
        let original = native_owned13_snapshot_schema()?;
        authenticate_native_owned13_snapshot_schema_data(&original)?;
        for axis in 0..7 {
            let mut changed = original.clone();
            match axis {
                0 => changed.version = 12,
                1 => changed.id = Id::new("changed-native-schema")?,
                2 => {
                    changed.definition.length =
                        crucible_node_format::U64::new(changed.definition.length.get() + 1)
                }
                3 => changed.definition.media_type.push('x'),
                4 => changed.definition.hash.algorithm.push('x'),
                5 => changed.definition.hash.domain.push('x'),
                _ => changed.definition.hash.digest.push('0'),
            }
            assert!(authenticate_native_owned13_snapshot_schema_data(&changed).is_err());
        }

        // Keep the digest's exact width and valid lowercase spelling while
        // independently changing every compared byte of the full reference.
        for index in 0..original.definition.hash.digest.len() {
            let mut changed = original.clone();
            let replacement = if changed.definition.hash.digest.as_bytes()[index] == b'0' {
                "1"
            } else {
                "0"
            };
            changed
                .definition
                .hash
                .digest
                .replace_range(index..index + 1, replacement);
            assert!(authenticate_native_owned13_snapshot_schema_data(&changed).is_err());
        }
        Ok(())
    }

    #[test]
    fn outer13_definition_and_known_layout_are_distinct_without_old_class_promotion()
    -> Result<(), ProviderError> {
        let contract = native_owned13_snapshot_contract()?;
        let schema = native_owned13_snapshot_schema()?;
        schema.definition.verify(&contract)?;
        assert_eq!(schema.version, 13);
        assert_ne!(
            schema.definition,
            native_owned11_snapshot_schema()?.definition
        );
        let layout = packet_native_owned13_snapshot_validation_layouts();
        assert_eq!(
            layout.plan_header_bytes,
            std::mem::size_of::<PacketNativeOwned13SnapshotPlan<'static>>()
        );
        assert_eq!(
            layout.raw_chunk_array_bytes,
            3072 + INNER_STARTUP_PREFIX.len()
        );
        assert_eq!(layout.maximum_simultaneous_field_cursors, 4);
        Ok(())
    }
}
