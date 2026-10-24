//! Defines the separately selected full Capture-allocation outer snapshot.
//!
//! ```text
//! {"capture":{},"capture_request":{},"control":{},"control_reference":{},
//!  "endpoint":["source-owned.packet-native-endpoint-state/12",...13 old fields...,
//!    ["source-private.native-capture-allocation-owner-reference/12",REPORT_REF]],
//!  "protocol":["source-private.native-before-protocol/12",BEFORE_REF,CAPACITY,COMPACT],
//!  "schema":"source-owned.packet-native-continuation/12"}
//! ```
//!
//! Report bytes remain in the actual inner native-state12 fourth owner and the
//! original Observe proof. This marker establishes a checked data join, never a
//! replacement for full inner alias/currency, Control/model and Source validation.

use super::*;
use crate::reference_packet::service::capture_allocation::{
    MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES, PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,
};

const SCHEMA: &str = "source-owned.packet-native-continuation/12";
const BEFORE_TAG: &str = "source-private.native-before-protocol/12";
const ENDPOINT_TAG: &str = "source-owned.packet-native-endpoint-state/12";
const OWNER_MARKER: &str = "source-private.native-capture-allocation-owner-reference/12";

/// Returns the complete definition for the selected allocation-owning snapshot.
///
/// # Errors
/// Reports canonical definition encoding failure.
pub fn native_owned12_snapshot_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(&serde_json::json!({
        "schema":"source-owned.packet-native-continuation-contract/12",
        "snapshot":SCHEMA,
        "fields":["capture","capture_request","control","control_reference","endpoint","protocol","schema"],
        "protocol":[BEFORE_TAG,"full application/json reference of exact original inner native-state12 bytes","actual original encoded Vec capacity","complete compact-bytes/7 literal bytes"],
        "endpoint":[ENDPOINT_TAG,"the same13 independently validated original endpoint fields of endpoint11",[OWNER_MARKER,"full original Observe allocation Report reference"]],
        "endpoint_fields":["tag12","storage","profile","metadata_limits","metadata_birth_facts","full original Hello","same-original-native-protocol-service-context/11","full original records","records capacity","full original pins","pins capacity","next provider sequence","retained transport credit","held=true","allocation owner reference marker"],
        "endpoint_context":"same-original-native-protocol-service-context/11 remains the exact actual service root marker",
        "control":"full source-owned.packet-native-control-state/6; selected original_observe12 field and exact original Capture",
        "inner":"full source-private.native-state/12 four-leaf codec; actual policy17 and Some same Capture; same actor/codec/frame/Control currency alias groups",
        "report":{"media":PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,"maximum_bytes":MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES,"body":"exact canonical original Observe Report, never recreated from counters"},
        "direct_dependencies":["exact separately returned complete Control","exact original Observe allocation Report"],
        "identity":"retain original raw before bytes/fullref/spare capacity; never parse and canonicalize to a replacement identity",
        "validation":"full four-leaf cold decoder, actual endpoint histories/pins/Hello, Control/model transition, Report typed/raw/fullref and same original Observe/Capture conjunction, terminal and fourth-Poll correspondence remain mandatory",
        "authority":"historical data only; no Source ticket, fresh allocation record, registrar, restored gate or Arm/Capture permission"
    }))?)
}

/// Returns the exact schema reference of the complete allocation-owning edition.
///
/// # Errors
/// Reports invalid schema identifier or canonical definition encoding failure.
pub fn native_owned12_snapshot_schema() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(SCHEMA)?,
        version: 12,
        definition: canonical::content_ref(
            &native_owned12_snapshot_contract()?,
            "application/json",
        )?,
        extensions: Default::default(),
    })
}

/// Borrows exact outer12 framing and its explicit original Report dependency.
///
/// This allocation-free framing/hash plan does not perform owning cold decoding
/// or prove Source, actor, currentness or adoption authority.
pub struct PacketNativeOwned12SnapshotPlan<'a> {
    capture: &'a [u8],
    capture_request: &'a [u8],
    control: &'a [u8],
    control_reference: &'a [u8],
    endpoint: PacketNativeOwned11EndpointPlan<'a>,
    before: PacketNativeBeforeProtocolPlan<'a>,
    report_reference: &'a [u8],
    report_length: usize,
}

impl<'a> PacketNativeOwned12SnapshotPlan<'a> {
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
        let endpoint = PacketNativeOwned11EndpointPlan::read_original_fields(
            &mut endpoint_fields,
            ENDPOINT_TAG,
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
    /// Borrows the independently verified exact original native-state12 bytes.
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

/// Returns known actual parser headers and declared fixed scratch for outer12.
///
/// This data substitutes the actual outer12 root size into the same bounded
/// Fields/compact/hash implementation. It excludes compiler/recursive frames,
/// decoded native/Control/model owners and the complete factory transient peak.
pub fn packet_native_owned12_snapshot_validation_layouts()
-> PacketNativeOwned11SnapshotValidationLayouts {
    let mut layouts = packet_native_owned11_snapshot_validation_layouts();
    layouts.plan_header_bytes = std::mem::size_of::<PacketNativeOwned12SnapshotPlan<'static>>();
    layouts.plan_header_alignment =
        std::mem::align_of::<PacketNativeOwned12SnapshotPlan<'static>>();
    layouts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
    use crucible_node_format::ContentRef;
    use serde_json::{Value, json};

    // These are framing-only data controls, intentionally not a fabricated
    // native-state12/Control6 positive or Source/SDK owner. Full cold codecs
    // must reject the dummy model; this plan verifies raw bytes and joins only.
    fn framing_data() -> Result<(Value, Vec<u8>, Vec<u8>, ContentRef), ProviderError> {
        let before = br#"{"preserved":1.0,"original":"literal order"}"#.to_vec();
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
                "same-original-native-protocol-service-context/11",[],0,[],0,1,0,true,
                [OWNER_MARKER,report_reference]],
            "protocol":[BEFORE_TAG,before_reference,before.len()+17,
                serde_json::to_value(BorrowedCompactBytes::new(&before)).map_err(crucible_node_format::ContractError::from)?],
            "schema":SCHEMA
        });
        Ok((value, before, report, report_reference))
    }

    #[test]
    fn outer12_framing_preserves_raw_before_and_exact_original_report_reference()
    -> Result<(), ProviderError> {
        let (value, before, report, reference) = framing_data()?;
        let encoded = canonical::canonical_json(&value)?;
        let plan =
            PacketNativeOwned12SnapshotPlan::validate(&encoded, encoded.len(), before.len() + 17)?;
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
        let mut changed = report;
        changed[1] ^= 1;
        assert!(plan.authenticate_allocation_bytes(&changed).is_err());
        Ok(())
    }

    #[test]
    fn outer12_refuses_wrong_endpoint_before_control_and_report_editions()
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
                PacketNativeOwned12SnapshotPlan::validate(
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
    fn outer12_definition_and_known_layout_are_distinct_without_old_class_promotion()
    -> Result<(), ProviderError> {
        let contract = native_owned12_snapshot_contract()?;
        let schema = native_owned12_snapshot_schema()?;
        schema.definition.verify(&contract)?;
        assert_eq!(schema.version, 12);
        assert_ne!(
            schema.definition,
            native_owned11_snapshot_schema()?.definition
        );
        let layout = packet_native_owned12_snapshot_validation_layouts();
        assert_eq!(
            layout.plan_header_bytes,
            std::mem::size_of::<PacketNativeOwned12SnapshotPlan<'static>>()
        );
        assert_eq!(layout.raw_chunk_array_bytes, 3072);
        assert_eq!(layout.maximum_simultaneous_field_cursors, 4);
        Ok(())
    }
}
