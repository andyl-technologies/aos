//! Frames settled native17 Capture without reinterpreting an old snapshot.
//!
//! The protocol leaf owns the complete current Endpoint17 and native graph.
//! This outer plan only binds exact raw-before bytes and current Control bytes;
//! the defining native17 reader validates their logical and historical joins.
//!
//! ```text
//! {"capture":{},"capture_request":{},"control":{},"control_reference":{},
//!  "protocol":["source-private.native-before-protocol/17",REF,CAPACITY,COMPACT],
//!  "schema":"source-owned.packet-native-continuation/17"}
//! ```

use super::*;
use crucible_node_contract::ContentRef;

const SCHEMA: &str = "source-owned.packet-native-continuation/17";
const BEFORE_TAG: &str = "source-private.native-before-protocol/17";
const CONTRACT: &[u8] = include_bytes!("restored_settled_contract17.json");

/// Borrows the exact full native17 snapshot contract.
pub fn native_restored_settled17_snapshot_contract_data() -> &'static [u8] {
    CONTRACT
}

/// Returns the distinct settled native snapshot definition.
///
/// # Errors
/// Reports invalid compiled identifiers or full reference construction failure.
pub fn native_restored_settled17_snapshot_schema() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(SCHEMA)?,
        version: 17,
        definition: canonical::content_ref(CONTRACT, "application/json")?,
        extensions: Default::default(),
    })
}

/// Checks the full selected native17 definition with fixed hash scratch.
///
/// This comparison is immutable DATA, not a live Capture grant or decoder.
///
/// # Errors
/// Refuses another identifier, version, extension or full definition reference.
pub fn authenticate_native_restored_settled17_snapshot_schema_data(
    schema: &SchemaRef,
) -> Result<(), ProviderError> {
    if schema.id.as_str() != SCHEMA || schema.version != 17 || !schema.extensions.is_empty() {
        return Err(invalid17());
    }
    authenticate_native_restored_settled17_snapshot_definition_data(&schema.definition)
}

/// Checks the entire current native17 definition using fixed borrowed hashing.
///
/// The defining Source signature and actual native phase owner are separate
/// requirements. A matching reference alone creates no upload/Capture right.
///
/// # Errors
/// Refuses another media, algorithm, domain, length or definition digest.
pub fn authenticate_native_restored_settled17_snapshot_definition_data(
    reference: &ContentRef,
) -> Result<(), ProviderError> {
    let length = u64::try_from(CONTRACT.len()).map_err(|_| invalid17())?;
    if reference.length.get() != length
        || reference.media_type != "application/json"
        || reference.hash.algorithm != "blake3-256"
        || reference.hash.domain != "cnp.blob.v1"
    {
        return Err(invalid17());
    }
    let mut hasher = blob_hasher(CONTRACT.len())?;
    hasher.update(CONTRACT);
    if hasher.finalize().to_hex().as_str() != reference.hash.digest.as_str() {
        return Err(invalid17());
    }
    Ok(())
}

/// Borrows a closed native17 outer with exact original protocol and Control.
///
/// No typed native owner, endpoint, socket, ledger or authority is reconstructed.
/// The complete native17 reader is a separate required validation stage.
pub struct PacketNativeRestoredSettled17SnapshotPlan<'a> {
    capture: &'a [u8],
    capture_request: &'a [u8],
    control: &'a [u8],
    control_reference: &'a [u8],
    before: PacketNativeBeforeProtocolPlan<'a>,
}

impl<'a> PacketNativeRestoredSettled17SnapshotPlan<'a> {
    /// Checks the exact six-field family and both full raw-body associations.
    ///
    /// The protocol tag17 is distinct from every old before tag. The complete
    /// native17 reader must independently validate the current Endpoint graph,
    /// Capture request/proof, immutable ancestry and actual Control semantics.
    ///
    /// # Errors
    /// Refuses oversized input/capacity, malformed or extra/missing fields,
    /// another family, invalid compact bytes or changed full body references.
    pub fn validate(
        input: &'a [u8],
        maximum_input: usize,
        maximum_before_capacity: usize,
    ) -> Result<Self, ProviderError> {
        if input.is_empty() || input.len() > maximum_input {
            return Err(invalid17());
        }
        let mut fields = Fields::object(input)?;
        let capture = fields.named("capture")?;
        let capture_request = fields.named("capture_request")?;
        let control = fields.named("control")?;
        let control_reference = fields.named("control_reference")?;
        let before = PacketNativeBeforeProtocolPlan::validate_edition(
            fields.named("protocol")?,
            maximum_input,
            maximum_before_capacity,
            BEFORE_TAG,
        )?;
        if plain_string(fields.named("schema")?)? != SCHEMA {
            return Err(invalid17());
        }
        fields.finish()?;
        if [capture, capture_request, control]
            .into_iter()
            .any(|body| body.first() != Some(&b'{'))
        {
            return Err(invalid17());
        }
        authenticate_blob(control_reference, control)?;
        Ok(Self {
            capture,
            capture_request,
            control,
            control_reference,
            before,
        })
    }

    /// Borrows actual original Capture arguments for the defining typed validator.
    pub fn capture_arguments_bytes(&self) -> &'a [u8] {
        self.capture
    }

    /// Borrows the exact assigned Capture Envelope, including its signed artifact.
    pub fn capture_request_bytes(&self) -> &'a [u8] {
        self.capture_request
    }

    /// Borrows exact current Control17 bytes rather than an old Control5 cast.
    pub fn control_bytes(&self) -> &'a [u8] {
        self.control
    }

    /// Borrows the complete content identity of the embedded Control body.
    pub fn control_reference_bytes(&self) -> &'a [u8] {
        self.control_reference
    }

    /// Borrows the independently bounded exact raw native-state17 protocol bank.
    pub fn before(&self) -> &PacketNativeBeforeProtocolPlan<'a> {
        &self.before
    }
}

/// Names fixed full-schema comparison scratch independently of a codec caller.
///
/// The defining parser/hash total is conservative for this smaller comparison.
/// No input-dependent body, output or reconstruction bank is included.
pub fn native_restored_settled17_snapshot_schema_counter_scratch_data() -> usize {
    native_restored_settled17_snapshot_counter_scratch_data()
}

/// Names the defining fixed parser/hash headers before any native17 framing pass.
///
/// This is requested-layout DATA only. Raw/DOM/typed owners, aliases, errors,
/// reconstruction, complete native graph semantics and output banks are separate.
pub fn native_restored_settled17_snapshot_counter_scratch_data() -> usize {
    use std::mem::{size_of, size_of_val};
    let hash = blake3::Hash::from_bytes([0; 32]);
    let terms = [
        size_of::<PacketNativeRestoredSettled17SnapshotPlan<'static>>(),
        size_of::<Result<PacketNativeRestoredSettled17SnapshotPlan<'static>, ProviderError>>(),
        size_of::<PacketNativeBeforeProtocolPlan<'static>>(),
        size_of::<Result<PacketNativeBeforeProtocolPlan<'static>, ProviderError>>(),
        4 * size_of::<Fields<'static>>(),
        size_of::<[u8; 128]>(),
        size_of::<[u8; 3072]>(),
        size_of::<ValidatedCompactBytes<'static>>(),
        size_of::<Result<ValidatedCompactBytes<'static>, ProviderError>>(),
        size_of::<blake3::Hasher>(),
        size_of::<Result<blake3::Hasher, ProviderError>>(),
        size_of::<blake3::Hash>(),
        size_of_val(&hash.to_hex()),
        8 * size_of::<&[u8]>(),
        size_of::<Option<&[u8]>>(),
        size_of::<Result<&[u8], ProviderError>>(),
        size_of::<Result<(&[u8], &str), ProviderError>>(),
        size_of::<(&[u8], &str)>(),
        size_of::<[&[u8]; 3]>(),
        size_of::<std::array::IntoIter<&[u8], 3>>(),
        size_of::<std::slice::Iter<'static, u8>>(),
        size_of::<std::slice::ChunksExact<'static, u8>>(),
        size_of::<std::iter::StepBy<std::ops::Range<usize>>>(),
        size_of::<Result<usize, std::num::TryFromIntError>>(),
        size_of::<Result<u64, std::num::TryFromIntError>>(),
        size_of::<Result<usize, ProviderError>>(),
        size_of::<Result<u64, ProviderError>>(),
        size_of::<Result<(), ProviderError>>(),
        size_of::<Option<&u8>>(),
        size_of::<[u8; 4]>(),
        size_of::<[u8; 8]>(),
        4 * size_of::<usize>(),
        size_of::<&SchemaRef>(),
        size_of::<&crucible_node_contract::ContentRef>(),
        size_of::<&str>(),
    ];
    size_of_val(&terms)
        + size_of::<std::array::IntoIter<usize, 35>>()
        + terms.into_iter().sum::<usize>()
}

fn invalid17() -> ProviderError {
    ProviderError::Correlation("settled native17 outer framing differs")
}

#[cfg(test)]
mod tests {
    // Inert framing fixtures intentionally panic when static DATA is invalid.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
    use crucible_node_contract::U64;

    fn snapshot() -> (serde_json::Value, Vec<u8>) {
        // This is framing DATA, not a valid native graph or live authority.
        let mut before = Vec::with_capacity(256);
        before.extend_from_slice(br#"{"schema":"source-private.native-state/17"}"#);
        assert!(before.capacity() > before.len());
        let control =
            serde_json::json!({"schema":"source-owned.packet-native-control-restored-settled/17"});
        let control_bytes = canonical::canonical_json(&control).unwrap();
        let value = serde_json::json!({
            "capture":{},
            "capture_request":{},
            "control":control,
            "control_reference":canonical::content_ref(&control_bytes,"application/json").unwrap(),
            "protocol":[BEFORE_TAG,canonical::content_ref(&before,"application/json").unwrap(),before.capacity(),BorrowedCompactBytes::new(&before)],
            "schema":SCHEMA,
        });
        (value, before)
    }

    #[test]
    fn raw_before_spare_capacity_and_control_reference_are_independent() {
        let (mut value, before) = snapshot();
        let bytes = canonical::canonical_json(&value).unwrap();
        let plan = PacketNativeRestoredSettled17SnapshotPlan::validate(
            &bytes,
            bytes.len(),
            before.capacity(),
        )
        .unwrap();
        plan.before().authenticate_original_bytes(&before).unwrap();
        assert_eq!(plan.before().original_capacity(), before.capacity());
        assert!(
            PacketNativeRestoredSettled17SnapshotPlan::validate(
                &bytes,
                bytes.len() - 1,
                before.capacity()
            )
            .is_err()
        );
        assert!(
            PacketNativeRestoredSettled17SnapshotPlan::validate(
                &bytes,
                bytes.len(),
                before.capacity() - 1
            )
            .is_err()
        );

        value["control"]["changed"] = serde_json::json!(true);
        let changed = canonical::canonical_json(&value).unwrap();
        assert!(
            PacketNativeRestoredSettled17SnapshotPlan::validate(
                &changed,
                changed.len(),
                before.capacity()
            )
            .is_err()
        );
    }

    #[test]
    fn old_families_and_extra_outer_fields_never_select_seventeen() {
        let (value, before) = snapshot();
        for schema in [
            "source-owned.packet-native-continuation/11",
            "source-owned.packet-native-continuation/14",
        ] {
            let mut changed = value.clone();
            changed["schema"] = serde_json::json!(schema);
            let bytes = canonical::canonical_json(&changed).unwrap();
            assert!(
                PacketNativeRestoredSettled17SnapshotPlan::validate(
                    &bytes,
                    bytes.len(),
                    before.capacity()
                )
                .is_err()
            );
        }
        let mut changed = value.clone();
        changed["protocol"][0] = serde_json::json!("source-private.native-before-protocol/14");
        let bytes = canonical::canonical_json(&changed).unwrap();
        assert!(
            PacketNativeRestoredSettled17SnapshotPlan::validate(
                &bytes,
                bytes.len(),
                before.capacity()
            )
            .is_err()
        );
        let mut changed = value;
        changed["endpoint"] = serde_json::json!([]);
        let bytes = canonical::canonical_json(&changed).unwrap();
        assert!(
            PacketNativeRestoredSettled17SnapshotPlan::validate(
                &bytes,
                bytes.len(),
                before.capacity()
            )
            .is_err()
        );

        let mut schema = native_restored_settled17_snapshot_schema().unwrap();
        authenticate_native_restored_settled17_snapshot_schema_data(&schema).unwrap();
        schema.definition.length = U64::new(schema.definition.length.get() + 1);
        assert!(authenticate_native_restored_settled17_snapshot_schema_data(&schema).is_err());
    }

    #[test]
    fn entire_current_definition_reference_is_required_independently_of_source_authority() {
        let current = native_restored_settled17_snapshot_schema()
            .unwrap()
            .definition;
        authenticate_native_restored_settled17_snapshot_definition_data(&current).unwrap();
        for field in 0..5 {
            let mut changed = current.clone();
            match field {
                0 => changed.length = U64::new(changed.length.get() + 1),
                1 => changed.media_type = "application/octet-stream".into(),
                2 => changed.hash.algorithm = "other-256".into(),
                3 => changed.hash.domain = "other.blob.v1".into(),
                4 => changed.hash.digest = "0".repeat(64),
                _ => unreachable!(),
            }
            assert!(
                authenticate_native_restored_settled17_snapshot_definition_data(&changed).is_err()
            );
        }
        let previous_unissued = canonical::content_ref(
            br#"{"schema":"source-private.native-state/17"}"#,
            "application/json",
        )
        .unwrap();
        assert!(
            authenticate_native_restored_settled17_snapshot_definition_data(&previous_unissued)
                .is_err()
        );
        // Full immutable definition correspondence creates no native owner,
        // Source MAC, phase debit or once-action capability.
        let definition: serde_json::Value = serde_json::from_slice(CONTRACT).unwrap();
        assert_eq!(definition["upload_history"]["family"], "capture_upload17");
    }
}
