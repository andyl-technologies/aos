//! Preserves exact native-before protocol bytes in a selected snapshot edition.
//!
//! ```text
//! {"capture":{},"capture_request":{},"control":{},"control_reference":{},
//!  "endpoint":[],"protocol":["source-private.native-before-protocol/11",
//!  {"hash":{},"length":"1","media_type":"application/json"},8,
//!  ["source-private.compact-bytes/7",1,["AA=="]]],
//!  "schema":"source-owned.packet-native-continuation/11"}
//! ```
//!
//! The borrowed plan checks framing and byte correspondence. Full typed native
//! protocol, endpoint history, Control/model transition and source authority
//! remain independent conjuncts. No decoded plan installs a live owner.

use crate::ProviderError;
use crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes;
use crate::protocol_snapshot::owned11::{
    OriginalOwned11Fields as Fields, original_owned11_plain_string as plain_string,
    original_owned11_unsigned as unsigned,
};
use crucible_node_contract::{Id, SchemaRef, canonical};

/// Names the defining fixed snapshot schema for internal construction accounting.
pub(crate) const SCHEMA: &str = "source-owned.packet-native-continuation/11";
const BEFORE_TAG: &str = "source-private.native-before-protocol/11";

#[path = "native_snapshot/owned11_contract_value.rs"]
mod owned11_contract_value;
pub(crate) use owned11_contract_value::native_owned11_snapshot_contract_storage_data;

/// Returns the complete definition for the selected raw-before snapshot edition.
///
/// # Errors
/// Reports canonical definition encoding failure.
pub fn native_owned11_snapshot_contract() -> Result<Vec<u8>, ProviderError> {
    Ok(canonical::canonical_json(
        &serde_json::to_value(owned11_contract_value::NativeOwned11SnapshotContractValue)
            .map_err(crucible_node_contract::ContractError::from)?,
    )?)
}

/// Returns the full immutable selected snapshot schema reference.
///
/// # Errors
/// Reports invalid schema identifier or definition encoding failure.
pub fn native_owned11_snapshot_schema() -> Result<SchemaRef, ProviderError> {
    Ok(SchemaRef {
        id: Id::new(SCHEMA)?,
        version: 11,
        definition: canonical::content_ref(
            &native_owned11_snapshot_contract()?,
            "application/json",
        )?,
        extensions: Default::default(),
    })
}

/// Borrows the exact seven-field outer snapshot and fourteen-field endpoint.
///
/// Private slices preserve input encoding. This plan neither allocates decoded
/// protocol storage nor claims full endpoint semantic validation.
pub struct PacketNativeOwned11SnapshotPlan<'a> {
    capture: &'a [u8],
    capture_request: &'a [u8],
    control: &'a [u8],
    control_reference: &'a [u8],
    endpoint: PacketNativeOwned11EndpointPlan<'a>,
    before: PacketNativeBeforeProtocolPlan<'a>,
}

impl<'a> PacketNativeOwned11SnapshotPlan<'a> {
    /// Checks exact selected outer framing and the complete raw-before identity.
    ///
    /// This pass uses fixed stack scratch only. Callers must independently admit
    /// typed decoding and full native/endpoint/Control semantic validation.
    ///
    /// # Errors
    /// Refuses wrong field order/edition, missing or extra fields, exceeded input
    /// or original-capacity bounds, malformed endpoint framing or changed bytes.
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
        let endpoint = PacketNativeOwned11EndpointPlan::validate(fields.named("endpoint")?)?;
        let before = PacketNativeBeforeProtocolPlan::validate(
            fields.named("protocol")?,
            maximum_input,
            maximum_before_capacity,
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
        Ok(Self {
            capture,
            capture_request,
            control,
            control_reference,
            endpoint,
            before,
        })
    }

    /// Borrows the complete original Capture arguments.
    pub fn capture_arguments_bytes(&self) -> &'a [u8] {
        self.capture
    }
    /// Borrows the complete original Capture request.
    pub fn capture_request_bytes(&self) -> &'a [u8] {
        self.capture_request
    }
    /// Borrows the exact embedded canonical Control snapshot.
    pub fn control_bytes(&self) -> &'a [u8] {
        self.control
    }
    /// Borrows the complete embedded Control reference.
    pub fn control_reference_bytes(&self) -> &'a [u8] {
        self.control_reference
    }
    /// Borrows the strict endpoint field plan for full historical validation.
    pub fn endpoint(&self) -> &PacketNativeOwned11EndpointPlan<'a> {
        &self.endpoint
    }
    /// Borrows the validated exact original native-before byte plan.
    pub fn before(&self) -> &PacketNativeBeforeProtocolPlan<'a> {
        &self.before
    }
}

/// Borrows every actual endpoint field without constructing a replacement state.
pub struct PacketNativeOwned11EndpointPlan<'a> {
    fields: [&'a [u8]; 13],
}

impl<'a> PacketNativeOwned11EndpointPlan<'a> {
    fn validate(input: &'a [u8]) -> Result<Self, ProviderError> {
        let mut tuple = Fields::array(input)?;
        let value =
            Self::read_original_fields(&mut tuple, "source-owned.packet-native-endpoint-state/11")?;
        tuple.finish()?;
        Ok(value)
    }

    fn read_original_fields(tuple: &mut Fields<'a>, tag: &str) -> Result<Self, ProviderError> {
        Self::read_original_fields_at_context(
            tuple,
            tag,
            "same-original-native-protocol-service-context/11",
        )
    }

    fn read_original_fields_at_context(
        tuple: &mut Fields<'a>,
        tag: &str,
        context: &str,
    ) -> Result<Self, ProviderError> {
        if plain_string(required(tuple)?)? != tag {
            return Err(invalid());
        }
        let mut fields = [&[][..]; 13];
        for field in &mut fields {
            *field = required(tuple)?;
        }
        if plain_string(fields[5])? != context || fields[12] != b"true" {
            return Err(invalid());
        }
        for (index, capacity_index) in [(6, 7), (8, 9)] {
            let capacity = unsigned(fields[capacity_index])?;
            if capacity > super::super::endpoint::EXCHANGES as u64 {
                return Err(invalid());
            }
            let mut entries = Fields::array(fields[index])?;
            let mut count = 0u64;
            while entries.next()?.is_some() {
                count = count.checked_add(1).ok_or_else(invalid)?;
                if count > capacity {
                    return Err(invalid());
                }
            }
            entries.finish()?;
        }
        unsigned(fields[10])?;
        if unsigned(fields[11])? > super::super::endpoint::MAXIMUM_PACKET_TRANSPORT_BYTES as u64 {
            return Err(invalid());
        }
        Ok(Self { fields })
    }

    /// Borrows the selected storage limits.
    pub fn storage_bytes(&self) -> &'a [u8] {
        self.fields[0]
    }
    /// Borrows the selected capture profile.
    pub fn profile_bytes(&self) -> &'a [u8] {
        self.fields[1]
    }
    /// Borrows the independently selected native metadata row limits.
    pub fn metadata_limits_bytes(&self) -> &'a [u8] {
        self.fields[2]
    }
    /// Borrows the actual born record and alias allocation facts.
    pub fn metadata_birth_facts_bytes(&self) -> &'a [u8] {
        self.fields[3]
    }
    /// Borrows the full original Hello state and literal bank.
    pub fn hello_bytes(&self) -> &'a [u8] {
        self.fields[4]
    }
    /// Borrows the complete retained exchange records.
    pub fn records_bytes(&self) -> &'a [u8] {
        self.fields[6]
    }
    /// Borrows the complete retained pin roster.
    pub fn pins_bytes(&self) -> &'a [u8] {
        self.fields[8]
    }
    /// Returns the actual endpoint counter preceding the Capture prefix.
    ///
    /// # Errors
    /// Reports inconsistent unsigned data framing.
    pub fn next_sequence_data(&self) -> Result<u64, ProviderError> {
        unsigned(self.fields[10])
    }
    /// Borrows every endpoint field in its original tuple order, excluding tag.
    pub fn fields(&self) -> &[&'a [u8]; 13] {
        &self.fields
    }
}

/// Borrows exact before bytes with their original full reference and capacity.
pub struct PacketNativeBeforeProtocolPlan<'a> {
    reference: &'a [u8],
    capacity: usize,
    bytes: ValidatedCompactBytes<'a>,
}

impl<'a> PacketNativeBeforeProtocolPlan<'a> {
    fn validate(
        input: &'a [u8],
        maximum_input: usize,
        maximum_capacity: usize,
    ) -> Result<Self, ProviderError> {
        Self::validate_edition(input, maximum_input, maximum_capacity, BEFORE_TAG)
    }

    fn validate_edition(
        input: &'a [u8],
        maximum_input: usize,
        maximum_capacity: usize,
        tag: &str,
    ) -> Result<Self, ProviderError> {
        let mut tuple = Fields::array(input)?;
        if plain_string(required(&mut tuple)?)? != tag {
            return Err(invalid());
        }
        let reference = required(&mut tuple)?;
        let capacity = usize::try_from(unsigned(required(&mut tuple)?)?).map_err(|_| invalid())?;
        if capacity > maximum_capacity {
            return Err(invalid());
        }
        let bytes =
            ValidatedCompactBytes::validate(required(&mut tuple)?, maximum_input, capacity)?;
        tuple.finish()?;
        let (_, digest) = blob_reference(reference, bytes.decoded_length())?;
        let mut hasher = blob_hasher(bytes.decoded_length())?;
        let mut scratch = [0u8; 3072];
        for offset in (0..bytes.decoded_length()).step_by(scratch.len()) {
            let length = scratch.len().min(bytes.decoded_length() - offset);
            bytes.copy_range(offset, &mut scratch[..length])?;
            hasher.update(&scratch[..length]);
        }
        if hasher.finalize().to_hex().as_str() != digest {
            return Err(invalid());
        }
        Ok(Self {
            reference,
            capacity,
            bytes,
        })
    }

    /// Borrows the original full ContentRef encoding.
    pub fn reference_bytes(&self) -> &'a [u8] {
        self.reference
    }
    /// Returns the actual original encoded Vec capacity, including spare bytes.
    pub fn original_capacity(&self) -> usize {
        self.capacity
    }
    /// Returns the exact used original encoded extent.
    pub fn encoded_length(&self) -> usize {
        self.bytes.decoded_length()
    }

    /// Fills the same independently precharged empty encoded bank.
    ///
    /// # Errors
    /// Refuses a different actual capacity or nonempty destination before writes.
    /// Partial bytes remain in the caller's bank if a later fill refuses.
    pub fn fill_preowned(&self, destination: &mut Vec<u8>) -> Result<(), ProviderError> {
        if destination.capacity() != self.capacity {
            return Err(invalid());
        }
        self.bytes.fill_preowned(destination)
    }

    /// Checks full equality against an independently retained exact byte body.
    ///
    /// # Errors
    /// Refuses any length or literal difference without canonicalizing the body.
    pub fn authenticate_original_bytes(&self, original: &[u8]) -> Result<(), ProviderError> {
        if original.len() != self.encoded_length() {
            return Err(invalid());
        }
        let mut scratch = [0u8; 3072];
        for (index, chunk) in original.chunks(scratch.len()).enumerate() {
            self.bytes
                .copy_range(index * scratch.len(), &mut scratch[..chunk.len()])?;
            if chunk != &scratch[..chunk.len()] {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

fn required<'a>(fields: &mut Fields<'a>) -> Result<&'a [u8], ProviderError> {
    fields.next()?.ok_or_else(invalid)
}

fn blob_reference(input: &[u8], length: usize) -> Result<(&[u8], &str), ProviderError> {
    let mut reference = Fields::object(input)?;
    let hash_bytes = reference.named("hash")?;
    let mut hash = Fields::object(hash_bytes)?;
    if plain_string(hash.named("algorithm")?)? != "blake3-256" {
        return Err(invalid());
    }
    let digest = plain_string(hash.named("digest")?)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || plain_string(hash.named("domain")?)? != "cnp.blob.v1"
    {
        return Err(invalid());
    }
    hash.finish()?;
    if unsigned(plain_string(reference.named("length")?)?.as_bytes())?
        != u64::try_from(length).map_err(|_| invalid())?
        || plain_string(reference.named("media_type")?)? != "application/json"
    {
        return Err(invalid());
    }
    reference.finish()?;
    Ok((hash_bytes, digest))
}

fn blob_hasher(length: usize) -> Result<blake3::Hasher, ProviderError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&("cnp.blob.v1".len() as u32).to_be_bytes());
    hasher.update(b"cnp.blob.v1");
    hasher.update(&u64::try_from(length).map_err(|_| invalid())?.to_be_bytes());
    Ok(hasher)
}

fn authenticate_blob(reference: &[u8], bytes: &[u8]) -> Result<(), ProviderError> {
    let (_, digest) = blob_reference(reference, bytes.len())?;
    let mut hasher = blob_hasher(bytes.len())?;
    hasher.update(bytes);
    if hasher.finalize().to_hex().as_str() != digest {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("native owned11 snapshot literal closure")
}

/// Reports named actual headers and declared scratch of the borrowed parser.
///
/// These are requested-layout data, not a measurement or upper bound of compiler
/// frames, allocator rounding or the complete factory/cold-owner peak. The plan
/// contains its endpoint and before headers; those informational sublayouts must
/// not be added again to its root header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketNativeOwned11SnapshotValidationLayouts {
    /// Sizes the actual borrowed root plan, including both child headers.
    pub plan_header_bytes: usize,
    /// Reports the actual root plan alignment.
    pub plan_header_alignment: usize,
    /// Sizes the contained endpoint header for independent layout inspection.
    pub endpoint_header_bytes: usize,
    /// Sizes the contained raw-before header for independent layout inspection.
    pub before_header_bytes: usize,
    /// Sizes the actual borrowed SDK Fields cursor.
    pub field_cursor_bytes: usize,
    /// Reports the maximum named coexisting Fields cursors in this parser.
    pub maximum_simultaneous_field_cursors: usize,
    /// Retains the source-pinned SDK Fields::span declared nesting array.
    pub field_scan_declared_array_bytes: usize,
    /// Retains the exact declared raw byte chunk used for hashing/comparison.
    pub raw_chunk_array_bytes: usize,
    /// Sizes the actual streaming BLAKE3 hasher payload.
    pub streaming_hash_header_bytes: usize,
    /// Sizes the actual final hash plus its fixed hexadecimal output wrapper.
    pub streaming_hash_output_bytes: usize,
    /// Sizes the actual SDK compact-byte borrowed validation plan.
    pub compact_plan_header_bytes: usize,
}

/// Returns actual parser layouts independently of any captured input or permit.
///
/// The 128-byte span array is pinned to the SDK Fields implementation consumed
/// by this selected edition; changing that implementation requires reconciling
/// this quote. Typed native protocol, Control/model, JSON DOM/canonical buffers,
/// decoded raw bank capacity and complete factory scratch remain separate.
pub fn packet_native_owned11_snapshot_validation_layouts()
-> PacketNativeOwned11SnapshotValidationLayouts {
    let hash = blake3::hash(&[]);
    let hexadecimal = hash.to_hex();
    PacketNativeOwned11SnapshotValidationLayouts {
        plan_header_bytes: std::mem::size_of::<PacketNativeOwned11SnapshotPlan<'static>>(),
        plan_header_alignment: std::mem::align_of::<PacketNativeOwned11SnapshotPlan<'static>>(),
        endpoint_header_bytes: std::mem::size_of::<PacketNativeOwned11EndpointPlan<'static>>(),
        before_header_bytes: std::mem::size_of::<PacketNativeBeforeProtocolPlan<'static>>(),
        field_cursor_bytes: std::mem::size_of::<Fields<'static>>(),
        maximum_simultaneous_field_cursors: 4,
        field_scan_declared_array_bytes: std::mem::size_of::<[u8; 128]>(),
        raw_chunk_array_bytes: std::mem::size_of::<[u8; 3072]>(),
        streaming_hash_header_bytes: std::mem::size_of::<blake3::Hasher>(),
        streaming_hash_output_bytes: std::mem::size_of_val(&hash)
            + std::mem::size_of_val(&hexadecimal),
        compact_plan_header_bytes: std::mem::size_of::<ValidatedCompactBytes<'static>>(),
    }
}

mod capture_allocation;
pub use capture_allocation::{
    PacketNativeOwned12SnapshotPlan, native_owned12_snapshot_contract,
    native_owned12_snapshot_schema, packet_native_owned12_snapshot_validation_layouts,
};

mod startup_capture_allocation;
pub use startup_capture_allocation::{
    PacketNativeOwned13SnapshotPlan, native_owned13_snapshot_contract,
    native_owned13_snapshot_schema, packet_native_owned13_snapshot_validation_layouts,
};

pub(crate) use startup_capture_allocation::{
    authenticate_native_owned13_snapshot_schema_data,
    native_owned13_snapshot_schema_counter_scratch_data,
};

mod invocation_capture;

pub use invocation_capture::{
    PacketNativeOwned14SnapshotPlan, native_owned14_snapshot_contract,
    native_owned14_snapshot_schema, packet_native_owned14_snapshot_validation_layouts,
};

pub use invocation_capture::{
    authenticate_native_owned14_snapshot_schema_data,
    native_owned14_snapshot_schema_counter_scratch_data,
};

mod restored_settled;
pub use restored_settled::{
    PacketNativeRestoredSettled17SnapshotPlan,
    authenticate_native_restored_settled17_snapshot_schema_data,
    native_restored_settled17_snapshot_contract_data,
    native_restored_settled17_snapshot_counter_scratch_data,
    native_restored_settled17_snapshot_schema,
    native_restored_settled17_snapshot_schema_counter_scratch_data,
};
