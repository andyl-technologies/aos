//! Checks the closed current Connection17 boundary and preserves native child spans.
//!
//! Native child semantics belong to the genuine native whole-owner reader. Host
//! controllers have none of those slots. This structural plan does not substitute
//! for that native validation or construct a stream, registrar, deadline or token.

use super::owned11::{OriginalOwned11Fields as Fields, original_owned11_plain_string as plain};
use crate::ProviderError;
use std::mem::size_of;

/// Lends the actual native-only children to their defining whole-owner validator.
#[derive(Clone, Copy)]
pub struct NativeConnection17ChildSpans<'a> {
    /// Contains the installed Prepare input/token custody component, when present.
    pub installed_inputs: Option<&'a [u8]>,
    /// Preserves both independently retained native restoration response slots.
    pub restore_responses: [Option<&'a [u8]>; 2],
    /// Contains the installed Commit/token/mapping component, when present.
    pub complete_restoration: Option<&'a [u8]>,
    /// Contains the actual native ACK admission component, when present.
    pub canonical_ack_admission: Option<&'a [u8]>,
}

/// Borrows a closed Connection17 roster pending defining child validation.
pub struct ConnectionSettledHistory17StructuralPlan<'a> {
    input: &'a [u8],
    authority: &'a [u8],
    correlations: &'a [u8],
    codec: &'a [u8],
    blobs: &'a [u8],
    frames: &'a [u8],
    reader: &'a [u8],
    packet_schema: &'a [u8],
    connected_packet_schema: &'a [u8],
    children: NativeConnection17ChildSpans<'a>,
    native: bool,
}

impl<'a> ConnectionSettledHistory17StructuralPlan<'a> {
    /// Checks the exact current family, roster, role and native child slot extent.
    ///
    /// The input is the canonical component, with strictly ordered object keys.
    /// The native caller must additionally validate every nonempty child against
    /// its actual Boot/Commit/custody/immutable-DAG context before accepting it.
    ///
    /// # Errors
    /// Refuses unknown/missing fields, another family/role or malformed fixed slots.
    pub fn validate(input: &'a [u8]) -> Result<Self, ProviderError> {
        let mut fields = Fields::object(input)?;
        let authority = fields.named("authority")?;
        let blobs = fields.named("blobs")?;
        let canonical_ack_admission = optional(fields.named("canonical_ack_admission")?);
        let codec = fields.named("codec")?;
        let complete_restoration = optional(fields.named("complete_restoration")?);
        let connected_packet_schema = fields.named("connected_packet_schema")?;
        let correlations = fields.named("correlations")?;
        boolean(fields.named("fenced")?)?;
        let frames = fields.named("frames")?;
        let packet_schema = fields.named("packet_schema")?;
        exact(
            fields.named("protocol_owner_role")?,
            "same-current-connection-actor",
        )?;
        let reader = fields.named("reader")?;
        let installed_inputs = optional(fields.named("restore_inputs")?);
        let responses = fields.named("restore_responses")?;
        let mut array = Fields::array(responses)?;
        let restore_responses = [
            optional(array.next()?.ok_or_else(invalid)?),
            optional(array.next()?.ok_or_else(invalid)?),
        ];
        array.finish()?;
        let native = match plain(fields.named("role")?)? {
            "controller" => false,
            "provider" => true,
            _ => return Err(invalid()),
        };
        exact(
            fields.named("schema")?,
            "source-private.connection-restored-settled/17",
        )?;
        exact(
            fields.named("supervisor_role")?,
            if native {
                "actual-native-service-supervisor"
            } else {
                "actual-retained-host-supervisor"
            },
        )?;
        fields.finish()?;
        if codec == b"null" {
            return Err(invalid());
        }
        Ok(Self {
            input,
            authority,
            correlations,
            codec,
            blobs,
            frames,
            reader,
            packet_schema,
            connected_packet_schema,
            children: NativeConnection17ChildSpans {
                installed_inputs,
                restore_responses,
                complete_restoration,
                canonical_ack_admission,
            },
            native,
        })
    }

    /// Requires the Controller branch to contain no native-only live owner slots.
    ///
    /// # Errors
    /// Refuses a native role or any native-only child, including just one response.
    pub fn authenticate_host_branch_data(&self) -> Result<(), ProviderError> {
        let children = self.children;
        if self.native
            || children.installed_inputs.is_some()
            || children.restore_responses.iter().any(Option::is_some)
            || children.complete_restoration.is_some()
            || children.canonical_ack_admission.is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Returns the exact native child spans without asserting their validity.
    pub const fn native_child_spans_data(&self) -> NativeConnection17ChildSpans<'a> {
        self.children
    }

    /// Returns whether the closed role is native; this grants no dispatch right.
    pub const fn is_native_data(&self) -> bool {
        self.native
    }

    /// Returns the exact immutable component bytes.
    pub const fn original_bytes_data(&self) -> &'a [u8] {
        self.input
    }

    /// Lends the actual Authority17, correlation, codec and Blob components.
    pub const fn protocol_parts_data(&self) -> (&'a [u8], &'a [u8], &'a [u8], &'a [u8]) {
        (self.authority, self.correlations, self.codec, self.blobs)
    }

    /// Lends literal-bank, reader, packet schema and connected schema components.
    pub const fn transport_parts_data(&self) -> (&'a [u8], &'a [u8], &'a [u8], &'a [u8]) {
        (
            self.frames,
            self.reader,
            self.packet_schema,
            self.connected_packet_schema,
        )
    }
}

/// Names the exact borrowed structural reader and all its fixed slot/result views.
pub fn current_connection17_counter_scratch_data() -> usize {
    size_of::<ConnectionSettledHistory17StructuralPlan<'static>>()
        + size_of::<Result<ConnectionSettledHistory17StructuralPlan<'static>, ProviderError>>()
        + size_of::<NativeConnection17ChildSpans<'static>>()
        + size_of::<Fields<'static>>() * 2
        + size_of::<Option<&[u8]>>() * 6
        + size_of::<Result<Option<&[u8]>, ProviderError>>()
        + size_of::<Result<&[u8], ProviderError>>()
        + size_of::<Result<&str, ProviderError>>()
        + size_of::<[Option<&[u8]>; 2]>()
        + size_of::<std::slice::Iter<'static, Option<&'static [u8]>>>()
        + size_of::<(&[u8], &[u8], &[u8], &[u8])>() * 2
        + size_of::<Result<(), ProviderError>>()
        + size_of::<bool>()
}

fn optional(input: &[u8]) -> Option<&[u8]> {
    (input != b"null").then_some(input)
}

fn boolean(input: &[u8]) -> Result<(), ProviderError> {
    if matches!(input, b"true" | b"false") {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn exact(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain(input)? == expected {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("current Connection17 structural history differs")
}

/// Checks the logical common Connection17 components after the owning row is admitted.
///
/// This deliberately leaves codec, Blob and native token child semantics to the
/// defining whole-native validator. The Host reader independently requires the
/// Controller codec and empty native-only slots. No live currentness is inferred.
///
/// # Errors
/// Refuses a changed common roster, authority/correlation syntax, invalid literal
/// bank, reader ceilings or role flags. Parser temporaries require caller credit.
pub fn authenticate_current_connection17_common_data(
    value: &serde_json::Value,
) -> Result<(), ProviderError> {
    use super::current_controller17::{boolean, field, invalid, number, object, optional, text};
    let value = object(
        value,
        &[
            "schema",
            "authority",
            "correlations",
            "codec",
            "blobs",
            "restore_inputs",
            "restore_responses",
            "complete_restoration",
            "canonical_ack_admission",
            "frames",
            "reader",
            "packet_schema",
            "connected_packet_schema",
            "fenced",
            "role",
            "protocol_owner_role",
            "supervisor_role",
        ],
    )?;
    text(
        field(value, "schema")?,
        "source-private.connection-restored-settled/17",
    )?;
    text(
        field(value, "protocol_owner_role")?,
        "same-current-connection-actor",
    )?;
    match field(value, "role")?.as_str() {
        Some("controller") => text(
            field(value, "supervisor_role")?,
            "actual-retained-host-supervisor",
        )?,
        Some("provider") => text(
            field(value, "supervisor_role")?,
            "actual-native-service-supervisor",
        )?,
        _ => return Err(invalid()),
    }
    super::current_controller17::authority(field(value, "authority")?)?;
    super::current_transport17::validate_correlations_data(field(value, "correlations")?)?;
    super::current_transport17::validate_frame_bank_data(field(value, "frames")?)?;
    let reader = object(
        field(value, "reader")?,
        &[
            "maximum_bytes",
            "maximum_nesting",
            "failed",
            "last_original_slot",
        ],
    )?;
    let maximum = number(field(reader, "maximum_bytes")?)?;
    let nesting = number(field(reader, "maximum_nesting")?)?;
    if maximum == 0
        || maximum > crate::transport::MAX_FRAME_BYTES as u64
        || nesting == 0
        || nesting > crate::transport::MAX_NESTING as u64
    {
        return Err(invalid());
    }
    boolean(field(reader, "failed")?)?;
    optional(field(reader, "last_original_slot")?, |v| {
        number(v).map(|_| ())
    })?;
    boolean(field(value, "packet_schema")?)?;
    boolean(field(value, "connected_packet_schema")?)?;
    boolean(field(value, "fenced")?)?;
    super::current_controller17::connection_parent_data(value)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use serde_json::{Value, json};

    pub(in crate::protocol_snapshot) fn connection(native: bool) -> Value {
        json!({
            "schema":"source-private.connection-restored-settled/17",
            "authority":{},"correlations":[],"codec":{},"blobs":null,
            "restore_inputs":null,"restore_responses":[null,null],
            "complete_restoration":null,"canonical_ack_admission":null,
            "frames":[],"reader":{},"packet_schema":false,
            "connected_packet_schema":false,"fenced":false,
            "role":if native {"provider"} else {"controller"},
            "protocol_owner_role":"same-current-connection-actor",
            "supervisor_role":if native {"actual-native-service-supervisor"} else {"actual-retained-host-supervisor"},
        })
    }

    #[test]
    fn structural_host_rejects_native_slot_and_native_preserves_exact_child_span() {
        // This is structural DATA, deliberately insufficient for whole-owner acceptance.
        let mut component = connection(false);
        let encoded = serde_json::to_vec(&component).unwrap();
        let plan = ConnectionSettledHistory17StructuralPlan::validate(&encoded).unwrap();
        assert!(plan.authenticate_host_branch_data().is_ok());

        component["restore_responses"][1] = json!({"actual_partial":"retained"});
        let encoded = serde_json::to_vec(&component).unwrap();
        let plan = ConnectionSettledHistory17StructuralPlan::validate(&encoded).unwrap();
        assert!(plan.authenticate_host_branch_data().is_err());
        assert_eq!(
            plan.native_child_spans_data().restore_responses[1],
            Some(b"{\"actual_partial\":\"retained\"}".as_slice())
        );

        component["role"] = json!("provider");
        component["supervisor_role"] = json!("actual-native-service-supervisor");
        let encoded = serde_json::to_vec(&component).unwrap();
        let plan = ConnectionSettledHistory17StructuralPlan::validate(&encoded).unwrap();
        assert!(plan.is_native_data());
        assert!(plan.authenticate_host_branch_data().is_err());
        assert!(plan.native_child_spans_data().restore_responses[1].is_some());
    }
}

/// Checks complete current native codec/Blob fields beside the common Connection.
///
/// Private native token/input/response/Commit children are deliberately returned
/// by the structural plan and require the defining native whole-graph validator.
/// This function constructs no live policy, Blob receiver or dispatch authority.
///
/// # Errors
/// Refuses a nonnative role, invalid common fields, native codec or Blob ledger.
/// Actual canonical/typed parser work must already have independent admission.
pub fn authenticate_current_connection17_native_data(
    value: &serde_json::Value,
) -> Result<(), ProviderError> {
    use super::current_controller17::{field, invalid, text};
    authenticate_current_connection17_common_data(value)?;
    let value = value.as_object().ok_or_else(invalid)?;
    text(field(value, "role")?, "provider")?;
    super::current_native_connection17::validate_native_codec_data(field(value, "codec")?)?;
    super::current_native_connection17::validate_blob_ledger_data(field(value, "blobs")?)
}

/// Checks the complete logical Blob ledger also used by retained quarantines.
///
/// This accepts the defining ledger component, not a whole old11 state, and
/// creates no receiver, token or dispatch permission. The native outer owner
/// separately binds the real session, limits, supervisor and shared groups.
///
/// # Errors
/// Refuses malformed records, content hashes, pins, tombstones or accounting.
/// The defining current Connection17 transient/counter rows must be admitted.
pub fn authenticate_current_blob_ledger17_data(
    value: &serde_json::Value,
) -> Result<(), ProviderError> {
    super::current_native_connection17::validate_blob_ledger_data(value)
}
