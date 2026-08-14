//! Node-fault payload errors and generated C ABI declarations.

use super::*;

/// Failure to encode or decode a typed node-fault payload.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum NodeFaultPayloadError {
    /// The payload length or one nested length is invalid.
    #[error("invalid typed node-fault payload length")]
    Length,
    /// Version or reserved bytes are invalid.
    #[error("invalid typed node-fault version or reserved bytes")]
    VersionOrReserved,
    /// The command kind is not a typed node-rule command.
    #[error("unsupported typed node-fault command kind {0}")]
    CommandKind(u16),
    /// The operation tag is unknown.
    #[error("unknown typed node-fault operation {0}")]
    Operation(u16),
    /// The target-kind tag is unknown.
    #[error("unknown typed node-fault target kind {0}")]
    TargetKind(u16),
    /// One required header value is zero or otherwise invalid.
    #[error("invalid typed node-fault header value")]
    HeaderValue,
    /// Too many or too few fields were supplied.
    #[error("invalid typed node-fault field count")]
    FieldCount,
    /// A field has tag zero.
    #[error("typed node-fault field tag must be nonzero")]
    FieldTag,
    /// Field tags are not strictly increasing.
    #[error("typed node-fault fields are not in canonical tag order")]
    FieldOrder,
    /// The field type tag is unknown.
    #[error("unknown typed node-fault field type {0}")]
    FieldType(u16),
    /// One field value is not canonical for its declared type.
    #[error("invalid typed node-fault value for field {tag}")]
    FieldValue {
        /// Field tag whose encoded value failed validation.
        tag: u16,
    },
    /// A removal command carried mutation parameters.
    #[error("typed node-fault removal must not carry fields")]
    RemoveFields,
    /// Fields do not exactly match the selected command and target schema.
    #[error("typed node-fault fields do not match command schema {command_kind}")]
    Schema {
        /// Numeric command kind whose schema was violated.
        command_kind: u16,
    },
    /// The command cannot operate on the supplied target category.
    #[error("typed node-fault command {command_kind} cannot target kind {target_kind}")]
    TargetSchema {
        /// Numeric command kind.
        command_kind: u16,
        /// Numeric target kind.
        target_kind: u16,
    },
    /// Resolved target coordinates conflict with effect coordinates.
    #[error("typed node-fault effect conflicts with its resolved target")]
    TargetValue,
    /// A closed policy field is not framed canonical JSON.
    #[error("typed node-fault policy field {tag} is not canonical CRUCJSN1 JSON")]
    PolicyJson {
        /// Invalid policy field tag.
        tag: u16,
    },
}

pub(crate) fn emit_fault_node_c_header(out: &mut String) {
    let _ = writeln!(
        out,
        "#define CRUCIBLE_NODE_FAULT_PAYLOAD_VERSION_V1 {NODE_FAULT_PAYLOAD_VERSION_V1}u"
    );
    let _ = writeln!(
        out,
        "#define CRUCIBLE_NODE_FAULT_PAYLOAD_HEADER_V1_BYTES {NODE_FAULT_PAYLOAD_HEADER_V1_BYTES}u"
    );
    let _ = writeln!(
        out,
        "#define CRUCIBLE_NODE_FAULT_FIELD_HEADER_V1_BYTES {NODE_FAULT_FIELD_HEADER_V1_BYTES}u"
    );
    let _ = writeln!(
        out,
        "#define CRUCIBLE_NODE_FAULT_EVIDENCE_V1_BYTES {NODE_FAULT_EVIDENCE_V1_BYTES}u"
    );
    let _ = writeln!(
        out,
        "#define CRUCIBLE_NODE_FAULT_MAX_FIELDS_V1 {NODE_FAULT_MAX_FIELDS_V1}u"
    );
    let _ = writeln!(
        out,
        "#define CRUCIBLE_NODE_FAULT_POLICY_JSON_MAGIC_V1 \"CRUCJSN1\""
    );
    let _ = writeln!(
        out,
        "#define CRUCIBLE_NODE_FAULT_POLICY_JSON_MAGIC_V1_BYTES 8u"
    );
    for (name, value) in [
        ("UPSERT", NodeFaultOperationV1::Upsert as u16),
        ("REMOVE", NodeFaultOperationV1::Remove as u16),
        ("APPLY", NodeFaultOperationV1::Apply as u16),
    ] {
        let _ = writeln!(out, "#define CRUCIBLE_NODE_FAULT_OPERATION_{name} {value}u");
    }
    for (name, value) in [
        ("NODE", NodeFaultTargetKindV1::Node as u16),
        ("VCPU", NodeFaultTargetKindV1::Vcpu as u16),
        ("REGISTER", NodeFaultTargetKindV1::Register as u16),
        ("MEMORY", NodeFaultTargetKindV1::Memory as u16),
        ("INTERRUPT", NodeFaultTargetKindV1::Interrupt as u16),
        ("CLOCK", NodeFaultTargetKindV1::Clock as u16),
        ("ACCELERATOR", NodeFaultTargetKindV1::Accelerator as u16),
    ] {
        let _ = writeln!(out, "#define CRUCIBLE_NODE_FAULT_TARGET_{name} {value}u");
    }
    for (name, value) in [
        ("U32", NodeFaultFieldTypeV1::U32 as u16),
        ("U64", NodeFaultFieldTypeV1::U64 as u16),
        ("I64", NodeFaultFieldTypeV1::I64 as u16),
        ("BOOL", NodeFaultFieldTypeV1::Bool as u16),
        ("RATIO", NodeFaultFieldTypeV1::Ratio as u16),
        ("HASH", NodeFaultFieldTypeV1::Hash as u16),
        ("BYTES", NodeFaultFieldTypeV1::Bytes as u16),
        ("HASH_SET", NodeFaultFieldTypeV1::HashSet as u16),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_NODE_FAULT_FIELD_TYPE_{name} {value}u"
        );
    }
    for (name, value) in [
        ("P1", node_fault_field::P1),
        ("P2", node_fault_field::P2),
        ("P3", node_fault_field::P3),
        ("P4", node_fault_field::P4),
        ("P5", node_fault_field::P5),
        ("P6", node_fault_field::P6),
        ("P7", node_fault_field::P7),
        ("P8", node_fault_field::P8),
        ("P9", node_fault_field::P9),
        ("P10", node_fault_field::P10),
        ("P11", node_fault_field::P11),
        ("T1", node_fault_field::T1),
        ("T2", node_fault_field::T2),
        ("T3", node_fault_field::T3),
        ("T4", node_fault_field::T4),
        ("T5", node_fault_field::T5),
    ] {
        let _ = writeln!(out, "#define CRUCIBLE_NODE_FAULT_FIELD_{name} {value}u");
    }
    for (name, value) in [
        ("MAGIC", 0),
        ("VERSION", 8),
        ("COMMAND_KIND", 10),
        ("OPERATION", 12),
        ("TARGET_KIND", 14),
        ("MODEL_PHASE", 16),
        ("RESERVED", 18),
        ("GENERATION", 20),
        ("ACTION_HASH", 28),
        ("TARGET_HASH", 60),
        ("SCHEMA_HASH", 92),
        ("FIELD_COUNT", 124),
        ("TRAILING_RESERVED", 126),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_NODE_FAULT_PAYLOAD_{name}_OFFSET {value}u"
        );
    }
    for (name, value) in [("TAG", 0), ("TYPE", 2), ("LENGTH", 4)] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_NODE_FAULT_FIELD_{name}_OFFSET {value}u"
        );
    }
    for (name, value) in [
        ("MAGIC", 0),
        ("VERSION", 8),
        ("COMMAND_KIND", 10),
        ("OPERATION", 12),
        ("TARGET_KIND", 14),
        ("MODEL_PHASE", 16),
        ("RESERVED", 18),
        ("GENERATION", 20),
        ("PRIOR_GENERATION", 28),
        ("ACTION_HASH", 36),
        ("TARGET_HASH", 68),
        ("SCHEMA_HASH", 100),
        ("REQUEST_SHA256", 132),
        ("BEFORE_SHA256", 164),
        ("AFTER_SHA256", 196),
    ] {
        let _ = writeln!(
            out,
            "#define CRUCIBLE_NODE_FAULT_EVIDENCE_{name}_OFFSET {value}u"
        );
    }
}
