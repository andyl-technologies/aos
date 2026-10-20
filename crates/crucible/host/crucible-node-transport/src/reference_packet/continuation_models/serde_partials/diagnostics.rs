//! Names fixed typed-decoder diagnostic literals from the actual Control DAG.
//!
//! This is a text-extent component, not an error heap row. Unknown input text,
//! numeric/location displays, parser syntax messages, message growth, ErrorImpl
//! and outer error wrapping are independently admitted by the real caller.

use super::*;

pub(super) trait ScalarDiagnosticNames {
    const BYTES: usize;
}

pub(super) const fn scalar_name_bytes_data<T: ScalarDiagnosticNames>() -> usize {
    T::BYTES
}

macro_rules! primitive_names {
    ($($type:ty),+ $(,)?) => {
        $(
            impl ScalarDiagnosticNames for $type {
                const BYTES: usize = 0;
            }
        )+
    };
}

primitive_names!(bool, u8, u16, u32, u64, usize, i64, String, Phase);

macro_rules! unit_names {
    ($type:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        impl ScalarDiagnosticNames for $type {
            const BYTES: usize = stringify!($type).len()
                $(+ $wire.len() + "``".len() + ", ".len())+;
        }

        const _: fn(&$type) = |value| match value {
            $($type::$variant => {},)+
        };
    };
}

unit_names!(Direction {
    Input => "input",
    Output => "output",
});

unit_names!(OperatingMode {
    Exact => "exact",
    Quantized => "quantized",
});

unit_names!(SchedulingRole {
    Active => "active",
    EventDriven => "event_driven",
    Autonomous => "autonomous",
});

unit_names!(Repeatability {
    Qualified => "qualified",
    Nondeterministic => "nondeterministic",
    Unqualified => "unqualified",
});

unit_names!(CaptureScope {
    CompleteModel => "complete_model",
    Architectural => "architectural",
    None => "none",
});

unit_names!(Continuation {
    Exact => "exact",
    BestEffort => "best_effort",
    Unsupported => "unsupported",
});

unit_names!(BoundaryPolicy {
    OrdinaryStop => "ordinary_stop",
    InputBlockedPark => "input_blocked_park",
});

unit_names!(BeginKind {
    ExactRun => "exact_run",
    BoundarySettle => "boundary_settle",
    QuantumBegin => "quantum_begin",
    Pause => "pause",
    Capture => "capture",
    PrepareRestore => "prepare_restore",
    Shutdown => "shutdown",
});

unit_names!(OperationState {
    NotStarted => "not_started",
    Running => "running",
    Completed => "completed",
    Unknown => "unknown",
});

unit_names!(EffectCertainty {
    NotStarted => "not_started",
    InProgress => "in_progress",
    Completed => "completed",
    Unknown => "unknown",
});

unit_names!(PacketNative5ConfirmationSelection {
    AfterProtocolPoll5 => "after_protocol_poll5",
});

unit_names!(PacketNative5AckEmitterSelection {
    CanonicalSdkBlob5 => "canonical_sdk_blob5",
});

unit_names!(PacketNative5CompleteRestoreSelection {
    SourceSignedOwned11 => "SourceSignedOwned11",
    SourceSignedTransfer12 => "SourceSignedTransfer12",
});

unit_names!(PacketNative5RestoreInputEmitterSelection {
    CanonicalSdkRestoreInputs12 => "CanonicalSdkRestoreInputs12",
});

unit_names!(PacketNative5CaptureAllocationSelection {
    OriginalObserve12 => "original_observe12",
});

unit_names!(PacketModelKind {
    Producer => "producer",
    Reactive => "reactive",
});

pub(super) const fn model_kind_name_bytes_data() -> usize {
    <PacketModelKind as ScalarDiagnosticNames>::BYTES
}

// Pinned serde_core1.0.228 de::Error/OneOf/Unexpected and derived visitor
// fragments, serde1.0.228 Content adapters, and serde_json1.0.150 Value/Number
// visitors. Placeholders add harmless literal bytes; dynamic replacements are
// deliberately separate. Error invalid_type/value uses JsonUnexpected, whose
// float branch is zmij rather than std's potentially long f64 Display.
const SERDE_FORMAT_LITERALS: &[&str] = &[
    "invalid type: {}, expected {}",
    "invalid value: {}, expected {}",
    "invalid length {}, expected {}",
    "unknown variant `{}`, there are no variants",
    "unknown variant `{}`, expected {}",
    "unknown field `{}`, there are no fields",
    "unknown field `{}`, expected {}",
    "missing field `{}`",
    "duplicate field `{}`",
    "one of ",
    " or ",
    "boolean `{}`",
    "integer `{}`",
    "floating point `{}`",
    "character `{}`",
    "string {:?}",
    "byte array",
    "null",
    "unit value",
    "Option value",
    "newtype struct",
    "sequence",
    "map",
    "enum",
    "unit variant",
    "newtype variant",
    "tuple variant",
    "struct variant",
    "struct ",
    "struct variant ",
    "::",
    " with ",
    " elements",
    "tuple ",
    "tuple struct ",
    "field identifier",
    "variant identifier",
    "a string",
    "a string key",
    "a byte array",
    "a boolean",
    "a sequence",
    "a map",
    "a JSON number",
    "u8",
    "u16",
    "u32",
    "u64",
    "usize",
    "i64",
    "any value",
    "any valid JSON value",
    "a type tag `{}` or any other value",
    "internally tagged enum ",
    "string or map",
    "fewer elements in map",
    "fewer elements in array",
    "fewer elements in sequence",
    "1 element in sequence",
    "1 element in map",
    "value is missing",
];

// Actual custom Id/U64/Version/Phase Deserialize errors, not general validation
// messages. ContractError's dynamic field/reason framing is kept by the caller.
const CONTRACT_DECODE_LITERALS: &[&str] = &[
    "id",
    "expected 1–128 bounded ASCII identifier bytes",
    "U64",
    "expected canonical decimal string",
    "integer outside declared range",
    "expected a JSON integer from 0 through 65535",
    "unsupported superdense phase",
];

pub(super) const fn format_literal_bytes_data() -> usize {
    let mut bytes = 0usize;
    let mut index = 0usize;
    while index < SERDE_FORMAT_LITERALS.len() {
        bytes += SERDE_FORMAT_LITERALS[index].len();
        index += 1;
    }
    index = 0;
    while index < CONTRACT_DECODE_LITERALS.len() {
        bytes += CONTRACT_DECODE_LITERALS[index].len();
        index += 1;
    }
    bytes
}

/// Names the actual schema Version field handler's additional fixed controls.
pub(super) fn version_field_counter_scratch_data() -> usize {
    use std::mem::size_of;

    // values.rs::deserialize_version retains the owned Number, tries as_u64,
    // then as_f64 + borrowed RyuJS output + parse::<u16>. The defining canonical
    // number counter already names real RyuJS Buffer and Option<f64> controls;
    // this handler additionally names its own Number/return/integer states.
    // NumberVisitor and the noncapturing invalid closure are zero-sized. There
    // is no formatter String allocation in this actual field handler.
    canonical::canonical_number_counter_scratch_bytes_data()
        + size_of::<serde_json::Number>()
        + size_of::<Result<serde_json::Number, serde_json::Error>>()
        + size_of::<Value>()
        + size_of::<Option<u64>>()
        + size_of::<u64>()
        + size_of::<u16>()
        + size_of::<&str>()
        + size_of::<Result<u16, std::num::TryFromIntError>>()
        + size_of::<Result<u16, std::num::ParseIntError>>()
        + size_of::<Result<u16, serde_json::Error>>()
}

/// Bounds one actual pinned serde_json ErrorImpl Box request by its fields.
pub(super) const fn error_impl_allocation_upper_bytes_data() -> usize {
    use std::mem::{align_of, size_of};

    // error.rs230: ErrorImpl={code:ErrorCode,line:usize,column:usize}.
    // ErrorCode has Message(Box<str>), Io(io::Error), and unit alternatives.
    // A usize dominates the finite enum tag; each actual payload/tag boundary
    // and enum tail may pad by at most alignment-1. No pointer header is used
    // as a substitute for the allocation behind Error.err:Box<ErrorImpl>.
    let payload = if size_of::<Box<str>>() > size_of::<std::io::Error>() {
        size_of::<Box<str>>()
    } else {
        size_of::<std::io::Error>()
    };
    let mut alignment = align_of::<Box<str>>();
    if align_of::<std::io::Error>() > alignment {
        alignment = align_of::<std::io::Error>();
    }
    if align_of::<usize>() > alignment {
        alignment = align_of::<usize>();
    }
    let code = payload + size_of::<usize>() + 2 * (alignment - 1);

    // Three actual struct fields have two interior boundaries and a tail.
    // Inner and outer Errors own separate allocations; the caller prices each.
    code + 2 * size_of::<usize>() + 3 * (alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::control::PacketDecodedCaptureFutureControlData;
    use serde::{Deserialize, de::DeserializeSeed};

    fn assert_message_text_bound<T: serde::de::DeserializeOwned>(source: Value) -> String {
        let before = serde_json::to_vec(&source).unwrap();
        let error = serde_json::from_value::<T>(source.clone()).err().unwrap();
        let message = error.to_string();
        let fixed =
            PacketDecodedCaptureFutureControlData::decoder_diagnostic_static_text_bytes_data();
        // Independent actual input Debug escaping, plus one each i64/u64,
        // zmij Float, collection length and line/column decimal display bank.
        let scalar_and_location = 21 + 20 + 24 + 20 + 20 + 20;
        assert!(message.len() <= 6 * before.len() + fixed + scalar_and_location);
        assert_eq!(serde_json::to_vec(&source).unwrap(), before);
        message
    }

    #[test]
    fn actual_missing_unknown_and_variant_diagnostics_fit_closed_names() {
        assert_message_text_bound::<SemanticVersion>(serde_json::json!({}));
        let changed = "unexpected".repeat(512);
        let unknown = assert_message_text_bound::<SemanticVersion>(serde_json::json!({
            "major":"0", "minor":"0", "patch":"0", "prerelease":null,
            "build":null, (changed): null,
        }));
        assert!(unknown.contains("unknown field"));

        let profile = assert_message_text_bound::<PacketNative5CaptureProfile>(
            serde_json::json!({"encoding":"foreign"}),
        );
        for expected in ["original_arrays6", "compact_bytes7", "owned_protocol11"] {
            assert!(profile.contains(expected));
        }
        let selected = assert_message_text_bound::<PacketNative5RestoreInputEmitterSelection>(
            Value::String("foreign".into()),
        );
        // This actual enum has no rename_all attribute: preserve its wire label.
        assert!(selected.contains("CanonicalSdkRestoreInputs12"));
    }

    #[test]
    fn actual_content_float_failure_uses_jsonunexpected_zmij_override() {
        use serde::__private228::de::{ContentDeserializer, ContentVisitor};

        let number: Value = serde_json::from_str("1e-300").unwrap();
        let content = ContentVisitor::new().deserialize(number).unwrap();
        let error = PacketNative5CaptureProfile::deserialize(ContentDeserializer::<
            serde_json::Error,
        >::new(content))
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("floating point `1e-300`"));
    }
}
