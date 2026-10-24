//! Exercises the actual framed APIs and literal, deep and failed-input behavior.

use super::*;
use serde_json::{Map, Value};
use std::io::{self, Cursor, Read, Write};

fn limits(bytes: usize, nodes: usize) -> StreamLimits {
    StreamLimits {
        maximum_wire_bytes: bytes,
        maximum_values: nodes,
    }
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_value(value, &mut bytes, limits(usize::MAX, usize::MAX)).unwrap();
    bytes
}

fn frame(payload: &[u8], nodes: u64, depth: u64) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&nodes.to_be_bytes());
    bytes.extend_from_slice(&depth.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn text(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

#[test]
fn actual_round_trip_preserves_every_primitive_and_literal_reserved_key() {
    let mut object = Map::new();
    object.insert(
        "$serde_json::private::RawValue".into(),
        Value::String("[1,2]".into()),
    );
    object.insert(
        "$serde_json::private::Number".into(),
        Value::String("1.000".into()),
    );
    object.insert("prefix".into(), Value::String("a\0é𝄞\"\\".into()));
    object.insert(
        "prefix-long".into(),
        Value::Array(vec![Value::Null, Value::Bool(false), Value::Bool(true)]),
    );
    let value = Value::Array(vec![
        Value::from(i64::MIN),
        Value::from(-1i64),
        Value::from(0u64),
        Value::from(u64::MAX),
        Value::from(i64::MAX as u64 + 1),
        Value::from(1.25),
        Value::from(-0.0f64),
        Value::Array(Vec::new()),
        Value::Object(Map::new()),
        Value::Object(object),
    ]);
    let bytes = encode(&value);
    let decoded = read_value(&mut bytes.as_slice(), limits(bytes.len(), 100)).unwrap();

    assert_eq!(decoded.value().unwrap(), &value);
    assert_eq!(encode(decoded.value().unwrap()), bytes);
    let values = decoded.value().unwrap().as_array().unwrap();
    assert_eq!(values[6].as_f64().unwrap().to_bits(), (-0.0f64).to_bits());
    assert_eq!(values[3].as_u64(), Some(u64::MAX));
    assert_eq!(values[9]["$serde_json::private::RawValue"], "[1,2]");
}

#[test]
fn real_wire_vectors_are_endian_explicit_and_exclude_noncanonical_numeric_tags() {
    let bytes = encode(&Value::from(u64::MAX));
    assert_eq!(&bytes[..8], MAGIC);
    assert_eq!(&bytes[8..16], &9u64.to_be_bytes());
    assert_eq!(&bytes[16..24], &1u64.to_be_bytes());
    assert_eq!(&bytes[24..32], &0u64.to_be_bytes());
    assert_eq!(&bytes[32..], &[3, 255, 255, 255, 255, 255, 255, 255, 255]);

    for (tag, bits, expected) in [
        (4, 1u64, StreamFormatReason::SignedTokenNotNegative),
        (
            5,
            f64::INFINITY.to_bits(),
            StreamFormatReason::NonFiniteFloat,
        ),
        (5, f64::NAN.to_bits(), StreamFormatReason::NonFiniteFloat),
    ] {
        let mut payload = vec![tag];
        payload.extend_from_slice(&bits.to_be_bytes());
        let bytes = frame(&payload, 1, 0);
        let failed = read_value(&mut bytes.as_slice(), limits(bytes.len(), 1)).unwrap_err();
        assert!(matches!(failed.error(), StreamError::Format(reason) if *reason == expected));
    }
}

#[test]
fn exact_and_one_short_limits_apply_to_real_writer_and_reader() {
    let value = Value::Array(vec![Value::from(7u64), Value::String("abc".into())]);
    let bytes = encode(&value);
    let mut exact = Vec::new();
    let statistics = write_value(&value, &mut exact, limits(bytes.len(), 3)).unwrap();
    assert_eq!(exact, bytes);
    assert_eq!(statistics.values, 3);
    assert!(read_value(&mut exact.as_slice(), limits(bytes.len(), 3)).is_ok());

    for (bound, writer_reason, reader_reason) in [
        (
            limits(bytes.len() - 1, 3),
            StreamLimitReason::WireBytes,
            StreamLimitReason::WireBytes,
        ),
        (
            limits(bytes.len(), 2),
            StreamLimitReason::TraversalWorkspaceOrValues,
            StreamLimitReason::ValueCount,
        ),
    ] {
        let mut untouched = Vec::new();
        assert!(
            matches!(write_value(&value, &mut untouched, bound), Err(StreamError::Limit(reason)) if reason == writer_reason)
        );
        assert!(untouched.is_empty());
        let failed = read_value(&mut bytes.as_slice(), bound).unwrap_err();
        assert!(matches!(failed.error(), StreamError::Limit(reason) if *reason == reader_reason));
    }
    assert!(matches!(
        checked_add(usize::MAX, 1),
        Err(StreamError::Limit(StreamLimitReason::SizeOverflow))
    ));
}

#[test]
fn malformed_chronology_duplicate_keys_utf8_and_header_counts_refuse() {
    let mut duplicate = vec![9];
    duplicate.extend(text(10, b"key"));
    duplicate.push(0);
    duplicate.extend(text(10, b"key"));
    duplicate.extend_from_slice(&[0, 11]);
    let mut invalid_utf8 = text(6, &[255]);
    let mut excessive_text = vec![6];
    excessive_text.extend_from_slice(&u64::MAX.to_be_bytes());
    let cases = [
        (frame(&[255], 1, 0), StreamFormatReason::UnknownToken),
        (
            frame(&[8], 1, 0),
            StreamFormatReason::MismatchedCloseOrMissingObjectValue,
        ),
        (
            frame(&[7, 11], 1, 1),
            StreamFormatReason::MismatchedCloseOrMissingObjectValue,
        ),
        (
            frame(&[9, 0, 11], 2, 1),
            StreamFormatReason::ValueWithoutDestination,
        ),
        (frame(&[0, 0], 2, 0), StreamFormatReason::TrailingPayload),
        (frame(&[0], 2, 0), StreamFormatReason::ImpossibleValueCount),
        (frame(&[0], 1, 1), StreamFormatReason::HeaderCountsDiffer),
        (frame(&duplicate, 3, 1), StreamFormatReason::DuplicateKey),
        (frame(&invalid_utf8, 1, 0), StreamFormatReason::InvalidUtf8),
        (
            frame(&excessive_text, 1, 0),
            StreamFormatReason::TextBeyondPayload,
        ),
    ];
    for (bytes, expected) in cases {
        let failed = read_value(&mut bytes.as_slice(), limits(bytes.len(), 10)).unwrap_err();
        assert!(matches!(failed.error(), StreamError::Format(reason) if *reason == expected));
    }
    invalid_utf8.clear();

    let mut overflow = frame(&[0], 1, 0);
    overflow[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    let failed = read_value(&mut overflow.as_slice(), limits(usize::MAX, usize::MAX)).unwrap_err();
    assert!(matches!(
        failed.error(),
        StreamError::Limit(StreamLimitReason::SizeOverflow)
    ));
    let mut foreign = encode(&Value::Null);
    foreign[7] = b'2';
    let failed = read_value(&mut foreign.as_slice(), limits(foreign.len(), 1)).unwrap_err();
    assert!(matches!(
        failed.error(),
        StreamError::Format(StreamFormatReason::MagicOrVersion)
    ));
}

#[test]
fn every_truncated_prefix_keeps_owning_partial_state_and_actual_text_prefix() {
    let value = Value::Array(vec![
        Value::String("original-text".into()),
        Value::from(9u64),
    ]);
    let bytes = encode(&value);
    for length in 0..bytes.len() {
        let failed = read_value(&mut &bytes[..length], limits(bytes.len(), 3)).unwrap_err();
        assert_eq!(failed.wire_bytes_read(), length);
        drop(failed);
    }

    let string = encode(&Value::String("retained-prefix".into()));
    let length = HEADER_BYTES + 1 + 8 + 5;
    let failed = read_value(&mut &string[..length], limits(string.len(), 1)).unwrap_err();
    assert_eq!(failed.partial_text(), b"retai");
    assert_eq!(failed.values_read(), 1);
}

#[test]
fn deep_success_and_late_failure_are_iterative_without_a_json_depth_limit() {
    let depth = 20_000usize;
    let mut payload = vec![7; depth];
    payload.push(0);
    payload.extend(std::iter::repeat_n(8, depth));
    let bytes = frame(&payload, (depth + 1) as u64, depth as u64);
    let decoded = read_value(&mut bytes.as_slice(), limits(bytes.len(), depth + 1)).unwrap();
    assert_eq!(decoded.statistics().depth, depth);
    assert_eq!(encode(decoded.value().unwrap()), bytes);
    drop(decoded);

    let failed = read_value(
        &mut &bytes[..bytes.len() - 1],
        limits(bytes.len(), depth + 1),
    )
    .unwrap_err();
    assert_eq!(failed.open_containers(), 1);
    assert_eq!(failed.values_read(), depth + 1);
    drop(failed);
}

struct PrefixWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for PrefixWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self.maximum - self.bytes.len();
        if remaining == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let length = remaining.min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..length]);
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn actual_partial_output_error_retains_prefix_and_original_input() {
    let value = Value::String("original-data".into());
    let complete = encode(&value);
    for maximum in 0..complete.len() {
        let mut writer = PrefixWriter {
            bytes: Vec::new(),
            maximum,
        };
        assert!(matches!(
            write_value(&value, &mut writer, limits(complete.len(), 1)),
            Err(StreamError::Io(_))
        ));
        assert_eq!(writer.bytes, complete[..maximum]);
        assert_eq!(value, "original-data");
    }
}

#[test]
fn framing_leaves_the_next_value_unread_and_validates_payload_before_return() {
    let first = encode(&Value::Bool(true));
    let second = encode(&Value::String("second".into()));
    let mut joined = first.clone();
    joined.extend_from_slice(&second);
    let mut input = Cursor::new(joined);
    let decoded = read_value(&mut input, limits(first.len(), 1)).unwrap();
    assert_eq!(decoded.value().unwrap(), &Value::Bool(true));
    assert_eq!(input.position(), first.len() as u64);
    let decoded = read_value(&mut input, limits(second.len(), 1)).unwrap();
    assert_eq!(decoded.value().unwrap(), &Value::String("second".into()));
}

struct PanicReader {
    input: Cursor<Vec<u8>>,
    stop: u64,
}

impl Read for PanicReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.input.position() >= self.stop {
            panic!("intentional reader unwind");
        }
        let length = buffer
            .len()
            .min((self.stop - self.input.position()) as usize);
        self.input.read(&mut buffer[..length])
    }
}

#[test]
fn deep_partial_input_unwind_keeps_the_iterative_guard_installed() {
    let depth = 10_000usize;
    let mut payload = vec![7; depth];
    payload.push(0);
    payload.extend(std::iter::repeat_n(8, depth));
    let bytes = frame(&payload, (depth + 1) as u64, depth as u64);
    let stop = (bytes.len() - 1) as u64;
    let mut input = PanicReader {
        input: Cursor::new(bytes.clone()),
        stop,
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = read_value(&mut input, limits(bytes.len(), depth + 1));
    }));
    assert!(outcome.is_err());
    assert_eq!(input.input.position(), stop);
}

#[test]
fn actual_header_retirement_overflow_refuses_before_allocation_or_values() {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&(1u64 << 63).to_be_bytes());
    bytes.extend_from_slice(&(1u64 << 63).to_be_bytes());
    bytes.extend_from_slice(&0u64.to_be_bytes());
    let failed = read_value(&mut bytes.as_slice(), limits(usize::MAX, usize::MAX)).unwrap_err();
    assert!(matches!(
        failed.error(),
        StreamError::Limit(StreamLimitReason::RetirementSizeOverflow)
    ));
    assert_eq!(failed.values_read(), 0);
    assert_eq!(failed.open_containers(), 0);
}

#[test]
fn wide_object_and_array_frontiers_remain_owned_through_success_and_late_error() {
    let mut values = Map::new();
    for index in 0..2_000usize {
        values.insert(
            format!("key-{index:04}"),
            Value::Array(vec![Value::Null, Value::Bool(true)]),
        );
    }
    let original = Value::Object(values);
    let bytes = encode(&original);
    let decoded = read_value(&mut bytes.as_slice(), limits(bytes.len(), 6_001)).unwrap();
    assert_eq!(encode(decoded.value().unwrap()), bytes);
    drop(decoded);

    let failed =
        read_value(&mut &bytes[..bytes.len() - 1], limits(bytes.len(), 6_001)).unwrap_err();
    assert_eq!(failed.open_containers(), 1);
    assert_eq!(failed.values_read(), 6_001);
    drop(failed);
}

#[test]
fn deep_object_placeholders_attach_without_reinserting_deep_values() {
    let depth = 2_048usize;
    let mut payload = Vec::new();
    for _ in 0..depth {
        payload.push(9);
        payload.extend(text(10, b"literal-key"));
    }
    payload.push(0);
    payload.extend(std::iter::repeat_n(11, depth));
    let bytes = frame(&payload, (depth + 1) as u64, depth as u64);
    let decoded = read_value(&mut bytes.as_slice(), limits(bytes.len(), depth + 1)).unwrap();
    assert_eq!(encode(decoded.value().unwrap()), bytes);
    drop(decoded);

    let failed = read_value(
        &mut &bytes[..bytes.len() - 1],
        limits(bytes.len(), depth + 1),
    )
    .unwrap_err();
    assert_eq!(failed.open_containers(), 1);
    assert_eq!(failed.values_read(), depth + 1);
    drop(failed);
}
