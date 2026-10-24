//! Checks compact failed custody using actual partial and completed streams.

use super::*;
use crate::source_birth::request_wire::CodecError;

fn frame(payload: &[u8], missing: usize, nodes: u64, depth: u64) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&((payload.len() + missing) as u64).to_be_bytes());
    bytes.extend_from_slice(&nodes.to_be_bytes());
    bytes.extend_from_slice(&depth.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn limits(bytes: usize, nodes: usize) -> StreamLimits {
    StreamLimits {
        maximum_wire_bytes: bytes,
        maximum_values: nodes,
    }
}

#[test]
fn real_early_refusal_and_codec_error_have_compact_inline_owners() {
    let failed = read_value(&mut [].as_slice(), limits(HEADER_BYTES, 1)).unwrap_err();

    assert!(std::mem::size_of_val(&failed) < 128);
    assert_eq!(failed.values_read(), 0);
    assert_eq!(failed.open_containers(), 0);
    assert_eq!(failed.wire_bytes_read(), 0);
    assert!(failed.partial_text().is_empty());
    assert!(matches!(failed.error(), StreamError::Io(error)
        if error.kind() == io::ErrorKind::UnexpectedEof));
    let codec = CodecError::LiteralRead(failed);
    assert!(std::mem::size_of_val(&codec) < 128);
}

#[test]
fn actual_short_object_text_keeps_all_original_allocations_keys_and_cause() {
    let mut payload = vec![9, 10];
    payload.extend_from_slice(&3u64.to_be_bytes());
    payload.extend_from_slice(b"key");
    payload.push(6);
    payload.extend_from_slice(&5u64.to_be_bytes());
    payload.extend_from_slice(b"ab");
    let bytes = frame(&payload, 3, 2, 1);
    let mut assembly = Assembly::new();
    let error = assembly
        .read(&mut bytes.as_slice(), limits(bytes.len() + 3, 2))
        .unwrap_err();
    let frames = (assembly.frames.as_ptr(), assembly.frames.capacity());
    let retirement = (assembly.retirement.as_ptr(), assembly.retirement.capacity());
    let text = (assembly.text.as_ptr(), assembly.text.capacity());
    let (key, placeholder) = match &assembly.frames[0] {
        Frame::Object { values, key } => (
            key.as_ref().unwrap().as_ptr(),
            values.get("key").unwrap() as *const Value,
        ),
        Frame::Array(_) => panic!("the actual object frame must stay retained"),
    };
    assert_eq!(assembly.text.len(), 5);
    assert_eq!(assembly.text_read, 2);

    let failed = ReadFailure {
        error,
        state: assembly.into_failure(),
    };

    assert_eq!(
        (failed.state.frames.as_ptr(), failed.state.frames.capacity()),
        frames
    );
    assert_eq!(
        (
            failed.state.retirement.as_ptr(),
            failed.state.retirement.capacity()
        ),
        retirement
    );
    assert_eq!(
        (failed.state.text.as_ptr(), failed.state.text.capacity()),
        text
    );
    assert_eq!(failed.state.text.len(), 2);
    assert_eq!(failed.partial_text(), b"ab");
    assert_eq!(failed.values_read(), 2);
    assert_eq!(failed.open_containers(), 1);
    assert_eq!(failed.wire_bytes_read(), bytes.len());
    assert!(matches!(failed.error(), StreamError::Io(error)
        if error.kind() == io::ErrorKind::UnexpectedEof));
    let source = std::error::Error::source(&failed).unwrap();
    assert!(std::ptr::eq(
        source.downcast_ref::<StreamError>().unwrap(),
        failed.error()
    ));
    match &failed.state.frames[0] {
        Frame::Object {
            values,
            key: actual,
        } => {
            assert_eq!(actual.as_ref().unwrap().as_ptr(), key);
            assert_eq!(values.get("key").unwrap() as *const Value, placeholder);
        }
        Frame::Array(_) => panic!("the original object owner was replaced"),
    }
    drop(failed);
}

#[test]
fn completed_deep_root_moves_into_the_original_retirement_bank_before_return() {
    let depth = 4_096usize;
    let mut payload = vec![7; depth];
    payload.push(0);
    payload.extend(std::iter::repeat_n(8, depth));
    payload.push(0);
    let bytes = frame(&payload, 0, (depth + 1) as u64, depth as u64);
    let mut assembly = Assembly::new();
    let error = assembly
        .read(&mut bytes.as_slice(), limits(bytes.len(), depth + 1))
        .unwrap_err();
    assert!(matches!(
        error,
        StreamError::Format(StreamFormatReason::TrailingPayload)
    ));
    let root = assembly.root.as_ref().unwrap().as_array().unwrap().as_ptr();
    let retirement = (assembly.retirement.as_ptr(), assembly.retirement.capacity());
    assert!(assembly.frames.is_empty());

    let failed = ReadFailure {
        error,
        state: assembly.into_failure(),
    };

    assert_eq!(
        (
            failed.state.retirement.as_ptr(),
            failed.state.retirement.capacity()
        ),
        retirement
    );
    assert_eq!(failed.state.retirement.len(), 1);
    assert_eq!(
        failed
            .state
            .retirement
            .last()
            .unwrap()
            .as_array()
            .unwrap()
            .as_ptr(),
        root
    );
    assert_eq!(failed.values_read(), depth + 1);
    assert_eq!(failed.open_containers(), 0);
    assert_eq!(failed.wire_bytes_read(), bytes.len() - 1);
    drop(CodecError::LiteralRead(failed));
}
