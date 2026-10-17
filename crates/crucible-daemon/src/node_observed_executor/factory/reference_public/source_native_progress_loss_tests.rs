//! Checks original partial frame retention and bounded operational waiting.
//!
//! These actual Unix-stream reader tests exercise data custody only. They mint
//! no native receipt, process enrollment, qualification or modeled progress.

// crucible-lint: allow panic-shortcut -- These stream-reader tests deliberately panic on invalid Unix-stream fixtures or violated custody invariants.
#![allow(clippy::unwrap_used)]

use std::io::Write;

use super::*;

#[test]
fn partial_header_retains_only_actual_original_bytes() {
    let (mut reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(&[0, 0]).unwrap();
    writer.shutdown(Shutdown::Write).unwrap();
    let mut header = [0; 4];
    let count = Cell::new(0);
    let declared = Cell::new(None);
    let mut bytes = Vec::with_capacity(MAXIMUM_PROGRESS_BYTES);

    let result = read_original_frame(
        &mut reader,
        &mut header,
        &count,
        &declared,
        &mut bytes,
        ProcessDeadline::after(Duration::from_secs(1)).unwrap(),
    );

    assert!(result.is_err());
    assert_eq!(count.get(), 2);
    assert_eq!(&header[..count.get()], &[0, 0]);
    assert_eq!(declared.get(), None);
    assert!(bytes.is_empty());
}

#[test]
fn partial_body_retains_actual_prefix_without_unreceived_padding() {
    let (mut reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(&5_u32.to_be_bytes()).unwrap();
    writer.write_all(b"ab").unwrap();
    writer.shutdown(Shutdown::Write).unwrap();
    let mut header = [0; 4];
    let count = Cell::new(0);
    let declared = Cell::new(None);
    let mut bytes = Vec::with_capacity(MAXIMUM_PROGRESS_BYTES);

    let result = read_original_frame(
        &mut reader,
        &mut header,
        &count,
        &declared,
        &mut bytes,
        ProcessDeadline::after(Duration::from_secs(1)).unwrap(),
    );

    assert!(result.is_err());
    assert_eq!(count.get(), 4);
    assert_eq!(declared.get(), Some(5));
    assert_eq!(bytes, b"ab");
}

#[test]
fn expired_original_deadline_does_not_receive_an_available_replacement() {
    let (mut reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(&1_u32.to_be_bytes()).unwrap();
    writer.write_all(b"a").unwrap();
    let mut header = [0; 4];
    let count = Cell::new(0);
    let declared = Cell::new(None);
    let mut bytes = Vec::with_capacity(MAXIMUM_PROGRESS_BYTES);

    let result = read_original_frame(
        &mut reader,
        &mut header,
        &count,
        &declared,
        &mut bytes,
        ProcessDeadline::after(Duration::ZERO).unwrap(),
    );

    assert!(result.is_err());
    assert_eq!(count.get(), 0);
    assert_eq!(declared.get(), None);
    assert!(bytes.is_empty());
}
