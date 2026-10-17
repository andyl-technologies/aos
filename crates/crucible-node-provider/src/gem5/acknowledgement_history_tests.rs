//! Exercises same-holder private ACK byte retention without a native child.
#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Pure data controls use unwrap only to identify failed setup.
#![allow(clippy::unwrap_used)]

use std::io::{self, Cursor};

use super::*;

struct SplitStream {
    reply: Cursor<Vec<u8>>,
    written: Vec<u8>,
    fail_write_after: Option<usize>,
}

impl SplitStream {
    fn new(body: &[u8]) -> Self {
        let mut reply = Vec::new();
        reply.extend_from_slice(&(body.len() as u32).to_be_bytes());
        reply.extend_from_slice(body);
        Self {
            reply: Cursor::new(reply),
            written: Vec::new(),
            fail_write_after: None,
        }
    }
}

impl Read for SplitStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let length = bytes.len().min(3);
        self.reply.read(&mut bytes[..length])
    }
}

impl Write for SplitStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .fail_write_after
            .is_some_and(|end| self.written.len() >= end)
        {
            return Err(io::Error::other("authored first-write refusal"));
        }
        let length = bytes.len().min(2);
        self.written.extend_from_slice(&bytes[..length]);
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn complete_reply_retains_exact_frames_and_single_original_slot() {
    let operation = Id::new("original/1").unwrap();
    let mut history = Gem5AcknowledgementHistory::reserve(1).unwrap();
    let mut stream = SplitStream::new(br#"{"kind":"acknowledged","operation":"original/1"}"#);
    let entry = history.begin(&operation).unwrap();

    exchange_once(&mut stream, entry).unwrap();
    assert_eq!(entry.request_frame(), stream.written);
    assert_eq!(entry.written_bytes(), stream.written.len());
    assert_eq!(entry.reply_frame(), stream.reply.get_ref());
    // Only the actual driver deadline check may accept success.
    assert!(!entry.acknowledged());
    assert!(history.begin(&operation).is_err());
    assert!(history.begin(&Id::new("original/2").unwrap()).is_err());
    assert_eq!(history.exchanges().len(), 1);
}

#[test]
fn partial_first_write_and_reply_remain_original_uncertainty() {
    let operation = Id::new("original/1").unwrap();
    let mut history = Gem5AcknowledgementHistory::reserve(2).unwrap();
    let mut stream = SplitStream::new(br#"{"kind":"acknowledged","operation":"original/1"}"#);
    stream.fail_write_after = Some(4);
    let entry = history.begin(&operation).unwrap();

    assert!(exchange_once(&mut stream, entry).is_err());
    assert_eq!(entry.written_bytes(), 4);
    assert!(entry.reply_frame().is_empty());
    assert!(!entry.acknowledged());
    assert!(history.begin(&operation).is_err());

    let second = Id::new("original/2").unwrap();
    let entry = history.begin(&second).unwrap();
    let mut truncated = SplitStream::new(br#"{"kind":"acknowledged","operation":"original/2"}"#);
    truncated.reply.get_mut().truncate(11);
    assert!(exchange_once(&mut truncated, entry).is_err());
    assert_eq!(entry.reply_frame(), truncated.reply.get_ref());
    assert_eq!(entry.reply_frame().len(), 11);
    assert!(!entry.acknowledged());
}

#[test]
fn changed_reply_and_invalid_capacity_never_accept_acknowledgement() {
    assert!(Gem5AcknowledgementHistory::reserve(0).is_err());
    assert!(Gem5AcknowledgementHistory::reserve(65_537).is_err());
    let mut history = Gem5AcknowledgementHistory::reserve(1).unwrap();
    let entry = history.begin(&Id::new("original/1").unwrap()).unwrap();
    let mut stream = SplitStream::new(br#"{"kind":"acknowledged","operation":"foreign/1"}"#);

    assert!(exchange_once(&mut stream, entry).is_err());
    assert_eq!(entry.reply_frame(), stream.reply.get_ref());
    assert!(!entry.acknowledged());
}

#[test]
fn retirement_encoding_precredits_exact_partial_original_geometry() {
    let mut history = Gem5AcknowledgementHistory::reserve(1).unwrap();
    let original = Id::new("original/retirement").unwrap();
    let entry = history.begin(&original).unwrap();
    let mut stream =
        SplitStream::new(br#"{"kind":"acknowledged","operation":"original/retirement"}"#);
    stream.fail_write_after = Some(4);
    assert!(exchange_once(&mut stream, entry).is_err());

    let body = history.encode_retirement_history(4096).unwrap();
    assert!(history.encode_retirement_history(body.len() - 1).is_err());
    assert_eq!(history.encode_retirement_history(body.len()).unwrap(), body);
    let tag = b"crucible.gem5.private-ack-history.v1\0";
    assert_eq!(&body[..tag.len()], tag);
    assert_eq!(&body[tag.len()..tag.len() + 8], &[0, 0, 0, 1, 0, 0, 0, 1]);
    assert_eq!(body.last(), Some(&0));
    assert_eq!(history.exchanges()[0].written_bytes(), 4);
    assert!(history.exchanges()[0].reply_frame().is_empty());
}
