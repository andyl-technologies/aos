//! Checks bounded original Shutdown bytes without a native process claim.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- These inert stream controls intentionally panic on changed original frame retention.
#![allow(clippy::unwrap_used)]

use std::io::Cursor;

use super::*;

struct OriginalIo {
    response: Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl Read for OriginalIo {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.response.read(bytes)
    }
}

impl Write for OriginalIo {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn original(body: &[u8]) -> OriginalIo {
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    OriginalIo {
        response: Cursor::new(frame),
        written: Vec::new(),
    }
}

#[test]
fn original_closed_shutdown_frame_is_retained_before_acknowledgement() {
    let mut io = original(b"{\"kind\":\"shutdown\"}");
    let mut exchange = Gem5ShutdownExchange::reserved();

    exchange_once(&mut io, &mut exchange).unwrap();

    assert_eq!(exchange.written_bytes(), 23);
    assert_eq!(exchange.received_bytes(), io.written);
    assert!(!exchange.acknowledged());
}

#[test]
fn partial_reply_retains_only_received_original_bytes() {
    for retained in [1, 3, 4, 9, 22] {
        let mut io = original(b"{\"kind\":\"shutdown\"}");
        io.response.get_mut().truncate(retained);
        let mut exchange = Gem5ShutdownExchange::reserved();

        assert!(exchange_once(&mut io, &mut exchange).is_err());

        assert_eq!(exchange.received_bytes(), io.response.get_ref());
        assert_eq!(exchange.written_bytes(), 23);
        assert!(!exchange.acknowledged());
    }
}

#[test]
fn wrong_duplicate_and_overcredit_original_replies_never_acknowledge() {
    for body in [
        b"{\"kind\":\"other\"}".as_slice(),
        b"{\"kind\":\"other\",\"kind\":\"shutdown\"}".as_slice(),
        &[b' '; 65],
    ] {
        let mut io = original(body);
        let mut exchange = Gem5ShutdownExchange::reserved();

        assert!(exchange_once(&mut io, &mut exchange).is_err());

        assert!(!exchange.acknowledged());
        assert_eq!(exchange.written_bytes(), 23);
        if body.len() > 64 {
            assert_eq!(exchange.received_bytes().len(), 4);
        }
    }
}
