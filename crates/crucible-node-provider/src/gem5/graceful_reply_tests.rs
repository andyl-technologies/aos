//! Checks same-stream reply continuation without any native owner or reap token.
//!
//! Real Unix stream bytes exercise framing; injected read/write refusals select
//! transport branches only. Kernel/group disappearance remains a separate native
//! prerequisite that these controls do not construct.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Original frame, deadline and stream assertions intentionally panic on mismatched retention.
#![allow(clippy::unwrap_used)]

use super::*;

const FRAME: &[u8] = b"\0\0\0\x13{\"kind\":\"shutdown\"}";

struct ReceiveRefusal {
    stream: UnixStream,
    refusal_at: usize,
    refusal: Option<std::io::ErrorKind>,
    read_bytes: usize,
    written: Vec<u8>,
}

impl Read for ReceiveRefusal {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if self.read_bytes == self.refusal_at
            && let Some(kind) = self.refusal.take()
        {
            return Err(std::io::Error::new(kind, "original receive refusal"));
        }
        let limit = if self.refusal.is_some() {
            bytes.len().min(self.refusal_at - self.read_bytes)
        } else {
            bytes.len()
        };
        let count = self.stream.read(&mut bytes[..limit])?;
        self.read_bytes += count;
        Ok(count)
    }
}

impl Write for ReceiveRefusal {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let count = self.stream.write(bytes)?;
        self.written.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

fn transport(reply: &[u8], refusal: std::io::ErrorKind) -> (ReceiveRefusal, UnixStream) {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.write_all(reply).unwrap();
    (
        ReceiveRefusal {
            stream,
            refusal_at: 9,
            refusal: Some(refusal),
            read_bytes: 0,
            written: Vec::new(),
        },
        peer,
    )
}

fn first_receive(
    io: &mut impl ReadWrite,
    exchange: &mut Gem5ShutdownExchange,
    original: OperationalDeadline,
) {
    assert!(
        OriginalShutdownIo::new(io, original)
            .exchange(exchange)
            .is_err()
    );
    assert_eq!(exchange.written_bytes(), FRAME.len());
    assert_eq!(exchange.received_bytes().len(), 9);
    assert!(!exchange.acknowledged());
}

#[test]
fn transient_original_reply_completes_without_another_frame_or_deadline() {
    for refusal in [
        std::io::ErrorKind::Interrupted,
        std::io::ErrorKind::WouldBlock,
    ] {
        let (mut io, mut peer) = transport(FRAME, refusal);
        let original = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
        let mut exchange = Gem5ShutdownExchange::reserved();
        first_receive(&mut io, &mut exchange, original);
        assert!(exchange.reply_continuation_pending());
        let mut request = [0; 23];
        peer.read_exact(&mut request).unwrap();
        assert_eq!(request, FRAME);

        OriginalShutdownIo::new(&mut io, original)
            .continue_reply(&mut exchange)
            .unwrap();

        assert!(exchange.acknowledged());
        assert!(!exchange.reply_continuation_pending());
        assert_eq!(exchange.received_bytes(), FRAME);
        assert_eq!(io.written, FRAME);
        peer.set_nonblocking(true).unwrap();
        let error = peer.read(&mut [0; 1]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    }
}

#[test]
fn expired_original_budget_refuses_without_reading_already_available_reply() {
    let (mut io, _peer) = transport(FRAME, std::io::ErrorKind::Interrupted);
    let original = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
    let mut exchange = Gem5ShutdownExchange::reserved();
    first_receive(&mut io, &mut exchange, original);
    let prefix = exchange.received_bytes().to_vec();
    let expired = OperationalDeadline::expired_fixture();

    assert!(
        OriginalShutdownIo::new(&mut io, expired)
            .continue_reply(&mut exchange)
            .is_err()
    );
    assert_eq!(exchange.received_bytes(), prefix);
    assert_eq!(io.read_bytes, 9);
    assert_eq!(io.written, FRAME);
    assert!(!exchange.acknowledged());
    assert!(!exchange.reply_continuation_pending());
    // Neither the expired budget nor a later supplied budget revives the latch.
    assert!(
        OriginalShutdownIo::new(&mut io, original)
            .continue_reply(&mut exchange)
            .is_err()
    );
    assert_eq!(io.read_bytes, 9);
}

#[test]
fn foreign_and_overcredit_reply_refusals_remain_sticky_after_continuation() {
    for body in [b"{\"kind\":\"other\"}".as_slice(), &[b' '; 65]] {
        let mut reply = (body.len() as u32).to_be_bytes().to_vec();
        reply.extend_from_slice(body);
        let (mut io, _peer) = transport(&reply, std::io::ErrorKind::Interrupted);
        let original = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
        let mut exchange = Gem5ShutdownExchange::reserved();
        assert!(
            OriginalShutdownIo::new(&mut io, original)
                .exchange(&mut exchange)
                .is_err()
        );
        if exchange.reply_continuation_pending() {
            assert!(
                OriginalShutdownIo::new(&mut io, original)
                    .continue_reply(&mut exchange)
                    .is_err()
            );
        }
        let received = exchange.received_bytes().to_vec();

        assert!(!exchange.reply_continuation_pending());
        assert!(
            OriginalShutdownIo::new(&mut io, original)
                .continue_reply(&mut exchange)
                .is_err()
        );
        assert_eq!(exchange.received_bytes(), received);
        assert_eq!(io.written, FRAME);
        assert!(!exchange.acknowledged());
    }
}

#[test]
fn eof_and_nontransient_receive_refusals_never_become_reaping_authority() {
    for refusal in [
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::PermissionDenied,
    ] {
        let (mut io, _peer) = transport(FRAME, refusal);
        let original = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
        let mut exchange = Gem5ShutdownExchange::reserved();
        first_receive(&mut io, &mut exchange, original);

        assert!(!exchange.reply_continuation_pending());
        assert!(
            OriginalShutdownIo::new(&mut io, original)
                .continue_reply(&mut exchange)
                .is_err()
        );
        assert_eq!(io.read_bytes, 9);
        assert!(!exchange.acknowledged());
    }
    let (mut io, peer) = transport(&FRAME[..9], std::io::ErrorKind::Interrupted);
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    let original = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
    let mut exchange = Gem5ShutdownExchange::reserved();
    first_receive(&mut io, &mut exchange, original);
    assert!(
        OriginalShutdownIo::new(&mut io, original)
            .continue_reply(&mut exchange)
            .is_err()
    );
    assert!(!exchange.reply_continuation_pending());
    assert!(!exchange.acknowledged());
    assert_eq!(exchange.received_bytes(), &FRAME[..9]);
}

struct PartialWrite {
    written: Vec<u8>,
    reads: usize,
}

impl Write for PartialWrite {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if !self.written.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "original partial write",
            ));
        }
        self.written.extend_from_slice(&bytes[..7]);
        Ok(7)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Read for PartialWrite {
    fn read(&mut self, _bytes: &mut [u8]) -> std::io::Result<usize> {
        self.reads += 1;
        Ok(0)
    }
}

#[test]
fn transient_partial_request_never_resends_or_enters_receive_continuation() {
    let original = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
    let mut io = PartialWrite {
        written: Vec::new(),
        reads: 0,
    };
    let mut exchange = Gem5ShutdownExchange::reserved();
    assert!(
        OriginalShutdownIo::new(&mut io, original)
            .exchange(&mut exchange)
            .is_err()
    );

    assert!(!exchange.reply_continuation_pending());
    assert!(
        OriginalShutdownIo::new(&mut io, original)
            .continue_reply(&mut exchange)
            .is_err()
    );
    assert_eq!(exchange.written_bytes(), 7);
    assert_eq!(io.written, &FRAME[..7]);
    assert_eq!(io.reads, 0);
    assert!(!exchange.acknowledged());
}
