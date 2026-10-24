//! Checks literal publication custody without granting JSON or SDK validity.

use super::*;
use std::io::Cursor;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

const REQUEST: &[u8] = b"original unparsed request";
const RESPONSE: &[u8] = br#"{"body":"prepared response"}"#;

fn wire(body: &[u8]) -> Vec<u8> {
    let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(body);
    bytes
}

fn cut() -> OperationalDeadline {
    OperationalDeadline::after(Duration::from_secs(10)).unwrap()
}

fn receive<S: Read + Write>(
    stream: S,
) -> (OriginalNativeHelloExchange<S>, OriginalNativeHelloLiteral) {
    let mut exchange = OriginalNativeHelloJournal::reserve(64, 64)
        .unwrap()
        .bind(stream)
        .unwrap();
    let mut literal = None;
    exchange.receive_literal_into_data(&mut literal).unwrap();
    (exchange, literal.unwrap())
}

#[test]
fn actual_unix_publication_retains_the_original_socket_and_literal_roles() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    let descriptor = stream.as_raw_fd();
    peer.write_all(&wire(REQUEST)).unwrap();
    peer.write_all(b"next-input-is-unread").unwrap();
    let mut publication = OriginalNativeHelloPublication::empty_data();
    let (mut exchange, literal) = receive(stream);
    let before = exchange.journal.allocated_bytes();
    let original_cut = cut();

    exchange
        .publish_literal_response_data(&literal, RESPONSE, &mut publication, original_cut)
        .unwrap();

    let mut observed = vec![0; RESPONSE.len() + 4];
    peer.read_exact(&mut observed).unwrap();
    assert_eq!(observed, wire(RESPONSE));
    assert_eq!(exchange.original_stream_data().as_raw_fd(), descriptor);
    assert_eq!(literal.body_data(&exchange).unwrap(), REQUEST);
    assert_eq!(exchange.journal.allocated_bytes(), before);
    assert_eq!(
        publication
            .retained_backing_beside_exchange_data(&exchange)
            .unwrap(),
        0
    );
    assert!(!exchange.journal.received);
    assert!(
        exchange
            .originals()
            .original_literal_frame_digests()
            .is_err()
    );
    let digests = publication
        .completed_frame_digests_data(&exchange, original_cut)
        .unwrap();
    let different_cut = cut();
    assert!(
        publication
            .completed_frame_digests_data(&exchange, different_cut)
            .is_err()
    );
    assert_eq!(
        publication
            .completed_frame_digests_data(&exchange, original_cut)
            .unwrap(),
        digests
    );

    assert!(
        exchange
            .publish_literal_response_data(&literal, b"substitute", &mut publication, original_cut)
            .is_err()
    );
    assert_eq!(
        publication
            .completed_frame_digests_data(&exchange, original_cut)
            .unwrap(),
        digests
    );
    let mut unread = [0; b"next-input-is-unread".len()];
    exchange
        .reader
        .stream_mut()
        .read_exact(&mut unread)
        .unwrap();
    assert_eq!(&unread, b"next-input-is-unread");
}

#[derive(Debug)]
struct OwnedDiagnostic(String);

impl std::fmt::Display for OwnedDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("owned publication diagnostic")
    }
}

impl std::error::Error for OwnedDiagnostic {}

struct CutStream {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    allowance: usize,
    interrupted: bool,
    custom: bool,
    zero: bool,
    expire_on_completion: bool,
}

impl Read for CutStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.input.read(bytes)
    }
}

impl Write for CutStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.interrupted {
            self.interrupted = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let remaining = self.allowance.saturating_sub(self.output.len());
        if remaining == 0 {
            if self.zero {
                return Ok(0);
            }
            return Err(if self.custom {
                io::Error::other(OwnedDiagnostic(String::with_capacity(8192)))
            } else {
                io::Error::from_raw_os_error(32)
            });
        }
        let count = remaining.min(bytes.len()).min(3);
        self.output.extend_from_slice(&bytes[..count]);
        if self.expire_on_completion && self.output.len() == self.allowance {
            std::thread::sleep(Duration::from_millis(1100));
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn controlled(
    allowance: usize,
) -> (
    OriginalNativeHelloExchange<CutStream>,
    OriginalNativeHelloLiteral,
) {
    receive(CutStream {
        input: Cursor::new(wire(REQUEST)),
        output: Vec::new(),
        allowance,
        interrupted: true,
        custom: false,
        zero: false,
        expire_on_completion: false,
    })
}

#[test]
fn every_partial_prefix_keeps_the_complete_proposal_and_first_actual_io_failure() {
    let proposal = wire(RESPONSE);
    for allowance in 0..proposal.len() {
        let (mut exchange, literal) = controlled(allowance);
        let mut publication = OriginalNativeHelloPublication::empty_data();
        let original_cut = cut();

        assert!(
            exchange
                .publish_literal_response_data(&literal, RESPONSE, &mut publication, original_cut)
                .is_err()
        );

        let bank = exchange.journal.bank.borrow();
        let frame = bank.frame(publication.slot.unwrap()).unwrap();
        assert_eq!(frame.bytes, proposal);
        assert_eq!(frame.transferred, allowance);
        assert!(!frame.complete);
        assert_eq!(
            exchange.original_stream_data().output,
            proposal[..allowance]
        );
        let Some(ProviderError::Io(error)) = publication.failure.as_ref() else {
            panic!("actual I/O failure was not retained")
        };
        assert_eq!(error.raw_os_error(), Some(32));
        assert_eq!(
            publication
                .retained_backing_beside_exchange_data(&exchange)
                .unwrap(),
            0
        );
        assert!(
            publication
                .completed_frame_digests_data(&exchange, original_cut)
                .is_err()
        );
        drop(bank);
        let failure = publication.failure.as_ref().map(std::ptr::from_ref);

        assert!(
            exchange
                .publish_literal_response_data(
                    &literal,
                    b"replacement",
                    &mut publication,
                    original_cut
                )
                .is_err()
        );
        assert_eq!(exchange.original_stream_data().output.len(), allowance);
        assert_eq!(
            publication.failure.as_ref().map(std::ptr::from_ref),
            failure
        );
        assert!(exchange.publish(&Value::Null).is_err());
    }
}

#[test]
fn zero_writes_and_unknown_custom_errors_stay_retained_and_spent() {
    for custom in [false, true] {
        let (mut exchange, literal) = controlled(5);
        exchange.reader.stream_mut().custom = custom;
        exchange.reader.stream_mut().zero = !custom;
        let mut publication = OriginalNativeHelloPublication::empty_data();
        let original_cut = cut();
        assert!(
            exchange
                .publish_literal_response_data(&literal, RESPONSE, &mut publication, original_cut)
                .is_err()
        );

        let Some(ProviderError::Io(error)) = publication.failure.as_ref() else {
            panic!("missing retained I/O failure")
        };
        if custom {
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<OwnedDiagnostic>()
                    .unwrap()
                    .0
                    .capacity(),
                8192
            );
            assert!(
                publication
                    .retained_backing_beside_exchange_data(&exchange)
                    .is_err()
            );
        } else {
            assert_eq!(error.kind(), io::ErrorKind::WriteZero);
            assert_eq!(
                publication
                    .retained_backing_beside_exchange_data(&exchange)
                    .unwrap(),
                0
            );
        }
        assert_eq!(exchange.original_stream_data().output.len(), 5);
        assert!(
            exchange
                .publish_literal_response_data(&literal, RESPONSE, &mut publication, original_cut)
                .is_err()
        );
        assert!(
            publication
                .completed_frame_digests_data(&exchange, original_cut)
                .is_err()
        );
    }
}

#[test]
fn invalid_extents_and_expired_original_cuts_write_nothing_and_cannot_retry() {
    for (body, original_cut) in [
        (&b""[..], cut()),
        (&[b'x'; 65][..], cut()),
        (RESPONSE, OperationalDeadline::expired_fixture()),
    ] {
        let (mut exchange, literal) = controlled(usize::MAX);
        let mut publication = OriginalNativeHelloPublication::empty_data();
        assert!(
            exchange
                .publish_literal_response_data(&literal, body, &mut publication, original_cut)
                .is_err()
        );
        assert!(exchange.original_stream_data().output.is_empty());
        assert!(publication.slot.is_none());
        assert!(publication.failure.is_some());
        assert!(
            exchange
                .publish_literal_response_data(&literal, RESPONSE, &mut publication, cut())
                .is_err()
        );
        assert!(exchange.original_stream_data().output.is_empty());
    }
}

#[test]
fn foreign_literals_and_banks_never_substitute_the_original_exchange() {
    let (mut exchange, literal) = controlled(usize::MAX);
    let (foreign, foreign_literal) = controlled(usize::MAX);
    let mut publication = OriginalNativeHelloPublication::empty_data();
    let original_cut = cut();
    exchange
        .publish_literal_response_data(&literal, RESPONSE, &mut publication, original_cut)
        .unwrap();
    assert!(
        publication
            .completed_frame_digests_data(&foreign, original_cut)
            .is_err()
    );
    assert!(
        publication
            .retained_backing_beside_exchange_data(&foreign)
            .is_err()
    );

    let (mut exchange, _) = controlled(usize::MAX);
    let mut refused = OriginalNativeHelloPublication::empty_data();
    assert!(
        exchange
            .publish_literal_response_data(&foreign_literal, RESPONSE, &mut refused, original_cut)
            .is_err()
    );
    assert!(exchange.original_stream_data().output.is_empty());
    assert!(refused.failure.is_some());
}

#[test]
fn expiry_after_the_last_write_preserves_complete_physical_progress_without_completion() {
    let (mut exchange, literal) = controlled(RESPONSE.len() + 4);
    exchange.reader.stream_mut().expire_on_completion = true;
    let mut publication = OriginalNativeHelloPublication::empty_data();
    let original_cut = OperationalDeadline::after(Duration::from_secs(1)).unwrap();

    assert!(
        exchange
            .publish_literal_response_data(&literal, RESPONSE, &mut publication, original_cut)
            .is_err()
    );

    let bank = exchange.journal.bank.borrow();
    let frame = bank.frame(publication.slot.unwrap()).unwrap();
    assert_eq!(frame.bytes, wire(RESPONSE));
    assert_eq!(frame.transferred, frame.bytes.len());
    assert!(frame.complete);
    assert!(!publication.complete);
    assert!(publication.failure.is_some());
    assert!(
        publication
            .completed_frame_digests_data(&exchange, original_cut)
            .is_err()
    );
    drop(bank);
    assert!(
        exchange
            .publish_literal_response_data(&literal, RESPONSE, &mut publication, cut())
            .is_err()
    );
    assert_eq!(exchange.original_stream_data().output, wire(RESPONSE));
}

#[test]
fn actual_unix_broken_pipe_retains_the_proposal_and_original_kernel_failure() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    let descriptor = stream.as_raw_fd();
    peer.write_all(&wire(REQUEST)).unwrap();
    peer.shutdown(std::net::Shutdown::Read).unwrap();
    let (mut exchange, literal) = receive(stream);
    let mut publication = OriginalNativeHelloPublication::empty_data();
    let original_cut = cut();

    assert!(
        exchange
            .publish_literal_response_data(&literal, RESPONSE, &mut publication, original_cut)
            .is_err()
    );

    let Some(ProviderError::Io(error)) = publication.failure.as_ref() else {
        panic!("missing original kernel error")
    };
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert!(error.get_ref().is_none());
    assert_eq!(
        publication
            .retained_backing_beside_exchange_data(&exchange)
            .unwrap(),
        0
    );
    assert_eq!(exchange.original_stream_data().as_raw_fd(), descriptor);
    let bank = exchange.journal.bank.borrow();
    let frame = bank.frame(publication.slot.unwrap()).unwrap();
    assert_eq!(frame.bytes, wire(RESPONSE));
    assert_eq!(frame.transferred, 0);
    assert!(!frame.complete);
    drop(bank);
    assert!(
        publication
            .completed_frame_digests_data(&exchange, original_cut)
            .is_err()
    );
    let mut replacement = OriginalNativeHelloPublication::empty_data();
    assert!(
        exchange
            .publish_literal_response_data(&literal, RESPONSE, &mut replacement, original_cut)
            .is_err()
    );
    assert!(replacement.slot.is_none());
}
