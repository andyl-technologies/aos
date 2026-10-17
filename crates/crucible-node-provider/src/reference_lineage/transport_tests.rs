//! Checks original socket allowance without exposing clock coordinates to codecs.

// crucible-lint: allow panic-shortcut -- Socket fixture failures invalidate this original transport contract test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{DeadlineIo, ExchangeBudget};
use std::{
    io::{ErrorKind, Read, Write},
    os::unix::net::UnixStream,
    time::Duration,
};

#[test]
fn later_fragments_cannot_renew_the_original_exchange_allowance() {
    let (mut socket, mut peer) = UnixStream::pair().unwrap();
    let budget = ExchangeBudget::after(Duration::from_millis(200)).unwrap();
    let mut original = DeadlineIo::new(&mut socket, budget);

    peer.write_all(b"a").unwrap();
    let mut first = [0; 1];
    original.read_exact(&mut first).unwrap();
    assert_eq!(first, *b"a");

    // Input is already available; refusal must precede another socket effect.
    peer.write_all(b"b").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let mut next = [0; 1];
    assert_eq!(
        original.read(&mut next).unwrap_err().kind(),
        ErrorKind::TimedOut
    );
    assert_eq!(
        original.write(b"c").unwrap_err().kind(),
        ErrorKind::TimedOut
    );

    let mut unchanged = [0; 1];
    socket.read_exact(&mut unchanged).unwrap();
    assert_eq!(unchanged, *b"b");
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut unchanged).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
}

#[test]
fn expired_allowance_neither_consumes_nor_emits_socket_bytes() {
    let (mut socket, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(b"original").unwrap();
    let budget = ExchangeBudget::after(Duration::ZERO).unwrap();
    let mut original = DeadlineIo::new(&mut socket, budget);

    let mut byte = [0; 1];
    assert_eq!(
        original.read(&mut byte).unwrap_err().kind(),
        ErrorKind::TimedOut
    );
    assert_eq!(
        original.write(b"replacement").unwrap_err().kind(),
        ErrorKind::TimedOut
    );

    let mut retained = [0; 8];
    socket.read_exact(&mut retained).unwrap();
    assert_eq!(retained, *b"original");
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut byte).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
}
