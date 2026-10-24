//! Checks original deadline transfer without renewing physical allowance.
// crucible-lint: allow panic-shortcut -- These deadline regressions deliberately panic when expected framing or timeout failures are absent.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn original_cut_survives_transfer_and_expiration() -> io::Result<()> {
    let deadline = ExchangeDeadline::start(Duration::from_secs(1))?;
    let (stream, _peer) = UnixStream::pair()?;
    let mut original = DeadlineStream::with_deadline(stream, deadline.clone())?;
    assert!(Rc::ptr_eq(&original.deadline.0, &deadline.0));

    deadline.0.set(OperationalDeadline::expired_fixture());
    assert_eq!(
        original.write(&[1]).err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(deadline.remaining().is_err());
    let (replacement, _peer) = UnixStream::pair()?;
    assert!(DeadlineStream::with_deadline(replacement, deadline).is_err());
    Ok(())
}

#[test]
fn original_cut_rejects_zero_and_overflow() {
    assert!(ExchangeDeadline::start(Duration::ZERO).is_err());
    assert!(ExchangeDeadline::start(Duration::MAX).is_err());
}

#[test]
fn original_cut_bounds_backpressured_bootstrap_transport() -> io::Result<()> {
    let deadline = ExchangeDeadline::start(Duration::from_millis(20))?;
    let (writer, mut unread_peer) = UnixStream::pair()?;
    let mut original = DeadlineStream::with_deadline(writer, deadline.clone())?;
    let bytes = vec![7; 4 * 1024 * 1024];

    // A genuine full socket buffer must exhaust this cut; progress on a prefix
    // cannot grant another budget. No Child or native authority is involved.
    let refusal = original.write_all(&bytes).err().map(|error| error.kind());
    assert!(matches!(
        refusal,
        Some(io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
    ));
    assert!(deadline.remaining().is_err());
    assert_eq!(
        original.write(&[1]).err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );

    unread_peer.set_nonblocking(true)?;
    let mut prefix = [0; 8];
    assert_eq!(unread_peer.read(&mut prefix)?, prefix.len());
    assert_eq!(prefix, [7; 8]);
    Ok(())
}

#[test]
fn idle_readiness_preserves_bytes_and_does_not_renew_original_cut() -> io::Result<()> {
    let (stream, mut peer) = UnixStream::pair()?;
    let (mut original, deadline) = DeadlineStream::new(stream, Duration::from_secs(1))?;
    deadline.0.set(OperationalDeadline::expired_fixture());
    peer.write_all(&[0, 0, 0, 2, b'{', b'}'])?;

    original.wait_for_request()?;

    assert_eq!(
        original.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    deadline.reset(Duration::from_secs(1))?;
    let mut frame = [0; 6];
    original.read_exact(&mut frame)?;
    assert_eq!(frame, [0, 0, 0, 2, b'{', b'}']);
    Ok(())
}

#[test]
fn readable_partial_frame_keeps_one_absolute_cut_and_poisoned_reader() -> io::Result<()> {
    let (stream, mut peer) = UnixStream::pair()?;
    let (original, deadline) = DeadlineStream::new(stream, Duration::from_secs(1))?;
    peer.write_all(&[0])?;
    original.wait_for_request()?;
    deadline.reset(Duration::from_millis(20))?;
    let mut reader = crate::transport::FrameReader::new(original, 1024).unwrap();

    let error = reader.read().unwrap_err();

    assert!(matches!(error, crate::ProviderError::Io(error)
        if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)));
    assert!(deadline.remaining().is_err());
    assert!(matches!(
        reader.read(),
        Err(crate::ProviderError::Frame("connection already failed"))
    ));
    Ok(())
}
