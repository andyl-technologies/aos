//! Checks original deadline transfer without renewing physical allowance.

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
