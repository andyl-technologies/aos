//! Checks original-cause identity and real descriptor custody across error clones.

use super::*;
use crate::{SchedulerError, SchedulerOperationalFailureClass};
use std::io::{self, Read};
use std::os::unix::net::UnixStream;

#[derive(Debug)]
struct RetainedTransport {
    _socket: UnixStream,
}

impl fmt::Display for RetainedTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original transport failure")
    }
}

impl Error for RetainedTransport {}

#[test]
fn scheduler_error_clones_keep_the_original_transport_open_until_last_drop()
-> Result<(), Box<dyn Error>> {
    let (socket, mut peer) = UnixStream::pair()?;
    peer.set_nonblocking(true)?;
    let cause = BackendOperationalCause::new(RetainedTransport { _socket: socket });
    let scheduler = SchedulerError::from(BackendError::RetainedOperationalFailure {
        kind: BackendOperationalFailureKind::Unavailable,
        source: cause.clone(),
    });
    let observer = scheduler.clone();

    assert_eq!(scheduler, observer);
    assert_eq!(
        scheduler.operational_failure_class(),
        Some(SchedulerOperationalFailureClass::Retryable)
    );
    assert!(
        scheduler
            .source()
            .and_then(Error::source)
            .and_then(Error::source)
            .is_some_and(|source| source.is::<RetainedTransport>())
    );
    drop(cause);
    drop(scheduler);
    let mut byte = [0];
    assert!(
        matches!(peer.read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    );

    drop(observer);
    assert_eq!(peer.read(&mut byte)?, 0);
    Ok(())
}

#[test]
fn equal_diagnostics_do_not_merge_independent_operational_causes() {
    let first = BackendOperationalCause::new(io::Error::other("same diagnostic"));
    let second = BackendOperationalCause::new(io::Error::other("same diagnostic"));

    assert_eq!(first, first.clone());
    assert_ne!(first, second);
    assert_eq!(first.to_string(), second.to_string());
}
