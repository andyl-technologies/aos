//! Exercises owning transport refusal with real Unix descriptors and modeled registrars.
//!
//! No child, native-five enrollment, capture, or fresh-installation authority is
//! issued by these constructor controls.

use super::*;
use std::{cell::Cell, io::Read, io::Write, os::fd::AsRawFd, time::Duration};

struct CountingSupervisor(Cell<usize>);
impl ConnectionSupervisor for CountingSupervisor {
    fn quarantine(&self, _: ConnectionIncident) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn native5_connection_birth_refusal_keeps_exact_socket_and_callback_owners() {
    let (mut handshake, authority, _, _) = scope(true);
    let (stream, mut peer) = UnixStream::pair().unwrap();
    let descriptor = stream.as_raw_fd();
    let supervisor = Rc::new(CountingSupervisor(Cell::new(0)));
    let schemas: Rc<dyn BodySchemaVerifier> = Rc::new(Uninstalled);
    let supervisor_weak = Rc::downgrade(&supervisor);
    let schemas_weak = Rc::downgrade(&schemas);
    handshake.contain();

    let failure = match Connection::new_native5_owned(
        stream,
        authority.clone(),
        supervisor.clone(),
        schemas.clone(),
    ) {
        Ok(_) => panic!("revoked original birth was accepted"),
        Err(failure) => failure,
    };
    drop(schemas);
    let original = failure.into_original();
    assert_eq!(original.stream().as_raw_fd(), descriptor);
    assert_eq!(
        original.authority().connection_id(),
        authority.connection_id()
    );
    assert!(!original.is_poisoned());
    assert!(schemas_weak.upgrade().is_some());
    assert!(supervisor_weak.upgrade().is_some());
    assert_eq!(supervisor.0.get(), 0);
    peer.write_all(b"same original socket").unwrap();
    let mut bytes = [0; 20];
    let mut borrowed = original.stream();
    borrowed.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"same original socket");

    let failure = match original.retry() {
        Ok(_) => panic!("retry replaced revoked authority"),
        Err(failure) => failure,
    };
    let original = failure.into_original();
    assert_eq!(original.stream().as_raw_fd(), descriptor);
    assert_eq!(supervisor.0.get(), 0);
    assert!(schemas_weak.upgrade().is_some());
}

#[test]
fn native5_connection_birth_installs_original_provider_framing_without_callbacks() {
    let (_handshake, authority, _, _) = scope(true);
    let (stream, _peer) = UnixStream::pair().unwrap();
    let supervisor = Rc::new(CountingSupervisor(Cell::new(0)));
    let mut connection = match Connection::new_native5_owned(
        stream,
        authority.clone(),
        supervisor.clone(),
        Rc::new(Uninstalled),
    ) {
        Ok(connection) => connection,
        Err(_) => panic!("current original framing refused"),
    };
    assert_eq!(
        connection.provider_authority().unwrap().connection_id(),
        authority.connection_id()
    );
    assert_eq!(supervisor.0.get(), 0);
    assert!(connection.authenticate_native5_source_codec().is_err());
}

#[test]
fn native5_expired_deadline_birth_returns_same_socket_and_nonrenewed_cut() {
    let (stream, mut peer) = UnixStream::pair().unwrap();
    let descriptor = stream.as_raw_fd();
    let deadline = crate::client::ExchangeDeadline::start(Duration::from_nanos(1)).unwrap();
    let original_cut = deadline.original_cut();
    assert!(deadline.remaining().is_err());
    let failure =
        match crate::client::DeadlineStream::with_original_deadline_owned(stream, deadline) {
            Ok(_) => panic!("expired birth was accepted"),
            Err(failure) => failure,
        };
    assert_eq!(failure.error().kind(), std::io::ErrorKind::TimedOut);
    let (mut stream, deadline) = failure.into_original();
    assert_eq!(stream.as_raw_fd(), descriptor);
    assert_eq!(deadline.original_cut(), original_cut);
    assert!(deadline.remaining().is_err());
    peer.write_all(b"held").unwrap();
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"held");
    assert!(crate::client::DeadlineStream::with_original_deadline_owned(stream, deadline).is_err());
}
