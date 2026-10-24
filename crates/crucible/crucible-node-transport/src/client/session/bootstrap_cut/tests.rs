//! Checks private budget snapshots on actual original SDK/socket owners.
//!
//! The registrar and seeded Hello are explicit DATA models. These controls do
//! not authenticate private Birth, selected Bootstrap18 policy or completion.

use super::*;
use crate::connection::{ConnectionIncident, ReceivedBody};

struct Supervisor;

impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, _: ConnectionIncident) {}
}

struct RefusingSchemas;

impl BodySchemaVerifier for RefusingSchemas {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        _: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "budget check must not decode a body",
        ))
    }
}

#[test]
fn original_bootstrap_cut_rejects_renewal_even_without_any_protocol_effect() {
    let (_handshake, authority) = crate::handshake::tests::controller_authority(true).unwrap();
    let (mut session, mut peer) =
        ClientSession::controller_fixture(authority, Rc::new(Supervisor), Rc::new(RefusingSchemas))
            .unwrap();
    session.seed_owned11_model_hello().unwrap();
    let original = session.deadline.original_cut();

    assert_eq!(
        session.original_bootstrap_hello_cut_data().unwrap(),
        original
    );
    assert_eq!(
        session.original_bootstrap_hello_cut_data().unwrap(),
        original
    );
    assert_eq!(session.deadline.original_cut(), original);

    session.deadline.reset(Duration::from_secs(60)).unwrap();
    assert_ne!(session.deadline.original_cut(), original);
    assert!(session.original_bootstrap_hello_cut_data().is_err());
    assert!(session.original_bootstrap_hello_cut_data().is_err());
    assert_eq!(session.sequence.get(), 2);

    use std::io::Read;
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn original_bootstrap_cut_refuses_same_expired_snapshot_without_replacement() {
    let deadline = ExchangeDeadline::start(Duration::from_secs(1)).unwrap();
    deadline.reset(Duration::from_nanos(1)).unwrap();
    let original = OriginalBootstrapHelloCut::capture(&deadline);
    assert!(original.0.is_expired());
    assert!(original.authenticate(&deadline).is_err());
    assert_eq!(deadline.original_cut(), original.0);

    deadline.reset(Duration::from_secs(60)).unwrap();
    assert!(original.authenticate(&deadline).is_err());
}

#[test]
fn original_bootstrap_cut_requires_original_hello_sequence_and_live_registration() {
    for fault in 0..3 {
        let (mut handshake, authority) =
            crate::handshake::tests::controller_authority(true).unwrap();
        let (mut session, _peer) = ClientSession::controller_fixture(
            authority,
            Rc::new(Supervisor),
            Rc::new(RefusingSchemas),
        )
        .unwrap();
        if fault != 0 {
            session.seed_owned11_model_hello().unwrap();
        }
        match fault {
            0 => {}
            1 => session.sequence = U64::new(3),
            2 => {
                handshake.contain();
            }
            _ => unreachable!(),
        }
        let original = session.deadline.original_cut();

        assert!(
            session.original_bootstrap_hello_cut_data().is_err(),
            "fault {fault}"
        );
        assert_eq!(session.deadline.original_cut(), original);
    }
}
