//! Checks actual borrowed SDK frontiers without bootstrap or native permission.

use super::*;
use crate::envelope::Nullable;
use crucible_node_format::U64;
use std::io::Read;

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
            "frontier inspection must not decode bodies",
        ))
    }
}

#[test]
fn original_bootstrap_frontier_refuses_other_traffic_without_mutating_it() {
    for fault in 0..4 {
        let (mut handshake, authority) =
            crate::handshake::tests::controller_authority(true).unwrap();
        let (stream, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut connection = Connection::new(
            stream,
            authority,
            Rc::new(Supervisor),
            Rc::new(RefusingSchemas),
            EndpointRole::Controller,
        )
        .unwrap();
        connection
            .authenticate_original_bootstrap_frontier_data()
            .unwrap();
        match fault {
            0 => connection.role = EndpointRole::Provider,
            1 => connection.fenced = true,
            2 => {
                let mut original = crate::envelope::tests::request();
                original.sequence = U64::new(2);
                original.session_id = Nullable(Some(connection.authority.session_id().clone()));
                original.incarnation_id =
                    Nullable(Some(connection.authority.incarnation_id().clone()));
                connection.guard.register_request(original).unwrap();
            }
            3 => handshake.contain(),
            _ => unreachable!(),
        }
        let pending = connection.guard.pending_requests().count();

        assert!(
            connection
                .authenticate_original_bootstrap_frontier_data()
                .is_err(),
            "fault {fault}"
        );
        assert_eq!(connection.guard.pending_requests().count(), pending);
        assert_eq!(connection.guard.unused(), fault != 2);

        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
