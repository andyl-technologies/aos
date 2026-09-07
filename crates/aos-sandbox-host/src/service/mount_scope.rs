//! Separate RootMount peer/session profile for exact-scope descriptor export.

use aos_sandbox_protocol::mount_scope::{MOUNT_SCOPE_DESCRIPTOR_ROLES, decode_mount_scope_request};

use super::*;
use crate::transport::HostConnection;

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostService<C, S, W> {
    pub(super) async fn serve_mount_scope(
        &mut self,
        connection: &HostConnection,
    ) -> Result<ConnectionOutcome> {
        let Ok(peer) = self
            .verifier
            .verify_mount_broker(connection.peer_identity())
        else {
            return Ok(ConnectionOutcome::PeerRejected);
        };

        let policy = PeerPolicy {
            uid: 0,
            gid: Some(0),
            audience: Audience::AUDIENCE_ROOT_MOUNT,
        };
        let Ok(hello) = connection.receive(MAXIMUM_HANDSHAKE_BYTES) else {
            return Ok(ConnectionOutcome::TransportRejected);
        };
        if !hello.descriptors.is_empty() {
            return Ok(send_hello_error(
                connection,
                &HostError::Protocol(ProtocolValidationError::DescriptorTableMismatch),
            ));
        }

        let method = BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE;
        let session = match negotiate_client_hello(
            &hello.bytes,
            peer.credentials(),
            policy,
            ProtocolId::HostBroker,
            &[signed_plan_lease_feature()?],
            &[method],
        ) {
            Ok(session) => session,
            Err(error) => return Ok(send_hello_error(connection, &HostError::Protocol(error))),
        };
        if connection
            .send(&session.server_hello().encode_to_vec())
            .is_err()
        {
            return Ok(ConnectionOutcome::TransportRejected);
        }

        let Ok(packet) = connection.receive(session.maximum_request_bytes()) else {
            return Ok(ConnectionOutcome::TransportRejected);
        };
        let Ok(request) = session.decode_request(&packet.bytes, packet.descriptors.len()) else {
            return Ok(ConnectionOutcome::RequestRejected);
        };
        if request.method() != method || validate_request_descriptor_roles(&request, &[]).is_err() {
            return Ok(ConnectionOutcome::RequestRejected);
        }

        let Some(artifacts) = request.authorization() else {
            return Ok(ConnectionOutcome::RequestRejected);
        };
        let Ok(validated) = decode_mount_scope_request(
            request.body(),
            peer.credentials(),
            policy,
            trusted_paired_clock_sample()?.boottime_nanoseconds(),
        ) else {
            return Ok(ConnectionOutcome::RequestRejected);
        };
        if session.validate_header(validated.header()).is_err() {
            return Ok(ConnectionOutcome::RequestRejected);
        }

        let request_id = validated.header().request_id();
        let ceiling = validated.header().maximum_response_bytes();
        let reply = match self
            .broker
            .prepare_mount_scope(
                artifacts,
                &validated,
                request.body(),
                &mut trusted_paired_clock_sample,
            )
            .await
        {
            Ok(reply) => reply,
            Err(error) => {
                return Ok(send_error(
                    connection, request_id, &request, &error, ceiling,
                ));
            }
        };

        let response = match encode_success_response_envelope(
            request_id,
            &request,
            reply.body().to_vec(),
            &MOUNT_SCOPE_DESCRIPTOR_ROLES,
            &[],
            ceiling,
        ) {
            Ok(response) => response,
            Err(_) => {
                return Ok(send_error(
                    connection,
                    request_id,
                    &request,
                    &HostError::ResourceExhausted,
                    ceiling,
                ));
            }
        };

        if self
            .verifier
            .verify_mount_broker(connection.peer_identity())
            .is_err()
        {
            return Ok(ConnectionOutcome::PeerRejected);
        }
        if let Err(error) = reply.check_before_send(&mut trusted_paired_clock_sample) {
            return Ok(send_error(
                connection, request_id, &request, &error, ceiling,
            ));
        }

        Ok(
            if connection
                .send_mount_scope(&response, reply.descriptors())
                .is_ok()
            {
                ConnectionOutcome::Served
            } else {
                ConnectionOutcome::TransportRejected
            },
        )
    }
}

fn send_error(
    connection: &HostConnection,
    request_id: &[u8; 16],
    request: &aos_sandbox_protocol::ValidatedBrokerRequestEnvelope,
    error: &HostError,
    ceiling: u32,
) -> ConnectionOutcome {
    match encode_method_error(request_id, request, error, ceiling) {
        Ok(bytes) if connection.send(&bytes).is_ok() => ConnectionOutcome::RequestRejected,
        _ => ConnectionOutcome::TransportRejected,
    }
}
