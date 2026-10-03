//! Exact request direction for each protected broker-session journal role.

use aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1;

/// Selects the only request direction admitted by an endpoint's durable head.
pub(super) const fn request_direction_for_endpoint(
    endpoint: BrokerSessionDurableEndpointV1,
) -> AuthenticatedBrokerRequestDirectionV1 {
    match endpoint {
        BrokerSessionDurableEndpointV1::Client => AuthenticatedBrokerRequestDirectionV1::ClientSend,
        BrokerSessionDurableEndpointV1::Broker => {
            AuthenticatedBrokerRequestDirectionV1::ServerReceive
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_head_rejects_broker_receive_direction() {
        let direction = request_direction_for_endpoint(BrokerSessionDurableEndpointV1::Client);

        assert_eq!(direction, AuthenticatedBrokerRequestDirectionV1::ClientSend);
        assert_ne!(
            direction,
            AuthenticatedBrokerRequestDirectionV1::ServerReceive
        );
    }

    #[test]
    fn broker_head_rejects_client_send_direction() {
        let direction = request_direction_for_endpoint(BrokerSessionDurableEndpointV1::Broker);

        assert_eq!(
            direction,
            AuthenticatedBrokerRequestDirectionV1::ServerReceive
        );
        assert_ne!(direction, AuthenticatedBrokerRequestDirectionV1::ClientSend);
    }
}
