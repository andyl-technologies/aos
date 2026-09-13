//! Private traffic-proved channels after both sequence-one durable commits.
//!
//! These typestates retain socket, protected custody, kernel-bound record
//! subjects, authenticated semantic state, and the corresponding durable owner.
//! They intentionally expose no transport, signer, context, descriptor, or raw
//! session-state accessor and have no sequence-two operation in this tranche.

use aos_sandbox::resource_inventory::{
    ControllerNetworkInventoryCheckpointOwnerV1, ControllerNetworkInventoryCommittedResultV1,
};
use aos_sandbox_network::namespace_catalog::{
    BrokerNetworkInventoryOutcomeReceiptV1, NetworkNamespaceCatalogV1,
};
use aos_sandbox_protocol::authenticated_session::{
    AuthenticatedBrokerSessionStateV1, AuthenticatedNetworkInventoryOutcomeV1,
    AuthenticatedNetworkInventoryRequestV1,
};

use super::{
    BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES, HandshakeCarrier, ProtectedBrokerSessionBrokerV1,
    ProtectedBrokerSessionClientV1, RemotePeerExpectation, RetainedSubject,
};

/// Retains the client side only after controller completion and currentness resolution.
pub(super) struct ClientHeads2ChannelV1 {
    pub(super) _custody: ProtectedBrokerSessionClientV1,
    pub(super) _carrier: HandshakeCarrier,
    pub(super) _publication_packet: Vec<u8>,
    pub(super) _client_packet: Vec<u8>,
    pub(super) _broker_packet: Vec<u8>,
    pub(super) _publication_subject: RetainedSubject,
    pub(super) _broker_subject: RetainedSubject,
    pub(super) _outcome_subject: RetainedSubject,
    pub(super) _broker_process: [u8; 16],
    pub(super) _expectation: RemotePeerExpectation,
    pub(super) _request_packet: Vec<u8>,
    pub(super) _outcome_packet: Vec<u8>,
    pub(super) _state: AuthenticatedBrokerSessionStateV1,
    pub(super) _request: AuthenticatedNetworkInventoryRequestV1,
    pub(super) _outcome: AuthenticatedNetworkInventoryOutcomeV1,
    pub(super) _checkpoint_owner: ControllerNetworkInventoryCheckpointOwnerV1,
    pub(super) _committed_result: ControllerNetworkInventoryCommittedResultV1,
}

/// Retains the broker side only after the exact committed outcome was sent.
pub(super) struct BrokerHeads2ChannelV1 {
    pub(super) _custody: ProtectedBrokerSessionBrokerV1,
    pub(super) _carrier: HandshakeCarrier,
    pub(super) _publication: [u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES],
    pub(super) _client_packet: Vec<u8>,
    pub(super) _client_subject: RetainedSubject,
    pub(super) _request_subject: RetainedSubject,
    pub(super) _broker_packet: Vec<u8>,
    pub(super) _client_process: [u8; 16],
    pub(super) _expectation: RemotePeerExpectation,
    pub(super) _request_packet: Vec<u8>,
    pub(super) _outcome_packet: Vec<u8>,
    pub(super) _state: AuthenticatedBrokerSessionStateV1,
    pub(super) _request: AuthenticatedNetworkInventoryRequestV1,
    pub(super) _outcome: AuthenticatedNetworkInventoryOutcomeV1,
    pub(super) _catalog_owner: NetworkNamespaceCatalogV1,
    pub(super) _outcome_receipt: BrokerNetworkInventoryOutcomeReceiptV1,
}
