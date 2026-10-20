//! Shares actual fresh/retained broker publication preparation on one reducer.
//!
//! The caller has already paid the genuine original's HELLO flight. This owner
//! parks actual custody, socket, peer and each builder Result before later
//! gates. It creates no authority and performs no request or socket I/O.

use super::*;

enum HelloRecipeV5 {
    Storage,
    Fixed(BrokerSessionProtocolV1),
    HostCleanup,
}

pub(super) struct StorageBrokerHandshakeStartV1 {
    root: &'static str,
    custody: Option<BrokerHandshakeCustodyV1>,
    socket: Option<SeqpacketSocket>,
    peer: Option<Result<ProcessEvidence, HandshakeError>>,
    peer_current: Option<Result<(), HandshakeError>>,
    publication: Option<Result<[u8; BROKER_SESSION_ENDPOINT_PUBLICATION_BYTES], BrokerSessionSecurityError>>,
    hello: Option<Result<BrokerHelloSelectionV5, aos_sandbox_broker_session_protocol::BrokerSessionNegotiationError>>,
    entered: bool,
}

impl StorageBrokerHandshakeStartV1 {
    pub(super) fn completed_transfer_shell_v1(&self) -> bool {
        self.entered && self.failure().is_none() && self.custody.is_none()
            && self.socket.is_none() && self.peer.is_none()
            && self.publication.is_none() && self.hello.is_none()
    }

    pub(super) fn new(
        root: &'static str,
        custody: BrokerHandshakeCustodyV1,
        socket: SeqpacketSocket,
    ) -> Self {
        Self {
            root,
            custody: Some(custody),
            socket: Some(socket),
            peer: None,
            peer_current: None,
            publication: None,
            hello: None,
            entered: false,
        }
    }

    pub(super) fn socket(&self) -> Option<&SeqpacketSocket> {
        self.socket.as_ref()
    }

    pub(super) fn retained_parts(&self) -> Result<(&aos_sandbox_controller_domain::Journal, &SeqpacketSocket), BrokerSessionSecurityError> {
        let Some(BrokerHandshakeCustodyV1::RetainedStorage(owner)) = &self.custody else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        let journal = owner.retained_storage_journal_v1()?;
        let socket = self.socket.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        Ok((journal, socket))
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.peer.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.peer_current.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.publication.as_ref().and_then(|result| result.as_ref().err()).map(|cause| {
                self.custody.as_ref().and_then(|custody| custody.retained_revalidation_failure_for(cause))
                    .unwrap_or(cause as &dyn std::error::Error)
            }))
            .or_else(|| self.hello.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error))
    }

    pub(super) fn initialize_once(&mut self) {
        self.initialize_hello_recipe_v4(HelloRecipeV5::Storage)
    }

    pub(super) fn initialize_fixed_service_once_v4(&mut self, protocol: BrokerSessionProtocolV1) {
        self.initialize_hello_recipe_v4(HelloRecipeV5::Fixed(protocol));
    }

    pub(super) fn initialize_host_cleanup_once_v1(&mut self) {
        self.initialize_hello_recipe_v4(HelloRecipeV5::HostCleanup);
    }

    fn initialize_hello_recipe_v4(&mut self, fixed: HelloRecipeV5) {
        if self.entered {
            return;
        }
        self.entered = true;
        let Some(socket) = self.socket.as_ref() else {
            return;
        };
        self.peer = Some(ProcessEvidence::capture_peer_retaining(socket.peer()));
        let Some(Ok(peer)) = self.peer.as_ref() else {
            return;
        };
        self.peer_current = Some(peer.validate_connection_retaining(socket.peer()));
        if !matches!(self.peer_current, Some(Ok(()))) {
            return;
        }

        let Some(custody) = self.custody.as_mut() else {
            return;
        };
        self.publication = Some(custody.finalize_endpoint_publication());
        if !matches!(self.publication, Some(Ok(_))) {
            return;
        }

        self.hello = Some(match fixed {
            HelloRecipeV5::Fixed(BrokerSessionProtocolV1::Mount) => aos_sandbox_broker_session_protocol::profile::mount_attachment_anchor_server_hello_v4(),
            HelloRecipeV5::Fixed(BrokerSessionProtocolV1::Network) => aos_sandbox_broker_session_protocol::profile::network_service_server_hello_v5(),
            HelloRecipeV5::Fixed(_) => return,
            HelloRecipeV5::Storage => aos_sandbox_broker_session_protocol::profile::storage_lifecycle_server_hello_v2(),
            HelloRecipeV5::HostCleanup => {
                self.hello = Some(Ok(BrokerHelloSelectionV5::HostCleanupDeferred));
                return;
            }
        }.map(BrokerHelloSelectionV5::Provided));
    }

    pub(super) fn take_ready(&mut self) -> Option<DormantBrokerEndpointHandshakeV1> {
        if self.failure().is_some() || !matches!(self.hello, Some(Ok(_))) {
            return None;
        }
        // All fallible preparation is already parked/positive. This is a pure
        // move into the SAME existing three-flight reducer, with its selected
        // retained disposition enabled before the first possible publication.
        let Some(Ok(peer)) = self.peer.take() else {
            std::process::abort()
        };
        let Some(Ok(pending)) = self.publication.take() else {
            std::process::abort()
        };
        let Some(Ok(broker_hello)) = self.hello.take() else {
            std::process::abort()
        };
        let Some(custody) = self.custody.take() else {
            std::process::abort()
        };
        let Some(socket) = self.socket.take() else {
            std::process::abort()
        };

        Some(DormantBrokerEndpointHandshakeV1 {
            root: self.root,
            state: DormantBrokerHandshakeStateV1::SendPublication(BrokerPublicationFlight {
                custody,
                pending,
                broker_hello,
                carrier: HandshakeCarrier::ordinary_from_peer_v1(
                    socket,
                    peer,
                    HandshakeReceiveProfileV1::StoragePreparation,
                ),
            }),
        })
    }
}
