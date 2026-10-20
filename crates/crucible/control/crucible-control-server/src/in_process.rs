//! Control client adapter over existing same-process actor handles.

use crate::ControlPlaneEventLog;
use crucible_control_api::*;
use crucible_control_client::{ControlClient, ControlClientFuture};
use crucible_session::{LiveSnapshot, SessionCommand};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Same-process client over a live `crucible-session` actor.
#[derive(Clone)]
pub struct InProcessControlClient {
    sender: mpsc::Sender<SessionCommand>,
    live: Arc<LiveSnapshot>,
    event_log: ControlPlaneEventLog,
    wire_model: ControlWireModel,
}

impl InProcessControlClient {
    /// Builds an in-process client from actor-owned session handles.
    #[must_use]
    pub fn new(
        sender: mpsc::Sender<SessionCommand>,
        live: Arc<LiveSnapshot>,
        event_log: ControlPlaneEventLog,
    ) -> Self {
        Self {
            sender,
            live,
            event_log,
            wire_model: ControlWireModel::current(),
        }
    }

    /// Returns the actor mailbox used by this in-process client.
    #[must_use]
    pub fn sender(&self) -> mpsc::Sender<SessionCommand> {
        self.sender.clone()
    }

    /// Returns the lock-free live session mirror used by this client.
    #[must_use]
    pub fn live_snapshot(&self) -> Arc<LiveSnapshot> {
        Arc::clone(&self.live)
    }

    /// Returns the event-log facade used by this client.
    #[must_use]
    pub const fn event_log(&self) -> &ControlPlaneEventLog {
        &self.event_log
    }
}

impl ControlClient for InProcessControlClient {
    fn transport(&self) -> ControlTransportKind {
        ControlTransportKind::InProcess
    }

    fn wire_model(&self) -> ControlWireModel {
        self.wire_model
    }

    fn hello(&self, request: HelloRequest) -> ControlClientFuture<'_, HelloResponse> {
        Box::pin(async move {
            let version = negotiate_rpc_protocol(request.version)?;
            Ok(HelloResponse::new(
                "crucible-in-process-session",
                version,
                self.wire_model.payload_kinds,
                self.transport(),
            ))
        })
    }
}
