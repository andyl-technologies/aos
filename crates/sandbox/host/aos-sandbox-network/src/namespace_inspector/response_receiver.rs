//! Non-authorizing broker receive precursor for one inspector response.
//!
//! A systemd `Accept=yes` connection names PID 1 as its establishing peer, not
//! the service which writes the response. This module preserves the exact
//! socket-bound SCM subject, checks the existing response wire role, and
//! type-checks the namespace and echoed accepted-endpoint descriptors. The
//! staged broker session owns publication, but production dispatch does not
//! invoke it. Echoing an FD is not independent PID 1 delivery or MAC proof.

use std::os::fd::{AsFd as _, OwnedFd};

use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, KernelAuthorizedRecordSubject, RecordBindingError, SeqpacketError,
};
use thiserror::Error;

use super::{
    InspectorResponsePid1GateErrorV3, InspectorResponsePid1GateV3, InspectorTrustedClockV1,
    NetworkNamespaceInspectionResponseV1, NetworkNamespaceInspectorError,
    PendingLifecycleWorkerInspectionV1, RESPONSE_BYTES,
};
use crate::inspector_deployment::ProtectedInspectorDeploymentV2;

/// Reports a fail-closed, nonauthorizing inspector response receive failure.
#[derive(Debug, Error)]
pub(super) enum InspectorResponseReceiveErrorV1 {
    /// The socket record or exact descriptor count was invalid.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// The received record did not originate on the retained socket endpoint.
    #[error(transparent)]
    RecordBinding(#[from] RecordBindingError),
    /// The existing response codec rejected the role, framing, or identity.
    #[error(transparent)]
    Response(#[from] NetworkNamespaceInspectorError),
    /// The first transferred descriptor was not a Network namespace.
    #[error(transparent)]
    Namespace(#[from] aos_sandbox_linux::Error),
    /// The typed namespace descriptor disagreed with the response record.
    #[error("inspector response namespace descriptor does not match its record")]
    NamespaceMismatch,
    /// The second descriptor was not a connected Unix sequenced-packet endpoint.
    #[error("inspector accepted-endpoint descriptor is invalid: {0}")]
    AcceptedEndpoint(SeqpacketError),
    /// The echoed endpoint named the broker's own connector object.
    #[error("inspector accepted endpoint is the broker connector")]
    ConnectorEcho,
    /// The pending response or fresh PID 1 service readback was rejected.
    #[error(transparent)]
    Pid1(#[from] InspectorResponsePid1GateErrorV3),
}

/// Retains one untrusted response, its exact SCM subject, and typed descriptor.
///
/// No constructor accepts standalone wire bytes. The response is still not a
/// completed inspection: the `Accept=yes` connection, protected publication,
/// and worker liveness have not been authenticated here.
#[derive(Debug)]
pub(super) struct InspectorResponseCandidateV1 {
    socket: DescriptorSubjectSocket,
    pub(super) response: NetworkNamespaceInspectionResponseV1,
    pub(super) record_subject: KernelAuthorizedRecordSubject,
    pub(super) namespace: NamespaceFd,
    pub(super) accepted_endpoint: OwnedFd,
    pub(super) accepted_peer: ConnectionPeerIdentity,
}

impl InspectorResponseCandidateV1 {
    /// Requeries PID 1 against the exact kernel-nominated record subject.
    ///
    /// This is only a source-level correlation precursor. The caller must
    /// independently prove systemd activation, durable expected publication,
    /// and worker currentness before completing the inspection model.
    ///
    /// # Errors
    ///
    /// Rejects an invalid or replayed pending response, stale clock, changed
    /// inspector invocation, pidfd, or signed unit payload.
    pub(super) fn correlate<'deployment>(
        self,
        deployment: &'deployment ProtectedInspectorDeploymentV2,
        inspector_unit: &str,
        pending: PendingLifecycleWorkerInspectionV1,
        clock: &mut impl InspectorTrustedClockV1,
    ) -> Result<CorrelatedInspectorResponseCandidateV1, InspectorResponseReceiveErrorV1> {
        let Self {
            socket,
            response,
            record_subject,
            namespace,
            accepted_endpoint,
            accepted_peer,
        } = self;
        let gate = InspectorResponsePid1GateV3::observe(
            deployment,
            record_subject,
            inspector_unit,
            pending,
            clock,
        )?;
        let (pending, record_subject) = gate.consume_once(&response, clock)?;
        Ok(CorrelatedInspectorResponseCandidateV1 {
            socket,
            pending,
            response,
            record_subject,
            namespace,
            accepted_endpoint,
            accepted_peer,
        })
    }
}

/// Retains the exact connected socket and SCM pidfd after signed PID 1 correlation.
///
/// This remains an activation candidate: an echoed FD and PID 1 service
/// readback do not prove manager delivery or the enforcing MAC policy.
#[derive(Debug)]
pub(super) struct CorrelatedInspectorResponseCandidateV1 {
    pub(super) socket: DescriptorSubjectSocket,
    pub(super) pending: PendingLifecycleWorkerInspectionV1,
    pub(super) response: NetworkNamespaceInspectionResponseV1,
    pub(super) record_subject: KernelAuthorizedRecordSubject,
    pub(super) namespace: NamespaceFd,
    pub(super) accepted_endpoint: OwnedFd,
    pub(super) accepted_peer: ConnectionPeerIdentity,
}

/// Receives one socket-bound response without asserting a service identity.
///
/// The caller must connect through a protected endpoint, authenticate the
/// socket's PID 1 peer, send the published pending request, and wait for a
/// bounded response deadline. This consumes the socket on every outcome;
/// success retains it through PID 1 correlation, and no second packet can be
/// accepted as a retry for this one-shot request.
///
/// # Errors
///
/// Rejects an inexact ancillary descriptor table, foreign socket origin,
/// invalid canonical response role or bytes, non-Network descriptor, or
/// namespace identity mismatch. No result grants effect authority.
pub(super) fn receive_candidate(
    mut socket: DescriptorSubjectSocket,
) -> Result<InspectorResponseCandidateV1, InspectorResponseReceiveErrorV1> {
    let record = socket.receive(RESPONSE_BYTES, 2)?;
    let bound = socket.bind_received(record)?;
    let (bytes, record_subject, descriptors, _) = bound.into_parts();
    let response = NetworkNamespaceInspectionResponseV1::decode_transport_v2(&bytes)?;
    let [descriptor, accepted_endpoint] = <[OwnedFd; 2]>::try_from(descriptors).map_err(|_| {
        NetworkNamespaceInspectorError::Protocol("response descriptor count changed")
    })?;
    let namespace = NamespaceFd::from_owned(descriptor, NamespaceKind::Network)?;
    let accepted_peer = ConnectionPeerIdentity::from_socket(accepted_endpoint.as_fd())
        .map_err(InspectorResponseReceiveErrorV1::AcceptedEndpoint)?;
    if accepted_peer.socket_cookie() == socket.peer().socket_cookie() {
        return Err(InspectorResponseReceiveErrorV1::ConnectorEcho);
    }
    if response.namespace != namespace.identity() {
        return Err(InspectorResponseReceiveErrorV1::NamespaceMismatch);
    }
    Ok(InspectorResponseCandidateV1 {
        socket,
        response,
        record_subject,
        namespace,
        accepted_endpoint,
        accepted_peer,
    })
}
