//! Non-authorizing broker receive precursor for one inspector response.
//!
//! A systemd `Accept=yes` connection names PID 1 as its establishing peer, not
//! the service which writes the response. This module preserves the exact
//! socket-bound SCM subject, checks the existing response wire role, and
//! type-checks the sole namespace descriptor. The broker still lacks the
//! authenticated activation owner and protected pending-attempt publisher
//! needed to call this from production or to grant Network effect authority.

use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind, PidFd};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{
    KernelAuthorizedRecordSubject, RecordBindingError, SeqpacketError,
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
    /// The sole transferred descriptor was not a Network namespace.
    #[error(transparent)]
    Namespace(#[from] aos_sandbox_linux::Error),
    /// The typed namespace descriptor disagreed with the response record.
    #[error("inspector response namespace descriptor does not match its record")]
    NamespaceMismatch,
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
}

impl InspectorResponseCandidateV1 {
    /// Requeries PID 1 against this exact record subject and a separately retained pidfd.
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
        inspector_pidfd: &PidFd,
        inspector_unit: &str,
        pending: PendingLifecycleWorkerInspectionV1,
        clock: &mut impl InspectorTrustedClockV1,
    ) -> Result<
        (
            PendingLifecycleWorkerInspectionV1,
            NetworkNamespaceInspectionResponseV1,
            NamespaceFd,
        ),
        InspectorResponseReceiveErrorV1,
    > {
        let Self {
            socket: _socket,
            response,
            record_subject,
            namespace,
        } = self;
        let mut gate = InspectorResponsePid1GateV3::observe(
            deployment,
            inspector_pidfd,
            record_subject,
            inspector_unit,
            pending,
        )?;
        let pending = gate.consume_once(&response, clock)?;
        Ok((pending, response, namespace))
    }
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
    let record = socket.receive(RESPONSE_BYTES, 1)?;
    let bound = socket.bind_received(record)?;
    let (bytes, record_subject, descriptors, _) = bound.into_parts();
    let response = NetworkNamespaceInspectionResponseV1::decode(&bytes)?;
    let [descriptor] = <[std::os::fd::OwnedFd; 1]>::try_from(descriptors).map_err(|_| {
        NetworkNamespaceInspectorError::Protocol("response descriptor count changed")
    })?;
    let namespace = NamespaceFd::from_owned(descriptor, NamespaceKind::Network)?;
    if response.namespace != namespace.identity() {
        return Err(InspectorResponseReceiveErrorV1::NamespaceMismatch);
    }
    Ok(InspectorResponseCandidateV1 {
        socket,
        response,
        record_subject,
        namespace,
    })
}
