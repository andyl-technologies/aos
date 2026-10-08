//! Sealed request and response envelopes for authenticated remote exchanges.
//!
//! This module owns session correlation, response-content validation, and
//! projections of authenticated response evidence. Shared DATA and codecs remain
//! in the parent protocol module.

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{NodeId, ObjectDigest, OperationId};

use super::super::assignment::{
    AuthenticatedSnapshotChunkV1, AuthenticatedSnapshotDependencyRangeV1,
};
use super::super::capability::{CarrierValidatedCapabilityObservationV1, NodeBootLineageV1};
use super::super::carrier_authority::{AuthenticatedFrameSealV1, CarrierResponseGrantV1};
use super::super::evidence::AuthenticatedEvidenceContextV1;
use super::{
    AuthenticatedNodeSessionV1, CanonicalNodeFrameV1, CanonicalNodeSemanticCodecV1,
    CarrierValidatedResyncInventoryV1, InvalidMultiNodeProtocol, MAX_WATCH_EVENTS,
    NodeRequestBodyV1, NodeResponseBodyV1, NodeWatchCursorV1, NodeWatchEventBodyV1,
    NodeWatchEventV1, carrier_binding_digest,
};

/// Carries one request bound to an authenticated session and correlation ID.
#[cfg(feature = "multi-node")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeRequestEnvelopeV1 {
    binding: [u8; 32],
    node: NodeId,
    request: OperationId,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    canonical_body_digest: ObjectDigest,
    canonical_frame_digest: ObjectDigest,
    canonical_frame_bytes: u32,
    body: NodeRequestBodyV1,
}

#[cfg(feature = "multi-node")]
impl NodeRequestEnvelopeV1 {
    /// Constructs one request under an exact session contract.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for a zero request identity, a
    /// cross-node assignment or drain body, or an invalid watch batch limit.
    pub(in crate::local_inventory) fn from_canonical_frame(
        session: &AuthenticatedNodeSessionV1,
        canonical_frame: &CanonicalNodeFrameV1<'_>,
        coordinator_unix_seconds: u64,
        codec: &CanonicalNodeSemanticCodecV1,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        let request = canonical_frame.request();
        let body = canonical_frame.decode_request_body(session, coordinator_unix_seconds, codec)?;
        let canonical_frame_bytes = u32::try_from(canonical_frame.bytes().len())
            .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
        if request.as_bytes() == &[0; 16]
            || canonical_frame.kind() != body.frame_kind()
            || canonical_frame.version() != session.version()
            || canonical_frame.binding_digest() != carrier_binding_digest(session.binding())
            || canonical_frame.audience_digest() != session.audience_digest()
            || canonical_frame.disclosure_domain_digest() != session.disclosure_domain_digest()
            || canonical_frame_bytes > session.maximum_request_bytes()
            || !session.is_current_at(coordinator_unix_seconds)
        {
            return Err(InvalidMultiNodeProtocol::Unspecified);
        }
        let matches_node = match &body {
            NodeRequestBodyV1::ReconcileAssignment(intent) => intent.node() == session.node(),
            NodeRequestBodyV1::ReconcileDrain(directive) => directive.node() == session.node(),
            NodeRequestBodyV1::BeginSnapshotTransfer { manifest, resume } => {
                manifest.identity().source_node() == session.node()
                    && manifest.identity().audience_digest() == session.audience_digest()
                    && manifest.identity().disclosure_domain_digest()
                        == session.disclosure_domain_digest()
                    && resume.as_ref().is_none_or(|checkpoint| {
                        checkpoint.identity() == manifest.identity()
                            && manifest
                                .prefix_commitment(checkpoint.next_chunk())
                                .is_ok_and(|digest| digest == checkpoint.verified_prefix_digest())
                    })
            }
            NodeRequestBodyV1::FetchSnapshotChunk { request } => {
                request.identity().source_node() == session.node()
                    && request.identity().audience_digest() == session.audience_digest()
                    && request.identity().disclosure_domain_digest()
                        == session.disclosure_domain_digest()
            }
            NodeRequestBodyV1::FetchSnapshotDependency { request } => {
                request.identity().source_node() == session.node()
                    && request.identity().audience_digest() == session.audience_digest()
                    && request.identity().disclosure_domain_digest()
                        == session.disclosure_domain_digest()
            }
            NodeRequestBodyV1::Watch {
                after,
                maximum_events,
            } => {
                after.node() == session.node()
                    && after.lineage() == session.lineage()
                    && after.binding().coordinator_epoch() == session.coordinator_epoch()
                    && after.binding().audience_digest() == session.audience_digest()
                    && after.binding().disclosure_domain_digest()
                        == session.disclosure_domain_digest()
                    && *maximum_events != 0
                    && usize::from(*maximum_events) <= MAX_WATCH_EVENTS
                    && after.binding().schema().admits(session.version())
            }
            NodeRequestBodyV1::RelistAssignments { binding } => {
                binding.coordinator_epoch() == session.coordinator_epoch()
                    && binding.audience_digest() == session.audience_digest()
                    && binding.disclosure_domain_digest() == session.disclosure_domain_digest()
                    && binding.schema().admits(session.version())
            }
            NodeRequestBodyV1::GetCapabilities => true,
        };
        if !matches_node {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        Ok(Self {
            binding: session.binding(),
            node: session.node(),
            request,
            audience_digest: session.audience_digest(),
            disclosure_domain_digest: session.disclosure_domain_digest(),
            canonical_body_digest: canonical_frame.body_digest(),
            canonical_frame_digest: canonical_frame.frame_digest(),
            canonical_frame_bytes,
            body,
        })
    }

    pub(in crate::local_inventory) fn from_generated_carrier(
        session: &AuthenticatedNodeSessionV1,
        request: OperationId,
        body: NodeRequestBodyV1,
        semantic_bytes: &[u8],
        carrier_bytes: &[u8],
        coordinator_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        let canonical_frame_bytes = u32::try_from(carrier_bytes.len())
            .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
        if request.as_bytes() == &[0; 16]
            || semantic_bytes.is_empty()
            || carrier_bytes.is_empty()
            || canonical_frame_bytes > session.maximum_request_bytes()
            || !session.is_current_at(coordinator_unix_seconds)
            || !request_body_matches_session(session, &body)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        Ok(Self {
            binding: session.binding(),
            node: session.node(),
            request,
            audience_digest: session.audience_digest(),
            disclosure_domain_digest: session.disclosure_domain_digest(),
            canonical_body_digest: ObjectDigest::from_bytes(Sha256::digest(semantic_bytes).into()),
            canonical_frame_digest: ObjectDigest::from_bytes(Sha256::digest(carrier_bytes).into()),
            canonical_frame_bytes,
            body,
        })
    }

    /// Returns the authenticated session binding.
    #[must_use]
    pub const fn binding(&self) -> &[u8; 32] {
        &self.binding
    }

    /// Returns the target node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the request correlation identity.
    #[must_use]
    pub const fn request(&self) -> OperationId {
        self.request
    }

    /// Returns the authenticated request audience commitment.
    #[must_use]
    pub const fn audience_digest(&self) -> ObjectDigest {
        self.audience_digest
    }

    /// Returns the authenticated request disclosure-domain commitment.
    #[must_use]
    pub const fn disclosure_domain_digest(&self) -> ObjectDigest {
        self.disclosure_domain_digest
    }

    /// Returns the canonical semantic request-body commitment.
    #[must_use]
    pub const fn canonical_body_digest(&self) -> ObjectDigest {
        self.canonical_body_digest
    }

    /// Returns the exact canonical request-frame commitment.
    #[must_use]
    pub const fn canonical_frame_digest(&self) -> ObjectDigest {
        self.canonical_frame_digest
    }

    /// Returns the exact bounded request-frame length.
    #[must_use]
    pub const fn canonical_frame_bytes(&self) -> u32 {
        self.canonical_frame_bytes
    }

    /// Returns the semantic request body.
    #[must_use]
    pub const fn body(&self) -> &NodeRequestBodyV1 {
        &self.body
    }
}

#[cfg(feature = "multi-node")]
fn request_body_matches_session(
    session: &AuthenticatedNodeSessionV1,
    body: &NodeRequestBodyV1,
) -> bool {
    match body {
        NodeRequestBodyV1::ReconcileAssignment(intent) => intent.node() == session.node(),
        NodeRequestBodyV1::ReconcileDrain(directive) => directive.node() == session.node(),
        NodeRequestBodyV1::BeginSnapshotTransfer { manifest, resume } => {
            manifest.identity().source_node() == session.node()
                && manifest.identity().audience_digest() == session.audience_digest()
                && manifest.identity().disclosure_domain_digest()
                    == session.disclosure_domain_digest()
                && resume.as_ref().is_none_or(|checkpoint| {
                    checkpoint.identity() == manifest.identity()
                        && manifest
                            .prefix_commitment(checkpoint.next_chunk())
                            .is_ok_and(|digest| digest == checkpoint.verified_prefix_digest())
                })
        }
        NodeRequestBodyV1::FetchSnapshotChunk { request } => {
            request.identity().source_node() == session.node()
                && request.identity().audience_digest() == session.audience_digest()
                && request.identity().disclosure_domain_digest()
                    == session.disclosure_domain_digest()
        }
        NodeRequestBodyV1::FetchSnapshotDependency { request } => {
            request.identity().source_node() == session.node()
                && request.identity().audience_digest() == session.audience_digest()
                && request.identity().disclosure_domain_digest()
                    == session.disclosure_domain_digest()
        }
        NodeRequestBodyV1::Watch {
            after,
            maximum_events,
        } => {
            after.node() == session.node()
                && after.lineage() == session.lineage()
                && after.binding().coordinator_epoch() == session.coordinator_epoch()
                && after.binding().audience_digest() == session.audience_digest()
                && after.binding().disclosure_domain_digest() == session.disclosure_domain_digest()
                && *maximum_events != 0
                && usize::from(*maximum_events) <= MAX_WATCH_EVENTS
                && after.binding().schema().admits(session.version())
        }
        NodeRequestBodyV1::RelistAssignments { binding } => {
            binding.coordinator_epoch() == session.coordinator_epoch()
                && binding.audience_digest() == session.audience_digest()
                && binding.disclosure_domain_digest() == session.disclosure_domain_digest()
                && binding.schema().admits(session.version())
        }
        NodeRequestBodyV1::GetCapabilities => true,
    }
}

/// Carries one response bound to its exact session and request.
#[cfg(feature = "multi-node")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeResponseEnvelopeV1 {
    context: AuthenticatedEvidenceContextV1,
    frame_seal: AuthenticatedFrameSealV1,
    binding: [u8; 32],
    node: NodeId,
    lineage: NodeBootLineageV1,
    request: OperationId,
    audience_digest: ObjectDigest,
    disclosure_domain_digest: ObjectDigest,
    canonical_body_digest: ObjectDigest,
    canonical_frame_digest: ObjectDigest,
    canonical_frame_bytes: u32,
    coordinator_epoch: u64,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    body: NodeResponseBodyV1,
}

#[cfg(feature = "multi-node")]
impl NodeResponseEnvelopeV1 {
    /// Constructs and validates one response to an exact request.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for session mismatch, method
    /// mismatch, cross-node content, or a noncanonical watch batch.
    pub(in crate::local_inventory) fn from_authenticated_carrier(
        grant: CarrierResponseGrantV1,
        request: &NodeRequestEnvelopeV1,
        canonical_frame: &CanonicalNodeFrameV1<'_>,
        authenticated_at_unix_seconds: u64,
        codec: &CanonicalNodeSemanticCodecV1,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        let (session, context, frame_seal) = grant.into_parts();
        let body =
            canonical_frame.decode_response_body(context, authenticated_at_unix_seconds, codec)?;
        let session_binding = session.binding();
        if request.binding() != &session_binding
            || request.node() != session.node()
            || request.audience_digest() != session.audience_digest()
            || request.disclosure_domain_digest() != session.disclosure_domain_digest()
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let canonical_frame_bytes = u32::try_from(canonical_frame.bytes().len())
            .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
        if canonical_frame.kind() != body.frame_kind()
            || canonical_frame.version() != session.version()
            || canonical_frame.binding_digest() != carrier_binding_digest(session.binding())
            || canonical_frame.audience_digest() != session.audience_digest()
            || canonical_frame.disclosure_domain_digest() != session.disclosure_domain_digest()
            || canonical_frame.request() != request.request()
            || canonical_frame_bytes > session.maximum_response_bytes()
            || !session.is_current_at(authenticated_at_unix_seconds)
            || context.node() != session.node()
            || context.lineage() != session.lineage()
            || context.audience_digest() != session.audience_digest()
            || context.disclosure_domain_digest() != session.disclosure_domain_digest()
            || context.carrier_binding_digest() != session.binding_digest()
            || context.canonical_frame_digest() != canonical_frame.frame_digest()
            || context.canonical_frame_bytes() != canonical_frame_bytes
            || context.replay_fence() != session.replay_fence()
            || !context.is_current_at(authenticated_at_unix_seconds)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        if request.body().method() != body.method() {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        }
        validate_response_body(&session, request.body(), &body)?;

        Ok(Self {
            context,
            frame_seal,
            binding: session_binding,
            node: session.node(),
            lineage: session.lineage(),
            request: request.request(),
            audience_digest: session.audience_digest(),
            disclosure_domain_digest: session.disclosure_domain_digest(),
            canonical_body_digest: canonical_frame.body_digest(),
            canonical_frame_digest: canonical_frame.frame_digest(),
            canonical_frame_bytes,
            coordinator_epoch: session.coordinator_epoch(),
            authenticated_at_unix_seconds,
            valid_until_unix_seconds: session.valid_until_unix_seconds(),
            body,
        })
    }

    pub(in crate::local_inventory) fn from_authenticated_generated_carrier(
        grant: CarrierResponseGrantV1,
        request: &NodeRequestEnvelopeV1,
        body: NodeResponseBodyV1,
        body_digest: ObjectDigest,
        carrier_digest: ObjectDigest,
        carrier_bytes: u32,
        authenticated_at_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeProtocol> {
        let (session, context, frame_seal) = grant.into_parts();
        if request.binding() != &session.binding()
            || request.node() != session.node()
            || request.audience_digest() != session.audience_digest()
            || request.disclosure_domain_digest() != session.disclosure_domain_digest()
            || carrier_bytes == 0
            || carrier_bytes > session.maximum_response_bytes()
            || context.canonical_frame_digest() != carrier_digest
            || context.canonical_frame_bytes() != carrier_bytes
            || context.node() != session.node()
            || context.lineage() != session.lineage()
            || context.audience_digest() != session.audience_digest()
            || context.disclosure_domain_digest() != session.disclosure_domain_digest()
            || context.carrier_binding_digest() != session.binding_digest()
            || context.replay_fence() != session.replay_fence()
            || !context.is_current_at(authenticated_at_unix_seconds)
            || !frame_seal.matches(body.frame_kind(), body_digest, context)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        if request.body().method() != body.method() {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        }
        validate_response_body(&session, request.body(), &body)?;
        Ok(Self {
            context,
            frame_seal,
            binding: session.binding(),
            node: session.node(),
            lineage: session.lineage(),
            request: request.request(),
            audience_digest: session.audience_digest(),
            disclosure_domain_digest: session.disclosure_domain_digest(),
            canonical_body_digest: body_digest,
            canonical_frame_digest: carrier_digest,
            canonical_frame_bytes: carrier_bytes,
            coordinator_epoch: session.coordinator_epoch(),
            authenticated_at_unix_seconds,
            valid_until_unix_seconds: session.valid_until_unix_seconds(),
            body,
        })
    }

    /// Returns the authenticated session binding.
    #[must_use]
    pub const fn binding(&self) -> &[u8; 32] {
        &self.binding
    }

    /// Returns the responding node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the echoed request correlation identity.
    #[must_use]
    pub const fn request(&self) -> OperationId {
        self.request
    }

    /// Returns the semantic response body.
    #[must_use]
    pub const fn body(&self) -> &NodeResponseBodyV1 {
        &self.body
    }

    /// Returns the canonical semantic response-body commitment.
    #[must_use]
    pub const fn canonical_body_digest(&self) -> ObjectDigest {
        self.canonical_body_digest
    }

    /// Returns the protected carrier context retained by this response.
    #[must_use]
    pub(in crate::local_inventory) const fn authenticated_context(
        &self,
    ) -> AuthenticatedEvidenceContextV1 {
        self.context
    }

    /// Returns the exact authenticated response-frame commitment.
    #[must_use]
    pub(in crate::local_inventory) const fn canonical_frame_digest(&self) -> ObjectDigest {
        self.canonical_frame_digest
    }

    /// Reports whether the response's authenticated interval covers `time`.
    #[must_use]
    pub(in crate::local_inventory) fn is_current_at(&self, time: u64) -> bool {
        time >= self.authenticated_at_unix_seconds && time <= self.valid_until_unix_seconds
    }

    /// Extracts carrier-validated capability evidence from this response.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::MethodMismatch`] for another body,
    /// or [`InvalidMultiNodeProtocol::Unspecified`] for a zero canonical digest.
    pub fn validated_capabilities(
        &self,
    ) -> Result<CarrierValidatedCapabilityObservationV1, InvalidMultiNodeProtocol> {
        let NodeResponseBodyV1::Capabilities(snapshot) = &self.body else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        CarrierValidatedCapabilityObservationV1::from_authenticated_carrier(
            (**snapshot).clone(),
            self.context,
            &self.frame_seal,
            self.canonical_body_digest,
        )
        .map_err(|_| InvalidMultiNodeProtocol::Unspecified)
    }

    /// Extracts a carrier-validated complete inventory from this response.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::MethodMismatch`] for another body,
    /// or [`InvalidMultiNodeProtocol::Unspecified`] for a zero canonical digest.
    pub fn validated_inventory(
        &self,
    ) -> Result<CarrierValidatedResyncInventoryV1, InvalidMultiNodeProtocol> {
        let NodeResponseBodyV1::AssignmentInventory(inventory) = &self.body else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        Ok(CarrierValidatedResyncInventoryV1 {
            inventory: (**inventory).clone(),
            audience_digest: self.audience_digest,
            disclosure_domain_digest: self.disclosure_domain_digest,
            carrier_binding_digest: carrier_binding_digest(self.binding),
            canonical_inventory_digest: self.canonical_frame_digest,
            canonical_frame_bytes: self.canonical_frame_bytes,
            coordinator_epoch: self.coordinator_epoch,
            authenticated_at_unix_seconds: self.authenticated_at_unix_seconds,
            valid_until_unix_seconds: self.valid_until_unix_seconds,
        })
    }

    /// Extracts one exact authenticated immutable chunk for the transfer reducer.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless request correlation, method,
    /// carrier context, scoped identity, length, and chunk digest all match.
    pub fn validated_snapshot_chunk(
        &self,
        request_envelope: &NodeRequestEnvelopeV1,
    ) -> Result<AuthenticatedSnapshotChunkV1, InvalidMultiNodeProtocol> {
        if request_envelope.request() != self.request
            || request_envelope.binding() != &self.binding
            || request_envelope.audience_digest() != self.audience_digest
            || request_envelope.disclosure_domain_digest() != self.disclosure_domain_digest
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let NodeRequestBodyV1::FetchSnapshotChunk { request } = request_envelope.body() else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        let NodeResponseBodyV1::SnapshotChunk {
            identity,
            index,
            bytes,
        } = &self.body
        else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        if identity != &request.identity() || *index != request.chunk().index() {
            return Err(InvalidMultiNodeProtocol::ResponseContentMismatch);
        }
        AuthenticatedSnapshotChunkV1::from_authenticated_carrier(
            *request,
            bytes.clone(),
            self.context,
            &self.frame_seal,
            self.canonical_body_digest,
            self.authenticated_at_unix_seconds,
        )
        .map_err(|_| InvalidMultiNodeProtocol::ResponseContentMismatch)
    }

    /// Extracts one exact authenticated immutable dependency range.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless request correlation, carrier
    /// context, transfer identity, descriptor, offset, and byte count all match.
    pub fn validated_snapshot_dependency_range(
        &self,
        request_envelope: &NodeRequestEnvelopeV1,
    ) -> Result<AuthenticatedSnapshotDependencyRangeV1, InvalidMultiNodeProtocol> {
        if request_envelope.request() != self.request
            || request_envelope.binding() != &self.binding
            || request_envelope.audience_digest() != self.audience_digest
            || request_envelope.disclosure_domain_digest() != self.disclosure_domain_digest
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let NodeRequestBodyV1::FetchSnapshotDependency { request } = request_envelope.body() else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        let NodeResponseBodyV1::SnapshotDependency {
            identity,
            dependency,
            offset,
            bytes,
        } = &self.body
        else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        if identity != &request.identity()
            || dependency != request.dependency()
            || *offset != request.offset()
            || bytes.len() != request.length() as usize
        {
            return Err(InvalidMultiNodeProtocol::ResponseContentMismatch);
        }
        AuthenticatedSnapshotDependencyRangeV1::from_authenticated_carrier(
            request.clone(),
            bytes.clone(),
            self.context,
            &self.frame_seal,
            self.canonical_body_digest,
            self.authenticated_at_unix_seconds,
        )
        .map_err(|_| InvalidMultiNodeProtocol::ResponseContentMismatch)
    }

    /// Extracts one carrier-validated capability event from a watch response.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol::MethodMismatch`] unless the indexed
    /// event is a capability event, or `Unspecified` for a zero commitment.
    pub fn validated_watch_capability(
        &self,
        event_index: usize,
    ) -> Result<CarrierValidatedCapabilityObservationV1, InvalidMultiNodeProtocol> {
        let NodeResponseBodyV1::WatchBatch { events, cursor_gap } = &self.body else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        if cursor_gap.is_some() {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
        }
        let Some(NodeWatchEventBodyV1::Capability(snapshot)) =
            events.get(event_index).map(NodeWatchEventV1::body)
        else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch);
        };
        CarrierValidatedCapabilityObservationV1::from_authenticated_carrier(
            (**snapshot).clone(),
            self.context,
            &self.frame_seal,
            self.canonical_body_digest,
        )
        .map_err(|_| InvalidMultiNodeProtocol::Unspecified)
    }
}

#[cfg(feature = "multi-node")]
pub(in crate::local_inventory) fn validate_response_body(
    session: &AuthenticatedNodeSessionV1,
    request: &NodeRequestBodyV1,
    response: &NodeResponseBodyV1,
) -> Result<(), InvalidMultiNodeProtocol> {
    let node = session.node();
    let content_matches_request = match response {
        NodeResponseBodyV1::Capabilities(snapshot) => {
            snapshot.node() == node && snapshot.lineage() == session.lineage()
        }
        NodeResponseBodyV1::Assignment(observation) => {
            let NodeRequestBodyV1::ReconcileAssignment(intent) = request else {
                return Err(InvalidMultiNodeProtocol::MethodMismatch);
            };
            observation.node() == node
                && observation.lineage() == session.lineage()
                && observation.matches(intent)
                && observation.desired_generation() <= intent.desired_generation()
        }
        NodeResponseBodyV1::AssignmentInventory(inventory) => {
            let NodeRequestBodyV1::RelistAssignments { binding } = request else {
                return Err(InvalidMultiNodeProtocol::MethodMismatch);
            };
            inventory.cursor().node() == node
                && inventory.cursor().lineage() == session.lineage()
                && inventory.cursor().binding() == *binding
                && binding.audience_digest() == session.audience_digest()
                && binding.disclosure_domain_digest() == session.disclosure_domain_digest()
        }
        NodeResponseBodyV1::Drain(observation) => {
            let NodeRequestBodyV1::ReconcileDrain(directive) = request else {
                return Err(InvalidMultiNodeProtocol::MethodMismatch);
            };
            observation.node() == node
                && observation.lineage() == session.lineage()
                && observation.matches(directive)
        }
        NodeResponseBodyV1::SnapshotTransferReady {
            identity,
            next_chunk,
        } => {
            let NodeRequestBodyV1::BeginSnapshotTransfer { manifest, resume } = request else {
                return Err(InvalidMultiNodeProtocol::MethodMismatch);
            };
            *identity == manifest.identity()
                && *next_chunk
                    == resume
                        .as_ref()
                        .map_or(0, |checkpoint| checkpoint.next_chunk())
        }
        NodeResponseBodyV1::SnapshotChunk {
            identity,
            index,
            bytes,
        } => {
            let NodeRequestBodyV1::FetchSnapshotChunk { request } = request else {
                return Err(InvalidMultiNodeProtocol::MethodMismatch);
            };
            identity == &request.identity()
                && *index == request.chunk().index()
                && request.chunk().verify_bytes(bytes).is_ok()
        }
        NodeResponseBodyV1::SnapshotDependency {
            identity,
            dependency,
            offset,
            bytes,
        } => {
            let NodeRequestBodyV1::FetchSnapshotDependency { request } = request else {
                return Err(InvalidMultiNodeProtocol::MethodMismatch);
            };
            identity == &request.identity()
                && dependency == request.dependency()
                && *offset == request.offset()
                && bytes.len() == request.length() as usize
        }
        NodeResponseBodyV1::WatchBatch { events, cursor_gap } => {
            let NodeRequestBodyV1::Watch {
                after,
                maximum_events,
            } = request
            else {
                return Err(InvalidMultiNodeProtocol::MethodMismatch);
            };
            if let Some(next_binding) = cursor_gap {
                events.is_empty()
                    && next_binding.coordinator_epoch() == session.coordinator_epoch()
                    && next_binding.query_digest() == after.binding().query_digest()
                    && next_binding.authorization_digest() == after.binding().authorization_digest()
                    && next_binding.schema() == after.binding().schema()
                    && next_binding.audience_digest() == session.audience_digest()
                    && next_binding.disclosure_domain_digest() == session.disclosure_domain_digest()
                    && next_binding.history_floor_sequence()
                        >= after.binding().history_floor_sequence()
                    && (next_binding.history_floor_sequence()
                        != after.binding().history_floor_sequence()
                        || next_binding.history_floor_event_uid()
                            == after.binding().history_floor_event_uid())
                    && next_binding.bootstrap_watermark() >= after.event_sequence()
                    && (*next_binding != after.binding()
                        || next_binding.bootstrap_watermark() > after.event_sequence())
            } else {
                events.len() <= usize::from(*maximum_events)
                    && events.len() <= MAX_WATCH_EVENTS
                    && events.iter().all(|event| event.cursor().node() == node)
                    && watch_events_follow(*after, events)
            }
        }
    };
    if content_matches_request {
        Ok(())
    } else if matches!(response, NodeResponseBodyV1::WatchBatch { .. }) {
        Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical)
    } else {
        Err(InvalidMultiNodeProtocol::ResponseContentMismatch)
    }
}

#[cfg(feature = "multi-node")]
fn watch_events_follow(after: NodeWatchCursorV1, events: &[NodeWatchEventV1]) -> bool {
    let mut previous = after;
    for event in events {
        let cursor = event.cursor();
        let Some(expected_sequence) = previous.event_sequence().checked_add(1) else {
            return false;
        };
        if cursor.node() != previous.node()
            || cursor.lineage() != previous.lineage()
            || cursor.binding() != previous.binding()
            || cursor.event_sequence() != expected_sequence
            || event.predecessor_event_uid() != previous.last_event_uid()
        {
            return false;
        }
        previous = cursor;
    }
    true
}
