//! Original-flight sealed-plan issuance and genuine four-owner Host dispatch.
//!
//! ```text
//! AOSFWH02 | original FUSE binding header(version=2) | method=49/purpose=56 |
//! Host1.0/RootMount | exact worker-feature1.0 | payload-size:u32be | payload
//! kind1 payload = body-size:u32be | exact canonical49 body | sealed plan[328]
//! kind2 payload = exact signed49 envelope including four-role table/quartet
//! ```
//!
//! Old AOSFWH01 worker HELLO and presentation-plan reservation ACK are unchanged.
//! These control bytes do not mint Mount/Root read authority or prove copy
//! closure. Both local producers remain borrowed throughout signing and send.

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, BrokerRequestEnvelope, PrepareHostFuseWorkerSessionRequestV1,
};
use aos_sandbox_core::HOST_FUSE_WORKER_SESSION_FEATURE_NAMESPACE;
use aos_sandbox_protocol::fuse_worker_preparation::{
    WORKER_PREPARATION_PLAN_BYTES_V1, WorkerPreparationPlanV1,
};
use buffa::Message as _;

use super::*;
use crate::controller_plan_signer::ControllerBrokerPlanSignerV1;
use crate::dormant_handshake::{
    DormantAuthenticatedBrokerSessionV1 as HostSession,
    DormantBrokerDescriptorRequestPreparationV1, DormantBrokerDescriptorRequestSendProgressV1,
};

const WORKER_MAGIC: &[u8; 8] = b"AOSFWH02";
const CONTRACT: &[u8] = &[0, 49, 0, 0, 0, 56, 0, 1, 0, 0, 0, 5];
const MAXIMUM_WORKER_CONTROL: usize = 1024 * 1024;

/// Retains real durable/send recovery without claiming live worker authority.
pub(crate) enum OriginalMountHostWorkerDispatchV1 {
    Durability(DormantBrokerDescriptorRequestPreparationV1),
    Transport(DormantBrokerDescriptorRequestSendProgressV1),
}

impl HeldFuseIntentTransportV1<'_> {
    /// Signs once from the same live Controller and original per-record Mount flight.
    pub(crate) fn issue_original_host_worker<T>(
        &mut self,
        controller: &mut CurrentControllerFuseIntentDispatchV1<'_>,
        signer: &ControllerBrokerPlanSignerV1,
        clock: &mut T,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        // A signed RootMount role and a live transcript do not select the
        // fixed service. Retain its actual verifier before accepting any
        // reservation/proposal; every later retry and wait rechecks it.
        self.retain_controller_worker_mount_peer()?;
        self.require_worker_feature()?;
        // This is the actual original reservation/ACK, not adoption of a row.
        self.receive_worker_reservation(controller, clock)?;
        let coordinates = self.prepared_coordinates()?;
        self.stage = Stage::WorkerIssuance(coordinates);
        let payload = self.receive_worker_frame(1)?;
        let (body, plan) = decode_worker_proposal(&payload)?;
        if plan.worker_instance != coordinates.worker_locator
            || plan.mount_reservation != coordinates.reservation_digest
            || plan.controller_request != self.request.signed_request_digest()
            || plan.preparation_deadline_boottime_ns != self.binding.deadline
        {
            self.stage = Stage::ReconciliationRequired;
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        let envelope = signer
            .sign_original_host_worker(controller, self, body, &plan, clock)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        self.recheck()?;
        self.send_worker_frame(2, &envelope.encode_to_vec())?;
        self.stage = Stage::WorkerDispatched(coordinates);
        controller
            .recheck(clock)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        self.recheck()?;
        Ok(())
    }

    fn receive_worker_reservation<T>(
        &mut self,
        controller: &mut CurrentControllerFuseIntentDispatchV1<'_>,
        clock: &mut T,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        loop {
            controller
                .recheck(clock)
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
            match self.receive_preparation_control() {
                Ok(()) => break,
                Err(DormantBrokerSessionHandshakeErrorV1::Transport) => {
                    self.wait_original_socket(false)?
                }
                Err(error) => return Err(error),
            }
        }
        loop {
            controller
                .recheck(clock)
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
            match self.send_preparation_control() {
                Ok(()) => return Ok(()),
                Err(DormantBrokerSessionHandshakeErrorV1::Transport) => {
                    self.wait_original_socket(true)?
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Sends only internally created roles while retaining the actual Mount owner.
    pub(crate) fn dispatch_original_host_worker<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        handoff: &mut aos_sandbox_mount::broker::PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        host: &mut HostSession,
    ) -> Result<OriginalMountHostWorkerDispatchV1, DormantBrokerSessionHandshakeErrorV1> {
        self.require_worker_feature()?;
        self.recheck()?;
        handoff
            .recheck()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let coordinates = self.prepared_coordinates()?;
        let worker = handoff.plan().clone();
        if worker.worker_instance != coordinates.worker_locator
            || worker.mount_reservation != coordinates.reservation_digest
            || worker.controller_request != self.request.signed_request_digest()
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        let method = BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1;
        let host_coordinates =
            host.original_worker_request_coordinates(worker.preparation_deadline_boottime_ns)?;
        let intent = decode_fuse_reserve_intent_request_v1(
            self.request.exact_body(),
            self.request.peer(),
            self.request.peer_policy(),
            crate::handshake::protected_boottime_nanoseconds()?,
        )
        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        let fence = intent.fence();
        let body = PrepareHostFuseWorkerSessionRequestV1 {
            header: Some(host_coordinates.request_header()).into(),
            fence: Some(AssignmentFence {
                sandbox_id: fence.sandbox_id().to_vec(),
                incarnation_id: fence.incarnation_id().to_vec(),
                assignment_epoch: fence.assignment_epoch(),
                desired_generation: fence.desired_generation(),
                assignment_digest: fence.assignment_digest().to_vec(),
                ..Default::default()
            })
            .into(),
            worker_instance_id: worker.worker_instance.to_vec(),
            preparation_plan_digest: worker
                .digest()
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?
                .to_vec(),
            mount_reservation_commitment: worker.mount_reservation.to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        let payload = encode_worker_proposal(&body, &worker)?;
        self.stage = Stage::WorkerIssuance(coordinates);
        self.send_worker_frame(1, &payload)?;
        let signed = self.receive_worker_frame(2)?;
        let envelope = BrokerRequestEnvelope::decode_from_slice(&signed)
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        if !envelope.__buffa_unknown_fields.is_empty()
            || envelope.encode_to_vec() != signed
            || envelope.method.as_known() != Some(method)
            || envelope.body != body
        {
            self.stage = Stage::ReconciliationRequired;
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        handoff
            .recheck()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        self.recheck()?;
        let progress =
            host.prepare_and_send_original_worker(handoff, envelope, host_coordinates)?;
        self.stage = Stage::WorkerDispatched(coordinates);
        handoff
            .recheck()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
        self.recheck()?;
        Ok(progress)
    }

    fn send_worker_frame(
        &mut self,
        kind: u8,
        payload: &[u8],
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.require_worker_feature()?;
        let frame = encode_worker_frame(self.binding, kind, payload)?;
        loop {
            self.recheck()?;
            match self.session.send_request_packet(&frame) {
                Ok(()) => {
                    self.recheck()?;
                    return Ok(());
                }
                Err(super::super::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                    self.wait_original_socket(true)?
                }
                Err(error) => {
                    self.stage = Stage::ReconciliationRequired;
                    return Err(error.into());
                }
            }
        }
    }

    fn receive_worker_frame(
        &mut self,
        kind: u8,
    ) -> Result<Vec<u8>, DormantBrokerSessionHandshakeErrorV1> {
        self.require_worker_feature()?;
        loop {
            self.recheck()?;
            match self.session.receive_response_packet(MAXIMUM_WORKER_CONTROL) {
                Ok(frame) => {
                    let (binding, payload) = decode_worker_frame(&frame, kind)?;
                    if binding != self.binding {
                        self.stage = Stage::ReconciliationRequired;
                        return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
                    }
                    self.recheck()?;
                    return Ok(payload.to_vec());
                }
                Err(super::super::DormantBrokerSessionHandshakeErrorV1::Transport) => {
                    self.wait_original_socket(false)?
                }
                Err(error) => {
                    self.stage = Stage::ReconciliationRequired;
                    return Err(error.into());
                }
            }
        }
    }

    fn require_worker_feature(&mut self) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.recheck()?;
        if !worker_features_selected(
            self.session.transcript.required_features(),
            self.session.transcript.advertised_features(),
        ) {
            self.stage = Stage::ReconciliationRequired;
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        Ok(())
    }

    /// Borrows only the actual Controller-side issuance phase, never a decoded row.
    pub(crate) fn recheck_worker_issuance(
        &mut self,
        worker: &WorkerPreparationPlanV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.worker_mount_verifier.is_none() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.recheck()?;
        let Stage::WorkerIssuance(coordinates) = self.stage else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        let authorization = self
            .request
            .authorization()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let presentation_type = aos_sandbox_core::MediaType::new(
            aos_sandbox_core::PortableMediaType::BrokerAuthorizationPlan
                .as_str()
                .to_owned(),
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let presentation =
            aos_sandbox_core::descriptor_for_bytes(presentation_type, authorization.broker_plan());
        if self.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || coordinates.presentation_plan_digest != *presentation.digest().as_bytes()
            || worker.worker_instance != coordinates.worker_locator
            || worker.mount_reservation != coordinates.reservation_digest
            || worker.controller_request != self.request.signed_request_digest()
            || worker.preparation_deadline_boottime_ns != self.binding.deadline
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    fn retain_controller_worker_mount_peer(
        &mut self,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        let result = (|| {
            if self.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
                || self.worker_mount_verifier.is_some()
            {
                return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
            }
            self.worker_mount_verifier =
                Some(controller_worker_mount_verifier(&self.session.socket)?);
            self.recheck()?;
            Ok(())
        })();
        if result.is_err() {
            self.stage = Stage::ReconciliationRequired;
        }
        result
    }
}

// Takes only the retained original socket, never RootMount claims in a body.
// The returned verifier retains the fixed cgroup root; pending-head rechecks
// repeat its actual service/pidfd membership proof throughout issuance.
fn controller_worker_mount_verifier(
    socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
) -> Result<aos_sandbox_host::peer::ControllerPeerVerifier, DormantBrokerSessionHandshakeErrorV1> {
    let verifier = super::super::fixed_mount_peer_verifier()?;
    verifier
        .verify_mount_broker(socket.peer())
        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
    Ok(verifier)
}

fn worker_features_selected(
    required: &[aos_sandbox_core::FeatureRef],
    advertised: &[aos_sandbox_core::FeatureRef],
) -> bool {
    let selected = |features: &[aos_sandbox_core::FeatureRef]| {
        features.iter().any(|feature| {
            feature.namespace() == HOST_FUSE_WORKER_SESSION_FEATURE_NAMESPACE
                && feature.major() == 1
                && feature.minor() == 0
        })
    };
    selected(required) && selected(advertised)
}

#[cfg(all(test, feature = "kernel-tests"))]
mod kernel_peer_tests {
    use super::*;

    #[test]
    fn controller_worker_issuer_rejects_a_live_peer_outside_fixed_mount_service() {
        // The kernel fixture runs outside aos-sandbox-mountd.service. It calls
        // the real issuer's initial gate with an original socket/pidfd, not
        // decoded credentials or a structural RootMount role. A full signed
        // pending flight and migration-between-effects remain installed tests.
        let (socket, _endpoint) =
            aos_sandbox_linux::seqpacket::SeqpacketSocket::pair_with_record_subjects().unwrap();
        assert!(socket.peer().is_alive().unwrap());
        assert_eq!(socket.peer().credentials().uid(), 0);
        assert_eq!(socket.peer().credentials().gid(), 0);

        assert!(controller_worker_mount_verifier(&socket).is_err());
        assert!(controller_worker_mount_verifier(&socket).is_err());

        assert!(socket.peer().is_alive().unwrap());
    }
}

fn encode_worker_frame(
    binding: Binding,
    kind: u8,
    payload: &[u8],
) -> Result<Vec<u8>, DormantBrokerSessionHandshakeErrorV1> {
    let feature = HOST_FUSE_WORKER_SESSION_FEATURE_NAMESPACE.as_bytes();
    if !matches!(kind, 1 | 2) || payload.is_empty() || payload.len() > MAXIMUM_WORKER_CONTROL / 2 {
        return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
    }
    let mut bytes = encode_binding_header(binding, WORKER_MAGIC, kind);
    bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
    bytes.extend_from_slice(CONTRACT);
    bytes.extend_from_slice(&(feature.len() as u16).to_be_bytes());
    bytes.extend_from_slice(feature);
    bytes.extend_from_slice(&[0, 1, 0, 0]);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn decode_worker_frame(
    bytes: &[u8],
    kind: u8,
) -> Result<(Binding, &[u8]), DormantBrokerSessionHandshakeErrorV1> {
    let feature = HOST_FUSE_WORKER_SESSION_FEATURE_NAMESPACE.as_bytes();
    let offset = HEADER_BYTES + CONTRACT.len() + 2 + feature.len() + 4;
    let invalid = || DormantBrokerSessionHandshakeErrorV1::RemoteInvalid;
    if bytes.len() <= offset + 4
        || bytes.len() > MAXIMUM_WORKER_CONTROL
        || bytes[10] != kind
        || bytes.get(HEADER_BYTES..HEADER_BYTES + CONTRACT.len()) != Some(CONTRACT)
        || bytes.get(HEADER_BYTES + CONTRACT.len()..offset)
            != Some(
                [
                    &(feature.len() as u16).to_be_bytes()[..],
                    feature,
                    &[0, 1, 0, 0],
                ]
                .concat()
                .as_slice(),
            )
    {
        return Err(invalid());
    }
    let binding = decode_binding_header_version(bytes, WORKER_MAGIC, 2)?;
    let length = u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .map_err(|_| invalid())?,
    ) as usize;
    if length == 0 || length > MAXIMUM_WORKER_CONTROL / 2 || length != bytes.len() - offset - 4 {
        return Err(invalid());
    }
    Ok((binding, &bytes[offset + 4..]))
}

fn encode_worker_proposal(
    body: &[u8],
    plan: &WorkerPreparationPlanV1,
) -> Result<Vec<u8>, DormantBrokerSessionHandshakeErrorV1> {
    let mut payload = (body.len() as u32).to_be_bytes().to_vec();
    payload.extend_from_slice(body);
    payload.extend_from_slice(
        &plan
            .encode()
            .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?,
    );
    decode_worker_proposal(&payload)?;
    Ok(payload)
}

fn decode_worker_proposal(
    bytes: &[u8],
) -> Result<(&[u8], WorkerPreparationPlanV1), DormantBrokerSessionHandshakeErrorV1> {
    let invalid = || DormantBrokerSessionHandshakeErrorV1::RemoteInvalid;
    if bytes.len() <= 4 + WORKER_PREPARATION_PLAN_BYTES_V1 {
        return Err(invalid());
    }
    let length = u32::from_be_bytes(bytes[..4].try_into().map_err(|_| invalid())?) as usize;
    if !(1..=4096).contains(&length) || bytes.len() != 4 + length + WORKER_PREPARATION_PLAN_BYTES_V1
    {
        return Err(invalid());
    }
    let plan = WorkerPreparationPlanV1::decode(&bytes[4 + length..]).map_err(|_| invalid())?;
    Ok((&bytes[4..4 + length], plan))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Binding {
        Binding {
            deadline: 100,
            session: [1; 32],
            signed_request: [2; 32],
            semantics: [3; 32],
            challenge: [4; 32],
        }
    }

    fn plan() -> WorkerPreparationPlanV1 {
        WorkerPreparationPlanV1 {
            worker_instance: [1; 16],
            kernel_boot: [2; 16],
            challenge: [3; 32],
            controller_request: [4; 32],
            mount_reservation: [5; 32],
            assignment: [6; 32],
            attachment: [7; 32],
            original_view_descriptor: [8; 32],
            resolved_policy_descriptor: [9; 32],
            mount_slot: [10; 32],
            ownership_lease: [11; 16],
            ownership_lease_expires_boottime_ns: 200,
            preparation_deadline_boottime_ns: 100,
        }
    }

    #[test]
    fn sealed_plan_control_is_not_hello_or_presentation_ack() {
        // This test covers framing only, never a held Mount/Controller issuer.
        let exact = encode_worker_frame(binding(), 1, b"proposal").unwrap();
        assert_eq!(
            decode_worker_frame(&exact, 1).unwrap(),
            (binding(), &b"proposal"[..])
        );
        assert!(decode(&exact).is_err());
        assert!(decode_worker_frame(&plan().hello().unwrap(), 1).is_err());
        let old = encode(
            binding(),
            Control::ReservationAcknowledgement(FuseIntentReservationCoordinatesV1 {
                worker_locator: [1; 16],
                reservation_digest: [2; 32],
                presentation_plan_digest: [3; 32],
            }),
        );
        assert_eq!(&old[..10], b"AOSFIC01\0\x01");
        assert!(decode_worker_frame(&old, 1).is_err());
        assert!(decode_worker_frame(&exact, 2).is_err());
    }

    #[test]
    fn worker_control_version_profile_feature_and_complete_payload_are_closed() {
        let exact = encode_worker_frame(binding(), 1, b"proposal").unwrap();
        for offset in [
            0,
            8,
            11,
            12,
            14,
            18,
            HEADER_BYTES,
            HEADER_BYTES + CONTRACT.len(),
            HEADER_BYTES + CONTRACT.len() + 2,
        ] {
            let mut changed = exact.clone();
            changed[offset] ^= 1;
            assert!(
                decode_worker_frame(&changed, 1).is_err(),
                "profile offset {offset}"
            );
        }
        let mut trailing = exact.clone();
        trailing.push(0);
        assert!(decode_worker_frame(&trailing, 1).is_err());
        for length in [0, 10, HEADER_BYTES, exact.len() - 1] {
            assert!(decode_worker_frame(&exact[..length], 1).is_err());
        }
    }

    #[test]
    fn proposal_retains_all_328_sealed_plan_bytes_and_no_trailing_data() {
        let original = plan();
        let exact = encode_worker_proposal(b"body", &original).unwrap();
        assert_eq!(
            decode_worker_proposal(&exact).unwrap(),
            (&b"body"[..], original)
        );
        let mut trailing = exact.clone();
        trailing.push(0);
        assert!(decode_worker_proposal(&trailing).is_err());
        assert!(decode_worker_proposal(&exact[..exact.len() - 1]).is_err());
        let mut wrong_count = exact;
        wrong_count[..4].copy_from_slice(&4097_u32.to_be_bytes());
        assert!(decode_worker_proposal(&wrong_count).is_err());
    }

    #[test]
    fn signing_or_dispatch_cannot_reenter_old_preparation_controls() {
        let coordinates = FuseIntentReservationCoordinatesV1 {
            worker_locator: [1; 16],
            reservation_digest: [2; 32],
            presentation_plan_digest: [3; 32],
        };
        for stage in [
            Stage::WorkerIssuance(coordinates),
            Stage::WorkerDispatched(coordinates),
        ] {
            assert!(
                next_control_stage(stage, Control::ReservationAcknowledgement(coordinates))
                    .is_err()
            );
            assert!(next_control_stage(stage, Control::HeldAcknowledgement).is_err());
        }
    }

    #[test]
    fn literal_frame_feature_never_substitutes_signed_peer_negotiation() {
        let exact = vec![
            aos_sandbox_core::FeatureRef::new(HOST_FUSE_WORKER_SESSION_FEATURE_NAMESPACE, 1, 0)
                .unwrap(),
        ];
        assert!(worker_features_selected(&exact, &exact));
        assert!(!worker_features_selected(&[], &exact));
        assert!(!worker_features_selected(&exact, &[]));
        let wrong = vec![
            aos_sandbox_core::FeatureRef::new(HOST_FUSE_WORKER_SESSION_FEATURE_NAMESPACE, 1, 1)
                .unwrap(),
        ];
        assert!(!worker_features_selected(&wrong, &exact));
        assert!(!worker_features_selected(&exact, &wrong));
    }
}
