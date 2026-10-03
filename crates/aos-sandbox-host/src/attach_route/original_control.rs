//! Held original route, assignment and exact monitor-control dispatch.
//!
//! Polling returns data only. An admitted control retains the same Host runtime
//! claim and exclusive route writer through reservation, Guest effect and final
//! receipt. Named-file checks are effect boundaries, not an atomic exclusion
//! fence against a separately privileged administrator replacing those names.

use aos_sandbox_agent::openssh_control::OpenSshControlRequestV5;
use aos_sandbox_agent::openssh_control_channel::{
    OriginalControlActionV5, OriginalControlPhaseV5, encode_original_control_request_v5,
    verify_original_control_response_v5,
};
use aos_sandbox_agent::openssh_ticket::{ticket_digest_v2, verify_ticket_gate_readback_v2};
use aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2;
use ed25519_dalek::VerifyingKey;

use super::{
    AgentFrameV1, DormantRuntimeExecutionClaimV1, GRANT_RESERVATION_PREFIX,
    HostOpenSshAttachRouteErrorV1 as Error, HostOpenSshAttachRouteEvidenceV1,
    HostOpenSshAttachRouteOwnerV1, JournalRecord, JournalTransaction, OpenSshGateAgentExchangeV1,
    OpenSshGateObserveRequestV1, OsRng, RecordNamespace, Sha256, VerifiedOwnershipLease,
    current_unix_seconds, decode_frame_v1, encode_frame_v1, evidence_from_protected,
    original_ticket_key_v2, read_protected_with_current_v3, route_transaction_id_v1,
    validate_deployment_trust, validate_grant_currentness_with_claim_v3,
    validate_held_route_names_v3, verify_openssh_gate_readback_v1, verify_readback_binding,
};
use rand::TryRngCore as _;
use sha2::Digest as _;

impl HostOpenSshAttachRouteOwnerV1 {
    /// Polls or applies exact original-monitor control under an admitted held cut.
    ///
    /// # Errors
    /// Rejects stale physical route names, assignment/lease/trust, expiry, ticket
    /// or request substitution, replay, invalid signed evidence or ambiguity.
    pub(crate) fn original_control_on_held_session_v5(
        &mut self,
        current: &DormantRuntimeExecutionClaimV1<'_>,
        lease: &VerifiedOwnershipLease,
        authority_expires_at: i64,
        effect_deadline_boottime_nanoseconds: u64,
        operation_id: [u8; 16],
        execution_id: [u8; 16],
        control: Option<(&[u8], [u8; 32], [u8; 32], &[u8])>,
        session_binding: [u8; 32],
        exchange: &mut impl OpenSshGateAgentExchangeV1,
    ) -> Result<HostOpenSshAttachRouteEvidenceV1, Error> {
        current.revalidate()?;
        let runtime = current.currentness().runtime().currentness();
        let mut authority = self
            .journal
            .claim_protected_authority(RecordNamespace::HostExecution)?;
        let protected = read_protected_with_current_v3(
            &authority,
            current,
            execution_id,
            *runtime.incarnation().as_bytes(),
            runtime.assignment_epoch().get(),
        )?;
        if protected.record.attach_operation_id != operation_id {
            return Err(Error::Stale);
        }
        let ticket_bytes = authority
            .get(&original_ticket_key_v2(execution_id))?
            .ok_or(Error::Missing)?
            .to_vec();
        let ticket =
            PublicAttachTicketBindingV2::decode(&ticket_bytes).map_err(|_| Error::Malformed)?;
        let grant = Self::verify_pending_grant(&ticket.pending_grant)?;
        validate_grant_currentness_with_claim_v3(&grant, lease, current)?;
        let now = u64::try_from(current_unix_seconds()?).map_err(|_| Error::Stale)?;
        let expiry = u64::try_from(authority_expires_at).map_err(|_| Error::Stale)?;
        if ticket.operation_id != operation_id
            || ticket.execution_id != execution_id
            || ticket.base_route_digest != protected.route_digest
            || ticket.valid_after > now
            || ticket.expires_at <= now
            || expiry <= now
            || expiry > ticket.expires_at
            || ticket.expires_at
                > u64::try_from(protected.record.expires_at).map_err(|_| Error::Stale)?
        {
            return Err(Error::Stale);
        }
        let digest = ticket_digest_v2(&ticket_bytes);
        let (action, binding, challenge, request) = match control {
            Some((supplied, binding, challenge, request))
                if supplied == ticket_bytes && binding != [0; 32] && challenge != [0; 32] =>
            {
                OpenSshControlRequestV5::decode(request).map_err(|_| Error::Malformed)?;
                (OriginalControlActionV5::Apply, binding, challenge, request)
            }
            Some(_) => return Err(Error::Stale),
            None => {
                let mut challenge = [0; 32];
                OsRng
                    .try_fill_bytes(&mut challenge)
                    .map_err(|_| Error::Entropy)?;
                if challenge == [0; 32] {
                    return Err(Error::Entropy);
                }
                (OriginalControlActionV5::Poll, [0; 32], challenge, &[][..])
            }
        };
        let mut grant_key = GRANT_RESERVATION_PREFIX.to_vec();
        grant_key.extend_from_slice(&operation_id);
        if authority.get(&grant_key)? != Some(Sha256::digest(ticket.pending_grant).as_slice()) {
            return Err(Error::GrantReused);
        }
        if action == OriginalControlActionV5::Apply {
            let sequence = OpenSshControlRequestV5::decode(request)
                .map_err(|_| Error::Malformed)?
                .sequence;
            let mut key = b"openssh-original-control-v5/".to_vec();
            key.extend_from_slice(&execution_id);
            key.extend_from_slice(&digest);
            key.extend_from_slice(&binding);
            key.extend_from_slice(&sequence.to_be_bytes());
            validate_held_route_names_v3(&authority)?;
            if authority.get(&key)?.is_some() {
                return Err(Error::GrantReused);
            }
            let mut marker = b"AOSHCM05".to_vec();
            for part in [
                digest.as_slice(),
                binding.as_slice(),
                challenge.as_slice(),
                request,
            ] {
                marker.extend_from_slice(part);
            }
            let transaction = JournalTransaction::new(
                route_transaction_id_v1(operation_id, &Sha256::digest(&marker))?,
                vec![JournalRecord::put(
                    RecordNamespace::HostExecution,
                    key.clone(),
                    marker.clone(),
                )],
            )?;
            authority.commit(&transaction)?;
            if authority.get(&key)? != Some(marker.as_slice()) {
                return Err(Error::Stale);
            }
        }
        let observe = OpenSshGateObserveRequestV1 {
            session_binding,
            challenge,
            route_digest: protected.route_digest,
            binding: protected.gate_binding(),
        };
        current.revalidate()?;
        validate_deployment_trust(&protected.record)?;
        let frame = encode_frame_v1(&AgentFrameV1::OriginalControlRequestV5(
            encode_original_control_request_v5(
                action,
                binding,
                request,
                authority_expires_at,
                effect_deadline_boottime_nanoseconds,
                &observe,
                &ticket_bytes,
            )?,
        ));
        validate_held_route_names_v3(&authority)?;
        let response = exchange.exchange(&frame)?;
        validate_held_route_names_v3(&authority)?;
        let AgentFrameV1::OriginalControlResponseV5(packet) = decode_frame_v1(&response)? else {
            return Err(Error::GateMismatch);
        };
        let agent_verifier = VerifyingKey::from_bytes(&current.agent_peer().public_key())
            .map_err(|_| Error::TrustUnavailable)?;
        let (observation, physical) =
            verify_original_control_response_v5(&packet, &agent_verifier)?;
        if action == OriginalControlActionV5::Apply
            && (observation.phase != OriginalControlPhaseV5::Applied
                || observation.binding != binding
                || observation.request != request)
        {
            return Err(Error::GateMismatch);
        }
        let (readback, measured, base) =
            verify_ticket_gate_readback_v2(physical, &current.agent_peer().public_key())?;
        if measured != digest {
            return Err(Error::GateMismatch);
        }
        verify_readback_binding(
            &protected,
            challenge,
            *current.agent_peer().channel_binding().as_bytes(),
            &readback,
        )?;
        let (_, commitment) =
            verify_openssh_gate_readback_v1(base, &current.agent_peer().public_key())?;
        current.revalidate()?;
        let latest = read_protected_with_current_v3(
            &authority,
            current,
            execution_id,
            protected.record.incarnation_id,
            protected.record.assignment_epoch,
        )?;
        if latest.route_digest != protected.route_digest
            || authority.get(&original_ticket_key_v2(execution_id))?
                != Some(ticket_bytes.as_slice())
        {
            return Err(Error::Stale);
        }
        let mut evidence = evidence_from_protected(latest, commitment, base);
        evidence.original_ticket_digest_v2 = Some(digest);
        evidence.signed_ticket_readback_v2 = physical.to_vec();
        evidence.original_session_observation_v5 = packet;
        Ok(evidence)
    }
}
