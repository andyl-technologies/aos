//! Borrows the genuine Controller resource and original Root profile for STATE.
//!
//! No public coordinates or durable DTO can open this flight. The callback
//! receives Policy comparison DATA only and returns unit diagnostics, so failed
//! postflight cannot discard an owning positive outcome. A real later E ingress
//! is still absent; this does not manufacture that producer or enable CONTINUE.

use aos_sandbox_core::{
    MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType, ProjectId, RawPairedClockSample,
    SandboxId,
};

use super::super::protected_journal::validated_candidate_body;
use super::ConsumerReadFlightErrorV1 as Error;
use super::transport::{Deadline, Flight};
use super::wire::{Correlation, Phase, STATE_PREFIX_BYTES, take};
use crate::attachment_effect_owner::CurrentControllerConsumerResourceV1;
use crate::normal_root::ProductionControllerNormalRootProfileV1;
use crate::ownership_authority::ProtectedOwnershipClockError;

/// Borrows canonical Policy comparison DATA received on the original flight.
///
/// This is not Root authentication, a read grant, a Source floor or a Ready
/// receipt. Its constructor is private and it cannot outlive the callback.
pub struct ConsumerReadPolicyStateV1<'state> {
    candidate: &'state [u8],
    current_envelope: ObjectDigest,
    candidate_envelope: ObjectDigest,
    generation: u64,
}

impl ConsumerReadPolicyStateV1<'_> {
    /// Borrows exact canonical Candidate bytes for later independent joins.
    #[must_use]
    pub const fn candidate_bytes(&self) -> &[u8] {
        self.candidate
    }

    /// Returns Current/Candidate envelope commitments, not authenticated heads.
    #[must_use]
    pub const fn envelopes(&self) -> (ObjectDigest, ObjectDigest) {
        (self.current_envelope, self.candidate_envelope)
    }

    /// Returns the structurally compared publication generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Holds one PRE-ROOT state-first flight under actually retained preparation.
///
/// The original Controller writer/profile remain borrowed through callback and
/// terminal ACK/EOF. No initiating Attach/public-cap expiry is reused. The
/// callback must not reacquire Controller/Policy and returns no owning result.
/// This function always ABORTs after comparison; it grants no read or cleanup.
/// Caller must retain/quarantine the real local preparation on every outcome.
///
/// # Errors
///
/// Rejects absent/failed/quarantined preparation, changed current resources or
/// named/profile custody, original peer/subjects, expiry, framing or Policy
/// mismatch. Failure cannot be retried on another endpoint within this flight.
pub fn with_consumer_read_policy_state_v1<T>(
    resource: &mut CurrentControllerConsumerResourceV1<'_>,
    profile: &ProductionControllerNormalRootProfileV1,
    clock: &mut T,
    action: impl for<'state> FnOnce(&ConsumerReadPolicyStateV1<'state>),
) -> Result<(), Error>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let (project, sandbox, cutoff) = resource.begin_pre_root_policy_flight(clock)?;
    let accepted = resource.accepted_policy().clone();
    let deadline = Deadline::capture(cutoff)?;
    profile.recheck()?;
    deadline.require_current()?;
    let nonce = super::super::controller_readback_session::fresh_root_nonce()?;
    let correlation = Correlation::from_bootstrap(
        &Correlation {
            nonce,
            deadline: cutoff,
        }
        .bootstrap(),
    )?;
    let mut flight = Flight::connect(correlation, deadline)?;
    let peer = profile.observe_original_peer(flight.stream())?;
    deadline.require_current()?;
    let mut check =
        |stream: &_, chunk: Option<&aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk>| {
            resource.prepared_policy_selector(clock)?;
            match chunk {
                Some(chunk) => peer.require_chunk(stream, chunk)?,
                None => peer.recheck_stream(stream)?,
            }
            Ok(())
        };
    flight.write(&correlation.bootstrap(), &mut check)?;
    let (phase, length) = flight.header(&mut check)?;
    if phase != Phase::Hello {
        return Err(Error::Protocol);
    }
    if flight.read_exact(length, &mut check)?.as_slice() != deadline.boot() {
        return Err(Error::Protocol);
    }
    let mut select = [0; 32];
    select[..16].copy_from_slice(project.as_bytes());
    select[16..].copy_from_slice(sandbox.as_bytes());
    flight.send_header(Phase::Select, select.len(), &mut check)?;
    flight.write(&select, &mut check)?;
    let (phase, length) = flight.header(&mut check)?;
    if phase != Phase::State {
        return Err(Error::Protocol);
    }
    let state_bytes = flight.read_exact(length, &mut check)?;
    let state = decode_state(&state_bytes, project, sandbox, &accepted)?;
    flight.checked(&mut check, None)?;
    action(&state);
    flight.checked(&mut check, None)?;
    flight.send_header(Phase::Abort, 0, &mut check)?;
    flight.finish_sending()?;
    if flight.header(&mut check)? != (Phase::Aborted, 0) {
        return Err(Error::Protocol);
    }
    flight.require_eof(&mut check)
}

fn decode_state<'state>(
    bytes: &'state [u8],
    project: ProjectId,
    sandbox: SandboxId,
    accepted: &ObjectDescriptor,
) -> Result<ConsumerReadPolicyStateV1<'state>, Error> {
    let length = u32::from_be_bytes(take(bytes, 72)?) as usize;
    if STATE_PREFIX_BYTES.checked_add(length) != Some(bytes.len()) {
        return Err(Error::Protocol);
    }
    let candidate = bytes.get(STATE_PREFIX_BYTES..).ok_or(Error::Protocol)?;
    let (header, _) = validated_candidate_body(candidate)?;
    let generation = u64::from_be_bytes(take(bytes, 64)?);
    let output = ObjectDescriptor::new(
        MediaType::new(PortableMediaType::Policy.as_str()).map_err(|_| Error::Protocol)?,
        header.outputs[0].0,
        header.outputs[0].1,
    );
    let current: [u8; 32] = take(bytes, 0)?;
    let envelope: [u8; 32] = take(bytes, 32)?;
    if current == [0; 32]
        || envelope == [0; 32]
        || generation == 0
        || header.project != project
        || header.sandbox != sandbox
        || header.generation != generation
        || &output != accepted
    {
        return Err(Error::Protocol);
    }
    Ok(ConsumerReadPolicyStateV1 {
        candidate,
        generation,
        current_envelope: ObjectDigest::from_bytes(current),
        candidate_envelope: ObjectDigest::from_bytes(envelope),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_compiler::protected_journal::resolved_policy_fixture as fixture;
    use crate::policy_compiler::resolved_policy::tests::{commit_fixture, open};
    use aos_sandbox_core::model::CacheDomainKind;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn state_reuses_actual_canonical_claim_and_accepted_policy_for_every_domain() {
        let mut publications = [
            CacheDomainKind::Private,
            CacheDomainKind::TrustDomain,
            CacheDomainKind::Public,
            CacheDomainKind::Project,
        ]
        .into_iter()
        .map(fixture::publication)
        .collect::<Vec<_>>();
        publications.push(fixture::compiled_publication());
        for publication in publications {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let mut owner = open(root.path());
            commit_fixture(&mut owner, &publication);
            owner
                .with_current_policy_claim(publication.project, publication.sandbox, |claim| {
                    let (current, envelope) = claim.envelopes();
                    let mut state = Vec::new();
                    state.extend_from_slice(current.as_bytes());
                    state.extend_from_slice(envelope.as_bytes());
                    state.extend_from_slice(&claim.candidate().1.to_be_bytes());
                    state.extend_from_slice(&(claim.candidate_bytes().len() as u32).to_be_bytes());
                    state.extend_from_slice(claim.candidate_bytes());
                    let decoded = decode_state(
                        &state,
                        publication.project,
                        publication.sandbox,
                        claim.policy_descriptor(),
                    )
                    .unwrap();
                    assert_eq!(decoded.candidate_bytes(), claim.candidate_bytes());
                    assert_eq!(decoded.envelopes(), claim.envelopes());
                    assert_eq!(decoded.generation(), claim.candidate().1);
                    for offset in [64, 72, state.len() - 1] {
                        let mut altered = state.clone();
                        altered[offset] ^= 1;
                        assert!(
                            decode_state(
                                &altered,
                                publication.project,
                                publication.sandbox,
                                claim.policy_descriptor()
                            )
                            .is_err()
                        );
                    }
                    let mut trailing = state.clone();
                    trailing.push(0);
                    assert!(
                        decode_state(
                            &trailing,
                            publication.project,
                            publication.sandbox,
                            claim.policy_descriptor()
                        )
                        .is_err()
                    );
                    assert!(
                        decode_state(
                            &state[..state.len() - 1],
                            publication.project,
                            publication.sandbox,
                            claim.policy_descriptor()
                        )
                        .is_err()
                    );
                    assert!(
                        decode_state(
                            &state,
                            ProjectId::from_bytes([90; 16]),
                            publication.sandbox,
                            claim.policy_descriptor()
                        )
                        .is_err()
                    );
                    assert!(
                        decode_state(
                            &state,
                            publication.project,
                            SandboxId::from_bytes([91; 16]),
                            claim.policy_descriptor()
                        )
                        .is_err()
                    );
                    let foreign = ObjectDescriptor::new(
                        claim.policy_descriptor().media_type().clone(),
                        ObjectDigest::from_bytes([92; 32]),
                        claim.policy_descriptor().encoded_size(),
                    );
                    assert!(
                        decode_state(&state, publication.project, publication.sandbox, &foreign)
                            .is_err()
                    );
                })
                .unwrap();
        }
    }
}
