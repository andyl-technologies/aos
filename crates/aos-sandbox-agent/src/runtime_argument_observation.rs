//! Guest-measured, signed runtime argument-limit readback.
//!
//! The provisioned Guest agent alone measures `_SC_ARG_MAX`; the Host supplies
//! a fresh challenge and the profile it expects, then verifies the response
//! against its protected current runtime and agent-key custody. This packet
//! does not prove that a later exec child retains the same stack limit.
//!
//! ```text
//! AOSARQ01 || runtime[104] || session[32] || channel[32] || challenge[32]
//!          || profile-length:u8 || profile || major:u32be || minor:u32be
//!          || profile-commitment[32]
//! AOSARP01 || request-length:u16be || canonical-request || arg-max:u64be
//!          || Ed25519(domain || preceding-readback-bytes)[64]
//! ```

use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, ExecutionRuntimeArgumentLimitV1, ExecutionTargetV1,
    FeatureRef, IncarnationId, NamespaceGeneration, ObjectDigest, PayloadBootId, SandboxId,
    validate_required_features,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::model::{AgentRuntimeBindingV1, AgentSessionBindingV1};
use crate::protected_entry::encode_agent_runtime_binding_v1;

/// Versioned request prefix accepted by the provisioned Guest agent.
pub const ARGUMENT_OBSERVE_REQUEST_MAGIC_V1: &[u8; 8] = b"AOSARQ01";
const READBACK_MAGIC: &[u8; 8] = b"AOSARP01";
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.guest-argument-readback.v1\0";
const MAXIMUM_REQUEST_BYTES: usize = 512;
const MAXIMUM_READBACK_BYTES: usize = MAXIMUM_REQUEST_BYTES + 82;

/// Reports a malformed, unauthenticated, or unavailable Guest measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GuestRuntimeArgumentObservationErrorV1 {
    /// Request or response bytes are invalid or exceed the closed bound.
    #[error("Guest argument-limit packet is invalid")]
    InvalidPacket,
    /// The profile or target cannot form a canonical v1 evidence value.
    #[error("Guest argument-limit profile is invalid")]
    InvalidProfile,
    /// The packet differs from the Host's exact current challenge and runtime.
    #[error("Guest argument-limit request is not current")]
    CurrentMismatch,
    /// The Guest signature does not match the trusted protected agent key.
    #[error("Guest argument-limit signature is invalid")]
    InvalidSignature,
    /// The Guest could not obtain a positive kernel `ARG_MAX` observation.
    #[error("Guest argument limit is unavailable")]
    MeasurementUnavailable,
}

/// Binds one Host challenge to its expected protected Guest runtime and profile.
///
/// Construction is nonauthorizing. The Host must obtain every field from its
/// current protected owner and retain the challenge until signed readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestRuntimeArgumentObserveRequestV1 {
    runtime: AgentRuntimeBindingV1,
    session: AgentSessionBindingV1,
    channel: ObjectDigest,
    challenge: [u8; 32],
    profile: FeatureRef,
    profile_commitment: ObjectDigest,
}

impl GuestRuntimeArgumentObserveRequestV1 {
    /// Constructs a bounded exact-runtime argument-limit challenge.
    ///
    /// # Errors
    ///
    /// Returns [`GuestRuntimeArgumentObservationErrorV1`] for sentinel fields,
    /// an unknown runtime feature, or an invalid profile commitment.
    pub fn new(
        runtime: AgentRuntimeBindingV1,
        session: AgentSessionBindingV1,
        channel: ObjectDigest,
        challenge: [u8; 32],
        profile: FeatureRef,
        profile_commitment: ObjectDigest,
    ) -> Result<Self, GuestRuntimeArgumentObservationErrorV1> {
        if channel.as_bytes() == &[0; 32]
            || challenge == [0; 32]
            || profile_commitment.as_bytes() == &[0; 32]
            || !profile.namespace().starts_with("aos.sandbox.runtime.")
            || validate_required_features(std::slice::from_ref(&profile)).is_err()
        {
            return Err(GuestRuntimeArgumentObservationErrorV1::InvalidProfile);
        }
        Ok(Self {
            runtime,
            session,
            channel,
            challenge,
            profile,
            profile_commitment,
        })
    }

    /// Borrows the exact runtime whose Guest agent must perform the measurement.
    #[must_use]
    pub const fn runtime(&self) -> &AgentRuntimeBindingV1 {
        &self.runtime
    }

    /// Returns the authenticated agent session expected by the Host.
    #[must_use]
    pub const fn session(&self) -> AgentSessionBindingV1 {
        self.session
    }

    /// Returns the exact Host/Guest channel commitment.
    #[must_use]
    pub const fn channel(&self) -> ObjectDigest {
        self.channel
    }

    /// Encodes the canonical bounded request sent on the Guest seqpacket channel.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(249 + self.profile.namespace().len());
        bytes.extend_from_slice(ARGUMENT_OBSERVE_REQUEST_MAGIC_V1);
        bytes.extend_from_slice(&encode_agent_runtime_binding_v1(self.runtime));
        bytes.extend_from_slice(self.session.digest().as_bytes());
        bytes.extend_from_slice(self.channel.as_bytes());
        bytes.extend_from_slice(&self.challenge);
        bytes.push(self.profile.namespace().len() as u8);
        bytes.extend_from_slice(self.profile.namespace().as_bytes());
        bytes.extend_from_slice(&self.profile.major().to_be_bytes());
        bytes.extend_from_slice(&self.profile.minor().to_be_bytes());
        bytes.extend_from_slice(self.profile_commitment.as_bytes());
        bytes
    }

    /// Decodes one exact canonical request without accepting trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns [`GuestRuntimeArgumentObservationErrorV1`] for malformed,
    /// oversized, noncanonical, or unsupported profile bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, GuestRuntimeArgumentObservationErrorV1> {
        if bytes.len() > MAXIMUM_REQUEST_BYTES {
            return Err(GuestRuntimeArgumentObservationErrorV1::InvalidPacket);
        }
        let mut cursor = bytes;
        if take::<8>(&mut cursor)? != *ARGUMENT_OBSERVE_REQUEST_MAGIC_V1 {
            return Err(GuestRuntimeArgumentObservationErrorV1::InvalidPacket);
        }
        let runtime = AgentRuntimeBindingV1::new(
            SandboxId::from_bytes(take(&mut cursor)?),
            IncarnationId::from_bytes(take(&mut cursor)?),
            AssignmentEpoch::new(u64::from_be_bytes(take(&mut cursor)?)),
            ObjectDigest::from_bytes(take(&mut cursor)?),
            DesiredGeneration::new(u64::from_be_bytes(take(&mut cursor)?)),
            NamespaceGeneration::new(u64::from_be_bytes(take(&mut cursor)?)),
            take(&mut cursor)?,
        )
        .map_err(|_| GuestRuntimeArgumentObservationErrorV1::InvalidPacket)?;
        let session =
            AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes(take(&mut cursor)?))
                .map_err(|_| GuestRuntimeArgumentObservationErrorV1::InvalidPacket)?;
        let channel = ObjectDigest::from_bytes(take(&mut cursor)?);
        let challenge = take(&mut cursor)?;
        let name_length = usize::from(take::<1>(&mut cursor)?[0]);
        let name = cursor
            .get(..name_length)
            .ok_or(GuestRuntimeArgumentObservationErrorV1::InvalidPacket)?;
        cursor = cursor
            .get(name_length..)
            .ok_or(GuestRuntimeArgumentObservationErrorV1::InvalidPacket)?;
        let name = std::str::from_utf8(name)
            .map_err(|_| GuestRuntimeArgumentObservationErrorV1::InvalidPacket)?;
        let major = u32::from_be_bytes(take(&mut cursor)?);
        let minor = u32::from_be_bytes(take(&mut cursor)?);
        let profile_commitment = ObjectDigest::from_bytes(take(&mut cursor)?);
        if !cursor.is_empty() {
            return Err(GuestRuntimeArgumentObservationErrorV1::InvalidPacket);
        }
        let profile = FeatureRef::new(name, major, minor)
            .map_err(|_| GuestRuntimeArgumentObservationErrorV1::InvalidProfile)?;
        let request = Self::new(
            runtime,
            session,
            channel,
            challenge,
            profile,
            profile_commitment,
        )?;
        if request.encode() != bytes {
            return Err(GuestRuntimeArgumentObservationErrorV1::InvalidPacket);
        }
        Ok(request)
    }
}

/// Holds a signature-checked Guest measurement tied to one expected challenge.
///
/// The verifier's key and expected request must come from current protected
/// Host custody. This value alone cannot authorize a later exec child whose
/// stack limit or runtime profile may differ from the measuring agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestRuntimeArgumentReadbackV1 {
    evidence: ExecutionRuntimeArgumentLimitV1,
    packet_digest: ObjectDigest,
}

impl GuestRuntimeArgumentReadbackV1 {
    /// Borrows the exact measured argument-limit evidence for spec production.
    #[must_use]
    pub const fn evidence(&self) -> &ExecutionRuntimeArgumentLimitV1 {
        &self.evidence
    }

    /// Returns the digest of the exact signed Guest packet.
    #[must_use]
    pub const fn packet_digest(&self) -> ObjectDigest {
        self.packet_digest
    }
}

/// Measures and signs the Guest's current process `ARG_MAX`.
///
/// Only the provisioned Guest entry calls this function with its sealed launch
/// key. No Host-supplied limit is accepted by the signing path.
///
/// # Errors
///
/// Returns [`GuestRuntimeArgumentObservationErrorV1`] if `sysconf` fails or
/// reports an absent/nonpositive value.
pub(crate) fn sign_current_guest_argument_readback_v1(
    request: &GuestRuntimeArgumentObserveRequestV1,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, GuestRuntimeArgumentObservationErrorV1> {
    let measured = nix::unistd::sysconf(nix::unistd::SysconfVar::ARG_MAX)
        .map_err(|_| GuestRuntimeArgumentObservationErrorV1::MeasurementUnavailable)?
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(GuestRuntimeArgumentObservationErrorV1::MeasurementUnavailable)?;
    sign_readback_with_limit(request, measured, signing_key)
}

/// Verifies a signed Guest measurement against the Host's exact current query.
///
/// The caller must supply the verifying key from protected agent peer custody,
/// not an untrusted packet, and recheck that the query's runtime/profile still
/// match current assignment before effect authorization.
///
/// # Errors
///
/// Returns [`GuestRuntimeArgumentObservationErrorV1`] for malformed bytes,
/// request substitution, invalid signature, or invalid core evidence.
pub fn verify_guest_runtime_argument_readback_v1(
    packet: &[u8],
    expected: &GuestRuntimeArgumentObserveRequestV1,
    trusted_agent_key: &VerifyingKey,
) -> Result<GuestRuntimeArgumentReadbackV1, GuestRuntimeArgumentObservationErrorV1> {
    if packet.len() > MAXIMUM_READBACK_BYTES || packet.len() < 82 {
        return Err(GuestRuntimeArgumentObservationErrorV1::InvalidPacket);
    }
    let mut cursor = packet;
    if take::<8>(&mut cursor)? != *READBACK_MAGIC {
        return Err(GuestRuntimeArgumentObservationErrorV1::InvalidPacket);
    }
    let request_length = usize::from(u16::from_be_bytes(take(&mut cursor)?));
    let request_bytes = cursor
        .get(..request_length)
        .ok_or(GuestRuntimeArgumentObservationErrorV1::InvalidPacket)?;
    let request = GuestRuntimeArgumentObserveRequestV1::decode(request_bytes)?;
    if request != *expected {
        return Err(GuestRuntimeArgumentObservationErrorV1::CurrentMismatch);
    }
    cursor = cursor
        .get(request_length..)
        .ok_or(GuestRuntimeArgumentObservationErrorV1::InvalidPacket)?;
    let measured = u64::from_be_bytes(take(&mut cursor)?);
    let signature_bytes = take::<64>(&mut cursor)?;
    if measured == 0 || !cursor.is_empty() {
        return Err(GuestRuntimeArgumentObservationErrorV1::InvalidPacket);
    }
    let signed_length = packet.len() - signature_bytes.len();
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + signed_length);
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&packet[..signed_length]);
    trusted_agent_key
        .verify_strict(&message, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| GuestRuntimeArgumentObservationErrorV1::InvalidSignature)?;

    let runtime = request.runtime();
    let target = ExecutionTargetV1::new(
        runtime.sandbox(),
        runtime.incarnation(),
        runtime.assignment_epoch(),
        runtime.assignment_digest(),
        runtime.namespace_generation(),
        PayloadBootId::new(*runtime.payload_boot_id())
            .map_err(|_| GuestRuntimeArgumentObservationErrorV1::InvalidProfile)?,
    )
    .map_err(|_| GuestRuntimeArgumentObservationErrorV1::InvalidProfile)?;
    let evidence = ExecutionRuntimeArgumentLimitV1::new(
        request.profile.clone(),
        request.profile_commitment,
        target,
        measured,
    )
    .map_err(|_| GuestRuntimeArgumentObservationErrorV1::InvalidProfile)?;
    Ok(GuestRuntimeArgumentReadbackV1 {
        evidence,
        packet_digest: ObjectDigest::from_bytes(Sha256::digest(packet).into()),
    })
}

fn sign_readback_with_limit(
    request: &GuestRuntimeArgumentObserveRequestV1,
    measured: u64,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, GuestRuntimeArgumentObservationErrorV1> {
    if measured == 0 {
        return Err(GuestRuntimeArgumentObservationErrorV1::MeasurementUnavailable);
    }
    let request_bytes = request.encode();
    let request_length = u16::try_from(request_bytes.len())
        .map_err(|_| GuestRuntimeArgumentObservationErrorV1::InvalidPacket)?;
    let mut packet = Vec::with_capacity(READBACK_MAGIC.len() + request_bytes.len() + 74);
    packet.extend_from_slice(READBACK_MAGIC);
    packet.extend_from_slice(&request_length.to_be_bytes());
    packet.extend_from_slice(&request_bytes);
    packet.extend_from_slice(&measured.to_be_bytes());
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + packet.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&packet);
    packet.extend_from_slice(&signing_key.sign(&message).to_bytes());
    Ok(packet)
}

fn take<const N: usize>(
    cursor: &mut &[u8],
) -> Result<[u8; N], GuestRuntimeArgumentObservationErrorV1> {
    let bytes = cursor
        .get(..N)
        .ok_or(GuestRuntimeArgumentObservationErrorV1::InvalidPacket)?
        .try_into()
        .map_err(|_| GuestRuntimeArgumentObservationErrorV1::InvalidPacket)?;
    *cursor = cursor
        .get(N..)
        .ok_or(GuestRuntimeArgumentObservationErrorV1::InvalidPacket)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_root_publication::CONCRETE_GUEST_FEATURE_MASK_V1;

    #[test]
    fn production_guest_root_does_not_advertise_unconsumed_observation() {
        let feature_bit =
            1_u16 << (crate::model::AgentFeatureV1::RuntimeArgumentObservation as u8 - 1);
        assert_eq!(CONCRETE_GUEST_FEATURE_MASK_V1 & feature_bit, 0);
    }

    fn request() -> GuestRuntimeArgumentObserveRequestV1 {
        let runtime = AgentRuntimeBindingV1::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            ObjectDigest::from_bytes([4; 32]),
            DesiredGeneration::new(5),
            NamespaceGeneration::new(6),
            [7; 16],
        )
        .expect("valid runtime");
        let session = AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes([8; 32]))
            .expect("valid session");
        let profile = FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0)
            .expect("valid registered profile");

        GuestRuntimeArgumentObserveRequestV1::new(
            runtime,
            session,
            ObjectDigest::from_bytes([9; 32]),
            [10; 32],
            profile,
            ObjectDigest::from_bytes([11; 32]),
        )
        .expect("valid request")
    }

    #[test]
    fn canonical_request_and_signed_readback_round_trip() {
        let request = request();
        let encoded = request.encode();
        assert_eq!(
            GuestRuntimeArgumentObserveRequestV1::decode(&encoded),
            Ok(request.clone())
        );

        let signing_key = SigningKey::from_bytes(&[12; 32]);
        let packet = sign_readback_with_limit(&request, 131_072, &signing_key)
            .expect("valid signed measurement");
        let verified = verify_guest_runtime_argument_readback_v1(
            &packet,
            &request,
            &signing_key.verifying_key(),
        )
        .expect("trusted Guest readback");

        assert_eq!(verified.evidence().runtime_limit_bytes(), 131_072);
        assert_eq!(verified.evidence().runtime_profile(), &request.profile);
        assert_eq!(
            verified.evidence().runtime_profile_commitment(),
            request.profile_commitment
        );
        assert_eq!(
            verified.packet_digest(),
            ObjectDigest::from_bytes(Sha256::digest(&packet).into())
        );
    }

    #[test]
    fn readback_rejects_changed_challenge_and_signature() {
        let request = request();
        let signing_key = SigningKey::from_bytes(&[12; 32]);
        let packet = sign_readback_with_limit(&request, 131_072, &signing_key)
            .expect("valid signed measurement");

        let mut changed_request = request.clone();
        changed_request.challenge = [13; 32];
        assert_eq!(
            verify_guest_runtime_argument_readback_v1(
                &packet,
                &changed_request,
                &signing_key.verifying_key(),
            ),
            Err(GuestRuntimeArgumentObservationErrorV1::CurrentMismatch)
        );

        let mut changed_packet = packet;
        let last = changed_packet.len() - 1;
        changed_packet[last] ^= 1;
        assert_eq!(
            verify_guest_runtime_argument_readback_v1(
                &changed_packet,
                &request,
                &signing_key.verifying_key(),
            ),
            Err(GuestRuntimeArgumentObservationErrorV1::InvalidSignature)
        );
        assert_eq!(
            verify_guest_runtime_argument_readback_v1(
                &changed_packet,
                &request,
                &SigningKey::from_bytes(&[14; 32]).verifying_key(),
            ),
            Err(GuestRuntimeArgumentObservationErrorV1::InvalidSignature)
        );
    }

    #[test]
    fn canonical_request_rejects_trailing_bytes_and_unknown_profile() {
        let request = request();
        let mut encoded = request.encode();
        encoded.push(0);
        assert_eq!(
            GuestRuntimeArgumentObserveRequestV1::decode(&encoded),
            Err(GuestRuntimeArgumentObservationErrorV1::InvalidPacket)
        );

        let invalid_profile = FeatureRef::new("aos.sandbox.runtime.not-registered", 1, 1)
            .expect("syntactically valid profile");
        assert_eq!(
            GuestRuntimeArgumentObserveRequestV1::new(
                request.runtime,
                request.session,
                request.channel,
                [10; 32],
                invalid_profile,
                ObjectDigest::from_bytes([11; 32]),
            ),
            Err(GuestRuntimeArgumentObservationErrorV1::InvalidProfile)
        );
    }

    #[test]
    fn provisioned_guest_measures_a_positive_kernel_limit() {
        let request = request();
        let signing_key = SigningKey::from_bytes(&[12; 32]);
        let packet = sign_current_guest_argument_readback_v1(&request, &signing_key)
            .expect("kernel provides ARG_MAX");
        let verified = verify_guest_runtime_argument_readback_v1(
            &packet,
            &request,
            &signing_key.verifying_key(),
        )
        .expect("trusted Guest measurement");

        assert!(verified.evidence().runtime_limit_bytes() > 0);
    }
}
