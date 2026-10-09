//! Physical argument-limit measurement under the provisioned Guest signer.
//!
//! The unsigned claim codec belongs to Agent. This owner alone obtains the
//! kernel observation before signing; no Host-supplied limit enters this path.

use aos_sandbox_agent::runtime_argument_observation::{
    GUEST_ARGUMENT_READBACK_SIGNATURE_DOMAIN_V1 as SIGNATURE_DOMAIN,
    GuestRuntimeArgumentObservationErrorV1, GuestRuntimeArgumentObserveRequestV1,
    encode_guest_argument_readback_subject_v1,
};
use ed25519_dalek::{Signer as _, SigningKey};

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
    let mut packet = encode_guest_argument_readback_subject_v1(request, measured)?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + packet.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&packet);
    packet.extend_from_slice(&signing_key.sign(&message).to_bytes());
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_agent::runtime_argument_observation::verify_guest_runtime_argument_readback_v1;
    use aos_sandbox_agent::{AgentRuntimeBindingV1, AgentSessionBindingV1};
    use aos_sandbox_core::{
        AssignmentEpoch, DesiredGeneration, FeatureRef, IncarnationId, NamespaceGeneration,
        ObjectDigest, SandboxId,
    };

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
