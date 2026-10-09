//! Portable sealed-launch record encoding for the fixed Guest entry.
//!
//! `AOSAGP01` carries a runtime-bound launch secret, not an authorization grant.
//! Host custody and Guest confinement independently establish its provenance.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

use crate::model::{AgentFeatureSetV1, AgentRuntimeBindingV1};

/// Exact byte length of the sealed Guest launch record.
pub const GUEST_AGENT_PROVISIONING_BYTES_V1: usize = 258;

/// Canonical version-one Guest launch record discriminator.
pub const GUEST_AGENT_PROVISIONING_MAGIC_V1: &[u8; 8] = b"AOSAGP01";

/// Builds the exact sealed launch record supplied to inherited FD 4.
///
/// The Host must publish the returned verifying key in its protected peer
/// binding and deliver the encoded bytes through a fully sealed memfd.
pub struct GuestAgentLaunchRecordV1 {
    runtime: AgentRuntimeBindingV1,
    channel: ObjectDigest,
    instance: [u8; 16],
    signing_key: SigningKey,
    features: AgentFeatureSetV1,
    package_binding: ObjectDigest,
}

impl GuestAgentLaunchRecordV1 {
    /// Constructs one non-sentinel launch record for a protected Host owner.
    ///
    /// # Errors
    ///
    /// Returns [`GuestAgentLaunchRecordErrorV1`] for a zero
    /// channel, instance, signing seed, or package binding.
    pub fn new(
        runtime: AgentRuntimeBindingV1,
        channel: ObjectDigest,
        instance: [u8; 16],
        signing_seed: [u8; 32],
        features: AgentFeatureSetV1,
        package_binding: ObjectDigest,
    ) -> Result<Self, GuestAgentLaunchRecordErrorV1> {
        if channel.as_bytes() == &[0; 32]
            || instance == [0; 16]
            || signing_seed == [0; 32]
            || package_binding.as_bytes() == &[0; 32]
        {
            return Err(GuestAgentLaunchRecordErrorV1);
        }
        Ok(Self {
            runtime,
            channel,
            instance,
            signing_key: SigningKey::from_bytes(&signing_seed),
            features,
            package_binding,
        })
    }

    /// Returns the public key the Host must bind to this exact channel.
    #[must_use]
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Returns the exact runtime for which this launch secret was minted.
    #[must_use]
    pub const fn runtime(&self) -> &AgentRuntimeBindingV1 {
        &self.runtime
    }

    /// Returns the protected channel to which this launch secret is bound.
    #[must_use]
    pub const fn channel_binding(&self) -> ObjectDigest {
        self.channel
    }

    /// Returns the one-time agent instance bound to this launch record.
    #[must_use]
    pub const fn agent_instance(&self) -> [u8; 16] {
        self.instance
    }

    /// Returns the exact feature set supplied to the guest.
    #[must_use]
    pub const fn features(&self) -> &AgentFeatureSetV1 {
        &self.features
    }

    /// Returns the guest package identity sealed into this launch record.
    #[must_use]
    pub const fn package_binding(&self) -> ObjectDigest {
        self.package_binding
    }

    /// Encodes the canonical 258-byte `AOSAGP01` sealed-memfd payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(GUEST_AGENT_PROVISIONING_BYTES_V1);
        bytes.extend_from_slice(GUEST_AGENT_PROVISIONING_MAGIC_V1);
        bytes.extend_from_slice(&encode_agent_runtime_binding_v1(self.runtime));
        bytes.extend_from_slice(self.channel.as_bytes());
        bytes.extend_from_slice(&self.instance);
        bytes.extend_from_slice(&self.signing_key.to_bytes());
        let feature_mask = self
            .features
            .as_slice()
            .iter()
            .fold(0_u16, |mask, feature| {
                mask | (1_u16 << (*feature as u8 - 1))
            });
        bytes.extend_from_slice(&feature_mask.to_be_bytes());
        bytes.extend_from_slice(self.package_binding.as_bytes());
        let checksum: [u8; 32] = Sha256::digest(&bytes).into();
        bytes.extend_from_slice(&checksum);
        bytes
    }
}

/// Encodes the exact runtime prefix shared by sealed guest launch credentials.
#[must_use]
pub fn encode_agent_runtime_binding_v1(runtime: AgentRuntimeBindingV1) -> [u8; 104] {
    let mut bytes = [0_u8; 104];
    bytes[..16].copy_from_slice(runtime.sandbox().as_bytes());
    bytes[16..32].copy_from_slice(runtime.incarnation().as_bytes());
    bytes[32..40].copy_from_slice(&runtime.assignment_epoch().get().to_be_bytes());
    bytes[40..72].copy_from_slice(runtime.assignment_digest().as_bytes());
    bytes[72..80].copy_from_slice(&runtime.desired_generation().get().to_be_bytes());
    bytes[80..88].copy_from_slice(&runtime.namespace_generation().get().to_be_bytes());
    bytes[88..104].copy_from_slice(runtime.payload_boot_id());
    bytes
}

/// Reports unspecified identities or secret material in a launch proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("guest agent provisioning record is invalid")]
pub struct GuestAgentLaunchRecordErrorV1;
