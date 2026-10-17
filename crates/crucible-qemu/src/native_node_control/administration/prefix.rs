//! Complete controller-nine preparation over the explicit scalar process protocol.
//!
//! Endpoint metadata measures the original inherited datagram. Complete root and
//! effect records remain unchanged ancestors; the distinct prefix commitment
//! correlates new bounded history without claiming native epoch or readiness.

use super::{NativeAdministrationTransport, NativeLaunchEndpoint, NativeQemuControlError};
use crucible_node_contract::U64;
use crucible_protocol::node_control::{
    NativeAdministrativePreparation, NativeChannel, NativeCommandError, NativeControlEdition,
    NativeEffectPreparation, NativeFrame, NativePhasePreparation, NativePrefixPreparation,
};
use std::os::unix::fs::MetadataExt;

/// Pins the independent prefix policy and unchanged ancestor effect allowances.
pub struct NativePrefixParameters {
    /// Pins the controller-eight ancestor's effect policy.
    pub effect_policy_digest: [u8; 32],
    /// Bounds callbacks against the original root profile.
    pub maximum_callbacks: u32,
    /// Bounds all original service retirements without renewing them on Continue.
    pub maximum_service_span: U64,
    /// Pins the distinct controller-nine prefix policy.
    pub prefix_policy_digest: [u8; 32],
    /// Bounds retained cut/result slots between two and sixty-four.
    pub maximum_prefixes: u32,
}

impl NativeAdministrationTransport {
    /// Measures the original endpoint and queues complete prefix preparation once.
    ///
    /// # Errors
    /// Rejects malformed ancestry, widened limits, invalid prefix capacity or
    /// socket/framing failures. This retains protocol custody, never native authority.
    pub fn prepare_prefix(
        phase: NativePhasePreparation,
        reader_policy_digest: [u8; 32],
        descriptor_slot: i32,
        parameters: super::super::super::root::NativeFixedMicrovmParameters,
        prefix_parameters: NativePrefixParameters,
    ) -> Result<(Self, NativeLaunchEndpoint), NativeQemuControlError> {
        phase.validate()?;
        let edition = NativeControlEdition::PrefixEffect;
        let (channel, provider) = NativeChannel::supervised_pair_for_edition(edition)?;
        let descriptor = provider
            .prepared_descriptor()
            .try_clone_to_owned()
            .map_err(crucible_protocol::node_control::NativeChannelError::from)?;
        let metadata = std::fs::File::from(descriptor)
            .metadata()
            .map_err(crucible_protocol::node_control::NativeChannelError::from)?;
        let preparation = NativeAdministrativePreparation {
            phase: phase.clone(),
            policy_digest: reader_policy_digest,
            descriptor_slot,
            socket_device: metadata.dev(),
            socket_inode: metadata.ino(),
        };
        preparation.validate()?;
        let original_root = parameters.bind(preparation.clone())?;
        let effect = NativeEffectPreparation {
            original_root: original_root.clone(),
            policy_digest: prefix_parameters.effect_policy_digest,
            maximum_callbacks: prefix_parameters.maximum_callbacks,
            maximum_service_span: prefix_parameters.maximum_service_span,
        };
        let prefix = NativePrefixPreparation {
            original_effect: effect.clone(),
            policy_digest: prefix_parameters.prefix_policy_digest,
            maximum_prefixes: prefix_parameters.maximum_prefixes,
        };
        prefix.validate()?;
        if !channel.send(&NativeFrame::PreparePrefix(Box::new(prefix.clone())))? {
            return Err(NativeCommandError::ResourceLimit.into());
        }
        let scope_digest = phase.initialization.preparation.scope.identity_digest()?;
        Ok((
            Self {
                channel,
                preparation,
                original: None,
                expected_process: None,
                fixed_microvm: Some(original_root),
                effect: Some(effect),
                prefix: Some(prefix),
                requested: false,
                failed: false,
            },
            NativeLaunchEndpoint {
                socket: provider.into_prepared_socket(),
                scope_digest,
                edition,
                initialization: Some(phase.initialization.clone()),
                phase_projection: Some(phase),
            },
        ))
    }

    /// Borrows the complete original prefix preparation without supplying permission.
    pub fn prefix_preparation(&self) -> Option<&NativePrefixPreparation> {
        self.prefix.as_ref()
    }
}
