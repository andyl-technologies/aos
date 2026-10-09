//! Original measured configuration for the separately selected fixed-root bootstrap.
//!
//! The launcher measures its initial firmware artifact and prepares the actual
//! socket before binding these parameters to the unchanged original companions.
//! Native constructor enrollment independently measures loaded firmware RAM,
//! device and bus topology. These records create no native epoch or effects.

use crucible_node_contract::U64;
use crucible_protocol::node_control::{
    NativeAdministrativePreparation, NativeCommandError, NativeFixedMicrovmMapping,
    NativeFixedMicrovmPreparation,
};

/// Supplies bounded initial artifact and service policy, without claimed native observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeFixedMicrovmParameters {
    /// Pins the independently installed root and finite ordering policy.
    pub policy_digest: [u8; 32],
    /// Measures the complete original loaded firmware file with SHA-256.
    ///
    /// This measurement does not make guest-writable firmware RAM immutable.
    pub firmware_sha256: [u8; 32],
    /// Pins the complete original firmware artifact extent.
    pub firmware_length: U64,
    /// Pins actual guest RAM separately from firmware RAM and its aliases.
    pub ram_length: U64,
    /// Pins the native deterministic guest entropy seed.
    pub seed: U64,
    /// Bounds instruction services in a separately authorized finite span.
    pub maximum_service_span: U64,
    /// Selects the independently installed CPU/timer tie rule.
    pub mapping: NativeFixedMicrovmMapping,
    /// Bounds callbacks in a separately authorized original source-selected cut.
    pub maximum_callbacks: u32,
}

impl NativeFixedMicrovmParameters {
    pub(super) fn bind(
        self,
        administration: NativeAdministrativePreparation,
    ) -> Result<NativeFixedMicrovmPreparation, NativeCommandError> {
        let maximum_microstep = administration.phase.maximum_microstep;
        let preparation = NativeFixedMicrovmPreparation {
            administration,
            policy_digest: self.policy_digest,
            firmware_sha256: self.firmware_sha256,
            firmware_length: self.firmware_length,
            ram_length: self.ram_length,
            seed: self.seed,
            maximum_microstep,
            maximum_service_span: self.maximum_service_span,
            mapping: self.mapping,
            maximum_callbacks: self.maximum_callbacks,
        };
        preparation.validate()?;
        Ok(preparation)
    }
}
