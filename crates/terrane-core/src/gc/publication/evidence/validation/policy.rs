//! Checks seeded profiles, semantic revisions and canonical property fences.

use super::*;
use crate::cbor::Decoder;
use crate::chunking::{
    CDC_1M_MAX, CDC_1M_MIN, CDC_1M_NORMALIZATION, CDC_1M_TARGET, CDC_1M_WINDOW, ChunkProfile,
};
use crate::properties::{PropertyName, validate_property};
use crate::tree_format::{MAX_NODE_ITEMS_BYTES, Property};

impl SeededChunkProfile {
    /// Recomputes the pure FastCDC profile from its six represented inputs.
    ///
    /// This derives masks and gear values, never backend or Guard authority.
    ///
    /// # Errors
    /// Rejects platform-unrepresentable sizes and invalid FastCDC parameters.
    pub fn to_chunk_profile(&self) -> Result<ChunkProfile, EvidenceError> {
        let minimum = usize::try_from(self.minimum).map_err(|_| EvidenceError::Schema)?;
        let target = usize::try_from(self.target).map_err(|_| EvidenceError::Schema)?;
        let maximum = usize::try_from(self.maximum).map_err(|_| EvidenceError::Schema)?;

        Ok(ChunkProfile::new(
            minimum,
            target,
            maximum,
            self.window,
            self.normalization,
            self.seed,
        )?)
    }
}

impl Validate for SeededChunkProfile {
    fn validate(&self) -> Result<(), EvidenceError> {
        self.to_chunk_profile()?;
        Ok(())
    }
}

impl Validate for TrustedGuardConfig {
    fn validate(&self) -> Result<(), EvidenceError> {
        nonempty(&self.store_name)?;
        domain(&self.storage_domain)?;
        acl(&self.initial_acl)?;
        self.chunk_profile.validate()?;

        if self.minimum_chunk_size != self.chunk_profile.minimum {
            return Err(EvidenceError::Contradiction);
        }
        if self.chunk_profile_name != "cdc-1m" {
            return Err(EvidenceError::Schema);
        }
        let profile = &self.chunk_profile;
        if profile.minimum != CDC_1M_MIN as u64
            || profile.target != CDC_1M_TARGET as u64
            || profile.maximum != CDC_1M_MAX as u64
            || profile.window != CDC_1M_WINDOW
            || profile.normalization != CDC_1M_NORMALIZATION
        {
            return Err(EvidenceError::Contradiction);
        }

        // The exact profile-record seed is an input, not a zero-seed assertion.
        // Encoding hints, optional locality and policy labels retain exact text;
        // actual current authority and ownership remain private-factory checks.
        Ok(())
    }
}

fn names(names: &[String]) -> Result<(), EvidenceError> {
    for name in names {
        if name.is_empty() || name.len() > 255 {
            return Err(EvidenceError::Schema);
        }
    }
    if names
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(EvidenceError::Schema);
    }

    Ok(())
}

impl Validate for ConfiguredRegistryInputs {
    fn validate(&self) -> Result<(), EvidenceError> {
        if [
            self.property_revision,
            self.attribute_revision,
            self.selector_revision,
            self.tree_revision,
            self.chunk_revision,
        ]
        .iter()
        .any(|revision| *revision != 1)
            || self.identity_profile != "terrane-v1"
        {
            return Err(EvidenceError::UnsupportedRevision);
        }
        names(&self.behavioral_properties)?;
        names(&self.later_properties)?;

        let mut registered: Vec<_> = PropertyName::ALL.iter().map(|name| name.as_str()).collect();
        registered.sort_unstable();
        if !self
            .behavioral_properties
            .iter()
            .map(String::as_str)
            .eq(registered)
        {
            return Err(EvidenceError::Contradiction);
        }
        if self
            .later_properties
            .iter()
            .any(|name| self.behavioral_properties.binary_search(name).is_ok())
        {
            return Err(EvidenceError::Contradiction);
        }

        // A nonempty later set remains inert decoded data. Genuine revision-one
        // configuration separately requires the currently supported empty set.
        Ok(())
    }
}

impl Validate for GuardSnapshot {
    fn validate(&self) -> Result<(), EvidenceError> {
        self.registration.validate()?;
        issuers(&self.issuers)?;
        disclosures(&self.disclosures)?;

        self.configuration.validate()?;
        self.registries.validate()?;
        if self.registration.physical_domain() != self.configuration.storage_domain {
            return Err(EvidenceError::Contradiction);
        }

        Ok(())
    }
}

/// Checks exact canonical property-map bytes and an optional behavior fence.
///
/// # Errors
/// Rejects malformed property maps, wrong registered values, and names outside
/// the represented behavioral and inert-name fence when one is supplied.
pub(super) fn property_map(
    bytes: &[u8],
    registries: Option<&ConfiguredRegistryInputs>,
) -> Result<(), EvidenceError> {
    if bytes.len() > MAX_NODE_ITEMS_BYTES {
        return Err(EvidenceError::Cbor(crate::cbor::Error::Limit));
    }
    let mut decoder = Decoder::new(bytes);
    let count = decoder.map(MAX_NODE_ITEMS_BYTES)?;
    let mut previous = None;
    for _ in 0..count {
        let key_start = decoder.position();
        let name = decoder.text(255)?;
        let encoded_key = decoder.slice(key_start, decoder.position())?;
        if name.is_empty() || previous.is_some_and(|prior: &[u8]| prior >= encoded_key) {
            return Err(EvidenceError::Schema);
        }
        previous = Some(encoded_key);

        let value_start = decoder.position();
        crate::tree_format::property_value(&mut decoder)?;
        let value = decoder.slice(value_start, decoder.position())?;
        if PropertyName::parse(name).is_ok() {
            validate_property(&Property { name, value })?;
        } else if let Some(registries) = registries
            && !registries
                .later_properties
                .iter()
                .any(|later| later == name)
        {
            return Err(EvidenceError::Schema);
        }
    }
    decoder.finish()?;
    Ok(())
}
