//! Backend-keyed model, dialect, original refusal and serial continuation data.
//!
//! These closed records are inert archive payloads. A signed common NativeArchive,
//! exact installed profile verifier, complete image/resources census, fresh kernel
//! peer and fresh opaque certificate are required before any reconstructed node
//! can execute or publish. Portable hashes and metadata never mint that authority.

use super::model::{Gem5ModelDialect, Gem5ModelSelection, Gem5SerialPublication};
use super::refusal::{Gem5DiagnosticCreditPolicy, Gem5RunRefusal, parse_run_refusal_for_model};
use super::{Gem5Boundary, Gem5Run};
use crate::ProviderError;
use crucible_node_contract::{ContentRef, Id, U64, Validate, canonical};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Retains the exact original refusal bytes and administrative settlement state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedModelRefusal {
    /// Names the subordinate attempt, separate from the common operation ID.
    pub operation: Id,
    /// Retains every original canonical wire byte for retries and custody.
    pub raw: Vec<u8>,
    /// Retains whether its distinct original administrative ACK occurred.
    pub acknowledged: bool,
}

/// Retains one exact original successful serial-producing prefix.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedSerialPrefix {
    /// Retains the original immutable permission; its ID is never regenerated.
    pub original: Gem5Run,
    /// Retains the authentic stopped cut before this prefix.
    pub before: Gem5Boundary,
    /// Retains the authentic stopped cut after this prefix.
    pub after: Gem5Boundary,
    /// Retains the original number of actual native callbacks serviced.
    pub processed_events: U64,
    /// Retains every original byte and its actual callback birth.
    pub publications: Vec<Gem5SerialPublication>,
}

/// Retains typed model-aware continuation data without admission authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmModelContinuation {
    /// Selects the new backend-local continuation edition explicitly.
    pub schema: String,
    /// Binds the independently installed exact profile; it is not a trust selector.
    pub installed_profile: ContentRef,
    /// Binds the complete original native image; its resource roster is external.
    pub native_image: ContentRef,
    /// Retains the source-owned model and every original asset commitment.
    pub model: Gem5ModelSelection,
    /// Retains the original explicitly selected dialect without legacy fallback.
    pub dialect: Gem5ModelDialect,
    /// Retains the exact original diagnostic reservation policy.
    pub diagnostic_policy: Gem5DiagnosticCreditPolicy,
    /// Names the original common operation whose earlier prefixes remain effects.
    pub common_operation: Id,
    /// Retains the original parked full logical/native cut.
    pub boundary: Gem5Boundary,
    /// Retains each original successful prefix and publication without synthesis.
    pub successful_prefixes: Vec<RetainedSerialPrefix>,
    /// Retains failed-prefix tombstones after distinct administrative ACK.
    pub refused_prefixes: Vec<RetainedModelRefusal>,
    /// Names the held successful prefix awaiting genuine original publication ACK.
    pub held_prefix: Option<Id>,
    /// Retains the authentic latest successful ACK for unchanged retries.
    pub last_acknowledged_prefix: Option<Id>,
}

impl ArmModelContinuation {
    /// Checks immutable archived model and original operation reconciliation.
    ///
    /// This is schema checking only. The current live opaque certificate must
    /// bind this exact original native boundary, image and installed profile.
    ///
    /// # Errors
    /// Refuses changed installed bindings, absent fields, legacy/model mismatch,
    /// duplicate prefix IDs, impossible births, ACK/refusal conflation or changed
    /// original callback cuts. A prior successful prefix never becomes NoEffects.
    pub fn validate_originals(&self, installed: &ContentRef) -> Result<(), ProviderError> {
        self.installed_profile.validate()?;
        self.native_image.validate()?;
        self.model.validate_for(self.dialect)?;
        if self.schema != "crucible.gem5.arm-model-continuation.v1"
            || self.dialect != Gem5ModelDialect::ArmLinux
            || &self.installed_profile != installed
            || self.successful_prefixes.len() > 1024
            || self.refused_prefixes.len() > 1024
        {
            return Err(ProviderError::Correlation(
                "ARM continuation differs from installed source custody",
            ));
        }
        let mut ids = BTreeSet::new();
        let mut previous_output = 0;
        for prefix in &self.successful_prefixes {
            if !ids.insert(&prefix.original.operation)
                || prefix.processed_events.get() == 0
                || prefix.processed_events.get() > prefix.original.maximum_events.get()
                || prefix
                    .after
                    .ordinal
                    .get()
                    .checked_sub(prefix.before.ordinal.get())
                    != Some(prefix.processed_events.get())
                || prefix.after.tick < prefix.before.tick
                || prefix.after.ordinal > self.boundary.ordinal
                || prefix.after.tick > self.boundary.tick
                || prefix.publications.len() > 65536
            {
                return Err(ProviderError::Correlation(
                    "ARM successful original prefix cut differs",
                ));
            }
            for publication in &prefix.publications {
                publication.validate_birth(
                    &prefix.before,
                    &prefix.after,
                    publication.output_id,
                    publication.causal_parent,
                )?;
                if publication.output_id.get() <= previous_output {
                    return Err(ProviderError::Correlation(
                        "ARM original serial FIFO identity reordered",
                    ));
                }
                previous_output = publication.output_id.get();
            }
        }
        for refused in &self.refused_prefixes {
            if !ids.insert(&refused.operation) {
                return Err(ProviderError::Conflict(
                    "ARM refusal and successful prefix identities collide",
                ));
            }
            let raw = canonical::parse_json(&refused.raw, super::GEM5_NATIVE_FRAME_BYTES)?;
            let receipt: Gem5RunRefusal = serde_json::from_value(raw)
                .map_err(|_| ProviderError::Frame("invalid retained original ARM refusal"))?;
            if receipt.operation != refused.operation
                || receipt.boundary.ordinal > self.boundary.ordinal
                || receipt.boundary.tick > self.boundary.tick
            {
                return Err(ProviderError::Correlation(
                    "ARM original refusal belongs to another cut",
                ));
            }
            parse_run_refusal_for_model(
                &refused.raw,
                "crucible.gem5.arm-linux-native/1",
                self.dialect,
                &self.diagnostic_policy,
                &receipt.original,
                &receipt.boundary,
            )?;
        }
        for prefix in [&self.held_prefix, &self.last_acknowledged_prefix]
            .into_iter()
            .flatten()
        {
            if !self
                .successful_prefixes
                .iter()
                .any(|original| &original.original.operation == prefix)
            {
                return Err(ProviderError::Correlation(
                    "ARM publication ACK references refusal or unknown prefix",
                ));
            }
        }
        if self.held_prefix.is_some() && self.held_prefix == self.last_acknowledged_prefix {
            return Err(ProviderError::Correlation(
                "ARM held output was falsely acknowledged",
            ));
        }
        Ok(())
    }
}
