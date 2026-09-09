//! Self-contained pure inputs for reconstructing one checked effect plan.
//!
//! The bundle is a diagnostic and offline-validation artifact. Canonical bytes
//! and an optional external digest establish exact integrity. They do not prove
//! that the environment observation is current or that its policy is trusted by
//! the reader; callers must establish those facts at their own trust boundary.
//!
//! The canonical envelope has this shape:
//!
//! ```json
//! {
//!   "schema": "aos.ability.inspection-bundle/v1",
//!   "required_features": [],
//!   "binding_plan": "sha256:<binding-plan-digest>",
//!   "effect_plan": "sha256:<effect-plan-digest>",
//!   "interfaces": [],
//!   "environment": { "schema": "aos.ability.environment/v1" },
//!   "desired_state": { "schema": "aos.ability.desired/v1" },
//!   "packages": [],
//!   "binding_document": { "schema": "aos.ability.binding-plan/v1" },
//!   "effect_document": { "schema": "aos.ability.effect-plan/v1" }
//! }
//! ```

use std::collections::BTreeSet;
use std::io::{self, Write};

use aos_ability_model::{
    ABILITY_LIMITS_V1, BindingPlanDocument, DesiredStateDocument, EffectPlanDocument,
    EnvironmentDocument, InterfaceDocument, PackageDocument, PlanId, RequiredFeature,
};
use aos_ability_validate::{BindingValidationInputs, CheckedEffectPlan, ValidationContext};
use aos_contract::Sha256Digest;
use aos_contract::limits::JsonLimits;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact schema discriminator for a portable inspection input bundle.
pub const INSPECTION_BUNDLE_SCHEMA: &str = "aos.ability.inspection-bundle/v1";

const INSPECTION_BUNDLE_COMPONENT_LIMIT: usize = 8;

/// Maximum encoded byte length accepted for one inspection bundle.
pub const INSPECTION_BUNDLE_MAX_BYTES: usize = (ABILITY_LIMITS_V1.max_document_bytes as usize)
    .saturating_mul(INSPECTION_BUNDLE_COMPONENT_LIMIT);

/// Retains every pure document needed to reconstruct one checked effect plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionBundle {
    schema: String,
    required_features: Vec<RequiredFeature>,
    binding_plan: PlanId,
    effect_plan: PlanId,
    interfaces: Vec<InterfaceDocument>,
    environment: EnvironmentDocument,
    desired_state: DesiredStateDocument,
    packages: Vec<PackageDocument>,
    binding_document: BindingPlanDocument,
    effect_document: EffectPlanDocument,
}

/// Carries a bundle whose complete graph has passed common semantic validation.
#[derive(Debug)]
pub struct CheckedInspectionBundle {
    bundle: InspectionBundle,
    digest: Sha256Digest,
    externally_anchored: bool,
    plan: CheckedEffectPlan,
}

/// Reports why an inspection bundle cannot be decoded or checked.
#[derive(Debug, Error)]
pub enum InspectionBundleError {
    /// Bounded strict JSON decoding failed.
    #[error("inspection bundle decoding failed: {0}")]
    Decode(#[source] anyhow::Error),
    /// Canonical JSON encoding failed.
    #[error("inspection bundle encoding failed: {0}")]
    Encode(#[source] anyhow::Error),
    /// The encoded bundle exceeds the explicit version bound.
    #[error("inspection bundle exceeds its encoded byte limit")]
    EncodedSizeLimit,
    /// The schema discriminator is unsupported.
    #[error("inspection bundle has an unsupported schema discriminator")]
    UnsupportedSchema,
    /// Version 1 does not support optional feature semantics.
    #[error("inspection bundle requires unsupported feature semantics")]
    UnsupportedFeatures,
    /// The bytes are valid JSON but are not their canonical representation.
    #[error("inspection bundle is not canonically encoded")]
    NoncanonicalEncoding,
    /// An externally supplied exact digest differs from the bundle.
    #[error("inspection bundle differs from its external digest")]
    CommitmentMismatch,
    /// Interface, binding, or effect semantics failed common validation.
    #[error("inspection bundle semantic validation failed: {0}")]
    Validation(#[source] aos_ability_validate::ValidationErrors),
    /// A claimed binding or effect-plan identity differs after validation.
    #[error("inspection bundle plan identity is inconsistent")]
    PlanIdentityMismatch,
}

impl InspectionBundle {
    /// Captures owned pure inputs from one semantically checked effect plan.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting canonical bundle exceeds its bound or
    /// cannot be encoded.
    pub fn from_checked(plan: &CheckedEffectPlan) -> Result<Self, InspectionBundleError> {
        let binding = plan.binding_plan();
        let bundle = Self {
            schema: INSPECTION_BUNDLE_SCHEMA.to_string(),
            required_features: Vec::new(),
            binding_plan: binding.id(),
            effect_plan: plan.id(),
            interfaces: plan.interfaces().values().cloned().collect(),
            environment: binding.environment().clone(),
            desired_state: binding.desired_state().clone(),
            packages: binding.packages().to_vec(),
            binding_document: binding.document().clone(),
            effect_document: plan.document().clone(),
        };
        bundle.canonical_bytes()?;
        Ok(bundle)
    }

    /// Returns the claimed checked binding-plan identity.
    #[must_use]
    pub const fn binding_plan(&self) -> PlanId {
        self.binding_plan
    }

    /// Returns the claimed checked effect-plan identity.
    #[must_use]
    pub const fn effect_plan(&self) -> PlanId {
        self.effect_plan
    }

    /// Returns the portable effect-plan document.
    #[must_use]
    pub const fn effect_document(&self) -> &EffectPlanDocument {
        &self.effect_document
    }

    /// Encodes the bundle in canonical bounded JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the encoded bundle exceeds
    /// the version-1 byte bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, InspectionBundleError> {
        if self.schema != INSPECTION_BUNDLE_SCHEMA {
            return Err(InspectionBundleError::UnsupportedSchema);
        }
        if !self.required_features.is_empty() {
            return Err(InspectionBundleError::UnsupportedFeatures);
        }

        let mut writer = BoundedWriter::new(INSPECTION_BUNDLE_MAX_BYTES);
        serde_json::to_writer(&mut writer, self).map_err(|error| {
            if writer.exceeded {
                InspectionBundleError::EncodedSizeLimit
            } else {
                InspectionBundleError::Encode(error.into())
            }
        })?;
        aos_contract::canonical::to_vec(self).map_err(InspectionBundleError::Encode)
    }

    /// Computes the domain-separated exact bundle identity.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical encoding fails.
    pub fn digest(&self) -> Result<Sha256Digest, InspectionBundleError> {
        Ok(Sha256Digest::separated(
            INSPECTION_BUNDLE_SCHEMA,
            self.canonical_bytes()?,
        ))
    }

    /// Decodes one strictly bounded canonical bundle without claiming authority.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, noncanonical, or unsupported
    /// input.
    pub fn decode(bytes: &[u8]) -> Result<Self, InspectionBundleError> {
        let bundle = inspection_limits()
            .decode::<Self>(bytes, INSPECTION_BUNDLE_SCHEMA)
            .map_err(InspectionBundleError::Decode)?;
        if bundle.schema != INSPECTION_BUNDLE_SCHEMA {
            return Err(InspectionBundleError::UnsupportedSchema);
        }
        if !bundle.required_features.is_empty() {
            return Err(InspectionBundleError::UnsupportedFeatures);
        }
        if bundle.canonical_bytes()? != bytes {
            return Err(InspectionBundleError::NoncanonicalEncoding);
        }
        Ok(bundle)
    }

    /// Reconstructs and validates the complete checked plan.
    ///
    /// `expected_digest` must come from an independent trusted record if the
    /// caller intends to treat the returned bundle as externally anchored.
    /// Omitting it still performs complete local semantic validation.
    ///
    /// # Errors
    ///
    /// Returns an error when an external digest differs, required feature
    /// semantics exceed this version-1 inspector, validation fails, or either
    /// reconstructed plan identity differs from the bundle.
    pub fn check(
        self,
        expected_digest: Option<Sha256Digest>,
    ) -> Result<CheckedInspectionBundle, InspectionBundleError> {
        let digest = self.digest()?;
        if expected_digest.is_some_and(|expected| expected != digest) {
            return Err(InspectionBundleError::CommitmentMismatch);
        }

        // Version 1 has no optional feature semantics. A later inspector must
        // explicitly add support rather than trusting a bundle-authored list.
        let supported_features = BTreeSet::from([RequiredFeature::new("abilities-v1")
            .map_err(|error| InspectionBundleError::Encode(error.into()))?]);
        let context = ValidationContext::new(supported_features, self.interfaces.clone())
            .map_err(InspectionBundleError::Validation)?;
        let binding = context
            .validate_binding_plan(
                self.binding_document.clone(),
                BindingValidationInputs {
                    environment: self.environment.clone(),
                    desired_state: self.desired_state.clone(),
                    packages: self.packages.clone(),
                },
            )
            .map_err(InspectionBundleError::Validation)?;
        if binding.id() != self.binding_plan {
            return Err(InspectionBundleError::PlanIdentityMismatch);
        }
        let plan = context
            .validate_effect_plan(self.effect_document.clone(), binding)
            .map_err(InspectionBundleError::Validation)?;
        if plan.id() != self.effect_plan {
            return Err(InspectionBundleError::PlanIdentityMismatch);
        }

        Ok(CheckedInspectionBundle {
            bundle: self,
            digest,
            externally_anchored: expected_digest.is_some(),
            plan,
        })
    }
}

impl CheckedInspectionBundle {
    /// Returns the exact portable bundle that was checked.
    #[must_use]
    pub const fn bundle(&self) -> &InspectionBundle {
        &self.bundle
    }

    /// Returns the domain-separated exact bundle identity.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Reports whether the caller supplied a matching independent digest.
    #[must_use]
    pub const fn is_externally_anchored(&self) -> bool {
        self.externally_anchored
    }

    /// Returns the freshly reconstructed semantically checked effect plan.
    #[must_use]
    pub const fn plan(&self) -> &CheckedEffectPlan {
        &self.plan
    }
}

struct BoundedWriter {
    remaining: usize,
    exceeded: bool,
}

impl BoundedWriter {
    const fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized inspection bundle exceeds its byte limit",
            ));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn inspection_limits() -> JsonLimits {
    JsonLimits {
        max_bytes: INSPECTION_BUNDLE_MAX_BYTES,
        max_depth: ABILITY_LIMITS_V1.max_structural_depth as usize,
        max_items: (ABILITY_LIMITS_V1.max_collection_items as usize)
            .saturating_mul(INSPECTION_BUNDLE_COMPONENT_LIMIT),
        max_string_bytes: ABILITY_LIMITS_V1.max_string_bytes as usize,
    }
}
