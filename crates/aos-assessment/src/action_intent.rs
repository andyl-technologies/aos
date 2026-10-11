//! Exact candidate recommendations for handoff to an independently authorized planner.
//!
//! `aos.assessment-update-intent/v1` commits to a reproduced bundle, source
//! subject, complete update-unit vector and exclusive freshness boundary. It
//! contains no executable commands, paths, downloads or mutation authority.
//!
//! ```text
//! reproduced bundle -> update intent -> clean checkout/source checks -> local plan
//! ```
//!
//! The closed wire document includes every commitment, even for offline handoff:
//!
//! ```json
//! {
//!   "schema": "aos.assessment-update-intent/v1",
//!   "bundleManifestDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!   "inventoryDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!   "scanInputDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!   "assessmentDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!   "engineDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!   "policyDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!   "historyDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!   "subjectRef": "source-package",
//!   "subjectDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!   "sourceContentDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!   "scanDefinitionDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!   "unitId": "example-1",
//!   "components": [{
//!     "componentRef": "component-main",
//!     "componentId": "main",
//!     "componentDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
//!     "current": { "upstreamId": "v1.2.0", "comparisonVersion": "1.2.0" },
//!     "target": { "upstreamId": "v1.3.0", "comparisonVersion": "1.3.0" },
//!     "observationDigests": ["sha256:0000000000000000000000000000000000000000000000000000000000000000"]
//!   }],
//!   "evaluatedAt": "2026-10-10T00:00:00Z",
//!   "validUntil": "2026-10-11T00:00:00Z"
//! }
//! ```

use anyhow::{Context as _, Result, ensure};
use aos_contract::Sha256Digest;
use aos_contract::limits::JsonLimits;
use serde::{Deserialize, Serialize};

use crate::bundle::{AssessmentBundleV1, BUNDLE_MANIFEST_V1};
use crate::identity::{ComponentId, UnitId};
use crate::input::Profile;
use crate::inventory::{Classification, ComponentVersion};
use crate::result::VersionDecision;
use crate::scan_inventory::SubjectKind;
use crate::time::Timestamp;
use crate::validation::{decode_with_limits, digest, sorted, text};

/// Names the closed candidate recommendation and its content identity domain.
pub const ASSESSMENT_UPDATE_INTENT_V1: &str = "aos.assessment-update-intent/v1";

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 262_144,
    max_depth: 12,
    max_items: 8192,
    max_string_bytes: 1024,
};

/// Binds one exact current component to a recommended or unchanged target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ComponentUpdateIntent {
    /// Exact component instance within the portable inventory.
    pub component_ref: String,
    /// Logical component within the independently planned unit.
    pub component_id: ComponentId,
    /// Exact source, security, patch and configuration context.
    pub component_digest: Sha256Digest,
    /// Current raw upstream and comparison identities.
    pub current: ComponentVersion,
    /// Exact selected candidate, or the unchanged current component.
    pub target: ComponentVersion,
    /// Exact normalized observations supporting the frozen version decision.
    pub observation_digests: Vec<Sha256Digest>,
}

/// Recommends one complete update-unit vector without granting execution authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PackageUpdateIntentV1 {
    /// Exact recommendation schema discriminator.
    pub schema: String,
    /// Exact self-contained or reference export manifest, independent of origin trust.
    pub bundle_manifest_digest: Sha256Digest,
    /// Exact immutable portable inventory.
    pub inventory_digest: Sha256Digest,
    /// Exact frozen evaluation contract.
    pub scan_input_digest: Sha256Digest,
    /// Exact reproduced version decisions and coverage.
    pub assessment_digest: Sha256Digest,
    /// Required shared semantic engine profile.
    pub engine_digest: Sha256Digest,
    /// Exact policy governing candidate eligibility and evidence age.
    pub policy_digest: Sha256Digest,
    /// Exact first-observation history governing stabilization.
    pub history_digest: Sha256Digest,
    /// Exact selected source subject; aggregate names cannot substitute for it.
    pub subject_ref: String,
    /// Complete portable subject identity.
    pub subject_digest: Sha256Digest,
    /// Exact source content required by the independently authorized local planner.
    pub source_content_digest: Sha256Digest,
    /// Complete package-authored scan declaration.
    pub scan_definition_digest: Sha256Digest,
    /// Exact update unit; a display name alone cannot select a different unit.
    pub unit_id: UnitId,
    /// Complete component vector in strictly increasing logical component order.
    pub components: Vec<ComponentUpdateIntent>,
    /// Original frozen evaluation time, never renewed by copying the intent.
    pub evaluated_at: Timestamp,
    /// Exclusive oldest-source freshness boundary, never a new source reservation.
    pub valid_until: Timestamp,
}

impl PackageUpdateIntentV1 {
    /// Projects one actionable source unit from a semantically reproduced bundle.
    ///
    /// Every declared component must have a fresh complete current or eligible
    /// update decision. A partial vector, provisional candidate, manual/frozen
    /// unit or artifact without exact source context cannot create an intent.
    /// Reproduction does not establish independent provider or publisher trust.
    ///
    /// # Errors
    /// Returns an error for invalid reproduction, absent/non-source subjects,
    /// incomplete or ineligible vectors, mismatched definitions or expired evidence.
    pub fn from_bundle(bundle: &AssessmentBundleV1, subject_ref: &str) -> Result<Self> {
        bundle.verify()?;
        ensure!(
            bundle.input.profiles.contains(&Profile::Updates),
            "handoff requires the update profile"
        );
        let subject = bundle
            .data
            .inventory
            .subjects
            .iter()
            .find(|subject| subject.subject_ref == subject_ref)
            .context("handoff source subject is absent")?;
        ensure!(
            subject.kind == SubjectKind::Source,
            "handoff requires an exact source subject"
        );
        let source_content_digest = subject
            .source_content_digest
            .context("handoff source content is absent")?;
        let definition = bundle
            .data
            .definitions
            .iter()
            .find(|definition| definition.digest().ok() == Some(subject.scan_definition_digest))
            .context("handoff scan definition is absent")?;
        ensure!(
            matches!(
                definition.classification,
                Classification::Automatic | Classification::Assisted
            ),
            "handoff unit requires manual selection or is frozen"
        );
        let result = bundle
            .assessment
            .subject_results
            .iter()
            .find(|result| result.subject_ref == subject_ref)
            .context("handoff subject was not assessed")?;
        let mut components = Vec::with_capacity(definition.components.len());
        let mut valid_until = u64::MAX;
        let mut changes = false;
        for declaration in &definition.components {
            let matches = bundle
                .data
                .inventory
                .components
                .iter()
                .filter(|component| {
                    component.subject_ref == subject_ref
                        && component.component_id == declaration.component_id
                })
                .collect::<Vec<_>>();
            ensure!(
                matches.len() == 1,
                "handoff component instance is absent or ambiguous"
            );
            let component = matches[0];
            ensure!(
                component.scan_definition_digest == subject.scan_definition_digest
                    && component.source_content_digest == Some(source_content_digest)
                    && component.current == declaration.current,
                "handoff component differs from the source declaration"
            );
            let version = result
                .versions
                .iter()
                .find(|version| version.component_ref == component.component_ref)
                .context("handoff component has no version decision")?;
            ensure!(
                version.current == component.current
                    && !version.latest_known_provisional
                    && matches!(
                        version.decision,
                        VersionDecision::Current | VersionDecision::UpdateAvailable
                    )
                    && !version.observation_digests.is_empty(),
                "handoff component lacks complete eligible evidence"
            );
            let target = match version.decision {
                VersionDecision::Current => component.current.clone(),
                VersionDecision::UpdateAvailable => {
                    changes = true;
                    version
                        .eligible
                        .clone()
                        .context("handoff update has no exact eligible candidate")?
                }
                _ => anyhow::bail!("handoff version decision is not eligible"),
            };
            let binding = bundle
                .data
                .upstream
                .iter()
                .find(|binding| binding.component_ref == component.component_ref)
                .context("handoff component has no upstream evidence")?;
            let deadline = binding
                .validated_at_unix()
                .checked_add(bundle.data.policy.upstream_max_age_seconds)
                .context("handoff freshness boundary overflow")?;
            valid_until = valid_until
                .min(deadline)
                .min(binding.expires_at_unix().unwrap_or(u64::MAX));
            components.push(ComponentUpdateIntent {
                component_ref: component.component_ref.clone(),
                component_id: component.component_id.clone(),
                component_digest: component.digest()?,
                current: component.current.clone(),
                target,
                observation_digests: version.observation_digests.clone(),
            });
        }
        ensure!(
            changes && valid_until > bundle.input.evaluated_at.unix_seconds(),
            "handoff has no actionable fresh candidate"
        );
        let value = Self {
            schema: ASSESSMENT_UPDATE_INTENT_V1.into(),
            bundle_manifest_digest: Sha256Digest::of_canonical(
                BUNDLE_MANIFEST_V1,
                &bundle.manifest,
            )?,
            inventory_digest: bundle.input.inventory_digest,
            scan_input_digest: bundle.input.digest()?,
            assessment_digest: bundle.assessment.digest()?,
            engine_digest: bundle.input.engine_digest,
            policy_digest: bundle.input.policy_digest,
            history_digest: bundle.input.history_digest,
            subject_ref: subject_ref.into(),
            subject_digest: Sha256Digest::of_canonical(
                "aos.assessment-subject-context/v1",
                subject,
            )?,
            source_content_digest,
            scan_definition_digest: subject.scan_definition_digest,
            unit_id: definition.unit_id.clone(),
            components,
            evaluated_at: bundle.input.evaluated_at.clone(),
            valid_until: Timestamp::from_unix_seconds(valid_until)?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Checks the exact recommendation against its reproduced closure and explicit clock.
    ///
    /// Callers separately verify current checkout, source, controller and provider
    /// authority before creating or applying a write plan.
    ///
    /// # Errors
    /// Returns an error for a replaced/tampered closure, future evaluation or expiry.
    pub fn verify_for(&self, bundle: &AssessmentBundleV1, now: &Timestamp) -> Result<()> {
        self.validate()?;
        ensure!(
            *self == Self::from_bundle(bundle, &self.subject_ref)?,
            "handoff differs from its exact reproduced assessment"
        );
        ensure!(
            self.evaluated_at <= *now && *now < self.valid_until,
            "handoff is not currently fresh"
        );
        Ok(())
    }

    /// Decodes bounded closed recommendation bytes without performing any effects.
    ///
    /// # Errors
    /// Returns an error for ambiguous JSON, unknown members or invalid vector bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode_with_limits(bytes, "assessment update intent", LIMITS)?;
        value.validate()?;
        Ok(value)
    }

    /// Encodes the canonical bounded recommendation for client handoff.
    ///
    /// # Errors
    /// Returns an error for invalid vector structure or encoded resource bounds.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        LIMITS.check_value(&value, "assessment update intent")?;
        let bytes = aos_contract::canonical::to_vec(&value)?;
        ensure!(
            bytes.len() <= LIMITS.max_bytes,
            "assessment update intent exceeds its byte limit"
        );
        Ok(bytes)
    }

    /// Computes the exact immutable recommendation identity.
    ///
    /// # Errors
    /// Returns an error for invalid or noncanonical recommendation content.
    pub fn digest(&self) -> Result<Sha256Digest> {
        self.to_bytes()?;
        digest(ASSESSMENT_UPDATE_INTENT_V1, self)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == ASSESSMENT_UPDATE_INTENT_V1
                && !self.components.is_empty()
                && self.components.len() <= 128
                && self.valid_until > self.evaluated_at,
            "invalid update intent schema, vector or freshness boundary"
        );
        text(&self.subject_ref, 128, "handoff subject")?;
        ensure!(
            self.components
                .windows(2)
                .all(|pair| pair[0].component_id < pair[1].component_id),
            "handoff component vector must be sorted and unique"
        );
        for component in &self.components {
            text(&component.component_ref, 128, "handoff component")?;
            for version in [&component.current, &component.target] {
                text(&version.upstream_id, 512, "handoff upstream identity")?;
                text(
                    &version.comparison_version,
                    256,
                    "handoff comparison version",
                )?;
            }
            ensure!(
                !component.observation_digests.is_empty()
                    && component.observation_digests.len() <= 256,
                "handoff component lacks bounded observation support"
            );
            sorted(&component.observation_digests, "handoff observations")?;
        }
        Ok(())
    }
}
