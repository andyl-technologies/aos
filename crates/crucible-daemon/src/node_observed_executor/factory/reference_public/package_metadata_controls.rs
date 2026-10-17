//! Streams actual installed artifacts under original and changed expectations.
//!
//! The fixture derives exclusively from the closed pinned package inventory.
//! A changed expected digest exercises the same production measurement code;
//! installed files remain untouched. These are source inspection observations,
//! not native execution, path enrollment or behavioral qualification.

use super::{Artifact, InstalledPublicReferencePackage, MAXIMUM_CLOSURE_BYTES};
use crate::node_observed_executor::NodeObservedError;
use crucible_node_contract::{Bytes, ContentRef, canonical};
use serde::Serialize;

#[derive(Serialize)]
struct ArtifactRow {
    role: String,
    path: std::path::PathBuf,
    original: ContentRef,
    changed_expectation: ContentRef,
}

/// Retains the complete original table before any candidate native effects.
pub(in crate::node_observed_executor::factory::reference_public) struct ArtifactMeasurementPlan {
    package: ContentRef,
    rows: Vec<(String, Artifact)>,
    bytes: Vec<u8>,
    reference: ContentRef,
}

/// Retains actual source-file measurements without granting native authority.
#[derive(Serialize)]
pub(in crate::node_observed_executor::factory::reference_public) struct OriginalArtifactControls {
    schema: &'static str,
    package: ContentRef,
    fixture: ContentRef,
    fixture_bytes: Bytes,
    observed: Vec<ArtifactRow>,
    observation_kind: &'static str,
    original_refusal: &'static str,
}

impl InstalledPublicReferencePackage {
    /// Enumerates the exact pinned source/runtime/build inventory and limits.
    ///
    /// # Errors
    /// Refuses aggregate size overflow, an over-budget table or a canonical
    /// fixture that exceeds the independent metadata byte ceiling.
    pub(in crate::node_observed_executor::factory::reference_public) fn artifact_measurement_plan(
        &self,
    ) -> Result<ArtifactMeasurementPlan, NodeObservedError> {
        let rows = self
            .manifest
            .artifacts
            .iter()
            .map(|(role, artifact)| (format!("executable/{role}"), artifact.clone()))
            .chain(
                self.manifest
                    .source_artifacts
                    .iter()
                    .map(|(role, artifact)| (format!("source/{role}"), artifact.clone())),
            )
            .chain(
                self.runtime
                    .objects
                    .iter()
                    .enumerate()
                    .map(|(index, artifact)| (format!("runtime-elf/{index}"), artifact.clone())),
            )
            .chain([
                (
                    "runtime-reference-graph".into(),
                    self.runtime.reference_graph.clone(),
                ),
                (
                    "build-reference-graph".into(),
                    self.runtime.build_reference_graph.clone(),
                ),
            ])
            .chain(
                self.runtime
                    .build_tools
                    .iter()
                    .map(|(role, artifact)| (format!("build-tool/{role}"), artifact.clone())),
            )
            .collect::<Vec<_>>();
        let mut total = 0u64;
        let mut declared = Vec::with_capacity(rows.len());
        for (role, artifact) in &rows {
            total = total
                .checked_add(artifact.content.length.get())
                .filter(|total| *total <= MAXIMUM_CLOSURE_BYTES)
                .ok_or_else(|| super::refused("artifact measurement table byte ceiling"))?;
            declared.push(
                serde_json::json!({"role":role,"path":artifact.path,"content":artifact.content}),
            );
        }
        let bytes = canonical::canonical_json(&serde_json::json!({
            "schema":"crucible.reference.artifact-measurement-plan.v1",
            "package":self.identity(),"artifacts":declared,
            "maximum_artifact_bytes":super::MAXIMUM_ARTIFACT_BYTES,
            "maximum_original_table_bytes":MAXIMUM_CLOSURE_BYTES,
            "source_measurement":"the same production Artifact::measure streams each original file under both its authentic and changed expected digest",
            "changed_digest_recipe":"replace first original digest hexadecimal nibble with 1 when 0, otherwise 0; preserve original path/length/media-type/algorithm/domain",
            "expected_refusal":"installed public reference artifact bytes differ",
            "limitations":["source inspection only","no installed file mutation","no arbitrary path enrollment or Ready","no future native behavior or complete qualification claim"]
        }))?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(super::refused("artifact measurement fixture byte ceiling"));
        }
        Ok(ArtifactMeasurementPlan {
            package: self.identity().clone(),
            rows,
            reference: canonical::content_ref(&bytes, "application/json")?,
            bytes,
        })
    }
}

impl ArtifactMeasurementPlan {
    /// Borrows the complete predeclared source inventory and independent recipe.
    pub(in crate::node_observed_executor::factory::reference_public) fn fixture(
        &self,
    ) -> serde_json::Value {
        serde_json::json!({"reference":self.reference,"bytes":Bytes::new(self.bytes.clone())})
    }

    /// Streams unchanged original files and independently rejects false hashes.
    ///
    /// # Errors
    /// Refuses changed package/table identities, unavailable original files or
    /// any negative that fails to reach the precise content mismatch predicate.
    pub(in crate::node_observed_executor::factory::reference_public) fn inspect(
        &self,
        package: &InstalledPublicReferencePackage,
    ) -> Result<OriginalArtifactControls, NodeObservedError> {
        let fresh = package.artifact_measurement_plan()?;
        if package.identity() != &self.package
            || fresh.reference != self.reference
            || fresh.bytes != self.bytes
        {
            return Err(super::refused("original artifact control table changed"));
        }
        let mut observed = Vec::with_capacity(self.rows.len());
        for (role, original) in &self.rows {
            original.measure()?;
            let mut changed = original.clone();
            let nibble = if changed.content.hash.digest.starts_with('0') {
                "1"
            } else {
                "0"
            };
            changed.content.hash.digest.replace_range(..1, nibble);
            match changed.measure() {
                Err(NodeObservedError::Native(reason))
                    if reason == "installed public reference artifact bytes differ" => {}
                _ => {
                    return Err(super::refused(
                        "artifact negative did not reach its exact mismatch",
                    ));
                }
            }
            // Recheck the authentic expectation after the negative measurement;
            // a transient read failure cannot become an integrity-rejection pass.
            original.measure()?;
            observed.push(ArtifactRow {
                role: role.clone(),
                path: original.path.clone(),
                original: original.content.clone(),
                changed_expectation: changed.content,
            });
        }
        Ok(OriginalArtifactControls {
            schema: "crucible.reference.original-artifact-integrity-controls.v1",
            package: self.package.clone(),
            fixture: self.reference.clone(),
            fixture_bytes: Bytes::new(self.bytes.clone()),
            observed,
            observation_kind: "source inspection of unchanged real files under inert changed expectations",
            original_refusal: "installed public reference artifact bytes differ",
        })
    }
}
