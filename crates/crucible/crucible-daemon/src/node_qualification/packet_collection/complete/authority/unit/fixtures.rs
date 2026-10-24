//! Retains full settled17 fixture records beneath a versioned reference document.
//!
//! ```text
//! {schema:"crucible.complete-scene.qualification-fixtures/1",
//!  coordinator:ContentRef, launches:[ContentRef;3], world:WorldBinding,
//!  requirements:ScenarioRequirements, scope:"original complete ..."}
//! ```
//!
//! Each referenced body retains its exact canonical bytes in the same private
//! authority content map. The independent one-MiB object and two-MiB aggregate
//! bounds remain unchanged. Older declarations retain their original inline
//! fixture tuple and identity. No native codec, query limit or admission changes.

use super::*;

const PURPOSE: &str = "original complete native-three/Host2 preparation collection; all effects and capture remain independently refused";

#[derive(Serialize)]
struct FixtureReferences<'a> {
    schema: &'static str,
    coordinator: ContentRef,
    launches: [ContentRef; 3],
    world: &'a WorldBinding,
    requirements: &'a ScenarioRequirements,
    scope: &'static str,
}

/// Retains the actual fixture records without treating metadata as permission.
///
/// # Errors
/// Refuses mixed or unavailable original declarations, canonical serialization,
/// any independently over-bound record or an inconsistent existing body.
pub(super) fn retain(
    bodies: &mut BTreeMap<ContentRef, Vec<u8>>,
    request: &PacketCompleteCollectionRequest<'_>,
) -> Result<ContentRef, QualificationError> {
    let selected = request.roster.sources[0]
        .requires_restored_capture17_scope_data()
        .map_err(|error| QualificationError::Evidence(error.to_string()))?;
    for source in &request.roster.sources[1..] {
        if source
            .requires_restored_capture17_scope_data()
            .map_err(|error| QualificationError::Evidence(error.to_string()))?
            != selected
        {
            return Err(refused());
        }
    }
    if !selected {
        return super::retain(
            bodies,
            &(
                request.coordinator,
                &request.launches,
                request.world,
                request.requirements,
                PURPOSE,
            ),
        );
    }

    // Install each original complete record before constructing the document.
    // The references do not replace or summarize any launch or coordinator data.
    let coordinator = super::retain(bodies, request.coordinator)?;
    let [first, second, third] = request
        .launches
        .each_ref()
        .map(|launch| super::retain(bodies, launch));
    let launches = [first?, second?, third?];
    super::retain(
        bodies,
        &FixtureReferences {
            schema: "crucible.complete-scene.qualification-fixtures/1",
            coordinator,
            launches,
            world: request.world,
            requirements: request.requirements,
            scope: PURPOSE,
        },
    )
}
