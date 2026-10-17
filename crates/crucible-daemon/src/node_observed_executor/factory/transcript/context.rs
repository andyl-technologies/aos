//! Complete immutable source context from the actual installed enrollment registry.
//!
//! Enrollment references are not reconstructed from execution labels. The
//! original bounded bodies are read from the same installed evidence that
//! authenticated the native resources and sealed their complete graph.

use crucible::node_admission::AdmissionEvidence;

use super::*;

const MAXIMUM_ENROLLMENT_BYTES: usize = 1024 * 1024;
const MAXIMUM_CONTEXT_OBJECTS: usize = 4_000;
const MAXIMUM_CONTEXT_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn source_context(
    graph: &AdmittedGraph,
    selections: &[InstalledNodeSelection],
    scenario: &NodeScenario,
    configuration: &NodeRunConfiguration,
    evidence: &trust::InstalledEvidence,
) -> Result<Vec<InputPayload>, NodeObservedError> {
    let original = recording::source_context(graph, selections, scenario, configuration)?;
    let mut materialized = Vec::new();
    for object in original {
        if object.reference.media_type
            == "application/vnd.crucible.installed-reference-recording-context+json"
        {
            let fragments = context_fragments::fragment_source_object(object.clone())?;
            if let Some(manifest) = fragments.iter().find(|fragment| {
                fragment.reference.media_type == context_fragments::FRAGMENT_MEDIA_TYPE
            }) && context_fragments::reconstruct_source_object(
                manifest,
                &fragments,
                MAXIMUM_CONTEXT_BYTES,
            )? != object
            {
                return Err(refused(
                    "original installed recording context fragment roundtrip differs",
                ));
            }
            materialized.extend(fragments);
        } else {
            materialized.push(object);
        }
    }
    let mut objects = materialized
        .into_iter()
        .map(|object| (object.reference.hash.digest.clone(), object))
        .collect::<BTreeMap<_, _>>();
    let mut total = objects
        .values()
        .try_fold(0usize, |total, object| {
            total.checked_add(object.bytes.len())
        })
        .ok_or_else(|| refused("recording source context length overflow"))?;

    for node in graph.node_ids() {
        let reference = &graph
            .binding(node)
            .ok_or_else(|| refused("recording source omitted an enrolled peer"))?
            .authority
            .host_receipt;
        if let Some(original) = objects.get(&reference.hash.digest) {
            if &original.reference != reference {
                return Err(refused("recording enrollment reference metadata conflicts"));
            }
            continue;
        }
        let declared = usize::try_from(reference.length.get())
            .map_err(|_| refused("recording enrollment length is not representable"))?;
        let next = total
            .checked_add(declared)
            .ok_or_else(|| refused("recording source context length overflow"))?;
        if declared > MAXIMUM_ENROLLMENT_BYTES
            || objects.len() >= MAXIMUM_CONTEXT_OBJECTS
            || next > MAXIMUM_CONTEXT_BYTES
        {
            return Err(refused(
                "recording enrollment exceeds its original context reservation",
            ));
        }
        let bytes = evidence
            .content(reference, MAXIMUM_ENROLLMENT_BYTES)
            .map_err(native)?;
        reference.verify(&bytes)?;
        objects.insert(
            reference.hash.digest.clone(),
            InputPayload {
                reference: reference.clone(),
                bytes,
            },
        );
        total = next;
    }
    Ok(objects.into_values().collect())
}
