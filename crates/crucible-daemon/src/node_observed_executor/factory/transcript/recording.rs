//! Materialized installed source context and complete native recording export.

use crucible::node_adapters::transcript::{
    AuthenticatedTranscript, TranscriptArchive, TranscriptLimits,
};

use super::*;

const CONTEXT_MEDIA_TYPE: &str =
    "application/vnd.crucible.installed-reference-recording-context+json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InstalledRecordingContext {
    pub(super) schema_version: u16,
    pub(super) selections: Vec<InstalledNodeSelection>,
    pub(super) scenario: NodeScenario,
    pub(super) configuration: NodeRunConfiguration,
}

/// Owns an inactive installed world and its original native recording handles.
///
/// The caller executes the prepared world through the common runtime. Export
/// refuses outstanding native publication custody and incomplete capture; it
/// never substitutes a later run or a shortened transcript for the source.
pub struct InstalledRecordedWorld {
    /// Owns the genuine inactive native world and its reserved retirement slot.
    pub prepared: InstalledPreparedWorld,
    /// Retains original capture handles independently of native world ownership.
    pub recording: InstalledReferenceRecording,
}

/// Retains one-shot recording exports after a prepared world moves into its runtime.
pub struct InstalledReferenceRecording {
    handles: BTreeMap<Id, RecordingHandle>,
}

impl InstalledReferenceRecording {
    /// Persists each complete original node recording under the archive signer.
    ///
    /// All handles are closed before any document is persisted. A failed export
    /// cannot be retried by running more physical work on a replacement source.
    /// Successfully persisted documents retain their actual source attempt and
    /// complete owner lineage even if a later archive write fails.
    ///
    /// # Errors
    /// Refuses pending source custody, failed/incomplete capture, repeated export
    /// or nondurable archive storage. It does not claim all-or-nothing file
    /// publication across distinct node documents.
    pub fn persist(
        &self,
        archive: &TranscriptArchive,
    ) -> Result<BTreeMap<Id, AuthenticatedTranscript>, NodeObservedError> {
        let captures = self
            .handles
            .iter()
            .map(|(node, handle)| Ok((node.clone(), handle.finish().map_err(native)?)))
            .collect::<Result<Vec<_>, NodeObservedError>>()?;
        captures
            .into_iter()
            .map(|(node, source)| Ok((node, archive.persist(source).map_err(native)?)))
            .collect()
    }
}

impl InstalledNodeCatalog {
    /// Prepares genuine installed native nodes with complete boundary recording.
    ///
    /// Every native reference node is wrapped after authentic catalog enrollment
    /// and complete graph admission. Other installed nodes keep their actual
    /// implementations. The recording retains the same admitted descriptors,
    /// world, original semantic IDs and origin guarantees; it grants no replay
    /// qualification or world activation by itself.
    ///
    /// # Errors
    /// Refuses invalid capture reservations, an unsupported source topology,
    /// changed installed artifacts, unavailable custody or native preparation.
    pub fn prepare_recorded_world(
        &mut self,
        selections: &[InstalledNodeSelection],
        scenario: NodeScenario,
        configuration: &NodeRunConfiguration,
        execution: ExecutionId,
        limits: TranscriptLimits,
    ) -> Result<InstalledRecordedWorld, NodeObservedError> {
        limits.validate().map_err(native)?;
        configuration.artifact(&scenario)?;
        if !selections.iter().any(|selection| {
            matches!(
                selection.kind,
                InstalledNodeKind::ReferenceDevice { .. }
                    | InstalledNodeKind::ReferenceNativeLinked { .. }
            )
        }) || selections.iter().any(|selection| {
            !matches!(
                selection.kind,
                InstalledNodeKind::HostClock
                    | InstalledNodeKind::HostNetLink { .. }
                    | InstalledNodeKind::ReferenceDevice { .. }
                    | InstalledNodeKind::ReferenceNativeLinked { .. }
            )
        }) {
            return Err(refused(
                "installed recording requires the qualified clock/link/reference source topology",
            ));
        }
        let retained_scenario = scenario.clone();
        let mut recorder = ReferenceRecorder {
            selections,
            scenario: &retained_scenario,
            configuration,
            attempt: Id::new(format!("observed/{}", execution_text(execution)))?,
            limits,
            handles: BTreeMap::new(),
            #[cfg(test)]
            preparation_fault: None,
        };
        let artifacts = self.artifacts.clone();
        let prepared = self
            .prepare_world_with_source(
                selections,
                scenario,
                execution,
                PreparationSource::default(),
                &artifacts,
                Some(&mut recorder),
            )?
            .0;
        Ok(InstalledRecordedWorld {
            prepared,
            recording: InstalledReferenceRecording {
                handles: recorder.handles,
            },
        })
    }
}

pub(super) fn source_context(
    graph: &AdmittedGraph,
    selections: &[InstalledNodeSelection],
    scenario: &NodeScenario,
    configuration: &NodeRunConfiguration,
) -> Result<Vec<InputPayload>, NodeObservedError> {
    let mut objects = BTreeMap::new();
    for object in &scenario.content {
        retain(&mut objects, object.reference.clone(), object.bytes.clone())?;
    }
    let declared = InstalledRecordingContext {
        schema_version: 1,
        selections: selections.to_vec(),
        scenario: scenario.clone(),
        configuration: configuration.clone(),
    };
    let bytes = json_bytes(&declared)?;
    let reference = canonical::content_ref(&bytes, CONTEXT_MEDIA_TYPE)?;
    retain(&mut objects, reference, bytes)?;

    let bytes = json_bytes(graph.world())?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    retain(&mut objects, reference, bytes)?;
    for descriptor in &scenario.descriptors {
        let binding = graph
            .binding(&descriptor.id)
            .ok_or_else(|| refused("recorded world omitted an actual peer binding"))?;
        let bytes = json_bytes(binding)?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        retain(&mut objects, reference, bytes)?;
    }
    Ok(objects.into_values().collect())
}

fn retain(
    objects: &mut BTreeMap<String, InputPayload>,
    reference: ContentRef,
    bytes: Vec<u8>,
) -> Result<(), NodeObservedError> {
    reference.verify(&bytes)?;
    if let Some(original) = objects.get(&reference.hash.digest) {
        if original.reference != reference || original.bytes != bytes {
            return Err(refused(
                "recording context has conflicting content metadata",
            ));
        }
        return Ok(());
    }
    if objects.len() >= 4_000 {
        return Err(refused(
            "recording context exceeds its finite object ceiling",
        ));
    }
    let total = objects.values().try_fold(bytes.len(), |total, object| {
        total.checked_add(object.bytes.len())
    });
    if total.is_none_or(|total| total > 64 * 1024 * 1024) {
        return Err(refused("recording context exceeds its finite byte ceiling"));
    }
    objects.insert(
        reference.hash.digest.clone(),
        InputPayload { reference, bytes },
    );
    Ok(())
}

fn json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, NodeObservedError> {
    Ok(canonical::canonical_json(&serde_json::to_value(value)?)?)
}
