//! Inspects authenticated reader history before a separate conditional installation.
//!
//! This fixture inspector retains signed originals and regenerates their native
//! metadata. Its report grants no native class, target readiness or capture facet.
//! A target still needs its own complete model definition and installed policy.

use std::collections::BTreeMap;

use crucible::node_adapters::transcript::{AuthenticatedTranscript, TranscriptAction};
use crucible::node_contract::{SavedOriginalInputLineage, SavedOriginalPublication};
use crucible::node_scheduling::InputPayload;
use crucible_node_contract::{ContentRef, Id, NodeBinding, U64, canonical};
use serde::Deserialize;

use super::super::package::InstalledReaderPackage;
use crate::node_observed_executor::factory::transcript::{
    ORIGINAL_CONTEXT_FRAGMENT_MEDIA_TYPE, reconstruct_fixture_context,
};

/// Identifies a refusal by the installed original-source inspection procedure.
#[derive(Debug)]
pub(super) struct InspectionError {
    reason: String,
}

impl InspectionError {
    pub(super) fn from_error(error: impl std::fmt::Display) -> Self {
        Self {
            reason: error.to_string(),
        }
    }
}

impl std::fmt::Display for InspectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for InspectionError {}

impl From<String> for InspectionError {
    fn from(reason: String) -> Self {
        Self { reason }
    }
}

impl From<&str> for InspectionError {
    fn from(reason: &str) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[path = "conditional_native.rs"]
mod native;

const MAXIMUM_CONTEXT_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_CONTEXT_OBJECTS: usize = 4096;
const MAXIMUM_DIRECT_EDGES: usize = 65_536;
const LINEAGE_MEDIA: &str = "application/vnd.crucible.transcript-original-lineage+json;version=2";

/// Accounts for unique retained bodies before allocating another body copy.
#[derive(Default)]
struct ObjectCredit {
    bytes: usize,
}

pub(super) struct InspectedReaderHistory {
    pub(super) originals: BTreeMap<Id, AuthenticatedTranscript>,
    pub(super) bindings: BTreeMap<Id, NodeBinding>,
    pub(super) objects: BTreeMap<ContentRef, Vec<u8>>,
    pub(super) publications: Vec<SavedOriginalPublication>,
    pub(super) inputs: Vec<SavedOriginalInputLineage>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedLineage {
    schema_version: u16,
    source_capture: crucible::node_contract::SavedRuntimeActivation,
    node: Id,
    interaction: Id,
    lineage: RecordedKind,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RecordedKind {
    Publication {
        publication: Box<SavedOriginalPublication>,
    },
    Input {
        input: Box<SavedOriginalInputLineage>,
    },
}

/// Checks a fixed original triple while borrowing all signer-authenticated seals.
///
/// The caller retains the originals on every returned refusal. Native source
/// classes remain unaccepted; this checks only the recorded candidate scope.
pub(super) fn inspect(
    package: &InstalledReaderPackage,
    originals: &BTreeMap<Id, AuthenticatedTranscript>,
) -> Result<InspectedReaderHistory, InspectionError> {
    let names = originals.keys().map(Id::as_str).collect::<Vec<_>>();
    if names != ["disk", "link", "source"] {
        return Err("recorded reader roster differs".into());
    }
    let first = originals
        .values()
        .next()
        .ok_or("recorded source is empty")?;
    let mut objects = BTreeMap::new();
    let mut object_credit = ObjectCredit::default();
    let mut bindings = BTreeMap::new();
    let mut publications = Vec::new();
    let mut inputs = Vec::new();
    publications
        .try_reserve_exact(9)
        .map_err(InspectionError::from_error)?;
    inputs
        .try_reserve_exact(4)
        .map_err(InspectionError::from_error)?;

    for (node, source) in originals {
        let tape = source.transcript();
        if tape.schema_version != 2
            || tape.origin.route.node != *node
            || tape.origin.attempt != first.transcript().origin.attempt
            || tape.origin.activation != first.transcript().origin.activation
            || tape.origin.repeatability != first.transcript().origin.repeatability
            || tape.origin.route.owners.len() != 1
        {
            return Err("signed source activation, taint or actor scope differs".into());
        }
        let context = materialize_context(&tape.origin.context)?;
        let binding_bytes = context
            .get(&tape.origin.source_binding)
            .ok_or("original binding body is absent")?;
        let binding: NodeBinding = decode(binding_bytes)?;
        let owner = &tape.origin.route.owners[0];
        let profile = package
            .profile(
                node.clone(),
                owner.owner.clone(),
                U64::new(1000),
                U64::new(1_000_000_000),
                node.as_str() == "source",
            )
            .map_err(InspectionError::from_error)?;
        let (regenerated, _) = profile
            .bind_qualified(
                binding.authority.clone(),
                &binding.compatibility.qualification_refs,
            )
            .map_err(InspectionError::from_error)?;
        if binding != regenerated
            || binding.authority.incarnation_id != owner.incarnation
            || binding.authority.owner_generation != owner.generation
            || profile.guarantees.repeatability != tape.origin.repeatability
        {
            return Err("original source metadata or owner differs from installed package".into());
        }
        bindings.insert(node.clone(), binding);
        for (reference, bytes) in context {
            retain(&mut objects, &mut object_credit, &reference, &bytes)?;
        }

        let mut action_counts = [0usize; 5];
        for (ordinal, record) in tape.records.iter().enumerate() {
            if record.sequence.get() != ordinal as u64 {
                return Err("recorded request ordering differs".into());
            }
            let slot = match record.request.action {
                TranscriptAction::StageInput => Some(0),
                TranscriptAction::Begin => Some(1),
                TranscriptAction::Complete => Some(2),
                TranscriptAction::CloseWindow => Some(3),
                TranscriptAction::Acknowledge => Some(4),
                TranscriptAction::Observe => None,
                TranscriptAction::Cancel => {
                    return Err("cancel trajectory is outside this source scope".into());
                }
            };
            if let Some(slot) = slot {
                action_counts[slot] += 1;
            }
            record
                .request
                .request_metadata()
                .map_err(InspectionError::from_error)?;
            record
                .response
                .verify(&record.response_bytes)
                .map_err(InspectionError::from_error)?;
            retain(
                &mut objects,
                &mut object_credit,
                &record.request.content,
                &record.request.bytes,
            )?;
            retain(
                &mut objects,
                &mut object_credit,
                &record.response,
                &record.response_bytes,
            )?;
            for object in &record.evidence {
                retain(
                    &mut objects,
                    &mut object_credit,
                    &object.reference,
                    &object.bytes,
                )?;
                if object.reference.media_type != LINEAGE_MEDIA {
                    continue;
                }
                let metadata: RecordedLineage = decode(&object.bytes)?;
                if metadata.schema_version != 2
                    || metadata.source_capture != tape.origin.activation
                    || metadata.node != *node
                    || metadata.interaction != record.request.identity
                {
                    return Err("recorded original lineage interaction differs".into());
                }
                match metadata.lineage {
                    RecordedKind::Publication { publication } => {
                        if record.request.action != TranscriptAction::Complete
                            || publication.origin.operation_id != record.request.identity
                            || publication.origin.world_binding_hash
                                != tape.origin.activation.world_binding_hash
                            || publication.origin.activation_id
                                != tape.origin.activation.activation_id
                            || publication.origin.execution_owner_id != owner.owner
                            || publication.origin.incarnation_id != owner.incarnation
                            || publication.origin.owner_generation != owner.generation
                        {
                            return Err("FIRST publication scope differs from native source".into());
                        }
                        if publications.len() >= 9 {
                            return Err("original publication reservation exhausted".into());
                        }
                        publications.push(*publication);
                    }
                    RecordedKind::Input { input } => {
                        if record.request.action != TranscriptAction::StageInput
                            || input.schema_version != 1
                            || input.source.source_activation != tape.origin.activation
                            || input.source.node != *node
                            || input.source.stage_operation != record.request.identity
                            || input.source.owners != tape.origin.route.owners
                        {
                            return Err("FIRST input scope differs from native source".into());
                        }
                        if inputs.len() >= 4 {
                            return Err("original input reservation exhausted".into());
                        }
                        inputs.push(*input);
                    }
                }
            }
        }
        if action_counts != [3; 5] {
            return Err("original nine-window trajectory is incomplete".into());
        }
    }
    if publications.len() != 9 || inputs.len() != 4 {
        return Err("original producer or consumer population is incomplete".into());
    }
    for claim in &publications {
        check_rows(claim, &objects)?;
    }
    for input in &inputs {
        for claim in &input.publications {
            check_rows(claim, &objects)?;
            if !publications.iter().any(|original| original == claim) {
                return Err("consumer claim has no exact original producer".into());
            }
        }
    }
    check_consistent_rows(&publications)?;
    native::verify_all(&publications, &bindings, &objects)?;

    Ok(InspectedReaderHistory {
        originals: originals.clone(),
        bindings,
        objects,
        publications,
        inputs,
    })
}

/// Exercises named inert refusals without changing any authenticated source seal.
fn verify_adverse_controls(history: &InspectedReaderHistory) -> Result<(), InspectionError> {
    let original = history
        .publications
        .first()
        .ok_or("no original publication")?;

    let mut missing_root = original.clone();
    missing_root.origin.measurement =
        canonical::content_ref(b"absent", "text/plain").map_err(InspectionError::from_error)?;
    if check_rows(&missing_root, &history.objects).is_ok() {
        return Err("missing-original-root was accepted".into());
    }

    let mut conflicting = original.clone();
    let row = conflicting
        .rows
        .iter_mut()
        .find(|row| !row.dependencies.is_empty())
        .ok_or("original publication has no dependency")?;
    row.dependencies.clear();
    if check_consistent_rows(&[original.clone(), conflicting]).is_ok() {
        return Err("conflicting-original-row was accepted".into());
    }

    let mut cycle = original.clone();
    cycle.objects.truncate(2);
    cycle.rows.truncate(2);
    let [first, second] = cycle.objects.as_slice() else {
        return Err("original geometry has fewer than two roles".into());
    };
    cycle.rows[0].dependencies = vec![second.clone()];
    cycle.rows[1].dependencies = vec![first.clone()];
    cycle.published = first.clone();
    cycle.origin.observation_batch = first.clone();
    cycle.origin.stop_receipt = first.clone();
    cycle.origin.measurement = first.clone();
    if check_graph(&cycle)
        .err()
        .as_ref()
        .map(|error| error.reason.as_str())
        != Some("original direct rows contain a cycle")
    {
        return Err("reachable-original-cycle refused at a different predicate".into());
    }

    let mut foreign_grant = history.publications.clone();
    foreign_grant[0].origin.grant_id = history.publications[1].origin.grant_id.clone();
    if native::verify_all(&foreign_grant, &history.bindings, &history.objects)
        .err()
        .as_ref()
        .map(|error| error.reason.as_str())
        != Some("recorded native/publication association differs")
    {
        return Err("foreign-original-grant refused at a different predicate".into());
    }

    let mut retagged = history.publications.clone();
    retagged[0].origin.measurement.media_type = "application/octet-stream".into();
    if native::verify_all(&retagged, &history.bindings, &history.objects)
        .err()
        .as_ref()
        .map(|error| error.reason.as_str())
        != Some("recorded native role differs: application/octet-stream")
    {
        return Err("typed-original-media-retag refused at a different predicate".into());
    }

    let mut changed_body = history.objects.clone();
    changed_body
        .get_mut(&original.origin.measurement)
        .ok_or("original measurement absent")?
        .push(b' ');
    if native::verify_all(&history.publications, &history.bindings, &changed_body).is_ok() {
        return Err("changed-body-under-original-reference was accepted".into());
    }
    Ok(())
}

fn materialize_context(
    objects: &[InputPayload],
) -> Result<BTreeMap<ContentRef, Vec<u8>>, InspectionError> {
    if objects.len() > MAXIMUM_CONTEXT_OBJECTS {
        return Err("source context role credit exceeded".into());
    }
    let mut result = BTreeMap::new();
    let mut total = 0usize;
    let mut credit = ObjectCredit::default();
    for object in objects {
        let original = if object.reference.media_type == ORIGINAL_CONTEXT_FRAGMENT_MEDIA_TYPE {
            reconstruct_fixture_context(object, objects, MAXIMUM_CONTEXT_BYTES)
                .map_err(InspectionError::from_error)?
        } else {
            object.clone()
        };
        total = total
            .checked_add(original.bytes.len())
            .ok_or("context extent overflow")?;
        if total > MAXIMUM_CONTEXT_BYTES {
            return Err("source context byte credit exceeded".into());
        }
        retain(
            &mut result,
            &mut credit,
            &original.reference,
            &original.bytes,
        )?;
    }
    Ok(result)
}

fn retain(
    objects: &mut BTreeMap<ContentRef, Vec<u8>>,
    credit: &mut ObjectCredit,
    reference: &ContentRef,
    bytes: &[u8],
) -> Result<(), InspectionError> {
    reference
        .verify(bytes)
        .map_err(InspectionError::from_error)?;
    if let Some(original) = objects.get(reference) {
        if original != bytes {
            return Err("one original full reference has different bodies".into());
        }
    } else {
        let total = credit
            .bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= MAXIMUM_CONTEXT_BYTES)
            .ok_or("original retained body credit exceeded")?;
        if objects.len() >= MAXIMUM_CONTEXT_OBJECTS {
            return Err("original retained role credit exceeded".into());
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(bytes.len())
            .map_err(InspectionError::from_error)?;
        retained.extend_from_slice(bytes);
        objects.insert(reference.clone(), retained);
        credit.bytes = total;
    }
    Ok(())
}

fn check_rows(
    claim: &SavedOriginalPublication,
    objects: &BTreeMap<ContentRef, Vec<u8>>,
) -> Result<(), InspectionError> {
    if claim.objects.len() != claim.rows.len()
        || claim.objects.len() > 4096
        || claim.objects.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("original direct-row roster differs".into());
    }
    for (reference, row) in claim.objects.iter().zip(&claim.rows) {
        if reference != &row.object
            || !objects.contains_key(reference)
            || row.dependencies.windows(2).any(|pair| pair[0] >= pair[1])
            || row.dependencies.contains(reference)
            || row
                .dependencies
                .iter()
                .any(|dependency| !claim.objects.contains(dependency))
        {
            return Err("original direct-row closure is incomplete".into());
        }
    }
    for root in [
        &claim.published,
        &claim.origin.observation_batch,
        &claim.origin.stop_receipt,
        &claim.origin.measurement,
    ] {
        if !claim.objects.contains(root) {
            return Err("original publication root is absent".into());
        }
    }
    check_graph(claim)?;
    Ok(())
}

/// Requires one original full-reference role to retain one dependency meaning.
fn check_consistent_rows(claims: &[SavedOriginalPublication]) -> Result<(), InspectionError> {
    for (index, claim) in claims.iter().enumerate() {
        for row in &claim.rows {
            for previous in &claims[..index] {
                if let Ok(found) = previous.objects.binary_search(&row.object)
                    && previous.rows[found].dependencies != row.dependencies
                {
                    return Err("original shared dependency role differs".into());
                }
            }
        }
    }
    Ok(())
}

fn check_graph(claim: &SavedOriginalPublication) -> Result<(), InspectionError> {
    let edges = claim.rows.iter().try_fold(0usize, |total, row| {
        total
            .checked_add(row.dependencies.len())
            .filter(|total| *total <= MAXIMUM_DIRECT_EDGES)
            .ok_or("original direct edge credit exceeded")
    })?;
    let index = |reference: &ContentRef| {
        claim
            .objects
            .binary_search(reference)
            .map_err(|_| "original dependency has no role")
    };
    let mut queue = Vec::new();
    queue
        .try_reserve_exact(edges + 4)
        .map_err(InspectionError::from_error)?;
    for root in [
        &claim.published,
        &claim.origin.observation_batch,
        &claim.origin.stop_receipt,
        &claim.origin.measurement,
    ] {
        queue.push(index(root)?);
    }
    let mut reachable = reserved_bitmap(claim.objects.len())?;
    while let Some(current) = queue.pop() {
        if reachable[current] {
            continue;
        }
        reachable[current] = true;
        for dependency in &claim.rows[current].dependencies {
            queue.push(index(dependency)?);
        }
    }
    if reachable.iter().any(|present| !present) {
        return Err("original direct rows contain an unrelated role".into());
    }

    // A row becomes complete only after all of its direct dependencies. This
    // authenticates data geometry; the installed native codec still owns edges.
    let mut completed = reserved_bitmap(claim.objects.len())?;
    for _ in 0..claim.objects.len() {
        let mut next = None;
        for (current, row) in claim.rows.iter().enumerate() {
            if completed[current] {
                continue;
            }
            let mut ready = true;
            for dependency in &row.dependencies {
                ready &= completed[index(dependency)?];
            }
            if ready {
                next = Some(current);
                break;
            }
        }
        let current = next.ok_or("original direct rows contain a cycle")?;
        completed[current] = true;
    }
    // Direct rows remain the stored proof format. Charge their complete derived
    // ancestry separately so a small dense DAG cannot bypass metadata credit.
    let mut descendants = reserved_bitmap(claim.objects.len())?;
    let mut derived = 0usize;
    for current in 0..claim.objects.len() {
        descendants.fill(false);
        queue.clear();
        for dependency in &claim.rows[current].dependencies {
            queue.push(index(dependency)?);
        }
        while let Some(next) = queue.pop() {
            if descendants[next] {
                continue;
            }
            descendants[next] = true;
            derived = derived
                .checked_add(1)
                .filter(|total| *total <= MAXIMUM_DIRECT_EDGES)
                .ok_or("original derived edge credit exceeded")?;
            for dependency in &claim.rows[next].dependencies {
                queue.push(index(dependency)?);
            }
        }
    }
    Ok(())
}

fn reserved_bitmap(length: usize) -> Result<Vec<bool>, InspectionError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(InspectionError::from_error)?;
    values.resize(length, false);
    Ok(values)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, InspectionError> {
    let value = canonical::parse_json(bytes, 1024 * 1024).map_err(InspectionError::from_error)?;
    if canonical::canonical_json(&value).map_err(InspectionError::from_error)? != bytes {
        return Err("original typed body is not canonical".into());
    }
    serde_json::from_value(value).map_err(InspectionError::from_error)
}

// Panics are assertions in this cfg(test)-only signed-source fixture.
#[cfg(test)]
#[test]
#[ignore = "requires explicitly bound original private signer and measured reader source package"]
fn authenticated_original_reader_history_regenerates_before_conditional_installation() {
    use crucible::node_adapters::transcript::{TranscriptArchive, TranscriptLimits};
    use std::path::PathBuf;

    let archive_path = PathBuf::from(
        std::env::var_os("CRUCIBLE_ORIGINAL_LINEAGE_TAPE_ARCHIVE")
            .expect("original signer must be bound"),
    );
    let evidence = PathBuf::from(
        std::env::var_os("CRUCIBLE_ORIGINAL_LINEAGE_TAPE_EVIDENCE")
            .expect("original body index must be bound"),
    );
    let manifest = PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_LINEAGE_READER_IMPLEMENTATION_MANIFEST")
            .expect("source package must be bound"),
    );
    assert!(archive_path.is_dir());
    assert!(
        archive_path
            .join("transcript-authentication-key-v1")
            .is_file()
    );
    let fixture =
        canonical::content_ref(include_bytes!("installed-fixture.json"), "application/json")
            .unwrap();
    let package = InstalledReaderPackage::load(&manifest, &fixture).unwrap();
    let archive = TranscriptArchive::open(
        &archive_path,
        TranscriptLimits {
            maximum_records: U64::new(128),
            maximum_record_bytes: U64::new(1024 * 1024),
            maximum_total_bytes: U64::new(256 * 1024 * 1024),
        },
    )
    .unwrap();
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(evidence.join("original-tape-index.json")).unwrap())
            .unwrap();
    let references: Vec<ContentRef> =
        serde_json::from_value(index["original_tapes"].clone()).unwrap();
    let mut originals = BTreeMap::new();
    for reference in references {
        let original = archive.load(&reference).unwrap();
        assert!(
            originals
                .insert(original.transcript().origin.route.node.clone(), original)
                .is_none()
        );
    }

    let inspected = inspect(&package, &originals).unwrap();

    assert_eq!(inspected.originals.len(), 3);
    assert_eq!(inspected.bindings.len(), 3);
    assert_eq!(inspected.publications.len(), 9);
    assert_eq!(inspected.inputs.len(), 4);
    assert!(!inspected.objects.is_empty());
    verify_adverse_controls(&inspected).unwrap();
    for (node, original) in &originals {
        assert_eq!(inspected.originals[node].reference(), original.reference());
        assert_eq!(inspected.originals[node].bytes(), original.bytes());
    }
}
