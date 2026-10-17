//! Prepares the distinct conditional triple from authentic signed native history.
//!
//! This preparation gate dispatches no replay response or capture. The later
//! whole-world cohort must still consume original controls, capture Runtime7 and
//! demonstrate fresh continuation under owning published runtime custody.

use super::conditional_source::InspectionError;

use std::{collections::BTreeMap, path::PathBuf, rc::Rc};

use crucible::{
    node_adapters::transcript::{TranscriptArchive, TranscriptLimits, TranscriptReplayNode},
    node_contract::NodeRoute,
};
use crucible_node_contract::{ContentRef, Id, U64, canonical};

use super::{
    InstalledReaderPackage, conditional_admission, conditional_policy::ConditionalPolicy,
    conditional_profile::ConditionalProfile, conditional_source, graph,
};

#[test]
#[ignore = "requires original private signed tapes and independently pinned reader package"]
fn signed_original_triple_prepares_distinct_complete_conditional_models()
-> Result<(), InspectionError> {
    let profile = load_profile("first-target")?;
    let graph = conditional_admission::admit(&profile)?;
    let installed = ConditionalPolicy::install(Rc::clone(&profile))?;

    // Construction is distinct from Ready, original response consumption and
    // the later Runtime7 capture. Keep every original seal in the profile.
    let mut models = Vec::new();
    models
        .try_reserve_exact(3)
        .map_err(|error| error.to_string())?;
    for node in ["disk", "link", "source"] {
        let node = Id::new(node).map_err(|error| error.to_string())?;
        let binding = graph.binding(&node).ok_or("target binding absent")?;
        let route = NodeRoute {
            node: node.clone(),
            owners: profile
                .activation
                .owners
                .iter()
                .filter(|owner| owner.owner == binding.compatibility.execution_owner.id)
                .cloned()
                .collect(),
        };
        let source = profile
            .history
            .originals
            .get(&node)
            .ok_or("source tape absent")?;
        models.push(
            TranscriptReplayNode::prepare(
                source.clone(),
                &graph,
                route,
                &source.transcript().origin.context,
                &installed,
            )
            .map_err(|error| error.to_string())?,
        );
    }
    if models.len() != 3 {
        return Err("conditional prepared roster differs".into());
    }
    Ok(())
}

/// Checks immutable reconstruction bodies before any target control or publication.
#[test]
#[ignore = "requires authentic private signed tapes and the original measured package"]
fn signed_original_conditional_immutable_codec_preflight() -> Result<(), InspectionError> {
    let profile = load_profile("immutable-codec-preflight")?;
    let graph = conditional_admission::admit(&profile)?;
    let factory =
        super::conditional_capture_factory::ConditionalCaptureFactory::install(profile, &graph)
            .map_err(InspectionError::from_error)?;
    factory
        .preflight_immutable()
        .map_err(InspectionError::from_error)
}

fn read_small_json(path: &std::path::Path) -> Result<serde_json::Value, InspectionError> {
    use std::io::Read;

    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let length = file.metadata().map_err(|error| error.to_string())?.len();
    if length > 65_536 {
        return Err("inert fixture index exceeds its finite metadata ceiling".into());
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length as usize + 1)
        .map_err(|error| error.to_string())?;
    file.take(length + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() != length as usize {
        return Err("inert fixture index changed while reading".into());
    }
    canonical::parse_json(&bytes, 65_536).map_err(InspectionError::from_error)
}

/// Authenticates the actual MAC-loaded originals before a target is assembled.
pub(super) fn load_profile(branch: &str) -> Result<Rc<ConditionalProfile>, InspectionError> {
    let variable = |name| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .ok_or_else(|| format!("required installed fixture binding {name} absent"))
    };
    let archive_path = variable("CRUCIBLE_ORIGINAL_LINEAGE_TAPE_ARCHIVE")?;
    let evidence = variable("CRUCIBLE_ORIGINAL_LINEAGE_TAPE_EVIDENCE")?;
    let package_manifest = variable("CRUCIBLE_REFERENCE_LINEAGE_READER_IMPLEMENTATION_MANIFEST")?;
    let fixture =
        canonical::content_ref(include_bytes!("installed-fixture.json"), "application/json")
            .map_err(|error| error.to_string())?;
    let package = InstalledReaderPackage::load(&package_manifest, &fixture)
        .map_err(|error| error.to_string())?;
    let archive = TranscriptArchive::open(
        &archive_path,
        TranscriptLimits {
            maximum_records: U64::new(128),
            maximum_record_bytes: U64::new(1024 * 1024),
            maximum_total_bytes: U64::new(256 * 1024 * 1024),
        },
    )
    .map_err(|error| error.to_string())?;
    let index = read_small_json(&evidence.join("original-tape-index.json"))?;
    let references: Vec<ContentRef> = serde_json::from_value(index["original_tapes"].clone())
        .map_err(|error| error.to_string())?;
    if references.len() != 3 {
        return Err("source signed roster differs".into());
    }
    let retirement = read_small_json(&evidence.join("original-retirement.json"))?;
    if retirement["all_original_capsules_reclaimed"] != true
        || retirement["all_original_journals_persisted"] != true
        || retirement["original_world_reserved"] != 0
        || retirement["slot_retention_failed"] != false
    {
        return Err("native source owning retirement witness is incomplete".into());
    }

    // The signer owns authentication. Portable index bodies select references
    // only; the archive verifies their original MAC before decoding the tape.
    let mut originals = BTreeMap::new();
    for reference in references {
        let source = archive
            .load(&reference)
            .map_err(|error| error.to_string())?;
        if originals
            .insert(source.transcript().origin.route.node.clone(), source)
            .is_some()
        {
            return Err("source original actor repeated".into());
        }
    }
    let history = Rc::new(conditional_source::inspect(&package, &originals)?);
    let mut profiles = Vec::new();
    let mut owners = Vec::new();
    let qualification = history
        .bindings
        .values()
        .next()
        .and_then(|binding| binding.compatibility.qualification_refs.first())
        .ok_or("source candidate qualification role absent")?
        .clone();
    let qualification_body = history
        .objects
        .get(&qualification)
        .ok_or("source original qualification bytes absent")?
        .clone();
    for (node, binding) in &history.bindings {
        if binding.compatibility.qualification_refs.as_slice()
            != std::slice::from_ref(&qualification)
        {
            return Err("source fixed candidate qualification roster differs".into());
        }
        let profile = package
            .profile(
                node.clone(),
                binding.compatibility.execution_owner.id.clone(),
                U64::new(1000),
                U64::new(1_000_000_000),
                node.as_str() == "source",
            )
            .map_err(|error| error.to_string())?;
        let (_, owner) = profile
            .bind_qualified(
                binding.authority.clone(),
                &binding.compatibility.qualification_refs,
            )
            .map_err(|error| error.to_string())?;
        owners.push(owner);
        profiles.push(profile);
    }
    let original = graph::Definition::build(&profiles, qualification_body, BTreeMap::new());
    let host = crucible_node_provider::conformance::measure_executable(std::path::Path::new(
        "/proc/self/exe",
    ))
    .map_err(|error| error.to_string())?;
    let mut profile = ConditionalProfile::build(
        history,
        &original.world,
        &original.descriptors,
        &owners,
        host,
        branch,
        None,
    )?;
    super::conditional_historical_rows::install(&mut profile, &profiles, &package)?;
    super::conditional_graph_rows::install(&mut profile, &profiles, &original)?;
    super::conditional_admission_rows::install(&mut profile, &profiles, &package, &original.world)?;
    Ok(Rc::new(profile))
}

/// Exercises the declared original six-window prefix and holds q2 before Poll.
#[test]
#[ignore = "requires authentic private signed native tapes and installed package"]
fn signed_original_prefix_publishes_six_windows_and_holds_three_original_permissions()
-> Result<(), InspectionError> {
    let mut world = prepare_original_prefix("original-prefix-target")?;
    world.export_prefix()
}

/// Captures the actual pending cut and resumes both complete namespace-gone twins.
#[test]
#[ignore = "requires authentic signed original tapes and the installed capture policy"]
fn signed_original_conditional_capture_pins_complete_pending_cut() -> Result<(), InspectionError> {
    let mut world = prepare_original_prefix("original-capture-target")?;
    world.export_prefix()?;
    world.capture_and_pin()?;
    world.export_pinned_bodies()?;
    world.remove_capture_namespace()?;
    world.retire_captured_models()?;
    world.restore_complete_twins()
}

fn prepare_original_prefix(
    branch: &str,
) -> Result<super::conditional_world::ConditionalWorld, InspectionError> {
    use super::conditional_world::ConditionalWorld;
    use crucible_node_contract::Event;

    let profile = load_profile(branch)?;
    let mut world = ConditionalWorld::prepare(Rc::clone(&profile))?;
    world.activate()?;

    for quantum in 0..2 {
        let order = if quantum == 0 {
            ["source", "link", "disk"]
        } else {
            ["disk", "link", "source"]
        };
        for name in order {
            let node = Id::new(name).map_err(InspectionError::from_error)?;
            let token = world.begin(&node, quantum)?;
            let publication = world.complete(&token)?;
            let operation =
                Id::new(format!("run/{node}/{quantum}")).map_err(InspectionError::from_error)?;
            let original = profile
                .history
                .publications
                .iter()
                .find(|claim| {
                    claim.origin.operation_id == operation
                        && claim.origin.execution_owner_id
                            == profile.history.bindings[&node]
                                .compatibility
                                .execution_owner
                                .id
                })
                .ok_or("exact original native publication claim absent")?;
            let body = profile
                .history
                .objects
                .get(&original.published)
                .ok_or("exact original native Event body absent")?;
            let event: Event = serde_json::from_value(
                canonical::parse_json(body, 65_536).map_err(InspectionError::from_error)?,
            )
            .map_err(InspectionError::from_error)?;
            let payload = profile
                .history
                .objects
                .get(&event.payload)
                .ok_or("exact original native payload body absent")?;
            if publication.publication_id != event.id
                || publication.endpoint != event.source
                || publication.native_sequence != event.source_sequence
                || publication.publication != event.publication_position
                || publication.payload != event.payload
                || publication.payload_bytes != *payload
                || !publication.causal_parents.is_empty()
                || !event.causal_parent_ids.is_empty()
            {
                return Err(
                    "conditional output differs from original native FIFO/Event/body".into(),
                );
            }
        }
    }

    // Accepted q2 permissions remain runtime-owned and unpolled. No future
    // terminal result is copied into the current consumed evidence prefix.
    for name in ["disk", "link", "source"] {
        let node = Id::new(name).map_err(InspectionError::from_error)?;
        let _original = world.begin(&node, 2)?;
    }
    Ok(world)
}
