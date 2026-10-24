//! Exercises actual structural code verification with no peer or native currentness.
//!
//! The existing scene measures this test ELF only as controlled fixture content.
//! These controls do not qualify that ELF as a native packet implementation, issue
//! an archive ticket or create a successful restored world.

// crucible-lint: allow panic-shortcut -- Controlled structural fixture setup and assertions are the test oracle.
#![allow(clippy::unwrap_used)]

use super::super::super::PacketCompleteArchiveCodeFactory;
use super::*;
use crucible_engine::node_admission::{
    AdmissionLimits, AdmissionRequest, admit_complete_archive_code_graph, admit_conformance_graph,
};
use crucible_node_format::{NodeBinding, NodeDescriptor, OwnerBinding};

struct Rows {
    descriptors: Vec<NodeDescriptor>,
    bindings: Vec<NodeBinding>,
    owners: Vec<OwnerBinding>,
}

impl Rows {
    fn new(scene: &Scene) -> Self {
        let selections = scene
            .roster
            .sources
            .iter()
            .map(|source| source.installation());
        let mut rows = Self {
            descriptors: Vec::new(),
            bindings: Vec::new(),
            owners: Vec::new(),
        };
        for selected in selections {
            rows.descriptors.push(selected.descriptor.clone());
            rows.bindings.push(selected.binding.clone());
            rows.owners.push(selected.owner.clone());
        }
        let host = scene.world.host_source.selection();
        rows.descriptors.push(host.descriptor.clone());
        rows.bindings.push(host.binding.clone());
        rows.owners.push(host.owner.clone());
        rows
    }

    fn request<'a>(&'a self, scene: &'a Scene) -> AdmissionRequest<'a> {
        AdmissionRequest {
            world: &scene.world.world,
            descriptors: &self.descriptors,
            bindings: &self.bindings,
            owners: &self.owners,
            requirements: &scene.world.requirements,
        }
    }
}

fn limits(scene: &Scene) -> AdmissionLimits {
    // Bounds follow the actual measured fixture body rather than pretending the
    // test ELF fits a four-MiB content window. This is a parser test bound only.
    let file = usize::try_from(scene.measurements.peer.content.length.get()).unwrap();
    let maximum = file.checked_add(8 * 1024 * 1024).unwrap();
    AdmissionLimits {
        maximum_content_bytes: maximum,
        maximum_total_content_bytes: maximum.checked_mul(4).unwrap(),
        ..AdmissionLimits::default()
    }
}

// This is only fixture-content closure. Known measured file pins are classified
// without reading them; actual byte/currentness/admission checks still run below.
fn fixture_content_closure_missing(
    scene: &Scene,
    rows: &Rows,
) -> Result<std::collections::BTreeSet<ContentRef>, String> {
    let mut pending = Vec::new();
    let core = serde_json::to_value((
        &scene.world.world,
        &scene.world.requirements,
        &rows.descriptors,
        &rows.bindings,
        &rows.owners,
    ))
    .map_err(|error| error.to_string())?;
    collect_fixture_content_refs(&core, &mut pending)?;
    let measured: std::collections::BTreeSet<ContentRef> =
        std::iter::once(scene.measurements.peer.content.clone())
            .chain(std::iter::once(scene.measurements.host.clone()))
            .chain(
                scene
                    .measurements
                    .sources
                    .iter()
                    .map(|source| source.content.clone()),
            )
            .collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut missing = std::collections::BTreeSet::new();
    while let Some(reference) = pending.pop() {
        if !seen.insert(reference.clone()) {
            continue;
        }
        if let Some(bytes) = scene.world.content.get(&reference) {
            reference.verify(bytes).map_err(|error| error.to_string())?;
            if reference.media_type == "application/json" {
                let body =
                    canonical::parse_json(bytes, bytes.len()).map_err(|error| error.to_string())?;
                collect_fixture_content_refs(&body, &mut pending)?;
            }
        } else if !measured.contains(&reference) {
            missing.insert(reference);
        }
    }
    Ok(missing)
}

fn collect_fixture_content_refs(
    value: &serde_json::Value,
    references: &mut Vec<ContentRef>,
) -> Result<(), String> {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_fixture_content_refs(value, references)?;
            }
        }
        serde_json::Value::Object(fields)
            if fields.contains_key("hash")
                && fields.contains_key("length")
                && fields.contains_key("media_type") =>
        {
            let reference: ContentRef =
                serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
            crucible_node_format::Validate::validate(&reference)
                .map_err(|error| error.to_string())?;
            references.push(reference);
        }
        serde_json::Value::Object(fields) => {
            for value in fields.values() {
                collect_fixture_content_refs(value, references)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[test]
fn archive_fixture_content_closure_detects_missing_and_mismatched_schema_bytes() {
    let mut scene = Scene::new();
    let rows = Rows::new(&scene);
    let continuation =
        crucible_engine::node_contract::host_scheduling_complete_continuation_schema().unwrap();
    assert!(
        fixture_content_closure_missing(&scene, &rows)
            .unwrap()
            .is_empty()
    );

    let bytes = scene
        .world
        .content
        .remove(&continuation.definition)
        .unwrap();
    assert_eq!(
        fixture_content_closure_missing(&scene, &rows).unwrap(),
        std::collections::BTreeSet::from([continuation.definition.clone()])
    );

    let mut changed = bytes.clone();
    changed.push(b' ');
    scene
        .world
        .content
        .insert(continuation.definition.clone(), changed);
    assert!(fixture_content_closure_missing(&scene, &rows).is_err());

    scene.world.content.insert(continuation.definition, bytes);
    assert!(
        fixture_content_closure_missing(&scene, &rows)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn collecting_policy_requires_actual_host_and_every_native_acceptance() {
    let scene = Scene::new();
    let rows = Rows::new(&scene);
    let nodes: Vec<_> = rows
        .descriptors
        .iter()
        .map(|node| node.id.clone())
        .collect();
    let actual_host = &scene.world.host_source.selection().descriptor.id;
    let accepted = &scene.world.requirements.accepted_nondeterministic_nodes;
    let policy = super::super::super::records::exact_collecting_nondeterminism_roster;

    // These call the same pure policy branch that records::validate applies
    // before CurrentFiles installation. Scene setup creates controlled files;
    // no graph owner, file measurement callback or native permission is installed.
    assert!(policy(&nodes, accepted));
    let without_host: Vec<_> = accepted
        .iter()
        .filter(|node| *node != actual_host)
        .cloned()
        .collect();
    assert_eq!(without_host.len(), 3);
    assert!(!policy(&nodes, &without_host));
    for native in &without_host {
        let omitted: Vec<_> = accepted
            .iter()
            .filter(|node| *node != native)
            .cloned()
            .collect();
        assert!(!policy(&nodes, &omitted));
    }

    let mut unknown_host = without_host;
    unknown_host.push(id("zz-undeclared-host"));
    unknown_host.sort();
    assert!(!policy(&nodes, &unknown_host));
    let mut extra = accepted.clone();
    extra.push(id("zz-undeclared-extra"));
    extra.sort();
    assert!(!policy(&nodes, &extra));
    let mut duplicate = accepted.clone();
    duplicate[3] = duplicate[2].clone();
    duplicate.sort();
    assert!(!policy(&nodes, &duplicate));
    let mut reversed = accepted.clone();
    reversed.reverse();
    assert!(!policy(&nodes, &reversed));
}

#[test]
fn archive_code_graph_uses_real_structural_validation_without_native_child() {
    let scene = Scene::new();
    let rows = Rows::new(&scene);
    let missing = fixture_content_closure_missing(&scene, &rows).unwrap();
    assert!(
        missing.is_empty(),
        "archive fixture missing immutable bodies: {missing:#?}"
    );
    let (_owner, authority) = collection_authority(&scene);
    let plan = Rc::new(authority.collection_plan().unwrap());
    let factory = PacketCompleteArchiveCodeFactory::install(
        Rc::clone(&authority),
        Rc::clone(&plan),
        crucible_engine::node_state::NativeArchiveLimits::default(),
    )
    .unwrap();
    assert!(scene.roster.current_native().is_err());
    assert!(authority.original_capture_factory().is_err());

    let graph = factory
        .admit_original_code_graph(rows.request(&scene), limits(&scene))
        .unwrap();

    graph
        .plan()
        .authenticate_authority(authority.as_ref())
        .unwrap();
    // The factory registers exactly the same actual graph allocation retained
    // by the later prebirth capsule. A second portable-equivalent result cannot
    // replace its once-associated owner.
    assert!(
        factory
            .admit_original_code_graph(rows.request(&scene), limits(&scene))
            .is_err()
    );
    assert!(
        factory
            .retained_requested_storage_data(512 * 1024 * 1024)
            .unwrap()
            > 0
    );
    assert!(
        scene.roster.sources[0]
            .original_complete_retained_storage_data(512 * 1024 * 1024)
            .is_err()
    );
    assert!(scene.roster.current_native().is_err());
    assert!(authority.original_capture_factory().is_err());
    assert!(admit_conformance_graph(rows.request(&scene), &plan, limits(&scene)).is_err());
}

#[test]
fn archive_code_graph_rejects_equal_data_from_another_actual_authority() {
    let scene = Scene::new();
    let (_first_owner, first) = collection_authority(&scene);
    let (_second_owner, second) = collection_authority(&scene);
    let first_plan = first.collection_plan().unwrap();
    let second_plan = Rc::new(second.collection_plan().unwrap());
    let factory = PacketCompleteArchiveCodeFactory::install(
        second,
        second_plan,
        crucible_engine::node_state::NativeArchiveLimits::default(),
    )
    .unwrap();
    let rows = Rows::new(&scene);

    assert!(
        admit_complete_archive_code_graph(
            rows.request(&scene),
            &first_plan,
            factory.as_ref(),
            limits(&scene),
        )
        .is_err()
    );
    assert!(scene.roster.current_native().is_err());
}

#[test]
fn archive_code_graph_preserves_missing_owner_and_finite_bound_refusals() {
    let scene = Scene::new();
    let (_owner, authority) = collection_authority(&scene);
    let plan = Rc::new(authority.collection_plan().unwrap());
    let factory = PacketCompleteArchiveCodeFactory::install(
        authority,
        plan,
        crucible_engine::node_state::NativeArchiveLimits::default(),
    )
    .unwrap();
    let mut rows = Rows::new(&scene);
    rows.owners.pop();
    assert!(
        factory
            .admit_original_code_graph(rows.request(&scene), limits(&scene))
            .is_err()
    );
    let rows = Rows::new(&scene);
    let narrow = AdmissionLimits {
        maximum_nodes: 3,
        ..limits(&scene)
    };
    assert!(
        factory
            .admit_original_code_graph(rows.request(&scene), narrow)
            .is_err()
    );
    assert!(scene.roster.current_native().is_err());
}
