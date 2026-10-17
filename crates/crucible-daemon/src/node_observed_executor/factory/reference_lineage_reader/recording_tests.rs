//! Records one original installed nine-window cohort before native retirement.
//!
//! Signed tape bodies retain actual source interactions and lineage callbacks.
//! They provide no class, physical capture, conditional replay or CutoffFold grant.

use super::*;
use crucible::node_adapters::transcript::{
    AuthenticatedTranscript, CapturedTranscript, RecordingHandle, RecordingNode, TranscriptAction,
    TranscriptArchive, TranscriptLimits,
};
use crucible::node_scheduling::InputPayload;
use std::os::unix::fs::PermissionsExt;

use crate::node_observed_executor::factory::transcript::{
    ORIGINAL_CONTEXT_FRAGMENT_MEDIA_TYPE, fragment_fixture_context, reconstruct_fixture_context,
};

const MAXIMUM_CONTEXT_OBJECTS: usize = 4094;
const MAXIMUM_CONTEXT_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn declared_scope() -> serde_json::Value {
    serde_json::json!({
        "schema": "crucible.reference.reader-live-tape2.candidate.v1",
        "boundary_envelope_schema_version": 2,
        "inner_control_encoding": "unchanged canonical JSON and original byte/array limits",
        "maximum_records_per_peer": 128,
        "maximum_record_bytes": 1048576,
        "maximum_total_bytes_per_peer": 268435456,
        "maximum_context_objects_before_binding": MAXIMUM_CONTEXT_OBJECTS,
        "maximum_context_raw_bytes": MAXIMUM_CONTEXT_BYTES,
        "workload": "same declared nine native windows and original resource budgets",
        "seal_order": "complete original ACKs, raw journal retention, one-shot finish, immutable bodies, private archive persist/reopen, original native retirement",
        "class_accepted": false,
        "conditional_replay_qualified": false,
        "physical_capture_qualified": false
    })
}

fn limits() -> TranscriptLimits {
    TranscriptLimits {
        maximum_records: U64::new(128),
        maximum_record_bytes: U64::new(1024 * 1024),
        maximum_total_bytes: U64::new(256 * 1024 * 1024),
    }
}

/// Keeps capture handles, immutable exports and failed owning nodes with World.
pub(super) struct RecordingCustody {
    archive: TranscriptArchive,
    private_archive: PathBuf,
    handles: Vec<RecordingHandle>,
    captures: Vec<Option<CapturedTranscript>>,
    failed_nodes: Vec<Box<dyn SimulationNode>>,
    bodies: Vec<InputPayload>,
    seals: Vec<AuthenticatedTranscript>,
    export_attempted: bool,
    exports_persisted: bool,
}

impl RecordingCustody {
    pub(super) fn reserve() -> Self {
        // The signer store must be private from its first directory creation.
        let directory = tempfile::Builder::new()
            .prefix("reader-private-tapes-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")
            .unwrap();
        let private_archive = directory.keep();
        let archive = TranscriptArchive::open(&private_archive, limits()).unwrap();
        Self {
            archive,
            private_archive,
            handles: Vec::with_capacity(3),
            captures: (0..3).map(|_| None).collect(),
            failed_nodes: Vec::with_capacity(3),
            bodies: Vec::with_capacity(3),
            seals: Vec::with_capacity(3),
            export_attempted: false,
            exports_persisted: false,
        }
    }

    pub(super) fn wrap(
        &mut self,
        graph: &AdmittedGraph,
        activation: &ActivationRecord,
        node: Box<dyn SimulationNode>,
        context: Vec<InputPayload>,
    ) -> Box<dyn SimulationNode> {
        let attempt = id("reader-live-recording-original");
        match RecordingNode::new_original_lineage(
            graph,
            node,
            attempt,
            activation,
            context,
            limits(),
        ) {
            Ok((node, handle)) => {
                self.handles.push(handle);
                Box::new(node)
            }
            Err(failure) => {
                let (error, original) = failure.into_parts();
                self.failed_nodes.push(original);
                panic!("original recording preparation refused: {error}");
            }
        }
    }

    pub(super) fn transfer_failed_nodes(&mut self) {
        self.failed_nodes.clear();
    }

    fn seal(&mut self, root: &std::path::Path) {
        assert!(!self.export_attempted);
        assert_eq!(self.handles.len(), 3);
        // This attempt is irreversible even if finish, encoding or storage fails.
        // Later teardown records the partial population without collecting again.
        self.export_attempted = true;
        for (index, handle) in self.handles.iter().enumerate() {
            // The preallocated owning slot receives the opaque finished capture
            // before assertions, raw copies or any archive operation can unwind.
            self.captures[index] = Some(handle.finish().unwrap());
            let capture = self.captures[index].as_ref().unwrap();
            assert_eq!(
                capture.transcript().origin.attempt,
                id("reader-live-recording-original")
            );
            let body = InputPayload {
                reference: capture.reference().clone(),
                bytes: capture.bytes().to_vec(),
            };
            self.bodies.push(body);
            let body = &self.bodies[index];
            std::fs::write(
                root.join(format!("original-tape-peer-{index}.json")),
                &body.bytes,
            )
            .unwrap();
            let capture = self.captures[index].take().unwrap();
            let seal = self.archive.persist(capture).unwrap();
            assert_eq!(seal.reference(), &body.reference);
            assert_eq!(seal.bytes(), body.bytes);
            self.seals.push(seal);
        }
        // Independently reopen the signer while the authentic native World lives.
        // Loading checks the stored MAC before decoding the original body.
        let reopened = TranscriptArchive::open(&self.private_archive, limits()).unwrap();
        for (body, seal) in self.bodies.iter().zip(&self.seals) {
            let loaded = reopened.load(&body.reference).unwrap();
            assert_eq!(loaded.bytes(), seal.bytes());
            assert_eq!(loaded.transcript(), seal.transcript());
        }
        verify_tapes(&self.seals);
        self.exports_persisted = true;
        assert!(self.persist_disposition(root));
    }

    pub(super) fn persist_disposition(&self, root: &std::path::Path) -> bool {
        let result = (|| -> Result<(), ProviderError> {
            for (index, body) in self.bodies.iter().enumerate() {
                body.reference.verify(&body.bytes)?;
                std::fs::write(
                    root.join(format!("original-tape-peer-{index}.json")),
                    &body.bytes,
                )?;
            }
            let document = serde_json::json!({
                "schema": "crucible.reference.reader-live-tape2.retained.v1",
                "export_attempted": self.export_attempted,
                "all_three_exports_persisted_and_reopened": self.exports_persisted,
                "original_tapes": self.bodies.iter().map(|body| &body.reference).collect::<Vec<_>>(),
                "class_accepted": false,
                "conditional_replay_qualified": false,
                "physical_capture_qualified": false
            });
            let bytes = canonical::canonical_json(&document)?;
            std::fs::write(root.join("original-tape-index.json"), bytes)?;
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("original tape retention unavailable: {error}");
            return false;
        }
        true
    }
}

pub(super) fn original_context(
    package: &InstalledReaderPackage,
    definition: &graph::Definition,
    activation: &ActivationRecord,
    installations: &[Installed],
    observations: &[Rc<RefCell<Option<ObservationHandle>>>],
) -> Vec<InputPayload> {
    let mut objects = definition.content.clone();
    let mut retain = |reference: ContentRef, bytes: Vec<u8>| {
        reference.verify(&bytes).unwrap();
        if let Some(original) = objects.insert(reference, bytes.clone()) {
            assert_eq!(original, bytes);
        }
    };
    retain(package.identity().clone(), package.document().to_vec());
    for value in [
        serde_json::to_value(&definition.world).unwrap(),
        serde_json::to_value(SavedRuntimeActivation::from(activation)).unwrap(),
    ] {
        let bytes = canonical::canonical_json(&value).unwrap();
        retain(
            canonical::content_ref(&bytes, "application/json").unwrap(),
            bytes,
        );
    }
    for (reference, bytes) in package.definition().objects() {
        retain(reference.clone(), bytes.clone());
    }
    for installed in installations {
        for object in &installed.bootstrap.installed_content {
            retain(object.reference.clone(), object.bytes.as_slice().to_vec());
        }
        let owner =
            canonical::canonical_json(&serde_json::to_value(&installed.owner).unwrap()).unwrap();
        retain(
            canonical::content_ref(&owner, "application/json").unwrap(),
            owner,
        );
    }
    for observation in observations {
        let slot = observation.try_borrow().unwrap();
        let handle = slot.as_ref().unwrap();
        let original = handle
            .snapshot(
                &handle.request_keys().unwrap(),
                &handle.content_references().unwrap(),
                observation_limits(),
            )
            .unwrap();
        let bytes = canonical::canonical_json(&serde_json::to_value(original).unwrap()).unwrap();
        retain(
            canonical::content_ref(&bytes, "application/json").unwrap(),
            bytes,
        );
    }
    let mut total = 0usize;
    let mut context = BTreeMap::new();
    for (reference, bytes) in objects {
        total = total.checked_add(bytes.len()).unwrap();
        assert!(total <= MAXIMUM_CONTEXT_BYTES);
        let original = InputPayload { reference, bytes };
        let fragments = fragment_fixture_context(original.clone()).unwrap();
        if let Some(manifest) = fragments
            .iter()
            .find(|body| body.reference.media_type == ORIGINAL_CONTEXT_FRAGMENT_MEDIA_TYPE)
        {
            let restored =
                reconstruct_fixture_context(manifest, &fragments, MAXIMUM_CONTEXT_BYTES).unwrap();
            assert_eq!(restored, original);
        }
        for body in fragments {
            if let Some(previous) = context.insert(body.reference.clone(), body.bytes.clone()) {
                assert_eq!(previous, body.bytes);
            }
            assert!(context.len() <= MAXIMUM_CONTEXT_OBJECTS);
        }
    }
    context
        .into_iter()
        .map(|(reference, bytes)| InputPayload { reference, bytes })
        .collect()
}

fn verify_tapes(seals: &[AuthenticatedTranscript]) {
    let mut publications = 0usize;
    let mut inputs = 0usize;
    for seal in seals {
        let tape = seal.transcript();
        for action in [
            TranscriptAction::StageInput,
            TranscriptAction::Begin,
            TranscriptAction::Complete,
            TranscriptAction::CloseWindow,
            TranscriptAction::Acknowledge,
        ] {
            assert_eq!(
                tape.records
                    .iter()
                    .filter(|record| record.request.action == action)
                    .count(),
                3
            );
        }
        for record in &tape.records {
            for body in &record.evidence {
                if body.reference.media_type
                    != "application/vnd.crucible.transcript-original-lineage+json;version=2"
                {
                    continue;
                }
                body.reference.verify(&body.bytes).unwrap();
                let metadata = canonical::parse_json(&body.bytes, 1024 * 1024).unwrap();
                assert_eq!(metadata["schema_version"], 2);
                assert_eq!(
                    metadata["source_capture"],
                    serde_json::to_value(&tape.origin.activation).unwrap()
                );
                match metadata["lineage"]["kind"].as_str() {
                    Some("publication") => publications += 1,
                    Some("input") => inputs += 1,
                    other => panic!("unknown actual Tape2 metadata kind: {other:?}"),
                }
            }
        }
    }
    assert_eq!(publications, 9);
    assert_eq!(inputs, 4);
}

#[test]
#[ignore = "requires the exact source-built reader package for one original live recording cohort"]
fn actual_installed_reader_records_original_nine_window_lineage_before_retirement() {
    let manifest = PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_LINEAGE_READER_IMPLEMENTATION_MANIFEST")
            .expect("reader implementation must be bound"),
    );
    let original =
        canonical::content_ref(include_bytes!("installed-fixture.json"), "application/json")
            .unwrap();
    let package = InstalledReaderPackage::load(&manifest, &original).unwrap();
    let mut world = World::prepare_selected(package, true);
    let mut windows = Vec::with_capacity(9);
    for index in 0..3 {
        let order = if index == 0 {
            ["source", "link", "disk"]
        } else {
            ["disk", "link", "source"]
        };
        for node in order {
            let original = quantum(&mut world, &id(node), index);
            let bytes = canonical::canonical_json(&original).unwrap();
            let root = world.directory.as_ref().unwrap().path();
            std::fs::write(
                root.join(format!("original-window-{}.json", windows.len())),
                bytes,
            )
            .unwrap();
            windows.push(original);
        }
    }
    let witnesses = world
        .policies
        .iter()
        .map(|policy| policy.witnesses().unwrap())
        .collect::<Vec<_>>();
    verify_original_three_peer_chain(&windows, &witnesses);
    let original = serde_json::json!({
        "schema":"crucible.reference.reader-three-peer.original.v1",
        "class_accepted":false,
        "windows":windows,
        "source_witnesses":witnesses,
        "live_recording":declared_scope()
    });
    let bytes = canonical::canonical_json(&original).unwrap();
    let root = world.directory.as_ref().unwrap().path().to_path_buf();
    std::fs::write(root.join("original-windows.json"), bytes).unwrap();
    assert!(world.persist_observations(&root, "-before-tape-seal"));
    world.recording.as_mut().unwrap().seal(&root);
    eprintln!("original live Tape2 evidence retained: {}", root.display());
}
