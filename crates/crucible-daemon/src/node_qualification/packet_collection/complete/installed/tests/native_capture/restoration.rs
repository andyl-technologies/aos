//! Compares two independently ticketed Worlds after original resource removal.
//!
//! Each fresh target has its own code authority, capsule, native processes,
//! live incarnations, activation and cleanup supervisor. They share only the
//! actual signed source archive and retained immutable implementation artifacts.

use super::*;
use crate::node_qualification::packet_collection::complete::tests::native_roundtrip::target_declaration_for;
use crate::node_qualification::packet_collection::{
    PacketWorldHostSupervisor,
    complete::{
        InstalledCompleteRestoration, PacketCompleteFreshRestorationInputs,
        PacketCompleteNativeLaunchInputs, PacketCompleteRestorationPrebirth,
        PreparedCompleteRestoration,
    },
};
use crucible::node_adapters::cnp::{CnpSemanticRegistry, CnpSemanticSource};
use crucible::node_contract::{
    ActivationRecord, HostSchedulingContinuationLimits, SavedRuntimeActivation,
};
use crucible::node_scheduling::{NativeSchedulingObservation, ValidatedSchedulingObservation};
use crucible::node_state::{NativeArchiveLimits, NativeArchiveRecord};
use std::os::unix::net::UnixStream;

struct FreshWorld {
    directory: tempfile::TempDir,
    prepared: Option<PreparedCompleteRestoration>,
    prebirth: Option<Rc<RefCell<PacketCompleteRestorationPrebirth>>>,
    target: Option<InstalledCompleteRestoration>,
    incoming: Option<PacketCompleteFreshRestorationInputs>,
    lifecycle_entered: bool,
    activation: Option<ActivationRecord>,
    prepare_ids: Option<[Id; 3]>,
    commit_ids: Option<[Id; 3]>,
    blobs: Arc<DirectoryBlobBackend>,
    refs: Arc<DirectoryRefBackend>,
    publisher: Option<StoredWorldActivationPublisher>,
    observation: Option<ValidatedSchedulingObservation>,
}

impl FreshWorld {
    fn new(label: &str) -> Self {
        let directory = private_directory();
        let blobs = Arc::new(DirectoryBlobBackend::new(
            format!("installed-packet-restoration-{label}"),
            directory.path().join("blobs"),
        ));
        let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
        let publisher = StoredWorldActivationPublisher::new(
            blobs.clone(),
            refs.clone(),
            RefName::new(format!(
                "node-world-activations/installed-packet-target-{label}"
            ))
            .unwrap(),
        )
        .unwrap();

        Self {
            directory,
            prepared: None,
            prebirth: None,
            target: None,
            incoming: None,
            lifecycle_entered: false,
            activation: None,
            prepare_ids: Some(std::array::from_fn(|member| {
                id(&format!("{label}-prepare-{member}"))
            })),
            commit_ids: Some(std::array::from_fn(|member| {
                id(&format!("{label}-commit-{member}"))
            })),
            blobs,
            refs,
            publisher: Some(publisher),
            observation: None,
        }
    }

    fn restore_and_observe(
        &mut self,
        original: &serde_json::Value,
        loaded: NativeArchiveRecord,
        limits: NativeArchiveLimits,
        label: &str,
    ) {
        let cut = loaded.manifest().cut;
        let declaration = target_declaration_for(original, label);
        let pin = pinned(self.directory.path(), &declaration);
        let selected = super::super::super::manifest::load(&pin).unwrap();
        let target_directory = self.directory.path().join("target");

        PreparedCompleteRestoration::prepare_into(
            pin,
            target_directory.clone(),
            limits,
            &mut self.prepared,
        )
        .unwrap();
        self.prepared
            .as_mut()
            .unwrap()
            .prepare_original_prebirth_into(
                loaded,
                HostSchedulingContinuationLimits {
                    maximum_record_bytes: limits.state.maximum_record_bytes,
                    lineage: OriginalInputLineageLimits::default(),
                },
                &mut self.prebirth,
            )
            .unwrap();
        PreparedCompleteRestoration::install_into(
            &mut self.prepared,
            Rc::clone(self.prebirth.as_ref().unwrap()),
            &mut self.target,
        )
        .unwrap();

        let installed = self.target.as_ref().unwrap();
        let sources = &installed.authority().roster().sources;
        assert!(sources.iter().all(|source| {
            source
                .is_original_restored_suffix_declaration_data()
                .unwrap()
        }));
        let mut registry = CnpSemanticRegistry::new(installed.authority().clone(), 3).unwrap();
        let mut roles = std::array::from_fn(|_| None);
        for (slot, source) in roles.iter_mut().zip(sources) {
            *slot = Some(
                registry
                    .install_complete_packet_for_conformance(
                        Rc::clone(source),
                        installed.authority().clone(),
                        installed.plan(),
                    )
                    .unwrap(),
            );
        }

        let saved: SavedRuntimeActivation = serde_json::from_value(
            selected
                .coordinator
                .template
                .get("activation")
                .unwrap()
                .clone(),
        )
        .unwrap();
        self.activation = Some(ActivationRecord {
            generation: saved.generation,
            activation_id: saved.activation_id,
            world_binding_hash: saved.world_binding_hash,
            owners: saved.owners,
            boundary: cut,
        });
        let activation = self.activation.as_ref().unwrap();
        let launches = std::array::from_fn(|member| {
            let directory = target_directory.join(format!("peer-{member}"));
            let (reader, writer) = UnixStream::pair().unwrap();
            Some(PacketCompleteNativeLaunchInputs {
                executable_path: selected.measurements[member].peer.path.clone(),
                executable: selected.measurements[member].peer.content.clone(),
                socket: directory.join("control.sock"),
                directory,
                slot: None,
                bootstrap_reader: Some(reader),
                bootstrap_writer: Some(writer),
                write_watchdog: installed.write_watchdog(),
            })
        });
        self.incoming = Some(PacketCompleteFreshRestorationInputs {
            supervisor: PacketWorldHostSupervisor::new_complete_original()
                .unwrap()
                .into(),
            activation: activation.clone(),
            runtime_limits: *installed.runtime_limits(),
            launches,
            registry: Some(registry),
            roles,
            query_ids: std::array::from_fn(|member| Some(id(&format!("{label}-query-{member}")))),
            admit_ids: Some(std::array::from_fn(|member| {
                id(&format!("{label}-admit-{member}"))
            })),
        });

        self.lifecycle_entered = true;
        PacketCompleteReportStartupHolder::start_original_fresh_restoration_into(
            installed.holder(),
            &mut self.incoming,
        )
        .unwrap();
        assert!(self.incoming.is_none());
        PacketCompleteReportStartupHolder::prepare_original_fresh_runtime(installed.holder())
            .unwrap();

        let observed_node = sources[0].installation().descriptor.id.clone();
        self.observation = Some(
            installed
                .restore_and_observe(
                    activation,
                    &mut self.prepare_ids,
                    &mut self.commit_ids,
                    &mut self.publisher,
                    Arc::clone(&self.blobs),
                    Arc::clone(&self.refs),
                    &observed_node,
                )
                .unwrap(),
        );
        let observation = self.observation.as_ref().unwrap();
        assert_eq!(observation.native().node, observed_node);
        assert_eq!(observation.reached(), cut);
        let owner = &sources[0].installation().owner.owner.id;
        let expected = activation
            .owners
            .iter()
            .find(|candidate| &candidate.owner == owner)
            .unwrap();
        assert_eq!(
            observation.native().owners.as_slice(),
            std::slice::from_ref(expected)
        );
        assert!(self.prepare_ids.is_none());
        assert!(self.commit_ids.is_none());
    }

    fn retire_and_reclaim(&mut self) {
        let Some(installed) = &self.target else {
            return;
        };
        PacketCompleteReportStartupHolder::retire_original_fresh_restoration(installed.holder())
            .unwrap();
        if !self.lifecycle_entered || self.incoming.is_some() {
            return;
        }

        let deadline = ProcessDeadline::after(Duration::from_secs(30)).unwrap();
        loop {
            match PacketCompleteReportStartupHolder::drive_original_fresh_reclamation(
                installed.holder(),
                1,
            )
            .unwrap()
            {
                Poll::Ready(Ok(observation)) => {
                    assert_eq!(observation.runtime_worlds, 0);
                    break;
                }
                Poll::Ready(Err(_)) => panic!("fresh target cleanup failed"),
                Poll::Pending => {
                    assert!(
                        !deadline.expired(),
                        "fresh target children were not reclaimed"
                    );
                    deadline.pause(Duration::from_millis(1));
                }
            }
        }
    }
}

pub(super) fn restore_two_worlds_and_observe(
    original: &serde_json::Value,
    loaded: [NativeArchiveRecord; 2],
    limits: NativeArchiveLimits,
) {
    assert_eq!(loaded[0].artifact(), loaded[1].artifact());
    assert_eq!(loaded[0].manifest(), loaded[1].manifest());
    let mut worlds = [FreshWorld::new("first"), FreshWorld::new("second")];

    // Both real targets and all partials survive the entire comparison. No
    // live authority, ticket, controller or supervisor is copied between them.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for ((world, archive), label) in worlds.iter_mut().zip(loaded).zip(["first", "second"]) {
            world.restore_and_observe(original, archive, limits, label);
        }

        let [first, second] = &worlds;
        let left = first.target.as_ref().unwrap();
        let right = second.target.as_ref().unwrap();
        assert!(!Rc::ptr_eq(left.holder(), right.holder()));
        assert!(!Rc::ptr_eq(left.authority(), right.authority()));
        assert!(!Rc::ptr_eq(
            first.prebirth.as_ref().unwrap(),
            second.prebirth.as_ref().unwrap()
        ));
        for (left, right) in left
            .authority()
            .roster()
            .sources
            .iter()
            .zip(&right.authority().roster().sources)
        {
            assert!(!Rc::ptr_eq(left, right));
        }
        let left_activation = first.activation.as_ref().unwrap();
        let right_activation = second.activation.as_ref().unwrap();
        assert_ne!(
            left_activation.activation_id,
            right_activation.activation_id
        );
        for owner in &left_activation.owners {
            assert!(
                right_activation
                    .owners
                    .iter()
                    .all(|other| owner.incarnation != other.incarnation)
            );
        }

        assert_same_semantic_state(
            first.observation.as_ref().unwrap().native(),
            second.observation.as_ref().unwrap().native(),
        );
    }));

    // A cleanup error in one World must not prevent attempting cleanup under
    // the other actual supervisor. Keep both owners until every attempt ends.
    let mut cleanup_failure = None;
    for world in &mut worlds {
        let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            world.retire_and_reclaim();
        }));
        if cleanup_failure.is_none() {
            cleanup_failure = cleanup.err();
        }
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    if let Some(panic) = cleanup_failure {
        std::panic::resume_unwind(panic);
    }
}

fn assert_same_semantic_state(
    left: &NativeSchedulingObservation,
    right: &NativeSchedulingObservation,
) {
    assert_eq!(left.node, right.node);
    assert_eq!(left.reached, right.reached);
    assert_eq!(left.closed_prefix, right.closed_prefix);
    assert_eq!(left.publications, right.publications);
    assert_eq!(left.bounds.len(), right.bounds.len());
    for (left, right) in left.bounds.iter().zip(&right.bounds) {
        assert_eq!(left.producer, right.producer);
        assert_eq!(left.bound, right.bound);
    }
    assert_eq!(
        left.input_progress.is_some(),
        right.input_progress.is_some()
    );
    if let (Some(left), Some(right)) = (&left.input_progress, &right.input_progress) {
        assert_eq!(left.batch, right.batch);
        assert_eq!(left.consumed, right.consumed);
    }
    assert_eq!(left.external_inputs.len(), right.external_inputs.len());
    for (left, right) in left.external_inputs.iter().zip(&right.external_inputs) {
        assert_eq!(left.endpoint, right.endpoint);
        assert_eq!(left.closed_before, right.closed_before);
        assert_eq!(left.inputs.len(), right.inputs.len());
        for (left, right) in left.inputs.iter().zip(&right.inputs) {
            assert_eq!(left.event_id, right.event_id);
            assert_eq!(left.native_sequence, right.native_sequence);
            assert_eq!(left.publication, right.publication);
            assert_eq!(left.payload, right.payload);
            assert_eq!(left.payload_bytes, right.payload_bytes);
        }
    }
}
