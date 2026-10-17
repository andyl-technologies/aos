//! Runs the actual initial public Root/Clock candidate beneath finite custody.

// crucible-lint: allow panic-shortcut -- Native witness failures deliberately panic while the real owning supervisors retain their original capsules.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};

use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
};
use crucible_node_contract::Id;

use super::{
    custody::RootCustodyQueue, installed::RootInstalledEngine, publication::RootPublisher,
};
use crate::node_observed_executor::StoredWorldActivationPublisher;

#[test]
#[ignore = "requires the fixed source-installed parent-zero ARM model and real native audit"]
fn actual_root_clock_initial_public_preparation_is_complete_and_reclaimed() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = directory.keep().canonicalize().unwrap();
    let engine = RootInstalledEngine::new(root.clone()).unwrap();
    let _failed_witness = FailedWitnessSupervision(&engine);
    let live = engine.prepare_initial().unwrap();
    let graph = live.graph;
    assert_eq!(live.target.owners.len(), 2);
    assert_eq!(live.profile.scenario.descriptors.len(), 2);
    assert!(live.namespace.starts_with(&root));
    let _enrolled_originals = live.evidence;
    let target = live.target;
    let mut runtime = live
        .realization
        .admit(&graph)
        .unwrap_or_else(|failure| panic!("{}", failure.error));
    runtime.arm_all().unwrap();
    let preparations = runtime.prepared_node_records().unwrap().to_vec();
    assert_eq!(preparations.len(), 2);
    assert!(
        preparations
            .iter()
            .all(|node| node.prepared_owners().is_some())
    );
    let coordinator = runtime
        .initial_coordinator_snapshot(&graph, 16 * 1024 * 1024)
        .unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> =
        Arc::new(DirectoryBlobBackend::new("root-initial", root.join("cas")));
    let refs: Arc<dyn MutableRefBackend> = Arc::new(DirectoryRefBackend::new(root.join("refs")));
    let stored = StoredWorldActivationPublisher::new(
        blobs,
        refs,
        RefName::new("node-world-activations/root-initial").unwrap(),
    )
    .unwrap()
    .with_prepared_coordinator(target.clone(), preparations, coordinator)
    .unwrap();
    let queue = RootCustodyQueue::installed().unwrap();
    let mut publisher = RootPublisher::for_initial(stored, queue.clone());
    let activation = runtime.activate(&mut publisher).unwrap();
    assert_eq!(activation.record(), &target);
    assert_eq!(activation.prepared_owners().unwrap().len(), 2);
    assert!(
        activation
            .prepared_owners()
            .unwrap()
            .iter()
            .any(|owner| owner.owner_id == Id::new("owner/root").unwrap())
    );

    drop(runtime);
    let deadline = crate::supervision::ProcessDeadline::after(Duration::from_secs(120)).unwrap();
    while !engine.poll_reclamation().unwrap() {
        assert!(
            !deadline.expired(),
            "actual Root whole-world group reclamation timed out"
        );
        deadline.pause(Duration::from_millis(10));
    }
}

pub(super) struct FailedWitnessSupervision<'a>(pub(super) &'a RootInstalledEngine);

impl Drop for FailedWitnessSupervision<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let deadline =
            crate::supervision::ProcessDeadline::after(Duration::from_secs(120)).unwrap();
        while !deadline.expired() {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.0.poll_reclamation()
            })) {
                Ok(Ok(true)) => return,
                Ok(Ok(false)) => {}
                Ok(Err(error)) => {
                    eprintln!("Root original failed-witness cleanup remains retained: {error}");
                    return;
                }
                Err(_) => {
                    eprintln!("Root original failed-witness cleanup remains retained after unwind");
                    return;
                }
            }
            deadline.pause(Duration::from_millis(10));
        }
        eprintln!("Root original failed-witness custody remains retained at deadline");
    }
}
