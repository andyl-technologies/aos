//! Captures genuine producer/relay/sink/Host state after three stored completions.
//!
//! This installed control launches only the explicitly measured source-built
//! packet provider. The expected cut is a request; actual unchanged-cut proofs
//! and the locally authenticated archive must establish it independently.

use super::*;
use crate::node_observed_executor::StoredWorldActivationPublisher;
use crate::node_qualification::packet_collection::complete::PacketCompleteWorldCapture;
use crate::supervision::ProcessDeadline;
use crucible::node_contract::OriginalInputLineageLimits;
use crucible::node_state::{NativeArchive, StateRequirements, StateRestoreMode};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend, RefName,
};
use crucible_node_contract::{Id, Phase, Position, U64};
use std::{
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn reclaim(installed: &mut InstalledCompleteScene) {
    installed.retire().unwrap();
    let deadline = ProcessDeadline::after(Duration::from_secs(30)).unwrap();
    while !installed.poll_reclamation().unwrap() {
        assert!(
            !deadline.expired(),
            "original packet children were not reclaimed"
        );
        deadline.pause(Duration::from_millis(1));
    }
    assert!(installed.is_reclaimed());
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_PACKET_PROVIDER pointing to the source-built packet provider"]
fn source_built_packet_three_stored_grants_capture_and_selected_reload() {
    let executable = PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_PACKET_PROVIDER")
            .expect("set CRUCIBLE_REFERENCE_PACKET_PROVIDER to the source-built provider binary"),
    );
    let (_code_source, declaration, limits) =
        super::super::super::tests::native_roundtrip::capture_declaration(&executable);
    let directory = private_directory();
    let manifest = pinned(directory.path(), &declaration);
    let mut installed =
        InstalledCompleteScene::install(manifest, directory.path().join("scene")).unwrap();
    let archive = NativeArchive::open(directory.path().join("archive"), limits).unwrap();
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "installed-packet-original",
        directory.path().join("blobs"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let blob_store: Arc<dyn ImmutableBlobBackend> = blobs.clone();
    let ref_store: Arc<dyn MutableRefBackend> = refs.clone();
    let mut activation_publisher = StoredWorldActivationPublisher::new(
        blob_store.clone(),
        ref_store.clone(),
        RefName::new("node-world-activations/installed-packet-original").unwrap(),
    )
    .unwrap();
    let mut captured = None;
    let mut results = None;
    let expected_cut = Position::new(U64::new(1), U64::new(0), Phase::BoundaryControl);
    let expected_ordinal = U64::new(0);

    // Every native owner remains outside the unwind boundary. A failed grant,
    // publication or Capture retains its partials until genuine reclamation.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        installed.prepare().unwrap();
        PacketCompleteReportStartupHolder::authenticate_original_inactive_actor_for_test(
            &installed.original,
        )
        .unwrap();
        PacketCompleteReportStartupHolder::arm_original_scene(&installed.original).unwrap();
        PacketCompleteReportStartupHolder::activate_original_scene(
            &installed.original,
            &mut activation_publisher,
            limits.state.maximum_record_bytes,
        )
        .unwrap();
        let references = std::array::from_fn(|index| {
            RefName::new(format!(
                "node-packet-collecting-results/installed-packet-original-{index}"
            ))
            .unwrap()
        });
        results = Some(
            PacketCompleteReportStartupHolder::prepare_original_scene_result_publisher(
                &installed.original,
                blob_store.clone(),
                ref_store.clone(),
                references,
                16 * 1024 * 1024,
                256 * 1024 * 1024,
            )
            .unwrap(),
        );

        // The two reactive empty batches still execute genuine Stage/ACK/Commit.
        // A successful poll and stored Complete publication precede each ACK.
        for _ in 0..3 {
            PacketCompleteReportStartupHolder::begin_original_scene_next(&installed.original)
                .unwrap();
            let deadline = ProcessDeadline::after(Duration::from_secs(30)).unwrap();
            let mut context = Context::from_waker(Waker::noop());
            loop {
                match PacketCompleteReportStartupHolder::poll_original_scene(
                    &installed.original,
                    &mut context,
                )
                .unwrap()
                {
                    Poll::Ready(()) => break,
                    Poll::Pending => {
                        assert!(
                            !deadline.expired(),
                            "original packet grant did not complete"
                        );
                        deadline.pause(Duration::from_millis(1));
                    }
                }
            }
            PacketCompleteReportStartupHolder::acknowledge_original_scene_stored(
                &installed.original,
                results.as_mut().unwrap(),
            )
            .unwrap();
        }
        // Keep the concrete publication owner and namespace through Capture
        // and native reclamation, including any later failure.
        PacketCompleteReportStartupHolder::capture_original_scene_into(
            &installed.original,
            PacketCompleteWorldCapture {
                archive: &archive,
                cut: expected_cut,
                ordinal: expected_ordinal,
                capture_id: id("installed-packet-bootstrap-capture"),
                requirements: StateRequirements {
                    preservation_contract: id("source-owned.packet-complete-original-lineage/5"),
                    exact_model_continuation: true,
                    deterministic: false,
                    restore_mode: StateRestoreMode::DurableRestart,
                },
                lineage_limits: OriginalInputLineageLimits::default(),
            },
            &mut captured,
        )
        .unwrap();
        let actual = captured.as_ref().unwrap();
        assert_eq!(actual.manifest().cut, expected_cut);
        assert_eq!(actual.manifest().event_ordinal, expected_ordinal);
        assert_eq!(actual.owners().len(), 4);
    }));
    reclaim(&mut installed);
    drop(results.take());
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }

    let captured = captured.unwrap();
    let loaded = archive.load_complete_original(captured.artifact()).unwrap();
    assert_eq!(loaded.artifact(), captured.artifact());
    assert_eq!(loaded.manifest(), captured.manifest());
    assert_eq!(loaded.owners().len(), 4);
    assert!(installed.prepare().is_err());
}
