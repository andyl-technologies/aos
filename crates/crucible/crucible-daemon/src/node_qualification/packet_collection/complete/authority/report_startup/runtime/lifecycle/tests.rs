//! Exercises the actual holder gates without manufacturing native readiness.

use super::*;
use crucible_engine::node_contract::{
    ActivationRecord, OriginalInputLineageLimits, PublicationStatus,
};
use crucible_engine::node_state::{
    NativeArchive, NativeArchiveLimits, StateRequirements, StateRestoreMode,
};
use crucible_node_format::{Id, Position, U64};

struct UnusedPublisher;

impl ConformanceResultPublisher for UnusedPublisher {}

impl ActivationPublisher for UnusedPublisher {
    fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
        panic!("an incomplete original scene must not publish");
    }

    fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
        panic!("an incomplete original scene must not reconcile");
    }
}

#[test]
fn missing_original_actor_refuses_arm_and_activation_without_source_changes() {
    let (_scene, original) =
        crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
    let before = original
        .borrow()
        .authority
        .roster
        .sources
        .each_ref()
        .map(|source| source.original_report_startup_audit_data().unwrap());

    assert!(matches!(
        PacketCompleteReportStartupHolder::arm_original_scene(&original),
        Err(RuntimeError::OutstandingObligations)
    ));
    assert!(matches!(
        PacketCompleteReportStartupHolder::activate_original_scene(
            &original,
            &mut UnusedPublisher,
            65_536,
        ),
        Err(RuntimeError::OutstandingObligations)
    ));

    assert!(matches!(
        PacketCompleteReportStartupHolder::begin_original_scene_next(&original),
        Err(RuntimeError::OutstandingObligations)
    ));
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        PacketCompleteReportStartupHolder::poll_original_scene(&original, &mut context),
        Err(RuntimeError::OutstandingObligations)
    ));
    assert!(matches!(
        PacketCompleteReportStartupHolder::acknowledge_original_scene(
            &original,
            &mut UnusedPublisher
        ),
        Err(RuntimeError::OutstandingObligations)
    ));

    let held = original.borrow();
    assert!(held.runtime_owners.borrow().actor.is_none());
    assert!(
        held.runtime_members
            .iter()
            .all(|member| member.get().is_none())
    );
    assert_eq!(
        held.authority
            .roster
            .sources
            .each_ref()
            .map(|source| source.original_report_startup_audit_data().unwrap()),
        before
    );
}

#[test]
fn busy_and_retired_original_holder_cannot_reenter_actor_lifecycle() {
    let (_scene, original) =
        crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
    let held = original.borrow_mut();

    assert!(matches!(
        PacketCompleteReportStartupHolder::arm_original_scene(&original),
        Err(RuntimeError::OwnerBusy)
    ));
    assert!(matches!(
        PacketCompleteReportStartupHolder::activate_original_scene(
            &original,
            &mut UnusedPublisher,
            65_536,
        ),
        Err(RuntimeError::OwnerBusy)
    ));
    held.original_scene_retired.set(true);
    drop(held);

    assert!(matches!(
        PacketCompleteReportStartupHolder::arm_original_scene(&original),
        Err(RuntimeError::OutstandingObligations)
    ));
    assert!(original.borrow().runtime_owners.borrow().actor.is_none());
}

#[test]
fn missing_original_actor_never_enters_capture_or_fills_archive_output() {
    let (_scene, original) =
        crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
    let directory = tempfile::tempdir().unwrap();
    let archive = NativeArchive::open(
        directory.path().join("archive"),
        NativeArchiveLimits::default(),
    )
    .unwrap();
    let mut output = None;
    let before = original
        .borrow()
        .authority
        .roster
        .sources
        .each_ref()
        .map(|source| source.original_report_startup_audit_data().unwrap());

    assert!(matches!(
        PacketCompleteReportStartupHolder::capture_original_scene_into(
            &original,
            PacketCompleteWorldCapture {
                archive: &archive,
                cut: Position::new(
                    U64::new(0),
                    U64::new(0),
                    crucible_node_format::Phase::BoundaryControl
                ),
                ordinal: U64::new(0),
                capture_id: Id::new("missing-original-actor-capture").unwrap(),
                requirements: StateRequirements {
                    preservation_contract: Id::new(
                        "source-owned.packet-complete-original-lineage/5"
                    )
                    .unwrap(),
                    exact_model_continuation: true,
                    deterministic: false,
                    restore_mode: StateRestoreMode::DurableRestart,
                },
                lineage_limits: OriginalInputLineageLimits::default(),
            },
            &mut output,
        ),
        Err(RuntimeError::OutstandingObligations)
    ));

    assert!(output.is_none());
    let held = original.borrow();
    assert!(held.runtime_owners.borrow().actor.is_none());
    assert_eq!(
        held.authority
            .roster
            .sources
            .each_ref()
            .map(|source| source.original_report_startup_audit_data().unwrap()),
        before
    );
}
