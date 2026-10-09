//! Exercises historical claims and the real protected admission/readback join.
//!
//! Capability and TLS facts are synthetic test inputs, not production peer
//! qualification. The journal, projection codec and reconciler are genuine.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use aos_proto::aos::sandbox::v1::ViewPhase;
use aos_sandbox_core::{ResourceId, ResourceKind, Selector};

use super::*;
use crate::controller_fuse_admission::AcceptedControllerFuseAdmissionV1;
use aos_sandbox_protocol::public_api::PublicOperationMethodV1;
use crate::{
    EffectFailure, EffectObservation, EffectPlan, EffectReceipt, IdempotencyKey, JournalLimits,
    JournalRecord, JournalTransaction, OperationPlan, PublicOperationAdmissionV1,
    PublicOperationAuthorizationV1, Reconciler, RecordNamespace, SingleNodeEffectExecutor,
};

use aos_sandbox_protocol as protocol;
#[path = "../../../../aos-sandbox-protocol/src/public_api/mutation_history/fuse/tests/fixture.rs"]
mod historical_fixture;

fn fixture() -> ControllerFuseAdmissionCarrierV1 {
    ControllerFuseAdmissionCarrierV1(historical_fixture::historical_fixture())
}

fn stored_bytes(carrier: &ControllerFuseAdmissionCarrierV1, field: &str) -> Vec<u8> {
    let bytes = carrier.canonical_bytes();
    let stored: serde_json::Value = serde_json::from_slice(&bytes[20..bytes.len() - 32]).unwrap();
    serde_json::from_value(stored[field].clone()).unwrap()
}

struct NoDispatch;

impl SingleNodeEffectExecutor for NoDispatch {
    fn observe(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        panic!("admission must not dispatch")
    }

    fn apply(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        panic!("admission must not dispatch")
    }
}

fn admit(
    journal: Journal,
    carrier: &ControllerFuseAdmissionCarrierV1,
    legacy: bool,
) -> Reconciler<NoDispatch> {
    let mut reconciler = Reconciler::new(journal, NoDispatch);
    let context = PublicMutationEffectV1::decode_plain(carrier.ordinary_effect())
        .unwrap()
        .unwrap();
    let context = if legacy {
        context
    } else {
        context.with_fuse_admission(carrier.clone()).unwrap()
    };
    let effect =
        EffectPlan::authorized_public_mutation(PublicOperationMethodV1::AttachView, context)
            .unwrap();
    let plan = OperationPlan::new(
        carrier.operation(),
        IdempotencyKey::new(vec![13; 16]).unwrap(),
        *carrier.request_digest().as_bytes(),
        stored_bytes(carrier, "attachment_key"),
        stored_bytes(carrier, "attachment_value"),
        vec![effect],
    )
    .unwrap()
    .with_public_operation(
        PublicOperationAdmissionV1::new(
            PublicOperationMethodV1::AttachView,
            1,
            [28; 16],
            150,
            PublicOperationAuthorizationV1::new(
                carrier.project(),
                ResourceKind::AttachmentSlot,
                Selector::Resource {
                    resource: ResourceId::from_bytes([10; 16]),
                },
            )
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    reconciler
        .journal_mut()
        .commit(
            &JournalTransaction::new(
                [29; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    stored_bytes(&carrier, "original_view_key"),
                    stored_bytes(&carrier, "original_view_value"),
                )],
            )
            .unwrap(),
        )
        .unwrap();
    reconciler.accept(&plan).unwrap();
    reconciler
}

fn open(directory: &Path) -> Journal {
    Journal::open_protected_at_uid(
        directory,
        "controller.journal",
        JournalLimits::default(),
        fs::metadata(directory).unwrap().uid(),
    )
    .unwrap()
    .0
}

fn read<'journal>(
    journal: &'journal Journal,
    root: &Path,
    operation: OperationId,
) -> Result<Option<AcceptedControllerFuseAdmissionV1<'journal>>, ControllerFuseAdmissionErrorV1> {
    AcceptedControllerFuseAdmissionV1::read_at_location(
        journal,
        operation,
        crate::controller_fuse_admission::ControllerAdmissionLocationV1 {
            fixture_root: Some(root.to_path_buf()),
        },
    )
}

#[test]
fn controller_fuse_admission_real_atomic_ledger_reopens_and_legacy_refuses() {
    for legacy in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let carrier = fixture();
        let mut reconciler = admit(open(directory.path()), &carrier, legacy);
        let accepted = read(
            reconciler.journal_mut(),
            directory.path(),
            carrier.operation(),
        )
        .unwrap();
        assert_eq!(accepted.is_none(), legacy);
        if let Some(accepted) = accepted {
            assert_eq!(accepted.carrier(), &carrier);
            accepted.recheck().unwrap();
        }
        drop(reconciler);

        let journal = open(directory.path());
        let accepted = read(&journal, directory.path(), carrier.operation()).unwrap();
        assert_eq!(accepted.is_none(), legacy);
        if let Some(accepted) = accepted {
            assert_eq!(accepted.digest(), carrier.digest());
        }
    }
}

#[test]
fn controller_fuse_admission_refuses_foreign_production_path_and_changed_owner_names() {
    for name in ["controller.journal", "controller.journal.lock"] {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let carrier = fixture();
        let mut reconciler = admit(open(directory.path()), &carrier, false);
        let journal = reconciler.journal_mut();
        let sequence = journal.snapshot_sequence();
        assert!(AcceptedControllerFuseAdmissionV1::read(journal, carrier.operation()).is_err());
        let accepted = read(journal, directory.path(), carrier.operation())
            .unwrap()
            .unwrap();
        fs::rename(
            directory.path().join(name),
            directory.path().join("moved-name"),
        )
        .unwrap();
        assert!(accepted.recheck().is_err());
        assert_eq!(journal.snapshot_sequence(), sequence);
    }
}

#[test]
fn controller_fuse_admission_keeps_historical_view_but_refuses_changed_attachment_or_release() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let carrier = fixture();
    let mut reconciler = admit(open(directory.path()), &carrier, false);
    let mut view = carrier.original_view().clone();
    view.revision.as_option_mut().unwrap().sha256 = vec![34; 32];
    view.desired_generation += 1;
    let latest = PublicProjectionPlanV1::new(
        carrier.project(),
        OperationId::from_bytes([35; 16]),
        PublicProjectionResourceV1::FilesystemView(view.clone()),
    )
    .unwrap();
    reconciler
        .journal_mut()
        .commit(
            &JournalTransaction::new(
                [36; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    latest.desired_key().to_vec(),
                    latest.desired_value().to_vec(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
    let accepted = read(
        reconciler.journal_mut(),
        directory.path(),
        carrier.operation(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(accepted.carrier().original_view(), carrier.original_view());
    drop(accepted);

    view.phase = ViewPhase::VIEW_PHASE_RELEASED.into();
    let released = PublicProjectionPlanV1::new(
        carrier.project(),
        OperationId::from_bytes([35; 16]),
        PublicProjectionResourceV1::FilesystemView(view),
    )
    .unwrap();
    reconciler
        .journal_mut()
        .commit(
            &JournalTransaction::new(
                [37; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    released.desired_key().to_vec(),
                    released.desired_value().to_vec(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        read(
            reconciler.journal_mut(),
            directory.path(),
            carrier.operation()
        )
        .is_err()
    );

    // Restore the View so the next rejection independently tests Attachment.
    reconciler
        .journal_mut()
        .commit(
            &JournalTransaction::new(
                [38; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    stored_bytes(&carrier, "original_view_key"),
                    stored_bytes(&carrier, "original_view_value"),
                )],
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        read(
            reconciler.journal_mut(),
            directory.path(),
            carrier.operation()
        )
        .unwrap()
        .is_some()
    );

    let mut attachment = carrier.attachment().clone();
    attachment.assignment_epoch += 1;
    let changed = PublicProjectionPlanV1::new(
        carrier.project(),
        carrier.operation(),
        PublicProjectionResourceV1::Attachment(attachment),
    )
    .unwrap();
    reconciler
        .journal_mut()
        .commit(
            &JournalTransaction::new(
                [39; 16],
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    changed.desired_key().to_vec(),
                    changed.desired_value().to_vec(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        read(
            reconciler.journal_mut(),
            directory.path(),
            carrier.operation()
        )
        .is_err()
    );
}
