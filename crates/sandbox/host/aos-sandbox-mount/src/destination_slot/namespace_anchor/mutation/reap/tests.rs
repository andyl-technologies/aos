//! Exercises the real lower rooted removal and independently owed native posts.
//!
//! These native temporary-directory tests do not manufacture signed62 admission
//! or Host disposal. The enclosing closed service owns those distinct gates.

use super::*;
use aos_sandbox_api::aos::sandbox::local::v1::{
    AssignmentFence, AttachmentAnchorResourceRecordV1, Descriptor, MountAssignmentBinding,
    MountOperationCorrelation,
};
use aos_sandbox_mount_native::JournalLimits;
use aos_sandbox_protocol::mount_attachment_anchor::seal_attachment_anchor_resource_v1;

struct Fixture {
    directory: tempfile::TempDir,
    _journal: Journal,
    store: DestinationSlotStoreV1,
    ready: ValidatedAttachmentAnchorResourceV1,
    path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            directory.path(),
            std::fs::Permissions::from_mode(PARENT_DIRECTORY_MODE),
        )
        .unwrap();
        let (journal, _) = Journal::open(
            directory.path().join("mount.journal"),
            JournalLimits::default(),
        )
        .unwrap();
        let mut store = DestinationSlotStoreV1::recover(
            directory.path(),
            rustix::process::geteuid().as_raw(),
            &journal,
        )
        .unwrap();
        let relative = anchor_catalog_relative_path(&[1; 16], &[2; 16], 6);
        let path = directory.path().join(&relative);
        std::fs::create_dir_all(&path).unwrap();
        let mut ancestor = path.as_path();
        while ancestor != directory.path() {
            let mode = if ancestor == path {
                ANCHOR_DIRECTORY_MODE
            } else {
                PARENT_DIRECTORY_MODE
            };
            std::fs::set_permissions(ancestor, std::fs::Permissions::from_mode(mode)).unwrap();
            ancestor = ancestor.parent().unwrap();
        }
        let pin = store
            .root
            .resolve(&relative, ResolveOptions::directory())
            .unwrap();
        let physical = pin.identity();
        let ready = seal_attachment_anchor_resource_v1(AttachmentAnchorResourceRecordV1 {
            binding: Some(MountAssignmentBinding {
                fence: Some(AssignmentFence {
                    sandbox_id: vec![1; 16],
                    incarnation_id: vec![2; 16],
                    assignment_epoch: 3,
                    desired_generation: 4,
                    assignment_digest: vec![5; 32],
                    ..Default::default()
                })
                .into(),
                namespace_generation: 6,
                ..Default::default()
            })
            .into(),
            sandbox_spec: Some(Descriptor {
                media_type: PortableMediaType::SandboxSpec.as_str().to_owned(),
                sha256: vec![9; 32],
                encoded_size: 1,
                ..Default::default()
            })
            .into(),
            lifecycle: Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY.into(),
            resource_kernel_boot_id: store.kernel_boot_id.to_vec(),
            materialization: Some(MountOperationCorrelation {
                operation_id: vec![7; 16],
                request_digest: vec![8; 32],
                ..Default::default()
            })
            .into(),
            directory_device: Some(physical.device),
            directory_inode: Some(physical.inode),
            anchor_unique_mount_id: Some(store.anchor_mount_id.get()),
            ..Default::default()
        })
        .unwrap();
        store.namespace_anchors.pins.insert(
            ready.key_v1(),
            Arc::new(BeneathRoot::from_resolved(pin).unwrap()),
        );
        store
            .namespace_anchors
            .records
            .insert(ready.key_v1(), ready.clone());
        Self {
            directory,
            _journal: journal,
            store,
            ready,
            path,
        }
    }
}

#[test]
fn actual_empty_removal_finishes_durability_and_both_native_posts_before_retirement() {
    let mut fixture = Fixture::new();
    let mut original = NamespaceReapOriginalV4::default();

    assert!(original.before_v4(&fixture.store, &fixture.ready).unwrap());
    original
        .remove_and_posts_v4(&fixture.store, &fixture.ready, true)
        .unwrap();

    assert!(matches!(original.removed, Some(Ok(()))));
    assert!(matches!(original.sync_result, Some(Ok(()))));
    assert!(matches!(original.held_after.compared, Some(Ok(()))));
    assert!(matches!(original.after_result, Some(Ok(()))));
    assert!(!fixture.path.exists());
    assert_eq!(
        original
            .held_after
            .metadata
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .st_nlink,
        0
    );
    assert!(original.failure_v4().is_none());
    original.retire_positive_native_v4();
    fixture
        .store
        .namespace_anchors
        .pins
        .remove(&fixture.ready.key_v1());
    assert!(original.before.borrowed_pin_v4().is_none());
    assert!(original.parent.borrowed_pin_v4().is_none());
    assert!(
        !fixture
            .store
            .namespace_anchors
            .pins
            .contains_key(&fixture.ready.key_v1())
    );
    assert!(fixture.directory.path().exists());
}

#[test]
fn nonempty_native_refusal_keeps_original_and_runs_every_prepaid_post() {
    let fixture = Fixture::new();
    std::fs::write(fixture.path.join("foreign"), b"must stay").unwrap();
    let mut original = NamespaceReapOriginalV4::default();
    assert!(original.before_v4(&fixture.store, &fixture.ready).unwrap());

    assert!(
        original
            .remove_and_posts_v4(&fixture.store, &fixture.ready, true)
            .is_err()
    );

    assert!(matches!(original.first, Some(First::Remove)));
    assert!(matches!(original.removed, Some(Err(_))));
    assert!(matches!(original.sync_result, Some(Ok(()))));
    assert!(original.held_after.metadata.is_some());
    assert!(original.held_after.mount.is_some());
    assert!(matches!(original.held_after.compared, Some(Err(_))));
    assert!(matches!(original.after_result, Some(Err(_))));
    assert!(original.before.borrowed_pin_v4().is_some());
    assert!(original.parent.borrowed_pin_v4().is_some());
    assert_eq!(
        std::fs::read(fixture.path.join("foreign")).unwrap(),
        b"must stay"
    );
    assert!(
        fixture
            .store
            .namespace_anchors
            .pins
            .contains_key(&fixture.ready.key_v1())
    );
    assert!(
        original
            .failure_v4()
            .unwrap()
            .downcast_ref::<rustix::io::Errno>()
            .is_some()
    );
}

#[test]
fn another_actual_local_pin_closes_the_before_without_removing_anything() {
    let fixture = Fixture::new();
    let export = Arc::clone(
        fixture
            .store
            .namespace_anchors
            .pins
            .get(&fixture.ready.key_v1())
            .unwrap(),
    );
    let mut original = NamespaceReapOriginalV4::default();

    assert!(original.before_v4(&fixture.store, &fixture.ready).is_err());

    assert!(original.removed.is_none());
    assert!(original.sync_result.is_none());
    assert!(fixture.path.exists());
    assert_eq!(Arc::strong_count(&export), 2);
}
