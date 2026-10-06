//! Persistent RAM storage and adversarial transfer conformance tests.

// crucible-lint: allow panic-shortcut -- adversarial fixtures panic only when their required setup or successful control operation fails.
// crucible-lint: allow rust-allow -- panic shortcuts are confined to this test module and preserve exact failure localization.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use crucible_ram::{Limits, RegionClass, RegionDescriptor, Scope, Topology};

use crate::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ContentId, DurabilityRequirement,
    ImmutableBlobBackend, ObjectKind, PutReceipt, SqliteBlobBackend, StoreError,
};

use super::*;

fn archive_offer(
    root: &LeasedRamRoot,
    chunk_bytes: u32,
) -> crucible_protocol::ram_transfer::RamTransferOffer {
    use crucible_protocol::ram_transfer::{RamTransferLimits, RamTransferOffer};
    RamTransferOffer {
        whole_world_root: ContentId::for_bytes(
            ObjectKind::ExactManifest,
            6,
            b"archive owner fixture",
        )
        .encode(),
        ram_root: root.object_id().encode(),
        root_record: root.record().encode(),
        destination: "test-destination".into(),
        durable_placements: 1,
        limits: RamTransferLimits {
            objects: 100_000,
            bytes: 64 * 1024 * 1024,
            chunk_bytes,
        },
    }
}

#[derive(Default)]
struct Retention {
    objects: Mutex<BTreeSet<ContentId>>,
}

struct Lease(ContentId);

impl RamRootLease for Lease {
    fn root(&self) -> ContentId {
        self.0
    }
}

impl RamRetention for Retention {
    fn retain_object(&self, id: ContentId) -> Result<(), RamStoreError> {
        self.objects
            .lock()
            .map_err(|_| RamStoreError::Retention("test lock poisoned".into()))?
            .insert(id);
        Ok(())
    }

    fn retain_root(&self, root: ContentId) -> Result<Arc<dyn RamRootLease>, RamStoreError> {
        self.retain_object(root)?;
        Ok(Arc::new(Lease(root)))
    }
}

fn store(path: &std::path::Path, limits: RamStoreLimits) -> RamStore {
    RamStore::new(
        Arc::new(SqliteBlobBackend::open("ram-test", path).unwrap()),
        DurabilityRequirement::new(1, false).unwrap(),
        limits,
    )
    .unwrap()
}

fn topology(length: u64) -> Topology {
    Topology::new(
        vec![RegionDescriptor::new("main", RegionClass::MutableMain, length).unwrap()],
        Limits::default(),
    )
    .unwrap()
}

fn patterned(_: &RegionDescriptor, index: u64, bytes: &mut [u8]) -> Result<(), RamStoreError> {
    bytes.fill((index % 251) as u8);
    Ok(())
}

#[test]
fn lazy_lookup_proves_partial_pages_and_persistent_updates() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let root = store
        .capture(
            topology(4096 * 7 + 19),
            Scope::Exact,
            &mut patterned,
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    let (bytes, proof) = store
        .read_page_with_proof(&root, "main", 7, &mut || Ok(()))
        .unwrap();

    assert_eq!(bytes, vec![7; 19]);
    proof
        .verify(&bytes, root.record(), root.logical_digest())
        .unwrap();
    assert!(
        proof
            .verify(&[8; 19], root.record(), root.logical_digest())
            .is_err()
    );
    assert!(store.read_page(&root, "main", 8, &mut || Ok(())).is_err());

    let updated = store
        .update(
            &root,
            [RamPageChange {
                region_id: "main".into(),
                page_index: 3,
                bytes: vec![99; 4096],
            }],
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    let mut differences = Vec::new();
    let changed = store
        .visit_differing_pages(
            &root,
            &updated,
            &mut |region, index| {
                differences.push((region.to_owned(), index));
                Ok(())
            },
            &mut || Ok(()),
        )
        .unwrap();

    assert_eq!(changed, 1);
    assert_eq!(differences, vec![("main".to_owned(), 3)]);
    assert_eq!(
        store.read_page(&root, "main", 3, &mut || Ok(())).unwrap(),
        vec![3; 4096]
    );
    assert_eq!(
        store
            .read_page(&updated, "main", 3, &mut || Ok(()))
            .unwrap(),
        vec![99; 4096]
    );
    assert_eq!(
        store
            .verify(&updated, &mut || Ok(()))
            .unwrap()
            .logical_bytes,
        4096 * 7 + 19
    );
}

#[test]
fn archive_wire_transfer_validates_repeated_and_changed_content() {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source = store(source_directory.path(), RamStoreLimits::default());
    let destination = store(destination_directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let root = source
        .capture(
            topology(4096 * 16 + 7),
            Scope::Exact,
            &mut patterned,
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    let world = ContentId::parse(&archive_offer(&root, 64).whole_world_root).unwrap();

    let first = source
        .transfer_archive_to(
            &root,
            world,
            &destination,
            "destination",
            [1; 32],
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(
        destination
            .verify(first.root(), &mut || Ok(()))
            .unwrap()
            .logical_bytes,
        4096 * 16 + 7
    );
    let repeated = source
        .transfer_archive_to(
            &root,
            world,
            &destination,
            "destination",
            [1; 32],
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(repeated.report().copied_objects, 0);
    assert!(repeated.report().authenticated_existing_objects > 0);

    let updated = source
        .update(
            &root,
            [RamPageChange {
                region_id: "main".into(),
                page_index: 2,
                bytes: vec![99; 4096],
            }],
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    let next = source
        .transfer_archive_to(
            &updated,
            world,
            &destination,
            "destination",
            [2; 32],
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(next.report().copied_objects, 8);
    assert!(next.report().copied_bytes < first.report().copied_bytes);
    assert_eq!(
        destination
            .read_page(next.root(), "main", 16, &mut || Ok(()))
            .unwrap(),
        vec![16; 7]
    );
}

#[test]
fn absolute_wire_credits_are_idempotent_and_coordinates_do_not_authorize_other_objects() {
    use crucible_protocol::ram_transfer::{
        RamTransferControl, RamTransferMessage, RamTransferNodeCoordinate,
    };
    let directory = tempfile::tempdir().unwrap();
    let source = store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let root = source
        .capture(
            topology(4096 * 2),
            Scope::Exact,
            &mut patterned,
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    let mut sender =
        RamTransferSender::new(source, root.clone(), [3; 32], archive_offer(&root, 13)).unwrap();
    let request = RamTransferMessage {
        operation: [3; 32],
        control: RamTransferControl::WantNode {
            coordinate: RamTransferNodeCoordinate::Root,
            object: root.object_id().encode(),
        },
    };
    let first = sender.respond(request, &mut || Ok(())).unwrap();
    let RamTransferControl::ObjectChunk {
        bytes,
        offset,
        last,
        ..
    } = first.control
    else {
        panic!("expected first chunk")
    };
    assert_eq!(offset, 0);
    assert_eq!(bytes.len(), 13);
    assert!(!last);
    let credit = RamTransferMessage {
        operation: [3; 32],
        control: RamTransferControl::Credit {
            object: root.object_id().encode(),
            offset: 13,
            bytes: 13,
        },
    };
    assert_eq!(
        sender.respond(credit.clone(), &mut || Ok(())).unwrap(),
        sender.respond(credit, &mut || Ok(())).unwrap()
    );
    let foreign = RamTransferMessage {
        operation: [4; 32],
        control: RamTransferControl::Cancel,
    };
    assert!(sender.respond(foreign, &mut || Ok(())).is_err());
    let forged = RamTransferMessage {
        operation: [3; 32],
        control: RamTransferControl::WantObject {
            region_id: "main".into(),
            page_index: 0,
            object: ContentId::for_bytes(ObjectKind::RamExtent, 1, b"unrelated backend object")
                .encode(),
        },
    };
    assert!(sender.respond(forged, &mut || Ok(())).is_err());
    let acknowledgment = sender
        .respond(
            RamTransferMessage {
                operation: [3; 32],
                control: RamTransferControl::Cancel,
            },
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(acknowledgment.control, RamTransferControl::Canceled);
}

#[test]
fn corrupt_or_foreign_wire_chunk_never_publishes_a_destination_root() {
    use crucible_protocol::ram_transfer::{RamTransferControl, RamTransferMessage};
    let source_directory = tempfile::tempdir().unwrap();
    let source = store(source_directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let root = source
        .capture(
            topology(4096 * 3),
            Scope::Exact,
            &mut patterned,
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    for foreign in [false, true] {
        let destination_directory = tempfile::tempdir().unwrap();
        let destination = store(destination_directory.path(), RamStoreLimits::default());
        let mut sender = RamTransferSender::new(
            source.clone(),
            root.clone(),
            [5; 32],
            archive_offer(&root, 64 * 1024),
        )
        .unwrap();
        let mut receiver =
            RamTransferReceiver::new(destination.clone(), &retention, sender.offer()).unwrap();
        let mut exchange = |message: RamTransferMessage| {
            let mut response = sender.respond(message, &mut || Ok(()))?;
            if let RamTransferControl::ObjectChunk { bytes, .. } = &mut response.control {
                if foreign {
                    response.operation = [6; 32];
                } else {
                    bytes[0] ^= 1;
                }
            }
            Ok(response)
        };
        assert!(receiver.receive(&mut exchange, &mut || Ok(())).is_err());
        assert!(!destination.backend.contains(root.object_id()).unwrap());
    }
}

#[test]
fn framed_transfer_operates_between_independent_socket_instances() {
    use crucible_protocol::ram_transfer::RamTransferMessage;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source = store(source_directory.path(), RamStoreLimits::default());
    let destination = store(destination_directory.path(), RamStoreLimits::default());
    let source_retention = Retention::default();
    let destination_retention = Retention::default();
    let root = source
        .capture(
            topology(4096 * 3 + 19),
            Scope::Exact,
            &mut patterned,
            &source_retention,
            &mut || Ok(()),
        )
        .unwrap();
    let mut sender =
        RamTransferSender::new(source, root.clone(), [8; 32], archive_offer(&root, 17)).unwrap();
    let (mut source_socket, mut destination_socket) = UnixStream::pair().unwrap();
    for socket in [&source_socket, &destination_socket] {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
    }
    let sending =
        std::thread::spawn(move || sender.serve_transport(&mut source_socket, &mut || Ok(())));
    let offer = RamTransferMessage::read(&mut destination_socket).unwrap();
    let mut receiver =
        RamTransferReceiver::new(destination.clone(), &destination_retention, offer).unwrap();
    let RamTransferStep::ClosureStored(stored) = receiver
        .receive_transport(&mut destination_socket, &mut || Ok(()))
        .unwrap()
    else {
        panic!("expected closure possession")
    };

    sending.join().unwrap().unwrap();
    assert_eq!(stored.root().logical_digest(), root.logical_digest());
    assert_eq!(
        destination
            .read_page(stored.root(), "main", 3, &mut || Ok(()))
            .unwrap(),
        vec![3; 19]
    );
    assert_eq!(
        destination
            .verify(stored.root(), &mut || Ok(()))
            .unwrap()
            .pages,
        4
    );
}

#[test]
fn inventory_walk_authenticates_actual_pages_under_borrowed_exclusive_authority() {
    use crate::content_store::{MemoryRefBackend, RefStoreAdmin};
    let directory = tempfile::tempdir().unwrap();
    let source = store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let root = source
        .capture(
            topology(4096 * 2 + 3),
            Scope::Exact,
            &mut patterned,
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    let refs = MemoryRefBackend::new();
    let fence = refs.acquire_ref_inventory_fence().unwrap();
    let mut visited = BTreeSet::new();
    source
        .visit_inventory_graph(root.object_id(), fence.as_ref(), &mut |id| {
            visited.insert(id);
            Ok(())
        })
        .unwrap();
    assert!(visited.contains(&root.object_id()));
    assert!(visited.contains(&first_page_object(&source, &root)));

    let blocked = first_page_object(&source, &root);
    let corrupt = RamStore::new(
        Arc::new(UnavailableObject {
            backend: source.backend.clone(),
            blocked,
            corrupt: true,
        }),
        DurabilityRequirement::new(1, false).unwrap(),
        RamStoreLimits::default(),
    )
    .unwrap();
    assert!(
        corrupt
            .visit_inventory_graph(root.object_id(), fence.as_ref(), &mut |_| Ok(()))
            .is_err()
    );
    assert!(
        source
            .visit_inventory_graph(root.object_id(), fence.as_ref(), &mut |_| Err(
                RamStoreError::Canceled
            ))
            .is_err()
    );
}

#[test]
fn canceled_wire_transfer_leaves_root_unpublished_and_retries_from_actual_content() {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source = store(source_directory.path(), RamStoreLimits::default());
    let destination = store(destination_directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let root = source
        .capture(
            topology(4096 * 32),
            Scope::Exact,
            &mut patterned,
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    let world = ContentId::parse(&archive_offer(&root, 64).whole_world_root).unwrap();
    let mut boundaries = 0;
    let result = source.transfer_archive_to(
        &root,
        world,
        &destination,
        "destination",
        [7; 32],
        &retention,
        &mut || {
            boundaries += 1;
            if boundaries > 120 {
                Err(RamStoreError::Canceled)
            } else {
                Ok(())
            }
        },
    );
    assert!(matches!(result, Err(RamStoreError::Canceled)));
    assert!(!destination.backend.contains(root.object_id()).unwrap());
    let retry = source
        .transfer_archive_to(
            &root,
            world,
            &destination,
            "destination",
            [7; 32],
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    assert!(retry.report().authenticated_existing_objects > 0);
    assert_eq!(
        destination
            .verify(retry.root(), &mut || Ok(()))
            .unwrap()
            .pages,
        32
    );
}

#[test]
fn transfer_authenticates_existing_closure_and_copies_only_changed_content() {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source = store(source_directory.path(), RamStoreLimits::default());
    let destination = store(destination_directory.path(), RamStoreLimits::default());
    let source_retention = Retention::default();
    let destination_retention = Retention::default();
    let root = source
        .capture(
            topology(4096 * 16),
            Scope::Exact,
            &mut patterned,
            &source_retention,
            &mut || Ok(()),
        )
        .unwrap();
    let first = source
        .transfer_to(&root, &destination, &destination_retention, &mut || Ok(()))
        .unwrap();

    assert!(first.report().copied_objects > 0);
    assert_eq!(
        destination
            .verify(first.root(), &mut || Ok(()))
            .unwrap()
            .pages,
        16
    );
    let repeated = source
        .transfer_to(&root, &destination, &destination_retention, &mut || Ok(()))
        .unwrap();
    assert_eq!(repeated.report().copied_objects, 0);
    assert!(repeated.report().authenticated_existing_objects > 0);

    let updated = source
        .update(
            &root,
            [RamPageChange {
                region_id: "main".into(),
                page_index: 2,
                bytes: vec![99; 4096],
            }],
            &source_retention,
            &mut || Ok(()),
        )
        .unwrap();
    let next = source
        .transfer_to(&updated, &destination, &destination_retention, &mut || {
            Ok(())
        })
        .unwrap();

    assert_eq!(next.report().copied_objects, 7); // Page, leaf, four ancestors, root.
    assert!(next.report().copied_bytes < first.report().copied_bytes);
    assert_eq!(
        destination
            .read_page(next.root(), "main", 2, &mut || Ok(()))
            .unwrap(),
        vec![99; 4096]
    );
}

#[test]
fn operation_budget_and_cancellation_do_not_publish_a_root() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(
        directory.path(),
        RamStoreLimits {
            maximum_object_visits: 3,
            ..RamStoreLimits::default()
        },
    );
    let retention = Retention::default();
    let result = store.capture(
        topology(4096 * 4),
        Scope::Exact,
        &mut patterned,
        &retention,
        &mut || Ok(()),
    );

    assert!(matches!(result, Err(RamStoreError::Limit("object visits"))));
    let canceled = store.capture(
        topology(4096),
        Scope::Exact,
        &mut patterned,
        &retention,
        &mut || Err(RamStoreError::Canceled),
    );
    assert!(matches!(canceled, Err(RamStoreError::Canceled)));
}

#[test]
fn exact_scope_includes_immutable_images_but_execution_omits_them() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let topology = Topology::new(
        vec![
            RegionDescriptor::new("main", RegionClass::MutableMain, 4096).unwrap(),
            RegionDescriptor::new("rom", RegionClass::ImmutableImage, 19).unwrap(),
        ],
        Limits::default(),
    )
    .unwrap();
    let retention = Retention::default();
    let exact = store
        .capture(
            topology.clone(),
            Scope::Exact,
            &mut patterned,
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    let execution = store
        .capture(
            topology,
            Scope::Execution,
            &mut patterned,
            &retention,
            &mut || Ok(()),
        )
        .unwrap();

    assert_eq!(
        store
            .read_page(&exact, "rom", 0, &mut || Ok(()))
            .unwrap()
            .len(),
        19
    );
    assert!(
        store
            .read_page(&execution, "rom", 0, &mut || Ok(()))
            .is_err()
    );
    assert_eq!(
        exact.record().topology().digest(),
        execution.record().topology().digest()
    );
    assert_ne!(exact.logical_digest(), execution.logical_digest());
}

struct UnavailableObject {
    backend: Arc<dyn ImmutableBlobBackend>,
    blocked: ContentId,
    corrupt: bool,
}

impl ImmutableBlobBackend for UnavailableObject {
    fn name(&self) -> &str {
        self.backend.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.backend.capabilities()
    }

    fn admit_object_graph(&self, objects: &[(ObjectKind, u64)]) -> Result<(), StoreError> {
        self.backend.admit_object_graph(objects)
    }

    fn contains(&self, _: ContentId) -> Result<bool, StoreError> {
        Ok(true)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        if id == self.blocked {
            if self.corrupt {
                return Ok(BlobHandle::from_bytes(b"corrupt object".to_vec()));
            }
            return Err(StoreError::NotFound { id });
        }
        self.backend.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.backend.put_if_absent(id, source)
    }
}

fn first_page_object(store: &RamStore, root: &LeasedRamRoot) -> ContentId {
    let mut reference = root.regions[0];
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &mut boundary);
    loop {
        match store.read_tree(reference, &mut work).unwrap() {
            codec::TreeNode::Branch { left, .. } => reference = left,
            codec::TreeNode::Leaf { page, .. } => return page,
            codec::TreeNode::Padding => panic!("real coordinate resolved to padding"),
        }
    }
}

#[test]
fn destination_presence_hint_cannot_hide_missing_or_corrupt_actual_page() {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source = store(source_directory.path(), RamStoreLimits::default());
    let destination = store(destination_directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let root = source
        .capture(
            topology(4096 * 2),
            Scope::Exact,
            &mut patterned,
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    source
        .transfer_to(&root, &destination, &retention, &mut || Ok(()))
        .unwrap();
    let page = first_page_object(&source, &root);

    for corrupt in [false, true] {
        let lying_backend = Arc::new(UnavailableObject {
            backend: destination.backend.clone(),
            blocked: page,
            corrupt,
        });
        assert!(lying_backend.contains(page).unwrap());
        let thin = RamStore::new(
            lying_backend,
            DurabilityRequirement::new(1, false).unwrap(),
            RamStoreLimits::default(),
        )
        .unwrap();

        assert!(
            source
                .transfer_to(&root, &thin, &retention, &mut || Ok(()))
                .is_err()
        );
    }
}

#[test]
fn fallible_change_stream_cannot_publish_a_truncated_successor() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let root = store
        .capture(
            topology(4096 * 2),
            Scope::Exact,
            &mut patterned,
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    let mut first = true;
    let result = store.update_with_reader(
        &root,
        &mut || {
            if first {
                first = false;
                return Ok(Some(RamPageChange {
                    region_id: "main".into(),
                    page_index: 0,
                    bytes: vec![99; 4096],
                }));
            }
            Err(RamStoreError::Invalid(
                "authenticated source stream truncated",
            ))
        },
        &retention,
        &mut || Ok(()),
    );

    assert!(result.is_err());
    assert_eq!(
        store.read_page(&root, "main", 0, &mut || Ok(())).unwrap(),
        vec![0; 4096]
    );
}

#[test]
fn logical_page_limit_is_rejected_before_reading_guest_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(
        directory.path(),
        RamStoreLimits {
            maximum_pages: 3,
            ..RamStoreLimits::default()
        },
    );
    let mut reads = 0_u64;
    let result = store.capture(
        topology(4096 * 4),
        Scope::Exact,
        &mut |_, _, _| {
            reads += 1;
            Ok(())
        },
        &Retention::default(),
        &mut || Ok(()),
    );

    assert!(matches!(
        result,
        Err(RamStoreError::Limit("logical page count"))
    ));
    assert_eq!(reads, 0);
}

#[test]
fn equal_subtrees_prune_root_difference_traversal() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let root = store
        .capture(
            topology(4096 * 256),
            Scope::Exact,
            &mut patterned,
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    let updated = store
        .update(
            &root,
            [RamPageChange {
                region_id: "main".into(),
                page_index: 129,
                bytes: vec![255; 4096],
            }],
            &retention,
            &mut || Ok(()),
        )
        .unwrap();
    let mut boundaries = 0_u64;
    let mut changed = Vec::new();
    store
        .visit_differing_pages(
            &root,
            &updated,
            &mut |_, page| {
                changed.push(page);
                Ok(())
            },
            &mut || {
                boundaries += 1;
                Ok(())
            },
        )
        .unwrap();

    assert_eq!(changed, vec![129]);
    assert!(
        boundaries <= 80,
        "an eight-level difference must not enumerate 256 pages"
    );
}

#[test]
fn dense_ram_capture_rejects_insufficient_packed_index_before_reading_pages() {
    let directory = tempfile::tempdir().unwrap();
    let packed = Arc::new(
        crate::content_store::PackedBlobBackend::open("ram-capacity", directory.path(), 64 * 1024)
            .unwrap(),
    );
    let ram = RamStore::new(
        packed.clone(),
        DurabilityRequirement::new(1, false).unwrap(),
        RamStoreLimits::default(),
    )
    .unwrap();
    let retention = Retention::default();
    let mut reads = 0;
    let result = ram.capture(
        topology(4096 * 32_768),
        Scope::Exact,
        &mut |_, _, _| {
            reads += 1;
            Ok(())
        },
        &retention,
        &mut || Ok(()),
    );

    assert!(matches!(
        result,
        Err(RamStoreError::Store(StoreError::Quota))
    ));
    assert_eq!(reads, 0);
    assert!(retention.objects.lock().unwrap().is_empty());
    ram.admit_ram_publication(&topology(4096 * 8 + 17), Scope::Exact)
        .unwrap();
}
