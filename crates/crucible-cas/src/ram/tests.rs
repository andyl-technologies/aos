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

mod bounded_read;
mod bounded_tree_parser;
mod catalog_progress;
mod checked_graph_adapters;
mod comparison_identity;
mod metadata_lifecycle;
mod packed_volume;
mod receiver_batch;
mod transfer_object;
mod wire_state;

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

struct FixtureRamQuota(crate::content_store::test_resources::FixtureResourceBudget);

impl crate::content_store::StorePhysicalQuotaGuard for FixtureRamQuota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(256 << 20)
    }

    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.0.reserve(descriptors, resident_bytes)
    }
}

struct FixtureCatalogSupervisor(Arc<FixtureRamQuota>);

struct FixtureCatalogOperation;

impl crate::content_store::SqliteCatalogOperation for FixtureCatalogOperation {
    fn check(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn complete(self: Box<Self>) -> Result<(), StoreError> {
        Ok(())
    }
}

impl crate::content_store::SqliteCatalogSupervisor for FixtureCatalogSupervisor {
    fn reserve_resident_bytes(
        &self,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.0.0.reserve(0, bytes)
    }

    fn begin(
        &self,
        _kind: crate::content_store::SqliteCatalogOperationKind,
    ) -> Result<Box<dyn crate::content_store::SqliteCatalogOperation>, StoreError> {
        Ok(Box::new(FixtureCatalogOperation))
    }
}

fn admitted_store(
    path: &std::path::Path,
    limits: RamStoreLimits,
) -> (RamStore, Arc<FixtureRamQuota>) {
    let quota = Arc::new(FixtureRamQuota(
        crate::content_store::test_resources::FixtureResourceBudget::new(128, 256 << 20),
    ));
    let backend = SqliteBlobBackend::open_with_physical_quota(
        "ram-test",
        path,
        quota.clone(),
        8 * 1024 * 1024,
        Arc::new(FixtureCatalogSupervisor(quota.clone())),
        &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
    )
    .unwrap();
    RamStore::new(
        backend,
        DurabilityRequirement::new(1, false).unwrap(),
        limits,
    )
    .map(|store| (store, quota))
    .unwrap()
}

fn store(path: &std::path::Path, limits: RamStoreLimits) -> RamStore {
    admitted_store(path, limits).0
}

fn fixture_original(store: &RamStore) -> crate::owned_decode::DecodeBudget {
    crate::owned_decode::DecodeBudget::for_store(store.backend.metadata_resources().unwrap())
        .unwrap()
}

fn fixture_boundary(
    original: &crate::owned_decode::DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    original
        .verify_live()
        .map_err(|error| crate::content_store::batch::admission_under(original, error))?;
    boundary()?;
    original
        .verify_live()
        .map_err(|error| crate::content_store::batch::admission_under(original, error))
}

#[test]
fn admitted_root_credit_survives_facades_and_last_shared_metadata_clone() {
    let directory = tempfile::tempdir().unwrap();
    let (store, quota) = admitted_store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let captured = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &retention,
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    let root = store
        .open_with_metadata_resources(
            retention.retain_root(captured.object_id()).unwrap(),
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    let cloned = root.clone();
    assert!(Arc::ptr_eq(&root.record, &cloned.record));
    drop(captured);
    drop(root);
    drop(store);

    assert!(quota.0.usage().unwrap().1 >= maximum_ram_root_decoding_bytes().unwrap());
    assert_eq!(cloned.record().scope(), Scope::Exact);
    drop(cloned);
    assert_eq!(quota.0.usage().unwrap(), (0, 0));
}

#[test]
fn admitted_root_refuses_missing_authority_and_discovery_retains_its_credit() {
    let directory = tempfile::tempdir().unwrap();
    let (store, quota) = admitted_store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let captured = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &retention,
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    let bare_directory = tempfile::tempdir().unwrap();
    let bare = RamStore::new(
        Arc::new(
            SqliteBlobBackend::open(
                "bare",
                bare_directory.path(),
                &crate::content_store::fixture_sqlite_heap()
                    .expect("authored SQLite fixture process"),
            )
            .unwrap(),
        ),
        DurabilityRequirement::new(1, false).unwrap(),
        RamStoreLimits::default(),
    )
    .unwrap();
    assert!(matches!(
        bare.open_with_metadata_resources(
            retention.retain_root(captured.object_id()).unwrap(),
            &fixture_original(&store),
            &mut || Ok(()),
        ),
        Err(RamStoreError::Store(StoreError::Unsupported {
            capability: "decoded-metadata-resources"
        }))
    ));
    let baseline = quota.0.usage().unwrap();
    let discovery = store
        .inspect_root_with_metadata_resources(
            captured.object_id(),
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    assert!(quota.0.usage().unwrap().1 >= baseline.1 + maximum_ram_root_decoding_bytes().unwrap());
    assert_eq!(discovery.record(), captured.record());
    drop(discovery);
    assert_eq!(quota.0.usage().unwrap(), baseline);
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
fn encoded_backing_bound_covers_four_unique_graphs_with_partial_regions() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let topology = Topology::new(
        vec![
            RegionDescriptor::new("main", RegionClass::MutableMain, 5 * 4096 + 19).unwrap(),
            RegionDescriptor::new("device", RegionClass::MutableDevice, 123).unwrap(),
        ],
        Limits::default(),
    )
    .unwrap();
    let bound = maximum_encoded_ram_graph_bytes(&topology, 4).unwrap();
    let mut roots = Vec::new();
    for version in 0..4_u8 {
        roots.push(
            store
                .capture(
                    topology.clone(),
                    Scope::Exact,
                    &mut |region, index, bytes| {
                        bytes.fill(version * 32 + index as u8 + u8::from(region.id() == "device"));
                        Ok(())
                    },
                    &retention,
                    &fixture_original(&store),
                    &mut || Ok(()),
                )
                .unwrap(),
        );
    }
    let persisted = retention
        .objects
        .lock()
        .unwrap()
        .iter()
        .map(|id| store.backend.read(*id, None).unwrap().logical_length())
        .sum::<u64>();

    assert!(persisted <= bound);
    assert!(bound > 4 * topology.total_logical_bytes());
    assert_eq!(roots.len(), 4);
    assert!(maximum_encoded_ram_graph_bytes(&topology, 0).is_err());
    assert!(maximum_encoded_ram_graph_bytes(&topology, u64::MAX).is_err());
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
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    let page = store
        .read_page_with_proof(&root, "main", 7, &fixture_original(&store), &mut || Ok(()))
        .unwrap();
    let bytes = page.bytes();
    let proof = page.proof();

    assert_eq!(bytes, vec![7; 19]);
    proof
        .verify(bytes, root.record(), root.logical_digest())
        .unwrap();
    assert!(
        proof
            .verify(&[8; 19], root.record(), root.logical_digest())
            .is_err()
    );
    assert!(
        store
            .read_page(&root, "main", 8, &fixture_original(&store), &mut || Ok(()))
            .is_err()
    );

    let updated = store
        .update(
            &root,
            [RamPageChange {
                region_id: "main".into(),
                page_index: 3,
                bytes: vec![99; 4096],
            }],
            &retention,
            &fixture_original(&store),
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
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();

    assert_eq!(changed, 1);
    assert_eq!(differences, vec![("main".to_owned(), 3)]);
    assert_eq!(
        store
            .read_page(&root, "main", 3, &fixture_original(&store), &mut || Ok(()))
            .unwrap(),
        vec![3; 4096]
    );
    assert_eq!(
        store
            .read_page(&updated, "main", 3, &fixture_original(&store), &mut || Ok(
                ()
            ))
            .unwrap(),
        vec![99; 4096]
    );
    assert_eq!(
        store
            .verify(&updated, &fixture_original(&store), &mut || Ok(()))
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
            &fixture_original(&source),
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
            &fixture_original(&source),
            &fixture_original(&destination),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(
        destination
            .verify(
                first.root(),
                &fixture_original(&destination),
                &mut || Ok(())
            )
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
            &fixture_original(&source),
            &fixture_original(&destination),
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
            &fixture_original(&source),
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
            &fixture_original(&source),
            &fixture_original(&destination),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(next.report().copied_objects, 8);
    assert!(next.report().copied_bytes < first.report().copied_bytes);
    assert_eq!(
        destination
            .read_page(
                next.root(),
                "main",
                16,
                &fixture_original(&destination),
                &mut || Ok(())
            )
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
            &fixture_original(&source),
            &mut || Ok(()),
        )
        .unwrap();
    let mut sender =
        archive_sender(source, root.clone(), [3; 32], archive_offer(&root, 13)).unwrap();
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
    } = &first.message().control
    else {
        panic!("expected first chunk")
    };
    assert_eq!(*offset, 0);
    assert_eq!(bytes.len(), 13);
    assert!(!*last);
    let credit = RamTransferMessage {
        operation: [3; 32],
        control: RamTransferControl::Credit {
            object: root.object_id().encode(),
            offset: 13,
            bytes: 13,
        },
    };
    assert_eq!(
        sender
            .respond(credit.clone(), &mut || Ok(()))
            .unwrap()
            .message(),
        sender.respond(credit, &mut || Ok(())).unwrap().message()
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
    assert_eq!(
        acknowledgment.message().control,
        RamTransferControl::Canceled
    );
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
            &fixture_original(&source),
            &mut || Ok(()),
        )
        .unwrap();
    for foreign in [false, true] {
        let destination_directory = tempfile::tempdir().unwrap();
        let destination = store(destination_directory.path(), RamStoreLimits::default());
        let mut sender = archive_sender(
            source.clone(),
            root.clone(),
            [5; 32],
            archive_offer(&root, 64 * 1024),
        )
        .unwrap();
        let mut receiver =
            RamTransferReceiver::new(destination.clone(), &retention, sender.offer().unwrap())
                .unwrap();
        let mut exchange = |message: RamTransferMessage| {
            let mut response = sender.respond(message, &mut || Ok(()))?;
            response.alter_for_test(|message| {
                if let RamTransferControl::ObjectChunk { bytes, .. } = &mut message.control {
                    if foreign {
                        message.operation = [6; 32];
                    } else {
                        bytes[0] ^= 1;
                    }
                }
            });
            Ok(response)
        };
        assert!(
            receiver
                .receive(
                    &mut exchange,
                    &receiver.original_for_test().unwrap(),
                    &mut || Ok(())
                )
                .is_err()
        );
        assert!(!destination.backend.contains(root.object_id()).unwrap());
    }
}

#[test]
fn framed_transfer_operates_between_independent_socket_instances() {
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
            &fixture_original(&source),
            &mut || Ok(()),
        )
        .unwrap();
    let mut sender =
        archive_sender(source, root.clone(), [8; 32], archive_offer(&root, 17)).unwrap();
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
    let offer = RamTransferResponse::read_offer(
        &mut destination_socket,
        &fixture_original(&destination),
        &mut || Ok(()),
    )
    .unwrap();
    let mut receiver =
        RamTransferReceiver::new(destination.clone(), &destination_retention, offer).unwrap();
    let RamTransferStep::ClosureStored(stored) = receiver
        .receive_transport(
            &mut destination_socket,
            &receiver.original_for_test().unwrap(),
            &mut || Ok(()),
        )
        .unwrap()
    else {
        panic!("expected closure possession")
    };

    sending.join().unwrap().unwrap();
    assert_eq!(stored.root().logical_digest(), root.logical_digest());
    assert_eq!(
        destination
            .read_page(
                stored.root(),
                "main",
                3,
                &fixture_original(&destination),
                &mut || Ok(())
            )
            .unwrap(),
        vec![3; 19]
    );
    assert_eq!(
        destination
            .verify(stored.root(), &fixture_original(&destination), &mut || Ok(
                ()
            ))
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
            &fixture_original(&source),
            &mut || Ok(()),
        )
        .unwrap();
    let refs = MemoryRefBackend::new();
    let fence = refs.acquire_ref_inventory_fence().unwrap();
    let mut visited = BTreeSet::new();
    source
        .visit_inventory_graph(
            root.object_id(),
            fence.as_ref(),
            &fixture_original(&source),
            &mut || Ok(()),
            &mut |id| {
                visited.insert(id);
                Ok(())
            },
        )
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
            .visit_inventory_graph(
                root.object_id(),
                fence.as_ref(),
                &fixture_original(&corrupt),
                &mut || Ok(()),
                &mut |_| Ok(())
            )
            .is_err()
    );
    assert!(
        source
            .visit_inventory_graph(
                root.object_id(),
                fence.as_ref(),
                &fixture_original(&source),
                &mut || Ok(()),
                &mut |_| Err(RamStoreError::Canceled)
            )
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
            &fixture_original(&source),
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
        &fixture_original(&source),
        &fixture_original(&destination),
        &mut || {
            boundaries += 1;
            if boundaries > 120 {
                Err(RamStoreError::Canceled)
            } else {
                Ok(())
            }
        },
    );
    // The original 120-check budget now expires during authenticated staging,
    // before the first batch becomes durable. Preserve the actual first cause.
    let Err(RamStoreError::Store(StoreError::RamReadBoundary {
        source: first_cause,
    })) = &result
    else {
        panic!("the bounded staging refusal retains its original cause: {result:?}");
    };
    assert!(matches!(
        first_cause.first_boundary(),
        Some(RamStoreError::Canceled)
    ));
    assert!(matches!(
        first_cause.storage_failure(),
        RamStoreError::Store(StoreError::RamBoundary { .. })
    ));
    assert!(!destination.backend.contains(root.regions[0].id).unwrap());
    assert_eq!(boundaries, 121);
    assert!(!destination.backend.contains(root.object_id()).unwrap());
    let retry = source
        .transfer_archive_to(
            &root,
            world,
            &destination,
            "destination",
            [7; 32],
            &retention,
            &fixture_original(&source),
            &fixture_original(&destination),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(retry.report().authenticated_existing_objects, 0);
    assert_eq!(
        destination
            .verify(
                retry.root(),
                &fixture_original(&destination),
                &mut || Ok(())
            )
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
            &fixture_original(&source),
            &mut || Ok(()),
        )
        .unwrap();
    let first = source
        .transfer_to(
            &root,
            &destination,
            &destination_retention,
            &fixture_original(&source),
            &fixture_original(&destination),
            &mut || Ok(()),
        )
        .unwrap();

    assert!(first.report().copied_objects > 0);
    assert_eq!(
        destination
            .verify(
                first.root(),
                &fixture_original(&destination),
                &mut || Ok(())
            )
            .unwrap()
            .pages,
        16
    );
    let repeated = source
        .transfer_to(
            &root,
            &destination,
            &destination_retention,
            &fixture_original(&source),
            &fixture_original(&destination),
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
            &source_retention,
            &fixture_original(&source),
            &mut || Ok(()),
        )
        .unwrap();
    let next = source
        .transfer_to(
            &updated,
            &destination,
            &destination_retention,
            &fixture_original(&source),
            &fixture_original(&destination),
            &mut || Ok(()),
        )
        .unwrap();

    assert_eq!(next.report().copied_objects, 7); // Page, leaf, four ancestors, root.
    assert!(next.report().copied_bytes < first.report().copied_bytes);
    assert_eq!(
        destination
            .read_page(
                next.root(),
                "main",
                2,
                &fixture_original(&destination),
                &mut || Ok(())
            )
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
        &fixture_original(&store),
        &mut || Ok(()),
    );

    assert!(matches!(result, Err(RamStoreError::Limit("object visits"))));
    let canceled = store.capture(
        topology(4096),
        Scope::Exact,
        &mut patterned,
        &retention,
        &fixture_original(&store),
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
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    let execution = store
        .capture(
            topology,
            Scope::Execution,
            &mut patterned,
            &retention,
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();

    assert_eq!(
        store
            .read_page(&exact, "rom", 0, &fixture_original(&store), &mut || Ok(()))
            .unwrap()
            .len(),
        19
    );
    assert!(
        store
            .read_page(&execution, "rom", 0, &fixture_original(&store), &mut || Ok(
                ()
            ))
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

    fn metadata_resources(
        &self,
    ) -> Result<Arc<dyn crate::content_store::StorePhysicalQuotaGuard>, StoreError> {
        self.backend.metadata_resources()
    }

    fn read_with_boundary(
        &self,
        original: &crate::owned_decode::DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        fixture_boundary(original, boundary)?;
        if id == self.blocked {
            if self.corrupt {
                return Ok(BlobHandle::from_bytes(b"corrupt object".to_vec()));
            }
            return Err(StoreError::NotFound { id });
        }
        self.backend
            .read_with_boundary(original, id, range, boundary)
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
    let work_original_921 = fixture_original(store);
    let mut work = Work::new(store.limits, &work_original_921, &mut boundary).unwrap();
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
            &fixture_original(&source),
            &mut || Ok(()),
        )
        .unwrap();
    source
        .transfer_to(
            &root,
            &destination,
            &retention,
            &fixture_original(&source),
            &fixture_original(&destination),
            &mut || Ok(()),
        )
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
                .transfer_to(
                    &root,
                    &thin,
                    &retention,
                    &fixture_original(&source),
                    &fixture_original(&thin),
                    &mut || Ok(())
                )
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
            &fixture_original(&store),
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
        &fixture_original(&store),
        &mut || Ok(()),
    );

    assert!(result.is_err());
    assert_eq!(
        store
            .read_page(&root, "main", 0, &fixture_original(&store), &mut || Ok(()))
            .unwrap(),
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
        &fixture_original(&store),
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
            &fixture_original(&store),
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
            &fixture_original(&store),
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
            &fixture_original(&store),
            &mut || {
                boundaries += 1;
                Ok(())
            },
        )
        .unwrap();

    assert_eq!(changed, vec![129]);
    assert!(
        boundaries <= 80,
        "an eight-level difference must not enumerate 256 pages: boundaries={boundaries}"
    );
}

#[test]
fn dense_ram_capture_declines_exhausted_original_before_reading_pages() {
    packed_volume::assert_exhausted_original_precedes_pages();
}

/// Declares an oversized object without permitting any stream allocation/read.
struct OversizedSource {
    length: u64,
    opens: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::content_store::BlobSource for OversizedSource {
    fn logical_length(&self) -> u64 {
        self.length
    }

    fn open(&self) -> Result<Box<dyn std::io::Read + Send>, StoreError> {
        self.opens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(StoreError::Unsupported {
            capability: "stream must not open",
        })
    }
}

struct OversizedBackend {
    backend: Arc<dyn ImmutableBlobBackend>,
    source: BlobHandle,
}

impl ImmutableBlobBackend for OversizedBackend {
    fn name(&self) -> &str {
        self.backend.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.backend.capabilities()
    }

    fn contains(&self, _: ContentId) -> Result<bool, StoreError> {
        Ok(true)
    }

    fn read(&self, _: ContentId, _: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        Ok(self.source.clone())
    }

    fn read_with_boundary(
        &self,
        original: &crate::owned_decode::DecodeBudget,
        _: ContentId,
        _: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        fixture_boundary(original, boundary)?;
        Ok(self.source.clone())
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.backend.put_if_absent(id, source)
    }
}

#[test]
fn oversized_ram_objects_are_rejected_before_opening_the_stream() {
    let directory = tempfile::tempdir().unwrap();
    let quota = Arc::new(FixtureRamQuota(
        crate::content_store::test_resources::FixtureResourceBudget::new(128, 256 << 20),
    ));
    let decoding = crate::owned_decode::DecodeBudget::for_store(quota).unwrap();
    let _scope = decoding.enter();
    let backend: Arc<dyn ImmutableBlobBackend> = Arc::new(
        SqliteBlobBackend::open(
            "oversized-test",
            directory.path(),
            &crate::content_store::fixture_sqlite_heap().expect("authored SQLite fixture process"),
        )
        .unwrap(),
    );
    for (kind, maximum_bytes) in [
        (ObjectKind::RamTree, 4096),
        (ObjectKind::RamExtent, 8192),
        (ObjectKind::ExactManifest, MAX_RAM_OBJECT_BYTES),
    ] {
        let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let source = BlobHandle::new(OversizedSource {
            length: maximum_bytes + 1,
            opens: opens.clone(),
        });
        let store = RamStore::new(
            Arc::new(OversizedBackend {
                backend: backend.clone(),
                source,
            }),
            DurabilityRequirement::new(1, false).unwrap(),
            RamStoreLimits::default(),
        )
        .unwrap();
        let id = ContentId::for_bytes(kind, 1, b"untrusted oversized object");
        let mut boundary = || Ok(());
        let mut work = Work::new(store.limits, &decoding, &mut boundary).unwrap();

        assert!(matches!(
            store.read_envelope(id, &mut work),
            Err(RamStoreError::Limit("single canonical object"))
        ));
        assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(work.io_bytes, 0);
    }
}

#[test]
fn leased_root_clones_share_the_origin_metadata_allocation() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let root = store
        .capture(
            topology(8193),
            Scope::Exact,
            &mut patterned,
            &retention,
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    let cloned = root.clone();
    assert!(Arc::ptr_eq(&root.record, &cloned.record));
    assert!(Arc::ptr_eq(&root.regions, &cloned.regions));
    assert!(Arc::ptr_eq(&root.lease, &cloned.lease));
    assert!(Arc::ptr_eq(
        &root.metadata_custody,
        &cloned.metadata_custody
    ));
    let id = root.object_id();
    drop(root);
    assert_eq!(cloned.object_id(), id);
    store
        .verify(&cloned, &fixture_original(&store), &mut || Ok(()))
        .unwrap();
}

#[test]
fn shared_transfer_metadata_retains_its_origin_until_destination_reader_closes() {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source_store = store(source_directory.path(), RamStoreLimits::default());
    let destination_store = store(destination_directory.path(), RamStoreLimits::default());
    let source_retention = Retention::default();
    let destination_retention = Retention::default();
    let source = source_store
        .capture(
            topology(8193),
            Scope::Exact,
            &mut patterned,
            &source_retention,
            &fixture_original(&source_store),
            &mut || Ok(()),
        )
        .unwrap();
    let origin = Arc::downgrade(&source.metadata_custody);
    let transferred = source_store
        .transfer_to(
            &source,
            &destination_store,
            &destination_retention,
            &fixture_original(&source_store),
            &fixture_original(&destination_store),
            &mut || Ok(()),
        )
        .unwrap();
    assert!(Arc::ptr_eq(&source.record, &transferred.root().record));
    assert!(Arc::ptr_eq(&source.regions, &transferred.root().regions));
    assert!(Arc::ptr_eq(
        &source.metadata_custody,
        &transferred.root().metadata_custody
    ));
    assert!(!Arc::ptr_eq(&source.lease, &transferred.root().lease));
    drop(source);
    assert!(
        origin.upgrade().is_some(),
        "destination reader still borrows the origin allocation"
    );
    destination_store
        .verify(
            transferred.root(),
            &fixture_original(&destination_store),
            &mut || Ok(()),
        )
        .unwrap();
    drop(transferred);
    assert!(
        origin.upgrade().is_none(),
        "final physical metadata borrower releases the origin"
    );
}

fn archive_sender(
    source: RamStore,
    root: LeasedRamRoot,
    operation: [u8; 32],
    offer: crucible_protocol::ram_transfer::RamTransferOffer,
) -> Result<RamTransferSender, RamStoreError> {
    let original = fixture_original(&source);
    RamTransferSender::new(
        source,
        root,
        operation,
        ContentId::parse(&offer.whole_world_root)?,
        &offer.destination,
        offer.durable_placements,
        offer.limits,
        &original,
    )
}
