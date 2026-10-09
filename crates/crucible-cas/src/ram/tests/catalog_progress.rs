//! Validated catalog progress, corrupt children and complete-root visibility.

use super::*;
use crucible_protocol::ram_transfer::RamTransferControl;

#[derive(Clone, Copy)]
enum SourceFault {
    Catalog,
    Page,
    MissingPage,
}

// These incomplete executions may retain requested identities, including the
// offered root. They must never establish the complete-root lease.
struct IncompleteRetention(Retention);

impl RamRetention for IncompleteRetention {
    fn retain_object(&self, id: ContentId) -> Result<(), RamStoreError> {
        self.0.retain_object(id)
    }

    fn retain_root(&self, _: ContentId) -> Result<Arc<dyn RamRootLease>, RamStoreError> {
        panic!("an incomplete authenticated closure cannot acquire a root lease")
    }
}

#[test]
fn corrupt_catalog_never_persists_or_requests_a_child() {
    catalog_fault(SourceFault::Catalog);
}

#[test]
fn corrupt_child_keeps_completed_catalog_without_publishing_root() {
    catalog_fault(SourceFault::Page);
}

#[test]
fn absent_child_keeps_completed_catalog_without_claiming_closure() {
    catalog_fault(SourceFault::MissingPage);
}

fn catalog_fault(fault: SourceFault) {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let (source, source_quota) = admitted_store(source_directory.path(), RamStoreLimits::default());
    let destination = store(destination_directory.path(), RamStoreLimits::default());
    let source_original = fixture_original(&source);
    let destination_original = fixture_original(&destination);
    let root = source
        .capture(
            topology(128),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &source_original,
            &mut || Ok(()),
        )
        .unwrap();
    let catalog = root.regions[0].id;
    let page = first_page_object(&source, &root);
    let damaged = match fault {
        SourceFault::Catalog => catalog,
        SourceFault::Page | SourceFault::MissingPage => page,
    };

    // This external writer uses the same finite source bank before opening
    // its managed connection. It alters actual backing bytes, not an identity.
    let fault_credit = source_quota.0.reserve(1, 8 << 20).unwrap();
    let connection = crate::content_store::fixture_sqlite_heap()
        .unwrap()
        .open_connection(
            source_directory.path().join("objects.sqlite3"),
            rusqlite::OpenFlags::default(),
        )
        .unwrap();
    let changed = damaged
        .with_encoded_text(|id| {
            let id = std::str::from_utf8(id).unwrap();
            match fault {
                SourceFault::MissingPage => {
                    connection.execute("DELETE FROM objects WHERE id = ?1", [id])
                }
                _ => connection.execute(
                    "UPDATE objects SET body = zeroblob(length(body)) WHERE id = ?1",
                    [id],
                ),
            }
        })
        .unwrap();
    assert_eq!(changed, 1);
    drop(connection);
    drop(fault_credit);

    let source_operation = source_original.child().unwrap();
    let destination_operation = destination_original.child().unwrap();
    let offer = archive_offer(&root, 64);
    let mut sender = RamTransferSender::new(
        source.clone(),
        root.clone(),
        [47; 32],
        ContentId::parse(&offer.whole_world_root).unwrap(),
        &offer.destination,
        offer.durable_placements,
        offer.limits,
        &source_operation,
    )
    .unwrap();
    let offered = super::super::response::decode_local(
        &sender.offer().unwrap(),
        &source_operation,
        &destination_operation,
    )
    .unwrap();
    let retention = IncompleteRetention(Retention::default());
    let mut receiver = RamTransferReceiver::new(destination.clone(), &retention, offered).unwrap();
    let mut page_requests = 0;
    let mut completed_acknowledgments = 0;

    let error = receiver
        .receive(
            &mut |message| {
                if matches!(&message.control, RamTransferControl::WantObject { .. }) {
                    page_requests += 1;
                    assert!(
                        destination.backend.contains(catalog).unwrap(),
                        "the complete authenticated catalog is durable before actual child demand"
                    );
                    assert!(!destination.backend.contains(root.object_id()).unwrap());
                }
                if matches!(&message.control, RamTransferControl::ClosureStored { .. }) {
                    completed_acknowledgments += 1;
                }
                sender.respond(message, &mut || Ok(()))
            },
            &destination_operation,
            &mut || Ok(()),
        )
        .unwrap_err();
    let RamStoreError::Store(storage) = &error else {
        panic!("actual backing refusal retains its typed storage cause: {error:?}");
    };
    match fault {
        SourceFault::MissingPage => {
            assert!(
                matches!(storage.original_failure(), StoreError::NotFound { id } if *id == page)
            );
        }
        _ => {
            assert!(
                matches!(storage.original_failure(), StoreError::Corrupt { id } if *id == damaged)
            );
        }
    }
    assert_eq!(completed_acknowledgments, 0);
    assert!(!destination.backend.contains(root.object_id()).unwrap());

    match fault {
        SourceFault::Catalog => {
            assert_eq!(page_requests, 0);
            assert!(!destination.backend.contains(catalog).unwrap());
        }
        SourceFault::Page | SourceFault::MissingPage => {
            assert_eq!(page_requests, 1);
            assert!(destination.backend.contains(catalog).unwrap());
            assert!(!destination.backend.contains(page).unwrap());
        }
    }

    // Closing incomplete progress provides no root or readiness claim. Real
    // fenced GC and journal collectability are exercised in the daemon suite.
    drop((
        receiver,
        sender,
        error,
        source_operation,
        destination_operation,
    ));
    source_original.verify_live().unwrap();
    destination_original.verify_live().unwrap();
}
