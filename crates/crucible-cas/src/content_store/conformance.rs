//! Shared semantic conformance routines for persistent store leaves.

use std::collections::BTreeMap;

use super::*;

pub(crate) fn assert_blob_leaf_conformance<B>(backend: &B)
where
    B: ImmutableBlobBackend + BlobStoreAdmin,
{
    let initial = inventory(backend);
    assert_eq!(initial.summary.objects(), 0);
    assert_eq!(initial.summary.logical_bytes(), 0);

    let mut bytes = Vec::with_capacity(96 * 1024);
    for ordinal in 0..96 * 1024_u32 {
        bytes.push((ordinal % 251) as u8);
    }
    let id = ContentId::for_bytes(ObjectKind::CampaignFact, 7, &bytes);
    assert!(!backend.contains(id).expect("initial absence"));
    assert!(matches!(
        backend.read(id, None),
        Err(StoreError::NotFound { id: missing }) if missing == id
    ));

    let wrong = ContentId::for_bytes(ObjectKind::CampaignFact, 7, b"different object");
    assert!(matches!(
        backend.put_if_absent(wrong, &BlobHandle::from_bytes(bytes.clone())),
        Err(StoreError::Corrupt { id: corrupt }) if corrupt == wrong
    ));
    assert!(!backend.contains(wrong).expect("wrong source has no effect"));
    let after_wrong_source = inventory(backend);
    assert!(after_wrong_source.records.is_empty());
    assert_eq!(after_wrong_source.summary.objects(), 0);
    assert_eq!(after_wrong_source.summary.logical_bytes(), 0);

    let receipt = backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.clone()))
        .expect("conforming put");
    assert_eq!(receipt.id, id);
    assert!(receipt.is_durable());
    assert!(backend.contains(id).expect("conforming presence"));
    assert_eq!(
        backend
            .read(id, None)
            .expect("conforming full read")
            .read_all(bytes.len() as u64)
            .expect("authenticate full read"),
        bytes
    );

    let range = ByteRange::new(4093, 8197).expect("bounded range");
    assert_eq!(
        backend
            .read(id, Some(range))
            .expect("conforming range read")
            .read_all(range.length)
            .expect("authenticate range read"),
        bytes[range.offset as usize..(range.offset + range.length) as usize]
    );

    let after_put = inventory(backend);
    assert_eq!(
        after_put.records,
        BTreeMap::from([(id, bytes.len() as u64)])
    );
    assert_eq!(after_put.summary.objects(), 1);
    assert_eq!(after_put.summary.logical_bytes(), bytes.len() as u64);
    assert_ne!(after_put.summary.generation(), initial.summary.generation());

    let replay = backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes.clone()))
        .expect("conforming exact replay");
    assert_eq!(replay, receipt);
    let after_replay = inventory(backend);
    assert_eq!(after_replay.records, after_put.records);
    assert_eq!(after_replay.summary.objects(), after_put.summary.objects());
    assert_eq!(
        after_replay.summary.logical_bytes(),
        after_put.summary.logical_bytes()
    );

    let empty = ContentId::for_bytes(ObjectKind::Trace, 1, b"");
    backend
        .put_if_absent(empty, &BlobHandle::from_bytes([]))
        .expect("conforming empty put");
    assert_eq!(
        backend
            .read(empty, None)
            .expect("conforming empty read")
            .read_all(0)
            .expect("authenticate empty read"),
        Vec::<u8>::new()
    );
    let with_empty = inventory(backend);
    assert_eq!(
        with_empty.records,
        BTreeMap::from([(id, bytes.len() as u64), (empty, 0)])
    );

    let mut fence = backend
        .acquire_inventory_fence()
        .expect("conforming deletion fence");
    assert_eq!(
        fence.delete_candidate(id).expect("delete exact candidate"),
        PlannedDeleteDisposition::Deleted
    );
    assert_eq!(
        fence.delete_candidate(id).expect("repeat exact deletion"),
        PlannedDeleteDisposition::AlreadyAbsent
    );
    drop(fence);
    assert!(!backend.contains(id).expect("candidate absent"));
    assert!(backend.contains(empty).expect("unselected object retained"));

    let after_delete = inventory(backend);
    assert_eq!(after_delete.records, BTreeMap::from([(empty, 0)]));
    assert_ne!(
        after_delete.summary.generation(),
        with_empty.summary.generation()
    );

    backend
        .put_if_absent(id, &BlobHandle::from_bytes(bytes))
        .expect("restore candidate after delete");
    let after_aba = inventory(backend);
    assert_ne!(
        after_aba.summary.generation(),
        after_put.summary.generation()
    );
    assert_eq!(after_aba.summary.objects(), 2);
}

pub(crate) fn assert_ref_leaf_conformance<R>(refs: &R)
where
    R: MutableRefBackend + RefStoreAdmin,
{
    let namespace = RefName::new("conformance").expect("conformance namespace");
    let alpha = RefName::new("conformance/alpha").expect("alpha ref");
    let omega = RefName::new("conformance/omega").expect("omega ref");
    let first = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"first");
    let second = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"second");
    let third = ContentId::for_bytes(ObjectKind::CampaignSnapshot, 1, b"third");

    let initial = ref_inventory(refs);
    assert_eq!(initial.summary.refs(), 0);
    assert_eq!(refs.read_ref(&alpha).expect("initial ref absence"), None);
    assert_eq!(
        refs.compare_exchange(&omega, None, second)
            .expect("create omega"),
        RefCasOutcome::Advanced { next: second }
    );
    assert_eq!(
        refs.compare_exchange(&alpha, None, first)
            .expect("create alpha"),
        RefCasOutcome::Advanced { next: first }
    );
    assert_eq!(refs.read_ref(&alpha).expect("read alpha"), Some(first));

    let after_create = ref_inventory(refs);
    assert_eq!(
        after_create.records,
        BTreeMap::from([(alpha.clone(), first), (omega.clone(), second)])
    );
    assert_eq!(after_create.summary.refs(), 2);
    assert_ne!(
        after_create.summary.generation(),
        initial.summary.generation()
    );

    assert_eq!(
        refs.compare_exchange(&alpha, Some(third), second)
            .expect("stale replacement"),
        RefCasOutcome::Conflict {
            expected: Some(third),
            current: Some(first),
        }
    );
    assert_eq!(ref_inventory(refs).summary, after_create.summary);

    let first_page = refs
        .scan_refs(&namespace, None, 1)
        .expect("first ordered ref page");
    assert_eq!(first_page.entries().len(), 1);
    assert_eq!(first_page.entries()[0].name(), &alpha);
    assert_eq!(first_page.entries()[0].target(), first);
    assert_eq!(first_page.next_after(), Some(&alpha));
    let second_page = refs
        .scan_refs(&namespace, first_page.next_after(), 1)
        .expect("second ordered ref page");
    assert_eq!(second_page.entries().len(), 1);
    assert_eq!(second_page.entries()[0].name(), &omega);
    assert_eq!(second_page.entries()[0].target(), second);
    assert_eq!(second_page.next_after(), None);

    assert_eq!(
        refs.compare_exchange(&alpha, Some(first), third)
            .expect("advance alpha"),
        RefCasOutcome::Advanced { next: third }
    );
    assert_eq!(
        refs.compare_exchange(&alpha, Some(third), first)
            .expect("restore alpha"),
        RefCasOutcome::Advanced { next: first }
    );
    let after_aba = ref_inventory(refs);
    assert_eq!(after_aba.records, after_create.records);
    assert_ne!(
        after_aba.summary.generation(),
        after_create.summary.generation()
    );
}

struct BlobInventory {
    summary: BlobInventorySummary,
    records: BTreeMap<ContentId, u64>,
}

fn inventory(backend: &dyn BlobStoreAdmin) -> BlobInventory {
    let mut fence = backend
        .acquire_inventory_fence()
        .expect("acquire conformance inventory fence");
    let mut records = BTreeMap::new();
    let summary = fence
        .visit_inventory(&mut |record| {
            assert!(
                records
                    .insert(record.id(), record.logical_length())
                    .is_none()
            );
            Ok(())
        })
        .expect("visit conforming inventory");
    BlobInventory { summary, records }
}

struct RefInventory {
    summary: RefInventorySummary,
    records: BTreeMap<RefName, ContentId>,
}

fn ref_inventory(refs: &dyn RefStoreAdmin) -> RefInventory {
    let mut fence = refs
        .acquire_ref_inventory_fence()
        .expect("acquire conformance ref inventory fence");
    let mut records = BTreeMap::new();
    let summary = fence
        .visit_refs(&mut |record| {
            assert!(
                records
                    .insert(record.name().clone(), record.target())
                    .is_none()
            );
            Ok(())
        })
        .expect("visit conforming ref inventory");
    RefInventory { summary, records }
}
