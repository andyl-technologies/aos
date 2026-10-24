//! Real files and independent Originals using one physical metadata owner.

use super::*;
use std::cell::Cell;

#[test]
fn distinct_readers_share_rows_without_retaining_descriptors_or_originals() {
    let fixture = Fixture::new();
    let baseline = fixture.quota.0.usage().unwrap();
    let aliases = Arc::strong_count(&fixture.quota);
    let id = fixture.objects[0].0;
    cost::reset();
    let packs = Cell::new(0);
    let saved = {
        let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
        packs.set(view.snapshot.header.packs);
        let mut reader = view
            .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
            .unwrap();
        reader
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                Some(fixture.quota.as_ref()),
                &mut || Ok(()),
            )
            .unwrap()
    };
    let retained = fixture.quota.0.usage().unwrap();
    assert_eq!(
        retained.0,
        baseline.0 + 1,
        "only the real returned object retains a pack FD"
    );
    assert!(retained.1 > baseline.1);
    drop(saved);
    let cache_only = fixture.quota.0.usage().unwrap();
    assert_eq!(cache_only.0, baseline.0);
    assert!(cache_only.1 > baseline.1);
    assert_eq!(
        Arc::strong_count(&fixture.quota),
        aliases,
        "cached rows retain no Original or guard"
    );

    let independent = DecodeBudget::for_store(fixture.quota.clone()).unwrap();
    {
        let view = View::begin(&fixture.backend, &independent, &mut || Ok(())).unwrap();
        let mut reader = view
            .reader(&fixture.backend, &independent, &mut || Ok(()))
            .unwrap();
        for (id, expected) in &fixture.objects {
            let handle = reader
                .lookup(
                    &fixture.backend,
                    &independent,
                    *id,
                    Some(fixture.quota.as_ref()),
                    &mut || {
                        assert!(
                            fixture.quota.1.reclaim(0)?.is_some(),
                            "boundary executes outside the cache mutex"
                        );
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(
                &*handle
                    .read_all_with_boundary(&independent, 24, &mut || Ok(()))
                    .unwrap(),
                &*expected.read_all(24).unwrap()
            );
        }
    }
    assert_eq!(cost::snapshot().authenticated_manifests, packs.get());
    drop(independent);
    let all_packs_retained = fixture.quota.0.usage().unwrap();
    assert_eq!(all_packs_retained.0, baseline.0);
    assert!(all_packs_retained.1 >= cache_only.1);
    let freed = fixture.quota.1.reclaim(u64::MAX).unwrap().unwrap();
    assert_eq!(freed, all_packs_retained.1 - baseline.1);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn evicting_rows_does_not_close_the_independent_active_pack_pin() {
    let fixture = Fixture::new();
    let baseline = fixture.quota.0.usage().unwrap();
    let id = fixture.objects[0].0;
    let handle = {
        let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
        let mut reader = view
            .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
            .unwrap();
        reader
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                Some(fixture.quota.as_ref()),
                &mut || Ok(()),
            )
            .unwrap()
    };
    assert!(fixture.quota.1.reclaim(u64::MAX).unwrap().unwrap() > 0);
    assert_eq!(fixture.quota.0.usage().unwrap().0, baseline.0 + 1);
    assert_eq!(
        handle
            .read_all_with_boundary(&fixture.original, 24, &mut || Ok(()))
            .unwrap()
            .len(),
        24
    );
    drop(handle);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn an_active_copy_still_refuses_changed_pack_bytes_and_the_old_object_at_eof() {
    let fixture = Fixture::new();
    let id = fixture.objects[0].0;
    let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
    let mut reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    let handle = reader
        .lookup(
            &fixture.backend,
            &fixture.original,
            id,
            Some(fixture.quota.as_ref()),
            &mut || Ok(()),
        )
        .unwrap();
    let pack = reader.last_pack.as_ref().unwrap();
    assert!(
        pack.manifest.is_some(),
        "the active pin retains an independently Original-paid copy"
    );
    let found = view
        .snapshot
        .find(&fixture.backend, id, &fixture.original, &mut || Ok(()))
        .unwrap()
        .unwrap();
    let name = index_io::pack_name(pack.id);
    let path = fixture
        .backend
        .packs
        .join(std::str::from_utf8(&name).unwrap());
    let writable = fs::OpenOptions::new().write(true).open(path).unwrap();
    writable.write_all_at(&[0xee], found.offset).unwrap();
    drop(writable);

    assert!(
        matches!(reader.lookup(&fixture.backend, &fixture.original, id,
        Some(fixture.quota.as_ref()), &mut || Ok(())), Err(StoreError::Corrupt { id: found }) if found == id)
    );
    // A fresh Reader has no active copy, so this lookup must borrow the
    // retained service rows and reject their stale stamp after unlocking.
    cost::reset();
    let mut fresh_reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    assert!(
        matches!(fresh_reader.lookup(&fixture.backend, &fixture.original, id,
        Some(fixture.quota.as_ref()), &mut || Ok(())), Err(StoreError::Corrupt { id: found }) if found == id)
    );
    assert_eq!(cost::snapshot().authenticated_manifests, 0);

    assert!(
        matches!(handle.read_all_with_boundary(&fixture.original, 24, &mut || Ok(())),
        Err(StoreError::Corrupt { id: found }) if found == id)
    );
}

#[test]
fn a_foreign_reader_account_cannot_borrow_a_paid_view_even_with_a_warm_cache() {
    let fixture = Fixture::new();
    let foreign = DecodeBudget::for_store(fixture.quota.clone()).unwrap();
    let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
    assert!(matches!(
        view.reader(&fixture.backend, &foreign, &mut || Ok(())),
        Err(StoreError::Incompatible)
    ));
    let mut reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    assert!(matches!(
        reader.lookup(
            &fixture.backend,
            &foreign,
            fixture.objects[0].0,
            Some(fixture.quota.as_ref()),
            &mut || Ok(())
        ),
        Err(StoreError::Incompatible)
    ));
}

#[test]
fn canceled_pending_fill_returns_its_real_credit_and_cannot_strand_the_lane() {
    let fixture = Fixture::new();
    let id = fixture.objects[0].0;
    let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
    let mut reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    drop(
        reader
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                None,
                &mut || Ok(()),
            )
            .unwrap(),
    );
    let pack = reader.last_pack.as_ref().unwrap();
    let entry = view
        .snapshot
        .find(&fixture.backend, id, &fixture.original, &mut || Ok(()))
        .unwrap()
        .unwrap();
    let baseline = fixture.quota.0.usage().unwrap();
    let admitted = Cell::new(false);
    let mut boundary = || {
        if admitted.get() {
            Err(StoreError::Unauthorized)
        } else {
            Ok(())
        }
    };
    let mut request = super::super::super::shared_cache::PackedManifestRead::new(
        pack.file.file().unwrap(),
        &fixture.backend,
        &fixture.original,
        id,
        entry,
        view.snapshot.digest(),
        &mut boundary,
    );
    let error = request
        .retain_in(&fixture.quota.1, |bytes, check| {
            check()?;
            let credit = fixture.quota.0.reserve_with_control(bytes)?;
            admitted.set(true);
            Ok(credit)
        })
        .unwrap_err();
    assert!(matches!(error, StoreError::Unauthorized));
    drop(request);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
    assert_eq!(fixture.quota.1.reclaim(u64::MAX).unwrap(), Some(0));

    let mut boundary = || Ok(());
    let mut retry = super::super::super::shared_cache::PackedManifestRead::new(
        pack.file.file().unwrap(),
        &fixture.backend,
        &fixture.original,
        id,
        entry,
        view.snapshot.digest(),
        &mut boundary,
    );
    fixture.quota.read_packed_manifest(&mut retry).unwrap();
    assert!(retry.finish().unwrap().is_some());
    assert!(fixture.quota.1.reclaim(u64::MAX).unwrap().unwrap() > 0);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn generation_change_reauthenticates_even_an_unchanged_pack_inode() {
    let fixture = Fixture::new();
    let id = fixture.objects[0].0;
    cost::reset();
    {
        let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
        let mut reader = view
            .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
            .unwrap();
        drop(
            reader
                .lookup(
                    &fixture.backend,
                    &fixture.original,
                    id,
                    Some(fixture.quota.as_ref()),
                    &mut || Ok(()),
                )
                .unwrap(),
        );
    }
    assert_eq!(cost::snapshot().authenticated_manifests, 1);
    let bytes = b"new placement generation without replacing the old pack";
    let added = (
        ContentId::for_bytes(ObjectKind::Trace, 1, bytes),
        BlobHandle::from_bytes(bytes.to_vec()),
    );
    let receipt = fixture
        .backend
        .put_many_if_absent_with_boundary(&fixture.original, &[added], &mut || Ok(()))
        .unwrap();
    drop(receipt.accept_with_boundary(&mut || Ok(())).unwrap());
    {
        let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
        let mut reader = view
            .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
            .unwrap();
        drop(
            reader
                .lookup(
                    &fixture.backend,
                    &fixture.original,
                    id,
                    Some(fixture.quota.as_ref()),
                    &mut || Ok(()),
                )
                .unwrap(),
        );
    }
    assert_eq!(cost::snapshot().authenticated_manifests, 2);
}

#[test]
fn shared_rows_do_not_accept_wrong_selected_coordinates() {
    let fixture = Fixture::new();
    let id = fixture.objects[0].0;
    let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
    let mut reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    drop(
        reader
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                Some(fixture.quota.as_ref()),
                &mut || Ok(()),
            )
            .unwrap(),
    );
    let pack = reader.last_pack.as_ref().unwrap();
    let mut entry = view
        .snapshot
        .find(&fixture.backend, id, &fixture.original, &mut || Ok(()))
        .unwrap()
        .unwrap();
    entry.offset += 1;
    let mut boundary = || Ok(());
    let mut wrong = super::super::super::shared_cache::PackedManifestRead::new(
        pack.file.file().unwrap(),
        &fixture.backend,
        &fixture.original,
        id,
        entry,
        view.snapshot.digest(),
        &mut boundary,
    );
    assert!(matches!(wrong.retain_in(&fixture.quota.1,
        |_, _| panic!("a warm key checks coordinates without another admission")),
        Err(StoreError::Corrupt { id: found }) if found == id));
}

#[test]
fn duplicate_fill_rechecks_the_real_stamp_after_its_publication_lock() {
    let fixture = Fixture::new();
    let id = fixture.objects[0].0;
    let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
    let mut reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    drop(
        reader
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                None,
                &mut || Ok(()),
            )
            .unwrap(),
    );
    let pack = reader.last_pack.as_ref().unwrap();
    let entry = view
        .snapshot
        .find(&fixture.backend, id, &fixture.original, &mut || Ok(()))
        .unwrap()
        .unwrap();
    let name = index_io::pack_name(pack.id);
    let path = fixture
        .backend
        .packs
        .join(std::str::from_utf8(&name).unwrap());
    let baseline = fixture.quota.0.usage().unwrap();
    cost::reset();
    let nested = Cell::new(false);
    let mutated = Cell::new(false);
    let mut boundary = || {
        if cost::snapshot().authenticated_manifests == 2 && !mutated.replace(true) {
            let writable = fs::OpenOptions::new().write(true).open(&path).unwrap();
            writable.write_all_at(&[0xee], entry.offset).unwrap();
        }
        Ok(())
    };
    let mut outer = super::super::super::shared_cache::PackedManifestRead::new(
        pack.file.file().unwrap(),
        &fixture.backend,
        &fixture.original,
        id,
        entry,
        view.snapshot.digest(),
        &mut boundary,
    );
    let error = outer
        .retain_in(&fixture.quota.1, |bytes, check| {
            check()?;
            let credit = fixture.quota.0.reserve_with_control(bytes)?;
            if !nested.replace(true) {
                // Complete a genuine competing fill before the outer one publishes.
                let mut boundary = || Ok(());
                let mut inner = super::super::super::shared_cache::PackedManifestRead::new(
                    pack.file.file().unwrap(),
                    &fixture.backend,
                    &fixture.original,
                    id,
                    entry,
                    view.snapshot.digest(),
                    &mut boundary,
                );
                fixture.quota.read_packed_manifest(&mut inner)?;
                assert!(inner.finish()?.is_some());
            }
            Ok(credit)
        })
        .unwrap_err();
    assert!(mutated.get());
    assert!(matches!(error, StoreError::Corrupt { id: found } if found == id));
    drop(outer);
    assert!(fixture.quota.1.reclaim(u64::MAX).unwrap().unwrap() > 0);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn tiny_manifest_selects_original_custody_before_any_shared_reservation() {
    let fixture = Fixture::with_pack_batches(&[1], BYTES, 1 << 20);
    let id = fixture.objects[0].0;
    let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
    let mut reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    drop(
        reader
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                None,
                &mut || Ok(()),
            )
            .unwrap(),
    );
    let pack = reader.last_pack.as_ref().unwrap();
    let entry = view
        .snapshot
        .find(&fixture.backend, id, &fixture.original, &mut || Ok(()))
        .unwrap()
        .unwrap();
    let baseline = fixture.quota.0.usage().unwrap();
    cost::reset();
    let mut boundary = || Ok(());
    let mut request = super::super::super::shared_cache::PackedManifestRead::new(
        pack.file.file().unwrap(),
        &fixture.backend,
        &fixture.original,
        id,
        entry,
        view.snapshot.digest(),
        &mut boundary,
    );
    request
        .retain_in(&fixture.quota.1, |_, _| {
            panic!("geometry selection precedes any shared credit request")
        })
        .unwrap();
    let ordinary = request.finish().unwrap().unwrap();
    assert_eq!(cost::snapshot().authenticated_manifests, 1);
    assert_eq!(fixture.quota.1.reclaim(u64::MAX).unwrap(), Some(0));
    assert!(fixture.quota.0.usage().unwrap().1 > baseline.1);
    ordinary
        .verify(
            pack.file.file().unwrap(),
            &fixture.original,
            id,
            entry,
            &mut || Ok(()),
        )
        .unwrap();
    drop(ordinary);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
    let handle = reader
        .lookup(
            &fixture.backend,
            &fixture.original,
            id,
            None,
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(
        &*handle
            .read_all_with_boundary(&fixture.original, 24, &mut || Ok(()))
            .unwrap(),
        &*fixture.objects[0].1.read_all(24).unwrap(),
    );
}

#[test]
fn a_paid_working_set_survives_without_an_artificial_directory_partition() {
    let fixture = Fixture::with_pack_batches(&[64; 32], 64 << 20, 1 << 20);
    let baseline = fixture.quota.0.usage().unwrap();
    for expected_authentications in [32, 0] {
        cost::reset();
        let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
        assert_eq!(view.snapshot.header.packs, 32);
        let mut reader = view
            .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
            .unwrap();
        for (id, expected) in &fixture.objects {
            let handle = reader
                .lookup(
                    &fixture.backend,
                    &fixture.original,
                    *id,
                    Some(fixture.quota.as_ref()),
                    &mut || Ok(()),
                )
                .unwrap();
            assert_eq!(
                &*handle
                    .read_all_with_boundary(&fixture.original, 24, &mut || Ok(()))
                    .unwrap(),
                &*expected.read_all(24).unwrap(),
            );
        }
        drop(reader);
        drop(view);
        assert_eq!(
            cost::snapshot().authenticated_manifests,
            expected_authentications
        );
        let retained = fixture.quota.0.usage().unwrap();
        assert_eq!(retained.0, baseline.0);
        assert!(retained.1 > baseline.1);
        assert!(retained.1 - baseline.1 <= 1 << 20);
    }
    let retained = fixture.quota.0.usage().unwrap();
    assert_eq!(
        fixture.quota.1.reclaim(u64::MAX).unwrap(),
        Some(retained.1 - baseline.1)
    );
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn a_miss_authenticates_the_actual_manifest_after_resource_admission() {
    for corrupt in [false, true] {
        let fixture = Fixture::new();
        let initial = fixture.quota.0.usage().unwrap();
        let id = fixture.objects[0].0;
        let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
        let mut reader = view
            .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
            .unwrap();
        drop(
            reader
                .lookup(
                    &fixture.backend,
                    &fixture.original,
                    id,
                    None,
                    &mut || Ok(()),
                )
                .unwrap(),
        );
        let pack = reader.last_pack.as_ref().unwrap();
        let entry = view
            .snapshot
            .find(&fixture.backend, id, &fixture.original, &mut || Ok(()))
            .unwrap()
            .unwrap();
        let name = index_io::pack_name(pack.id);
        let path = fixture
            .backend
            .packs
            .join(std::str::from_utf8(&name).unwrap());
        let file = pack.file.file().unwrap();
        let before =
            super::super::manifest::FileStamp::read(file, &fixture.original, &mut || Ok(()))
                .unwrap();
        let offset = (PACK_MAGIC.len() + 32 + 4 + 4) as u64;
        let mut byte = [0];
        file.read_exact_at(&mut byte, offset).unwrap();
        let baseline = fixture.quota.0.usage().unwrap();
        let mut reservations = 0;
        let mut boundary = || Ok(());
        cost::reset();
        let mut request = super::super::super::shared_cache::PackedManifestRead::new(
            file,
            &fixture.backend,
            &fixture.original,
            id,
            entry,
            view.snapshot.digest(),
            &mut boundary,
        );
        let result = request.retain_in(&fixture.quota.1, |bytes, check| {
            check()?;
            let credit = fixture.quota.0.reserve_with_control(bytes)?;
            reservations += 1;
            if reservations == 2 {
                // Rewrite during real admission, before full authentication.
                // Equal bytes change only the stamp; changed bytes must still
                // fail the actual manifest checksum, not a pre-admission stat.
                let writable = fs::OpenOptions::new().write(true).open(&path).unwrap();
                writable
                    .write_all_at(&[byte[0] ^ u8::from(corrupt)], offset)
                    .unwrap();
                // Force a real stamp change without timestamp-granularity races.
                writable.set_modified(std::time::UNIX_EPOCH).unwrap();
            }
            Ok(credit)
        });
        assert_eq!(reservations, 2);
        let after =
            super::super::manifest::FileStamp::read(file, &fixture.original, &mut || Ok(()))
                .unwrap();
        assert!(
            before != after,
            "the actual file stamp changed during admission"
        );
        if corrupt {
            assert!(matches!(result, Err(StoreError::Incompatible)));
            assert_eq!(cost::snapshot().authenticated_manifests, 0);
            drop(request);
            assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
            assert_eq!(fixture.quota.1.reclaim(u64::MAX).unwrap(), Some(0));
        } else {
            result.unwrap();
            assert!(request.finish().unwrap().is_some());
            assert_eq!(cost::snapshot().authenticated_manifests, 1);
        }
        drop(reader);
        drop(view);

        if !corrupt {
            // A fresh reader consumes only the fully authenticated new stamp,
            // and still reads and authenticates the actual selected object EOF.
            let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
            let mut reader = view
                .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
                .unwrap();
            let handle = reader
                .lookup(
                    &fixture.backend,
                    &fixture.original,
                    id,
                    Some(fixture.quota.as_ref()),
                    &mut || Ok(()),
                )
                .unwrap();
            assert_eq!(
                &*handle
                    .read_all_with_boundary(&fixture.original, 24, &mut || Ok(()))
                    .unwrap(),
                &*fixture.objects[0].1.read_all(24).unwrap(),
            );
        }
        let retained = fixture.quota.0.usage().unwrap();
        assert_eq!(retained.0, initial.0);
        assert_eq!(
            fixture.quota.1.reclaim(u64::MAX).unwrap(),
            Some(retained.1 - initial.1)
        );
        assert_eq!(fixture.quota.0.usage().unwrap(), initial);
        fixture.original.verify_live().unwrap();
    }
}

#[test]
fn an_original_paid_copy_survives_physical_service_row_reclamation() {
    let fixture = Fixture::new();
    let initial = fixture.quota.0.usage().unwrap();
    let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
    let mut reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    drop(
        reader
            .lookup(
                &fixture.backend,
                &fixture.original,
                fixture.objects[0].0,
                Some(fixture.quota.as_ref()),
                &mut || Ok(()),
            )
            .unwrap(),
    );
    let copied = reader
        .last_pack
        .as_ref()
        .unwrap()
        .manifest
        .as_ref()
        .unwrap();
    let pointer = copied.entries.as_ptr();
    let retained = fixture.quota.0.usage().unwrap();
    let freed = fixture.quota.1.reclaim(u64::MAX).unwrap().unwrap();
    let active_only = fixture.quota.0.usage().unwrap();
    assert!(freed > 0);
    assert_eq!(active_only.0, retained.0);
    assert_eq!(active_only.1, retained.1 - freed);
    assert!(
        active_only.1 > initial.1,
        "the Original still funds its independent active copy"
    );
    assert_eq!(
        reader
            .last_pack
            .as_ref()
            .unwrap()
            .manifest
            .as_ref()
            .unwrap()
            .entries
            .as_ptr(),
        pointer
    );

    cost::reset();
    let handle = reader
        .lookup(
            &fixture.backend,
            &fixture.original,
            fixture.objects[1].0,
            Some(fixture.quota.as_ref()),
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(
        &*handle
            .read_all_with_boundary(&fixture.original, 24, &mut || Ok(()))
            .unwrap(),
        &*fixture.objects[1].1.read_all(24).unwrap(),
    );
    drop(handle);
    assert_eq!(
        cost::snapshot().authenticated_manifests,
        0,
        "same-pack reads use the paid copy"
    );
    assert_eq!(fixture.quota.1.reclaim(u64::MAX).unwrap(), Some(0));
    assert_eq!(fixture.quota.0.usage().unwrap(), active_only);
    drop(reader);
    drop(view);
    assert_eq!(fixture.quota.0.usage().unwrap(), initial);
}

#[test]
fn copy_admission_observes_the_same_caller_before_any_shared_debit() {
    let fixture = Fixture::new();
    let id = fixture.objects[0].0;
    let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
    let mut reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    drop(
        reader
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                None,
                &mut || Ok(()),
            )
            .unwrap(),
    );
    let pack = reader.last_pack.as_ref().unwrap();
    let entry = view
        .snapshot
        .find(&fixture.backend, id, &fixture.original, &mut || Ok(()))
        .unwrap()
        .unwrap();
    let baseline = fixture.quota.0.usage().unwrap();
    let mut boundary = || {
        if fixture.quota.0.usage()?.1 > baseline.1 {
            Err(StoreError::Unauthorized)
        } else {
            Ok(())
        }
    };
    let mut request = super::super::super::shared_cache::PackedManifestRead::new(
        pack.file.file().unwrap(),
        &fixture.backend,
        &fixture.original,
        id,
        entry,
        view.snapshot.digest(),
        &mut boundary,
    );
    let error = request
        .retain_in(&fixture.quota.1, |_, _| {
            panic!("a refused Original copy cannot request shared credit")
        })
        .unwrap_err();
    assert!(matches!(error, StoreError::Unauthorized));
    drop(request);
    assert_eq!(fixture.quota.1.reclaim(u64::MAX).unwrap(), Some(0));
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}

#[test]
fn a_copy_miss_rechecks_the_paid_count_after_actual_service_grants() {
    let fixture = Fixture::new();
    let id = fixture.objects[0].0;
    let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
    let mut reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    drop(
        reader
            .lookup(
                &fixture.backend,
                &fixture.original,
                id,
                None,
                &mut || Ok(()),
            )
            .unwrap(),
    );
    let pack = reader.last_pack.as_ref().unwrap();
    let entry = view
        .snapshot
        .find(&fixture.backend, id, &fixture.original, &mut || Ok(()))
        .unwrap()
        .unwrap();
    let name = index_io::pack_name(pack.id);
    let path = fixture
        .backend
        .packs
        .join(std::str::from_utf8(&name).unwrap());
    let baseline = fixture.quota.0.usage().unwrap();
    cost::reset();
    let mut reservations = 0;
    let mut boundary = || Ok(());
    let mut request = super::super::super::shared_cache::PackedManifestRead::new(
        pack.file.file().unwrap(),
        &fixture.backend,
        &fixture.original,
        id,
        entry,
        view.snapshot.digest(),
        &mut boundary,
    );
    let error = request
        .retain_in(&fixture.quota.1, |bytes, check| {
            check()?;
            let credit = fixture.quota.0.reserve_with_control(bytes)?;
            reservations += 1;
            if reservations == 2 {
                let writable = fs::OpenOptions::new().write(true).open(&path).unwrap();
                writable
                    .write_all_at(&63_u32.to_be_bytes(), (PACK_MAGIC.len() + 32) as u64)
                    .unwrap();
            }
            Ok(credit)
        })
        .unwrap_err();
    assert_eq!(reservations, 2);
    assert!(matches!(error, StoreError::Corrupt { id: found } if found == id));
    assert_eq!(cost::snapshot().authenticated_manifests, 0);
    drop(request);
    assert_eq!(fixture.quota.1.reclaim(u64::MAX).unwrap(), Some(0));
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
}
