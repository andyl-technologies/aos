//! Real tiny, mixed and dense pack work under one finite metadata owner.
//!
//! Ordinary and shared reads use identical files and full object EOF checks.
//! Cold and retained passes expose directory churn instead of assuming every
//! namespace fits the cache. These are component costs, not kernel accounting.

use super::*;

#[derive(Clone, Copy, Debug)]
enum ReadOrder {
    Sequential,
    Strided,
}

#[test]
fn shared_metadata_costs_preserve_dense_one_row_and_mixed_object_reads() {
    for order in [ReadOrder::Sequential, ReadOrder::Strided] {
        let one_row = vec![1; 1024];
        let mut mixed = vec![1; 128];
        mixed.extend([128; 4]);
        for (name, batches) in [
            ("dense", vec![128; 8]),
            ("one_row", one_row),
            ("two_rows", vec![2; 512]),
            ("four_rows", vec![4; 256]),
            ("eight_rows", vec![8; 128]),
            ("sixteen_rows", vec![16; 64]),
            ("mixed", mixed),
        ] {
            let fixture = Fixture::with_pack_batches(&batches, 64 << 20, 64 << 20);
            let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
            assert_eq!(view.snapshot.header.packs, batches.len() as u64);
            drop(view);
            // Warm actual file pages before measuring either implementation.
            // No shared metadata survives this ordinary full-EOF pass.
            read_all(&fixture, false, order);
            for repetition in 0..4 {
                compare_read_costs(&fixture, name, batches.len(), order, repetition);
            }
        }
    }
}

fn compare_read_costs(
    fixture: &Fixture,
    name: &str,
    packs: usize,
    order: ReadOrder,
    repetition: usize,
) {
    assert_eq!(fixture.quota.1.reclaim(u64::MAX).unwrap(), Some(0));
    let baseline = fixture.quota.0.usage().unwrap();
    // Alternate the ordinary pass around the cold/warm pair so neither path
    // always benefits from filesystem order or elapsed background activity.
    let ordinary_first = repetition % 2 == 0;
    let first = ordinary_first.then(|| read_all(fixture, false, order));
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
    let (cold, cold_ns) = read_all(fixture, true, order);
    let retained = fixture.quota.0.usage().unwrap();
    assert_eq!(retained.0, baseline.0);
    let (warm, warm_ns) = read_all(fixture, true, order);
    let after_warm = fixture.quota.0.usage().unwrap();
    assert_eq!(after_warm.0, baseline.0);
    assert!(after_warm.1 - baseline.1 <= 64 << 20);
    let freed = fixture.quota.1.reclaim(u64::MAX).unwrap().unwrap();
    assert_eq!(freed, after_warm.1 - baseline.1);
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);
    let (ordinary, ordinary_ns) = first.unwrap_or_else(|| read_all(fixture, false, order));
    assert_eq!(fixture.quota.0.usage().unwrap(), baseline);

    if name == "one_row" {
        assert_eq!(retained, baseline, "tiny rows never enter shared admission");
        assert_eq!(after_warm, baseline);
    }
    if retained.1 == baseline.1 {
        assert_eq!(after_warm, baseline);
        assert_eq!(
            cold.authenticated_manifests,
            ordinary.authenticated_manifests
        );
        assert_eq!(
            warm.authenticated_manifests,
            ordinary.authenticated_manifests
        );
    } else {
        assert!(after_warm.1 > baseline.1);
        assert!(warm.authenticated_manifests < ordinary.authenticated_manifests);
    }
    assert_eq!(ordinary.lookups, fixture.objects.len() as u64);
    for measured in [cold, warm] {
        assert_eq!(measured.lookups, ordinary.lookups);
        assert_eq!(measured.pack_switches, ordinary.pack_switches);
        assert!(measured.authenticated_manifests <= ordinary.authenticated_manifests);
    }
    // crucible-lint: allow direct-diagnostic -- actual full EOF read work and retained accounting only.
    eprintln!(
        "packed_shared_metadata_costs repetition={repetition} ordinary_first={ordinary_first} order={order:?} shape={name} objects={} packs={packs} retained_bytes={} ordinary_ns={ordinary_ns} cold_ns={cold_ns} warm_ns={warm_ns} ordinary={ordinary:?} cold={cold:?} warm={warm:?}",
        fixture.objects.len(),
        after_warm.1 - baseline.1,
    );
}

// crucible-lint: allow clippy-disallowed-method -- reports component read duration without supplying operational time.
#[allow(
    clippy::disallowed_methods,
    reason = "Reports actual fixture read duration without supplying guest or operational time."
)]
fn read_all(fixture: &Fixture, shared: bool, order: ReadOrder) -> (cost::ReadViewCost, u128) {
    cost::reset();
    let started = std::time::Instant::now();
    let view = View::begin(&fixture.backend, &fixture.original, &mut || Ok(())).unwrap();
    let mut reader = view
        .reader(&fixture.backend, &fixture.original, &mut || Ok(()))
        .unwrap();
    let physical = shared.then_some(fixture.quota.as_ref() as &dyn StorePhysicalQuotaGuard);
    let mut read_object = |index: usize| {
        let (id, expected) = &fixture.objects[index];
        let handle = reader
            .lookup(
                &fixture.backend,
                &fixture.original,
                *id,
                physical,
                &mut || Ok(()),
            )
            .unwrap();
        let bytes = handle
            .read_all_with_boundary(&fixture.original, 24, &mut || Ok(()))
            .unwrap();
        assert_eq!(&*bytes, &*expected.read_all(24).unwrap());
    };
    match order {
        ReadOrder::Sequential => {
            for index in 0..fixture.objects.len() {
                read_object(index);
            }
        }
        ReadOrder::Strided => {
            // Cross dense packs while visiting every key exactly once.
            for offset in 0..32 {
                for index in (offset..fixture.objects.len()).step_by(32) {
                    read_object(index);
                }
            }
        }
    }
    drop(reader);
    drop(view);
    (cost::snapshot(), started.elapsed().as_nanos())
}
