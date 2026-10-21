//! Large-object copy scheduling, partial failure custody and exact geometry.

use std::{cell::Cell, time::Duration};

use aos_hub_db::direct_upload::*;

use super::copy_parts;

fn parts(count: u32) -> Vec<DirectManifestPart> {
    (1..=count)
        .map(|number| DirectManifestPart {
            part: DirectPart {
                part_number: number,
                offset: WireInteger::new(u64::from(number - 1) * 8 * 1024 * 1024),
                byte_size: WireInteger::new(8 * 1024 * 1024),
                sha256: "00".repeat(32),
                checksum: DirectPartChecksum {
                    algorithm: DirectChecksumAlgorithm::Sha256,
                    value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                },
            },
            etag: format!("\"source-{number}\""),
        })
        .collect()
}

#[tokio::test]
async fn two_gib_copy_uses_bounded_parallel_waves_and_keeps_manifest_order() {
    let originals = parts(256);
    let barrier = &tokio::sync::Barrier::new(8);
    let active = &Cell::new(0);
    let peak = &Cell::new(0);

    let copied = tokio::time::timeout(
        Duration::from_secs(2),
        copy_parts(&originals, 8, |original| async move {
            active.set(active.get() + 1);
            peak.set(peak.get().max(active.get()));
            barrier.wait().await;
            active.set(active.get() - 1);
            Ok(DirectManifestPart {
                part: original.part.clone(),
                etag: format!("\"destination-{}\"", original.part.part_number),
            })
        }),
    )
    .await
    .expect("independent copies must not wait for a sequential predecessor")
    .unwrap();

    assert_eq!(peak.get(), 8);
    assert_eq!(active.get(), 0);
    assert_eq!(copied.len(), 256);
    for (original, copied) in originals.iter().zip(copied) {
        assert_eq!(copied.part, original.part);
        assert_eq!(
            copied.etag,
            format!("\"destination-{}\"", original.part.part_number)
        );
    }
}

#[tokio::test]
async fn failed_wave_drains_dispatched_neighbors_and_stops_later_parts() {
    let originals = parts(16);
    let dispatched = &Cell::new(0);
    let acknowledged = &Cell::new(0);

    let result = copy_parts(&originals, 8, |original| async move {
        dispatched.set(dispatched.get() + 1);
        tokio::task::yield_now().await;
        if original.part.part_number == 1 {
            anyhow::bail!("copy outcome unknown");
        }

        tokio::task::yield_now().await;
        acknowledged.set(acknowledged.get() + 1);
        Ok(original.clone())
    })
    .await;

    assert!(result.is_err());
    assert_eq!(dispatched.get(), 8);
    assert_eq!(acknowledged.get(), 7);
}

#[tokio::test]
async fn changed_copy_geometry_refuses_completion_and_invalid_capacity_dispatches_nothing() {
    let originals = parts(16);
    let dispatched = &Cell::new(0);

    let result = copy_parts(&originals, 8, |original| async move {
        dispatched.set(dispatched.get() + 1);
        let mut copied = original.clone();
        copied.part.offset = WireInteger::new(original.part.offset.get() + 1);
        Ok(copied)
    })
    .await;

    assert!(result.is_err());
    assert_eq!(dispatched.get(), 8);

    for maximum in [0, 65] {
        let result = copy_parts(&originals, maximum, |original| async move {
            dispatched.set(dispatched.get() + 1);
            Ok(original.clone())
        })
        .await;

        assert!(result.is_err());
        assert_eq!(dispatched.get(), 8);
    }
}
