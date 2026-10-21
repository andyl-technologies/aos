//! Large-object copy scheduling, partial failure custody and exact geometry.

use std::{cell::Cell, time::Duration};

use aos_hub_db::direct_upload::*;

use super::copy_parts;
use crate::direct_upload::provider_capacity::{self, Class};
use crate::external_object::MAX_PENDING_DESTINATION_PARTS;

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
    let barrier = &tokio::sync::Barrier::new(MAX_PENDING_DESTINATION_PARTS);
    let active = &Cell::new(0);
    let peak = &Cell::new(0);

    let copied = tokio::time::timeout(
        Duration::from_secs(2),
        copy_parts(&originals, |original| async move {
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

    assert_eq!(peak.get(), MAX_PENDING_DESTINATION_PARTS);
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
    let originals = parts(128);
    let dispatched = &Cell::new(0);
    let acknowledged = &Cell::new(0);

    let result = copy_parts(&originals, |original| async move {
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
    assert_eq!(dispatched.get(), MAX_PENDING_DESTINATION_PARTS);
    assert_eq!(acknowledged.get(), MAX_PENDING_DESTINATION_PARTS - 1);
}

#[tokio::test]
async fn changed_copy_geometry_refuses_completion() {
    let originals = parts(128);
    let dispatched = &Cell::new(0);

    let result = copy_parts(&originals, |original| async move {
        dispatched.set(dispatched.get() + 1);
        let mut copied = original.clone();
        copied.part.offset = WireInteger::new(original.part.offset.get() + 1);
        Ok(copied)
    })
    .await;

    assert!(result.is_err());
    assert_eq!(dispatched.get(), MAX_PENDING_DESTINATION_PARTS);
}

#[tokio::test]
async fn journal_pipeline_keeps_provider_and_reserved_metadata_capacity_independent() {
    provider_capacity::configure(3).unwrap();
    let metadata = provider_capacity::acquire_class(1, Class::Metadata)
        .await
        .unwrap();
    let originals = parts(256);
    let controls = &tokio::sync::Barrier::new(MAX_PENDING_DESTINATION_PARTS);
    let active = &Cell::new(0);
    let peak = &Cell::new(0);

    let copied = tokio::time::timeout(
        Duration::from_secs(2),
        copy_parts(&originals, |original| async move {
            // All compact controls can progress before the provider slots free.
            controls.wait().await;
            let permit = provider_capacity::acquire_class(1, Class::Bulk)
                .await
                .unwrap();
            active.set(active.get() + 1);
            peak.set(peak.get().max(active.get()));
            tokio::task::yield_now().await;
            active.set(active.get() - 1);
            drop(permit);
            Ok(original.clone())
        }),
    )
    .await
    .expect("journal controls must not be serialized by provider capacity")
    .unwrap();

    assert_eq!(copied, originals);
    assert_eq!(peak.get(), 2);
    assert_eq!(active.get(), 0);
    assert_eq!(provider_capacity::observation().peak_active, 3);
    drop(metadata);
    assert_eq!(provider_capacity::observation().active, 0);
}
