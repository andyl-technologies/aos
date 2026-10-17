//! Exercises the production ordered scheduler with real asynchronous read scopes.

use super::*;
use aos_hub_core::hybrid_ingress::live::{HybridLiveDeliveryClass, HybridLiveDeliveryTarget};
use std::{cell::Cell, rc::Rc};

fn targets(count: usize) -> Vec<HybridLiveDeliveryTarget> {
    (0..count)
        .map(|index| HybridLiveDeliveryTarget {
            registry_id: 1,
            registry_resource_version: 1,
            mirror_resource_version: 1,
            placement_id: 1,
            placement_resource_version: 1,
            write_spec_version: 1,
            placement_prefix: "registry".into(),
            binding_id: 1,
            binding_resource_version: 1,
            protected_profile_digest: "a".repeat(64),
            upstream_base: "https://example.org/registry/".into(),
            path: format!("channels/stable/{index:02x}"),
            class: HybridLiveDeliveryClass::Metadata,
            maximum_bytes: 128 * 1024,
        })
        .collect()
}

#[tokio::test]
async fn actual_scheduler_bounds_two_producers_and_preserves_mixed_order() {
    let active = Rc::new(Cell::new(0));
    let peak = Rc::new(Cell::new(0));
    let originals = targets(32);
    let results = collect(&originals, &|| Ok(()), |target| {
        let active = active.clone();
        let peak = peak.clone();
        async move {
            active.set(active.get() + 1);
            peak.set(peak.get().max(active.get()));
            // Real asynchronous pending reads, deliberately completing out of order.
            let index = usize::from_str_radix(target.path.rsplit('/').next().unwrap(), 16).unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(if index % 2 == 0 {
                4
            } else {
                1
            }))
            .await;
            active.set(active.get() - 1);
            match index % 3 {
                0 => Ok((StorageWorkOutcome::NotFound, 0)),
                1 => Err(anyhow::anyhow!("source framing refused")),
                _ => Ok((
                    StorageWorkOutcome::MirrorLiveMetadata {
                        sha256: aos_hub_core::hybrid_ingress::body_sha256(b"{}"),
                        size: 2,
                        content_base64: "e30=".into(),
                    },
                    2,
                )),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(peak.get(), 2);
    assert_eq!(active.get(), 0);
    assert_eq!(results.len(), 32);
    for (target, result) in originals.iter().zip(&results) {
        assert_eq!(
            result.target_digest,
            live_metadata_batch::target_digest(target).unwrap()
        );
    }
    assert!(matches!(results[0].outcome, LiveMetadataOutcome::NotFound));
    assert!(matches!(
        results[1].outcome,
        LiveMetadataOutcome::Refused { .. }
    ));
    assert!(matches!(
        results[2].outcome,
        LiveMetadataOutcome::Found { .. }
    ));
}

#[tokio::test]
async fn expired_original_cannot_be_hidden_inside_source_refusals() {
    let current = Cell::new(true);
    let originals = targets(1);
    let result = collect(
        &originals,
        &|| {
            ensure!(current.get(), "original expired");
            Ok(())
        },
        |_| async {
            current.set(false);
            Err(anyhow::anyhow!("provider read failed"))
        },
    )
    .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn retained_results_are_bounded_before_the_whole_envelope_is_encoded() {
    let originals = targets(32);
    let reads = Cell::new(0);
    let items = collect(&originals, &|| Ok(()), |_| async {
        reads.set(reads.get() + 1);
        use base64::Engine as _;
        let bytes = vec![0; 128 * 1024];
        Ok((
            StorageWorkOutcome::MirrorLiveMetadata {
                sha256: aos_hub_core::hybrid_ingress::body_sha256(&bytes),
                size: bytes.len() as u64,
                content_base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            },
            bytes.len() as u64,
        ))
    })
    .await
    .unwrap();
    assert!(
        serde_json::to_vec(&items).unwrap().len() < aos_hub_core::storage_work::MAX_RESULT_BYTES
    );
    assert_eq!(
        items
            .iter()
            .filter(|item| matches!(item.outcome, LiveMetadataOutcome::Found { .. }))
            .count(),
        1
    );
    assert_eq!(
        items
            .iter()
            .filter_map(|item| item.source_bytes)
            .sum::<u64>(),
        reads.get() as u64 * 128 * 1024
    );
    assert!(
        reads.get() <= 3,
        "response exhaustion must stop later provider reads"
    );
}

#[tokio::test]
async fn original_batch_expiry_drops_both_actual_pending_producers() {
    struct PendingRead<'a> {
        active: &'a Cell<usize>,
        dropped: &'a Cell<usize>,
    }
    impl Drop for PendingRead<'_> {
        fn drop(&mut self) {
            self.active.set(self.active.get() - 1);
            self.dropped.set(self.dropped.get() + 1);
        }
    }

    let originals = targets(32);
    let now = Cell::new(101_u64);
    let original_expires_at = 103;
    let active = Cell::new(0);
    let dropped = Cell::new(0);
    let requested_wait = Cell::new(std::time::Duration::ZERO);

    let result = collect_until_expiry(
        &originals,
        &|| {
            ensure!(now.get() < original_expires_at as u64, "original expired");
            Ok(())
        },
        |_| async {
            active.set(active.get() + 1);
            let _read = PendingRead {
                active: &active,
                dropped: &dropped,
            };
            std::future::pending::<Result<(StorageWorkOutcome, u64)>>().await
        },
        original_expires_at,
        &|| Ok(now.get()),
        |wait| {
            requested_wait.set(wait);
            async {
                // Controlled UTC advances to the original expiry while both real
                // async producer futures remain pending. No source completes.
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                assert_eq!(active.get(), 2);
                now.set(original_expires_at as u64);
            }
        },
    )
    .await;

    assert!(result.is_err());
    assert_eq!(requested_wait.get(), std::time::Duration::from_secs(2));
    assert_eq!(dropped.get(), 2);
    assert_eq!(active.get(), 0);
}
