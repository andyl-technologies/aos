// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for exact failures.
#![allow(clippy::expect_used)]

use std::sync::mpsc;
use std::time::Duration;

use crucible_cas::content_store::ObjectKind;

use super::*;

fn key(label: &str) -> QemuHotForkTemplateKey {
    let digest = CampaignHash::derive(
        "crucible.test.hot-checkpoint-retention.v1",
        label.as_bytes(),
    );
    QemuHotForkTemplateKey::new(
        CampaignLineageId::parse(&format!(
            "crucible.campaign.lineage@campaign-fact.1.{}",
            digest.to_hex()
        ))
        .expect("lineage"),
        ContentHash::from_bytes(format!("configuration:{label}").as_bytes()),
    )
}

fn exact(label: &str) -> ExactCheckpointId {
    ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        4,
        label.as_bytes(),
    ))
    .expect("exact checkpoint")
}

fn thin(label: &str) -> ConfigurationArtifactId {
    let content = ContentId::for_bytes(ObjectKind::Configuration, 1, label.as_bytes());
    ConfigurationArtifactId::parse(&format!(
        "crucible.campaign.configuration-artifact@{}",
        content.encode()
    ))
    .expect("configuration artifact")
}

fn roots(admin: &dyn HotCheckpointFallbackRetentionAdmin) -> Vec<ContentId> {
    let mut fence = admin
        .acquire_hot_checkpoint_retention_fence()
        .expect("retention fence");
    let mut roots = Vec::new();
    let summary = fence
        .visit_roots(&mut |root| {
            roots.push(root);
            Ok(())
        })
        .expect("root inventory");
    assert_eq!(summary.roots(), roots.len() as u64);
    roots
}

#[test]
fn memory_catalog_is_bounded_conditional_and_roots_both_tiers() {
    let store = MemoryHotCheckpointFallbackRetentionStore::new();
    let first_slot = HotCheckpointFallbackSlot::new(0).expect("first slot");
    let last_slot =
        HotCheckpointFallbackSlot::new(MAX_HOT_CHECKPOINT_FALLBACK_ROOTS - 1).expect("last slot");
    assert!(matches!(
        HotCheckpointFallbackSlot::new(MAX_HOT_CHECKPOINT_FALLBACK_ROOTS),
        Err(HotCheckpointFallbackRetentionError::SlotOutOfRange { .. })
    ));

    let first = HotCheckpointFallbackRecord::new(
        key("first"),
        HotCheckpointFallback::Exact(exact("first")),
    );
    let last =
        HotCheckpointFallbackRecord::new(key("last"), HotCheckpointFallback::Thin(thin("last")));
    assert_eq!(
        store
            .compare_exchange_fallback(first_slot, None, Some(first))
            .expect("insert first"),
        HotCheckpointFallbackRetentionCas::Advanced
    );
    assert_eq!(
        store
            .compare_exchange_fallback(last_slot, None, Some(last))
            .expect("insert last"),
        HotCheckpointFallbackRetentionCas::Advanced
    );
    assert_eq!(
        store
            .compare_exchange_fallback(first_slot, None, Some(last))
            .expect("stale insert"),
        HotCheckpointFallbackRetentionCas::Conflict {
            current: Some(first)
        }
    );
    assert_eq!(roots(&store), vec![first.root(), last.root()]);

    assert_eq!(
        store
            .compare_exchange_fallback(first_slot, Some(first), None)
            .expect("remove first"),
        HotCheckpointFallbackRetentionCas::Advanced
    );
    assert_eq!(roots(&store), vec![last.root()]);
}

#[test]
fn directory_catalog_survives_restart_and_rejects_corruption() {
    let directory = tempfile::tempdir().expect("catalog directory");
    let slot = HotCheckpointFallbackSlot::new(23).expect("slot");
    let record = HotCheckpointFallbackRecord::new(
        key("restart"),
        HotCheckpointFallback::Exact(exact("restart")),
    );
    {
        let store = DirectoryHotCheckpointFallbackRetentionStore::open(directory.path())
            .expect("open catalog");
        assert_eq!(
            store
                .compare_exchange_fallback(slot, None, Some(record))
                .expect("store fallback"),
            HotCheckpointFallbackRetentionCas::Advanced
        );
        assert_eq!(roots(&store), vec![record.root()]);
    }
    let abandoned_staging = directory.path().join("records").join(".staging-crash");
    std::fs::write(&abandoned_staging, b"incomplete").expect("write abandoned staging record");
    let reopened = DirectoryHotCheckpointFallbackRetentionStore::open(directory.path())
        .expect("reopen catalog");
    assert!(!abandoned_staging.exists());
    assert_eq!(
        reopened.load_fallback(slot).expect("load fallback"),
        Some(record)
    );
    assert_eq!(roots(&reopened), vec![record.root()]);
    drop(reopened);

    std::fs::write(directory.path().join("records").join("0017"), b"corrupt")
        .expect("corrupt record");
    assert!(matches!(
        DirectoryHotCheckpointFallbackRetentionStore::open(directory.path()),
        Err(HotCheckpointFallbackRetentionError::Corrupt { .. })
    ));
}

#[test]
fn directory_inventory_fence_blocks_root_replacement() {
    let directory = tempfile::tempdir().expect("catalog directory");
    let store =
        DirectoryHotCheckpointFallbackRetentionStore::open(directory.path()).expect("open catalog");
    let slot = HotCheckpointFallbackSlot::new(7).expect("slot");
    let first = HotCheckpointFallbackRecord::new(
        key("fenced-first"),
        HotCheckpointFallback::Exact(exact("fenced-first")),
    );
    let second = HotCheckpointFallbackRecord::new(
        key("fenced-second"),
        HotCheckpointFallback::Thin(thin("fenced-second")),
    );
    store
        .compare_exchange_fallback(slot, None, Some(first))
        .expect("store first");
    let fence = store
        .acquire_hot_checkpoint_retention_fence()
        .expect("inventory fence");

    let writer = store.clone();
    let (sent, received) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = writer.compare_exchange_fallback(slot, Some(first), Some(second));
        sent.send(result).expect("send mutation result");
    });
    assert!(matches!(
        received.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    drop(fence);

    assert_eq!(
        received
            .recv_timeout(Duration::from_secs(2))
            .expect("mutation completed")
            .expect("replace fallback"),
        HotCheckpointFallbackRetentionCas::Advanced
    );
    worker.join().expect("join writer");
    assert_eq!(roots(&store), vec![second.root()]);
}
