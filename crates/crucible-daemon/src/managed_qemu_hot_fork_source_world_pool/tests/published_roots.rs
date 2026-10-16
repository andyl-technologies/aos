//! Published-root binding and fit-or-reject admission.

use crucible_campaign::ConfigurationArtifactId;
use crucible_cas::content_store::{ContentId, ObjectKind};

use super::super::test_support::advanced_published_root_source_for_test;
use super::*;
use crate::qemu_hot_fork_source_capture::AuthenticatedPublishedRootQemuHotForkSource;

fn published_artifact(name: &[u8]) -> ConfigurationArtifactId {
    ConfigurationArtifactId::parse(&format!(
        "crucible.campaign.configuration-artifact@{}",
        ContentId::for_bytes(ObjectKind::Configuration, 1, name).encode()
    ))
    .expect("published child artifact id")
}

fn prepared_source() -> ProductionVmHotForkSourceWorld {
    let node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("scripted source");
    let (_nodes, source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![node]).expect("prepared source");
    source
}

fn advanced_source(name: &str) -> ProductionVmHotForkSourceWorld {
    advanced_published_root_source_for_test(name)
}

fn published_key(source: &ProductionVmHotForkSourceWorld) -> QemuHotForkSourceWorldKey {
    QemuHotForkSourceWorldKey::new_published(
        lineage_id(0x51),
        source.continuation().configuration().def.id(),
        source.continuation().configuration().id(),
        compatibility_profile(),
    )
}

/// Admits exactly one root, with headroom for measurement variance between worlds.
fn single_template_limits(source: &mut ProductionVmHotForkSourceWorld) -> HotCheckpointLimits {
    let usage = source
        .measure_retained_resources()
        .expect("measure source resources");
    let resources = HotCheckpointResourceProfile::new(
        usage.template_bytes().saturating_mul(4),
        usage.expected_private_dirty_bytes().saturating_mul(4),
        usage.process_count().saturating_mul(4),
        usage.virtual_cpu_count().saturating_mul(4),
        usage.descriptor_count().saturating_mul(4),
        usage.overlay_count().saturating_mul(4).max(1),
    )
    .expect("pool resource ceiling");
    HotCheckpointLimits::new(1, resources, 4, 1_000_000_000).expect("managed limits")
}

#[test]
fn published_binding_requires_an_advanced_nonterminal_boundary() {
    let genesis = prepared_source();
    let key = published_key(&genesis);

    let failure = ManagedQemuHotForkSourceWorld::bind_published_root(key, genesis)
        .err()
        .expect("a genesis schedule is not a published boundary");
    let (genesis, error) = failure.into_parts();
    assert!(matches!(
        error,
        ManagedQemuHotForkSourceWorldBindingError::NonPublishedBoundary { .. }
    ));
    genesis.retire().expect("retire genesis source");

    let advanced = advanced_source("published.binding");
    let canonical = QemuHotForkSourceWorldKey::new(
        lineage_id(0x51),
        advanced.continuation().configuration().def.id(),
        advanced.continuation().configuration().id(),
        compatibility_profile(),
    );
    let failure = ManagedQemuHotForkSourceWorld::bind_published_root(canonical.clone(), advanced)
        .err()
        .expect("a canonical-genesis key cannot bind a published root");
    let (advanced, error) = failure.into_parts();
    assert!(matches!(
        error,
        ManagedQemuHotForkSourceWorldBindingError::NonPublishedBoundary { .. }
    ));

    // The ordinary canonical binding rejects the same advanced world.
    let failure = ManagedQemuHotForkSourceWorld::bind(canonical, advanced)
        .err()
        .expect("canonical binding rejects a recorded schedule");
    let (advanced, error) = failure.into_parts();
    assert!(matches!(
        error,
        ManagedQemuHotForkSourceWorldBindingError::NonCanonicalBoundary { .. }
    ));
    advanced.retire().expect("retire advanced source");
}

#[test]
fn published_root_persists_its_thin_fallback_before_it_becomes_reusable() {
    let mut source = advanced_source("published.admission");
    let key = published_key(&source);
    let manager_key = manager_source_key(&key);
    let canonical = QemuHotForkSourceWorldKey::new(
        key.template_key().lineage(),
        key.scenario(),
        key.configuration(),
        compatibility_profile(),
    );
    let limits = single_template_limits(&mut source);
    let retention = MemoryHotCheckpointFallbackRetentionStore::new();
    let mut pool =
        ManagedQemuHotForkSourceWorldPool::open(limits, ReapingDemotionSink, retention.clone())
            .expect("managed source-world pool");
    let published = published_artifact(b"published-admission-child");
    assert!(pool.has_free_template_slot());

    pool.admit_authenticated_published_root(
        AuthenticatedPublishedRootQemuHotForkSource::new(key.clone(), published, source),
        HotCheckpointHotnessSignals::new(),
    )
    .expect("admit published root");

    assert_eq!(manager_key, key.template_key());
    assert!(pool.source_available(&key));
    assert!(!pool.source_available(&canonical));
    assert!(!pool.has_free_template_slot());
    let slot = *pool.active.get(&manager_key).expect("active fallback slot");
    let record = retention
        .load_fallback(slot)
        .expect("load thin fallback")
        .expect("persisted thin fallback");
    assert_eq!(record.template_key(), key.template_key());
    assert_eq!(record.fallback(), HotCheckpointFallback::Thin(published));

    // Only the exact published-boundary key checks the root out.
    assert!(
        pool.checkout(&canonical)
            .expect("canonical-key checkout")
            .is_none()
    );
    let lease = pool
        .checkout(&key)
        .expect("published-key checkout")
        .expect("published root lease");
    pool.restore(lease);
    assert!(pool.source_available(&key));

    pool.orderly_shutdown().expect("retire published root");
    let (_slot, record) = pool
        .cold_fallbacks()
        .next()
        .expect("cold thin fallback root");
    assert_eq!(record.fallback(), HotCheckpointFallback::Thin(published));
}

#[test]
fn published_root_never_evicts_a_retained_source_with_equal_signals() {
    let mut retained = advanced_source("published.retained");
    let retained_key = published_key(&retained);
    let limits = single_template_limits(&mut retained);
    let retention = MemoryHotCheckpointFallbackRetentionStore::new();
    let mut pool =
        ManagedQemuHotForkSourceWorldPool::open(limits, ReapingDemotionSink, retention.clone())
            .expect("managed source-world pool");
    pool.admit_authenticated_published_root(
        AuthenticatedPublishedRootQemuHotForkSource::new(
            retained_key.clone(),
            published_artifact(b"published-retained-child"),
            retained,
        ),
        HotCheckpointHotnessSignals::new(),
    )
    .expect("admit first published root");

    let candidate = advanced_source("published.candidate");
    let candidate_key = published_key(&candidate);
    let failure = pool
        .admit_authenticated_published_root(
            AuthenticatedPublishedRootQemuHotForkSource::new(
                candidate_key.clone(),
                published_artifact(b"published-candidate-child"),
                candidate,
            ),
            HotCheckpointHotnessSignals::new(),
        )
        .expect_err("a full pool rejects an equally hot root");
    let ManagedQemuHotForkAuthenticatedAdmissionFailure::Admission(failure) = failure else {
        panic!("binding must succeed for the candidate root")
    };
    let (candidate, cleanup_slot, error) = failure.into_parts();
    assert!(cleanup_slot.is_none());
    assert!(matches!(
        error,
        ManagedQemuHotForkSourceWorldAdmissionError::Rejected(_)
    ));
    assert!(pool.source_available(&retained_key));
    assert!(!pool.source_available(&candidate_key));
    // Only the retained root's durable record remains.
    assert_eq!(pool.records.len(), 1);
    candidate
        .into_source()
        .map_err(|_| "rejected candidate lost its source")
        .expect("rejected candidate source")
        .retire()
        .expect("retire rejected candidate");

    pool.orderly_shutdown().expect("retire retained root");
}
