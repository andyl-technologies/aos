//! Published-root binding, fit-or-reject admission, and sink retirement.

use crucible_campaign::ConfigurationArtifactId;
use crucible_cas::content_store::{ContentId, ObjectKind};

use super::super::test_support::advanced_published_root_source_for_test;
use super::*;
use crate::qemu_hot_fork_source_capture::{
    AuthenticatedPublishedRootQemuHotForkSource, QemuPublishedRootOrigin,
    QemuPublishedRootProvenance,
};
use crate::{QemuPublishedRootAdmission, QemuPublishedRootSink, QemuPublishedRootState};

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

/// Stop-root provenance naming the source's own boundary configuration.
fn provenance(source: &ProductionVmHotForkSourceWorld) -> QemuPublishedRootProvenance {
    QemuPublishedRootProvenance::new(
        QemuPublishedRootOrigin::AttemptStop,
        source.continuation().configuration().clone(),
        Some(true),
    )
}

/// Seals `source` as a published root with provenance at its own boundary.
fn published_root(
    key: QemuHotForkSourceWorldKey,
    published: ConfigurationArtifactId,
    source: ProductionVmHotForkSourceWorld,
) -> AuthenticatedPublishedRootQemuHotForkSource {
    let provenance = provenance(&source);
    AuthenticatedPublishedRootQemuHotForkSource::new(key, published, source, provenance)
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

    let genesis_provenance = provenance(&genesis);
    let failure =
        ManagedQemuHotForkSourceWorld::bind_published_root(key, genesis, genesis_provenance)
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
    let advanced_provenance = provenance(&advanced);
    let failure = ManagedQemuHotForkSourceWorld::bind_published_root(
        canonical.clone(),
        advanced,
        advanced_provenance,
    )
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
        published_root(key.clone(), published, source),
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
        published_root(
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
            published_root(
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

#[test]
fn published_root_sink_admits_and_retires_rejected_roots() {
    let mut first = advanced_source("published.sink-first");
    let first_key = published_key(&first);
    let limits = single_template_limits(&mut first);
    let pool = SharedManagedQemuHotForkSourceWorldPool::new(
        ManagedQemuHotForkSourceWorldPool::open(
            limits,
            ReapingDemotionSink,
            MemoryHotCheckpointFallbackRetentionStore::new(),
        )
        .expect("managed source-world pool"),
    );
    let sink = ManagedQemuPublishedRootSink::new(pool.clone(), HotCheckpointHotnessSignals::new());
    assert!(sink.may_admit());

    let admitted = sink
        .admit(published_root(
            first_key,
            published_artifact(b"published-sink-first-child"),
            first,
        ))
        .expect("admit first root");
    assert_eq!(admitted, QemuPublishedRootAdmission::Admitted);
    assert!(!sink.may_admit());

    let second = advanced_source("published.sink-second");
    let second_key = published_key(&second);
    let rejected = sink
        .admit(published_root(
            second_key,
            published_artifact(b"published-sink-second-child"),
            second,
        ))
        .expect("a rejected root is retired");
    let QemuPublishedRootAdmission::Rejected(reason) = rejected else {
        panic!("a full pool must reject the second root")
    };
    assert!(reason.contains("insufficient") || reason.contains("rejected"));

    pool.orderly_shutdown().expect("retire admitted root");
}

#[test]
fn published_root_keeps_its_provenance_beside_the_admitted_source() {
    let mut source = advanced_source("published.provenance");
    let key = published_key(&source);
    let boundary = source.continuation().configuration().clone();
    let limits = single_template_limits(&mut source);
    let mut pool = ManagedQemuHotForkSourceWorldPool::open(
        limits,
        ReapingDemotionSink,
        MemoryHotCheckpointFallbackRetentionStore::new(),
    )
    .expect("managed source-world pool");
    let anchor = QemuPublishedRootProvenance::new(
        QemuPublishedRootOrigin::BranchParentAnchor,
        boundary.clone(),
        Some(true),
    );

    pool.admit_authenticated_published_root(
        AuthenticatedPublishedRootQemuHotForkSource::new(
            key.clone(),
            published_artifact(b"published-provenance-child"),
            source,
            anchor,
        ),
        HotCheckpointHotnessSignals::new(),
    )
    .expect("admit anchor root");

    let world = pool
        .worlds
        .get(&manager_source_key(&key))
        .expect("retained anchor root");
    let provenance = world
        .published_root_provenance()
        .expect("published root provenance");
    assert_eq!(
        provenance.origin(),
        QemuPublishedRootOrigin::BranchParentAnchor
    );
    assert_eq!(provenance.configuration(), &boundary);
    assert_eq!(provenance.live_network_choice_pause(), Some(true));
    pool.orderly_shutdown().expect("retire anchor root");
}

#[test]
fn published_binding_rejects_provenance_for_another_configuration() {
    let advanced = advanced_source("published.provenance-source");
    let other = advanced_source("published.provenance-other");
    let key = published_key(&advanced);
    let mismatched = provenance(&other);
    other.retire().expect("retire unrelated source");

    let failure = ManagedQemuHotForkSourceWorld::bind_published_root(key, advanced, mismatched)
        .err()
        .expect("provenance must name the source's own boundary");
    let (advanced, error) = failure.into_parts();
    assert!(matches!(
        error,
        ManagedQemuHotForkSourceWorldBindingError::NonPublishedBoundary { ref detail }
            if detail.contains("provenance_matches=false")
    ));

    // Canonical and exact sources carry no published-root provenance.
    let genesis = prepared_source();
    let canonical = QemuHotForkSourceWorldKey::new(
        lineage_id(0x51),
        genesis.continuation().configuration().def.id(),
        genesis.continuation().configuration().id(),
        compatibility_profile(),
    );
    let genesis = ManagedQemuHotForkSourceWorld::bind(canonical, genesis)
        .map_err(|failure| failure.to_string())
        .expect("bind canonical genesis");
    assert!(genesis.published_root_provenance().is_none());
    genesis
        .into_source()
        .map_err(|_| "canonical source is bound")
        .expect("canonical source")
        .retire()
        .expect("retire canonical source");
    advanced.retire().expect("retire advanced source");
}

/// Pool limits at `numerator / denominator` of one measured source.
fn scaled_limits(
    source: &mut ProductionVmHotForkSourceWorld,
    maximum_templates: usize,
    numerator: u64,
    denominator: u64,
) -> HotCheckpointLimits {
    let usage = source
        .measure_retained_resources()
        .expect("measure source resources");
    let scale = |value: u64| value.saturating_mul(numerator) / denominator;
    let scale_count =
        |value: u32| u32::try_from(scale(u64::from(value))).expect("scaled count fits");
    let resources = HotCheckpointResourceProfile::new(
        scale(usage.template_bytes()),
        scale(usage.expected_private_dirty_bytes()),
        scale_count(usage.process_count()),
        scale_count(usage.virtual_cpu_count()),
        scale_count(usage.descriptor_count()),
        scale_count(usage.overlay_count()).max(1),
    )
    .expect("pool resource ceiling");
    HotCheckpointLimits::new(maximum_templates, resources, 4, 1_000_000_000)
        .expect("managed limits")
}

fn anchor_root(
    key: QemuHotForkSourceWorldKey,
    published: ConfigurationArtifactId,
    source: ProductionVmHotForkSourceWorld,
) -> AuthenticatedPublishedRootQemuHotForkSource {
    let provenance = QemuPublishedRootProvenance::new(
        QemuPublishedRootOrigin::BranchParentAnchor,
        source.continuation().configuration().clone(),
        Some(true),
    );
    AuthenticatedPublishedRootQemuHotForkSource::new(key, published, source, provenance)
}

#[test]
fn anchor_root_with_room_for_one_child_persists_its_thin_fallback_and_leases() {
    let mut source = advanced_source("anchor.fits");
    let key = published_key(&source);
    let limits = scaled_limits(&mut source, 1, 4, 1);
    let retention = MemoryHotCheckpointFallbackRetentionStore::new();
    let mut pool =
        ManagedQemuHotForkSourceWorldPool::open(limits, ReapingDemotionSink, retention.clone())
            .expect("managed source-world pool");
    let published = published_artifact(b"anchor-fits-parent");

    pool.admit_authenticated_anchor_root(
        anchor_root(key.clone(), published, source),
        HotCheckpointHotnessSignals::new(),
    )
    .expect("admit anchor root");

    let slot = *pool
        .active
        .get(&manager_source_key(&key))
        .expect("active fallback slot");
    let record = retention
        .load_fallback(slot)
        .expect("load thin fallback")
        .expect("persisted thin fallback");
    assert_eq!(record.fallback(), HotCheckpointFallback::Thin(published));
    assert!(pool.source_available(&key));

    // The headroom the anchor was admitted with is exactly one child lease.
    let lease = pool
        .checkout_lease_for(1, &key)
        .expect("child lease fits")
        .expect("anchor root lease");
    pool.restore_lease_for(1, lease);
    pool.orderly_shutdown().expect("retire anchor root");
}

#[test]
fn anchor_root_without_child_headroom_is_rejected_where_a_stop_root_fits() {
    let mut source = advanced_source("anchor.no-headroom");
    let key = published_key(&source);
    // One measured world fits; the world plus one child reservation does not.
    let limits = scaled_limits(&mut source, 1, 3, 2);
    let retention = MemoryHotCheckpointFallbackRetentionStore::new();
    let mut pool =
        ManagedQemuHotForkSourceWorldPool::open(limits, ReapingDemotionSink, retention.clone())
            .expect("managed source-world pool");

    let failure = pool
        .admit_authenticated_anchor_root(
            anchor_root(
                key.clone(),
                published_artifact(b"anchor-no-headroom-parent"),
                source,
            ),
            HotCheckpointHotnessSignals::new(),
        )
        .expect_err("an anchor no child could fork from is refused");
    let ManagedQemuHotForkAuthenticatedAdmissionFailure::Admission(failure) = failure else {
        panic!("binding must succeed for the anchor root")
    };
    let (candidate, cleanup_slot, error) = failure.into_parts();
    assert!(cleanup_slot.is_none());
    assert!(matches!(
        error,
        ManagedQemuHotForkSourceWorldAdmissionError::AnchorChildCapacity { .. }
    ));
    // The refusal precedes fallback persistence.
    assert!(pool.records.is_empty());
    assert!(!pool.source_available(&key));

    // The same world is still an admissible stop root under the same limits.
    let source = candidate
        .into_source()
        .map_err(|_| "refused anchor kept its source")
        .expect("refused anchor source");
    pool.admit_authenticated_published_root(
        published_root(
            key.clone(),
            published_artifact(b"anchor-no-headroom-stop"),
            source,
        ),
        HotCheckpointHotnessSignals::new(),
    )
    .expect("a stop root needs no child headroom");
    assert!(pool.source_available(&key));
    pool.orderly_shutdown().expect("retire stop root");
}

#[test]
fn anchor_sink_names_capacity_refusals_and_reuses_an_equal_root() {
    let mut first = advanced_source("anchor.sink");
    let key = published_key(&first);
    let limits = scaled_limits(&mut first, 2, 4, 1);
    let pool = SharedManagedQemuHotForkSourceWorldPool::new(
        ManagedQemuHotForkSourceWorldPool::open(
            limits,
            ReapingDemotionSink,
            MemoryHotCheckpointFallbackRetentionStore::new(),
        )
        .expect("managed source-world pool"),
    );
    let sink = ManagedQemuPublishedRootSink::new(pool.clone(), HotCheckpointHotnessSignals::new());

    let admitted = sink
        .admit_anchor(anchor_root(
            key.clone(),
            published_artifact(b"anchor-sink-parent"),
            first,
        ))
        .expect("admit anchor root");
    assert_eq!(admitted, QemuPublishedRootAdmission::Admitted);

    // A second world at the same boundary is retired; the first serves it.
    let equal = advanced_source("anchor.sink");
    assert_eq!(published_key(&equal), key);
    let duplicate = sink
        .admit_anchor(anchor_root(
            key,
            published_artifact(b"anchor-sink-parent"),
            equal,
        ))
        .expect("a duplicate anchor is retired");
    assert_eq!(duplicate, QemuPublishedRootAdmission::AlreadyRetained);
    pool.orderly_shutdown().expect("retire anchor root");

    let mut tight = advanced_source("anchor.sink-tight");
    let tight_key = published_key(&tight);
    let limits = scaled_limits(&mut tight, 1, 3, 2);
    let pool = SharedManagedQemuHotForkSourceWorldPool::new(
        ManagedQemuHotForkSourceWorldPool::open(
            limits,
            ReapingDemotionSink,
            MemoryHotCheckpointFallbackRetentionStore::new(),
        )
        .expect("managed source-world pool"),
    );
    let sink = ManagedQemuPublishedRootSink::new(pool.clone(), HotCheckpointHotnessSignals::new());
    let refused = sink
        .admit_anchor(anchor_root(
            tight_key,
            published_artifact(b"anchor-sink-tight-parent"),
            tight,
        ))
        .expect("a refused anchor is retired");
    let QemuPublishedRootAdmission::Rejected(reason) = refused else {
        panic!("a tight anchor must be refused: {refused:?}");
    };
    assert!(
        reason.starts_with("anchor-child-capacity ")
            && reason.contains("pressure=")
            && reason.contains("projected=")
            && reason.contains("limits="),
        "the refusal names its capacity dimensions: {reason}"
    );
    pool.orderly_shutdown().expect("nothing retained");
}

/// An invalidated root keeps its coordinate but is never counted as kept:
/// the coordinate reads unusable, and a racing anchor there is refused.
#[test]
fn anchor_at_an_invalidated_root_is_refused_not_counted_as_retained() {
    let mut first = advanced_source("anchor.invalidated");
    let key = published_key(&first);
    let limits = scaled_limits(&mut first, 2, 4, 1);
    let pool = SharedManagedQemuHotForkSourceWorldPool::new(
        ManagedQemuHotForkSourceWorldPool::open(
            limits,
            ReapingDemotionSink,
            MemoryHotCheckpointFallbackRetentionStore::new(),
        )
        .expect("managed source-world pool"),
    );
    let sink = ManagedQemuPublishedRootSink::new(pool.clone(), HotCheckpointHotnessSignals::new());
    assert_eq!(sink.root_state(&key), QemuPublishedRootState::Absent);
    let admitted = sink
        .admit_anchor(anchor_root(
            key.clone(),
            published_artifact(b"anchor-invalidated-parent"),
            first,
        ))
        .expect("admit anchor root");
    assert_eq!(admitted, QemuPublishedRootAdmission::Admitted);
    assert_eq!(sink.root_state(&key), QemuPublishedRootState::Live);

    // A child fails and is abandoned; the root it was leased from is spent.
    let mut inner = pool.pool.lock().expect("shared pool");
    let lease = inner
        .checkout_lease_for(1, &key)
        .expect("child lease fits")
        .expect("anchor root lease");
    inner.abandon_lease_for(1);
    drop(lease);
    drop(inner);
    assert_eq!(sink.root_state(&key), QemuPublishedRootState::Unusable);

    // An anchor that raced the invalidation is retired with a named refusal.
    let equal = advanced_source("anchor.invalidated");
    assert_eq!(published_key(&equal), key);
    let refused = sink
        .admit_anchor(anchor_root(
            key.clone(),
            published_artifact(b"anchor-invalidated-parent"),
            equal,
        ))
        .expect("a refused anchor is retired");
    assert_eq!(
        refused,
        QemuPublishedRootAdmission::Rejected(String::from("anchor-root-invalidated"))
    );
    assert_eq!(sink.root_state(&key), QemuPublishedRootState::Unusable);

    // The abandoned root's authority stays in quarantine, not in the pool.
    assert!(pool.orderly_shutdown().is_err());
}

fn attempt_key(index: u32) -> crate::AttemptExecutionKey {
    let attempt = crucible_campaign::AttemptId::parse(&format!(
        "crucible.campaign.attempt@campaign-fact.9.{index:08x}{}",
        "00".repeat(28)
    ))
    .expect("attempt id");
    crate::AttemptExecutionKey::new(lineage_id(0x61), attempt)
}

/// Each attempt anchors once; a bounded memory forgets only the oldest
/// claims, so at worst one long-past attempt could anchor once more.
#[test]
fn anchor_claims_are_once_per_attempt_and_bounded() {
    let mut source = advanced_source("anchor.claims");
    let limits = scaled_limits(&mut source, 1, 4, 1);
    source.retire().expect("retire sizing source");
    let pool = SharedManagedQemuHotForkSourceWorldPool::new(
        ManagedQemuHotForkSourceWorldPool::open(
            limits,
            ReapingDemotionSink,
            MemoryHotCheckpointFallbackRetentionStore::new(),
        )
        .expect("managed source-world pool"),
    );
    let sink = ManagedQemuPublishedRootSink::new(pool.clone(), HotCheckpointHotnessSignals::new());

    assert!(sink.claim_anchor(attempt_key(0)));
    assert!(!sink.claim_anchor(attempt_key(0)));
    assert!(sink.claim_anchor(attempt_key(1)));

    // 4096 claims are remembered; the next one forgets attempt 0 first.
    for index in 2..=4096 {
        assert!(sink.claim_anchor(attempt_key(index)));
    }
    assert!(!sink.claim_anchor(attempt_key(1)));
    assert!(sink.claim_anchor(attempt_key(0)));
    assert!(!sink.claim_anchor(attempt_key(4096)));
    pool.orderly_shutdown().expect("nothing retained");
}
