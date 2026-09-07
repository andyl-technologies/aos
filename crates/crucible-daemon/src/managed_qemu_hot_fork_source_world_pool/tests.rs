//! Managed whole-world admission, accounting, routing, and retirement tests.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for exact failures.
#![allow(clippy::expect_used)]

use crucible::ContentHash;
use crucible_api::vm_lifecycle::prepared_multi_node_hot_fork_source_world_for_test;
use crucible_campaign::{CampaignLineageId, ExactCheckpointId, ExecutorCompatibilityProfile};
use crucible_qemu::{QemuTestHotForkOutcome, scripted_hot_fork_source_for_test};
use std::collections::BTreeMap;

use super::*;
use crate::{
    HotCheckpointDemotionReason, HotCheckpointFallback, HotCheckpointHotnessSignals,
    HotCheckpointLimits, HotCheckpointResourceProfile, HotCheckpointSourceDemoter,
    MemoryHotCheckpointFallbackRetentionStore, QemuHotForkSourceWorldDemotionError,
};

struct ReapingDemotionSink;

impl HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld> for ReapingDemotionSink {
    type Error = QemuHotForkSourceWorldDemotionError;

    fn validate_fallback(
        &mut self,
        _key: QemuHotForkTemplateKey,
        _fallback: HotCheckpointFallback,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn demote(
        &mut self,
        world: ManagedQemuHotForkSourceWorld,
        plan: HotCheckpointPlannedDemotion,
    ) -> Result<(), HotCheckpointTemplateDemotionFailure<ManagedQemuHotForkSourceWorld, Self::Error>>
    {
        QemuHotForkSourceWorldDemoter.demote_source(world, plan)
    }
}

#[test]
fn admission_uses_measured_world_resources_and_charges_only_matching_checkouts() {
    let source_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("scripted source");
    let (_nodes, mut source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![source_node])
            .expect("prepared source world");
    let usage = source
        .measure_retained_resources()
        .expect("measure source resources");
    let expected_resources = HotCheckpointResourceProfile::new(
        usage.template_bytes(),
        usage.expected_private_dirty_bytes(),
        usage.process_count(),
        usage.virtual_cpu_count(),
        usage.descriptor_count(),
        usage.overlay_count(),
    )
    .expect("measured resource profile");
    let key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x31),
        source.continuation().configuration().def.id(),
        source.continuation().configuration().id(),
        compatibility_profile(),
    );
    let template = key.template_key();
    let authenticated = AuthenticatedCanonicalQemuHotForkSource::new_for_test(key.clone(), source);
    let maximum_resources = HotCheckpointResourceProfile::new(
        expected_resources.template_bytes(),
        expected_resources.expected_private_dirty_bytes(),
        expected_resources.process_count(),
        expected_resources.virtual_cpu_count(),
        expected_resources.descriptor_count(),
        expected_resources.overlay_count(),
    )
    .expect("pool resource ceiling");
    let limits =
        HotCheckpointLimits::new(1, maximum_resources, 1, 1_000_000_000).expect("managed limits");
    let retention = MemoryHotCheckpointFallbackRetentionStore::new();
    let mut pool =
        ManagedQemuHotForkSourceWorldPool::open(limits, ReapingDemotionSink, retention.clone())
            .expect("managed source-world pool");
    let fallback = exact_fallback(0x41);

    pool.admit_authenticated_source(authenticated, HotCheckpointHotnessSignals::new(), fallback)
        .expect("admit measured source world");

    let status = pool
        .manager()
        .status(QemuHotForkTemplatePoolSlot::new(template, 0))
        .expect("managed status");
    assert_eq!(status.resources(), expected_resources);
    assert!(pool.source_available(&key));

    let wrong_key = QemuHotForkSourceWorldKey::new(
        template.lineage(),
        ContentHash::from_bytes(b"another-scenario"),
        key.configuration(),
        compatibility_profile(),
    );
    assert!(
        pool.checkout(&wrong_key)
            .expect("mismatched checkout")
            .is_none()
    );
    let mismatched_profile = ExecutorCompatibilityProfile::new(
        "crucible-test",
        "another-qemu-build",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        4,
    )
    .expect("mismatched compatibility profile");
    let wrong_profile_key = QemuHotForkSourceWorldKey::new(
        template.lineage(),
        key.scenario(),
        key.configuration(),
        mismatched_profile,
    );
    assert!(
        pool.checkout(&wrong_profile_key)
            .expect("incompatible profile checkout")
            .is_none()
    );

    let checked_out = pool
        .checkout(&key)
        .expect("matching checkout")
        .expect("matching source");
    pool.restore(checked_out);
    assert!(matches!(
        pool.checkout(&key),
        Err(ManagedQemuHotForkSourceWorldCheckoutError::ForkRate(_))
    ));

    pool.demote_source(template, HotCheckpointDemotionReason::OperatorRequest)
        .expect("orderly source retirement");
    let (slot, record) = pool.cold_fallbacks().next().expect("cold fallback root");
    assert_eq!(record.fallback(), fallback);
    let released = pool
        .release_cold_fallback(slot)
        .expect("release cold fallback");
    assert_eq!(released, record);
    assert!(pool.cold_fallbacks().next().is_none());
}

#[test]
fn resource_decline_retires_the_source_and_keeps_a_cold_fallback() {
    let source_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("scripted source");
    let (_nodes, mut source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![source_node])
            .expect("prepared source world");
    let usage = source
        .measure_retained_resources()
        .expect("measure source resources");
    assert!(usage.template_bytes() > 1);
    let key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x34),
        source.continuation().configuration().def.id(),
        source.continuation().configuration().id(),
        compatibility_profile(),
    );
    let maximum_resources = HotCheckpointResourceProfile::new(
        usage.template_bytes().saturating_sub(1).max(1),
        usage.expected_private_dirty_bytes(),
        usage.process_count(),
        usage.virtual_cpu_count(),
        usage.descriptor_count(),
        usage.overlay_count(),
    )
    .expect("constrained pool resource ceiling");
    let limits =
        HotCheckpointLimits::new(1, maximum_resources, 1, 1_000_000_000).expect("managed limits");
    let retention = MemoryHotCheckpointFallbackRetentionStore::new();
    let mut pool =
        ManagedQemuHotForkSourceWorldPool::open(limits, ReapingDemotionSink, retention.clone())
            .expect("managed source-world pool");
    let fallback = exact_fallback(0x44);

    let failure = pool
        .admit_authenticated_source(
            AuthenticatedCanonicalQemuHotForkSource::new_for_test(key.clone(), source),
            HotCheckpointHotnessSignals::new(),
            fallback,
        )
        .expect_err("resource ceiling must decline hot admission");
    let ManagedQemuHotForkAuthenticatedAdmissionFailure::Admission(failure) = failure else {
        panic!("resource ceiling should reject after source binding");
    };
    let (candidate, cleanup_slot, error) = failure.into_parts();
    assert!(cleanup_slot.is_none());
    assert!(matches!(
        error,
        ManagedQemuHotForkSourceWorldAdmissionError::Rejected(_)
    ));
    let slot = pool
        .retain_cold_fallback(key.template_key(), fallback)
        .expect("retain declined source fallback");
    let source = match candidate.into_source() {
        Ok(source) => source,
        Err(_candidate) => panic!("declined source remains owned"),
    };
    source.retire().expect("retire declined source");

    assert_eq!(
        retention.load_fallback(slot).expect("load fallback"),
        Some(HotCheckpointFallbackRecord::new(
            key.template_key(),
            fallback
        ))
    );
    assert!(!pool.source_available(&key));

    drop(pool);
    for _restart in 0..3 {
        let source_node = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked)
            .expect("restarted scripted source");
        let (_nodes, source) =
            prepared_multi_node_hot_fork_source_world_for_test(vec![source_node])
                .expect("restarted prepared source world");
        let mut pool =
            ManagedQemuHotForkSourceWorldPool::open(limits, ReapingDemotionSink, retention.clone())
                .expect("reopen declined-source fallback inventory");
        let failure = pool
            .admit_authenticated_source(
                AuthenticatedCanonicalQemuHotForkSource::new_for_test(key.clone(), source),
                HotCheckpointHotnessSignals::new(),
                fallback,
            )
            .expect_err("resource ceiling must decline restarted hot admission");
        let ManagedQemuHotForkAuthenticatedAdmissionFailure::Admission(failure) = failure else {
            panic!("restarted resource ceiling should reject after source binding");
        };
        let (candidate, cleanup_slot, error) = failure.into_parts();
        assert!(cleanup_slot.is_none());
        assert!(matches!(
            error,
            ManagedQemuHotForkSourceWorldAdmissionError::Rejected(_)
        ));
        let reused = pool
            .retain_cold_fallback(key.template_key(), fallback)
            .expect("reuse declined source fallback after restart");
        assert_eq!(reused, slot);
        assert_eq!(pool.cold_fallbacks().count(), 1);
        let source = match candidate.into_source() {
            Ok(source) => source,
            Err(_candidate) => panic!("restarted declined source remains owned"),
        };
        source.retire().expect("retire restarted declined source");
    }
}

#[test]
fn same_configuration_at_an_advanced_frontier_is_rejected() {
    let source_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("scripted source");
    let (_nodes, mut source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![source_node])
            .expect("prepared source world");
    let key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x32),
        source.continuation().configuration().def.id(),
        source.continuation().configuration().id(),
        compatibility_profile(),
    );
    source.mark_reuse_boundary_advanced_for_test();

    let failure = ManagedQemuHotForkSourceWorld::bind(key, source)
        .err()
        .expect("advanced same-configuration boundary must be rejected");
    let (source, error) = failure.into_parts();

    assert!(matches!(
        error,
        ManagedQemuHotForkSourceWorldBindingError::NonCanonicalBoundary
    ));
    source.retire().expect("retire rejected source world");
}

#[test]
fn wrong_world_restore_keeps_the_checked_out_source_authority_pending() {
    let first_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let second_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let (_first_nodes, mut first_source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![first_node])
            .expect("first prepared source world");
    let (_second_nodes, second_source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![second_node])
            .expect("second prepared source world");
    let key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x33),
        first_source.continuation().configuration().def.id(),
        first_source.continuation().configuration().id(),
        compatibility_profile(),
    );
    assert_eq!(
        second_source.continuation().configuration(),
        first_source.continuation().configuration()
    );

    let resources = first_source
        .measure_retained_resources()
        .expect("measure first source");
    let limits = HotCheckpointLimits::new(
        1,
        HotCheckpointResourceProfile::new(
            resources.template_bytes(),
            resources.expected_private_dirty_bytes(),
            resources.process_count(),
            resources.virtual_cpu_count(),
            resources.descriptor_count(),
            resources.overlay_count(),
        )
        .expect("source resource ceiling"),
        1,
        1_000_000_000,
    )
    .expect("managed limits");
    let mut pool = ManagedQemuHotForkSourceWorldPool::open(
        limits,
        ReapingDemotionSink,
        MemoryHotCheckpointFallbackRetentionStore::new(),
    )
    .expect("managed source-world pool");
    pool.admit_authenticated_source(
        AuthenticatedCanonicalQemuHotForkSource::new_for_test(key.clone(), first_source),
        HotCheckpointHotnessSignals::new(),
        exact_fallback(0x43),
    )
    .expect("admit first source");

    let checked_out = pool
        .checkout(&key)
        .expect("check out first source")
        .expect("first source available");
    pool.restore(second_source);
    assert!(matches!(
        pool.checkout(&key),
        Err(ManagedQemuHotForkSourceWorldCheckoutError::PriorCheckoutPending)
    ));
    assert!(
        pool.manager()
            .status(source_slot(key.template_key()))
            .is_some()
    );

    pool.restore(checked_out);
    assert!(pool.source_available(&key));
    pool.demote_source(
        key.template_key(),
        HotCheckpointDemotionReason::OperatorRequest,
    )
    .expect("retire restored source");
}

#[test]
fn pressure_demotion_reauthenticates_the_victim_catalog_record() {
    let first_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let second_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let (_first_nodes, mut first_source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![first_node])
            .expect("first prepared source world");
    let (_second_nodes, mut second_source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![second_node])
            .expect("second prepared source world");
    let first_key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x34),
        first_source.continuation().configuration().def.id(),
        first_source.continuation().configuration().id(),
        compatibility_profile(),
    );
    let second_key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x35),
        second_source.continuation().configuration().def.id(),
        second_source.continuation().configuration().id(),
        compatibility_profile(),
    );

    let first_usage = first_source
        .measure_retained_resources()
        .expect("measure first source");
    let second_usage = second_source
        .measure_retained_resources()
        .expect("measure second source");
    let maximum_resources = HotCheckpointResourceProfile::new(
        first_usage
            .template_bytes()
            .max(second_usage.template_bytes()),
        first_usage
            .expected_private_dirty_bytes()
            .max(second_usage.expected_private_dirty_bytes()),
        first_usage
            .process_count()
            .max(second_usage.process_count()),
        first_usage
            .virtual_cpu_count()
            .max(second_usage.virtual_cpu_count()),
        first_usage
            .descriptor_count()
            .max(second_usage.descriptor_count()),
        first_usage
            .overlay_count()
            .max(second_usage.overlay_count()),
    )
    .expect("one-source resource ceiling");
    let limits =
        HotCheckpointLimits::new(1, maximum_resources, 1, 1_000_000_000).expect("managed limits");
    let retention = MemoryHotCheckpointFallbackRetentionStore::new();
    let mut pool =
        ManagedQemuHotForkSourceWorldPool::open(limits, ReapingDemotionSink, retention.clone())
            .expect("managed source-world pool");
    let first_fallback = exact_fallback(0x44);
    pool.admit_authenticated_source(
        AuthenticatedCanonicalQemuHotForkSource::new_for_test(first_key.clone(), first_source),
        HotCheckpointHotnessSignals::new(),
        first_fallback,
    )
    .expect("admit first source");

    let active_slot = pool.active[&first_key.template_key()];
    let active_record = HotCheckpointFallbackRecord::new(first_key.template_key(), first_fallback);
    let replacement_record =
        HotCheckpointFallbackRecord::new(first_key.template_key(), exact_fallback(0x45));
    assert!(matches!(
        retention
            .compare_exchange_fallback(active_slot, Some(active_record), Some(replacement_record))
            .expect("replace active catalog record"),
        HotCheckpointFallbackRetentionCas::Advanced
    ));

    let hotter = HotCheckpointHotnessSignals::new()
        .with_pending_attempts(1)
        .expect("hotter source signals");
    let failure = pool
        .admit_authenticated_source(
            AuthenticatedCanonicalQemuHotForkSource::new_for_test(second_key, second_source),
            hotter,
            exact_fallback(0x46),
        )
        .expect_err("changed victim record must reject admission");
    let ManagedQemuHotForkAuthenticatedAdmissionFailure::Admission(failure) = failure else {
        panic!("source binding unexpectedly failed");
    };
    let (mut candidate, cleanup_slot, error) = failure.into_parts();
    assert!(cleanup_slot.is_none());
    assert!(matches!(
        error,
        ManagedQemuHotForkSourceWorldAdmissionError::VictimCatalog { .. }
    ));
    assert!(pool.source_available(&first_key));
    candidate
        .take()
        .expect("rejected candidate source")
        .retire()
        .expect("retire rejected candidate");

    assert!(matches!(
        retention
            .compare_exchange_fallback(active_slot, Some(replacement_record), Some(active_record))
            .expect("restore active catalog record"),
        HotCheckpointFallbackRetentionCas::Advanced
    ));
    pool.demote_source(
        first_key.template_key(),
        HotCheckpointDemotionReason::OperatorRequest,
    )
    .expect("retire protected victim");
}

#[test]
fn shared_worker_providers_release_before_orderly_shutdown_and_restart_inventory() {
    let first_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("first source");
    let second_node =
        scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked).expect("second source");
    let (_first_nodes, mut first_source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![first_node])
            .expect("first prepared source world");
    let (_second_nodes, mut second_source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![second_node])
            .expect("second prepared source world");
    let first_key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x36),
        first_source.continuation().configuration().def.id(),
        first_source.continuation().configuration().id(),
        compatibility_profile(),
    );
    let second_key = QemuHotForkSourceWorldKey::new(
        lineage_id(0x37),
        second_source.continuation().configuration().def.id(),
        second_source.continuation().configuration().id(),
        compatibility_profile(),
    );
    let first_usage = first_source
        .measure_retained_resources()
        .expect("measure first source");
    let second_usage = second_source
        .measure_retained_resources()
        .expect("measure second source");
    let maximum_resources = HotCheckpointResourceProfile::new(
        first_usage.template_bytes() + second_usage.template_bytes(),
        first_usage.expected_private_dirty_bytes() + second_usage.expected_private_dirty_bytes(),
        first_usage.process_count() + second_usage.process_count(),
        first_usage.virtual_cpu_count() + second_usage.virtual_cpu_count(),
        first_usage.descriptor_count() + second_usage.descriptor_count(),
        first_usage.overlay_count() + second_usage.overlay_count(),
    )
    .expect("two-source resource ceiling");
    let limits = HotCheckpointLimits::new(2, maximum_resources, 2, 1_000_000_000)
        .expect("shared managed limits");
    let retention = MemoryHotCheckpointFallbackRetentionStore::new();
    let mut pool =
        ManagedQemuHotForkSourceWorldPool::open(limits, ReapingDemotionSink, retention.clone())
            .expect("shared managed pool");
    pool.admit_authenticated_source(
        AuthenticatedCanonicalQemuHotForkSource::new_for_test(first_key.clone(), first_source),
        HotCheckpointHotnessSignals::new(),
        exact_fallback(0x47),
    )
    .expect("admit first shared source");
    pool.admit_authenticated_source(
        AuthenticatedCanonicalQemuHotForkSource::new_for_test(second_key.clone(), second_source),
        HotCheckpointHotnessSignals::new(),
        exact_fallback(0x48),
    )
    .expect("admit second shared source");

    let shared = SharedManagedQemuHotForkSourceWorldPool::new(pool);
    let mut first_provider = shared.provider().expect("first worker provider");
    let mut second_provider = shared.provider().expect("second worker provider");
    let first_checked_out = first_provider
        .checkout(&first_key)
        .expect("first worker checkout")
        .expect("first source available");
    let second_checked_out = second_provider
        .checkout(&second_key)
        .expect("second worker checkout")
        .expect("second source available");
    assert!(matches!(
        first_provider.checkout(&second_key),
        Err(SharedQemuHotForkSourceWorldProviderError::Checkout(
            ManagedQemuHotForkSourceWorldCheckoutError::PriorCheckoutPending
        ))
    ));
    let shutdown = shared
        .orderly_shutdown()
        .expect_err("checked-out sources block orderly shutdown");
    let SharedManagedQemuHotForkSourceWorldShutdownError::Sources(shutdown) = shutdown else {
        panic!("shared shutdown lock remained healthy");
    };
    let failed_keys = shutdown
        .failures()
        .iter()
        .map(|(key, _source)| *key)
        .collect::<Vec<_>>();
    assert_eq!(
        failed_keys,
        vec![first_key.template_key(), second_key.template_key()]
    );

    first_provider.restore(first_checked_out);
    second_provider.restore(second_checked_out);
    drop(first_provider);
    drop(second_provider);

    let demotions = shared.orderly_shutdown().expect("retire shared sources");
    assert_eq!(demotions.len(), 2);
    assert!(
        demotions
            .iter()
            .all(|demotion| demotion.reason() == HotCheckpointDemotionReason::DaemonShutdown)
    );
    drop(shared);

    let mut reopened =
        ManagedQemuHotForkSourceWorldPool::open(limits, ReapingDemotionSink, retention)
            .expect("reopen cold fallback inventory");
    assert_eq!(reopened.cold_fallbacks().count(), 2);

    let restarted_node = scripted_hot_fork_source_for_test(QemuTestHotForkOutcome::Forked)
        .expect("restarted source");
    let (_nodes, restarted_source) =
        prepared_multi_node_hot_fork_source_world_for_test(vec![restarted_node])
            .expect("restarted prepared source world");
    reopened
        .admit_authenticated_source(
            AuthenticatedCanonicalQemuHotForkSource::new_for_test(
                first_key.clone(),
                restarted_source,
            ),
            HotCheckpointHotnessSignals::new(),
            exact_fallback(0x47),
        )
        .expect("promote matching cold fallback to active after restart");

    assert_eq!(reopened.records.len(), 2);
    assert_eq!(reopened.cold_fallbacks().count(), 1);
    reopened
        .orderly_shutdown()
        .expect("retire restarted source");
    assert_eq!(reopened.cold_fallbacks().count(), 2);
}

fn compatibility_profile() -> ExecutorCompatibilityProfile {
    ExecutorCompatibilityProfile::new(
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        4,
    )
    .expect("compatibility profile")
}

fn lineage_id(byte: u8) -> CampaignLineageId {
    CampaignLineageId::parse(&format!(
        "crucible.campaign.lineage@campaign-fact.1.{}",
        format!("{byte:02x}").repeat(32)
    ))
    .expect("lineage id")
}

fn exact_fallback(byte: u8) -> HotCheckpointFallback {
    HotCheckpointFallback::Exact(
        ExactCheckpointId::parse(&format!(
            "crucible.executor.exact-checkpoint-root@exact-manifest.4.{}",
            format!("{byte:02x}").repeat(32)
        ))
        .expect("exact checkpoint id"),
    )
}
