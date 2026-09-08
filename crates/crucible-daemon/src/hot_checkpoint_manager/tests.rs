//! Tests bounded hotness scoring and deterministic template retention decisions.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for precise failures.
#![allow(clippy::expect_used)]

use crucible::ContentHash;
use crucible_campaign::{CampaignLineageId, ConfigurationArtifactId};
use crucible_cas::content_store::{ContentId, ObjectKind};

use super::*;

#[test]
fn score_is_bounded_explainable_and_signed() {
    let signals = HotCheckpointHotnessSignals::new()
        .with_pending_attempts(20)
        .expect("pending")
        .with_expected_future_widening(30)
        .expect("widening")
        .with_descendant_continuations(40)
        .expect("descendants")
        .with_interactive_or_finding_value(50)
        .expect("pin value")
        .with_dirty_memory_pressure(60)
        .expect("dirty pressure")
        .with_descriptor_pressure(70)
        .expect("descriptor pressure")
        .with_restore_or_replay_cost_paid_elsewhere(80)
        .expect("paid cost")
        .with_pin(true);
    assert_eq!(signals.score().value(), -70);
    assert!(signals.pinned());

    let error = HotCheckpointHotnessSignals::new()
        .with_pending_attempts(MAX_HOT_CHECKPOINT_SCORE_COMPONENT + 1)
        .expect_err("bounded component");
    assert_eq!(
        error.component(),
        HotCheckpointHotnessComponent::PendingAttempts
    );
    assert_eq!(error.value(), MAX_HOT_CHECKPOINT_SCORE_COMPONENT + 1);
}

#[test]
fn within_budget_commit_accounts_every_resource_dimension() {
    let mut manager = manager(2, resources(20, 12, 2, 4, 30, 4), 3);
    let candidate = candidate(1, 10, false, resources(9, 5, 1, 2, 12, 2));
    let coordinate = slot(1, 0);
    let plan = manager
        .plan_admission(candidate)
        .expect("within-budget plan");
    assert!(plan.demotions().is_empty());
    let committed = manager
        .commit_admission(plan, coordinate)
        .expect("within-budget commit");

    assert_eq!(committed.retained().slot(), coordinate);
    assert_eq!(
        committed.retained().reason(),
        HotCheckpointRetentionReason::WithinBudget
    );
    assert!(committed.demoted().is_empty());
    assert_eq!(manager.retained().len(), 1);
    assert_eq!(manager.usage().templates(), 1);
    assert_eq!(manager.usage().template_bytes(), 9);
    assert_eq!(manager.usage().expected_private_dirty_bytes(), 5);
    assert_eq!(manager.usage().process_count(), 1);
    assert_eq!(manager.usage().virtual_cpu_count(), 2);
    assert_eq!(manager.usage().descriptor_count(), 12);
    assert_eq!(manager.usage().overlay_count(), 2);
}

#[test]
fn fallback_identity_survives_planning_and_inventory_commit() {
    let mut manager = manager(2, resources(20, 20, 2, 2, 20, 2), 4);
    let exact = exact_fallback(1);
    let thin = thin_fallback(2);
    assert_ne!(exact, exact_fallback(3));
    assert_eq!(exact.tier(), HotCheckpointFallbackTier::Exact);
    assert_eq!(thin.tier(), HotCheckpointFallbackTier::Thin);
    assert!(exact.exact_checkpoint().is_some());
    assert!(exact.thin_configuration().is_none());
    assert!(thin.exact_checkpoint().is_none());
    assert!(thin.thin_configuration().is_some());

    let candidate = HotCheckpointCandidate::new(key(1), unit_resources(), signals(1, false), thin);
    let plan = manager.plan_admission(candidate).expect("thin plan");
    let retained = manager
        .commit_admission(plan, slot(1, 0))
        .expect("thin commit")
        .retained();

    assert_eq!(retained.fallback(), thin);
    assert_eq!(manager.status(retained.slot()), Some(retained));
}

#[test]
fn pressure_demotes_the_coldest_exact_coordinate_deterministically() {
    let mut manager = manager(2, resources(20, 20, 2, 2, 20, 2), 4);
    let first_slot = slot(1, 0);
    let second_slot = slot(2, 0);
    retain(
        &mut manager,
        candidate(1, 5, false, unit_resources()),
        first_slot,
    );
    retain(
        &mut manager,
        candidate(2, 5, false, unit_resources()),
        second_slot,
    );

    let incoming = candidate(3, 6, false, unit_resources());
    let plan = manager.plan_admission(incoming).expect("colder victim");
    let expected = first_slot.min(second_slot);
    assert_eq!(plan.demotions().len(), 1);
    assert_eq!(plan.demotions()[0].slot(), expected);
    assert_eq!(
        plan.demotions()[0].reason(),
        HotCheckpointDemotionReason::CapacityPressure
    );
    let replacement = slot(3, 0);
    let committed = manager
        .commit_admission(plan, replacement)
        .expect("pressure commit");
    assert_eq!(committed.demoted()[0].status().slot(), expected);
    assert_eq!(
        committed.demoted()[0].reason(),
        HotCheckpointDemotionReason::CapacityPressure
    );
    assert_eq!(
        committed.retained().reason(),
        HotCheckpointRetentionReason::ReplacedColderSources
    );
    assert_eq!(manager.usage().templates(), 2);
    assert!(manager.status(expected).is_none());
    assert!(manager.status(replacement).is_some());

    let tied = manager
        .plan_admission(candidate(4, 5, false, unit_resources()))
        .expect_err("existing sources win score ties");
    assert!(matches!(
        tied,
        HotCheckpointAdmissionRejection::InsufficientDemotableCapacity { .. }
    ));
}

#[test]
fn pins_and_multi_resource_pressure_fail_closed_without_mutation() {
    let mut manager = manager(2, resources(10, 10, 2, 2, 10, 2), 4);
    let pinned = slot(1, 0);
    let cold = slot(2, 0);
    retain(
        &mut manager,
        candidate(1, 1, true, resources(5, 5, 1, 1, 5, 1)),
        pinned,
    );
    retain(
        &mut manager,
        candidate(2, 1, false, resources(5, 5, 1, 1, 5, 1)),
        cold,
    );
    let before_generation = manager.generation();
    let before_usage = manager.usage();

    let error = manager
        .plan_admission(candidate(3, 100, false, resources(6, 6, 2, 2, 6, 2)))
        .expect_err("pinned capacity remains unavailable");
    let (pressure, pinned_sources) = match error {
        HotCheckpointAdmissionRejection::InsufficientDemotableCapacity {
            pressure,
            pinned_sources,
        } => (pressure, pinned_sources),
        other => panic!("unexpected rejection: {other:?}"),
    };
    assert_eq!(pinned_sources, 1);
    assert!(!pressure.templates());
    assert!(pressure.template_bytes());
    assert!(pressure.expected_private_dirty_bytes());
    assert!(pressure.process_count());
    assert!(pressure.virtual_cpu_count());
    assert!(pressure.descriptor_count());
    assert!(pressure.overlay_count());
    assert!(pressure.any());
    assert_eq!(manager.generation(), before_generation);
    assert_eq!(manager.usage(), before_usage);
    assert!(manager.status(pinned).is_some());
    assert!(manager.status(cold).is_some());
}

#[test]
fn pinned_candidate_can_replace_unpinned_hotter_source() {
    let mut manager = manager(1, resources(10, 10, 1, 1, 10, 1), 2);
    let existing = slot(1, 0);
    retain(
        &mut manager,
        candidate(1, 100, false, unit_resources()),
        existing,
    );
    let plan = manager
        .plan_admission(candidate(2, -100, true, unit_resources()))
        .expect("hard pin outranks score");
    assert_eq!(plan.demotions()[0].slot(), existing);
}

#[test]
fn individual_limits_report_all_resource_dimensions_before_planning() {
    let manager = manager(1, resources(10, 10, 1, 1, 1, 1), 1);
    let error = manager
        .plan_admission(candidate(1, 1, false, resources(11, 11, 2, 2, 2, 2)))
        .expect_err("individual resource bound");
    let pressure = match error {
        HotCheckpointAdmissionRejection::IndividualLimit { pressure } => pressure,
        other => panic!("unexpected rejection: {other:?}"),
    };
    assert!(!pressure.templates());
    assert!(pressure.template_bytes());
    assert!(pressure.expected_private_dirty_bytes());
    assert!(pressure.process_count());
    assert!(pressure.virtual_cpu_count());
    assert!(pressure.descriptor_count());
    assert!(pressure.overlay_count());
}

#[test]
fn stale_foreign_wrong_key_and_occupied_commits_are_read_only() {
    let limits = limits(3, resources(30, 30, 3, 3, 30, 3), 3);
    let mut first = HotCheckpointManager::new(limits);
    let second = HotCheckpointManager::new(limits);
    let stale = first
        .plan_admission(candidate(1, 1, false, unit_resources()))
        .expect("stale plan");
    retain(
        &mut first,
        candidate(2, 2, false, unit_resources()),
        slot(2, 0),
    );
    let before = first.usage();
    assert!(matches!(
        first.commit_admission(stale, slot(1, 0)),
        Err(HotCheckpointAdmissionCommitError::StalePlan { .. })
    ));
    assert_eq!(first.usage(), before);

    let foreign = second
        .plan_admission(candidate(3, 3, false, unit_resources()))
        .expect("foreign plan");
    assert_eq!(
        first.commit_admission(foreign, slot(3, 0)),
        Err(HotCheckpointAdmissionCommitError::ForeignPlan)
    );
    assert_eq!(first.usage(), before);

    let wrong_key = first
        .plan_admission(candidate(4, 4, false, unit_resources()))
        .expect("wrong-key plan");
    assert_eq!(
        first.commit_admission(wrong_key, slot(5, 0)),
        Err(HotCheckpointAdmissionCommitError::WrongInstalledKey)
    );
    assert_eq!(first.usage(), before);

    let occupied = first
        .plan_admission(candidate(2, 5, false, unit_resources()))
        .expect("occupied-coordinate plan");
    assert_eq!(
        first.commit_admission(occupied, slot(2, 0)),
        Err(HotCheckpointAdmissionCommitError::OccupiedSlot)
    );
    assert_eq!(first.usage(), before);
}

#[test]
fn signal_refresh_invalidates_plans_and_changes_eviction_order() {
    let mut manager = manager(2, resources(20, 20, 2, 2, 20, 2), 2);
    let first = slot(1, 0);
    let second = slot(2, 0);
    retain(
        &mut manager,
        candidate(1, 1, false, unit_resources()),
        first,
    );
    retain(
        &mut manager,
        candidate(2, 2, false, unit_resources()),
        second,
    );
    let stale = manager
        .plan_admission(candidate(3, 10, false, unit_resources()))
        .expect("initial plan");
    let refreshed = signals(20, false);
    let status = manager
        .update_signals(first, refreshed)
        .expect("signal refresh");
    assert_eq!(
        status.reason(),
        HotCheckpointRetentionReason::SignalsUpdated
    );
    assert!(matches!(
        manager.commit_admission(stale, slot(3, 0)),
        Err(HotCheckpointAdmissionCommitError::StalePlan { .. })
    ));

    let plan = manager
        .plan_admission(candidate(3, 10, false, unit_resources()))
        .expect("recomputed plan");
    assert_eq!(plan.demotions()[0].slot(), second);
}

#[test]
fn orderly_demotion_releases_exact_accounting_and_coordinate() {
    let mut manager = manager(2, resources(20, 20, 2, 2, 20, 2), 2);
    let coordinate = slot(1, 0);
    retain(
        &mut manager,
        candidate(1, 1, false, resources(7, 3, 1, 1, 4, 0)),
        coordinate,
    );
    let plan = manager
        .plan_orderly_demotion(coordinate, HotCheckpointDemotionReason::OperatorRequest)
        .expect("orderly-demotion plan");
    assert_eq!(plan.status().slot(), coordinate);
    assert_eq!(plan.reason(), HotCheckpointDemotionReason::OperatorRequest);
    let removed = manager
        .commit_orderly_demotion(plan)
        .expect("orderly demotion");
    assert_eq!(removed.status().slot(), coordinate);
    assert_eq!(
        removed.status().fallback().tier(),
        HotCheckpointFallbackTier::Exact
    );
    assert_eq!(
        removed.reason(),
        HotCheckpointDemotionReason::OperatorRequest
    );
    assert_eq!(manager.usage(), HotCheckpointUsage::default());
    assert!(manager.status(coordinate).is_none());
    assert!(matches!(
        manager.plan_orderly_demotion(coordinate, HotCheckpointDemotionReason::OperatorRequest),
        Err(HotCheckpointInventoryError::MissingSlot)
    ));
}

#[test]
fn orderly_demotion_plan_is_foreign_and_generation_fenced() {
    let limits = limits(2, resources(20, 20, 2, 2, 20, 2), 2);
    let mut first = HotCheckpointManager::new(limits);
    let coordinate = slot(1, 0);
    retain(
        &mut first,
        candidate(1, 1, false, unit_resources()),
        coordinate,
    );
    let stale = first
        .plan_orderly_demotion(coordinate, HotCheckpointDemotionReason::DaemonShutdown)
        .expect("stale plan");
    first
        .update_signals(coordinate, signals(2, false))
        .expect("invalidate plan");
    assert!(matches!(
        first.commit_orderly_demotion(stale),
        Err(HotCheckpointInventoryError::StalePlan { .. })
    ));
    assert!(first.status(coordinate).is_some());

    let mut second = HotCheckpointManager::new(limits);
    retain(
        &mut second,
        candidate(1, 1, false, unit_resources()),
        coordinate,
    );
    let foreign = second
        .plan_orderly_demotion(coordinate, HotCheckpointDemotionReason::SourceInvalidated)
        .expect("foreign plan");
    assert_eq!(
        first.commit_orderly_demotion(foreign),
        Err(HotCheckpointInventoryError::ForeignPlan)
    );
    assert!(first.status(coordinate).is_some());
}

#[test]
fn fork_rate_is_sticky_bounded_and_monotonic() {
    let mut manager = manager(1, resources(10, 10, 1, 1, 10, 1), 2);
    let first = manager.admit_fork(70).expect("first fork");
    let second = manager.admit_fork(79).expect("second fork");
    assert!(first.belongs_to(&manager));
    assert_eq!((first.window(), first.ordinal()), (7, 1));
    assert_eq!((second.window(), second.ordinal()), (7, 2));
    assert_eq!(
        manager.admit_fork(79).map(|permit| permit.ordinal()),
        Err(HotCheckpointForkRateError::RateLimited {
            window: 7,
            maximum: 2,
        })
    );
    assert_eq!(
        manager.admit_fork(78).map(|permit| permit.ordinal()),
        Err(HotCheckpointForkRateError::StaleClock {
            requested: 78,
            current: 79,
        })
    );
    let next = manager.admit_fork(80).expect("new window");
    assert_eq!((next.window(), next.ordinal()), (8, 1));
}

#[test]
fn limits_match_the_static_pool_ceiling() {
    assert_eq!(
        HotCheckpointLimits::new(0, resources(1, 0, 1, 1, 1, 0), 1, 10),
        Err(HotCheckpointLimitsError::ZeroTemplates)
    );
    assert_eq!(
        HotCheckpointLimits::new(
            MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS + 1,
            resources(1, 0, 1, 1, 1, 0),
            1,
            10,
        ),
        Err(HotCheckpointLimitsError::TooManyTemplates {
            requested: MAX_QEMU_HOT_FORK_TEMPLATE_POOL_SLOTS + 1,
        })
    );
    assert_eq!(
        HotCheckpointLimits::new(1, resources(1, 0, 1, 1, 1, 0), 0, 10),
        Err(HotCheckpointLimitsError::ZeroForkRate)
    );
    assert_eq!(
        HotCheckpointLimits::new(1, resources(1, 0, 1, 1, 1, 0), 1, 0),
        Err(HotCheckpointLimitsError::ZeroForkRateWindow)
    );
}

#[test]
fn exhausted_generation_rejects_plans_before_external_work() {
    let mut manager = manager(1, unit_resources(), 1);
    manager.generation = u64::MAX;
    assert!(matches!(
        manager.plan_admission(candidate(1, 1, false, unit_resources())),
        Err(HotCheckpointAdmissionRejection::GenerationExhausted)
    ));

    manager.generation = 0;
    let coordinate = slot(1, 0);
    retain(
        &mut manager,
        candidate(1, 1, false, unit_resources()),
        coordinate,
    );
    manager.generation = u64::MAX;
    assert!(matches!(
        manager.plan_orderly_demotion(coordinate, HotCheckpointDemotionReason::OperatorRequest),
        Err(HotCheckpointInventoryError::GenerationExhausted)
    ));
    assert!(manager.status(coordinate).is_some());
}

#[test]
fn ten_thousand_admissions_under_capacity_pressure_stay_bounded_and_secured() {
    // Every lifecycle retains a source hotter than all before it under a
    // four-template ceiling, so from the fifth on each admission must demote
    // exactly the coldest retained source and carry that source's secured
    // fallback; the inventory never grows past the ceiling.
    const LIFECYCLES: usize = 10_000;
    const CEILING: usize = 4;
    // Keys cycle through 250 bytes, far beyond the ceiling, so a reused key's
    // earlier coordinate was demoted long before the key returns.
    const KEY_CYCLE: usize = 250;
    let key_byte = |lifecycle: usize| u8::try_from(lifecycle % KEY_CYCLE + 1).expect("key byte");

    let mut manager = manager(CEILING, resources(40, 40, 4, 4, 40, 4), 1);
    let mut demoted = 0;
    for lifecycle in 0..LIFECYCLES {
        let byte = key_byte(lifecycle);
        let score = i64::try_from(lifecycle).expect("score");
        let nanos = u64::try_from(lifecycle).expect("clock") * 10;
        let _permit = manager
            .admit_fork(nanos)
            .expect("one fork start per rate window");

        let plan = manager
            .plan_admission(candidate(byte, score, false, unit_resources()))
            .expect("a strictly hotter candidate always admits");
        if lifecycle < CEILING {
            assert!(plan.demotions().is_empty());
        } else {
            assert_eq!(plan.demotions().len(), 1);
            let victim = plan.demotions()[0];
            assert_eq!(
                victim.reason(),
                HotCheckpointDemotionReason::CapacityPressure
            );
            let coldest = key_byte(lifecycle - CEILING);
            assert_eq!(victim.slot(), slot(coldest, 0));
            assert_eq!(victim.fallback(), exact_fallback(coldest));
        }

        let committed = manager
            .commit_admission(plan, slot(byte, 0))
            .expect("pressure commit");
        demoted += committed.demoted().len();
        assert!(manager.usage().templates() <= CEILING);
        assert!(manager.retained().len() <= CEILING);
    }

    assert_eq!(manager.usage().templates(), CEILING);
    assert_eq!(demoted, LIFECYCLES - CEILING);
    let mut retained: Vec<_> = manager.retained().map(|status| status.slot()).collect();
    retained.sort();
    let mut expected: Vec<_> = (LIFECYCLES - CEILING..LIFECYCLES)
        .map(|lifecycle| slot(key_byte(lifecycle), 0))
        .collect();
    expected.sort();
    assert_eq!(retained, expected);
}

fn manager(
    maximum_templates: usize,
    maximum_resources: HotCheckpointResourceProfile,
    maximum_forks_per_window: u32,
) -> HotCheckpointManager {
    HotCheckpointManager::new(limits(
        maximum_templates,
        maximum_resources,
        maximum_forks_per_window,
    ))
}

fn limits(
    maximum_templates: usize,
    maximum_resources: HotCheckpointResourceProfile,
    maximum_forks_per_window: u32,
) -> HotCheckpointLimits {
    HotCheckpointLimits::new(
        maximum_templates,
        maximum_resources,
        maximum_forks_per_window,
        10,
    )
    .expect("limits")
}

fn resources(
    template_bytes: u64,
    expected_private_dirty_bytes: u64,
    process_count: u32,
    virtual_cpu_count: u32,
    descriptor_count: u32,
    overlay_count: u32,
) -> HotCheckpointResourceProfile {
    HotCheckpointResourceProfile::new(
        template_bytes,
        expected_private_dirty_bytes,
        process_count,
        virtual_cpu_count,
        descriptor_count,
        overlay_count,
    )
    .expect("resources")
}

fn unit_resources() -> HotCheckpointResourceProfile {
    resources(10, 10, 1, 1, 10, 1)
}

fn candidate(
    byte: u8,
    score: i64,
    pinned: bool,
    resources: HotCheckpointResourceProfile,
) -> HotCheckpointCandidate {
    HotCheckpointCandidate::new(
        key(byte),
        resources,
        signals(score, pinned),
        exact_fallback(byte),
    )
}

fn exact_fallback(byte: u8) -> HotCheckpointFallback {
    HotCheckpointFallback::Exact(
        ExactCheckpointId::try_from(ContentId::for_bytes(ObjectKind::ExactManifest, 4, &[byte]))
            .expect("exact fallback"),
    )
}

fn thin_fallback(byte: u8) -> HotCheckpointFallback {
    let content = ContentId::for_bytes(ObjectKind::Configuration, 1, &[byte]);
    HotCheckpointFallback::Thin(
        ConfigurationArtifactId::parse(&format!(
            "crucible.campaign.configuration-artifact@{}",
            content.encode()
        ))
        .expect("thin fallback"),
    )
}

fn signals(score: i64, pinned: bool) -> HotCheckpointHotnessSignals {
    let signals = if score >= 0 {
        HotCheckpointHotnessSignals::new()
            .with_pending_attempts(score.unsigned_abs())
            .expect("positive score")
    } else {
        HotCheckpointHotnessSignals::new()
            .with_dirty_memory_pressure(score.unsigned_abs())
            .expect("negative score")
    };
    signals.with_pin(pinned)
}

fn retain(
    manager: &mut HotCheckpointManager,
    candidate: HotCheckpointCandidate,
    coordinate: QemuHotForkTemplatePoolSlot,
) {
    let plan = manager.plan_admission(candidate).expect("retention plan");
    assert!(plan.demotions().is_empty());
    manager
        .commit_admission(plan, coordinate)
        .expect("retention commit");
}

fn slot(byte: u8, index: usize) -> QemuHotForkTemplatePoolSlot {
    QemuHotForkTemplatePoolSlot::new(key(byte), index)
}

fn key(byte: u8) -> QemuHotForkTemplateKey {
    let content = ContentId::for_bytes(ObjectKind::CampaignFact, 1, &[byte]);
    let lineage =
        CampaignLineageId::parse(&format!("crucible.campaign.lineage@{}", content.encode()))
            .expect("lineage ID");
    QemuHotForkTemplateKey::new(lineage, ContentHash::from_bytes(&[byte]))
}
