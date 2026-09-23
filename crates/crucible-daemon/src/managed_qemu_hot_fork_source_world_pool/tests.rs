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
        _key: HotCheckpointPoolKey,
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

#[path = "tests/admission.rs"]
mod admission;
#[path = "tests/leases.rs"]
mod leases;

#[test]
fn managed_demotion_preserves_the_concrete_source_failure_diagnostic() {
    let error = ManagedQemuHotForkSourceWorldDemotionError::Demotion(
        QemuHotForkSourceWorldDemotionError::Unavailable,
    );
    let source = std::error::Error::source(&error).expect("demotion diagnostic source");

    assert_eq!(
        source.to_string(),
        "source world is unavailable for orderly demotion"
    );
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
    HotCheckpointFallback::Exact(exact_checkpoint(byte))
}

fn exact_checkpoint(byte: u8) -> ExactCheckpointId {
    ExactCheckpointId::parse(&format!(
        "crucible.executor.exact-checkpoint-root@exact-manifest.5.{}",
        format!("{byte:02x}").repeat(32)
    ))
    .expect("exact checkpoint id")
}
