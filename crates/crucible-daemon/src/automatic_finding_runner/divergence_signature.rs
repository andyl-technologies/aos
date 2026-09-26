//! Canonical signatures for native QEMU divergence findings.

use crucible::FailureClusterReportDivergence;
use crucible_campaign::{CampaignHash, ScenarioDefId};

/// Derives the normalized campaign fingerprint for one native divergence source.
pub(crate) fn divergence_fingerprint_for_scenario(
    scenario: ScenarioDefId,
    divergence: &FailureClusterReportDivergence,
) -> CampaignHash {
    let node = divergence
        .node
        .as_ref()
        .map_or("", |node| node.name.as_str());
    let kind = CampaignHash::derive(
        "crucible.daemon.qemu-causal-divergence-kind.v1",
        divergence.kind.as_bytes(),
    );
    let node = CampaignHash::derive(
        "crucible.daemon.qemu-causal-divergence-node.v1",
        node.as_bytes(),
    );

    let mut material = Vec::with_capacity(96);
    material.extend_from_slice(&scenario.as_hash().as_bytes());
    material.extend_from_slice(&kind.as_bytes());
    material.extend_from_slice(&node.as_bytes());
    CampaignHash::derive(
        "crucible.daemon.qemu-causal-divergence-fingerprint.v1",
        &material,
    )
}
