//! Reproduced candidate handoffs checked against current local planning authority.
//!
//! Imported recommendations cannot replace locally retained discovery. The
//! planner requires the same clean source content, controller, declared policy
//! and complete component vector before selecting exact observed candidates.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use aos_assessment::action_intent::PackageUpdateIntentV1;
use aos_assessment::bundle::AssessmentBundleV1;
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use aos_maintain::discovery::{DiscoverySnapshotV1, select_unit};
use aos_maintain::envelope::InventoryEnvelopeV1;
use aos_maintain::identity::UnitId;
use aos_maintain::workflow::DiscoveryDecision;

pub(super) fn select_from_files(
    intent_path: &Path,
    evidence_path: &Path,
    envelope: &InventoryEnvelopeV1,
    snapshot: &mut DiscoverySnapshotV1,
    unit_id: &UnitId,
    now_unix: u64,
) -> Result<()> {
    let intent = PackageUpdateIntentV1::from_slice(&read_file(intent_path, 262_144)?)?;
    let bundle = AssessmentBundleV1::from_slice(&read_file(evidence_path, 16 * 1024 * 1024)?)?;
    intent.verify_for(&bundle, &Timestamp::from_unix_seconds(now_unix)?)?;
    ensure!(
        intent.unit_id == *unit_id,
        "assessment intent selects another update unit"
    );

    envelope.validate()?;
    let target = &envelope
        .target_evaluations
        .first()
        .context("local inventory has no evaluated target")?
        .target;
    let current = super::inventory::bind_evaluated(
        Path::new(&envelope.repository_root),
        serde_json::to_value(&envelope.inventory)?,
        target.clone(),
    )?;
    ensure!(
        current.content.permits_write_plan()
            && current.content == envelope.content
            && current.repository_root == envelope.repository_root
            && current.git_common_dir == envelope.git_common_dir
            && current.canonical_remote == envelope.canonical_remote
            && current.controller == envelope.controller,
        "assessment handoff requires the original clean checkout and controller; refresh inventory"
    );
    select_local_candidates(&intent, &bundle, envelope, snapshot, now_unix)
}

fn select_local_candidates(
    intent: &PackageUpdateIntentV1,
    bundle: &AssessmentBundleV1,
    envelope: &InventoryEnvelopeV1,
    snapshot: &mut DiscoverySnapshotV1,
    now_unix: u64,
) -> Result<()> {
    snapshot.validate()?;
    ensure!(
        snapshot.inventory_envelope_digest
            == Sha256Digest::of_canonical(
                aos_maintain::MAINTENANCE_INVENTORY_ENVELOPE_V1,
                envelope
            )?,
        "local discovery belongs to another inventory envelope"
    );
    ensure!(
        intent.source_content_digest
            == Sha256Digest::of_canonical("aos.source-content/v1", &envelope.content)?,
        "assessment handoff source content differs from the local clean base"
    );
    let unit = envelope
        .inventory
        .units
        .iter()
        .find(|unit| unit.unit_id == intent.unit_id)
        .context("assessment handoff unit is absent locally")?;
    let definition = bundle
        .data
        .definitions
        .iter()
        .find(|definition| definition.unit_id == intent.unit_id)
        .context("assessment handoff definition is absent")?;
    let subject = bundle
        .data
        .inventory
        .subjects
        .iter()
        .find(|subject| subject.subject_ref == intent.subject_ref)
        .context("assessment handoff source subject is absent")?;
    ensure!(
        unit.family == definition.family
            && unit.stream == definition.stream
            && unit.classification == definition.classification
            && unit.members == definition.members
            && unit.policy.lifecycle == definition.lifecycle
            && unit
                .package
                .as_ref()
                .is_some_and(|package| package.current_version == subject.version)
            && unit
                .package
                .as_ref()
                .map(|package| &package.version_projection)
                == definition.version_projection.as_ref()
            && unit.components.len() == intent.components.len(),
        "assessment handoff unit differs from local package policy or component scope"
    );

    let mut observations = BTreeMap::new();
    for recommended in &intent.components {
        let component = unit
            .components
            .get(&recommended.component_id)
            .context("assessment handoff component is absent locally")?;
        let declared = definition
            .components
            .iter()
            .find(|declared| declared.component_id == recommended.component_id)
            .context("assessment handoff component declaration is absent")?;
        ensure!(
            component.current == recommended.current
                && component.primary == declared.discovery.primary
                && component.advisors == declared.discovery.advisors
                && component.release_policy == declared.release_policy,
            "assessment handoff component differs from current local identity or discovery policy"
        );
        let key = format!("{}/{}/primary", unit.unit_id, recommended.component_id);
        let observation = snapshot
            .observations
            .get(&key)
            .context("assessment handoff requires independently retained local discovery")?;
        let mut selected = observation.clone();
        if recommended.target == recommended.current {
            // The complete local enumeration independently establishes whether
            // an unchanged component is known. No candidate is invented.
            selected.candidates.clear();
        } else {
            selected
                .candidates
                .retain(|candidate| candidate.raw_id == recommended.target.upstream_id);
            ensure!(
                selected.candidates.len() == 1,
                "assessment handoff candidate is absent or ambiguous in local discovery"
            );
        }
        observations.insert(recommended.component_id.to_string(), selected);
    }
    let selected = select_unit(unit, &observations, now_unix, 86400)?;
    ensure!(
        selected.decision == DiscoveryDecision::UpdateAvailable,
        "assessment handoff candidate vector is not locally eligible"
    );
    for recommended in &intent.components {
        let component = selected
            .components
            .iter()
            .find(|component| component.component == recommended.component_id.as_str())
            .context("locally selected handoff component is absent")?;
        let target = component.selected.as_ref().unwrap_or(&recommended.current);
        ensure!(
            *target == recommended.target,
            "local discovery selected a different raw or comparison identity"
        );
    }
    let retained = snapshot
        .units
        .iter_mut()
        .find(|retained| retained.unit_id == unit.unit_id.as_str())
        .context("local unit discovery is absent")?;
    *retained = selected;
    Ok(())
}

#[cfg(test)]
mod tests;

fn read_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit,
        "assessment handoff requires a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "assessment handoff input exceeded its read limit"
    );
    Ok(bytes)
}
