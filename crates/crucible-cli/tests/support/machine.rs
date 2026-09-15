//! Generic process-test artifact discovery helpers.

use super::*;

pub(super) fn savepoint_handle_text(
    form: &crucible::ScenarioDefForm,
    schedule: &crucible::Schedule,
    checkpoint: &crucible::Checkpoint,
) -> Result<String, Box<dyn Error>> {
    let scenario = form.scenario_def();
    let scenario_payload = form.to_compact_binary();
    let schedule_payload = schedule.to_compact_binary();
    let replay_closure = crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::from_canonical_bytes(
        b"CCRC\0\0\0\x01\0\0\0\0",
    )?;
    replay_closure.validate_for_schedule(form, schedule)?;
    let replay_closure = replay_closure.to_canonical_bytes()?;
    let boundary_predicate = crucible::Predicate::quiescent().to_compact_binary();
    let mut text = String::new();
    artifact_line(&mut text, &["schema", "crucible.savepoint-handle.v5"]);
    artifact_line(&mut text, &["label", "process-replay-to"]);
    artifact_line(
        &mut text,
        &[
            "checkpoint",
            &crucible::ContentAddressedBlobRef::from_hash(checkpoint.id).to_uri(),
        ],
    );
    artifact_line(
        &mut text,
        &[
            "campaign-replay-closure",
            &content_address_bytes(&replay_closure),
            &hex_bytes(&replay_closure),
        ],
    );
    artifact_line(
        &mut text,
        &["scenario", &scenario.id().to_hex(), "process-replay-to.scn"],
    );
    artifact_line(
        &mut text,
        &[
            "scenario-payload",
            &content_address_bytes(&scenario_payload),
            &hex_bytes(&scenario_payload),
        ],
    );
    artifact_line(
        &mut text,
        &[
            "schedule-payload",
            &content_address_bytes(&schedule_payload),
            &hex_bytes(&schedule_payload),
        ],
    );
    artifact_line(
        &mut text,
        &["frontier", &checkpoint.virtual_time.ticks.to_string()],
    );
    artifact_line(&mut text, &["at", "quiescence"]);
    artifact_line(&mut text, &["selector", "none"]);
    artifact_line(
        &mut text,
        &[
            "boundary-proof",
            "breakpoint",
            "1",
            "suspend",
            &checkpoint.virtual_time.ticks.to_string(),
            "1",
        ],
    );
    artifact_line(
        &mut text,
        &[
            "boundary-predicate",
            &content_address_bytes(&boundary_predicate),
            &hex_bytes(&boundary_predicate),
        ],
    );
    artifact_line(&mut text, &["terminal-condition", "quiescence"]);
    artifact_line(&mut text, &["materialization", "create-savepoint", "reply"]);
    artifact_line(&mut text, &["oracle", "fat==thin-passed"]);
    artifact_line(
        &mut text,
        &[
            "canonical-log",
            &content_address_bytes(b"process-replay-to-canonical-log"),
        ],
    );
    Ok(text)
}
