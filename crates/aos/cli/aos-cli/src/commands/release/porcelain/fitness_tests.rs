//! Fitness age math and binding comparison.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use aos_release_format::fitness::FITNESS_ATTESTATION;
use aos_release_format::plan::{PlannedDestination, RolloutRing, SurfaceKind, SurfaceRole};
use aos_release_format::qualification_evidence::CheckObservation;

use super::*;
use crate::commands::release::porcelain::testing::contract;

const DAY: u64 = 86_400;

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000)
}

fn at(days_ago: u64) -> String {
    humantime::format_rfc3339_seconds(now() - Duration::from_secs(days_ago * DAY)).to_string()
}

fn live() -> LiveBindings {
    LiveBindings {
        registry: "andyl/main".to_owned(),
        surface: Some("cdn-2026-09".to_owned()),
        surface_kind: Some(SurfaceKind::Static),
        hub_schema: None,
        signer_roster: Some(Sha256Digest::of_bytes("roster")),
        tooling: Some(Sha256Digest::of_bytes("tooling")),
        alert_config: Some(Sha256Digest::of_bytes("alert")),
    }
}

fn attestation(
    kind: &FitnessKind,
    performed_at: String,
    live: &LiveBindings,
) -> anyhow::Result<FitnessAttestation> {
    Ok(FitnessAttestation {
        schema_version: FITNESS_ATTESTATION.to_owned(),
        kind: kind.kind.clone(),
        registry: live.registry.clone(),
        performed_at,
        checks: kind
            .checks
            .iter()
            .map(|check| {
                (
                    check.clone(),
                    CheckObservation {
                        passed: true,
                        detail: "observed".to_owned(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
        bindings: live.recorded(kind)?,
        evidence_digest: Sha256Digest::of_bytes("report"),
        operator: "oncall".to_owned(),
        authority_id: "evidence-1".to_owned(),
    })
}

fn destination(name: &str, profile: &str) -> PlannedDestination {
    PlannedDestination {
        name: name.to_owned(),
        surface: SurfaceRole::Production,
        channel: name.rsplit('/').next().unwrap_or_default().to_owned(),
        profile: profile.to_owned(),
        profile_digest: Sha256Digest::of_bytes(profile),
        soak_seconds: 0,
        gates: Vec::new(),
        rings: vec![RolloutRing {
            partitions: 256,
            observe_seconds: 0,
        }],
    }
}

#[test]
fn age_is_whole_seconds_and_future_times_fail() -> anyhow::Result<()> {
    assert_eq!(age_seconds(&at(3), now())?, 3 * DAY);
    assert!(age_seconds(&at(0), now() - Duration::from_secs(1)).is_err());
    assert!(age_seconds("yesterday", now()).is_err());
    assert!(is_fresh(14 * DAY, 14 * DAY));
    assert!(!is_fresh(14 * DAY + 1, 14 * DAY));
    assert_eq!(format_age(3 * DAY + 4 * 3_600 + 59), "3d 4h");
    assert_eq!(format_age(2 * 3_600 + 5 * 60), "2h 5m");
    assert_eq!(format_age(59), "0m");
    Ok(())
}

#[test]
fn newest_attestation_decides_freshness_per_profile() -> anyhow::Result<()> {
    let contract = contract()?;
    let kind = contract.fitness_kind("storage-restore")?.clone();
    let live = live();
    let destinations = [
        destination("production/candidate", "functional"),
        destination("production/stable", "soak"),
    ];
    let max = contract
        .profile("functional")?
        .fitness
        .get("storage-restore")
        .map(|demand| demand.max_age_seconds)
        .unwrap_or_default();
    let days = max / DAY;

    let fresh = attestation(&kind, at(days - 1), &live)?;
    let old = attestation(&kind, at(days + 30), &live)?;
    let status = kind_status(
        &contract,
        &destinations,
        &kind,
        &[old.clone(), fresh],
        &live,
        now(),
    )?;
    assert_eq!(status.newest, Some((at(days - 1), (days - 1) * DAY)));
    assert!(status.demands.iter().all(|(_, _, fresh)| *fresh));
    assert!(status.bindings.iter().all(|(_, matches)| *matches));
    assert!(status.destinations.iter().all(|(_, satisfied)| *satisfied));

    let expired = kind_status(&contract, &destinations, &kind, &[old], &live, now())?;
    assert!(expired.demands.iter().all(|(_, _, fresh)| !*fresh));
    assert!(
        expired
            .destinations
            .iter()
            .all(|(_, satisfied)| !*satisfied)
    );
    let lines = render_status(&[expired]);
    assert!(lines[0].starts_with("storage-restore: performed"));
    assert!(lines.iter().any(|line| line.contains("expired")));
    assert!(
        lines
            .iter()
            .any(|line| line == "  blocks production/stable")
    );
    Ok(())
}

#[test]
fn a_changed_live_identity_invalidates_the_binding() -> anyhow::Result<()> {
    let contract = contract()?;
    let kind = contract.fitness_kind("storage-restore")?.clone();
    let recorded = attestation(&kind, at(1), &live())?;
    let mut changed = live();
    changed.tooling = Some(Sha256Digest::of_bytes("new tooling"));
    let status = kind_status(
        &contract,
        &[destination("production/candidate", "functional")],
        &kind,
        &[recorded],
        &changed,
        now(),
    )?;
    assert!(status.bindings.iter().any(|(_, matches)| !*matches));
    assert_eq!(
        status.destinations,
        [("production/candidate".to_owned(), false)]
    );

    let missing = kind_status(&contract, &[], &kind, &[], &live(), now())?;
    assert_eq!(missing.newest, None);
    assert_eq!(
        render_status(&[missing])[0],
        "storage-restore: no attestation"
    );
    Ok(())
}

#[test]
fn context_needs_no_plan_when_a_contract_export_exists() -> anyhow::Result<()> {
    use super::super::testing::config_fixture;
    use super::super::workdir::{ReleaseIndex, WORK_INDEX};

    let fixture = config_fixture()?;
    let work = WorkDir::new(&fixture.config.work_root.join("release-1"))?;
    std::fs::create_dir_all(work.root())?;
    work.create_index(&ReleaseIndex {
        schema_version: WORK_INDEX.to_owned(),
        registry: fixture.config.registry.clone(),
        version: "2026.9.0-dev.20260929.1".to_owned(),
        release_id: "release-2026.9.0-dev.20260929.1".to_owned(),
        config_digest: Sha256Digest::of_bytes("config").to_string(),
        created_at: "2026-09-29T00:00:00Z".to_owned(),
        latest_journal: None,
    })?;
    let exported = contract()?;
    std::fs::write(work.contract(), canonical::to_vec(&exported)?)?;

    // Without a frozen plan, the exported contract and configured roster apply.
    let context = FitnessContext::load(&fixture.config)?;
    assert_eq!(context.contract, exported);
    assert!(context.destinations.is_empty());
    assert_eq!(context.evidence_keys, ["evidence-1", "evidence-2"]);

    // Without a configured roster, only a plan could supply one.
    let mut unrostered = fixture.config.clone();
    unrostered.signer.roles.remove("release-evidence");
    let Err(error) = FitnessContext::load(&unrostered) else {
        panic!("a plan-less context without a configured roster must fail");
    };
    assert!(error.to_string().contains("release-evidence roster"));
    Ok(())
}
