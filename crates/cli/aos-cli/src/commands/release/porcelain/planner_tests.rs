//! Next-step computation over synthetic journal summaries and layouts.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use aos_release_format::plan::SurfaceRole;
use aos_release_format::platform::Platform;
use aos_release_format::state::ReleaseState;

use super::*;

const HOUR: Duration = Duration::from_secs(3_600);

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000)
}

fn options() -> Options {
    Options {
        accept_transaction: false,
        ring_limit: None,
        now: now(),
    }
}

fn finalized_release() -> ReleaseFacts {
    ReleaseFacts {
        global: Some(ReleaseState::Finalized),
        verified: true,
        ..ReleaseFacts::default()
    }
}

fn built_release() -> ReleaseFacts {
    ReleaseFacts {
        global: Some(ReleaseState::Built),
        images: vec![ImageFact {
            system_variant: "server".to_owned(),
            platform: Platform::X86_64Linux,
            output: Output::Complete,
        }],
        source_registry_input: true,
        ..ReleaseFacts::default()
    }
}

fn staging() -> DestinationFacts {
    DestinationFacts {
        name: "staging/edge".to_owned(),
        surface: SurfaceRole::Staging,
        state: None,
        after_blocker: None,
        bootstrap_blocker: None,
        fitness_blocker: None,
        surface_metadata: None,
        review_threshold: 0,
        phases: BTreeMap::new(),
        ring_observations: vec![0],
        advanced: Vec::new(),
        published_at: None,
        soak_seconds: 0,
        requires_completion: false,
        completion_threshold: 2,
        completion_approvals: 0,
    }
}

fn stable() -> DestinationFacts {
    DestinationFacts {
        name: "production/stable".to_owned(),
        surface: SurfaceRole::Production,
        review_threshold: 1,
        ring_observations: vec![86_400, 172_800, 0],
        soak_seconds: 604_800,
        requires_completion: true,
        ..staging()
    }
}

fn run(step: Step) -> Next {
    Next::Run(step)
}

fn waits(next: &Next, fragment: &str) -> bool {
    matches!(next, Next::Wait(text) if text.contains(fragment))
}

#[test]
fn a_new_release_builds_first() -> anyhow::Result<()> {
    assert_eq!(
        next(&ReleaseFacts::default(), &staging(), &options())?,
        run(Step::Build)
    );
    Ok(())
}

#[test]
fn built_releases_finalize_images_then_sign_and_assemble_in_order() -> anyhow::Result<()> {
    let mut release = built_release();
    release.images[0].output = Output::Absent;
    assert_eq!(
        next(&release, &staging(), &options())?,
        run(Step::FinalizeImage {
            system_variant: "server".to_owned(),
            platform: Platform::X86_64Linux,
        })
    );

    release.images[0].output = Output::Incomplete;
    assert!(next(&release, &staging(), &options()).is_err());

    release.images[0].output = Output::Complete;
    release.container_required = true;
    assert!(waits(
        &next(&release, &staging(), &options())?,
        "inputs/container/"
    ));

    release.container_input = true;
    release.source_registry_input = false;
    assert!(waits(
        &next(&release, &staging(), &options())?,
        "inputs/source-registry/"
    ));

    release.source_registry_input = true;
    assert_eq!(
        next(&release, &staging(), &options())?,
        run(Step::PrepareRegistry)
    );

    release.registry_prepared = true;
    assert_eq!(
        next(&release, &staging(), &options())?,
        run(Step::FinalizeRegistry)
    );

    release.registry_finalized = true;
    assert_eq!(
        next(&release, &staging(), &options())?,
        run(Step::FinalizeCache)
    );

    release.cache = true;
    assert!(waits(
        &next(&release, &staging(), &options())?,
        "inputs/advisory-disposition.json"
    ));

    release.advisory_input = true;
    assert_eq!(next(&release, &staging(), &options())?, run(Step::Assemble));

    release.assembled = true;
    assert_eq!(next(&release, &staging(), &options())?, run(Step::Finalize));

    release.global = Some(ReleaseState::Finalized);
    assert_eq!(next(&release, &staging(), &options())?, run(Step::Verify));
    Ok(())
}

#[test]
fn transaction_review_stops_until_accepted() -> anyhow::Result<()> {
    let mut release = built_release();
    release.registry_prepared = true;
    release.transaction_review_required = true;
    let waiting = next(&release, &staging(), &options())?;
    assert!(waits(&waiting, "--accept-transaction"));

    let accepting = Options {
        accept_transaction: true,
        ..options()
    };
    assert_eq!(
        next(&release, &staging(), &accepting)?,
        run(Step::AcceptTransaction)
    );

    release.transaction_accepted = true;
    assert_eq!(
        next(&release, &staging(), &options())?,
        run(Step::FinalizeRegistry)
    );
    Ok(())
}

#[test]
fn staging_destinations_publish_then_advance_their_single_ring() -> anyhow::Result<()> {
    let release = finalized_release();
    let mut destination = staging();
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::Publish)
    );

    destination.state = Some(ReleaseState::Published);
    destination.published_at = Some(now());
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::AdvanceRing(1))
    );

    destination.state = Some(ReleaseState::Complete);
    assert!(matches!(
        next(&release, &destination, &options())?,
        Next::Done(_)
    ));

    // A final ring that left the destination rolling contradicts the profile.
    destination.state = Some(ReleaseState::Rolling);
    destination.advanced = vec![AdvancedRing {
        ring: 1,
        committed_at: now(),
    }];
    assert!(next(&release, &destination, &options()).is_err());
    Ok(())
}

#[test]
fn first_release_publication_waits_for_the_surface_bootstrap() -> anyhow::Result<()> {
    let release = finalized_release();
    let instruction =
        "bootstrap the staging surface with step bootstrap --output bootstrap/staging";

    let mut destination = staging();
    destination.bootstrap_blocker = Some(instruction.to_owned());
    assert!(waits(
        &next(&release, &destination, &options())?,
        "bootstrap/staging"
    ));

    // The production surface waits before its staging-phase qualification,
    // which would otherwise read an unbootstrapped surface's state.
    let mut production = stable();
    production.bootstrap_blocker = Some(instruction.replace("staging", "production"));
    assert!(waits(
        &next(&release, &production, &options())?,
        "bootstrap/production"
    ));

    // An unmet `after` dependency is reported first.
    production.after_blocker = Some("publish a staging destination first".to_owned());
    assert!(waits(
        &next(&release, &production, &options())?,
        "staging destination first"
    ));

    destination.bootstrap_blocker = None;
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::Publish)
    );
    Ok(())
}

#[test]
fn production_publication_requires_after_reviewed_staging_evidence_and_fitness()
-> anyhow::Result<()> {
    let release = finalized_release();
    let mut destination = stable();
    destination.after_blocker = Some("publish a staging destination first".to_owned());
    assert!(waits(
        &next(&release, &destination, &options())?,
        "staging destination first"
    ));

    destination.after_blocker = None;
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::Collect(Phase::Staging))
    );

    destination.phases.insert(
        Phase::Staging,
        PhaseFacts {
            has_cases: true,
            prepared: true,
            ..PhaseFacts::default()
        },
    );
    let waiting = next(&release, &destination, &options())?;
    assert!(waits(&waiting, "1 reviewer signature(s)"));
    assert!(waits(
        &waiting,
        "qualification/production-stable/staging/prepared/"
    ));

    destination.phases.insert(
        Phase::Staging,
        PhaseFacts {
            has_cases: true,
            prepared: true,
            rejected: true,
            ..PhaseFacts::default()
        },
    );
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::Retire(Phase::Staging))
    );

    destination.phases.insert(
        Phase::Staging,
        PhaseFacts {
            has_cases: true,
            prepared: true,
            accepted_reviews: 1,
            ..PhaseFacts::default()
        },
    );
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::Admit(Phase::Staging))
    );

    destination.phases.insert(
        Phase::Staging,
        PhaseFacts {
            has_cases: true,
            prepared: true,
            accepted_reviews: 1,
            signed: true,
            ..PhaseFacts::default()
        },
    );
    destination.fitness_blocker = Some("production/stable requires fresh key-rotation".into());
    assert!(waits(
        &next(&release, &destination, &options())?,
        "aos maintain release fitness run"
    ));

    destination.fitness_blocker = None;
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::Publish)
    );
    Ok(())
}

fn published_stable() -> DestinationFacts {
    let mut destination = stable();
    destination.state = Some(ReleaseState::Published);
    destination.published_at = Some(now() - 10 * 24 * HOUR);
    destination.phases.insert(
        Phase::Staging,
        PhaseFacts {
            has_cases: true,
            prepared: true,
            accepted_reviews: 1,
            signed: true,
            ..PhaseFacts::default()
        },
    );
    for ring in 1..=3 {
        destination.phases.insert(
            Phase::Rollout(ring),
            PhaseFacts {
                has_cases: true,
                ..PhaseFacts::default()
            },
        );
    }
    destination.phases.insert(
        Phase::Complete,
        PhaseFacts {
            has_cases: true,
            ..PhaseFacts::default()
        },
    );
    destination
}

#[test]
fn rings_wait_for_observation_and_rollout_qualification() -> anyhow::Result<()> {
    let release = finalized_release();
    let mut destination = published_stable();
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::Collect(Phase::Rollout(1)))
    );

    destination.phases.insert(
        Phase::Rollout(1),
        PhaseFacts {
            has_cases: true,
            prepared: true,
            accepted_reviews: 1,
            signed: true,
            ..PhaseFacts::default()
        },
    );
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::AdvanceRing(1))
    );

    // Ring 1 committed an hour ago; its 24-hour window has not elapsed.
    destination.state = Some(ReleaseState::Rolling);
    destination.advanced.push(AdvancedRing {
        ring: 1,
        committed_at: now() - HOUR,
    });
    let waiting = next(&release, &destination, &options())?;
    assert!(waits(
        &waiting,
        "ring 1 of production/stable observation until"
    ));

    let later = Options {
        now: now() + 24 * HOUR,
        ..options()
    };
    assert_eq!(
        next(&release, &destination, &later)?,
        run(Step::Collect(Phase::Rollout(2)))
    );

    let limited = Options {
        ring_limit: Some(1),
        ..later
    };
    assert_eq!(
        next(&release, &destination, &limited)?,
        Next::Done("stopped after ring 1 of production/stable".to_owned())
    );
    Ok(())
}

#[test]
fn rings_without_rollout_cases_advance_directly() -> anyhow::Result<()> {
    let release = finalized_release();
    let mut destination = published_stable();
    destination.phases.remove(&Phase::Rollout(1));
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::AdvanceRing(1))
    );
    Ok(())
}

#[test]
fn qualified_destinations_soak_then_collect_approvals_and_complete() -> anyhow::Result<()> {
    let release = finalized_release();
    let mut destination = published_stable();
    destination.state = Some(ReleaseState::Rolling);
    destination.advanced = (1..=3)
        .map(|ring| AdvancedRing {
            ring,
            committed_at: now() - 5 * 24 * HOUR,
        })
        .collect();

    destination.published_at = Some(now() - HOUR);
    assert!(waits(
        &next(&release, &destination, &options())?,
        "soak of production/stable until"
    ));

    destination.published_at = Some(now() - 8 * 24 * HOUR);
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::Collect(Phase::Complete))
    );

    destination.phases.insert(
        Phase::Complete,
        PhaseFacts {
            has_cases: true,
            prepared: true,
            accepted_reviews: 1,
            signed: true,
            ..PhaseFacts::default()
        },
    );
    destination.completion_approvals = 1;
    assert!(waits(
        &next(&release, &destination, &options())?,
        "1 completion approval(s) needed"
    ));

    destination.completion_approvals = 2;
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::Complete)
    );
    Ok(())
}

#[test]
fn failed_journals_stop_the_driver() {
    let release = ReleaseFacts {
        global: Some(ReleaseState::Failed),
        ..ReleaseFacts::default()
    };
    assert!(next(&release, &staging(), &options()).is_err());
}

#[test]
fn stale_admissions_are_retired_and_recollected() -> anyhow::Result<()> {
    let release = finalized_release();
    let mut destination = published_stable();
    destination.phases.insert(
        Phase::Rollout(1),
        PhaseFacts {
            has_cases: true,
            prepared: true,
            accepted_reviews: 1,
            signed: true,
            stale: true,
            ..PhaseFacts::default()
        },
    );
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::Retire(Phase::Rollout(1)))
    );

    // A signed admission is used even if a reviewer later rejected the report.
    destination.phases.insert(
        Phase::Rollout(1),
        PhaseFacts {
            has_cases: true,
            prepared: true,
            accepted_reviews: 1,
            signed: true,
            rejected: true,
            ..PhaseFacts::default()
        },
    );
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::AdvanceRing(1))
    );
    Ok(())
}

/// Surface metadata of a destination that publishes first on its surface.
fn owns_metadata(record_required: bool) -> Option<SurfaceMetadataFacts> {
    Some(SurfaceMetadataFacts {
        record_required,
        ..SurfaceMetadataFacts::default()
    })
}

/// Returns the destination's surface-metadata facts for in-place edits.
fn metadata(destination: &mut DestinationFacts) -> &mut SurfaceMetadataFacts {
    destination
        .surface_metadata
        .as_mut()
        .expect("destination owns surface metadata")
}

#[test]
fn first_staging_publication_carries_tuf_metadata_then_publishes_its_timestamp()
-> anyhow::Result<()> {
    let release = finalized_release();
    let mut destination = staging();
    destination.surface_metadata = owns_metadata(false);
    assert_eq!(next(&release, &destination, &options())?, run(Step::Tuf));

    metadata(&mut destination).tuf = true;
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::RefreshTimestamp)
    );

    metadata(&mut destination).timestamp_expires = Some(now() + 47 * HOUR);
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::ComposeSurface)
    );

    metadata(&mut destination).composed = true;
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::Publish)
    );

    assert!(super::super::advance::publication_step(&Step::Publish));

    // The timestamp moves only after the immutable metadata is served.
    destination.state = Some(ReleaseState::Published);
    destination.published_at = Some(now());
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::PublishTimestamp)
    );

    assert!(super::super::advance::publication_step(
        &Step::PublishTimestamp
    ));

    metadata(&mut destination).timestamp_published = true;
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::AdvanceRing(1))
    );
    assert!(!super::super::advance::publication_step(
        &Step::AdvanceRing(1)
    ));
    Ok(())
}

#[test]
fn first_production_publication_records_after_signed_staging_and_fitness() -> anyhow::Result<()> {
    let release = finalized_release();
    let mut destination = stable();
    destination.surface_metadata = owns_metadata(true);
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::Collect(Phase::Staging))
    );

    destination.phases.insert(
        Phase::Staging,
        PhaseFacts {
            has_cases: true,
            prepared: true,
            accepted_reviews: 1,
            signed: true,
            ..PhaseFacts::default()
        },
    );
    destination.fitness_blocker = Some("production/stable requires fresh key-rotation".into());
    assert!(waits(
        &next(&release, &destination, &options())?,
        "aos maintain release fitness run"
    ));

    destination.fitness_blocker = None;
    assert_eq!(next(&release, &destination, &options())?, run(Step::Record));

    metadata(&mut destination).record = true;
    assert_eq!(next(&release, &destination, &options())?, run(Step::Tuf));
    Ok(())
}

#[test]
fn a_destination_reusing_its_surface_publishes_without_metadata() -> anyhow::Result<()> {
    let release = finalized_release();
    let mut destination = stable();
    destination.phases.insert(
        Phase::Staging,
        PhaseFacts {
            has_cases: true,
            signed: true,
            ..PhaseFacts::default()
        },
    );
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::Publish)
    );
    Ok(())
}

#[test]
fn expiring_timestamps_are_retired_before_and_after_publication() -> anyhow::Result<()> {
    let release = finalized_release();
    let mut destination = staging();
    destination.surface_metadata = Some(SurfaceMetadataFacts {
        tuf: true,
        timestamp_expires: Some(now() + HOUR / 2),
        composed: true,
        ..SurfaceMetadataFacts::default()
    });
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::RetireTimestamp)
    );

    // After publication the successor is signed and composed again before
    // the pointer moves.
    destination.state = Some(ReleaseState::Published);
    destination.published_at = Some(now());
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::RetireTimestamp)
    );
    *metadata(&mut destination) = SurfaceMetadataFacts {
        tuf: true,
        ..SurfaceMetadataFacts::default()
    };
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::RefreshTimestamp)
    );
    metadata(&mut destination).timestamp_expires = Some(now() + 48 * HOUR);
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::ComposeSurface)
    );
    Ok(())
}

#[test]
fn missing_tuf_configuration_waits_with_the_key_name() -> anyhow::Result<()> {
    let release = finalized_release();
    let mut destination = staging();
    destination.surface_metadata = Some(SurfaceMetadataFacts {
        missing_config: Some("[signer.roles.tuf-snapshot]".to_owned()),
        ..SurfaceMetadataFacts::default()
    });
    let waiting = next(&release, &destination, &options())?;
    assert!(waits(&waiting, "configure [signer.roles.tuf-snapshot]"));

    // A published timestamp needs no further configuration.
    destination.state = Some(ReleaseState::Published);
    destination.published_at = Some(now());
    metadata(&mut destination).timestamp_published = true;
    assert_eq!(
        next(&release, &destination, &options())?,
        run(Step::AdvanceRing(1))
    );
    Ok(())
}
