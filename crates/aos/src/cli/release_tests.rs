//! Parser contract tests for `aos maintain release` porcelain and `aos maintain release step`.

use std::path::PathBuf;

use clap::Parser as _;

use super::{ReleaseCommand, ReleaseFitnessCommand, ReleaseStepCommand};
use crate::cli::{Cli, Commands, MaintainArgs, MaintainCommand};

#[test]
fn assembler_accepts_repeatable_image_sets_and_optional_container() {
    let Ok(parsed) = Cli::try_parse_from([
        "aos",
        "maintain",
        "release",
        "step",
        "assemble",
        "--plan",
        "plan.json",
        "--build-report",
        "build.json",
        "--sbom",
        "sbom.json",
        "--contributor-authorization",
        "authorization.json",
        "--advisory-disposition",
        "advisories.json",
        "--cache",
        "cache",
        "--cache-key",
        "cache-1=cache-1.pub",
        "--registry",
        "registry",
        "--registry-result",
        "registry-result.json",
        "--image-set",
        "images/amd64",
        "--image-set",
        "images/arm64",
        "--container",
        "container",
        "--completed-at",
        "2026-09-03T14:00:00Z",
        "--output",
        "assembled",
    ]) else {
        panic!("release assemble arguments should parse");
    };
    let Commands::Maintain(MaintainArgs {
        command:
            Some(MaintainCommand::Release {
                command:
                    ReleaseCommand::Step {
                        command: ReleaseStepCommand::Assemble(args),
                    },
            }),
        ..
    }) = parsed.command
    else {
        panic!("expected release assemble command");
    };
    assert_eq!(args.image_sets.len(), 2);
    assert_eq!(args.container, Some(PathBuf::from("container")));
    assert_eq!(args.output, PathBuf::from("assembled"));
}

#[test]
fn verifier_requires_explicit_trust_input() {
    assert!(
        Cli::try_parse_from(["aos", "maintain", "release", "step", "verify", "bundle"]).is_err()
    );

    let Ok(parsed) = Cli::try_parse_from([
        "aos",
        "maintain",
        "release",
        "step",
        "verify",
        "bundle",
        "--trusted-key",
        "release=/keys/release.pub",
    ]) else {
        panic!("release verifier arguments should parse");
    };
    assert!(matches!(
        parsed.command,
        Commands::Maintain(MaintainArgs {
            command: Some(MaintainCommand::Release { .. }),
            ..
        })
    ));
}

#[test]
fn planner_requires_review_and_authorization_inputs() {
    assert!(
        Cli::try_parse_from([
            "aos",
            "maintain",
            "release",
            "step",
            "plan",
            "--request",
            "request.json",
            "--contributor-authorization",
            "authorization.json",
            "--output",
            "release-plan.json",
        ])
        .is_ok()
    );
}

#[test]
fn build_captures_its_completion_time() {
    let command = [
        "aos",
        "maintain",
        "release",
        "step",
        "build",
        "--plan",
        "release-plan.json",
        "--output",
        "release-build",
        "--started-at",
        "2026-09-03T10:00:00Z",
    ];
    assert!(Cli::try_parse_from(command).is_ok());

    let supplied_completion = command
        .into_iter()
        .chain(["--completed-at", "2026-09-03T12:00:00Z"]);
    assert!(Cli::try_parse_from(supplied_completion).is_err());
}

#[test]
fn image_finalization_requires_explicit_role_keys() {
    assert!(
        Cli::try_parse_from([
            "aos",
            "maintain",
            "release",
            "step",
            "finalize-image",
            "--plan",
            "release-plan.json",
            "--assembly",
            "/nix/store/example-assembly",
            "--signer-executable",
            "/opt/aos/signer",
            "--work",
            "/var/lib/aos-release/work",
        ])
        .is_err()
    );
}

#[test]
fn registry_preparation_requires_provenance_role_key() {
    let base = [
        "aos",
        "maintain",
        "release",
        "step",
        "prepare-registry",
        "--plan",
        "release-plan.json",
        "--build-report",
        "build-report.json",
        "--source-registry",
        "registry",
        "--output",
        "isolated-registry",
        "--transaction",
        "registry-transaction.json",
        "--signer-executable",
        "/opt/aos/signer",
        "--provenance-key",
        "provenance=provenance.pub",
        "--provenance-verification-identity",
        "provider-provenance",
        "--registry-key",
        "registry=registry.pub",
        "--registry-verification-identity",
        "provider-registry",
    ];
    assert!(Cli::try_parse_from(base).is_ok());

    let with_container = base
        .into_iter()
        .chain([
            "--container-release",
            "container-release.json",
            "--container-signature-input",
            "signature-input.json",
            "--container-layout",
            "container-layout",
        ])
        .collect::<Vec<_>>();
    assert!(Cli::try_parse_from(with_container).is_ok());

    let unpaired = base
        .into_iter()
        .chain(["--container-release", "container-release.json"])
        .collect::<Vec<_>>();
    assert!(Cli::try_parse_from(unpaired).is_err());
}

#[test]
fn registry_finalization_requires_reviewed_tree_and_registry_key() {
    let base = [
        "aos",
        "maintain",
        "release",
        "step",
        "finalize-registry",
        "--plan",
        "release-plan.json",
        "--build-report",
        "build-report.json",
        "--transaction",
        "registry-transaction.json",
        "--prepared-registry",
        "isolated-registry",
        "--result",
        "registry-result.json",
        "--signer-executable",
        "/opt/aos/signer",
        "--registry-key",
        "registry=registry.pub",
        "--registry-verification-identity",
        "provider-registry",
        "--git-name",
        "AOS Release",
        "--git-email",
        "release@example.invalid",
        "--git-unix-seconds",
        "1",
    ];
    assert!(Cli::try_parse_from(base).is_ok());

    let with_container = base
        .into_iter()
        .chain([
            "--container-release",
            "container-release.json",
            "--container-signature-input",
            "signature-input.json",
        ])
        .collect::<Vec<_>>();
    assert!(Cli::try_parse_from(with_container).is_ok());

    let unpaired = base
        .into_iter()
        .chain(["--container-release", "container-release.json"])
        .collect::<Vec<_>>();
    assert!(Cli::try_parse_from(unpaired).is_err());
}

#[test]
fn bundle_finalization_requires_provider_identity_for_signers() {
    assert!(
        Cli::try_parse_from([
            "aos",
            "maintain",
            "release",
            "step",
            "finalize",
            "--plan",
            "release-plan.json",
            "--payload",
            "payload",
            "--manifest-payload",
            "manifest-payload.json",
            "--journal",
            "release-journal.jsonl",
            "--signing-key",
            "release-1=release-1.pub",
            "--verification-identity",
            "release-1=provider-slot-1",
            "--signer-executable",
            "/opt/aos/signer",
            "--recorded-at",
            "2026-09-03T12:00:00Z",
            "--output",
            "finalized",
        ])
        .is_ok()
    );
}

#[test]
fn tuf_construction_requires_each_online_release_role() {
    assert!(
        Cli::try_parse_from([
            "aos",
            "maintain",
            "release",
            "step",
            "tuf",
            "--plan",
            "release-plan.json",
            "--bundle",
            "bundle",
            "--manifest-key",
            "release=release.pub",
            "--root",
            "1.root.json",
            "--trusted-root-key",
            "root-1=root-1.pub",
            "--targets-key",
            "targets-1=targets-1.pub",
            "--delegated-key",
            "stable-1=stable-1.pub",
            "--snapshot-key",
            "snapshot-1=snapshot-1.pub",
            "--signer-executable",
            "/opt/aos/signer",
            "--targets-version",
            "1",
            "--delegated-version",
            "1",
            "--snapshot-version",
            "1",
            "--targets-expires",
            "2027-01-01T00:00:00Z",
            "--delegated-expires",
            "2027-01-01T00:00:00Z",
            "--snapshot-expires",
            "2027-01-01T00:00:00Z",
            "--now",
            "2026-09-03T12:00:00Z",
            "--output",
            "tuf",
        ])
        .is_ok()
    );
}

#[test]
fn cache_finalization_requires_external_key_and_provider_identity() {
    assert!(
        Cli::try_parse_from([
            "aos",
            "maintain",
            "release",
            "step",
            "finalize-cache",
            "--plan",
            "release-plan.json",
            "--build-report",
            "build-report.json",
            "--registry",
            "registry",
            "--cache-key",
            "cache-1=cache-1.pub",
            "--verification-identity",
            "provider-cache-slot",
            "--signer-executable",
            "/opt/aos/signer",
            "--output",
            "cache",
        ])
        .is_ok()
    );
}

#[test]
fn qualification_run_requires_native_matrix_and_authority_inputs() {
    assert!(
        Cli::try_parse_from([
            "aos",
            "maintain",
            "release",
            "step",
            "qualify-run",
            "--to",
            "production/candidate",
            "--bundle",
            "bundle",
            "--staging-receipt",
            "staging.json",
            "--trusted-key",
            "release=release.pub",
            "--hub-receipt-key",
            "staging=staging.pub",
            "--executor",
            "x86_64-linux=/opt/aos/qualify-linux-x86",
            "--executor",
            "aarch64-linux=/opt/aos/qualify-linux-arm",
            "--executor",
            "x86_64-darwin=/opt/aos/qualify-darwin-x86",
            "--executor",
            "aarch64-darwin=/opt/aos/qualify-darwin-arm",
            "--executor-identity",
            "x86_64-linux=linux-x86-v1",
            "--executor-identity",
            "aarch64-linux=linux-arm-v1",
            "--executor-identity",
            "x86_64-darwin=darwin-x86-v1",
            "--executor-identity",
            "aarch64-darwin=darwin-arm-v1",
            "--authority-executable",
            "/opt/aos/signer",
            "--authority-key",
            "qualification=qualification.pub",
            "--authority-verification-identity",
            "qualification-provider-v1",
            "--executor-nonce",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--authority-nonce",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "--qualified-at",
            "2026-09-03T12:00:00Z",
            "--output",
            "qualification",
        ])
        .is_ok()
    );
}

#[test]
fn qualification_response_requires_one_report_source() {
    let base = [
        "aos",
        "maintain",
        "release",
        "step",
        "qualification",
        "respond",
        "--request",
        "request.json",
        "--scenarios",
        "scenarios.json",
        "--identity",
        "linux-x86-v1",
    ];

    assert!(Cli::try_parse_from(base.into_iter().chain(["--report", "report.json"])).is_ok());
    assert!(
        Cli::try_parse_from(
            base.into_iter()
                .chain(["--report-root", "/run/aos-release/reports"])
        )
        .is_ok()
    );
    assert!(Cli::try_parse_from(base).is_err());
    assert!(
        Cli::try_parse_from(base.into_iter().chain([
            "--report",
            "report.json",
            "--report-root",
            "/run/aos-release/reports",
        ]))
        .is_err()
    );
}

#[test]
fn surface_composition_requires_the_complete_tuf_set() {
    assert!(
        Cli::try_parse_from([
            "aos",
            "maintain",
            "release",
            "step",
            "compose-surface",
            "--to",
            "production/stable",
            "--plan",
            "release-plan.json",
            "--bundle",
            "bundle",
            "--manifest-key",
            "release=release.pub",
            "--base-surface",
            "registry-surface",
            "--root",
            "12.root.json",
            "--targets",
            "43.targets.json",
            "--delegated",
            "19.stable.json",
            "--snapshot",
            "44.snapshot.json",
            "--timestamp",
            "87.timestamp.json",
            "--trusted-root-key",
            "root-1=root-1.pub",
            "--now",
            "2026-09-03T12:00:00Z",
            "--output",
            "complete-surface",
        ])
        .is_ok()
    );
}

#[test]
fn publish_requires_a_destination_and_receipt_trust() {
    let base = [
        "aos",
        "maintain",
        "release",
        "step",
        "publish",
        "--to",
        "production/stable",
        "--bundle",
        "bundle",
        "--journal",
        "journal.jsonl",
        "--trusted-key",
        "release=release.pub",
        "--receipt-key",
        "production=production.pub",
        "--evidence",
        "qualification-a",
        "--evidence",
        "qualification-b",
        "--output",
        "published",
    ];
    let Ok(parsed) = Cli::try_parse_from(base) else {
        panic!("publish arguments should parse");
    };
    let Commands::Maintain(MaintainArgs {
        command:
            Some(MaintainCommand::Release {
                command:
                    ReleaseCommand::Step {
                        command: ReleaseStepCommand::Publish(args),
                    },
            }),
        ..
    }) = parsed.command
    else {
        panic!("expected release step publish");
    };
    assert_eq!(args.evidence.len(), 2);
    assert!(
        Cli::try_parse_from(
            base.iter()
                .filter(|value| **value != "--to" && **value != "production/stable")
        )
        .is_err()
    );

    // A composed surface is admitted only against independent TUF root trust.
    let composed = |extra: &[&'static str]| {
        Cli::try_parse_from(base.iter().copied().chain(extra.iter().copied()))
    };
    assert!(composed(&["--surface", "composed"]).is_err());
    assert!(composed(&["--trusted-root-key", "root=root.pub"]).is_err());
    assert!(
        composed(&[
            "--surface",
            "composed",
            "--trusted-root-key",
            "root=root.pub"
        ])
        .is_ok()
    );
}

#[test]
fn rollout_qualification_requires_ring_and_generation() {
    let base = [
        "aos",
        "maintain",
        "release",
        "step",
        "qualify-run",
        "--to",
        "production/stable",
        "--phase",
        "rollout",
        "--bundle",
        "bundle",
        "--staging-receipt",
        "receipt.json",
        "--trusted-key",
        "release=release.pub",
        "--hub-receipt-key",
        "production=production.pub",
        "--executor",
        "x86_64-linux=/opt/aos/qualify",
        "--executor-identity",
        "x86_64-linux=linux-x86-v1",
        "--authority-executable",
        "/opt/aos/signer",
        "--authority-key",
        "qualification=qualification.pub",
        "--authority-verification-identity",
        "qualification-provider-v1",
        "--executor-nonce",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--authority-nonce",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "--output",
        "qualification",
    ];
    assert!(Cli::try_parse_from(base).is_err());
    assert!(
        Cli::try_parse_from(
            base.into_iter()
                .chain(["--ring", "2", "--prior-generation", "7"])
        )
        .is_ok()
    );
}

#[test]
fn channel_advance_names_a_ring_not_partitions() {
    let base = [
        "aos",
        "maintain",
        "release",
        "step",
        "channel",
        "advance",
        "--to",
        "staging/edge",
        "--ring",
        "1",
        "--bundle",
        "bundle",
        "--journal",
        "journal.jsonl",
        "--publication-receipt",
        "receipt.json",
        "--trusted-key",
        "release=release.pub",
        "--receipt-key",
        "staging=staging.pub",
        "--output",
        "ring-1",
    ];
    assert!(Cli::try_parse_from(base).is_ok());
    assert!(Cli::try_parse_from(base.into_iter().chain(["--first-partition", "0"])).is_err());
}

#[test]
fn channel_commands_reject_the_retired_production_receipt_alias() {
    for command in ["advance", "complete"] {
        let error = match Cli::try_parse_from([
            "aos",
            "maintain",
            "release",
            "step",
            "channel",
            command,
            "--production-receipt",
            "receipt.json",
        ]) {
            Ok(_) => panic!("retired production receipt flag must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}

#[test]
fn new_requires_registry_version_and_image_decisions() {
    assert!(
        Cli::try_parse_from([
            "aos",
            "maintain",
            "release",
            "new",
            "--registry",
            "andyl/experimental",
            "--version",
            "2026.9.0-dev.1",
        ])
        .is_err()
    );

    let Ok(parsed) = Cli::try_parse_from([
        "aos",
        "maintain",
        "release",
        "new",
        "--registry",
        "andyl/experimental",
        "--version",
        "2026.9.0-dev.20260929.1",
        "--images",
        "images.json",
        "--override",
        "approvals",
        "--work",
        "work",
        "--config",
        "maintainer.toml",
    ]) else {
        panic!("release new arguments should parse");
    };
    let Commands::Maintain(MaintainArgs {
        command:
            Some(MaintainCommand::Release {
                command: ReleaseCommand::New(args),
            }),
        ..
    }) = parsed.command
    else {
        panic!("expected release new command");
    };
    assert_eq!(args.registry, "andyl/experimental");
    assert_eq!(args.release_id, None);
    assert_eq!(args.images, PathBuf::from("images.json"));
    assert_eq!(args.override_dir, Some(PathBuf::from("approvals")));
    assert_eq!(args.work, Some(PathBuf::from("work")));
    assert_eq!(args.config, Some(PathBuf::from("maintainer.toml")));
}

#[test]
fn advance_names_a_destination_and_optional_ring() {
    assert!(Cli::try_parse_from(["aos", "maintain", "release", "advance"]).is_err());

    let Ok(parsed) = Cli::try_parse_from([
        "aos",
        "maintain",
        "release",
        "advance",
        "--to",
        "production/stable",
        "--ring",
        "2",
        "--accept-transaction",
    ]) else {
        panic!("release advance arguments should parse");
    };
    let Commands::Maintain(MaintainArgs {
        command:
            Some(MaintainCommand::Release {
                command: ReleaseCommand::Advance(args),
            }),
        ..
    }) = parsed.command
    else {
        panic!("expected release advance command");
    };
    assert_eq!(args.to, "production/stable");
    assert_eq!(args.ring, Some(2));
    assert!(!args.stop_after_upload);
    assert!(args.accept_transaction);
    assert_eq!(args.override_dir, None);
    assert_eq!(args.work, None);
}

#[test]
fn status_explain_and_review_select_a_work_directory() {
    let Ok(parsed) =
        Cli::try_parse_from(["aos", "maintain", "release", "status", "--work", "work"])
    else {
        panic!("release status arguments should parse");
    };
    assert!(matches!(
        parsed.command,
        Commands::Maintain(MaintainArgs { command: Some(MaintainCommand::Release {
            command: ReleaseCommand::Status(ref args),
        }), .. }) if args.work == Some(PathBuf::from("work"))
    ));

    assert!(Cli::try_parse_from(["aos", "maintain", "release", "explain"]).is_err());
    let Ok(parsed) = Cli::try_parse_from([
        "aos",
        "maintain",
        "release",
        "explain",
        "--to",
        "production/candidate",
    ]) else {
        panic!("release explain arguments should parse");
    };
    assert!(matches!(
        parsed.command,
        Commands::Maintain(MaintainArgs { command: Some(MaintainCommand::Release {
            command: ReleaseCommand::Explain(ref args),
        }), .. }) if args.to == "production/candidate"
    ));

    let Ok(parsed) = Cli::try_parse_from(["aos", "maintain", "release", "review"]) else {
        panic!("release review arguments should parse");
    };
    assert!(matches!(
        parsed.command,
        Commands::Maintain(MaintainArgs { command: Some(MaintainCommand::Release {
            command: ReleaseCommand::Review(ref args),
        }), .. }) if !args.reject && args.reason.is_none()
    ));
}

#[test]
fn review_rejection_requires_a_reason() {
    assert!(Cli::try_parse_from(["aos", "maintain", "release", "review", "--reject"]).is_err());
    assert!(
        Cli::try_parse_from(["aos", "maintain", "release", "review", "--reason", "late"]).is_err()
    );

    let Ok(parsed) = Cli::try_parse_from([
        "aos",
        "maintain",
        "release",
        "review",
        "--reject",
        "--reason",
        "container lifecycle log shows a retried stop",
    ]) else {
        panic!("release review rejection should parse");
    };
    let Commands::Maintain(MaintainArgs {
        command:
            Some(MaintainCommand::Release {
                command: ReleaseCommand::Review(args),
            }),
        ..
    }) = parsed.command
    else {
        panic!("expected release review command");
    };
    assert!(args.reject);
    assert_eq!(
        args.reason.as_deref(),
        Some("container lifecycle log shows a retried stop")
    );
}

#[test]
fn fitness_run_takes_a_kind_and_optional_report() {
    assert!(Cli::try_parse_from(["aos", "maintain", "release", "fitness", "run"]).is_err());

    let Ok(parsed) = Cli::try_parse_from([
        "aos",
        "maintain",
        "release",
        "fitness",
        "run",
        "hub-restore",
        "--report",
        "hub-restore.json",
    ]) else {
        panic!("release fitness run arguments should parse");
    };
    let Commands::Maintain(MaintainArgs {
        command:
            Some(MaintainCommand::Release {
                command:
                    ReleaseCommand::Fitness {
                        command: ReleaseFitnessCommand::Run(args),
                    },
            }),
        ..
    }) = parsed.command
    else {
        panic!("expected release fitness run command");
    };
    assert_eq!(args.kind, "hub-restore");
    assert_eq!(args.report, Some(PathBuf::from("hub-restore.json")));

    let Ok(parsed) = Cli::try_parse_from([
        "aos",
        "maintain",
        "release",
        "fitness",
        "status",
        "--config",
        "maintainer.toml",
    ]) else {
        panic!("release fitness status arguments should parse");
    };
    assert!(matches!(
        parsed.command,
        Commands::Maintain(MaintainArgs {
            command: Some(MaintainCommand::Release {
                command: ReleaseCommand::Fitness {
                    command: ReleaseFitnessCommand::Status(_),
                },
            }),
            ..
        })
    ));
}

#[test]
fn removed_top_level_release_is_rejected() {
    assert!(Cli::try_parse_from(["aos", "release", "status"]).is_err());
}

#[test]
fn upload_stop_and_explicit_publication_are_distinct_commands() {
    let parsed = Cli::try_parse_from([
        "aos",
        "maintain",
        "release",
        "advance",
        "--to",
        "staging/edge",
        "--stop-after-upload",
    ])
    .expect("upload stopping point parses");
    assert!(matches!(parsed.command, Commands::Maintain(MaintainArgs {
        command: Some(MaintainCommand::Release { command: ReleaseCommand::Advance(args) }), ..
    }) if args.stop_after_upload));

    let parsed = Cli::try_parse_from([
        "aos",
        "maintain",
        "release",
        "publish",
        "--to",
        "staging/edge",
        "--work",
        "release-work",
    ])
    .expect("explicit staged publication parses");
    assert!(matches!(parsed.command, Commands::Maintain(MaintainArgs {
        command: Some(MaintainCommand::Release { command: ReleaseCommand::Publish(args) }), ..
    }) if args.work == Some(PathBuf::from("release-work"))));
}
