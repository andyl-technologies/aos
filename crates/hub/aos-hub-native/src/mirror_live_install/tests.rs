//! Checks the actual command parser and public help contract without network access.

use clap::{CommandFactory as _, Parser as _};

use super::super::{Cli, Command, WorkerCommand};

fn arguments() -> Vec<&'static str> {
    vec![
        "aos-hub",
        "worker",
        "activate-hybrid-mirror-live",
        "--name",
        "storage-executor",
        "--bucket",
        "registry-private",
        "--deployment-id",
        "deployment-1",
        "--external-url",
        "https://hub.example.test",
        "--native-origin-url",
        "https://native.example.test",
        "--direct-upload-guard-key-file",
        "guard.key",
        "--mirror-acceptance-file",
        "reviewed-mirror.json",
        "--mirror-pack-acceptance-file",
        "reviewed-pack.json",
        "--mirror-live-acceptance-file",
        "reviewed-live.json",
        "--mirror-qualification-public-key-file",
        "reviewer.pub",
        "--mirror-acceptance-namespace-id",
        "review-registry",
    ]
}

#[test]
fn command_requires_all_three_artifacts_and_preserves_the_existing_guard_file_input() {
    let parsed = Cli::try_parse_from(arguments()).unwrap();
    let Command::Worker {
        command: WorkerCommand::ActivateHybridMirrorLive(args),
    } = parsed.command
    else {
        panic!("expected explicit live activation");
    };
    assert_eq!(
        args.mirror_live_acceptance_file,
        std::path::Path::new("reviewed-live.json")
    );
    assert_eq!(
        args.direct_upload_guard_key_file,
        std::path::Path::new("guard.key")
    );
    for missing in [
        "--mirror-acceptance-file",
        "--mirror-pack-acceptance-file",
        "--mirror-live-acceptance-file",
    ] {
        let mut selected = arguments();
        let index = selected.iter().position(|value| *value == missing).unwrap();
        selected.drain(index..index + 2);
        assert!(Cli::try_parse_from(selected).is_err());
    }
}

#[test]
fn actual_public_help_names_thirteen_case_review_and_installed_trust_inputs() {
    let mut command = Cli::command()
        .find_subcommand("worker")
        .unwrap()
        .find_subcommand("activate-hybrid-mirror-live")
        .unwrap()
        .clone();
    let help = command.render_long_help().to_string();

    assert!(help.contains("thirteen-case live-purpose review"));
    for flag in [
        "--mirror-live-acceptance-file",
        "--mirror-pack-acceptance-file",
        "--mirror-qualification-public-key-file",
        "--mirror-acceptance-namespace-id",
        "--direct-upload-guard-key-file",
    ] {
        assert!(help.contains(flag), "missing public flag {flag}");
    }
    assert!(!help.contains("--accept-unqualified"));
}
