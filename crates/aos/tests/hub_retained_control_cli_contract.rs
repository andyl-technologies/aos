//! Parse-contract tests for the production retained-control CLI.

use std::ffi::OsString;

use clap::{Command, CommandFactory, Parser};

#[path = "../src/cli/mod.rs"]
mod cli;

use cli::Cli;

fn parse_cli<I, T>(args: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    std::thread::Builder::new()
        .name("hub-cli-contract-parser".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || Cli::try_parse_from(args))
        .expect("CLI contract parser thread must start")
        .join()
        .expect("CLI contract parser thread must complete")
}

fn cli_command() -> Command {
    std::thread::Builder::new()
        .name("hub-cli-contract-command".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(Cli::command)
        .expect("CLI contract command thread must start")
        .join()
        .expect("CLI contract command thread must complete")
}

const REVIEWED_ACTION_PATHS: &[&[&str]] = &[
    &["hub", "instance", "identity", "update"],
    &["hub", "instance", "resource-defaults", "update"],
    &["hub", "instance", "branding", "update"],
    &["hub", "org", "service-account", "create"],
    &["hub", "org", "member", "set-role"],
    &["hub", "org", "member", "remove"],
    &["hub", "registry", "token", "issue"],
    &["hub", "registry", "token", "retire"],
    &["hub", "signing-key", "enroll"],
    &["hub", "signing-key", "rotate"],
    &["hub", "signing-key", "retire"],
    &["hub", "signing-key", "set-usage"],
];

fn command_at<'a>(root: &'a Command, path: &[&str]) -> &'a Command {
    let mut command = root;
    for name in path {
        command = command
            .get_subcommands()
            .find(|candidate| candidate.get_name() == *name)
            .unwrap_or_else(|| panic!("missing production command path {}", path.join(" ")));
    }
    command
}

#[test]
fn retained_queries_use_final_resource_scoped_roots() {
    for argv in [
        vec![
            "aos",
            "hub",
            "org",
            "member",
            "show",
            "--hub",
            "https://hub.test",
            "--principal-kind",
            "user",
            "--principal",
            "dev@example.test",
            "--scope",
            "acme",
        ],
        vec![
            "aos",
            "hub",
            "registry",
            "token",
            "list",
            "--hub",
            "https://hub.test",
            "acme/main",
        ],
        vec![
            "aos",
            "hub",
            "instance",
            "branding",
            "show",
            "--hub",
            "https://hub.test",
        ],
        vec![
            "aos",
            "hub",
            "signing-key",
            "list",
            "--hub",
            "https://hub.test",
            "--scope",
            "registry:acme/main",
        ],
        vec![
            "aos",
            "hub",
            "signing-key",
            "show",
            "--hub",
            "https://hub.test",
            "--scope",
            "registry:acme/main",
            "release",
        ],
    ] {
        parse_cli(argv).unwrap();
    }

    for legacy in [
        &["aos", "hub", "org", "identity"][..],
        &["aos", "hub", "org", "identity", "grant"],
        &["aos", "hub", "org", "identity", "revoke"],
    ] {
        assert!(parse_cli(legacy.iter().copied()).is_err());
    }

    assert!(parse_cli(["aos", "hub", "instance", "show"]).is_err());
    assert!(parse_cli(["aos", "hub", "instance", "update"]).is_err());
    assert!(parse_cli(["aos", "hub", "signing"]).is_err());
}

#[test]
fn every_retained_mutation_exposes_only_plan_and_apply() {
    let root = cli_command();
    for path in REVIEWED_ACTION_PATHS {
        let names = command_at(&root, path)
            .get_subcommands()
            .map(Command::get_name)
            .collect::<Vec<_>>();
        assert_eq!(names, ["plan", "apply"], "unexpected flow at {path:?}");
    }
}

#[test]
fn planning_requires_a_caller_supplied_idempotency_key() {
    let valid = [
        "aos",
        "hub",
        "org",
        "member",
        "set-role",
        "plan",
        "--hub",
        "https://hub.test",
        "--idempotency-key",
        "membership-plan-1",
        "--principal-kind",
        "user",
        "--principal",
        "dev@example.test",
        "--scope",
        "acme",
        "--role",
        "viewer",
        "--if-version",
        "absent",
    ];
    parse_cli(valid).unwrap();

    let without_key = valid
        .into_iter()
        .filter(|argument| !matches!(*argument, "--idempotency-key" | "membership-plan-1"))
        .collect::<Vec<_>>();
    assert!(parse_cli(without_key).is_err());
}

#[test]
fn apply_is_sealed_and_requires_plan_confirmation_and_idempotency() {
    let valid = [
        "aos",
        "hub",
        "registry",
        "token",
        "issue",
        "apply",
        "--hub",
        "https://hub.test",
        "--plan-id",
        "plan-token-1",
        "--confirm-hash",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--idempotency-key",
        "token-apply-1",
        "--yes",
    ];
    parse_cli(valid).unwrap();

    for missing in ["--plan-id", "--confirm-hash", "--idempotency-key"] {
        let index = valid
            .iter()
            .position(|argument| *argument == missing)
            .expect("fixture flag");
        let mut invalid = valid.to_vec();
        invalid.drain(index..=index + 1);
        assert!(
            parse_cli(invalid).is_err(),
            "apply accepted missing {missing}"
        );
    }

    for mutable in ["--owner", "--permission", "--if-version"] {
        let mut invalid = valid.to_vec();
        invalid.extend([mutable, "mutable-value"]);
        assert!(
            parse_cli(invalid).is_err(),
            "apply accepted mutable planning input {mutable}"
        );
    }
}

#[test]
fn token_vocabulary_has_no_mint_rotate_or_revoke_paths() {
    let root = cli_command();
    let token = command_at(&root, &["hub", "registry", "token"]);
    let names = token
        .get_subcommands()
        .map(Command::get_name)
        .collect::<Vec<_>>();
    assert_eq!(names, ["list", "issue", "retire"]);
}
