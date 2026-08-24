//! Public APM, APR, and Hub CLI feature-surface coverage guard.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use clap::{Command, CommandFactory};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::Cli;

const MANIFEST: &str = include_str!("../../../../docs/quality/apm-hub-feature-coverage.json");
const REPOSITORY_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

#[derive(Debug, Deserialize)]
struct CoverageEntry {
    command: String,
    coverage: String,
    tests: Vec<String>,
    #[serde(default)]
    interface_sha256: String,
}

fn interface_sha256(command: &Command) -> String {
    let help = command.clone().render_long_help().to_string();
    format!("{:x}", Sha256::digest(help.as_bytes()))
}

fn public_leaf_commands(command: &Command, prefix: &str, leaves: &mut BTreeMap<String, String>) {
    let public_children = command
        .get_subcommands()
        .filter(|child| !child.is_hide_set())
        .collect::<Vec<_>>();

    if public_children.is_empty() {
        leaves.insert(prefix.to_owned(), interface_sha256(command));
        return;
    }

    for child in public_children {
        let child_prefix = format!("{prefix} {}", child.get_name());
        public_leaf_commands(child, &child_prefix, leaves);
    }
}

fn expected_commands() -> BTreeMap<String, String> {
    let root = Cli::command();
    let mut expected = BTreeMap::new();

    let package = root
        .get_subcommands()
        .find(|command| command.get_name() == "package")
        .expect("aos package command is present");
    for command in package
        .get_subcommands()
        .filter(|command| !command.is_hide_set())
    {
        if command.get_name() == "registry" {
            for registry_command in command
                .get_subcommands()
                .filter(|registry_command| !registry_command.is_hide_set())
            {
                public_leaf_commands(
                    registry_command,
                    &format!("apr {}", registry_command.get_name()),
                    &mut expected,
                );
            }
        } else {
            public_leaf_commands(
                command,
                &format!("apm {}", command.get_name()),
                &mut expected,
            );
        }
    }

    let hub = root
        .get_subcommands()
        .find(|command| command.get_name() == "hub")
        .expect("aos hub command is present");
    for command in hub
        .get_subcommands()
        .filter(|command| !command.is_hide_set())
    {
        public_leaf_commands(
            command,
            &format!("aos hub {}", command.get_name()),
            &mut expected,
        );
    }

    expected
}

#[test]
fn every_public_apm_apr_and_hub_command_has_a_coverage_owner() {
    let entries: Vec<CoverageEntry> =
        serde_json::from_str(MANIFEST).expect("feature coverage manifest is valid JSON");
    let mut actual = BTreeMap::new();

    for entry in entries
        .into_iter()
        .filter(|entry| !entry.command.starts_with("aos-hub "))
    {
        assert!(
            actual.insert(entry.command.clone(), entry).is_none(),
            "duplicate feature coverage entry"
        );
    }

    let actual_commands = actual.keys().cloned().collect::<BTreeSet<_>>();
    let expected_commands = expected_commands();
    assert_eq!(
        actual_commands,
        expected_commands.keys().cloned().collect::<BTreeSet<_>>(),
        "feature coverage manifest does not match the public CLI surface"
    );
    assert_eq!(
        actual
            .iter()
            .map(|(command, entry)| (command.clone(), entry.interface_sha256.clone()))
            .collect::<BTreeMap<_, _>>(),
        expected_commands,
        "feature coverage manifest has stale public CLI help contracts"
    );

    let allowed_coverage = BTreeSet::from([
        "native-fleet",
        "fleet",
        "vm",
        "integration",
        "unit-contract",
        "parser-only",
        "external-provider",
    ]);
    for entry in actual.values() {
        assert!(
            allowed_coverage.contains(entry.coverage.as_str()),
            "{} has unknown coverage class {}",
            entry.command,
            entry.coverage
        );
        assert!(
            !entry.tests.is_empty(),
            "{} has no coverage evidence",
            entry.command
        );
        for test in &entry.tests {
            assert!(
                Path::new(REPOSITORY_ROOT).join(test).exists(),
                "{} references missing coverage evidence {}",
                entry.command,
                test
            );
        }
    }
}
