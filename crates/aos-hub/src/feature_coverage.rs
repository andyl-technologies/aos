//! Standalone Hub process CLI feature-surface coverage guard.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use clap::{Command, CommandFactory};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::Cli;

const MANIFEST: &str = include_str!("../../../docs/quality/apm-hub-feature-coverage.json");
const API_MANIFEST: &str = include_str!("../../../docs/quality/aos-hub-api-feature-coverage.json");
const HUB_PROTO: &str = include_str!("../../aos-proto/src/proto/aos/hub/v1/hub.proto");
const REPOSITORY_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

#[derive(Debug, Deserialize)]
struct CoverageEntry {
    command: String,
    coverage: String,
    tests: Vec<String>,
    #[serde(default)]
    interface_sha256: String,
}

#[derive(Debug, Deserialize)]
struct ApiCoverageEntry {
    rpc: String,
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
        public_leaf_commands(child, &format!("{prefix} {}", child.get_name()), leaves);
    }
}

fn expected_commands() -> BTreeMap<String, String> {
    let root = Cli::command();
    let mut expected = BTreeMap::new();
    for command in root
        .get_subcommands()
        .filter(|command| !command.is_hide_set())
    {
        public_leaf_commands(
            command,
            &format!("aos-hub {}", command.get_name()),
            &mut expected,
        );
    }
    expected
}

#[test]
fn every_public_process_command_has_a_coverage_owner() {
    let entries: Vec<CoverageEntry> =
        serde_json::from_str(MANIFEST).expect("feature coverage manifest is valid JSON");
    let actual = entries
        .into_iter()
        .filter(|entry| entry.command.starts_with("aos-hub "))
        .map(|entry| (entry.command.clone(), entry))
        .collect::<BTreeMap<_, _>>();

    let actual_commands = actual.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        actual_commands,
        expected_commands().keys().cloned().collect::<BTreeSet<_>>(),
        "feature coverage manifest does not match the public aos-hub process CLI surface"
    );
    assert_eq!(
        actual
            .iter()
            .map(|(command, entry)| (command.clone(), entry.interface_sha256.clone()))
            .collect::<BTreeMap<_, _>>(),
        expected_commands(),
        "feature coverage manifest has stale public aos-hub help contracts"
    );

    for entry in actual.values() {
        assert!(
            !entry.coverage.is_empty(),
            "{} has no coverage class",
            entry.command
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

fn public_rpc_methods() -> BTreeMap<String, String> {
    let mut service = None;
    let mut pending: Option<(String, String)> = None;
    let mut methods = BTreeMap::new();

    for line in HUB_PROTO.lines() {
        let trimmed = line.trim();
        if let Some((rpc, signature)) = pending.as_mut() {
            signature.push(' ');
            signature.push_str(trimmed);
            if trimmed.contains(';') {
                let normalized = signature.split_whitespace().collect::<Vec<_>>().join(" ");
                methods.insert(
                    rpc.clone(),
                    format!("{:x}", Sha256::digest(normalized.as_bytes())),
                );
                pending = None;
            }
            continue;
        }
        if let Some(name) = trimmed
            .strip_prefix("service ")
            .and_then(|rest| rest.split_whitespace().next())
        {
            service = Some(name.to_owned());
            continue;
        }
        if trimmed == "}" {
            service = None;
            continue;
        }
        if let (Some(service), Some(method)) = (
            service.as_deref(),
            trimmed
                .strip_prefix("rpc ")
                .and_then(|rest| rest.split('(').next()),
        ) {
            let rpc = format!("{service}.{}", method.trim());
            if trimmed.contains(';') {
                let normalized = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
                methods.insert(rpc, format!("{:x}", Sha256::digest(normalized.as_bytes())));
            } else {
                pending = Some((rpc, trimmed.to_owned()));
            }
        }
    }

    assert!(
        pending.is_none(),
        "unterminated RPC declaration in Hub protobuf"
    );
    methods
}

#[test]
fn every_public_hub_rpc_has_a_coverage_owner() {
    let entries: Vec<ApiCoverageEntry> =
        serde_json::from_str(API_MANIFEST).expect("Hub API coverage manifest is valid JSON");
    let mut actual = BTreeMap::new();
    for entry in entries {
        assert!(
            actual.insert(entry.rpc.clone(), entry).is_none(),
            "duplicate Hub API coverage entry"
        );
    }

    assert_eq!(
        actual.keys().cloned().collect::<BTreeSet<_>>(),
        public_rpc_methods()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        "Hub API coverage manifest does not match the public ConnectRPC surface"
    );
    assert_eq!(
        actual
            .iter()
            .map(|(rpc, entry)| (rpc.clone(), entry.interface_sha256.clone()))
            .collect::<BTreeMap<_, _>>(),
        public_rpc_methods(),
        "Hub API coverage manifest has stale RPC signatures"
    );
    for entry in actual.values() {
        assert!(
            !entry.coverage.is_empty(),
            "{} has no coverage class",
            entry.rpc
        );
        assert!(
            !entry.tests.is_empty(),
            "{} has no coverage evidence",
            entry.rpc
        );
        for test in &entry.tests {
            assert!(
                Path::new(REPOSITORY_ROOT).join(test).exists(),
                "{} references missing coverage evidence {}",
                entry.rpc,
                test
            );
        }
    }
}
