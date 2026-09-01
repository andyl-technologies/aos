//! Executable VM/fleet ownership for the production Hub and package CLIs.

use std::fs;
use std::path::Path;

use clap::{Command, CommandFactory};

#[path = "../src/cli/mod.rs"]
mod cli;

use cli::Cli;

fn cli_command() -> Command {
    std::thread::Builder::new()
        .name("production-cli-coverage-command".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(Cli::command)
        .expect("CLI coverage command thread must start")
        .join()
        .expect("CLI coverage command thread must complete")
}

fn command_at<'a>(root: &'a Command, path: &[&str]) -> &'a Command {
    path.iter().fold(root, |command, name| {
        command
            .get_subcommands()
            .find(|candidate| candidate.get_name() == *name)
            .unwrap_or_else(|| panic!("missing production command path {}", path.join(" ")))
    })
}

fn collect_leaves(command: &Command, prefix: &mut Vec<String>, leaves: &mut Vec<String>) {
    let visible = command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
        .collect::<Vec<_>>();
    if visible.is_empty() {
        leaves.push(prefix.join(" "));
        return;
    }

    for subcommand in visible {
        prefix.push(subcommand.get_name().to_string());
        collect_leaves(subcommand, prefix, leaves);
        prefix.pop();
    }
}

fn collect_nix_sources(directory: &Path, source: &mut String) {
    for entry in fs::read_dir(directory).expect("integration test directory must be readable") {
        let path = entry
            .expect("integration test entry must be readable")
            .path();
        if path.is_dir() {
            collect_nix_sources(&path, source);
        } else if path.extension().is_some_and(|extension| extension == "nix") {
            let contents = fs::read_to_string(&path).expect("integration test must be readable");
            for line in contents.lines() {
                if !line.trim_start().starts_with('#') {
                    source.push_str(line);
                    source.push(' ');
                }
            }
        }
    }
}

#[test]
fn every_production_command_leaf_is_owned_by_an_executable_nix_test() {
    let root = cli_command();
    let mut leaves = Vec::new();
    collect_leaves(
        command_at(&root, &["hub"]),
        &mut vec!["aos".into(), "hub".into()],
        &mut leaves,
    );
    collect_leaves(
        command_at(&root, &["package"]),
        &mut vec!["apm".into()],
        &mut leaves,
    );
    leaves.sort();

    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut source = String::new();
    collect_nix_sources(&repository.join("tests/vm/apm"), &mut source);
    collect_nix_sources(&repository.join("tests/fleet"), &mut source);
    source.push_str(
        &fs::read_to_string(repository.join("tests/vm/hub-native-operations.nix"))
            .expect("native Hub operation test must be readable"),
    );
    let source = source.split_whitespace().collect::<Vec<_>>().join(" ");

    let missing = leaves
        .into_iter()
        .filter(|leaf| {
            let command = leaf
                .strip_prefix("aos hub ")
                .or_else(|| leaf.strip_prefix("apm registry "))
                .or_else(|| leaf.strip_prefix("apm "))
                .expect("production leaf must have a known multicall prefix");
            let reviewed_base = command.strip_suffix(" apply");
            !source.contains(command) && !reviewed_base.is_some_and(|base| source.contains(base))
        })
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "production commands without executable Nix VM/fleet ownership:\n{}",
        missing.join("\n")
    );
}
