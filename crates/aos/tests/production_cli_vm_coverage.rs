//! Executable VM/fleet ownership for the production Hub and package CLIs.

use std::fs;
use std::path::Path;

use clap::{Command, CommandFactory};

#[path = "../src/cli/mod.rs"]
mod cli;

use cli::{ApmCli, AprCli, Cli};

fn aos_command() -> Command {
    std::thread::Builder::new()
        .name("production-cli-coverage-command".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(Cli::command)
        .expect("CLI coverage command thread must start")
        .join()
        .expect("CLI coverage command thread must complete")
}

fn apm_command() -> Command {
    std::thread::Builder::new()
        .name("production-apm-coverage-command".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(ApmCli::command)
        .expect("APM coverage command thread must start")
        .join()
        .expect("APM coverage command thread must complete")
}

fn apr_command() -> Command {
    std::thread::Builder::new()
        .name("production-apr-coverage-command".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(AprCli::command)
        .expect("APR coverage command thread must start")
        .join()
        .expect("APR coverage command thread must complete")
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
    let root = aos_command();
    let apm = apm_command();
    let apr = apr_command();
    let mut leaves = Vec::new();
    collect_leaves(
        command_at(&root, &["hub"]),
        &mut vec!["aos".into(), "hub".into()],
        &mut leaves,
    );
    collect_leaves(&apm, &mut vec!["apm".into()], &mut leaves);
    collect_leaves(&apr, &mut vec!["apr".into()], &mut leaves);
    leaves.sort();

    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut source = String::new();
    collect_nix_sources(&repository.join("tests/vm/apm"), &mut source);
    collect_nix_sources(&repository.join("tests/fleet"), &mut source);
    source.push_str(
        &fs::read_to_string(repository.join("tests/vm/hub-native-operations.nix"))
            .expect("native Hub operation test must be readable"),
    );
    let settings_vm = fs::read_to_string(repository.join("tests/vm/hub-settings.nix"))
        .expect("Hub settings VM test must be readable");
    assert!(settings_vm.contains("builtins.readFile ../native/hub-settings.py"));
    // This VM delegates its executable command coverage to the same Python
    // process harness used locally. Its CLI calls spell out complete leaves.
    source.push_str(
        &fs::read_to_string(repository.join("tests/native/hub-settings.py"))
            .expect("Hub settings process test must be readable"),
    );
    let source = source.split_whitespace().collect::<Vec<_>>().join(" ");

    let missing = leaves
        .into_iter()
        .filter(|leaf| {
            let command = leaf
                .strip_prefix("aos hub ")
                .or_else(|| leaf.strip_prefix("apm registry "))
                .or_else(|| leaf.strip_prefix("apm "))
                .or_else(|| leaf.strip_prefix("apr "))
                .expect("production leaf must have a known CLI prefix");
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
