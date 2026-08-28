//! Arguments for `aos package` (a.k.a. `apm`) — the package manager.
//!
//! `PackageArgs` wraps the `PackageCommand` subcommand tree defined in
//! the `aos-package` crate (install, remove, registry operations, ...)
//! and adds the global `--dry-run` and `--yes` flags. Invoking the
//! binary as `apm` or `apr` routes here implicitly (see the multicall
//! dispatch in `main.rs`).
//!
//! Doc comments here are clap `--help` text; the implementation lives in
//! `commands::package`, which delegates to `aos_package::run`.

use clap::Args;

// Re-export command enums from the package library crate so clap can use them.
pub use aos_package::PackageCommand;

#[derive(Args)]
#[command(after_long_help = aos_package::ENVIRONMENT_HELP)]
pub struct PackageArgs {
    #[command(subcommand)]
    pub command: PackageCommand,

    /// Show what would be done without doing it
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Assume yes to all prompts
    #[arg(short = 'y', long, global = true)]
    pub yes: bool,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use aos_package::RegistryCommand;
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Commands};

    #[test]
    fn registry_release_parses_paired_container_attachment_paths() {
        let cli = Cli::try_parse_from([
            "aos",
            "package",
            "registry",
            "release",
            "1.0.0",
            "--container-release",
            "containers-v1-index.json",
            "--container-signature-input",
            "signature-input.json",
        ])
        .expect("container registry release command");
        let Commands::Package(PackageArgs {
            command:
                PackageCommand::Registry {
                    command:
                        RegistryCommand::Release {
                            container_release,
                            container_signature_input,
                            ..
                        },
                    ..
                },
            ..
        }) = cli.command
        else {
            panic!("expected registry release command");
        };
        assert_eq!(
            container_release,
            Some(PathBuf::from("containers-v1-index.json"))
        );
        assert_eq!(
            container_signature_input,
            Some(PathBuf::from("signature-input.json"))
        );
    }
}
