//! Container-runtime and read-only command admission.
//!
//! The official AOS OCI image injects `AOS_RUNTIME=container`. Its init process
//! additionally injects `AOS_CONTAINER_READ_ONLY=1` when package state cannot
//! be mutated. This module interprets those exact markers and rejects an
//! incompatible command before configuration loading, profile discovery,
//! subprocess execution, or host-state access.

use std::ffi::OsStr;

use anyhow::{bail, Result};

use crate::{
    AttestCommand, BranchCommand, CacheCommand, ChangeCommand, ChannelCommand, CredentialCommand,
    DocumentationCacheCommand, DocumentationCommand, KeysCommand, OptionsCommand, OriginCommand,
    PackageCommand, RegistryCommand, RuntimeConfigCommand, SbCertsCommand, StoreCommand,
    TrustCommand,
};

const RUNTIME_ENV: &str = "AOS_RUNTIME";
const READ_ONLY_ENV: &str = "AOS_CONTAINER_READ_ONLY";

const CONTAINER_HOST_OPERATION_ERROR: &str = "AOS containers support only user-scope package management; --system and host boot, systemd, TPM, and activation operations are unavailable. Run this operation on an AOS machine or VM.";
const READ_ONLY_MUTATION_ERROR: &str = "this AOS container is read-only; user-scope package mutations are unavailable. Restart it without the runtime's read-only-root option and mount writable APM and Nix state to modify packages.";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RuntimeBoundary {
    container: bool,
    read_only: bool,
}

impl RuntimeBoundary {
    fn from_env() -> Self {
        Self::from_values(
            std::env::var_os(RUNTIME_ENV).as_deref(),
            std::env::var_os(READ_ONLY_ENV).as_deref(),
        )
    }

    fn from_values(runtime: Option<&OsStr>, read_only: Option<&OsStr>) -> Self {
        Self {
            container: runtime == Some(OsStr::new("container")),
            read_only: read_only == Some(OsStr::new("1")),
        }
    }

    fn validate(self, command: &PackageCommand) -> Result<()> {
        if self.container && requires_host_runtime(command) {
            bail!(CONTAINER_HOST_OPERATION_ERROR);
        }
        if self.read_only && !is_read_only(command) {
            bail!(READ_ONLY_MUTATION_ERROR);
        }
        Ok(())
    }
}

/// Checks the process runtime markers against one parsed package command.
///
/// This is intentionally the first operation in [`crate::run`].
///
/// # Errors
///
/// Returns an error when container mode admits only user scope but the command
/// requires system or host facilities, or when read-only mode prohibits the
/// requested mutation.
pub(crate) fn validate(command: &PackageCommand) -> Result<()> {
    let mut boundary = RuntimeBoundary::from_env();
    if boundary.container && requires_host_runtime(command) {
        bail!(CONTAINER_HOST_OPERATION_ERROR);
    }

    if let Some(state) = aos_core::container_runtime::synchronize()? {
        boundary.read_only |= state.is_read_only();
    }
    boundary.validate(command)
}

/// Returns whether a command requires AOS host facilities unavailable in OCI.
///
/// The match is exhaustive so a future command must receive an explicit
/// runtime classification before the crate compiles.
fn requires_host_runtime(command: &PackageCommand) -> bool {
    match command {
        PackageCommand::Install {
            from,
            system,
            image,
            kexec,
            reboot,
            live,
            drain,
            ..
        } => *system || from.is_some() || image.is_some() || *kexec || *reboot || *live || *drain,
        PackageCommand::Update { system, .. }
        | PackageCommand::Search { system, .. }
        | PackageCommand::Show { system, .. }
        | PackageCommand::Info { system, .. }
        | PackageCommand::List { system, .. }
        | PackageCommand::Depends { system, .. }
        | PackageCommand::Rdepends { system, .. }
        | PackageCommand::Policy { system, .. }
        | PackageCommand::Files { system, .. }
        | PackageCommand::Held { system, .. }
        | PackageCommand::Orphans { system, .. }
        | PackageCommand::Clean { system, .. } => *system,
        PackageCommand::Upgrade {
            system,
            kexec,
            reboot,
            live,
            drain,
            ..
        } => *system || *kexec || *reboot || *live || *drain,
        PackageCommand::Rollback {
            system,
            image,
            kexec,
            reboot,
            live,
            drain,
            ..
        } => *system || *image || *kexec || *reboot || *live || *drain,
        PackageCommand::Registry { system, .. } => *system,
        PackageCommand::Docs { command } => documentation_requires_host_runtime(command),
        PackageCommand::Options { command } => options_require_host_runtime(command),
        PackageCommand::Schema { system, .. } => *system,
        PackageCommand::Attest { command } => match command {
            AttestCommand::Quote { .. } | AttestCommand::VerifyBootCommit { .. } => true,
            AttestCommand::Verify { system, .. } | AttestCommand::Catalog { system, .. } => *system,
            AttestCommand::Enroll { .. } => false,
        },
        PackageCommand::TestVerifyPackageAttestation { system, .. } => *system,
        PackageCommand::Remove { .. }
        | PackageCommand::Autoremove
        | PackageCommand::Reinstall { .. }
        | PackageCommand::FullUpgrade
        | PackageCommand::Hold { .. }
        | PackageCommand::Unhold { .. }
        | PackageCommand::Gc
        | PackageCommand::Verify { .. }
        | PackageCommand::Source { .. }
        | PackageCommand::Credential(_) => false,
        PackageCommand::ActivatePreEtcSwap { .. }
        | PackageCommand::ActivatePostEtcSwap { .. }
        | PackageCommand::ActivateRestoreRoutedSources { .. }
        | PackageCommand::RecoverCredentialTransactions
        | PackageCommand::TestSystemdClient { .. }
        | PackageCommand::TestReconcileExposedUnits { .. }
        | PackageCommand::TestProducePackageAttestationQuote { .. }
        | PackageCommand::LoadEbpfLsmPolicies { .. }
        | PackageCommand::Eval { .. }
        | PackageCommand::EvalRetained { .. }
        | PackageCommand::Materialize { .. }
        | PackageCommand::ActivateConfig { .. }
        | PackageCommand::Switch { .. }
        | PackageCommand::Config { .. }
        | PackageCommand::Fetch { .. }
        | PackageCommand::RenderOne { .. }
        | PackageCommand::GraphCompile { .. } => true,
    }
}

/// Returns whether a command is observational with respect to user state.
///
/// The match is exhaustive so additions must be classified. Conditional
/// dry-run and query variants are admitted only when their parsed flags prove
/// they do not write.
fn is_read_only(command: &PackageCommand) -> bool {
    match command {
        PackageCommand::Search { .. }
        | PackageCommand::Show { .. }
        | PackageCommand::Info { .. }
        | PackageCommand::List { .. }
        | PackageCommand::Depends { .. }
        | PackageCommand::Rdepends { .. }
        | PackageCommand::Policy { .. }
        | PackageCommand::Files { .. }
        | PackageCommand::Held { .. }
        | PackageCommand::Orphans { .. }
        | PackageCommand::Verify { .. }
        | PackageCommand::TestVerifyPackageAttestation { .. } => true,
        PackageCommand::Docs { command } => documentation_is_read_only(command),
        PackageCommand::Options { .. } | PackageCommand::Schema { .. } => true,
        PackageCommand::Config { command } => runtime_config_is_read_only(command),
        PackageCommand::Source { fetch, verify, .. } => !*fetch && !*verify,
        PackageCommand::Rollback { list, .. } => *list,
        PackageCommand::Attest { command } => matches!(
            command,
            AttestCommand::Verify { .. }
                | AttestCommand::Catalog { .. }
                | AttestCommand::VerifyBootCommit { .. }
        ),
        PackageCommand::Credential(CredentialCommand::Encrypt { output, .. }) => output.is_none(),
        PackageCommand::Registry { command, .. } => registry_is_read_only(command),
        PackageCommand::Install { .. }
        | PackageCommand::Remove { .. }
        | PackageCommand::Autoremove
        | PackageCommand::Reinstall { .. }
        | PackageCommand::Update { .. }
        | PackageCommand::Upgrade { .. }
        | PackageCommand::FullUpgrade
        | PackageCommand::Hold { .. }
        | PackageCommand::Unhold { .. }
        | PackageCommand::Clean { .. }
        | PackageCommand::Gc
        | PackageCommand::ActivatePreEtcSwap { .. }
        | PackageCommand::ActivatePostEtcSwap { .. }
        | PackageCommand::ActivateRestoreRoutedSources { .. }
        | PackageCommand::RecoverCredentialTransactions
        | PackageCommand::TestSystemdClient { .. }
        | PackageCommand::TestReconcileExposedUnits { .. }
        | PackageCommand::TestProducePackageAttestationQuote { .. }
        | PackageCommand::LoadEbpfLsmPolicies { .. }
        | PackageCommand::Eval { .. }
        | PackageCommand::EvalRetained { .. }
        | PackageCommand::Materialize { .. }
        | PackageCommand::ActivateConfig { .. }
        | PackageCommand::Switch { .. }
        | PackageCommand::Fetch { .. }
        | PackageCommand::RenderOne { .. }
        | PackageCommand::GraphCompile { .. } => false,
    }
}

fn documentation_requires_host_runtime(command: &DocumentationCommand) -> bool {
    match command {
        DocumentationCommand::Search { system, .. }
        | DocumentationCommand::Show { system, .. }
        | DocumentationCommand::Man { system, .. }
        | DocumentationCommand::Lsp { system, .. }
        | DocumentationCommand::Serve { system, .. } => *system,
        DocumentationCommand::Cache { command } => match command {
            DocumentationCacheCommand::Status { system }
            | DocumentationCacheCommand::Gc { system } => *system,
        },
        DocumentationCommand::Schema { .. } => false,
    }
}

fn options_require_host_runtime(command: &OptionsCommand) -> bool {
    match command {
        OptionsCommand::Search { system, .. }
        | OptionsCommand::Show { system, .. }
        | OptionsCommand::Complete { system, .. } => *system,
        OptionsCommand::Compare { .. } => false,
    }
}

fn documentation_is_read_only(command: &DocumentationCommand) -> bool {
    match command {
        DocumentationCommand::Search { .. }
        | DocumentationCommand::Schema { .. }
        | DocumentationCommand::Lsp { .. }
        | DocumentationCommand::Serve { .. }
        | DocumentationCommand::Cache {
            command: DocumentationCacheCommand::Status { .. },
        } => true,
        DocumentationCommand::Show { output, .. } => output.is_none(),
        DocumentationCommand::Man { install, .. } => !*install,
        DocumentationCommand::Cache {
            command: DocumentationCacheCommand::Gc { .. },
        } => false,
    }
}

fn runtime_config_is_read_only(command: &RuntimeConfigCommand) -> bool {
    matches!(
        command,
        RuntimeConfigCommand::Status { .. }
            | RuntimeConfigCommand::List { .. }
            | RuntimeConfigCommand::Diff { .. }
    )
}

fn registry_is_read_only(command: &RegistryCommand) -> bool {
    match command {
        RegistryCommand::List
        | RegistryCommand::Show { .. }
        | RegistryCommand::Packages { .. }
        | RegistryCommand::Diff { .. }
        | RegistryCommand::Status { .. }
        | RegistryCommand::Log { .. }
        | RegistryCommand::Store {
            command: StoreCommand::Verify { .. },
        }
        | RegistryCommand::Trust {
            command: TrustCommand::List { .. },
        }
        | RegistryCommand::Keys {
            command: KeysCommand::List { .. },
        }
        | RegistryCommand::SbCerts {
            command: SbCertsCommand::List { .. },
        }
        | RegistryCommand::Branch {
            command: BranchCommand::List { .. },
        }
        | RegistryCommand::Channel {
            command: ChannelCommand::Status { .. },
        }
        | RegistryCommand::Change {
            command: ChangeCommand::List { .. } | ChangeCommand::Show { .. },
        } => true,
        RegistryCommand::Verify { fix, .. } | RegistryCommand::Validate { fix, .. } => !*fix,
        RegistryCommand::Cache {
            command: CacheCommand::Gc { dry_run, .. },
        }
        | RegistryCommand::Release { dry_run, .. } => *dry_run,
        RegistryCommand::Origin {
            command:
                OriginCommand::Config {
                    upload_urls,
                    token,
                    view,
                    http_user,
                    http_password,
                    header,
                    s3_region,
                    s3_profile,
                    s3_endpoint,
                    ssh_key,
                    ssh_password,
                    ssh_ask_pass,
                    unset,
                    ..
                },
        } => {
            upload_urls.is_empty()
                && token.is_none()
                && view.is_none()
                && http_user.is_none()
                && http_password.is_none()
                && header.is_empty()
                && s3_region.is_none()
                && s3_profile.is_none()
                && s3_endpoint.is_none()
                && ssh_key.is_none()
                && ssh_password.is_none()
                && !*ssh_ask_pass
                && unset.is_empty()
        }
        RegistryCommand::Create { .. }
        | RegistryCommand::Add { .. }
        | RegistryCommand::Remove { .. }
        | RegistryCommand::Enable { .. }
        | RegistryCommand::Disable { .. }
        | RegistryCommand::Trust { .. }
        | RegistryCommand::Keys { .. }
        | RegistryCommand::SbCerts { .. }
        | RegistryCommand::Publish { .. }
        | RegistryCommand::Unpublish { .. }
        | RegistryCommand::Commit { .. }
        | RegistryCommand::Branch { .. }
        | RegistryCommand::Push { .. }
        | RegistryCommand::Pull { .. }
        | RegistryCommand::Merge { .. }
        | RegistryCommand::Channel { .. }
        | RegistryCommand::Change { .. }
        | RegistryCommand::Cache { .. }
        | RegistryCommand::Store { .. }
        | RegistryCommand::Origin { .. }
        | RegistryCommand::Web { .. }
        | RegistryCommand::Tag { .. }
        | RegistryCommand::Sign { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: PackageCommand,
    }

    fn command(arguments: &[&str]) -> PackageCommand {
        TestCli::try_parse_from(std::iter::once("apm").chain(arguments.iter().copied()))
            .expect("test command parses")
            .command
    }

    #[test]
    fn detects_only_the_exact_runtime_markers() {
        assert_eq!(
            RuntimeBoundary::from_values(Some(OsStr::new("container")), Some(OsStr::new("1"))),
            RuntimeBoundary {
                container: true,
                read_only: true,
            }
        );
        assert_eq!(
            RuntimeBoundary::from_values(Some(OsStr::new("Container")), Some(OsStr::new("true"))),
            RuntimeBoundary::default()
        );
        assert_eq!(
            RuntimeBoundary::from_values(None, Some(OsStr::new("1"))),
            RuntimeBoundary {
                container: false,
                read_only: true,
            }
        );
    }

    #[test]
    fn unset_runtime_preserves_system_and_hidden_command_admission() {
        let boundary = RuntimeBoundary::default();
        boundary
            .validate(&command(&["list", "--system"]))
            .expect("unset marker preserves system behavior");
        boundary
            .validate(&command(&[
                "_test-systemd-client",
                "is-active",
                "a.service",
            ]))
            .expect("unset marker preserves hidden behavior");
    }

    #[test]
    fn writable_container_allows_user_scope_and_rejects_host_operations() {
        let boundary = RuntimeBoundary {
            container: true,
            read_only: false,
        };
        boundary
            .validate(&command(&["install", "hello"]))
            .expect("user install remains supported");
        boundary
            .validate(&command(&["registry", "list"]))
            .expect("user registry query remains supported");
        boundary
            .validate(&command(&["docs", "search", "hello"]))
            .expect("user documentation query remains supported");

        for arguments in [
            &["list", "--system"][..],
            &["docs", "search", "hello", "--system"][..],
            &["install", "hello", "--image", "raw"][..],
            &["attest", "quote", "--nonce", "00", "--output-dir", "/tmp/q"][..],
            &["_test-systemd-client", "is-active", "a.service"][..],
            &["activate-post-etc-swap", "--plan", "/tmp/plan"][..],
            &["activate-restore-routed-sources", "--plan", "/tmp/plan"][..],
        ] {
            let error = boundary
                .validate(&command(arguments))
                .expect_err("host operation is rejected");
            assert_eq!(error.to_string(), CONTAINER_HOST_OPERATION_ERROR);
        }
    }

    #[test]
    fn read_only_container_rejects_mutations_and_allows_queries() {
        let boundary = RuntimeBoundary {
            container: true,
            read_only: true,
        };
        for arguments in [
            &["install", "hello"][..],
            &["remove", "hello"][..],
            &["update"][..],
            &["gc"][..],
            &["source", "hello", "--fetch"][..],
            &["docs", "man", "hello", "--install"][..],
            &["registry", "add", "https://example.invalid/repo.git"][..],
        ] {
            let error = boundary
                .validate(&command(arguments))
                .expect_err("mutation is rejected");
            assert_eq!(error.to_string(), READ_ONLY_MUTATION_ERROR);
        }

        for arguments in [
            &["search", "hello"][..],
            &["show", "hello"][..],
            &["list"][..],
            &["source", "hello"][..],
            &["docs", "search", "hello"][..],
            &["options", "show", "services.example.enable"][..],
            &["schema"][..],
            &["rollback", "--list"][..],
            &["registry", "list"][..],
            &["registry", "verify"][..],
            &["registry", "branch", "list"][..],
            &["registry", "cache", "gc", "--dry-run"][..],
        ] {
            boundary
                .validate(&command(arguments))
                .expect("query remains admitted");
        }
    }

    #[test]
    fn system_error_takes_precedence_over_the_read_only_error() {
        let boundary = RuntimeBoundary {
            container: true,
            read_only: true,
        };
        let error = boundary
            .validate(&command(&["upgrade", "--system"]))
            .expect_err("system mutation is rejected");
        assert_eq!(error.to_string(), CONTAINER_HOST_OPERATION_ERROR);
    }
}
