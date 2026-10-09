//! Container-runtime and read-only command admission.
//!
//! The official AOS OCI image injects `AOS_RUNTIME=container`. Its init process
//! additionally injects `AOS_CONTAINER_READ_ONLY=1` when package state cannot
//! be mutated. This module interprets those exact markers and rejects an
//! incompatible command before configuration loading, profile discovery,
//! subprocess execution, or host-state access.

use std::ffi::OsStr;

use anyhow::{Result, bail};

use crate::{
    ApmRegistryCommand, AttestCommand, BranchCommand, CacheCommand, ChangeCommand, ChannelCommand,
    CredentialCommand, DocumentationCacheCommand, DocumentationCommand, ImageCommand, KeysCommand,
    OriginCommand, PackageCommand, RegistryCommand, RegistryStageCommand, RuntimeConfigCommand,
    StoreCommand, TrustCommand,
};

const RUNTIME_ENV: &str = "AOS_RUNTIME";
const READ_ONLY_ENV: &str = "AOS_CONTAINER_READ_ONLY";

const CONTAINER_HOST_OPERATION_ERROR: &str = "this operation requires host boot or TPM facilities unavailable in an AOS container. Run it on an AOS machine or VM.";
const READ_ONLY_MUTATION_ERROR: &str = "this AOS container is read-only; package mutations are unavailable. Restart it without the runtime's read-only-root option and mount writable APM and Nix state to modify packages.";

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

    fn profile_scope(self, system: bool) -> crate::types::ProfileScope {
        if system && !self.container {
            crate::types::ProfileScope::System
        } else {
            crate::types::ProfileScope::User
        }
    }

    fn configuration_scope(self) -> crate::types::ProfileScope {
        self.profile_scope(true)
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

    fn validate_registry(self, command: &RegistryCommand, _system: bool) -> Result<()> {
        if self.read_only && !registry_is_read_only(command) {
            bail!(READ_ONLY_MUTATION_ERROR);
        }
        Ok(())
    }
}

/// Returns whether the process runs in the official container environment.
pub(crate) fn is_container() -> bool {
    RuntimeBoundary::from_env().container
}

/// Resolves a requested scope to the profile owned by this runtime.
///
/// Container package and registry operations share the user profile seeded by
/// their image. `--system` aliases that same profile rather than creating a
/// separate namespace that container startup cannot recover or activate.
pub(crate) fn profile_scope(system: bool) -> crate::types::ProfileScope {
    RuntimeBoundary::from_env().profile_scope(system)
}

/// Selects the native profile whose operator configuration owns this runtime.
///
/// Container configuration extends the ordinary user package profile seeded by
/// the image. Machine configuration continues to own the system profile.
pub(crate) fn configuration_scope() -> crate::types::ProfileScope {
    RuntimeBoundary::from_env().configuration_scope()
}

/// Rejects explicit runtime incompatibilities before image setup can mutate state.
///
/// # Errors
///
/// Returns an error for host-only commands or explicitly read-only mutations.
pub(crate) fn validate_environment(command: &PackageCommand) -> Result<()> {
    RuntimeBoundary::from_env().validate(command)
}

/// Rejects explicitly read-only registry mutations before image setup.
///
/// # Errors
///
/// Returns an error when the read-only environment prohibits the mutation.
pub(crate) fn validate_registry_environment(command: &RegistryCommand, system: bool) -> Result<()> {
    RuntimeBoundary::from_env().validate_registry(command, system)
}

/// Checks the process runtime markers against one parsed package command.
///
/// Explicit environment admission and image setup precede this synchronization.
///
/// # Errors
///
/// Returns an error when the command requires host boot or TPM facilities, or
/// when read-only mode prohibits the requested mutation.
pub(crate) fn validate(command: &PackageCommand) -> Result<()> {
    let mut boundary = RuntimeBoundary::from_env();
    if boundary.container && requires_host_runtime(command) {
        bail!(CONTAINER_HOST_OPERATION_ERROR);
    }

    // The initializer invokes private deployment helpers while holding its
    // lock and before publishing readiness. Waiting here would deadlock it.
    if !command.is_runtime_internal() {
        if boundary.container && !crate::container_environment::package_state_writable() {
            boundary.read_only = true;
        } else if let Some(state) = aos_core::container_runtime::synchronize()? {
            boundary.read_only |= state.is_read_only();
        }
    }
    boundary.validate(command)
}

/// Checks runtime markers for one parsed registry-authoring command.
///
/// # Errors
///
/// Returns an error when read-only container mode prohibits the requested
/// authoring mutation.
pub(crate) fn validate_registry(command: &RegistryCommand, system: bool) -> Result<()> {
    let mut boundary = RuntimeBoundary::from_env();
    if boundary.container && !crate::container_environment::package_state_writable() {
        boundary.read_only = true;
    } else if let Some(state) = aos_core::container_runtime::synchronize()? {
        boundary.read_only |= state.is_read_only();
    }
    boundary.validate_registry(command, system)
}

/// Returns whether a command requires AOS host facilities unavailable in OCI.
///
/// Ordinary package and configuration commands are admitted here. Their
/// ability graphs validate the handlers required by the selected environment.
fn requires_host_runtime(command: &PackageCommand) -> bool {
    match command {
        PackageCommand::Image { .. } => true,
        PackageCommand::Attest {
            command: AttestCommand::Quote { .. },
        } => true,
        _ => false,
    }
}

/// Returns whether a command is observational with respect to user state.
///
/// The match is exhaustive so additions must be classified. Conditional
/// dry-run and query variants are admitted only when their parsed flags prove
/// they do not write.
fn is_read_only(command: &PackageCommand) -> bool {
    match command {
        PackageCommand::Image { command } => matches!(command, ImageCommand::List),
        PackageCommand::Apply { .. } => false,
        PackageCommand::Search { .. }
        | PackageCommand::Show { .. }
        | PackageCommand::List { .. }
        | PackageCommand::Depends { .. }
        | PackageCommand::Rdepends { .. }
        | PackageCommand::Policy { .. }
        | PackageCommand::Files { .. }
        | PackageCommand::Held { .. }
        | PackageCommand::Orphans { .. }
        | PackageCommand::Verify { .. }
        | PackageCommand::VerifyDeployment(..)
        | PackageCommand::DeploymentCurrent { .. }
        | PackageCommand::DeploymentRetainedEffects { .. }
        | PackageCommand::DeploymentResult { .. } => true,
        PackageCommand::Docs { command } => documentation_is_read_only(command),
        PackageCommand::Options { .. } | PackageCommand::Schema { .. } => true,
        PackageCommand::Config { command } => runtime_config_is_read_only(command),
        PackageCommand::Source { fetch, verify, .. } => !*fetch && !*verify,
        PackageCommand::Rollback { list, .. } => *list,
        PackageCommand::Attest { command } => matches!(
            command,
            AttestCommand::Verify { .. } | AttestCommand::Catalog { .. }
        ),
        PackageCommand::Credential(CredentialCommand::Encrypt { output, .. }) => output.is_none(),
        PackageCommand::Registry { command, .. } => apm_registry_is_read_only(command),
        PackageCommand::Install { .. }
        | PackageCommand::ApplyDeployment(..)
        | PackageCommand::ContainerStartup(..)
        | PackageCommand::Remove { .. }
        | PackageCommand::Autoremove { .. }
        | PackageCommand::Reinstall { .. }
        | PackageCommand::Update { .. }
        | PackageCommand::Upgrade { .. }
        | PackageCommand::FullUpgrade { .. }
        | PackageCommand::Hold { .. }
        | PackageCommand::Unhold { .. }
        | PackageCommand::Clean { .. }
        | PackageCommand::Gc { .. }
        | PackageCommand::Switch { .. } => false,
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
        RuntimeConfigCommand::Rollback { list: true, .. }
            | RuntimeConfigCommand::Status { .. }
            | RuntimeConfigCommand::List { .. }
            | RuntimeConfigCommand::Diff { .. }
    )
}

fn apm_registry_is_read_only(command: &ApmRegistryCommand) -> bool {
    matches!(
        command,
        ApmRegistryCommand::List
            | ApmRegistryCommand::Trust {
                command: TrustCommand::List { .. },
            }
    )
}

fn registry_is_read_only(command: &RegistryCommand) -> bool {
    match command {
        RegistryCommand::Stage { command } => matches!(
            command,
            RegistryStageCommand::List { .. } | RegistryStageCommand::Show { .. }
        ),
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

    #[derive(Parser)]
    struct TestRegistryCli {
        #[command(subcommand)]
        command: RegistryCommand,
    }

    fn command(arguments: &[&str]) -> PackageCommand {
        TestCli::try_parse_from(std::iter::once("apm").chain(arguments.iter().copied()))
            .expect("test command parses")
            .command
    }

    fn registry_command(arguments: &[&str]) -> RegistryCommand {
        TestRegistryCli::try_parse_from(std::iter::once("apr").chain(arguments.iter().copied()))
            .expect("test registry command parses")
            .command
    }

    #[test]
    fn remove_preserves_user_default_and_selects_system_scope_explicitly() {
        let user = command(&["remove", "nix-daemon"]);
        assert!(matches!(
            &user,
            PackageCommand::Remove { packages, autoremove: false, system: false }
                if packages == &["nix-daemon"]
        ));
        assert!(!user.is_system());
        assert_eq!(
            user.runtime_requirement(),
            crate::environment::RuntimeRequirement::Portable
        );

        let system = command(&["remove", "--system", "nix-daemon", "--autoremove"]);
        assert!(matches!(
            &system,
            PackageCommand::Remove { packages, autoremove: true, system: true }
                if packages == &["nix-daemon"]
        ));
        assert!(system.is_system());
        assert_eq!(
            system.runtime_requirement(),
            crate::environment::RuntimeRequirement::AosRoot
        );
        assert!(!is_read_only(&system));

        let container = RuntimeBoundary {
            container: true,
            read_only: false,
        };
        container.validate(&user).unwrap();
        container.validate(&system).unwrap();
    }

    #[test]
    fn image_prepare_requires_a_writable_host_and_system_scope() {
        for arguments in [
            &["image", "prepare", "server"][..],
            &[
                "image",
                "prepare",
                "server",
                "--registry",
                "trusted",
                "--qualified",
            ][..],
        ] {
            let command = command(arguments);
            assert!(command.is_system());
            assert_eq!(
                command.runtime_requirement(),
                crate::environment::RuntimeRequirement::LiveAos
            );
            RuntimeBoundary::default().validate(&command).unwrap();
            assert!(
                RuntimeBoundary {
                    container: true,
                    read_only: false
                }
                .validate(&command)
                .is_err()
            );
            assert!(
                RuntimeBoundary {
                    container: false,
                    read_only: true
                }
                .validate(&command)
                .is_err()
            );
        }
    }

    #[test]
    fn image_prepare_parser_preserves_registry_and_admission_purpose() {
        let parsed = command(&[
            "image",
            "prepare",
            "server",
            "--registry",
            "trusted",
            "--qualified",
        ]);
        assert!(matches!(parsed, PackageCommand::Image {
            command: crate::ImageCommand::Prepare { package, registry: Some(registry), qualified: true }
        } if package == "server" && registry == "trusted"));
        assert!(TestCli::try_parse_from(["apm", "image", "prepare"]).is_err());
        assert!(
            TestCli::try_parse_from(["apm", "image", "prepare", "server", "--reboot"]).is_err()
        );
    }

    #[test]
    fn requested_scopes_share_the_container_runtime_profile() {
        use crate::types::ProfileScope;

        let machine = RuntimeBoundary::default();
        let container = RuntimeBoundary::from_values(Some(OsStr::new("container")), None);
        let read_only =
            RuntimeBoundary::from_values(Some(OsStr::new("container")), Some(OsStr::new("1")));
        let unmatched = RuntimeBoundary::from_values(Some(OsStr::new("Container")), None);

        for system in [false, true] {
            assert_eq!(container.profile_scope(system), ProfileScope::User);
            assert_eq!(read_only.profile_scope(system), ProfileScope::User);
            let requested = if system {
                ProfileScope::System
            } else {
                ProfileScope::User
            };
            assert_eq!(machine.profile_scope(system), requested);
            assert_eq!(unmatched.profile_scope(system), requested);
        }
    }

    #[test]
    fn operator_configuration_uses_the_profile_seeded_by_its_runtime() {
        use crate::types::ProfileScope;

        let container = RuntimeBoundary::from_values(Some(OsStr::new("container")), None);
        let read_only =
            RuntimeBoundary::from_values(Some(OsStr::new("container")), Some(OsStr::new("1")));

        assert_eq!(container.configuration_scope(), ProfileScope::User);
        assert_eq!(read_only.configuration_scope(), ProfileScope::User);
        assert_eq!(
            RuntimeBoundary::default().configuration_scope(),
            ProfileScope::System
        );
        assert_eq!(
            RuntimeBoundary::from_values(Some(OsStr::new("Container")), None).configuration_scope(),
            ProfileScope::System
        );
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
                "deployment-current",
                "--profile",
                "/tmp/profile",
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
            &["install", "nginx", "--system"][..],
            &["remove", "nginx", "--system"][..],
            &["reinstall", "nginx", "--system"][..],
            &["upgrade", "--system"][..],
            &["full-upgrade", "--system"][..],
            &["autoremove", "--system"][..],
            &["hold", "nginx", "--system"][..],
            &["unhold", "nginx", "--system"][..],
            &["verify", "nginx", "--system"][..],
            &["source", "nginx", "--system"][..],
            &["rollback", "--system"][..],
            &["gc", "--system"][..],
            &["apply", "--system", "--from", "desired.toml"][..],
            &["config", "rollback", "--list"][..],
            &["docs", "search", "hello", "--system"][..],
            &["deployment-current", "--profile", "/tmp/profile"][..],
            &["config", "status"][..],
        ] {
            boundary
                .validate(&command(arguments))
                .expect("portable and graph-validated operations remain admitted");
        }

        for arguments in [
            &["image", "install", "aos"][..],
            &["image", "upgrade"][..],
            &["image", "rollback"][..],
            &["image", "list"][..],
            &["image", "prepare", "aos"][..],
            &["image", "download", "hello", "--format", "raw"][..],
            &["attest", "quote", "--nonce", "00", "--output-dir", "/tmp/q"][..],
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
            &["schema", "hello"][..],
            &["rollback", "--list"][..],
            &["registry", "list"][..],
        ] {
            boundary
                .validate(&command(arguments))
                .expect("query remains admitted");
        }
    }

    #[test]
    fn read_only_container_classifies_registry_authoring_commands() {
        let boundary = RuntimeBoundary {
            container: true,
            read_only: true,
        };

        for arguments in [
            &["list"][..],
            &["verify"][..],
            &["branch", "list"][..],
            &["cache", "gc", "--dry-run"][..],
            &["stage", "list"][..],
            &["stage", "show", "candidate-1"][..],
        ] {
            boundary
                .validate_registry(&registry_command(arguments), false)
                .expect("registry query remains admitted");
        }

        let error = boundary
            .validate_registry(
                &registry_command(&["stage", "discard", "candidate-1", "--stage-revision", "1"]),
                false,
            )
            .expect_err("candidate discard is a mutation");
        assert_eq!(error.to_string(), READ_ONLY_MUTATION_ERROR);

        let error = boundary
            .validate_registry(&registry_command(&["create", "example"]), false)
            .expect_err("registry mutation is rejected");
        assert_eq!(error.to_string(), READ_ONLY_MUTATION_ERROR);

        RuntimeBoundary {
            container: true,
            read_only: false,
        }
        .validate_registry(&registry_command(&["list"]), true)
        .expect("system registry state is supported");
    }

    #[test]
    fn read_only_system_mutations_are_rejected() {
        let boundary = RuntimeBoundary {
            container: true,
            read_only: true,
        };
        let error = boundary
            .validate(&command(&["upgrade", "--system"]))
            .expect_err("system mutation is rejected");
        assert_eq!(error.to_string(), READ_ONLY_MUTATION_ERROR);
    }
}
