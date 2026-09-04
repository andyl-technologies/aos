//! Arguments for Hub OCI container administration.
//!
//! The top-level `aos container` namespace transfers artifacts. These commands
//! inspect and mutate the Hub catalog through `ContainerService`, using the
//! same reviewed plan/apply and optimistic-concurrency contract as the rest of
//! `aos hub`.

use clap::Subcommand;

use super::{HubAccessArgs, HubMutationArgs, HubPaginationArgs};

#[derive(Subcommand)]
pub enum HubContainerCmd {
    /// Inspect and administer repositories
    Repository {
        #[command(subcommand)]
        command: HubContainerRepositoryCmd,
    },
    /// Inspect and administer tags
    Tag {
        #[command(subcommand)]
        command: HubContainerTagCmd,
    },
    /// Inspect manifests and indexes
    Manifest {
        #[command(subcommand)]
        command: HubContainerManifestCmd,
    },
    /// Inspect runnable platform variants
    Platform {
        #[command(subcommand)]
        command: HubContainerPlatformCmd,
    },
    /// Inspect compressed layers and closure mappings
    Layer {
        #[command(subcommand)]
        command: HubContainerLayerCmd,
    },
    /// Inspect OCI referrers and evidence
    Referrer {
        #[command(subcommand)]
        command: HubContainerReferrerCmd,
    },
    /// Inspect verified publication transactions
    Publication {
        #[command(subcommand)]
        command: HubContainerPublicationCmd,
    },
    /// Inspect signed release and package provenance
    Provenance {
        #[command(subcommand)]
        command: HubContainerProvenanceCmd,
    },
    /// Inspect and update container retention policy
    Retention {
        #[command(subcommand)]
        command: HubContainerRetentionCmd,
    },
    /// Plan and inspect container garbage collection
    Gc {
        #[command(subcommand)]
        command: HubContainerGcCmd,
    },
}

#[derive(Subcommand)]
pub enum HubContainerRepositoryCmd {
    /// List visible repositories in one registry
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[arg(long)]
        repository_prefix: Option<String>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one repository and its usage summary
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        repository: String,
    },
    /// Plan creation or apply a reviewed repository plan
    Create {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: Option<String>,
        repository: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Plan a description update or apply a reviewed plan
    Update {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: Option<String>,
        repository: Option<String>,
        #[arg(long, conflicts_with = "clear_description")]
        description: Option<String>,
        #[arg(long, conflicts_with = "description")]
        clear_description: bool,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Plan deletion of an empty repository or apply a reviewed plan
    Delete {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: Option<String>,
        repository: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubContainerTagCmd {
    /// List tags in one repository
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        repository: String,
        #[arg(long)]
        tag_prefix: Option<String>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one tag and its current target
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        repository: String,
        tag: String,
    },
    /// Resolve a tag or digest to an exact manifest
    Resolve {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        repository: String,
        reference: String,
    },
    /// List the append-only history of one tag
    History {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        repository: String,
        tag: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Plan a manual tag compare-and-swap or apply a reviewed plan
    Set {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: Option<String>,
        repository: Option<String>,
        tag: Option<String>,
        #[arg(long)]
        digest: Option<String>,
        #[arg(long)]
        if_digest: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Plan removal of a manual tag or apply a reviewed plan
    Unset {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: Option<String>,
        repository: Option<String>,
        tag: Option<String>,
        #[arg(long, required_unless_present = "plan_id")]
        if_digest: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubContainerManifestCmd {
    /// Show one manifest or index by tag or digest
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        repository: String,
        reference: String,
    },
}

#[derive(Subcommand)]
pub enum HubContainerPlatformCmd {
    /// List platform variants under one image index
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        repository: String,
        reference: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one platform variant and its image configuration
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        repository: String,
        reference: String,
        platform: String,
        #[arg(long)]
        os_version: Option<String>,
        #[arg(long = "os-feature")]
        os_features: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum HubContainerLayerCmd {
    /// List layers under one platform manifest
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        repository: String,
        reference: String,
        #[arg(long)]
        platform: Option<String>,
        #[arg(long, requires = "platform")]
        os_version: Option<String>,
        #[arg(long = "os-feature", requires = "platform")]
        os_features: Vec<String>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one layer, size accounting, and closure packages
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        repository: String,
        root: String,
        manifest: String,
        digest: String,
    },
}

#[derive(Subcommand)]
pub enum HubContainerReferrerCmd {
    /// List referrers attached to one manifest subject
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        repository: String,
        subject: String,
        #[arg(long)]
        artifact_type: Option<String>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubContainerPublicationCmd {
    /// List verified publication transactions
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[arg(long)]
        repository: Option<String>,
        #[arg(long)]
        state: Option<String>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Show one publication and its placement health
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        publication_id: String,
    },
}

#[derive(Subcommand)]
pub enum HubContainerProvenanceCmd {
    /// Show signed release, package, source, license, and SBOM provenance
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        repository: String,
        reference: String,
        #[arg(long)]
        release: String,
    },
}

#[derive(Subcommand)]
pub enum HubContainerRetentionCmd {
    /// Show the effective retention policy
    Show {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
    },
    /// Plan a retention-policy update or apply a reviewed plan
    Set {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: Option<String>,
        #[arg(long)]
        untagged_grace: Option<String>,
        #[arg(long)]
        deleted_tag_history: Option<String>,
        #[arg(long)]
        recent_manual_tag_revisions: Option<u32>,
        #[arg(long, value_parser = ["enabled", "disabled"])]
        retain_referrers: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubContainerGcCmd {
    /// Create a reviewable garbage-collection plan
    Plan {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[arg(long)]
        if_version: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Apply one reviewed garbage-collection plan
    Apply {
        #[command(flatten)]
        access: HubAccessArgs,
        #[arg(long)]
        plan_id: String,
        #[arg(long)]
        confirm_hash: String,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        yes: bool,
    },
    /// Requeue one failed frozen placement action after exact repair
    Requeue {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        run_id: String,
        action_id: String,
        #[arg(long)]
        if_version: String,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        yes: bool,
    },
    /// Inspect and repair provider objects missing catalog identity
    Untracked {
        #[command(subcommand)]
        command: HubContainerGcUntrackedCmd,
    },
    /// Review, apply, or inspect the registry writer fence required for purge
    PurgeFence {
        #[command(subcommand)]
        command: HubContainerGcPurgeFenceCmd,
    },
    /// Get one garbage-collection plan or operation
    #[command(alias = "status")]
    Get {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        id: String,
    },
    /// List garbage-collection plans and runs
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        /// List runs, candidates, blockers, or placement-actions.
        #[arg(long, default_value = "runs", value_parser = ["runs", "candidates", "blockers", "placement-actions"])]
        resource: String,
        /// Exact run required for candidate, blocker, and placement-action lists.
        #[arg(long)]
        run_id: Option<String>,
        #[arg(long)]
        state: Option<String>,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
}

#[derive(Subcommand)]
pub enum HubContainerGcPurgeFenceCmd {
    /// Plan acquisition or explicit abort of the purge writer fence
    Plan {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[arg(long, value_parser = ["begin", "abort"])]
        action: String,
        #[arg(long)]
        if_version: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Apply one reviewed purge-fence plan
    Apply {
        #[command(flatten)]
        access: HubAccessArgs,
        #[arg(long)]
        plan_id: String,
        #[arg(long)]
        confirm_hash: String,
        #[arg(long)]
        if_version: String,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        yes: bool,
    },
    /// Read one actor-owned purge-fence plan and current readiness
    Status {
        #[command(flatten)]
        access: HubAccessArgs,
        plan_id: String,
    },
}

#[derive(Subcommand)]
pub enum HubContainerGcUntrackedCmd {
    /// List exact current-head untracked provider observations
    List {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: String,
        #[command(flatten)]
        pagination: HubPaginationArgs,
    },
    /// Plan an exact conditional delete or apply its reviewed plan
    Repair {
        #[command(flatten)]
        access: HubAccessArgs,
        registry: Option<String>,
        #[arg(long)]
        placement_id: Option<i64>,
        #[arg(long)]
        inventory_generation_id: Option<String>,
        #[arg(long)]
        object_key: Option<String>,
        #[command(flatten)]
        mutation: HubMutationArgs,
    },
    /// Read one actor-owned durable repair and its conditional evidence
    RepairStatus {
        #[command(flatten)]
        access: HubAccessArgs,
        plan_id: String,
    },
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Commands, HubCmd, HubRegistryCmd};

    #[test]
    fn parses_repository_inventory_and_platform_inspection() {
        let cli = Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "repository",
            "list",
            "andyl/main",
            "--repository-prefix",
            "base/",
            "--page-size",
            "25",
        ])
        .expect("container repository list command");
        let Commands::Hub {
            command:
                HubCmd::Registry {
                    command:
                        HubRegistryCmd::Container {
                            command:
                                HubContainerCmd::Repository {
                                    command:
                                        HubContainerRepositoryCmd::List {
                                            registry,
                                            repository_prefix,
                                            pagination,
                                            ..
                                        },
                                },
                        },
                },
        } = cli.command
        else {
            panic!("expected Hub container repository list command");
        };
        assert_eq!(registry, "andyl/main");
        assert_eq!(repository_prefix.as_deref(), Some("base/"));
        assert_eq!(pagination.page_size, Some(25));

        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "platform",
            "show",
            "andyl/main",
            "aos",
            "stable",
            "linux/amd64",
            "--os-version",
            "6.8",
            "--os-feature",
            "seccomp",
            "--os-feature",
            "landlock",
        ])
        .expect("container platform show command");

        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "layer",
            "show",
            "andyl/main",
            "aos",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ])
        .expect("container layer show binds root, manifest, and layer digests");

        assert!(
            Cli::try_parse_from([
                "aos",
                "hub",
                "registry",
                "container",
                "provenance",
                "show",
                "andyl/main",
                "aos",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ])
            .is_err()
        );
        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "provenance",
            "show",
            "andyl/main",
            "aos",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--release",
            "1.2.3",
        ])
        .expect("container provenance binds the exact release identity");
    }

    #[test]
    fn reviewed_mutations_allow_plan_and_apply_recovery() {
        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "tag",
            "set",
            "andyl/main",
            "aos",
            "stable",
            "--digest",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--if-version",
            "7",
            "--plan",
        ])
        .expect("manual tag plan command");

        assert!(
            Cli::try_parse_from([
                "aos",
                "hub",
                "registry",
                "container",
                "tag",
                "unset",
                "andyl/main",
                "aos",
                "manual",
                "--if-version",
                "7",
                "--plan",
            ])
            .is_err()
        );
        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "tag",
            "unset",
            "andyl/main",
            "aos",
            "manual",
            "--if-version",
            "7",
            "--if-digest",
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "--plan",
        ])
        .expect("manual tag unset binds the exact prior digest");

        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "retention",
            "set",
            "--plan-id",
            "plan-1",
            "--confirm-hash",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--yes",
        ])
        .expect("retention apply command");
    }

    #[test]
    fn container_gc_exposes_exact_plan_apply_get_and_bounded_lists() {
        assert!(
            Cli::try_parse_from([
                "aos",
                "hub",
                "registry",
                "container",
                "gc",
                "plan",
                "andyl/main",
            ])
            .is_err()
        );
        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "gc",
            "plan",
            "andyl/main",
            "--if-version",
            "7",
        ])
        .expect("GC plan requires the retention policy CAS version");
        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "gc",
            "apply",
            "--plan-id",
            "gc-1",
            "--confirm-hash",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--idempotency-key",
            "change-1",
            "--yes",
        ])
        .expect("GC apply carries confirmation and idempotency");
        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "gc",
            "requeue",
            "andyl/main",
            "gc-1",
            "action-1",
            "--if-version",
            "9",
            "--idempotency-key",
            "repair-1",
            "--yes",
        ])
        .expect("GC requeue binds registry, run, action, CAS, and idempotency");
        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "gc",
            "get",
            "andyl/main",
            "gc-1",
        ])
        .expect("GC get command");
        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "gc",
            "list",
            "andyl/main",
            "--resource",
            "placement-actions",
            "--run-id",
            "gc-1",
            "--state",
            "failed",
            "--page-size",
            "25",
        ])
        .expect("GC placement-action keyset list");

        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "gc",
            "untracked",
            "list",
            "andyl/main",
            "--page-size",
            "25",
            "--page-token",
            "opaque-current-head-cursor",
        ])
        .expect("untracked inventory uses bounded keyset pagination");
        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "gc",
            "untracked",
            "repair",
            "andyl/main",
            "--placement-id",
            "4",
            "--inventory-generation-id",
            "inventory-7",
            "--object-key",
            "oci/blobs/sha256/deadbeef",
            "--if-version",
            "12",
            "--plan",
        ])
        .expect("untracked repair plan binds head, object, placement, and epoch");
        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "gc",
            "untracked",
            "repair",
            "--plan-id",
            "repair-1",
            "--confirm-hash",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--if-version",
            "1",
            "--idempotency-key",
            "repair-apply-1",
            "--yes",
        ])
        .expect("untracked repair apply binds plan, confirmation, CAS, and retry key");
        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "gc",
            "untracked",
            "repair-status",
            "repair-1",
        ])
        .expect("untracked repair status is actor-bound by plan identity");
        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "gc",
            "purge-fence",
            "plan",
            "andyl/main",
            "--action",
            "begin",
            "--if-version",
            "9",
        ])
        .expect("purge-fence begin plan binds the registry CAS");
        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "gc",
            "purge-fence",
            "apply",
            "--plan-id",
            "purge-plan-1",
            "--confirm-hash",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--if-version",
            "1",
            "--idempotency-key",
            "purge-apply-1",
            "--yes",
        ])
        .expect("purge-fence apply binds review, CAS, and retry identity");
        Cli::try_parse_from([
            "aos",
            "hub",
            "registry",
            "container",
            "gc",
            "purge-fence",
            "status",
            "purge-plan-1",
        ])
        .expect("purge-fence status is actor-bound by plan identity");
    }
}
