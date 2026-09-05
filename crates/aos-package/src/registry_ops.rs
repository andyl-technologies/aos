//! Registry management operations (`apr` / `apm registry`).
//!
//! This module implements the producer-side `apr` command surface for
//! maintaining AOS package registries. A registry is a git repository
//! (SHA-256 object format) whose working tree holds `registry.toml`,
//! per-package metadata under `packages/<letter>/<name>.toml`, closure
//! adjacency lists under `closures/`, and the committed signing-key roster
//! `keys.toml`. Commands operate on local authoring clones stored at
//! `~/.local/share/apm/registries/<name>/`.
//!
//! The subcommand families map onto the registry git workflow as follows:
//!
//! - **Lifecycle**: [`create`] initializes a new authoring clone;
//!   [`local_registries`] and [`authoring_clone_precious`] support
//!   `apr list`/`apr remove` over clones that have no consumer config.
//! - **Publishing**: [`publish()`] introspects a Nix store path and records it
//!   in package TOML and `store/` realisation records for every
//!   closure member; [`unpublish`] removes packages, versions, or platform
//!   entries. Both commit the change (optionally SSH-signed) unless
//!   `--no-commit` is given. [`run_store`] maintains the realisation graph
//!   directly (bless/revoke/verify/backfill).
//! - **Query and integrity**: [`show`], [`packages`], [`verify`] (closure
//!   consistency), and [`validate`] (cache reachability over HTTP).
//! - **Git workflow**: [`status`], [`log`], [`diff`], [`run_branch`],
//!   [`push`], [`pull`], and [`merge`] wrap git in the registry clone.
//!   Network transports keep the host git configuration visible while all
//!   other invocations run hermetically (see `crate::registry::porcelain`).
//! - **Releases**: [`release()`] / [`release_registry_tree`] create the signed
//!   semver release tag and generate full/delta pack artifacts for the
//!   static dumb-HTTP origin; [`tag`] and [`sign`] manage signed tags
//!   directly.
//! - **Channels**: [`run_channel`] initializes and advances 256-partition
//!   rollout channels whose partitions are signed tag payloads stored under
//!   `.git/channels/`.
//! - **Keys and trust**: [`run_keys`] manages the committed `keys.toml`
//!   roster (generate/register/add/retire, including re-signing tags after
//!   a retirement); [`run_trust`] manages the consumer-side pinned trust
//!   store.
//! - **Distribution**: [`run_cache`] generates and uploads the static Nix
//!   binary cache; [`run_origin`] uploads the static git origin files;
//!   [`run_web`] generates and uploads the static no-JS web surface.
//!
//! After any operation that adds commits or moves refs, the static
//! dumb-HTTP object store metadata is refreshed so plain-file origins stay
//! cloneable.

mod attestation;
mod cache_validation;
mod channels;
mod config;
mod config_modules;
mod distribution;
mod documentation;
mod git;
mod images;
mod lifecycle;
mod mac;
mod metadata;
mod provenance;
mod publish;
mod query;
mod release;
mod sb_certs;
mod signing;
mod store_commands;
mod store_paths;
mod tags;
#[cfg(test)]
mod test_support;
mod trust;
mod uki;
mod workflow;

pub use cache_validation::validate;
pub use channels::run_channel;
pub use config::{resolve_mirrors, resolve_mirrors_for_registry};
pub use distribution::{run_cache, run_origin, run_web};
pub(crate) use git::{refresh_registry_object_store, validate_canonical_release_registry_index};
pub use lifecycle::{LocalRegistry, authoring_clone_precious, create, local_registries};
pub(crate) use provenance::require_active_registry_key;
pub use publish::publish;
pub(crate) use publish::publish_canonical_release_entry;
pub use query::{packages, show, unpublish, verify};
pub use release::{
    ContainerReleaseAttachment, ReleaseReport, ReleaseStorePublish, ReleaseTreeOptions,
    load_container_release_attachment, release, release_registry_tree,
};
pub use sb_certs::run_sb_certs;
pub use store_commands::run_store;
pub use tags::{sign, tag};
pub use trust::{run_keys, run_trust};
pub(crate) use uki::{extract_expected_pcr11, pe_section, verify_detached_db_signature};
pub use workflow::{commit_changes, diff, log, merge, pull, push, run_branch, run_change, status};
