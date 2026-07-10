//! Binary cache client for the `aos cache` subcommands.
//!
//! This crate implements push/pull/list/prefetch against Nix-compatible
//! binary caches. A cache is addressed by URL and accessed through the
//! [`CacheBackend`] trait, with one implementation per scheme:
//!
//! - `file://` — local directory ([`backend::fs::FsBackend`])
//! - `http://` / `https://` — generic binary caches and the AOS server API
//!   ([`backend::http::HttpBackend`])
//! - `s3://` — S3 buckets ([`backend::s3::S3Backend`])
//! - `sftp://` / `ssh://` — remote directories over SSH
//!   ([`backend::sftp::SftpBackend`])
//!
//! [`from_url`] picks the right backend from a URL string plus
//! [`AuthOptions`] collected from CLI flags.
//!
//! # How the pieces fit
//!
//! - [`resolve`] turns installable arguments (bare names, `-A` attrs, raw
//!   expressions, direct store paths) into store paths via the Nix CLI.
//! - [`push`] ([`run_push`]) enumerates the closure, queries the cache for
//!   missing paths, compresses NARs ([`compress`]), and uploads NAR +
//!   narinfo pairs — batching small NARs into packs for AOS servers.
//! - [`pull`] ([`run_pull`]) downloads narinfo + compressed NARs for paths
//!   missing locally and imports them with `nix-store --import`.
//! - [`list`] ([`run_list`]) reports local-store vs cache presence for a
//!   closure.
//! - [`prefetch`] ([`run_prefetch`]) discovers fixed-output derivations
//!   ([`discover`]) in a build closure, realises the missing sources, and
//!   pushes them so later builds never hit upstream mirrors.
//! - [`bandwidth`] provides a shared token-bucket limiter and
//!   human-readable rate/size parsing for `--max-bandwidth`-style flags.

#![forbid(unsafe_code)]

pub mod backend;
pub mod bandwidth;
pub mod compress;
pub mod discover;
pub mod list;
pub mod prefetch;
pub mod pull;
pub mod push;
pub mod resolve;

pub use backend::{AuthOptions, CacheBackend, from_url};
pub use list::run_list;
pub use prefetch::run_prefetch;
pub use pull::run_pull;
pub use push::run_push;

#[cfg(test)]
mod tests {
    #[test]
    fn cache_operations_use_configured_nix_cli() {
        for (module, source) in [
            ("list", include_str!("list.rs")),
            ("prefetch", include_str!("prefetch.rs")),
            ("pull", include_str!("pull.rs")),
            ("push", include_str!("push.rs")),
        ] {
            assert!(
                !source.contains("NixCli::new(0)"),
                "{module} must not drop evaluator options"
            );
            assert!(
                source.contains("NixCli::with_eval_config(0, eval_config.clone())"),
                "{module} must construct NixCli with the caller's eval config"
            );
        }
    }
}
