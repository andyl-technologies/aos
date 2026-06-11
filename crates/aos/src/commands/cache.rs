//! `aos cache` — the binary cache client (push, pull, prefetch, list).
//!
//! A thin dispatcher: it resolves the cache backend from the `--to` /
//! `--from` URL (`file://`, `http://`, `s3://`, `sftp://`), converts the
//! shared authentication flags into `aos_cache::backend::AuthOptions`,
//! and hands off to the matching `aos_cache::run_*` function, which does
//! the actual closure computation and transfers.

use anyhow::Result;

use aos_cache::backend::{self, AuthOptions};
use aos_core::output::Printer;

use crate::cli::{CacheAuthArgs, CacheCmd};

/// Entry point for `aos cache <subcommand>`.
///
/// # Errors
///
/// Returns an error if the cache URL cannot be resolved to a backend or
/// if the delegated `aos-cache` operation fails (evaluation, transfer,
/// or authentication).
pub async fn run(printer: &Printer, cmd: &CacheCmd) -> Result<()> {
    match cmd {
        CacheCmd::Push {
            installables,
            to,
            file,
            attr,
            expr,
            jobs,
            max_bandwidth,
            batch_threshold,
            compression,
            compression_level,
            dry_run,
            auth,
            ..
        } => {
            let auth_opts = auth_from_args(auth);
            let backend = backend::from_url(to, &auth_opts).await?;
            aos_cache::run_push(
                printer,
                backend.as_ref(),
                installables,
                file.as_deref(),
                attr.as_deref(),
                expr.as_deref(),
                *jobs,
                max_bandwidth.as_deref(),
                batch_threshold,
                compression.as_deref().unwrap_or("zstd"),
                *compression_level,
                *dry_run,
            )
            .await
        }
        CacheCmd::Pull {
            installables,
            from,
            file,
            attr,
            expr,
            jobs,
            max_bandwidth,
            dry_run,
            auth,
            ..
        } => {
            let auth_opts = auth_from_args(auth);
            let backend = backend::from_url(from, &auth_opts).await?;
            aos_cache::run_pull(
                printer,
                backend.as_ref(),
                installables,
                file.as_deref(),
                attr.as_deref(),
                expr.as_deref(),
                *jobs,
                max_bandwidth.as_deref(),
                *dry_run,
            )
            .await
        }
        CacheCmd::Prefetch {
            installables,
            to,
            file,
            attr,
            expr,
            jobs,
            dry_run,
            auth,
            ..
        } => {
            let auth_opts = auth_from_args(auth);
            let backend = backend::from_url(to, &auth_opts).await?;
            aos_cache::run_prefetch(
                printer,
                backend.as_ref(),
                installables,
                file.as_deref(),
                attr.as_deref(),
                expr.as_deref(),
                *jobs,
                *dry_run,
            )
            .await
        }
        CacheCmd::List {
            installables,
            from,
            file,
            attr,
            expr,
            auth,
            ..
        } => {
            let auth_opts = auth_from_args(auth);
            let backend = backend::from_url(from, &auth_opts).await?;
            aos_cache::run_list(
                printer,
                backend.as_ref(),
                installables,
                file.as_deref(),
                attr.as_deref(),
                expr.as_deref(),
            )
            .await
        }
    }
}

/// Convert CLI auth args to [`AuthOptions`].
fn auth_from_args(args: &CacheAuthArgs) -> AuthOptions {
    AuthOptions {
        token: args.token.clone(),
        view: args.view.clone(),
        http_user: args.http_user.clone(),
        http_password: args.http_password.clone(),
        headers: args.header.clone(),
        s3_region: args.s3_region.clone(),
        s3_profile: args.s3_profile.clone(),
        s3_endpoint: args.s3_endpoint.clone(),
        ssh_key: args.ssh_key.clone(),
        ssh_password: args.ssh_password.clone(),
        ssh_ask_pass: args.ssh_ask_pass,
    }
}
