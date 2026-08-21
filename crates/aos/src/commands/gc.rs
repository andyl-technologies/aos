//! `aos gc` — garbage collection across local, view, and remote stores.
//!
//! One command, several modes selected by the flags:
//!
//! - **Default** — local `nix-store` GC, deleting generations older than
//!   the 7-day retention window.
//! - **`--list-generations`** — list system generations instead of
//!   collecting.
//! - **`--view NAME`** — server-style view GC on the local AOS store:
//!   expire TTL roots, score and report eviction candidates, and (with
//!   `--collect`) run `nix-store --gc`. `--all` removes every root for
//!   the view (decommission); `--pin PATH` creates a permanent root.
//! - **`--remote URL`** — delegate GC to a remote AOS server over
//!   ConnectRPC (requires `--token`/`AOS_TOKEN`).

use anyhow::{Context, Result, bail};

use aos_core::nix::NixRunner;
use aos_core::output::Printer;
use aos_remote::AosClient;

/// Default retention period for local garbage collection.
const DEFAULT_GC_RETENTION: &str = "7d";

/// `aos gc` — garbage collection with local, view-based, or remote modes.
///
/// Dispatches to one of the modes described in the module docs based on
/// which flags are set.
///
/// # Errors
///
/// Returns an error if mutually-dependent flags are missing (`--pin`
/// without `--view`, remote mode without a token), if the local store
/// database is absent in view mode, or if the underlying GC operation
/// (local `nix-store`, view eviction, or remote RPC) fails.
pub async fn run(
    nix: &NixRunner,
    printer: &Printer,
    list_generations: bool,
    remote: Option<&str>,
    view: Option<&str>,
    token: Option<&str>,
    collect: bool,
    dry_run: bool,
    all: bool,
    pin: Option<&str>,
) -> Result<()> {
    if list_generations {
        return show_generations(nix, printer);
    }

    // Pin mode: create a permanent GC root (requires --view)
    if let Some(pin_path) = pin {
        if let Some(view_name) = view {
            return pin_root(nix, printer, view_name, pin_path);
        }
        bail!("--pin requires --view");
    }

    // Remote mode: delegate to server via HTTP
    if let Some(url) = remote {
        return run_remote(printer, url, view, token, collect, dry_run, all).await;
    }

    // View-local mode: TTL expiry + eviction on local views
    if let Some(view_name) = view {
        return run_view_gc(nix, printer, view_name, collect, dry_run, all);
    }

    // Default: basic nix garbage collection
    collect_default(nix, printer)
}

/// Remote GC: call the server's GC endpoint and report the results
/// (expired roots, eviction candidates, bytes freed).
async fn run_remote(
    printer: &Printer,
    url: &str,
    view: Option<&str>,
    token: Option<&str>,
    collect: bool,
    dry_run: bool,
    _all: bool,
) -> Result<()> {
    let view_name = view.unwrap_or("default");
    let token = token.context("--token (or AOS_TOKEN) is required for remote GC")?;

    let spinner = printer.activity("authenticating with remote server");
    let client = AosClient::connect(url, view_name, token).await?;
    spinner.finish_and_clear();

    let spinner = printer.activity(&format!("running GC on view '{view_name}'"));
    let resp = client.gc(dry_run, collect, None).await?;
    spinner.finish_and_clear();

    if resp.dry_run {
        printer.info("[dry run]");
    }

    printer.info(&format!("Expired {} TTL roots", resp.expired));

    if resp.eviction_candidates.is_empty() {
        printer.info("No eviction candidates");
    } else {
        printer.header(&format!("Eviction candidates ({} total):", resp.evicted));
        for c in &resp.eviction_candidates {
            let size_mb = c.unique_size as f64 / (1024.0 * 1024.0);
            printer.plain(&format!(
                "  {}: score={:.0} age={:.1}d unique={size_mb:.1}MB {}",
                c.hash, c.score, c.age_days, c.store_path
            ));
        }
    }

    if let Some(freed) = resp.collected_bytes {
        let freed_mb = freed as f64 / (1024.0 * 1024.0);
        printer.info(&format!(
            "Collected: {freed_mb:.1} MB freed by nix-store --gc"
        ));
    }

    printer.success("Remote GC complete");
    Ok(())
}

/// View-local GC: expire TTL roots, then either remove all roots
/// (`--all`, decommission mode) or score and report eviction candidates;
/// finally run `nix-store --gc` if `--collect` was given.
fn run_view_gc(
    nix: &NixRunner,
    printer: &Printer,
    view: &str,
    collect: bool,
    dry_run: bool,
    all: bool,
) -> Result<()> {
    use aos_server::evict;
    use aos_server::store::NixStore;
    use aos_server::views::ViewManager;

    let root = aos_server::aos_root();
    let db_path = root.join("var/nix/db/db.sqlite");

    if !db_path.exists() {
        bail!(
            "Nix store database not found at {}. Is this an AOS server?",
            db_path.display()
        );
    }

    let store = NixStore::open(&db_path).context("opening Nix store database")?;

    // We need a ViewManager but we don't have full config.
    // Create a minimal one with just the target view.
    let view_config = aos_server::config::ViewConfig {
        name: view.to_string(),
        ttl: None,
        source_ttl: None,
        source_mirror: true,
        anonymous_read: false,
        max_concurrent_builds: 4,
        max_store_size: None,
        max_paths: None,
    };
    let view_mgr = ViewManager::new(root.clone(), vec![view_config]);

    // Step 1: Expire TTL roots
    let spinner = printer.activity("checking TTL expiry");
    let expired = evict::expire_ttl_roots(&view_mgr, view)?;
    spinner.finish_and_clear();

    if !expired.is_empty() {
        printer.info(&format!("Expired {} TTL roots", expired.len()));
        for hash in &expired {
            printer.plain(&format!("  expired: {hash}"));
        }
    }

    if all {
        // Remove ALL roots for this view (decommission mode)
        printer.info(&format!("Removing all roots for view '{view}'..."));
        let roots = evict::scan_roots(&view_mgr, view)?;
        if dry_run {
            printer.info(&format!("Would remove {} roots (dry run)", roots.len()));
            for root_info in &roots {
                printer.plain(&format!(
                    "  would remove: {} ({})",
                    root_info.hash, root_info.store_path
                ));
            }
        } else {
            for root_info in &roots {
                let link = view_mgr
                    .root()
                    .join("gcroots")
                    .join(view)
                    .join("bin")
                    .join(&root_info.hash);
                let meta = view_mgr
                    .root()
                    .join("meta")
                    .join(view)
                    .join("bin")
                    .join(format!("{}.json", root_info.hash));
                if let Err(e) = std::fs::remove_file(&link) {
                    eprintln!("warning: failed to remove gc root {}: {e}", link.display());
                }
                if let Err(e) = std::fs::remove_file(&meta) {
                    eprintln!(
                        "warning: failed to remove gc metadata {}: {e}",
                        meta.display()
                    );
                }
            }
            printer.success(&format!("Removed {} roots from view '{view}'", roots.len()));
        }
    } else {
        // Step 2: Score and report eviction candidates
        let spinner = printer.activity("scoring eviction candidates");
        let roots = evict::scan_roots(&view_mgr, view)?;
        let candidates = evict::score_candidates(&store, &roots)?;
        spinner.finish_and_clear();

        if candidates.is_empty() {
            printer.info("No eviction candidates found");
        } else {
            printer.header("Eviction candidates (highest score first):");
            for c in &candidates {
                let size_mb = c.unique_size as f64 / (1024.0 * 1024.0);
                printer.plain(&format!(
                    "  {}: score={:.0} age={:.1}d unique={:.1}MB {}",
                    c.hash, c.score, c.age_days, size_mb, c.store_path
                ));
            }
        }
    }

    // Step 3: Run nix-store --gc if requested
    if collect && !dry_run {
        printer.info("Running nix-store --gc...");
        let spinner = printer.activity("collecting garbage");
        nix.collect_garbage(None)?;
        spinner.finish_and_clear();
        printer.success("Garbage collection complete");
    }

    Ok(())
}

/// Default mode: local `nix-store` GC with the standard retention window.
fn collect_default(nix: &NixRunner, printer: &Printer) -> Result<()> {
    printer.info(&format!(
        "Collecting garbage (deleting generations older than {DEFAULT_GC_RETENTION})..."
    ));

    let spinner = printer.activity("collecting garbage");
    nix.collect_garbage(Some(DEFAULT_GC_RETENTION))
        .context("garbage collection")?;
    spinner.finish_and_clear();

    if printer.json_if_active(&serde_json::json!({
        "action": "gc",
        "older_than": DEFAULT_GC_RETENTION,
        "status": "complete",
    })) {
        return Ok(());
    }

    printer.success("Garbage collection complete");

    Ok(())
}

/// Pin a store path as a permanent GC root (no TTL expiry) in a view.
fn pin_root(_nix: &NixRunner, printer: &Printer, view: &str, store_path: &str) -> Result<()> {
    use aos_server::views::ViewManager;
    use std::time::{SystemTime, UNIX_EPOCH};

    let root = aos_server::aos_root();

    let view_config = aos_server::config::ViewConfig {
        name: view.to_string(),
        ttl: None,
        source_ttl: None,
        source_mirror: true,
        anonymous_read: false,
        max_concurrent_builds: 4,
        max_store_size: None,
        max_paths: None,
    };
    let view_mgr = ViewManager::new(root.clone(), vec![view_config]);

    let hash =
        ViewManager::store_path_hash(store_path).context("extracting hash from store path")?;

    // Create the GC root symlink.
    view_mgr.create_gc_root(view, "bin", hash, store_path)?;

    // Write metadata with no expires_at (permanent).
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock error")?
        .as_secs() as i64;

    let meta = serde_json::json!({
        "store_path": store_path,
        "pushed_at": now,
        "access_count": 0,
        "pinned": true,
    });
    view_mgr.write_metadata(view, "bin", hash, &meta)?;

    printer.success(&format!(
        "Pinned {store_path} in view '{view}' (permanent, no TTL)"
    ));
    Ok(())
}

/// `--list-generations` mode: print the system generation list.
fn show_generations(nix: &NixRunner, printer: &Printer) -> Result<()> {
    printer.info("Listing system generations...");

    let output = nix
        .list_generations()
        .context("listing system generations")?;

    if printer.json_if_active(&serde_json::json!({
        "action": "list-generations",
        "output": output.trim(),
    })) {
        return Ok(());
    }

    printer.header("System generations:");
    printer.plain(output.trim());

    Ok(())
}
