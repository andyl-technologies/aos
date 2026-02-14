use anyhow::{bail, Context, Result};

use crate::nix::NixRunner;
use crate::output::{create_spinner, Printer};
use crate::server;

/// `aos gc` — garbage collection with local, view-based, or remote modes.
pub fn run(
    nix: &NixRunner,
    printer: &Printer,
    list_generations: bool,
    remote: Option<&str>,
    view: Option<&str>,
    collect: bool,
    dry_run: bool,
    all: bool,
) -> Result<()> {
    if list_generations {
        return show_generations(nix, printer);
    }

    // Remote mode: delegate to server via HTTP
    if let Some(url) = remote {
        return run_remote(printer, url, view, collect, dry_run, all);
    }

    // View-local mode: TTL expiry + eviction on local views
    if let Some(view_name) = view {
        return run_view_gc(nix, printer, view_name, collect, dry_run, all);
    }

    // Default: basic nix garbage collection
    collect_default(nix, printer)
}

/// Remote GC: call the server's GC endpoint.
fn run_remote(
    printer: &Printer,
    _url: &str,
    view: Option<&str>,
    _collect: bool,
    _dry_run: bool,
    _all: bool,
) -> Result<()> {
    let view_name = view.unwrap_or("default");
    printer.info(&format!("Remote GC not yet fully wired (view: {view_name})"));
    // TODO: HTTP client calls to server GC endpoint
    // This will be implemented when the GC HTTP endpoint is added to routes.rs
    bail!("remote GC is not yet implemented — use local view GC or basic GC")
}

/// View-local GC: expire TTL roots, run eviction if needed.
fn run_view_gc(
    nix: &NixRunner,
    printer: &Printer,
    view: &str,
    collect: bool,
    dry_run: bool,
    all: bool,
) -> Result<()> {
    use crate::server::evict;
    use crate::server::store::NixStore;
    use crate::server::views::ViewManager;

    let root = server::aos_root();
    let db_path = root.join("var/nix/db/db.sqlite");

    if !db_path.exists() {
        bail!("Nix store database not found at {}. Is this an AOS server?", db_path.display());
    }

    let store = NixStore::open(&db_path)
        .context("opening Nix store database")?;

    // We need a ViewManager but we don't have full config.
    // Create a minimal one with just the target view.
    let view_config = crate::server::config::ViewConfig {
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
    let spinner = create_spinner("checking TTL expiry");
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
                printer.plain(&format!("  would remove: {} ({})", root_info.hash, root_info.store_path));
            }
        } else {
            for root_info in &roots {
                let link = view_mgr.root().join("gcroots").join(view).join("bin").join(&root_info.hash);
                let meta = view_mgr.root().join("meta").join(view).join("bin").join(format!("{}.json", root_info.hash));
                let _ = std::fs::remove_file(&link);
                let _ = std::fs::remove_file(&meta);
            }
            printer.success(&format!("Removed {} roots from view '{view}'", roots.len()));
        }
    } else {
        // Step 2: Score and report eviction candidates
        let spinner = create_spinner("scoring eviction candidates");
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
        let spinner = create_spinner("collecting garbage");
        nix.collect_garbage(None)?;
        spinner.finish_and_clear();
        printer.success("Garbage collection complete");
    }

    Ok(())
}

fn collect_default(nix: &NixRunner, printer: &Printer) -> Result<()> {
    printer.info("Collecting garbage (deleting generations older than 7 days)...");

    let spinner = create_spinner("collecting garbage");
    nix.collect_garbage(Some("7d"))
        .context("garbage collection")?;
    spinner.finish_and_clear();

    if printer.json_if_active(&serde_json::json!({
        "action": "gc",
        "older_than": "7d",
        "status": "complete",
    })) {
        return Ok(());
    }

    printer.success("Garbage collection complete");

    Ok(())
}

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
