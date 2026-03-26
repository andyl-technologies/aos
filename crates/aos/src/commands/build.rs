use anyhow::{bail, Context, Result};

use aos_core::error::AosError;
use aos_core::nix::NixRunner;
use aos_core::output::{create_spinner, Printer};
use aos_remote::build::RemoteClient;
use aos_remote::sse::EventAction;

/// `aos build <package>` or `aos build --all`.
pub fn run(nix: &NixRunner, printer: &Printer, package: Option<&str>, all: bool) -> Result<()> {
    if all {
        return build_all(nix, printer);
    }

    let package = package.ok_or_else(|| AosError::InvalidArgument {
        message: "provide a package name, or use --all to build everything".to_string(),
    })?;

    let attr = format!("pkgs.{package}");

    printer.info(&format!("Building package '{package}'..."));

    let spinner = create_spinner(&format!("building {package}"));
    let store_path = nix
        .build(&attr, None)
        .with_context(|| format!("building package '{package}'"))?;
    spinner.finish_and_clear();

    if printer.json_if_active(&serde_json::json!({
        "package": package,
        "store_path": store_path.to_string_lossy(),
    })) {
        return Ok(());
    }

    printer.success(&format!(
        "Built {package} -> {}",
        store_path.display()
    ));

    Ok(())
}

/// `aos build <package> --remote URL` — evaluate locally, upload, build remotely.
pub async fn run_remote(
    nix: &NixRunner,
    printer: &Printer,
    package: Option<&str>,
    remote_url: &str,
    view: &str,
    token: Option<&str>,
) -> Result<()> {
    let package = package.ok_or_else(|| AosError::InvalidArgument {
        message: "provide a package name for remote builds".to_string(),
    })?;

    let token = token.ok_or_else(|| AosError::InvalidArgument {
        message: "provide --token or set AOS_TOKEN for remote builds".to_string(),
    })?;

    printer.info(&format!("Remote build: {package} on {remote_url} (view: {view})"));

    // Step 1: Evaluate locally to get the .drv path.
    let spinner = create_spinner(&format!("evaluating {package}"));
    let attr = format!("pkgs.{package}");
    let drv_path = nix
        .instantiate(&attr)
        .with_context(|| format!("evaluating package '{package}'"))?;
    spinner.finish_and_clear();
    let drv_str = drv_path.to_string_lossy().to_string();
    printer.info(&format!("Derivation: {drv_str}"));

    // Step 2: Authenticate with the remote server.
    let mut client = RemoteClient::new(remote_url, view, token)?;
    let spinner = create_spinner("authenticating");
    client.authenticate().await.context("authenticating with remote server")?;
    spinner.finish_and_clear();

    // Step 3: Query runtime closure and find missing paths.
    let spinner = create_spinner("querying closure");
    let closure_output = nix.store_query(&drv_path, &["-qR"])?;
    let closure: Vec<String> = closure_output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect();
    spinner.finish_and_clear();
    printer.info(&format!("Closure: {} paths", closure.len()));

    let spinner = create_spinner("querying missing paths");
    let missing = client.query_missing(&closure).await?;
    spinner.finish_and_clear();

    if missing.is_empty() {
        printer.info("All paths present on server");
    } else {
        printer.info(&format!("Missing: {} paths to upload", missing.len()));

        // Step 4: Upload missing paths. Partition into small .drv files
        // (pack together) and large sources (upload individually).
        const PACK_SIZE_LIMIT: usize = 1024 * 1024; // 1MB threshold

        let mut pack_paths = Vec::new();
        let mut large_paths = Vec::new();

        for path in &missing {
            let output = std::process::Command::new("nix-store")
                .args(["--export", path])
                .output()
                .with_context(|| format!("exporting {path}"))?;

            if !output.status.success() {
                bail!("nix-store --export failed for {path}");
            }

            let hash = path
                .rsplit('/')
                .next()
                .and_then(|b| b.split('-').next())
                .unwrap_or("unknown")
                .to_string();

            if path.ends_with(".drv") && output.stdout.len() < PACK_SIZE_LIMIT {
                pack_paths.push(aos_core::nar::pack::PackPath {
                    hash,
                    nar_data: output.stdout,
                });
            } else {
                large_paths.push((hash, output.stdout));
            }
        }

        // Upload small .drv files as a pack.
        if !pack_paths.is_empty() {
            let spinner = create_spinner(&format!("uploading {} small paths as pack", pack_paths.len()));
            let pack_data = aos_core::nar::pack::create_pack(&pack_paths);
            client.upload_pack(&pack_data).await
                .context("uploading path pack")?;
            spinner.finish_and_clear();
        }

        // Upload large sources individually.
        if !large_paths.is_empty() {
            let spinner = create_spinner(&format!("uploading {} large paths", large_paths.len()));
            for (hash, data) in &large_paths {
                client.upload_path(hash, data).await
                    .with_context(|| format!("uploading {hash}"))?;
            }
            spinner.finish_and_clear();
        }
    }

    // Step 5: Request remote build and stream logs via SSE with reconnection.
    printer.info("Starting remote build...");

    client.build(&drv_str, 5, |event| {
        match event.event.as_deref() {
            Some("log") => printer.plain(&event.data),
            Some("status") => printer.info(&format!("[status] {}", event.data)),
            Some("complete") => {
                printer.success(&format!("Build complete: {}", event.data));
                return EventAction::Stop;
            }
            Some("error") => {
                printer.error(&format!("Build error: {}", event.data));
                return EventAction::Stop;
            }
            Some("daemon-unavailable") => {
                printer.warning(&format!("[daemon] {}", event.data));
            }
            Some("drain") => {
                printer.warning("Server is draining; will reconnect if disconnected");
            }
            _ => {}
        }
        EventAction::Continue
    }).await?;

    Ok(())
}

fn build_all(nix: &NixRunner, printer: &Printer) -> Result<()> {
    printer.info("Building all packages...");

    let spinner = create_spinner("building all packages");
    let paths = nix
        .build_all("pkgs")
        .context("building all packages")?;
    spinner.finish_and_clear();

    if printer.json_if_active(&serde_json::json!({
        "packages": paths.iter().map(|p| p.to_string_lossy().to_string()).collect::<Vec<_>>(),
        "count": paths.len(),
    })) {
        return Ok(());
    }

    for path in &paths {
        printer.plain(&format!("  {}", path.display()));
    }

    printer.success(&format!("Built {} packages", paths.len()));

    Ok(())
}
