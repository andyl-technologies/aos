//! `aos build` — build a package from source.
//!
//! Local mode builds the `pkgs.<name>` attribute (or every package with
//! `--all`) via `nix-build` and prints the resulting store path. Remote
//! mode (`--remote URL`) evaluates the derivation locally, uploads any
//! store paths the server is missing (small `.drv` files batched into a
//! pack, large sources individually), then streams the remote build's
//! log and status events back to the terminal.

use anyhow::{Context, Result, bail};

use aos_core::error::AosError;
use aos_core::nix::NixRunner;
use aos_core::output::Printer;
use aos_package::types::validate_platform_name;
use aos_remote::AosClient;

/// `aos build <package>` or `aos build --all`.
///
/// Builds the named package (the `pkgs.<package>` attribute) and prints
/// its store path, or builds every package when `all` is set.
///
/// # Errors
///
/// Returns an error if no package is named and `all` is not set, or if
/// the underlying `nix-build` fails.
pub fn run(
    nix: &NixRunner,
    printer: &Printer,
    package: Option<&str>,
    all: bool,
    target: Option<&str>,
) -> Result<()> {
    if let Some(target) = target {
        validate_platform_name(target)?;
    }

    if all {
        return build_all(nix, printer, target);
    }

    let package = package.ok_or_else(|| AosError::InvalidArgument {
        message: "provide a package name, or use --all to build everything".to_string(),
    })?;

    let attr = format!("pkgs.{package}");

    let target_label = target.map_or_else(String::new, |target| format!(" for {target}"));
    printer.info(&format!("Building package '{package}'{target_label}..."));

    let spinner = printer.activity(&format!("building {package}"));
    let store_path = match target {
        Some(target) => nix.build_for_target(&attr, None, target),
        None => nix.build(&attr, None),
    }
    .with_context(|| format!("building package '{package}'{target_label}"))?;
    spinner.finish_and_clear();

    if printer.json_if_active(&serde_json::json!({
        "package": package,
        "target": target,
        "store_path": store_path.to_string_lossy(),
    })) {
        return Ok(());
    }

    printer.success(&format!("Built {package} -> {}", store_path.display()));

    Ok(())
}

/// `aos build <package> --remote URL` — evaluate locally, upload, build remotely.
///
/// The pipeline: instantiate the derivation locally, authenticate with
/// the server, diff the derivation closure against the server's store,
/// upload missing paths, then request the build and stream its events
/// until a `complete` or `error` event arrives.
///
/// # Errors
///
/// Returns an error if `package` or `token` is missing, or if any
/// pipeline step (local evaluation, authentication, closure export and
/// upload, or the build RPC stream) fails. A build that fails on the
/// server side is reported via its `error` event and does not error here.
pub async fn run_remote(
    nix: &NixRunner,
    printer: &Printer,
    package: Option<&str>,
    target: Option<&str>,
    remote_url: &str,
    view: &str,
    token: Option<&str>,
) -> Result<()> {
    if let Some(target) = target {
        validate_platform_name(target)?;
    }

    let package = package.ok_or_else(|| AosError::InvalidArgument {
        message: "provide a package name for remote builds".to_string(),
    })?;

    let token = token.ok_or_else(|| AosError::InvalidArgument {
        message: "provide --token or set AOS_TOKEN for remote builds".to_string(),
    })?;

    let target_label = target.map_or_else(String::new, |target| format!(", target: {target}"));
    printer.info(&format!(
        "Remote build: {package} on {remote_url} (view: {view}{target_label})"
    ));

    // Step 1: Evaluate locally to get the .drv path.
    let spinner = printer.activity(&format!("evaluating {package}"));
    let attr = format!("pkgs.{package}");
    let drv_path = match target {
        Some(target) => nix.instantiate_for_target(&attr, target),
        None => nix.instantiate(&attr),
    }
    .with_context(|| format!("evaluating package '{package}'{target_label}"))?;
    spinner.finish_and_clear();
    let drv_str = drv_path.to_string_lossy().to_string();
    printer.info(&format!("Derivation: {drv_str}"));

    // Step 2: Authenticate with the remote server.
    let spinner = printer.activity("authenticating");
    let client = AosClient::connect(remote_url, view, token)
        .await
        .context("authenticating with remote server")?;
    spinner.finish_and_clear();

    // Step 3: Query runtime closure and find missing paths.
    let spinner = printer.activity("querying closure");
    let closure_output = nix.store_query(&drv_path, &["-qR"])?;
    let closure: Vec<String> = closure_output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect();
    spinner.finish_and_clear();
    printer.info(&format!("Closure: {} paths", closure.len()));

    let spinner = printer.activity("querying missing paths");
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

        let pack_data =
            (!pack_paths.is_empty()).then(|| aos_core::nar::pack::create_pack(&pack_paths));
        let upload_bytes = pack_data
            .as_ref()
            .map_or(0, |pack| pack.len() as u64)
            .checked_add(large_paths.iter().map(|(_, data)| data.len() as u64).sum())
            .context("remote build upload byte total overflow")?;
        let progress = printer.transfer("Uploading remote build inputs", upload_bytes);

        // Upload small .drv files as a pack.
        if !pack_paths.is_empty() {
            let pack_data = pack_data
                .as_ref()
                .context("remote build path pack was not prepared")?;
            client
                .upload_pack(pack_data)
                .await
                .context("uploading path pack")?;
            progress.inc(pack_data.len() as u64);
        }

        // Upload large sources individually.
        if !large_paths.is_empty() {
            for (hash, data) in &large_paths {
                client
                    .upload(hash, data)
                    .await
                    .with_context(|| format!("uploading {hash}"))?;
                progress.inc(data.len() as u64);
            }
        }
        progress.finish();
    }

    // Step 5: Request remote build and stream events via ConnectRPC.
    printer.info("Starting remote build...");

    client
        .build(&drv_str, |event| {
            match event.event_type.as_str() {
                "log" => printer.plain(&event.message),
                "status" => printer.info(&format!("[status] {}", event.message)),
                "complete" => {
                    printer.success(&format!("Build complete: {}", event.message));
                    return false;
                }
                "error" => {
                    printer.error(&format!("Build error: {}", event.message));
                    return false;
                }
                "daemon-unavailable" => {
                    printer.warning(&format!("[daemon] {}", event.message));
                }
                "drain" => {
                    printer.warning("Server is draining; will reconnect if disconnected");
                }
                _ => {}
            }
            true
        })
        .await?;

    Ok(())
}

/// Build every package in the `pkgs` set and list the store paths.
fn build_all(nix: &NixRunner, printer: &Printer, target: Option<&str>) -> Result<()> {
    let target_label = target.map_or_else(String::new, |target| format!(" for {target}"));
    printer.info(&format!("Building all packages{target_label}..."));

    let spinner = printer.activity("building all packages");
    let paths = match target {
        Some(target) => nix.build_target_packages(target),
        None => nix.build_all("pkgs"),
    }
    .with_context(|| format!("building all packages{target_label}"))?;
    spinner.finish_and_clear();

    if printer.json_if_active(&serde_json::json!({
        "packages": paths.iter().map(|p| p.to_string_lossy().to_string()).collect::<Vec<_>>(),
        "target": target,
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
