use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use aos_core::output::Printer;
use aos_server::{self, bootstrap, build, config, drain, routes, sign, store, tokens, views};

/// `aos serve` — start the HTTP binary cache server.
pub async fn run(printer: &Printer, config_path: &Path) -> Result<()> {
    printer.info(&format!("Loading config from {}", config_path.display()));
    let cfg = config::load_config(config_path).context("loading server configuration")?;

    let root = aos_server::aos_root();
    let store_dir = root.join("store").to_string_lossy().to_string();
    let db_path = root.join("var/nix/db/db.sqlite");

    printer.info(&format!("Opening Nix store DB at {}", db_path.display()));
    let nix_store = store::NixStore::open(&db_path).context("opening Nix store database")?;

    // Initialize the token database.
    let meta_dir = root.join("meta");
    std::fs::create_dir_all(&meta_dir)
        .with_context(|| format!("creating {}", meta_dir.display()))?;
    let token_db_path = meta_dir.join("tokens.db");
    printer.info(&format!("Opening token DB at {}", token_db_path.display()));
    let token_store =
        tokens::TokenStore::open(&token_db_path).context("opening token database")?;

    // Load or generate the JWT signing secret.
    let jwt_secret = load_jwt_secret(&cfg).context("loading JWT secret")?;

    let view_mgr = views::ViewManager::new(root.clone(), cfg.views.clone());
    view_mgr
        .init_directories()
        .context("initializing view directories")?;

    let view_names: Vec<&str> = cfg.views.iter().map(|v| v.name.as_str()).collect();
    printer.info(&format!("Views: {}", view_names.join(", ")));

    // Recover any builds that were in-flight when the server last crashed.
    let incomplete = drain::BuildState::scan_incomplete(&root);
    if !incomplete.is_empty() {
        printer.info(&format!(
            "Recovering {} incomplete build(s) from previous run",
            incomplete.len()
        ));
        for build_state in &incomplete {
            let outputs_exist = check_store_outputs(&build_state.drv);
            if outputs_exist {
                printer.info(&format!(
                    "  {}: outputs already in store, cleaning up",
                    build_state.drv
                ));
            } else {
                printer.warning(&format!(
                    "  {} ({}): outputs missing, cleaning up stale state",
                    build_state.drv, build_state.status
                ));
            }
            build_state.remove(&root);
        }
    }

    // Load narinfo signing key (if configured).
    let signer = sign::NarInfoSigner::load(cfg.signing.secret_key_file.as_deref())?;
    if signer.is_configured() {
        printer.info(&format!("Signing narinfo with key: {}", signer.key_name().unwrap()));
    }

    let build_mgr = Arc::new(build::BuildManager::new());
    let drain_state = Arc::new(drain::DrainState::new());

    let state = Arc::new(routes::AppState {
        store: nix_store,
        views: view_mgr,
        config: cfg.clone(),
        store_dir,
        jwt_secret,
        tokens: token_store,
        build_mgr,
        drain: Arc::clone(&drain_state),
        signer,
    });

    let app = routes::router(Arc::clone(&state));

    // Start the bootstrap socket listener in the background.
    let bootstrap_state = Arc::clone(&state);
    let bootstrap_path = cfg.bootstrap.socket.clone();
    tokio::spawn(async move {
        if let Err(e) = bootstrap::run_bootstrap_listener(bootstrap_state, &bootstrap_path).await {
            eprintln!("bootstrap listener error: {e}");
        }
    });

    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("binding to {}", cfg.listen))?;

    printer.success(&format!("Serving on http://{}", cfg.listen));

    // Run the server with graceful shutdown on SIGTERM/SIGINT.
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            drain::wait_for_shutdown_signal().await;
            eprintln!("Shutdown signal received, draining...");
            drain_state.start_drain();
            state.build_mgr.broadcast_drain();
            // Wait up to 75s for in-flight builds.
            let completed = drain_state.wait_for_completion(Duration::from_secs(75)).await;
            if completed {
                eprintln!("All builds complete, shutting down");
            } else {
                eprintln!("Drain timeout reached, forcing shutdown");
            }
        })
        .await
        .context("server error")?;

    Ok(())
}

/// Load the JWT HMAC-SHA256 secret from the configured file, or generate a
/// random ephemeral secret if no file is configured.
fn load_jwt_secret(cfg: &config::ServerConfig) -> Result<Vec<u8>> {
    match &cfg.oauth2.jwt_secret_file {
        Some(path) => {
            let data = std::fs::read(path)
                .with_context(|| format!("reading JWT secret from {}", path.display()))?;
            Ok(data)
        }
        None => {
            // No secret file configured — generate a random 32-byte key.
            // Tokens signed with this key become invalid on server restart.
            let secret: [u8; 32] = rand::random();
            Ok(secret.to_vec())
        }
    }
}

/// Check whether a derivation's outputs are valid in the Nix store.
/// Runs `nix-store -q --outputs <drv>` to get output paths, then
/// `nix-store --check-validity` to see if they actually exist.
fn check_store_outputs(drv: &str) -> bool {
    let output = match std::process::Command::new("nix-store")
        .args(["-q", "--outputs", drv])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return false,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let paths: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    if paths.is_empty() {
        return false;
    }

    let mut cmd = std::process::Command::new("nix-store");
    cmd.arg("--check-validity");
    for p in &paths {
        cmd.arg(p);
    }
    cmd.status().map(|s| s.success()).unwrap_or(false)
}
