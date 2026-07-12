//! `aos serve` — run the AOS HTTP binary cache server.
//!
//! This module is the daemon bootstrap; the request handling itself
//! lives in the `aos-server` crate. Startup sequence: install the
//! stderr tracing subscriber (`crate::logging`), load the TOML config,
//! open the Nix store and token databases, initialise the view
//! directories, recover builds left in-flight by a previous crash, load
//! the narinfo signing key, spawn the bootstrap Unix-socket listener
//! (for `aos token`), and finally accept connections.
//!
//! The listener serves HTTP/1.1 and HTTP/2 on one port — TLS with ALPN
//! when `tls.enabled` (generating a self-signed certificate if none is
//! configured), cleartext h2c otherwise. On SIGTERM/SIGINT the server
//! drains: in-flight builds get up to 75 seconds to finish before
//! connections are shut down gracefully.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use aos_core::nix::aos_nix_command;
use aos_core::output::Printer;
use aos_server::{self, bootstrap, build, config, drain, routes, sign, store, tls, tokens, views};

/// `aos serve` — start the HTTP binary cache server.
///
/// Runs until a shutdown signal is received and the drain completes.
///
/// # Errors
///
/// Returns an error if startup fails: unreadable configuration, store or
/// token database cannot be opened, view directories cannot be created,
/// TLS material cannot be loaded or generated, or the listen address
/// cannot be bound. Per-connection errors after startup are logged, not
/// returned.
pub async fn run(printer: &Printer, config_path: &Path) -> Result<()> {
    // Install a stderr tracing subscriber so aos-server's request
    // instrumentation (`tracing::info!` in routes.rs etc.) reaches
    // journald. Without this the daemon's logs are silently dropped.
    crate::logging::init();

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
    let token_store = tokens::TokenStore::open(&token_db_path).context("opening token database")?;

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
        printer.info(&format!(
            "Signing narinfo with key: {}",
            signer.key_name().unwrap_or("unknown")
        ));
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
        memo: Arc::new(aos_server::memo::MemoStore::new(
            aos_server::aos_root().join("memo"),
            cfg.memo.writable,
        )),
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

    let shutdown = async move {
        drain::wait_for_shutdown_signal().await;
        eprintln!("Shutdown signal received, draining...");
        drain_state.start_drain();
        state.build_mgr.broadcast_drain();
        let completed = drain_state
            .wait_for_completion(Duration::from_secs(75))
            .await;
        if completed {
            eprintln!("All builds complete, shutting down");
        } else {
            eprintln!("Drain timeout reached, forcing shutdown");
        }
    };

    let tls_acceptor = if cfg.tls.enabled {
        let cert_path = cfg
            .tls
            .cert_file
            .clone()
            .unwrap_or_else(tls::default_cert_path);
        let key_path = cfg
            .tls
            .key_file
            .clone()
            .unwrap_or_else(tls::default_key_path);

        let acceptor = if cert_path.exists() && key_path.exists() {
            printer.info(&format!("Loading TLS cert from {}", cert_path.display()));
            tls::acceptor_from_pem(&cert_path, &key_path).context("loading TLS certificates")?
        } else {
            printer.info("Generating self-signed TLS certificate");
            tls::generate_self_signed(&cert_path, &key_path, &cfg.tls.san)
                .context("generating self-signed certificate")?
        };

        printer.success(&format!(
            "Serving on https://{} (h2 + http/1.1)",
            cfg.listen
        ));
        Some(acceptor)
    } else {
        printer.success(&format!(
            "Serving on http://{} (h2c + http/1.1)",
            cfg.listen
        ));
        None
    };

    serve_h2(listener, app, tls_acceptor, shutdown).await?;

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

/// Accept connections and serve with HTTP/1.1 + HTTP/2 support.
///
/// When `tls_acceptor` is `Some`, each TCP connection is wrapped with TLS
/// (ALPN-negotiated h2 / http/1.1). When `None`, connections are served in
/// cleartext with h2c (HTTP/2 upgrade / prior-knowledge) and HTTP/1.1.
async fn serve_h2(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let token = tokio_util::sync::CancellationToken::new();
    let child_token = token.clone();

    tokio::spawn(async move {
        shutdown.await;
        child_token.cancel();
    });

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            result = listener.accept() => {
                let (stream, _addr) = result.context("accepting TCP connection")?;
                let tls = tls_acceptor.clone();
                let app = app.clone();
                let cancel = token.clone();
                tokio::spawn(async move {
                    let builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    let hyper_svc = hyper_util::service::TowerToHyperService::new(app);

                    if let Some(acceptor) = tls {
                        // TLS path: ALPN-negotiated h2 / http/1.1.
                        let tls_stream = match acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                eprintln!("TLS handshake failed: {e}");
                                return;
                            }
                        };
                        let io = hyper_util::rt::TokioIo::new(tls_stream);
                        let conn = builder.serve_connection(io, hyper_svc);
                        tokio::pin!(conn);
                        tokio::select! {
                            result = &mut conn => {
                                if let Err(e) = result {
                                    eprintln!("connection error: {e}");
                                }
                            }
                            _ = cancel.cancelled() => {
                                conn.as_mut().graceful_shutdown();
                                let _ = conn.await;
                            }
                        }
                    } else {
                        // Cleartext path: h2c (prior-knowledge + upgrade) and HTTP/1.1.
                        let io = hyper_util::rt::TokioIo::new(stream);
                        let conn = builder.serve_connection_with_upgrades(io, hyper_svc);
                        tokio::pin!(conn);
                        tokio::select! {
                            result = &mut conn => {
                                if let Err(e) = result {
                                    eprintln!("connection error: {e}");
                                }
                            }
                            _ = cancel.cancelled() => {
                                conn.as_mut().graceful_shutdown();
                                let _ = conn.await;
                            }
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

/// Check whether a derivation's outputs are valid in the Nix store.
/// Runs `nix-store -q --outputs <drv>` to get output paths, then
/// `nix-store --check-validity` to see if they actually exist.
fn check_store_outputs(drv: &str) -> bool {
    let output = match aos_nix_command("nix-store")
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

    let mut cmd = aos_nix_command("nix-store");
    cmd.arg("--check-validity");
    for p in &paths {
        cmd.arg(p);
    }
    cmd.status().map(|s| s.success()).unwrap_or(false)
}
