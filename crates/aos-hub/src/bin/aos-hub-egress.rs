//! Optional authenticated outbound router for AOS Hub Worker deployments.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Parser;

#[derive(Parser)]
#[command(name = "aos-hub-egress", version)]
struct Args {
    /// Address on which the private router listens.
    #[arg(long, default_value = "127.0.0.1:8430")]
    listen: SocketAddr,
    /// Owner-private file containing at least 32 bytes of shared key material.
    #[arg(long, env = "HUB_EGRESS_GATEWAY_KEY_FILE")]
    gateway_key_file: PathBuf,
    /// Stable id for the current shared key.
    #[arg(long, env = "HUB_EGRESS_GATEWAY_KEY_ID")]
    key_id: String,
    /// Stable id for an optional next key accepted during overlap rotation.
    #[arg(long, env = "HUB_EGRESS_GATEWAY_NEXT_KEY_ID")]
    next_key_id: Option<String>,
    /// Owner-private file for the optional next overlap key.
    #[arg(long, env = "HUB_EGRESS_GATEWAY_NEXT_KEY_FILE")]
    next_key_file: Option<PathBuf>,
    /// Durable nonce database URL shared by every gateway replica.
    ///
    /// Use PostgreSQL for a replicated gateway. A file-backed SQLite URL is
    /// safe only for one gateway process, but retains replay state on restart.
    #[arg(long, env = "HUB_EGRESS_GATEWAY_NONCE_DATABASE_URL")]
    nonce_database_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let key_file = aos_hub::auth::seal::read_secret_file(&args.gateway_key_file)
        .context("loading hardened-egress shared key")?;
    let key =
        aos_hub::auth::seal::parse_key(&key_file).context("parsing hardened-egress shared key")?;
    let mut keys = vec![(args.key_id, key)];
    match (args.next_key_id, args.next_key_file) {
        (Some(key_id), Some(path)) => {
            let bytes = aos_hub::auth::seal::read_secret_file(&path)
                .context("loading next hardened-egress shared key")?;
            let key = aos_hub::auth::seal::parse_key(&bytes)
                .context("parsing next hardened-egress shared key")?;
            keys.push((key_id, key));
        }
        (None, None) => {}
        _ => anyhow::bail!("next egress key id and file must be configured together"),
    }
    let nonce_database = Arc::new(
        aos_hub_core::db::Database::connect(&args.nonce_database_url)
            .await
            .context("opening durable hardened-egress nonce database")?,
    );
    let gateway = aos_hub::egress_gateway::EgressGateway::new(keys, nonce_database).await?;
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .context("binding hardened-egress listener")?;
    axum::serve(listener, gateway.router())
        .await
        .context("serving hardened-egress gateway")
}
