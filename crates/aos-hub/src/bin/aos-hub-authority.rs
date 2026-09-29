//! Dedicated per-authority Native issuer process with explicit manual initialization.
//!
//! The process opens no Hub SQL, creates no default bindings and owns no provider
//! operation. Its private SQLite journal and issuer-only seed belong to a
//! separately provisioned retained resource. Serving never initializes missing
//! state; configuration alone establishes no physical or clock qualification.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use aos_hub::authority_server::{AuthorityConfiguration, AuthorityServer};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "aos-hub-authority", version)]
struct Args {
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand)]
enum Operation {
    /// Initialize a separately provisioned never-used private issuer resource.
    Initialize {
        /// Read explicit installation, journal, policy and private coordinates.
        #[arg(long)]
        configuration: PathBuf,
        /// Read the reviewed canonical first-generation publication.
        #[arg(long)]
        publication: PathBuf,
    },
    /// Serve only an existing exact private issuer installation.
    Serve {
        /// Read explicit installation, private credentials and listener coordinates.
        #[arg(long)]
        configuration: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().operation {
        Operation::Initialize {
            configuration,
            publication,
        } => {
            let configuration = AuthorityConfiguration::read(&configuration)
                .context("loading explicit authority configuration")?;
            configuration
                .initialize(&publication)
                .context("initializing fresh private authority resource")?;
        }
        Operation::Serve { configuration } => {
            let configuration = AuthorityConfiguration::read(&configuration)
                .context("loading explicit authority configuration")?;
            let server = AuthorityServer::open(&configuration)
                .context("opening existing private authority resource")?;
            server
                .serve()
                .await
                .context("serving private authority resource")?;
        }
    }
    Ok(())
}
