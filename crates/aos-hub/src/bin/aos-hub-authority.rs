//! Dedicated per-authority Native issuer process with explicit manual initialization.
//!
//! The process opens no Hub SQL, creates no default bindings and owns no provider
//! operation. Its private SQLite journal and issuer-only seed belong to a
//! separately provisioned retained resource. Serving never initializes missing
//! state; configuration alone establishes no physical or clock qualification.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use aos_hub::authority_server::{recovery_operator, AuthorityConfiguration, AuthorityServer};
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
        /// Consume one exact retained format 3 recovery receipt, once.
        #[arg(long)]
        clock_resolution: Option<PathBuf>,
    },
    /// Inspect inactive format 3 state without changing the old session.
    InspectClockSession {
        /// Read exact installation and immutable recovery policy.
        #[arg(long)]
        configuration: PathBuf,
        /// Create a private canonical plan file for the independent reviewer.
        #[arg(long)]
        output: PathBuf,
    },
    /// Independently sign one exact inspected plan under the pinned public policy.
    SignClockResolution {
        /// Read the independently selected canonical reviewer policy.
        #[arg(long)]
        policy: PathBuf,
        /// Read the exact canonical inspected plan.
        #[arg(long)]
        plan: PathBuf,
        /// Read the existing private independent reviewer seed.
        #[arg(long)]
        reviewer_seed: PathBuf,
        /// Create a private canonical signed review file.
        #[arg(long)]
        output: PathBuf,
    },
    /// Resolve an inactive exact session after reviewed clock and expiry bounds.
    ResolveClockSession {
        /// Read exact installation and immutable recovery policy.
        #[arg(long)]
        configuration: PathBuf,
        /// Read the independently signed canonical review.
        #[arg(long)]
        review: PathBuf,
        /// Create a private canonical retained positive receipt file.
        #[arg(long)]
        output: PathBuf,
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
        Operation::Serve {
            configuration,
            clock_resolution,
        } => {
            let configuration = AuthorityConfiguration::read(&configuration)
                .context("loading explicit authority configuration")?;
            let receipt = clock_resolution
                .as_deref()
                .map(recovery_operator::read_receipt)
                .transpose()?;
            let server =
                AuthorityServer::open_with_clock_resolution(&configuration, receipt.as_ref())
                    .context("opening existing private authority resource")?;
            server
                .serve()
                .await
                .context("serving private authority resource")?;
        }
        Operation::InspectClockSession {
            configuration,
            output,
        } => {
            recovery_operator::inspect(&AuthorityConfiguration::read(&configuration)?, &output)?;
        }
        Operation::SignClockResolution {
            policy,
            plan,
            reviewer_seed,
            output,
        } => {
            recovery_operator::sign(&policy, &plan, &reviewer_seed, &output)?;
        }
        Operation::ResolveClockSession {
            configuration,
            review,
            output,
        } => {
            recovery_operator::resolve(
                &AuthorityConfiguration::read(&configuration)?,
                &review,
                &output,
            )?;
        }
    }
    Ok(())
}
