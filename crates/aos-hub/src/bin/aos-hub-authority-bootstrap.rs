//! Exports reviewed external authority metadata and hydrates the paired executor.
//!
//! This separate operator process requires live SQL and explicit private files.
//! Provider material is resolved only by operator staging and hydration and
//! sent through protected Worker controls. It emits no readiness or acceptance.

use std::path::PathBuf;

use anyhow::{ensure, Context, Result};
use aos_hub::authority_server::AuthorityConfiguration;
use aos_hub::storage_work::RemoteStorageWorkClient;
use aos_hub_core::storage_authority::PhysicalStorageAuthorityId;
use clap::{Parser, Subcommand};

#[path = "../authority_bootstrap/mod.rs"]
mod bootstrap;

#[derive(Parser)]
#[command(name = "aos-hub-authority-bootstrap", version)]
struct Args {
    /// Read the live SQL URL from an owner-private file.
    #[arg(long, env = "HUB_DATABASE_URL_FILE")]
    database_url_file: PathBuf,
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand)]
enum Operation {
    /// Export the current reviewed SQL authority publication in any admission state.
    ExportPublication {
        /// Select the permanent authority already approved through root Plan/Apply.
        #[arg(long)]
        authority_id: String,
        /// Bind the actual configured Worker guard namespace identity.
        #[arg(long)]
        guard_namespace_id: String,
        /// Bind the actual configured Worker storage executor identity.
        #[arg(long)]
        executor_identity: String,
        /// Create a new private export directory under an existing private parent.
        #[arg(long)]
        output: PathBuf,
    },
    /// Recover held historical delete material for an active frozen cleanup claim.
    StageCleanupCredential {
        /// Select the original claimed OCI placement action.
        #[arg(long)]
        action_id: String,
        /// Read the current live claim token from an owner-private file.
        #[arg(long)]
        claim_token_file: PathBuf,
        /// Bind the immutable paired deployment identity.
        #[arg(long)]
        deployment_id: String,
        /// Select the paired Worker's HTTPS origin.
        #[arg(long)]
        worker_url: String,
        /// Read the paired storage control key from an owner-private file.
        #[arg(long)]
        storage_work_key_file: PathBuf,
        /// Resolve exact historical versions from an operator-private manifest.
        #[arg(long)]
        secret_version_manifest: PathBuf,
        /// Bound recovered material custody without extending the cleanup claim.
        #[arg(long, default_value_t = 86400)]
        retention_seconds: i64,
        /// Create a new private material-free acknowledgement directory.
        #[arg(long)]
        output: PathBuf,
    },
    /// Stage material on Worker for an actual queued credential validation task.
    StageCredential {
        /// Select the original operation queued by PlanValidateBindingCredential.
        #[arg(long)]
        operation_id: String,
        /// Bind the immutable paired deployment identity.
        #[arg(long)]
        deployment_id: String,
        /// Select the paired Worker's HTTPS origin.
        #[arg(long)]
        worker_url: String,
        /// Read the paired storage control key from an owner-private file.
        #[arg(long)]
        storage_work_key_file: PathBuf,
        /// Resolve exact provider versions from an operator-private manifest.
        #[arg(long)]
        secret_version_manifest: PathBuf,
        /// Bound initial material custody; active validated adoption renews custody.
        #[arg(long, default_value_t = 86400)]
        retention_seconds: i64,
        /// Create a new private material-free acknowledgement directory.
        #[arg(long)]
        output: PathBuf,
    },
    /// Export reviewed SQL decisions for an isolated external qualification domain.
    Export {
        /// Select the permanent authority already approved through root Plan/Apply.
        #[arg(long)]
        authority_id: String,
        /// Select its exact admitted SQL binding association.
        #[arg(long)]
        association_id: String,
        /// Bind the immutable paired deployment identity.
        #[arg(long)]
        deployment_id: String,
        /// Read the separately provisioned issuer configuration without reading keys.
        #[arg(long)]
        issuer_configuration: PathBuf,
        /// Read the independently supplied lowercase hexadecimal public verifier.
        #[arg(long)]
        issuer_public_key_file: PathBuf,
        /// Narrow within the binding to a .aos-direct-qualification component.
        #[arg(long)]
        admitted_prefix: String,
        /// Create a new private export directory under an existing private parent.
        #[arg(long)]
        output: PathBuf,
    },
    /// Hydrate current exact SQL credentials through protected Worker binding control.
    Hydrate {
        /// Read the private canonical bootstrap.json from Export.
        #[arg(long)]
        bootstrap: PathBuf,
        /// Select the actual paired Worker's HTTPS origin.
        #[arg(long)]
        worker_url: String,
        /// Read the existing paired storage control key from an owner-private file.
        #[arg(long)]
        storage_work_key_file: PathBuf,
        /// Resolve exact provider versions from an operator-private file manifest.
        #[arg(long)]
        secret_version_manifest: PathBuf,
        /// Create a new private receipt directory under an existing private parent.
        #[arg(long)]
        output: PathBuf,
    },
}

async fn run(args: Args) -> Result<()> {
    let raw = zeroize::Zeroizing::new(aos_hub::auth::seal::read_secret_file(
        &args.database_url_file,
    )?);
    let database_url = std::str::from_utf8(&raw)?.trim();
    ensure!(
        !database_url.is_empty() && !database_url.contains(['\n', '\r']),
        "database URL file invalid"
    );
    let db = bootstrap::open_existing(database_url)
        .await
        .map_err(|_| anyhow::anyhow!("opening live operator database failed"))?;
    match args.operation {
        Operation::ExportPublication {
            authority_id,
            guard_namespace_id,
            executor_identity,
            output,
        } => {
            let authority = PhysicalStorageAuthorityId::parse(&authority_id)?;
            bootstrap::export_publication(
                &db,
                &authority,
                &guard_namespace_id,
                &executor_identity,
                &output,
            )
            .await?;
            println!("Reviewed SQL authority publication exported.");
        }
        Operation::StageCleanupCredential {
            action_id,
            claim_token_file,
            deployment_id,
            worker_url,
            storage_work_key_file,
            secret_version_manifest,
            retention_seconds,
            output,
        } => {
            let raw =
                zeroize::Zeroizing::new(aos_hub::auth::seal::read_secret_file(&claim_token_file)?);
            let token = std::str::from_utf8(&raw)?.trim();
            ensure!(
                !token.is_empty() && token.len() <= 64 && !token.chars().any(char::is_control),
                "cleanup claim token file invalid"
            );
            let claim = db
                .active_oci_gc_placement_action_claim(
                    &action_id,
                    token,
                    aos_hub_core::clock::now_unix_secs(),
                )
                .await?
                .context("active cleanup claim absent")?;
            let key = zeroize::Zeroizing::new(aos_hub::auth::seal::read_secret_file(
                &storage_work_key_file,
            )?);
            let client = RemoteStorageWorkClient::new(&worker_url, deployment_id, &key)?;
            let resolver =
                aos_hub::coreports::load_secret_version_manifest(&secret_version_manifest)?;
            let receipt = client
                .stage_frozen_cleanup_credential(&db, &claim, resolver.as_ref(), retention_seconds)
                .await?;
            bootstrap::write_cleanup_stage_receipt(&output, &receipt)?;
            println!("Held cleanup material staged; provider settlement is pending.");
        }
        Operation::StageCredential {
            operation_id,
            deployment_id,
            worker_url,
            storage_work_key_file,
            secret_version_manifest,
            retention_seconds,
            output,
        } => {
            let key = zeroize::Zeroizing::new(aos_hub::auth::seal::read_secret_file(
                &storage_work_key_file,
            )?);
            let client = RemoteStorageWorkClient::new(&worker_url, deployment_id, &key)?;
            let resolver =
                aos_hub::coreports::load_secret_version_manifest(&secret_version_manifest)?;
            let receipt = bootstrap::stage_queued_credential(
                &db,
                &client,
                &operation_id,
                resolver.as_ref(),
                retention_seconds,
            )
            .await?;
            bootstrap::write_stage_receipt(&output, &receipt)?;
            println!("Queued credential material staged; Native controller validation is pending.");
        }
        Operation::Export {
            authority_id,
            association_id,
            deployment_id,
            issuer_configuration,
            issuer_public_key_file,
            admitted_prefix,
            output,
        } => {
            let configuration = AuthorityConfiguration::read(&issuer_configuration)?;
            let raw_public = aos_hub::auth::seal::read_secret_file(&issuer_public_key_file)?;
            let public_key = std::str::from_utf8(&raw_public)?.trim();
            let authority = PhysicalStorageAuthorityId::parse(&authority_id)?;
            let value = bootstrap::derive(
                &db,
                &deployment_id,
                &authority,
                &association_id,
                &configuration,
                public_key,
                &admitted_prefix,
            )
            .await?;
            bootstrap::write_export(&output, &value)?;
            println!("Reviewed authority metadata exported; provider qualification is pending.");
        }
        Operation::Hydrate {
            bootstrap: path,
            worker_url,
            storage_work_key_file,
            secret_version_manifest,
            output,
        } => {
            let value = bootstrap::read_bootstrap(&path)?;
            let key = zeroize::Zeroizing::new(aos_hub::auth::seal::read_secret_file(
                &storage_work_key_file,
            )?);
            let client =
                RemoteStorageWorkClient::new(&worker_url, value.deployment_id.clone(), &key)?;
            let resolver =
                aos_hub::coreports::load_secret_version_manifest(&secret_version_manifest)?;
            let receipt = bootstrap::hydrate(&db, &value, &client, resolver.as_ref()).await?;
            bootstrap::write_receipt(&output, &receipt)?;
            println!("Binding metadata hydrated; provider qualification is pending.");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    run(Args::parse())
        .await
        .context("authority bootstrap operation failed")
}
