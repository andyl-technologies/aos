//! One-off registry indexing with an explicit Native or hybrid storage adapter.
//!
//! Hybrid commands authenticate the paired Worker before reading a placement;
//! they neither create local storage authority nor download bulk object bodies.
//! Local commands retain the Native snapshot and credential adapters.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Args;

use aos_hub::db::Database;
use aos_hub_core::fetch::SurfaceProvider;
use aos_hub_core::secret_version::{EmptySecretVersionResolver, SecretVersionResolver};

#[derive(Args)]
pub(super) struct IndexArgs {
    /// Index this registry; omit to index everything.
    pub(super) slug: Option<String>,
    /// Select the Native or Worker-fronted hybrid topology.
    #[arg(long, env = "HUB_TOPOLOGY", default_value = "native", value_parser = ["native", "hybrid"])]
    topology: String,
    /// Set the paired Worker's HTTPS origin.
    #[arg(long, env = "HUB_HYBRID_WORKER_URL")]
    hybrid_worker_url: Option<String>,
    /// Set the shared Native and Worker deployment identity.
    #[arg(long, env = "HUB_DEPLOYMENT_ID")]
    deployment_id: Option<String>,
    /// Read the storage-work HMAC key from an owner-private file.
    #[arg(long, env = "HUB_STORAGE_WORK_KEY_FILE")]
    storage_work_key_file: Option<PathBuf>,
    /// Read exact provider-secret references from an owner-private manifest.
    #[arg(long, env = "HUB_SECRET_VERSION_MANIFEST_FILE")]
    secret_version_manifest_file: Option<PathBuf>,
}

impl IndexArgs {
    fn validate(&self, database_url: Option<&str>) -> Result<()> {
        if self.topology == "native" {
            anyhow::ensure!(
                self.hybrid_worker_url.is_none() && self.storage_work_key_file.is_none(),
                "Worker storage configuration requires --topology hybrid"
            );
            return Ok(());
        }

        anyhow::ensure!(
            database_url.is_some_and(|url| {
                url.starts_with("postgres://") || url.starts_with("postgresql://")
            }),
            "hybrid indexing requires a PostgreSQL HUB_DATABASE_URL"
        );
        anyhow::ensure!(
            self.hybrid_worker_url.is_some()
                && self.deployment_id.is_some()
                && self.storage_work_key_file.is_some(),
            "hybrid indexing requires HUB_HYBRID_WORKER_URL, HUB_DEPLOYMENT_ID, and HUB_STORAGE_WORK_KEY_FILE"
        );
        Ok(())
    }
}

/// Runs the shared indexer against the configured authoritative database.
///
/// # Errors
///
/// Returns an error for incomplete topology configuration, database or Worker
/// unavailability, missing placements, or any registry that cannot be indexed.
pub(super) async fn run(
    arguments: IndexArgs,
    root: &Option<PathBuf>,
    target: &str,
    database_url: Option<&str>,
) -> Result<()> {
    // Validate before opening or migrating state so an incomplete hybrid
    // command cannot accidentally initialize the local SQLite default.
    arguments.validate(database_url)?;
    let secrets = match &arguments.secret_version_manifest_file {
        Some(path) => aos_hub::coreports::load_secret_version_manifest(path)?,
        None => EmptySecretVersionResolver::shared(),
    };
    let db = Arc::new(super::open_db(root, target, database_url).await?);
    let surfaces = surfaces(&arguments, root, Arc::clone(&db), secrets).await?;
    let registries = match arguments.slug {
        Some(slug) => vec![db
            .registry_by_slug(&slug)
            .await?
            .with_context(|| format!("no registry '{slug}'"))?],
        None => db.list_registries().await?,
    };

    let mut failures = Vec::new();
    for registry in registries {
        let placement = db
            .reconciled_surface_reader(aos_hub_core::db::SurfaceTarget::Registry(registry.id))
            .await?;
        let fetch = surfaces.placement_fetcher(&placement).await?;
        match aos_hub_core::indexer::index_and_record_from_placement(
            db.as_ref(),
            fetch.as_ref(),
            &registry,
            Some(placement.id),
        )
        .await
        {
            Ok(outcome) => println!(
                "{}: {} packages, {} releases, {} channels @ {}",
                registry.slug, outcome.packages, outcome.releases, outcome.channels, outcome.commit,
            ),
            Err(error) => {
                eprintln!("{}: index failed: {error:#}", registry.slug);
                failures.push(registry.slug);
            }
        }
    }
    anyhow::ensure!(
        failures.is_empty(),
        "indexing failed for {}",
        failures.join(", ")
    );
    Ok(())
}

async fn surfaces(
    arguments: &IndexArgs,
    root: &Option<PathBuf>,
    db: Arc<Database>,
    secrets: Arc<dyn SecretVersionResolver>,
) -> Result<Arc<dyn SurfaceProvider>> {
    if arguments.topology == "hybrid" {
        let key_path = arguments
            .storage_work_key_file
            .as_ref()
            .context("hybrid indexing requires HUB_STORAGE_WORK_KEY_FILE")?;
        let key = aos_hub::auth::seal::read_secret_file(key_path)?;
        let work = aos_hub::storage_work::RemoteStorageWorkClient::new(
            arguments
                .hybrid_worker_url
                .as_deref()
                .context("missing hybrid Worker URL")?,
            arguments
                .deployment_id
                .clone()
                .context("missing hybrid deployment identity")?,
            &key,
        )?;
        work.check_ready().await?;
        return Ok(Arc::new(aos_hub::storage_work::HybridSurfaceProvider::new(
            db,
            Arc::new(work),
        )));
    }

    let root = super::resolve_root(root.clone(), false)?;
    let snapshots = aos_hub::image_snapshot::ImageSnapshotStore::open(&root)?;
    snapshots.load_tracked(&db).await?;
    Ok(Arc::new(
        aos_hub::coreports::HubSurfaceProvider::new(
            db,
            aos_hub::fetch::hardened_client().await,
            Some(snapshots),
        )
        .with_credentials(secrets)
        .for_image_indexing(),
    ))
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    fn arguments(options: &[&str]) -> IndexArgs {
        let mut command = vec!["aos-hub", "index"];
        command.extend_from_slice(options);
        let super::super::Command::Index(arguments) =
            super::super::Cli::try_parse_from(command).unwrap().command
        else {
            panic!("expected the index command");
        };
        arguments
    }

    #[test]
    fn native_index_retains_the_positional_registry() {
        let arguments = arguments(&["fleet/containers", "--topology", "native"]);
        arguments.validate(None).unwrap();
        assert_eq!(arguments.slug.as_deref(), Some("fleet/containers"));
    }

    #[test]
    fn hybrid_index_requires_postgres_and_the_complete_pairing() {
        let arguments = arguments(&[
            "--topology",
            "hybrid",
            "--hybrid-worker-url",
            "https://worker.example",
            "--deployment-id",
            "deployment-1",
            "--storage-work-key-file",
            "/private/key",
        ]);
        assert!(arguments.validate(None).is_err());
        assert!(arguments.validate(Some("sqlite::memory:")).is_err());
        arguments.validate(Some("postgresql://hub@db/hub")).unwrap();
        assert!(self::arguments(&["--topology", "hybrid"])
            .validate(Some("postgresql://hub@db/hub"))
            .is_err());
    }

    #[test]
    fn native_index_rejects_worker_storage_configuration() {
        let arguments = arguments(&[
            "--topology",
            "native",
            "--hybrid-worker-url",
            "https://worker.example",
        ]);
        assert!(arguments.validate(None).is_err());
    }
}
