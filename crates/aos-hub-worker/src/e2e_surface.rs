//! Disk-backed surface adapters for the non-default live-workerd artifact.
//!
//! Open-source workerd cannot instantiate Cloudflare R2. The `do-e2e` build
//! therefore injects these adapters at the same [`SurfaceProvider`] and
//! [`SurfaceWriteProvider`] boundary used by production R2. Bytes and multipart
//! parts live in the `HubDb` Durable Object's SQLite storage, so separate HTTP
//! requests and isolates observe one persistent deployment-like object store.

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use worker::{SqlStorage, SqlStorageValue};

use aos_hub_core::db::{
    Database, EndpointHostInput, EndpointRevisionSpec, GrantResource, NewSurfacePlacementSpec,
    RouteSpec, SurfacePlacementRecord, SurfaceTarget,
};
use aos_hub_core::fetch::{
    StreamedRead, SurfaceFetch, SurfaceListPage, SurfaceListedEvidence, SurfaceProvider,
};
use aos_hub_core::surface_write::{
    MultipartAbortOutcome, PartTag, SurfaceDeleteOutcome, SurfaceDeletePrecondition, SurfaceWrite,
    SurfaceWriteProvider,
};

/// Keeps every SQLite value comfortably below Durable Object SQL's value cap.
const SURFACE_CHUNK_BYTES: usize = 256 * 1024;
const MAIN_HTTP_ENDPOINT_ID: &str = "worker-e2e-http";
const PUBLIC_BOUNDARY_ID: &str = "instance:public";
const MAIN_HTTP_PORT: u16 = 8799;

/// Persistent test provider rooted in Durable Object SQLite.
pub(crate) struct DoE2eSurfaceProvider {
    sql: SqlStorage,
}

impl DoE2eSurfaceProvider {
    /// Creates the test object-store tables and returns their provider.
    ///
    /// # Errors
    ///
    /// Returns an error when Durable Object SQLite rejects the schema.
    pub(crate) fn new(sql: SqlStorage) -> Result<Self> {
        sql.exec(
            "CREATE TABLE IF NOT EXISTS aos_e2e_surface_objects (
               object_key TEXT PRIMARY KEY,
               byte_size INTEGER NOT NULL,
               content_hash TEXT NOT NULL,
               strong_etag TEXT NOT NULL
             )",
            None,
        )?;
        sql.exec(
            "CREATE TABLE IF NOT EXISTS aos_e2e_surface_chunks (
               object_key TEXT NOT NULL,
               content_hash TEXT NOT NULL,
               chunk_number INTEGER NOT NULL,
               body BLOB NOT NULL,
               PRIMARY KEY (object_key, content_hash, chunk_number)
             )",
            None,
        )?;
        sql.exec(
            "CREATE TABLE IF NOT EXISTS aos_e2e_surface_uploads (
               upload_id TEXT PRIMARY KEY,
               object_key TEXT NOT NULL
             )",
            None,
        )?;
        sql.exec(
            "CREATE TABLE IF NOT EXISTS aos_e2e_surface_parts (
               upload_id TEXT NOT NULL,
               part_number INTEGER NOT NULL,
               body BLOB NOT NULL,
               etag TEXT NOT NULL,
               PRIMARY KEY (upload_id, part_number)
             )",
            None,
        )?;
        Ok(Self { sql })
    }

    /// Publishes and indexes public/private signed image surfaces in the live DO.
    pub(crate) async fn install_signed_image_fixtures(
        &self,
        db: &Database,
        fixture: WorkerImageFixture,
    ) -> Result<WorkerImageFixture> {
        let binding = db.binding(1).await?.context("e2e binding is missing")?;
        let owner_scope = db
            .org_by_id(1)
            .await?
            .context("e2e organization is missing")?
            .stable_id;
        let binding_resource = GrantResource::Binding {
            id: binding.id,
            stable_id: &binding.stable_id,
        };
        if !db
            .list_consumer_scope_grants(binding_resource)
            .await?
            .iter()
            .any(|grant| grant.consumer_scope_key == owner_scope && grant.state == "active")
        {
            db.grant_consumer_scope(
                binding_resource,
                &owner_scope,
                "explicit",
                "workerd-e2e",
                "worker-image-binding-grant",
            )
            .await?;
        }
        let mut registry_ids = Vec::new();
        for (name, visibility, prefix) in [
            ("images-public", "public", "images-public"),
            ("images-private", "private", "images-private"),
        ] {
            let registry_id = db
                .create_managed_registry(
                    1,
                    "",
                    name,
                    visibility,
                    std::slice::from_ref(&fixture.trust_key),
                    true,
                )
                .await?;
            let registry = db
                .registry_by_id(registry_id)
                .await?
                .context("created image registry disappeared")?;
            anyhow::ensure!(
                registry.owner_scope_key == owner_scope,
                "image registry owner scope drifted from the shared binding grant"
            );
            let placement = db
                .create_surface_placement(&NewSurfacePlacementSpec {
                    surface: SurfaceTarget::Registry(registry_id),
                    name: format!("{name}-placement"),
                    binding_id: binding.id,
                    prefix: prefix.to_string(),
                    kind: "complete".to_string(),
                    desired_state: "active".to_string(),
                    hash_range: None,
                    desired_read_enabled: true,
                    read_order: 0,
                    requires_conditional_writes: false,
                })
                .await?;
            db.observe_surface_placement(placement.id, "ready", "complete", 1)
                .await?;
            let writer = self.placement_writer(&placement).await?;
            for (path, bytes) in fixture
                .objects
                .iter()
                .filter(|(path, _)| !is_publication_pointer(path))
            {
                writer.write(path, bytes).await?;
            }
            let fetch = self.placement_fetcher(&placement).await?;
            aos_hub_core::indexer::index_and_record_from_placement(
                db,
                fetch.as_ref(),
                &registry,
                Some(placement.id),
            )
            .await?;
            anyhow::ensure!(
                db.list_system_images(registry_id).await?.is_empty(),
                "image publication became visible before its mutable pointers"
            );
            for (path, bytes) in fixture
                .objects
                .iter()
                .filter(|(path, _)| is_publication_pointer(path))
            {
                writer.write(path, bytes).await?;
            }
            aos_hub_core::indexer::index_and_record_from_placement(
                db,
                fetch.as_ref(),
                &registry,
                Some(placement.id),
            )
            .await?;
            anyhow::ensure!(
                db.list_system_images(registry_id).await?.len() == 2,
                "signed store-backed image encodings were not indexed"
            );
            configure_hub_route(
                db,
                SurfaceTarget::Registry(registry_id),
                placement.id,
                &registry.slug,
            )
            .await?;
            registry_ids.push(registry_id);
        }
        anyhow::ensure!(
            registry_ids.len() == 2,
            "worker image fixture registry count drifted"
        );
        Ok(fixture)
    }
}

pub(crate) async fn configure_hub_route(
    db: &Database,
    surface: SurfaceTarget,
    placement_id: i64,
    slug: &str,
) -> Result<()> {
    let (org_id, owner_scope, visibility) = match surface {
        SurfaceTarget::Registry(id) => {
            let registry = db
                .registry_by_id(id)
                .await?
                .context("worker fixture registry is missing")?;
            (
                registry.org_id,
                registry.owner_scope_key,
                registry.visibility,
            )
        }
        SurfaceTarget::BinaryCache(id) => {
            let cache = db
                .binary_cache_by_id(id)
                .await?
                .context("worker fixture cache is missing")?;
            (cache.org_id, cache.owner_scope_key, cache.visibility)
        }
    };

    let boundary = GrantResource::NetworkPolicy {
        id: PUBLIC_BOUNDARY_ID,
    };
    if !db
        .list_consumer_scope_grants(boundary)
        .await?
        .iter()
        .any(|grant| grant.consumer_scope_key == owner_scope && grant.state == "active")
    {
        db.grant_consumer_scope(
            boundary,
            &owner_scope,
            "explicit",
            "workerd-e2e",
            "worker-image-boundary-grant",
        )
        .await?;
    }
    if db.endpoint(MAIN_HTTP_ENDPOINT_ID).await?.is_none() {
        db.create_endpoint(
            MAIN_HTTP_ENDPOINT_ID,
            &owner_scope,
            org_id,
            "http",
            &EndpointHostInput::Ipv4([127, 0, 0, 1]),
            MAIN_HTTP_PORT,
            PUBLIC_BOUNDARY_ID,
            &EndpointRevisionSpec {
                boundary_revision: 1,
                ingress_kind: "hub".to_string(),
                listener_configuration: "workerd-e2e".to_string(),
                tls_configuration: "{}".to_string(),
                probe_configuration: "{\"provider\":\"native_file\",\"signerSecretRef\":\"worker-e2e-probe-key\",\"publicKey\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}".to_string(),
            },
            Some(1),
            "workerd-e2e",
            "worker-image-endpoint",
        )
        .await?;
        db.reconcile_endpoint(MAIN_HTTP_ENDPOINT_ID, 1, 1, "healthy", true, false, None, 1)
            .await?;
    }

    let base_path = format!("/{slug}");
    let canonical_url = format!("http://127.0.0.1:{MAIN_HTTP_PORT}{base_path}");
    let access_policy_json = "{}";
    let access_policy_digest = hex::encode(Sha256::digest(access_policy_json.as_bytes()));
    let endpoint = db
        .endpoint(MAIN_HTTP_ENDPOINT_ID)
        .await?
        .context("worker image endpoint disappeared")?;
    let endpoint_digest = hex::decode(&endpoint.endpoint_identity_digest)
        .context("decoding worker image endpoint identity")?;
    let reservation_key = [9_u8; 32];
    let reservation_digest = Database::route_reservation_digest(
        &reservation_key,
        &endpoint_digest,
        &base_path,
        &canonical_url,
    )?;
    let route_id = format!("worker-e2e-{}", slug.replace('/', "-"));
    let (serves_git, serves_cache) = match surface {
        SurfaceTarget::Registry(_) => (true, false),
        SurfaceTarget::BinaryCache(_) => (false, true),
    };
    let route = db
        .create_route(
            &route_id,
            surface,
            &RouteSpec {
                consumer_scope_key: owner_scope,
                endpoint_id: MAIN_HTTP_ENDPOINT_ID.to_string(),
                endpoint_generation: 1,
                endpoint_ingress_kind: "hub".to_string(),
                base_path,
                mode: "hub_proxy".to_string(),
                access_policy_kind: if visibility == "public" {
                    "public".to_string()
                } else {
                    "hub_auth".to_string()
                },
                access_policy_json: access_policy_json.to_string(),
                access_policy_digest: access_policy_digest.clone(),
                access_boundary_id: None,
                access_boundary_revision: None,
                external_provider_kind: None,
                external_provider_resource_id: None,
                external_provider_revision: None,
                gateway_id: None,
                gateway_generation: None,
                target_binding_id: None,
                gateway_client_base_path: None,
                target_placement_prefix: None,
                placement_id: Some(placement_id),
                placement_policy_revision_id: None,
                serves_git,
                serves_cache,
                serves_web: true,
                serves_oci: false,
                enabled: true,
            },
            &canonical_url,
            1,
            &reservation_digest,
            &[(1, reservation_digest.to_vec())],
            None,
            "workerd-e2e",
        )
        .await?;
    db.reconcile_route(
        &route_id,
        route
            .configuration_generation
            .context("worker image route has no selected generation")?,
        route
            .configuration_digest
            .as_deref()
            .context("worker image route has no configuration digest")?,
        &access_policy_digest,
        "healthy",
        "verified",
        None,
        None,
        1,
    )
    .await?;
    let audiences: &[&str] = match surface {
        SurfaceTarget::Registry(_) => &["git", "web"],
        SurfaceTarget::BinaryCache(_) => &["nix_cache", "web"],
    };
    for audience in audiences {
        db.set_route_advertisement(surface, audience, &route_id, None)
            .await?;
    }
    Ok(())
}

/// Configures one root-mounted OCI route for the live-workerd parity fixture.
///
/// The public and authenticated authorities intentionally use distinct
/// loopback ports. This lets the same workerd service qualify authority-bound
/// tokens and route policy without relying on TLS or external DNS inside the
/// hermetic test.
///
/// # Errors
///
/// Returns an error when the registry, endpoint, grant, route, or ready route
/// generation cannot be installed in Durable Object SQLite.
pub(crate) async fn configure_oci_route(
    db: &Database,
    registry_id: i64,
    placement_id: i64,
    port: u16,
    access_policy_kind: &str,
) -> Result<()> {
    let registry = db
        .registry_by_id(registry_id)
        .await?
        .context("worker OCI fixture registry is missing")?;
    // The public OCI authority is served by the main workerd socket. Reuse its
    // endpoint record: endpoint identity is authority + boundary, and the
    // database correctly rejects aliases for the same identity.
    let endpoint_id = if port == MAIN_HTTP_PORT {
        MAIN_HTTP_ENDPOINT_ID.to_string()
    } else {
        format!("worker-e2e-oci-{registry_id}")
    };
    let boundary_id = PUBLIC_BOUNDARY_ID;

    let boundary = GrantResource::NetworkPolicy { id: boundary_id };
    if !db
        .list_consumer_scope_grants(boundary)
        .await?
        .iter()
        .any(|grant| {
            grant.consumer_scope_key == registry.owner_scope_key && grant.state == "active"
        })
    {
        db.grant_consumer_scope(
            boundary,
            &registry.owner_scope_key,
            "explicit",
            "workerd-e2e",
            "worker-oci-boundary-grant",
        )
        .await?;
    }
    if db.endpoint(&endpoint_id).await?.is_none() {
        db.create_endpoint(
            &endpoint_id,
            &registry.owner_scope_key,
            registry.org_id,
            "http",
            &EndpointHostInput::Ipv4([127, 0, 0, 1]),
            port,
            boundary_id,
            &EndpointRevisionSpec {
                boundary_revision: 1,
                ingress_kind: "hub".to_string(),
                listener_configuration: "workerd-e2e-oci".to_string(),
                tls_configuration: "{}".to_string(),
                probe_configuration: "{\"provider\":\"native_file\",\"signerSecretRef\":\"worker-e2e-probe-key\",\"publicKey\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}".to_string(),
            },
            Some(1),
            "workerd-e2e",
            "worker-oci-endpoint",
        )
        .await?;
        db.reconcile_endpoint(&endpoint_id, 1, 1, "healthy", true, false, None, 1)
            .await?;
    }

    let canonical_url = format!("http://127.0.0.1:{port}");
    let access_policy_json = "{}";
    let access_policy_digest = hex::encode(Sha256::digest(access_policy_json.as_bytes()));
    let endpoint = db
        .endpoint(&endpoint_id)
        .await?
        .context("worker OCI fixture endpoint disappeared")?;
    let endpoint_digest = hex::decode(&endpoint.endpoint_identity_digest)
        .context("decoding worker OCI endpoint identity")?;
    let reservation_digest =
        Database::route_reservation_digest(&[19_u8; 32], &endpoint_digest, "", &canonical_url)?;
    let route_id = format!("worker-e2e-oci-{registry_id}");
    let route = db
        .create_route(
            &route_id,
            SurfaceTarget::Registry(registry_id),
            &RouteSpec {
                consumer_scope_key: registry.owner_scope_key,
                endpoint_id,
                endpoint_generation: 1,
                endpoint_ingress_kind: "hub".to_string(),
                base_path: String::new(),
                mode: "hub_proxy".to_string(),
                access_policy_kind: access_policy_kind.to_string(),
                access_policy_json: access_policy_json.to_string(),
                access_policy_digest: access_policy_digest.clone(),
                access_boundary_id: None,
                access_boundary_revision: None,
                external_provider_kind: None,
                external_provider_resource_id: None,
                external_provider_revision: None,
                gateway_id: None,
                gateway_generation: None,
                target_binding_id: None,
                gateway_client_base_path: None,
                target_placement_prefix: None,
                placement_id: Some(placement_id),
                placement_policy_revision_id: None,
                serves_git: false,
                serves_cache: false,
                serves_web: false,
                serves_oci: true,
                enabled: true,
            },
            &canonical_url,
            1,
            &reservation_digest,
            &[(1, reservation_digest.to_vec())],
            None,
            "workerd-e2e",
        )
        .await?;
    db.reconcile_route(
        &route_id,
        route
            .configuration_generation
            .context("worker OCI route has no selected generation")?,
        route
            .configuration_digest
            .as_deref()
            .context("worker OCI route has no configuration digest")?,
        &access_policy_digest,
        "healthy",
        "verified",
        None,
        None,
        1,
    )
    .await?;
    Ok(())
}

fn is_publication_pointer(path: &str) -> bool {
    path == "HEAD" || path == "info/refs" || path.starts_with("channels/")
}

pub(crate) struct WorkerImageFixture {
    trust_key: String,
    objects: std::collections::BTreeMap<String, Vec<u8>>,
}

#[derive(serde::Deserialize)]
struct ProducerSurfaceFixture {
    trust_key: String,
    objects: std::collections::BTreeMap<String, String>,
}

/// Decodes the exact static origin emitted by the external `apr release` fixture.
pub(crate) fn decode_producer_surface_fixture(bytes: &[u8]) -> Result<WorkerImageFixture> {
    let encoded: ProducerSurfaceFixture =
        serde_json::from_slice(bytes).context("decoding apr producer surface")?;
    let mut objects = std::collections::BTreeMap::new();
    for (path, body) in encoded.objects {
        anyhow::ensure!(
            aos_hub_core::url_guard::validate_http_surface_path(&path).is_ok(),
            "producer fixture contains an unsafe surface path"
        );
        objects.insert(
            path,
            base64::engine::general_purpose::STANDARD
                .decode(body)
                .context("decoding producer surface object")?,
        );
    }
    anyhow::ensure!(
        objects.keys().any(|path| path.ends_with(".narinfo")),
        "apr producer surface has no unified-cache metadata"
    );
    anyhow::ensure!(
        objects
            .keys()
            .any(|path| path.starts_with("nar/") && path.ends_with(".nar.zst")),
        "apr producer surface has no unified-cache NAR objects"
    );
    Ok(WorkerImageFixture {
        trust_key: encoded.trust_key,
        objects,
    })
}

struct DoE2eSurface {
    sql: SqlStorage,
    prefix: String,
}

impl DoE2eSurface {
    fn object_key(&self, path: &str) -> String {
        let prefix = self.prefix.trim_matches('/');
        if prefix.is_empty() {
            path.trim_start_matches('/').to_string()
        } else {
            format!("{prefix}/{}", path.trim_start_matches('/'))
        }
    }

    fn blob(value: SqlStorageValue) -> Result<Vec<u8>> {
        match value {
            SqlStorageValue::Blob(bytes) => Ok(bytes),
            _ => anyhow::bail!("test object store returned a non-blob body"),
        }
    }

    fn load_object(&self, path: &str) -> Result<Option<(Vec<u8>, String, String, i64)>> {
        let object_key = self.object_key(path);
        let cursor = self.sql.exec(
            "SELECT byte_size, content_hash, strong_etag FROM aos_e2e_surface_objects
             WHERE object_key = ?",
            Some(vec![SqlStorageValue::String(object_key.clone())]),
        )?;
        let Some(row) = cursor.raw().next().transpose()? else {
            return Ok(None);
        };
        let [SqlStorageValue::Integer(byte_size), SqlStorageValue::String(content_hash), SqlStorageValue::String(strong_etag)] =
            row.as_slice()
        else {
            anyhow::bail!("test object metadata row had an invalid shape");
        };
        anyhow::ensure!(*byte_size >= 0, "test object has a negative byte size");
        let cursor = self.sql.exec(
            "SELECT body FROM aos_e2e_surface_chunks
             WHERE object_key = ? AND content_hash = ? ORDER BY chunk_number",
            Some(vec![
                SqlStorageValue::String(object_key),
                SqlStorageValue::String(content_hash.clone()),
            ]),
        )?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(*byte_size).context("test object size exceeds address space")?,
        );
        for row in cursor.raw() {
            let row = row?;
            let body = row
                .into_iter()
                .next()
                .context("test object chunk row had no body")?;
            bytes.extend(Self::blob(body)?);
        }
        anyhow::ensure!(
            bytes.len() == usize::try_from(*byte_size)?,
            "test object chunk coverage is incomplete"
        );
        Ok(Some((
            bytes,
            content_hash.clone(),
            strong_etag.clone(),
            *byte_size,
        )))
    }
}

#[async_trait(?Send)]
impl SurfaceProvider for DoE2eSurfaceProvider {
    async fn placement_fetcher(
        &self,
        placement: &SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceFetch>> {
        Ok(Box::new(DoE2eSurface {
            sql: self.sql.clone(),
            prefix: placement.prefix.clone(),
        }))
    }
}

#[async_trait(?Send)]
impl SurfaceWriteProvider for DoE2eSurfaceProvider {
    async fn placement_writer(
        &self,
        placement: &SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceWrite>> {
        Ok(Box::new(DoE2eSurface {
            sql: self.sql.clone(),
            prefix: placement.prefix.clone(),
        }))
    }

    async fn placement_writer_at_revision(
        &self,
        placement: &SurfacePlacementRecord,
        revision: &aos_hub_core::db::BindingWriteRevisionRecord,
    ) -> Result<Box<dyn SurfaceWrite>> {
        anyhow::ensure!(placement.binding_id == revision.binding_id);
        self.placement_writer(placement).await
    }

    async fn placement_deleter(
        &self,
        placement: &SurfacePlacementRecord,
        _expected_binding_resource_version: i64,
        _delete_credential_generation: i64,
    ) -> Result<Box<dyn SurfaceWrite>> {
        self.placement_writer(placement).await
    }
}

#[async_trait(?Send)]
impl SurfaceFetch for DoE2eSurface {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.load_object(path)?.map(|(bytes, _, _, _)| bytes))
    }

    async fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<SurfaceListPage> {
        anyhow::ensure!(limit > 0, "test surface listing limit must be positive");
        let query_limit = i64::try_from(
            limit
                .checked_add(1)
                .context("test surface listing limit overflowed")?,
        )
        .context("test surface listing limit exceeds SQLite")?;
        let prefix = match self.prefix.trim_matches('/') {
            "" => String::new(),
            prefix => format!("{prefix}/"),
        };
        let after_key = cursor
            .map(|cursor| self.object_key(cursor))
            .unwrap_or_else(|| prefix.clone());
        let cursor = self.sql.exec(
            "SELECT object_key, byte_size, strong_etag
             FROM aos_e2e_surface_objects
             WHERE substr(object_key, 1, ?) = ? AND object_key > ?
             ORDER BY object_key LIMIT ?",
            Some(vec![
                SqlStorageValue::Integer(i64::try_from(prefix.len())?),
                SqlStorageValue::String(prefix.clone()),
                SqlStorageValue::String(after_key),
                SqlStorageValue::Integer(query_limit),
            ]),
        )?;
        let mut paths = Vec::new();
        let mut evidence = std::collections::BTreeMap::new();
        for row in cursor.raw() {
            let row = row?;
            let [SqlStorageValue::String(object_key), SqlStorageValue::Integer(byte_size), SqlStorageValue::String(strong_etag)] =
                row.as_slice()
            else {
                anyhow::bail!("test object listing row had an invalid shape");
            };
            anyhow::ensure!(*byte_size >= 0, "test object has a negative byte size");
            let path = object_key
                .strip_prefix(&prefix)
                .context("test object escaped its placement prefix")?
                .to_string();
            paths.push(path.clone());
            evidence.insert(
                path,
                SurfaceListedEvidence {
                    size: *byte_size,
                    strong_etag: strong_etag.clone(),
                },
            );
        }
        let next_cursor = if paths.len() > limit {
            for overflow in paths.split_off(limit) {
                evidence.remove(&overflow);
            }
            paths.last().cloned()
        } else {
            None
        };
        Ok(SurfaceListPage {
            paths,
            evidence,
            next_cursor,
        })
    }

    async fn inventory_strong_etag(&self, path: &str) -> Result<Option<String>> {
        let cursor = self.sql.exec(
            "SELECT strong_etag FROM aos_e2e_surface_objects WHERE object_key = ?",
            Some(vec![SqlStorageValue::String(self.object_key(path))]),
        )?;
        let Some(row) = cursor.raw().next().transpose()? else {
            return Ok(None);
        };
        match row
            .into_iter()
            .next()
            .context("test object row had no version")?
        {
            SqlStorageValue::String(etag) => Ok(Some(etag)),
            _ => anyhow::bail!("test object store returned a non-string version"),
        }
    }

    fn describe(&self) -> String {
        format!("do-e2e://{}", self.prefix)
    }

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<StreamedRead>> {
        let Some((bytes, _, strong_etag, byte_size)) = self.load_object(path)? else {
            return Ok(None);
        };
        let total = u64::try_from(byte_size).context("test object size is negative")?;
        let (body, served) = match range {
            Some((start, end)) if start < total => {
                let end = end.min(total.saturating_sub(1));
                (
                    bytes[start as usize..=end as usize].to_vec(),
                    Some((start, end)),
                )
            }
            _ => (bytes, None),
        };
        Ok(Some(StreamedRead {
            body: axum::body::Body::from(body),
            total,
            range: served,
            strong_etag: Some(strong_etag),
            snapshot_lease_id: None,
        }))
    }
}

#[async_trait(?Send)]
impl SurfaceWrite for DoE2eSurface {
    fn multipart_protocol_version(&self) -> Option<u32> {
        Some(1)
    }

    fn abandoned_multipart_lifetime_secs(&self) -> Option<u64> {
        Some(24 * 60 * 60)
    }

    fn expected_multipart_etag(&self, parts: &[PartTag]) -> Result<Option<String>> {
        let mut ordered = parts.to_vec();
        ordered.sort_by_key(|part| part.part_number);
        anyhow::ensure!(
            ordered.iter().enumerate().all(|(index, part)| {
                part.part_number as usize == index + 1
                    && part.etag.len() == 64
                    && part.etag.bytes().all(|byte| byte.is_ascii_hexdigit())
            }),
            "test multipart completion manifest is malformed"
        );
        let mut identities = Vec::with_capacity(ordered.len() * 32);
        for part in &ordered {
            identities.extend(hex::decode(&part.etag)?);
        }
        Ok(Some(format!(
            "\"do-multipart-{}-{}\"",
            hex::encode(Sha256::digest(&identities)),
            ordered.len()
        )))
    }

    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let content_hash = hex::encode(Sha256::digest(bytes));
        let strong_etag = format!("\"do-{content_hash}\"");
        let object_key = self.object_key(path);
        for (chunk_number, chunk) in bytes.chunks(SURFACE_CHUNK_BYTES).enumerate() {
            self.sql.exec(
                "INSERT INTO aos_e2e_surface_chunks
                 (object_key, content_hash, chunk_number, body) VALUES (?, ?, ?, ?)
                 ON CONFLICT(object_key, content_hash, chunk_number) DO UPDATE SET
                   body = excluded.body",
                Some(vec![
                    SqlStorageValue::String(object_key.clone()),
                    SqlStorageValue::String(content_hash.clone()),
                    SqlStorageValue::Integer(i64::try_from(chunk_number)?),
                    SqlStorageValue::Blob(chunk.to_vec()),
                ]),
            )?;
        }
        let byte_size = i64::try_from(bytes.len()).context("test object is too large")?;
        self.sql.exec(
            "INSERT INTO aos_e2e_surface_objects
             (object_key, byte_size, content_hash, strong_etag)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(object_key) DO UPDATE SET
               byte_size = excluded.byte_size, content_hash = excluded.content_hash,
               strong_etag = excluded.strong_etag",
            Some(vec![
                SqlStorageValue::String(object_key.clone()),
                SqlStorageValue::Integer(byte_size),
                SqlStorageValue::String(content_hash),
                SqlStorageValue::String(strong_etag),
            ]),
        )?;
        self.sql.exec(
            "DELETE FROM aos_e2e_surface_chunks
             WHERE object_key = ? AND content_hash != (
               SELECT content_hash FROM aos_e2e_surface_objects WHERE object_key = ?)",
            Some(vec![
                SqlStorageValue::String(object_key.clone()),
                SqlStorageValue::String(object_key),
            ]),
        )?;
        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let object_key = self.object_key(path);
        self.sql.exec(
            "DELETE FROM aos_e2e_surface_objects WHERE object_key = ?",
            Some(vec![SqlStorageValue::String(object_key.clone())]),
        )?;
        self.sql.exec(
            "DELETE FROM aos_e2e_surface_chunks WHERE object_key = ?",
            Some(vec![SqlStorageValue::String(object_key)]),
        )?;
        Ok(())
    }

    async fn delete_if_matches(
        &self,
        path: &str,
        expected: &SurfaceDeletePrecondition,
    ) -> Result<SurfaceDeleteOutcome> {
        let object_key = self.object_key(path);
        let cursor = self.sql.exec(
            "SELECT content_hash, byte_size FROM aos_e2e_surface_objects
             WHERE object_key = ?",
            Some(vec![SqlStorageValue::String(object_key.clone())]),
        )?;
        let Some(row) = cursor.raw().next().transpose()? else {
            return Ok(SurfaceDeleteOutcome::NotFound);
        };
        let [SqlStorageValue::String(content_hash), SqlStorageValue::Integer(size)] =
            row.as_slice()
        else {
            anyhow::bail!("test object identity row had an invalid shape");
        };
        let expected_hash = expected
            .content_hash
            .as_deref()
            .or_else(|| expected.etag.as_deref().map(|etag| etag.trim_matches('"')))
            .context("test identity-checked deletion requires a content hash or ETag")?;
        if !content_hash.eq_ignore_ascii_case(expected_hash)
            || expected
                .size
                .is_some_and(|expected_size| expected_size != *size)
        {
            return Ok(SurfaceDeleteOutcome::PreconditionFailed {
                detail: "test object identity changed after inventory".to_string(),
            });
        }
        let deleted = self.sql.exec(
            "DELETE FROM aos_e2e_surface_objects
             WHERE object_key = ? AND content_hash = ? AND byte_size = ?",
            Some(vec![
                SqlStorageValue::String(object_key),
                SqlStorageValue::String(content_hash.clone()),
                SqlStorageValue::Integer(*size),
            ]),
        )?;
        if deleted.rows_written() != 1 {
            return Ok(SurfaceDeleteOutcome::PreconditionFailed {
                detail: "test object identity changed during deletion".to_string(),
            });
        }
        self.sql.exec(
            "DELETE FROM aos_e2e_surface_chunks WHERE object_key = ?",
            Some(vec![SqlStorageValue::String(self.object_key(path))]),
        )?;
        Ok(SurfaceDeleteOutcome::Deleted {
            etag: expected.etag.clone(),
            content_hash: Some(content_hash.clone()),
            size: Some(*size),
        })
    }

    async fn create_multipart(&self, path: &str) -> Result<String> {
        let upload_id = uuid::Uuid::new_v4().to_string();
        self.sql.exec(
            "INSERT INTO aos_e2e_surface_uploads (upload_id, object_key) VALUES (?, ?)",
            Some(vec![
                SqlStorageValue::String(upload_id.clone()),
                SqlStorageValue::String(self.object_key(path)),
            ]),
        )?;
        Ok(upload_id)
    }

    async fn upload_part(
        &self,
        path: &str,
        upload_id: &str,
        part_number: u32,
        bytes: &[u8],
    ) -> Result<PartTag> {
        let object_key = self.object_key(path);
        let upload = self.sql.exec(
            "SELECT object_key FROM aos_e2e_surface_uploads
             WHERE upload_id = ? AND object_key = ?",
            Some(vec![
                SqlStorageValue::String(upload_id.to_string()),
                SqlStorageValue::String(object_key),
            ]),
        )?;
        anyhow::ensure!(
            upload.raw().next().transpose()?.is_some(),
            "multipart upload does not exist"
        );
        let etag = hex::encode(Sha256::digest(bytes));
        self.sql.exec(
            "INSERT INTO aos_e2e_surface_parts (upload_id, part_number, body, etag)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(upload_id, part_number) DO UPDATE SET
               body = excluded.body, etag = excluded.etag",
            Some(vec![
                SqlStorageValue::String(upload_id.to_string()),
                SqlStorageValue::Integer(i64::from(part_number)),
                SqlStorageValue::Blob(bytes.to_vec()),
                SqlStorageValue::String(etag.clone()),
            ]),
        )?;
        Ok(PartTag { part_number, etag })
    }

    async fn complete_multipart(
        &self,
        path: &str,
        upload_id: &str,
        parts: &[PartTag],
    ) -> Result<String> {
        let mut body = Vec::new();
        let cursor = self.sql.exec(
            "SELECT part_number, body, etag FROM aos_e2e_surface_parts
             WHERE upload_id = ? ORDER BY part_number",
            Some(vec![SqlStorageValue::String(upload_id.to_string())]),
        )?;
        let rows = cursor.raw().collect::<worker::Result<Vec<_>>>()?;
        if rows.is_empty() {
            let (_, _, strong_etag, _) = self
                .load_object(path)?
                .context("completed test multipart object disappeared")?;
            return Ok(strong_etag);
        }
        anyhow::ensure!(rows.len() == parts.len(), "multipart part count changed");
        for (row, expected) in rows.into_iter().zip(parts) {
            let [SqlStorageValue::Integer(part_number), body_value, SqlStorageValue::String(etag)] =
                row.as_slice()
            else {
                anyhow::bail!("test multipart row had an invalid shape");
            };
            anyhow::ensure!(
                i64::from(expected.part_number) == *part_number
                    && expected.etag.as_str() == etag.as_str()
            );
            body.extend(Self::blob(body_value.clone())?);
        }
        let strong_etag = self
            .expected_multipart_etag(parts)?
            .context("test multipart completion identity was unavailable")?;
        self.write(path, &body).await?;
        self.sql.exec(
            "UPDATE aos_e2e_surface_objects SET strong_etag = ? WHERE object_key = ?",
            Some(vec![
                SqlStorageValue::String(strong_etag.clone()),
                SqlStorageValue::String(self.object_key(path)),
            ]),
        )?;
        self.abort_multipart(path, upload_id).await?;
        Ok(strong_etag)
    }

    async fn abort_multipart(&self, _path: &str, upload_id: &str) -> Result<MultipartAbortOutcome> {
        self.sql.exec(
            "DELETE FROM aos_e2e_surface_parts WHERE upload_id = ?",
            Some(vec![SqlStorageValue::String(upload_id.to_string())]),
        )?;
        let deleted = self.sql.exec(
            "DELETE FROM aos_e2e_surface_uploads WHERE upload_id = ?",
            Some(vec![SqlStorageValue::String(upload_id.to_string())]),
        )?;
        Ok(if deleted.rows_written() == 0 {
            MultipartAbortOutcome::Absent
        } else {
            MultipartAbortOutcome::Aborted
        })
    }
}
