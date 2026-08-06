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
    Database, GrantResource, NewSurfacePlacementSpec, SurfacePlacementRecord, SurfaceTarget,
};
use aos_hub_core::fetch::{StreamedRead, SurfaceFetch, SurfaceProvider};
use aos_hub_core::surface_write::{
    MultipartAbortOutcome, PartTag, SurfaceDeleteOutcome, SurfaceDeletePrecondition, SurfaceWrite,
    SurfaceWriteProvider,
};

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
               body BLOB NOT NULL,
               content_hash TEXT NOT NULL
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
        let binding = db
            .storage_binding(1)
            .await?
            .context("e2e binding is missing")?;
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
            let scope = db.registry_authorization_scope(registry_id).await?;
            db.grant_consumer_scope(
                GrantResource::StorageBinding {
                    id: binding.id,
                    stable_id: &binding.stable_id,
                },
                &scope,
                "explicit",
                "workerd-e2e",
                &format!("worker-image-grant-{name}"),
            )
            .await?;
            let placement = db
                .create_surface_placement(&NewSurfacePlacementSpec {
                    surface: SurfaceTarget::Registry(registry_id),
                    name: format!("{name}-placement"),
                    storage_binding_id: binding.id,
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
            let registry = db
                .registry_by_id(registry_id)
                .await?
                .context("created image registry disappeared")?;
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
            registry_ids.push(registry_id);
        }
        anyhow::ensure!(
            registry_ids.len() == 2,
            "worker image fixture registry count drifted"
        );
        Ok(fixture)
    }
}

fn is_publication_pointer(path: &str) -> bool {
    path == "HEAD" || path == "info/refs" || path.starts_with("channels/")
}

pub(crate) struct WorkerImageFixture {
    trust_key: String,
    objects: std::collections::BTreeMap<String, Vec<u8>>,
    pub(crate) raw_key: String,
    pub(crate) qcow2_key: String,
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
    let raw_key = objects
        .keys()
        .find(|path| path.starts_with("images/sha256/") && path.ends_with("/aos-e2e.img"))
        .context("apr producer surface has no raw image object")?
        .clone();
    let qcow2_key = objects
        .keys()
        .find(|path| path.starts_with("images/sha256/") && path.ends_with("/aos-e2e.qcow2"))
        .context("apr producer surface has no QCOW2 image object")?
        .clone();
    Ok(WorkerImageFixture {
        trust_key: encoded.trust_key,
        objects,
        raw_key,
        qcow2_key,
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
        let cursor = self.sql.exec(
            "SELECT body FROM aos_e2e_surface_objects WHERE object_key = ?",
            Some(vec![SqlStorageValue::String(self.object_key(path))]),
        )?;
        let Some(row) = cursor.raw().next().transpose()? else {
            return Ok(None);
        };
        Ok(Some(Self::blob(
            row.into_iter()
                .next()
                .context("test object row had no body")?,
        )?))
    }

    async fn inventory_strong_etag(&self, path: &str) -> Result<Option<String>> {
        let cursor = self.sql.exec(
            "SELECT content_hash FROM aos_e2e_surface_objects WHERE object_key = ?",
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
            SqlStorageValue::String(version) => Ok(Some(format!("\"do-{version}\""))),
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
        let cursor = self.sql.exec(
            "SELECT body, content_hash FROM aos_e2e_surface_objects WHERE object_key = ?",
            Some(vec![SqlStorageValue::String(self.object_key(path))]),
        )?;
        let Some(row) = cursor.raw().next().transpose()? else {
            return Ok(None);
        };
        let mut values = row.into_iter();
        let bytes = Self::blob(values.next().context("test object row had no body")?)?;
        let version = match values.next().context("test object row had no version")? {
            SqlStorageValue::String(version) => version,
            _ => anyhow::bail!("test object store returned a non-string version"),
        };
        let total = bytes.len() as u64;
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
            strong_etag: Some(format!("\"do-{version}\"")),
            snapshot_lease_id: None,
        }))
    }
}

#[async_trait(?Send)]
impl SurfaceWrite for DoE2eSurface {
    fn multipart_protocol_version(&self) -> Option<u32> {
        Some(1)
    }

    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let content_hash = hex::encode(Sha256::digest(bytes));
        self.sql.exec(
            "INSERT INTO aos_e2e_surface_objects (object_key, body, content_hash)
             VALUES (?, ?, ?)
             ON CONFLICT(object_key) DO UPDATE SET
               body = excluded.body, content_hash = excluded.content_hash",
            Some(vec![
                SqlStorageValue::String(self.object_key(path)),
                SqlStorageValue::Blob(bytes.to_vec()),
                SqlStorageValue::String(content_hash),
            ]),
        )?;
        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        self.sql.exec(
            "DELETE FROM aos_e2e_surface_objects WHERE object_key = ?",
            Some(vec![SqlStorageValue::String(self.object_key(path))]),
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
            "SELECT content_hash, length(body) FROM aos_e2e_surface_objects
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
             WHERE object_key = ? AND content_hash = ? AND length(body) = ?",
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
    ) -> Result<()> {
        let mut body = Vec::new();
        let cursor = self.sql.exec(
            "SELECT part_number, body, etag FROM aos_e2e_surface_parts
             WHERE upload_id = ? ORDER BY part_number",
            Some(vec![SqlStorageValue::String(upload_id.to_string())]),
        )?;
        let rows = cursor.raw().collect::<worker::Result<Vec<_>>>()?;
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
        self.write(path, &body).await?;
        self.abort_multipart(path, upload_id).await?;
        Ok(())
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
