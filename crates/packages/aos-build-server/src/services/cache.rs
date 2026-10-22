//! ConnectRPC implementation of `CacheService`.
//!
//! RPC twins of the REST cache endpoints in [`crate::routes`]:
//! `GetCacheInfo`, `GetNarInfo`, and `QueryMissing` are unary;
//! `Upload`/`UploadPack` are client-streaming through bounded private spool
//! files before import with the same `.drv`-or-CA check as REST uploads;
//! `Download` is server-streaming, chunking the same compressed NAR pipeline
//! used by `GET /{view}/nar/{filename}`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use connectrpc::{
    ConnectError, Encodable, ErrorCode, InboundStream, RequestContext, Response, ServiceRequest,
    ServiceResult,
};
use futures_util::{Stream, StreamExt};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Semaphore;

use aos_build_api::aos::cache::v1::*;
use aos_nar::info as core_narinfo;
use aos_nix::{StoreHash, aos_nix_env};

use crate::access;
use crate::compress::{self, Compression};
use crate::narinfo;
use crate::pack;
use crate::routes::{AppState, NarMaterializationError, measure_nar_bounded};
use crate::services;
#[cfg(test)]
use crate::views::ViewManager;

/// Boxed server-streaming response used by the generated service traits.
type ResponseStream<T> = Pin<Box<dyn Stream<Item = Result<T, ConnectError>> + Send>>;

/// ConnectRPC cache service backed by the shared [`AppState`].
pub struct CacheServiceImpl {
    /// Shared server state (store, views, signer, config).
    pub state: Arc<AppState>,
    upload_admission: Arc<Semaphore>,
}

impl CacheServiceImpl {
    /// Creates a cache service with the configured shared upload budget.
    pub fn new(state: Arc<AppState>) -> Self {
        let upload_admission = Arc::new(Semaphore::new(state.config.uploads.max_concurrent));
        Self {
            state,
            upload_admission,
        }
    }

    fn upload_deadline(&self, context: &RequestContext) -> Instant {
        let configured = Instant::now()
            .checked_add(Duration::from_secs(
                self.state.config.uploads.timeout_seconds,
            ))
            .unwrap_or_else(Instant::now);

        context
            .deadline()
            .map_or(configured, |deadline| deadline.min(configured))
    }
}

struct UploadSpool {
    path: PathBuf,
    file: tokio::fs::File,
    length: u64,
}

impl UploadSpool {
    async fn create(root: &Path) -> Result<Self, ConnectError> {
        let directory = root.join("uploads").join("rpc");
        tokio::fs::create_dir_all(&directory)
            .await
            .map_err(internal_upload_error("creating RPC upload directory"))?;
        tokio::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(internal_upload_error(
                "setting RPC upload directory permissions",
            ))?;

        let path = directory.join(format!(".{}.upload", uuid::Uuid::new_v4()));
        let file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .await
            .map_err(internal_upload_error("creating RPC upload spool"))?;

        Ok(Self {
            path,
            file,
            length: 0,
        })
    }

    async fn append(&mut self, data: &[u8], maximum: u64) -> Result<(), ConnectError> {
        let data_length = u64::try_from(data.len()).map_err(|_| {
            ConnectError::new(ErrorCode::ResourceExhausted, "upload chunk is too large")
        })?;
        let new_length = self.length.checked_add(data_length).ok_or_else(|| {
            ConnectError::new(ErrorCode::ResourceExhausted, "upload size overflow")
        })?;
        if new_length > maximum {
            return Err(ConnectError::new(
                ErrorCode::ResourceExhausted,
                format!("upload exceeds {maximum} byte limit"),
            ));
        }

        self.file
            .write_all(data)
            .await
            .map_err(internal_upload_error("writing RPC upload spool"))?;
        self.length = new_length;
        Ok(())
    }

    async fn read_bounded(&mut self) -> Result<Vec<u8>, ConnectError> {
        self.file
            .flush()
            .await
            .map_err(internal_upload_error("flushing RPC upload spool"))?;
        self.file
            .seek(std::io::SeekFrom::Start(0))
            .await
            .map_err(internal_upload_error("rewinding RPC upload spool"))?;

        let capacity = usize::try_from(self.length).map_err(|_| {
            ConnectError::new(ErrorCode::ResourceExhausted, "upload is too large to parse")
        })?;
        let mut data = Vec::new();
        data.try_reserve_exact(capacity).map_err(|_| {
            ConnectError::new(
                ErrorCode::ResourceExhausted,
                "upload buffer allocation failed",
            )
        })?;
        self.file
            .read_to_end(&mut data)
            .await
            .map_err(internal_upload_error("reading RPC upload spool"))?;
        Ok(data)
    }
}

impl Drop for UploadSpool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn internal_upload_error(operation: &'static str) -> impl FnOnce(std::io::Error) -> ConnectError {
    move |error| ConnectError::new(ErrorCode::Internal, format!("{operation}: {error}"))
}

impl CacheService for CacheServiceImpl {
    /// `GetCacheInfo` — cache metadata and capability list for a view.
    ///
    /// Allowed anonymously when the view has `anonymous_read = true`,
    /// otherwise requires a JWT with the `read` permission on the view.
    async fn get_cache_info<'a>(
        &'a self,
        ctx: RequestContext,
        req: ServiceRequest<'_, GetCacheInfoRequest>,
    ) -> ServiceResult<impl Encodable<CacheInfo> + Send + use<'a>> {
        let view: &str = req.view;

        let view_config = self
            .state
            .views
            .get_view(view)
            .ok_or_else(|| ConnectError::new(ErrorCode::NotFound, "unknown view"))?;
        services::require_rpc_read_access(&ctx, &self.state, view, view_config.anonymous_read)?;

        let response = CacheInfo {
            store_dir: self.state.store_dir.clone(),
            want_mass_query: true,
            priority: 30,
            capabilities: vec![
                "pack-upload".into(),
                "query-missing".into(),
                "sse-logs".into(),
                "zstd".into(),
                "xz".into(),
                "content-range".into(),
            ],
            ..Default::default()
        };

        Response::ok(response)
    }

    /// `GetNarInfo` — structured narinfo for a store hash.
    ///
    /// Same read-access rules as `GetCacheInfo`. The hash must be visible
    /// in the view (`not_found` otherwise). Serving the info bumps the
    /// path's access metadata for eviction scoring. Internally the narinfo
    /// text is rendered (and signed) exactly as for REST, then parsed back
    /// into the proto message.
    async fn get_nar_info<'a>(
        &'a self,
        ctx: RequestContext,
        req: ServiceRequest<'_, GetNarInfoRequest>,
    ) -> ServiceResult<impl Encodable<NarInfo> + Send + use<'a>> {
        let view: &str = req.view;
        let store_hash: StoreHash = req.store_hash.parse().map_err(|error| {
            ConnectError::new(
                ErrorCode::InvalidArgument,
                format!("invalid store hash: {error}"),
            )
        })?;

        let view_config = self
            .state
            .views
            .get_view(view)
            .ok_or_else(|| ConnectError::new(ErrorCode::NotFound, "unknown view"))?;
        services::require_rpc_read_access(&ctx, &self.state, view, view_config.anonymous_read)?;

        let store_path = self
            .state
            .views
            .check_visibility(view, &store_hash)
            .map_err(|e| ConnectError::new(ErrorCode::Internal, format!("visibility check: {e}")))?
            .ok_or_else(|| ConnectError::new(ErrorCode::NotFound, "path not in view"))?;

        let info = self
            .state
            .store
            .path_info(&store_path)
            .map_err(|e| ConnectError::new(ErrorCode::Internal, format!("store query: {e}")))?
            .ok_or_else(|| ConnectError::new(ErrorCode::NotFound, "path not in store"))?;

        // Update access metadata (best-effort).
        let _ = access::update_access(&self.state.views, view, &store_hash);

        let measured_file = measure_nar_bounded(&self.state, info.clone())
            .await
            .map_err(|error| match error {
                NarMaterializationError::Busy => ConnectError::new(
                    ErrorCode::ResourceExhausted,
                    "NAR materialization capacity is busy",
                ),
                NarMaterializationError::Failed(error) => ConnectError::new(
                    ErrorCode::Internal,
                    format!("narinfo measurement: {error:#}"),
                ),
            })?;

        let narinfo_text = narinfo::format_narinfo(
            &info,
            &self.state.store_dir,
            &self.state.config.compression,
            measured_file,
            Some(&self.state.signer),
        )
        .map_err(|e| ConnectError::new(ErrorCode::Internal, format!("narinfo rendering: {e}")))?;

        // Parse the narinfo text back into structured fields.
        let response = parse_narinfo_to_proto(&narinfo_text)?;

        Response::ok(response)
    }

    /// `QueryMissing` — reports which of the given store paths the server
    /// lacks.
    ///
    /// Requires a JWT authorized for the view. Paths are matched by store
    /// hash as well as exact path, so client and server store roots may
    /// differ.
    async fn query_missing<'a>(
        &'a self,
        ctx: RequestContext,
        req: ServiceRequest<'_, QueryMissingRequest>,
    ) -> ServiceResult<impl Encodable<QueryMissingResponse> + Send + use<'a>> {
        let view: &str = req.view;

        if self.state.views.get_view(view).is_none() {
            return Err(ConnectError::new(ErrorCode::NotFound, "unknown view"));
        }
        services::require_rpc_view(&ctx, &self.state, view)?;

        let store_paths: Vec<String> = req.store_paths.iter().map(|s| s.to_string()).collect();
        let mut missing = Vec::new();

        for path in &store_paths {
            match self.state.store.is_valid_path_or_hash(path) {
                Ok(true) => {}
                Ok(false) => missing.push(path.clone()),
                Err(e) => {
                    return Err(ConnectError::new(
                        ErrorCode::Internal,
                        format!("store query: {e}"),
                    ));
                }
            }
        }

        Response::ok(QueryMissingResponse {
            missing,
            ..Default::default()
        })
    }

    /// `Upload` — client-streamed NAR upload of a single store path.
    ///
    /// Authentication precedes stream consumption. The first chunk fixes the
    /// authorized view and store identity; contiguous chunks are written to a
    /// bounded private spool and streamed into `nix-store --import`. The
    /// imported path must pass the `.drv`-or-CA check and receives a temporary
    /// GC root.
    async fn upload<'a>(
        &'a self,
        ctx: RequestContext,
        requests: InboundStream<UploadChunk>,
    ) -> ServiceResult<impl Encodable<UploadResponse> + Send + use<'a>> {
        services::require_rpc_claims(&ctx, &self.state)?;
        let _permit = Arc::clone(&self.upload_admission)
            .try_acquire_owned()
            .map_err(|_| {
                ConnectError::new(ErrorCode::ResourceExhausted, "upload capacity reached")
            })?;
        let deadline = tokio::time::Instant::from_std(self.upload_deadline(&ctx));

        tokio::time::timeout_at(deadline, receive_nar_upload(self, &ctx, requests))
            .await
            .map_err(|_| {
                ConnectError::new(ErrorCode::DeadlineExceeded, "upload deadline exceeded")
            })?
            .and_then(Response::ok)
    }

    /// `Download` — server-streamed NAR download.
    ///
    /// Same read-access rules as `GetCacheInfo`. The filename's extension
    /// selects the compression (`.nar`, `.nar.zst`, `.nar.xz`) and its
    /// leading hash must be visible in the view. Chunks carry a running
    /// byte offset; `total_size` is `0` because the compressed length is
    /// unknown while streaming.
    async fn download(
        &self,
        ctx: RequestContext,
        req: ServiceRequest<'_, DownloadRequest>,
    ) -> ServiceResult<ResponseStream<impl Encodable<DownloadChunk> + Send + use<>>> {
        let view: &str = req.view;
        let filename: &str = req.filename;

        let view_config = self
            .state
            .views
            .get_view(view)
            .ok_or_else(|| ConnectError::new(ErrorCode::NotFound, "unknown view"))?;
        services::require_rpc_read_access(&ctx, &self.state, view, view_config.anonymous_read)?;

        let zstd_level = self.state.config.compression.level;
        let (name, compression) = if let Some(name) = filename.strip_suffix(".nar.zst") {
            (name, Compression::Zstd { level: zstd_level })
        } else if let Some(name) = filename.strip_suffix(".nar.xz") {
            (name, Compression::Xz { level: zstd_level })
        } else if let Some(name) = filename.strip_suffix(".nar") {
            (name, Compression::None)
        } else {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "expected .nar, .nar.zst, or .nar.xz suffix",
            ));
        };

        let store_hash = parse_nar_filename(name)?;

        let store_path = self
            .state
            .views
            .check_visibility(view, &store_hash)
            .map_err(|e| ConnectError::new(ErrorCode::Internal, format!("visibility check: {e}")))?
            .ok_or_else(|| ConnectError::new(ErrorCode::NotFound, "path not in view"))?;

        let body = compress::nar_stream(&store_path, compression)
            .await
            .map_err(|e| ConnectError::new(ErrorCode::Internal, format!("streaming NAR: {e}")))?;

        // Convert the axum body stream into DownloadChunk messages.
        let offset = std::sync::atomic::AtomicI64::new(0);
        let offset = std::sync::Arc::new(offset);

        let chunk_stream = body.into_data_stream().map(move |result| match result {
            Ok(bytes) => {
                let current_offset =
                    offset.fetch_add(bytes.len() as i64, std::sync::atomic::Ordering::Relaxed);
                Ok(DownloadChunk {
                    data: bytes.to_vec(),
                    offset: current_offset,
                    total_size: 0, // unknown for streamed compression
                    ..Default::default()
                })
            }
            Err(e) => Err(ConnectError::new(
                ErrorCode::Internal,
                format!("NAR stream error: {e}"),
            )),
        });

        Response::ok(Box::pin(chunk_stream))
    }

    /// `UploadPack` — client-streamed batched upload in the AOSP pack
    /// format.
    ///
    /// Authentication precedes stream consumption. The first chunk fixes the
    /// authorized view; bounded chunks are spooled privately, checksum-verified,
    /// and parsed ([`pack::parse_pack`]) before import. Every imported path
    /// receives a temporary GC root.
    async fn upload_pack<'a>(
        &'a self,
        ctx: RequestContext,
        requests: InboundStream<PackChunk>,
    ) -> ServiceResult<impl Encodable<UploadPackResponse> + Send + use<'a>> {
        services::require_rpc_claims(&ctx, &self.state)?;
        let _permit = Arc::clone(&self.upload_admission)
            .try_acquire_owned()
            .map_err(|_| {
                ConnectError::new(ErrorCode::ResourceExhausted, "upload capacity reached")
            })?;
        let deadline = tokio::time::Instant::from_std(self.upload_deadline(&ctx));

        tokio::time::timeout_at(deadline, receive_pack_upload(self, &ctx, requests))
            .await
            .map_err(|_| {
                ConnectError::new(ErrorCode::DeadlineExceeded, "upload deadline exceeded")
            })?
            .and_then(Response::ok)
    }
}

fn authorize_upload_view(
    service: &CacheServiceImpl,
    context: &RequestContext,
    view: &str,
) -> Result<(), ConnectError> {
    let view_config = service
        .state
        .views
        .get_view(view)
        .ok_or_else(|| ConnectError::new(ErrorCode::NotFound, "unknown view"))?;
    services::require_rpc_permission(context, &service.state, view, "build")?;

    if let Some(maximum) = view_config.max_paths {
        let count = service.state.views.count_roots(view).map_err(|error| {
            ConnectError::new(ErrorCode::Internal, format!("counting view roots: {error}"))
        })?;
        if count >= maximum {
            return Err(ConnectError::new(
                ErrorCode::ResourceExhausted,
                format!("view has {count} rooted paths, max is {maximum}"),
            ));
        }
    }

    Ok(())
}

async fn receive_nar_upload(
    service: &CacheServiceImpl,
    context: &RequestContext,
    mut requests: InboundStream<UploadChunk>,
) -> Result<UploadResponse, ConnectError> {
    let first = requests
        .next()
        .await
        .transpose()?
        .ok_or_else(|| ConnectError::new(ErrorCode::InvalidArgument, "no chunks received"))?;
    let first_view = first.view();
    let view = first_view.view.to_string();
    let store_hash = first_view.store_hash.to_string();
    if view.is_empty() || store_hash.is_empty() {
        return Err(ConnectError::new(
            ErrorCode::InvalidArgument,
            "first chunk must identify a view and store hash",
        ));
    }
    authorize_upload_view(service, context, &view)?;

    let limits = &service.state.config.uploads;
    let mut spool = UploadSpool::create(service.state.views.root()).await?;
    let mut expected_offset = 0u64;
    let mut final_seen = false;
    let mut next = Some(first);

    loop {
        let Some(message) = next.take() else {
            break;
        };
        let chunk = message.view();
        if chunk.view != view || chunk.store_hash != store_hash {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "upload identity changed between chunks",
            ));
        }
        if final_seen {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "upload continued after final chunk",
            ));
        }
        if chunk.offset < 0 || chunk.offset as u64 != expected_offset {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "upload chunk offset is not contiguous",
            ));
        }
        if chunk.data.len() as u64 > limits.max_chunk_bytes {
            return Err(ConnectError::new(
                ErrorCode::ResourceExhausted,
                format!("upload chunk exceeds {} byte limit", limits.max_chunk_bytes),
            ));
        }

        spool.append(chunk.data, limits.max_bytes).await?;
        expected_offset = spool.length;
        final_seen = chunk.is_final;
        next = requests.next().await.transpose()?;
    }

    if !final_seen {
        return Err(ConnectError::new(
            ErrorCode::InvalidArgument,
            "upload ended without a final chunk",
        ));
    }

    spool
        .file
        .flush()
        .await
        .map_err(internal_upload_error("flushing RPC upload spool"))?;
    let imported = import_nar_file(&spool.path).await.map_err(|error| {
        ConnectError::new(ErrorCode::Internal, format!("import failed: {error}"))
    })?;
    if let Ok(hash) = StoreHash::from_store_path(&imported) {
        let _ = service.state.views.create_tmp_root(&view, &hash, &imported);
    }

    Ok(UploadResponse {
        store_path: imported,
        ..Default::default()
    })
}

async fn receive_pack_upload(
    service: &CacheServiceImpl,
    context: &RequestContext,
    mut requests: InboundStream<PackChunk>,
) -> Result<UploadPackResponse, ConnectError> {
    let first = requests
        .next()
        .await
        .transpose()?
        .ok_or_else(|| ConnectError::new(ErrorCode::InvalidArgument, "no chunks received"))?;
    let view = first.view().view.to_string();
    if view.is_empty() {
        return Err(ConnectError::new(
            ErrorCode::InvalidArgument,
            "first chunk must identify a view",
        ));
    }
    authorize_upload_view(service, context, &view)?;

    let limits = &service.state.config.uploads;
    let mut spool = UploadSpool::create(service.state.views.root()).await?;
    let mut final_seen = false;
    let mut next = Some(first);
    loop {
        let Some(message) = next.take() else { break };
        let chunk = message.view();
        if chunk.view != view {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "upload view changed between chunks",
            ));
        }
        if final_seen {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "upload continued after final chunk",
            ));
        }
        if chunk.data.len() as u64 > limits.max_chunk_bytes {
            return Err(ConnectError::new(
                ErrorCode::ResourceExhausted,
                format!("upload chunk exceeds {} byte limit", limits.max_chunk_bytes),
            ));
        }
        spool.append(chunk.data, limits.max_bytes).await?;
        final_seen = chunk.is_final;
        next = requests.next().await.transpose()?;
    }
    if !final_seen {
        return Err(ConnectError::new(
            ErrorCode::InvalidArgument,
            "upload ended without a final chunk",
        ));
    }

    let data = spool.read_bounded().await?;
    let entries = pack::parse_pack(&data, limits.max_pack_entries).map_err(|error| {
        ConnectError::new(ErrorCode::InvalidArgument, format!("invalid pack: {error}"))
    })?;
    let count = entries.len();
    let paths = pack::import_pack(&entries).await.map_err(|error| {
        ConnectError::new(ErrorCode::Internal, format!("pack import failed: {error}"))
    })?;
    for path in &paths {
        if let Ok(hash) = StoreHash::from_store_path(path) {
            let _ = service.state.views.create_tmp_root(&view, &hash, path);
        }
    }

    Ok(UploadPackResponse {
        accepted: count as i32,
        rejected: 0,
        paths,
        ..Default::default()
    })
}

fn parse_nar_filename(name: &str) -> Result<StoreHash, ConnectError> {
    if name.is_empty()
        || !name.is_ascii()
        || !name
            .bytes()
            .all(|character| character.is_ascii_alphanumeric() || character == b'-')
    {
        return Err(ConnectError::new(
            ErrorCode::InvalidArgument,
            "invalid NAR filename",
        ));
    }

    let hash = name.split_once('-').map_or(name, |(hash, _suffix)| hash);
    hash.parse().map_err(|error| {
        ConnectError::new(
            ErrorCode::InvalidArgument,
            format!("invalid NAR filename: {error}"),
        )
    })
}

/// Parses rendered narinfo text into a proto `NarInfo` message.
fn parse_narinfo_to_proto(narinfo_text: &str) -> Result<NarInfo, ConnectError> {
    let parsed = core_narinfo::parse(narinfo_text)
        .map_err(|e| ConnectError::new(ErrorCode::Internal, format!("narinfo parse: {e}")))?;

    Ok(NarInfo {
        store_path: parsed.store_path,
        url: parsed.url,
        compression: parsed.compression,
        file_hash: parsed.file_hash.unwrap_or_default(),
        file_size: parsed.file_size.unwrap_or_default() as i64,
        nar_hash: parsed.nar_hash,
        nar_size: parsed.nar_size as i64,
        references: parsed.references,
        deriver: parsed.deriver.unwrap_or_default(),
        signatures: parsed.signatures,
        ..Default::default()
    })
}

/// Imports a spooled NAR via `nix-store --import` and returns the imported
/// store path, after vetting it with [`pack::validate_imported_path`].
async fn import_nar_file(path: &Path) -> Result<String, String> {
    use std::process::Stdio;
    use tokio::process::Command;

    let mut child = Command::new("nix-store")
        .envs(aos_nix_env())
        .arg("--import")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawning nix-store --import: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|e| format!("opening spooled NAR: {e}"))?;
        tokio::io::copy(&mut file, &mut stdin)
            .await
            .map_err(|e| format!("writing NAR: {e}"))?;
        drop(stdin);
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("waiting for nix-store: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nix-store --import failed: {stderr}"));
    }

    let imported = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if let Err(reason) = pack::validate_imported_path(&imported).await {
        return Err(reason);
    }

    Ok(imported)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::http::{HeaderMap, HeaderValue, header};
    use connectrpc::{RequestContext, StreamMessage};
    use futures_util::stream;

    use super::*;
    use crate::auth;
    use crate::build::BuildManager;
    use crate::config::ServerConfig;
    use crate::drain::DrainState;
    use crate::sign::NarInfoSigner;
    use crate::store::NixStore;
    use crate::tokens::TokenStore;

    fn test_service(maximum_bytes: u64) -> (tempfile::TempDir, CacheServiceImpl, RequestContext) {
        test_service_with(maximum_bytes, |_| {})
    }

    fn test_service_with(
        maximum_bytes: u64,
        configure: impl FnOnce(&mut ServerConfig),
    ) -> (tempfile::TempDir, CacheServiceImpl, RequestContext) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().to_path_buf();
        let database = root.join("store.sqlite");
        drop(rusqlite::Connection::open(&database).unwrap());

        let mut config = ServerConfig::default();
        config.uploads.max_bytes = maximum_bytes;
        config.uploads.max_chunk_bytes = maximum_bytes;
        configure(&mut config);
        let tokens = TokenStore::open(&root.join("tokens.sqlite")).unwrap();
        let (_, record) = tokens
            .create_token(&["default".into()], &["build".into()], None, None, None)
            .unwrap();
        let access_token = auth::create_access_token(&[42; 32], &record, 3600).unwrap();
        let state = Arc::new(AppState {
            store: NixStore::open(&database).unwrap(),
            views: ViewManager::new(root.clone(), config.views.clone()).unwrap(),
            nar_materialization_admission: Arc::new(Semaphore::new(
                config.compression.max_concurrent_materializations,
            )),
            config,
            store_dir: root.join("store").display().to_string(),
            jwt_secret: vec![42; 32],
            tokens,
            build_mgr: Arc::new(BuildManager::new()),
            drain: Arc::new(DrainState::new()),
            signer: NarInfoSigner::load(None).unwrap(),
        });
        let service = CacheServiceImpl::new(state);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {access_token}")).unwrap(),
        );
        (directory, service, RequestContext::new(headers))
    }

    #[tokio::test]
    async fn unauthenticated_upload_does_not_poll_the_payload_stream() {
        let (_directory, service, _) = test_service(8);
        let polls = Arc::new(AtomicUsize::new(0));
        let observed_polls = Arc::clone(&polls);
        let requests = stream::poll_fn(move |_| {
            observed_polls.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(None)
        });

        let error =
            match CacheService::upload(&service, RequestContext::default(), Box::pin(requests))
                .await
            {
                Ok(_) => panic!("unauthenticated upload was accepted"),
                Err(error) => error,
            };

        assert_eq!(error.code, ErrorCode::Unauthenticated);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn upload_stops_when_aggregate_limit_is_crossed() {
        let (_directory, service, context) = test_service(5);
        let messages = [
            UploadChunk {
                view: "default".into(),
                store_hash: "hash".into(),
                data: vec![1; 3],
                offset: 0,
                is_final: false,
                ..Default::default()
            },
            UploadChunk {
                view: "default".into(),
                store_hash: "hash".into(),
                data: vec![2; 3],
                offset: 3,
                is_final: true,
                ..Default::default()
            },
        ];
        let requests = stream::iter(
            messages
                .into_iter()
                .map(|message| Ok(StreamMessage::from_message(&message))),
        );

        let error = match CacheService::upload(&service, context, Box::pin(requests)).await {
            Ok(_) => panic!("oversized upload was accepted"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::ResourceExhausted);
        assert!(error.to_string().contains("5 byte limit"), "{error}");
        let spool_directory = service.state.views.root().join("uploads/rpc");
        assert_eq!(std::fs::read_dir(spool_directory).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn upload_stops_when_a_chunk_limit_is_crossed() {
        let (_directory, service, context) = test_service_with(8, |config| {
            config.uploads.max_chunk_bytes = 2;
        });
        let message = UploadChunk {
            view: "default".into(),
            store_hash: "hash".into(),
            data: vec![1; 3],
            offset: 0,
            is_final: true,
            ..Default::default()
        };
        let requests = stream::iter([Ok(StreamMessage::from_message(&message))]);

        let error = match CacheService::upload(&service, context, Box::pin(requests)).await {
            Ok(_) => panic!("upload with an oversized chunk was accepted"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::ResourceExhausted);
        assert!(error.to_string().contains("2 byte limit"), "{error}");
    }

    #[tokio::test]
    async fn upload_observes_the_view_path_quota_before_spooling() {
        let (_directory, service, context) = test_service_with(8, |config| {
            config.views[0].max_paths = Some(0);
        });
        let message = UploadChunk {
            view: "default".into(),
            store_hash: "hash".into(),
            data: vec![1],
            offset: 0,
            is_final: true,
            ..Default::default()
        };
        let requests = stream::iter([Ok(StreamMessage::from_message(&message))]);

        let error = match CacheService::upload(&service, context, Box::pin(requests)).await {
            Ok(_) => panic!("upload above the view path quota was accepted"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::ResourceExhausted);
        assert!(error.to_string().contains("max is 0"), "{error}");
        assert!(!service.state.views.root().join("uploads/rpc").exists());
    }

    #[tokio::test]
    async fn upload_rejects_a_view_change_before_import() {
        let (_directory, service, context) = test_service(16);
        let messages = [
            UploadChunk {
                view: "default".into(),
                store_hash: "hash".into(),
                data: vec![1],
                offset: 0,
                ..Default::default()
            },
            UploadChunk {
                view: "other".into(),
                store_hash: "hash".into(),
                data: vec![2],
                offset: 1,
                is_final: true,
                ..Default::default()
            },
        ];
        let requests = stream::iter(
            messages
                .into_iter()
                .map(|message| Ok(StreamMessage::from_message(&message))),
        );

        let error = match CacheService::upload(&service, context, Box::pin(requests)).await {
            Ok(_) => panic!("upload with a changed view was accepted"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.to_string().contains("identity changed"), "{error}");
    }

    #[tokio::test]
    async fn upload_capacity_is_checked_before_polling_the_stream() {
        let (_directory, service, context) = test_service(8);
        let permit_count = service.state.config.uploads.max_concurrent as u32;
        let _held = Arc::clone(&service.upload_admission)
            .acquire_many_owned(permit_count)
            .await
            .unwrap();
        let polls = Arc::new(AtomicUsize::new(0));
        let observed_polls = Arc::clone(&polls);
        let requests = stream::poll_fn(move |_| {
            observed_polls.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(None)
        });

        let error = match CacheService::upload(&service, context, Box::pin(requests)).await {
            Ok(_) => panic!("upload above concurrent capacity was accepted"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::ResourceExhausted);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn upload_honors_the_request_deadline() {
        let (_directory, service, context) = test_service(8);
        let context = context.with_deadline(Some(
            Instant::now()
                .checked_add(Duration::from_millis(10))
                .unwrap(),
        ));
        let requests = stream::pending();

        let error = match CacheService::upload(&service, context, Box::pin(requests)).await {
            Ok(_) => panic!("upload outlived its request deadline"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::DeadlineExceeded);
    }

    #[tokio::test]
    async fn unauthenticated_pack_upload_does_not_poll_the_payload_stream() {
        let (_directory, service, _) = test_service(8);
        let polls = Arc::new(AtomicUsize::new(0));
        let observed_polls = Arc::clone(&polls);
        let requests = stream::poll_fn(move |_| {
            observed_polls.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(None)
        });

        let error = match CacheService::upload_pack(
            &service,
            RequestContext::default(),
            Box::pin(requests),
        )
        .await
        {
            Ok(_) => panic!("unauthenticated pack upload was accepted"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::Unauthenticated);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pack_upload_stops_when_aggregate_limit_is_crossed() {
        let (_directory, service, context) = test_service(5);
        let messages = [
            PackChunk {
                view: "default".into(),
                data: vec![1; 3],
                ..Default::default()
            },
            PackChunk {
                view: "default".into(),
                data: vec![2; 3],
                is_final: true,
                ..Default::default()
            },
        ];
        let requests = stream::iter(
            messages
                .into_iter()
                .map(|message| Ok(StreamMessage::from_message(&message))),
        );

        let error = match CacheService::upload_pack(&service, context, Box::pin(requests)).await {
            Ok(_) => panic!("oversized pack upload was accepted"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::ResourceExhausted);
        assert!(error.to_string().contains("5 byte limit"), "{error}");
        let spool_directory = service.state.views.root().join("uploads/rpc");
        assert_eq!(std::fs::read_dir(spool_directory).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn pack_upload_rejects_a_view_change_before_import() {
        let (_directory, service, context) = test_service(8);
        let messages = [
            PackChunk {
                view: "default".into(),
                data: vec![1],
                ..Default::default()
            },
            PackChunk {
                view: "other".into(),
                data: vec![2],
                is_final: true,
                ..Default::default()
            },
        ];
        let requests = stream::iter(
            messages
                .into_iter()
                .map(|message| Ok(StreamMessage::from_message(&message))),
        );

        let error = match CacheService::upload_pack(&service, context, Box::pin(requests)).await {
            Ok(_) => panic!("pack upload with a changed view was accepted"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.to_string().contains("view changed"), "{error}");
    }

    #[test]
    fn rpc_nar_filenames_require_a_canonical_store_hash() {
        let valid_hash = "0123456789abcdfghijklmnpqrsvwxyz";
        assert_eq!(
            parse_nar_filename(&format!("{valid_hash}-sha256-deadbeef"))
                .unwrap()
                .as_str(),
            valid_hash
        );

        for filename in [
            "../00000000000000000000000000000000",
            "/00000000000000000000000000000000",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-sha256-deadbeef",
        ] {
            assert!(
                parse_nar_filename(filename).is_err(),
                "accepted {filename:?}"
            );
        }
    }

    #[test]
    fn narinfo_proto_preserves_download_metadata() {
        let narinfo = "\
StorePath: /nix/store/abc123-tool-1.0
URL: nar/abc123-sha256-deadbeef.nar.zst
Compression: zstd
FileHash: sha256:feedface
FileSize: 42
NarHash: sha256:deadbeef
NarSize: 24
References: dep456-lib-1.0
Deriver: drv789-tool.drv
Sig: cache.example:signature
";

        let parsed = parse_narinfo_to_proto(narinfo).unwrap();

        assert_eq!(parsed.store_path, "/nix/store/abc123-tool-1.0");
        assert_eq!(parsed.url, "nar/abc123-sha256-deadbeef.nar.zst");
        assert_eq!(parsed.compression, "zstd");
        assert_eq!(parsed.file_hash, "sha256:feedface");
        assert_eq!(parsed.file_size, 42);
        assert_eq!(parsed.nar_hash, "sha256:deadbeef");
        assert_eq!(parsed.nar_size, 24);
        assert_eq!(parsed.references, vec!["dep456-lib-1.0"]);
        assert_eq!(parsed.deriver, "drv789-tool.drv");
        assert_eq!(parsed.signatures, vec!["cache.example:signature"]);
    }
}
