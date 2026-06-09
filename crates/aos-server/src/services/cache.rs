//! ConnectRPC implementation of `CacheService`.

use std::pin::Pin;
use std::sync::Arc;

use connectrpc::{ConnectError, Context, ErrorCode};
use futures_util::{Stream, StreamExt};

use aos_proto::aos::cache::v1::*;

use crate::access;
use crate::compress::{self, Compression};
use crate::narinfo;
use crate::pack;
use crate::routes::AppState;
use crate::views::ViewManager;

type ResponseStream<T> = Pin<Box<dyn Stream<Item = Result<T, ConnectError>> + Send>>;
type RequestStream<V> =
    Pin<Box<dyn Stream<Item = Result<buffa::view::OwnedView<V>, ConnectError>> + Send>>;

/// ConnectRPC cache service backed by the shared `AppState`.
pub struct CacheServiceImpl {
    pub state: Arc<AppState>,
}

impl CacheService for CacheServiceImpl {
    async fn get_cache_info(
        &self,
        ctx: Context,
        req: buffa::view::OwnedView<GetCacheInfoRequestView<'static>>,
    ) -> Result<(CacheInfo, Context), ConnectError> {
        let view: &str = req.view;

        let _view_config = self
            .state
            .views
            .get_view(view)
            .ok_or_else(|| ConnectError::new(ErrorCode::NotFound, "unknown view"))?;

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

        Ok((response, ctx))
    }

    async fn get_nar_info(
        &self,
        ctx: Context,
        req: buffa::view::OwnedView<GetNarInfoRequestView<'static>>,
    ) -> Result<(NarInfo, Context), ConnectError> {
        let view: &str = req.view;
        let store_hash: &str = req.store_hash;

        if self.state.views.get_view(view).is_none() {
            return Err(ConnectError::new(ErrorCode::NotFound, "unknown view"));
        }

        let store_path = self
            .state
            .views
            .check_visibility(view, store_hash)
            .map_err(|e| ConnectError::new(ErrorCode::Internal, format!("visibility check: {e}")))?
            .ok_or_else(|| ConnectError::new(ErrorCode::NotFound, "path not in view"))?;

        let info = self
            .state
            .store
            .path_info(&store_path)
            .map_err(|e| ConnectError::new(ErrorCode::Internal, format!("store query: {e}")))?
            .ok_or_else(|| ConnectError::new(ErrorCode::NotFound, "path not in store"))?;

        // Update access metadata (best-effort).
        let _ = access::update_access(&self.state.views, view, store_hash);

        let narinfo_text = narinfo::format_narinfo(
            &info,
            &self.state.store_dir,
            &self.state.config.compression,
            Some(&self.state.signer),
        );

        // Parse the narinfo text back into structured fields.
        let response = parse_narinfo_to_proto(&narinfo_text, &info);

        Ok((response, ctx))
    }

    async fn query_missing(
        &self,
        ctx: Context,
        req: buffa::view::OwnedView<QueryMissingRequestView<'static>>,
    ) -> Result<(QueryMissingResponse, Context), ConnectError> {
        let view: &str = req.view;

        if self.state.views.get_view(view).is_none() {
            return Err(ConnectError::new(ErrorCode::NotFound, "unknown view"));
        }

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

        Ok((
            QueryMissingResponse {
                missing,
                ..Default::default()
            },
            ctx,
        ))
    }

    async fn upload(
        &self,
        ctx: Context,
        mut requests: RequestStream<UploadChunkView<'static>>,
    ) -> Result<(UploadResponse, Context), ConnectError> {
        let mut all_data = Vec::new();
        let mut view_name = String::new();

        while let Some(chunk_result) = requests.next().await {
            let chunk = chunk_result?;
            if view_name.is_empty() {
                view_name = chunk.view.to_string();
            }
            let data: &[u8] = chunk.data;
            all_data.extend_from_slice(data);
        }

        if view_name.is_empty() {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "no chunks received",
            ));
        }

        if self.state.views.get_view(&view_name).is_none() {
            return Err(ConnectError::new(ErrorCode::NotFound, "unknown view"));
        }

        // Import via nix-store --import.
        let imported = import_nar_data(&all_data)
            .await
            .map_err(|e| ConnectError::new(ErrorCode::Internal, format!("import failed: {e}")))?;

        // Create a temporary GC root.
        if let Some(hash) = ViewManager::store_path_hash(&imported) {
            let _ = self
                .state
                .views
                .create_tmp_root(&view_name, hash, &imported);
        }

        Ok((
            UploadResponse {
                store_path: imported,
                ..Default::default()
            },
            ctx,
        ))
    }

    async fn download(
        &self,
        ctx: Context,
        req: buffa::view::OwnedView<DownloadRequestView<'static>>,
    ) -> Result<(ResponseStream<DownloadChunk>, Context), ConnectError> {
        let view: &str = req.view;
        let filename: &str = req.filename;

        if self.state.views.get_view(view).is_none() {
            return Err(ConnectError::new(ErrorCode::NotFound, "unknown view"));
        }

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

        let store_hash = match name.split('-').next() {
            Some(h) if !h.is_empty() => h,
            _ => {
                return Err(ConnectError::new(
                    ErrorCode::InvalidArgument,
                    "invalid NAR filename",
                ));
            }
        };

        let store_path = self
            .state
            .views
            .check_visibility(view, store_hash)
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

        Ok((Box::pin(chunk_stream), ctx))
    }

    async fn upload_pack(
        &self,
        ctx: Context,
        mut requests: RequestStream<PackChunkView<'static>>,
    ) -> Result<(UploadPackResponse, Context), ConnectError> {
        let mut all_data = Vec::new();
        let mut view_name = String::new();

        while let Some(chunk_result) = requests.next().await {
            let chunk = chunk_result?;
            if view_name.is_empty() {
                view_name = chunk.view.to_string();
            }
            let data: &[u8] = chunk.data;
            all_data.extend_from_slice(data);
        }

        if view_name.is_empty() {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "no chunks received",
            ));
        }

        if self.state.views.get_view(&view_name).is_none() {
            return Err(ConnectError::new(ErrorCode::NotFound, "unknown view"));
        }

        let entries = pack::parse_pack(&all_data).map_err(|e| {
            ConnectError::new(ErrorCode::InvalidArgument, format!("invalid pack: {e}"))
        })?;

        let count = entries.len();

        let paths = pack::import_pack(&entries).await.map_err(|e| {
            ConnectError::new(ErrorCode::Internal, format!("pack import failed: {e}"))
        })?;

        // Create temporary GC roots for all imported paths.
        for path in &paths {
            if let Some(hash) = ViewManager::store_path_hash(path) {
                let _ = self.state.views.create_tmp_root(&view_name, hash, path);
            }
        }

        Ok((
            UploadPackResponse {
                accepted: count as i32,
                rejected: 0,
                paths,
                ..Default::default()
            },
            ctx,
        ))
    }
}

/// Parse structured narinfo text + DB info into proto NarInfo message.
fn parse_narinfo_to_proto(_narinfo_text: &str, info: &crate::store::DbPathInfo) -> NarInfo {
    NarInfo {
        store_path: info.path.clone(),
        nar_hash: info.nar_hash.clone(),
        nar_size: info.nar_size,
        compression: String::new(), // filled by caller if needed
        references: info.refs.clone(),
        deriver: info.deriver.clone().unwrap_or_default(),
        signatures: info.sigs.clone(),
        ..Default::default()
    }
}

/// Import NAR data via `nix-store --import`, return the imported store path.
async fn import_nar_data(data: &[u8]) -> Result<String, String> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;

    let mut child = Command::new("nix-store")
        .arg("--import")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawning nix-store --import: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(data)
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

    if let Err(reason) = pack::validate_imported_path(&imported) {
        return Err(reason);
    }

    Ok(imported)
}
