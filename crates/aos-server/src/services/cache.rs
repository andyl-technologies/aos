//! ConnectRPC implementation of `CacheService`.
//!
//! RPC twins of the REST cache endpoints in [`crate::routes`]:
//! `GetCacheInfo`, `GetNarInfo`, and `QueryMissing` are unary;
//! `Upload`/`UploadPack` are client-streaming (chunks are buffered, then
//! imported via `nix-store --import` with the same `.drv`-or-CA safety
//! check as REST uploads); `Download` is server-streaming, chunking the
//! same compressed NAR pipeline used by `GET /{view}/nar/{filename}`.

use std::pin::Pin;
use std::sync::Arc;

use connectrpc::{ConnectError, Context, ErrorCode};
use futures_util::{Stream, StreamExt};

use aos_core::nar::info as core_narinfo;
use aos_core::nix::aos_nix_env;
use aos_proto::aos::cache::v1::*;

use crate::access;
use crate::compress::{self, Compression};
use crate::narinfo;
use crate::pack;
use crate::routes::AppState;
use crate::services;
use crate::views::ViewManager;

/// Boxed server-streaming response used by the generated service traits.
type ResponseStream<T> = Pin<Box<dyn Stream<Item = Result<T, ConnectError>> + Send>>;
/// Boxed client-streaming request used by the generated service traits.
type RequestStream<V> =
    Pin<Box<dyn Stream<Item = Result<buffa::view::OwnedView<V>, ConnectError>> + Send>>;

/// ConnectRPC cache service backed by the shared [`AppState`].
pub struct CacheServiceImpl {
    /// Shared server state (store, views, signer, config).
    pub state: Arc<AppState>,
}

impl CacheService for CacheServiceImpl {
    /// `GetCacheInfo` — cache metadata and capability list for a view.
    ///
    /// Allowed anonymously when the view has `anonymous_read = true`,
    /// otherwise requires a JWT with the `read` permission on the view.
    async fn get_cache_info(
        &self,
        ctx: Context,
        req: buffa::view::OwnedView<GetCacheInfoRequestView<'static>>,
    ) -> Result<(CacheInfo, Context), ConnectError> {
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

        Ok((response, ctx))
    }

    /// `GetNarInfo` — structured narinfo for a store hash.
    ///
    /// Same read-access rules as `GetCacheInfo`. The hash must be visible
    /// in the view (`not_found` otherwise). Serving the info bumps the
    /// path's access metadata for eviction scoring. Internally the narinfo
    /// text is rendered (and signed) exactly as for REST, then parsed back
    /// into the proto message.
    async fn get_nar_info(
        &self,
        ctx: Context,
        req: buffa::view::OwnedView<GetNarInfoRequestView<'static>>,
    ) -> Result<(NarInfo, Context), ConnectError> {
        let view: &str = req.view;
        let store_hash: &str = req.store_hash;

        let view_config = self
            .state
            .views
            .get_view(view)
            .ok_or_else(|| ConnectError::new(ErrorCode::NotFound, "unknown view"))?;
        services::require_rpc_read_access(&ctx, &self.state, view, view_config.anonymous_read)?;

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
        )
        .map_err(|e| ConnectError::new(ErrorCode::Internal, format!("narinfo rendering: {e}")))?;

        // Parse the narinfo text back into structured fields.
        let response = parse_narinfo_to_proto(&narinfo_text)?;

        Ok((response, ctx))
    }

    /// `QueryMissing` — reports which of the given store paths the server
    /// lacks.
    ///
    /// Requires a JWT authorized for the view. Paths are matched by store
    /// hash as well as exact path, so client and server store roots may
    /// differ.
    async fn query_missing(
        &self,
        ctx: Context,
        req: buffa::view::OwnedView<QueryMissingRequestView<'static>>,
    ) -> Result<(QueryMissingResponse, Context), ConnectError> {
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

        Ok((
            QueryMissingResponse {
                missing,
                ..Default::default()
            },
            ctx,
        ))
    }

    /// `Upload` — client-streamed NAR upload of a single store path.
    ///
    /// The view name is taken from the first chunk; all chunk data is
    /// buffered, then imported via `nix-store --import`. Requires a JWT
    /// with the `build` permission on the view (checked after the stream
    /// is consumed). The imported path must pass the `.drv`-or-CA safety
    /// check and receives a temporary GC root.
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
        services::require_rpc_permission(&ctx, &self.state, &view_name, "build")?;

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

    /// `Download` — server-streamed NAR download.
    ///
    /// Same read-access rules as `GetCacheInfo`. The filename's extension
    /// selects the compression (`.nar`, `.nar.zst`, `.nar.xz`) and its
    /// leading hash must be visible in the view. Chunks carry a running
    /// byte offset; `total_size` is `0` because the compressed length is
    /// unknown while streaming.
    async fn download(
        &self,
        ctx: Context,
        req: buffa::view::OwnedView<DownloadRequestView<'static>>,
    ) -> Result<(ResponseStream<DownloadChunk>, Context), ConnectError> {
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

    /// `UploadPack` — client-streamed batched upload in the AOSP pack
    /// format.
    ///
    /// Chunks are buffered into the full pack, which is checksum-verified
    /// and parsed ([`pack::parse_pack`]) before its entries are imported.
    /// Requires a JWT with the `build` permission on the view (from the
    /// first chunk). Every imported path gets a temporary GC root.
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
        services::require_rpc_permission(&ctx, &self.state, &view_name, "build")?;

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

/// Imports NAR data via `nix-store --import` and returns the imported
/// store path, after vetting it with [`pack::validate_imported_path`].
async fn import_nar_data(data: &[u8]) -> Result<String, String> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;

    let mut child = Command::new("nix-store")
        .envs(aos_nix_env())
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

#[cfg(test)]
mod tests {
    use super::parse_narinfo_to_proto;

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
