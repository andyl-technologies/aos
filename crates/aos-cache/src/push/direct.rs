//! Descriptor-backed parallel NAR and narinfo staging with one final barrier.
//!
//! Compression output lives in anonymous bounded disk files. Narinfos remain
//! exact provider objects; Native receives authenticated parsed projections
//! from storage workers, rather than raw narinfo batches from this client.

use std::io::Write as _;
use std::time::Duration;

use anyhow::{Context as _, Result};
use aos_core::nar::info as narinfo;
use aos_core::nix::PathInfo;
use aos_core::output::Printer;
use aos_net::direct_upload::AdmittedSource;
use aos_proto_types::direct_upload::{
    DirectCapabilitiesTarget, DirectDependencyPhase, DirectUploadTarget,
};
use aos_remote::{DirectStageFile, DirectUploadCoordinator};
use futures::stream::{StreamExt as _, TryStreamExt as _};
use sha2::{Digest as _, Sha256};

use super::build_narinfo;
use crate::compress::{compression_ext, streaming_compress_to_file};

pub(super) async fn push(
    printer: &Printer,
    coordinator: &DirectUploadCoordinator,
    infos: &[PathInfo],
    missing: &[String],
    jobs: usize,
    compression: &str,
    level: i32,
) -> Result<()> {
    let DirectCapabilitiesTarget::Cache { cache_id } = coordinator.target() else {
        anyhow::bail!("direct cache discovery returned a different owner");
    };
    let missing: std::collections::BTreeSet<_> = missing.iter().map(String::as_str).collect();
    let pending: Vec<_> = infos
        .iter()
        .filter(|info| missing.contains(narinfo::store_hash(&info.path)))
        .collect();
    let progress = printer.items("Staging direct cache paths", pending.len() as u64);
    let parallel = jobs.clamp(1, 8);
    for wave in pending.chunks(parallel) {
        let prepared: Vec<_> = futures::stream::iter(wave.iter().copied())
            .map(|info| async move {
                let spool = streaming_compress_to_file(
                    &info.path,
                    compression,
                    level,
                    16 * 1024 * 1024 * 1024,
                )
                .await?;
                let (file, size, sha) = spool.into_parts();
                let file_hash = format!("sha256:{sha}");
                let name = format!("sha256-{sha}.{}", compression_ext(compression));
                let narinfo = build_narinfo(info, &file_hash, size, &name, compression);
                let source =
                    AdmittedSource::admit(file, size, &sha, coordinator.part_size()).await?;
                let metadata = metadata_source(narinfo.as_bytes(), coordinator.part_size()).await?;
                Ok::<_, anyhow::Error>([
                    DirectStageFile {
                        target: DirectUploadTarget::CacheObject {
                            cache_id: cache_id.clone(),
                            path: format!("nar/{name}"),
                        },
                        source,
                        phase: DirectDependencyPhase::Content,
                    },
                    DirectStageFile {
                        target: DirectUploadTarget::CacheObject {
                            cache_id: cache_id.clone(),
                            path: format!("{}.narinfo", narinfo::store_hash(&info.path)),
                        },
                        source: metadata,
                        phase: DirectDependencyPhase::Visibility,
                    },
                ])
            })
            .buffer_unordered(parallel)
            .try_collect()
            .await?;
        let count = prepared.len();
        coordinator
            .stage(prepared.into_iter().flatten().collect())
            .await?;
        progress.inc(count as u64);
    }
    let cache_info = b"StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 30\n";
    coordinator
        .stage(vec![DirectStageFile {
            target: DirectUploadTarget::CacheObject {
                cache_id: cache_id.clone(),
                path: "nix-cache-info".into(),
            },
            source: metadata_source(cache_info, coordinator.part_size()).await?,
            phase: DirectDependencyPhase::Visibility,
        }])
        .await?;
    coordinator.finish(Duration::from_secs(3600)).await?;
    printer.info(&format!(
        "Direct upload client: {}",
        coordinator.diagnostic_summary()
    ));
    progress.finish();
    printer.success("Direct cache upload committed.");
    Ok(())
}

async fn metadata_source(bytes: &[u8], part_size: u64) -> Result<AdmittedSource> {
    anyhow::ensure!(
        bytes.len() <= 1024 * 1024,
        "direct cache metadata exceeds its bound"
    );
    let mut file = tempfile::tempfile().context("creating direct cache metadata snapshot")?;
    file.write_all(bytes)?;
    Ok(AdmittedSource::admit(
        file,
        bytes.len() as u64,
        &hex::encode(Sha256::digest(bytes)),
        part_size,
    )
    .await?)
}
