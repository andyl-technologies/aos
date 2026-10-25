//! Checks configured index policy against genuine enrolled and recovered caches.
//!
//! The native supervisor supplies existing portable buckets and the original
//! publisher/quota services. Signed source fixtures remain outside the cache.

use super::{CompiledIndex, File, MetadataExt, Result, fs, require_empty_capabilities, tree};
use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};
use terrane_linux::{configured::NativeCachePlan, quota_confinement};
use terrane_sdk::config::Config;

#[path = "configured/recovery.rs"]
mod recovery;

#[path = "configured/cold.rs"]
mod cold;

#[path = "configured/paused_lower.rs"]
mod paused_lower;

#[path = "configured/mounted.rs"]
pub(super) mod mounted;

#[path = "configured/worker.rs"]
pub(super) mod worker;

/// Runs the fresh actor without adding its async frame to the other selectors.
///
/// # Errors
/// Rejects invalid arguments, role or confinement failures, unavailable genuine
/// recovery and any mismatch with the selected admission/refusal control.
pub(super) fn run() -> Result<()> {
    require_empty_capabilities()?;
    let mut arguments = std::env::args().skip(2);
    let path = PathBuf::from(arguments.next().ok_or("missing configured TOML path")?);
    let mode = arguments
        .next()
        .ok_or("missing configured surface control")?;
    if arguments.next().is_some()
        || !matches!(
            mode.as_str(),
            "disabled" | "bound" | "admit" | "recover-draining"
        )
    {
        return Err("invalid configured surface control".into());
    }

    let source_parent = path.parent().ok_or("configured TOML has no parent")?;
    let config = Config::parse(&fs::read_to_string(&path)?)?;
    let host = config.host_tier().ok_or("missing configured host tier")?;
    let plan = NativeCachePlan::from_host(host, Default::default())?;
    let confinement = Arc::new(quota_confinement::install()?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(Box::pin(verify(
        plan,
        host,
        confinement,
        &mode,
        source_parent,
    )))
}

async fn verify(
    plan: NativeCachePlan,
    host: &terrane_sdk::config::host::HostTier,
    confinement: Arc<quota_confinement::Installed>,
    mode: &str,
    source_parent: &Path,
) -> Result<()> {
    if mode == "recover-draining" {
        return Box::pin(recovery::verify(plan, host, confinement, source_parent)).await;
    }

    let mut caches = plan.open(confinement).await?;
    let cache = caches
        .get("public")
        .ok_or("missing genuine configured cache")?;
    let owner = cache.content().ready().owner();
    let root = PathBuf::from(&host.domains["public"].path);
    let records = root.join("state/cache/records.toml");
    let before = fs::read(&records)?;
    let (digest, nodes) = tree()?;

    if mode != "admit" {
        let error = owner
            .cache_surface_index(digest, nodes)
            .await
            .err()
            .ok_or("configured disabled or restrictive policy admitted an index")?;
        let expected = if mode == "disabled" {
            io::ErrorKind::Unsupported
        } else {
            io::ErrorKind::InvalidInput
        };
        if error.kind() != expected || fs::read(&records)? != before {
            return Err("configured policy refusal changed original cache state".into());
        }
        println!("PASS configured surface {mode} policy refuses before durable mutation");
        return Ok(());
    }

    let admitted = owner.cache_surface_index(digest, nodes.clone()).await?;
    admitted.check_native_backing()?;
    let hexadecimal: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let canonical = root
        .join("objects")
        .join(format!(".terrane-surface:2:{hexadecimal}"));
    let original = File::open(&canonical)?.metadata()?;
    let compiled = CompiledIndex::from_nodes(digest, &nodes, 262144, 16, 65536, 65536)?;
    compiled.verify_reader(&mut File::open(&canonical)?)?;
    if admitted.key().root() != digest
        || original.uid() != 840
        || original.gid() != 845
        || original.mode() & 0o7777 != 0o400
        || original.nlink() != 1
        || original.blocks() * 512 != admitted.synchronized_inode_bytes()
    {
        return Err("configured admission differs from original sealed native inode".into());
    }

    let funded = fs::read(&records)?;
    if funded == before {
        return Err("configured admission omitted durable funding".into());
    }
    let reused = owner.cache_surface_index(digest, nodes).await?;
    reused.check_native_backing()?;
    let after = File::open(&canonical)?.metadata()?;
    if (after.dev(), after.ino()) != (original.dev(), original.ino())
        || fs::read(&records)? != funded
    {
        return Err("configured warm reuse changed the original inode or policy".into());
    }
    println!(
        "PASS configured funded surface policy reaches actual recovered owner and warm reuse retains original sealed inode"
    );
    drop(reused);
    drop(admitted);
    let cache = caches
        .remove("public")
        .ok_or("missing original configured cache")?;
    Box::pin(cold::verify(cache, source_parent)).await?;
    Ok(())
}
