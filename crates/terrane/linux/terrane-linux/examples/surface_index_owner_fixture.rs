//! Exercises derived-index admission through the genuine native owner in a guest.
//!
//! Root provisions project quotas and independent service identities. This actor
//! runs as UID 840 without capabilities, installs confinement before threads,
//! and uses actual recovery and publisher Resume before any cache allocation.

#[path = "host_cache_fixture/config.rs"]
mod config;

#[path = "surface_index_owner_fixture/exposure.rs"]
mod exposure;

#[path = "surface_index_owner_fixture/eviction.rs"]
mod eviction;

#[path = "host_cache_fixture/repository_fixture.rs"]
mod repository_fixture;

#[path = "surface_index_owner_fixture/scoped.rs"]
mod scoped;

#[path = "surface_index_owner_fixture/scoped_worker.rs"]
mod scoped_worker;

#[path = "surface_index_owner_fixture/worker_crash.rs"]
mod worker_crash;

#[path = "surface_index_owner_fixture/pressure.rs"]
mod pressure;

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    future::Future,
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    task::{Context, Poll, Waker},
};
use terrane_format::{
    identity::Digest,
    tree_builder::Tree,
    tree_format::{ContentRef, Entry, EntryKind, LeafItem, TreeUse},
};
use terrane_linux::{
    host_cache::{NativeCachePreparation, NativeMetadataOwner, SurfaceIndexPolicy},
    host_quota::{HostQuotaClient, NativeProject},
    quota_confinement,
    structural_index::{CompiledIndex, MappedIndex},
};
use terrane_sdk::{host::cache::CacheState, store::TokioLocalFs};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "worker-child" {
        return scoped_worker::child();
    }
    if mode == "worker-crash-child" {
        return worker_crash::child();
    }
    let launched = if mode == "worker-send" {
        Some(scoped_worker::launch()?)
    } else if mode == "worker-crash" {
        let launched = scoped_worker::launch_crash()?;
        println!("WORKER_PID {}", launched.child_id());
        Some(launched)
    } else {
        None
    };
    require_empty_capabilities()?;
    let confinement = std::sync::Arc::new(quota_confinement::install()?);
    eprintln!("SURFACE_STAGE mode={mode} phase=native-inspection");
    let inputs = config::Inputs::load()?;
    let mut settings = inputs.owner_config()?;
    let mut policy = SurfaceIndexPolicy {
        max_entries: 16,
        max_node_bytes: 65536,
        max_index_bytes: if mode == "cap" { 4096 } else { 65536 },
        capacity_bytes: if mode == "cap" { 4096 } else { 131072 },
        future_hold_bytes: config::HOLD + 65536,
    };
    settings.surface_index = Some(policy);
    let mut preparation = NativeCachePreparation::inspect(settings, confinement.clone())?;
    let pressure_baseline = if matches!(mode.as_str(), "pressure-calibrate" | "pressure") {
        let mut quota = HostQuotaClient::connect(&inputs.quota, 0, config::EPOCH)?;
        let baseline = quota_sample(&mut quota, &inputs)?.0;
        if mode == "pressure" {
            policy = pressure::policy(policy, baseline)?;
            drop(preparation);
            let mut settings = inputs.owner_config()?;
            settings.surface_index = Some(policy);
            preparation = NativeCachePreparation::inspect(settings, confinement.clone())?;
        }
        Some(baseline)
    } else {
        None
    };
    if mode == "cap" {
        let mut quota = HostQuotaClient::connect(&inputs.quota, 0, config::EPOCH)?;
        let baseline = quota_sample(&mut quota, &inputs)?.0;
        // The real empty snapshot consumes one ext4 block. Leave room for that
        // snapshot and the small compiled payload, but not another data block.
        policy.capacity_bytes = baseline.checked_add(6144).ok_or("fixture cap overflows")?;
        drop(preparation);
        let mut settings = inputs.owner_config()?;
        settings.surface_index = Some(policy);
        preparation = NativeCachePreparation::inspect(settings, confinement.clone())?;
    }
    if mode == "prepare" {
        println!("PASS actual surface owner native preparation");
        return Ok(());
    }
    if !matches!(
        mode.as_str(),
        "run"
            | "cap"
            | "refuse-cold"
            | "exposure"
            | "file-closure"
            | "cold-closure"
            | "index-closure"
            | "worker-send"
            | "worker-crash"
            | "crash-refuse"
            | "crash-recover"
            | "pressure-calibrate"
            | "pressure"
    ) {
        return Err("unknown surface-owner selector".into());
    }
    eprintln!("SURFACE_STAGE mode={mode} phase=owner-start");
    let owner = NativeMetadataOwner::start(preparation)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    if mode == "refuse-cold" {
        return refuse_malformed_cold(&owner, &runtime, &inputs);
    }
    if matches!(mode.as_str(), "crash-refuse" | "crash-recover") {
        return worker_crash::recover(&mode, &runtime, &owner, &inputs);
    }
    let (root, nodes) = tree()?;
    let before = snapshot(&inputs)?;
    eprintln!("SURFACE_STAGE mode={mode} phase=pre-resume-refusal");
    if runtime
        .block_on(owner.cache_surface_index(root, nodes.clone()))
        .is_ok()
        || snapshot(&inputs)? != before
    {
        return Err("surface admission before actual Resume changed state".into());
    }
    eprintln!("SURFACE_STAGE mode={mode} phase=recovery");
    let completed = runtime.block_on(owner.recover())?;
    eprintln!("SURFACE_STAGE mode={mode} phase=resume");
    runtime.block_on(owner.resume_recovered(completed))?;
    println!("PASS surface admission requires actual recovery and acknowledged Resume");
    if let Some(baseline) = pressure_baseline {
        return pressure::run(&mode, &runtime, &owner, &inputs, policy, baseline);
    }
    if let Some(launched) = launched {
        if mode == "worker-crash" {
            return worker_crash::run(launched, &runtime, &owner, &inputs);
        }
        return scoped_worker::run(launched, &runtime, &owner, &inputs);
    }
    if mode == "cold-closure" {
        return exposure::cold_closure::verify(owner, &runtime, &inputs, policy, confinement);
    }
    if mode == "file-closure" {
        return runtime.block_on(exposure::file_closure::verify(&owner, &inputs));
    }
    if mode == "index-closure" {
        return runtime.block_on(exposure::verify_index_closure(&owner, &inputs));
    }
    if mode == "exposure" {
        runtime.block_on(exposure::verify(&owner, &inputs))?;
        drop(owner);
        let before = snapshot(&inputs)?;
        let restarted = restart(&inputs, policy, confinement)?;
        let error = runtime
            .block_on(restarted.recover())
            .err()
            .ok_or("cold recovery discarded retained exposure custody")?;
        if error.kind() != io::ErrorKind::WouldBlock || snapshot(&inputs)? != before {
            return Err("unreconciled cold exposure changed original policy".into());
        }
        println!(
            "PASS cold exposure refuses recovery before mutation while kernel closure remains unreconciled"
        );
        return Ok(());
    }

    let original = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            config::STATE,
        ))?
        .ok_or("durable surface snapshot missing")?;
    if mode == "cap" {
        let error = runtime
            .block_on(owner.cache_surface_index(root, nodes))
            .err()
            .ok_or("separate actual surface cap unexpectedly accepted")?;
        if error.kind() != io::ErrorKind::StorageFull {
            return Err(error.into());
        }
        let canonical = canonical_path(&inputs, root);
        let file = File::open(&canonical)?;
        terrane_linux::verity::measure(&file)?;
        let mut quota = HostQuotaClient::connect(&inputs.quota, 0, config::EPOCH)?;
        if quota_sample(&mut quota, &inputs)?.0 <= policy.capacity_bytes
            || runtime
                .block_on(owner.cache_surface_index(root, BTreeMap::new()))
                .is_ok()
        {
            return Err("actual surface cap failure lost physical fault custody".into());
        }
        let retained = runtime
            .block_on(CacheState::load(
                &TokioLocalFs,
                &inputs.root.join("state/cache"),
                config::STATE,
            ))?
            .ok_or("durable surface snapshot missing")?;
        if retained.reservations.len() != original.reservations.len() + 1 {
            return Err("late surface cap failure discarded its funded job".into());
        }
        println!(
            "PASS actual separate surface cap retains sealed inode, durable hold and faulted owner"
        );
        drop(file);
        drop(owner);
        let restarted = restart(&inputs, policy, confinement)?;
        let completed = runtime.block_on(restarted.recover())?;
        runtime.block_on(restarted.resume_recovered(completed))?;
        no_surface_hold(&runtime, &inputs)?;
        if canonical.exists() {
            return Err("cold cap-failure inode survived retirement".into());
        }
        println!(
            "PASS cold recovery retires actual cap-failure index before releasing its copy hold"
        );
        return Ok(());
    }

    eprintln!("SURFACE_STAGE mode={mode} phase=cancelled-admission");
    let stall = runtime.block_on(owner.stall_policy_for_fixture())?;
    let mut abandoned = Box::pin(owner.cache_surface_index(root, nodes.clone()));
    let mut context = Context::from_waker(Waker::noop());
    if !matches!(abandoned.as_mut().poll(&mut context), Poll::Pending) {
        return Err(
            "surface cancellation control did not enqueue behind actual held policy".into(),
        );
    }
    drop(abandoned);
    drop(stall);
    let admitted = runtime.block_on(owner.cache_surface_index(root, nodes.clone()))?;
    admitted.check_native_backing()?;
    if admitted.key().root() != root || admitted.key().version() != 2 {
        return Err("surface cache key differs from actual compilation".into());
    }
    let canonical = canonical_path(&inputs, root);
    let file = File::open(&canonical)?;
    let metadata = file.metadata()?;
    if metadata.uid() != 840
        || metadata.gid() != 845
        || metadata.mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
        || NativeProject::inspect(&file)?.project_id != inputs.project
        || metadata.blocks() * 512 != admitted.synchronized_inode_bytes()
    {
        return Err("surface cache inode differs from actual native custody".into());
    }
    let compiled = CompiledIndex::from_nodes(root, &nodes, 262144, 16, 65536, 65536)?;
    compiled.verify_reader(&mut File::open(&canonical)?)?;
    println!(
        "PASS cancelled surface waiter retains canonical sealed inode and warm requests share original inode"
    );

    // Restore owner write permission to distinguish permanent kernel sealing
    // from a DAC-only write refusal, then restore the presentation mode.
    fs::set_permissions(&canonical, fs::Permissions::from_mode(0o600))?;
    let attempted = OpenOptions::new().write(true).open(&canonical);
    fs::set_permissions(&canonical, fs::Permissions::from_mode(0o400))?;
    let error = attempted
        .err()
        .ok_or("sealed surface index accepted a writer")?;
    if error.raw_os_error() != Some(libc::EPERM) {
        return Err(error.into());
    }
    admitted.check_native_backing()?;
    let stable = snapshot(&inputs)?;
    let reused = runtime.block_on(owner.cache_surface_index(root, nodes.clone()))?;
    reused.check_native_backing()?;
    if snapshot(&inputs)? != stable || File::open(&canonical)?.metadata()?.ino() != metadata.ino() {
        return Err("warm surface admission changed original inode or durable state".into());
    }
    let mut changed = nodes;
    let body = changed
        .values_mut()
        .next()
        .ok_or("canonical fixture has no nodes")?;
    *body.last_mut().ok_or("canonical node is empty")? ^= 1;
    if runtime
        .block_on(owner.cache_surface_index(root, changed))
        .is_ok()
        || snapshot(&inputs)? != stable
    {
        return Err("misbound canonical surface input changed admitted state".into());
    }
    let after = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            config::STATE,
        ))?
        .ok_or("durable surface snapshot missing")?;
    if after.reservations.len() != original.reservations.len() + 1
        || !after.reservations.iter().any(|hold| {
            hold.id.starts_with("surface-index:")
                && hold.owner == inputs.owner
                && hold.bytes == policy.future_hold_bytes
        })
        || !fs::read_dir(inputs.root.join("chunks"))?
            .collect::<io::Result<Vec<_>>>()?
            .is_empty()
    {
        return Err("surface admission funding or metadata-only boundary changed".into());
    }
    println!(
        "PASS surface indexes are kernel immutable; warm reuse and invalid nodes cause no durable mutation or content fetch"
    );
    let binding = terrane_linux::verity::measure(&file)?;
    let mapping = MappedIndex::open(File::open(&canonical)?.into(), root, &binding, 65536)?;
    let old_allocated = admitted.synchronized_inode_bytes();
    drop(file);
    drop(admitted);
    drop(reused);
    drop(owner);

    let restarted = restart(&inputs, policy, confinement)?;
    let completed = runtime.block_on(restarted.recover())?;
    if canonical.exists()
        || completed.charged_reserved_bytes() < old_allocated
        || mapping.index().lookup(b"file").is_none()
    {
        return Err("cold surface retirement lost retained mapping or physical charge".into());
    }
    runtime.block_on(restarted.resume_recovered(completed))?;
    no_surface_hold(&runtime, &inputs)?;
    println!(
        "PASS cold recovery retires index names and copy holds while retaining actual mapped bytes and project charge"
    );

    let (_, nodes) = tree()?;
    let replacement = runtime.block_on(restarted.cache_surface_index(root, nodes))?;
    replacement.check_native_backing()?;
    if File::open(&canonical)?.metadata()?.ino() == metadata.ino() {
        return Err("cold recompilation reused a still-mapped retired inode".into());
    }
    let mut quota = HostQuotaClient::connect(&inputs.quota, 0, config::EPOCH)?;
    let before = quota_sample(&mut quota, &inputs)?;
    drop(mapping);
    let deadline = observation_now() + std::time::Duration::from_secs(5);
    loop {
        let after = quota_sample(&mut quota, &inputs)?;
        if before.0.checked_sub(after.0) == Some(old_allocated)
            && before.1.checked_sub(after.1) == Some(1)
        {
            break;
        }
        if observation_now() >= deadline {
            return Err(
                "final index unmap did not release exactly its actual charged blocks and inode"
                    .into(),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    println!(
        "PASS cold recompilation creates a distinct inode and final old-index unmap releases exactly its project charge"
    );
    eviction::verify(&runtime, &restarted, &inputs, replacement)?;
    runtime.block_on(scoped::verify(&restarted, &inputs))?;
    require_empty_capabilities()?;
    Ok(())
}

fn restart(
    inputs: &config::Inputs,
    policy: SurfaceIndexPolicy,
    confinement: std::sync::Arc<quota_confinement::Installed>,
) -> Result<NativeMetadataOwner> {
    let mut settings = inputs.owner_config()?;
    settings.surface_index = Some(policy);
    Ok(NativeMetadataOwner::start(
        NativeCachePreparation::inspect(settings, confinement)?,
    )?)
}

fn no_surface_hold(runtime: &tokio::runtime::Runtime, inputs: &config::Inputs) -> Result<()> {
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            config::STATE,
        ))?
        .ok_or("cold surface snapshot missing")?;
    if state
        .reservations
        .iter()
        .any(|hold| hold.id.starts_with("surface-index:"))
    {
        return Err("cold surface copy hold survived successful retirement".into());
    }
    Ok(())
}

fn quota_sample(client: &mut HostQuotaClient, inputs: &config::Inputs) -> Result<(u64, u64)> {
    rustix::fs::syncfs(&File::open(&inputs.root)?)?;
    let verified = client.query(&inputs.owner, &inputs.domain)?;
    let actual = verified.observation();
    Ok((actual.charged_reserved_bytes, actual.charged_inodes))
}

// This native guest observes real kernel deallocation, outside Crucible state.
#[allow(clippy::disallowed_methods)]
fn observation_now() -> std::time::Instant {
    std::time::Instant::now()
}

fn refuse_malformed_cold(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &config::Inputs,
) -> Result<()> {
    let before = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            config::STATE,
        ))?
        .ok_or("original cold surface snapshot missing")?;
    let error = runtime
        .block_on(owner.recover())
        .err()
        .ok_or("malformed cold surface namespace was accepted")?;
    if error.kind() != io::ErrorKind::InvalidData {
        return Err(error.into());
    }
    let after = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            config::STATE,
        ))?
        .ok_or("failed cold surface snapshot missing")?;
    let mut found = false;
    for original in before
        .reservations
        .iter()
        .filter(|hold| hold.id.starts_with("surface-index:"))
    {
        found = true;
        if !after.reservations.iter().any(|hold| {
            hold.id == original.id && hold.owner == original.owner && hold.bytes == original.bytes
        }) {
            return Err("malformed cold namespace discarded original surface funding".into());
        }
    }
    if !found {
        return Err("cold refusal fixture has no original surface hold".into());
    }
    println!(
        "PASS malformed cold surface namespace preserves original copy holds and refuses recovery"
    );
    Ok(())
}

fn snapshot(inputs: &config::Inputs) -> io::Result<Option<Vec<u8>>> {
    match fs::read(inputs.root.join("state/cache/records.toml")) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn canonical_path(inputs: &config::Inputs, root: Digest) -> std::path::PathBuf {
    let hash: String = root.iter().map(|byte| format!("{byte:02x}")).collect();
    inputs
        .root
        .join("objects")
        .join(format!(".terrane-surface:2:{hash}"))
}

fn tree() -> Result<(Digest, BTreeMap<Digest, Vec<u8>>)> {
    tree_with_content([3; 32])
}

fn tree_with_content(content: Digest) -> Result<(Digest, BTreeMap<Digest, Vec<u8>>)> {
    let tree = Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
                kind: EntryKind::File {
                    mode: 0o444,
                    size: 1,
                    content: ContentRef::Inline(content),
                    link_id: None,
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }],
        None,
        262144,
        TreeUse::Ordinary,
    )?;
    Ok((
        tree.root_identity(),
        tree.nodes()
            .map(|node| (node.identity(), node.encoded().to_vec()))
            .collect(),
    ))
}

fn require_empty_capabilities() -> Result<()> {
    if rustix::process::geteuid().as_raw() != 840 {
        return Err("surface actor requires UID 840".into());
    }
    let status = fs::read_to_string("/proc/self/status")?;
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        if !status
            .lines()
            .any(|line| line == format!("{field}:\t0000000000000000"))
        {
            return Err(format!("surface actor retains {field}").into());
        }
    }
    Ok(())
}
