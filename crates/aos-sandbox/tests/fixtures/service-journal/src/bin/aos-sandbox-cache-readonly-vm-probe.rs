//! VM-only bootstrap and nonauthorizing readback of protected Cache journals.
//!
//! `initialize` runs with the Controller UID before the root view is mounted.
//! `read` invokes only the fixed root policy diagnostic after the view exists.

use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox::cache_residency::{
    BackingIsolationV1, CacheIsolationPolicyV1, CacheNodeIdV1,
    CacheReplayControllerBootstrapOwnerV1, NodeCacheQuotaV1, PhysicalPartitionId,
    ProjectCacheQuotaV1, ProtectedBackingIdentityV1, ResidencyEnforcementV1,
    encode_cache_replay_controller_bundle_v1, encode_cache_replay_genesis_manifest_v1,
};
use aos_sandbox::policy_compiler::{
    read_fixed_policy_cache_hold_v1, read_fixed_policy_cache_journals_v1,
};
use aos_sandbox_core::model::{CacheDomain, CacheDomainKind};
use aos_sandbox_core::{CacheDomainId, ObjectDigest, ProjectId};

const CONTROLLER_UID: u32 = 811;

fn main() {
    if let Err(error) = run() {
        eprintln!("Cache read-only VM qualification failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = std::env::args().collect();
    match arguments.as_slice() {
        [_, operation] if operation == "initialize" => initialize(),
        [_, operation] if operation == "read" => read(),
        [_, operation] if operation == "read-hold" => read_hold(),
        _ => Err("usage: aos-sandbox-cache-readonly-vm-probe initialize|read|read-hold".into()),
    }
}

fn initialize() -> Result<(), Box<dyn Error>> {
    let project = ProjectId::from_bytes([1; 16]);
    let node = CacheNodeIdV1::from_bytes([2; 16])?;
    let backing = ProtectedBackingIdentityV1::new(
        ObjectDigest::from_bytes([3; 32]),
        ObjectDigest::from_bytes([4; 32]),
        ObjectDigest::from_bytes([5; 32]),
        ObjectDigest::from_bytes([6; 32]),
    )?;
    let disclosure = CacheDomain::new(
        CacheDomainKind::Project,
        CacheDomainId::from_bytes(*project.as_bytes()),
    );
    let isolation = CacheIsolationPolicyV1 {
        backing: BackingIsolationV1::SeparateFilesystemOrDataset,
        residency: ResidencyEnforcementV1::HardIsolatedResidency,
        reflink_or_clone: false,
        block_deduplication: false,
        shared_page_cache: false,
        fetch_coalescing: false,
        strict: true,
        revision: 1,
    };
    let partition = PhysicalPartitionId::from_policy(node, backing, disclosure, isolation)?;

    let node_quota = NodeCacheQuotaV1 {
        partition,
        maximum_physical_bytes: 1024 * 1024,
        maximum_resident_objects: 16,
        maximum_logical_pins: 16,
        maximum_source_retentions: 16,
        maximum_kernel_references: 16,
        maximum_backing_registrations: 16,
        recovery_reserve_bytes: 4096,
        high_water_bytes: 768 * 1024,
        low_water_bytes: 512 * 1024,
    };
    let project_quota = ProjectCacheQuotaV1 {
        project,
        partition,
        maximum_charged_bytes: 1024 * 1024,
        maximum_logical_pins: 16,
        maximum_source_retentions: 16,
        maximum_kernel_references: 16,
        maximum_backing_registrations: 16,
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let valid_until = now.checked_add(86_400).ok_or("VM clock overflow")?;
    let manifest = encode_cache_replay_genesis_manifest_v1(
        partition,
        node_quota,
        vec![project_quota],
        valid_until,
    )?;
    let bundle = encode_cache_replay_controller_bundle_v1([manifest])?;

    CacheReplayControllerBootstrapOwnerV1::import_fixed_bundle_for_uid(CONTROLLER_UID, &bundle)?;
    let (mut controller, _) =
        CacheReplayControllerBootstrapOwnerV1::open_fixed_protected_for_uid(CONTROLLER_UID)?;
    let (mut owner, _) = controller.bootstrap_fixed_cache(partition.digest())?;
    if owner.reconstructed_partitions()?.len() != 1 {
        return Err("bootstrap did not reconstruct the one Cache partition".into());
    }

    println!("cache-protected-three-journal-bootstrap:PASS");
    Ok(())
}

fn read() -> Result<(), Box<dyn Error>> {
    let replay = read_fixed_policy_cache_journals_v1()?;
    if replay.partitions != 1
        || replay.journals.state.committed_transactions != 0
        || replay.journals.authority.committed_transactions == 0
        || replay.journals.clock.committed_transactions == 0
    {
        return Err("root readback did not replay all three initialized journals".into());
    }

    println!("cache-root-read-only-replay:PASS");
    Ok(())
}

fn read_hold() -> Result<(), Box<dyn Error>> {
    let observed = read_fixed_policy_cache_hold_v1()?;
    if !observed.hold.is_held() || observed.replay.partitions != 1 {
        return Err("root did not replay one active Cache hold".into());
    }

    println!("cache-root-read-only-held-replay:PASS");
    Ok(())
}
