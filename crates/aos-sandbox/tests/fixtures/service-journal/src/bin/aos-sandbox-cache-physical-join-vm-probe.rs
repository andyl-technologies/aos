//! Qualifies the local held Cache/physical cut on a real ext4-verity VM mount.
//!
//! The harness owns the fixed paths and deployment limits. This fixture may
//! prepare an inert Cache hold, but it cannot issue a policy binding or effect.

use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox::cache_residency::{
    BackingIsolationV1, CacheIsolationPolicyV1, CacheNodeIdV1, CacheOwnerErrorV1,
    CacheOwnerLimitsV1, CacheReplayControllerBootstrapOwnerV1,
    CacheResidencyHeldPhysicalCutErrorV1, DormantCacheOwnerV1, NodeCacheQuotaV1,
    PhysicalPartitionId, ProjectCacheQuotaV1, ProtectedBackingIdentityV1, ResidencyEnforcementV1,
    encode_cache_replay_controller_bundle_v1, encode_cache_replay_genesis_manifest_v1,
    with_fixed_closed_cache_physical_policy_cut_v1,
};
use aos_sandbox_core::model::{CacheDomain, CacheDomainKind};
use aos_sandbox_core::{CacheDomainId, ObjectDigest, ProjectId};
use rustix::fs::{FlockOperation, flock};

const CONTROLLER_UID: u32 = 811;
const JOURNAL_ROOT: &str = "/var/lib/aos/sandbox/cache-residency-journals";
const PHYSICAL_ROOT: &str = "/var/lib/aos/sandbox/cache-residency/objects";
const JOURNAL_NAMES: [&str; 4] = [
    "clock.journal",
    "authority.journal",
    "state.journal",
    "policy-hold.journal",
];

fn main() {
    if let Err(error) = run() {
        eprintln!("Cache physical join VM qualification failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let project = ProjectId::from_bytes([1; 16]);
    let node = CacheNodeIdV1::from_bytes([2; 16])?;
    let backing = ProtectedBackingIdentityV1::new(
        ObjectDigest::from_bytes([3; 32]),
        ObjectDigest::from_bytes([4; 32]),
        ObjectDigest::from_bytes([5; 32]),
        ObjectDigest::from_bytes([6; 32]),
    )?;
    let domain = CacheDomain::new(
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
    let partition = PhysicalPartitionId::from_policy(node, backing, domain, isolation)?;
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
    let (mut protected, _) = controller.bootstrap_fixed_cache(partition.digest())?;
    let quotas = protected.reconstructed_node_quotas()?;
    let limits = CacheOwnerLimitsV1::from_node_quotas(1024 * 1024, quotas)?;
    let hold = protected.acquire_vm_fixture_closed_policy_hold_v1(
        project,
        ObjectDigest::from_bytes([9; 32]),
        5,
    )?;
    drop(protected);
    drop(controller);

    let mut physical = DormantCacheOwnerV1::open_fixed(limits)?;
    physical.initialize_empty_manifest_for_vm_fixture()?;
    let ticket = physical
        .release_for_ordered_reopen()
        .map_err(|failure| failure.into_parts().1)?;

    let mut callback_seen = false;
    with_fixed_closed_cache_physical_policy_cut_v1(
        ticket,
        CONTROLLER_UID,
        hold,
        limits,
        |snapshot, inventories| {
            callback_seen = true;
            assert_eq!(inventories.len(), 1);
            assert_eq!(inventories[0].global.node_quota, node_quota);
            assert_eq!(snapshot.currentness().generation(), 1);
            snapshot
                .borrow_descriptors()
                .expect("held physical descriptors");
            prove_contended_locks();
            Ok(())
        },
    )?;
    assert!(callback_seen);
    println!("cache-held-four-journal-physical-flock:PASS");

    let physical = DormantCacheOwnerV1::open_fixed(limits)?;
    let ticket = physical
        .release_for_ordered_reopen()
        .map_err(|failure| failure.into_parts().1)?;
    let mut replacement_seen = false;
    let result = with_fixed_closed_cache_physical_policy_cut_v1(
        ticket,
        CONTROLLER_UID,
        hold,
        limits,
        |snapshot, _| {
            prove_contended_locks();
            replace_manifest_with_same_bytes().expect("same-byte inode replacement");
            replacement_seen = true;
            assert!(matches!(
                snapshot.revalidate(),
                Err(CacheOwnerErrorV1::Stale)
            ));
            Ok(())
        },
    );
    assert!(replacement_seen);
    assert!(matches!(
        result,
        Err(CacheResidencyHeldPhysicalCutErrorV1::Physical(
            CacheOwnerErrorV1::Stale
        ))
    ));
    println!("cache-held-same-byte-manifest-replacement:PASS");

    let physical = DormantCacheOwnerV1::open_fixed(limits)?;
    let ticket = physical
        .release_for_ordered_reopen()
        .map_err(|failure| failure.into_parts().1)?;
    replace_manifest_with_same_bytes()?;
    let mut entered = false;
    let result = with_fixed_closed_cache_physical_policy_cut_v1(
        ticket,
        CONTROLLER_UID,
        hold,
        limits,
        |_, _| {
            entered = true;
            Ok(())
        },
    );
    assert!(!entered);
    assert!(matches!(
        result,
        Err(CacheResidencyHeldPhysicalCutErrorV1::Physical(
            CacheOwnerErrorV1::Stale
        ))
    ));
    println!("cache-ticket-same-byte-manifest-replacement:PASS");
    Ok(())
}

fn prove_contended_locks() {
    for name in JOURNAL_NAMES {
        let path = Path::new(JOURNAL_ROOT).join(format!("{name}.lock"));
        prove_contended_lock(&path);
    }
    prove_contended_lock(&Path::new(PHYSICAL_ROOT).join(".owner.lock"));
}

fn prove_contended_lock(path: &Path) {
    let competing = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open independent lock description");
    assert!(matches!(
        flock(&competing, FlockOperation::NonBlockingLockExclusive),
        Err(rustix::io::Errno::WOULDBLOCK)
    ));
}

fn replace_manifest_with_same_bytes() -> Result<(), Box<dyn Error>> {
    let root = Path::new(PHYSICAL_ROOT);
    let manifest = root.join("owner-state");
    let replacement = root.join("owner-state.vm-replacement");
    let original_bytes = fs::read(&manifest)?;
    let original_inode = fs::metadata(&manifest)?.ino();

    fs::copy(&manifest, &replacement)?;
    File::open(&replacement)?.sync_all()?;
    fs::rename(&replacement, &manifest)?;
    File::open(root)?.sync_all()?;

    assert_eq!(fs::read(&manifest)?, original_bytes);
    assert_ne!(fs::metadata(&manifest)?.ino(), original_inode);
    Ok(())
}
