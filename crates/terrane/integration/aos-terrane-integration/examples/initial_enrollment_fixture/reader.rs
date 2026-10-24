//! Observes real unprivileged quota, metadata and disclosure-boundary behavior.

use super::config::{Case, DOMAINS, LIMIT, OWNERS, PrivateHash, SEED};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io,
    os::unix::fs::MetadataExt,
    path::Path,
};
use terrane_format::chunking::ChunkProfile;
use terrane_sdk::{
    bucket::portable_reader::{PortableReadLimits, validate_existing},
    repository::MetadataValidator,
    store::{CapabilityReport, RefCapability, TokioClock, TokioLocalFs},
};

pub(super) fn actual_identity(uid: u32, groups: &[u32]) -> io::Result<()> {
    terrane_linux::host_quota::require_host_root_namespace_boundary()?;
    let status = fs::read_to_string("/proc/self/status")?;
    for label in ["Uid:", "Gid:"] {
        let values = status
            .lines()
            .find_map(|line| line.strip_prefix(label))
            .ok_or_else(|| io::Error::other("native status omitted identity"))?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(super::source_error)?;
        assert_eq!(
            values,
            vec![uid; 4],
            "supervisor must set all real/effective/saved/filesystem role identities"
        );
    }
    let observed = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .ok_or_else(|| io::Error::other("native status omitted groups"))?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(super::source_error)?;
    assert_eq!(observed, groups.iter().copied().collect());
    for label in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(label))
            .ok_or_else(|| io::Error::other("native status omitted capability set"))?
            .trim();
        assert_eq!(
            u64::from_str_radix(value, 16).map_err(super::source_error)?,
            0,
            "role must have empty {label}"
        );
    }
    assert_eq!(
        status
            .lines()
            .find_map(|line| line.strip_prefix("NoNewPrivs:"))
            .map(str::trim),
        Some("1")
    );
    Ok(())
}

fn denied(path: &Path) -> io::Result<()> {
    #[allow(
        clippy::expect_used,
        reason = "The native fixture asserts actual permission denial."
    )]
    let error = File::open(path).expect_err("unprivileged role unexpectedly opened protected path");
    assert_eq!(
        error.kind(),
        io::ErrorKind::PermissionDenied,
        "must refuse actual traversal/access, not report absent: {path:?}"
    );
    Ok(())
}

/// Observes an explicitly selected unprivileged role on the enrolled root.
///
/// # Errors
/// Returns credential-inspection, authenticated quota, portable validation or native path errors.
///
/// # Panics
/// Panics if a required physical fixture invariant is not observed.
pub(super) fn run(selector: &str) -> io::Result<()> {
    let publisher = selector == "read-publisher";
    let foreign = selector == "foreign-private";
    actual_identity(
        if foreign {
            842
        } else if publisher {
            841
        } else {
            840
        },
        if foreign {
            &[]
        } else if publisher {
            &[845]
        } else {
            &[844, 845]
        },
    )?;
    let case = Case::existing("positive")?;
    if foreign {
        #[allow(
            clippy::expect_used,
            reason = "The native fixture asserts actual permission denial."
        )]
        let error = fs::read_dir(case.root(1)).expect_err("foreign UID listed private root");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        for path in [
            case.root(1).join("CAPABILITIES"),
            case.root(1).join("publication/PORTABLE"),
            case.root(1).join("publication/SELECTED-HISTORY"),
        ] {
            denied(&path)?;
        }
        let hash: PrivateHash =
            toml::from_str(&fs::read_to_string(case.path.join("private-hash.toml"))?)
                .map_err(super::source_error)?;
        assert!(hash.present.starts_with(case.root(1)));
        assert!(hash.absent.starts_with(case.root(1)));
        denied(&hash.present)?;
        denied(&hash.absent)?;
        println!(
            "PASS actual foreign UID cannot list private root or distinguish present/absent hash paths"
        );
        return Ok(());
    }
    let owner = if selector == "read-public" { 0 } else { 1 };
    let observation =
        aos_terrane_integration::host::query(&case.config(), OWNERS[owner], DOMAINS[owner])?;
    let value = observation.observation();
    assert_eq!(value.owner_id, OWNERS[owner]);
    assert_eq!(value.domain, DOMAINS[owner]);
    assert_eq!(value.project_id, case.project(owner));
    assert_eq!(value.hard_limit_bytes, LIMIT);
    assert!(value.accounting && value.enforcement);
    assert_eq!(value.roots.len(), 9);
    assert!(value.roots.iter().all(|root| root.project_inherit));
    assert_eq!(value.configured_limit_sum_bytes, 2 * LIMIT);
    assert_eq!(value.tier_charge_budget_bytes, 2 * LIMIT);
    let root = fs::metadata(case.root(owner))?;
    assert!(
        value
            .roots
            .iter()
            .any(|entry| entry.role_directory == "layout-root"
                && entry.device == root.dev()
                && entry.inode == root.ino())
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let profile = ChunkProfile::cdc_1m(SEED);
    let validated = runtime
        .block_on(validate_existing(
            case.bucket(owner, SEED),
            &TokioLocalFs,
            TokioClock,
            MetadataValidator::new(profile),
            PortableReadLimits {
                max_file_bytes: 1024 * 1024,
                max_input_bytes: 4 * 1024 * 1024,
                max_files: 2048,
                max_selected_bytes: 1024 * 1024,
            },
        ))
        .map_err(super::source_error)?;
    assert_eq!(validated.root(), case.root(owner));
    assert_eq!(validated.profile().seed, SEED);
    assert_eq!(validated.capabilities().refs, RefCapability::None);
    assert!(!validated.capabilities().sealed);
    denied(&case.control(owner).join("backend-registration.cbor"))?;
    let coordination = case.root(owner).join(
        terrane_format::bucket::BucketKey::parse("CAPABILITIES")
            .map_err(super::source_error)?
            .lock_name(),
    );
    denied(&coordination)?;
    if publisher {
        denied(&case.root(owner).join("state/cache"))?;
    } else {
        denied(&case.root(owner).join("sealed"))?;
        denied(&case.root(owner).join("staging"))?;
    }
    println!(
        "PASS actual {selector} quota query and same-root metadata-only validation; no ContentStore or live-R authority"
    );
    Ok(())
}
