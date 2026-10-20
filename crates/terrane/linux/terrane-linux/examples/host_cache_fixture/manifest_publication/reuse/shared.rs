//! Checks shared directory reads over original manifest-backed consumer ranges.
//!
//! Each grant comes from the physical owner after actual assembly and source
//! retirement. The repeated chunk keeps its first object's original residence;
//! the distinct tails exercise nonzero offsets in two different sealed inodes.

use super::{Data, Inputs, NativeMetadataOwner, emit, fs, hex, invalid};
use std::{io, time::SystemTime};
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_linux::host_cache::NativeSharedResidences;
use terrane_sdk::{
    domain::DomainBinding,
    host::cache::DomainHostLayout,
    repository::MetadataValidator,
    store::{ContentStore, TokioLocalFs, shared_dir::SharedDir},
};

/// Reads three original sealed ranges and independently revokes their grants.
///
/// # Errors
/// Refuses absent native grants, duplicate standalone bytes, changed policy,
/// incorrect chunk ranges or reads that survive their original lease release.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    first: &Data,
    second: &Data,
) -> io::Result<()> {
    let plaintext = [
        first.first.as_slice(),
        first.tail.as_slice(),
        second.tail.as_slice(),
    ];
    let expires = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| invalid("shared manifest consumer clock overflow"))?;
    let mut leases = Vec::with_capacity(plaintext.len());
    for bytes in plaintext {
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, bytes)
            .map_err(io::Error::other)?;
        let hash = hex(identity.digest());
        // A canonical encoded copy could mask a failed sealed-range fallback.
        // Empty shard directories are expected after actual source retirement.
        for codec in 0..=2 {
            let path = inputs
                .root
                .join("chunks")
                .join(&hash[..2])
                .join(format!("{hash}.{codec}"));
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
                Ok(_) => return Err(invalid("shared manifest range has a standalone copy")),
            }
        }
        leases.push(runtime.block_on(owner.pin_resident_chunk(identity, expires))?);
    }
    let config = inputs.owner_config()?;
    let profile = config.location.chunk_profile().clone();
    let layout = DomainHostLayout::new(
        inputs.root.clone(),
        DomainBinding {
            domain: inputs.domain.clone(),
            reference: "refs/heads/shared-manifest-fixture".into(),
            root: TERRANE_V1
                .calculate(IdentityKind::Node, b"shared manifest fixture routing")
                .map_err(io::Error::other)?,
            path: b"/".to_vec(),
        },
        profile.clone(),
    )
    .map_err(io::Error::other)?;
    let policy = inputs.root.join("state/cache/records.toml");
    let before = fs::read(&policy)?;
    let residences = NativeSharedResidences::new(&layout, leases.clone(), plaintext.len())
        .map_err(io::Error::other)?;
    let directory = runtime
        .block_on(SharedDir::open_existing(
            layout,
            TokioLocalFs,
            MetadataValidator::new(profile),
        ))
        .map_err(io::Error::other)?
        .with_residences(residences, plaintext.len())
        .map_err(io::Error::other)?;

    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    for (lease, expected) in leases.iter().zip(plaintext) {
        let encoded = runtime
            .block_on(directory.get(lease.identity(), None))
            .map_err(io::Error::other)?;
        if encoded.first() != Some(&0) || encoded.get(1..) != Some(expected) {
            return Err(invalid("shared manifest range changed its exact plaintext"));
        }
    }
    drop(stalled);
    if fs::read(&policy)? != before {
        return Err(invalid("shared manifest directory read mutated policy"));
    }

    for (index, lease) in leases.iter().enumerate() {
        runtime.block_on(owner.release_consumer_lease(lease))?;
        let released = fs::read(&policy)?;
        let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
        if runtime
            .block_on(directory.get(lease.identity(), None))
            .is_ok()
            || runtime
                .block_on(directory.has(std::slice::from_ref(lease.identity())))
                .is_ok()
        {
            return Err(invalid("shared manifest range outlived its original grant"));
        }
        for (remaining, expected) in leases[index + 1..].iter().zip(&plaintext[index + 1..]) {
            let encoded = runtime
                .block_on(directory.get(remaining.identity(), None))
                .map_err(io::Error::other)?;
            if encoded.first() != Some(&0) || encoded.get(1..) != Some(*expected) {
                return Err(invalid("releasing one range revoked an independent grant"));
            }
        }
        drop(stalled);
        if fs::read(&policy)? != released {
            return Err(invalid("revoked shared manifest lookup mutated policy"));
        }
    }
    emit(
        "PASS native shared-directory manifest ranges, original residences, held-policy reads and independent release revocation",
    )
}
