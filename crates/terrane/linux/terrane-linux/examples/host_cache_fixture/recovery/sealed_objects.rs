//! Exercises whole-file leases from actual recovered files sharing every chunk.

use super::{Fixture, INLINE_BYTES, directory, hex, invalid, require_seed_capabilities, write};
use crate::{config::Inputs, sealed_consumer::check_backing};
use std::{collections::BTreeMap, fs::File, io, os::unix::fs::MetadataExt};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{Identity, IdentityKind, TERRANE_V1},
    manifest::Manifest,
};
use terrane_linux::host_cache::NativeMetadataOwner;
use terrane_sdk::{
    pack::{EntryKind, PackClass, PackId, PackWriter},
    store::{Clock, TokioClock},
};

const DOMAIN: &str = "tenant:sealed-consumer-cold";

/// Seeds real bytes and seals, without producing policy or recovery authority.
///
/// # Errors
/// Refuses another administrative identity, domain, existing paths or failed
/// project inheritance, file synchronization or actual fs-verity operations.
pub(crate) fn seed() -> io::Result<()> {
    use std::io::Read;

    if rustix::process::geteuid().as_raw() != 0 {
        return Err(invalid("cold whole-file seed requires root administration"));
    }
    require_seed_capabilities()?;
    let inputs = Inputs::load()?;
    if inputs.domain != DOMAIN {
        return Err(invalid(
            "cold whole-file seed requires its dedicated domain",
        ));
    }
    let fixture = Fixture::new()?;
    let alternate = alternate(&fixture)?;
    let mut random = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let id = PackId::from_random_bytes(random);
    let mut writer = PackWriter::new(id, PackClass::Meta, false);
    for canonical in [&fixture.manifest, &alternate] {
        writer
            .append_raw(EntryKind::Manifest, canonical)
            .map_err(io::Error::other)?;
    }
    let pack = writer.seal().map_err(io::Error::other)?;
    let packs = inputs.root.join("objects/pack");
    directory(&packs, 840, 845, 0o2770)?;
    let parent = packs.join(format!("{:02x}", id.as_bytes()[0]));
    directory(&parent, 840, 845, 0o2770)?;
    for (key, bytes) in [
        (id.pack_key(), pack.bytes()),
        (id.index_key(), pack.index_object()),
    ] {
        write(&inputs, &inputs.root.join(key), bytes, 840, 845, 0o660)?;
    }
    File::open(parent)?.sync_all()?;
    File::open(packs)?.sync_all()?;
    File::open(inputs.root.join("objects"))?.sync_all()?;

    for (kind, canonical, plaintext) in [
        (
            IdentityKind::Manifest,
            fixture.manifest.as_slice(),
            fixture.plaintext.as_slice(),
        ),
        (
            IdentityKind::Manifest,
            alternate.as_slice(),
            fixture.plaintext.as_slice(),
        ),
        (IdentityKind::Chunk, INLINE_BYTES, INLINE_BYTES),
    ] {
        let identity = identity(kind, canonical)?;
        let hash = hex(identity.digest());
        let parent = inputs.root.join("sealed").join(&hash[..2]);
        if !parent.exists() {
            directory(&parent, 841, 841, 0o755)?;
        }
        let path = parent.join(hash);
        write(&inputs, &path, plaintext, 841, 841, 0o400)?;
        let file = File::open(path)?;
        terrane_linux::verity::enable(&file)?;
        file.sync_all()?;
        File::open(parent)?.sync_all()?;
    }
    File::open(inputs.root.join("sealed"))?.sync_all()?;
    println!("SEEDED actual cold whole-file candidates; no publication or recovery authority");
    Ok(())
}

/// Exercises genuine recovery, acknowledged Resume and independent consumer pins.
///
/// # Errors
/// Refuses pre-existing policy, changed recovery funding, a premature grant,
/// missing whole-file backing or failed exact descriptor and plaintext checks.
pub(crate) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    if inputs.domain != DOMAIN || original.is_some() {
        return Err(invalid(
            "cold whole-file consumers require fresh dedicated policy",
        ));
    }
    let fixture = Fixture::new()?;
    let alternate = alternate(&fixture)?;
    let identities = [
        identity(IdentityKind::Manifest, &fixture.manifest)?,
        identity(IdentityKind::Manifest, &alternate)?,
        identity(IdentityKind::Chunk, INLINE_BYTES)?,
    ];
    let expires = TokioClock
        .now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| invalid("cold consumer deadline overflow"))?;
    refuse_before_resume(owner, runtime, inputs, &identities, expires)?;
    let completed = runtime.block_on(owner.recover())?;
    completed.check_current()?;
    refuse_before_resume(owner, runtime, inputs, &identities, expires)?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;

    let mut leases = Vec::new();
    let mut backings = Vec::new();
    let mut manifest_inodes = Vec::new();
    for (identity, plaintext) in identities.iter().zip([
        fixture.plaintext.as_slice(),
        fixture.plaintext.as_slice(),
        INLINE_BYTES,
    ]) {
        let lease = runtime.block_on(owner.pin_sealed_object(identity.clone(), expires))?;
        let backing = lease.backing()?;
        let file = File::from(std::os::fd::AsFd::as_fd(&backing).try_clone_to_owned()?);
        let inode = file.metadata()?.ino();
        check_backing(&backing, plaintext, inode)?;
        if identity.kind() == IdentityKind::Manifest {
            manifest_inodes.push(inode);
        }
        println!(
            "COLD_SEALED_OBJECT hash={} inode={inode} bytes={}",
            hex(identity.digest()),
            plaintext.len()
        );
        leases.push(lease);
        backings.push(backing);
    }
    if manifest_inodes.len() != 2 || manifest_inodes[0] == manifest_inodes[1] {
        return Err(invalid(
            "recovered manifest identities collapsed to one physical file",
        ));
    }
    for (identity, canonical) in identities
        .iter()
        .take(2)
        .zip([&fixture.manifest, &alternate])
    {
        let metadata = runtime.block_on(owner.pin_resident_metadata(identity.clone(), expires))?;
        if metadata.read_verified()? != *canonical {
            return Err(invalid(
                "recovered whole-file pin replaced canonical metadata",
            ));
        }
        runtime.block_on(owner.release_consumer_lease(&metadata))?;
    }
    let mut offset = 0;
    for chunk in &fixture.chunks {
        let chunk_identity = TERRANE_V1
            .from_digest(IdentityKind::Chunk, &chunk.digest)
            .map_err(io::Error::other)?;
        if runtime
            .block_on(owner.pin_sealed_object(chunk_identity.clone(), expires))
            .is_ok()
        {
            return Err(invalid(
                "a recovered chunk range became a whole sealed file",
            ));
        }
        let range = runtime.block_on(owner.pin_resident_chunk(chunk_identity, expires))?;
        let end = offset + chunk.length as usize;
        if range.read_verified()? != fixture.plaintext[offset..end] {
            return Err(invalid(
                "whole-file selection changed ordinary recovered chunk reads",
            ));
        }
        runtime.block_on(owner.release_consumer_lease(&range))?;
        offset = end;
    }
    for (index, lease) in leases.iter().enumerate() {
        runtime.block_on(owner.release_sealed_object_lease(lease))?;
        if lease.backing().is_ok() {
            return Err(invalid("released recovered lease reopened its file"));
        }
        let expected = if index == 2 {
            INLINE_BYTES
        } else {
            &fixture.plaintext
        };
        let file = File::from(std::os::fd::AsFd::as_fd(&backings[index]).try_clone_to_owned()?);
        check_backing(&backings[index], expected, file.metadata()?.ino())?;
    }
    drop(backings);
    println!(
        "PASS actual recovered whole inline and distinct manifest inodes sharing every chunk; no pre-Resume grant or range substitution; retained descriptors survive release"
    );
    Ok(())
}

fn refuse_before_resume(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    identities: &[Identity],
    expires: u64,
) -> io::Result<()> {
    let path = inputs.root.join("state/cache/records.toml");
    let before = match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    for identity in identities {
        if runtime
            .block_on(owner.pin_sealed_object(identity.clone(), expires))
            .is_ok()
        {
            return Err(invalid(
                "cold whole-file source bypassed acknowledged Resume",
            ));
        }
    }
    let after = match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if before != after {
        return Err(invalid(
            "refused cold whole-file grant changed durable policy",
        ));
    }
    Ok(())
}

fn alternate(fixture: &Fixture) -> io::Result<Vec<u8>> {
    Manifest {
        size: fixture.plaintext.len() as u64,
        chunks: fixture.chunks.clone(),
        hashes: BTreeMap::from([(
            "blake3".into(),
            blake3::hash(&fixture.plaintext).as_bytes().to_vec(),
        )]),
        media_type: Some("application/octet-stream".into()),
    }
    .encode(&ChunkProfile::cdc_1m([0; 32]))
    .map_err(io::Error::other)
}

fn identity(kind: IdentityKind, bytes: &[u8]) -> io::Result<Identity> {
    TERRANE_V1.calculate(kind, bytes).map_err(io::Error::other)
}
