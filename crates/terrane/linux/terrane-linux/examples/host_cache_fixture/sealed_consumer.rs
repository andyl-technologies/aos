//! Exercises real whole-file descriptors under independent durable consumer pins.

use super::{config::Inputs, manifest_publication};
use std::{
    fs::File,
    io::{self, Write},
    os::{
        fd::AsFd,
        unix::fs::{FileExt, MetadataExt},
    },
    time::Duration,
};
use terrane_format::identity::{Descriptor, Identity, IdentityKind, TERRANE_V1};
use terrane_linux::host_cache::{NativeMetadataOwner, NativeSealedBacking};
use terrane_sdk::store::{ChunkPosition, Clock, TokioClock};

const INLINE: &[u8] = b"whole sealed-file consumer backing";

/// Exercises genuine inline and manifest files without accepting caller file claims.
///
/// # Errors
/// Refuses reused state, incorrect lease or descriptor observations, failed
/// native publication, durability or quota operations, and unavailable clocks.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    if inputs.domain != "tenant:sealed-consumer" || original.is_some() {
        return Err(invalid(
            "sealed consumers require their fresh dedicated domain",
        ));
    }
    let inline = identity(IdentityKind::Chunk, INLINE)?;
    let expires = deadline(90)?;
    if runtime
        .block_on(owner.pin_sealed_object(inline.clone(), expires))
        .is_ok()
    {
        return Err(invalid("sealed consumer acknowledged before actual Resume"));
    }
    let completed = runtime.block_on(owner.recover())?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    let descriptor =
        Descriptor::from_identity(&TERRANE_V1, &inline, INLINE).map_err(io::Error::other)?;
    let published = runtime
        .block_on(owner.publish_inline(descriptor, [vec![0], INLINE.to_vec()].concat()))
        .map_err(io::Error::other)?;
    let inode = published.handle().metadata()?.ino();
    let first = runtime.block_on(owner.pin_sealed_object(inline.clone(), expires))?;
    let second = runtime.block_on(owner.pin_sealed_object(inline.clone(), expires))?;
    let alias = runtime.block_on(owner.pin_resident_chunk(inline.clone(), expires))?;
    if first.identity() != &inline
        || first.owner() == second.owner()
        || first.initial_accounting().synchronized_sealed_inode_bytes
            != published.synchronized_sealed_inode_bytes()
    {
        return Err(invalid(
            "whole-file grant lost original identity or measured inode",
        ));
    }

    let backing = first.backing()?;
    check_backing(&backing, INLINE, inode)?;
    if !matches!(first.clone().backing(), Err(error) if error.kind() == io::ErrorKind::WouldBlock) {
        return Err(invalid("cloning a lease bypassed its single backing bound"));
    }
    drop(backing);
    let backing = first.backing()?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    let other_backing = second.backing()?;
    check_backing(&backing, INLINE, inode)?;
    check_backing(&other_backing, INLINE, inode)?;
    if alias.read_verified()? != INLINE {
        return Err(invalid(
            "held whole-file backings consumed ordinary read capacity",
        ));
    }
    drop(stalled);

    runtime.block_on(owner.release_sealed_object_lease(&first))?;
    if first.backing().is_ok() || first.expires_at().is_ok() {
        return Err(invalid("released whole-file grant issued new backing"));
    }
    check_backing(&backing, INLINE, inode)?;
    drop(backing);
    let renewed = deadline(120)?;
    runtime.block_on(owner.renew_sealed_object_lease(&second, renewed))?;
    if second.expires_at()? != renewed {
        return Err(invalid(
            "whole-file renewal lacks its synchronized deadline",
        ));
    }

    runtime.block_on(published.close_resident_reads(owner))?;
    runtime.block_on(published.finish_retired_sources(owner))?;
    runtime
        .block_on(published.into_cache(owner))
        .map_err(io::Error::other)?;
    check_backing(&other_backing, INLINE, inode)?;
    drop(other_backing);
    let cached = second.backing()?;
    check_backing(&cached, INLINE, inode)?;
    emit(
        "PASS actual whole inline inode, bounded backing ownership, held-policy access, renewal, release and independent cache handoff",
    )?;

    let data = manifest_publication::data(false, false)?;
    let (admission, _, _, _) =
        manifest_publication::admit_manifest_retained(owner, runtime, &data)?;
    if runtime
        .block_on(owner.pin_resident_metadata(data.identity.clone(), expires))
        .is_ok()
    {
        return Err(invalid("producer metadata bypassed consumer cache handoff"));
    }
    runtime
        .block_on(admission.into_cache(owner))
        .map_err(io::Error::other)?;
    let metadata = runtime.block_on(owner.pin_resident_metadata(data.identity.clone(), expires))?;
    if metadata.read_verified()? != data.canonical
        || runtime
            .block_on(owner.pin_sealed_object(data.identity.clone(), expires))
            .is_ok()
    {
        return Err(invalid(
            "metadata-only admission became a whole-file descriptor",
        ));
    }
    for (plaintext, encoded, position) in [
        (
            &data.first,
            data.encoded_first.clone(),
            ChunkPosition::NonFinal,
        ),
        (
            &data.tail,
            [vec![0], data.tail.clone()].concat(),
            ChunkPosition::Final,
        ),
    ] {
        let chunk = identity(IdentityKind::Chunk, plaintext)?;
        let descriptor =
            Descriptor::from_identity(&TERRANE_V1, &chunk, plaintext).map_err(io::Error::other)?;
        runtime
            .block_on(owner.admit_chunk(descriptor, position, encoded))
            .map_err(io::Error::other)?;
    }
    let assembled = runtime
        .block_on(owner.publish_manifest(data.identity.clone()))
        .map_err(io::Error::other)?;
    let object = runtime.block_on(owner.pin_sealed_object(data.identity.clone(), expires))?;
    let whole = object.backing()?;
    check_backing(
        &whole,
        &data.plaintext,
        assembled.handle().metadata()?.ino(),
    )?;
    let first_chunk = identity(IdentityKind::Chunk, &data.first)?;
    if runtime
        .block_on(owner.pin_sealed_object(first_chunk, expires))
        .is_ok()
        || metadata.read_verified()? != data.canonical
    {
        return Err(invalid(
            "a chunk range or metadata grant became an assembled object",
        ));
    }

    let short_deadline = deadline(3)?;
    let short = runtime.block_on(owner.pin_sealed_object(data.identity.clone(), short_deadline))?;
    let retained = short.backing()?;
    runtime.block_on(TokioClock.sleep(Duration::from_secs(
        short_deadline.saturating_sub(now()?) + 1,
    )))?;
    if short.backing().is_ok()
        || runtime
            .block_on(owner.renew_sealed_object_lease(&short, deadline(90)?))
            .is_ok()
    {
        return Err(invalid(
            "expired whole-file grant issued or renewed backing",
        ));
    }
    check_backing(
        &retained,
        &data.plaintext,
        assembled.handle().metadata()?.ino(),
    )?;
    drop(retained);
    if short.backing().is_ok() {
        return Err(invalid("closing an expired backing reopened its grant"));
    }
    runtime.block_on(owner.release_sealed_object_lease(&object))?;
    check_backing(
        &whole,
        &data.plaintext,
        assembled.handle().metadata()?.ino(),
    )?;
    drop(whole);
    runtime.block_on(owner.release_sealed_object_lease(&second))?;
    check_backing(&cached, INLINE, inode)?;
    drop(cached);
    runtime.block_on(owner.release_consumer_lease(&alias))?;
    runtime.block_on(owner.release_consumer_lease(&metadata))?;
    emit(
        "PASS actual whole manifest inode, metadata/range refusal, expiry and retained delegated descriptor lifetime",
    )
}

fn check_backing(backing: &NativeSealedBacking, expected: &[u8], inode: u64) -> io::Result<()> {
    let file = File::from(backing.as_fd().try_clone_to_owned()?);
    let metadata = file.metadata()?;
    let flags = rustix::fs::fcntl_getfl(&file)?;
    if metadata.ino() != inode
        || metadata.len() != expected.len() as u64
        || !rustix::io::fcntl_getfd(backing)?.contains(rustix::io::FdFlags::CLOEXEC)
        || flags.intersects(
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR | rustix::fs::OFlags::PATH,
        )
    {
        return Err(invalid(
            "consumer descriptor differs from the original read-only whole inode",
        ));
    }
    terrane_linux::verity::measure(&file)?;
    let mut actual = vec![0; expected.len()];
    file.read_exact_at(&mut actual, 0)?;
    if actual != expected {
        return Err(invalid(
            "whole-file consumer descriptor returned different bytes",
        ));
    }
    Ok(())
}

fn identity(kind: IdentityKind, bytes: &[u8]) -> io::Result<Identity> {
    TERRANE_V1.calculate(kind, bytes).map_err(io::Error::other)
}

fn now() -> io::Result<u64> {
    TokioClock
        .now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(io::Error::other)
}

fn deadline(seconds: u64) -> io::Result<u64> {
    now()?
        .checked_add(seconds)
        .ok_or_else(|| invalid("native deadline overflow"))
}

fn emit(message: &str) -> io::Result<()> {
    println!("{message}");
    io::stdout().flush()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
