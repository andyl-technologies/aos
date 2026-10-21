//! Exercises actual shared-chunk extraction, protected eviction and final closure.

use super::*;
use terrane_linux::host_cache::{NativeCacheEvictionReport, NativeConsumerLease};
use terrane_sdk::store::{Clock, TokioClock};

/// Keeps one real owner and independent consumers alive through body eviction.
///
/// # Errors
/// Refuses invented residence transitions, lost consumers, premature deletion,
/// missing original cleanup or accounting that claims early quota reclamation.
pub(crate) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    if inputs.domain != "tenant:shared-reextract" {
        return Err(invalid("shared extraction requires its dedicated domain"));
    }
    let first = data(false, false)?;
    let second = data_with_tail(false, false, 100)?;
    let completed = runtime.block_on(owner.recover())?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    admit(
        owner,
        runtime,
        &first.first,
        ChunkPosition::NonFinal,
        first.encoded_first.clone(),
    )?;
    admit(
        owner,
        runtime,
        &first.tail,
        ChunkPosition::Final,
        [vec![0], first.tail.clone()].concat(),
    )?;
    let (first_metadata, ..) = admit_manifest_retained(owner, runtime, &first)?;
    let original = runtime.block_on(owner.publish_manifest(first.identity.clone()))?;
    admit(
        owner,
        runtime,
        &second.tail,
        ChunkPosition::Final,
        [vec![0], second.tail.clone()].concat(),
    )?;
    let (other_metadata, ..) = admit_manifest_retained(owner, runtime, &second)?;
    let other = runtime.block_on(owner.publish_manifest(second.identity.clone()))?;
    let inode = original.handle().metadata()?;
    emit(&format!(
        "SHARED_EXTRACTION_ORIGINAL object={} inode={} bytes={}",
        hex(first.identity.digest()),
        inode.ino(),
        inode.blocks() * 512
    ))?;
    emit("READY shared extraction originals published; wait for source retirement grace")?;
    control("cleanup")?;
    if runtime
        .block_on(original.finish_retired_sources(owner))?
        .completed_sources
        != 2
        || runtime
            .block_on(other.finish_retired_sources(owner))?
            .completed_sources
            != 1
    {
        return Err(invalid("shared extraction lost original source cleanup"));
    }
    let expires = TokioClock
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(300)
        .ok_or_else(|| invalid("shared extraction consumer expiry overflows"))?;
    let protected = pin(owner, runtime, &first.first, expires)?;
    let independent = pin(owner, runtime, &second.tail, expires)?;
    let first_handoff = runtime
        .block_on(original.into_cache(owner))
        .map_err(io::Error::other)?;
    let other_handoff = runtime
        .block_on(other.into_cache(owner))
        .map_err(io::Error::other)?;
    let before = fs::read(policy(inputs))?;
    let refused = pressure(owner, runtime, inputs)?;
    if refused.retired_allocations != 0 || refused.target_met || fs::read(policy(inputs))? != before
    {
        return Err(invalid("pinned shared body changed its actual residence"));
    }
    runtime.block_on(owner.release_consumer_lease(&protected))?;
    // Publishing a body does not relinquish its independent metadata producer.
    // Transfer both original receipts before expecting either object to evict;
    // their retained reconstruction pins continue to protect the actual pairs.
    let first_metadata_handoff = runtime
        .block_on(first_metadata.into_cache(owner))
        .map_err(io::Error::other)?;
    let other_metadata_handoff = runtime
        .block_on(other_metadata.into_cache(owner))
        .map_err(io::Error::other)?;
    let state = load(runtime, inputs)?;
    let grace = state
        .pins
        .iter()
        .filter(|pin| pin.owner.starts_with("consumer-grace:"))
        .map(|pin| pin.expires)
        .max()
        .unwrap_or(0)
        .max(first_handoff.release_grace_ends_at)
        .max(other_handoff.release_grace_ends_at)
        .max(first_metadata_handoff.release_grace_ends_at)
        .max(other_metadata_handoff.release_grace_ends_at);
    emit(&format!("SHARED_EXTRACTION_GRACE expires={grace}"))?;
    emit("READY pinned shared eviction refused; original body and range retained")?;
    control("extract")?;
    let before = runtime.block_on(owner.evict_cached(0))?;
    let extracted = pressure(owner, runtime, inputs)?;
    let chunk = hex(TERRANE_V1
        .calculate(IdentityKind::Chunk, &first.first)
        .map_err(io::Error::other)?
        .digest());
    let standalone = inputs
        .root
        .join("chunks")
        .join(&chunk[..2])
        .join(format!("{chunk}.0"));
    let after = load(runtime, inputs)?;
    let object = hex(first.identity.digest());
    emit(&format!(
        "SHARED_EXTRACTION_MEASUREMENT retired={} target_met={} charged_before={} charged_after={} future_before={} future_after={}",
        extracted.retired_allocations,
        extracted.target_met,
        before.charged_reserved_bytes,
        extracted.charged_reserved_bytes,
        before.future_hold_bytes,
        extracted.future_hold_bytes,
    ))?;
    if extracted.retired_allocations != 0 || extracted.target_met {
        return Err(invalid(
            "shared extraction retired an allocation or claimed its pressure target",
        ));
    }
    if extracted.charged_reserved_bytes <= before.charged_reserved_bytes {
        return Err(invalid(
            "shared extraction lacks measured replacement allocation",
        ));
    }
    if extracted.future_hold_bytes != before.future_hold_bytes {
        return Err(invalid("shared extraction changed retained future holds"));
    }
    if fs::read(&standalone)? != [vec![0], first.first.clone()].concat() {
        return Err(invalid(
            "shared extraction replacement differs from verified original bytes",
        ));
    }
    if after.residences.iter().any(|row| row.chunk == chunk) {
        return Err(invalid(
            "shared extraction retained a duplicate sealed residence",
        ));
    }
    if !after.residences.iter().any(|row| row.object == object) {
        return Err(invalid(
            "shared extraction lost the original body's other residence",
        ));
    }
    let replacement = pin(owner, runtime, &first.first, expires)?;
    check_reads(owner, runtime, &replacement, &independent, &first, &second)?;
    // Reconstruction metadata intentionally retains a permanent object pin.
    // The replacement's actual handoff instead pins both chunk and object
    // under one finite admission grace and its matching durable lease.
    let mut graces = after.pins.iter().filter(|pin| {
        pin.hash == object
            && pin.owner.starts_with("admission-grace:")
            && after.pins.iter().any(|replacement| {
                replacement.hash == chunk
                    && replacement.owner == pin.owner
                    && replacement.expires == pin.expires
            })
    });
    let grace = graces
        .next()
        .ok_or_else(|| invalid("extraction lost original object's release grace"))?;
    let deadline = grace.expires;
    if graces.next().is_some()
        || deadline > expires
        || after
            .leases
            .iter()
            .filter(|lease| lease.owner == grace.owner && lease.expires == deadline)
            .count()
            != 1
    {
        return Err(invalid(
            "extraction has no unique finite copy handoff grace",
        ));
    }
    emit(&format!(
        "SHARED_EXTRACTION_COPY chunk={chunk} object={object} expires={deadline}"
    ))?;
    emit(
        "READY verified standalone replacement and independent consumers; original body still charged",
    )?;
    control("retire")?;
    let retired = pressure(owner, runtime, inputs)?;
    if retired.retired_allocations != 1 || retired.target_met {
        return Err(invalid(
            "shared extraction did not retire exactly its original body",
        ));
    }
    emit(
        "READY original shared body pending deletion; replacement and independent consumer retained",
    )?;
    control("deleted")?;
    runtime.block_on(owner.evict_cached(0))?;
    let state = load(runtime, inputs)?;
    if inputs
        .root
        .join("sealed")
        .join(&object[..2])
        .join(&object)
        .exists()
        || state.residences.iter().any(|row| row.object == object)
    {
        return Err(invalid(
            "retired shared body retains its original canonical residence",
        ));
    }
    check_reads(owner, runtime, &replacement, &independent, &first, &second)?;
    emit("READY original shared body removed; real consumers remain readable with policy held")?;
    control("finish")?;
    runtime.block_on(owner.release_consumer_lease(&replacement))?;
    runtime.block_on(owner.release_consumer_lease(&independent))?;
    emit(
        "PASS actual shared-chunk re-extraction preserves one residence, durable grace, independent consumers and final original descriptor closure; no Ready",
    )
}

fn pin(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    bytes: &[u8],
    expires: u64,
) -> io::Result<NativeConsumerLease> {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, bytes)
        .map_err(io::Error::other)?;
    runtime.block_on(owner.pin_resident_chunk(identity, expires))
}

fn check_reads(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    replacement: &NativeConsumerLease,
    independent: &NativeConsumerLease,
    first: &Data,
    second: &Data,
) -> io::Result<()> {
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    if replacement.read_verified()? != first.first || independent.read_verified()? != second.tail {
        return Err(invalid(
            "shared extraction invalidated an independent consumer",
        ));
    }
    drop(stalled);
    Ok(())
}

fn pressure(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<NativeCacheEvictionReport> {
    let actual = runtime.block_on(owner.evict_cached(0))?;
    let total = actual
        .charged_reserved_bytes
        .checked_add(actual.future_hold_bytes)
        .ok_or_else(|| invalid("shared extraction pressure overflows"))?;
    let incoming = inputs
        .owner_config()?
        .policy
        .capacity
        .checked_sub(total)
        .and_then(|free| free.checked_add(1))
        .ok_or_else(|| invalid("shared extraction already exceeds capacity"))?;
    runtime.block_on(owner.evict_cached(incoming))
}

fn policy(inputs: &Inputs) -> std::path::PathBuf {
    inputs.root.join("state/cache/records.toml")
}

fn load(runtime: &tokio::runtime::Runtime, inputs: &Inputs) -> io::Result<CacheState> {
    runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("shared extraction policy missing"))
}
