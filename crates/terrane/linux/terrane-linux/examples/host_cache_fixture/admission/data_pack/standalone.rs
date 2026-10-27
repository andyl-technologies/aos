//! Exercises a canonical standalone chunk whose nested dictionaries stay packed.

use super::*;

/// Checks real standalone admission and the same consumer through source handoff.
///
/// # Errors
/// Refuses changed native custody, missing funding or any incorrect original read.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let (_, chunks) = fixture()?;
    let pair = cross_pack::dictionary_pair(&chunks)?;
    let source_id = PackId::from_random_bytes([122; 16]);
    let container = TERRANE_V1
        .calculate(IdentityKind::Pack, pair.bytes())
        .map_err(io::Error::other)?;
    let middle = descriptor(&chunks[1].plaintext)?;
    let root = descriptor(&chunks[2].plaintext)?;
    let source_hold = hold(
        pair.bytes().len() + pair.index_object().len(),
        [
            hex(descriptor(&chunks[0].plaintext)?.digest()),
            hex(middle.digest()),
            hex(container.digest()),
        ],
    )?;
    let source = runtime
        .block_on(owner.admit_data_pack(
            source_id,
            pair.bytes().to_vec(),
            pair.index_object().to_vec(),
        ))
        .map_err(io::Error::other)?;
    check_state(runtime, inputs, std::slice::from_ref(&source_hold))?;

    let root_hold = hold(
        chunks[2].encoded.len(),
        [
            hex(root.digest()),
            hex(middle.digest()),
            hex(container.digest()),
        ],
    )?;
    let dependent = runtime
        .block_on(owner.admit_chunk(
            root.clone(),
            ChunkPosition::Final,
            chunks[2].encoded.clone(),
        ))
        .map_err(io::Error::other)?;
    check_state(runtime, inputs, &[source_hold, root_hold])?;
    let hash = hex(root.digest());
    let body = PathBuf::from(format!("chunks/{}/{hash}.2", &hash[..2]));
    let prefix = format!("objects/pack/7a/{source_id}");
    let pack = PathBuf::from(format!("{prefix}.pack"));
    let index = PathBuf::from(format!("{prefix}.idx"));
    let (body_bytes, _) = canonical(inputs, &body, &chunks[2].encoded)?;
    let (pack_bytes, _) = canonical(inputs, &pack, pair.bytes())?;
    let (index_bytes, _) = canonical(inputs, &index, pair.index_object())?;
    if dependent.synchronized_chunk_bytes() != body_bytes
        || source.synchronized_pair_bytes() != pack_bytes + index_bytes
    {
        return Err(invalid(
            "standalone packed-dictionary receipt changed actual allocation",
        ));
    }
    emit("READY standalone root retains one funded chunk and original dictionary pair")?;
    control("handoff-packed-dictionary")?;

    runtime
        .block_on(dependent.into_cache(owner))
        .map_err(io::Error::other)?;
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Chunk, root.digest())
        .map_err(io::Error::other)?;
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| invalid("standalone consumer expiry overflow"))?;
    let lease = runtime.block_on(owner.pin_resident_chunk(identity.clone(), expires))?;
    if lease.read_verified()? != chunks[2].plaintext || lease.read_encoded()? != chunks[2].encoded {
        return Err(invalid(
            "standalone consumer lost producer-held packed dictionaries",
        ));
    }
    runtime
        .block_on(source.into_cache(owner))
        .map_err(io::Error::other)?;
    if lease.read_verified()? != chunks[2].plaintext || lease.read_encoded()? != chunks[2].encoded {
        return Err(invalid(
            "dictionary handoff invalidated the original standalone consumer",
        ));
    }
    runtime.block_on(owner.release_consumer_lease(&lease))?;
    drop(lease);
    let lease = runtime.block_on(owner.pin_resident_chunk(identity, expires))?;
    if lease.read_verified()? != chunks[2].plaintext || lease.read_encoded()? != chunks[2].encoded {
        return Err(invalid(
            "new standalone consumer lost cached packed dictionaries",
        ));
    }
    runtime.block_on(owner.release_consumer_lease(&lease))?;
    drop(lease);
    canonical(inputs, &body, &chunks[2].encoded)?;
    canonical(inputs, &pack, pair.bytes())?;
    canonical(inputs, &index, pair.index_object())?;
    emit("READY standalone reads preserve original packed dictionaries across cache handoff")?;
    control("packed-dictionary-observed")?;
    emit(
        "PASS actual standalone consumers retain original nested packed dictionaries through producer and cache handoff without extraction; no Ready",
    )
}
