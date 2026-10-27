//! Exercises a data pack whose nested dictionary records live in another pair.

use super::*;

/// Checks both actual pairs, funding, source handoff and original consumer reads.
///
/// # Errors
/// Refuses failed admission, changed original backing, accounting or reads.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let (_, chunks) = fixture()?;
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let dictionaries: BTreeMap<terrane_format::identity::Digest, Vec<u8>> = BTreeMap::from([(
        descriptor(&chunks[0].plaintext)?
            .digest()
            .try_into()
            .map_err(io::Error::other)?,
        chunks[0].plaintext.clone(),
    )]);
    let decoder = NativeBodyDecoder::new(&profile, &dictionaries);
    let source_id = PackId::from_random_bytes([122; 16]);
    let mut writer = PackWriter::new(source_id, PackClass::Data, false);
    for chunk in &chunks[..2] {
        writer
            .append_chunk(
                descriptor(&chunk.plaintext)?
                    .digest()
                    .try_into()
                    .map_err(io::Error::other)?,
                &chunk.encoded,
                u32::try_from(chunk.plaintext.len()).map_err(io::Error::other)?,
                0,
                &decoder,
            )
            .map_err(io::Error::other)?;
    }
    let source_pair = writer.seal().map_err(io::Error::other)?;
    let dependent_pair = external_dictionary(&chunks)?;
    let dependent_id = PackId::from_random_bytes([121; 16]);
    let source_hash = TERRANE_V1
        .calculate(IdentityKind::Pack, source_pair.bytes())
        .map_err(io::Error::other)?;
    let dependent_hash = TERRANE_V1
        .calculate(IdentityKind::Pack, dependent_pair.bytes())
        .map_err(io::Error::other)?;
    let middle = descriptor(&chunks[1].plaintext)?;
    let root = descriptor(&chunks[2].plaintext)?;
    let source_hold = hold(
        source_pair.bytes().len() + source_pair.index_object().len(),
        [
            hex(descriptor(&chunks[0].plaintext)?.digest()),
            hex(middle.digest()),
            hex(source_hash.digest()),
        ],
    )?;
    let source = runtime
        .block_on(owner.admit_data_pack(
            source_id,
            source_pair.bytes().to_vec(),
            source_pair.index_object().to_vec(),
        ))
        .map_err(io::Error::other)?;
    check_state(runtime, inputs, std::slice::from_ref(&source_hold))?;
    let dependent_hold = hold(
        dependent_pair.bytes().len() + dependent_pair.index_object().len(),
        [
            hex(root.digest()),
            hex(dependent_hash.digest()),
            hex(middle.digest()),
            hex(source_hash.digest()),
        ],
    )?;
    let dependent = runtime
        .block_on(owner.admit_data_pack(
            dependent_id,
            dependent_pair.bytes().to_vec(),
            dependent_pair.index_object().to_vec(),
        ))
        .map_err(io::Error::other)?;
    check_state(runtime, inputs, &[source_hold, dependent_hold])?;
    let mut originals = Vec::new();
    for (id, pair, receipt) in [
        (source_id, &source_pair, &source),
        (dependent_id, &dependent_pair, &dependent),
    ] {
        let prefix = format!("objects/pack/{:02x}/{id}", id.as_bytes()[0]);
        let pack = PathBuf::from(format!("{prefix}.pack"));
        let index = PathBuf::from(format!("{prefix}.idx"));
        let (pack_bytes, _) = canonical(inputs, &pack, pair.bytes())?;
        let (index_bytes, _) = canonical(inputs, &index, pair.index_object())?;
        if receipt.synchronized_pair_bytes() != pack_bytes + index_bytes {
            return Err(invalid(
                "cross-pack receipt differs from actual original pair",
            ));
        }
        originals.push((pack, pair.bytes()));
        originals.push((index, pair.index_object()));
    }
    emit("READY cross-pack dictionary graph retains two funded original pairs")?;
    control("handoff-cross-pack")?;
    runtime
        .block_on(dependent.into_cache(owner))
        .map_err(io::Error::other)?;
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &chunks[2].plaintext)
        .map_err(io::Error::other)?;
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| invalid("cross-pack consumer expiry overflow"))?;
    let lease = runtime.block_on(owner.pin_resident_chunk(identity.clone(), expires))?;
    if lease.read_verified()? != chunks[2].plaintext || lease.read_encoded()? != chunks[2].encoded {
        return Err(invalid(
            "cross-pack read lost its producer-held original dictionary",
        ));
    }
    // Keep the same consumer alive while the dictionary pair changes protection.
    runtime
        .block_on(source.into_cache(owner))
        .map_err(io::Error::other)?;
    if lease.read_verified()? != chunks[2].plaintext {
        return Err(invalid(
            "source handoff invalidated the retained cross-pack consumer",
        ));
    }
    runtime.block_on(owner.release_consumer_lease(&lease))?;
    drop(lease);
    let lease = runtime.block_on(owner.pin_resident_chunk(identity, expires))?;
    if lease.read_verified()? != chunks[2].plaintext {
        return Err(invalid(
            "new cross-pack consumer lost cached original dictionaries",
        ));
    }
    runtime.block_on(owner.release_consumer_lease(&lease))?;
    drop(lease);
    for (relative, bytes) in originals {
        canonical(inputs, &relative, bytes)?;
    }
    if fs::read_dir(inputs.root.join("chunks"))?.next().is_some()
        || fs::read_dir(inputs.root.join("pending-delete"))?
            .next()
            .is_some()
    {
        return Err(invalid(
            "cross-pack read extracted or retired original members",
        ));
    }
    emit("READY cross-pack reads retain original pairs through dictionary cache handoff")?;
    control("cross-pack-observed")?;
    emit(
        "PASS actual cross-pack dictionary reads retain both original pairs through producer and cache handoff without extraction; no Ready",
    )
}
