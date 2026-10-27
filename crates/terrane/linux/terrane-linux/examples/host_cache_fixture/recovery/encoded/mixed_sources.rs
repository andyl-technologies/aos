//! Exercises cold dictionary custody alternating original pairs and chunks.
//!
//! Explicit administration seeds six untrusted native inodes. A separate
//! confined actor must recover and Resume before it can read any source.

use super::*;
use std::path::PathBuf;

/// Identifies the dedicated alternating-source native scenario.
pub(super) fn selected(inputs: &Inputs) -> bool {
    inputs.domain == "tenant:encoded-mixed-sources"
}

fn chain() -> io::Result<Vec<Chunk>> {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let plaintexts = [
        b"mixed cold terminal vocabulary ".repeat(16),
        b"mixed cold terminal vocabulary intermediate ".repeat(64),
        b"mixed cold terminal vocabulary intermediate packed ".repeat(128),
        b"mixed cold terminal vocabulary intermediate packed root ".repeat(256),
    ];
    let mut chunks = Vec::new();
    for (position, bytes) in plaintexts.iter().enumerate() {
        let encoded = if position == 0 {
            [vec![0], bytes.clone()].concat()
        } else {
            terrane_sdk::codec::encode_chunk(
                bytes,
                profile.maximum(),
                3,
                Some(&plaintexts[position - 1]),
            )
            .map_err(io::Error::other)?
        };
        if position > 0 && encoded.first() != Some(&2) {
            return Err(invalid(
                "mixed cold fixture lacks its original dictionary chain",
            ));
        }
        chunks.push(Chunk {
            bytes: bytes.clone(),
            encoded,
        });
    }
    Ok(chunks)
}

fn pair(chunks: &[Chunk], position: usize, id: u8) -> io::Result<terrane_sdk::pack::SealedPack> {
    let dictionaries = chunks
        .iter()
        .map(|chunk| {
            let identity = TERRANE_V1
                .calculate(IdentityKind::Chunk, &chunk.bytes)
                .map_err(io::Error::other)?;
            Ok((
                identity.terrane_v1_digest().map_err(io::Error::other)?,
                chunk.bytes.clone(),
            ))
        })
        .collect::<io::Result<BTreeMap<_, _>>>()?;
    let chunk = chunks
        .get(position)
        .ok_or_else(|| invalid("mixed cold record is absent"))?;
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let decoder = NativeBodyDecoder::new(&profile, &dictionaries);
    let mut writer = PackWriter::new(PackId::from_random_bytes([id; 16]), PackClass::Data, false);
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &chunk.bytes)
        .map_err(io::Error::other)?;
    writer
        .append_chunk(
            identity.terrane_v1_digest().map_err(io::Error::other)?,
            &chunk.encoded,
            u32::try_from(chunk.bytes.len()).map_err(io::Error::other)?,
            0,
            &decoder,
        )
        .map_err(io::Error::other)?;
    writer.seal().map_err(io::Error::other)
}

fn original_paths(inputs: &Inputs, chunks: &[Chunk]) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for id in [123, 124] {
        paths.extend(paths_for_id(inputs, PackId::from_random_bytes([id; 16])));
    }
    for position in [1, 3] {
        let chunk = chunks
            .get(position)
            .ok_or_else(|| invalid("mixed cold chunk is absent"))?;
        paths.push(path(inputs, chunk, 2)?);
    }
    Ok(paths)
}

/// Seeds the original chain with the dependent pair sorting before its source.
///
/// # Errors
/// Refuses invalid fixture encodings, native writes or directory synchronization.
pub(super) fn seed(inputs: &Inputs) -> io::Result<()> {
    let chunks = chain()?;
    directory(&inputs.root.join("objects/pack"), 840, 845, 0o2770)?;
    for (position, id) in [(0, 124), (2, 123)] {
        let pair = pair(&chunks, position, id)?;
        let [index, pack] = paths_for_id(inputs, PackId::from_random_bytes([id; 16]));
        let parent = pack
            .parent()
            .ok_or_else(|| invalid("mixed cold shard is absent"))?;
        if !parent.exists() {
            directory(parent, 840, 845, 0o2770)?;
        }
        write(inputs, &index, pair.index_object(), 840, 845, 0o640)?;
        write(inputs, &pack, pair.bytes(), 840, 845, 0o640)?;
        File::open(parent)?.sync_all()?;
    }
    for position in [1, 3] {
        let chunk = &chunks[position];
        let target = path(inputs, chunk, 2)?;
        let parent = target
            .parent()
            .ok_or_else(|| invalid("mixed cold chunk shard is absent"))?;
        if !parent.exists() {
            directory(parent, 840, 845, 0o2770)?;
        }
        write(inputs, &target, &chunk.encoded, 840, 845, 0o640)?;
        File::open(parent)?.sync_all()?;
    }
    for directory in ["objects/pack", "objects", "chunks"] {
        File::open(inputs.root.join(directory))?.sync_all()?;
    }
    println!("SEEDED cold encoded candidates; no recovery or serving authority");
    Ok(())
}

fn descriptor_counts() -> io::Result<BTreeMap<(u64, u64), usize>> {
    let mut retained = BTreeMap::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        let metadata = match fs::metadata(entry?.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        *retained
            .entry((metadata.dev(), metadata.ino()))
            .or_default() += 1;
    }
    Ok(retained)
}

/// Recovers and reads every original source without retaining inspection handles.
///
/// # Errors
/// Refuses failed recovery or Resume, changed original sources, incorrect reads,
/// hidden inspection descriptors and lost cold policy.
pub(super) fn run(
    mode: &str,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    if mode != "recover-encoded" {
        return Err(invalid("mixed cold sources require actual recovery"));
    }
    let chunks = chain()?;
    let paths = original_paths(inputs, &chunks)?;
    let originals = paths
        .iter()
        .map(|path| {
            let metadata = fs::metadata(path)?;
            Ok(((metadata.dev(), metadata.ino()), fs::read(path)?))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let old = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("mixed cold promises are absent"))?;
    let completed = runtime.block_on(owner.recover())?;
    completed.check_current()?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    let retained = descriptor_counts()?;
    if originals
        .iter()
        .any(|(inode, _)| retained.get(inode) != Some(&1))
    {
        return Err(invalid("mixed cold inspection descriptors survived Resume"));
    }

    let expires = terrane_sdk::store::TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| invalid("mixed cold consumer expiry overflow"))?;
    for chunk in &chunks {
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, &chunk.bytes)
            .map_err(io::Error::other)?;
        let lease = runtime.block_on(owner.pin_resident_chunk(identity, expires))?;
        if lease.read_verified()? != chunk.bytes || lease.read_encoded()? != chunk.encoded {
            return Err(invalid(
                "mixed cold consumer changed its original dictionary source",
            ));
        }
        runtime.block_on(owner.release_consumer_lease(&lease))?;
    }
    if standalone_count(inputs)? != 2 {
        return Err(invalid("mixed cold recovery extracted packed dictionaries"));
    }
    for (path, (inode, bytes)) in paths.iter().zip(&originals) {
        let metadata = fs::metadata(path)?;
        if (metadata.dev(), metadata.ino()) != *inode || fs::read(path)? != *bytes {
            return Err(invalid(
                "mixed cold recovery replaced original native backing",
            ));
        }
    }
    let current = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("mixed cold policy is absent"))?;
    if !current.residences.is_empty()
        || old.pins.iter().any(|pin| {
            !current.pins.iter().any(|row| {
                row.owner == pin.owner && row.hash == pin.hash && row.expires == pin.expires
            })
        })
        || old.leases.iter().any(|lease| {
            !current
                .leases
                .iter()
                .any(|row| row.owner == lease.owner && row.expires == lease.expires)
        })
        || old.reservations.iter().any(|hold| {
            !current
                .reservations
                .iter()
                .any(|row| row.id == hold.id && row.owner == hold.owner && row.bytes == hold.bytes)
        })
    {
        return Err(invalid("mixed cold recovery lost original promises"));
    }
    println!(
        "PASS cold mixed-source recovery imports pair chunk pair chunk in original dependency order, releases inspection descriptors and serves exact original encodings without extraction; no Ready"
    );
    Ok(())
}
