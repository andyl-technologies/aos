//! Exercises cold canonical encodings through genuine recovery and consumer pins.

use super::*;
use std::{os::unix::fs::MetadataExt, time::UNIX_EPOCH};
use terrane_sdk::store::Clock;

struct Chunk {
    bytes: Vec<u8>,
    encoded: Vec<u8>,
}

fn chunks() -> io::Result<Vec<Chunk>> {
    let mut random = 0x9e3779b97f4a7c15_u64;
    let dictionary: Vec<u8> = (0..8192)
        .map(|_| {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            random as u8
        })
        .collect();
    let dependent = [dictionary.as_slice(), b"independent dependent suffix"].concat();
    let compressed = vec![b'z'; 32768];
    let mut result = Vec::new();
    for (bytes, dictionary) in [
        (b"cold raw canonical chunk".to_vec(), None),
        (compressed, None),
        (dictionary.clone(), None),
        (dependent, Some(dictionary.as_slice())),
    ] {
        let encoded = terrane_sdk::codec::encode_chunk(&bytes, 2 * 1024 * 1024, 3, dictionary)
            .map_err(io::Error::other)?;
        result.push(Chunk { bytes, encoded });
    }
    if result
        .iter()
        .map(|chunk| chunk.encoded[0])
        .collect::<Vec<_>>()
        != [0, 1, 0, 2]
    {
        return Err(invalid(
            "cold encoding fixture lacks raw, Zstd and dictionary envelopes",
        ));
    }
    Ok(result)
}

fn path(inputs: &Inputs, chunk: &Chunk, codec: u8) -> io::Result<std::path::PathBuf> {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &chunk.bytes)
        .map_err(io::Error::other)?;
    let hash: String = identity
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(inputs
        .root
        .join("chunks")
        .join(&hash[..2])
        .join(format!("{hash}.{codec}")))
}

fn metadata_pair(data_pack: bool) -> io::Result<terrane_sdk::pack::SealedPack> {
    let id = PackId::from_random_bytes([117; 16]);
    let class = if data_pack {
        PackClass::Data
    } else {
        PackClass::Meta
    };
    let mut writer = PackWriter::new(id, class, false);
    if data_pack {
        writer
            .append_raw(EntryKind::Chunk, b"unadmitted data pack dictionary")
            .map_err(io::Error::other)?;
    } else {
        let data = super::super::manifest_publication::data(false, false)?;
        writer
            .append_raw(EntryKind::Manifest, &data.canonical)
            .map_err(io::Error::other)?;
    }
    writer.seal().map_err(io::Error::other)
}

fn metadata_paths(inputs: &Inputs) -> [std::path::PathBuf; 2] {
    let id = PackId::from_random_bytes([117; 16]);
    let parent = inputs
        .root
        .join(format!("objects/pack/{:02x}", id.as_bytes()[0]));
    [
        parent.join(format!("{id}.idx")),
        parent.join(format!("{id}.pack")),
    ]
}

/// Seeds untrusted canonical encodings under explicit root administration.
///
/// # Errors
/// Refuses missing native project inheritance or an invalid fixture envelope.
pub(crate) fn seed() -> io::Result<()> {
    let inputs = Inputs::load()?;
    let chunks = if inputs.domain == "tenant:encoded-metadata-only" {
        Vec::new()
    } else {
        chunks()?
    };
    for chunk in &chunks {
        let file = path(&inputs, chunk, chunk.encoded[0])?;
        let parent = file
            .parent()
            .ok_or_else(|| invalid("missing chunk shard"))?;
        if !parent.exists() {
            directory(parent, 840, 845, 0o2770)?;
        }
        let mut bytes = chunk.encoded.clone();
        if inputs.domain == "tenant:encoded-corrupt" && chunk.encoded[0] == 0 {
            bytes.push(b'!');
        }
        write(&inputs, &file, &bytes, 840, 845, 0o640)?;
    }
    if matches!(
        inputs.domain.as_str(),
        "tenant:encoded-metadata" | "tenant:encoded-metadata-only" | "tenant:encoded-data-pack"
    ) {
        let pair = metadata_pair(inputs.domain == "tenant:encoded-data-pack")?;
        let [index, pack] = metadata_paths(&inputs);
        let parent = pack
            .parent()
            .ok_or_else(|| invalid("metadata pair shard missing"))?;
        directory(&inputs.root.join("objects/pack"), 840, 845, 0o2770)?;
        directory(parent, 840, 845, 0o2770)?;
        write(&inputs, &index, pair.index_object(), 840, 845, 0o640)?;
        write(&inputs, &pack, pair.bytes(), 840, 845, 0o640)?;
        File::open(parent)?.sync_all()?;
        File::open(inputs.root.join("objects/pack"))?.sync_all()?;
        File::open(inputs.root.join("objects"))?.sync_all()?;
    }
    if inputs.domain == "tenant:encoded-metadata" {
        // Old policy is deliberately just candidate data. Recovery must match
        // this pin to the actual verified pack entry before preserving it.
        let data = super::super::manifest_publication::data(false, false)?;
        let hash: String = data
            .identity
            .digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let policy = format!(
            "version = 1\nresidences = []\n[[pins]]\nowner = \"cold-metadata\"\nhash = \"{hash}\"\nexpires = 9223372036854775807\n[[leases]]\nowner = \"cold-metadata\"\nexpires = 9223372036854775807\n[[reservations]]\nid = \"{}\"\nowner = \"{}\"\nbytes = 262144\n",
            "a".repeat(32),
            inputs.owner_config()?.quota_owner,
        );
        write(
            &inputs,
            &inputs.root.join("state/cache/records.toml"),
            policy.as_bytes(),
            840,
            844,
            0o640,
        )?;
        File::open(inputs.root.join("state/cache"))?.sync_all()?;
    }
    if inputs.domain == "tenant:encoded-duplicate" {
        // This second encoding is valid, so only exclusivity can reject it.
        let chunk = &chunks[1];
        write(
            &inputs,
            &path(&inputs, chunk, 0)?,
            &[vec![0], chunk.bytes.clone()].concat(),
            840,
            845,
            0o640,
        )?;
    }
    if inputs.domain == "tenant:encoded-missing-dictionary" {
        fs::remove_file(path(&inputs, &chunks[2], 0)?)?;
    }
    if inputs.domain == "tenant:encoded-unknown" {
        write(
            &inputs,
            &inputs.root.join("chunks/unrelated"),
            b"unknown",
            840,
            845,
            0o640,
        )?;
    }
    if matches!(
        inputs.domain.as_str(),
        "tenant:encoded-sealed" | "tenant:encoded-old-range"
    ) {
        let canonical = path(&inputs, &chunks[0], 0)?;
        let hash = canonical
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("encoded overlap fixture lacks a canonical hash"))?;
        let parent = inputs.root.join("sealed").join(&hash[..2]);
        directory(&parent, 841, 841, 0o755)?;
        let sealed = parent.join(hash);
        write(&inputs, &sealed, &chunks[0].bytes, 841, 841, 0o400)?;
        let file = File::open(sealed)?;
        terrane_linux::verity::enable(&file)?;
        file.sync_all()?;
        File::open(parent)?.sync_all()?;
        File::open(inputs.root.join("sealed"))?.sync_all()?;
    }
    File::open(inputs.root.join("chunks"))?.sync_all()?;
    println!("SEEDED cold encoded candidates; no recovery or serving authority");
    Ok(())
}

/// Verifies recovery refusal or real post-Resume consumer reads over original inodes.
///
/// # Errors
/// Refuses incorrect acceptance, changed inodes, policy loss or incorrect plaintext.
pub(crate) fn run(
    mode: &str,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let original = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?;
    let recovered = runtime.block_on(owner.recover());
    if mode == "refuse-encoded" {
        if recovered.is_ok() {
            return Err(invalid("unresolved encoded namespace completed recovery"));
        }
        println!("PASS unresolved cold encoding refused; no Resume");
        return Ok(());
    }
    let completed = recovered?;
    completed.check_current()?;
    let chunks = if inputs.domain == "tenant:encoded-metadata-only" {
        Vec::new()
    } else {
        chunks()?
    };
    let inodes = chunks
        .iter()
        .map(|chunk| {
            let metadata = fs::metadata(path(inputs, chunk, chunk.encoded[0])?)?;
            Ok((metadata.dev(), metadata.ino()))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let metadata = if matches!(
        inputs.domain.as_str(),
        "tenant:encoded-metadata" | "tenant:encoded-metadata-only"
    ) {
        metadata_paths(inputs)
            .into_iter()
            .map(|path| {
                let value = fs::metadata(&path)?;
                let bytes = fs::read(&path)?;
                Ok((path, (value.dev(), value.ino()), bytes))
            })
            .collect::<io::Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    let mut retained = BTreeMap::<(u64, u64), usize>::new();
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
    if inodes.iter().any(|inode| retained.get(inode) != Some(&1)) {
        return Err(invalid(
            "cold observations retain hidden source descriptors after Resume",
        ));
    }
    for (path, inode, bytes) in &metadata {
        let value = fs::metadata(path)?;
        if (value.dev(), value.ino()) != *inode
            || fs::read(path)? != *bytes
            || retained.get(inode) != Some(&1)
        {
            return Err(invalid(
                "metadata recovery changed original pair or retained hidden descriptors",
            ));
        }
    }
    if !metadata.is_empty() {
        let snapshot = inputs.root.join("state/cache/records.toml");
        let before = fs::read(&snapshot)?;
        let pack = metadata_pair(false)?;
        let refused = runtime.block_on(owner.admit_metadata_pack(
            PackId::from_random_bytes([117; 16]),
            pack.bytes().to_vec(),
            pack.index_object().to_vec(),
        ));
        if !matches!(refused, Err(terrane_linux::host_cache::NativeMetadataAdmissionError::Accepted(error)) if error.kind() == io::ErrorKind::AlreadyExists)
            || fs::read(snapshot)? != before
        {
            return Err(invalid(
                "recovered metadata failed genuine duplicate registry protection",
            ));
        }
    }
    let expires = terrane_sdk::store::TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| invalid("encoded consumer expiry overflow"))?;
    for (chunk, inode) in chunks.iter().zip(inodes) {
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, &chunk.bytes)
            .map_err(io::Error::other)?;
        let lease = runtime.block_on(owner.pin_resident_chunk(identity, expires))?;
        let metadata = fs::metadata(path(inputs, chunk, chunk.encoded[0])?)?;
        if lease.read_verified()? != chunk.bytes || inode != (metadata.dev(), metadata.ino()) {
            return Err(invalid(
                "recovered encoded consumer changed plaintext or original inode",
            ));
        }
        runtime.block_on(owner.release_consumer_lease(&lease))?;
    }
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("recovered encoded policy missing"))?;
    if !state.residences.is_empty()
        || original.as_ref().is_some_and(|old| {
            old.pins.iter().any(|pin| {
                !state.pins.iter().any(|new| {
                    new.owner == pin.owner && new.hash == pin.hash && new.expires == pin.expires
                })
            }) || old.leases.iter().any(|lease| {
                !state
                    .leases
                    .iter()
                    .any(|new| new.owner == lease.owner && new.expires == lease.expires)
            }) || old.reservations.iter().any(|hold| {
                !state.reservations.iter().any(|new| {
                    new.id == hold.id && new.owner == hold.owner && new.bytes == hold.bytes
                })
            })
        })
    {
        return Err(invalid(
            "encoded recovery lost cold promises or invented sealed residences",
        ));
    }
    if inputs.domain == "tenant:encoded-metadata-only" {
        println!(
            "PASS cold metadata pair recovered; original pair registered after Resume; cold promises preserved; no Ready"
        );
    } else {
        println!(
            "PASS cold raw, Zstd, dictionary and metadata candidates recovered; original inodes served under durable consumer pins; cold promises preserved; no Ready"
        );
    }
    Ok(())
}
