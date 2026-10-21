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

/// Seeds untrusted canonical encodings under explicit root administration.
///
/// # Errors
/// Refuses missing native project inheritance or an invalid fixture envelope.
pub(crate) fn seed() -> io::Result<()> {
    let inputs = Inputs::load()?;
    let chunks = chunks()?;
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
    let chunks = chunks()?;
    let inodes = chunks
        .iter()
        .map(|chunk| {
            let metadata = fs::metadata(path(inputs, chunk, chunk.encoded[0])?)?;
            Ok((metadata.dev(), metadata.ino()))
        })
        .collect::<io::Result<Vec<_>>>()?;
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
    println!(
        "PASS cold raw, Zstd and dictionary encodings recovered; original inodes served under durable consumer pins; cold promises preserved; no Ready"
    );
    Ok(())
}
