//! Exercises cold canonical encodings through genuine recovery and consumer pins.

#[path = "encoded/mixed_sources.rs"]
mod mixed_sources;

use super::*;
use std::{io::Seek, os::unix::fs::MetadataExt, time::UNIX_EPOCH};
use terrane_linux::host_cache::{NativeRecoveryInspector, VerifiedEncodedBody};
use terrane_sdk::pack::NativeBodyDecoder;
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

fn packed_chunks() -> io::Result<Vec<Chunk>> {
    let terminal = b"packed terminal vocabulary ".repeat(16);
    let middle = b"packed terminal vocabulary intermediate ".repeat(64);
    let root = b"packed terminal vocabulary intermediate content ".repeat(128);
    let maximum = ChunkProfile::cdc_1m([0; 32]).maximum();
    let terminal_encoded = [vec![0], terminal.clone()].concat();
    let middle_encoded = terrane_sdk::codec::encode_chunk(&middle, maximum, 3, Some(&terminal))
        .map_err(io::Error::other)?;
    let root_encoded = terrane_sdk::codec::encode_chunk(&root, maximum, 3, Some(&middle))
        .map_err(io::Error::other)?;
    if middle_encoded[0] != 2 || root_encoded[0] != 2 {
        return Err(invalid("packed fixture lacks nested dictionary envelopes"));
    }
    Ok(vec![
        Chunk {
            bytes: terminal,
            encoded: terminal_encoded,
        },
        Chunk {
            bytes: middle,
            encoded: middle_encoded,
        },
        Chunk {
            bytes: root,
            encoded: root_encoded,
        },
    ])
}

enum PackFixture {
    Metadata,
    ClosedData,
    ExternalData,
    DictionaryData,
}

fn metadata_pair(fixture: PackFixture) -> io::Result<terrane_sdk::pack::SealedPack> {
    let id_byte = if matches!(fixture, PackFixture::DictionaryData) {
        118
    } else {
        117
    };
    let id = PackId::from_random_bytes([id_byte; 16]);
    let class = match fixture {
        PackFixture::Metadata => PackClass::Meta,
        PackFixture::ClosedData | PackFixture::ExternalData | PackFixture::DictionaryData => {
            PackClass::Data
        }
    };
    let mut writer = PackWriter::new(id, class, false);
    if class == PackClass::Data {
        let chunks = packed_chunks()?;
        let dictionaries = chunks[..2]
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
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let decoder = NativeBodyDecoder::new(&profile, &dictionaries);
        let selected = match fixture {
            PackFixture::ExternalData => &chunks[2..],
            PackFixture::DictionaryData => &chunks[..2],
            _ => chunks.as_slice(),
        };
        for chunk in selected {
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
        }
    } else {
        let data = super::super::manifest_publication::data(false, false)?;
        writer
            .append_raw(EntryKind::Manifest, &data.canonical)
            .map_err(io::Error::other)?;
    }
    writer.seal().map_err(io::Error::other)
}

/// Seeds real standalone dictionary originals before their dependent cold pair.
fn cold_chunks(inputs: &Inputs) -> io::Result<Vec<Chunk>> {
    if inputs.domain == "tenant:encoded-metadata-only"
        || inputs.domain == "tenant:encoded-cross-pack"
        || super::packed_manifest::selected(inputs)
    {
        return Ok(Vec::new());
    }
    let mut chunks = chunks()?;
    if inputs.domain == "tenant:encoded-external-data-pack" {
        chunks.extend(packed_chunks()?.into_iter().take(2));
    }
    Ok(chunks)
}

pub(super) fn pack_paths(inputs: &Inputs) -> [std::path::PathBuf; 2] {
    paths_for_id(inputs, PackId::from_random_bytes([117; 16]))
}

fn paths_for_id(inputs: &Inputs, id: PackId) -> [std::path::PathBuf; 2] {
    let parent = inputs
        .root
        .join(format!("objects/pack/{:02x}", id.as_bytes()[0]));
    [
        parent.join(format!("{id}.idx")),
        parent.join(format!("{id}.pack")),
    ]
}

/// Reads original packed envelopes using genuine drained native inspection.
///
/// # Errors
/// Refuses missing verified custody, changed envelopes, descriptors or cursors,
/// and incorrect missing-entry or wrong-kind refusals. This grants no admission.
pub(crate) fn inspect_pack(inspector: &NativeRecoveryInspector) -> io::Result<()> {
    let inspection = inspector.inspect()?;
    let pack = inspection
        .candidates()
        .iter()
        .find_map(|candidate| match candidate.verified() {
            Some(VerifiedEncodedBody::Pack(pack))
                if pack.pack_id() == PackId::from_random_bytes([117; 16])
                    && candidate.issues().is_empty() =>
            {
                Some(pack)
            }
            _ => None,
        })
        .ok_or_else(|| invalid("actual native data pack was not independently verified"))?;
    let mut file = pack.pack_file();
    let original_cursor = file.stream_position()?;
    file.seek(io::SeekFrom::Start(7))?;
    let original = file.metadata()?;

    for chunk in packed_chunks()? {
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, &chunk.bytes)
            .map_err(io::Error::other)?;
        let (descriptor, encoded) = pack.read_chunk_encoded(&identity)?;
        let verified = descriptor
            .verify_bytes(&TERRANE_V1, IdentityKind::Chunk, &chunk.bytes)
            .map_err(io::Error::other)?;
        if encoded != chunk.encoded || verified != identity || file.stream_position()? != 7 {
            return Err(invalid(
                "packed extraction changed original envelope, descriptor or cursor",
            ));
        }
    }
    for (kind, expected) in [
        (IdentityKind::Chunk, io::ErrorKind::NotFound),
        (IdentityKind::Manifest, io::ErrorKind::InvalidInput),
    ] {
        let identity = TERRANE_V1
            .calculate(kind, b"absent packed entry")
            .map_err(io::Error::other)?;
        let error = pack
            .read_chunk_encoded(&identity)
            .err()
            .ok_or_else(|| invalid("invalid packed selection succeeded"))?;
        if error.kind() != expected || file.stream_position()? != 7 {
            return Err(invalid("packed selection refusal kind or cursor changed"));
        }
    }
    let current = file.metadata()?;
    if (original.dev(), original.ino(), original.len())
        != (current.dev(), current.ino(), current.len())
    {
        return Err(invalid("packed extraction replaced original native source"));
    }
    file.seek(io::SeekFrom::Start(original_cursor))?;
    pack.check_current()?;
    println!(
        "PASS actual verified pack extraction preserves original envelopes, descriptors and cursor without admission or Resume"
    );
    Ok(())
}

/// Seeds untrusted canonical encodings under explicit root administration.
///
/// # Errors
/// Refuses missing native project inheritance or an invalid fixture envelope.
pub(crate) fn seed() -> io::Result<()> {
    let inputs = Inputs::load()?;
    if mixed_sources::selected(&inputs) {
        return mixed_sources::seed(&inputs);
    }
    if super::packed_manifest::selected(&inputs) {
        return super::packed_manifest::seed(&inputs);
    }
    let chunks = cold_chunks(&inputs)?;
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
        "tenant:encoded-metadata"
            | "tenant:encoded-metadata-only"
            | "tenant:encoded-data-pack"
            | "tenant:encoded-external-data-pack"
            | "tenant:encoded-cross-pack"
    ) {
        let fixture = match inputs.domain.as_str() {
            "tenant:encoded-data-pack" => PackFixture::ClosedData,
            "tenant:encoded-external-data-pack" | "tenant:encoded-cross-pack" => {
                PackFixture::ExternalData
            }
            _ => PackFixture::Metadata,
        };
        let pair = metadata_pair(fixture)?;
        let [index, pack] = pack_paths(&inputs);
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
    if inputs.domain == "tenant:encoded-cross-pack" {
        let pair = metadata_pair(PackFixture::DictionaryData)?;
        let [index, pack] = paths_for_id(&inputs, PackId::from_random_bytes([118; 16]));
        let parent = pack
            .parent()
            .ok_or_else(|| invalid("dictionary pair shard absent"))?;
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

fn verify_packed_consumers(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    expires: u64,
) -> io::Result<()> {
    let standalone_before = standalone_count(inputs)?;
    let external = inputs.domain == "tenant:encoded-external-data-pack";
    for chunk in packed_chunks()?
        .into_iter()
        .skip(if external { 2 } else { 0 })
    {
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, &chunk.bytes)
            .map_err(io::Error::other)?;
        let lease = runtime.block_on(owner.pin_resident_chunk(identity, expires))?;
        if lease.read_verified()? != chunk.bytes || lease.read_encoded()? != chunk.encoded {
            return Err(invalid(
                "original data pack did not serve its verified chunk envelope",
            ));
        }
        if path(inputs, &chunk, chunk.encoded[0])?.exists() {
            return Err(invalid(
                "data pack read substituted a standalone extraction",
            ));
        }
        runtime.block_on(owner.release_consumer_lease(&lease))?;
    }
    if standalone_before != standalone_count(inputs)? {
        return Err(invalid(
            "data pack consumers allocated standalone chunk copies",
        ));
    }
    if inputs.domain == "tenant:encoded-cross-pack" {
        println!(
            "PASS cold cross-pack consumers read all original nested records without standalone extraction"
        );
    } else if external {
        println!(
            "PASS cold external data pair serves its original packed root through nested standalone dictionary custody without extraction"
        );
    } else {
        println!(
            "PASS cold data pack serves original raw and nested dictionary envelopes through actual consumer pins without standalone extraction"
        );
    }
    Ok(())
}

fn standalone_count(inputs: &Inputs) -> io::Result<usize> {
    let mut count = 0_usize;
    for shard in fs::read_dir(inputs.root.join("chunks"))? {
        for entry in fs::read_dir(shard?.path())? {
            entry?;
            count = count
                .checked_add(1)
                .ok_or_else(|| invalid("fixture chunk count overflow"))?;
        }
    }
    Ok(count)
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
    if mixed_sources::selected(inputs) {
        return mixed_sources::run(mode, owner, runtime, inputs);
    }
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
    let chunks = cold_chunks(inputs)?;
    let inodes = chunks
        .iter()
        .map(|chunk| {
            let metadata = fs::metadata(path(inputs, chunk, chunk.encoded[0])?)?;
            Ok((metadata.dev(), metadata.ino()))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let metadata = if matches!(
        inputs.domain.as_str(),
        "tenant:encoded-metadata"
            | "tenant:encoded-metadata-only"
            | "tenant:encoded-data-pack"
            | "tenant:encoded-external-data-pack"
            | "tenant:encoded-cross-pack"
    ) {
        let mut paths = pack_paths(inputs).to_vec();
        if inputs.domain == "tenant:encoded-cross-pack" {
            paths.extend(paths_for_id(inputs, PackId::from_random_bytes([118; 16])));
        }
        paths
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
    if super::packed_manifest::selected(inputs) {
        return super::packed_manifest::run(owner, runtime, inputs);
    }
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
        let pack = metadata_pair(PackFixture::Metadata)?;
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
    if matches!(
        inputs.domain.as_str(),
        "tenant:encoded-data-pack"
            | "tenant:encoded-external-data-pack"
            | "tenant:encoded-cross-pack"
    ) {
        verify_packed_consumers(owner, runtime, inputs, expires)?;
    }
    let mut retained_consumers = Vec::new();
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
        if inputs.domain == "tenant:encoded-data-pack" {
            retained_consumers.push(lease);
        } else {
            runtime.block_on(owner.release_consumer_lease(&lease))?;
        }
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
    if inputs.domain == "tenant:encoded-cross-pack" {
        println!(
            "PASS cold cross-pack recovery imports original dictionary pairs before dependents, releases inspection descriptors and preserves cold promises; no Ready"
        );
    } else if inputs.domain == "tenant:encoded-metadata-only" {
        println!(
            "PASS cold metadata pair recovered; original pair registered after Resume; cold promises preserved; no Ready"
        );
    } else {
        println!(
            "PASS cold raw, Zstd, dictionary and metadata candidates recovered; original inodes served under durable consumer pins; cold promises preserved; no Ready"
        );
    }
    if inputs.domain == "tenant:encoded-data-pack" {
        super::packed_eviction::run(owner, runtime, inputs, &retained_consumers)?;
    }
    Ok(())
}
