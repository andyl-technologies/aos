//! Checks producer data-pair refusal, native completion, handoff and original reads.

use super::*;
use std::time::UNIX_EPOCH;
use terrane_linux::host_cache::NativeDataPackAdmissionError;
use terrane_sdk::{
    pack::{NativeBodyDecoder, SealedPack},
    store::{Clock, TokioClock},
};

struct Chunk {
    plaintext: Vec<u8>,
    encoded: Vec<u8>,
}

fn fixture() -> io::Result<(SealedPack, Vec<Chunk>)> {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let terminal = b"producer packed terminal vocabulary ".repeat(16);
    let middle = b"producer packed terminal vocabulary intermediate ".repeat(64);
    let root = b"producer packed terminal vocabulary intermediate content ".repeat(128);
    let dictionaries = [&terminal, &middle]
        .into_iter()
        .map(|bytes| {
            let identity = TERRANE_V1
                .calculate(IdentityKind::Chunk, bytes)
                .map_err(io::Error::other)?;
            Ok((
                identity.terrane_v1_digest().map_err(io::Error::other)?,
                bytes.clone(),
            ))
        })
        .collect::<io::Result<BTreeMap<_, _>>>()?;
    let middle_encoded =
        terrane_sdk::codec::encode_chunk(&middle, profile.maximum(), 3, Some(&terminal))
            .map_err(io::Error::other)?;
    let root_encoded = terrane_sdk::codec::encode_chunk(&root, profile.maximum(), 3, Some(&middle))
        .map_err(io::Error::other)?;
    if middle_encoded.first() != Some(&2) || root_encoded.first() != Some(&2) {
        return Err(invalid(
            "producer data fixture lost nested dictionary codecs",
        ));
    }
    let chunks = vec![
        Chunk {
            encoded: raw(&terminal),
            plaintext: terminal,
        },
        Chunk {
            encoded: middle_encoded,
            plaintext: middle,
        },
        Chunk {
            encoded: root_encoded,
            plaintext: root,
        },
    ];
    let decoder = NativeBodyDecoder::new(&profile, &dictionaries);
    let mut writer = PackWriter::new(PackId::from_random_bytes([120; 16]), PackClass::Data, false);
    for chunk in &chunks {
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, &chunk.plaintext)
            .map_err(io::Error::other)?;
        writer
            .append_chunk(
                identity.terrane_v1_digest().map_err(io::Error::other)?,
                &chunk.encoded,
                u32::try_from(chunk.plaintext.len()).map_err(io::Error::other)?,
                0,
                &decoder,
            )
            .map_err(io::Error::other)?;
    }
    Ok((writer.seal().map_err(io::Error::other)?, chunks))
}

/// Produces structurally valid, freshly checksummed bytes with a dishonest body.
fn corrupt_content(pair: &SealedPack) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let reader = PackReader::open(pair.bytes()).map_err(io::Error::other)?;
    let mut bodies = Vec::new();
    let mut records = Vec::new();
    for (position, entry) in reader.entries().iter().enumerate() {
        let start = usize::try_from(entry.offset()).map_err(io::Error::other)?;
        let end = start
            .checked_add(entry.body_len() as usize)
            .ok_or_else(|| invalid("fixture record overflow"))?;
        let mut encoded = pair
            .bytes()
            .get(start..end)
            .ok_or_else(|| invalid("fixture body absent"))?
            .to_vec();
        if position == 1 {
            let last = encoded
                .last_mut()
                .ok_or_else(|| invalid("fixture body empty"))?;
            *last ^= 1;
        }
        records.push(Record {
            hash: *entry.hash(),
            offset: (pack_format::HEADER_SIZE + bodies.len()) as u64,
            body_len: entry.body_len(),
            plaintext_len: entry.plaintext_len(),
            codec: entry.codec() as u8,
            kind: entry.kind() as u8,
            dictionary_id: 0,
        });
        bodies.extend_from_slice(&encoded);
    }
    let bytes = pack_format::encode_pack(
        Header::new(*reader.header().id().as_bytes(), false, false),
        &bodies,
        &records,
    )
    .map_err(io::Error::other)?;
    let index = PackReader::open(&bytes)
        .map_err(io::Error::other)?
        .index_object();
    Ok((bytes, index))
}

/// Offers a valid pack whose only chunk requires a dictionary outside the pair.
fn external_dictionary(chunks: &[Chunk]) -> io::Result<SealedPack> {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let dictionaries = chunks[..2]
        .iter()
        .map(|chunk| {
            let identity = TERRANE_V1
                .calculate(IdentityKind::Chunk, &chunk.plaintext)
                .map_err(io::Error::other)?;
            Ok((
                identity.terrane_v1_digest().map_err(io::Error::other)?,
                chunk.plaintext.clone(),
            ))
        })
        .collect::<io::Result<BTreeMap<_, _>>>()?;
    let decoder = NativeBodyDecoder::new(&profile, &dictionaries);
    let chunk = &chunks[2];
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &chunk.plaintext)
        .map_err(io::Error::other)?;
    let mut writer = PackWriter::new(PackId::from_random_bytes([121; 16]), PackClass::Data, false);
    writer
        .append_chunk(
            identity.terrane_v1_digest().map_err(io::Error::other)?,
            &chunk.encoded,
            u32::try_from(chunk.plaintext.len()).map_err(io::Error::other)?,
            0,
            &decoder,
        )
        .map_err(io::Error::other)?;
    writer.seal().map_err(io::Error::other)
}

/// Checks real producer refusal and original pair custody through cache consumers.
///
/// # Errors
/// Refuses unexpected admission, changed original bytes or accounting, failed
/// handoff or consumer reads, and missing independent observer controls.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let (pair, chunks) = fixture()?;
    let id = PackId::from_random_bytes([120; 16]);
    let metadata = metadata_pair()?;
    let external = external_dictionary(&chunks)?;
    let (corrupt_pack, corrupt_index) = corrupt_content(&pair)?;
    let mut wrong_index = pair.index_object().to_vec();
    wrong_index[0] ^= 1;
    let baseline = state_bytes(inputs)?;
    let names = namespace(inputs)?;
    for attempt in 0..(6 * REJECTIONS) {
        let (key, pack, index) = match attempt % 6 {
            0 => (id, vec![255], pair.index_object().to_vec()),
            1 => (id, pair.bytes().to_vec(), wrong_index.clone()),
            2 => (
                random_id()?,
                pair.bytes().to_vec(),
                pair.index_object().to_vec(),
            ),
            3 => (metadata.id, metadata.pack.clone(), metadata.index.clone()),
            4 => (id, corrupt_pack.clone(), corrupt_index.clone()),
            _ => (
                PackId::from_random_bytes([121; 16]),
                external.bytes().to_vec(),
                external.index_object().to_vec(),
            ),
        };
        match runtime.block_on(owner.admit_data_pack(key, pack, index)) {
            Err(NativeDataPackAdmissionError::Accepted(error))
                if !matches!(
                    error.kind(),
                    io::ErrorKind::StorageFull | io::ErrorKind::WouldBlock
                ) => {}
            _ => {
                return Err(invalid(
                    "invalid data pair was not refused before native effects",
                ));
            }
        }
        unchanged(inputs, &baseline, &names)?;
    }
    let hashes = PackReader::open(pair.bytes())
        .map_err(io::Error::other)?
        .entries()
        .iter()
        .map(|entry| hex(entry.hash()))
        .chain(std::iter::once(hex(TERRANE_V1
            .calculate(IdentityKind::Pack, pair.bytes())
            .map_err(io::Error::other)?
            .digest())))
        .collect::<BTreeSet<_>>();
    let expected_hold = hold(pair.bytes().len() + pair.index_object().len(), hashes)?;
    let receipt = runtime
        .block_on(owner.admit_data_pack(id, pair.bytes().to_vec(), pair.index_object().to_vec()))
        .map_err(io::Error::other)?;
    let directory = format!("objects/pack/{:02x}", id.as_bytes()[0]);
    let pack_path = PathBuf::from(format!("{directory}/{id}.pack"));
    let index_path = PathBuf::from(format!("{directory}/{id}.idx"));
    let (pack_bytes, directories) = canonical(inputs, &pack_path, pair.bytes())?;
    let (index_bytes, index_directories) = canonical(inputs, &index_path, pair.index_object())?;
    if receipt.pack_id() != id
        || receipt.synchronized_pair_bytes() != pack_bytes + index_bytes
        || receipt.synchronized_directory_bytes() != directories
        || directories != index_directories
        || receipt.future_hold_bytes() != expected_hold.bytes
        || receipt.charged_reserved_bytes() != quota(inputs)?
    {
        return Err(invalid(
            "producer data receipt differs from native pair or funding",
        ));
    }
    check_state(runtime, inputs, std::slice::from_ref(&expected_hold))?;
    emit("READY actual producer data pair verified with original funding; no standalone copies")?;
    control("handoff-data-pack")?;
    let report = runtime
        .block_on(receipt.into_cache(owner))
        .map_err(io::Error::other)?;
    if report.synchronized_member_bytes != pack_bytes + index_bytes
        || report.released_future_hold_bytes != expected_hold.bytes
        || report.future_hold_bytes != HOLD
        || report.charged_reserved_bytes != quota(inputs)?
    {
        return Err(invalid(
            "producer data handoff changed measured pair or funding",
        ));
    }
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| invalid("data lease expiry overflow"))?;
    for chunk in &chunks {
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, &chunk.plaintext)
            .map_err(io::Error::other)?;
        let lease = runtime.block_on(owner.pin_resident_chunk(identity, expires))?;
        if lease.read_verified()? != chunk.plaintext || lease.read_encoded()? != chunk.encoded {
            return Err(invalid(
                "producer pack consumer substituted original content",
            ));
        }
        runtime.block_on(owner.release_consumer_lease(&lease))?;
    }
    canonical(inputs, &pack_path, pair.bytes())?;
    canonical(inputs, &index_path, pair.index_object())?;
    if fs::read_dir(inputs.root.join("chunks"))?.next().is_some()
        || fs::read_dir(inputs.root.join("pending-delete"))?
            .next()
            .is_some()
    {
        return Err(invalid(
            "producer pack generated standalone or pending copies",
        ));
    }
    emit("READY actual producer data pair serves original nested envelopes after cache handoff")?;
    control("data-pack-observed")?;
    emit(
        "PASS actual producer data pair rejects invalid content before funding, retains both original members and serves nested chunks without extraction; no Ready",
    )
}
