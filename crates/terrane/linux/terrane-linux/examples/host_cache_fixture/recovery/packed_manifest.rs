//! Reassembles actual cold packed inputs without manufacturing standalone custody.
//!
//! The administrative seed contains only candidate bytes. The confined actor
//! must recover both original pairs, Resume, fund copying and receive a genuine
//! publisher result before it can expose the assembled object.

use super::{Inputs, STATE};
use crate::manifest_publication;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io,
    os::unix::fs::{FileExt, MetadataExt},
    path::PathBuf,
    time::UNIX_EPOCH,
};
use terrane_format::{
    chunking::ChunkProfile,
    identity::{IdentityKind, TERRANE_V1},
};
use terrane_linux::host_cache::NativeMetadataOwner;
use terrane_sdk::{
    host::cache::CacheState,
    pack::{EntryKind, NativeBodyDecoder, PackClass, PackId, PackWriter},
    store::{Clock, TokioClock, TokioLocalFs},
};

const DATA_ID: [u8; 16] = [118; 16];
const META_ID: [u8; 16] = [119; 16];

/// Recognizes the two independently seeded packed-publication controls.
pub(super) fn selected(inputs: &Inputs) -> bool {
    matches!(
        inputs.domain.as_str(),
        "tenant:encoded-packed-manifest" | "tenant:encoded-packed-manifest-bad-whole"
    )
}

/// Writes only untrusted original pairs through explicit guest administration.
///
/// # Errors
/// Refuses invalid format fixtures or failed native creation and synchronization.
pub(super) fn seed(inputs: &Inputs) -> io::Result<()> {
    let data = manifest_publication::data(bad_whole(inputs), true)?;
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let dictionary = data
        .dictionary
        .as_ref()
        .ok_or_else(|| invalid("packed manifest dictionary absent"))?;
    let dictionary_identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, dictionary)
        .map_err(io::Error::other)?;
    let dictionaries = BTreeMap::from([(
        dictionary_identity
            .terrane_v1_digest()
            .map_err(io::Error::other)?,
        dictionary.clone(),
    )]);
    let decoder = NativeBodyDecoder::new(&profile, &dictionaries);
    let mut writer = PackWriter::new(PackId::from_random_bytes(DATA_ID), PackClass::Data, false);
    for (plaintext, encoded) in [
        (
            dictionary.as_slice(),
            [vec![0], dictionary.clone()].concat(),
        ),
        (data.first.as_slice(), data.encoded_first.clone()),
        (data.tail.as_slice(), [vec![0], data.tail.clone()].concat()),
    ] {
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, plaintext)
            .map_err(io::Error::other)?;
        writer
            .append_chunk(
                identity.terrane_v1_digest().map_err(io::Error::other)?,
                &encoded,
                u32::try_from(plaintext.len()).map_err(io::Error::other)?,
                0,
                &decoder,
            )
            .map_err(io::Error::other)?;
    }
    write_pair(inputs, DATA_ID, writer)?;
    let mut metadata = PackWriter::new(PackId::from_random_bytes(META_ID), PackClass::Meta, false);
    metadata
        .append_raw(EntryKind::Manifest, &data.canonical)
        .map_err(io::Error::other)?;
    write_pair(inputs, META_ID, metadata)?;
    println!("SEEDED cold encoded candidates; no recovery or serving authority");
    Ok(())
}

/// Checks actual ordered copying, immutable publication and source-pair handoff.
///
/// # Errors
/// Refuses absent real pair custody, wrong plaintext or whole-file acceptance,
/// standalone substitution, premature source release and retained private reads.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let data = manifest_publication::data(bad_whole(inputs), true)?;
    let paths = pair_paths(inputs, DATA_ID);
    let original = paths
        .iter()
        .map(|path| {
            let metadata = path.metadata()?;
            Ok(((metadata.dev(), metadata.ino()), fs::read(path)?))
        })
        .collect::<io::Result<Vec<_>>>()?;
    check_originals(&paths, &original)?;
    check_descriptor_count(&original, 1)?;
    let before = state(runtime, inputs)?;
    let result = runtime.block_on(owner.publish_manifest(data.identity.clone()));
    if bad_whole(inputs) {
        if result.is_ok() {
            return Err(invalid("packed sources bypassed whole-file verification"));
        }
        let after = state(runtime, inputs)?;
        let hash = hex(data.identity.digest());
        if after.reservations.len() <= before.reservations.len()
            || !after
                .pins
                .iter()
                .any(|pin| pin.owner.starts_with("publication:") && pin.hash == hash)
            || after.residences.iter().any(|row| row.object == hash)
            || inputs
                .root
                .join("sealed")
                .join(&hash[..2])
                .join(&hash)
                .exists()
        {
            return Err(invalid(
                "failed packed copy lost funding or installed a residence",
            ));
        }
        check_originals(&paths, &original)?;
        println!(
            "PASS actual packed manifest rejects a wrong whole-file hash while retaining original pairs and durable copy funding; no Ready"
        );
        return Ok(());
    }
    let publication = result?;
    let mut bytes = vec![0; data.plaintext.len()];
    publication.handle().read_exact_at(&mut bytes, 0)?;
    if bytes != data.plaintext
        || publication.claim().descriptor().digest() != data.identity.digest()
    {
        return Err(invalid(
            "packed manifest did not publish its exact ordered plaintext",
        ));
    }
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| invalid("packed consumer expiry overflow"))?;
    for plaintext in [&data.first, &data.tail] {
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, plaintext)
            .map_err(io::Error::other)?;
        let hash = hex(identity.digest());
        for codec in 0..=2 {
            if inputs
                .root
                .join("chunks")
                .join(&hash[..2])
                .join(format!("{hash}.{codec}"))
                .exists()
            {
                return Err(invalid("packed manifest created a standalone source copy"));
            }
        }
        let consumer = runtime.block_on(owner.pin_resident_chunk(identity, expires))?;
        if consumer.read_verified()? != *plaintext {
            return Err(invalid(
                "packed manifest installed an incorrect sealed range",
            ));
        }
        runtime.block_on(owner.release_consumer_lease(&consumer))?;
    }
    runtime.block_on(publication.close_resident_reads(owner))?;
    let cleanup = runtime.block_on(publication.finish_retired_sources(owner))?;
    if cleanup.completed_sources != 0 {
        return Err(invalid(
            "packed publication invented a standalone retirement",
        ));
    }
    let handoff = runtime
        .block_on(publication.into_cache(owner))
        .map_err(io::Error::other)?;
    if handoff.released_source_admissions != 0 {
        return Err(invalid(
            "packed handoff released an independent source admission",
        ));
    }
    let pack_hash = hex(TERRANE_V1
        .calculate(IdentityKind::Pack, &original[1].1)
        .map_err(io::Error::other)?
        .digest());
    if !state(runtime, inputs)?.pins.iter().any(|pin| {
        pin.owner.starts_with("publication-grace:")
            && pin.hash == pack_hash
            && pin.expires == handoff.release_grace_ends_at
    }) {
        return Err(invalid("packed handoff lost original container grace"));
    }
    check_originals(&paths, &original)?;
    check_descriptor_count(&original, 1)?;
    println!(
        "PASS actual packed manifest verifies repeated dictionary-backed chunks and whole-file hashes, publishes immutable ranges and releases private pair reads under durable container grace without standalone extraction; no Ready"
    );
    Ok(())
}

fn write_pair(inputs: &Inputs, id: [u8; 16], writer: PackWriter) -> io::Result<()> {
    let sealed = writer.seal().map_err(io::Error::other)?;
    let [index, pack] = pair_paths(inputs, id);
    let parent = pack
        .parent()
        .ok_or_else(|| invalid("packed shard absent"))?;
    if !inputs.root.join("objects/pack").exists() {
        super::directory(&inputs.root.join("objects/pack"), 840, 845, 0o2770)?;
    }
    super::directory(parent, 840, 845, 0o2770)?;
    super::write(inputs, &index, sealed.index_object(), 840, 845, 0o640)?;
    super::write(inputs, &pack, sealed.bytes(), 840, 845, 0o640)?;
    File::open(parent)?.sync_all()?;
    File::open(inputs.root.join("objects/pack"))?.sync_all()?;
    File::open(inputs.root.join("objects"))?.sync_all()
}

fn pair_paths(inputs: &Inputs, id: [u8; 16]) -> [PathBuf; 2] {
    let pack = PackId::from_random_bytes(id);
    let shard = inputs
        .root
        .join("objects/pack")
        .join(format!("{:02x}", id[0]));
    [
        shard.join(format!("{pack}.idx")),
        shard.join(format!("{pack}.pack")),
    ]
}

fn check_originals(paths: &[PathBuf; 2], originals: &[((u64, u64), Vec<u8>)]) -> io::Result<()> {
    for (path, (inode, bytes)) in paths.iter().zip(originals) {
        let actual = path.metadata()?;
        if (actual.dev(), actual.ino()) != *inode || fs::read(path)? != *bytes {
            return Err(invalid(
                "packed publication changed an original pair member",
            ));
        }
    }
    Ok(())
}

fn check_descriptor_count(originals: &[((u64, u64), Vec<u8>)], expected: usize) -> io::Result<()> {
    let mut counts = BTreeMap::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        match fs::metadata(entry?.path()) {
            Ok(metadata) => *counts.entry((metadata.dev(), metadata.ino())).or_insert(0) += 1,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
    }
    if originals
        .iter()
        .any(|(inode, _)| counts.get(inode) != Some(&expected))
    {
        return Err(invalid(
            "packed publication retained hidden source descriptions",
        ));
    }
    Ok(())
}

fn state(runtime: &tokio::runtime::Runtime, inputs: &Inputs) -> io::Result<CacheState> {
    runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("packed manifest state absent"))
}

fn bad_whole(inputs: &Inputs) -> bool {
    inputs.domain == "tenant:encoded-packed-manifest-bad-whole"
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
