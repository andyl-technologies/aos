//! Builds a new sealed object from original recovered ranges and one new source.
//!
//! All native handles and durable metadata come from the actual Running owner.
//! The supervisor independently compares sealed bytes to the original recovered
//! body and retired new prefix, including their actual native inode custody.

use super::*;
use std::os::unix::fs::{FileExt, MetadataExt};
use terrane::host::cache::{CacheState, ResidenceRecord};
use terrane::store::ChunkPosition;
use terrane_core::identity::{Descriptor, Identity};

/// Publishes a distinct manifest while preserving original recovered residences.
///
/// # Errors
/// Refuses missing actual recovery, stale metadata or pins, duplicate standalone
/// sources, changed original residences, wrong whole bytes or incomplete retirement.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let recovered = Fixture::new()?;
    run_body(
        owner,
        runtime,
        inputs,
        &recovered.plaintext,
        recovered.chunks,
    )
}

/// Reuses original pinned inline recovery as the final source of another object.
///
/// # Errors
/// Refuses invalid bytes, absent real source custody or any actual assembly,
/// metadata, native retirement or synchronized funding failure.
pub(super) fn run_inline(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, INLINE_BYTES)
        .map_err(io::Error::other)?;
    let chunks = vec![ChunkRef {
        digest: identity.terrane_v1_digest().map_err(io::Error::other)?,
        length: INLINE_BYTES.len() as u64,
    }];
    run_body(owner, runtime, inputs, INLINE_BYTES, chunks)
}

fn run_body(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    recovered_plaintext: &[u8],
    recovered_chunks: Vec<ChunkRef>,
) -> io::Result<()> {
    let original = load_state(runtime, inputs)?;
    let prefix = super::super::manifest_publication::nonfinal_fixture_chunk()?;
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let prefix_identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &prefix)
        .map_err(io::Error::other)?;
    let prefix_descriptor = Descriptor::from_identity(&TERRANE_V1, &prefix_identity, &prefix)
        .map_err(io::Error::other)?;
    let encoded = [b"\0".as_slice(), prefix.as_slice()].concat();
    runtime
        .block_on(owner.admit_chunk(prefix_descriptor, ChunkPosition::NonFinal, encoded.clone()))
        .map_err(io::Error::other)?;
    let canonical_prefix = inputs
        .root
        .join("chunks")
        .join(&hex(prefix_identity.digest())[..2])
        .join(format!("{}.0", hex(prefix_identity.digest())));
    let prefix_inode = canonical_prefix.metadata()?.ino();

    let plaintext = [prefix.as_slice(), recovered_plaintext].concat();
    let mut chunks = vec![ChunkRef {
        digest: prefix_identity
            .terrane_v1_digest()
            .map_err(io::Error::other)?,
        length: prefix.len() as u64,
    }];
    chunks.extend(recovered_chunks);
    let canonical = Manifest {
        size: plaintext.len() as u64,
        chunks,
        hashes: BTreeMap::from([(
            "blake3".into(),
            blake3::hash(&plaintext).as_bytes().to_vec(),
        )]),
        media_type: None,
    }
    .encode(&profile)
    .map_err(io::Error::other)?;
    let identity = TERRANE_V1
        .calculate(IdentityKind::Manifest, &canonical)
        .map_err(io::Error::other)?;
    let metadata_bytes = admit_metadata(owner, runtime, &canonical)?;
    let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
    let first = profile
        .ranges(recovered_plaintext)
        .next()
        .ok_or_else(|| invalid("recovered assembly has no actual source range"))?;
    let old_bytes = &recovered_plaintext[first];
    let old_identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, old_bytes)
        .map_err(io::Error::other)?;
    let old_descriptor = Descriptor::from_identity(&TERRANE_V1, &old_identity, old_bytes)
        .map_err(io::Error::other)?;
    if runtime
        .block_on(owner.admit_chunk(
            old_descriptor,
            ChunkPosition::Final,
            [b"\0".as_slice(), old_bytes].concat(),
        ))
        .is_ok()
        || fs::read(inputs.root.join("state/cache/records.toml"))? != before
    {
        return Err(invalid(
            "recovered range gained a duplicate standalone source",
        ));
    }

    let retained = runtime.block_on(owner.retain_resident_chunk(old_identity))?;
    let published = runtime.block_on(owner.publish_manifest(identity.clone()))?;
    let mut actual = vec![0; plaintext.len()];
    published.handle().read_exact_at(&mut actual, 0)?;
    let original_holds = original
        .reservations
        .iter()
        .map(|hold| hold.bytes)
        .sum::<u64>();
    let expected_holds = original_holds + 4 * HOLD + encoded.len() as u64 + metadata_bytes as u64;
    if actual != plaintext
        || published.claim().canonical_manifest() != Some(canonical.as_slice())
        || published.claim().descriptor().digest() != identity.digest()
        || published.future_hold_bytes() != expected_holds
        || published.charged_reserved_bytes() > HARD_LIMIT
        || canonical_prefix.try_exists()?
    {
        return Err(invalid(
            "recovered reassembly lacks actual backing, funding or retirement",
        ));
    }
    drop(published);

    let state = load_state(runtime, inputs)?;
    check_state(
        &original,
        &state,
        &identity,
        &prefix_identity,
        prefix.len(),
        expected_holds,
    )?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    let old_actual = retained.read_verified()?;
    drop(stalled);
    if old_actual != old_bytes {
        return Err(invalid(
            "new assembly changed the actual retained recovered source",
        ));
    }
    let source = runtime.block_on(owner.retain_resident_chunk(prefix_identity.clone()))?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    let new_actual = source.read_verified()?;
    drop(stalled);
    if new_actual != prefix || source.span().offset != 0 || source.span().final_chunk {
        return Err(invalid(
            "new assembled prefix lacks its original checked range",
        ));
    }
    println!(
        "RECOVERED_ASSEMBLY {} {} {prefix_inode} {}",
        hex(identity.digest()),
        hex(prefix_identity.digest()),
        prefix.len()
    );
    println!(
        "PASS actual reassembly reused recovered manifest ranges, preserved original residences and retired only its new standalone prefix; no Ready"
    );
    Ok(())
}

fn admit_metadata(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    canonical: &[u8],
) -> io::Result<usize> {
    let mut random = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let id = PackId::from_random_bytes(random);
    let mut writer = PackWriter::new(id, PackClass::Meta, false);
    writer
        .append_raw(EntryKind::Manifest, canonical)
        .map_err(io::Error::other)?;
    let sealed = writer.seal().map_err(io::Error::other)?;
    let bytes = sealed.bytes().len() + sealed.index_object().len();
    runtime
        .block_on(owner.admit_metadata_pack(
            id,
            sealed.bytes().to_vec(),
            sealed.index_object().to_vec(),
        ))
        .map_err(io::Error::other)?;
    Ok(bytes)
}

fn load_state(runtime: &tokio::runtime::Runtime, inputs: &Inputs) -> io::Result<CacheState> {
    runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("recovered assembly snapshot absent"))
}

fn check_state(
    original: &CacheState,
    current: &CacheState,
    manifest: &Identity,
    prefix: &Identity,
    prefix_bytes: usize,
    expected_holds: u64,
) -> io::Result<()> {
    let reservations_preserved = original.reservations.iter().all(|previous| {
        current.reservations.iter().any(|candidate| {
            previous.id == candidate.id
                && previous.owner == candidate.owner
                && previous.bytes == candidate.bytes
        })
    });
    let leases_preserved = original.leases.iter().all(|previous| {
        current.leases.iter().any(|candidate| {
            previous.owner == candidate.owner && previous.expires == candidate.expires
        })
    });
    let pins_preserved = original.pins.iter().all(|previous| {
        current.pins.iter().any(|candidate| {
            previous.owner == candidate.owner
                && previous.hash == candidate.hash
                && previous.expires == candidate.expires
        })
    });
    let residences_preserved = original.residences.iter().all(|previous| {
        current
            .residences
            .iter()
            .any(|candidate| same_row(previous, candidate))
    });
    if !reservations_preserved
        || !leases_preserved
        || !pins_preserved
        || !residences_preserved
        || current.reservations.len() != original.reservations.len() + 4
        || current.leases.len() != original.leases.len() + 4
        || current.pins.len() != original.pins.len() + 6
        || current.residences.len() != original.residences.len() + 1
        || current
            .reservations
            .iter()
            .map(|hold| hold.bytes)
            .sum::<u64>()
            != expected_holds
        || !current.residences.iter().any(|row| {
            row.chunk == hex(prefix.digest())
                && row.object == hex(manifest.digest())
                && row.offset == 0
                && row.length == prefix_bytes as u64
        })
    {
        return Err(invalid(
            "recovered reassembly changed original custody or exact new policy closure",
        ));
    }
    Ok(())
}

fn same_row(first: &ResidenceRecord, second: &ResidenceRecord) -> bool {
    first.chunk == second.chunk
        && first.object == second.object
        && first.offset == second.offset
        && first.length == second.length
}
