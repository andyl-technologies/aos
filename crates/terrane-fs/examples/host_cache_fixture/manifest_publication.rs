//! Exercises actual funded Running manifest copies, source retirement and cancellation.
//!
//! Pure byte fixtures establish no native authority. Every admission, metadata
//! pin, anonymous output, publisher reply and residence comes from the real owner.

use super::config::{HOLD, Inputs, STATE};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    future::Future,
    io::{self, BufRead, Read, Write},
    os::unix::fs::{FileExt, MetadataExt},
    task::{Context, Poll, Waker},
};
use terrane::{
    host::cache::CacheState,
    pack::{EntryKind, PackClass, PackId, PackWriter},
    store::{ChunkPosition, TokioLocalFs},
};
use terrane_core::{
    chunking::ChunkProfile,
    identity::{Descriptor, Identity, IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
};
use terrane_fs::{
    host_cache::{NativeManifestPublication, NativeMetadataOwner},
    host_quota::synchronized_allocated_bytes,
};

struct Data {
    first: Vec<u8>,
    tail: Vec<u8>,
    plaintext: Vec<u8>,
    canonical: Vec<u8>,
    identity: Identity,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn descriptor(bytes: &[u8], kind: IdentityKind) -> io::Result<Descriptor> {
    let identity = TERRANE_V1
        .calculate(kind, bytes)
        .map_err(io::Error::other)?;
    Descriptor::from_identity(&TERRANE_V1, &identity, bytes).map_err(io::Error::other)
}

fn data(bad_whole: bool) -> io::Result<Data> {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let mut first = None;
    // Search bounded deterministic input for an honest early cut. Repetition
    // then supplies two valid nonfinal occurrences with one actual source inode.
    for seed in 1_u64..=512 {
        let mut generator = seed;
        let mut bytes = vec![0; 320 * 1024];
        for byte in &mut bytes {
            generator ^= generator << 13;
            generator ^= generator >> 7;
            generator ^= generator << 17;
            *byte = generator.to_le_bytes()[0];
        }
        let boundary = profile.first_boundary(&bytes);
        bytes.truncate(boundary);
        if profile.valid_nonfinal_chunk(&bytes) {
            first = Some(bytes);
            break;
        }
    }
    let first = first.ok_or_else(|| invalid("bounded fixture lacks an honest nonfinal cut"))?;
    let tail = vec![99; 31];
    let plaintext = [first.as_slice(), first.as_slice(), tail.as_slice()].concat();
    let chunks = [first.as_slice(), first.as_slice(), tail.as_slice()]
        .into_iter()
        .map(|bytes| {
            Ok(ChunkRef {
                digest: TERRANE_V1
                    .calculate(IdentityKind::Chunk, bytes)
                    .map_err(io::Error::other)?
                    .terrane_v1_digest()
                    .map_err(io::Error::other)?,
                length: bytes.len() as u64,
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let hash = if bad_whole {
        blake3::hash(b"another whole file")
    } else {
        blake3::hash(&plaintext)
    };
    let canonical = Manifest {
        size: plaintext.len() as u64,
        chunks,
        hashes: BTreeMap::from([("blake3".into(), hash.as_bytes().to_vec())]),
        media_type: None,
    }
    .encode(&profile)
    .map_err(io::Error::other)?;
    let identity = TERRANE_V1
        .calculate(IdentityKind::Manifest, &canonical)
        .map_err(io::Error::other)?;
    Ok(Data {
        first,
        tail,
        plaintext,
        canonical,
        identity,
    })
}

/// Runs one actual manifest-publication selector in its dedicated native domain.
///
/// # Errors
/// Refuses reused state, incorrect actual native outcomes or missing durable
/// source/metadata funding, cancellation custody or exact residence closure.
pub(super) fn run(
    mode: &str,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    let case = match mode {
        "publish-manifest" => "tenant:publication-manifest",
        "publish-manifest-cancel" => "tenant:publication-manifest-cancel",
        "publish-manifest-bad-whole" => "tenant:publication-manifest-bad-whole",
        _ => return Err(invalid("unknown manifest publication selector")),
    };
    if inputs.domain != case || original.is_some() {
        return Err(invalid(
            "manifest publication requires a fresh dedicated domain",
        ));
    }
    let bad = mode == "publish-manifest-bad-whole";
    let data = data(bad)?;
    if runtime
        .block_on(owner.publish_manifest(data.identity.clone()))
        .is_ok()
    {
        return Err(invalid(
            "manifest publication acknowledged before actual Resume",
        ));
    }
    if !matches!(fs::read(inputs.root.join("state/cache/records.toml")), Err(error) if error.kind() == io::ErrorKind::NotFound)
    {
        return Err(invalid(
            "pre-Resume manifest refusal changed durable policy",
        ));
    }
    let completed = runtime.block_on(owner.recover())?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    for (bytes, position) in [
        (&data.first, ChunkPosition::NonFinal),
        (&data.tail, ChunkPosition::Final),
    ] {
        let declared = descriptor(bytes, IdentityKind::Chunk)?;
        let mut encoded = vec![0];
        encoded.extend_from_slice(bytes);
        let receipt = runtime
            .block_on(owner.admit_chunk(declared.clone(), position, encoded))
            .map_err(io::Error::other)?;
        if receipt.descriptor() != &declared || receipt.synchronized_chunk_bytes() == 0 {
            return Err(invalid(
                "manifest source lacks actual admission acknowledgment",
            ));
        }
    }
    let mut random = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let id = PackId::from_random_bytes(random);
    let mut writer = PackWriter::new(id, PackClass::Meta, false);
    writer
        .append_raw(EntryKind::Manifest, &data.canonical)
        .map_err(io::Error::other)?;
    let sealed = writer.seal().map_err(io::Error::other)?;
    let pack = sealed.bytes().to_vec();
    let index = sealed.index_object().to_vec();
    let pack_identity = TERRANE_V1
        .calculate(IdentityKind::Pack, &pack)
        .map_err(io::Error::other)?;
    runtime
        .block_on(owner.admit_metadata_pack(id, pack.clone(), index.clone()))
        .map_err(io::Error::other)?;
    emit("READY actual manifest sources and metadata admitted; wait for publication control")?;
    control("start")?;
    let receipt = if mode == "publish-manifest-cancel" {
        let mut pending = Box::pin(owner.publish_manifest(data.identity.clone()));
        if !matches!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return Err(invalid(
                "stopped publisher did not retain a pending manifest waiter",
            ));
        }
        emit("QUEUED actual manifest publication; wait for durable funding control")?;
        control("cancel")?;
        drop(pending);
        emit("CANCELLED manifest waiter; original physical source and metadata custody retained")?;
        control("resumed")?;
        None
    } else {
        match runtime.block_on(owner.publish_manifest(data.identity.clone())) {
            Ok(receipt) if !bad => Some(receipt),
            Err(_) if bad => None,
            _ => {
                return Err(invalid(
                    "manifest publication supplied an unexpected native outcome",
                ));
            }
        }
    };
    if bad {
        check_state(
            runtime,
            inputs,
            &data,
            &pack_identity,
            pack.len() + index.len(),
            false,
        )?;
        if runtime
            .block_on(owner.retain_manifest(data.identity.clone()))
            .is_ok()
        {
            return Err(invalid("failed manifest copy released owner exclusion"));
        }
        emit(
            "REFUSED actual wrong whole-file hash with durable manifest funding and no residence; no Ready",
        )?;
        control("finish")?;
        emit(
            "PASS actual wrong whole-file hash retained the funded anonymous output without publisher submission; no Ready",
        )?;
    } else {
        // A valid later command must complete behind the abandoned operation;
        // arbitrary refusal could hide an earlier failed physical command.
        let retained = runtime.block_on(owner.retain_manifest(data.identity.clone()))?;
        retained.check_current()?;
        check_state(
            runtime,
            inputs,
            &data,
            &pack_identity,
            pack.len() + index.len(),
            true,
        )?;
        if let Some(receipt) = &receipt {
            check_receipt(receipt, &data, pack.len() + index.len())?;
        }
        emit(
            "PASS actual manifest publication retained metadata, repeated-chunk ranges and pending original sources across later work; no Ready",
        )?;
    }
    Ok(())
}

fn check_receipt(
    receipt: &NativeManifestPublication,
    data: &Data,
    metadata_bytes: usize,
) -> io::Result<()> {
    let mut bytes = vec![0; data.plaintext.len()];
    receipt.handle().read_exact_at(&mut bytes, 0)?;
    let flags = rustix::fs::fcntl_getfl(receipt.handle())?;
    let metadata = receipt.handle().metadata()?;
    if bytes != data.plaintext
        || receipt.claim().canonical_manifest() != Some(data.canonical.as_slice())
        || receipt.claim().descriptor().digest() != data.identity.digest()
        || receipt.synchronized_sealed_inode_bytes()
            != synchronized_allocated_bytes(receipt.handle())?
        || receipt.synchronized_sealed_inode_bytes() == 0
        || receipt.charged_reserved_bytes() == 0
        || receipt.future_hold_bytes()
            != 6 * HOLD
                + (data.first.len() + data.tail.len() + 2 + metadata_bytes) as u64
                + 2 * data.plaintext.len() as u64
        || metadata.uid() != 841
        || metadata.gid() != 841
        || metadata.mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
        || metadata.len() != data.plaintext.len() as u64
        || flags.intersects(
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR | rustix::fs::OFlags::PATH,
        )
    {
        return Err(invalid(
            "manifest receipt differs from independently read native backing",
        ));
    }
    Ok(())
}

fn check_state(
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    data: &Data,
    pack_identity: &Identity,
    metadata_bytes: usize,
    success: bool,
) -> io::Result<()> {
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("manifest publication snapshot absent"))?;
    let retained = if success { 2 } else { 1 };
    if state.reservations.len() != 5 + retained
        || state.leases.len() != 4 + retained
        || state.pins.len() != 5 + 2 * retained
        || state.residences.len() != if success { 2 } else { 0 }
    {
        return Err(invalid(
            "manifest publication lost exact durable policy closure",
        ));
    }
    let object = hex(data.identity.digest());
    let metadata_hashes = BTreeSet::from([object.clone(), hex(pack_identity.digest())]);
    let first = hex(descriptor(&data.first, IdentityKind::Chunk)?.digest());
    let tail = hex(descriptor(&data.tail, IdentityKind::Chunk)?.digest());
    let mut kinds = [0; 4];
    for reservation in &state.reservations {
        if reservation.owner != inputs.owner {
            return Err(invalid("manifest hold has another owner"));
        }
        let mut prefix = None;
        for candidate in ["admission", "metadata", "publication"] {
            let owner = format!("{candidate}:{}", reservation.id);
            if state.leases.iter().any(|row| row.owner == owner) {
                prefix = Some((candidate, owner));
            }
        }
        let expected = match prefix {
            Some(("publication", ref owner)) => {
                kinds[0] += 1;
                check_pins(&state, owner, &BTreeSet::from([object.clone()]))?;
                HOLD + 2 * data.plaintext.len() as u64
            }
            Some(("metadata", ref owner)) => {
                kinds[1] += 1;
                check_pins(&state, owner, &metadata_hashes)?;
                HOLD
            }
            Some(("admission", ref owner)) => {
                kinds[2] += 1;
                let hashes = state
                    .pins
                    .iter()
                    .filter(|row| row.owner == *owner)
                    .map(|row| row.hash.clone())
                    .collect::<BTreeSet<_>>();
                let bytes = if hashes == metadata_hashes {
                    metadata_bytes
                } else if hashes == BTreeSet::from([first.clone()]) {
                    data.first.len() + 1
                } else if hashes == BTreeSet::from([tail.clone()]) {
                    data.tail.len() + 1
                } else {
                    return Err(invalid("manifest admission pin closure differs"));
                };
                check_pins(&state, owner, &hashes)?;
                HOLD + bytes as u64
            }
            None => {
                kinds[3] += 1;
                HOLD
            }
            _ => return Err(invalid("unexpected manifest reservation class")),
        };
        if reservation.bytes != expected {
            return Err(invalid(
                "manifest future hold differs from actual input lifetimes",
            ));
        }
    }
    if kinds != [1, retained, 3, 1] {
        return Err(invalid("manifest reservation classes differ"));
    }
    if success {
        for (chunk, offset, length) in [
            (first, 0, data.first.len()),
            (tail, 2 * data.first.len(), data.tail.len()),
        ] {
            if !state.residences.iter().any(|row| {
                row.chunk == chunk
                    && row.object == object
                    && row.offset == offset as u64
                    && row.length == length as u64
            }) {
                return Err(invalid(
                    "repeated manifest chunks did not retain their first exact range",
                ));
            }
        }
    }
    Ok(())
}

fn check_pins(state: &CacheState, owner: &str, expected: &BTreeSet<String>) -> io::Result<()> {
    let pins = state
        .pins
        .iter()
        .filter(|row| row.owner == owner && row.expires == i64::MAX as u64)
        .map(|row| row.hash.clone())
        .collect::<BTreeSet<_>>();
    if &pins != expected
        || !state
            .leases
            .iter()
            .any(|row| row.owner == owner && row.expires == i64::MAX as u64)
    {
        return Err(invalid("manifest pins or real owner lease differ"));
    }
    Ok(())
}

fn emit(message: &str) -> io::Result<()> {
    println!("{message}");
    io::stdout().flush()
}

fn control(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim() != expected {
        return Err(invalid("unexpected manifest publication control"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use terrane::host::publication::{PublicationClaim, PublicationRecipe};

    #[test]
    fn manifest_fixture_repeats_an_honest_cut_and_checks_independent_whole_hashes() {
        for bad in [false, true] {
            let data = data(bad).unwrap();
            let profile = ChunkProfile::cdc_1m([0; 32]);
            assert!(profile.valid_nonfinal_chunk(&data.first));
            let claim = PublicationClaim::new(
                "tenant:manifest-fixture".into(),
                PublicationRecipe::Manifest {
                    object: descriptor(&data.canonical, IdentityKind::Manifest).unwrap(),
                    canonical_manifest: data.canonical,
                },
                &profile,
            )
            .unwrap();
            assert_eq!(
                claim
                    .verify_reader(&mut io::Cursor::new(data.plaintext))
                    .is_err(),
                bad
            );
            let manifest = claim.manifest().unwrap();
            assert_eq!(manifest.chunks.len(), 3);
            assert_eq!(manifest.chunks[0], manifest.chunks[1]);
        }
    }
}
