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
    encoded_first: Vec<u8>,
    dictionary: Option<Vec<u8>>,
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

fn data(bad_whole: bool, dictionary_backed: bool) -> io::Result<Data> {
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
    // A distinct ordinary chunk supplies the actual dictionary. Its suffix
    // overlaps the random first source, so the public encoder must really choose
    // dictionary compression rather than silently fall back to raw bytes.
    let dictionary = dictionary_backed.then(|| first[1..].to_vec());
    let encoded_first = if let Some(dictionary) = &dictionary {
        let encoded = terrane::codec::encode_chunk(&first, profile.maximum(), 3, Some(dictionary))
            .map_err(io::Error::other)?;
        if encoded.first() != Some(&2) {
            return Err(invalid(
                "manifest fixture did not select dictionary compression",
            ));
        }
        encoded
    } else {
        [vec![0], first.clone()].concat()
    };
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
        encoded_first,
        dictionary,
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
        "publish-manifest-dictionary" => "tenant:publication-manifest-dictionary",
        _ => return Err(invalid("unknown manifest publication selector")),
    };
    if inputs.domain != case || original.is_some() {
        return Err(invalid(
            "manifest publication requires a fresh dedicated domain",
        ));
    }
    let bad = mode == "publish-manifest-bad-whole";
    let data = data(bad, mode == "publish-manifest-dictionary")?;
    if runtime
        .block_on(owner.publish_manifest(data.identity.clone()))
        .is_ok()
    {
        return Err(invalid(
            "manifest publication acknowledged before actual Resume",
        ));
    }
    let first_identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &data.first)
        .map_err(io::Error::other)?;
    if runtime
        .block_on(owner.read_resident_chunk(first_identity))
        .is_ok()
    {
        return Err(invalid("resident read acknowledged before actual Resume"));
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
    if let Some(dictionary) = &data.dictionary {
        let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
        if runtime
            .block_on(owner.admit_chunk(
                descriptor(&data.first, IdentityKind::Chunk)?,
                ChunkPosition::NonFinal,
                data.encoded_first.clone(),
            ))
            .is_ok()
            || fs::read(inputs.root.join("state/cache/records.toml"))? != before
        {
            return Err(invalid(
                "unadmitted dictionary gained native admission custody",
            ));
        }
        admit(
            owner,
            runtime,
            dictionary,
            ChunkPosition::Final,
            [vec![0], dictionary.clone()].concat(),
        )?;
    }
    admit(
        owner,
        runtime,
        &data.first,
        ChunkPosition::NonFinal,
        data.encoded_first.clone(),
    )?;
    admit(
        owner,
        runtime,
        &data.tail,
        ChunkPosition::Final,
        [vec![0], data.tail.clone()].concat(),
    )?;
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
        // The physical registry and durable pins, not the publication waiter or
        // receipt, must retain the backing for subsequent sealed-range reads.
        drop(receipt);
        check_resident_reads(owner, runtime, inputs, &data)?;
        let message = if data.dictionary.is_some() {
            "PASS actual dictionary-backed manifest publication retained its original dictionary inode, pins and holds while retiring repeated sources; checked retained range reads; no Ready"
        } else {
            "PASS actual manifest publication retained metadata, repeated-chunk ranges and pending original sources across later work; checked retained range reads; no Ready"
        };
        emit(message)?;
    }
    Ok(())
}

fn check_resident_reads(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    data: &Data,
) -> io::Result<()> {
    let snapshot = inputs.root.join("state/cache/records.toml");
    let before = fs::read(&snapshot)?;
    let missing = TERRANE_V1
        .calculate(IdentityKind::Chunk, b"unseen resident source")
        .map_err(io::Error::other)?;
    let error = runtime
        .block_on(owner.read_resident_chunk(missing))
        .err()
        .ok_or_else(|| invalid("absent resident source unexpectedly read"))?;
    if error.kind() != io::ErrorKind::NotFound
        || runtime
            .block_on(owner.read_resident_chunk(data.identity.clone()))
            .is_ok()
    {
        return Err(invalid(
            "resident read accepted an absent chunk or manifest identity",
        ));
    }
    for (bytes, offset, final_chunk) in [
        (data.first.as_slice(), 0, false),
        (data.tail.as_slice(), 2 * data.first.len(), true),
    ] {
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, bytes)
            .map_err(io::Error::other)?;
        let read = runtime.block_on(owner.read_resident_chunk(identity.clone()))?;
        if read.identity() != &identity
            || read.plaintext() != bytes
            || read.span().offset != offset as u64
            || read.span().length != bytes.len()
            || read.span().final_chunk != final_chunk
        {
            return Err(invalid(
                "actual retained resident read differs from the first verified range",
            ));
        }
    }
    if fs::read(snapshot)? != before {
        return Err(invalid(
            "read-only resident lookup changed durable pins or holds",
        ));
    }
    Ok(())
}

fn admit(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    bytes: &[u8],
    position: ChunkPosition,
    encoded: Vec<u8>,
) -> io::Result<()> {
    let declared = descriptor(bytes, IdentityKind::Chunk)?;
    let receipt = runtime
        .block_on(owner.admit_chunk(declared.clone(), position, encoded))
        .map_err(io::Error::other)?;
    if receipt.descriptor() != &declared || receipt.synchronized_chunk_bytes() == 0 {
        return Err(invalid(
            "manifest source lacks actual admission acknowledgment",
        ));
    }
    Ok(())
}

fn admission_bytes(data: &Data) -> usize {
    data.encoded_first.len()
        + data.tail.len()
        + 1
        + data
            .dictionary
            .as_ref()
            .map_or(0, |dictionary| dictionary.len() + 1)
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
            != (6 + u64::from(data.dictionary.is_some())) * HOLD
                + (admission_bytes(data) + metadata_bytes) as u64
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
    let dictionaries = usize::from(data.dictionary.is_some());
    if state.reservations.len() != 5 + retained + dictionaries
        || state.leases.len() != 4 + retained + dictionaries
        || state.pins.len() != 5 + 2 * retained + 2 * dictionaries
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
    let dictionary = data
        .dictionary
        .as_ref()
        .map(|bytes| descriptor(bytes, IdentityKind::Chunk).map(|value| hex(value.digest())))
        .transpose()?;
    let mut first_pins = BTreeSet::from([first.clone()]);
    if let Some(dictionary) = &dictionary {
        first_pins.insert(dictionary.clone());
    }
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
                } else if hashes == first_pins {
                    data.encoded_first.len()
                } else if dictionary
                    .as_ref()
                    .is_some_and(|hash| hashes == BTreeSet::from([hash.clone()]))
                {
                    data.dictionary.as_ref().map_or(0, |bytes| bytes.len() + 1)
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
    if kinds != [1, retained, 3 + dictionaries, 1] {
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
    fn dictionary_manifest_fixture_requires_its_distinct_verified_dependency() {
        let data = data(false, true).unwrap();
        let dictionary = data.dictionary.as_ref().unwrap();
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, &data.first)
            .unwrap();
        assert_ne!(
            identity,
            TERRANE_V1
                .calculate(IdentityKind::Chunk, dictionary)
                .unwrap()
        );
        assert_eq!(data.encoded_first[0], 2);
        let profile = ChunkProfile::cdc_1m([0; 32]);
        assert!(
            terrane::codec::decode_verified(
                &data.encoded_first,
                data.first.len(),
                &profile,
                false,
                &identity,
                None,
            )
            .is_err()
        );
        let verified = terrane::codec::decode_verified(
            &data.encoded_first,
            data.first.len(),
            &profile,
            false,
            &identity,
            Some(dictionary),
        )
        .unwrap();
        assert_eq!(verified.plaintext(), data.first);
    }

    #[test]
    fn manifest_fixture_repeats_an_honest_cut_and_checks_independent_whole_hashes() {
        for bad in [false, true] {
            let data = data(bad, false).unwrap();
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
