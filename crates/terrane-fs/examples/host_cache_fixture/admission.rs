//! Exercises real running-owner admission without constructing native authority.
//!
//! Each selector starts with genuine empty recovery and acknowledged Resume.
//! Untrusted byte fixtures confer no hash, quota or publication evidence. The
//! old cold-recovery selectors remain separate. These cases grant no bucket
//! readiness, consumer lease, full HOST acceptance or admission-time EDQUOT proof.

use super::config::{EPOCH, HARD_LIMIT, HOLD, Inputs, STATE};
use rustix::fs::{self as native, Mode, OFlags, ResolveFlags};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata, OpenOptions},
    future::Future,
    io::{self, BufRead, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};
use terrane::{
    host::cache::CacheState,
    pack::{EntryKind, PackClass, PackId, PackReader, PackWriter},
    store::{ChunkPosition, TokioLocalFs},
};
use terrane_core::{
    chunking::ChunkProfile,
    identity::{Descriptor, IdentityKind, TERRANE_V1},
    manifest::{ChunkRef, Manifest},
    pack_format::{self, Header, Record},
};
use terrane_fs::{
    host_cache::{NativeChunkAdmissionError, NativeMetadataAdmissionError, NativeMetadataOwner},
    host_quota::{HostQuotaClient, NativeProject, synchronized_allocated_bytes},
};

const WINDOW: usize = 2 * 1024 * 1024;
const CAPACITY: u64 = 6 * 1024 * 1024;
const REJECTIONS: usize = 65;
// Ordinary expected policy data, matching the existing signed TOML integer range.
const RETAINED_LEASE_DEADLINE: u64 = i64::MAX as u64;

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}

/// Executes a distinct genuine admission selector after ordinary owner startup.
///
/// # Errors
/// Refuses a reused fixture, failed actual recovery/Resume, incorrect native
/// bytes/custody/accounting, or any unexpected submission or physical outcome.
pub(super) fn run(
    mode: &str,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    let case = match mode {
        "admit-chunk" => "tenant:admission-chunk",
        "admit-metadata" => "tenant:admission-metadata",
        "admit-cancel" => "tenant:admission-cancel",
        _ => return Err(invalid("unknown admission selector")),
    };
    if inputs.domain != case || original.is_some() {
        return Err(invalid("admission requires its fresh dedicated domain"));
    }
    let completed = runtime.block_on(owner.recover())?;
    completed.check_current()?;
    check_state(runtime, inputs, &[])?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    emit("ACK actual empty recovery Resume; no Ready")?;

    match mode {
        "admit-chunk" => chunks(owner, runtime, inputs),
        "admit-metadata" => metadata(owner, runtime, inputs),
        "admit-cancel" => cancelled(owner, runtime, inputs),
        _ => Err(invalid("unreachable admission selector")),
    }
}

#[derive(Clone)]
struct Hold {
    bytes: u64,
    hashes: BTreeSet<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn descriptor(bytes: &[u8]) -> io::Result<Descriptor> {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, bytes)
        .map_err(io::Error::other)?;
    Descriptor::from_identity(&TERRANE_V1, &identity, bytes).map_err(io::Error::other)
}

fn raw(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(bytes.len() + 1);
    encoded.push(0);
    encoded.extend_from_slice(bytes);
    encoded
}

fn hold(bytes: usize, hashes: impl IntoIterator<Item = String>) -> io::Result<Hold> {
    Ok(Hold {
        bytes: HOLD
            .checked_add(u64::try_from(bytes).map_err(io::Error::other)?)
            .ok_or_else(|| invalid("fixture hold overflow"))?,
        hashes: hashes.into_iter().collect(),
    })
}

fn state_bytes(inputs: &Inputs) -> io::Result<Vec<u8>> {
    read_file(&inputs.root.join("state/cache/records.toml"), STATE.bytes).map(|(_, bytes)| bytes)
}

fn check_state(
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    expected: &[Hold],
) -> io::Result<()> {
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("admission snapshot missing"))?;
    if !state.residences.is_empty()
        || state.reservations.len() != expected.len() + 1
        || state.leases.len() != expected.len()
        || state.pins.len() != expected.iter().map(|row| row.hashes.len()).sum::<usize>()
    {
        return Err(invalid("admission policy row closure differs"));
    }
    let mut unmatched = expected.to_vec();
    let mut bootstrap = 0;
    let mut ids = BTreeSet::new();
    let mut expected_pins = BTreeSet::new();
    let mut expected_leases = BTreeSet::new();
    let mut future = 0_u64;
    for row in &state.reservations {
        if row.owner != inputs.owner
            || row.id.len() != 32
            || !row
                .id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !row.id.bytes().any(|byte| byte != b'0')
            || !ids.insert(&row.id)
        {
            return Err(invalid("admission reservation owner or token differs"));
        }
        future = future
            .checked_add(row.bytes)
            .ok_or_else(|| invalid("fixture future sum overflow"))?;
        let pin_owner = format!("admission:{}", row.id);
        let hashes = state
            .pins
            .iter()
            .filter(|pin| pin.owner == pin_owner)
            .map(|pin| pin.hash.clone())
            .collect::<BTreeSet<_>>();
        if row.bytes == HOLD && hashes.is_empty() {
            bootstrap += 1;
            continue;
        }
        let index = unmatched
            .iter()
            .position(|value| value.bytes == row.bytes && value.hashes == hashes)
            .ok_or_else(|| invalid("admission hold or protected hash closure differs"))?;
        unmatched.remove(index);
        expected_leases.insert((pin_owner.clone(), RETAINED_LEASE_DEADLINE));
        expected_pins.extend(
            hashes
                .into_iter()
                .map(|hash| (pin_owner.clone(), hash, RETAINED_LEASE_DEADLINE)),
        );
    }
    if bootstrap != 1
        || !unmatched.is_empty()
        || state
            .leases
            .iter()
            .map(|row| (row.owner.clone(), row.expires))
            .collect::<BTreeSet<_>>()
            != expected_leases
        || state
            .pins
            .iter()
            .map(|row| (row.owner.clone(), row.hash.clone(), row.expires))
            .collect::<BTreeSet<_>>()
            != expected_pins
    {
        return Err(invalid(
            "admission durable pin, lease or bootstrap closure differs",
        ));
    }
    let quota = quota(inputs)?;
    if quota
        .checked_add(future)
        .is_none_or(|total| total > CAPACITY)
    {
        return Err(invalid(
            "fresh actual charge plus distinct holds exceeds policy",
        ));
    }
    Ok(())
}

fn quota(inputs: &Inputs) -> io::Result<u64> {
    let mut client = HostQuotaClient::connect(&inputs.quota, 0, EPOCH)?;
    let verified = client.query(&inputs.owner, &inputs.domain)?;
    let value = verified.observation();
    if value.project_id != inputs.project
        || value.hard_limit_bytes != HARD_LIMIT
        || value.tier_charge_budget_bytes != inputs.budget
        || value.configured_limit_sum_bytes > inputs.budget
        || value.charged_reserved_bytes > HARD_LIMIT
    {
        return Err(invalid("admission fresh helper observation differs"));
    }
    Ok(value.charged_reserved_bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    identity: (u64, u64),
    custody: (u32, u32, u32, u64),
    size: (u64, u64),
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<Metadata> for Stamp {
    fn from(value: Metadata) -> Self {
        Self {
            identity: (value.dev(), value.ino()),
            custody: (value.uid(), value.gid(), value.mode(), value.nlink()),
            size: (value.len(), value.blocks()),
            modified: (value.mtime(), value.mtime_nsec()),
            changed: (value.ctime(), value.ctime_nsec()),
        }
    }
}

fn open_path(path: &Path) -> io::Result<File> {
    Ok(File::from(native::openat2(
        native::CWD,
        path,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )?))
}

fn read_file(path: &Path, limit: usize) -> io::Result<(File, Vec<u8>)> {
    let retained = open_path(path)?;
    let before = retained.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.len() > limit as u64 {
        return Err(invalid(
            "fixture input is not a bounded single-link ordinary file",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOATIME)
        .open(format!("/proc/self/fd/{}", retained.as_raw_fd()))?;
    if Stamp::from(file.metadata()?) != Stamp::from(before) {
        return Err(invalid(
            "classified fixture file changed during readable open",
        ));
    }
    let stamp = Stamp::from(file.metadata()?);
    let mut bytes = Vec::new();
    (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit
        || Stamp::from(file.metadata()?) != stamp
        || Stamp::from(open_path(path)?.metadata()?) != stamp
    {
        return Err(invalid("fixture file changed during bounded read"));
    }
    Ok((file, bytes))
}

fn namespace(inputs: &Inputs) -> io::Result<BTreeMap<PathBuf, (Stamp, Vec<u8>)>> {
    let mut pending = vec![inputs.root.join("chunks"), inputs.root.join("objects")];
    let mut entries = BTreeMap::new();
    while let Some(path) = pending.pop() {
        if entries.len() >= 128 {
            return Err(invalid("fixture namespace exceeds bound"));
        }
        let file = open_path(&path)?;
        let stamp = file.metadata()?;
        if stamp.is_dir() {
            for child in fs::read_dir(&path)? {
                pending.push(child?.path());
            }
            if pending.len() > 128 {
                return Err(invalid("fixture pending namespace exceeds bound"));
            }
            entries.insert(path, (Stamp::from(stamp), Vec::new()));
        } else {
            let (_, bytes) = read_file(&path, WINDOW)?;
            entries.insert(path, (Stamp::from(stamp), bytes));
        }
    }
    Ok(entries)
}

fn unchanged(
    inputs: &Inputs,
    snapshot: &[u8],
    names: &BTreeMap<PathBuf, (Stamp, Vec<u8>)>,
) -> io::Result<()> {
    if state_bytes(inputs)? != snapshot || &namespace(inputs)? != names {
        return Err(invalid(
            "effect-free admission refusal changed policy or namespace",
        ));
    }
    Ok(())
}

fn canonical(inputs: &Inputs, relative: &Path, expected: &[u8]) -> io::Result<(u64, u64)> {
    let path = inputs.root.join(relative);
    let (file, bytes) = read_file(&path, WINDOW)?;
    let metadata = file.metadata()?;
    let project = NativeProject::inspect(&file)?;
    if bytes != expected
        || metadata.uid() != 840
        || metadata.gid() != 845
        || metadata.mode() & 0o7777 != 0o640
        || project.project_id != inputs.project
    {
        return Err(invalid("canonical admission inode bytes or custody differ"));
    }
    let allocated = synchronized_allocated_bytes(&file)?;
    let mut directory_bytes = 0_u64;
    let mut parent = relative
        .parent()
        .ok_or_else(|| invalid("canonical parent absent"))?;
    loop {
        let directory = File::from(native::openat2(
            native::CWD,
            inputs.root.join(parent),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )?);
        let value = directory.metadata()?;
        let actual = NativeProject::inspect(&directory)?;
        if value.uid() != 840
            || value.gid() != 845
            || value.mode() & 0o7777 != 0o2770
            || actual.project_id != inputs.project
            || !actual.inherit
            || value.dev() != metadata.dev()
        {
            return Err(invalid("canonical admission parent custody differs"));
        }
        directory_bytes = directory_bytes
            .checked_add(synchronized_allocated_bytes(&directory)?)
            .ok_or_else(|| invalid("fixture directory allocation overflow"))?;
        parent = parent
            .parent()
            .ok_or_else(|| invalid("canonical ancestry absent"))?;
        if parent.as_os_str().is_empty() {
            break;
        }
    }
    if allocated == 0 {
        return Err(invalid("canonical admission has no measured allocation"));
    }
    Ok((allocated, directory_bytes))
}

fn chunk_path(value: &Descriptor) -> PathBuf {
    let hash = hex(value.digest());
    PathBuf::from(format!("chunks/{}/{}.0", &hash[..2], hash))
}

fn verify_chunk(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    plaintext: &[u8],
    holds: &mut Vec<Hold>,
) -> io::Result<()> {
    let declared = descriptor(plaintext)?;
    let encoded = raw(plaintext);
    let expected_hold = hold(encoded.len(), [hex(declared.digest())])?;
    let receipt = runtime
        .block_on(owner.admit_chunk(declared.clone(), ChunkPosition::Final, encoded.clone()))
        .map_err(io::Error::other)?;
    let (allocated, directories) = canonical(inputs, &chunk_path(&declared), &encoded)?;
    if receipt.descriptor() != &declared
        || receipt.synchronized_chunk_bytes() != allocated
        || receipt.synchronized_directory_bytes() != directories
        || receipt.future_hold_bytes() != expected_hold.bytes
        || receipt.charged_reserved_bytes() != quota(inputs)?
    {
        return Err(invalid("chunk admission acknowledgment accounting differs"));
    }
    holds.push(expected_hold);
    drop(receipt);
    check_state(runtime, inputs, holds)?;
    canonical(inputs, &chunk_path(&declared), &encoded)?;
    Ok(())
}

fn chunks(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let plaintext = vec![31; 65536];
    let declared = descriptor(&plaintext)?;
    let baseline = state_bytes(inputs)?;
    let names = namespace(inputs)?;
    // Each rejection class independently exceeds the 64-entry physical registry.
    // A leak in either path must prevent the subsequent genuine valid ACK.
    for index in 0..(2 * REJECTIONS) {
        let encoded = if index % 2 == 0 {
            vec![255]
        } else {
            raw(&vec![32; plaintext.len()])
        };
        match runtime.block_on(owner.admit_chunk(declared.clone(), ChunkPosition::Final, encoded)) {
            Err(NativeChunkAdmissionError::Accepted(error))
                if !matches!(
                    error.kind(),
                    io::ErrorKind::StorageFull | io::ErrorKind::WouldBlock
                ) => {}
            _ => {
                return Err(invalid(
                    "malformed chunk was not rejected by the physical owner",
                ));
            }
        }
        unchanged(inputs, &baseline, &names).inspect_err(|error| {
            eprintln!("admission invalid-chunk iteration {index}: {error}");
        })?;
    }
    let oversized = vec![7; WINDOW + 1];
    let original_capacity = oversized.capacity();
    match runtime.block_on(owner.admit_chunk(declared.clone(), ChunkPosition::Final, oversized)) {
        Err(NativeChunkAdmissionError::Unsubmitted {
            error,
            descriptor,
            position,
            encoded,
        }) if error.kind() == io::ErrorKind::StorageFull
            && descriptor == declared
            && position == ChunkPosition::Final
            && encoded.len() == WINDOW + 1
            && encoded.capacity() == original_capacity
            && encoded.iter().all(|byte| *byte == 7) => {}
        _ => {
            return Err(invalid(
                "oversized unsubmitted chunk did not return exact inputs",
            ));
        }
    }
    unchanged(inputs, &baseline, &names)?;
    let mut holds = Vec::new();
    verify_chunk(owner, runtime, inputs, &plaintext, &mut holds)?;
    // Stay below the minimum boundary so this is a genuinely valid final chunk,
    // independently of where the content-defined cutter would stop larger data.
    let refusal_length = inputs
        .owner_config()?
        .location
        .chunk_profile()
        .minimum()
        .checked_sub(1)
        .ok_or_else(|| invalid("fixture profile has no positive final chunk"))?;
    let refusal_plaintext = vec![54; refusal_length];
    let refusal_descriptor = descriptor(&refusal_plaintext)?;
    let refusal_encoded = raw(&refusal_plaintext);
    let refusal_hold = hold(refusal_encoded.len(), [hex(refusal_descriptor.digest())])?;
    for value in 33..53 {
        let protected = holds.iter().try_fold(HOLD, |total, hold| {
            total
                .checked_add(hold.bytes)
                .ok_or_else(|| invalid("fixture protected hold sum overflow"))
        })?;
        let proposed = quota(inputs)?
            .checked_add(protected)
            .and_then(|total| total.checked_add(refusal_hold.bytes))
            .ok_or_else(|| invalid("fixture preflight budget overflow"))?;
        if proposed > CAPACITY {
            let snapshot = state_bytes(inputs)?;
            let names = namespace(inputs)?;
            // Final reconciliation can also reject capacity after allocation.
            // This separate valid probe's future hold ALONE exceeds the fresh
            // charge budget, so its refusal must precede policy/namespace effects.
            match runtime.block_on(owner.admit_chunk(
                refusal_descriptor.clone(),
                ChunkPosition::Final,
                refusal_encoded.clone(),
            )) {
                Err(NativeChunkAdmissionError::Accepted(error))
                    if error.kind() == io::ErrorKind::StorageFull
                        && error.to_string()
                            == "actual charge and future admission holds exceed capacity" => {}
                _ => return Err(invalid("known preflight capacity deficit did not refuse")),
            }
            unchanged(inputs, &snapshot, &names)?;
            check_state(runtime, inputs, &holds)?;
            return emit(
                "PASS actual repeated chunk refusals, valid canonical admission and finite policy capacity; no Ready",
            );
        }
        let plaintext = vec![value; 65536];
        verify_chunk(owner, runtime, inputs, &plaintext, &mut holds)?;
    }
    Err(invalid(
        "bounded admission sequence did not reach policy capacity",
    ))
}

fn random_id() -> io::Result<PackId> {
    let mut bytes = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(PackId::from_random_bytes(bytes))
}

fn manifest(value: u8) -> io::Result<Vec<u8>> {
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let plaintext = vec![value; profile.minimum() + 1];
    let chunks = plaintext
        .chunks(profile.minimum())
        .map(|bytes| {
            let identity = TERRANE_V1
                .calculate(IdentityKind::Chunk, bytes)
                .map_err(io::Error::other)?;
            Ok(ChunkRef {
                digest: identity.terrane_v1_digest().map_err(io::Error::other)?,
                length: bytes.len() as u64,
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    Manifest {
        size: plaintext.len() as u64,
        chunks,
        hashes: BTreeMap::from([(
            "blake3".into(),
            blake3::hash(&plaintext).as_bytes().to_vec(),
        )]),
        media_type: None,
    }
    .encode(&profile)
    .map_err(io::Error::other)
}

fn metadata_pair() -> io::Result<(PackId, Vec<u8>, Vec<u8>, BTreeSet<String>)> {
    let id = random_id()?;
    let mut writer = PackWriter::new(id, PackClass::Meta, false);
    let mut hashes = BTreeSet::new();
    for value in [41, 42] {
        let bytes = manifest(value)?;
        hashes.insert(hex(&writer
            .append_raw(EntryKind::Manifest, &bytes)
            .map_err(io::Error::other)?));
    }
    let sealed = writer.seal().map_err(io::Error::other)?;
    hashes.insert(hex(TERRANE_V1
        .calculate(IdentityKind::Pack, sealed.bytes())
        .map_err(io::Error::other)?
        .digest()));
    Ok((
        id,
        sealed.bytes().to_vec(),
        sealed.index_object().to_vec(),
        hashes,
    ))
}

fn invalid_metadata_body() -> io::Result<(PackId, Vec<u8>, Vec<u8>)> {
    let id = random_id()?;
    let valid = manifest(43)?;
    // A canonical CBOR integer is structurally valid pack data, but cannot be a
    // Manifest. Select a bounded scalar whose honest digest follows the valid
    // entry in index order, so validating only the first entry cannot suffice.
    let valid_hash = TERRANE_V1
        .calculate(IdentityKind::Manifest, &valid)
        .map_err(io::Error::other)?
        .terrane_v1_digest()
        .map_err(io::Error::other)?;
    let mut invalid_body = None;
    for value in 0..=u16::MAX {
        let mut bytes = Vec::with_capacity(3);
        terrane_core::cbor::write_uint(&mut bytes, u64::from(value));
        let hash = TERRANE_V1
            .calculate(IdentityKind::Manifest, &bytes)
            .map_err(io::Error::other)?
            .terrane_v1_digest()
            .map_err(io::Error::other)?;
        if hash > valid_hash {
            invalid_body = Some(bytes);
            break;
        }
    }
    let invalid_body = invalid_body
        .ok_or_else(|| invalid("bounded semantic fixture has no later scalar entry"))?;
    let mut bodies = Vec::new();
    let mut records = Vec::new();
    for bytes in [&valid, &invalid_body] {
        records.push(Record {
            hash: TERRANE_V1
                .calculate(IdentityKind::Manifest, bytes)
                .map_err(io::Error::other)?
                .terrane_v1_digest()
                .map_err(io::Error::other)?,
            offset: (pack_format::HEADER_SIZE + bodies.len()) as u64,
            body_len: u32::try_from(bytes.len()).map_err(io::Error::other)?,
            plaintext_len: u32::try_from(bytes.len()).map_err(io::Error::other)?,
            codec: 0,
            kind: EntryKind::Manifest as u8,
            dictionary_id: 0,
        });
        bodies.extend_from_slice(bytes);
    }
    records.sort_by_key(|record| record.hash);
    let pack =
        pack_format::encode_pack(Header::new(*id.as_bytes(), true, false), &bodies, &records)
            .map_err(io::Error::other)?;
    let reader = PackReader::open(&pack).map_err(io::Error::other)?;
    if reader.entries().len() != 2 || reader.entries()[0].hash() != &valid_hash {
        return Err(invalid("semantic fixture lost its later invalid entry"));
    }
    let index = reader.index_object();
    Ok((id, pack, index))
}

fn metadata(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let (id, pack, index, hashes) = metadata_pair()?;
    let (semantic_id, semantic_pack, semantic_index) = invalid_metadata_body()?;
    let data_id = random_id()?;
    let mut data = PackWriter::new(data_id, PackClass::Data, false);
    data.append_raw(EntryKind::Chunk, b"wrong metadata class")
        .map_err(io::Error::other)?;
    let data = data.seal().map_err(io::Error::other)?;
    let mut wrong_index = index.clone();
    let first = wrong_index
        .first_mut()
        .ok_or_else(|| invalid("empty detached index fixture"))?;
    *first ^= 1;
    let baseline = state_bytes(inputs)?;
    let names = namespace(inputs)?;
    // Exercise every invalid class beyond the registry bound before valid data.
    for attempt in 0..(5 * REJECTIONS) {
        let (expected, body, detached) = match attempt % 5 {
            0 => (id, vec![255], index.clone()),
            1 => (id, pack.clone(), wrong_index.clone()),
            2 => (random_id()?, pack.clone(), index.clone()),
            3 => (data_id, data.bytes().to_vec(), data.index_object().to_vec()),
            _ => (semantic_id, semantic_pack.clone(), semantic_index.clone()),
        };
        match runtime.block_on(owner.admit_metadata_pack(expected, body, detached)) {
            Err(NativeMetadataAdmissionError::Accepted(error))
                if !matches!(
                    error.kind(),
                    io::ErrorKind::StorageFull | io::ErrorKind::WouldBlock
                ) => {}
            _ => {
                return Err(invalid(
                    "invalid metadata was not rejected by the physical owner",
                ));
            }
        }
        unchanged(inputs, &baseline, &names)?;
    }
    let expected_hold = hold(
        pack.len()
            .checked_add(index.len())
            .ok_or_else(|| invalid("fixture pair length overflow"))?,
        hashes,
    )?;
    let receipt = runtime
        .block_on(owner.admit_metadata_pack(id, pack.clone(), index.clone()))
        .map_err(io::Error::other)?;
    let directory = format!("objects/pack/{:02x}", id.as_bytes()[0]);
    let (pack_bytes, directories) =
        canonical(inputs, Path::new(&format!("{directory}/{id}.pack")), &pack)?;
    let (index_bytes, same_directories) =
        canonical(inputs, Path::new(&format!("{directory}/{id}.idx")), &index)?;
    if receipt.pack_id() != id
        || receipt.synchronized_pair_bytes() != pack_bytes + index_bytes
        || directories != same_directories
        || receipt.synchronized_directory_bytes() != directories
        || receipt.future_hold_bytes() != expected_hold.bytes
        || receipt.charged_reserved_bytes() != quota(inputs)?
    {
        return Err(invalid(
            "metadata acknowledgment or deduplicated pair allocation differs",
        ));
    }
    drop(receipt);
    check_state(runtime, inputs, &[expected_hold])?;
    canonical(inputs, Path::new(&format!("{directory}/{id}.pack")), &pack)?;
    canonical(inputs, Path::new(&format!("{directory}/{id}.idx")), &index)?;
    emit(
        "PASS actual repeated metadata refusals and fully verified canonical pair with retained holds; no Ready",
    )
}

struct NoopWake;
impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn cancelled(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    emit("READY actual admission Resume acknowledged; wait for stopped-helper control")?;
    control("enqueue")?;
    let plaintext = vec![61; 65536];
    let declared = descriptor(&plaintext)?;
    let encoded = raw(&plaintext);
    let first_hold = hold(encoded.len(), [hex(declared.digest())])?;
    let mut request =
        Box::pin(owner.admit_chunk(declared.clone(), ChunkPosition::Final, encoded.clone()));
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    if !matches!(request.as_mut().poll(&mut context), Poll::Pending) {
        return Err(invalid(
            "admission cancellation did not observe accepted Pending",
        ));
    }
    drop(request);
    emit("CANCELLED accepted admission waiter; physical owner retained")?;
    control("resumed")?;

    // A second VALID command must acknowledge. An arbitrary refusal could also
    // result from a late-faulted first job, and therefore proves no completion.
    let second = vec![62; 65536];
    let second_descriptor = descriptor(&second)?;
    let second_encoded = raw(&second);
    let second_hold = hold(second_encoded.len(), [hex(second_descriptor.digest())])?;
    let receipt = runtime
        .block_on(owner.admit_chunk(
            second_descriptor.clone(),
            ChunkPosition::Final,
            second_encoded.clone(),
        ))
        .map_err(io::Error::other)?;
    let (allocated, directories) =
        canonical(inputs, &chunk_path(&second_descriptor), &second_encoded)?;
    if receipt.descriptor() != &second_descriptor
        || receipt.synchronized_chunk_bytes() != allocated
        || receipt.synchronized_directory_bytes() != directories
        || receipt.future_hold_bytes() != second_hold.bytes
        || receipt.charged_reserved_bytes() != quota(inputs)?
    {
        return Err(invalid("valid cancellation barrier acknowledgment differs"));
    }
    drop(receipt);
    canonical(inputs, &chunk_path(&declared), &encoded)?;
    check_state(runtime, inputs, &[first_hold, second_hold])?;
    emit(
        "PASS dropped admission waiter retained physical completion, both canonical inodes and durable holds; no Ready",
    )
}

fn control(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().take(64).read_line(&mut line)?;
    if line.strip_suffix('\n') != Some(expected) {
        return Err(invalid("unexpected admission supervisor control"));
    }
    Ok(())
}

fn emit(message: &str) -> io::Result<()> {
    let mut output = io::stdout().lock();
    writeln!(output, "{message}")?;
    output.flush()
}

#[cfg(test)]
mod tests {
    //! Checks that the adversarial fixture fails semantics after a valid first body.

    use super::*;

    #[test]
    fn semantic_fixture_keeps_honest_hashes_and_a_later_invalid_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        let (id, pack, index) = invalid_metadata_body()?;
        let reader = PackReader::open(&pack)?;
        assert_eq!(reader.header().id(), id);
        reader.check_index_object(&index)?;

        // Generic structure, canonical CBOR and both actual content hashes pass.
        // Only the full Manifest decoder distinguishes the later invalid body.
        let bodies = reader.verified_admissions(&[], &terrane::pack::RawBodyDecoder)?;
        assert_eq!(bodies.len(), 2);
        let profile = ChunkProfile::cdc_1m([0; 32]);
        Manifest::decode(&bodies[0].bytes, &profile)?;
        assert!(Manifest::decode(&bodies[1].bytes, &profile).is_err());
        assert!(
            terrane::host::cache::reconstruct_pack_index(
                &pack,
                id,
                &profile,
                &terrane::repository::MetadataValidator::new(profile.clone()),
                &BTreeMap::new(),
                terrane::host::cache::HostReadLimits {
                    max_allocation_bytes: WINDOW,
                },
            )
            .is_err()
        );
        Ok(())
    }
}
