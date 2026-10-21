//! Exercises actual mixed FIFO order, encoded restoration and unit retirement.
//!
//! The supervisor observes the original inodes independently. Retained files
//! here describe those inodes without granting a lease or retirement authority.
//! Every transition uses the real confined owner and authenticated publisher.

#[path = "admission_pressure.rs"]
mod admission_pressure;

use super::{
    config::{HOLD, Inputs, STATE},
    manifest_publication,
};
use std::{
    fs::{self, File},
    io::{self, BufRead, Read, Write},
    os::unix::fs::{FileExt, MetadataExt},
    time::UNIX_EPOCH,
};
use terrane_format::identity::{Descriptor, Identity, IdentityKind, TERRANE_V1};
use terrane_linux::host_cache::{
    NativeCacheEvictionReport, NativeChunkAdmissionError, NativeMetadataAdmissionError,
    NativeMetadataOwner,
};
use terrane_sdk::{
    host::cache::CacheState,
    pack::{EntryKind, PackClass, PackId, PackWriter},
    store::{ChunkPosition, Clock, TokioClock, TokioLocalFs},
};

const RAW: &[u8] = b"original raw FIFO allocation";
const SEALED: &[u8] = b"original sealed FIFO allocation";

struct Observed {
    file: File,
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
    allocated: u64,
}

impl Observed {
    fn new(file: File, bytes: Vec<u8>) -> io::Result<Self> {
        let metadata = file.metadata()?;
        let observed = Self {
            file,
            bytes,
            device: metadata.dev(),
            inode: metadata.ino(),
            allocated: metadata
                .blocks()
                .checked_mul(512)
                .ok_or_else(|| invalid("encoded eviction allocation overflows"))?,
        };
        observed.check(1)?;
        Ok(observed)
    }

    fn check(&self, links: u64) -> io::Result<()> {
        let metadata = self.file.metadata()?;
        let mut bytes = vec![0; self.bytes.len()];
        self.file.read_exact_at(&mut bytes, 0)?;
        if (metadata.dev(), metadata.ino()) != (self.device, self.inode)
            || metadata.nlink() != links
            || metadata.len() != self.bytes.len() as u64
            || bytes != self.bytes
            || self.allocated == 0
        {
            return Err(invalid(
                "encoded eviction changed original observed backing",
            ));
        }
        Ok(())
    }
}

/// Retains genuine mixed allocations and exercises every original removal path.
///
/// # Errors
/// Refuses incorrect FIFO order, changed original backing, lost dictionary or
/// consumer protection, premature funding release and failed real transitions.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    if inputs.domain != "tenant:encoded-eviction" || original.is_some() {
        return Err(invalid(
            "encoded eviction requires its fresh dedicated domain",
        ));
    }
    let data = manifest_publication::data(false, true)?;
    let dictionary_bytes = data
        .dictionary
        .as_ref()
        .ok_or_else(|| invalid("encoded eviction lacks a genuine dictionary"))?;
    let completed = runtime.block_on(owner.recover())?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;

    // Interleave classes deliberately. Enumerating sealed jobs before encoded
    // jobs would select the second allocation when the first should retire.
    let (raw, raw_deadline) = admit(
        owner,
        runtime,
        inputs,
        RAW,
        ChunkPosition::Final,
        raw_envelope(RAW),
    )?;
    let raw_identity = identity(RAW)?;
    let publication = runtime
        .block_on(owner.publish_inline(descriptor(SEALED)?, raw_envelope(SEALED)))
        .map_err(io::Error::other)?;
    let sealed = Observed::new(publication.handle().try_clone()?, SEALED.to_vec())?;
    if runtime
        .block_on(publication.finish_retired_sources(owner))?
        .completed_sources
        != 0
    {
        return Err(invalid(
            "isolated sealed allocation invented a transfer source",
        ));
    }
    let sealed_deadline = runtime
        .block_on(publication.into_cache(owner))
        .map_err(io::Error::other)?
        .release_grace_ends_at;

    let mut random = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let pack_id = PackId::from_random_bytes(random);
    let mut writer = PackWriter::new(pack_id, PackClass::Meta, false);
    writer
        .append_raw(EntryKind::Manifest, &data.canonical)
        .map_err(io::Error::other)?;
    let pack = writer.seal().map_err(io::Error::other)?;
    let admission = runtime
        .block_on(owner.admit_metadata_pack(
            pack_id,
            pack.bytes().to_vec(),
            pack.index_object().to_vec(),
        ))
        .map_err(io::Error::other)?;
    let directory = inputs
        .root
        .join(format!("objects/pack/{:02x}", pack_id.as_bytes()[0]));
    let pair = [
        Observed::new(
            File::open(directory.join(format!("{pack_id}.idx")))?,
            pack.index_object().to_vec(),
        )?,
        Observed::new(
            File::open(directory.join(format!("{pack_id}.pack")))?,
            pack.bytes().to_vec(),
        )?,
    ];
    let pair_deadline = runtime
        .block_on(admission.into_cache(owner))
        .map_err(io::Error::other)?
        .release_grace_ends_at;
    let (dictionary, dictionary_deadline) = admit(
        owner,
        runtime,
        inputs,
        dictionary_bytes,
        ChunkPosition::Final,
        raw_envelope(dictionary_bytes),
    )?;
    let (dependent, dependent_deadline) = admit(
        owner,
        runtime,
        inputs,
        &data.first,
        ChunkPosition::NonFinal,
        data.encoded_first.clone(),
    )?;
    let dependent_identity = identity(&data.first)?;
    let dictionary_identity = identity(dictionary_bytes)?;
    let deadlines = [
        raw_deadline,
        sealed_deadline,
        pair_deadline,
        dictionary_deadline,
        dependent_deadline,
    ];
    let earliest = deadlines
        .into_iter()
        .min()
        .ok_or_else(|| invalid("missing original grace"))?;
    let expires = deadlines
        .into_iter()
        .max()
        .ok_or_else(|| invalid("missing original grace"))?;
    if now()? >= earliest
        || pressure(owner, runtime, inputs, raw.allocated)?.retired_allocations != 0
    {
        return Err(invalid(
            "original producer grace did not protect every allocation",
        ));
    }
    emit(&format!(
        "ENCODED_EVICTION_INIT expires={expires} raw={} sealed={} pack={pack_id} dictionary={} dependent={}",
        hex(raw_identity.digest()),
        hex(identity(SEALED)?.digest()),
        hex(dictionary_identity.digest()),
        hex(dependent_identity.digest())
    ))?;
    emit("READY mixed encoded allocations retain original producer grace")?;
    control("first")?;
    retired(owner, runtime, inputs, raw.allocated, "first")?;
    raw.check(1)?;
    emit("READY original raw allocation retires before the later sealed allocation")?;

    control("repin")?;
    let deadline = now()?
        .checked_add(600)
        .ok_or_else(|| invalid("consumer deadline overflows"))?;
    let raw_lease = runtime.block_on(owner.pin_resident_chunk(raw_identity.clone(), deadline))?;
    let dependent_lease =
        runtime.block_on(owner.pin_resident_chunk(dependent_identity.clone(), deadline))?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    if raw_lease.read_verified()? != RAW || dependent_lease.read_verified()? != data.first {
        return Err(invalid(
            "restored raw or genuine dictionary-backed consumer failed",
        ));
    }
    if raw_lease.read_encoded()? != raw.bytes || dependent_lease.read_encoded()? != dependent.bytes
    {
        return Err(invalid(
            "consumer changed original raw or dictionary codec envelope",
        ));
    }
    drop(stalled);
    raw.check(1)?;

    // Keep a newer, genuinely unread probationary allocation protected until
    // the dependent finishes. Its actual compressed blocks exceed probation's
    // target so later selection distinguishes dictionary promotion from age.
    let mut noise = vec![0; 96 * 1024];
    File::open("/dev/urandom")?.read_exact(&mut noise)?;
    let unread_plaintext = [noise.as_slice(), noise.as_slice()].concat();
    let encoded = terrane_sdk::codec::encode_chunk(
        &unread_plaintext,
        inputs.owner_config()?.location.chunk_profile().maximum(),
        3,
        None,
    )
    .map_err(io::Error::other)?;
    if encoded.first() != Some(&1) {
        return Err(invalid(
            "unread companion did not exercise genuine Zstd admission",
        ));
    }
    let unread_identity = identity(&unread_plaintext)?;
    let (unread, _) = admit(
        owner,
        runtime,
        inputs,
        &unread_plaintext,
        ChunkPosition::Final,
        encoded,
    )?;
    drop(unread_plaintext);
    drop(noise);
    if unread.allocated <= inputs.owner_config()?.policy.probation_bytes {
        return Err(invalid(
            "unread companion cannot distinguish the actual probation target",
        ));
    }
    let unread_lease =
        runtime.block_on(owner.pin_resident_chunk(unread_identity.clone(), deadline))?;
    emit(&format!(
        "ENCODED_EVICTION_UNREAD hash={}",
        hex(unread_identity.digest())
    ))?;
    emit("READY original encoded allocation restores before a fresh policy-held consumer read")?;

    control("second")?;
    retired(owner, runtime, inputs, sealed.allocated, "sealed")?;
    emit("READY next sealed allocation retires in original mixed FIFO order")?;
    control("pair")?;
    let pair_bytes = pair.iter().try_fold(0_u64, |sum, file| {
        sum.checked_add(file.allocated)
            .ok_or_else(|| invalid("metadata pair allocation overflows"))
    })?;
    retired(owner, runtime, inputs, pair_bytes, "pair")?;
    emit("READY complete original pack and index retire as one allocation")?;
    control("duplicate-pair")?;
    let previous = fs::read(inputs.root.join("state/cache/records.toml"))?;
    let duplicate = runtime.block_on(owner.admit_metadata_pack(
        pack_id,
        pack.bytes().to_vec(),
        pack.index_object().to_vec(),
    ));
    if !matches!(duplicate, Err(NativeMetadataAdmissionError::Accepted(ref error))
        if error.kind() == io::ErrorKind::AlreadyExists)
        || fs::read(inputs.root.join("state/cache/records.toml"))? != previous
    {
        return Err(invalid(
            "restored duplicate pair changed funding or allocated replacement",
        ));
    }
    for member in &pair {
        member.check(1)?;
    }
    emit("READY duplicate pack admission restores both originals and refuses before new funding")?;
    control("retire-pair-duplicate")?;
    retired(owner, runtime, inputs, pair_bytes, "pair-duplicate")?;
    emit("READY restored original pack unit retires under a fresh actual acknowledgment")?;
    control("drop-pair")?;
    sealed.check(0)?;
    for member in &pair {
        member.check(0)?;
    }
    drop(sealed);
    drop(pair);
    observe(owner, runtime, "pair-held")?;
    emit(
        "READY removed pack and sealed descriptions close while independent observers retain charge",
    )?;
    control("after-pair-observers")?;
    observe(owner, runtime, "pair-closed")?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    if raw_lease.read_verified()? != RAW || dependent_lease.read_verified()? != data.first {
        return Err(invalid(
            "unrelated removal invalidated live encoded consumers",
        ));
    }
    if raw_lease.read_encoded()? != raw.bytes || dependent_lease.read_encoded()? != dependent.bytes
    {
        return Err(invalid(
            "unrelated removal changed original encoded consumer bytes",
        ));
    }
    drop(stalled);
    emit("READY independent encoded consumers survive actual pack and sealed removal")?;

    control("release-raw")?;
    runtime.block_on(owner.release_consumer_lease(&raw_lease))?;
    if [raw_lease.read_verified(), raw_lease.read_encoded()]
        .into_iter()
        .any(|result| {
            result
                .err()
                .is_none_or(|error| error.kind() != io::ErrorKind::PermissionDenied)
        })
    {
        return Err(invalid("released raw consumer retained access"));
    }
    drop(raw_lease);
    grace(owner, runtime, inputs, &raw_identity, "raw")?;
    control("retire-raw")?;
    retired(owner, runtime, inputs, raw.allocated, "raw")?;
    emit("READY restored original raw allocation retires only after actual consumer grace")?;
    control("duplicate-raw")?;
    let previous = fs::read(inputs.root.join("state/cache/records.toml"))?;
    let duplicate = runtime.block_on(owner.admit_chunk(
        descriptor(RAW)?,
        ChunkPosition::Final,
        raw_envelope(RAW),
    ));
    if !matches!(duplicate, Err(NativeChunkAdmissionError::Accepted(ref error))
        if error.kind() == io::ErrorKind::AlreadyExists)
        || fs::read(inputs.root.join("state/cache/records.toml"))? != previous
    {
        return Err(invalid(
            "restored duplicate chunk changed funding or allocated replacement",
        ));
    }
    raw.check(1)?;
    emit(
        "READY duplicate chunk admission restores original backing and refuses before new funding",
    )?;
    control("retire-raw-duplicate")?;
    retired(owner, runtime, inputs, raw.allocated, "raw-duplicate")?;
    emit("READY restored duplicate raw allocation retires under a fresh actual acknowledgment")?;
    control("drop-raw")?;
    raw.check(0)?;
    drop(raw);
    observe(owner, runtime, "raw-held")?;
    emit("READY removed raw description closes while independent observer retains charge")?;
    control("after-raw-observer")?;
    observe(owner, runtime, "raw-closed")?;
    if runtime
        .block_on(owner.pin_resident_chunk(raw_identity, deadline))
        .is_ok()
    {
        return Err(invalid("removed raw allocation regained a native grant"));
    }
    emit("READY removed raw allocation cannot issue a fresh consumer grant")?;

    control("release-dependent")?;
    runtime.block_on(owner.release_consumer_lease(&dependent_lease))?;
    if [
        dependent_lease.read_verified(),
        dependent_lease.read_encoded(),
    ]
    .into_iter()
    .any(|result| {
        result
            .err()
            .is_none_or(|error| error.kind() != io::ErrorKind::PermissionDenied)
    }) {
        return Err(invalid(
            "released dictionary-backed consumer retained access",
        ));
    }
    drop(dependent_lease);
    grace(owner, runtime, inputs, &dependent_identity, "dependent")?;
    control("retire-dependent")?;
    retired(owner, runtime, inputs, dependent.allocated, "dependent")?;
    dictionary.check(1)?;
    emit("READY original dictionary remains protected throughout dependent retirement")?;
    control("drop-dependent")?;
    dependent.check(0)?;
    drop(dependent);
    observe(owner, runtime, "dependent-held")?;
    emit(
        "READY removed dependent description closes after its actual dictionary promise releases",
    )?;
    control("after-dependent-observer")?;
    observe(owner, runtime, "dependent-closed")?;

    control("release-unread")?;
    runtime.block_on(owner.release_consumer_lease(&unread_lease))?;
    if [unread_lease.read_verified(), unread_lease.read_encoded()]
        .into_iter()
        .any(|result| {
            result
                .err()
                .is_none_or(|error| error.kind() != io::ErrorKind::PermissionDenied)
        })
    {
        return Err(invalid(
            "released unread companion retained consumer access",
        ));
    }
    drop(unread_lease);
    // The dictionary is now eligible, so observing this grace must not request
    // an eviction before the companion's own durable protection has expired.
    report_grace(runtime, inputs, &unread_identity, "unread")?;
    control("retire-unread")?;
    retired(owner, runtime, inputs, unread.allocated, "unread")?;
    dictionary.check(1)?;
    emit(
        "READY unread Zstd companion retires before the older dictionary actually consumed by verified reads",
    )?;
    control("drop-unread")?;
    unread.check(0)?;
    drop(unread);
    observe(owner, runtime, "unread-held")?;
    emit(
        "READY removed unread companion description closes while its independent observer retains charge",
    )?;
    control("after-unread-observer")?;
    observe(owner, runtime, "unread-closed")?;
    emit("READY promoted original dictionary remains canonical after unread companion closure")?;

    control("retire-dictionary")?;
    retired(owner, runtime, inputs, dictionary.allocated, "dictionary")?;
    emit("READY original dictionary retires only after acknowledged dependent removal")?;
    control("drop-dictionary")?;
    dictionary.check(0)?;
    drop(dictionary);
    observe(owner, runtime, "dictionary-held")?;
    emit("READY removed dictionary description closes while independent observer retains charge")?;
    control("finish")?;
    let final_report = observe(owner, runtime, "dictionary-closed")?;
    if final_report.future_hold_bytes != HOLD
        || runtime
            .block_on(owner.pin_resident_chunk(dependent_identity, deadline))
            .is_ok()
        || runtime
            .block_on(owner.pin_resident_chunk(dictionary_identity, deadline))
            .is_ok()
    {
        return Err(invalid(
            "encoded removal lost bootstrap funding or restored a removed grant",
        ));
    }
    emit("READY all original encoded allocations removed with the Running owner retained")?;
    control("done")?;
    emit(
        "PASS actual mixed FIFO encoded restoration, consumer and dictionary protection, complete pack unit removal and original descriptor closure; no Ready",
    )?;
    admission_pressure::run(owner, runtime, inputs)
}

fn admit(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    bytes: &[u8],
    position: ChunkPosition,
    encoded: Vec<u8>,
) -> io::Result<(Observed, u64)> {
    let descriptor = descriptor(bytes)?;
    let codec = encoded
        .first()
        .copied()
        .ok_or_else(|| invalid("fixture envelope absent"))?;
    let admission = runtime
        .block_on(owner.admit_chunk(descriptor.clone(), position, encoded.clone()))
        .map_err(io::Error::other)?;
    let hash = hex(descriptor.digest());
    let path = inputs
        .root
        .join("chunks")
        .join(&hash[..2])
        .join(format!("{hash}.{codec}"));
    let original = Observed::new(File::open(path)?, encoded)?;
    let report = runtime
        .block_on(admission.into_cache(owner))
        .map_err(io::Error::other)?;
    if report.synchronized_member_bytes != original.allocated {
        return Err(invalid("encoded handoff misreported original allocation"));
    }
    Ok((original, report.release_grace_ends_at))
}

fn pressure(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    bytes: u64,
) -> io::Result<NativeCacheEvictionReport> {
    let current = runtime.block_on(owner.evict_cached(0))?;
    let total = current
        .charged_reserved_bytes
        .checked_add(current.future_hold_bytes)
        .ok_or_else(|| invalid("native pressure sum overflows"))?;
    let incoming = inputs
        .owner_config()?
        .policy
        .capacity
        .checked_sub(total)
        .and_then(|free| free.checked_add(bytes))
        .ok_or_else(|| invalid("native pressure overflows"))?;
    runtime.block_on(owner.evict_cached(incoming))
}

fn retired(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    bytes: u64,
    kind: &str,
) -> io::Result<()> {
    let report = pressure(owner, runtime, inputs, bytes)?;
    if report.retired_allocations != 1 || report.target_met {
        return Err(invalid(
            "native FIFO lost exact unit order or inferred premature reclamation",
        ));
    }
    emit(&format!(
        "ENCODED_EVICTION_PENDING kind={kind} charged={} future={}",
        report.charged_reserved_bytes, report.future_hold_bytes
    ))
}

fn observe(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    kind: &str,
) -> io::Result<NativeCacheEvictionReport> {
    let report = runtime.block_on(owner.evict_cached(0))?;
    if !report.target_met {
        return Err(invalid(
            "native cache exceeds its actual configured capacity",
        ));
    }
    emit(&format!(
        "ENCODED_EVICTION_MEASUREMENT kind={kind} charged={} future={}",
        report.charged_reserved_bytes, report.future_hold_bytes
    ))?;
    Ok(report)
}

fn grace(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    identity: &Identity,
    kind: &str,
) -> io::Result<()> {
    let current = pressure(owner, runtime, inputs, 4096)?;
    if current.retired_allocations != 0 {
        return Err(invalid(
            "native FIFO evicted actual consumer grace or dictionary protection",
        ));
    }
    report_grace(runtime, inputs, identity, kind)
}

fn report_grace(
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    identity: &Identity,
    kind: &str,
) -> io::Result<()> {
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("encoded eviction policy absent"))?;
    let hash = hex(identity.digest());
    let pins = state
        .pins
        .iter()
        .filter(|pin| pin.hash == hash && pin.owner.starts_with("consumer-grace:"))
        .collect::<Vec<_>>();
    let [pin] = pins.as_slice() else {
        return Err(invalid("original encoded consumer grace absent"));
    };
    if !state
        .leases
        .iter()
        .any(|lease| lease.owner == pin.owner && lease.expires == pin.expires)
    {
        return Err(invalid(
            "encoded consumer grace lacks its actual durable lease",
        ));
    }
    emit(&format!(
        "ENCODED_EVICTION_GRACE kind={kind} expires={}",
        pin.expires
    ))?;
    emit(&format!(
        "READY actual {kind} consumer grace protects original encoded allocation"
    ))
}

fn identity(bytes: &[u8]) -> io::Result<Identity> {
    TERRANE_V1
        .calculate(IdentityKind::Chunk, bytes)
        .map_err(io::Error::other)
}

fn descriptor(bytes: &[u8]) -> io::Result<Descriptor> {
    Descriptor::from_identity(&TERRANE_V1, &identity(bytes)?, bytes).map_err(io::Error::other)
}

fn raw_envelope(bytes: &[u8]) -> Vec<u8> {
    [vec![0], bytes.to_vec()].concat()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now() -> io::Result<u64> {
    TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(io::Error::other)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn emit(message: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{message}")?;
    out.flush()
}

fn control(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim_end() != expected {
        return Err(invalid("encoded eviction control mismatch"));
    }
    Ok(())
}
