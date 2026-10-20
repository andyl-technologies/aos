//! Exercises genuine encoded cache custody, dictionary protection and transfer.
//!
//! File observations establish no authority. All handoffs and subsequent source
//! retirement run on the original physical owner with actual admitted resources.

use super::{
    config::{HOLD, Inputs, STATE},
    manifest_publication,
};
use std::{
    fs::{self, File},
    future::Future,
    io::{self, BufRead, Read, Write},
    os::unix::fs::{FileExt, MetadataExt},
    path::PathBuf,
    task::{Context, Poll, Waker},
};
use terrane::{
    host::cache::CacheState,
    pack::{EntryKind, PackClass, PackId, PackWriter},
    store::{ChunkPosition, TokioLocalFs},
};
use terrane_core::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_fs::host_cache::{
    NativeAdmissionHandoffError, NativeAdmissionHandoffReport, NativeChunkAdmission,
    NativeMetadataOwner,
};

struct Observation {
    path: PathBuf,
    file: File,
    device: u64,
    inode: u64,
    bytes: Vec<u8>,
}

impl Observation {
    fn open(path: PathBuf, bytes: Vec<u8>) -> io::Result<Self> {
        let file = File::open(&path)?;
        let metadata = file.metadata()?;
        let result = Self {
            path,
            file,
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes,
        };
        result.check(true)?;
        Ok(result)
    }

    fn check(&self, canonical: bool) -> io::Result<()> {
        let metadata = self.file.metadata()?;
        let mut bytes = vec![0; self.bytes.len()];
        self.file.read_exact_at(&mut bytes, 0)?;
        if metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.len() != self.bytes.len() as u64
            || bytes != self.bytes
            || metadata.nlink() != u64::from(canonical)
        {
            return Err(invalid(
                "encoded cache handoff changed original native backing",
            ));
        }
        if canonical {
            let named = fs::metadata(&self.path)?;
            if named.dev() != self.device || named.ino() != self.inode {
                return Err(invalid("encoded cache canonical name changed inode"));
            }
        }
        Ok(())
    }

    fn allocated(&self) -> io::Result<u64> {
        self.file
            .metadata()?
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| invalid("encoded member allocation overflows"))
    }
}

/// Runs actual handoffs without constructing native ownership from policy rows.
///
/// # Errors
/// Refuses changed native bytes, false funding release, lost waiter custody,
/// missing dictionary protection or incorrect original source retirement.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    if inputs.domain != "tenant:admission-cache" || original.is_some() {
        return Err(invalid(
            "encoded cache handoff requires a fresh dedicated domain",
        ));
    }
    let completed = runtime.block_on(owner.recover())?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    let data = manifest_publication::data(false, true)?;
    let dictionary = data
        .dictionary
        .as_ref()
        .ok_or_else(|| invalid("encoded handoff fixture lacks its real dictionary"))?;
    let (admission, dictionary_file) = admit(
        owner,
        runtime,
        inputs,
        dictionary,
        ChunkPosition::Final,
        raw(dictionary),
    )?;
    let admission = refuse_full_queue(owner, runtime, inputs, admission)?;
    let before = load(runtime, inputs)?;
    let report = runtime
        .block_on(admission.into_cache(owner))
        .map_err(io::Error::other)?;
    check_report(
        runtime,
        inputs,
        &before,
        &report,
        dictionary_file.allocated()?,
    )?;

    // The dictionary's original producer reservation is already gone. The next
    // real admission must retain its native cache custody and exact dependency.
    let (admission, first_file) = admit(
        owner,
        runtime,
        inputs,
        &data.first,
        ChunkPosition::NonFinal,
        data.encoded_first.clone(),
    )?;
    let before = load(runtime, inputs)?;
    let report = runtime
        .block_on(admission.into_cache(owner))
        .map_err(io::Error::other)?;
    check_report(runtime, inputs, &before, &report, first_file.allocated()?)?;

    let (admission, tail_file) = admit(
        owner,
        runtime,
        inputs,
        &data.tail,
        ChunkPosition::Final,
        raw(&data.tail),
    )?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    let before = fs::read(policy(inputs))?;
    let mut attempt = Box::pin(admission.into_cache(owner));
    if !matches!(
        attempt
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ) {
        return Err(invalid(
            "stalled handoff failed to retain its accepted command",
        ));
    }
    drop(attempt);
    emit("READY accepted encoded handoff waiter cancelled with physical owner stalled")?;
    control("release-handoff")?;
    if fs::read(policy(inputs))? != before {
        return Err(invalid(
            "cancelled handoff completed while physical owner was stalled",
        ));
    }
    drop(stalled);
    // A real queued command is the completion barrier; dropping the reply never
    // creates a synthetic completion or releases the original admission job.
    runtime.block_on(owner.sweep_consumer_leases())?;
    let cancelled = load(runtime, inputs)?;
    if cancelled.reservations.len() != 1 || future(&cancelled)? != HOLD {
        return Err(invalid(
            "cancelled handoff lost physical custody or retained producer funding",
        ));
    }
    tail_file.check(true)?;

    let mut random = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let id = PackId::from_random_bytes(random);
    let mut writer = PackWriter::new(id, PackClass::Meta, false);
    writer
        .append_raw(EntryKind::Manifest, &data.canonical)
        .map_err(io::Error::other)?;
    let sealed = writer.seal().map_err(io::Error::other)?;
    let pair = runtime
        .block_on(owner.admit_metadata_pack(
            id,
            sealed.bytes().to_vec(),
            sealed.index_object().to_vec(),
        ))
        .map_err(io::Error::other)?;
    let directory = inputs
        .root
        .join(format!("objects/pack/{:02x}", id.as_bytes()[0]));
    let pack_file = Observation::open(
        directory.join(format!("{id}.pack")),
        sealed.bytes().to_vec(),
    )?;
    let index_file = Observation::open(
        directory.join(format!("{id}.idx")),
        sealed.index_object().to_vec(),
    )?;
    let before = load(runtime, inputs)?;
    let report = runtime
        .block_on(pair.into_cache(owner))
        .map_err(io::Error::other)?;
    let pair_bytes = pack_file
        .allocated()?
        .checked_add(index_file.allocated()?)
        .ok_or_else(|| invalid("metadata pair allocation overflows"))?;
    check_report(runtime, inputs, &before, &report, pair_bytes)?;
    let cached = load(runtime, inputs)?;
    check_cached(&cached, 4, true)?;
    let expires = cached
        .leases
        .iter()
        .filter(|row| row.owner.starts_with("admission-grace:"))
        .map(|row| row.expires)
        .max()
        .ok_or_else(|| invalid("encoded grace deadline absent"))?;
    let before_grace = fs::read(policy(inputs))?;
    emit(&format!(
        "ADMISSION_CACHE_GRACE expires={expires} charged_reserved_bytes={} future_hold_bytes={}",
        report.charged_reserved_bytes, report.future_hold_bytes
    ))?;
    emit("READY genuine encoded chunks and metadata pair cached with original inodes retained")?;
    control("after-grace")?;
    let expired = load(runtime, inputs)?;
    check_cached(&expired, 0, true)?;
    if fs::read(policy(inputs))? == before_grace {
        return Err(invalid(
            "original encoded release grace was not durably swept",
        ));
    }
    for member in [
        &dictionary_file,
        &first_file,
        &tail_file,
        &pack_file,
        &index_file,
    ] {
        member.check(true)?;
    }

    // This actual publication consumes cached admissions after both their old
    // producer holds and release grace have disappeared. Dictionary decoding
    // and reconstruction metadata must still come from the original resources.
    let publication = runtime.block_on(owner.publish_manifest(data.identity))?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    let mut plaintext = vec![0; data.plaintext.len()];
    publication.handle().read_exact_at(&mut plaintext, 0)?;
    if plaintext != data.plaintext {
        return Err(invalid(
            "cached encoded sources failed real verified reconstruction",
        ));
    }
    drop(stalled);
    emit("READY genuine cached admissions transferred into verified sealed manifest")?;
    control("finish-sources")?;
    let cleanup = runtime.block_on(publication.finish_retired_sources(owner))?;
    if cleanup.completed_sources != 2 {
        return Err(invalid(
            "cached admission cleanup lacks original source acknowledgements",
        ));
    }
    first_file.check(false)?;
    tail_file.check(false)?;
    drop(first_file);
    drop(tail_file);
    runtime.block_on(publication.close_resident_reads(owner))?;
    let report = runtime
        .block_on(publication.into_cache(owner))
        .map_err(io::Error::other)?;
    let after = load(runtime, inputs)?;
    check_cached(&after, 0, false)?;
    if report.released_source_admissions != 2
        || report.future_hold_bytes != HOLD
        || after.reservations.len() != 1
        || !after
            .pins
            .iter()
            .any(|row| row.owner.starts_with("metadata:"))
    {
        return Err(invalid(
            "publication failed to release exact cached source dependencies",
        ));
    }
    dictionary_file.check(true)?;
    pack_file.check(true)?;
    index_file.check(true)?;
    emit(&format!(
        "ADMISSION_CACHE_FINAL charged_reserved_bytes={} future_hold_bytes={}",
        report.charged_reserved_bytes, report.future_hold_bytes
    ))?;
    emit(
        "READY original cache owner retains dictionary and reconstruction pair after acknowledged source retirement",
    )?;
    control("finish")?;
    emit(
        "PASS genuine encoded cache handoff preserves queue retry, cancelled waiter custody, dictionary dependencies and native pair through grace and actual source retirement; no Ready",
    )
}

fn refuse_full_queue(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    admission: NativeChunkAdmission,
) -> io::Result<NativeChunkAdmission> {
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    let before = fs::read(policy(inputs))?;
    let mut queued = Vec::new();
    for _ in 0..inputs.owner_config()?.queued_commands {
        let mut sweep = Box::pin(owner.sweep_consumer_leases());
        if !matches!(
            sweep.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return Err(invalid("stalled owner completed a queued encoded control"));
        }
        queued.push(sweep);
    }
    let mut attempt = Box::pin(admission.into_cache(owner));
    let original = match attempt
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Err(NativeAdmissionHandoffError::Unsubmitted { error, admission }))
            if error.kind() == io::ErrorKind::WouldBlock =>
        {
            admission
        }
        _ => return Err(invalid("full encoded queue lost original retry admission")),
    };
    drop(attempt);
    if fs::read(policy(inputs))? != before {
        return Err(invalid(
            "unsubmitted encoded handoff changed original policy",
        ));
    }
    drop(stalled);
    for sweep in queued {
        if runtime.block_on(sweep)? != 0 {
            return Err(invalid(
                "encoded queue control unexpectedly expired protection",
            ));
        }
    }
    emit("PASS full encoded handoff queue returns original admission without policy mutation")?;
    Ok(original)
}

fn check_report(
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    before: &CacheState,
    report: &NativeAdmissionHandoffReport,
    allocated: u64,
) -> io::Result<()> {
    let after = load(runtime, inputs)?;
    if report.synchronized_member_bytes != allocated
        || allocated == 0
        || report.charged_reserved_bytes < allocated
        || report.released_future_hold_bytes == 0
        || future(before)?.checked_sub(report.released_future_hold_bytes) != Some(future(&after)?)
        || report.future_hold_bytes != future(&after)?
        || before.reservations.len().checked_sub(1) != Some(after.reservations.len())
    {
        return Err(invalid(
            "encoded cache report confused physical allocation and future funding",
        ));
    }
    Ok(())
}

fn check_cached(state: &CacheState, grace: usize, dependency: bool) -> io::Result<()> {
    if future(state)? != HOLD
        || state.reservations.len() != 1
        || state
            .leases
            .iter()
            .any(|row| row.owner.starts_with("admission:"))
        || state
            .pins
            .iter()
            .any(|row| row.owner.starts_with("admission:"))
        || state
            .leases
            .iter()
            .filter(|row| row.owner.starts_with("admission-grace:"))
            .count()
            != grace
        || state
            .leases
            .iter()
            .filter(|row| row.owner.starts_with("cache-dependency:"))
            .count()
            != usize::from(dependency)
        || state
            .pins
            .iter()
            .filter(|row| row.owner.starts_with("cache-dependency:"))
            .count()
            != usize::from(dependency)
    {
        return Err(invalid(
            "encoded cache protection differs from actual retained dependencies",
        ));
    }
    Ok(())
}

fn admit(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    plaintext: &[u8],
    position: ChunkPosition,
    encoded: Vec<u8>,
) -> io::Result<(NativeChunkAdmission, Observation)> {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .map_err(io::Error::other)?;
    let descriptor =
        Descriptor::from_identity(&TERRANE_V1, &identity, plaintext).map_err(io::Error::other)?;
    let hash: String = descriptor
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let codec = *encoded
        .first()
        .ok_or_else(|| invalid("encoded fixture is empty"))?;
    let admission = runtime
        .block_on(owner.admit_chunk(descriptor, position, encoded.clone()))
        .map_err(io::Error::other)?;
    let file = Observation::open(
        inputs
            .root
            .join(format!("chunks/{}/{hash}.{codec}", &hash[..2])),
        encoded,
    )?;
    Ok((admission, file))
}

fn load(runtime: &tokio::runtime::Runtime, inputs: &Inputs) -> io::Result<CacheState> {
    runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("encoded cache policy absent"))
}

fn future(state: &CacheState) -> io::Result<u64> {
    state.reservations.iter().try_fold(0_u64, |sum, row| {
        sum.checked_add(row.bytes)
            .ok_or_else(|| invalid("encoded future hold sum overflows"))
    })
}

fn policy(inputs: &Inputs) -> PathBuf {
    inputs.root.join("state/cache/records.toml")
}

fn raw(bytes: &[u8]) -> Vec<u8> {
    [vec![0], bytes.to_vec()].concat()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn emit(message: &str) -> io::Result<()> {
    writeln!(io::stdout().lock(), "{message}")?;
    io::stdout().flush()
}

fn control(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim_end() != expected {
        return Err(invalid("encoded cache control mismatch"));
    }
    Ok(())
}
