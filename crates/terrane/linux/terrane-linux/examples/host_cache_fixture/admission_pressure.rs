//! Exercises automatic admission pressure on the original running native owner.
//!
//! The supervisor independently retains every original inode. No explicit
//! eviction request supplies pressure: only the incoming verified admission
//! may select victims. Original open descriptors keep their actual quota charge.

#[path = "lower_fetch.rs"]
mod lower_fetch;

use super::{
    HOLD, Inputs, NativeChunkAdmissionError, NativeMetadataOwner, Observed, admit, control,
    descriptor, emit, hex, identity, invalid, now, raw_envelope,
};
use std::{fs, fs::File, io, time::Duration};
use terrane_linux::host_cache::NativeChunkFetchRequest;
use terrane_sdk::{
    host::cache::CircuitBreaker,
    repository::MetadataValidator,
    store::{ChunkPosition, StoreErrorKind, TokioClock},
};

const MEMBERS: usize = 19;
const PROTECTED: usize = 3;
const MEMBER_PLAINTEXT: usize = 256 * 1024 - 1;
const INCOMING_PLAINTEXT: usize = 16 * 1024 - 1;

/// Refuses invalid input before eviction and retries valid input after real closure.
///
/// # Errors
/// Refuses absent pressure, changed originals, wrong FIFO selection, evicted
/// consumers, premature quota release and failed native reservation or retry.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let mut originals = Vec::<Option<Observed>>::new();
    let mut hashes = Vec::new();
    let mut expires = 0;
    for index in 0..MEMBERS {
        let bytes = vec![u8::try_from(index + 100).map_err(io::Error::other)?; MEMBER_PLAINTEXT];
        let hash = hex(identity(&bytes)?.digest());
        let (original, deadline) = admit(
            owner,
            runtime,
            inputs,
            &bytes,
            ChunkPosition::Final,
            raw_envelope(&bytes),
        )?;
        expires = expires.max(deadline);
        emit(&format!(
            "ADMISSION_PRESSURE_MEMBER index={index} hash={hash}"
        ))?;
        originals.push(Some(original));
        hashes.push(hash);
    }

    // Three real, independently funded consumers leave the cache just below
    // capacity. Their existing grants must survive both refusal and retry.
    let mut consumers = Vec::new();
    for index in MEMBERS - PROTECTED..MEMBERS {
        let original = original(&originals, index)?;
        consumers.push(
            runtime.block_on(
                owner.pin_resident_chunk(
                    identity(&original.bytes[1..])?,
                    now()?
                        .checked_add(600)
                        .ok_or_else(|| invalid("consumer deadline overflows"))?,
                ),
            )?,
        );
    }
    let incoming = vec![221; INCOMING_PLAINTEXT];
    let encoded = raw_envelope(&incoming);
    let incoming_hash = hex(identity(&incoming)?.digest());
    let incoming_hold = HOLD
        .checked_add(u64::try_from(encoded.len()).map_err(io::Error::other)?)
        .ok_or_else(|| invalid("incoming fixture hold overflows"))?;
    read_protected(owner, runtime, &originals, &consumers)?;
    emit(&format!(
        "ADMISSION_PRESSURE_INIT expires={expires} incoming={incoming_hash} hold={incoming_hold}"
    ))?;
    emit("READY original admission pressure allocations and independent consumers retained")?;
    control("pressure-invalid")?;
    let before = measure(owner, runtime, "before")?;
    let capacity = inputs.owner_config()?.policy.capacity;
    if before
        .charged_reserved_bytes
        .checked_add(before.future_hold_bytes)
        .and_then(|total| total.checked_add(incoming_hold))
        .is_none_or(|total| total <= capacity)
    {
        return Err(invalid(
            "incoming native admission does not exceed actual capacity",
        ));
    }

    let policy = fs::read(inputs.root.join("state/cache/records.toml"))?;
    let mut corrupted = encoded.clone();
    corrupted[1] ^= 1;
    if runtime
        .block_on(owner.admit_chunk(descriptor(&incoming)?, ChunkPosition::Final, corrupted))
        .is_ok()
        || fs::read(inputs.root.join("state/cache/records.toml"))? != policy
    {
        return Err(invalid("invalid incoming bytes changed original funding"));
    }
    emit("READY invalid incoming chunk refused before automatic eviction or funding")?;
    control("pressure-admit")?;
    let descriptor = descriptor(&incoming)?;
    let sources = [lower_fetch::LowerChunk::new(
        identity(&incoming)?,
        encoded.clone(),
    )];
    let mut circuits = [CircuitBreaker::new(1, Duration::from_secs(5)).map_err(io::Error::other)?];
    let validator = MetadataValidator::new(inputs.owner_config()?.location.chunk_profile().clone());
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    let mut corrupt = encoded.clone();
    *corrupt
        .last_mut()
        .ok_or_else(|| invalid("missing lower chunk body"))? ^= 1;
    let corrupt_sources = [lower_fetch::LowerChunk::new(identity(&incoming)?, corrupt)];
    let mut corrupt_circuits =
        [CircuitBreaker::new(1, Duration::from_secs(5)).map_err(io::Error::other)?];
    let refused = runtime.block_on(owner.fetch_chunk(
        &corrupt_sources,
        &mut corrupt_circuits,
        &TokioClock,
        NativeChunkFetchRequest {
            descriptor: &descriptor,
            position: ChunkPosition::Final,
            dictionary: None,
            budget: Duration::from_secs(5),
        },
        &validator,
    ));
    if !matches!(refused, Err(ref error) if matches!(error.kind(), StoreErrorKind::Corrupt(_)))
        || corrupt_sources[0].calls() != 1
    {
        return Err(invalid(
            "corrupt lower bytes escaped verification or did not reach the actual provider",
        ));
    }
    emit(
        "PASS corrupt lower bytes return no serving body or admission ticket while actual policy is stalled",
    )?;

    let fetched = runtime
        .block_on(owner.fetch_chunk(
            &sources,
            &mut circuits,
            &TokioClock,
            NativeChunkFetchRequest {
                descriptor: &descriptor,
                position: ChunkPosition::Final,
                dictionary: None,
                budget: Duration::from_secs(5),
            },
            &validator,
        ))
        .map_err(io::Error::other)?;
    if fetched.encoded_bytes() != encoded || sources[0].calls() != 1 {
        return Err(invalid(
            "lower fetch did not return the exact verified original body",
        ));
    }
    let (served, admission) = fetched.into_parts();
    let ticket = admission.map_err(io::Error::other)?;
    emit(
        "READY verified lower bytes returned while native admission remains queued behind actual stalled policy",
    )?;
    control("pressure-release-fetch")?;
    if fs::read(inputs.root.join("state/cache/records.toml"))? != policy {
        return Err(invalid(
            "lower fetch changed policy while the physical worker was stalled",
        ));
    }
    drop(stalled);
    let attempt = runtime.block_on(ticket.finish());
    if !matches!(attempt, Err(NativeChunkAdmissionError::Accepted(ref error))
        if error.kind() == io::ErrorKind::StorageFull)
    {
        return Err(invalid(
            "automatic pressure did not retain actual pending charge",
        ));
    }
    if served != encoded {
        return Err(invalid(
            "native capacity refusal changed independently served lower bytes",
        ));
    }
    emit("PASS verified lower bytes survive the genuine queued native admission capacity refusal")?;
    let mut removed = Vec::new();
    for (index, hash) in hashes.iter().enumerate() {
        let path = inputs
            .root
            .join("chunks")
            .join(&hash[..2])
            .join(format!("{hash}.0"));
        match fs::symlink_metadata(path) {
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => removed.push(index),
            Err(error) => return Err(error),
        }
    }
    if removed.is_empty()
        || removed.len() >= MEMBERS - PROTECTED
        || removed.iter().copied().ne(0..removed.len())
    {
        return Err(invalid(
            "automatic admission pressure lost original eligible FIFO order",
        ));
    }
    for index in &removed {
        original(&originals, *index)?.check(1)?;
    }
    read_protected(owner, runtime, &originals, &consumers)?;
    measure(owner, runtime, "pending")?;
    emit(&format!(
        "ADMISSION_PRESSURE_PENDING members={}",
        removed.len()
    ))?;
    emit(
        "READY verified incoming admission retires original FIFO units but refuses pending quota charge",
    )?;

    control("pressure-drop")?;
    for index in removed {
        original(&originals, index)?.check(0)?;
        drop(originals[index].take());
    }
    measure(owner, runtime, "held")?;
    emit("READY automatic pressure victims close while independent observers retain charge")?;
    control("pressure-observers")?;
    measure(owner, runtime, "closed")?;
    emit(
        "READY original pressure observer closure releases measured quota without changing funding",
    )?;
    control("pressure-retry")?;
    let fetched = runtime
        .block_on(owner.fetch_chunk(
            &sources,
            &mut circuits,
            &TokioClock,
            NativeChunkFetchRequest {
                descriptor: &descriptor,
                position: ChunkPosition::Final,
                dictionary: None,
                budget: Duration::from_secs(5),
            },
            &validator,
        ))
        .map_err(io::Error::other)?;
    let (retry_bytes, ticket) = fetched.into_parts();
    if retry_bytes != served || sources[0].calls() != 2 {
        return Err(invalid(
            "lower retry did not fetch and verify the same original body",
        ));
    }
    let admission = runtime
        .block_on(ticket.map_err(io::Error::other)?.finish())
        .map_err(io::Error::other)?;
    let path = inputs
        .root
        .join("chunks")
        .join(&incoming_hash[..2])
        .join(format!("{incoming_hash}.0"));
    let admitted = Observed::new(File::open(path)?, retry_bytes)?;
    let handoff = runtime
        .block_on(admission.into_cache(owner))
        .map_err(io::Error::other)?;
    if handoff.synchronized_member_bytes != admitted.allocated {
        return Err(invalid(
            "lower retry handoff misreported actual incoming allocation",
        ));
    }
    admitted.check(1)?;
    read_protected(owner, runtime, &originals, &consumers)?;
    let final_report = measure(owner, runtime, "admitted")?;
    if final_report.future_hold_bytes != HOLD * (1 + PROTECTED as u64) {
        return Err(invalid(
            "successful retry lost original independent consumer funding",
        ));
    }
    emit("READY same incoming admission succeeds after actual last-description quota release")?;
    emit(
        "PASS same verified lower body admits through its actual completion ticket after original quota release",
    )?;
    control("pressure-done")?;
    emit(
        "PASS genuine verified admission requests bounded native eviction, retains pending charge and live consumers, then retries after original descriptor closure; no Ready",
    )
}

fn original(originals: &[Option<Observed>], index: usize) -> io::Result<&Observed> {
    originals
        .get(index)
        .and_then(Option::as_ref)
        .ok_or_else(|| invalid("admission pressure lost original fixture description"))
}

fn read_protected(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    originals: &[Option<Observed>],
    consumers: &[terrane_linux::host_cache::NativeConsumerLease],
) -> io::Result<()> {
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    for (offset, consumer) in consumers.iter().enumerate() {
        if consumer.read_verified()?
            != original(originals, MEMBERS - PROTECTED + offset)?.bytes[1..]
        {
            return Err(invalid(
                "pressure invalidated an original policy-held consumer",
            ));
        }
    }
    drop(stalled);
    Ok(())
}

fn measure(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    stage: &str,
) -> io::Result<terrane_linux::host_cache::NativeCacheEvictionReport> {
    let report = runtime.block_on(owner.evict_cached(0))?;
    if !report.target_met || report.retired_allocations != 0 {
        return Err(invalid(
            "pressure observation changed original cache allocation",
        ));
    }
    emit(&format!(
        "ADMISSION_PRESSURE_MEASUREMENT kind={stage} charged={} future={}",
        report.charged_reserved_bytes, report.future_hold_bytes
    ))?;
    Ok(report)
}
