//! Exercises automatic admission pressure on the original running native owner.
//!
//! The supervisor independently retains every original inode. No explicit
//! eviction request supplies pressure: only the incoming verified admission
//! may select victims. Original open descriptors keep their actual quota charge.

use super::{
    HOLD, Inputs, NativeChunkAdmissionError, NativeMetadataOwner, Observed, admit, control,
    descriptor, emit, hex, identity, invalid, now, raw_envelope,
};
use std::{fs, io};
use terrane_sdk::store::ChunkPosition;

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
    let attempt = runtime.block_on(owner.admit_chunk(
        descriptor(&incoming)?,
        ChunkPosition::Final,
        encoded.clone(),
    ));
    if !matches!(attempt, Err(NativeChunkAdmissionError::Accepted(ref error))
        if error.kind() == io::ErrorKind::StorageFull)
    {
        return Err(invalid(
            "automatic pressure did not retain actual pending charge",
        ));
    }
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
    let (admitted, _) = admit(
        owner,
        runtime,
        inputs,
        &incoming,
        ChunkPosition::Final,
        encoded,
    )?;
    admitted.check(1)?;
    read_protected(owner, runtime, &originals, &consumers)?;
    let final_report = measure(owner, runtime, "admitted")?;
    if final_report.future_hold_bytes != HOLD * (1 + PROTECTED as u64) {
        return Err(invalid(
            "successful retry lost original independent consumer funding",
        ));
    }
    emit("READY same incoming admission succeeds after actual last-description quota release")?;
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
