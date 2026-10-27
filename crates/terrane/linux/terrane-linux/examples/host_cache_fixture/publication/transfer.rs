//! Exercises actual standalone residence transfer and retained failed/cancelled work.

use super::*;
use terrane_sdk::store::ChunkPosition;

/// Runs a fresh actual admitted-source transfer under the real native owner.
///
/// # Errors
/// Refuses altered source bytes, missing retirement, incorrect holds, premature
/// acknowledgment, no-replace failure or a cancellation that loses physical work.
pub(super) fn run(
    mode: &str,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let admitted = runtime
        .block_on(owner.admit_chunk(descriptor()?, ChunkPosition::Final, encoded()))
        .map_err(io::Error::other)?;
    let hash = hex(descriptor()?.digest());
    let canonical = inputs
        .root
        .join("chunks")
        .join(&hash[..2])
        .join(format!("{hash}.0"));
    let original = fs::metadata(&canonical)?;
    if fs::read(&canonical)? != encoded() || admitted.descriptor() != &descriptor()? {
        return Err(invalid(
            "transfer lacks the actual admitted canonical bytes",
        ));
    }
    emit("READY actual standalone admission retained; wait for transfer control")?;
    control("start")?;
    if mode == "publish-inline-transfer-conflict" {
        return conflict(owner, runtime, inputs, &canonical, &original);
    }
    let first = if mode == "publish-inline-transfer-cancel" {
        let mut pending = Box::pin(owner.publish_inline(descriptor()?, encoded()));
        if !matches!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return Err(invalid(
                "stopped publisher did not retain the transfer waiter",
            ));
        }
        emit("QUEUED actual inline transfer; wait for durable funding control")?;
        control("cancel")?;
        drop(pending);
        emit("CANCELLED inline transfer waiter; actual source and physical owner retained")?;
        control("finish")?;
        None
    } else {
        Some(
            runtime
                .block_on(owner.publish_inline(descriptor()?, encoded()))
                .map_err(io::Error::other)?,
        )
    };
    let prior_inode = if let Some(first) = &first {
        check_result(first, inputs, 1, 1)?;
        check_policy(runtime, inputs, 1, 1)?;
        Some(first.handle().metadata()?.ino())
    } else {
        None
    };
    if canonical.try_exists()? {
        return Err(invalid(
            "standalone source remained canonical after actual transfer",
        ));
    }
    let repeated = runtime
        .block_on(owner.publish_inline(descriptor()?, encoded()))
        .map_err(io::Error::other)?;
    check_result(&repeated, inputs, 2, 1)?;
    check_policy(runtime, inputs, 2, 1)?;
    let repeated_inode = repeated.handle().metadata()?.ino();
    if prior_inode.is_some_and(|inode| inode != repeated_inode) {
        return Err(invalid(
            "repeated transfer publication replaced its sealed inode",
        ));
    }
    let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
    if runtime
        .block_on(owner.admit_chunk(descriptor()?, ChunkPosition::Final, encoded()))
        .is_ok()
        || fs::read(inputs.root.join("state/cache/records.toml"))? != before
        || canonical.try_exists()?
    {
        return Err(invalid(
            "sealed residence allowed duplicate standalone readmission",
        ));
    }
    if let Some(first) = &first {
        read_plaintext(first)?;
    }
    // This original receipt remains live through the final Q observation. Its
    // actual registered descriptor and holds must not disappear at waiter Drop.
    if admitted.synchronized_chunk_bytes() == 0 || original.nlink() != 1 {
        return Err(invalid(
            "original admission lacks measured source allocation",
        ));
    }
    emit(
        "PASS actual inline transfer retained original source, pending retirement, sealed bytes and durable holds; no Ready",
    )
}

fn conflict(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    canonical: &std::path::Path,
    original: &fs::Metadata,
) -> io::Result<()> {
    if runtime
        .block_on(owner.publish_inline(descriptor()?, encoded()))
        .is_ok()
    {
        return Err(invalid(
            "occupied pending name acknowledged standalone transfer",
        ));
    }
    let actual = fs::metadata(canonical)?;
    if (actual.dev(), actual.ino()) != (original.dev(), original.ino())
        || fs::read(canonical)? != encoded()
    {
        return Err(invalid(
            "failed transfer replaced or removed the original source",
        ));
    }
    let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("failed transfer snapshot absent"))?;
    if state.reservations.len() != 3
        || state.pins.len() != 2
        || state.leases.len() != 2
        || !state.residences.is_empty()
    {
        return Err(invalid(
            "failed transfer lost actual funding or acknowledged a residence",
        ));
    }
    if runtime
        .block_on(owner.publish_inline(descriptor()?, encoded()))
        .is_ok()
        || fs::read(inputs.root.join("state/cache/records.toml"))? != before
    {
        return Err(invalid(
            "failed physical transfer did not retain faulted exclusion",
        ));
    }
    emit(
        "PASS occupied pending name refused inline transfer while retaining original inode, sealed outcome and funded fault; no Ready",
    )
}
