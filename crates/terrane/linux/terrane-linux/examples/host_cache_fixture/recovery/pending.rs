//! Checks actual conservative retirement deadlines across physical owner restarts.

use super::{
    HARD_LIMIT, HOLD, INLINE_BYTES, Inputs, STATE, invalid, require_seed_capabilities, write,
};
use std::{
    fs::{self, File},
    io,
};
use terrane_linux::{
    host_cache::NativeMetadataOwner,
    publisher_local::{Error as PublisherError, wire::ResultCode},
};
use terrane_sdk::{host::cache::CacheState, store::TokioLocalFs};

/// Seeds one actual sealed pending chunk without forging retirement metadata.
///
/// # Errors
/// Refuses unexpected administration, domain, project inheritance or seal failure.
pub(crate) fn seed() -> io::Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(invalid("pending seed requires root administration"));
    }
    require_seed_capabilities()?;
    let inputs = Inputs::load()?;
    require_domain(&inputs)?;
    let path = inputs
        .root
        .join("pending-delete")
        .join(super::inline_hash()?);
    write(&inputs, &path, INLINE_BYTES, 841, 841, 0o400)?;
    let file = File::open(path)?;
    terrane_linux::verity::enable(&file)?;
    file.sync_all()?;
    File::open(inputs.root.join("pending-delete"))?.sync_all()?;
    println!("SEEDED actual sealed pending inode without a retirement deadline");
    Ok(())
}

/// Exercises genuine recovery refusal or completion on the physical owner.
///
/// # Errors
/// Refuses an unexpected result, lost original holds, premature Resume,
/// policy mutation after a fault or incorrect measured accounting.
pub(crate) fn run(
    mode: &str,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    require_domain(inputs)?;
    let load = || {
        runtime
            .block_on(CacheState::load(
                &TokioLocalFs,
                &inputs.root.join("state/cache"),
                STATE,
            ))
            .map_err(io::Error::other)
    };
    let before = load()?.unwrap_or_default();
    let result = runtime.block_on(owner.recover());
    let after = load()?.ok_or_else(|| invalid("pending recovery lost bootstrap"))?;
    if after.reservations.len() != before.reservations.len() + 1
        || before.reservations.iter().any(|old| {
            !after
                .reservations
                .iter()
                .any(|new| new.id == old.id && new.owner == old.owner && new.bytes == old.bytes)
        })
        || after
            .reservations
            .iter()
            .any(|hold| hold.owner != inputs.owner || hold.bytes != HOLD)
        || !after.pins.is_empty()
        || !after.leases.is_empty()
        || !after.residences.is_empty()
    {
        return Err(invalid("pending recovery changed original policy holds"));
    }
    if mode == "refuse-pending-inline" {
        let error = result
            .err()
            .ok_or_else(|| invalid("unexpired pending inode was removed"))?;
        if !matches!(
            error
                .get_ref()
                .and_then(|error| error.downcast_ref::<PublisherError>()),
            Some(PublisherError::Remote(ResultCode::Unavailable))
        ) {
            return Err(io::Error::other(format!(
                "unexpected pending refusal: {error}"
            )));
        }
        let path = inputs.root.join("state/cache/records.toml");
        let bytes = fs::read(&path)?;
        let retry = runtime
            .block_on(owner.recover())
            .err()
            .ok_or_else(|| invalid("faulted pending owner completed recovery"))?;
        if retry.kind() != io::ErrorKind::WouldBlock || fs::read(path)? != bytes {
            return Err(invalid("pending refusal lost faulted bootstrap custody"));
        }
        println!(
            "PASS actual unexpired pending inode refused; original bootstrap holds retained; no Resume"
        );
        return Ok(());
    }
    if mode != "recover-pending-inline" {
        return Err(invalid("unknown pending recovery selector"));
    }
    let completed = result?;
    completed.check_current()?;
    if completed.future_hold_bytes() != after.reservations.len() as u64 * HOLD
        || completed.charged_reserved_bytes() > HARD_LIMIT
        || completed.synchronized_retained_inode_bytes() == 0
    {
        return Err(invalid(
            "pending recovery confused holds and native charges",
        ));
    }
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    println!(
        "PASS actual expired pending inode removed before completed recovery and acknowledged Resume; original holds retained; no Ready"
    );
    Ok(())
}

fn require_domain(inputs: &Inputs) -> io::Result<()> {
    if matches!(
        inputs.domain.as_str(),
        "tenant:pending-expired" | "tenant:pending-unknown"
    ) {
        Ok(())
    } else {
        Err(invalid(
            "pending fixture requires its isolated native domain",
        ))
    }
}
