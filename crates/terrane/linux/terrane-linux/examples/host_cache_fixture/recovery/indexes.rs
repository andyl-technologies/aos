//! Checks actual startup-index refusals without clearing funded native custody.

use super::{FixtureCase, HOLD, Inputs, STATE, invalid, refuse_resident_source};
use std::{fs, io};
use terrane_linux::host_cache::{CompletedRecovery, NativeMetadataOwner};
use terrane_sdk::{host::cache::CacheState, store::TokioLocalFs};

/// Verifies original policy and faulted custody after an actual refused repair.
///
/// # Errors
/// Refuses a successful recovery, wrong refusal, changed funding, a usable
/// resident source or a second attempt that bypasses the original fault.
pub(super) fn refuse(
    case: FixtureCase,
    result: io::Result<CompletedRecovery>,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let (kind, message) = match case {
        FixtureCase::DisabledIndexRepair => (
            io::ErrorKind::Unsupported,
            "native index repair is disabled",
        ),
        FixtureCase::BoundedIndexRepair => (
            io::ErrorKind::OutOfMemory,
            "derived index exceeds configured repair payload policy",
        ),
        FixtureCase::MismatchingIndex => (
            io::ErrorKind::WouldBlock,
            "recovery will not overwrite a mismatching detached index",
        ),
        _ => return Err(invalid("unexpected index refusal fixture")),
    };
    let error = result
        .err()
        .ok_or_else(|| invalid("invalid index candidate completed recovery"))?;
    if error.kind() != kind || error.to_string() != message {
        return Err(io::Error::other(format!(
            "unexpected index recovery refusal: {error}"
        )));
    }
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("index refusal lost durable bootstrap"))?;
    if state.reservations.len() != 1
        || state.reservations[0].owner != inputs.owner
        || state.reservations[0].bytes != HOLD
        || !state.pins.is_empty()
        || !state.leases.is_empty()
        || !state.residences.is_empty()
    {
        return Err(invalid(
            "index refusal changed the exact bootstrap-only policy",
        ));
    }
    let path = inputs.root.join("state/cache/records.toml");
    let before = fs::read(&path)?;
    let retry = runtime
        .block_on(owner.recover())
        .err()
        .ok_or_else(|| invalid("faulted index owner completed a second recovery"))?;
    if retry.kind() != io::ErrorKind::WouldBlock
        || retry.to_string() != "failed physical work requires native reconciliation"
        || fs::read(&path)? != before
    {
        return Err(invalid(
            "index refusal lost original faulted policy custody",
        ));
    }
    refuse_resident_source(owner, runtime, inputs)?;
    println!(
        "PASS actual {} retained bootstrap-only funding and faulted custody; no Resume",
        case.refusal_label()
    );
    Ok(())
}
