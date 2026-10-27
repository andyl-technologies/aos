//! Allows original draining-body retirement while retaining exposure obligations.
//!
//! This exception affects publisher namespace retirement only. Durable exposure
//! pins survive final publisher removal and descriptor closure; only the separate
//! authenticated census can discharge them. Active exposures and ordinary pins
//! continue to protect the actual allocation.

use super::graph::Unit;
use crate::host_cache::owner::{retention::Custody, surface_index::bindings};
use std::io;
use terrane_sdk::host::cache::{ExposureBackingKind, ExposurePhase, PinRecord};

/// Requires the exact recorded sealed incarnation, never a digest-only match.
pub(super) fn allows_retirement(owner: &Custody, unit: &Unit, pin: &PinRecord) -> io::Result<bool> {
    let Some(id) = pin.owner.strip_prefix("exposure:") else {
        return Ok(false);
    };
    let Some(record) = owner.state.exposures.iter().find(|row| row.id == id) else {
        return Ok(false);
    };
    if record.phase != ExposurePhase::Draining {
        return Ok(false);
    }
    let claim = unit.body.claim();
    if pin.hash != crate::host_cache::owner::consumer::state::hex(claim.descriptor().digest()) {
        return Ok(false);
    }
    let kind = if claim.manifest().is_some() {
        ExposureBackingKind::Manifest
    } else {
        ExposureBackingKind::Inline
    };
    let digest = claim.descriptor().digest().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "draining body digest has unsupported width",
        )
    })?;
    let observed = bindings::capture(owner, unit.body.handle(), kind, digest)?;
    Ok(record.backings.iter().any(|original| original == &observed))
}
