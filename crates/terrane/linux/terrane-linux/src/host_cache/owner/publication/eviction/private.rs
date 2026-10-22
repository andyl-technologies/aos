//! Schedules private whole-file erasure after real consumer and producer release.
//!
//! The physical worker retains every original publication, descriptor and charge
//! through ordinary retirement acknowledgments. Completed private publications
//! and original recovered bodies enter that protocol without quota pressure.

use super::super::invalid;
use crate::host_cache::owner::retention::NativeOwnerExecutor;
use std::io;
use terrane_format::properties::Domain;

/// Runs original retirement work only on a healthy private owner.
///
/// Producer-funded and pinned objects remain protected by the common graph and
/// permit checks. Shared sources use ordinary verified extraction. Errors and
/// cancellation retain original pending receipts and physical funding.
pub(in crate::host_cache::owner) async fn background(
    executor: &mut NativeOwnerExecutor,
) -> io::Result<()> {
    let private = {
        let owner = executor
            .custody()
            .lock()
            .map_err(|_| invalid("private release custody poisoned"))?;
        !owner.faulted
            && !owner.recovery_required
            && matches!(
                Domain::parse(owner.preparation.config.location.domain()),
                Ok(Domain::Private(_))
            )
    };

    if !private {
        return Ok(());
    }

    let mut cached =
        !executor.inline_registry().is_empty() || !executor.verified_manifests().is_empty();
    for resource in executor.publication_jobs() {
        let job = resource
            .lock()
            .map_err(|_| invalid("private release publication poisoned"))?;
        if job.cached.is_some() {
            cached = true;
            break;
        }
    }

    if cached {
        super::lifecycle::run(executor, 0).await?;
    }

    Ok(())
}
