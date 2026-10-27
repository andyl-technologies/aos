//! Transfers actual shared sealed ranges before selecting physical retirement.

use super::{
    super::{invalid, residence, state},
    graph::Unit,
};
use crate::host_cache::{
    NativeResidencePlan,
    owner::{admission, retention::NativeOwnerExecutor},
};
use std::io;

/// Re-extracts only shared chunks independently present in the original body.
///
/// # Errors
/// Refuses protected units, a changed original residence, missing metadata,
/// insufficient copy headroom and uncertain native or durable transitions.
pub(super) async fn run(executor: &mut NativeOwnerExecutor, unit: &Unit) -> io::Result<()> {
    if unit.protected {
        return Err(invalid(
            "protected cache body cannot start shared extraction",
        ));
    }
    let budget = executor
        .custody()
        .lock()
        .map_err(|_| invalid("extraction configuration poisoned"))?
        .preparation
        .config
        .inventory_entries;
    let plan = NativeResidencePlan::new(unit.body.layout(), unit.body.claim(), budget)?;
    let mut remaining = unit.shared_chunks.clone();
    for identity in plan.identities()? {
        let hash = state::hex(identity.digest());
        if !remaining.contains(&hash) {
            continue;
        }
        let source = residence::prepare(executor, identity).await?;
        if source.protected_object_digest() != unit.body.claim().descriptor().digest() {
            return Err(invalid("shared extraction selected another original body"));
        }
        admission::reextract::run(executor, source).await?;
        remaining.remove(&hash);
    }
    if !remaining.is_empty() {
        return Err(invalid(
            "shared extraction lacks verified original chunk metadata",
        ));
    }
    Ok(())
}
