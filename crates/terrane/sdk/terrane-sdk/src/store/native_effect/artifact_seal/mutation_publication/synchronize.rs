//! Builds exact mutation outputs for the shared native durability mechanic.

use super::super::FencePolicy;
use super::super::publication_sync::outputs::{
    Inventory, Target, insert_target, synchronize as synchronize_outputs,
};
use super::{MutationRequest, NativeEffectFailure, Worker};
use std::{collections::BTreeMap, io, path::PathBuf};

fn targets(request: &MutationRequest) -> io::Result<BTreeMap<PathBuf, Target>> {
    let mut targets = BTreeMap::new();
    for (path, bytes, root, protected) in [
        (&request.slot_path, &request.slot, &request.control, true),
        (
            &request.transaction_path,
            &request.transaction,
            &request.control,
            true,
        ),
        (
            &request.snapshot_path,
            &request.snapshot,
            &request.root,
            false,
        ),
        (
            &request.root.join("publication/PORTABLE"),
            &request.pointer,
            &request.root,
            false,
        ),
    ] {
        insert_target(
            &mut targets,
            path.clone(),
            Target {
                root: root.clone(),
                owner: request.owner,
                protected,
                expected: Some(bytes.clone()),
            },
        )?;
    }
    for (path, bytes) in &request.proofs {
        insert_target(
            &mut targets,
            path.clone(),
            Target {
                root: request.control.clone(),
                owner: request.owner,
                protected: true,
                expected: Some(bytes.clone()),
            },
        )?;
    }
    for (path, bytes) in &request.changes {
        insert_target(
            &mut targets,
            path.clone(),
            Target {
                root: request.root.clone(),
                owner: request.owner,
                protected: false,
                expected: bytes.clone(),
            },
        )?;
    }
    for (path, write) in request.writes.records() {
        let (owner, protected) = match write.policy() {
            FencePolicy::Payload { owner } => (owner, false),
            FencePolicy::ProtectedRecord { owner } => (owner, true),
            _ => return Err(io::Error::other("completed mutation write policy differs")),
        };
        if !request.scopes.iter().any(|scope| {
            scope.path == write.root() && scope.owner == owner && scope.protected == protected
        }) {
            return Err(io::Error::other(
                "completed mutation write boundary differs",
            ));
        }
        insert_target(
            &mut targets,
            path.clone(),
            Target {
                root: write.root().to_owned(),
                owner,
                protected,
                expected: write.expected().map(<[u8]>::to_vec),
            },
        )?;
    }
    Ok(targets)
}

/// Synchronizes fixed mutation outputs while retaining complete native refresh.
///
/// # Errors
/// Refuses inconsistent output inventories, current authority or actual durability.
pub(super) fn synchronize(
    request: &MutationRequest,
    worker: &mut Worker,
) -> Result<(), NativeEffectFailure> {
    synchronize_outputs(
        Inventory {
            scopes: &request.scopes,
            targets: targets(request)?,
            original_directories: &request.original_directories,
            #[cfg(all(test, feature = "tokio"))]
            completed_syncs: request.completed_syncs.as_ref(),
        },
        worker,
    )
}
