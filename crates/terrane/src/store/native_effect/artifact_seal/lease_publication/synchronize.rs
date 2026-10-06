//! Builds exact lease outputs and complete consumed Original-control durability.
//!
//! Historical inputs remain in every full Worker refresh. The inventory cannot
//! create lease, current authority or elapsed ownership permission.

use super::super::publication_sync::outputs::{
    Inventory, Target, insert_target, synchronize as synchronize_outputs,
};
use super::{FencePolicy, LeaseRequest, NativeEffectFailure, Worker};
use std::{collections::BTreeMap, io};

/// Synchronizes exact lease outputs and real completed repairs/removals.
///
/// # Errors
/// Refuses inconsistent scopes or preimages, stale authority and actual sync failure.
pub(super) fn synchronize(
    request: &LeaseRequest,
    worker: &mut Worker,
) -> Result<(), NativeEffectFailure> {
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
        (
            &request.root.join("gc/lease"),
            &request.lease,
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
    for (path, bytes, root, owner) in &request.required_records {
        insert_target(
            &mut targets,
            path.clone(),
            Target {
                root: root.clone(),
                owner: *owner,
                protected: true,
                expected: Some(bytes.clone()),
            },
        )?;
    }
    for (path, write) in request.writes.records() {
        let (owner, protected) = match write.policy() {
            FencePolicy::Payload { owner } => (owner, false),
            FencePolicy::ProtectedRecord { owner } => (owner, true),
            _ => return Err(io::Error::other("completed lease write policy differs").into()),
        };
        if !request.scopes.iter().any(|scope| {
            scope.path == write.root() && scope.owner == owner && scope.protected == protected
        }) {
            return Err(io::Error::other("completed lease write boundary differs").into());
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
    synchronize_outputs(
        Inventory {
            scopes: &request.scopes,
            targets,
            original_directories: &request.original_directories,
            #[cfg(all(test, feature = "tokio"))]
            completed_syncs: request.completed_syncs.as_ref(),
        },
        worker,
    )
}
