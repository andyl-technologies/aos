//! Recovers only the exact durably staged existing Pending registration.
//!
//! The ordinary opener retains its original guard throughout recovery and the
//! subsequent Active probes. This program duplicates that actual exclusion;
//! decoded records never supply a new creator receipt or another operation nonce.

#[cfg(all(test, feature = "tokio", unix))]
#[path = "pending_tests.rs"]
mod tests;

use super::NativePublicationInitialization;
use crate::bucket::BucketBinding;
use crate::store::{LocalFs, NativeExclusion, StoreErrorKind, StoreFailure};

#[cfg(unix)]
use super::super::super::{FencePolicy, MetadataStamp};
#[cfg(unix)]
use super::super::io_failure;
#[cfg(unix)]
use super::fresh::bootstrap;
#[cfg(unix)]
use super::{NativeGenesisStage, corrupt};
#[cfg(unix)]
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use terrane_core::bucket::BucketKey;
#[cfg(unix)]
use terrane_core::gc::publication::{
    Activation, BackendRegistration, PortableCurrent, PublicationTransaction,
};

/// Finishes the recorded Pending operation under actual existing-only exclusion.
///
/// # Errors
/// Rejects unavailable or mismatched retention, unsafe original namespaces,
/// missing exact staged records, noncanonical proposals and uncertain durability.
pub(crate) async fn activate_existing<F: LocalFs + BucketBinding>(
    fs: &F,
    request: NativePublicationInitialization,
    retained: NativeExclusion,
) -> Result<(), StoreFailure> {
    #[cfg(unix)]
    {
        let exclusions: Arc<[_]> = vec![retained].into();
        let owned = Arc::clone(&exclusions);
        // The read worker retains the real guard independently of the waiter;
        // it returns directory observations, never a creator capability.
        #[cfg(feature = "tokio")]
        let (request, directories, binding) = {
            let runtime = tokio::runtime::Handle::try_current()
                .map_err(|_| StoreFailure::new(StoreErrorKind::Unsupported))?;
            runtime
                .spawn_blocking(move || capture(request, &owned))
                .await
                .map_err(|_| corrupt())??
        };
        #[cfg(not(feature = "tokio"))]
        let (request, directories, binding) = capture(request, &owned)?;

        let mut frame = bootstrap::frame(request.operator_uid, exclusions);
        for directory in &directories {
            if directory.path != std::path::Path::new("/") {
                frame
                    .name(
                        fs,
                        directory.path.clone(),
                        directory.stamp.identity,
                        directory.policy,
                        None,
                    )
                    .await?;
            }
        }
        let lock = request.root.join(
            BucketKey::parse("CAPABILITIES")
                .map_err(|_| corrupt())?
                .lock_name(),
        );
        let stamp = MetadataStamp::checked(&fs.symlink_metadata(&lock).await.map_err(io_failure)?)
            .map_err(io_failure)?;
        frame
            .name(
                fs,
                lock,
                stamp.identity,
                FencePolicy::NamespaceCoordination {
                    owner: request.operator_uid,
                },
                Some(0),
            )
            .await?;
        let protected = FencePolicy::ProtectedRecord {
            owner: request.operator_uid,
        };
        let pending = frame
            .actual_read(
                fs,
                &request.control.join("backend-registration.cbor"),
                protected,
            )
            .await?
            .ok_or_else(corrupt)?;
        let registration = BackendRegistration::decode(&pending).map_err(|_| corrupt())?;
        if registration.binding != binding || registration.activation != Activation::Pending {
            return Err(corrupt());
        }
        let payload = FencePolicy::Payload {
            owner: request.operator_uid,
        };
        let pointer = frame
            .actual_read(fs, &request.root.join("publication/PORTABLE"), payload)
            .await?
            .ok_or_else(corrupt)?;
        let pointer = PortableCurrent::decode(&pointer).map_err(|_| corrupt())?;
        if !pointer.key.starts_with("publication/snapshots/0:") {
            return Err(corrupt());
        }
        let snapshot_bytes = frame
            .actual_read(fs, &request.root.join(&pointer.key), payload)
            .await?
            .ok_or_else(corrupt)?;
        pointer
            .check_snapshot(&snapshot_bytes)
            .map_err(|_| corrupt())?;
        let (_, operation) = pointer.key.rsplit_once(':').ok_or_else(corrupt)?;
        let bytes = frame
            .actual_read(
                fs,
                &request
                    .control
                    .join(format!("publication/transactions/{operation}")),
                protected,
            )
            .await?
            .ok_or_else(corrupt)?;
        let transaction = PublicationTransaction::decode(&bytes).map_err(|_| corrupt())?;
        transaction
            .check_key(&format!("publication/transactions/{operation}"))
            .map_err(|_| corrupt())?;
        let staged = NativeGenesisStage {
            snapshot_bytes,
            transaction,
        };
        bootstrap::validate_stage(&request, &binding, &staged)?;
        for row in &staged.transaction.changes {
            if BucketKey::parse(&row.key)
                .map_err(|_| corrupt())?
                .mutability()
                == terrane_core::bucket::Mutability::Immutable
                && frame
                    .actual_read(fs, &request.root.join(&row.key), payload)
                    .await?
                    != row.new
            {
                return Err(corrupt());
            }
        }
        let directories = Arc::new(Mutex::new(Arc::from(directories)));
        bootstrap::finish(
            fs,
            &request,
            &binding,
            &pending,
            &staged,
            &mut frame,
            &directories,
        )
        .await
    }
    #[cfg(not(unix))]
    {
        let _ = (fs, request, retained);
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}

#[cfg(unix)]
fn capture(
    request: NativePublicationInitialization,
    exclusions: &[NativeExclusion],
) -> Result<
    (
        NativePublicationInitialization,
        Vec<super::super::super::NativeOpenedDirectory>,
        terrane_core::gc::publication::BackendBinding,
    ),
    StoreFailure,
> {
    let owner = request.operator_uid;
    let directories = vec![
        bootstrap::directory(
            request.root.parent().ok_or_else(corrupt)?,
            FencePolicy::ProtectedAncestor { owner },
        )?,
        bootstrap::directory(
            request.control.parent().ok_or_else(corrupt)?,
            FencePolicy::ProtectedAncestor { owner },
        )?,
        bootstrap::directory(&request.root, FencePolicy::NamespaceDirectory { owner })?,
        bootstrap::directory(
            &request.control,
            FencePolicy::PrivateControlDirectory { owner },
        )?,
    ];
    let binding = bootstrap::binding(&request, &directories, exclusions)?;
    Ok((request, directories, binding))
}
