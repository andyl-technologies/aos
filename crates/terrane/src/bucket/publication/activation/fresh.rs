//! Creates actual absent roots and activates their exact retained empty genesis.
//!
//! Only a successful native create-new operation supplies the creator event.
//! The one submitted worker retains opened parent/root/control descriptors and
//! actual coordination exclusion through durable Pending and recoverable staging.

#[cfg(unix)]
#[path = "bootstrap.rs"]
pub(super) mod bootstrap;
#[cfg(unix)]
#[path = "genesis.rs"]
mod genesis;
#[cfg(unix)]
#[path = "io.rs"]
mod io;

#[cfg(all(test, feature = "tokio", unix))]
#[path = "fresh_tests.rs"]
pub(super) mod tests;

#[cfg(all(test, feature = "tokio", unix))]
#[path = "test_fs.rs"]
pub(super) mod test_fs;

use super::NativePendingRoot;
use crate::bucket::BucketBinding;
use crate::store::{LocalFs, StoreErrorKind, StoreFailure};

#[cfg(unix)]
use super::super::super::{
    FencePolicy, MetadataStamp, NativeEffectFailure, NativeExclusion, Plan, open_native,
};
#[cfg(unix)]
use super::super::io_failure;
#[cfg(unix)]
use super::{
    NativeGenesisStage, NativePublicationInitialization, NativePublicationInitializationOutcome,
    corrupt,
};
#[cfg(unix)]
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use terrane_core::bucket::{BucketKey, Mutability};
#[cfg(unix)]
use terrane_core::gc::publication::{Activation, BackendRegistration};

/// Executes the entire native creator inside its already submitted worker.
///
/// # Errors
/// Rejects unsafe ancestry, nonexclusive creator inputs, unavailable native
/// retention, failed actual creation, incomplete staging and uncertain durability.
#[cfg(unix)]
pub(crate) fn initialize(
    request: NativePublicationInitialization,
) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
    use std::future::Future;
    let mut future = std::pin::pin!(create(request));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    // Only immediate WorkerFs futures are driven inside the owned creator.
    // Pending cannot be retried by an external executor or detached task.
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => Err(StoreFailure::new(StoreErrorKind::Unsupported)),
    }
}

#[cfg(unix)]
async fn create(
    request: NativePublicationInitialization,
) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
    let owner = request.operator_uid;
    if rustix::process::geteuid().as_raw() != owner {
        return Err(StoreFailure::new(StoreErrorKind::Unsupported));
    }
    let ancestor = FencePolicy::ProtectedAncestor { owner };
    let parents = vec![
        bootstrap::directory(request.root.parent().ok_or_else(corrupt)?, ancestor)?,
        bootstrap::directory(request.control.parent().ok_or_else(corrupt)?, ancestor)?,
    ];
    let directories = Arc::new(Mutex::new(Arc::from(parents)));
    let worker = io::WorkerFs {
        directories: Arc::clone(&directories),
    };
    let mut frame = bootstrap::frame(owner, Arc::from(Vec::new()));
    match worker.symlink_metadata(&request.root).await {
        Ok(_) => return Ok(NativePublicationInitializationOutcome::Existing),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_failure(error)),
    }
    let protected = FencePolicy::ProtectedRecord { owner };
    if frame
        .actual_read(&worker, &request.control, protected)
        .await?
        .is_some()
    {
        return Err(corrupt());
    }
    frame.parents(&worker, &request.root, owner).await?;
    match worker
        .execute_retained_effect(frame.effect(Plan::CreateDirectoryNew {
            path: request.root.clone(),
        })?)
        .await
    {
        Ok(()) => {}
        Err(NativeEffectFailure::Io(error))
            if error.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            return Ok(NativePublicationInitializationOutcome::Existing);
        }
        Err(NativeEffectFailure::Io(error)) => return Err(io_failure(error)),
        Err(NativeEffectFailure::Rejected(error)) => return Err(error),
    }
    let root = bootstrap::directory(&request.root, FencePolicy::NamespaceDirectory { owner })?;
    frame
        .name(
            &worker,
            root.path.clone(),
            root.stamp.identity,
            root.policy,
            None,
        )
        .await?;
    bootstrap::retain_directory(&directories, root)?;

    let coordination_key = BucketKey::parse("CAPABILITIES")
        .map_err(|_| corrupt())?
        .lock_name();
    frame
        .install(
            &worker,
            &request.root,
            &coordination_key,
            &[],
            FencePolicy::Payload { owner },
            Mutability::CreateOnce,
        )
        .await?;
    let coordination_path = request.root.join(&coordination_key);
    let coordination = open_native(&coordination_path, false).map_err(io_failure)?;
    coordination.lock().map_err(io_failure)?;
    let stamp = MetadataStamp::checked(&coordination.metadata().map_err(io_failure)?)
        .map_err(io_failure)?;
    FencePolicy::NamespaceCoordination { owner }
        .validate(stamp)
        .map_err(io_failure)?;
    frame.exclusions = Arc::from(vec![NativeExclusion { file: coordination }]);
    frame
        .name(
            &worker,
            coordination_path,
            stamp.identity,
            FencePolicy::NamespaceCoordination { owner },
            Some(0),
        )
        .await?;

    frame
        .directory(
            &worker,
            &request.control,
            FencePolicy::PrivateControlDirectory { owner },
        )
        .await?;
    let control = bootstrap::directory(
        &request.control,
        FencePolicy::PrivateControlDirectory { owner },
    )?;
    bootstrap::retain_directory(&directories, control)?;
    let binding = bootstrap::binding(
        &request,
        &directories.lock().map_err(|_| corrupt())?,
        &frame.exclusions,
    )?;
    let pending = BackendRegistration {
        binding: binding.clone(),
        activation: Activation::Pending,
        genesis: None,
    }
    .encode()
    .map_err(|_| corrupt())?;
    frame
        .install(
            &worker,
            &request.control,
            "backend-registration.cbor",
            &pending,
            protected,
            Mutability::CreateOnce,
        )
        .await?;

    let catalog = genesis::catalog(request.profile.clone(), binding.clone(), request.timestamp)?;
    for (key, value) in &catalog.logical {
        let parsed = BucketKey::parse(key).map_err(|_| corrupt())?;
        if parsed.mutability() == Mutability::Immutable {
            frame
                .install(
                    &worker,
                    &request.root,
                    key,
                    value.as_deref().ok_or_else(corrupt)?,
                    FencePolicy::Payload { owner },
                    Mutability::Immutable,
                )
                .await?;
        }
    }
    let nonce = worker
        .random_bytes(32)
        .await
        .map_err(io_failure)?
        .try_into()
        .map_err(|_| corrupt())?;
    let genesis::Genesis {
        snapshot_bytes,
        transaction,
    } = genesis::stage(catalog, nonce)?;
    let staged = NativeGenesisStage {
        snapshot_bytes,
        transaction,
    };
    frame
        .install(
            &worker,
            &request.root,
            &staged.transaction.snapshot.key,
            &staged.snapshot_bytes,
            FencePolicy::Payload { owner },
            Mutability::Immutable,
        )
        .await?;
    frame
        .install(
            &worker,
            &request.control,
            &format!("publication/transactions/{}", bootstrap::operation(&staged)),
            &staged.transaction.encode().map_err(|_| corrupt())?,
            protected,
            Mutability::CreateOnce,
        )
        .await?;
    frame
        .install(
            &worker,
            &request.root,
            "publication/PORTABLE",
            &staged
                .transaction
                .snapshot
                .encode()
                .map_err(|_| corrupt())?,
            FencePolicy::Payload { owner },
            Mutability::CreateOnce,
        )
        .await?;
    frame
        .directory(
            &worker,
            &request.control.join("publication/commits"),
            FencePolicy::PrivateControlDirectory { owner },
        )
        .await?;
    frame
        .directory(
            &worker,
            &request.root.join("gc"),
            FencePolicy::NamespaceDirectory { owner },
        )
        .await?;
    if frame
        .actual_read(
            &worker,
            &request.control.join("publication/commits/0"),
            protected,
        )
        .await?
        .is_some()
    {
        return Err(corrupt());
    }
    frame
        .execute(
            &worker,
            Plan::SyncDirectory {
                path: request.control.clone(),
            },
        )
        .await?;
    let directories = Arc::clone(&*directories.lock().map_err(|_| corrupt())?);
    Ok(NativePublicationInitializationOutcome::Fresh(Box::new(
        NativePendingRoot {
            _private: (),
            request,
            directories,
            exclusions: frame.exclusions,
            binding,
            pending,
            staged,
            names: frame.names,
            reads: frame.reads,
        },
    )))
}

/// Consumes the actual creator receipt through complete activation and probes.
///
/// # Errors
/// Rejects original descriptor or staged-leaf replacement, incomplete genesis,
/// unsafe paths, failed native or binding probes and uncertain durability.
pub(crate) async fn activate<F: LocalFs + BucketBinding>(
    fs: &F,
    receipt: NativePendingRoot,
) -> Result<(), StoreFailure> {
    #[cfg(unix)]
    {
        let NativePendingRoot {
            _private: (),
            request,
            directories,
            exclusions,
            binding,
            pending,
            staged,
            names,
            reads,
        } = receipt;
        let directories = Arc::new(Mutex::new(directories));
        let mut frame = bootstrap::restore_frame(request.operator_uid, exclusions, names, reads)?;
        bootstrap::finish(
            fs,
            &request,
            &binding,
            &pending,
            &staged,
            &mut frame,
            &directories,
        )
        .await?;
        bootstrap::probe(fs, &request, &staged, &mut frame, &directories).await
    }
    #[cfg(not(unix))]
    {
        let _ = (fs, receipt);
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}
