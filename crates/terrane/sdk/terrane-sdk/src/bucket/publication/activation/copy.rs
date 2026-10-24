//! Performs native portable-copy registration and exact D-108 pointer staging.
//!
//! A successful create-new external control directory is the independently
//! configured operator's administrative event. Retained root and coordination
//! descriptors bind it to the actual destination. Copied data cannot manufacture
//! this receipt, select a slot, or import source authority.

use super::super::super::super::{FencePolicy, NativeExclusion, Plan};
use super::super::super::{Frame, io_failure, unsupported};
use super::super::{
    NativeGenesisStage, NativePendingRoot, NativePublicationInitialization,
    NativePublicationInitializationOutcome, corrupt, digest,
};
use super::{bootstrap, genesis, io};
use crate::bucket::BucketBinding;
use crate::store::{LocalFs, StoreFailure};
use std::sync::{Arc, Mutex};
use terrane_format::bucket::{BucketKey, Mutability};
use terrane_format::gc::publication::{
    Activation, BackendBinding, BackendRegistration, PublicationCommit,
};

/// Stages a complete destination proposal before retaining its exact Pending.
///
/// # Errors
/// Rejects same-root or already registered payloads, unsafe native binding,
/// changed closure reads, failed create-new registration and uncertain durability.
pub(super) async fn create(
    request: NativePublicationInitialization,
) -> Result<NativePublicationInitializationOutcome, StoreFailure> {
    let owner = request.operator_uid;
    if rustix::process::geteuid().as_raw() != owner {
        return Err(unsupported());
    }
    let copy = request.copy.as_ref().ok_or_else(corrupt)?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if matches!(&copy.payload.origin, BackendBinding::Local { root, .. }
            if root.as_slice() == request.root.as_os_str().as_bytes())
        {
            return Err(unsupported());
        }
    }
    let exclusions = Arc::from(vec![NativeExclusion {
        file: copy.exclusion.file.try_clone().map_err(io_failure)?,
    }]);
    let ancestor = FencePolicy::ProtectedAncestor { owner };
    let directories = Arc::new(Mutex::new(Arc::from(vec![
        bootstrap::directory(request.root.parent().ok_or_else(corrupt)?, ancestor)?,
        bootstrap::directory(request.control.parent().ok_or_else(corrupt)?, ancestor)?,
        bootstrap::directory(&request.root, FencePolicy::NamespaceDirectory { owner })?,
    ])));
    let worker = io::WorkerFs {
        directories: Arc::clone(&directories),
    };
    let mut frame = bootstrap::frame(owner, exclusions);
    let binding = bootstrap::binding(
        &request,
        &directories.lock().map_err(|_| corrupt())?,
        &frame.exclusions,
    )?;
    let BackendBinding::Local {
        root_device,
        root_inode,
        coordination_device,
        coordination_inode,
        ..
    } = &binding
    else {
        return Err(unsupported());
    };
    frame
        .name(
            &worker,
            request.root.clone(),
            (*root_device, *root_inode),
            FencePolicy::NamespaceDirectory { owner },
            None,
        )
        .await?;
    frame
        .name(
            &worker,
            request.root.join(
                BucketKey::parse("CAPABILITIES")
                    .map_err(|_| corrupt())?
                    .lock_name(),
            ),
            (*coordination_device, *coordination_inode),
            FencePolicy::NamespaceCoordination { owner },
            Some(0),
        )
        .await?;
    capture_payload(&worker, &request, &mut frame).await?;
    match worker.symlink_metadata(&request.control).await {
        Ok(_) => return Err(unsupported()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_failure(error)),
    }
    let protected = FencePolicy::ProtectedRecord { owner };
    if frame
        .actual_read(&worker, &request.control, protected)
        .await?
        .is_some()
    {
        return Err(unsupported());
    }
    // This create-new event is deliberately separate from copied origin data.
    // Existing control, including orphaned staging, cannot be reinitialized.
    frame
        .execute(
            &worker,
            Plan::CreateDirectoryNew {
                path: request.control.clone(),
            },
        )
        .await?;
    frame.reads.retain(|read| read.path != request.control);
    let control = bootstrap::directory(
        &request.control,
        FencePolicy::PrivateControlDirectory { owner },
    )?;
    frame
        .name(
            &worker,
            request.control.clone(),
            control.stamp.identity,
            control.policy,
            None,
        )
        .await?;
    bootstrap::retain_directory(&directories, control)?;
    frame
        .execute(
            &worker,
            Plan::SyncDirectory {
                path: request.control.parent().ok_or_else(corrupt)?.to_owned(),
            },
        )
        .await?;
    let nonce = worker
        .random_bytes(32)
        .await
        .map_err(io_failure)?
        .try_into()
        .map_err(|_| corrupt())?;
    let proposal = genesis::stage(
        genesis::copied_catalog(
            copy.payload.logical.clone(),
            binding.clone(),
            request.timestamp,
        )?,
        nonce,
    )?;
    let staged = NativeGenesisStage {
        snapshot_bytes: proposal.snapshot_bytes,
        transaction: proposal.transaction,
    };
    let payload = FencePolicy::Payload { owner };
    frame
        .install(
            &worker,
            &request.root,
            &staged.transaction.snapshot.key,
            &staged.snapshot_bytes,
            payload,
            Mutability::Immutable,
        )
        .await?;
    let transaction_key = format!("publication/transactions/{}", bootstrap::operation(&staged));
    let transaction_bytes = staged.transaction.encode().map_err(|_| corrupt())?;
    frame
        .install(
            &worker,
            &request.control,
            &transaction_key,
            &transaction_bytes,
            protected,
            Mutability::CreateOnce,
        )
        .await?;
    let activation = PublicationCommit {
        revision: 0,
        predecessor: None,
        transaction_key,
        transaction_digest: digest(&transaction_bytes),
    }
    .encode()
    .map_err(|_| corrupt())?;
    frame
        .install(
            &worker,
            &request.control,
            "publication/ACTIVATION",
            &activation,
            protected,
            Mutability::CreateOnce,
        )
        .await?;
    let pending = BackendRegistration {
        binding: binding.clone(),
        activation: Activation::Pending,
        genesis: Some(digest(&activation)),
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

/// Retains every configured-validator read for native preimage revalidation.
///
/// # Errors
/// Rejects reads outside the fixed destination namespaces and unsafe metadata.
pub(in super::super) async fn capture_payload<F: LocalFs + BucketBinding>(
    fs: &F,
    request: &NativePublicationInitialization,
    frame: &mut Frame,
) -> Result<(), StoreFailure> {
    let copy = request.copy.as_ref().ok_or_else(corrupt)?;
    for read in &copy.payload.reads {
        let policy = if read.path().starts_with(&request.root) {
            FencePolicy::Payload {
                owner: request.operator_uid,
            }
        } else if read.path().starts_with(&request.control) {
            FencePolicy::ProtectedRecord {
                owner: request.operator_uid,
            }
        } else {
            return Err(corrupt());
        };
        frame
            .observed_read(fs, read.path(), read.bytes(), read.metadata(), policy)
            .await?;
    }
    Ok(())
}

/// Makes the exact destination pointer durable before the actual genesis slot.
///
/// # Errors
/// Rejects conflicting staging or Pending digest, missing exact proposal bytes
/// and uncertain pointer durability. Staging itself never selects authority.
pub(super) async fn prepare_pointer<F: LocalFs + BucketBinding>(
    fs: &F,
    request: &NativePublicationInitialization,
    registration: &BackendRegistration,
    stage: &NativeGenesisStage,
    frame: &mut Frame,
) -> Result<(), StoreFailure> {
    let protected = FencePolicy::ProtectedRecord {
        owner: request.operator_uid,
    };
    let bytes = frame
        .actual_read(
            fs,
            &request.control.join("publication/ACTIVATION"),
            protected,
        )
        .await?
        .ok_or_else(corrupt)?;
    if registration.genesis != Some(digest(&bytes)) {
        return Err(corrupt());
    }
    let commit = PublicationCommit::decode(&bytes).map_err(|_| corrupt())?;
    let transaction = stage.transaction.encode().map_err(|_| corrupt())?;
    commit
        .check_transaction("publication/commits/0", &transaction)
        .map_err(|_| corrupt())?;
    let payload = FencePolicy::Payload {
        owner: request.operator_uid,
    };
    if frame
        .actual_read(
            fs,
            &request.root.join(&stage.transaction.snapshot.key),
            payload,
        )
        .await?
        .as_deref()
        != Some(stage.snapshot_bytes.as_slice())
    {
        return Err(corrupt());
    }
    frame
        .install(
            fs,
            &request.root,
            "publication/PORTABLE",
            &stage.transaction.snapshot.encode().map_err(|_| corrupt())?,
            payload,
            Mutability::CompareAndSwap,
        )
        .await
}
