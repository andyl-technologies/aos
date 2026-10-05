//! Routes native fixtures through the production protected retention factory.
//!
//! The wrapper preserves coordinator observations and typed publication failures.
//! Authored verbs use the same retained preparation loop as ordinary repositories.

#![allow(clippy::unwrap_used)]

use std::{
    ops::Deref,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

use super::tests::Validator;
use super::{AdvanceError, CommitRequest, Coordinator, FoldOutcome, WriterSession};
use crate::{
    bucket::{BucketBinding, FileBucket},
    domain::DomainNamespace,
    repository::{Error, Repository},
    store::{InvalidReason, LocalFs, StoreErrorKind, StoreFailure, TokioClock},
};
use terrane_core::refs::{MergePolicy, RefRecord};

/// Wraps the production native repository for shared guarded-publication tests.
pub(crate) struct NativeFixture<F: LocalFs + BucketBinding> {
    repository: Repository<FileBucket<F, TokioClock, Validator>, TokioClock, F>,
}

impl<F: LocalFs + BucketBinding + Sync + 'static> NativeFixture<F> {
    /// Initializes the same protected native authority used by repository callers.
    ///
    /// # Panics
    /// Panics when actual namespace setup or production authority validation fails.
    pub(super) async fn initialize(
        coordinator: Coordinator<FileBucket<F, TokioClock, Validator>, TokioClock, F>,
    ) -> Self {
        let (namespace, control, owner) = binding(&coordinator).await;
        coordinator.fs().create_dir_new(&control).await.unwrap();
        coordinator
            .fs()
            .set_permissions_and_sync(&control, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
        let repository =
            Repository::initialize_native_retention(coordinator, &namespace, &control, owner)
                .await
                .unwrap();
        Self { repository }
    }

    /// Reopens the existing protected authority without repairing missing history.
    ///
    /// # Panics
    /// Panics when actual retained registration or historical evidence fails validation.
    pub(super) async fn reopen(
        coordinator: Coordinator<FileBucket<F, TokioClock, Validator>, TokioClock, F>,
    ) -> Self {
        let (namespace, control, owner) = binding(&coordinator).await;
        let repository =
            Repository::reopen_native_retention(coordinator, &namespace, &control, owner)
                .await
                .unwrap();
        Self { repository }
    }

    /// Publishes through the production prepare, retain and held publication loop.
    ///
    /// # Errors
    /// Preserves typed admission, retention, fencing and storage failures with sources.
    pub(crate) async fn advance(
        &self,
        session: &mut WriterSession,
        request: CommitRequest,
    ) -> Result<RefRecord, AdvanceError> {
        self.repository
            .commit_request(session, request)
            .await
            .map_err(failure)
    }

    /// Forks through the production source-authorized retained publication loop.
    ///
    /// # Errors
    /// Preserves current source/destination denial, retention, fencing and storage failures.
    pub(crate) async fn fork(
        &self,
        source: &str,
        destination: &str,
        request: CommitRequest,
    ) -> Result<RefRecord, AdvanceError> {
        self.repository
            .fork(source, destination, request)
            .await
            .map_err(failure)
    }

    /// Merges through production ordered recomputation and exact retained candidates.
    ///
    /// # Errors
    /// Preserves merge, authority, retention, fencing and storage failures with sources.
    pub(super) async fn merge(
        &self,
        session: &mut WriterSession,
        source: &str,
        request: CommitRequest,
        policies: &[MergePolicy],
    ) -> Result<RefRecord, AdvanceError> {
        self.repository
            .merge(session, source, request, policies)
            .await
            .map_err(failure)
    }

    /// Folds through production recomputation and returns the final exclusions.
    ///
    /// # Errors
    /// Preserves fold, authority, retention, fencing and storage failures with sources.
    pub(super) async fn fold(
        &self,
        session: &mut WriterSession,
        source: &str,
        request: CommitRequest,
        policies: &[MergePolicy],
    ) -> Result<FoldOutcome, AdvanceError> {
        self.repository
            .fold(session, source, request, policies)
            .await
            .map_err(failure)
    }
}

impl<F: LocalFs + BucketBinding + Sync + 'static> Deref for NativeFixture<F> {
    type Target = Coordinator<FileBucket<F, TokioClock, Validator>, TokioClock, F>;

    fn deref(&self) -> &Self::Target {
        self.repository.coordinator()
    }
}

async fn binding<F: LocalFs + BucketBinding>(
    coordinator: &Coordinator<FileBucket<F, TokioClock, Validator>, TokioClock, F>,
) -> (DomainNamespace, std::path::PathBuf, u32) {
    let root = coordinator.store().root().to_owned();
    let control = root.with_file_name(format!(
        "{}-original-control",
        root.file_name().unwrap().to_string_lossy(),
    ));
    let owner = coordinator
        .fs()
        .symlink_metadata(&root)
        .await
        .unwrap()
        .uid();
    (
        DomainNamespace {
            root,
            domain: coordinator.guard().config().storage_domain.clone(),
        },
        control,
        owner,
    )
}

fn failure(error: Error) -> AdvanceError {
    match error {
        Error::Advance(error) => error,
        Error::Store(error) => AdvanceError::Store(error),
        Error::Io(error) => {
            StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, error)
                .into()
        }
        error @ Error::Denied => StoreFailure::with_source(
            StoreErrorKind::Denied {
                verb: "commit",
                pattern: "fixture publication".into(),
            },
            error,
        )
        .into(),
        error => StoreFailure::with_source(
            StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
            error,
        )
        .into(),
    }
}
