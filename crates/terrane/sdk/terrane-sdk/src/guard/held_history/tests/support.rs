//! Builds actual protected repositories and captures their held read controls.

use super::fs::ReadFs;
use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::guard::{ConsumedResolver, Guard, HistoryObservation};
use crate::ref_advance::tests::{Validator, fixture, request_file, token};
use crate::ref_advance::{CommitTiming, Coordinator};
use crate::repository::Repository;
use crate::store::{LocalFs, TokioClock, TokioLocalFs};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;
use terrane_format::refs::RefRecord;

/// Names the genuine production repository behind the observing filesystem.
pub(super) type NativeRepository =
    Repository<FileBucket<ReadFs, TokioClock, Validator>, TokioClock, ReadFs>;

/// Preserves fixture setup and production verification errors.
pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Names the actual selected branch used by every request.
pub(super) const REFERENCE: &str = "refs/heads/_/main";

/// Retains a real published history and its separately installed observer.
pub(super) struct Fixture {
    /// Owns native retention, admission and publication.
    pub(super) repository: NativeRepository,
    /// Observes actual filesystem operations without constructing evidence.
    pub(super) fs: ReadFs,
    /// Names the real signed ancestor required by the final history.
    pub(super) base: RefRecord,
    /// Names the real currently selected complete ref.
    pub(super) head: RefRecord,
}

impl Fixture {
    // Reopen genuine factory output with an observer, preserving native physical
    // ownership and existing protected history rather than constructing rows.
    /// Publishes and reopens real native history with physical read observation.
    ///
    /// # Errors
    /// Preserves publication, retained authority, filesystem and reopen failures.
    ///
    /// # Panics
    /// Panics if the shared native seed fixture cannot initialize.
    pub(super) async fn open() -> TestResult<Self> {
        let seed = fixture().await;
        let mut writer = seed.begin(REFERENCE, &token(), "sdk").await?;
        let base = seed
            .advance(&mut writer, request_file(Vec::new(), b"original baseline"))
            .await?;
        let head = seed
            .advance(
                &mut writer,
                request_file(vec![base.commit], b"held owner history"),
            )
            .await?;
        let source = seed.guard();
        let authority = source.configured_original_authority()?;
        let fs = ReadFs::default();
        let bucket = FileBucket::open(
            FileBucketConfig {
                root: source.store().root().to_path_buf(),
                publication_control: Some(FileBucketPublicationConfig {
                    operator_uid: TokioLocalFs
                        .symlink_metadata(authority.control())
                        .await?
                        .uid(),
                    control: None,
                }),
                chunk_profile_name: source.config().chunk_profile_name.clone(),
                chunk_profile: (*source.config().chunk_profile).clone(),
                locality: source.config().home.clone(),
            },
            fs.clone(),
            TokioClock,
            Validator,
        )
        .await?;
        // Keep the actual ordinary selections and executed view associations.
        // Native Original state is restored separately by the owning factory.
        let guard = source.configuration_adapter(bucket, TokioClock);
        let coordinator = Coordinator::new(
            guard,
            CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )?,
            fs.clone(),
        );
        let owner = TokioLocalFs
            .symlink_metadata(authority.control())
            .await?
            .uid();
        let repository = Repository::from_native_authority(coordinator, authority, owner).await?;
        Ok(Self {
            repository,
            fs,
            base,
            head,
        })
    }

    /// Borrows the actual configured guard used by the production coordinator.
    pub(super) fn guard(&self) -> &Guard<FileBucket<ReadFs, TokioClock, Validator>, TokioClock> {
        self.repository.coordinator().guard()
    }

    /// Completes a fresh held Read using the fixture capability.
    ///
    /// # Errors
    /// Preserves capture, authentication, physical closing and final ACL failures.
    ///
    /// # Panics
    /// Panics if successful authorization supplies no tree evidence.
    pub(super) async fn authorize(
        &self,
    ) -> TestResult<(
        crate::guard::AuthorizedRef,
        terrane_format::gc::publication::evidence::LineageUsedInputs,
    )> {
        self.authorize_token(&token()).await
    }

    /// Completes one new authorization and returns its independently consumed ledger.
    ///
    /// # Errors
    /// Preserves actual control retention, history, token, physical and ACL failures.
    ///
    /// # Panics
    /// Panics if successful authorization supplies no tree evidence.
    pub(super) async fn authorize_token(
        &self,
        capability: &[u8],
    ) -> TestResult<(
        crate::guard::AuthorizedRef,
        terrane_format::gc::publication::evidence::LineageUsedInputs,
    )> {
        let source = self.guard();
        let holder = crate::bucket::held::SingleHeld::acquire_read_only(source.store()).await?;
        let held = holder.source();
        let observed = held.observe_publication_ordinary_retained().await?;
        let authority = source.configured_original_authority()?;
        let mut controls = source
            .hold_original_registration(&authority, observed.identity())
            .await?;
        let retained = crate::guard::read::indexes::retention::capture(
            source,
            &authority,
            &mut controls,
            &held,
            &observed,
        )
        .await?;
        let guard = source.held_guard(holder.source(), TokioClock)?;
        guard.retain_original_controls(retained.controls())?;
        let identity = held.identity_proof();
        let consumed = ConsumedResolver::new(&guard, &authority)?;
        let (authorized, evidence) = guard
            .authorize_observed_with_evidence(
                REFERENCE,
                capability,
                terrane_format::auth::Verb::Read,
                &[],
                "sdk",
                HistoryObservation::held(&identity).tracked(&consumed),
            )
            .await?;
        assert!(evidence.is_some());
        Ok((authorized, consumed.finish()?))
    }
}
