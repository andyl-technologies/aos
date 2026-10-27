//! Publishes genuine ancestor, historical target and newer current-head fixtures.

use super::fs::ReadFs;
use crate::bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig};
use crate::guard::Guard;
use crate::ref_advance::tests::{recorded_fixture, request, request_file, token};
use crate::ref_advance::{CommitTiming, Coordinator};
use crate::repository::{MetadataValidator, Repository};
use crate::store::{LocalFs, TokioClock, TokioLocalFs};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;
use terrane_format::refs::RefRecord;

/// Names the actual registered native metadata backend.
pub(super) type Bucket = FileBucket<ReadFs, TokioClock, MetadataValidator>;

/// Names the genuine production repository behind the observing filesystem.
pub(super) type NativeRepository =
    Repository<FileBucket<ReadFs, TokioClock, MetadataValidator>, TokioClock, ReadFs>;

/// Preserves fixture setup and production verification errors.
pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct StageError {
    phase: &'static str,
    source: Box<dyn std::error::Error>,
}

impl std::fmt::Display for StageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.phase, self.source)
    }
}

impl std::error::Error for StageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Labels an actual failed phase while retaining its complete originating error.
///
/// # Errors
/// Returns the original failure as the contextual error's source.
pub(super) fn at_stage<T, E: Into<Box<dyn std::error::Error>>>(
    phase: &'static str,
    result: Result<T, E>,
) -> TestResult<T> {
    result.map_err(|source| {
        Box::new(StageError {
            phase,
            source: source.into(),
        }) as _
    })
}

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
    /// Names the real historical target, deliberately distinct from the current ref.
    pub(super) head: RefRecord,
    /// Names the later genuine current ref, excluded from historical completion.
    pub(super) current: RefRecord,
    /// Names the canonical signed target root decoded from actual published bytes.
    pub(super) target_root: terrane_format::identity::Digest,
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
        let seed = at_stage(
            "Recorded seed setup",
            recorded_fixture(
                terrane_format::properties::semantics::RecordedContext::new(1, 3, &[])?,
                1,
            )
            .await,
        )?;
        Self::from_seed(seed).await
    }

    /// Publishes a separate genuine Legacy historical control before current authoring.
    ///
    /// # Errors
    /// Preserves actual publication, configuration and protected factory failures.
    ///
    /// # Panics
    /// Panics if the shared native seed fixture cannot initialize.
    pub(super) async fn legacy() -> TestResult<Self> {
        Self::from_seed(crate::ref_advance::tests::fixture().await).await
    }

    async fn from_seed(
        seed: crate::ref_advance::native_fixture::NativeFixture<TokioLocalFs>,
    ) -> TestResult<Self> {
        let mut writer = at_stage("A begin", seed.begin(REFERENCE, &token(), "sdk").await)?;
        let base_request = request_file(Vec::new(), b"original baseline");
        let base = at_stage(
            "A publication",
            seed.advance(&mut writer, base_request).await,
        )?;
        let head_request = request_file(vec![base.commit], b"held owner history");
        let head = at_stage(
            "H publication",
            seed.advance(&mut writer, head_request).await,
        )?;
        let source = seed.guard();
        let target_identity = terrane_format::identity::TERRANE_V1
            .from_digest(terrane_format::identity::IdentityKind::Commit, &head.commit)?;
        let target_body = at_stage(
            "raw H get",
            crate::store::ContentStore::get(source.store(), &target_identity, None).await,
        )?;
        let target_root = terrane_format::refs::Commit::decode(&target_body)?.tree;
        let base_identity = terrane_format::identity::TERRANE_V1
            .from_digest(terrane_format::identity::IdentityKind::Commit, &base.commit)?;
        let base_body = at_stage(
            "raw A get",
            crate::store::ContentStore::get(source.store(), &base_identity, None).await,
        )?;
        let base_root = terrane_format::refs::Commit::decode(&base_body)?.tree;
        let authority = source.configured_original_authority()?;
        let fs = ReadFs::default();
        let bucket = at_stage(
            "observer FileBucket open",
            FileBucket::open(
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
                MetadataValidator::new((*source.config().chunk_profile).clone()),
            )
            .await,
        )?;
        // A fresh authoring configuration must precede any execution. Copy only
        // genuine source-selected ordinary rows; the owning factory separately
        // restores and rechecks protected Original records.
        let mut selections = Vec::new();
        for (view, root) in [(base.commit, base_root), (head.commit, target_root)] {
            let (selection, profile) = source.selected_view_context_for_tests(view, root)?;
            selections.push(crate::guard::ViewSelection::new(
                view,
                root,
                selection,
                profile.attribute_revision,
            )?);
        }
        let mut fresh = Guard::new(
            bucket,
            TokioClock,
            source.keys().to_vec(),
            source.config().clone(),
        );
        fresh.configured_current = source.configured_current;
        let guard = at_stage(
            "Recorded authoring configuration",
            fresh.with_recorded_authoring(
                terrane_format::properties::semantics::RecordedContext::new(3, 3, &[])?,
                2,
            ),
        )?;
        let guard = at_stage(
            "historical ordinary associations",
            guard.with_view_selections(selections),
        )?;
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
        let repository = at_stage(
            "native Original reopen",
            Repository::from_native_authority(coordinator, authority, owner).await,
        )?;
        // Publish a genuinely later current3/attribute2 owner. Historical A/H
        // keep their previously executed Recorded1/current3/attribute1 rows.
        let mut current_writer = at_stage(
            "N begin",
            repository.begin(REFERENCE, &token(), "sdk").await,
        )?;
        let current = at_stage(
            "N publication",
            repository
                .commit_request(&mut current_writer, request(vec![head.commit]))
                .await,
        )?;
        Ok(Self {
            repository,
            fs,
            base,
            head,
            current,
            target_root,
        })
    }

    /// Borrows the actual configured guard used by the production coordinator.
    pub(super) fn guard(
        &self,
    ) -> &Guard<FileBucket<ReadFs, TokioClock, MetadataValidator>, TokioClock> {
        self.repository.coordinator().guard()
    }
}
