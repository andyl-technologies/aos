//! Owns public repository verbs and their common authorization path (CRATE-23).
//!
//! A repository composes the same store and coordinator types for local and
//! future remote backends. Directory import stages immutable content; commit
//! publication remains exclusively the guarded coordinator's responsibility.

#[cfg(unix)]
mod audit;
#[cfg(unix)]
mod audit_codec;
#[cfg(all(feature = "surface-sdk", unix))]
mod checkout;
mod diff;
#[cfg(unix)]
mod disclosure_rotation;
#[cfg(unix)]
mod domain_deletion;
mod error;
#[cfg(feature = "std")]
mod import;
#[cfg(all(feature = "std", unix))]
mod local;
#[cfg(all(feature = "std", unix))]
/// Persists protected local signing and retained original-authority evidence.
pub(crate) mod local_authority;
#[cfg(unix)]
mod overlay;
mod path;
mod prepared;
pub(crate) mod read;
mod validator;

#[cfg(unix)]
pub use audit::RegisteredDomainAudit;
pub use diff::Difference;
pub use error::Error;
#[cfg(all(feature = "std", unix))]
pub use import::import_directory;
#[cfg(all(feature = "std", unix))]
pub use local::{CommitMetadata, LocalRepositoryLocation, LocalRepositoryPolicy};
#[cfg(all(feature = "std", unix))]
pub use local_authority::{LocalAuthority, LocalAuthorityIdentity, LocalAuthorityParameters};
#[cfg(all(feature = "std", unix))]
pub use overlay::RetainedOverlayLayer;
pub use prepared::PreparedTree;
pub use validator::MetadataValidator;

use terrane_core::{chunking::ChunkProfile, identity::Digest, refs::RefRecord};

use crate::{
    ref_advance::{CommitRequest, Coordinator, PreparedAdvance, PublicationStep, WriterSession},
    store::{Clock, LocalFs, Store},
};

/// Provides repository verbs over one guarded local or remote store (CRATE-26).
///
/// Mutable references have one publication path: the coordinator verifies
/// current policy, signatures, fencing, and immutable dependencies before
/// publishing the reflog and reference. Surfaces never access this store.
pub struct Repository<S: Store, C: Clock, F: LocalFs> {
    coordinator: Coordinator<S, C, F>,
    local_backend_root: Option<std::path::PathBuf>,
    #[cfg(unix)]
    local_retention: Option<local_authority::NativeRetention>,
}

impl<S: Store, C: Clock, F: LocalFs> Repository<S, C, F> {
    /// Composes the shared coordinator with its exact filesystem and chunk profile.
    ///
    /// Composition supplies no original authoring authority. Mutating verbs that
    /// need protected historical retention fail closed until a trusted repository
    /// factory binds that retention to the actual opened backend. Local callers
    /// use `Repository::initialize_local` or `Repository::open_local` on Unix.
    pub fn new(coordinator: Coordinator<S, C, F>) -> Self {
        Self {
            coordinator,
            local_backend_root: None,
            #[cfg(unix)]
            local_retention: None,
        }
    }
}

impl<S, C, F> Repository<S, C, F>
where
    S: Store + Sync,
    C: Clock + Sync,
    F: LocalFs + Sync,
{
    /// Borrows the composed coordinator for internal authority and state inspection.
    pub(crate) fn coordinator(&self) -> &Coordinator<S, C, F> {
        &self.coordinator
    }

    /// Returns the profile used by directory import and object reconstruction.
    pub fn chunk_profile(&self) -> &ChunkProfile {
        &self.coordinator().guard().config().chunk_profile
    }

    /// Materializes authorized checkout entries using the repository filesystem binding.
    ///
    /// # Errors
    /// Rejects unsupported entries, escaping paths, existing destinations, and
    /// failed filesystem writes, metadata preservation or durability.
    #[cfg(all(feature = "surface-sdk", unix))]
    pub(crate) async fn materialize_checkout(
        &self,
        destination: &std::path::Path,
        view: &read::ReadView,
    ) -> Result<(), Error> {
        checkout::materialize(
            self.coordinator.fs(),
            destination,
            &view.entries,
            view.minimum,
        )
        .await
    }

    /// Opens a fenced writer session under the supplied exposure token.
    ///
    /// # Errors
    /// Returns a denial, unavailable authority, or invalid reference error if
    /// a writable session cannot be established under current policy.
    pub async fn begin(
        &self,
        reference: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<WriterSession, Error> {
        self.coordinator
            .begin(reference, token, surface)
            .await
            .map_err(Error::Advance)
    }

    /// Requalifies an unchanged source through separate ordinary full verification.
    ///
    /// Current Fork authority is checked on every actual source occurrence.
    /// Only fresh protected lineage and a publication revision are installed;
    /// the signed Commit, whole head/log, Guard and loss generation stay unchanged.
    /// A later fork independently qualifies this source through its final ACK.
    ///
    /// # Errors
    /// Preserves current denial, incomplete signed history/profile/index/Original,
    /// stale controls, deadlines and native durability failures. Unknown retained
    /// history, absent native dispatch and byte-identical existing context return
    /// Unsupported without claiming fresh qualification or acknowledgment.
    pub async fn requalify_fork_source(
        &self,
        source: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<RefRecord, Error> {
        self.coordinator
            .requalify_fork_source(source, token, surface)
            .await
            .map_err(Error::Advance)
    }

    /// Watches the current committed branch and every subsequent durable advance.
    ///
    /// Each event rechecks the exposure token and current ACL. Idle subscriptions
    /// remain open until explicitly closed; missing committed logs fail closed.
    ///
    /// # Errors
    /// Rejects unsupported ref classes, denied current authority, and store
    /// failures while establishing the live subscription.
    pub async fn watch(
        &self,
        reference: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<crate::ref_advance::GuardedWatch<'_, S, C, F>, Error> {
        self.coordinator
            .watch(reference, token, surface)
            .await
            .map_err(Error::Advance)
    }

    /// Publishes a staged canonical tree through the sole commit path.
    ///
    /// The proposal must name the prepared tree exactly. Edited roots without
    /// an explicit domain inherit the current authenticated ownership before
    /// final encoding, and the proposal names that finalized root. All staged
    /// uploads are admitted only after current authority checks.
    ///
    /// # Errors
    /// Rejects mismatched roots or chunk profiles, invalid metadata, denied
    /// authority, stale writer sessions, or failed durable publication.
    pub async fn commit(
        &self,
        session: &mut WriterSession,
        mut tree: PreparedTree,
        mut request: CommitRequest,
    ) -> Result<RefRecord, Error> {
        if request.commit.tree != tree.root || tree.minimum != self.chunk_profile().minimum() as u64
        {
            return Err(Error::Unrealizable);
        }
        if session.record().is_some() && !tree.has_domain() {
            let guard = self.coordinator.guard();
            let snapshot = guard
                .read_snapshot(session.reference(), &request.token, b"/", &request.surface)
                .await?;
            let policy = snapshot.evidence.policy_path(b"/", tree.minimum)?;
            let layers = policy
                .iter()
                .map(
                    |(properties, overrides)| terrane_core::properties::RootLayer {
                        properties,
                        overrides,
                    },
                )
                .collect::<Vec<_>>();
            let effective =
                terrane_core::properties::resolve(&layers, guard.defaults_for(&snapshot.evidence))
                    .map_err(|_| Error::Denied)?;
            let domain = crate::guard::domain_label(&effective).map_err(|_| Error::Denied)?;
            tree.inherit_domain(domain)?;
            request.commit.tree = tree.root;
        }
        request.uploads.extend(tree.uploads);
        self.commit_request(session, request).await
    }

    /// Publishes a canonical proposal through the shared protected retention path.
    ///
    /// Public tree staging performs inherited-domain normalization first. This
    /// internal entry point admits every supplied root, upload and receipt through
    /// the same guard; it supplies neither original authority nor historical policy.
    ///
    /// # Errors
    /// Rejects missing or inconsistent protected evidence, failed durability,
    /// invalid proposals, denied current authority, expired deadlines and fenced
    /// or indeterminate publication, preserving the originating typed failure.
    pub(crate) async fn commit_request(
        &self,
        session: &mut WriterSession,
        request: CommitRequest,
    ) -> Result<RefRecord, Error> {
        self.retain_baseline(session).await?;
        let prepared = self
            .coordinator
            .prepare_advance(session, request)
            .await
            .map_err(Error::Advance)?;
        Ok(self.publish_retained(session, prepared).await?.record)
    }

    /// Forks a source reference into a fresh signed guarded reference.
    ///
    /// Native preparation and final publication reuse only genuinely selected,
    /// complete supported lineage. Missing per-view context requires separate
    /// [`Self::requalify_fork_source`] before a later fork; no full walk fallback
    /// runs within the native cold operation.
    ///
    /// # Errors
    /// Rejects absent or unsupported native source context, denied source Fork or
    /// destination Commit/Admin, changed Original or selected controls, an existing
    /// target, stale whole heads, expiry and failed or uncertain durable publication.
    pub async fn fork(
        &self,
        source: &str,
        destination: &str,
        request: CommitRequest,
    ) -> Result<RefRecord, Error> {
        let mut session = self
            .begin(destination, &request.token, &request.surface)
            .await?;
        self.retain_baseline(&session).await?;
        let prepared = self
            .coordinator
            .prepare_fork(&mut session, source, request)
            .await
            .map_err(Error::Advance)?;
        Ok(self.publish_retained(&mut session, prepared).await?.record)
    }

    /// Merges authenticated source changes into the session's destination branch.
    ///
    /// The coordinator derives the merge base and recomputes canonical trees,
    /// recipes, and receipts. Caller uploads must be empty.
    ///
    /// # Errors
    /// Rejects denied authority, ambiguous ancestry, nonempty uploads, stale
    /// sessions, unresolved merge policies, or failed durable publication.
    pub async fn merge(
        &self,
        session: &mut WriterSession,
        source: &str,
        request: CommitRequest,
        policies: &[terrane_core::refs::MergePolicy],
    ) -> Result<RefRecord, Error> {
        self.retain_baseline(session).await?;
        let (prepared, _) = self
            .coordinator
            .prepare_join(
                session,
                crate::guard::JoinRequest {
                    source,
                    request,
                    policies,
                    kind: crate::guard::JoinKind::Merge,
                },
            )
            .await
            .map_err(Error::Advance)?;
        Ok(self.publish_retained(session, prepared).await?.record)
    }

    /// Folds authenticated child changes into the destination while retaining the child.
    ///
    /// Exclusions under current destination authority are returned explicitly.
    /// The coordinator derives the fork point and recomputes stored receipts.
    ///
    /// # Errors
    /// Rejects invalid fork ancestry, denied authority, nonempty uploads, stale
    /// sessions, unresolved policies, or failed durable publication.
    pub async fn fold(
        &self,
        session: &mut WriterSession,
        source: &str,
        request: CommitRequest,
        policies: &[terrane_core::refs::MergePolicy],
    ) -> Result<crate::ref_advance::FoldOutcome, Error> {
        self.retain_baseline(session).await?;
        let (prepared, _) = self
            .coordinator
            .prepare_join(
                session,
                crate::guard::JoinRequest {
                    source,
                    request,
                    policies,
                    kind: crate::guard::JoinKind::Fold,
                },
            )
            .await
            .map_err(Error::Advance)?;
        self.publish_retained(session, prepared).await
    }

    async fn retain_baseline(&self, session: &WriterSession) -> Result<(), Error> {
        #[cfg(unix)]
        {
            self.local_retention
                .as_ref()
                .ok_or(Error::Denied)?
                .retain_baseline(self.coordinator.guard(), self.coordinator.fs(), session)
                .await
        }
        #[cfg(not(unix))]
        {
            let _ = session;
            Err(Error::UnavailableOperation("native original authority"))
        }
    }

    async fn publish_retained(
        &self,
        session: &mut WriterSession,
        mut prepared: PreparedAdvance,
    ) -> Result<crate::ref_advance::FoldOutcome, Error> {
        #[cfg(unix)]
        {
            let retention = self.local_retention.as_ref().ok_or(Error::Denied)?;
            loop {
                let context = retention
                    .retain_candidate(self.coordinator.guard(), self.coordinator.fs(), &prepared)
                    .await?;
                match self
                    .coordinator
                    .publish_prepared(session, prepared, context)
                    .await
                    .map_err(Error::Advance)?
                {
                    PublicationStep::Published(outcome) => return Ok(*outcome),
                    PublicationStep::Reprepare(next) => prepared = *next,
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (session, prepared);
            Err(Error::UnavailableOperation("native original authority"))
        }
    }

    /// Creates an immutable tag pointing to the source's current signed commit.
    ///
    /// # Errors
    /// Rejects denied source or destination access, invalid tag names, existing
    /// tags, unavailable content, or failed durable publication.
    pub async fn tag(
        &self,
        source: &str,
        destination: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<RefRecord, Error> {
        self.coordinator
            .tag(source, destination, token, surface)
            .await
            .map_err(Error::Advance)
    }

    /// Fetches immutable repository content from another repository.
    ///
    /// # Errors
    /// Returns an explicit unavailable-operation result until remote content
    /// negotiation is implemented by its later milestone.
    pub async fn fetch<T: Store, D: Clock, G: LocalFs>(
        &self,
        _source: &Repository<T, D, G>,
        _commit: Digest,
        _token: &[u8],
    ) -> Result<(), Error> {
        Err(Error::UnavailableOperation("fetch"))
    }

    /// Pushes a signed commit through a destination repository's admission path.
    ///
    /// # Errors
    /// Returns an explicit unavailable-operation result until remote
    /// negotiation and publication are implemented by their later milestone.
    pub async fn push<T: Store, D: Clock, G: LocalFs>(
        &self,
        _destination: &Repository<T, D, G>,
        _commit: Digest,
        _token: &[u8],
    ) -> Result<(), Error> {
        Err(Error::UnavailableOperation("push"))
    }
}
