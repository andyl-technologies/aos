//! Serves registered domain routes under signed active-state and caller fences.
//!
//! Every operation holds the canonical audit/target exclusion pair. Signed
//! pending or completed intent disables both existing handles and fresh opens;
//! the operator audit token never grants the caller target access.

use crate::bucket::{BucketBinding, FileBucket, held::HeldBuckets};
use crate::guard::{DisclosureSourceSelection, HistoryObservation};
use crate::repository::{Error, RegisteredDomainAudit, Repository};
use crate::selected_bridge::native_guard::domain_deletion;
use crate::store::{ByteRange, Clock, ContentUpload, ContentValidator, LocalFs};
use terrane_format::{
    identity::{Digest, Identity},
    tree_format::ContentRef,
};

use super::{DomainDeletionAudit, DomainStore};

/// Selects an exact immutable file alongside its separate current Read authority.
pub struct DomainReadRequest<'a> {
    /// Current policy reference independently checked for this operation.
    pub reference: &'a str,
    /// Caller capability authenticated against the target's actual configured keys.
    pub token: &'a [u8],
    /// Fixed immutable commit containing the selected file.
    pub commit: Digest,
    /// Canonical absolute file path inside that selected commit.
    pub path: &'a [u8],
    /// Exact inline or manifest selector from the authenticated file entry.
    pub content: ContentRef,
    /// Exact logical file size from the authenticated entry.
    pub size: u64,
    /// Registered caller surface checked against capability caveats.
    pub surface: &'a str,
}

/// Selects a current destination root for independently authorized content staging.
pub struct DomainWriteRequest<'a> {
    /// Current destination reference checked for Commit authority.
    pub reference: &'a str,
    /// Caller capability authenticated against the target's actual configured keys.
    pub token: &'a [u8],
    /// Canonical destination path selecting the effective root.
    pub path: &'a [u8],
    /// Registered caller surface checked against capability caveats.
    pub surface: &'a str,
}

/// Borrows an actual native target and its independently registered audit route.
///
/// It stores no mutable enabled flag. Each operation rechecks the signed route,
/// current caller authority, exact selected content and consumed protected inputs.
pub struct RoutedDomainStore<'a, 'registered, F, B, V, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    repository: &'a Repository<FileBucket<F, B, V>, C, F>,
    audit: &'a RegisteredDomainAudit<'registered, FileBucket<F, B, V>, C, F>,
}

enum Operation<'a, 'credentials> {
    Get(
        &'a DomainReadRequest<'credentials>,
        &'a Identity,
        Option<ByteRange>,
    ),
    Has(&'a DomainReadRequest<'credentials>, &'a [Identity]),
    Read(&'a DomainReadRequest<'credentials>),
    Put(&'a DomainWriteRequest<'credentials>, ContentUpload<'a>),
}

enum Outcome {
    Bytes(Vec<u8>),
    Membership(Vec<bool>),
    Identity(Identity),
}

impl<'a, 'registered, F, B, V, C> RoutedDomainStore<'a, 'registered, F, B, V, C>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock + Sync,
    FileBucket<F, B, V>: Sync,
{
    /// Opens a configured route only from actual repositories and signed active state.
    ///
    /// # Errors
    /// Rejects the wrong physical target/domain, unsafe or missing audit state,
    /// and a pending or completed deletion.
    pub async fn new(
        repository: &'a Repository<FileBucket<F, B, V>, C, F>,
        audit: &'a RegisteredDomainAudit<'registered, FileBucket<F, B, V>, C, F>,
    ) -> Result<Self, Error> {
        let (_, _, configured) = audit.native_binding();
        let guard = repository.coordinator().guard();
        if guard.store().root() != configured.target().root
            || guard.config().storage_domain != configured.target().domain
            || audit.domain_deleted(&configured.target().domain).await?
        {
            return Err(Error::Denied);
        }
        Ok(Self { repository, audit })
    }

    /// Returns encoded content only from the freshly verified selected file closure.
    ///
    /// # Errors
    /// Rejects disabled routes, current caller or selected-file denial, unknown
    /// identities, invalid ranges, failed verification and underlying storage errors.
    pub async fn get(
        &self,
        request: &DomainReadRequest<'_>,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, Error> {
        match self
            .execute(Operation::Get(request, identity, range))
            .await?
        {
            Outcome::Bytes(bytes) => Ok(bytes),
            _ => Err(Error::Denied),
        }
    }

    /// Reports ordered scoped membership after fresh route and caller checks.
    ///
    /// # Errors
    /// Preserves disabled routing, caller/file verification and storage failures.
    pub async fn has(
        &self,
        request: &DomainReadRequest<'_>,
        identities: &[Identity],
    ) -> Result<Vec<bool>, Error> {
        match self.execute(Operation::Has(request, identities)).await? {
            Outcome::Membership(membership) => Ok(membership),
            _ => Err(Error::Denied),
        }
    }

    /// Returns verified plaintext for the exact freshly authorized file selection.
    ///
    /// # Errors
    /// Preserves disabled routing, caller/file/dictionary verification and storage failures.
    pub async fn read_content(&self, request: &DomainReadRequest<'_>) -> Result<Vec<u8>, Error> {
        match self.execute(Operation::Read(request)).await? {
            Outcome::Bytes(bytes) => Ok(bytes),
            _ => Err(Error::Denied),
        }
    }

    /// Admits offered content under current caller Commit and active signed routing.
    ///
    /// # Errors
    /// Rejects disabled routing, current caller Commit denial, invalid offered
    /// records and failed or indeterminate contextual native effects.
    pub async fn put(
        &self,
        request: &DomainWriteRequest<'_>,
        upload: ContentUpload<'_>,
    ) -> Result<Identity, Error> {
        match self.execute(Operation::Put(request, upload)).await? {
            Outcome::Identity(identity) => Ok(identity),
            _ => Err(Error::Denied),
        }
    }

    async fn execute(&self, operation: Operation<'_, '_>) -> Result<Outcome, Error> {
        let concrete = self.repository.coordinator().guard();
        let (audit_repository, _, configured) = self.audit.native_binding();
        let audit_concrete = audit_repository.coordinator().guard();
        let pair = HeldBuckets::acquire(audit_concrete.store(), concrete.store()).await?;
        let audit_clock = audit_concrete
            .clock()
            .retain_native_clock()
            .map_err(|_| Error::Denied)?;
        let target_clock = concrete
            .clock()
            .retain_native_clock()
            .map_err(|_| Error::Denied)?;
        let audit = audit_concrete.held_guard(pair.source(), audit_clock)?;
        let audit_observed = audit.store().observe_publication_retained().await?;
        let audit_context = self.audit.held_active(&audit, &audit_observed).await?;

        if let Operation::Put(request, upload) = operation {
            let target = concrete.held_guard(pair.destination(), target_clock)?;
            let target_observed = target.store().observe_publication_retained().await?;
            let store = DomainStore::new(configured.target().domain.clone(), pair.destination())?;
            let (access, caller_context) = domain_deletion::qualify_write(
                concrete,
                &target,
                &target_observed,
                request,
                self.repository.coordinator().timing(),
            )
            .await?;
            let context = domain_deletion::staging_context(
                caller_context,
                audit_context,
                &target_observed,
                &audit_observed,
            );
            let identity = store.put_contextual(&access, upload, &context).await?;
            context.recheck()?;
            return Ok(Outcome::Identity(identity));
        }

        let target = concrete.held_guard(pair.destination_read_only(), target_clock)?;
        #[cfg(feature = "tokio")]
        let target_observed = target
            .store()
            .observe_publication_ordinary_retained()
            .await?;
        #[cfg(not(feature = "tokio"))]
        let target_observed = target.store().observe_for_read().await?;
        let store = DomainStore::new(
            configured.target().domain.clone(),
            pair.destination_read_only(),
        )?;

        let request = match &operation {
            Operation::Get(request, ..)
            | Operation::Has(request, ..)
            | Operation::Read(request) => *request,
            Operation::Put(..) => return Err(Error::Denied),
        };
        let selection = DisclosureSourceSelection {
            reference: request.reference,
            commit: request.commit,
            token: request.token,
            path: request.path,
            surface: request.surface,
        };
        let (snapshot, access, caller_context) = domain_deletion::qualify_read(
            concrete,
            &target,
            &target_observed,
            selection,
            request.content,
            request.size,
            self.repository.coordinator().timing(),
        )
        .await?;
        let context = domain_deletion::paired_context(audit_context, caller_context);
        let result = match operation {
            Operation::Get(_, identity, range) => {
                Outcome::Bytes(store.get(&access, identity, range).await?)
            }
            Operation::Has(_, identities) => {
                Outcome::Membership(store.has(&access, identities).await?)
            }
            Operation::Read(_) => Outcome::Bytes(
                target
                    .read_content_observed(
                        &snapshot,
                        request.path,
                        request.content,
                        request.size,
                        HistoryObservation::held(target_observed.identity()),
                    )
                    .await?,
            ),
            Operation::Put(..) => return Err(Error::Denied),
        };
        // Caller and audit operator requests remain independent through the
        // final release boundary; no bytes or membership escapes after expiry.
        target_observed.revalidate().await?;
        audit_observed.revalidate().await?;
        for controls in context.controls() {
            controls
                .revalidate(self.repository.coordinator().fs())
                .await?;
        }
        context.final_check().recheck()?;
        Ok(result)
    }
}
