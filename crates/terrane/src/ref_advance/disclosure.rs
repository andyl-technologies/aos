//! Admits explicit cross-domain uploads through the real source and destination guards.

use terrane_core::auth::Verb;
use terrane_core::identity::{Digest, Identity, TERRANE_V1};
use terrane_core::tree_format::EntryKind;

use super::{AdvanceError, Coordinator, StagedUpload};
use crate::domain::{DomainDisclosure, DomainStore};
use crate::guard::Guard;
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, Clock, ContentStore, ContentUpload, IdentityPrefix,
    LocalFs, Store, StoreFailure,
};

/// Supplies exact source selection and destination authority for a fresh disclosure upload.
pub struct DisclosureUpload {
    /// Current source policy authority reference.
    pub source_reference: String,
    /// Immutable source commit containing the selected file.
    pub source_commit: Digest,
    /// Canonical absolute source file path.
    pub source_path: Vec<u8>,
    /// Capability checked only by the source guard.
    pub source_token: Vec<u8>,
    /// Destination reference whose current root permits the admission.
    pub destination_reference: String,
    /// Canonical absolute destination root or entry path.
    pub destination_path: Vec<u8>,
    /// Capability checked only by the destination guard.
    pub destination_token: Vec<u8>,
    /// Registered operation surface for both authorization requests.
    pub surface: String,
    /// Canonical upload whose bytes must equal the verified source encoding.
    pub upload: StagedUpload,
}

/// Borrows one already configured physical backend without opening a second namespace.
struct Backend<'a, S>(&'a S);

impl<S: ContentStore> CapabilityReport for Backend<'_, S> {
    fn capabilities(&self) -> &Capabilities {
        self.0.capabilities()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<S: ContentStore + Sync> ContentStore for Backend<'_, S> {
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        self.0.put(upload).await
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.0.get(identity, range).await
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        self.0.has(identities).await
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        self.0.list(prefix).await
    }
}

impl<S: Store + Sync, C: Clock, F: LocalFs> Coordinator<S, C, F> {
    /// Admits one explicitly selected encoding into an independently authorized destination domain.
    ///
    /// Both guards read their own real backends. Source credentials remain in
    /// guard calls, and the lower domain stores receive only opaque decisions.
    /// The returned receipt records an immutable upload, not a published ref;
    /// final signed disclosure admission must recheck the source authority.
    ///
    /// # Errors
    /// Denies stale or unrelated source selections, revoked ACLs or tokens,
    /// distinct principals, an unauthorized destination, mismatching bytes,
    /// expired upload windows, and storage failures.
    pub async fn prepare_disclosure<T: Store + Sync, D: Clock>(
        &self,
        source: &Guard<T, D>,
        request: DisclosureUpload,
    ) -> Result<DomainDisclosure, AdvanceError> {
        let started = self.guard().clock().monotonic();
        let snapshot = source
            .read_commit_snapshot(
                request.source_commit,
                &request.source_token,
                &request.source_path,
                &request.surface,
            )
            .await?;
        let relative = request
            .source_path
            .strip_prefix(b"/")
            .ok_or_else(crate::guard::invalid)?;
        let (content, size) = {
            let (location, _) = snapshot
                .history
                .locate(request.source_commit, relative)
                .map_err(|_| crate::guard::invalid())?;
            let entry = snapshot
                .history
                .entry(&location)
                .map_err(|_| crate::guard::invalid())?;
            let EntryKind::File { content, size, .. } = entry.kind else {
                return Err(crate::guard::invalid().into());
            };
            (content, size)
        };
        let source_access = source
            .domain_content_access(&snapshot, &request.source_path, content, size)
            .await?;
        if source_access.binding().reference != request.source_reference {
            return Err(crate::guard::denied(&request.source_reference, Verb::Read).into());
        }
        let destination = self
            .guard()
            .domain_access(
                &request.destination_reference,
                &request.destination_token,
                Verb::Commit,
                &request.destination_path,
                &request.surface,
            )
            .await?;
        let identity = match &request.upload {
            StagedUpload::Meta { kind, bytes } => TERRANE_V1
                .calculate(*kind, bytes)
                .map_err(|_| crate::guard::invalid())?,
            StagedUpload::Chunk { identity, .. } => identity.clone(),
        };
        if !source_access.permits_identity(&identity) {
            return Err(crate::guard::denied(&request.source_reference, Verb::Read).into());
        }
        source
            .authorize_snapshot_path(&snapshot, &request.source_path)
            .await?;
        let current_source = source
            .authorize(
                &request.source_reference,
                &request.source_token,
                Verb::Read,
                std::slice::from_ref(&request.source_path),
                &request.surface,
            )
            .await?;
        if current_source.record() != source_access.reference_record() {
            return Err(crate::guard::denied(&request.source_reference, Verb::Read).into());
        }
        let current_destination = self
            .guard()
            .authorize(
                &request.destination_reference,
                &request.destination_token,
                Verb::Commit,
                std::slice::from_ref(&request.destination_path),
                &request.surface,
            )
            .await?;
        if current_destination.record() != destination.reference_record() {
            return Err(crate::guard::denied(&request.destination_reference, Verb::Commit).into());
        }
        self.check_time(started)?;
        let source_store = DomainStore::new(
            source.config().storage_domain.clone(),
            Backend(source.store()),
        )?;
        let destination_store = DomainStore::new(
            self.guard().config().storage_domain.clone(),
            Backend(self.store()),
        )?;
        let receipt = destination_store
            .disclose_from(
                &destination,
                &source_store,
                &source_access,
                &identity,
                request.upload.as_upload()?,
            )
            .await?;
        self.check_time(started)?;
        Ok(receipt)
    }
}
