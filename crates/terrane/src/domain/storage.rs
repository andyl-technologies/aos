//! Restricts content operations to one independently opened domain backend.
//!
//! Every request consults only the bound backend. In particular, a miss never
//! probes a global index or another domain, and an upload never short-circuits
//! on another domain's content. Software-controlled existence and dedup timing
//! channels from cross-domain lookup and pack sharing are closed this way.
//! Physical device, network, and operating-system scheduling contention remain
//! residual channels; this module makes no Security-level conformance claim.

use terrane_core::auth::Verb;
use terrane_core::identity::{Identity, IdentityKind};
use terrane_core::properties::Domain;

use super::{DomainAccess, DomainRecord};
use crate::store::{
    ByteRange, ContentStore, ContentUpload, InvalidReason, StoreErrorKind, StoreFailure,
};

/// Records an explicitly authorized admission into an existing open root.
///
/// The coordinator must bind this evidence to the fold commit's signed entry
/// receipts and provenance before publishing its ref (DOM-7). Possession of
/// this receipt alone does not authorize a ref advance or policy widening.
#[derive(Clone, Debug)]
pub struct DomainDisclosure {
    source_access: DomainAccess,
    source_path: Vec<u8>,
    destination: super::DomainBinding,
    record: DomainRecord,
    subject: String,
    token_id: [u8; 16],
}

impl DomainDisclosure {
    /// Returns the root from which bytes were read with source authority.
    #[must_use]
    pub fn source(&self) -> &super::DomainBinding {
        self.source_access.binding()
    }

    /// Returns the opaque source decision including its exact authority record.
    #[must_use]
    pub fn source_access(&self) -> &DomainAccess {
        &self.source_access
    }

    /// Returns the full source-file path whose entry and content guard verified.
    #[must_use]
    pub fn source_path(&self) -> &[u8] {
        &self.source_path
    }

    /// Returns the existing destination root authorized to admit these bytes.
    #[must_use]
    pub fn destination(&self) -> &super::DomainBinding {
        &self.destination
    }

    /// Returns the freshly admitted destination-domain record.
    #[must_use]
    pub fn record(&self) -> &DomainRecord {
        &self.record
    }

    /// Returns the authenticated principal performing the disclosure.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the destination authority token's audit identifier.
    #[must_use]
    pub fn token_id(&self) -> &[u8; 16] {
        &self.token_id
    }
}

/// Serves one disclosure scope from a physically independent backend.
///
/// The trusted backend factory must open separate storage for each label;
/// sharing a backend or its packs across scopes violates this contract. The
/// wrapper never searches other stores, even for public content. Cross-domain
/// references are resolved with separate, independently authorized requests.
/// The guard calls this enforcement component with a fresh operation decision;
/// repository APIs must not expose reusable snapshots as live authorization.
pub struct DomainStore<S> {
    domain: String,
    pub(super) backend: S,
}

impl<S: ContentStore> DomainStore<S> {
    /// Explicitly discloses verified source bytes into an already-open root.
    ///
    /// Source reads and destination writes use separate guard decisions for
    /// the same authenticated principal. The destination backend validates a
    /// fresh upload even when the identity is already present elsewhere; no
    /// old-domain record is reused.
    ///
    /// # Errors
    ///
    /// Returns `Denied` for different principals, missing source commit/ref/path evidence,
    /// or missing source read or destination commit authority, `Invalid(Upload)` if the uploaded bytes
    /// differ from the source, or a backend verification/admission failure.
    /// The coordinator must still record and validate the disclosure in the signed commit provenance.
    pub async fn disclose_from<T: ContentStore>(
        &self,
        destination: &DomainAccess,
        source: &DomainStore<T>,
        source_access: &DomainAccess,
        identity: &Identity,
        upload: ContentUpload<'_>,
    ) -> Result<DomainDisclosure, StoreFailure> {
        self.check(destination, Verb::Commit)?;
        if source_access.subject() != destination.subject()
            || source_access.reference_record().is_none()
            || source_access.read_commit().is_none()
        {
            return Err(StoreFailure::new(StoreErrorKind::Denied {
                verb: "commit",
                pattern: destination.binding().reference.clone(),
            }));
        }

        let source_path = source_access
            .read_path(identity)
            .ok_or_else(|| {
                StoreFailure::new(StoreErrorKind::Denied {
                    verb: "read",
                    pattern: source_access.binding().reference.clone(),
                })
            })?
            .to_vec();
        let bytes = source.get(source_access, identity, None).await?;
        let (offered_kind, offered_bytes) = match upload {
            ContentUpload::Chunk(chunk) => (IdentityKind::Chunk, chunk.encoded),
            ContentUpload::Meta(meta) => (meta.kind(), meta.bytes()),
        };
        if offered_kind != identity.kind() || offered_bytes != bytes {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::Upload { rule_id: "DOM-7" },
            )));
        }

        let record = self.put_record(destination, upload).await?;
        if record.identity() != identity {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::Upload { rule_id: "DOM-7" },
            )));
        }

        Ok(DomainDisclosure {
            source_access: source_access.clone(),
            source_path,
            destination: destination.binding().clone(),
            record,
            subject: destination.subject().to_owned(),
            token_id: *destination.token_id(),
        })
    }

    /// Admits bytes and returns evidence for commit or merge reference checks.
    ///
    /// # Errors
    ///
    /// Returns the same authorization and admission failures as [`Self::put`].
    pub async fn put_record(
        &self,
        access: &DomainAccess,
        upload: ContentUpload<'_>,
    ) -> Result<DomainRecord, StoreFailure> {
        let identity = self.put(access, upload).await?;
        DomainRecord::admitted(identity, self.domain.clone())
    }

    /// Verifies an existing record before issuing scoped reference evidence.
    ///
    /// # Errors
    ///
    /// Returns the same authorization and verification failures as [`Self::get`].
    pub async fn verify_reference(
        &self,
        access: &DomainAccess,
        identity: &Identity,
    ) -> Result<DomainRecord, StoreFailure> {
        self.get(access, identity, None).await?;
        DomainRecord::admitted(identity.clone(), self.domain.clone())
    }

    /// Binds an independently opened backend to its canonical domain label.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(MalformedRequest)` for an unregistered domain label.
    pub fn new(domain: String, backend: S) -> Result<Self, StoreFailure> {
        Domain::parse(&domain).map_err(|_| {
            StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::MalformedRequest))
        })?;

        Ok(Self { domain, backend })
    }

    /// Returns the sole disclosure domain served by this backend.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Admits verified content under the destination root's commit authority.
    ///
    /// # Errors
    ///
    /// Returns `Denied` for a different scope or a nonwriting decision, or the
    /// backend's admission failure. No other domain's presence is consulted.
    pub async fn put(
        &self,
        access: &DomainAccess,
        upload: ContentUpload<'_>,
    ) -> Result<Identity, StoreFailure> {
        self.check(access, Verb::Commit)?;
        self.backend.put(upload).await
    }

    /// Retrieves content solely within the authorized disclosure scope.
    ///
    /// # Errors
    ///
    /// Returns `Denied` for an unauthorized scope, or the backend's retrieval
    /// failure. An identity outside the authorized reachable set returns
    /// `Absent` without consulting storage, even within the same domain.
    pub async fn get(
        &self,
        access: &DomainAccess,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.check(access, Verb::Read)?;
        if !access.permits_identity(identity) {
            return Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())));
        }
        self.backend.get(identity, range).await
    }

    /// Tests ordered membership only in the authorized domain (DOM-10/16).
    ///
    /// # Errors
    ///
    /// Returns `Denied` for an unauthorized scope, or the backend's membership
    /// failure, including an invalid backend response length. Identities
    /// outside the authorized reachable set return false without a lookup.
    pub async fn has(
        &self,
        access: &DomainAccess,
        identities: &[Identity],
    ) -> Result<Vec<bool>, StoreFailure> {
        self.check(access, Verb::Read)?;
        let readable: Vec<_> = identities
            .iter()
            .filter(|identity| access.permits_identity(identity))
            .cloned()
            .collect();
        if readable.is_empty() {
            return Ok(vec![false; identities.len()]);
        }
        let present = self.backend.has(&readable).await?;
        if present.len() != readable.len() {
            return Err(StoreFailure::new(StoreErrorKind::Unavailable {
                retry_after: None,
            }));
        }
        let mut answers = present.into_iter();
        Ok(identities
            .iter()
            .map(|identity| {
                if access.permits_identity(identity) {
                    answers.next().unwrap_or(false)
                } else {
                    false
                }
            })
            .collect())
    }

    /// Retrieves a filter built and stored in this domain alone (DOM-11).
    ///
    /// A public filter is available through a guard-authorized public root;
    /// no caller can use a private-root decision to fetch another filter.
    ///
    /// # Errors
    ///
    /// Returns `Denied` for a different scope, `Invalid(MalformedRequest)` for
    /// a non-filter identity, `Absent` outside the authorized reachable set,
    /// or the backend's retrieval failure.
    pub async fn filter(
        &self,
        access: &DomainAccess,
        identity: &Identity,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.check(access, Verb::Read)?;
        if !access.permits_identity(identity) {
            return Err(StoreFailure::new(StoreErrorKind::Absent(identity.clone())));
        }
        if identity.kind() != IdentityKind::Filter {
            return Err(StoreFailure::new(StoreErrorKind::Invalid(
                InvalidReason::MalformedRequest,
            )));
        }

        self.backend.get(identity, None).await
    }

    fn check(&self, access: &DomainAccess, verb: Verb) -> Result<(), StoreFailure> {
        let permitted = access.verb() == Verb::Admin
            || access.verb() == verb
            || (verb == Verb::Read
                && matches!(access.verb(), Verb::Commit | Verb::Fork | Verb::Tag));
        if access.binding().domain != self.domain || !permitted {
            let verb = if verb == Verb::Commit {
                "commit"
            } else {
                "read"
            };
            return Err(StoreFailure::new(StoreErrorKind::Denied {
                verb,
                pattern: access.binding().reference.clone(),
            }));
        }

        Ok(())
    }
}
