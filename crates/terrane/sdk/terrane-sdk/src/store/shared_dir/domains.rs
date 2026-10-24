//! Routes guarded reads to one configured domain without cross-domain fallback.

use super::{HostViewReader, SharedView};
use crate::domain::{DomainAccess, DomainNamespace, DomainNamespaces};
use crate::host::cache::{HostReadOnlyContent, HostResidentContent};
use crate::store::{ByteRange, ContentStore, StoreErrorKind, StoreFailure};
use terrane_format::identity::Identity;

/// Selects independent shared directories using a guard-issued root decision.
///
/// Each domain has exactly one configured adapter. A missing or mismatched
/// domain never falls back to another domain, including `public`. The calling
/// repository must obtain a fresh guard decision for each operation; retaining
/// this routing table does not extend an authorization decision's lifetime.
pub type SharedDirRoutes<F, V> = SharedRoutes<HostReadOnlyContent<F, V>>;

/// Routes guarded reads through concrete host readers with residence fallback.
pub type ResidentSharedDirRoutes<F, V, R> = SharedRoutes<HostResidentContent<F, V, R>>;

/// Shares canonical-domain routing across the two supported host view readers.
///
/// The sealed reader interface prevents unrelated stores from bypassing the
/// concrete host verification path. Each operation retains guard reachability.
pub struct SharedRoutes<S> {
    directories: Vec<SharedView<S>>,
}

impl<S: HostViewReader> SharedRoutes<S> {
    /// Validates unique domain labels and disjoint configured root paths.
    ///
    /// Host opening validates actual directory components. Trusted operators
    /// must also prevent bind-mount aliases and later namespace replacement;
    /// lexical separation alone cannot establish those deployment invariants.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` for duplicate domains, overlapping configured paths,
    /// or roots observed as the same device and inode at opening.
    pub fn new(directories: Vec<SharedView<S>>) -> Result<Self, StoreFailure> {
        DomainNamespaces::new(
            directories
                .iter()
                .map(|directory| DomainNamespace {
                    domain: directory.domain_binding().domain.clone(),
                    root: directory.layout().root().to_owned(),
                })
                .collect(),
        )?;

        for (index, directory) in directories.iter().enumerate() {
            if directories[..index]
                .iter()
                .any(|previous| previous.directory_identity() == directory.directory_identity())
            {
                return Err(StoreFailure::new(StoreErrorKind::Invalid(
                    crate::store::InvalidReason::MalformedRequest,
                )));
            }
        }

        Ok(Self { directories })
    }

    /// Reads verified encoded content from the authorized effective domain.
    ///
    /// # Errors
    ///
    /// Returns `Denied` for an unknown domain or an identity outside its verified
    /// closure; otherwise preserves store errors.
    pub async fn get(
        &self,
        access: &DomainAccess,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        let directory = self.select(access)?;
        if !access.permits_identity(identity) {
            return Err(denied(access));
        }

        directory.get(identity, range).await
    }

    /// Tests scoped membership in input order without looking up unreadable IDs.
    ///
    /// # Errors
    ///
    /// Returns `Denied` for an unknown domain, and preserves the selected
    /// directory's membership failure.
    pub async fn has(
        &self,
        access: &DomainAccess,
        identities: &[Identity],
    ) -> Result<Vec<bool>, StoreFailure> {
        let directory = self.select(access)?;
        let readable: Vec<_> = identities
            .iter()
            .filter(|identity| access.permits_identity(identity))
            .cloned()
            .collect();
        if readable.is_empty() {
            return Ok(vec![false; identities.len()]);
        }

        let presence = directory.has(&readable).await?;
        if presence.len() != readable.len() {
            return Err(StoreFailure::new(StoreErrorKind::Unavailable {
                retry_after: None,
            }));
        }

        let mut answers = presence.into_iter();
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

    fn select(&self, access: &DomainAccess) -> Result<&SharedView<S>, StoreFailure> {
        self.directories
            .iter()
            .find(|directory| directory.domain_binding().domain == access.binding().domain)
            .ok_or_else(|| denied(access))
    }
}

fn denied(access: &DomainAccess) -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Denied {
        verb: "read",
        pattern: access.binding().reference.clone(),
    })
}
