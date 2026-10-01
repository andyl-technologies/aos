//! Checks effective domain transitions and introduced reference ordering.

use terrane_core::identity::Identity;
use terrane_core::properties::Domain;

use crate::store::{InvalidReason, StoreErrorKind, StoreFailure};

/// Proves that a verified immutable record was admitted in one storage scope.
///
/// Equal identities in other scopes are separate records. Only scoped storage
/// and guarded publication can construct this evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainRecord {
    identity: Identity,
    domain: String,
}

impl DomainRecord {
    /// Constructs evidence after verified publication in the bound backend.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(Upload)` for an unregistered domain label.
    pub(crate) fn admitted(identity: Identity, domain: String) -> Result<Self, StoreFailure> {
        Domain::parse(&domain).map_err(|_| invalid("DOM-8"))?;
        Ok(Self { identity, domain })
    }

    /// Returns the verified immutable identity.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Returns the domain in which the record was verified.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }
}

/// Associates an introduced immutable reference with its actual storage scope.
#[derive(Clone, Copy, Debug)]
pub struct DomainReference<'a> {
    /// Identity of the referenced object, chunk, node, or graft root.
    pub identity: &'a Identity,
    /// Effective domain of the referenced record, resolved by the repository.
    pub domain: Domain<'a>,
}

/// Certifies disclosure ordering before a commit or merge can become visible.
///
/// The repository must supply every introduced entry and graft, including all
/// entries beneath a changed domain. This value does not prove traversal
/// completeness or authorize writing a different domain.
#[derive(Clone, Debug)]
pub struct DomainAdmission {
    domain: String,
    readmission: bool,
}

impl DomainAdmission {
    /// Checks ordering using storage-issued evidence for every reference.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(Upload)` for a forbidden transition or reference, or
    /// DOM-3 when a more-closed transition reuses an old-domain record.
    pub fn from_records(
        previous: Option<Domain<'_>>,
        effective: Domain<'_>,
        records: &[DomainRecord],
    ) -> Result<Self, StoreFailure> {
        let references: Result<Vec<_>, _> = records
            .iter()
            .map(|record| {
                Ok(DomainReference {
                    identity: record.identity(),
                    domain: Domain::parse(record.domain()).map_err(|_| invalid("DOM-8"))?,
                })
            })
            .collect();
        let admission = Self::new(previous, effective, &references?)?;
        if admission.readmission
            && records
                .iter()
                .any(|record| record.domain() != admission.domain)
        {
            return Err(invalid("DOM-3"));
        }

        Ok(admission)
    }

    /// Checks the old root policy and every newly carried reference (DOM-2/6).
    ///
    /// A more-closed transition requires fresh destination records for every
    /// entry. Explicit publication instead targets an already-open root under
    /// that root's commit authority; it cannot widen an existing root.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(Upload)` naming DOM-2 for an incomparable or widening
    /// transition, or DOM-5 for a reference to a more-closed storage scope.
    pub fn new(
        previous: Option<Domain<'_>>,
        effective: Domain<'_>,
        references: &[DomainReference<'_>],
    ) -> Result<Self, StoreFailure> {
        if previous.is_some_and(|old| !effective.permits_reference(old)) {
            return Err(invalid("DOM-2"));
        }
        if references
            .iter()
            .any(|reference| !effective.permits_reference(reference.domain))
        {
            return Err(invalid("DOM-5"));
        }

        Ok(Self {
            domain: super::label(effective),
            readmission: previous.is_some_and(|old| old != effective),
        })
    }

    /// Returns the canonical effective destination domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Reports that all entries need fresh destination-domain records (DOM-3).
    #[must_use]
    pub fn requires_readmission(&self) -> bool {
        self.readmission
    }
}

fn invalid(rule_id: &'static str) -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::Upload { rule_id }))
}
