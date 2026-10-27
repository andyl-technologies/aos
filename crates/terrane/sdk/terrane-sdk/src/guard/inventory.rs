//! Filters a complete candidate inventory through fresh current ref policy.
//!
//! Inventory names establish neither existence nor authority. Every returned
//! whole record is independently authorized before and after enumeration.
//! The result is materialized and does not promise an atomic multi-ref snapshot.

use std::collections::BTreeSet;

use terrane_format::{
    auth::{self, Grant, SubjectPattern, Verb, Verbs},
    refs::{RefName, RefRecord},
};

use super::{Guard, denied, invalid};
use crate::store::{Clock, RefInventory, Store, StoreErrorKind, StoreFailure};

/// Reports a named whole ref record observed under current read authority.
///
/// This metadata is not a retained capability. Reading its commit or any
/// reachable content still requires fresh guarded operation checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedRef {
    name: String,
    record: RefRecord,
}

impl ListedRef {
    /// Returns the canonical ref name from the authoritative inventory.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the complete current record, including epoch, home and selector.
    pub fn record(&self) -> &RefRecord {
        &self.record
    }
}

impl<S: Store + RefInventory, C: Clock> Guard<S, C> {
    /// Enumerates matching refs under fresh current read policy.
    ///
    /// The pattern uses the capability language's byte globs: `*` stays within
    /// a slash component and `**` crosses components. Root suffixes are invalid.
    /// Deleted or losing candidates and refs without current Read are omitted.
    /// Results are ordered by canonical ref bytes. Each whole returned record
    /// must remain unchanged through its closing authorization check.
    ///
    /// The inventory is complete at its backend observation, but later creation
    /// is not part of that observation. This materialized result supplies no
    /// cross-ref transaction or bounded streaming resource policy.
    ///
    /// # Errors
    /// Rejects malformed patterns, invalid or expired tokens (even for an empty
    /// match), malformed or incomplete inventories, backend or history failures,
    /// and policy revocation while closing results. A changed whole record
    /// returns `Unavailable`, allowing a fresh enumeration attempt. Candidate
    /// failures omit names and backend causes because those candidates may be
    /// outside the caller's current authority.
    pub async fn list_refs(
        &self,
        pattern: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<Vec<ListedRef>, StoreFailure> {
        let requested_pattern = pattern;
        let pattern = checked_pattern(pattern)?;
        self.verify_inventory_identity(token)?;
        let names = self.store.ref_names().await.map_err(|error| {
            if matches!(error.kind(), StoreErrorKind::Unsupported) {
                StoreFailure::new(StoreErrorKind::Unsupported)
            } else {
                unavailable()
            }
        })?;
        let names = checked_names(names)?;
        let mut selected = Vec::new();

        for name in names.into_iter().filter(|name| pattern.matches(name)) {
            let authorized = match self.authorize(&name, token, Verb::Read, &[], surface).await {
                Ok(authorized) => authorized,
                Err(error) if matches!(error.kind(), StoreErrorKind::Denied { .. }) => continue,
                Err(_) => return Err(unavailable()),
            };
            if let Some(record) = authorized.record() {
                selected.push(ListedRef {
                    name,
                    record: record.clone(),
                });
            }
        }

        // A result gathered earlier must not escape after revocation, expiry,
        // or replacement while later candidates were awaited. Compare every
        // whole record, including equal-commit epoch and selector changes.
        for entry in &selected {
            let current = match self
                .authorize(&entry.name, token, Verb::Read, &[], surface)
                .await
            {
                Ok(current) => current,
                Err(error) if matches!(error.kind(), StoreErrorKind::Denied { .. }) => {
                    return Err(denied(requested_pattern, Verb::Read));
                }
                Err(_) => return Err(unavailable()),
            };
            if current.record() != Some(&entry.record) {
                return Err(unavailable());
            }
        }
        self.verify_inventory_identity(token)?;
        Ok(selected)
    }

    fn verify_inventory_identity(&self, token: &[u8]) -> Result<(), StoreFailure> {
        let now = self.now("refs/**", Verb::Read)?;
        auth::verify(token, &self.keys, now)
            .map(|_| ())
            .map_err(|_| denied("refs/**", Verb::Read))
    }
}

fn checked_pattern(pattern: &str) -> Result<SubjectPattern, StoreFailure> {
    if pattern.contains(':') {
        return Err(invalid());
    }
    let verbs = Verbs::new(Verb::Read as u8).map_err(|_| invalid())?;
    Grant::new(pattern.to_owned(), verbs).map_err(|_| invalid())?;
    // The shared byte matcher imposes no subject-specific grammar; the grant
    // validator above supplies the canonical, root-free ref-pattern grammar.
    Ok(SubjectPattern::new(pattern.to_owned()))
}

fn checked_names(names: Vec<String>) -> Result<BTreeSet<String>, StoreFailure> {
    let mut checked = BTreeSet::new();
    for name in names {
        if RefName::parse(&name).is_err() || !checked.insert(name.clone()) {
            return Err(unavailable());
        }
    }
    Ok(checked)
}

// Even a diagnostic source could reveal a name not yet authorized for this
// caller. Refuse the attempt without exporting per-candidate failure details.
fn unavailable() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None })
}
