//! Binds guarded operations to trusted root policy without forwarding tokens.

use terrane_core::auth::Verb;
use terrane_core::identity::{Digest, Identity};
use terrane_core::properties::Domain;
use terrane_core::refs::RefRecord;

use crate::store::{InvalidReason, StoreErrorKind, StoreFailure};

/// Names the verified operation snapshot resolved by the repository guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainBinding {
    /// Canonical effective disclosure-domain label.
    pub domain: String,
    /// Canonical ref containing the root.
    pub reference: String,
    /// Immutable identity of the effective root.
    pub root: Identity,
    /// Canonical absolute path of that root in the ref.
    pub path: Vec<u8>,
}

/// Carries a guard decision for exactly one root and domain.
///
/// Fields and construction remain private to the enforcement layer. A caller
/// cannot select a different domain by editing an authorized request.
/// Read authority covers only identities whose reachability the guard verified
/// beneath the authorized path, rather than every hash stored in the domain.
/// This decision belongs to one guarded operation. Repository entry points
/// recheck the token, revocation state, and current ACL for each later operation;
/// cloning this snapshot does not establish that its authority remains current.
#[derive(Clone, Debug)]
pub struct DomainAccess {
    binding: DomainBinding,
    verb: Verb,
    subject: String,
    token_id: [u8; 16],
    read_identities: Vec<Identity>,
    read_paths: Vec<(Identity, Vec<u8>)>,
    reference_record: Option<RefRecord>,
    read_commit: Option<Digest>,
}

impl DomainAccess {
    /// Constructs the binding after token and current-ACL authorization.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(MalformedRequest)` for an unregistered domain label.
    pub(crate) fn authorized(
        binding: DomainBinding,
        verb: Verb,
        subject: String,
        token_id: [u8; 16],
    ) -> Result<Self, StoreFailure> {
        Domain::parse(&binding.domain).map_err(|_| {
            StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::MalformedRequest))
        })?;

        Ok(Self {
            binding,
            verb,
            subject,
            token_id,
            read_identities: Vec::new(),
            read_paths: Vec::new(),
            reference_record: None,
            read_commit: None,
        })
    }

    /// Binds reads to identities whose authorized reachability guard proved.
    ///
    /// A root decision alone starts with no hash-read authority. Guard supplies
    /// only verified reachable content or the exact authorized domain filter;
    /// requesters cannot attach their own allowlist.
    pub(crate) fn with_read_identities(mut self, identities: Vec<Identity>) -> Self {
        self.read_identities = identities;
        self
    }

    /// Reports whether guard proved this identity readable in the bound scope.
    pub(crate) fn permits_identity(&self, identity: &Identity) -> bool {
        self.read_identities.contains(identity)
    }

    /// Binds one identity to its exact authenticated full source-file path.
    ///
    /// Guard calls this only after history entry and content membership match.
    /// Equal hashes at different aliases require separate operation decisions.
    ///
    /// # Errors
    ///
    /// Returns `Invalid(MalformedRequest)` for a noncanonical absolute file
    /// path or conflicting source aliases for the same identity.
    pub(crate) fn with_read_path(
        mut self,
        identity: Identity,
        full_path: Vec<u8>,
    ) -> Result<Self, StoreFailure> {
        let invalid =
            || StoreFailure::new(StoreErrorKind::Invalid(InvalidReason::MalformedRequest));
        let relative = full_path.strip_prefix(b"/").ok_or_else(invalid)?;
        terrane_core::tree_format::validate_key(relative).map_err(|_| invalid())?;
        if let Some((_, previous)) = self.read_paths.iter().find(|(id, _)| id == &identity) {
            if previous != &full_path {
                return Err(invalid());
            }
            return Ok(self);
        }

        if !self.read_identities.contains(&identity) {
            self.read_identities.push(identity.clone());
        }
        self.read_paths.push((identity, full_path));
        Ok(self)
    }

    /// Returns the exact file path whose authenticated entry proved this read.
    pub(crate) fn read_path(&self, identity: &Identity) -> Option<&[u8]> {
        self.read_paths
            .iter()
            .find(|(id, _)| id == identity)
            .map(|(_, path)| path.as_slice())
    }

    /// Binds the immutable commit whose verified snapshot supplied the bytes.
    ///
    /// Guard keeps the selected snapshot root in the binding and separately
    /// retains the current live policy authority record.
    pub(crate) fn with_read_commit(mut self, commit: Digest) -> Self {
        self.read_commit = Some(commit);
        self
    }

    /// Returns the selected immutable source commit verified for this read.
    ///
    /// This target can differ from the current live authorization record.
    #[must_use]
    pub fn read_commit(&self) -> Option<&Digest> {
        self.read_commit.as_ref()
    }

    /// Pins the exact authority record reread after current-policy authorization.
    pub(crate) fn with_reference_record(mut self, record: RefRecord) -> Self {
        self.reference_record = Some(record);
        self
    }

    /// Returns the whole authority record checked for this operation.
    ///
    /// Deletion compares this record, including its complete CAS metadata,
    /// against the current authority while holding backend exclusion. Absence
    /// cannot authorize deletion. An immutable commit view may retain a target
    /// distinct from this current policy record.
    #[must_use]
    pub fn reference_record(&self) -> Option<&RefRecord> {
        self.reference_record.as_ref()
    }

    /// Returns the immutable snapshot binding checked by guard.
    #[must_use]
    pub fn binding(&self) -> &DomainBinding {
        &self.binding
    }

    /// Returns the authorized verb.
    #[must_use]
    pub fn verb(&self) -> Verb {
        self.verb
    }

    /// Returns the authenticated actor for disclosure and deletion records.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the authenticated token identifier for audit correlation.
    #[must_use]
    pub fn token_id(&self) -> &[u8; 16] {
        &self.token_id
    }
}
