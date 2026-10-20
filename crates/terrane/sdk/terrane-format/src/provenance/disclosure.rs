//! Authenticates scoped disclosure certificates and complete candidate boundaries.
//!
//! Provisional validation owns its history privately. Only a successful complete
//! batch exposes attested audit edges; source commits are never fabricated.
//!
//! ```text
//! binding = BLAKE3("terrane-disclosure-target-v1" || 0 || normalized unsigned commit)
//! proof = Ed25519("terrane-disclosure-proof-v1" || 0 || canonical statement)
//! ```

mod candidate;
mod statement;
mod witness;

pub use candidate::DisclosureCandidate;
pub use statement::{DisclosureSigning, disclosure_target_binding, sign_disclosure};

use super::{EntryLocation, Rejected};
use crate::{identity::Digest, properties::Domain, refs::EntrySource};
use alloc::{string::String, vec::Vec};

/// Configures a separately trusted, historically scoped source disclosure key.
///
/// Repository identifiers come from trusted physical backend configuration.
/// They are never inferred from a token issuer or the certificate's bare key.
/// Retaining old intervals permits historical verification after key rotation;
/// removing a role from this configuration explicitly revokes its evidence.
#[derive(Clone, Copy, Debug)]
pub struct DisclosureAuthority<'a> {
    /// Stable identity of the exact physical source repository.
    pub repository: &'a str,
    /// Canonical effective source domain governed by this role.
    pub domain: &'a str,
    /// Ed25519 public key registered specifically for source disclosure.
    pub public_key: [u8; 32],
    /// Earliest inclusive issue time authorized for this key.
    pub not_before: u64,
    /// Exclusive issue-time bound, or no upper bound.
    pub not_after: Option<u64>,
}

impl DisclosureAuthority<'_> {
    fn permits(&self, observed_at: u64) -> Result<(), Rejected> {
        Domain::parse(self.domain).map_err(|_| Rejected)?;
        if self.repository.is_empty()
            || self.not_after.is_some_and(|end| end <= self.not_before)
            || observed_at < self.not_before
            || self.not_after.is_some_and(|end| observed_at >= end)
        {
            return Err(Rejected);
        }
        Ok(())
    }
}

/// Exposes one authenticated source attestation without private commit authority.
///
/// Fields remain private so raw receipt metadata cannot construct a boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDisclosureBoundary {
    pub(super) target: EntryLocation,
    pub(super) source: EntrySource,
    pub(super) original_introducer: Digest,
    pub(super) authority_repository: String,
    pub(super) authority_domain: String,
    pub(super) authority_key: [u8; 32],
    pub(super) observed_at: u64,
    pub(super) target_domain: String,
    pub(super) root_occurrences: Vec<Vec<u8>>,
    pub(super) binding: Digest,
}

impl VerifiedDisclosureBoundary {
    /// Returns the exact canonical destination entry covered by this certificate.
    pub fn target(&self) -> &EntryLocation {
        &self.target
    }

    /// Returns the source witness identity attested by the configured authority.
    pub fn source(&self) -> &EntrySource {
        &self.source
    }

    /// Returns the attested original introduction, not a verified private commit.
    pub fn original_introducer(&self) -> Digest {
        self.original_introducer
    }

    /// Returns the trusted physical source repository identifier.
    pub fn authority_repository(&self) -> &str {
        &self.authority_repository
    }

    /// Returns the separately scoped source disclosure domain.
    pub fn authority_domain(&self) -> &str {
        &self.authority_domain
    }

    /// Returns the historical source disclosure verification key.
    pub fn authority_key(&self) -> &[u8; 32] {
        &self.authority_key
    }

    /// Returns the authenticated source authority issue time.
    pub fn observed_at(&self) -> u64 {
        self.observed_at
    }

    /// Returns the actual effective destination domain.
    pub fn target_domain(&self) -> &str {
        &self.target_domain
    }

    /// Returns absolute paths of the checked destination root occurrences.
    ///
    /// The main root is `/`; graft roots include their full absolute prefix.
    pub fn root_occurrences(&self) -> &[Vec<u8>] {
        &self.root_occurrences
    }

    /// Returns the normalized complete unsigned destination binding.
    pub fn destination_binding(&self) -> Digest {
        self.binding
    }
}

/// Carries exact audit boundaries admitted by complete candidate validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDisclosureBatch {
    view: Digest,
    boundaries: Vec<VerifiedDisclosureBoundary>,
    parents: Vec<Digest>,
    dependencies: Vec<Digest>,
}

impl VerifiedDisclosureBatch {
    /// Returns the immutable signed destination identity validated by this batch.
    pub fn view(&self) -> Digest {
        self.view
    }

    /// Returns every authenticated entry boundary in the destination candidate.
    pub fn boundaries(&self) -> &[VerifiedDisclosureBoundary] {
        &self.boundaries
    }

    /// Reports whether this exact signed parent edge is certified audit-only.
    pub fn certified_parent(&self, child: Digest, parent: Digest) -> bool {
        child == self.view && self.parents.contains(&parent)
    }

    /// Returns retained ordinary parent and source commit dependencies.
    ///
    /// This list omits only exact authenticated content reintroduction edges
    /// and certified input-parent edges. Independent attribute sources remain.
    pub fn required_commits(&self) -> &[Digest] {
        &self.dependencies
    }
}

pub(super) fn key_name(key: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in key {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 15)]));
    }
    text
}
