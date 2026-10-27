//! Checks explicitly trusted original physical-authority bootstrap ACL evidence.
//!
//! Bootstrap policies are protected configuration inputs, not signed commit
//! fields. Their identity binds the original physical authority, ref and epoch;
//! the candidate and mutable current ACL cannot establish that configuration.

use super::super::{Rejected, VerifiedCommit};
use crate::{cbor, properties, tree_format::Property};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// Supplies a separately retained trusted original bootstrap policy.
///
/// The verifier's protected configuration must establish the exact physical
/// authoring authority. A token issuer, store expression, caller label or
/// candidate ACL cannot supply that binding. This input is never a verified
/// permit and never changes signed commit bytes.
#[derive(Clone, Copy, Debug)]
pub struct OriginalBootstrapPolicy<'a> {
    /// Identity of the independently established original physical authority.
    pub authority: &'a str,
    /// Exact original canonical ref governed by this retained baseline.
    pub reference: &'a str,
    /// Exact original writer epoch governed by this retained baseline.
    pub writer_epoch: u64,
    /// Original ordered principal/group verb grants, including an explicit empty baseline.
    pub acl: &'a [(&'a str, u8)],
}

#[derive(Clone, Eq, PartialEq)]
/// Retains a checked protected bootstrap association inside verified history.
pub(in crate::provenance) struct CheckedBootstrap {
    /// Independently established physical authoring authority.
    pub authority: String,
    /// Exact original canonical ref covered by the baseline.
    pub reference: String,
    /// Exact original writer epoch covered by the baseline.
    pub writer_epoch: u64,
    /// Separately retained original principal/group grants.
    pub acl: Vec<(String, u8)>,
}

impl core::fmt::Debug for CheckedBootstrap {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Protected control policy is not public provenance metadata.
        formatter
            .debug_struct("CheckedBootstrap")
            .finish_non_exhaustive()
    }
}

impl OriginalBootstrapPolicy<'_> {
    /// Checks retained configuration without exposing an authority permit.
    ///
    /// # Errors
    /// Returns [`Rejected`] for missing signed context, a mismatched original
    /// authority/ref/epoch association or invalid canonical ACL grants.
    pub(in crate::provenance) fn check(
        self,
        original: &VerifiedCommit,
        expected_authority: &str,
    ) -> Result<(), Rejected> {
        self.validate(original, expected_authority).map(|_| ())
    }

    /// Binds trusted original configuration to this authenticated commit context.
    ///
    /// # Errors
    /// Returns [`Rejected`] for missing signed context, a mismatched original
    /// authority/ref/epoch association or invalid canonical ACL grants.
    pub(super) fn validate(
        self,
        original: &VerifiedCommit,
        expected_authority: &str,
    ) -> Result<CheckedBootstrap, Rejected> {
        let record = original.commit();
        let context = record
            .profile_pair
            .commit_context
            .as_ref()
            .ok_or(Rejected)?;
        if expected_authority.is_empty()
            || self.authority != expected_authority
            || self.reference != context.reference()
            || self.writer_epoch != record.provenance.writer_epoch
        {
            return Err(Rejected);
        }
        let mut acl = Vec::new();
        cbor::write_array(&mut acl, self.acl.len());
        for (principal, verbs) in self.acl {
            cbor::write_array(&mut acl, 2);
            cbor::write_text(&mut acl, principal);
            cbor::write_uint(&mut acl, u64::from(*verbs));
        }
        properties::validate_property(&Property {
            name: "acl",
            value: &acl,
        })
        .map_err(|_| Rejected)?;
        Ok(CheckedBootstrap {
            authority: self.authority.to_string(),
            reference: self.reference.to_string(),
            writer_epoch: self.writer_epoch,
            acl: self
                .acl
                .iter()
                .map(|(name, verbs)| ((*name).to_string(), *verbs))
                .collect(),
        })
    }
}

/// Projects ACL operations using AUTH-22 rather than comparing raw wire masks.
pub(super) fn administrative_verbs(mask: u8) -> u8 {
    if mask & 16 != 0 { 20 } else { mask & 4 }
}

/// Reports actual Commit/Admin delegation beyond the governing grants.
pub(super) fn widens(child: &[(String, u8)], parent: &[(String, u8)]) -> bool {
    child.iter().any(|(principal, verbs)| {
        let inherited = parent
            .iter()
            .filter(|(name, _)| name == principal)
            .fold(0u8, |mask, (_, verbs)| mask | administrative_verbs(*verbs));
        administrative_verbs(*verbs) & !inherited != 0
    })
}
