//! Transport-authenticated debugger authorization policy.
//!
//! TLS and Unix transports establish identities; this module maps those
//! identities to the session layer's closed debugger capability roles. The
//! policy grants nothing by default and models an explicitly trusted
//! unauthenticated listener separately from authenticated principals.

use std::collections::BTreeMap;

use crucible_session::DebugRole;
use thiserror::Error;

use crate::DebugTransportIdentity;

/// Capability policy applied to debugger transport requests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DebugAuthorizationPolicy {
    certificate_roles: BTreeMap<String, DebugRole>,
    trusted_unauthenticated_role: Option<DebugRole>,
}

impl DebugAuthorizationPolicy {
    /// Builds a deny-by-default authorization policy.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Grants a role to one lowercase SHA-256 certificate fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`DebugAuthorizationPolicyError::InvalidCertificateFingerprint`]
    /// unless `fingerprint` contains exactly 64 lowercase hexadecimal digits,
    /// or [`DebugAuthorizationPolicyError::DuplicateCertificateFingerprint`]
    /// when that principal already has a configured role.
    pub fn grant_certificate_role(
        &mut self,
        fingerprint: impl Into<String>,
        role: DebugRole,
    ) -> Result<(), DebugAuthorizationPolicyError> {
        let fingerprint = fingerprint.into();
        if !valid_certificate_fingerprint(&fingerprint) {
            return Err(DebugAuthorizationPolicyError::InvalidCertificateFingerprint);
        }
        if self.certificate_roles.contains_key(&fingerprint) {
            return Err(DebugAuthorizationPolicyError::DuplicateCertificateFingerprint);
        }
        self.certificate_roles.insert(fingerprint, role);
        Ok(())
    }

    /// Grants a role to requests on an explicitly trusted unauthenticated
    /// listener.
    pub fn grant_trusted_unauthenticated_role(&mut self, role: DebugRole) {
        self.trusted_unauthenticated_role = Some(role);
    }

    /// Resolves the role for one transport identity.
    ///
    /// # Errors
    ///
    /// Returns [`DebugAuthorizationPolicyError::PrincipalDenied`] when the
    /// authenticated certificate has no configured role or when an
    /// unauthenticated transport has not been explicitly trusted.
    pub fn role_for(
        &self,
        identity: Option<&DebugTransportIdentity>,
    ) -> Result<&DebugRole, DebugAuthorizationPolicyError> {
        match identity {
            Some(identity) => self
                .certificate_roles
                .get(identity.certificate_sha256())
                .ok_or(DebugAuthorizationPolicyError::PrincipalDenied),
            None => self
                .trusted_unauthenticated_role
                .as_ref()
                .ok_or(DebugAuthorizationPolicyError::PrincipalDenied),
        }
    }
}

/// Errors returned by debugger authorization policy configuration and lookup.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DebugAuthorizationPolicyError {
    /// A certificate fingerprint was not canonical lowercase SHA-256 text.
    #[error("debug certificate fingerprint must be 64 lowercase hexadecimal digits")]
    InvalidCertificateFingerprint,
    /// A certificate fingerprint appeared more than once in daemon policy.
    #[error("debug certificate fingerprint has more than one configured role")]
    DuplicateCertificateFingerprint,
    /// No debugger role was configured for the authenticated principal.
    #[error("debug transport principal has no authorized role")]
    PrincipalDenied,
}

fn valid_certificate_fingerprint(fingerprint: &str) -> bool {
    fingerprint.len() == 64
        && fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use crucible_session::{DebugCapability, DebugRole};

    use super::*;

    #[test]
    fn policy_denies_unknown_and_noncanonical_principals() {
        let mut policy = DebugAuthorizationPolicy::deny_all();
        assert_eq!(
            policy.grant_certificate_role("AB", DebugRole::observer()),
            Err(DebugAuthorizationPolicyError::InvalidCertificateFingerprint)
        );
        let identity = DebugTransportIdentity::from_leaf_certificate(b"unknown");
        assert_eq!(
            policy.role_for(Some(&identity)),
            Err(DebugAuthorizationPolicyError::PrincipalDenied)
        );
        assert_eq!(
            policy.role_for(None),
            Err(DebugAuthorizationPolicyError::PrincipalDenied)
        );
    }

    #[test]
    fn certificate_and_explicit_trusted_roles_remain_distinct() {
        let identity = DebugTransportIdentity::from_leaf_certificate(b"operator");
        let controller = DebugRole::new([DebugCapability::Observe, DebugCapability::Control]);
        let mut policy = DebugAuthorizationPolicy::deny_all();
        policy
            .grant_certificate_role(identity.certificate_sha256(), controller.clone())
            .unwrap_or_else(|error| panic!("valid fingerprint should be accepted: {error}"));
        policy.grant_trusted_unauthenticated_role(DebugRole::observer());
        assert_eq!(policy.role_for(Some(&identity)), Ok(&controller));
        assert_eq!(policy.role_for(None), Ok(&DebugRole::observer()));
        assert_eq!(
            policy.grant_certificate_role(identity.certificate_sha256(), DebugRole::observer()),
            Err(DebugAuthorizationPolicyError::DuplicateCertificateFingerprint)
        );
    }
}
