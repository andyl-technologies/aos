//! Stable certificate identity shared by authenticated control transports.
//!
//! TLS verification remains with the transport. These values identify the same
//! leaf bytes on client and server without importing either runtime into the
//! other. Certificate fingerprinting uses the existing SHA-256 representation.

use sha2::{Digest, Sha256};

/// Names a leaf certificate presented by a daemon transport connection.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DebugTransportIdentity {
    certificate_sha256: String,
}

impl DebugTransportIdentity {
    /// Derives an identity from the leaf certificate bytes.
    ///
    /// This operation does not authenticate a certificate or grant authority.
    #[must_use]
    pub fn from_leaf_certificate(certificate: &[u8]) -> Self {
        let digest = Sha256::digest(certificate);
        let mut certificate_sha256 = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(certificate_sha256, "{byte:02x}");
        }
        Self { certificate_sha256 }
    }

    /// Returns the lowercase SHA-256 fingerprint of the leaf certificate.
    #[must_use]
    pub fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_identity_is_stable_and_unambiguous() {
        let identity = DebugTransportIdentity::from_leaf_certificate(b"client-certificate");
        assert_eq!(identity.certificate_sha256().len(), 64);
        assert!(
            identity
                .certificate_sha256()
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert_eq!(
            identity,
            DebugTransportIdentity::from_leaf_certificate(b"client-certificate")
        );
        assert_ne!(
            identity,
            DebugTransportIdentity::from_leaf_certificate(b"other-certificate")
        );
    }
}
