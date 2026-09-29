//! Computes domain-separated immutable identities and validates descriptors.
//!
//! A store chooses one [`IdentityProfile`]. The initial [`TERRANE_V1`] profile
//! binds eleven registered kinds to BLAKE3-256 domains. Future profiles can
//! register a separate domain table and digest algorithm without changing any
//! identity already issued by an existing store.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

/// The fixed-width digest field used by the initial on-disk formats.
pub type Digest = [u8; 32];

/// An immutable kind with a distinct domain in each identity profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IdentityKind {
    /// A plaintext chunk.
    Chunk,
    /// An object manifest.
    Manifest,
    /// A tree node.
    Node,
    /// A commit.
    Commit,
    /// A bundle.
    Bundle,
    /// A pack.
    Pack,
    /// A per-pack index or merged index shard.
    Index,
    /// A filter.
    Filter,
    /// A derived attribute record.
    Attribute,
    /// A policy object.
    Policy,
    /// A recipe memo.
    Memo,
}

/// One registered kind and its ASCII identity domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainRegistration {
    kind: IdentityKind,
    name: &'static str,
}

impl DomainRegistration {
    /// Declares a domain for a versioned identity profile.
    #[must_use]
    pub const fn new(kind: IdentityKind, name: &'static str) -> Self {
        Self { kind, name }
    }

    /// Returns the immutable kind.
    #[must_use]
    pub const fn kind(&self) -> IdentityKind {
        self.kind
    }

    /// Returns the domain string.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }
}

const V1_DOMAINS: [DomainRegistration; 11] = [
    DomainRegistration::new(IdentityKind::Chunk, "terrane-chunk-v1"),
    DomainRegistration::new(IdentityKind::Manifest, "terrane-manifest-v1"),
    DomainRegistration::new(IdentityKind::Node, "terrane-node-v1"),
    DomainRegistration::new(IdentityKind::Commit, "terrane-commit-v1"),
    DomainRegistration::new(IdentityKind::Bundle, "terrane-bundle-v1"),
    DomainRegistration::new(IdentityKind::Pack, "terrane-pack-v1"),
    DomainRegistration::new(IdentityKind::Index, "terrane-index-v1"),
    DomainRegistration::new(IdentityKind::Filter, "terrane-filter-v1"),
    DomainRegistration::new(IdentityKind::Attribute, "terrane-attr-v1"),
    DomainRegistration::new(IdentityKind::Policy, "terrane-policy-v1"),
    DomainRegistration::new(IdentityKind::Memo, "terrane-memo-v1"),
];

/// A digest algorithm whose identifier and output length are profile data.
///
/// An implementation is selected by a configured profile, never by an
/// untrusted descriptor. This trait is the registration hook for a second
/// digest algorithm; an algorithm cannot replace the one in TERRANE_V1.
pub trait IdentityHasher: Sync {
    /// Returns the wire algorithm identifier.
    fn identifier(&self) -> &'static str;

    /// Returns the number of digest bytes.
    fn output_len(&self) -> usize;

    /// Hashes a complete domain-separated preimage.
    fn digest(&self, preimage: &[u8]) -> Vec<u8>;
}

/// BLAKE3-256 for the initial identity profile.
pub struct Blake3Hasher;

impl IdentityHasher for Blake3Hasher {
    fn identifier(&self) -> &'static str {
        "blake3"
    }

    fn output_len(&self) -> usize {
        32
    }

    fn digest(&self, preimage: &[u8]) -> Vec<u8> {
        blake3::hash(preimage).as_bytes().to_vec()
    }
}

/// The initial digest implementation.
pub static BLAKE3: Blake3Hasher = Blake3Hasher;

/// The immutable initial identity profile.
pub static TERRANE_V1: IdentityProfile = IdentityProfile {
    name: "terrane-v1",
    hasher: &BLAKE3,
    domains: &V1_DOMAINS,
};

/// A store's digest algorithm, output length, and complete domain set.
pub struct IdentityProfile {
    name: &'static str,
    hasher: &'static dyn IdentityHasher,
    domains: &'static [DomainRegistration],
}

impl IdentityProfile {
    /// Registers a future profile after its domains enter the specification registry.
    ///
    /// The table must cover each immutable kind exactly once. Domain names
    /// cannot reuse any initial-profile name; separate stores bridge profiles
    /// by import rather than rewriting identities in place.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidProfile`] for invalid algorithm,
    /// profile, or domain declarations.
    pub fn register(
        name: &'static str,
        hasher: &'static dyn IdentityHasher,
        domains: &'static [DomainRegistration],
    ) -> Result<Self, IdentityError> {
        if name.is_empty() || name == TERRANE_V1.name || !name.is_ascii() {
            return Err(IdentityError::InvalidProfile);
        }

        let algorithm = hasher.identifier();
        if algorithm.is_empty()
            || !algorithm.is_ascii()
            || hasher.output_len() == 0
            || domains.len() != V1_DOMAINS.len()
        {
            return Err(IdentityError::InvalidProfile);
        }

        for required in V1_DOMAINS {
            if domains
                .iter()
                .filter(|item| item.kind == required.kind)
                .count()
                != 1
            {
                return Err(IdentityError::InvalidProfile);
            }
        }

        for (index, item) in domains.iter().enumerate() {
            if item.name.is_empty()
                || !item.name.is_ascii()
                || item.name.as_bytes().contains(&0)
                || V1_DOMAINS.iter().any(|existing| existing.name == item.name)
                || domains[index + 1..]
                    .iter()
                    .any(|other| other.name == item.name)
            {
                return Err(IdentityError::InvalidProfile);
            }
        }

        Ok(Self {
            name,
            hasher,
            domains,
        })
    }

    /// Returns the store profile name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the profile's wire algorithm identifier.
    #[must_use]
    pub fn algorithm(&self) -> &'static str {
        self.hasher.identifier()
    }

    /// Returns the digest output length.
    #[must_use]
    pub fn digest_len(&self) -> usize {
        self.hasher.output_len()
    }

    /// Returns the registered domain table.
    #[must_use]
    pub const fn domains(&self) -> &'static [DomainRegistration] {
        self.domains
    }

    /// Returns the registered domain for a kind.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::UnknownDomain`] if the kind is not registered.
    pub fn domain(&self, kind: IdentityKind) -> Result<&'static str, IdentityError> {
        self.domains
            .iter()
            .find(|item| item.kind == kind)
            .map(|item| item.name)
            .ok_or(IdentityError::UnknownDomain)
    }

    /// Resolves a registered domain to its immutable kind.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::UnknownDomain`] for an unregistered string.
    pub fn kind(&self, domain: &str) -> Result<IdentityKind, IdentityError> {
        self.domains
            .iter()
            .find(|item| item.name == domain)
            .map(|item| item.kind)
            .ok_or(IdentityError::UnknownDomain)
    }

    /// Computes an identity from plaintext chunk or canonical immutable bytes.
    ///
    /// Callers pass plaintext for chunks and the canonical encoding for every
    /// other kind. Compression belongs to the storage layer. The preimage is
    /// exactly domain ASCII, one zero byte, and these bytes.
    ///
    /// # Errors
    ///
    /// Returns an unknown-domain error or a digest-length error if the
    /// registered hasher violates its declared output length.
    pub fn calculate(&self, kind: IdentityKind, bytes: &[u8]) -> Result<Identity, IdentityError> {
        let domain = self.domain(kind)?;
        let mut preimage = Vec::with_capacity(domain.len() + 1 + bytes.len());
        preimage.extend_from_slice(domain.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(bytes);

        let digest = self.hasher.digest(&preimage);
        if digest.len() != self.hasher.output_len() {
            return Err(IdentityError::InvalidDigestLength);
        }

        Ok(Identity {
            profile: self.name,
            kind,
            digest,
        })
    }

    /// Verifies bytes before they are used or admitted to a cache.
    ///
    /// # Errors
    ///
    /// Returns a profile error for an identity from another store, a digest
    /// error for changed bytes, or an error from [`Self::calculate`].
    pub fn verify(&self, identity: &Identity, bytes: &[u8]) -> Result<(), IdentityError> {
        if identity.profile != self.name {
            return Err(IdentityError::ProfileMismatch);
        }
        if self.calculate(identity.kind, bytes)?.digest != identity.digest {
            return Err(IdentityError::DigestMismatch);
        }
        Ok(())
    }
}

/// A digest bound to its immutable kind and identity profile.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Identity {
    profile: &'static str,
    kind: IdentityKind,
    digest: Vec<u8>,
}

impl Identity {
    /// Returns the name of the profile that created this identity.
    #[must_use]
    pub const fn profile(&self) -> &'static str {
        self.profile
    }

    /// Returns the immutable kind.
    #[must_use]
    pub const fn kind(&self) -> IdentityKind {
        self.kind
    }

    /// Borrows the digest bytes.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Returns a fixed-width digest for the initial on-disk profile.
    ///
    /// # Errors
    ///
    /// Returns a profile or digest-length error if conversion is unsafe.
    pub fn terrane_v1_digest(&self) -> Result<Digest, IdentityError> {
        if self.profile != TERRANE_V1.name {
            return Err(IdentityError::ProfileMismatch);
        }
        self.digest
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::InvalidDigestLength)
    }
}

/// A portable identity descriptor carried outside a store.
///
/// Its wire encoding is the CDDL array of algorithm, domain, digest, and
/// encoded immutable size. Size is validated but is not part of identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptor {
    algorithm: String,
    domain: String,
    digest: Vec<u8>,
    size: u64,
}

impl Descriptor {
    /// Builds a descriptor for previously identified immutable bytes.
    ///
    /// # Errors
    ///
    /// Returns an identity or size error if the bytes and identity disagree.
    pub fn from_identity(
        profile: &IdentityProfile,
        identity: &Identity,
        bytes: &[u8],
    ) -> Result<Self, IdentityError> {
        profile.verify(identity, bytes)?;
        Ok(Self {
            algorithm: profile.algorithm().to_string(),
            domain: profile.domain(identity.kind)?.to_string(),
            digest: identity.digest.clone(),
            size: u64::try_from(bytes.len()).map_err(|_| IdentityError::InvalidSize)?,
        })
    }

    /// Validates four decoded wire fields under the configured store profile.
    ///
    /// Unknown algorithms and domains are rejected, even when digest bytes
    /// happen to match. [`Self::verify_bytes`] additionally checks size and
    /// digest against the immutable before admission.
    ///
    /// # Errors
    ///
    /// Returns an algorithm, domain, or digest-length error for bad fields.
    pub fn from_wire(
        profile: &IdentityProfile,
        algorithm: &str,
        domain: &str,
        digest: &[u8],
        size: u64,
    ) -> Result<Self, IdentityError> {
        if algorithm != profile.algorithm() {
            return Err(IdentityError::UnknownAlgorithm);
        }
        profile.kind(domain)?;
        if digest.len() != profile.digest_len() {
            return Err(IdentityError::InvalidDigestLength);
        }
        Ok(Self {
            algorithm: algorithm.to_string(),
            domain: domain.to_string(),
            digest: digest.to_vec(),
            size,
        })
    }

    /// Returns the digest algorithm identifier.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Returns the registered domain string.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Borrows the digest bytes.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Returns the encoded immutable size in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Verifies descriptor fields and bytes before cache admission.
    ///
    /// # Errors
    ///
    /// Returns an algorithm, domain, size, or digest error on disagreement.
    pub fn verify_bytes(
        &self,
        profile: &IdentityProfile,
        expected_kind: IdentityKind,
        bytes: &[u8],
    ) -> Result<Identity, IdentityError> {
        if self.algorithm != profile.algorithm() {
            return Err(IdentityError::UnknownAlgorithm);
        }
        if self.domain != profile.domain(expected_kind)? {
            return Err(IdentityError::WrongDomain);
        }
        if self.size != u64::try_from(bytes.len()).map_err(|_| IdentityError::InvalidSize)? {
            return Err(IdentityError::InvalidSize);
        }
        if self.digest.len() != profile.digest_len() {
            return Err(IdentityError::InvalidDigestLength);
        }

        let identity = profile.calculate(expected_kind, bytes)?;
        if self.digest != identity.digest {
            return Err(IdentityError::DigestMismatch);
        }
        Ok(identity)
    }
}

impl fmt::Display for Descriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}:", self.algorithm, self.domain)?;
        for byte in &self.digest {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A rejected identity, profile declaration, or portable descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// A profile registration is invalid or conflicts with the initial profile.
    InvalidProfile,
    /// A descriptor's algorithm is not configured for this store.
    UnknownAlgorithm,
    /// A kind or domain is not registered for this profile.
    UnknownDomain,
    /// A descriptor's domain names a different immutable kind.
    WrongDomain,
    /// An identity belongs to another store profile.
    ProfileMismatch,
    /// Digest bytes do not have the declared profile length.
    InvalidDigestLength,
    /// A descriptor's size differs from the immutable byte count.
    InvalidSize,
    /// Immutable bytes do not match their asserted digest.
    DigestMismatch,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProfile => "invalid identity profile registration",
            Self::UnknownAlgorithm => "descriptor algorithm is not configured",
            Self::UnknownDomain => "identity domain is not registered",
            Self::WrongDomain => "descriptor domain names a different immutable kind",
            Self::ProfileMismatch => "identity belongs to another store profile",
            Self::InvalidDigestLength => "digest length does not match its profile",
            Self::InvalidSize => "descriptor size does not match immutable bytes",
            Self::DigestMismatch => "immutable bytes do not match their identity",
        })
    }
}

impl core::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use core::fmt::Write;

    fn hex(bytes: &[u8]) -> String {
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(text, "{byte:02x}").expect("String writing succeeds");
        }
        text
    }

    #[test]
    fn chunk_identity_matches_both_golden_vectors() {
        let cases = [
            (
                b"".as_slice(),
                "b8c424f844a636a1baddbc5fbc1fe533739c7399de74eae490e9f6d50a120dc0",
            ),
            (
                b"hello, terrane\n".as_slice(),
                "9479e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba0",
            ),
        ];

        for (plaintext, expected) in cases {
            let identity = TERRANE_V1
                .calculate(IdentityKind::Chunk, plaintext)
                .expect("registered kind");
            assert_eq!(hex(identity.digest()), expected);
            TERRANE_V1.verify(&identity, plaintext).expect("same bytes");
        }
    }

    #[test]
    fn every_immutable_kind_has_a_distinct_registered_domain() {
        let mut digests = Vec::new();
        for registration in TERRANE_V1.domains() {
            let identity = TERRANE_V1
                .calculate(registration.kind(), b"same bytes")
                .expect("registered kind");
            assert!(!digests.contains(&identity.digest().to_vec()));
            assert_eq!(
                TERRANE_V1.kind(registration.name()),
                Ok(registration.kind())
            );
            digests.push(identity.digest().to_vec());
        }
        assert_eq!(
            TERRANE_V1.kind("terrane-unknown-v1"),
            Err(IdentityError::UnknownDomain)
        );
    }

    #[test]
    fn descriptor_rejects_mismatched_fields_and_bytes() {
        let bytes = b"hello, terrane\n";
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, bytes)
            .expect("registered kind");
        let descriptor =
            Descriptor::from_identity(&TERRANE_V1, &identity, bytes).expect("valid bytes");

        assert_eq!(descriptor.size(), 15);
        assert_eq!(
            descriptor.to_string(),
            format!("blake3:terrane-chunk-v1:{}", hex(identity.digest()))
        );
        assert_eq!(
            descriptor.verify_bytes(&TERRANE_V1, IdentityKind::Chunk, bytes),
            Ok(identity.clone())
        );
        assert_eq!(
            descriptor.verify_bytes(&TERRANE_V1, IdentityKind::Manifest, bytes),
            Err(IdentityError::WrongDomain)
        );
        assert_eq!(
            descriptor.verify_bytes(&TERRANE_V1, IdentityKind::Chunk, b"changed"),
            Err(IdentityError::InvalidSize)
        );
        assert_eq!(
            descriptor.verify_bytes(&TERRANE_V1, IdentityKind::Chunk, b"hello, terrane?"),
            Err(IdentityError::DigestMismatch)
        );

        assert_eq!(
            Descriptor::from_wire(
                &TERRANE_V1,
                "sha256",
                descriptor.domain(),
                descriptor.digest(),
                15
            ),
            Err(IdentityError::UnknownAlgorithm)
        );
        assert_eq!(
            Descriptor::from_wire(
                &TERRANE_V1,
                "blake3",
                "terrane-unknown-v1",
                descriptor.digest(),
                15
            ),
            Err(IdentityError::UnknownDomain)
        );
        assert_eq!(
            Descriptor::from_wire(&TERRANE_V1, "blake3", descriptor.domain(), &[0; 31], 15),
            Err(IdentityError::InvalidDigestLength)
        );
    }

    #[test]
    fn a_second_profile_cannot_reinterpret_initial_identities() {
        static FUTURE: [DomainRegistration; 11] = [
            DomainRegistration::new(IdentityKind::Chunk, "future-chunk-v2"),
            DomainRegistration::new(IdentityKind::Manifest, "future-manifest-v2"),
            DomainRegistration::new(IdentityKind::Node, "future-node-v2"),
            DomainRegistration::new(IdentityKind::Commit, "future-commit-v2"),
            DomainRegistration::new(IdentityKind::Bundle, "future-bundle-v2"),
            DomainRegistration::new(IdentityKind::Pack, "future-pack-v2"),
            DomainRegistration::new(IdentityKind::Index, "future-index-v2"),
            DomainRegistration::new(IdentityKind::Filter, "future-filter-v2"),
            DomainRegistration::new(IdentityKind::Attribute, "future-attr-v2"),
            DomainRegistration::new(IdentityKind::Policy, "future-policy-v2"),
            DomainRegistration::new(IdentityKind::Memo, "future-memo-v2"),
        ];

        let future =
            IdentityProfile::register("future-v2", &BLAKE3, &FUTURE).expect("distinct profile");
        let old = TERRANE_V1
            .calculate(IdentityKind::Chunk, b"content")
            .expect("registered kind");
        let new = future
            .calculate(IdentityKind::Chunk, b"content")
            .expect("registered kind");

        assert_ne!(old.digest(), new.digest());
        assert_eq!(
            future.verify(&old, b"content"),
            Err(IdentityError::ProfileMismatch)
        );
        assert_eq!(
            TERRANE_V1.verify(&new, b"content"),
            Err(IdentityError::ProfileMismatch)
        );
        assert_eq!(
            Descriptor::from_wire(
                &TERRANE_V1,
                future.algorithm(),
                future.domain(IdentityKind::Chunk).expect("registered kind"),
                new.digest(),
                7
            ),
            Err(IdentityError::UnknownDomain)
        );
    }
}
