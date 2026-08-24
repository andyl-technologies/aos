//! Deterministic delivery-route parsing, matching, and partition selection.
//!
//! Native AOS Hub and the Worker call this module before framework path
//! decoding. It owns the canonical request-path grammar, segment-boundary
//! longest-prefix matching, reserved control namespaces, machine capability
//! classification, and RFC-0012's versioned object partition keys.
//!
//! A canonical delivery path has one leading slash, no trailing slash except
//! for `/`, no empty or dot segments, and NFC-normalized Unicode. Percent
//! escapes may encode only non-ASCII UTF-8 bytes; encoded ASCII is rejected so
//! a slash, dot, percent sign, or other routing-significant byte has exactly one
//! representation.

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization as _;

const PARTITION_KEY_DOMAIN: &[u8] = b"aos-hub-surface-object-v1\0";
const SELECTOR_DOMAIN: &[u8] = b"aos-hub-hash-range-v1\0";

/// A canonical absolute path used by delivery-route matching.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteAdvertisementPath(String);

impl RouteAdvertisementPath {
    /// Parses the path portion of a raw HTTP request target.
    ///
    /// The query is excluded before validation. A fragment is invalid in an
    /// HTTP request target and is rejected rather than silently discarded.
    ///
    /// # Errors
    ///
    /// Returns [`RoutePathError`] when the target is not an absolute canonical
    /// path, contains an unsafe literal or escape, is not UTF-8 after one
    /// decoding pass, or contains empty/dot segments.
    pub fn parse_raw_target(raw_target: &str) -> Result<Self, RoutePathError> {
        if raw_target.contains('#') {
            return Err(RoutePathError::Fragment);
        }
        let raw_path = raw_target
            .split_once('?')
            .map_or(raw_target, |(path, _query)| path);
        Self::parse_path(raw_path)
    }

    /// Returns the canonical absolute path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the surface-relative portion after a matching route base.
    ///
    /// # Errors
    ///
    /// Returns [`RoutePathError::NotBelowBase`] when this request path does not
    /// equal the base and does not begin with it on a segment boundary.
    pub fn relative_to<'a>(
        &'a self,
        base: &RouteAdvertisementBasePath,
    ) -> Result<&'a str, RoutePathError> {
        if base.0 .0 == "/" {
            return Ok(self.0.strip_prefix('/').unwrap_or(&self.0));
        }
        if self.0 == base.0 .0 {
            return Ok("");
        }
        self.0
            .strip_prefix(&base.0 .0)
            .and_then(|suffix| suffix.strip_prefix('/'))
            .ok_or(RoutePathError::NotBelowBase)
    }

    fn parse_path(raw_path: &str) -> Result<Self, RoutePathError> {
        if !raw_path.starts_with('/') {
            return Err(RoutePathError::NotAbsolute);
        }
        if raw_path.len() > 1 && raw_path.ends_with('/') {
            return Err(RoutePathError::TrailingSlash);
        }

        let input = raw_path.as_bytes();
        let mut decoded = Vec::with_capacity(input.len());
        let mut index = 0;
        while index < input.len() {
            let byte = input[index];
            if byte == b'%' {
                if index + 2 >= input.len() {
                    return Err(RoutePathError::InvalidPercentEscape);
                }
                let high =
                    decode_hex(input[index + 1]).ok_or(RoutePathError::InvalidPercentEscape)?;
                let low =
                    decode_hex(input[index + 2]).ok_or(RoutePathError::InvalidPercentEscape)?;
                let escaped = (high << 4) | low;
                if escaped.is_ascii() {
                    return Err(RoutePathError::EncodedAscii(escaped));
                }
                decoded.push(escaped);
                index += 3;
                continue;
            }
            if byte == b'\\' || byte == 0 || byte.is_ascii_control() {
                return Err(RoutePathError::UnsafeLiteral(byte));
            }
            decoded.push(byte);
            index += 1;
        }

        let decoded = String::from_utf8(decoded).map_err(|_| RoutePathError::InvalidUtf8)?;
        let normalized: String = decoded.nfc().collect();
        if normalized == "/" {
            return Ok(Self(normalized));
        }
        for segment in normalized[1..].split('/') {
            if segment.is_empty() {
                return Err(RoutePathError::EmptySegment);
            }
            if segment == "." || segment == ".." {
                return Err(RoutePathError::DotSegment);
            }
        }
        Ok(Self(normalized))
    }
}

impl AsRef<str> for RouteAdvertisementPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// A canonical delivery-route base that cannot overlap Hub control paths.
///
/// This type is intentionally distinct from [`RouteAdvertisementPath`], so a
/// validated request path cannot be reused as configuration without the
/// additional reserved-namespace validation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteAdvertisementBasePath(RouteAdvertisementPath);

impl RouteAdvertisementBasePath {
    /// Parses a stored or operator-supplied route base path.
    ///
    /// # Errors
    ///
    /// Returns [`RoutePathError`] for queries, fragments, non-canonical path
    /// representations, or a base overlapping a Hub control namespace.
    pub fn parse(base_path: &str) -> Result<Self, RoutePathError> {
        if base_path.contains('?') {
            return Err(RoutePathError::QueryInBasePath);
        }
        if base_path.contains('#') {
            return Err(RoutePathError::Fragment);
        }
        let path = RouteAdvertisementPath::parse_path(base_path)?;
        if is_reserved_control_path(&path) {
            return Err(RoutePathError::ReservedControlNamespace);
        }
        Ok(Self(path))
    }

    /// Returns the canonical absolute base path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl AsRef<str> for RouteAdvertisementBasePath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// A canonical-path parsing or relationship failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RoutePathError {
    /// The path did not begin with `/`.
    #[error("delivery path must be absolute")]
    NotAbsolute,
    /// A route base included a query.
    #[error("route base path cannot contain a query")]
    QueryInBasePath,
    /// The request target included a fragment.
    #[error("HTTP request target cannot contain a fragment")]
    Fragment,
    /// A percent escape was truncated or non-hexadecimal.
    #[error("delivery path contains an invalid percent escape")]
    InvalidPercentEscape,
    /// An ASCII byte used a percent-encoded alias.
    #[error("delivery path percent-encodes ASCII byte 0x{0:02x}")]
    EncodedAscii(u8),
    /// A routing-unsafe byte occurred literally.
    #[error("delivery path contains unsafe literal byte 0x{0:02x}")]
    UnsafeLiteral(u8),
    /// One decoding pass did not yield valid UTF-8.
    #[error("delivery path is not valid UTF-8 after percent decoding")]
    InvalidUtf8,
    /// A non-root path had a trailing slash.
    #[error("delivery path has a trailing slash")]
    TrailingSlash,
    /// The path had `//` and therefore an empty interior segment.
    #[error("delivery path contains an empty segment")]
    EmptySegment,
    /// The path had a literal dot traversal segment.
    #[error("delivery path contains a dot segment")]
    DotSegment,
    /// A route base tried to claim a Hub control namespace.
    #[error("route base path overlaps a reserved Hub control namespace")]
    ReservedControlNamespace,
    /// The request did not lie below the selected route base.
    #[error("request path is not below the selected route base")]
    NotBelowBase,
}
/// One route candidate for deterministic longest-prefix selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCandidate<T> {
    /// The route's canonical base path.
    pub base_path: RouteAdvertisementBasePath,
    /// Caller-owned route identity or configuration.
    pub route: T,
}

/// One selected route and its surface-relative request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteMatch<'a, T> {
    /// The caller-owned matched route value.
    pub route: &'a T,
    /// The matched canonical base path.
    pub base_path: &'a RouteAdvertisementBasePath,
    /// The request path relative to the route base, without a leading slash.
    pub relative_path: &'a str,
}

/// A failure to select from an invalid route candidate set.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RouteMatchError {
    /// Two candidates claimed the same endpoint/base-path reservation.
    #[error("duplicate route base path '{base_path}'")]
    DuplicateBasePath {
        /// Duplicated canonical path.
        base_path: String,
    },
}

/// Selects the longest route base that matches on a segment boundary.
///
/// # Errors
///
/// Returns [`RouteMatchError::DuplicateBasePath`] and fails closed when the
/// candidate set violates the unique endpoint/base-path invariant.
pub fn longest_prefix_match<'a, T>(
    request_path: &'a RouteAdvertisementPath,
    candidates: &'a [RouteCandidate<T>],
) -> Result<Option<RouteMatch<'a, T>>, RouteMatchError> {
    let mut seen_bases = HashSet::with_capacity(candidates.len());
    for candidate in candidates {
        if !seen_bases.insert(candidate.base_path.as_str()) {
            return Err(RouteMatchError::DuplicateBasePath {
                base_path: candidate.base_path.as_str().to_string(),
            });
        }
    }

    let mut selected: Option<(&RouteCandidate<T>, &str)> = None;
    for candidate in candidates {
        let Ok(relative_path) = request_path.relative_to(&candidate.base_path) else {
            continue;
        };
        let replace = selected
            .map(|(current, _)| {
                candidate.base_path.as_str().len() > current.base_path.as_str().len()
            })
            .unwrap_or(true);
        if replace {
            selected = Some((candidate, relative_path));
        }
    }
    let Some((selected, relative_path)) = selected else {
        return Ok(None);
    };
    Ok(Some(RouteMatch {
        route: &selected.route,
        base_path: &selected.base_path,
        relative_path,
    }))
}

/// Reports whether a canonical path belongs to a reserved Hub namespace.
#[must_use]
pub fn is_reserved_control_path(path: &RouteAdvertisementPath) -> bool {
    let mut segments = path.0.trim_start_matches('/').split('/');
    let first = segments.next().unwrap_or("");
    first == "_assets"
        || first == "login"
        || first == "logout"
        || first.starts_with("aos.hub.v1.")
        || first == "-"
        || segments.any(|segment| segment == "-")
}

/// A logical surface whose request capability is being classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliverySurfaceKind {
    /// A package registry with Git, Nix-cache, and Web views.
    Registry,
    /// A standalone Nix binary cache with machine and Web views.
    BinaryCache,
}

/// A delivery capability selected from a surface-relative path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryCapability {
    /// Dumb-HTTP Git and registry release/channel machine data.
    Git,
    /// Nix binary-cache protocol data.
    NixCache,
    /// Human-facing browse/search content.
    Web,
}

/// Classifies a canonical surface-relative path into its route capability.
#[must_use]
pub fn classify_capability(
    surface: DeliverySurfaceKind,
    relative_path: &str,
) -> DeliveryCapability {
    if is_nix_cache_path(relative_path) {
        return DeliveryCapability::NixCache;
    }
    if surface == DeliverySurfaceKind::Registry && is_registry_git_path(relative_path) {
        return DeliveryCapability::Git;
    }
    DeliveryCapability::Web
}

fn is_nix_cache_path(path: &str) -> bool {
    path == "nix-cache-info"
        || path == "query-paths"
        || path
            .strip_suffix(".narinfo")
            .is_some_and(|store_hash| !store_hash.is_empty() && !store_hash.contains('/'))
        || path == "nar"
        || path.starts_with("nar/")
}

fn is_registry_git_path(path: &str) -> bool {
    path == "HEAD"
        || path == "info"
        || path.starts_with("info/")
        || path == "objects"
        || path.starts_with("objects/")
        || path == "releases"
        || path.starts_with("releases/")
        || path == "channels"
        || path.starts_with("channels/")
}

/// A digest-algorithm tag in RFC-0012 object identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DigestAlgorithm {
    /// MD5.
    Md5 = 0x00,
    /// SHA-1.
    Sha1 = 0x01,
    /// SHA-256.
    Sha256 = 0x02,
    /// SHA-512.
    Sha512 = 0x03,
}

impl DigestAlgorithm {
    fn digest_len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// A typed immutable logical-object identity used to derive a partition key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionObjectIdentity<'a> {
    /// A Git object in the repository's declared object format.
    GitObject {
        /// SHA-1 or SHA-256.
        algorithm: DigestAlgorithm,
        /// Raw object digest bytes.
        digest: &'a [u8],
    },
    /// A Git pack checksum in the repository's declared object format.
    GitPack {
        /// SHA-1 or SHA-256.
        algorithm: DigestAlgorithm,
        /// Raw pack checksum bytes.
        digest: &'a [u8],
    },
    /// A release artifact content hash.
    ReleaseArtifact {
        /// Content-hash algorithm.
        algorithm: DigestAlgorithm,
        /// Raw content digest bytes.
        digest: &'a [u8],
    },
    /// A Nix narinfo identified by its raw 20-byte store hash.
    Narinfo {
        /// Raw Nix store-hash bytes.
        store_hash: &'a [u8],
    },
    /// A NAR payload content hash.
    Nar {
        /// NAR content-hash algorithm.
        algorithm: DigestAlgorithm,
        /// Raw content digest bytes.
        digest: &'a [u8],
    },
}

/// An invalid typed object identity.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PartitionKeyError {
    /// The algorithm is not valid for a Git object or pack format.
    #[error("Git object and pack identities require SHA-1 or SHA-256")]
    UnsupportedGitAlgorithm,
    /// Digest bytes did not match the selected algorithm.
    #[error("{algorithm:?} digest has {actual} bytes; expected {expected}")]
    DigestLength {
        /// Selected digest algorithm.
        algorithm: DigestAlgorithm,
        /// Required byte length.
        expected: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// A Nix store hash was not exactly 20 bytes.
    #[error("Nix store hash has {actual} bytes; expected 20")]
    StoreHashLength {
        /// Supplied byte length.
        actual: usize,
    },
}

/// Derives RFC-0012's immutable 32-byte object partition key.
///
/// # Errors
///
/// Returns [`PartitionKeyError`] if an algorithm is invalid for the object kind
/// or the raw digest has the wrong byte length.
pub fn partition_key(identity: PartitionObjectIdentity<'_>) -> Result<[u8; 32], PartitionKeyError> {
    let (kind, canonical_key) = canonical_partition_identity(identity)?;
    // Closed identities are at most one algorithm byte plus 64 SHA-512 bytes,
    // so the version-one u32 length field is infallible.
    let key_length = canonical_key.len() as u32;
    let mut hasher = Sha256::new();
    hasher.update(PARTITION_KEY_DOMAIN);
    hasher.update([kind]);
    hasher.update(key_length.to_be_bytes());
    hasher.update(&canonical_key);
    Ok(hasher.finalize().into())
}

/// Derives the RFC-0012 hash-range selector digest and bucket.
#[must_use]
pub fn hash_range_v1(partition_key: &[u8; 32]) -> ([u8; 32], u16) {
    let mut hasher = Sha256::new();
    hasher.update(SELECTOR_DOMAIN);
    hasher.update(partition_key);
    let digest: [u8; 32] = hasher.finalize().into();
    let bucket = u16::from_be_bytes([digest[0], digest[1]]);
    (digest, bucket)
}

fn canonical_partition_identity(
    identity: PartitionObjectIdentity<'_>,
) -> Result<(u8, Vec<u8>), PartitionKeyError> {
    let (kind, algorithm, digest, git_only) = match identity {
        PartitionObjectIdentity::GitObject { algorithm, digest } => {
            (0x01, Some(algorithm), digest, true)
        }
        PartitionObjectIdentity::GitPack { algorithm, digest } => {
            (0x02, Some(algorithm), digest, true)
        }
        PartitionObjectIdentity::ReleaseArtifact { algorithm, digest } => {
            (0x03, Some(algorithm), digest, false)
        }
        PartitionObjectIdentity::Narinfo { store_hash } => {
            if store_hash.len() != 20 {
                return Err(PartitionKeyError::StoreHashLength {
                    actual: store_hash.len(),
                });
            }
            return Ok((0x11, store_hash.to_vec()));
        }
        PartitionObjectIdentity::Nar { algorithm, digest } => {
            (0x12, Some(algorithm), digest, false)
        }
    };
    let algorithm = algorithm.ok_or(PartitionKeyError::UnsupportedGitAlgorithm)?;
    if git_only && !matches!(algorithm, DigestAlgorithm::Sha1 | DigestAlgorithm::Sha256) {
        return Err(PartitionKeyError::UnsupportedGitAlgorithm);
    }
    let expected = algorithm.digest_len();
    if digest.len() != expected {
        return Err(PartitionKeyError::DigestLength {
            algorithm,
            expected,
            actual: digest.len(),
        });
    }
    let mut key = Vec::with_capacity(1 + digest.len());
    key.push(algorithm as u8);
    key.extend_from_slice(digest);
    Ok((kind, key))
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn path_parser_normalizes_unicode_and_ignores_query() {
        let composed = RouteAdvertisementPath::parse_raw_target("/caf%C3%A9/item?x=%2f").unwrap();
        let decomposed = RouteAdvertisementPath::parse_raw_target("/cafe\u{301}/item").unwrap();
        assert_eq!(composed, decomposed);
        assert_eq!(composed.as_str(), "/café/item");
    }

    #[test]
    fn path_parser_rejects_routing_aliases() {
        for path in [
            "relative",
            "/a/",
            "/a//b",
            "/a/./b",
            "/a/../b",
            "/a\\b",
            "/a%2fb",
            "/a%252fb",
            "/a%2eb",
            "/a%00b",
            "/a%zz",
            "/a#fragment",
        ] {
            assert!(
                RouteAdvertisementPath::parse_raw_target(path).is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn longest_prefix_requires_a_segment_boundary() {
        let candidates = vec![
            RouteCandidate {
                base_path: RouteAdvertisementBasePath::parse("/").unwrap(),
                route: "root",
            },
            RouteCandidate {
                base_path: RouteAdvertisementBasePath::parse("/cache").unwrap(),
                route: "cache",
            },
            RouteCandidate {
                base_path: RouteAdvertisementBasePath::parse("/cache/acme").unwrap(),
                route: "acme",
            },
        ];
        let path = RouteAdvertisementPath::parse_raw_target("/cache/acme/nar/x").unwrap();
        let selected = longest_prefix_match(&path, &candidates).unwrap().unwrap();
        assert_eq!(*selected.route, "acme");
        assert_eq!(selected.relative_path, "nar/x");

        let sibling = RouteAdvertisementPath::parse_raw_target("/cacheable").unwrap();
        let selected = longest_prefix_match(&sibling, &candidates)
            .unwrap()
            .unwrap();
        assert_eq!(*selected.route, "root");
    }

    #[test]
    fn duplicate_route_bases_fail_closed() {
        let candidates = vec![
            RouteCandidate {
                base_path: RouteAdvertisementBasePath::parse("/cache").unwrap(),
                route: 1,
            },
            RouteCandidate {
                base_path: RouteAdvertisementBasePath::parse("/cache").unwrap(),
                route: 2,
            },
        ];
        let path = RouteAdvertisementPath::parse_raw_target("/elsewhere").unwrap();
        assert_eq!(
            longest_prefix_match(&path, &candidates),
            Err(RouteMatchError::DuplicateBasePath {
                base_path: "/cache".to_string(),
            })
        );
    }

    #[test]
    fn reserved_namespaces_are_segment_exact() {
        for path in [
            "/-/settings",
            "/a/-/b",
            "/_assets/app.js",
            "/login",
            "/aos.hub.v1.RouteService/GetRoute",
        ] {
            let path = RouteAdvertisementPath::parse_raw_target(path).unwrap();
            assert!(is_reserved_control_path(&path));
        }
        for path in ["/-suffix", "/asset", "/logins", "/aos.hub.v10/foo"] {
            let path = RouteAdvertisementPath::parse_raw_target(path).unwrap();
            assert!(!is_reserved_control_path(&path));
        }
        for base in [
            "/-",
            "/-/settings",
            "/a/-/b",
            "/_assets",
            "/login",
            "/logout",
        ] {
            assert!(RouteAdvertisementBasePath::parse(base).is_err(), "{base}");
        }
    }

    #[test]
    fn capability_classification_is_surface_aware() {
        assert_eq!(
            classify_capability(DeliverySurfaceKind::Registry, "info/refs"),
            DeliveryCapability::Git
        );
        assert_eq!(
            classify_capability(DeliverySurfaceKind::Registry, "x.narinfo"),
            DeliveryCapability::NixCache
        );
        assert_eq!(
            classify_capability(DeliverySurfaceKind::BinaryCache, "HEAD"),
            DeliveryCapability::Web
        );
        assert_eq!(
            classify_capability(DeliverySurfaceKind::BinaryCache, "query-paths"),
            DeliveryCapability::NixCache
        );
        assert_eq!(
            classify_capability(DeliverySurfaceKind::BinaryCache, "nested/x.narinfo"),
            DeliveryCapability::Web
        );
    }

    #[test]
    fn selector_vectors_match_the_rfc() {
        for (key, expected_digest, expected_bucket) in [
            (
                [0_u8; 32],
                "c84df95b5544ccded87876f4a24fc63445f48af7dcddac6af26f2a7a7742abda",
                51_277,
            ),
            (
                std::array::from_fn(|index| index as u8),
                "5266775ea5f5297e717cfd66abe696828282822c7793ad0d5c5ab0b0fc5f0cbc",
                21_094,
            ),
            (
                [0xff_u8; 32],
                "5de6f7beb4067b866bc9835b476fd57f583f208dd247679ef8098bfd65aa4b01",
                24_038,
            ),
        ] {
            let (digest, bucket) = hash_range_v1(&key);
            assert_eq!(hex(&digest), expected_digest);
            assert_eq!(bucket, expected_bucket);
        }
    }

    #[test]
    fn partition_key_vectors_match_the_rfc() {
        let git = partition_key(PartitionObjectIdentity::GitObject {
            algorithm: DigestAlgorithm::Sha1,
            digest: &[0_u8; 20],
        })
        .unwrap();
        assert_eq!(
            hex(&git),
            "53966266be3ec6639ef217cb4e16996fc1e69833512df48ba9e091f7f1b147d8"
        );
        assert_eq!(hash_range_v1(&git).1, 52_736);

        let narinfo = partition_key(PartitionObjectIdentity::Narinfo {
            store_hash: &[0_u8; 20],
        })
        .unwrap();
        assert_eq!(
            hex(&narinfo),
            "9cda12e164949c4166f051e41f7103f66fa097c380c333263b73a0bc2f58f939"
        );
        assert_eq!(hash_range_v1(&narinfo).1, 22_494);

        let digest: [u8; 32] = std::array::from_fn(|index| index as u8);
        let nar = partition_key(PartitionObjectIdentity::Nar {
            algorithm: DigestAlgorithm::Sha256,
            digest: &digest,
        })
        .unwrap();
        assert_eq!(
            hex(&nar),
            "0a5e8e4a54ac17e4130754a6b3d2c2328994bba50864aed8b53e670aaf1f6529"
        );
        assert_eq!(hash_range_v1(&nar).1, 20_101);
    }

    #[test]
    fn partition_identities_enforce_algorithm_and_digest_shape() {
        assert_eq!(
            partition_key(PartitionObjectIdentity::GitObject {
                algorithm: DigestAlgorithm::Sha512,
                digest: &[0_u8; 64],
            }),
            Err(PartitionKeyError::UnsupportedGitAlgorithm)
        );
        assert_eq!(
            partition_key(PartitionObjectIdentity::GitPack {
                algorithm: DigestAlgorithm::Sha256,
                digest: &[0_u8; 20],
            }),
            Err(PartitionKeyError::DigestLength {
                algorithm: DigestAlgorithm::Sha256,
                expected: 32,
                actual: 20,
            })
        );
        assert_eq!(
            partition_key(PartitionObjectIdentity::Narinfo {
                store_hash: &[0_u8; 19],
            }),
            Err(PartitionKeyError::StoreHashLength { actual: 19 })
        );
    }
}
