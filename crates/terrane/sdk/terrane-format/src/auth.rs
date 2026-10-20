//! Verifies and attenuates Terrane v1 Ed25519 capabilities without I/O.
//!
//! AUTH-7 through AUTH-22 are implemented using the canonical CBOR codec,
//! caller-supplied issuer keys and time, closed caveats, and byte globs.
//! Token possession includes the private half of the final next-key; private
//! keys are never encoded in the bearer token. Request context is supplied by
//! the trusted guard and must cover every root and writer epoch touched.
//!
//! ```text
//! token = [ authority-block, * attenuation-block ]
//! authority signature = Ed25519(canonical authority map without key 12)
//! attenuation signature = Ed25519(previous signature || map without key 6)
//! ```

mod format;
mod pattern;
#[cfg(test)]
mod tests;

use alloc::{string::String, vec::Vec};
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Derives the Ed25519 public key for a caller-supplied private seed.
///
/// This pure operation performs no entropy or key storage I/O. The caller
/// supplies and retains the secret through its host binding.
#[must_use]
pub fn public_key_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret).verifying_key().to_bytes()
}

/// Denies authentication or authorization without revealing its cause (AUTH-12).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unauthorized;

impl fmt::Display for Unauthorized {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unauthorized")
    }
}

impl core::error::Error for Unauthorized {}

/// Reports a rejection cause exclusively to trusted diagnostic consumers.
///
/// This information must never reach a remote caller; guard-facing protocol
/// responses expose only [`Unauthorized`] (AUTH-12). Diagnosis performs no I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Diagnostic {
    /// The canonical encoding, schema, or field vocabulary is invalid.
    Encoding,
    /// No active configured key matches the issuer and key identifier.
    Issuer,
    /// An Ed25519 signature or delegated public key is invalid.
    Signature,
    /// The validity interval excludes the supplied current time.
    Time,
    /// A block widens its parent authority.
    Widening,
    /// Exact language containment exceeded the local 16,384-state proof budget.
    ResourceLimit,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Encoding => "invalid token encoding",
            Self::Issuer => "unknown or retired issuer key",
            Self::Signature => "invalid token signature chain",
            Self::Time => "token outside validity interval",
            Self::Widening => "attenuation widens authority",
            Self::ResourceLimit => "attenuation containment proof budget exceeded",
        })
    }
}

impl core::error::Error for Diagnostic {}

/// Reuses the shared principal and locality models (CRATE-20).
pub use crate::refs::{Locality, PrincipalKind};

/// Names one registered authorization operation (AUTH-19/22).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verb {
    /// Reads reachable content and metadata.
    Read = 1,
    /// Forks the source ref.
    Fork = 2,
    /// Advances the matched ref.
    Commit = 4,
    /// Creates a tag of reachable content.
    Tag = 8,
    /// Changes authority-bearing policy and forces or deletes refs.
    Admin = 16,
}

/// Holds a nonempty registered verb mask with AUTH-22 implications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Verbs(u8);

impl Verbs {
    /// Validates a v1 wire bitmask.
    ///
    /// # Errors
    /// Returns [`Unauthorized`] for empty or unregistered bits.
    pub fn new(mask: u8) -> Result<Self, Unauthorized> {
        if mask == 0 || mask & !31 != 0 {
            return Err(Unauthorized);
        }
        Ok(Self(mask))
    }

    /// Returns the original wire mask without adding implied verbs.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Tests membership after applying AUTH-22 verb implications.
    pub fn contains(self, verb: Verb) -> bool {
        self.effective() & verb as u8 != 0
    }

    fn effective(self) -> u8 {
        if self.0 & 16 != 0 {
            31
        } else if self.0 & 14 != 0 {
            self.0 | 1
        } else {
            self.0
        }
    }
}

/// Grants a validated ref or ref-qualified root pattern a verb set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    pattern: String,
    verbs: Verbs,
}

/// Matches subject names with the capability language's byte glob semantics.
///
/// `*` matches bytes within one slash-separated component; `**` crosses
/// components. Other bytes are literal, with no Unicode normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectPattern(String);

impl SubjectPattern {
    /// Stores a subject pattern without imposing ref-name restrictions.
    pub fn new(pattern: String) -> Self {
        Self(pattern)
    }

    /// Tests a subject against the stored byte pattern.
    pub fn matches(&self, subject: &str) -> bool {
        pattern::matches(&self.0, subject.as_bytes())
    }
}

impl Grant {
    /// Validates a canonical grant glob (AUTH-19/20).
    ///
    /// Only `*` and `**` are operators; other bytes are literal. No Unicode
    /// normalization or percent decoding is performed.
    ///
    /// # Errors
    /// Returns [`Unauthorized`] for a malformed pattern.
    pub fn new(pattern: String, verbs: Verbs) -> Result<Self, Unauthorized> {
        if !pattern::valid_grant(&pattern) {
            return Err(Unauthorized);
        }
        Ok(Self { pattern, verbs })
    }

    /// Returns the canonical pattern.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Returns the declared verbs.
    pub const fn verbs(&self) -> Verbs {
        self.verbs
    }
}

/// Names one closed v1 context predicate (AUTH-17/18).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Caveat {
    /// Requires request time strictly before this timestamp.
    Before(u64),
    /// Requires request time strictly after this timestamp.
    After(u64),
    /// Matches the request ref's canonical bytes.
    Ref(String),
    /// Matches every touched root's canonical path bytes.
    Root(String),
    /// Restricts the operation using the registered verb mask.
    Verb(Verbs),
    /// Requires this effective domain on every touched root.
    Domain(String),
    /// Requires this surface name.
    Surface(String),
    /// Requires every specified locality field.
    Locality(Locality),
    /// Requires the named ref's current epoch to be at most this bound.
    Epoch(String, u64),
}

/// Supplies the authority block's signed subject and initial grants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authority {
    /// Configured issuer identifier.
    pub issuer: String,
    /// Configured issuer key identifier.
    pub key_id: String,
    /// Subject principal name.
    pub subject: String,
    /// Authentication class of the subject.
    pub kind: PrincipalKind,
    /// Issuer-provided group claims.
    pub groups: Vec<String>,
    /// Inclusive not-after timestamp in Unix seconds.
    pub not_after: u64,
    /// Optional inclusive not-before timestamp.
    pub not_before: Option<u64>,
    /// Issuer-generated token identifier.
    pub token_id: [u8; 16],
    /// Initial nonempty grant union.
    pub grants: Vec<Grant>,
    /// Optional workload identity claim.
    pub workload: Option<String>,
}

/// Supplies restrictions to append without contacting an issuer (AUTH-14/16).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Attenuation {
    /// Replaces the expiry with the same or an earlier timestamp.
    pub not_after: Option<u64>,
    /// Adds or advances the earliest valid timestamp.
    pub not_before: Option<u64>,
    /// Replaces grants with a nonempty union contained in the parent union.
    pub grants: Option<Vec<Grant>>,
    /// Adds conjunctive predicates; existing caveats cannot be removed.
    pub caveats: Vec<Caveat>,
}

/// Configures one per-store issuer public key and its retirement (AUTH-13).
#[derive(Clone, Debug)]
pub struct IssuerKey {
    /// Issuer identifier.
    pub issuer: String,
    /// Issuer's rotation key identifier.
    pub key_id: String,
    /// Ed25519 public key bytes.
    pub public_key: [u8; 32],
    /// Time at which the key ceases to be accepted, if configured.
    pub retirement: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Signed<T> {
    body: T,
    next_key: [u8; 32],
    signature: [u8; 64],
}

/// Holds a structurally validated canonical v1 token chain.
///
/// Decoding alone does not authenticate a token. Call [`Token::verify`] before
/// authorization. The wire version supports Ed25519 only (AUTH-9/10).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    authority: Signed<Authority>,
    blocks: Vec<Signed<Attenuation>>,
}

impl Token {
    /// Returns the terminal public key used to sign commits with this token.
    ///
    /// This accessor does not authenticate the chain. Call [`Self::verify`]
    /// before trusting the key or any claims carried by the token.
    pub fn signing_public_key(&self) -> [u8; 32] {
        self.blocks
            .last()
            .map_or(self.authority.next_key, |block| block.next_key)
    }

    /// Parses a canonical token without authenticating its signatures.
    ///
    /// # Errors
    /// Returns [`Unauthorized`] for malformed/noncanonical data, unregistered
    /// fields or caveats, invalid grants, limits, or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Unauthorized> {
        format::decode(bytes).map_err(|_| Unauthorized)
    }

    /// Encodes the validated chain using the v1 canonical CBOR profile.
    pub fn encode(&self) -> Vec<u8> {
        format::encode(self)
    }

    /// Signs an authority block using the caller's issuer and delegation keys.
    ///
    /// # Errors
    /// Returns [`Unauthorized`] for invalid authority fields or limits.
    pub fn issue(
        authority: Authority,
        issuer_secret: &[u8; 32],
        next_key: [u8; 32],
    ) -> Result<Self, Unauthorized> {
        let mut token = Self {
            authority: Signed {
                body: authority,
                next_key,
                signature: [0; 64],
            },
            blocks: Vec::new(),
        };
        // Decode the generated wire object to share schema validation with readers.
        token = Self::decode(&token.encode())?;
        token.authority.signature = SigningKey::from_bytes(issuer_secret)
            .sign(&format::authority_preimage(&token.authority))
            .to_bytes();
        Ok(token)
    }

    /// Appends a signed, monotone restriction using the final delegation key.
    ///
    /// This operation is entirely offline. The caller must authenticate the
    /// parent separately before trusting it. Possession of an issuer key is
    /// unnecessary; only the final delegation private key is used (AUTH-16).
    ///
    /// # Errors
    /// Returns [`Unauthorized`] for the wrong delegation key, schema/size
    /// violations, or restrictions that widen the parent authority.
    pub fn attenuate(
        &self,
        restriction: Attenuation,
        delegation_secret: &[u8; 32],
        next_key: [u8; 32],
    ) -> Result<Self, Unauthorized> {
        let previous = self
            .blocks
            .last()
            .map_or(&self.authority.next_key, |block| &block.next_key);
        let signing_key = SigningKey::from_bytes(delegation_secret);
        if signing_key.verifying_key().to_bytes() != *previous {
            return Err(Unauthorized);
        }
        let mut token = self.clone();
        let signature = token
            .blocks
            .last()
            .map_or(token.authority.signature, |block| block.signature);
        let mut block = Signed {
            body: restriction,
            next_key,
            signature: [0; 64],
        };
        let mut preimage = signature.to_vec();
        preimage.extend(format::attenuation_preimage(&block));
        block.signature = signing_key.sign(&preimage).to_bytes();
        token.blocks.push(block);

        let token = Self::decode(&token.encode())?;
        token.effective().map_err(|_| Unauthorized)?;
        Ok(token)
    }

    /// Authenticates signatures, issuer configuration, time, and attenuation.
    ///
    /// # Errors
    /// Returns only [`Unauthorized`] for every rejection cause (AUTH-12).
    pub fn verify(&self, keys: &[IssuerKey], now: u64) -> Result<VerifiedToken, Unauthorized> {
        self.verify_diagnostic(keys, now).map_err(|_| Unauthorized)
    }

    /// Authenticates a chain and reports a cause to trusted logging consumers.
    ///
    /// # Errors
    /// Returns a privileged [`Diagnostic`] for invalid issuer keys, signatures,
    /// time bounds, or widening. Never expose this result to an untrusted caller.
    pub fn verify_diagnostic(
        &self,
        keys: &[IssuerKey],
        now: u64,
    ) -> Result<VerifiedToken, Diagnostic> {
        let authority = &self.authority.body;
        let keys: Vec<_> = keys
            .iter()
            .filter(|key| {
                key.issuer == authority.issuer
                    && key.key_id == authority.key_id
                    && key.retirement.is_none_or(|retirement| now < retirement)
            })
            .collect();
        if keys.len() != 1 {
            return Err(Diagnostic::Issuer);
        }
        let mut key =
            VerifyingKey::from_bytes(&keys[0].public_key).map_err(|_| Diagnostic::Signature)?;
        key.verify_strict(
            &format::authority_preimage(&self.authority),
            &Signature::from_bytes(&self.authority.signature),
        )
        .map_err(|_| Diagnostic::Signature)?;
        let mut previous_signature = self.authority.signature;
        let mut previous_key = self.authority.next_key;
        for block in &self.blocks {
            key = VerifyingKey::from_bytes(&previous_key).map_err(|_| Diagnostic::Signature)?;
            let mut preimage = previous_signature.to_vec();
            preimage.extend(format::attenuation_preimage(block));
            key.verify_strict(&preimage, &Signature::from_bytes(&block.signature))
                .map_err(|_| Diagnostic::Signature)?;
            previous_key = block.next_key;
            previous_signature = block.signature;
        }
        // Even an unused terminal key must be a real, non-weak Ed25519 key.
        if VerifyingKey::from_bytes(&previous_key)
            .map_err(|_| Diagnostic::Signature)?
            .is_weak()
        {
            return Err(Diagnostic::Signature);
        }

        let mut effective = self.effective()?;
        if let Some(retirement) = keys[0].retirement {
            // A verified value cannot be reused beyond the configured key lifetime.
            effective.not_after = effective.not_after.min(retirement.saturating_sub(1));
        }
        let (not_before, not_after) = effective.validity().ok_or(Diagnostic::Time)?;
        effective.not_before = not_before;
        effective.not_after = not_after;
        if now > not_after || now < not_before {
            return Err(Diagnostic::Time);
        }
        Ok(VerifiedToken {
            authority: authority.clone(),
            effective,
        })
    }

    fn effective(&self) -> Result<Effective, Diagnostic> {
        let mut effective = Effective {
            grants: self.authority.body.grants.clone(),
            not_after: self.authority.body.not_after,
            not_before: self.authority.body.not_before.unwrap_or(0),
            caveats: Vec::new(),
        };
        for block in &self.blocks {
            if let Some(expiry) = block.body.not_after {
                if expiry > effective.not_after {
                    return Err(Diagnostic::Widening);
                }
                effective.not_after = expiry;
            }
            if let Some(start) = block.body.not_before {
                if start < effective.not_before {
                    return Err(Diagnostic::Widening);
                }
                effective.not_before = start;
            }
            if let Some(grants) = &block.body.grants {
                for grant in grants {
                    for verb in [1, 2, 4, 8, 16] {
                        if grant.verbs.effective() & verb != 0
                            && !pattern::contained(grant, &effective.grants, verb)
                                .map_err(|_| Diagnostic::ResourceLimit)?
                        {
                            return Err(Diagnostic::Widening);
                        }
                    }
                }
                effective.grants = grants.clone();
            }
            effective.caveats.extend(block.body.caveats.iter().cloned());
        }
        Ok(effective)
    }
}

/// Parses and authenticates token bytes through a uniform rejection interface.
///
/// # Errors
/// Returns [`Unauthorized`] for every parsing, signature, policy, or time error.
pub fn verify(bytes: &[u8], keys: &[IssuerKey], now: u64) -> Result<VerifiedToken, Unauthorized> {
    Token::decode(bytes)?.verify(keys, now)
}

/// Parses and authenticates token bytes for trusted diagnostic consumers.
///
/// # Errors
/// Returns a privileged [`Diagnostic`]; callers must keep it out of public
/// responses and use [`verify`] at an untrusted boundary (AUTH-12).
pub fn verify_diagnostic(
    bytes: &[u8],
    keys: &[IssuerKey],
    now: u64,
) -> Result<VerifiedToken, Diagnostic> {
    format::decode(bytes)
        .map_err(|_| Diagnostic::Encoding)?
        .verify_diagnostic(keys, now)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Effective {
    grants: Vec<Grant>,
    not_after: u64,
    not_before: u64,
    caveats: Vec<Caveat>,
}

impl Effective {
    /// Intersects inclusive block bounds with strict time predicates.
    fn validity(&self) -> Option<(u64, u64)> {
        let mut earliest = self.not_before;
        let mut latest = self.not_after;
        for caveat in &self.caveats {
            match caveat {
                Caveat::Before(time) => latest = latest.min(time.checked_sub(1)?),
                Caveat::After(time) => earliest = earliest.max(time.checked_add(1)?),
                _ => {}
            }
        }
        (earliest <= latest).then_some((earliest, latest))
    }
}

/// Holds a cryptographically authenticated subject and effective restrictions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedToken {
    authority: Authority,
    effective: Effective,
}

/// Describes one touched root using canonical bytes and trusted domain policy.
#[derive(Clone, Copy, Debug)]
pub struct RequestRoot<'a> {
    /// Canonical absolute root path within the request ref.
    pub path: &'a [u8],
    /// Current effective disclosure domain.
    pub domain: &'a str,
}

/// Supplies all trusted context needed to authorize one operation.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// Canonical ref name bytes.
    pub reference: &'a [u8],
    /// Operation being authorized.
    pub verb: Verb,
    /// Every root touched; an empty list denotes a ref-only operation.
    pub roots: &'a [RequestRoot<'a>],
    /// Current request timestamp, checked again against token validity.
    pub now: u64,
    /// Surface through which the operation arrived.
    pub surface: &'a str,
    /// Serving store's trusted locality label.
    pub locality: &'a Locality,
    /// Current epochs of every ref named by an epoch caveat.
    pub epochs: &'a [(&'a str, u64)],
}

impl VerifiedToken {
    /// Returns the authenticated issuer-provided subject and claims.
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// Returns the effective inclusive authorization expiry.
    ///
    /// This bound intersects every block's not-after time, configured issuer
    /// retirement, and every strict `before` caveat (timestamp minus one).
    /// Verification rejects an empty validity interval, including `before(0)`
    /// and `after(u64::MAX)`, so callers can safely bound delegated read
    /// lifetimes without inspecting private caveats (AUTH-14/17).
    pub const fn not_after(&self) -> u64 {
        self.effective.not_after
    }

    /// Authorizes every touched root against grants and every added caveat.
    ///
    /// The repository guard must additionally intersect the current ACL; this
    /// pure primitive implements token authority only (AUTH-21, AUTH-26).
    ///
    /// # Errors
    /// Returns [`Unauthorized`] for noncanonical context, expiry, missing
    /// grants, mismatched caveats, or missing/ambiguous epoch context.
    pub fn authorize(&self, request: &Request<'_>) -> Result<(), Unauthorized> {
        if !pattern::canonical_reference(request.reference)
            || request.now > self.effective.not_after
            || request.now < self.effective.not_before
            || request
                .roots
                .iter()
                .any(|root| !pattern::canonical_root(root.path))
        {
            return Err(Unauthorized);
        }
        let grants = &self.effective.grants;
        let permits = |root| {
            grants.iter().any(|grant| {
                grant.verbs.contains(request.verb)
                    && pattern::grant_matches(&grant.pattern, request.reference, root)
            })
        };
        if (request.roots.is_empty()
            && !grants.iter().any(|grant| {
                !grant.pattern.contains(':')
                    && grant.verbs.contains(request.verb)
                    && pattern::matches(&grant.pattern, request.reference)
            }))
            || request.roots.iter().any(|root| !permits(root.path))
        {
            return Err(Unauthorized);
        }
        for caveat in &self.effective.caveats {
            let satisfied = match caveat {
                Caveat::Before(time) => request.now < *time,
                Caveat::After(time) => request.now > *time,
                Caveat::Ref(pattern) => pattern::matches(pattern, request.reference),
                Caveat::Root(pattern) => {
                    !request.roots.is_empty()
                        && request
                            .roots
                            .iter()
                            .all(|root| pattern::matches(pattern, root.path))
                }
                Caveat::Verb(verbs) => verbs.bits() & request.verb as u8 != 0,
                Caveat::Domain(domain) => {
                    !request.roots.is_empty()
                        && request.roots.iter().all(|root| root.domain == domain)
                }
                Caveat::Surface(surface) => request.surface == surface,
                Caveat::Locality(label) => locality_matches(label, request.locality),
                Caveat::Epoch(reference, epoch) => {
                    let mut values = request.epochs.iter().filter(|(name, _)| name == reference);
                    let first = values.next();
                    first.is_some_and(|(_, actual)| actual <= epoch) && values.next().is_none()
                }
            };
            if !satisfied {
                return Err(Unauthorized);
            }
        }
        Ok(())
    }
}

fn locality_matches(expected: &Locality, actual: &Locality) -> bool {
    [
        (&expected.region, &actual.region),
        (&expected.zone, &actual.zone),
        (&expected.host, &actual.host),
    ]
    .iter()
    .all(|(expected, actual)| expected.is_none() || expected == actual)
}
