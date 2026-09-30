//! Authenticates canonical commits and their embedded capability chains.

use crate::auth::{self, IssuerKey, Request, RequestRoot, Token, Verb, VerifiedToken};
use crate::identity::Digest;
use crate::refs::Commit;
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Rejects a commit without exposing private authorization diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rejected;

impl fmt::Display for Rejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("commit rejected")
    }
}

impl core::error::Error for Rejected {}

/// Describes a rejection exclusively for trusted diagnostic consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Diagnostic {
    /// The commit violates its canonical record schema.
    Encoding,
    /// The embedded token is absent, malformed, or unauthenticated.
    Token,
    /// Provenance disagrees with the authenticated authority block.
    Claims,
    /// The epoch or authorization context does not authorize this commit.
    Authorization,
    /// The signature is absent, invalid, or made by a different terminal key.
    Signature,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Encoding => "invalid canonical commit",
            Self::Token => "invalid embedded capability",
            Self::Claims => "commit claims differ from capability authority",
            Self::Authorization => "capability does not authorize commit context",
            Self::Signature => "invalid terminal-key commit signature",
        })
    }
}

impl core::error::Error for Diagnostic {}

/// Holds an authenticated commit and the token claims bound into its signature.
///
/// Construction is restricted to verification. Repository guards must still
/// enforce current ACLs before accepting a ref update (AUTH-26, PROV-4).
#[derive(Clone, Debug)]
pub struct VerifiedCommit {
    commit: Commit,
    identity: Digest,
    token: VerifiedToken,
    public_key: [u8; 32],
}

impl VerifiedCommit {
    /// Returns the complete immutable signed record.
    pub fn commit(&self) -> &Commit {
        &self.commit
    }

    /// Returns the identity of the canonical record including its signature.
    pub const fn identity(&self) -> Digest {
        self.identity
    }

    /// Returns issuer-authenticated principal and group claims.
    pub fn authority(&self) -> &auth::Authority {
        self.token.authority()
    }

    /// Returns the terminal Ed25519 public key authenticated by the token.
    pub const fn signing_public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

fn authenticate(
    commit: &Commit,
    keys: &[IssuerKey],
    request: &Request<'_>,
    writer_epoch: u64,
) -> Result<(Token, VerifiedToken), Diagnostic> {
    commit
        .signature_preimage()
        .map_err(|_| Diagnostic::Encoding)?;

    let bytes = commit
        .provenance
        .embedded_token
        .as_deref()
        .ok_or(Diagnostic::Token)?;
    let token = Token::decode(bytes).map_err(|_| Diagnostic::Token)?;
    let authenticated = token
        .verify(keys, commit.timestamp)
        .map_err(|_| Diagnostic::Token)?;
    let authority = authenticated.authority();
    let claims = &commit.provenance;
    if claims.issuer != authority.issuer
        || claims.token_id != authority.token_id
        || claims.subject != authority.subject
        || claims.kind != authority.kind
        || claims.workload_identity != authority.workload
        || claims.observed_at != commit.timestamp
    {
        return Err(Diagnostic::Claims);
    }

    // The caller supplies the target ref's trusted fencing epoch. An epoch
    // claim in the signed record cannot select its own authorization context.
    if request.verb != Verb::Commit
        || request.now != commit.timestamp
        || claims.writer_epoch != writer_epoch
        || !request
            .epochs
            .iter()
            .any(|(name, epoch)| name.as_bytes() == request.reference && *epoch == writer_epoch)
        || request
            .epochs
            .iter()
            .filter(|(name, _)| name.as_bytes() == request.reference)
            .count()
            != 1
        || commit
            .profile_pair
            .commit_context
            .as_ref()
            .is_some_and(|context| !context.matches_request(request))
    {
        return Err(Diagnostic::Authorization);
    }

    authenticated
        .authorize(request)
        .map_err(|_| Diagnostic::Authorization)?;
    Ok((token, authenticated))
}

/// Signs a canonical commit using its authorizing token's terminal private key.
///
/// The embedded chain and provenance are authenticated before signing. The
/// supplied request describes the commit-time ref, roots, surface, and epochs.
/// Current ACL intersection remains the repository guard's responsibility.
///
/// # Errors
/// Returns [`Rejected`] for invalid schema, token, claims, authorization
/// context, or a private key different from the embedded terminal public key.
pub fn sign(
    mut commit: Commit,
    secret: &[u8; 32],
    keys: &[IssuerKey],
    request: &Request<'_>,
    writer_epoch: u64,
) -> Result<VerifiedCommit, Rejected> {
    let (token, _) = authenticate(&commit, keys, request, writer_epoch).map_err(|_| Rejected)?;
    let signing_key = SigningKey::from_bytes(secret);
    if signing_key.verifying_key().to_bytes() != token.signing_public_key() {
        return Err(Rejected);
    }

    let preimage = commit.signature_preimage().map_err(|_| Rejected)?;
    commit.signature = Some(signing_key.sign(&preimage).to_bytes());
    verify(&commit, keys, request, writer_epoch)
}

/// Signs a newly authored commit carrying its complete original scope.
///
/// The caller must construct signed context from canonical affected roots and
/// their effective domains and separately enforce current ACLs (PROV-4).
/// Legacy draft signing remains available through [`sign`] for explicit
/// compatibility workflows; guards use this operation for new authored commits.
///
/// # Errors
/// Returns [`Rejected`] when context is absent or does not match the request,
/// or when any schema, token, signature-key, claim, or authorization check fails.
pub fn sign_authored(
    commit: Commit,
    secret: &[u8; 32],
    keys: &[IssuerKey],
    request: &Request<'_>,
    writer_epoch: u64,
) -> Result<VerifiedCommit, Rejected> {
    if commit.profile_pair.commit_context.is_none() {
        return Err(Rejected);
    }
    sign(commit, secret, keys, request, writer_epoch)
}

/// Verifies historical authority using the signed original authoring scope.
///
/// `validated_roots` must be independently established from canonical candidate
/// and previous trees, including effective disclosure policy. A signature alone
/// does not establish these facts. `original_epochs` supplies trusted historical
/// evidence for every epoch caveat, including the authoring ref's epoch. Current
/// reads, forks, tags, and advances still require current grants and ACLs.
///
/// Legacy draft commits without stored context require [`verify`] with a trusted
/// complete original request; this operation never invents missing context.
///
/// # Errors
/// Returns [`Rejected`] for absent stored context, roots differing from signed
/// assertions, unavailable or incorrect epoch evidence, or any verification error.
pub fn verify_history(
    commit: &Commit,
    keys: &[IssuerKey],
    validated_roots: &[RequestRoot<'_>],
    original_epochs: &[(&str, u64)],
) -> Result<VerifiedCommit, Rejected> {
    let context = commit
        .profile_pair
        .commit_context
        .as_ref()
        .ok_or(Rejected)?;
    let request = Request {
        reference: context.reference().as_bytes(),
        verb: Verb::Commit,
        roots: validated_roots,
        now: commit.timestamp,
        surface: context.surface(),
        locality: context.locality(),
        epochs: original_epochs,
    };
    verify(commit, keys, &request, commit.provenance.writer_epoch)
}

/// Verifies a signed commit and its embedded capability against trusted context.
///
/// # Errors
/// Returns [`Rejected`] for every schema, signature, token, claims, epoch,
/// or token authorization failure. This operation does not check current ACLs.
pub fn verify(
    commit: &Commit,
    keys: &[IssuerKey],
    request: &Request<'_>,
    writer_epoch: u64,
) -> Result<VerifiedCommit, Rejected> {
    verify_diagnostic(commit, keys, request, writer_epoch).map_err(|_| Rejected)
}

/// Verifies a commit and reports causes only to privileged diagnostics.
///
/// # Errors
/// Returns [`Diagnostic`] for malformed, unauthenticated, unauthorized, or
/// mismatched records. Never expose this diagnostic through a public surface.
pub fn verify_diagnostic(
    commit: &Commit,
    keys: &[IssuerKey],
    request: &Request<'_>,
    writer_epoch: u64,
) -> Result<VerifiedCommit, Diagnostic> {
    let (token, authenticated) = authenticate(commit, keys, request, writer_epoch)?;
    let public_key = token.signing_public_key();
    let key = VerifyingKey::from_bytes(&public_key).map_err(|_| Diagnostic::Signature)?;
    let signature = commit.signature.ok_or(Diagnostic::Signature)?;
    key.verify_strict(
        &commit
            .signature_preimage()
            .map_err(|_| Diagnostic::Encoding)?,
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| Diagnostic::Signature)?;

    Ok(VerifiedCommit {
        commit: commit.clone(),
        identity: commit.identity().map_err(|_| Diagnostic::Encoding)?,
        token: authenticated,
        public_key,
    })
}
