//! Mints bounded workload capabilities from configured static signing authority.
//!
//! The native issuer loads a private raw Ed25519 seed and checks it against an
//! independently configured public key. Job claims and grants come from a
//! trusted scheduler or authenticated provisioning policy. This module does
//! not authenticate incoming requests or infer grants from client claims.
//! The repository guard still checks current ACLs on every operation.
//!
//! ```text
//! trusted job claims + configured key + secure entropy + injected clock
//!   -> workload token and host-held terminal signing secret
//! expiry <= min(job end + margin, now + maximum lifetime, key retirement - 1)
//! ```

use std::{fmt, time::UNIX_EPOCH};

use terrane_format::auth::{self, Authority, Grant, IssuerKey, PrincipalKind, Token};
use zeroize::Zeroizing;

use crate::store::{Clock, LocalFs};

#[cfg(unix)]
mod key_file;

/// Holds finite validity bounds and independently configured public authority.
#[derive(Clone, Debug)]
pub struct IssuerPolicy {
    key: IssuerKey,
    maximum_lifetime: u64,
    lifetime_margin: u64,
}

impl IssuerPolicy {
    /// Checks a configured issuer and its lifetime and job-overrun bounds in seconds.
    ///
    /// # Errors
    /// Rejects empty issuer identifiers, zero or unbounded maximum lifetimes,
    /// and margins larger than the configured maximum lifetime.
    pub fn new(
        key: IssuerKey,
        maximum_lifetime: u64,
        lifetime_margin: u64,
    ) -> Result<Self, MintError> {
        if key.issuer.is_empty()
            || key.key_id.is_empty()
            || maximum_lifetime == 0
            || maximum_lifetime == u64::MAX
            || lifetime_margin > maximum_lifetime
        {
            return Err(MintError::Policy);
        }

        Ok(Self {
            key,
            maximum_lifetime,
            lifetime_margin,
        })
    }

    /// Returns the configured public issuer key, without private signing material.
    pub fn key(&self) -> &IssuerKey {
        &self.key
    }

    fn expiry(&self, now: u64, claims: &WorkloadClaims) -> Result<u64, MintError> {
        let job_bound = claims
            .expected_end
            .checked_add(self.lifetime_margin)
            .ok_or(MintError::Lifetime)?;
        let issuer_bound = now
            .checked_add(self.maximum_lifetime)
            .ok_or(MintError::Lifetime)?;
        let retirement_bound = match self.key.retirement {
            Some(retirement) => retirement.checked_sub(1).ok_or(MintError::Lifetime)?,
            None => u64::MAX,
        };
        let expiry = job_bound
            .min(issuer_bound)
            .min(retirement_bound)
            .min(claims.not_after.unwrap_or(u64::MAX));
        if expiry <= now {
            return Err(MintError::Lifetime);
        }

        Ok(expiry)
    }
}

/// Supplies claims from trusted job configuration after authenticating the workload.
///
/// These fields are authority inputs. An unauthenticated remote request must
/// never be copied into this value to select its own identity, groups or grants.
#[derive(Clone, Debug)]
pub struct WorkloadClaims {
    /// Names the configured workload principal.
    pub subject: String,
    /// Binds this credential to one concrete job, run, pod or instance assignment.
    pub workload: String,
    /// Carries group memberships supplied by the trusted identity source.
    pub groups: Vec<String>,
    /// Supplies the configured job's initial grant set.
    pub grants: Vec<Grant>,
    /// Gives the expected job completion time in Unix seconds.
    pub expected_end: u64,
    /// Optionally requests an earlier expiry; it cannot widen the issuer bounds.
    pub not_after: Option<u64>,
}

/// Holds static signing authority without exposing secrets through diagnostics.
///
/// The Unix `open` constructor loads a private key file. Its public
/// counterpart must already be configured independently at the repository guard.
/// Private seed memory is zeroized when this issuer is dropped.
pub struct StaticKeyIssuer {
    policy: IssuerPolicy,
    secret: Zeroizing<[u8; 32]>,
}

impl StaticKeyIssuer {
    /// Opens a private raw 32-byte Ed25519 seed matching the configured public key.
    ///
    /// The actual descriptor must be a singly linked regular file owned by
    /// `owner_uid`, with mode 0400 or 0600. The final component is opened without
    /// following symlinks. The descriptor's metadata is checked before and after
    /// its bounded read; the independent public-key match prevents a substituted
    /// ancestor from selecting different signing authority. File I/O occurs
    /// synchronously during issuer startup.
    ///
    /// # Errors
    /// Rejects relative or noncanonical paths, unsafe ownership, permissions,
    /// links, inode kinds, changed metadata, incorrect seed length, public-key
    /// mismatch and actual filesystem errors. Error messages omit key material.
    #[cfg(unix)]
    pub fn open(
        path: &std::path::Path,
        owner_uid: u32,
        policy: IssuerPolicy,
    ) -> Result<Self, MintError> {
        let secret = key_file::read(path, owner_uid)?;
        if auth::public_key_from_secret(&secret) != policy.key.public_key {
            return Err(MintError::Key);
        }

        Ok(Self { policy, secret })
    }

    /// Returns the independently configured public issuer policy.
    pub fn policy(&self) -> &IssuerPolicy {
        &self.policy
    }

    /// Mints a fresh workload capability under trusted job claims and finite bounds.
    ///
    /// Token identifiers and terminal Ed25519 seeds use the host's secure
    /// randomness binding. The clock is checked again after asynchronous entropy
    /// acquisition; regression or expiry during that operation refuses issuance.
    /// The result grants no repository access without current guard authorization.
    ///
    /// # Errors
    /// Rejects absent workload identity, invalid canonical authority fields,
    /// overflow, expired job/key/request limits, pre-epoch or regressed clocks,
    /// expiry during entropy acquisition, and entropy errors or incorrect lengths.
    pub async fn mint<F: LocalFs + Sync, C: Clock + Sync>(
        &self,
        fs: &F,
        clock: &C,
        claims: WorkloadClaims,
    ) -> Result<WorkloadCredential, MintError> {
        if claims.subject.is_empty() || claims.workload.is_empty() {
            return Err(MintError::Claims);
        }
        let now = unix_seconds(clock)?;
        let not_after = self.policy.expiry(now, &claims)?;

        let random = Zeroizing::new(fs.random_bytes(48).await.map_err(MintError::Io)?);
        if random.len() != 48 {
            return Err(MintError::Entropy);
        }
        let mut terminal = Zeroizing::new([0_u8; 32]);
        terminal.copy_from_slice(&random[..32]);
        let token_id = random[32..].try_into().map_err(|_| MintError::Entropy)?;
        let token = Token::issue(
            Authority {
                issuer: self.policy.key.issuer.clone(),
                key_id: self.policy.key.key_id.clone(),
                subject: claims.subject,
                kind: PrincipalKind::Workload,
                groups: claims.groups,
                not_after,
                not_before: Some(now),
                token_id,
                grants: claims.grants,
                workload: Some(claims.workload),
            },
            &self.secret,
            auth::public_key_from_secret(&terminal),
        )
        .map_err(|_| MintError::Claims)?;

        let completed = unix_seconds(clock)?;
        if completed < now || completed >= not_after {
            return Err(MintError::Lifetime);
        }
        token
            .verify(std::slice::from_ref(&self.policy.key), completed)
            .map_err(|_| MintError::Claims)?;

        Ok(WorkloadCredential {
            token: Zeroizing::new(token.encode()),
            terminal,
        })
    }
}

/// Holds a workload bearer token and its host-only terminal signing secret.
///
/// Neither credential implements `Debug`. Both buffers are zeroized on drop.
/// The signing secret is separate from the canonical wire token; it must remain
/// in the trusted host and must never be passed into a realized surface.
pub struct WorkloadCredential {
    token: Zeroizing<Vec<u8>>,
    terminal: Zeroizing<[u8; 32]>,
}

impl WorkloadCredential {
    /// Borrows the canonical capability for authenticated guard requests.
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// Borrows host-only proof material for offline attenuation or commit signing.
    ///
    /// This private seed must not be sent as the token, logged, or exposed to a
    /// guest process. Its public key is authenticated by the token's final block.
    pub fn signing_secret(&self) -> &[u8; 32] {
        &self.terminal
    }
}

fn unix_seconds(clock: &impl Clock) -> Result<u64, MintError> {
    clock
        .now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| MintError::Clock)
}

/// Reports local issuance failures without placing secrets in display messages.
#[derive(Debug)]
pub enum MintError {
    /// Rejects invalid issuer configuration.
    Policy,
    /// Rejects unsafe or mismatched signing key material.
    Key,
    /// Rejects invalid workload authority fields.
    Claims,
    /// Rejects overflow, expiry or a clock change during issuance.
    Lifetime,
    /// Rejects a wall clock before the Unix epoch.
    Clock,
    /// Rejects an entropy binding that returns an incorrect number of bytes.
    Entropy,
    /// Retains the underlying local filesystem or entropy failure.
    Io(std::io::Error),
}

impl fmt::Display for MintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Policy => "invalid workload issuer policy",
            Self::Key => "invalid workload issuer key file",
            Self::Claims => "invalid workload claims",
            Self::Lifetime => "invalid workload validity interval",
            Self::Clock => "invalid workload issuer clock",
            Self::Entropy => "invalid workload issuer entropy",
            Self::Io(_) => "workload issuer I/O failed",
        })
    }
}

impl std::error::Error for MintError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
