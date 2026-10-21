//! Exchanges Google-signed GCE identities for configured workload capabilities.
//!
//! Fresh public keys are fetched only from Google's fixed HTTPS JWKS endpoint
//! through the trusted HTTP binding. The token cannot choose a key URL. Full
//! instance claims, audience, service account and job assignment must all match
//! trusted configuration before the static issuer receives any grants.
//!
//! The claim contract is documented at
//! <https://cloud.google.com/compute/docs/instances/verifying-instance-identity>.
//!
//! ```text
//! RS256 Google JWT -> exact instance + service account + configured job
//!   -> finite workload capability bound to both instance and job
//! ```

use std::{collections::BTreeSet, fmt, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode,
    jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
};
use serde::Deserialize;

use super::{MintError, StaticKeyIssuer, WorkloadClaims, WorkloadCredential, unix_seconds};
use crate::store::{
    Clock, LocalFs,
    http_stream::{
        HttpBodyStream, HttpStreamError, HttpStreamLimits, LimitedHttpBody, StreamingHttpClient,
        StreamingHttpRequest,
    },
};

/// Pins the signing-key endpoint published by Google's OpenID discovery document.
pub const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUER: &str = "https://accounts.google.com";
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_JWKS_BYTES: usize = 64 * 1024;
const MAX_KEYS: usize = 16;
const MAX_IDENTITY_SECONDS: u64 = 3600;

/// Binds one exact GCE incarnation and service account to one trusted job.
#[derive(Clone, Debug)]
pub struct InstanceAssignment {
    /// Names the Google Cloud project containing the assigned VM.
    pub project_id: String,
    /// Gives the project's immutable numeric identifier.
    pub project_number: u64,
    /// Names the VM's zone; instance names alone are not unique across zones.
    pub zone: String,
    /// Gives the immutable decimal instance identifier from the full identity token.
    pub instance_id: String,
    /// Binds the assignment to the exact VM creation timestamp in Unix seconds.
    pub creation_timestamp: u64,
    /// Gives the service account's numeric subject, independently of its email.
    pub service_account_subject: String,
    /// Supplies trusted job identity, groups, grants and expected completion time.
    pub job: WorkloadClaims,
}

impl InstanceAssignment {
    fn matches(&self, claims: &InstanceClaims, job: &str) -> bool {
        let instance = &claims.google.compute_engine;
        self.project_id == instance.project_id
            && self.project_number == instance.project_number
            && self.zone == instance.zone
            && self.instance_id == instance.instance_id
            && self.creation_timestamp == instance.instance_creation_timestamp
            && self.service_account_subject == claims.sub
            && claims.azp == claims.sub
            && self.job.workload == job
    }
}

/// Authenticates instance identities against explicit assignments before minting.
///
/// The injected HTTP client is trusted infrastructure: it must verify HTTPS
/// server identity. No URL or key from the presented token is followed. A fresh
/// bounded key fetch is required for each exchange; stale cached keys are not
/// used when Google's endpoint is unavailable. The outer service still owns
/// transport authentication, rate limits and cancellation.
pub struct GcpInstanceIssuer {
    issuer: StaticKeyIssuer,
    audience: String,
    assignments: Vec<InstanceAssignment>,
    timeout: Duration,
}

/// Checks trusted assignment policy without opening signing material or the network.
///
/// # Errors
/// Rejects invalid audience/deadline policy, incomplete identities and duplicate
/// instance assignments before a configured opener accesses its signing key.
pub(crate) fn validate_configuration(
    audience: &str,
    assignments: &[InstanceAssignment],
    timeout: Duration,
) -> Result<(), InstanceError> {
    if audience.is_empty()
        || audience.len() > 2048
        || assignments.is_empty()
        || timeout.is_zero()
        || timeout > Duration::from_secs(30)
    {
        return Err(InstanceError::Configuration);
    }
    let mut unique = BTreeSet::new();
    for assignment in assignments {
        if assignment.project_id.is_empty()
            || assignment.project_number == 0
            || assignment.zone.is_empty()
            || !decimal(&assignment.instance_id)
            || !decimal(&assignment.service_account_subject)
            || assignment.job.subject.is_empty()
            || assignment.job.workload.is_empty()
            || assignment.job.grants.is_empty()
            || !unique.insert((
                assignment.project_id.clone(),
                assignment.zone.clone(),
                assignment.instance_id.clone(),
            ))
        {
            return Err(InstanceError::Configuration);
        }
    }

    Ok(())
}

impl GcpInstanceIssuer {
    /// Checks the exact audience, finite exchange deadline and unambiguous assignments.
    ///
    /// Each instance may have only one configured assignment. Grant and group
    /// configuration is never derived from the submitted Google token or job name.
    ///
    /// # Errors
    /// Rejects missing identity fields, nondecimal numeric identities, empty or
    /// duplicate assignments, an empty audience, or a zero/unbounded deadline.
    pub fn new(
        issuer: StaticKeyIssuer,
        audience: String,
        assignments: Vec<InstanceAssignment>,
        timeout: Duration,
    ) -> Result<Self, InstanceError> {
        validate_configuration(&audience, &assignments, timeout)?;

        Ok(Self {
            issuer,
            audience,
            assignments,
            timeout,
        })
    }

    /// Authenticates a full GCE identity and exchanges it for its configured job token.
    ///
    /// Signature, algorithm, issuer, exact audience, full instance incarnation,
    /// service-account subject, validity interval and job assignment all precede
    /// issuance. The resulting workload claim encodes the instance and job as a
    /// JSON tuple. Capability expiry also cannot outlive the Google identity.
    ///
    /// # Errors
    /// Rejects malformed or excessive tokens/keys, unsupported headers, wrong
    /// signatures/claims, unknown or mismatched assignments, expired/future
    /// identities, unavailable key fetches, stream failures, deadline expiry and
    /// underlying capability issuance failures. No partial credential is returned.
    ///
    /// # Panics
    /// Requires an active Tokio runtime with its timer driver enabled.
    pub async fn exchange<F: LocalFs + Sync, C: Clock + Sync, H: StreamingHttpClient + Sync>(
        &self,
        fs: &F,
        clock: &C,
        http: &H,
        identity: &str,
        job: &str,
    ) -> Result<WorkloadCredential, InstanceError> {
        tokio::time::timeout(
            self.timeout,
            self.exchange_inner(fs, clock, http, identity, job),
        )
        .await
        .map_err(|_| InstanceError::Deadline)?
    }

    async fn exchange_inner<F: LocalFs + Sync, C: Clock + Sync, H: StreamingHttpClient + Sync>(
        &self,
        fs: &F,
        clock: &C,
        http: &H,
        identity: &str,
        job: &str,
    ) -> Result<WorkloadCredential, InstanceError> {
        let header = checked_header(identity)?;
        if !self
            .assignments
            .iter()
            .any(|assignment| assignment.job.workload == job)
        {
            return Err(InstanceError::Unauthorized);
        }
        let began = unix_seconds(clock).map_err(InstanceError::Mint)?;
        let keys = fetch_keys(http).await?;
        let now = unix_seconds(clock).map_err(InstanceError::Mint)?;
        if now < began {
            return Err(InstanceError::Unauthorized);
        }
        let claims = verify(identity, &header, &keys, &self.audience, now)?;
        let assignment = self
            .assignments
            .iter()
            .find(|assignment| assignment.matches(&claims, job))
            .ok_or(InstanceError::Unauthorized)?;

        let instance = &claims.google.compute_engine;
        let mut job = assignment.job.clone();
        job.workload = serde_json::to_string(&(
            "gce",
            &instance.project_id,
            instance.project_number,
            &instance.zone,
            &instance.instance_id,
            instance.instance_creation_timestamp,
            &job.workload,
        ))
        .map_err(|_| InstanceError::Unauthorized)?;
        // Google's exp is exclusive; Terrane's authority expiry is inclusive.
        job.not_after = Some(
            job.not_after.unwrap_or(u64::MAX).min(
                claims
                    .exp
                    .checked_sub(1)
                    .ok_or(InstanceError::Unauthorized)?,
            ),
        );
        let credential = self
            .issuer
            .mint(fs, clock, job)
            .await
            .map_err(InstanceError::Mint)?;
        let completed = unix_seconds(clock).map_err(InstanceError::Mint)?;
        if completed < now || completed >= claims.exp {
            return Err(InstanceError::Unauthorized);
        }
        Ok(credential)
    }
}

fn decimal(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32 && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoogleHeader {
    alg: String,
    kid: String,
    typ: Option<String>,
}

fn checked_header(token: &str) -> Result<GoogleHeader, InstanceError> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(InstanceError::Unauthorized);
    }
    let encoded = token.split('.').next().ok_or(InstanceError::Unauthorized)?;
    if encoded.len() > 4096 {
        return Err(InstanceError::Unauthorized);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| InstanceError::Unauthorized)?;
    let header: GoogleHeader =
        serde_json::from_slice(&bytes).map_err(|_| InstanceError::Unauthorized)?;
    if header.alg != "RS256"
        || header.kid.is_empty()
        || header.kid.len() > 128
        || header.typ.as_deref().is_some_and(|kind| kind != "JWT")
    {
        return Err(InstanceError::Unauthorized);
    }
    Ok(header)
}

#[derive(Deserialize)]
struct InstanceClaims {
    iss: String,
    aud: String,
    sub: String,
    azp: String,
    iat: u64,
    exp: u64,
    nbf: Option<u64>,
    google: GoogleClaims,
}

#[derive(Deserialize)]
struct GoogleClaims {
    compute_engine: ComputeClaims,
}

#[derive(Deserialize)]
struct ComputeClaims {
    project_id: String,
    project_number: u64,
    zone: String,
    instance_id: String,
    instance_creation_timestamp: u64,
}

fn verify(
    token: &str,
    header: &GoogleHeader,
    keys: &JwkSet,
    audience: &str,
    now: u64,
) -> Result<InstanceClaims, InstanceError> {
    let key = keys.find(&header.kid).ok_or(InstanceError::Unauthorized)?;
    let decoding = DecodingKey::from_jwk(key).map_err(|_| InstanceError::Unavailable)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[GOOGLE_ISSUER]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    // Signature and issuer/audience validation remain enabled. Time is checked
    // explicitly below against the injected clock, never the library's host clock.
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.leeway = 0;
    let claims = decode::<InstanceClaims>(token, &decoding, &validation)
        .map_err(|_| InstanceError::Unauthorized)?
        .claims;
    if claims.iss != GOOGLE_ISSUER
        || claims.aud != audience
        || claims.iat > now
        || claims.exp <= now
        || claims.exp <= claims.iat
        || claims.exp - claims.iat > MAX_IDENTITY_SECONDS
        || claims.nbf.is_some_and(|earliest| earliest > now)
        || claims.google.compute_engine.instance_creation_timestamp > claims.iat
    {
        return Err(InstanceError::Unauthorized);
    }
    Ok(claims)
}

struct EmptyBody;

#[async_trait::async_trait]
impl HttpBodyStream for EmptyBody {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, HttpStreamError> {
        Ok(None)
    }
}

async fn fetch_keys(http: &(impl StreamingHttpClient + Sync)) -> Result<JwkSet, InstanceError> {
    let limits = HttpStreamLimits::new(MAX_JWKS_BYTES, MAX_JWKS_BYTES as u64)
        .map_err(|_| InstanceError::Configuration)?;
    let response = http
        .send_stream(
            StreamingHttpRequest {
                method: "GET".into(),
                url: GOOGLE_JWKS_URL.into(),
                headers: vec![("accept".into(), b"application/json".to_vec())],
                body: Box::new(EmptyBody),
            },
            limits,
            limits,
        )
        .await
        .map_err(|_| InstanceError::Unavailable)?;
    if response.status != 200 {
        return Err(InstanceError::Unavailable);
    }
    let mut body = LimitedHttpBody::new(response.body, limits);
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next().await.map_err(|_| InstanceError::Unavailable)? {
        bytes.extend(chunk);
    }
    let keys: JwkSet = serde_json::from_slice(&bytes).map_err(|_| InstanceError::Unavailable)?;
    if keys.keys.is_empty() || keys.keys.len() > MAX_KEYS {
        return Err(InstanceError::Unavailable);
    }
    let mut unique = BTreeSet::new();
    for key in &keys.keys {
        let kid = key
            .common
            .key_id
            .as_deref()
            .ok_or(InstanceError::Unavailable)?;
        let AlgorithmParameters::RSA(parameters) = &key.algorithm else {
            return Err(InstanceError::Unavailable);
        };
        if kid.is_empty()
            || kid.len() > 128
            || !unique.insert(kid)
            || key.common.key_algorithm != Some(KeyAlgorithm::RS256)
            || key.common.public_key_use != Some(PublicKeyUse::Signature)
            || key
                .common
                .key_operations
                .as_ref()
                .is_some_and(|ops| ops != &[KeyOperations::Verify])
            || parameters.n.len() > 1024
            || parameters.e.len() > 8
        {
            return Err(InstanceError::Unavailable);
        }
    }
    Ok(keys)
}

/// Distinguishes local setup and availability failures from uniform identity denial.
#[derive(Debug)]
pub enum InstanceError {
    /// Rejects invalid trusted issuer or job configuration.
    Configuration,
    /// Denies every identity, claim or assignment mismatch without exposing its cause.
    Unauthorized,
    /// Refuses unavailable or malformed signing-key responses.
    Unavailable,
    /// Refuses an exchange that exceeded its complete deadline.
    Deadline,
    /// Retains a local capability issuance failure for trusted diagnostics.
    Mint(MintError),
}

impl fmt::Display for InstanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "invalid GCP instance issuer configuration",
            Self::Unauthorized => "unauthorized",
            Self::Unavailable => "GCP signing keys unavailable",
            Self::Deadline => "GCP instance exchange deadline exceeded",
            Self::Mint(_) => "workload capability issuance failed",
        })
    }
}

impl std::error::Error for InstanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Mint(error) => Some(error),
            _ => None,
        }
    }
}
