//! Bounded browser source commitments and immutable private resume records.
//!
//! Checkpoints contain logical identities and observed receipts, never delegated
//! URLs, provider UploadIds, credential material or authentication tokens.
//!
//! IndexedDB stores closed JSON records under these keys:
//! ```text
//! <scope>:active                         => ResumeHead
//! <scope>:<run>:<placement>:<part-number> => PartCheckpoint
//! ```

use aos_proto_types::direct_upload::*;
use base64::Engine as _;
use md5::{Digest as _, Md5};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Maximum buffer used to read a selected browser file.
pub(crate) const SOURCE_CHUNK_BYTES: usize = 64 * 1024;
/// Stable protocol geometry, above the provider's minimum nonfinal part size.
pub(crate) const BROWSER_PART_BYTES: u64 = 8 * 1024 * 1024;

/// Checks the original file size against its authenticated direct upload policy.
///
/// # Errors
/// Returns an explicit direct upload error when the file falls outside the
/// advertised object bounds. Refusal does not authorize another transfer mode.
pub(crate) fn validate_object_size(
    capabilities: &DirectUploadCapabilities,
    byte_size: u64,
) -> Result<(), String> {
    if byte_size < capabilities.minimum_object_bytes.get() {
        return Err(format!(
            "The direct upload minimum file size is {} bytes for these destinations",
            capabilities.minimum_object_bytes.get()
        ));
    }

    if byte_size > capabilities.maximum_object_bytes.get() {
        return Err("The selected file exceeds the direct upload limit".into());
    }

    Ok(())
}

/// Original checksum identity of one source range, independent of placement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SourcePart {
    /// One-based source part number.
    pub number: u32,
    /// Exact byte offset in the original selected file.
    pub offset: u64,
    /// Exact length of this original source range.
    pub size: u64,
    /// Lowercase SHA-256 of the original source range.
    pub sha256: String,
    /// Canonical base64 MD5 used when that provider algorithm is qualified.
    pub md5: String,
}

impl SourcePart {
    /// Converts an original range to the selected qualified checksum descriptor.
    ///
    /// # Errors
    /// Returns an error for a malformed retained checksum.
    pub(crate) fn descriptor(
        &self,
        algorithm: DirectChecksumAlgorithm,
    ) -> Result<DirectPart, String> {
        if !valid_direct_digest(&self.sha256) || self.md5.len() != 24 {
            return Err("The retained source checksum is invalid".into());
        }
        let md5 = base64::engine::general_purpose::STANDARD
            .decode(&self.md5)
            .map_err(|_| "The retained source checksum is invalid".to_string())?;
        if md5.len() != 16 || base64::engine::general_purpose::STANDARD.encode(md5) != self.md5 {
            return Err("The retained source checksum is invalid".into());
        }
        let value = match algorithm {
            DirectChecksumAlgorithm::Md5 => self.md5.clone(),
            DirectChecksumAlgorithm::Sha256 => {
                // Source commitments are locally constructed from exact digest bytes.
                let bytes = hex::decode(&self.sha256)
                    .map_err(|_| "The retained source checksum is invalid".to_string())?;
                base64::engine::general_purpose::STANDARD.encode(bytes)
            }
        };
        Ok(DirectPart {
            part_number: self.number,
            offset: WireInteger::new(self.offset),
            byte_size: WireInteger::new(self.size),
            sha256: self.sha256.clone(),
            checksum: DirectPartChecksum { algorithm, value },
        })
    }
}

/// One bounded streaming pass over the immutable selected file.
pub(crate) struct SourceAccumulator {
    expected_size: u64,
    total: u64,
    full: Sha256,
    part_sha: Sha256,
    part_md5: Md5,
    part_size: u64,
    parts: Vec<SourcePart>,
}

impl SourceAccumulator {
    /// Starts a bounded source checksum pass.
    ///
    /// # Errors
    /// Returns an error when the declared source exceeds the protocol limit.
    pub(crate) fn new(expected_size: u64) -> Result<Self, String> {
        if expected_size > MAX_DIRECT_OBJECT_BYTES {
            return Err("The selected file exceeds the direct upload limit".into());
        }
        Ok(Self {
            expected_size,
            total: 0,
            full: Sha256::new(),
            part_sha: Sha256::new(),
            part_md5: Md5::new(),
            part_size: 0,
            parts: Vec::new(),
        })
    }

    /// Consumes one bounded source slice with exact declared length accounting.
    ///
    /// # Errors
    /// Returns an error for an oversized slice or changed source length.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > SOURCE_CHUNK_BYTES
            || self
                .total
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > self.expected_size)
        {
            return Err("The selected file changed while its checksums were read".into());
        }
        self.full.update(bytes);
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let count = remaining
                .len()
                .min((BROWSER_PART_BYTES - self.part_size) as usize);
            let (chunk, tail) = remaining.split_at(count);
            self.part_sha.update(chunk);
            self.part_md5.update(chunk);
            self.total += count as u64;
            self.part_size += count as u64;
            remaining = tail;
            if self.part_size == BROWSER_PART_BYTES {
                self.finish_part()?;
            }
        }
        Ok(())
    }

    fn finish_part(&mut self) -> Result<(), String> {
        if self.parts.len() >= MAX_DIRECT_PARTS as usize {
            return Err("The selected file requires too many parts".into());
        }
        let sha = std::mem::replace(&mut self.part_sha, Sha256::new()).finalize();
        let md5 = std::mem::replace(&mut self.part_md5, Md5::new()).finalize();
        self.parts.push(SourcePart {
            number: self.parts.len() as u32 + 1,
            offset: self.total - self.part_size,
            size: self.part_size,
            sha256: hex::encode(sha),
            md5: base64::engine::general_purpose::STANDARD.encode(md5),
        });
        self.part_size = 0;
        Ok(())
    }

    /// Finishes the full SHA-256 and original ordered part checksums.
    ///
    /// # Errors
    /// Returns an error for an incomplete source or excessive part count.
    pub(crate) fn finish(mut self) -> Result<(String, Vec<SourcePart>), String> {
        if self.total != self.expected_size {
            return Err("The selected file changed while its checksums were read".into());
        }
        if self.part_size > 0 {
            self.finish_part()?;
        }
        Ok((hex::encode(self.full.finalize()), self.parts))
    }
}

/// Retained original business intent before its first Native admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResumeHead {
    /// Digest of authenticated deployment, principal and logical owner/path.
    pub scope: String,
    /// Random immutable identity for this browser upload run.
    pub run_nonce: String,
    /// Authenticated deployment namespace returned by discovery.
    pub deployment_id: String,
    /// Authenticated immutable actor commitment returned by discovery.
    pub principal_id: String,
    /// Original source, geometry and owner bound before admission.
    pub intent: DirectUploadIntent,
    /// Most recently observed exact admitted session without delegated URLs.
    pub session: Option<DirectSessionStatus>,
    /// Original completion CAS and manifests, retained before first dispatch.
    pub complete: Option<DirectCompleteRequest>,
}

/// One original source commitment and monotonic grant-attempt ordinal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PartCheckpoint {
    /// Original required placement and protected profile association.
    pub placement: DirectPlacementRef,
    /// Original independently measured source range.
    pub original: SourcePart,
    /// Monotonic ordinal persisted before requesting a replacement grant.
    pub attempt: u64,
    /// First positive provider observation retained before reporting.
    pub receipt: Option<PartReceipt>,
    /// Exact positive part observation returned by the broker.
    pub server_observed: Option<DirectManifestPart>,
}

/// Positive provider observation retained before ReportPartsBatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PartReceipt {
    /// Original opaque grant identity; no delegated URL is retained.
    pub grant_id: String,
    /// Original grant revision used for exact report replay.
    pub grant_revision: WireInteger,
    /// Original content-bound part and strong exposed provider ETag.
    pub observed: DirectManifestPart,
}

/// Preserves previously acknowledged history during one atomic checkpoint write.
pub(crate) trait CheckpointRecord: Serialize + for<'de> Deserialize<'de> + Clone {
    /// Merges an update with the exact record read inside its write transaction.
    ///
    /// # Errors
    /// Returns an error if immutable identity or a positive receipt changes.
    fn merge(self, previous: Option<Self>) -> Result<Self, String>;
}

impl CheckpointRecord for ResumeHead {
    fn merge(mut self, previous: Option<Self>) -> Result<Self, String> {
        let Some(old) = previous else {
            if self.session.is_some() || self.complete.is_some() {
                return Err("The original upload checkpoint was retired or removed".into());
            }
            return Ok(self);
        };
        if self.scope != old.scope
            || self.run_nonce != old.run_nonce
            || self.deployment_id != old.deployment_id
            || self.principal_id != old.principal_id
            || self.intent != old.intent
        {
            return Err("Another original upload is retained for this path".into());
        }
        if let Some(complete) = old.complete {
            if self.complete.as_ref().is_some_and(|new| new != &complete) {
                return Err("The original completion intent changed".into());
            }
            self.complete = Some(complete);
        }
        if let Some(original) = old.session {
            if let Some(next) = &self.session {
                next.validate_for(&original.session, &old.intent, &original.placements)
                    .map_err(|_| "The original upload session changed".to_string())?;
                if original.state == DirectSessionState::Committed
                    || original.resource_version.get() > next.resource_version.get()
                {
                    self.session = Some(original);
                }
            } else {
                self.session = Some(original);
            }
        }
        Ok(self)
    }
}

impl CheckpointRecord for PartCheckpoint {
    fn merge(mut self, previous: Option<Self>) -> Result<Self, String> {
        if self.attempt == 0 {
            return Err("The retained grant attempt is invalid".into());
        }
        let Some(old) = previous else {
            return Ok(self);
        };
        if self.placement != old.placement || self.original != old.original {
            return Err("The original browser part changed".into());
        }
        self.attempt = self.attempt.max(old.attempt);
        if let Some(receipt) = old.receipt {
            if self.receipt.as_ref().is_some_and(|new| new != &receipt) {
                return Err("The original positive provider receipt changed".into());
            }
            self.receipt = Some(receipt);
        }
        if let Some(observed) = old.server_observed {
            if self
                .server_observed
                .as_ref()
                .is_some_and(|new| new != &observed)
            {
                return Err("The original observed provider part changed".into());
            }
            self.server_observed = Some(observed);
        }
        Ok(self)
    }
}

/// Bounded memory-only proof of the actor/owner authenticated by one exact bearer.
#[derive(Clone)]
pub(crate) struct DirectActorProof {
    bearer_digest: [u8; 32],
    deployment: String,
    principal: String,
    target: DirectCapabilitiesTarget,
    valid_until: u64,
    capabilities: DirectUploadCapabilities,
}

impl std::fmt::Debug for DirectActorProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DirectActorProof { [REDACTED] }")
    }
}

impl DirectActorProof {
    /// Binds a validated authenticated discovery response to its exact token.
    ///
    /// The transport must have used this same captured bearer for discovery.
    /// This helper cannot itself prove TLS/request provenance and stores only
    /// a token digest in memory, never the token or a durable checkpoint proof.
    ///
    /// # Errors
    /// Returns an error for a changed actor/owner or invalid/expired discovery.
    pub(crate) fn from_authenticated(
        bearer: &str,
        deployment: &str,
        principal: &str,
        target: &DirectCapabilitiesTarget,
        capabilities: &DirectUploadCapabilities,
        now: u64,
    ) -> Result<Self, String> {
        capabilities
            .validate_at_for(target, now)
            .and_then(|()| capabilities.validate_actor_for(deployment, principal))
            .map_err(|_| "The authenticated upload actor or owner changed".to_string())?;
        Ok(Self {
            bearer_digest: Sha256::digest(bearer.as_bytes()).into(),
            deployment: deployment.into(),
            principal: principal.into(),
            target: target.clone(),
            valid_until: capabilities.valid_until.get(),
            capabilities: capabilities.clone(),
        })
    }

    /// Preserves the original reviewed authority while renewing its lifetime.
    ///
    /// # Errors
    /// Refuses changed actor, owner, provider profiles or admission limits before
    /// an original control request can be replayed with the renewed bearer.
    pub(crate) fn validate_capabilities(
        &self,
        original: &DirectUploadCapabilities,
    ) -> Result<(), String> {
        let mut expected = original.clone();
        expected.valid_until = self.capabilities.valid_until;

        if expected != self.capabilities {
            return Err("The original direct upload policy changed during renewal".into());
        }

        Ok(())
    }

    /// Checks whether a memory proof still binds the exact captured bearer/scope.
    pub(crate) fn matches(
        &self,
        bearer: &str,
        deployment: &str,
        principal: &str,
        target: &DirectCapabilitiesTarget,
        now: u64,
    ) -> bool {
        self.bearer_digest == <[u8; 32]>::from(Sha256::digest(bearer.as_bytes()))
            && self.deployment == deployment
            && self.principal == principal
            && &self.target == target
            && now < self.valid_until
    }

    /// Invokes a direct control boundary using the same proven token snapshot.
    ///
    /// # Errors
    /// Returns an error before dispatch if token, actor/owner or proof expiry changed.
    pub(crate) fn dispatch_with<'a, T>(
        &self,
        bearer: &'a str,
        deployment: &str,
        principal: &str,
        target: &DirectCapabilitiesTarget,
        now: u64,
        dispatch: impl FnOnce(&'a str) -> T,
    ) -> Result<T, String> {
        if !self.matches(bearer, deployment, principal, target, now) {
            return Err("The exact upload actor proof changed or expired".into());
        }
        Ok(dispatch(bearer))
    }
}

/// Original immutable grant coordinates retained independently of delegated URLs.
#[derive(Debug, Clone)]
pub(crate) struct PartDispatchContext {
    /// Original admitted logical session and admission fingerprint.
    pub session: DirectSessionRef,
    /// Original required placement and immutable profile association.
    pub placement: DirectPlacementRef,
    /// Original full source, geometry and owner declaration.
    pub intent: DirectUploadIntent,
    /// Original independently measured part bytes and qualified checksum.
    pub part: DirectPart,
}

/// Historical capability classification, which never authorizes provider dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantLifetime {
    /// The capability currently meets the client dispatch preflight budget.
    Ready,
    /// The capability is still live but too near expiry for dispatch.
    Expiring,
    /// The capability is expired; outstanding effects remain separately retained.
    Expired,
}

impl PartDispatchContext {
    /// Correlates a current or expired grant with its exact retained coordinates.
    ///
    /// Expired grants are checked at their last valid second solely to preserve
    /// URL/header/signing-time correlation before a new attempt is journaled.
    /// This historical check never grants dispatch authority or settles old I/O.
    ///
    /// # Errors
    /// Returns an error for a changed tuple, malformed capability or clock overflow.
    pub(crate) fn classify(
        &self,
        grant: &DirectPartGrant,
        now: u64,
    ) -> Result<GrantLifetime, String> {
        let last_valid = grant
            .expires_at
            .get()
            .checked_sub(1)
            .ok_or_else(|| "The original provider grant expiry is invalid".to_string())?;
        grant
            .validate_for(
                &self.session,
                &self.placement,
                &self.intent,
                &self.part,
                now.min(last_valid),
                0,
            )
            .map_err(|_| {
                "The provider grant changed its original source or authority".to_string()
            })?;
        if grant.expires_at.get() <= now {
            return Ok(GrantLifetime::Expired);
        }
        let deadline = now
            .checked_add(1)
            .ok_or_else(|| "The browser upload clock overflowed".to_string())?;
        Ok(if deadline < grant.expires_at.get() {
            GrantLifetime::Ready
        } else {
            GrantLifetime::Expiring
        })
    }

    /// Revalidates the full retained grant and final clock before synchronous dispatch.
    ///
    /// The caller supplies the actual Fetch boundary; this helper performs no
    /// await. The second observation follows tuple/URL/header validation CPU and
    /// refuses rollback or expiry before invoking the dispatch closure. This is
    /// a local client preflight, not server clock qualification or I/O settlement.
    ///
    /// # Errors
    /// Returns an error for a changed tuple, invalid capability, clock failure,
    /// rollback, overflow or insufficient remaining lifetime. No dispatch occurs.
    pub(crate) fn dispatch_with<T>(
        &self,
        grant: &DirectPartGrant,
        mut clock: impl FnMut() -> Result<u64, String>,
        dispatch: impl FnOnce() -> T,
    ) -> Result<T, String> {
        let before = clock()?;
        grant
            .validate_for(
                &self.session,
                &self.placement,
                &self.intent,
                &self.part,
                before,
                1,
            )
            .map_err(|_| "The original provider grant is invalid or expired".to_string())?;
        let latest = clock()?;
        if latest < before
            || latest
                .checked_add(1)
                .is_none_or(|deadline| deadline >= grant.expires_at.get())
        {
            return Err("The original provider grant expired before dispatch".into());
        }
        Ok(dispatch())
    }
}

/// Retains one positive authenticated upload policy for an exact bearer/origin.
///
/// Empty mode is accepted only by this existing console compatibility path
/// after successful WhoAmI. Failed/unknown discovery never selects legacy.
#[derive(Clone)]
pub(crate) struct InitialUploadPolicy {
    bearer_digest: [u8; 32],
    origin: String,
    valid_until: u64,
    actor: Option<(String, String)>,
}

impl std::fmt::Debug for InitialUploadPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitialUploadPolicy")
            .field("bearer_digest", &"[REDACTED]")
            .field("origin", &self.origin)
            .field("valid_until", &self.valid_until)
            .field("direct_required", &self.actor.is_some())
            .finish()
    }
}

impl InitialUploadPolicy {
    /// Interprets one successful WhoAmI response obtained with this bearer.
    ///
    /// # Errors
    /// Rejects unknown policy/kind, missing direct identity or an expired
    /// assertion. The caller must establish authenticated HTTP success first.
    pub(crate) fn from_authenticated(
        bearer: &str,
        origin: &str,
        identity: &aos_proto_types::WhoAmIResponse,
        now: u64,
    ) -> Result<Self, String> {
        let valid_until = u64::try_from(identity.access_expires_at)
            .map_err(|_| "Authenticated upload policy has an invalid deadline")?;
        if bearer.is_empty()
            || origin.is_empty()
            || now >= valid_until
            || !matches!(identity.principal_kind.as_str(), "user" | "service_account")
        {
            return Err("Authenticated upload policy has an invalid actor or deadline".into());
        }
        let actor = match identity.transfer_mode.as_str() {
            "legacy" => None,
            "" if identity.deployment_id.is_empty() && identity.principal_id.is_empty() => None,
            "direct_required" => {
                if !valid_direct_identity(&identity.deployment_id)
                    || !valid_direct_digest(&identity.principal_id)
                {
                    return Err("Direct upload requires a configured actor namespace".into());
                }
                Some((
                    identity.deployment_id.clone(),
                    identity.principal_id.clone(),
                ))
            }
            _ => return Err("The Hub returned an unknown upload policy".into()),
        };
        Ok(Self {
            bearer_digest: Sha256::digest(bearer.as_bytes()).into(),
            origin: origin.into(),
            valid_until,
            actor,
        })
    }

    /// Checks whether this bounded memory-only proof still matches its token.
    pub(crate) fn matches(&self, bearer: &str, origin: &str, now: u64) -> bool {
        let digest: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
        digest == self.bearer_digest && origin == self.origin && now < self.valid_until
    }

    /// Reports an explicit legacy or successful older-server policy observation.
    pub(crate) fn is_legacy(&self) -> bool {
        self.actor.is_none()
    }

    /// Dispatches under the exact observed token, origin and transfer policy.
    ///
    /// # Errors
    /// Rejects changed token/origin, expired proof or another requested mode.
    /// The caller sends the supplied snapshot, never rereads shared state.
    pub(crate) fn dispatch_with<'a, T>(
        &self,
        bearer: &'a str,
        origin: &str,
        now: u64,
        legacy: bool,
        dispatch: impl FnOnce(&'a str) -> T,
    ) -> Result<T, String> {
        if !self.matches(bearer, origin, now) || self.is_legacy() != legacy {
            return Err("Authenticated upload policy changed or expired".into());
        }
        Ok(dispatch(bearer))
    }

    /// Correlates current discovery with the original positive direct policy.
    ///
    /// # Errors
    /// Rejects expired/malformed discovery, changed actor/owner or a legacy
    /// response under direct-required policy. Unready never means fallback.
    pub(crate) fn validate_discovery(
        &self,
        capabilities: &DirectUploadCapabilities,
        target: &DirectCapabilitiesTarget,
        now: u64,
    ) -> Result<(), String> {
        let Some((deployment, principal)) = self.actor.as_ref() else {
            return Err("Legacy upload cannot adopt direct capabilities".into());
        };
        if now >= self.valid_until
            || capabilities.transfer_mode != DirectAdvertisedTransferMode::DirectRequired
        {
            return Err("Direct upload policy expired or discovery changed mode".into());
        }
        capabilities
            .validate_at_for(target, now)
            .and_then(|()| capabilities.validate_actor_for(deployment, principal))
            .map_err(|_| "Direct upload discovery changed the original actor or owner".into())
    }
}

/// Computes a stable client operation without including provider capabilities.
///
/// # Errors
/// Returns an error when the immutable operation exceeds its control bound.
pub(crate) fn operation_id(
    kind: &str,
    run: &str,
    value: &impl Serialize,
) -> Result<String, String> {
    let bytes = encode_direct_control(value)
        .map_err(|_| "Upload operation exceeds its control limit".to_string())?;
    let mut digest = Sha256::new();
    digest.update(b"aos.console.direct-operation.v1\0");
    for part in [kind.as_bytes(), run.as_bytes(), bytes.as_slice()] {
        digest.update((part.len() as u32).to_be_bytes());
        digest.update(part);
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who_policy(mode: &str) -> aos_proto_types::WhoAmIResponse {
        aos_proto_types::WhoAmIResponse {
            principal_kind: "user".into(),
            transfer_mode: mode.into(),
            access_expires_at: (CURRENT_SIGNED_AT + 300) as i64,
            ..Default::default()
        }
    }

    #[test]
    fn positive_older_standalone_policy_needs_no_discovery_or_configured_ids() {
        let identity = who_policy("");
        let proof = InitialUploadPolicy::from_authenticated(
            "legacy-a",
            "http://local-hub.test",
            &identity,
            CURRENT_SIGNED_AT,
        )
        .unwrap();
        let discoveries = std::cell::Cell::new(0);
        let bodies = std::cell::Cell::new(0);

        assert!(proof.is_legacy());
        assert!(proof
            .dispatch_with(
                "legacy-a",
                "http://local-hub.test",
                CURRENT_SIGNED_AT,
                false,
                |_| discoveries.set(discoveries.get() + 1)
            )
            .is_err());
        proof
            .dispatch_with(
                "legacy-a",
                "http://local-hub.test",
                CURRENT_SIGNED_AT,
                true,
                |bearer| {
                    assert_eq!(bearer, "legacy-a");
                    bodies.set(bodies.get() + 1);
                },
            )
            .unwrap();

        assert_eq!(discoveries.get(), 0);
        assert_eq!(bodies.get(), 1);
    }

    #[test]
    fn explicit_modern_legacy_policy_preserves_unconfigured_standalone() {
        let mut identity = who_policy("legacy");
        identity.principal_kind = "service_account".into();
        let proof = InitialUploadPolicy::from_authenticated(
            "legacy-service",
            "https://hub.test",
            &identity,
            CURRENT_SIGNED_AT,
        )
        .unwrap();

        assert!(identity.deployment_id.is_empty());
        assert!(identity.principal_id.is_empty());
        assert!(proof.is_legacy());
        assert!(proof
            .dispatch_with(
                "legacy-service",
                "https://hub.test",
                CURRENT_SIGNED_AT,
                true,
                |_| ()
            )
            .is_ok());
    }

    #[test]
    fn unknown_required_unconfigured_or_partial_modern_policy_never_selects_legacy() {
        for mode in ["unknown", "LEGACY", "direct_required"] {
            assert!(InitialUploadPolicy::from_authenticated(
                "token",
                "https://hub.test",
                &who_policy(mode),
                CURRENT_SIGNED_AT
            )
            .is_err());
        }
        let mut partial = who_policy("");
        partial.deployment_id = "deployment".into();
        partial.principal_id = "aa".repeat(32);
        assert!(InitialUploadPolicy::from_authenticated(
            "token",
            "https://hub.test",
            &partial,
            CURRENT_SIGNED_AT
        )
        .is_err());
    }

    #[test]
    fn required_policy_reconciles_same_bearer_actor_owner_and_mode() {
        let mut identity = who_policy("direct_required");
        identity.deployment_id = "deployment".into();
        identity.principal_id = "aa".repeat(32);
        let proof = InitialUploadPolicy::from_authenticated(
            "token-a",
            "https://hub.test",
            &identity,
            CURRENT_SIGNED_AT,
        )
        .unwrap();
        let capabilities = actor_capabilities(&identity.principal_id);
        let shared = std::cell::RefCell::new("token-a".to_string());
        let captured = shared.borrow().clone();
        *shared.borrow_mut() = "token-b".into();

        proof
            .dispatch_with(
                &captured,
                "https://hub.test",
                CURRENT_SIGNED_AT,
                false,
                |bearer| assert_eq!(bearer, "token-a"),
            )
            .unwrap();
        proof
            .validate_discovery(&capabilities, &capabilities.target, CURRENT_SIGNED_AT)
            .unwrap();
        let changed = actor_capabilities(&"bb".repeat(32));
        assert!(proof
            .validate_discovery(&changed, &changed.target, CURRENT_SIGNED_AT)
            .is_err());
        let mut legacy = capabilities.clone();
        legacy.transfer_mode = DirectAdvertisedTransferMode::Legacy;
        assert!(proof
            .validate_discovery(&legacy, &legacy.target, CURRENT_SIGNED_AT)
            .is_err());
        let other_owner = DirectCapabilitiesTarget::Cache {
            cache_id: "another".into(),
        };
        assert!(proof
            .validate_discovery(&capabilities, &other_owner, CURRENT_SIGNED_AT)
            .is_err());
    }

    #[test]
    fn shared_legacy_to_required_refresh_sends_no_legacy_control_or_body() {
        let legacy = InitialUploadPolicy::from_authenticated(
            "token-a",
            "https://hub.test",
            &who_policy("legacy"),
            CURRENT_SIGNED_AT,
        )
        .unwrap();
        let mut identity_b = who_policy("direct_required");
        identity_b.deployment_id = "deployment".into();
        identity_b.principal_id = "bb".repeat(32);
        let required_b = InitialUploadPolicy::from_authenticated(
            "token-b",
            "https://hub.test",
            &identity_b,
            CURRENT_SIGNED_AT,
        )
        .unwrap();
        let dispatches = std::cell::Cell::new(0);

        for proof in [&legacy, &required_b] {
            assert!(proof
                .dispatch_with(
                    "token-b",
                    "https://hub.test",
                    CURRENT_SIGNED_AT,
                    true,
                    |_| dispatches.set(dispatches.get() + 1)
                )
                .is_err());
        }

        assert_eq!(dispatches.get(), 0);
        assert!(!legacy.matches("token-b", "https://hub.test", CURRENT_SIGNED_AT));
    }

    #[test]
    fn policy_cache_requires_exact_origin_token_and_actual_advertised_deadline() {
        let identity = who_policy("legacy");
        let proof = InitialUploadPolicy::from_authenticated(
            "memory-only-bearer",
            "https://hub.test",
            &identity,
            CURRENT_SIGNED_AT,
        )
        .unwrap();
        let expiry = identity.access_expires_at as u64;

        assert!(proof.matches("memory-only-bearer", "https://hub.test", expiry - 1));
        assert!(!proof.matches("memory-only-bearer", "https://other.test", expiry - 1));
        assert!(!proof.matches("memory-only-bearer", "https://hub.test", expiry));
        assert!(!proof.matches("another-bearer", "https://hub.test", expiry - 1));
        assert!(!format!("{proof:?}").contains("memory-only-bearer"));
        assert!(InitialUploadPolicy::from_authenticated(
            "token",
            "https://hub.test",
            &identity,
            expiry
        )
        .is_err());
        let mut invalid = identity;
        invalid.access_expires_at = -1;
        assert!(InitialUploadPolicy::from_authenticated(
            "token",
            "https://hub.test",
            &invalid,
            CURRENT_SIGNED_AT
        )
        .is_err());
    }

    #[test]
    fn streaming_source_checksums_match_vectors_and_reject_changed_size() {
        let mut source = SourceAccumulator::new(3).unwrap();
        source.push(b"a").unwrap();
        source.push(b"bc").unwrap();
        let (sha, parts) = source.finish().unwrap();
        assert_eq!(
            sha,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(parts[0].md5, "kAFQmDzST7DWlj99KOF/cg==");
        assert_eq!(
            parts[0]
                .descriptor(DirectChecksumAlgorithm::Sha256)
                .unwrap()
                .sha256,
            sha
        );
        assert!(SourceAccumulator::new(4).unwrap().finish().is_err());
        assert!(SourceAccumulator::new(2).unwrap().push(b"abc").is_err());
        assert!(SourceAccumulator::new(MAX_DIRECT_OBJECT_BYTES + 1).is_err());
    }

    #[test]
    fn empty_and_multi_part_sources_use_exact_geometry_without_whole_file_buffer() {
        let (sha, parts) = SourceAccumulator::new(0).unwrap().finish().unwrap();
        assert_eq!(
            sha,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(parts.is_empty());
        let mut source = SourceAccumulator::new(BROWSER_PART_BYTES + 1).unwrap();
        for _ in 0..BROWSER_PART_BYTES as usize / SOURCE_CHUNK_BYTES {
            source.push(&[7; SOURCE_CHUNK_BYTES]).unwrap();
        }
        source.push(&[9]).unwrap();
        let (_, parts) = source.finish().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].offset, BROWSER_PART_BYTES);
        assert_eq!(parts[1].size, 1);
        assert!(SourceAccumulator::new(SOURCE_CHUNK_BYTES as u64 + 1)
            .unwrap()
            .push(&vec![0; SOURCE_CHUNK_BYTES + 1])
            .is_err());
    }

    #[test]
    fn object_policy_accepts_managed_empty_and_refuses_external_empty_and_oversize() {
        let mut capabilities = actor_capabilities(&"aa".repeat(32));

        validate_object_size(&capabilities, 0).unwrap();
        validate_object_size(&capabilities, MAX_DIRECT_OBJECT_BYTES).unwrap();
        assert!(validate_object_size(&capabilities, MAX_DIRECT_OBJECT_BYTES + 1).is_err());

        capabilities.minimum_object_bytes = WireInteger::new(1);

        let error = validate_object_size(&capabilities, 0).unwrap_err();
        assert!(error.contains("The direct upload minimum file size is 1 bytes"));
        validate_object_size(&capabilities, 1).unwrap();
        validate_object_size(&capabilities, MAX_DIRECT_OBJECT_BYTES).unwrap();
        assert!(validate_object_size(&capabilities, MAX_DIRECT_OBJECT_BYTES + 1).is_err());
    }

    #[test]
    fn actor_proof_pins_every_reviewed_limit_and_profile_except_expiry() {
        let original = actor_capabilities(&"aa".repeat(32));
        for change in 0..7 {
            let mut renewed = original.clone();
            renewed.valid_until = WireInteger::new(original.valid_until.get() + 60);
            match change {
                0 => {}
                1 => renewed.minimum_object_bytes = WireInteger::new(1),
                2 => renewed.maximum_object_bytes = WireInteger::new(1024),
                3 => renewed.minimum_part_bytes = WireInteger::new(BROWSER_PART_BYTES),
                4 => renewed.maximum_batch_items = 32,
                5 => renewed.config_generation = WireInteger::new(2),
                _ => renewed.profiles[0].profile_fingerprint = "bb".repeat(32),
            }
            let proof = DirectActorProof::from_authenticated(
                "renewed-bearer",
                &original.deployment_id,
                &original.principal_id,
                &original.target,
                &renewed,
                CURRENT_SIGNED_AT,
            )
            .unwrap();

            assert_eq!(proof.validate_capabilities(&original).is_ok(), change == 0);
            // A cached proof must pass the same pin check as a fresh proof.
            assert_eq!(
                proof.clone().validate_capabilities(&original).is_ok(),
                change == 0
            );
        }
    }

    #[test]
    fn http_renewal_with_raised_minimum_sends_no_original_empty_begin_replay() {
        use std::io::{Read as _, Write as _};
        use std::net::{TcpListener, TcpStream};

        fn exchange(
            address: std::net::SocketAddr,
            path: &str,
            bearer: &str,
            body: &[u8],
        ) -> (u16, Vec<u8>) {
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            write!(stream, "POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {bearer}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(body).unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).unwrap();
            let end = response
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .unwrap();
            let status = std::str::from_utf8(&response[..end])
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse()
                .unwrap();
            (status, response[end + 4..].to_vec())
        }

        for renewed_bearer in ["original-bearer", "renewed-bearer"] {
            let original = actor_capabilities(&"aa".repeat(32));
            let mut renewed = original.clone();
            renewed.minimum_object_bytes = WireInteger::new(1);
            let reply = encode_direct_control(&renewed).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let worker = std::thread::spawn(move || {
                let mut requests = Vec::new();
                for (status, body) in [(401, Vec::new()), (200, reply)] {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut request = Vec::new();
                    loop {
                        let mut bytes = [0u8; 4096];
                        let count = stream.read(&mut bytes).unwrap();
                        assert!(count > 0);
                        request.extend_from_slice(&bytes[..count]);
                        assert!(request.len() <= MAX_DIRECT_CONTROL_BYTES + 8192);
                        let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                        else {
                            continue;
                        };
                        let length: usize = std::str::from_utf8(&request[..end])
                            .unwrap()
                            .lines()
                            .find_map(|line| line.strip_prefix("Content-Length: "))
                            .unwrap()
                            .parse()
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                    requests.push(request);
                    write!(stream, "HTTP/1.1 {status} Reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                    stream.write_all(&body).unwrap();
                }
                listener.set_nonblocking(true).unwrap();
                assert_eq!(
                    listener.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                requests
            });
            let mut retained = head();
            retained.deployment_id = original.deployment_id.clone();
            retained.principal_id = original.principal_id.clone();
            retained.intent.byte_size = WireInteger::new(0);
            retained.intent.expected_sha256 = hex::encode(Sha256::digest(b""));
            let before = retained.clone();
            let begin = DirectBeginBatch {
                operation_id: operation_id("begin", &retained.run_nonce, &retained.intent).unwrap(),
                items: vec![retained.intent.clone()],
            };
            let body = encode_direct_control(&begin).unwrap();
            let proof = DirectActorProof::from_authenticated(
                "original-bearer",
                &original.deployment_id,
                &original.principal_id,
                &original.target,
                &original,
                CURRENT_SIGNED_AT,
            )
            .unwrap();
            proof.validate_capabilities(&original).unwrap();
            let initial = proof
                .dispatch_with(
                    "original-bearer",
                    &original.deployment_id,
                    &original.principal_id,
                    &original.target,
                    CURRENT_SIGNED_AT,
                    |bearer| {
                        exchange(
                            address,
                            aos_proto_types::DIRECT_UPLOAD_SERVICE_BEGIN_BATCH_PATH,
                            bearer,
                            &body,
                        )
                    },
                )
                .unwrap();
            assert_eq!(initial.0, 401);
            let request = encode_direct_control(&DirectGetCapabilities {
                target: original.target.clone(),
            })
            .unwrap();
            let (status, bytes) = exchange(
                address,
                aos_proto_types::DIRECT_UPLOAD_SERVICE_GET_CAPABILITIES_PATH,
                renewed_bearer,
                &request,
            );
            assert_eq!(status, 200);
            let discovered: DirectUploadCapabilities = decode_direct_control(&bytes).unwrap();
            let renewed_proof = DirectActorProof::from_authenticated(
                renewed_bearer,
                &original.deployment_id,
                &original.principal_id,
                &original.target,
                &discovered,
                CURRENT_SIGNED_AT,
            )
            .unwrap();

            let replay = renewed_proof
                .validate_capabilities(&original)
                .and_then(|()| {
                    renewed_proof.dispatch_with(
                        renewed_bearer,
                        &original.deployment_id,
                        &original.principal_id,
                        &original.target,
                        CURRENT_SIGNED_AT,
                        |bearer| {
                            exchange(
                                address,
                                aos_proto_types::DIRECT_UPLOAD_SERVICE_BEGIN_BATCH_PATH,
                                bearer,
                                &body,
                            )
                        },
                    )
                });

            assert!(replay.is_err());
            assert_eq!(retained, before);
            let captured = worker.join().unwrap();
            assert_eq!(captured.len(), 2);
            let original_request = String::from_utf8(captured[0].clone()).unwrap();
            assert_eq!(
                original_request
                    .split_once("\r\n\r\n")
                    .unwrap()
                    .1
                    .as_bytes(),
                body
            );
            assert!(String::from_utf8(captured[1].clone())
                .unwrap()
                .contains(&format!("Authorization: Bearer {renewed_bearer}")));
        }
    }

    fn head() -> ResumeHead {
        ResumeHead {
            scope: "aa".repeat(32),
            run_nonce: "bb".repeat(32),
            deployment_id: "deployment".into(),
            principal_id: "cc".repeat(32),
            intent: DirectUploadIntent {
                version: 1,
                client_operation_id: "dd".repeat(32),
                target: DirectUploadTarget::CacheObject {
                    cache_id: "cache".into(),
                    path: "object.nar".into(),
                },
                expected_sha256: "ee".repeat(32),
                byte_size: WireInteger::new(3),
                part_size: WireInteger::new(BROWSER_PART_BYTES),
                dependency_phase: DirectDependencyPhase::Content,
                transfer_mode: DirectTransferMode::DirectRequired,
            },
            session: None,
            complete: None,
        }
    }

    fn checkpoint() -> PartCheckpoint {
        let mut source = SourceAccumulator::new(3).unwrap();
        source.push(b"abc").unwrap();
        let (_, parts) = source.finish().unwrap();
        PartCheckpoint {
            placement: DirectPlacementRef {
                placement_id: WireInteger::new(1),
                placement_fingerprint: "11".repeat(32),
                placement_resource_version: WireInteger::new(2),
                write_spec_version: WireInteger::new(3),
                binding_id: WireInteger::new(4),
                binding_resource_version: WireInteger::new(5),
                binding_write_revision: WireInteger::new(6),
                profile_fingerprint: "22".repeat(32),
                private_policy_digest: "33".repeat(32),
                checksum_algorithm: DirectChecksumAlgorithm::Md5,
            },
            original: parts[0].clone(),
            attempt: 1,
            receipt: None,
            server_observed: None,
        }
    }

    #[test]
    fn atomic_checkpoint_merge_preserves_original_complete_across_stale_writers() {
        let stale = head();
        let mut committed = stale.clone();
        committed.complete = Some(DirectCompleteRequest {
            session: DirectSessionRef {
                session_id: "session".into(),
                logical_fingerprint: "ff".repeat(32),
            },
            operation_id: "44".repeat(32),
            expected_resource_version: WireInteger::new(7),
            manifests: vec![],
        });
        assert_eq!(
            stale
                .clone()
                .merge(Some(committed.clone()))
                .unwrap()
                .complete,
            committed.complete
        );
        let mut changed = committed.clone();
        changed.complete.as_mut().unwrap().expected_resource_version = WireInteger::new(8);
        assert!(changed.merge(Some(committed.clone())).is_err());
        assert!(committed.merge(None).is_err());
        let mut another_run = stale.clone();
        another_run.run_nonce = "99".repeat(32);
        assert!(another_run.merge(Some(stale)).is_err());
    }

    #[test]
    fn atomic_part_merge_keeps_monotonic_attempt_and_positive_receipt() {
        let stale = checkpoint();
        let mut acknowledged = stale.clone();
        acknowledged.attempt = 3;
        let observed = DirectManifestPart {
            part: acknowledged
                .original
                .descriptor(DirectChecksumAlgorithm::Md5)
                .unwrap(),
            etag: "\"original\"".into(),
        };
        acknowledged.receipt = Some(PartReceipt {
            grant_id: "44".repeat(32),
            grant_revision: WireInteger::new(2),
            observed: observed.clone(),
        });
        acknowledged.server_observed = Some(observed);
        let merged = stale.clone().merge(Some(acknowledged.clone())).unwrap();
        assert_eq!(merged, acknowledged);
        let mut changed = acknowledged.clone();
        changed.receipt.as_mut().unwrap().grant_id = "55".repeat(32);
        assert!(changed.merge(Some(acknowledged.clone())).is_err());
        let mut changed = stale;
        changed.original.sha256 = "66".repeat(32);
        assert!(changed.merge(Some(acknowledged)).is_err());
    }
    #[test]
    fn malformed_retained_checksums_fail_before_constructing_a_grant_descriptor() {
        let mut part = checkpoint().original;
        part.sha256 = "ff".repeat(33);
        assert!(part.descriptor(DirectChecksumAlgorithm::Sha256).is_err());
        let mut part = checkpoint().original;
        part.md5 = "A".repeat(24);
        assert!(part.descriptor(DirectChecksumAlgorithm::Md5).is_err());
    }

    #[test]
    fn session_merge_retains_committed_and_higher_revision_history() {
        let mut old = head();
        let original = DirectSessionStatus {
            session: DirectSessionRef {
                session_id: "session".into(),
                logical_fingerprint: "77".repeat(32),
            },
            resource_version: WireInteger::new(9),
            intent: old.intent.clone(),
            placements: vec![checkpoint().placement],
            state: DirectSessionState::Committed,
            parts: vec![],
            next_cursor: None,
            outstanding_grants: false,
        };
        old.session = Some(original.clone());
        let mut stale = old.clone();
        stale.session.as_mut().unwrap().state = DirectSessionState::Active;
        stale.session.as_mut().unwrap().resource_version = WireInteger::new(8);
        assert_eq!(
            stale.clone().merge(Some(old.clone())).unwrap().session,
            Some(original)
        );
        assert!(stale.merge(None).is_err());
        let mut changed = old.clone();
        changed.session.as_mut().unwrap().placements[0].binding_write_revision =
            WireInteger::new(10);
        assert!(changed.merge(Some(old)).is_err());
    }
    #[test]
    fn stable_operation_commitments_bind_run_and_original_request() {
        let original = head();
        let first = operation_id("begin", &original.run_nonce, &original.intent).unwrap();
        assert_eq!(
            first,
            operation_id("begin", &original.run_nonce, &original.intent).unwrap()
        );
        assert_ne!(
            first,
            operation_id("complete", &original.run_nonce, &original.intent).unwrap()
        );
        assert_ne!(
            first,
            operation_id("begin", &"99".repeat(32), &original.intent).unwrap()
        );
        let mut changed = original.intent;
        changed.expected_sha256 = "88".repeat(32);
        assert_ne!(
            first,
            operation_id("begin", &original.run_nonce, &changed).unwrap()
        );
    }
    const CURRENT_SIGNED_AT: u64 = 1790683200;

    fn dated_grant() -> (PartDispatchContext, DirectPartGrant) {
        let record = checkpoint();
        let retained = PartDispatchContext {
            session: DirectSessionRef {
                session_id: "session".into(),
                logical_fingerprint: "77".repeat(32),
            },
            placement: record.placement.clone(),
            intent: head().intent,
            part: record
                .original
                .descriptor(DirectChecksumAlgorithm::Md5)
                .unwrap(),
        };
        let grant = DirectPartGrant {
            session_id: retained.session.session_id.clone(), logical_fingerprint: retained.session.logical_fingerprint.clone(),
            placement: retained.placement.clone(), grant_id: "88".repeat(32), grant_revision: WireInteger::new(1),
            part: retained.part.clone(), method: "PUT".into(),
            url: format!("https://provider.test/bucket/private?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=access%2F20260929%2Fauto%2Fs3%2Faws4_request&X-Amz-Date=20260929T120000Z&X-Amz-Expires=120&X-Amz-Signature={}&X-Amz-SignedHeaders=content-length%3Bcontent-md5%3Bhost&partNumber=1&uploadId=retained-provider-session", "99".repeat(32)),
            required_headers: vec![DirectRequiredHeader { name: "content-length".into(), value: "3".into() }, DirectRequiredHeader { name: "content-md5".into(), value: retained.part.checksum.value.clone() }],
            expires_at: WireInteger::new(CURRENT_SIGNED_AT + 120),
        };
        (retained, grant)
    }

    #[test]
    fn current_dated_grant_admission_uses_actual_clock_and_dispatches_exact_tuple() {
        let (retained, grant) = dated_grant();
        // The old driver epoch-zero probe rejects this ordinary positive date.
        assert!(grant
            .validate_for(
                &retained.session,
                &retained.placement,
                &retained.intent,
                &retained.part,
                0,
                0
            )
            .is_err());
        assert_eq!(
            retained.classify(&grant, CURRENT_SIGNED_AT + 1).unwrap(),
            GrantLifetime::Ready
        );
        let dispatched = std::cell::Cell::new(0);
        retained
            .dispatch_with(
                &grant,
                || Ok(CURRENT_SIGNED_AT + 1),
                || dispatched.set(dispatched.get() + 1),
            )
            .unwrap();
        assert_eq!(dispatched.get(), 1);
    }

    #[test]
    fn grant_expiry_during_source_read_or_queue_prevents_first_fetch() {
        let (retained, grant) = dated_grant();
        assert_eq!(
            retained.classify(&grant, CURRENT_SIGNED_AT + 1).unwrap(),
            GrantLifetime::Ready
        );
        // After source-read/queue awaits, first dispatch must observe this later
        // clock, rather than reuse the earlier admission-time observation.
        for later in [CURRENT_SIGNED_AT + 119, CURRENT_SIGNED_AT + 120] {
            let dispatched = std::cell::Cell::new(0);
            assert!(retained
                .dispatch_with(&grant, || Ok(later), || dispatched.set(1))
                .is_err());
            assert_eq!(dispatched.get(), 0);
        }
    }

    #[test]
    fn final_clock_recheck_refuses_expiry_rollback_and_overflow_after_validation() {
        let (retained, grant) = dated_grant();
        for times in [
            [CURRENT_SIGNED_AT + 118, CURRENT_SIGNED_AT + 119],
            [CURRENT_SIGNED_AT + 5, CURRENT_SIGNED_AT + 4],
            [CURRENT_SIGNED_AT + 1, u64::MAX],
        ] {
            let mut observations = times.into_iter();
            let dispatched = std::cell::Cell::new(0);
            assert!(retained
                .dispatch_with(
                    &grant,
                    || Ok(observations.next().unwrap()),
                    || dispatched.set(1)
                )
                .is_err());
            assert_eq!(dispatched.get(), 0);
        }
    }

    #[test]
    fn historical_expiry_classification_preserves_scope_without_dispatch_authority() {
        let (retained, grant) = dated_grant();
        assert_eq!(
            retained.classify(&grant, CURRENT_SIGNED_AT + 119).unwrap(),
            GrantLifetime::Expiring
        );
        assert_eq!(
            retained.classify(&grant, CURRENT_SIGNED_AT + 120).unwrap(),
            GrantLifetime::Expired
        );
        let mut changed = grant.clone();
        changed.logical_fingerprint = "aa".repeat(32);
        assert!(retained
            .classify(&changed, CURRENT_SIGNED_AT + 120)
            .is_err());
        let dispatched = std::cell::Cell::new(0);
        assert!(retained
            .dispatch_with(&grant, || Ok(CURRENT_SIGNED_AT + 120), || dispatched.set(1))
            .is_err());
        assert_eq!(dispatched.get(), 0);
        let mut changed = retained;
        changed.placement.binding_write_revision = WireInteger::new(100);
        assert!(changed
            .dispatch_with(&grant, || Ok(CURRENT_SIGNED_AT + 1), || dispatched.set(1))
            .is_err());
        assert_eq!(dispatched.get(), 0);
    }
    fn actor_capabilities(principal: &str) -> DirectUploadCapabilities {
        let reference = checkpoint().placement;
        DirectUploadCapabilities {
            target: DirectCapabilitiesTarget::Cache {
                cache_id: "cache".into(),
            },
            requested_delivery_url: None,
            deployment_id: "deployment".into(),
            principal_id: principal.into(),
            version: 1,
            capability: DIRECT_UPLOAD_CAPABILITY.into(),
            transfer_mode: DirectAdvertisedTransferMode::DirectRequired,
            config_generation: WireInteger::new(1),
            valid_until: WireInteger::new(CURRENT_SIGNED_AT + 300),
            maximum_control_bytes: MAX_DIRECT_CONTROL_BYTES as u32,
            maximum_batch_items: MAX_DIRECT_BATCH_ITEMS as u32,
            maximum_batch_parts: MAX_DIRECT_BATCH_PARTS as u32,
            maximum_object_bytes: WireInteger::new(MAX_DIRECT_OBJECT_BYTES),
            minimum_object_bytes: WireInteger::new(0),
            minimum_part_bytes: WireInteger::new(MIN_DIRECT_PART_BYTES),
            maximum_part_bytes: WireInteger::new(MAX_DIRECT_PART_BYTES),
            profiles: vec![DirectProviderProfile {
                placement_id: reference.placement_id,
                placement_resource_version: reference.placement_resource_version,
                write_spec_version: reference.write_spec_version,
                binding_id: reference.binding_id,
                binding_resource_version: reference.binding_resource_version,
                binding_write_revision: reference.binding_write_revision,
                checksum_algorithm: reference.checksum_algorithm,
                provider_origin: "https://provider.test".into(),
                profile_fingerprint: reference.profile_fingerprint,
                private_policy_digest: reference.private_policy_digest,
            }],
        }
    }

    #[test]
    fn retained_actor_a_with_shared_bearer_b_dispatches_no_mutation() {
        let principal_a = "aa".repeat(32);
        let principal_b = "bb".repeat(32);
        let capabilities = actor_capabilities(&principal_a);
        let proof = DirectActorProof::from_authenticated(
            "token-a",
            "deployment",
            &principal_a,
            &capabilities.target,
            &capabilities,
            CURRENT_SIGNED_AT,
        )
        .unwrap();
        let mutations = std::cell::Cell::new(0);
        assert!(proof
            .dispatch_with(
                "token-b",
                "deployment",
                &principal_a,
                &capabilities.target,
                CURRENT_SIGNED_AT + 1,
                |_| mutations.set(1)
            )
            .is_err());
        assert_eq!(mutations.get(), 0);
        // A fresh readback forB cannot establish actorA's immutable scope.
        let actor_b = actor_capabilities(&principal_b);
        assert!(DirectActorProof::from_authenticated(
            "token-b",
            "deployment",
            &principal_a,
            &actor_b.target,
            &actor_b,
            CURRENT_SIGNED_AT + 1
        )
        .is_err());
        assert_eq!(mutations.get(), 0);
    }

    #[test]
    fn concurrent_shared_refresh_cannot_replace_the_proven_bearer_snapshot() {
        let principal = "aa".repeat(32);
        let capabilities = actor_capabilities(&principal);
        let shared = std::cell::RefCell::new("token-a".to_string());
        let captured = shared.borrow().clone();
        let proof = DirectActorProof::from_authenticated(
            &captured,
            "deployment",
            &principal,
            &capabilities.target,
            &capabilities,
            CURRENT_SIGNED_AT,
        )
        .unwrap();
        // Another client refreshes while the captured token's proof is awaited.
        *shared.borrow_mut() = "token-b".into();
        let observed = proof
            .dispatch_with(
                &captured,
                "deployment",
                &principal,
                &capabilities.target,
                CURRENT_SIGNED_AT + 1,
                str::to_owned,
            )
            .unwrap();
        assert_eq!(observed, "token-a");
        let mutations = std::cell::Cell::new(0);
        assert!(proof
            .dispatch_with(
                &shared.borrow(),
                "deployment",
                &principal,
                &capabilities.target,
                CURRENT_SIGNED_AT + 1,
                |_| mutations.set(1)
            )
            .is_err());
        assert_eq!(mutations.get(), 0);
    }

    #[test]
    fn memory_actor_proofs_expire_and_redact_token_scope() {
        let principal = "aa".repeat(32);
        let capabilities = actor_capabilities(&principal);
        let proof = DirectActorProof::from_authenticated(
            "secret-token-canary",
            "deployment",
            &principal,
            &capabilities.target,
            &capabilities,
            CURRENT_SIGNED_AT,
        )
        .unwrap();
        assert!(!format!("{proof:?}").contains("canary"));
        assert!(!proof.matches(
            "secret-token-canary",
            "deployment",
            &principal,
            &capabilities.target,
            CURRENT_SIGNED_AT + 300
        ));
        assert!(!proof.matches(
            "secret-token-canary",
            "different",
            &principal,
            &capabilities.target,
            CURRENT_SIGNED_AT + 1
        ));
        let changed = DirectCapabilitiesTarget::Cache {
            cache_id: "different".into(),
        };
        assert!(!proof.matches(
            "secret-token-canary",
            "deployment",
            &principal,
            &changed,
            CURRENT_SIGNED_AT + 1
        ));
    }
}
