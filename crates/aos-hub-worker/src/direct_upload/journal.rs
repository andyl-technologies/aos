//! Original admission, effect and attempt identities retained without expiry.
//!
//! Each effect and part is a separate bounded record. An unresolved dispatched
//! mutation permanently fences its original owner. Only an exact immutable read
//! can acquire another attempt; a new attempt never changes the business effect.
//!
//! ```text
//! admission/v1 -> exact original admission
//! effect/v1/<operation> -> original intent + pending attempt or terminal receipt
//! attempt/v1/<operation>/<nonce> -> exact original dispatch observation
//! part/v1/<placement>/<number> -> immutable grant + optional reported part
//! ```

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Allows inspection of an old script's original without authorizing new effects.
pub(crate) fn sdk_probe_original_allows(
    original: &DirectHostedSdkProbeOriginal,
    run_id: &str,
    account_id: &str,
    bucket_name: &str,
    current_script: &str,
    phase: &str,
) -> bool {
    original.run_id == run_id
        && original.account_id == account_id
        && original.bucket_name == bucket_name
        && (phase == "status" || original.script_version == current_script)
}

/// One bounded exact effect independently of transport retries.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Effect {
    pub(crate) operation_id: String,
    pub(crate) intent_digest: String,
    pub(crate) immutable_read: bool,
    pub(crate) pending_attempt: Option<String>,
    pub(crate) terminal: Option<serde_json::Value>,
    pub(crate) attempt_count: u32,
}

impl Effect {
    pub(crate) fn new<T: Serialize>(
        operation_id: String,
        intent: &T,
        immutable_read: bool,
    ) -> Result<Self> {
        ensure!(
            valid_direct_digest(&operation_id),
            "direct effect identity invalid"
        );
        Ok(Self {
            operation_id,
            intent_digest: digest(intent)?,
            immutable_read,
            pending_attempt: None,
            terminal: None,
            attempt_count: 0,
        })
    }

    /// Returns historical receipt first; an unknown mutation never redispatches.
    pub(crate) fn begin(
        &self,
        expected: &Self,
        nonce: &str,
    ) -> Result<(Self, Option<serde_json::Value>)> {
        ensure!(
            self.operation_id == expected.operation_id
                && self.intent_digest == expected.intent_digest
                && self.immutable_read == expected.immutable_read
                && valid_direct_digest(nonce),
            "direct effect original differs"
        );
        if let Some(terminal) = &self.terminal {
            return Ok((self.clone(), Some(terminal.clone())));
        }
        ensure!(
            self.pending_attempt.is_none() || self.immutable_read,
            "direct effect outcome unknown"
        );
        ensure!(
            self.attempt_count < 100_000,
            "direct effect attempts exhausted"
        );
        let mut next = self.clone();
        next.pending_attempt = Some(nonce.into());
        next.attempt_count += 1;
        Ok((next, None))
    }

    pub(crate) fn finish(&self, nonce: &str, terminal: serde_json::Value) -> Result<Self> {
        ensure!(
            self.pending_attempt.as_deref() == Some(nonce),
            "direct effect attempt differs"
        );
        ensure!(
            encode_direct_control(&terminal)?.len() <= 64 * 1024,
            "direct terminal receipt exceeds bound"
        );
        if let Some(existing) = &self.terminal {
            ensure!(existing == &terminal, "direct terminal receipt changed");
            return Ok(self.clone());
        }
        let mut next = self.clone();
        next.terminal = Some(terminal);
        next.pending_attempt = None;
        Ok(next)
    }
}

/// Exact delegated part identity and immutable first exposure horizon.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PartRecord {
    pub(crate) session: DirectSessionRef,
    pub(crate) placement: DirectPlacementRef,
    pub(crate) grant_id: String,
    pub(crate) grant_revision: WireInteger,
    pub(crate) part: DirectPart,
    pub(crate) issued_at: WireInteger,
    pub(crate) expires_at: WireInteger,
    pub(crate) observed: Option<DirectManifestPart>,
}

impl PartRecord {
    pub(crate) fn validate_report(&self, report: &DirectPartReport) -> Result<()> {
        ensure!(
            report.session == self.session
                && report.placement == self.placement
                && report.grant_id == self.grant_id
                && report.grant_revision == self.grant_revision
                && report.observed.part == self.part
                && valid_direct_etag(&report.observed.etag)
                && self
                    .observed
                    .as_ref()
                    .is_none_or(|value| value == &report.observed),
            "direct reported original part differs"
        );
        Ok(())
    }
}

pub(crate) fn digest<T: Serialize>(value: &T) -> Result<String> {
    let bytes = encode_direct_control(value)?;
    let mut hash = Sha256::new();
    hash.update(b"aos.direct-upload.broker-journal.v1\0");
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_script_probe_inspection_never_authorizes_an_effect() {
        let original = DirectHostedSdkProbeOriginal {
            run_id: "11".repeat(32),
            account_id: "account".into(),
            bucket_name: "bucket".into(),
            script_version: "old-script".into(),
            colo: "AAA".into(),
        };
        let allows = |phase| {
            sdk_probe_original_allows(
                &original,
                &original.run_id,
                "account",
                "bucket",
                "new-script",
                phase,
            )
        };

        assert!(allows("status"));
        for phase in ["start", "finish", "cleanup"] {
            assert!(!allows(phase));
        }
        assert!(!sdk_probe_original_allows(
            &original,
            &original.run_id,
            "other-account",
            "bucket",
            "new-script",
            "status"
        ));
        assert!(!sdk_probe_original_allows(
            &original,
            &original.run_id,
            "account",
            "other-bucket",
            "new-script",
            "status"
        ));
        assert!(!sdk_probe_original_allows(
            &original,
            "22",
            "account",
            "bucket",
            "new-script",
            "status"
        ));
    }

    #[test]
    fn eviction_and_elapsed_time_never_clear_an_unknown_mutation() {
        let original = Effect::new("11".repeat(32), &"create-exact-upload", false).unwrap();
        let (dispatched, _) = original.begin(&original, &"22".repeat(32)).unwrap();
        let persisted = serde_json::to_vec(&dispatched).unwrap();
        let restored: Effect = serde_json::from_slice(&persisted).unwrap();

        assert!(restored.begin(&original, &"33".repeat(32)).is_err());
        let terminal = serde_json::json!({"upload_id":"provider-original"});
        let acknowledged = restored.finish(&"22".repeat(32), terminal.clone()).unwrap();
        let (_, replay) = acknowledged.begin(&original, &"33".repeat(32)).unwrap();
        assert_eq!(replay, Some(terminal));
    }

    #[test]
    fn immutable_read_recovery_changes_attempt_without_changing_original() {
        let original = Effect::new("11".repeat(32), &"closed-incarnation", true).unwrap();
        let (first, _) = original.begin(&original, &"22".repeat(32)).unwrap();
        let (second, _) = first.begin(&original, &"33".repeat(32)).unwrap();

        assert_eq!(second.attempt_count, 2);
        assert!(second
            .finish(&"22".repeat(32), serde_json::json!({}))
            .is_err());
        let changed = Effect::new("11".repeat(32), &"replacement-incarnation", true).unwrap();
        assert!(second.begin(&changed, &"44".repeat(32)).is_err());
    }
}
