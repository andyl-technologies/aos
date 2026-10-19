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

/// Acquires one journal turn and checks its original transport deadline.
///
/// # Errors
/// Returns an error when the clock is unavailable or the transport has expired.
pub(crate) async fn acquire_turn<'a>(
    gate: &'a futures_util::lock::Mutex<()>,
    clock: impl FnOnce() -> Result<u64>,
    expires_at: WireInteger,
) -> Result<(futures_util::lock::MutexGuard<'a, ()>, u64)> {
    let permit = gate.lock().await;
    // A queued request must not compare its earlier timestamp with a clock
    // floor advanced by another turn, or use a deadline that expired in queue.
    let now = clock()?;
    ensure!(
        now < expires_at.get() && expires_at.get() <= now.saturating_add(30),
        "direct journal transport expired"
    );
    Ok((permit, now))
}

/// Classifies journal refusals without disclosing original or provider values.
pub(crate) fn refusal_category(error: &anyhow::Error) -> &'static str {
    match error.root_cause().to_string().as_str() {
        "direct durable clock regressed" => "clock_regressed",
        "direct journal transport expired" => "transport_expired",
        "direct original admission changed" => "admission_changed",
        "direct original admission absent" => "admission_absent",
        "direct grant absent" => "grant_absent",
        "direct reported original part differs" => "report_changed",
        "direct reports frozen" => "reports_frozen",
        _ => "other",
    }
}

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

/// Bounds a provider capability separately from its issuing control request.
///
/// UploadPart capabilities can outlive the foreground invocation. Their exact
/// horizons remain in the part journal and physical guard until closure.
///
/// # Errors
/// Returns an error when the admission or configured lifetime has expired.
pub(crate) fn grant_expiry(
    issued_at: u64,
    admission_expires_at: u64,
    maximum_lifetime: u64,
) -> Result<u64> {
    let expires_at = admission_expires_at.min(issued_at.saturating_add(maximum_lifetime));
    ensure!(expires_at > issued_at, "direct grant lifetime exhausted");
    Ok(expires_at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_categories_never_include_unrecognized_error_values() {
        let error = anyhow::anyhow!("direct durable clock regressed").context("journal turn");
        assert_eq!(refusal_category(&error), "clock_regressed");

        let private_error = anyhow::anyhow!("provider https://example.test/?private=value");
        assert_eq!(refusal_category(&private_error), "other");
    }

    #[tokio::test]
    async fn queued_turn_observes_the_clock_after_acquiring_the_gate() {
        let gate = futures_util::lock::Mutex::new(());
        let held = gate.lock().await;
        let now = std::cell::Cell::new(100);
        let turn = acquire_turn(&gate, || Ok(now.get()), WireInteger::new(130));
        futures_util::pin_mut!(turn);

        assert!(futures_util::poll!(turn.as_mut()).is_pending());
        now.set(101);
        drop(held);
        let (_permit, observed) = turn.await.unwrap();

        assert_eq!(observed, 101);
    }

    #[tokio::test]
    async fn transport_expiring_while_queued_is_refused() {
        let gate = futures_util::lock::Mutex::new(());
        let held = gate.lock().await;
        let now = std::cell::Cell::new(100);
        let turn = acquire_turn(&gate, || Ok(now.get()), WireInteger::new(101));
        futures_util::pin_mut!(turn);

        assert!(futures_util::poll!(turn.as_mut()).is_pending());
        now.set(102);
        drop(held);

        assert!(turn.await.is_err());
    }

    #[test]
    fn provider_grants_cover_client_dispatch_without_extending_admission() {
        let issued_at = 1_790_000_000;
        let admission = crate::direct_guard::fixture::reservation("fixture", "object").admission;
        let session = DirectSessionRef {
            session_id: admission.session_id.clone(),
            logical_fingerprint: admission.logical_fingerprint.clone(),
        };
        let placement = admission.placements[0].public_ref("fixture").unwrap();
        let part = DirectPart {
            part_number: 1,
            offset: WireInteger::new(0),
            byte_size: admission.intent.byte_size,
            sha256: admission.intent.expected_sha256.clone(),
            checksum: DirectPartChecksum {
                algorithm: DirectChecksumAlgorithm::Md5,
                value: "ndTkYSaMgDT1yFZOFVxnpg==".into(),
            },
        };
        let grant = |expires_at| {
            let date = aos_hub_core::sigv4::amz_date_from_unix(issued_at as i64);
            let signed = aos_hub_core::sigv4::presign_direct_upload_part(
                &aos_hub_core::sigv4::PresignParams {
                    access_key: "fixture-access",
                    secret_key: "fixture-secret",
                    region: "auto",
                    service: "s3",
                    scheme: "https",
                    host: "provider.example",
                    path: "/bucket/private-object",
                    expires_secs: (expires_at - issued_at) as u32,
                    amz_date: &date,
                },
                "fixture-upload",
                &part,
                300,
            )
            .unwrap();
            DirectPartGrant {
                session_id: session.session_id.clone(),
                logical_fingerprint: session.logical_fingerprint.clone(),
                placement: placement.clone(),
                grant_id: "11".repeat(32),
                grant_revision: WireInteger::new(1),
                part: part.clone(),
                method: "PUT".into(),
                url: signed.url,
                required_headers: signed.required_headers,
                expires_at: WireInteger::new(expires_at),
            }
        };
        let validate = |grant: DirectPartGrant| {
            grant.validate_for(
                &session,
                &placement,
                &admission.intent,
                &part,
                issued_at + 10,
                30,
            )
        };
        let admission_deadline = issued_at + 3_600;
        let expires_at = grant_expiry(issued_at, admission_deadline, 300).unwrap();

        // The default client reserves ten seconds of skew plus thirty seconds
        // before dispatch. The old foreground-limited grant always failed this.
        assert!(validate(grant(issued_at + 30)).is_err());
        validate(grant(expires_at)).unwrap();
        assert_eq!(
            grant_expiry(issued_at, issued_at + 60, 300).unwrap(),
            issued_at + 60
        );
        assert_eq!(
            grant_expiry(issued_at, admission_deadline, 60).unwrap(),
            issued_at + 60
        );
        assert!(grant_expiry(issued_at, issued_at, 300).is_err());
        assert!(grant_expiry(issued_at, admission_deadline, 0).is_err());
        assert!(grant_expiry(u64::MAX, u64::MAX, 300).is_err());
    }

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
