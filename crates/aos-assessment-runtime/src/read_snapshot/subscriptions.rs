//! Immutable public subscription pages, excluding private review credentials.
//!
//! A capture retains the original public reviews and database observation time.
//! Expiry and current caller authorization are independent of review enablement.
//!
//! ```json
//! {"schema":"aos.assessment-subscription-read-snapshot/v1",
//!  "resourceScope":"registry-incarnation","limit":10,
//!  "asOf":"2026-10-10T12:00:00Z","expiresAt":"2026-10-10T12:15:00Z",
//!  "subscriptions":[],"pageHandles":[]}
//! ```

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::{Sha256Digest, canonical, limits::JsonLimits};
use serde::{Deserialize, Serialize};

use super::{ScanPageError, parse_cursor, validate_handle};
use crate::notifications::{SubscriptionPageV1, SubscriptionV1};
use crate::validation::{reject_null, text};

/// Identifies retained public subscription captures.
pub const SUBSCRIPTION_READ_SNAPSHOT_V1: &str = "aos.assessment-subscription-read-snapshot/v1";

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 8 * 1024 * 1024,
    max_depth: 24,
    max_items: 250_000,
    max_string_bytes: 4096,
};

/// Retains all public reviews under one bounded selector and exclusive deadline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubscriptionReadSnapshotV1 {
    /// Exact snapshot discriminator.
    pub schema: String,
    /// Independently authorized non-reusable resource incarnation.
    pub resource_scope: String,
    /// Fixed page size, from one through ten.
    pub limit: u32,
    /// Database observation time shared by every page.
    pub as_of: Timestamp,
    /// Exclusive custody deadline, at most fifteen minutes after observation.
    pub expires_at: Timestamp,
    /// At most sixty-four public reviews in public identity order.
    pub subscriptions: Vec<SubscriptionV1>,
    /// Distinct random 128-bit handles for pages after the first.
    pub page_handles: Vec<String>,
}

impl SubscriptionReadSnapshotV1 {
    /// Decodes a bounded, closed public capture.
    ///
    /// # Errors
    /// Returns an error for ambiguous JSON, private or unknown fields, invalid
    /// reviews, selectors, ordering, handles or exceeded bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: serde_json::Value = LIMITS.decode(bytes, "subscription read snapshot")?;
        reject_null(&value)?;
        let snapshot: Self = serde_json::from_value(value)?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Encodes a validated capture for immutable scoped custody.
    ///
    /// # Errors
    /// Returns an error for invalid content or exceeded encoding bounds.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self)?;
        LIMITS.check_value(&value, "subscription read snapshot")?;
        let bytes = canonical::to_vec(&value)?;
        ensure!(
            bytes.len() <= LIMITS.max_bytes,
            "subscription snapshot exceeds byte bound"
        );
        Ok(bytes)
    }

    /// Computes the domain-separated immutable capture identity.
    ///
    /// # Errors
    /// Returns an error for invalid content or exceeded encoding bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        let value: serde_json::Value =
            LIMITS.decode(&self.to_bytes()?, "subscription read snapshot")?;
        Sha256Digest::of_canonical(SUBSCRIPTION_READ_SNAPSHOT_V1, &value)
    }

    /// Projects one original page without reading mutable review state.
    ///
    /// # Errors
    /// Returns an error for expired custody, changed scope/page size, unknown
    /// handles or invalid retained content. Callers separately authorize the read.
    pub fn page(
        &self,
        scope: &str,
        limit: u32,
        handle: Option<&str>,
        now: &Timestamp,
    ) -> Result<SubscriptionPageV1> {
        self.validate()?;
        if scope != self.resource_scope || limit != self.limit {
            return Err(ScanPageError::SelectorChanged.into());
        }
        if now < &self.as_of || now >= &self.expires_at {
            return Err(ScanPageError::CursorExpired.into());
        }
        let index = match handle {
            None => 0,
            Some(handle) => self
                .page_handles
                .iter()
                .position(|candidate| candidate == handle)
                .map(|position| position + 1)
                .ok_or(ScanPageError::InvalidCursor)?,
        };
        let start = index * self.limit as usize;
        let end = (start + self.limit as usize).min(self.subscriptions.len());
        let next_subscription = self
            .page_handles
            .get(index)
            .map(|handle| -> Result<String> { Ok(format!("n1:{}:{handle}", self.digest()?.hex())) })
            .transpose()?;
        let page = SubscriptionPageV1 {
            schema: "aos.assessment-subscription-page/v1".into(),
            resource_scope: self.resource_scope.clone(),
            as_of: self.as_of.clone(),
            subscriptions: self.subscriptions[start..end].to_vec(),
            next_subscription,
        };
        page.to_bytes()?;
        Ok(page)
    }

    fn validate(&self) -> Result<()> {
        text(&self.resource_scope, 128, "subscription snapshot scope")?;
        ensure!(
            self.schema == SUBSCRIPTION_READ_SNAPSHOT_V1
                && (1..=10).contains(&self.limit)
                && self.subscriptions.len() <= 64
                && self.expires_at > self.as_of
                && self.expires_at.unix_seconds() - self.as_of.unix_seconds() <= 900,
            "invalid subscription snapshot selector or retention bounds"
        );
        ensure!(
            self.page_handles.len()
                == self
                    .subscriptions
                    .len()
                    .div_ceil(self.limit as usize)
                    .saturating_sub(1),
            "invalid subscription snapshot page count"
        );
        ensure!(
            self.subscriptions
                .windows(2)
                .all(|pair| pair[0].subscription_id < pair[1].subscription_id),
            "subscription snapshot identities are duplicated or unordered"
        );
        for subscription in &self.subscriptions {
            ensure!(
                subscription.resource_scope == self.resource_scope,
                "subscription snapshot contains another resource"
            );
            subscription.to_bytes()?;
        }
        let mut handles = std::collections::BTreeSet::new();
        for handle in &self.page_handles {
            validate_handle(handle)?;
            ensure!(
                handles.insert(handle),
                "subscription snapshot repeats a page handle"
            );
        }
        Ok(())
    }
}

/// Decodes a canonical opaque subscription continuation without granting access.
///
/// # Errors
/// Returns an error for legacy row identities, different cursor kinds or malformed tokens.
pub fn parse_subscription_cursor(token: &str) -> Result<(Sha256Digest, &str)> {
    parse_cursor(token, "n1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::IssueFamily;
    use crate::notifications::{
        NotificationConfigurationV1, NotificationEventKind, NotificationFrequency,
        NotificationThreshold,
    };

    fn snapshot() -> SubscriptionReadSnapshotV1 {
        let scope = "registry-incarnation";
        SubscriptionReadSnapshotV1 {
            schema: SUBSCRIPTION_READ_SNAPSHOT_V1.into(),
            resource_scope: scope.into(),
            limit: 1,
            as_of: Timestamp::from_unix_seconds(1000).unwrap(),
            expires_at: Timestamp::from_unix_seconds(1900).unwrap(),
            subscriptions: ["a", "b", "c"]
                .into_iter()
                .map(|id| SubscriptionV1 {
                    service_authority: None,
                    schema: "aos.assessment-subscription/v1".into(),
                    resource_scope: scope.into(),
                    subscription_id: id.into(),
                    revision: 1,
                    enabled: true,
                    authority_expires_at: Timestamp::from_unix_seconds(1500).unwrap(),
                    configuration: NotificationConfigurationV1 {
                        schema: "aos.assessment-notification-configuration/v1".into(),
                        events: vec![NotificationEventKind::ScanCompleted],
                        families: vec![IssueFamily::Vulnerability],
                        threshold: NotificationThreshold::AllAttention,
                        package_coordinates: vec![],
                        severity: None,
                        suppressions: vec![],
                        frequency: NotificationFrequency::Immediate {},
                        destination_reference: "webhook:1".into(),
                        destination_revision: 1,
                        destination_digest: Sha256Digest::of_bytes("destination"),
                        review_expires_at: Timestamp::from_unix_seconds(1500).unwrap(),
                    },
                })
                .collect(),
            page_handles: vec![
                "0123456789abcdef0123456789abcdef".into(),
                "abcdef0123456789abcdef0123456789".into(),
            ],
        }
    }

    #[test]
    fn public_subscription_capture_has_exact_pages_and_a_separate_clock() -> Result<()> {
        let snapshot = snapshot();
        let now = Timestamp::from_unix_seconds(1600)?;
        // A historical public review can be inspected after its authority expires.
        let first = snapshot.page(&snapshot.resource_scope, 1, None, &now)?;
        let token = first.next_subscription.as_deref().unwrap();
        let (digest, handle) = parse_subscription_cursor(token)?;
        assert_eq!(digest, snapshot.digest()?);
        assert!(!token.contains("registry"));
        assert!(super::super::parse_scan_cursor(token).is_err());
        let next = snapshot.page(&snapshot.resource_scope, 1, Some(handle), &now)?;
        assert_eq!(next.subscriptions[0].subscription_id, "b");
        assert_eq!(next.as_of, first.as_of);
        assert_eq!(SubscriptionPageV1::from_slice(&next.to_bytes()?)?, next);
        assert!(snapshot.page("foreign", 1, Some(handle), &now).is_err());
        assert!(
            snapshot
                .page(&snapshot.resource_scope, 2, Some(handle), &now)
                .is_err()
        );
        assert!(
            snapshot
                .page(
                    &snapshot.resource_scope,
                    1,
                    Some("00000000000000000000000000000000"),
                    &now
                )
                .is_err()
        );
        assert!(
            snapshot
                .page(&snapshot.resource_scope, 1, None, &snapshot.expires_at)
                .is_err()
        );
        assert!(parse_subscription_cursor("b").is_err());
        Ok(())
    }

    #[test]
    fn subscription_capture_rejects_private_fields_ambiguity_and_invalid_closure() -> Result<()> {
        let original = snapshot();
        assert_eq!(
            SubscriptionReadSnapshotV1::from_slice(&original.to_bytes()?)?,
            original
        );
        let value = serde_json::to_value(&original)?;
        for field in ["claims", "secretVersionReference", "destinationUrl"] {
            let mut altered = value.clone();
            altered[field] = "private".into();
            assert!(
                SubscriptionReadSnapshotV1::from_slice(&serde_json::to_vec(&altered)?).is_err()
            );
        }
        let mut altered = original.clone();
        altered.subscriptions[1].resource_scope = "foreign".into();
        assert!(altered.to_bytes().is_err());
        let mut altered = original.clone();
        altered.subscriptions.swap(0, 1);
        assert!(altered.to_bytes().is_err());
        let mut altered = original.clone();
        altered.page_handles[1] = altered.page_handles[0].clone();
        assert!(altered.to_bytes().is_err());
        let mut altered = value.clone();
        altered["pageHandles"] = serde_json::Value::Null;
        assert!(SubscriptionReadSnapshotV1::from_slice(&serde_json::to_vec(&altered)?).is_err());
        let encoded = String::from_utf8(serde_json::to_vec(&value)?)?;
        let duplicated = encoded.replacen("{", "{\"limit\":1,", 1);
        assert!(SubscriptionReadSnapshotV1::from_slice(duplicated.as_bytes()).is_err());
        Ok(())
    }
}
