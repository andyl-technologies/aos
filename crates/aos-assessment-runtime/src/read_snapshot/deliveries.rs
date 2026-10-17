//! Immutable notification delivery pages without physical execution capabilities.
//!
//! Captures preserve original states, attempts, receipt commitments and batch
//! linkage across retries. Current read authority is independent of custody.
//! Reads never retry callbacks or establish current delivery authority.
//!
//! ```json
//! {"schema":"aos.assessment-delivery-read-snapshot/v1",
//!  "resourceScope":"registry-incarnation","limit":10,
//!  "asOf":"2026-10-10T12:00:00Z","expiresAt":"2026-10-10T12:15:00Z",
//!  "deliveries":[],"pageHandles":[]}
//! ```

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::{Sha256Digest, canonical, limits::JsonLimits};
use serde::{Deserialize, Serialize};

use super::{ScanPageError, parse_cursor, validate_handle};
use crate::notifications::{NotificationDeliveryPageV1, NotificationDeliveryV1};
use crate::validation::{reject_null, text};

/// Identifies retained notification delivery captures.
pub const DELIVERY_READ_SNAPSHOT_V1: &str = "aos.assessment-delivery-read-snapshot/v1";

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 8 * 1024 * 1024,
    max_depth: 24,
    max_items: 250_000,
    max_string_bytes: 4096,
};

/// Retains complete delivery state under one fixed filter and exclusive deadline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeliveryReadSnapshotV1 {
    /// Exact snapshot discriminator.
    pub schema: String,
    /// Independently authorized non-reusable resource incarnation.
    pub resource_scope: String,
    /// Exact public subscription filter, absent for all resource deliveries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    /// Fixed page size, from one through ten.
    pub limit: u32,
    /// Database observation time shared by every page.
    pub as_of: Timestamp,
    /// Exclusive custody deadline, at most fifteen minutes after observation.
    pub expires_at: Timestamp,
    /// At most one hundred twenty-eight delivery projections in public identity order.
    pub deliveries: Vec<NotificationDeliveryV1>,
    /// Distinct random 128-bit handles for pages after the first.
    pub page_handles: Vec<String>,
}

impl DeliveryReadSnapshotV1 {
    /// Decodes a bounded, closed public capture.
    ///
    /// # Errors
    /// Returns an error for ambiguous JSON, private or unknown fields, invalid
    /// deliveries, selectors, ordering, handles or exceeded bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: serde_json::Value = LIMITS.decode(bytes, "delivery read snapshot")?;
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
        LIMITS.check_value(&value, "delivery read snapshot")?;
        let bytes = canonical::to_vec(&value)?;
        ensure!(
            bytes.len() <= LIMITS.max_bytes,
            "delivery snapshot exceeds byte bound"
        );
        Ok(bytes)
    }

    /// Computes the domain-separated immutable capture identity.
    ///
    /// # Errors
    /// Returns an error for invalid content or exceeded encoding bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        let value: serde_json::Value =
            LIMITS.decode(&self.to_bytes()?, "delivery read snapshot")?;
        Sha256Digest::of_canonical(DELIVERY_READ_SNAPSHOT_V1, &value)
    }

    /// Projects one original page without reading mutable delivery state.
    ///
    /// # Errors
    /// Returns an error for expired custody, changed scope/filter/page size, unknown
    /// handles or invalid retained content. Callers separately authorize the read.
    pub fn page(
        &self,
        scope: &str,
        limit: u32,
        subscription_id: Option<&str>,
        handle: Option<&str>,
        now: &Timestamp,
    ) -> Result<NotificationDeliveryPageV1> {
        self.validate()?;
        if scope != self.resource_scope
            || limit != self.limit
            || subscription_id != self.subscription_id.as_deref()
        {
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
        let end = (start + self.limit as usize).min(self.deliveries.len());
        let next_delivery = self
            .page_handles
            .get(index)
            .map(|handle| -> Result<String> { Ok(format!("d1:{}:{handle}", self.digest()?.hex())) })
            .transpose()?;
        let page = NotificationDeliveryPageV1 {
            schema: "aos.assessment-notification-delivery-page/v1".into(),
            resource_scope: self.resource_scope.clone(),
            as_of: self.as_of.clone(),
            subscription_id: self.subscription_id.clone(),
            deliveries: self.deliveries[start..end].to_vec(),
            next_delivery,
        };
        page.to_bytes()?;
        Ok(page)
    }

    fn validate(&self) -> Result<()> {
        text(&self.resource_scope, 128, "delivery snapshot scope")?;
        if let Some(id) = &self.subscription_id {
            text(id, 128, "delivery snapshot subscription")?;
        }
        ensure!(
            self.schema == DELIVERY_READ_SNAPSHOT_V1
                && (1..=10).contains(&self.limit)
                && self.deliveries.len() <= 128
                && self.expires_at > self.as_of
                && self.expires_at.unix_seconds() - self.as_of.unix_seconds() <= 900,
            "invalid delivery snapshot selector or retention bounds"
        );
        ensure!(
            self.page_handles.len()
                == self
                    .deliveries
                    .len()
                    .div_ceil(self.limit as usize)
                    .saturating_sub(1),
            "invalid delivery snapshot page count"
        );
        ensure!(
            self.deliveries
                .windows(2)
                .all(|pair| pair[0].delivery_id < pair[1].delivery_id),
            "delivery snapshot identities are duplicated or unordered"
        );
        for delivery in &self.deliveries {
            delivery.validate()?;
            ensure!(
                self.subscription_id
                    .as_ref()
                    .is_none_or(|id| id == &delivery.subscription_id),
                "delivery snapshot differs from its subscription filter"
            );
        }
        let mut handles = std::collections::BTreeSet::new();
        for handle in &self.page_handles {
            validate_handle(handle)?;
            ensure!(
                handles.insert(handle),
                "delivery snapshot repeats a page handle"
            );
        }
        Ok(())
    }
}

/// Decodes a canonical opaque delivery continuation without granting access.
///
/// # Errors
/// Returns an error for legacy row identities, different cursor kinds or malformed tokens.
pub fn parse_delivery_cursor(token: &str) -> Result<(Sha256Digest, &str)> {
    parse_cursor(token, "d1")
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifications::NotificationIntentState;

    fn delivery() -> NotificationDeliveryV1 {
        NotificationDeliveryV1 {
            delivery_id: "intent-a".into(),
            subscription_id: "review".into(),
            subscription_revision: "1".into(),
            event_sequence: u64::MAX.to_string(),
            state: NotificationIntentState::Pending,
            attempt: 0,
            not_before: Timestamp::parse("2026-10-10T00:00:00Z").unwrap(),
            lease_expires_at: None,
            resource_version: "1".into(),
            created_at: Timestamp::parse("2026-10-10T00:00:00Z").unwrap(),
            updated_at: Timestamp::parse("2026-10-10T00:00:00Z").unwrap(),
            last_error_code: None,
            batch_delivery_id: None,
            body_digest: None,
            receipt_digest: None,
        }
    }

    fn snapshot() -> DeliveryReadSnapshotV1 {
        let mut deliveries = ["intent-a", "intent-b", "intent-c"].map(|id| {
            let mut item = delivery();
            item.delivery_id = id.into();
            item
        });
        deliveries[1].state = NotificationIntentState::Leased;
        deliveries[1].attempt = 1;
        deliveries[1].lease_expires_at = Some(Timestamp::parse("2026-10-10T00:00:30Z").unwrap());
        deliveries[1].batch_delivery_id = Some("physical-batch".into());
        deliveries[1].body_digest = Some(Sha256Digest::of_bytes("immutable body"));
        DeliveryReadSnapshotV1 {
            schema: DELIVERY_READ_SNAPSHOT_V1.into(),
            resource_scope: "registry-incarnation".into(),
            subscription_id: Some("review".into()),
            limit: 1,
            as_of: Timestamp::parse("2026-10-10T00:00:00Z").unwrap(),
            expires_at: Timestamp::parse("2026-10-10T00:15:00Z").unwrap(),
            deliveries: deliveries.into(),
            page_handles: vec![
                "0123456789abcdef0123456789abcdef".into(),
                "abcdef0123456789abcdef0123456789".into(),
            ],
        }
    }

    #[test]
    fn original_attempt_facts_survive_lease_expiry_without_authorizing_retry() -> Result<()> {
        let snapshot = snapshot();
        let now = Timestamp::parse("2026-10-10T00:05:00Z")?;
        let first = snapshot.page(&snapshot.resource_scope, 1, Some("review"), None, &now)?;
        let token = first.next_delivery.as_deref().unwrap();
        let (digest, handle) = parse_delivery_cursor(token)?;
        assert_eq!(digest, snapshot.digest()?);
        assert!(!token.contains("registry"));
        assert!(super::super::parse_scan_cursor(token).is_err());
        let second = snapshot.page(
            &snapshot.resource_scope,
            1,
            Some("review"),
            Some(handle),
            &now,
        )?;
        assert_eq!(second.deliveries, snapshot.deliveries[1..2]);
        assert_eq!(second.as_of, first.as_of);
        assert_eq!(second.deliveries[0].state, NotificationIntentState::Leased);
        assert!(second.deliveries[0].lease_expires_at.as_ref().unwrap() < &now);
        let (_, handle) = parse_delivery_cursor(second.next_delivery.as_deref().unwrap())?;
        let last = snapshot.page(
            &snapshot.resource_scope,
            1,
            Some("review"),
            Some(handle),
            &now,
        )?;
        assert_eq!(last.deliveries, snapshot.deliveries[2..]);
        assert!(last.next_delivery.is_none());
        assert_eq!(
            DeliveryReadSnapshotV1::from_slice(&snapshot.to_bytes()?)?,
            snapshot
        );
        assert_eq!(
            NotificationDeliveryPageV1::from_slice(&second.to_bytes()?)?,
            second
        );
        for (scope, limit, filter, handle, clock, expected) in [
            (
                "other",
                1,
                Some("review"),
                None,
                now.clone(),
                ScanPageError::SelectorChanged,
            ),
            (
                snapshot.resource_scope.as_str(),
                2,
                Some("review"),
                None,
                now.clone(),
                ScanPageError::SelectorChanged,
            ),
            (
                snapshot.resource_scope.as_str(),
                1,
                None,
                None,
                now.clone(),
                ScanPageError::SelectorChanged,
            ),
            (
                snapshot.resource_scope.as_str(),
                1,
                Some("other"),
                None,
                now.clone(),
                ScanPageError::SelectorChanged,
            ),
            (
                snapshot.resource_scope.as_str(),
                1,
                Some("review"),
                Some("00000000000000000000000000000000"),
                now,
                ScanPageError::InvalidCursor,
            ),
            (
                snapshot.resource_scope.as_str(),
                1,
                Some("review"),
                None,
                snapshot.expires_at.clone(),
                ScanPageError::CursorExpired,
            ),
            (
                snapshot.resource_scope.as_str(),
                1,
                Some("review"),
                None,
                Timestamp::parse("2026-10-09T23:59:59Z")?,
                ScanPageError::CursorExpired,
            ),
        ] {
            assert_eq!(
                snapshot
                    .page(scope, limit, filter, handle, &clock)
                    .unwrap_err()
                    .downcast_ref::<ScanPageError>(),
                Some(&expected)
            );
        }
        Ok(())
    }

    #[test]
    fn captures_reject_private_fields_cross_filter_facts_and_ambiguous_handles() -> Result<()> {
        let original = snapshot();
        for field in ["claims", "claimToken", "destination", "callbackBody"] {
            let mut value = serde_json::to_value(&original)?;
            value[field] = serde_json::json!("private");
            assert!(DeliveryReadSnapshotV1::from_slice(&serde_json::to_vec(&value)?).is_err());
        }
        let mut changed = original.clone();
        changed.deliveries[1].subscription_id = "other".into();
        assert!(changed.to_bytes().is_err());
        changed = original.clone();
        changed.page_handles[1] = changed.page_handles[0].clone();
        assert!(changed.to_bytes().is_err());
        changed = original.clone();
        changed.deliveries.swap(0, 1);
        assert!(changed.to_bytes().is_err());
        let mut value = serde_json::to_value(&original)?;
        value["deliveries"][0]["receiptDigest"] = serde_json::Value::Null;
        assert!(DeliveryReadSnapshotV1::from_slice(&serde_json::to_vec(&value)?).is_err());
        for token in ["intent-a", "d1:broken", "s1:broken", "D1:broken"] {
            assert!(parse_delivery_cursor(token).is_err());
        }
        assert!(DeliveryReadSnapshotV1::from_slice(&vec![b' '; 8 * 1024 * 1024 + 1]).is_err());
        Ok(())
    }
}
