//! Immutable public schedule revisions and scope-bound continuation handles.
//!
//! Retained reviews describe the original selection and due time. Their presence
//! authorizes neither future execution nor a configuration mutation.
//!
//! ```json
//! {"schema":"aos.assessment-schedule-read-snapshot/v1",
//!  "resourceScope":"registry-incarnation","limit":10,
//!  "asOf":"2026-10-10T12:00:00Z","expiresAt":"2026-10-10T12:15:00Z",
//!  "schedules":[],"pageHandles":[]}
//! ```

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use aos_contract::{Sha256Digest, canonical, limits::JsonLimits};
use serde::{Deserialize, Serialize};

use super::{ScanPageError, parse_cursor, validate_handle};
use crate::schedules::{SchedulePageV1, ScheduleV1};
use crate::validation::{reject_null, text};

/// Identifies retained public schedule captures.
pub const SCHEDULE_READ_SNAPSHOT_V1: &str = "aos.assessment-schedule-read-snapshot/v1";

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 8 * 1024 * 1024,
    max_depth: 24,
    max_items: 250_000,
    max_string_bytes: 4096,
};

/// Retains finite public reviews under one selector and exclusive deadline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScheduleReadSnapshotV1 {
    /// Exact immutable capture discriminator.
    pub schema: String,
    /// Independently authorized, non-reusable registry incarnation.
    pub resource_scope: String,
    /// Fixed page size, from one through ten.
    pub limit: u32,
    /// Database observation time shared by every page.
    pub as_of: Timestamp,
    /// Exclusive custody deadline, at most fifteen minutes after observation.
    pub expires_at: Timestamp,
    /// At most sixty-four original public revisions in scoped identity order.
    pub schedules: Vec<ScheduleV1>,
    /// Distinct random 128-bit handles for pages after the first.
    pub page_handles: Vec<String>,
}

impl ScheduleReadSnapshotV1 {
    /// Decodes a bounded closed capture without accepting private provenance.
    ///
    /// # Errors
    /// Returns an error for ambiguous/null-bearing JSON, private or unknown
    /// fields, invalid reviews, selectors, ordering, handles or exceeded bounds.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: serde_json::Value = LIMITS.decode(bytes, "schedule read snapshot")?;
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
        LIMITS.check_value(&value, "schedule read snapshot")?;
        let bytes = canonical::to_vec(&value)?;
        ensure!(
            bytes.len() <= LIMITS.max_bytes,
            "schedule snapshot exceeds byte bound"
        );
        Ok(bytes)
    }

    /// Computes the domain-separated immutable capture identity.
    ///
    /// # Errors
    /// Returns an error for invalid content or exceeded encoding bounds.
    pub fn digest(&self) -> Result<Sha256Digest> {
        let value: serde_json::Value =
            LIMITS.decode(&self.to_bytes()?, "schedule read snapshot")?;
        Sha256Digest::of_canonical(SCHEDULE_READ_SNAPSHOT_V1, &value)
    }

    /// Projects one original page independently from mutable schedule state.
    ///
    /// # Errors
    /// Returns an error for expired custody, changed scope/page size, unknown
    /// handles or invalid retained content. Hosts separately authorize every read.
    pub fn page(
        &self,
        scope: &str,
        limit: u32,
        handle: Option<&str>,
        now: &Timestamp,
    ) -> Result<SchedulePageV1> {
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
        let end = (start + self.limit as usize).min(self.schedules.len());
        let next_schedule = self
            .page_handles
            .get(index)
            .map(|handle| -> Result<String> { Ok(format!("r1:{}:{handle}", self.digest()?.hex())) })
            .transpose()?;
        let page = SchedulePageV1 {
            schema: "aos.assessment-schedule-page/v1".into(),
            resource_scope: self.resource_scope.clone(),
            as_of: self.as_of.clone(),
            schedules: self.schedules[start..end].to_vec(),
            next_schedule,
        };
        page.to_bytes()?;
        Ok(page)
    }

    fn validate(&self) -> Result<()> {
        text(&self.resource_scope, 128, "schedule snapshot scope")?;
        ensure!(
            self.schema == SCHEDULE_READ_SNAPSHOT_V1
                && (1..=10).contains(&self.limit)
                && self.schedules.len() <= 64
                && self.expires_at > self.as_of
                && self.expires_at.unix_seconds() - self.as_of.unix_seconds() <= 900,
            "invalid schedule snapshot selector or retention bounds"
        );
        ensure!(
            self.page_handles.len()
                == self
                    .schedules
                    .len()
                    .div_ceil(self.limit as usize)
                    .saturating_sub(1),
            "invalid schedule snapshot page count"
        );

        let mut previous = None;
        for schedule in &self.schedules {
            ensure!(
                schedule.resource_scope == self.resource_scope,
                "schedule snapshot contains another resource"
            );
            schedule.to_bytes()?;
            let key = Sha256Digest::of_canonical(
                "aos.assessment-schedule-key/v1",
                &(&self.resource_scope, &schedule.schedule_id),
            )?;
            ensure!(
                previous.is_none_or(|previous| previous < key),
                "schedule snapshot identities are duplicated or unordered"
            );
            previous = Some(key);
        }

        let mut handles = std::collections::BTreeSet::new();
        for handle in &self.page_handles {
            validate_handle(handle)?;
            ensure!(
                handles.insert(handle),
                "schedule snapshot repeats a page handle"
            );
        }
        Ok(())
    }
}

/// Decodes a canonical opaque schedule continuation without granting access.
///
/// # Errors
/// Returns an error for legacy row identities, other cursor kinds or malformed tokens.
pub fn parse_schedule_cursor(token: &str) -> Result<(Sha256Digest, &str)> {
    parse_cursor(token, "r1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::ScanLimits;
    use crate::schedules::ScheduleConfigurationV1;
    use aos_assessment::input::{FreshnessMode, Profile};

    fn snapshot() -> ScheduleReadSnapshotV1 {
        let scope = "registry-incarnation";
        let mut schedules = ["a", "b", "c"]
            .into_iter()
            .map(|id| ScheduleV1 {
                service_authority: None,
                schema: "aos.assessment-schedule/v1".into(),
                resource_scope: scope.into(),
                schedule_id: id.into(),
                revision: 1,
                enabled: true,
                authority_expires_at: Timestamp::from_unix_seconds(1500).unwrap(),
                next_due_at: Timestamp::from_unix_seconds(1200).unwrap(),
                configuration: ScheduleConfigurationV1 {
                    schema: "aos.assessment-schedule-configuration/v1".into(),
                    packages: vec!["fixture/example".into()],
                    profiles: vec![Profile::Updates],
                    freshness: FreshnessMode::RefreshStale,
                    cadence_seconds: 60,
                    review_expires_at: Timestamp::from_unix_seconds(1500).unwrap(),
                    limits: ScanLimits::default(),
                },
            })
            .collect::<Vec<_>>();
        schedules.sort_by_cached_key(|schedule| {
            Sha256Digest::of_canonical(
                "aos.assessment-schedule-key/v1",
                &(scope, &schedule.schedule_id),
            )
            .unwrap()
        });
        ScheduleReadSnapshotV1 {
            schema: SCHEDULE_READ_SNAPSHOT_V1.into(),
            resource_scope: scope.into(),
            limit: 1,
            as_of: Timestamp::from_unix_seconds(1000).unwrap(),
            expires_at: Timestamp::from_unix_seconds(1900).unwrap(),
            schedules,
            page_handles: vec![
                "0123456789abcdef0123456789abcdef".into(),
                "abcdef0123456789abcdef0123456789".into(),
            ],
        }
    }

    #[test]
    fn schedule_capture_retains_due_reviews_after_their_execution_authority_expires() -> Result<()>
    {
        let snapshot = snapshot();
        let now = Timestamp::from_unix_seconds(1600)?;
        let first = snapshot.page(&snapshot.resource_scope, 1, None, &now)?;
        let token = first.next_schedule.as_deref().unwrap();
        let (digest, handle) = parse_schedule_cursor(token)?;
        assert_eq!(digest, snapshot.digest()?);
        let second = snapshot.page(&snapshot.resource_scope, 1, Some(handle), &now)?;
        assert_eq!(second.schedules, snapshot.schedules[1..2]);
        assert_eq!(second.as_of, first.as_of);
        assert_eq!(SchedulePageV1::from_slice(&second.to_bytes()?)?, second);
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
        assert!(
            snapshot
                .page(
                    &snapshot.resource_scope,
                    1,
                    None,
                    &Timestamp::from_unix_seconds(999)?
                )
                .is_err()
        );
        for token in [
            "a",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(parse_schedule_cursor(token).is_err());
        }
        assert!(super::super::parse_scan_cursor(token).is_err());
        assert!(super::super::subscriptions::parse_subscription_cursor(token).is_err());
        assert!(super::super::alerts::parse_alert_cursor(token).is_err());
        Ok(())
    }

    #[test]
    fn schedule_capture_rejects_private_provenance_and_changed_custody() -> Result<()> {
        let original = snapshot();
        assert_eq!(
            ScheduleReadSnapshotV1::from_slice(&original.to_bytes()?)?,
            original
        );
        let value = serde_json::to_value(&original)?;
        for field in ["claims", "actorRef", "credentialReference"] {
            let mut altered = value.clone();
            altered["schedules"][0][field] = "private".into();
            assert!(ScheduleReadSnapshotV1::from_slice(&serde_json::to_vec(&altered)?).is_err());
        }
        let mut altered = original.clone();
        altered.schedules[1].resource_scope = "foreign".into();
        assert!(altered.to_bytes().is_err());
        let mut altered = original.clone();
        altered.schedules.swap(0, 1);
        assert!(altered.to_bytes().is_err());
        let mut altered = original.clone();
        altered.page_handles[1] = altered.page_handles[0].clone();
        assert!(altered.to_bytes().is_err());
        let mut altered = value.clone();
        altered["pageHandles"] = serde_json::Value::Null;
        assert!(ScheduleReadSnapshotV1::from_slice(&serde_json::to_vec(&altered)?).is_err());
        let encoded = String::from_utf8(serde_json::to_vec(&value)?)?;
        let duplicate = encoded.replacen("{", "{\"limit\":1,", 1);
        assert!(ScheduleReadSnapshotV1::from_slice(duplicate.as_bytes()).is_err());
        Ok(())
    }
}
