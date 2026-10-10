//! Retained scan-list snapshots and opaque, scope-bound continuation tokens.
//!
//! Tokens name a stored immutable snapshot and one random page handle. They
//! contain no registry IDs, query text, actor claims or mutable row positions.
//! Possession never authorizes a read; hosts recheck current resource authority.
//!
//! An empty snapshot has the following wire form. Nonempty snapshots add typed
//! scan summaries and a random hexadecimal handle for each continuation page.
//!
//! ```json
//! {"schema":"aos.assessment-scan-read-snapshot/v1",
//!  "resourceScope":"registry-incarnation","limit":25,
//!  "asOf":"2026-10-10T12:00:00Z","expiresAt":"2026-10-10T12:15:00Z",
//!  "scans":[],"pageHandles":[]}
//! ```

use anyhow::{Result, bail};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use aos_contract::limits::{BoundedWriter, JsonLimits};
use serde::{Deserialize, Serialize};

use crate::control::{ScanListV1, ScanSummary};
use crate::validation::{reject_null, text};

/// Identifies immutable retained scan-list snapshots.
pub const SCAN_READ_SNAPSHOT_V1: &str = "aos.assessment-scan-read-snapshot/v1";

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 8 * 1024 * 1024,
    max_depth: 16,
    max_items: 250_000,
    max_string_bytes: 1024,
};

/// Classifies public pagination failures without exposing storage diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanPageError {
    /// The token is malformed or does not name a retained page handle.
    InvalidCursor,
    /// Retained custody expired, disappeared or has an unusable clock interval.
    CursorExpired,
    /// The current resource incarnation or requested page size differs.
    SelectorChanged,
    /// A finite snapshot row or retained-storage bound was exhausted.
    CapacityExceeded,
}

impl std::fmt::Display for ScanPageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCursor => "invalid retained scan cursor",
            Self::CursorExpired => {
                "cursor-expired: scan snapshot is unavailable; restart pagination"
            }
            Self::SelectorChanged => "scan snapshot selector changed; restart pagination",
            Self::CapacityExceeded => "retained scan snapshot capacity exceeded",
        })
    }
}

impl std::error::Error for ScanPageError {}

/// Retains ordered scan state under one fixed observation time and page size.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScanReadSnapshotV1 {
    /// Exact immutable snapshot discriminator.
    pub schema: String,
    /// Independently authorized, non-reusable resource incarnation.
    pub resource_scope: String,
    /// Fixed page size; continuations cannot reinterpret the selector.
    pub limit: u32,
    /// Database observation time retained across every page.
    pub as_of: Timestamp,
    /// Exclusive retention deadline, at most fifteen minutes after observation.
    pub expires_at: Timestamp,
    /// Exact scan summaries captured by one database read, at most ten thousand.
    pub scans: Vec<ScanSummary>,
    /// Random 128-bit page handles for pages after the first, in page order.
    pub page_handles: Vec<String>,
}

impl ScanReadSnapshotV1 {
    /// Decodes and validates bounded immutable snapshot content.
    ///
    /// # Errors
    /// Returns an error for ambiguous or excessive JSON, invalid rows or handles.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let value: serde_json::Value = LIMITS.decode(bytes, "scan read snapshot")?;
        reject_null(&value)?;
        let snapshot: Self = serde_json::from_value(value)?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Encodes validated content for shared immutable object custody.
    ///
    /// # Errors
    /// Returns an error for invalid content or excessive encoded size.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut writer = BoundedWriter::new(LIMITS.max_bytes as u64, "scan snapshot exceeds bound");
        serde_json::to_writer(&mut writer, self)?;
        let value = serde_json::to_value(self)?;
        LIMITS.check_value(&value, "scan read snapshot")?;
        aos_contract::canonical::to_vec(&value)
    }

    /// Computes the identity used by retained continuation tokens.
    ///
    /// # Errors
    /// Returns an error for invalid or excessive snapshot content.
    pub fn digest(&self) -> Result<Sha256Digest> {
        let value: serde_json::Value = LIMITS.decode(&self.to_bytes()?, "scan read snapshot")?;
        Sha256Digest::of_canonical(SCAN_READ_SNAPSHOT_V1, &value)
    }

    /// Projects an exact page without consulting changing scan rows.
    ///
    /// # Errors
    /// Returns an error for expired retention, changed scope/page size or an
    /// unrecognized handle. A missing handle selects the first page only.
    pub fn page(
        &self,
        scope: &str,
        limit: u32,
        handle: Option<&str>,
        now: &Timestamp,
    ) -> Result<ScanListV1> {
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
        let end = (start + self.limit as usize).min(self.scans.len());
        let next_scan = self
            .page_handles
            .get(index)
            .map(|handle| -> Result<String> { Ok(format!("s1:{}:{handle}", self.digest()?.hex())) })
            .transpose()?;
        Ok(ScanListV1 {
            schema: "aos.assessment-scan-list/v1".into(),
            resource_scope: self.resource_scope.clone(),
            as_of: self.as_of.clone(),
            scans: self.scans[start..end].to_vec(),
            next_scan,
        })
    }

    fn validate(&self) -> Result<()> {
        text(&self.resource_scope, 128, "scan snapshot scope")?;
        if self.schema != SCAN_READ_SNAPSHOT_V1
            || !(1..=100).contains(&self.limit)
            || self.scans.len() > 10_000
            || self.expires_at <= self.as_of
            || self.expires_at.unix_seconds() - self.as_of.unix_seconds() > 900
            || self.page_handles.len()
                != self
                    .scans
                    .len()
                    .div_ceil(self.limit as usize)
                    .saturating_sub(1)
        {
            bail!("invalid scan snapshot schema, retention or page bounds");
        }
        let mut handles = std::collections::BTreeSet::new();
        for handle in &self.page_handles {
            validate_handle(handle)?;
            if !handles.insert(handle) {
                bail!("repeated scan snapshot page handle");
            }
        }
        if self
            .scans
            .windows(2)
            .any(|pair| pair[0].scan_id >= pair[1].scan_id)
        {
            bail!("scan snapshot rows are not strictly ordered");
        }
        for rows in self.scans.chunks(100) {
            ScanListV1 {
                schema: "aos.assessment-scan-list/v1".into(),
                resource_scope: self.resource_scope.clone(),
                as_of: self.as_of.clone(),
                scans: rows.to_vec(),
                next_scan: None,
            }
            .to_bytes()?;
        }
        Ok(())
    }
}

/// Decodes an opaque retained page token without granting resource authority.
///
/// # Errors
/// Returns an error for noncanonical or excessive token data.
pub fn parse_scan_cursor(token: &str) -> Result<(Sha256Digest, &str)> {
    if token.len() != 100 {
        return Err(ScanPageError::InvalidCursor.into());
    }
    let mut parts = token.split(':');
    if parts.next() != Some("s1") {
        return Err(ScanPageError::InvalidCursor.into());
    }
    let digest = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("scan cursor lacks snapshot"))?;
    validate_hex(digest, 64).map_err(|_| ScanPageError::InvalidCursor)?;
    let handle = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("scan cursor lacks page handle"))?;
    validate_handle(handle).map_err(|_| ScanPageError::InvalidCursor)?;
    if parts.next().is_some() {
        return Err(ScanPageError::InvalidCursor.into());
    }
    Ok((Sha256Digest::parse(&format!("sha256:{digest}"))?, handle))
}

fn validate_handle(handle: &str) -> Result<()> {
    validate_hex(handle, 32)
}

fn validate_hex(value: &str, length: usize) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("scan cursor requires canonical lowercase hexadecimal");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::ScanState;

    fn snapshot() -> ScanReadSnapshotV1 {
        let as_of = Timestamp::from_unix_seconds(1000).unwrap();
        ScanReadSnapshotV1 {
            schema: SCAN_READ_SNAPSHOT_V1.into(),
            resource_scope: "registry-incarnation".into(),
            limit: 1,
            as_of: as_of.clone(),
            expires_at: Timestamp::from_unix_seconds(1900).unwrap(),
            scans: ["a", "b", "c"]
                .into_iter()
                .map(|scan_id| ScanSummary {
                    scan_id: scan_id.into(),
                    request_digest: Sha256Digest::of_bytes(scan_id),
                    state: ScanState::Queued,
                    generation: 1,
                    resource_version: 1,
                    created_at: as_of.clone(),
                    assessment_digest: None,
                })
                .collect(),
            page_handles: vec![
                "0123456789abcdef0123456789abcdef".into(),
                "abcdef0123456789abcdef0123456789".into(),
            ],
        }
    }

    #[test]
    fn opaque_pages_preserve_exact_rows_clock_and_selector() -> Result<()> {
        let retained = snapshot();
        let now = Timestamp::from_unix_seconds(1001)?;
        let mut page = retained.page("registry-incarnation", 1, None, &now)?;
        let mut ids = Vec::new();
        loop {
            assert_eq!(ScanListV1::from_slice(&page.to_bytes()?)?, page);
            assert_eq!(page.as_of, retained.as_of);
            ids.push(page.scans[0].scan_id.clone());
            let Some(token) = page.next_scan else {
                break;
            };
            assert!(!token.contains("registry-incarnation"));
            let (digest, handle) = parse_scan_cursor(&token)?;
            assert_eq!(digest, retained.digest()?);
            page = retained.page("registry-incarnation", 1, Some(handle), &now)?;
        }
        assert_eq!(ids, ["a", "b", "c"]);
        assert_eq!(
            ScanReadSnapshotV1::from_slice(&retained.to_bytes()?)?,
            retained
        );
        assert!(retained.page("other-registry", 1, None, &now).is_err());
        assert!(
            retained
                .page("registry-incarnation", 2, None, &now)
                .is_err()
        );
        assert!(
            retained
                .page("registry-incarnation", 1, Some("unknown"), &now)
                .is_err()
        );
        assert!(
            retained
                .page("registry-incarnation", 1, None, &retained.expires_at)
                .is_err()
        );
        assert!(
            retained
                .page(
                    "registry-incarnation",
                    1,
                    None,
                    &Timestamp::from_unix_seconds(999)?
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn malformed_snapshots_and_noncanonical_cursors_are_refused() -> Result<()> {
        let valid = snapshot();
        let token = valid
            .page("registry-incarnation", 1, None, &valid.as_of)?
            .next_scan
            .unwrap();
        for invalid in [
            token.to_uppercase(),
            format!("{token}:extra"),
            "a".repeat(129),
            token.replace("s1:", "s2:"),
        ] {
            assert!(parse_scan_cursor(&invalid).is_err());
        }
        let mut changed = valid.clone();
        changed.page_handles[1] = changed.page_handles[0].clone();
        assert!(changed.to_bytes().is_err());
        changed = valid.clone();
        changed.scans.swap(0, 1);
        assert!(changed.to_bytes().is_err());
        changed = valid.clone();
        changed.limit = 0;
        assert!(changed.to_bytes().is_err());
        changed = valid.clone();
        changed.expires_at = Timestamp::from_unix_seconds(1901)?;
        assert!(changed.to_bytes().is_err());
        changed = valid.clone();
        changed.page_handles.pop();
        assert!(changed.to_bytes().is_err());
        let bytes = valid.to_bytes()?;
        let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
        value["authority"] = "forged".into();
        assert!(ScanReadSnapshotV1::from_slice(&serde_json::to_vec(&value)?).is_err());
        assert!(ScanReadSnapshotV1::from_slice(b"{\"schema\":null}").is_err());
        assert!(ScanReadSnapshotV1::from_slice(&vec![b' '; 8 * 1024 * 1024 + 1]).is_err());
        Ok(())
    }
}
