//! Logical archive-transfer receipts under the caller's original Transfer guard.
//!
//! Each interval covers one existing durable transfer call, including its
//! authentication and publication. Missing receipts expose no inferred bytes.
//! These scalar observations do not describe block-device I/O or cold caches.

use super::companion_measurements::{self, Interval};
use crate::campaign_transfer::{CampaignArchiveDurabilityReceipt, CampaignArchiveTransferError};
use crucible_campaign::CampaignArchiveTransferReport;

#[derive(Debug, serde::Serialize)]
struct Measurement {
    interval: Interval,
    complete: bool,
    incomplete_reason: Option<&'static str>,
    copied_objects: Option<u64>,
    existing_objects: Option<u64>,
    logical_copied_bytes: Option<u64>,
    minimum_observed_durable_placements: Option<u16>,
}

impl Measurement {
    fn new(interval: Interval, report: Option<CampaignArchiveTransferReport>) -> Self {
        Self {
            interval,
            complete: report.is_some() && interval.incomplete_reason.is_none(),
            incomplete_reason: if report.is_none() {
                Some("transfer_failed_before_authenticated_receipt")
            } else {
                interval.incomplete_reason
            },
            copied_objects: report.map(|report| report.copied_objects),
            existing_objects: report.map(|report| report.existing_objects),
            logical_copied_bytes: report.map(|report| report.copied_bytes),
            minimum_observed_durable_placements: report
                .map(|report| report.minimum_observed_durable_placements),
        }
    }
}

/// Preserves the actual result and streams only the existing receipt's scalars.
pub(super) fn attempt(
    label: &'static str,
    run: impl FnOnce() -> Result<CampaignArchiveDurabilityReceipt, CampaignArchiveTransferError>,
) -> Result<CampaignArchiveDurabilityReceipt, CampaignArchiveTransferError> {
    let started = companion_measurements::now();
    let result = run();
    let interval = Interval::finish(started);
    let report = result.as_ref().ok().map(|receipt| receipt.transfer());
    companion_measurements::publish(label, &Measurement::new(interval, report));
    result
}

#[test]
fn failed_transfer_has_no_inferred_copied_counts_or_bytes() {
    let failed = Measurement::new(Interval::finish(super::companion_measurements::now()), None);
    assert!(!failed.complete);
    assert!(failed.logical_copied_bytes.is_none());
    assert!(failed.copied_objects.is_none());
    assert!(failed.existing_objects.is_none());
    assert!(failed.minimum_observed_durable_placements.is_none());
    assert!(failed.incomplete_reason.is_some());
}

#[test]
fn successful_receipt_preserves_actual_counts_including_zero() {
    let report = CampaignArchiveTransferReport {
        copied_objects: 0,
        existing_objects: 17,
        copied_bytes: 0,
        minimum_observed_durable_placements: 1,
    };
    let measured = Measurement::new(
        Interval {
            elapsed_ns: Some(3),
            incomplete_reason: None,
        },
        Some(report),
    );
    assert!(measured.complete);
    assert_eq!(measured.logical_copied_bytes, Some(0));
    assert_eq!(measured.copied_objects, Some(0));
    assert_eq!(measured.existing_objects, Some(17));
}
