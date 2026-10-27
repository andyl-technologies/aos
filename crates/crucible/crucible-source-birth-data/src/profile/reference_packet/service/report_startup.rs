//! Describes closed publication allowances in an original private Source birth.
//!
//! ```text
//! {"schema":"source-private.native-report-startup-allocation/13",
//!  "original_observe12":{"raw_report_capacity":"16384",
//!   "retained_growth_bytes":"...","maximum_simultaneous_transient_bytes":"...",
//!   "declared_counter_scratch_bytes":"..."},"fresh_completed_admit13":null}
//! ```
//!
//! These values are process-protocol data. Core's original installed scenario
//! policy admits the actual pre-Child owners before Source finalizes this part
//! of the same private birth. Native code must independently authenticate that
//! actual boot/ACK association and the selected purpose before obtaining any
//! internal construction right. Deserialization and arithmetic issue no permit.

use crate::ProviderError;
use crucible_node_format::U64;
use serde::{Deserialize, Serialize};

/// Names the closed startup allocation object inside Source binding13.
pub const PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA: &str =
    "source-private.native-report-startup-allocation/13";

/// Names the exact raw report reservation shared by the two selected classes.
pub const PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY: usize = 16 * 1024;

/// Distinguishes independently selected report publication purposes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketNativeReportStartupPurpose {
    /// Publishes the actual selected original active Observe12 report.
    OriginalObserve12,
    /// Publishes the actual inactive target's completed-Admit13 report.
    FreshCompletedAdmit13,
}

/// Carries one purpose's separately admitted prospective construction data.
///
/// Current baseline native owners remain independent. Retained growth includes
/// every new report, reply/cache and protocol-prefix owner. The transient term
/// covers the complete simultaneous publication phase, rather than the largest
/// single buffer. Declared counter scratch is a separate simultaneous term.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeReportStartupAllocationRow {
    /// Requires the actual fixed raw report reservation of 16,384 bytes.
    pub raw_report_capacity: U64,
    /// Includes all new independently retained owners for this purpose.
    pub retained_growth_bytes: U64,
    /// Includes the entire simultaneously live construction/publication phase.
    pub maximum_simultaneous_transient_bytes: U64,
    /// Includes the actual declared quote, counter and fixed roster scratch.
    pub declared_counter_scratch_bytes: U64,
}

impl PacketNativeReportStartupAllocationRow {
    /// Checks the closed reservation and sums its three independent terms.
    ///
    /// # Errors
    /// Refuses a different raw capacity, a missing term or checked overflow.
    pub fn requested_peak_data(&self) -> Result<u64, ProviderError> {
        if self.raw_report_capacity.get() != PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY as u64
            || self.retained_growth_bytes.get() == 0
            || self.maximum_simultaneous_transient_bytes.get() == 0
            || self.declared_counter_scratch_bytes.get() == 0
        {
            return Err(invalid());
        }
        self.retained_growth_bytes
            .get()
            .checked_add(self.maximum_simultaneous_transient_bytes.get())
            .and_then(|bytes| bytes.checked_add(self.declared_counter_scratch_bytes.get()))
            .ok_or_else(invalid)
    }

    /// Compares each actual construction term against its original allowance.
    ///
    /// This checks data only. Callers must first authenticate their actual
    /// selected Source birth and native ACK origin; this method creates none.
    ///
    /// # Errors
    /// Refuses invalid rows or an actual component above its own allowance,
    /// even when a different component has unused space.
    pub fn authenticate_actual_data(&self, actual: &Self) -> Result<(), ProviderError> {
        self.requested_peak_data()?;
        actual.requested_peak_data()?;
        if actual.retained_growth_bytes > self.retained_growth_bytes
            || actual.maximum_simultaneous_transient_bytes
                > self.maximum_simultaneous_transient_bytes
            || actual.declared_counter_scratch_bytes > self.declared_counter_scratch_bytes
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Retains both required nullable purpose rows in a closed Source binding13.
///
/// At least one purpose is present. The native birth validator additionally
/// requires the exact correspondence between present rows and the immutable
/// capture/fresh selectors. Missing nullable fields are rejected rather than
/// silently projected to `None`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeReportStartupAllocation {
    /// Names the exact closed startup allocation schema.
    pub schema: String,
    /// Retains the original active Observe12 allowance, or literal null.
    #[serde(deserialize_with = "required_nullable")]
    pub original_observe12: Option<PacketNativeReportStartupAllocationRow>,
    /// Retains the inactive completed-Admit13 allowance, or literal null.
    #[serde(deserialize_with = "required_nullable")]
    pub fresh_completed_admit13: Option<PacketNativeReportStartupAllocationRow>,
}

impl PacketNativeReportStartupAllocation {
    /// Checks the closed schema and returns the exact selected purpose row.
    ///
    /// # Errors
    /// Refuses invalid or empty allocation data, or an absent purpose row.
    pub fn row_data(
        &self,
        purpose: PacketNativeReportStartupPurpose,
    ) -> Result<&PacketNativeReportStartupAllocationRow, ProviderError> {
        self.requested_peak_data()?;
        match purpose {
            PacketNativeReportStartupPurpose::OriginalObserve12 => self.original_observe12.as_ref(),
            PacketNativeReportStartupPurpose::FreshCompletedAdmit13 => {
                self.fresh_completed_admit13.as_ref()
            }
        }
        .ok_or_else(invalid)
    }

    /// Sums retained growth and the largest complete sequential scratch phase.
    ///
    /// Both purposes may leave independent retained owners. Their complete
    /// transient-plus-counter phases execute sequentially under the original
    /// selected publisher, so the largest combined phase is added once.
    ///
    /// # Errors
    /// Refuses another schema, no selected purpose, invalid rows or overflow.
    pub fn requested_peak_data(&self) -> Result<u64, ProviderError> {
        if self.schema != PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA {
            return Err(invalid());
        }
        let mut retained = 0u64;
        let mut phase = 0u64;
        let mut selected = false;
        for row in [self.original_observe12, self.fresh_completed_admit13]
            .into_iter()
            .flatten()
        {
            row.requested_peak_data()?;
            selected = true;
            retained = retained
                .checked_add(row.retained_growth_bytes.get())
                .ok_or_else(invalid)?;
            phase = phase.max(
                row.maximum_simultaneous_transient_bytes
                    .get()
                    .checked_add(row.declared_counter_scratch_bytes.get())
                    .ok_or_else(invalid)?,
            );
        }
        if !selected {
            return Err(invalid());
        }
        retained.checked_add(phase).ok_or_else(invalid)
    }
}

/// Checks the complete declared rows against one explicit invocation target.
///
/// Every positive compiled publisher retains its independent 512 MiB ceiling.
/// The full checked retained sum plus largest complete phase is returned even
/// when it exceeds that per-publisher ceiling. Core separately admits this whole
/// owner aggregate; neither the returned number nor purpose DATA grants access.
/// The private native consumer authenticates its real invocation before entry.
///
/// # Errors
/// Refuses a foreign full target, mismatched selections, absent reachable row,
/// invalid row, per-publisher excess or checked whole-owner overflow.
pub fn original_invocation_report_startup_allocation_peak_data(
    launch: &super::PacketNative5SourceLaunch,
    invocation: &super::native_startup::invocation::PacketNativeInvocationPurposeData,
    original: Option<PacketNativeReportStartupAllocationRow>,
    fresh: Option<PacketNativeReportStartupAllocationRow>,
) -> Result<u64, ProviderError> {
    invocation.authenticate_target_data(launch)?;
    if original.is_some() != launch.capture_allocation_selection.is_some()
        || fresh.is_some() != launch.fresh_restore_allocation_selection.is_some()
    {
        return Err(invalid());
    }
    let reachable = if invocation.is_original_execution_data() {
        original
    } else {
        fresh
    };
    reachable.ok_or_else(invalid)?.requested_peak_data()?;
    invocation_allocation_peak_data(original, fresh)
}

type InvocationRows = (
    Option<PacketNativeReportStartupAllocationRow>,
    Option<PacketNativeReportStartupAllocationRow>,
);

/// Counts declared local headers for the borrowed invocation DATA validator.
///
/// Core prequote and native invocation consumers independently fund this row
/// before validation. This arithmetic has no dependency on a native producer.
pub const fn original_invocation_report_startup_allocation_counter_scratch_data() -> usize {
    use super::native_startup::invocation::PacketNativeInvocationPurposeData;
    use std::mem::size_of;

    size_of::<&PacketNativeInvocationPurposeData>()
        + size_of::<Option<&PacketNativeInvocationPurposeData>>()
        + size_of::<[Option<PacketNativeReportStartupAllocationRow>; 2]>()
        + size_of::<std::array::IntoIter<Option<PacketNativeReportStartupAllocationRow>, 2>>()
        + size_of::<
            std::iter::Flatten<
                std::array::IntoIter<Option<PacketNativeReportStartupAllocationRow>, 2>,
            >,
        >()
        + size_of::<Option<PacketNativeReportStartupAllocationRow>>()
        + size_of::<Result<PacketNativeReportStartupAllocationRow, ProviderError>>()
        + size_of::<InvocationRows>()
        + size_of::<Result<InvocationRows, ProviderError>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<&serde_json::Map<String, serde_json::Value>>()
        + size_of::<Result<&serde_json::Map<String, serde_json::Value>, ProviderError>>()
        + size_of::<u64>()
        + size_of::<bool>()
        + size_of::<[usize; 6]>()
        + size_of::<std::array::IntoIter<usize, 6>>()
}

// The compiled ceiling bounds each publisher's constructor, not the sum of
// independently retained declarations. Keep the complete aggregate checked;
// the actual installed admission remains responsible for funding all owners.
fn invocation_allocation_peak_data(
    original: Option<PacketNativeReportStartupAllocationRow>,
    fresh: Option<PacketNativeReportStartupAllocationRow>,
) -> Result<u64, ProviderError> {
    let mut retained = 0u64;
    let mut phase = 0u64;
    let mut present = false;
    for row in [original, fresh].into_iter().flatten() {
        if row.requested_peak_data()? > 512 * 1024 * 1024 {
            return Err(invalid());
        }
        present = true;
        retained = retained
            .checked_add(row.retained_growth_bytes.get())
            .ok_or_else(invalid)?;
        phase = phase.max(
            row.maximum_simultaneous_transient_bytes
                .get()
                .checked_add(row.declared_counter_scratch_bytes.get())
                .ok_or_else(invalid)?,
        );
    }
    if !present {
        return Err(invalid());
    }
    retained.checked_add(phase).ok_or_else(invalid)
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("original report startup allocation data")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(retained: u64, transient: u64, scratch: u64) -> PacketNativeReportStartupAllocationRow {
        PacketNativeReportStartupAllocationRow {
            raw_report_capacity: U64::new(PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY as u64),
            retained_growth_bytes: U64::new(retained),
            maximum_simultaneous_transient_bytes: U64::new(transient),
            declared_counter_scratch_bytes: U64::new(scratch),
        }
    }

    #[test]
    fn invocation_publishers_keep_exact_individual_caps_and_all_axes() {
        let ceiling = 512 * 1024 * 1024;
        let exact = row(ceiling - 3, 2, 1);
        let second = row(1, 2, 1);
        assert_eq!(
            invocation_allocation_peak_data(Some(exact), Some(second)).unwrap(),
            ceiling + 1
        );
        assert_eq!(
            invocation_allocation_peak_data(Some(second), Some(exact)).unwrap(),
            ceiling + 1
        );

        for exceeded in [
            row(ceiling - 2, 2, 1),
            row(ceiling - 3, 3, 1),
            row(ceiling - 3, 2, 2),
        ] {
            assert!(invocation_allocation_peak_data(Some(exceeded), Some(second)).is_err());
            assert!(invocation_allocation_peak_data(Some(second), Some(exceeded)).is_err());
        }
        assert!(invocation_allocation_peak_data(None, None).is_err());
        assert!(invocation_allocation_peak_data(Some(row(u64::MAX, 2, 1)), None).is_err());
    }

    #[test]
    fn startup_data_requires_literal_nulls_and_refuses_unknown_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let original = PacketNativeReportStartupAllocation {
            schema: PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA.into(),
            original_observe12: Some(row(20, 7, 3)),
            fresh_completed_admit13: None,
        };
        let encoded = serde_json::to_value(&original)?;
        assert_eq!(encoded["fresh_completed_admit13"], serde_json::Value::Null);
        assert_eq!(
            serde_json::from_value::<PacketNativeReportStartupAllocation>(encoded.clone())?,
            original
        );
        let mut omitted = encoded.clone();
        omitted
            .as_object_mut()
            .ok_or("startup object")?
            .remove("fresh_completed_admit13");
        assert!(serde_json::from_value::<PacketNativeReportStartupAllocation>(omitted).is_err());
        let mut unknown = encoded;
        unknown
            .as_object_mut()
            .ok_or("startup object")?
            .insert("permission".into(), true.into());
        assert!(serde_json::from_value::<PacketNativeReportStartupAllocation>(unknown).is_err());
        Ok(())
    }

    #[test]
    fn startup_data_keeps_independent_terms_and_complete_sequential_phases()
    -> Result<(), ProviderError> {
        let data = PacketNativeReportStartupAllocation {
            schema: PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA.into(),
            original_observe12: Some(row(20, 9, 2)),
            fresh_completed_admit13: Some(row(30, 3, 10)),
        };
        assert_eq!(data.requested_peak_data()?, 63);
        let allowed = row(20, 9, 2);
        allowed.authenticate_actual_data(&allowed)?;
        for widened in [row(21, 1, 1), row(1, 10, 1), row(1, 1, 3)] {
            assert!(allowed.authenticate_actual_data(&widened).is_err());
        }
        assert!(row(u64::MAX, 1, 1).requested_peak_data().is_err());
        assert!(row(20, 0, 2).requested_peak_data().is_err());
        Ok(())
    }
}
