//! Derives bounded publication access from the same admitted private birth.
//!
//! The portable row is never an issuer. This private non-Clone owner can only
//! originate from the installed ACK token after its actual boot, policy and
//! source binding13 have been authenticated. It is transient through report
//! publication and must not become an omitted future-affecting Capture owner.

use super::*;
use crate::connection::{Connection, ProviderStream};
use crate::reference_packet::service::report_startup::{
    PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA, PacketNativeReportStartupAllocationRow,
    PacketNativeReportStartupPurpose,
};
use serde_json::{Map, Value};

pub(crate) struct OriginalNativeReportStartupAllocation {
    boot: Rc<RefCell<NativeAckBoot>>,
    policy: Rc<crate::reference_packet::Native5Policy>,
    purpose: PacketNativeReportStartupPurpose,
    row: PacketNativeReportStartupAllocationRow,
    source_digest: blake3::Hash,
}

impl VerifiedCanonicalAckAdmission {
    pub(crate) fn retain_original_report_startup_allocation<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        purpose: PacketNativeReportStartupPurpose,
    ) -> Result<OriginalNativeReportStartupAllocation, ProviderError> {
        self.authenticate_current(connection)?;
        let boot = self.boot.try_borrow().map_err(|_| refused())?;
        let row = boot.report_startup_row_data(purpose)?;
        if purpose == PacketNativeReportStartupPurpose::OriginalObserve12
            && self.policy.capture_allocation_selection()
                != Some(crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12)
        {
            return Err(refused());
        }
        if purpose == PacketNativeReportStartupPurpose::FreshCompletedAdmit13
            && self.policy.fresh_restore_allocation_selection()
                != Some(crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
        {
            return Err(refused());
        }
        let result = OriginalNativeReportStartupAllocation {
            boot: Rc::clone(&self.boot),
            policy: Rc::clone(&self.policy),
            purpose,
            row,
            source_digest: blake3::hash(&boot.source_body),
        };
        drop(boot);
        result.authenticate_current(connection)?;
        Ok(result)
    }
}

impl OriginalNativeReportStartupAllocation {
    pub(crate) const fn purpose_data(&self) -> PacketNativeReportStartupPurpose {
        self.purpose
    }

    pub(crate) fn authenticate_query_header_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: &crate::envelope::Envelope,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        self.policy
            .authenticate_original_report_query_header_data(self.purpose, original)
    }

    pub(crate) fn authenticate_current<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        // This reaches the real registrar/actor/codec/literal identity before
        // either RefCell borrow. Numeric row equality cannot replace it.
        let installed = connection.original_native_owned11_admission()?;
        if !Rc::ptr_eq(&installed.boot, &self.boot) || !Rc::ptr_eq(&installed.policy, &self.policy)
        {
            return Err(refused());
        }
        let boot = self.boot.try_borrow().map_err(|_| refused())?;
        boot.ensure_origin()?;
        if boot.report_startup_row_data(self.purpose)? != self.row
            || blake3::hash(&boot.source_body) != self.source_digest
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl NativeAckBoot {
    fn report_startup_row_data(
        &self,
        purpose: PacketNativeReportStartupPurpose,
    ) -> Result<PacketNativeReportStartupAllocationRow, ProviderError> {
        self.ensure_origin()?;
        if !self.ready
            || !self.verified
            || self.data.source_birth.get("schema").and_then(Value::as_str)
                != Some("source-owned.packet-canonical-ack-source-binding/13")
        {
            return Err(refused());
        }
        let grant = self
            .data
            .source_birth
            .get("report_startup_allocation")
            .and_then(Value::as_object)
            .ok_or_else(refused)?;
        exact_keys(
            grant,
            &["schema", "original_observe12", "fresh_completed_admit13"],
        )?;
        if grant.get("schema").and_then(Value::as_str)
            != Some(PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA)
        {
            return Err(refused());
        }
        let original = row_data(grant.get("original_observe12").ok_or_else(refused)?)?;
        let fresh = row_data(grant.get("fresh_completed_admit13").ok_or_else(refused)?)?;
        let original_selected = self
            .data
            .source_birth
            .get("capture_allocation_selection")
            .and_then(Value::as_str)
            == Some("original_observe12");
        let fresh_selected = self
            .data
            .source_birth
            .get("fresh_restore_allocation_selection")
            .and_then(Value::as_str)
            == Some("completed_admit13");
        if original.is_none() != !original_selected
            || fresh.is_none() != !fresh_selected
            || original.is_none() && fresh.is_none()
        {
            return Err(refused());
        }
        // Both positive purpose terms must fit even when only one is borrowed.
        // The actual startup issuer authenticates the stronger whole-owner sum.
        original
            .into_iter()
            .chain(fresh)
            .try_fold(0u64, |sum, row| {
                sum.checked_add(row.requested_peak_data()?)
                    .ok_or_else(refused)
            })?;
        match purpose {
            PacketNativeReportStartupPurpose::OriginalObserve12 => original,
            PacketNativeReportStartupPurpose::FreshCompletedAdmit13 => fresh,
        }
        .ok_or_else(refused)
    }
}

fn exact_keys(object: &Map<String, Value>, keys: &[&str]) -> Result<(), ProviderError> {
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(refused());
    }
    Ok(())
}

fn row_data(
    value: &Value,
) -> Result<Option<PacketNativeReportStartupAllocationRow>, ProviderError> {
    if value.is_null() {
        return Ok(None);
    }
    let row = value.as_object().ok_or_else(refused)?;
    exact_keys(
        row,
        &[
            "raw_report_capacity",
            "retained_growth_bytes",
            "maximum_simultaneous_transient_bytes",
            "declared_counter_scratch_bytes",
        ],
    )?;
    let read = |key: &str| {
        let raw = row.get(key).and_then(Value::as_str).ok_or_else(refused)?;
        if raw.is_empty()
            || raw.len() > 20
            || !raw.bytes().all(|byte| byte.is_ascii_digit())
            || raw.len() > 1 && raw.starts_with('0')
        {
            return Err(refused());
        }
        Ok(U64::new(raw.parse::<u64>().map_err(|_| refused())?))
    };
    let row = PacketNativeReportStartupAllocationRow {
        raw_report_capacity: read("raw_report_capacity")?,
        retained_growth_bytes: read("retained_growth_bytes")?,
        maximum_simultaneous_transient_bytes: read("maximum_simultaneous_transient_bytes")?,
        declared_counter_scratch_bytes: read("declared_counter_scratch_bytes")?,
    };
    row.requested_peak_data()?;
    Ok(Some(row))
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native report startup original allocation differs")
}

/// Names this actual private owner header; it carries no heap or permission.
pub(crate) const fn original_native_report_startup_scope_layout_data() -> usize {
    std::mem::size_of::<OriginalNativeReportStartupAllocation>()
}

// Invoked by the actual private boot validator before ACK installation. No
// report-selection branch can boot with omitted, foreign or unmatched rows.
pub(super) fn authenticate_binding_data(
    value: &Value,
    capture: Option<crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection>,
    fresh: Option<crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection>,
) -> Result<(), ProviderError> {
    let object = value.as_object().ok_or_else(refused)?;
    exact_keys(
        object,
        &["schema", "original_observe12", "fresh_completed_admit13"],
    )?;
    if object.get("schema").and_then(Value::as_str)
        != Some(PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA)
    {
        return Err(refused());
    }
    let original = row_data(object.get("original_observe12").ok_or_else(refused)?)?;
    let inactive = row_data(object.get("fresh_completed_admit13").ok_or_else(refused)?)?;
    if original.is_some() != capture.is_some()
        || inactive.is_some() != fresh.is_some()
        || original.is_none() && inactive.is_none()
    {
        return Err(refused());
    }
    let mut retained = 0u64;
    let mut phase = 0u64;
    for row in [original, inactive].into_iter().flatten() {
        retained = retained
            .checked_add(row.retained_growth_bytes.get())
            .ok_or_else(refused)?;
        phase = phase.max(
            row.maximum_simultaneous_transient_bytes
                .get()
                .checked_add(row.declared_counter_scratch_bytes.get())
                .ok_or_else(refused)?,
        );
    }
    if retained
        .checked_add(phase)
        .is_none_or(|bytes| bytes > 512 * 1024 * 1024)
    {
        return Err(refused());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection;

    fn allocation() -> Value {
        serde_json::json!({
            "schema": PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA,
            "original_observe12": {
                "raw_report_capacity": "16384",
                "retained_growth_bytes": "100",
                "maximum_simultaneous_transient_bytes": "200",
                "declared_counter_scratch_bytes": "300"
            },
            "fresh_completed_admit13": null
        })
    }

    #[test]
    fn private_birth_startup_rows_require_matching_selected_purpose() {
        let original = Some(PacketNative5CaptureAllocationSelection::OriginalObserve12);
        let data = allocation();

        assert!(authenticate_binding_data(&data, original, None).is_ok());
        assert!(authenticate_binding_data(&data, None, None).is_err());
        let mut missing = data.clone();
        if let Some(fields) = missing.as_object_mut() {
            fields.remove("fresh_completed_admit13");
        }
        assert!(authenticate_binding_data(&missing, original, None).is_err());
        let mut extra = data;
        extra["unexpected"] = Value::Null;
        assert!(authenticate_binding_data(&extra, original, None).is_err());
    }

    #[test]
    fn private_birth_startup_rows_refuse_noncanonical_or_overflowing_credit() {
        let original = Some(PacketNative5CaptureAllocationSelection::OriginalObserve12);
        for value in ["0", "0100", "18446744073709551616"] {
            let mut data = allocation();
            data["original_observe12"]["retained_growth_bytes"] = Value::from(value);
            assert!(authenticate_binding_data(&data, original, None).is_err());
        }
        let mut oversized = allocation();
        oversized["original_observe12"]["retained_growth_bytes"] = Value::from("536870913");
        assert!(authenticate_binding_data(&oversized, original, None).is_err());
    }
}
