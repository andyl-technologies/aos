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
use crate::retained_metadata::{
    MetadataObserver, NativeCaptureMetadataRoots, aliases::MetadataSharedKind,
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

    /// Requires the real Source14 baseline before checking initial model state.
    ///
    /// Invocation15 and old public paths retain their existing broad projection.
    /// The wire row never selects this restriction or grants an initial owner.
    ///
    /// # Errors
    /// Refuses stale boot/connection identity, incomplete actual Source14 birth,
    /// changed Control selection or any noninitial original model state.
    pub(crate) fn authenticate_original_initial_observation_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        native: &crate::reference_packet::control::PacketControl,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        let boot = self.boot.try_borrow().map_err(|_| refused())?;
        if self.purpose == PacketNativeReportStartupPurpose::OriginalObserve12
            && boot.data.source_birth.get("schema").and_then(Value::as_str)
                == Some(crate::reference_packet::service::native_startup::PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA)
        {
            boot.authenticate_original_native_baseline_data()?;
            let selection = native.original_initial_observation_selection_data()?;
            self.policy.authenticate_original_control_selection(selection)?;
        }
        Ok(())
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

    pub(crate) fn fresh_restore_nonce_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<[u8; 32], ProviderError> {
        self.authenticate_fresh_purpose(connection)?;
        let boot = self.boot.try_borrow().map_err(|_| refused())?;
        boot.ensure_origin()?;
        let key: &[u8; 32] = boot
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        let nonce = crate::reference_packet::service::fresh_restore_allocation::fresh_restore_allocation_nonce_data(key);
        drop(boot);
        self.authenticate_fresh_purpose(connection)?;
        Ok(nonce)
    }

    pub(crate) fn fresh_restore_ack_context_digest_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<[u8; 32], ProviderError> {
        self.authenticate_fresh_purpose(connection)?;
        let boot = self.boot.try_borrow().map_err(|_| refused())?;
        boot.ensure_origin()?;
        let digest = boot
            .proof
            .as_ref()
            .ok_or_else(refused)?
            .context_digest
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        drop(boot);
        self.authenticate_fresh_purpose(connection)?;
        Ok(digest)
    }

    pub(crate) fn fresh_restore_report_proof_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        data: &crate::reference_packet::service::fresh_restore_allocation::PacketNativeFreshRestoreAllocationData,
    ) -> Result<crate::reference_packet::service::fresh_restore_allocation::PacketNativeFreshRestoreAllocationProof, ProviderError>{
        self.authenticate_fresh_purpose(connection)?;
        if data.scope.ack_context.as_slice()
            != self.fresh_restore_ack_context_digest_data(connection)?
            || data.scope.nonce.as_slice() != self.fresh_restore_nonce_data(connection)?
        {
            return Err(refused());
        }
        let boot = self.boot.try_borrow().map_err(|_| refused())?;
        boot.ensure_origin()?;
        let key: &[u8; 32] = boot
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        let proof = crate::reference_packet::service::fresh_restore_allocation::fresh_restore_allocation_proof_data(key, data)?;
        drop(boot);
        self.authenticate_fresh_purpose(connection)?;
        Ok(proof)
    }

    fn authenticate_fresh_purpose<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        if self.purpose != PacketNativeReportStartupPurpose::FreshCompletedAdmit13 {
            return Err(refused());
        }
        Ok(())
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

    /// Requires the same genuine complete native baseline construction owner.
    ///
    /// Portable report rows/selection cannot substitute for the actual private
    /// boot6 owner. The legacy boot5 constructor initializes None and continues
    /// to refuse here. Only Source189's independent admitted bootstrap/lifecycle
    /// can eventually satisfy the complete baseline guard.
    ///
    /// # Errors
    /// Refuses changed origin, missing baseline owner or an unfinished/changed
    /// private startup lifecycle before report/cache/proof materialization.
    pub(crate) fn authenticate_complete_native_baseline<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        let boot = self.boot.try_borrow().map_err(|_| refused())?;
        if boot.data.schema == crate::reference_packet::service::native_startup::PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA {
            boot.authenticate_original_invocation_report_purpose_data(self.purpose)
        } else {
            boot.authenticate_original_native_baseline_data()
        }
    }

    pub(crate) fn maximum_requested_bytes(&self) -> Result<usize, ProviderError> {
        let maximum = usize::try_from(self.row.requested_peak_data()?).map_err(|_| refused())?;
        if maximum > 512 * 1024 * 1024 {
            return Err(refused());
        }
        Ok(maximum)
    }

    // A whole caller must invoke this before its full quote capsule or complete
    // report owner is constructed. The closed pre-child allowance is not a
    // promise that any future changed private layout will fit it.
    pub(crate) fn authenticate_compiled_headers<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        quote: usize,
        owner: usize,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        if quote
            > usize::try_from(self.row.declared_counter_scratch_bytes.get())
                .map_err(|_| refused())?
            || owner
                > usize::try_from(self.row.retained_growth_bytes.get()).map_err(|_| refused())?
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn authenticate_actual_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        actual: &PacketNativeReportStartupAllocationRow,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        self.row.authenticate_actual_data(actual)
    }

    pub(crate) fn observe_unique_capture_metadata<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        roots: &mut NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        let Self {
            boot,
            policy,
            purpose,
            row,
            source_digest,
        } = self;
        if roots.observe_shared(observer, MetadataSharedKind::NativeBoot, boot.as_ref())? {
            boot.try_borrow()
                .map_err(|_| refused())?
                .observe_unique_capture_metadata(roots, observer)?;
        }
        if roots.observe_shared(observer, MetadataSharedKind::NativePolicy, policy.as_ref())? {
            policy.observe_unique_capture_metadata(roots, observer)?;
        }
        observer.observe(&match purpose {
            PacketNativeReportStartupPurpose::OriginalObserve12 => 0u8,
            PacketNativeReportStartupPurpose::FreshCompletedAdmit13 => 1u8,
        })?;
        observer.observe(&row.raw_report_capacity)?;
        observer.observe(&row.retained_growth_bytes)?;
        observer.observe(&row.maximum_simultaneous_transient_bytes)?;
        observer.observe(&row.declared_counter_scratch_bytes)?;
        // The fixed digest has no owned children. Its complete inline storage
        // is part of this capsule's actual compiled scratch/header layout.
        observer.observe(&source_digest.as_bytes().len())?;
        self.authenticate_current(connection)
    }
}

impl NativeAckBoot {
    fn report_startup_row_data(
        &self,
        purpose: PacketNativeReportStartupPurpose,
    ) -> Result<PacketNativeReportStartupAllocationRow, ProviderError> {
        self.ensure_origin()?;
        if !self.ready || !self.verified {
            return Err(refused());
        }
        match self.data.source_birth.get("schema").and_then(Value::as_str) {
            Some("source-owned.packet-canonical-ack-source-binding/13") => {
                // Existing publication rows remain DATA under the old origin;
                // authenticate_complete_native_baseline still refuses None.
            }
            Some("source-owned.packet-canonical-ack-source-binding/14") => {
                // Do not accept a new schema label as evidence. This checks
                // real boot6 issuance/completion and unchanged source, launch
                // and private birth before reading a purpose's existing row.
                self.authenticate_original_native_baseline_data()?;
                let source = self.data.source_birth.as_object().ok_or_else(refused)?;
                exact_keys(
                    source,
                    &[
                        "schema",
                        "selection",
                        "program",
                        "coordinator",
                        "limits",
                        "storage",
                        "capture_profile",
                        "confirmation_selection",
                        "ack_emitter_selection",
                        "codec_metadata_extent",
                        "native_codec_metadata_extent",
                        "protocol_metadata_limits",
                        "complete_restore_selection",
                        "restore_input_emitter_selection",
                        "capture_allocation_selection",
                        "fresh_restore_allocation_selection",
                        "report_startup_allocation",
                        "native_startup_allocation",
                    ],
                )?;
            }
            Some("source-owned.packet-canonical-ack-source-binding/15") => {
                // Actual private issuance, completed baseline and immutable full
                // identities precede use of the purpose's existing report row.
                self.authenticate_original_invocation_report_purpose_data(purpose)?;
            }
            _ => return Err(refused()),
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
        + crate::reference_packet::control::PacketControl::original_initial_observation_counter_scratch_data()
        + std::mem::size_of::<Result<(), ProviderError>>()
        + std::mem::size_of::<&crate::reference_packet::control::PacketControl>()
        + std::mem::size_of::<std::cell::Ref<'static, NativeAckBoot>>()
        + std::mem::size_of::<Result<std::cell::Ref<'static, NativeAckBoot>, std::cell::BorrowError>>()
        + std::mem::size_of::<Result<std::cell::Ref<'static, NativeAckBoot>, ProviderError>>()
        + std::mem::size_of::<Option<&Value>>()
        + std::mem::size_of::<Option<&str>>()
        + std::mem::size_of::<Result<&crate::reference_packet::control::PacketControlSelection, ProviderError>>()
        + std::mem::size_of::<bool>()
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

// Only prepare_retained_data's authenticated private invocation branch calls
// this validator. Legacy Source13/14 retains authenticate_binding_data exactly.
pub(super) fn authenticate_invocation_binding_data(
    value: &Value,
    launch: &PacketNative5SourceLaunch,
    invocation: &crate::reference_packet::service::native_startup::PacketNativeInvocationPurposeData,
) -> Result<(), ProviderError> {
    let (original, fresh) = invocation_rows(value)?;
    crate::reference_packet::service::report_startup::original_invocation_report_startup_allocation_peak_data(
        launch, invocation, original, fresh,
    )?;
    Ok(())
}

fn invocation_rows(
    value: &Value,
) -> Result<
    (
        Option<PacketNativeReportStartupAllocationRow>,
        Option<PacketNativeReportStartupAllocationRow>,
    ),
    ProviderError,
> {
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
    // Reuse the exact canonical decimal/raw-capacity/positive-axis reader.
    Ok((
        row_data(object.get("original_observe12").ok_or_else(refused)?)?,
        row_data(object.get("fresh_completed_admit13").ok_or_else(refused)?)?,
    ))
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

    #[test]
    fn invocation_rows_preserve_full_pair_and_legacy_aggregate_refusal() {
        let data = serde_json::json!({
            "schema": PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA,
            "original_observe12": {
                "raw_report_capacity": "16384",
                "retained_growth_bytes": "167671065",
                "maximum_simultaneous_transient_bytes": "203707650",
                "declared_counter_scratch_bytes": "992065"
            },
            "fresh_completed_admit13": {
                "raw_report_capacity": "16384",
                "retained_growth_bytes": "266139595",
                "maximum_simultaneous_transient_bytes": "266755905",
                "declared_counter_scratch_bytes": "992065"
            }
        });
        let (original, fresh) = invocation_rows(&data).unwrap();
        let allocation =
            crate::reference_packet::service::report_startup::PacketNativeReportStartupAllocation {
                schema: PACKET_NATIVE_REPORT_STARTUP_ALLOCATION_SCHEMA.into(),
                original_observe12: original,
                fresh_completed_admit13: fresh,
            };
        assert_eq!(allocation.requested_peak_data().unwrap(), 701_558_630);
        assert!(authenticate_binding_data(
            &data,
            Some(PacketNative5CaptureAllocationSelection::OriginalObserve12),
            Some(crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13),
        ).is_err());
        for field in ["original_observe12", "fresh_completed_admit13"] {
            let mut changed = data.clone();
            changed.as_object_mut().unwrap().remove(field);
            assert!(invocation_rows(&changed).is_err());
            changed = data.clone();
            changed[field] = serde_json::json!({"unknown": "field"});
            assert!(invocation_rows(&changed).is_err());
            changed = data.clone();
            changed[field]["retained_growth_bytes"] = Value::from("00");
            assert!(invocation_rows(&changed).is_err());
        }
        let mut unknown = data;
        unknown["unknown"] = Value::Null;
        assert!(invocation_rows(&unknown).is_err());
        assert!(invocation_rows(&Value::Null).is_err());
    }
}

#[path = "fresh_query_frontier.rs"]
mod fresh_query_frontier;
pub(crate) use fresh_query_frontier::OriginalNativeFreshQueryFrontierData;

#[path = "report_startup/settled17.rs"]
mod settled17;
pub(crate) use settled17::HistoricalReportStartupAllocation17;
