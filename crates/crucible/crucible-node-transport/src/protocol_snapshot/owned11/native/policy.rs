//! Reconstructs an inert complete native policy from its explicit eleven leaf.

use super::super::{
    state::{next, tag},
    typed::{Fields, HistoricalType, Ledger, invalid},
};
use crate::reference_packet::service::confirmation::PacketNative5ConfirmationSelection;
use crate::reference_packet::service::{
    PacketNative5AckEmitterSelection, PacketNative5CaptureProfile,
};
use crate::reference_packet::{
    control::PacketControlSelection, coordinator::PacketNative5CoordinatorInstallation,
};
use crate::{ProviderError, client::CanonicalAckCodecMetadataExtent};
use crucible_node_format::ContentRef;

mod capture;
mod fresh;

/// Owns all immutable native policy fields as inert historical data.
pub struct HistoricalNativePolicy {
    /// Retains the complete source-selected control declaration.
    pub selection: PacketControlSelection,
    /// Retains the full installed coordinator reference.
    pub coordinator_reference: ContentRef,
    /// Retains every coordinator byte and its original Vec capacity.
    pub coordinator_bytes: Vec<u8>,
    /// Retains the actual complete ingress schema reference.
    pub definition: ContentRef,
    /// Retains the complete decoded typed coordinator state.
    pub connected: PacketNative5CoordinatorInstallation,
    /// Retains the explicitly selected protocol encoding and all three bounds.
    pub capture_profile: PacketNative5CaptureProfile,
    /// Retains the closed confirmation choice independently from activation.
    pub confirmation_selection: Option<PacketNative5ConfirmationSelection>,
    /// Retains the full installed confirmation schema reference.
    pub confirmation_definition: Option<ContentRef>,
    /// Retains the closed writer choice independently from native activation.
    pub ack_emitter_selection: Option<PacketNative5AckEmitterSelection>,
    /// Retains the full installed canonical ACK schema reference.
    pub ack_emitter_definition: Option<ContentRef>,
    /// Retains the closed native immutable metadata extent independently.
    pub native_codec_metadata_extent: Option<CanonicalAckCodecMetadataExtent>,
    /// Retains the separate source-signed restoration mechanism as inert data.
    pub complete_restore_selection: Option<
        crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection,
    >,
    /// Retains all three original installed restore schema definitions.
    pub complete_restore_definitions: Option<[ContentRef; 3]>,
    /// Retains all seven separately selected phase12 definitions.
    pub complete_restore_transfer_definitions: Option<[ContentRef; 7]>,
    /// Retains the selected canonical input writer as historical data.
    pub restore_input_emitter_selection: Option<crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection>,
    /// Retains its exact immutable schema definition.
    pub restore_input_emitter_definition: Option<ContentRef>,
    /// Retains the original Observe allocation-report selection as data only.
    pub capture_allocation_selection: Option<crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection>,
    /// Retains both full report and record definitions, in that order.
    pub capture_allocation_definitions: Option<[ContentRef; 2]>,
    /// Retains the completed-Admit fresh report selection as inert data only.
    pub fresh_restore_allocation_selection: Option<crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection>,
    /// Retains full Query, Report, Proof, Receipt and PrepareBinding definitions.
    pub fresh_restore_allocation_definitions: Option<[ContentRef; 5]>,
    /// Retains independent selected row allowances without installation rights.
    pub protocol_metadata_limits:
        Option<crate::reference_packet::service::PacketNative5ProtocolMetadataLimits>,
}

impl HistoricalNativePolicy {
    fn read_selected(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
        allow_transfer: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let policy_tag = super::super::typed::plain_string(next(&mut fields)?)?;
        if policy_tag == fresh::FRESH_POLICY_FORMAT {
            return fresh::read_selected(fields, ledger, build, allow_transfer);
        }
        if policy_tag == capture::CAPTURE_POLICY_FORMAT {
            return capture::read_selected(fields, ledger, build, allow_transfer);
        }
        if policy_tag == "source-private.native5-policy-owned-restore-input-emitter/16" {
            if allow_transfer
                || super::super::typed::plain_string(next(&mut fields)?)?
                    != "CanonicalSdkRestoreInputs12"
            {
                return Err(invalid());
            }
            let raw_definition = next(&mut fields)?;
            if raw_definition == b"null" {
                return Err(invalid());
            }
            let base = next(&mut fields)?;
            let mut header = Fields::array(base)?;
            tag(
                &mut header,
                "source-private.native5-policy-owned-restore-transfer/15",
            )?;
            let policy = Self::read_selected(base, ledger, build, false)?;
            let definition = ledger.read::<ContentRef>(raw_definition, build)?;
            fields.finish()?;
            return match policy {
                Some(mut policy) => {
                    if policy.restore_input_emitter_selection.is_some() || policy.restore_input_emitter_definition.is_some()
                        || policy.complete_restore_selection != Some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12) { return Err(invalid()); }
                    policy.restore_input_emitter_selection = Some(crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12);
                    policy.restore_input_emitter_definition = Some(definition.ok_or_else(invalid)?);
                    Ok(Some(policy))
                }
                None => Ok(None),
            };
        }
        if policy_tag == "source-private.native5-policy-owned-restore-transfer/15" {
            if allow_transfer {
                return Err(invalid());
            }
            let raw_definitions = next(&mut fields)?;
            if raw_definitions == b"null" {
                return Err(invalid());
            }
            let base = next(&mut fields)?;
            let mut header = Fields::array(base)?;
            tag(
                &mut header,
                "source-private.native5-policy-owned-complete-restore/14",
            )?;
            let policy = Self::read_selected(base, ledger, build, true)?;
            let mut definitions = Fields::array(raw_definitions)?;
            let mut owners: [Option<ContentRef>; 7] = std::array::from_fn(|_| None);
            for owner in &mut owners {
                *owner = ledger.read::<ContentRef>(next(&mut definitions)?, build)?;
            }
            definitions.finish()?;
            fields.finish()?;
            return match policy {
                Some(mut policy) => {
                    if policy.complete_restore_selection != Some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                        || policy.complete_restore_transfer_definitions.is_some() { return Err(invalid()); }
                    let [a, b, c, d, e, f, g] = owners;
                    policy.complete_restore_transfer_definitions = Some([
                        a.ok_or_else(invalid)?,
                        b.ok_or_else(invalid)?,
                        c.ok_or_else(invalid)?,
                        d.ok_or_else(invalid)?,
                        e.ok_or_else(invalid)?,
                        f.ok_or_else(invalid)?,
                        g.ok_or_else(invalid)?,
                    ]);
                    Ok(Some(policy))
                }
                None => Ok(None),
            };
        }
        if policy_tag == "source-private.native5-policy-owned-complete-restore/14" {
            let selected = super::super::typed::plain_string(next(&mut fields)?)?;
            if selected
                != if allow_transfer {
                    "SourceSignedTransfer12"
                } else {
                    "SourceSignedOwned11"
                }
            {
                return Err(invalid());
            }
            let raw_definitions = next(&mut fields)?;
            if raw_definitions == b"null" {
                return Err(invalid());
            }
            let policy = Self::read_selected(next(&mut fields)?, ledger, build, false)?;
            let mut definitions = Fields::array(raw_definitions)?;
            let mut owners = std::array::from_fn::<_, 3, _>(|_| None);
            for owner in &mut owners {
                *owner = ledger.read::<ContentRef>(next(&mut definitions)?, build)?;
            }
            definitions.finish()?;
            fields.finish()?;
            return match policy {
                Some(mut policy) => {
                    if policy.complete_restore_selection.is_some()
                        || policy.protocol_metadata_limits.is_none()
                    {
                        return Err(invalid());
                    }
                    let [a, b, c] = owners;
                    policy.complete_restore_selection = Some(if allow_transfer {
                        crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12
                    } else {
                        crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedOwned11
                    });
                    policy.complete_restore_definitions = Some([
                        a.ok_or_else(invalid)?,
                        b.ok_or_else(invalid)?,
                        c.ok_or_else(invalid)?,
                    ]);
                    Ok(Some(policy))
                }
                None => Ok(None),
            };
        }
        if policy_tag == "source-private.native5-policy-owned-selected/13" {
            let limits = ledger
                .read::<crate::reference_packet::service::PacketNative5ProtocolMetadataLimits>(
                    next(&mut fields)?,
                    true,
                )?
                .ok_or_else(invalid)?;
            limits.validate_data()?;
            let original = next(&mut fields)?;
            let mut original_fields = Fields::array(original)?;
            tag(
                &mut original_fields,
                "source-private.native5-policy-owned/11",
            )?;
            for _ in 0..4 {
                next(&mut original_fields)?;
            }
            let mut profile = Fields::object(next(&mut original_fields)?)?;
            if super::super::typed::plain_string(profile.named("encoding")?)? != "owned_protocol11"
            {
                return Err(invalid());
            }
            let policy = Self::read(original, ledger, build)?;
            fields.finish()?;
            return match policy {
                Some(mut policy) => {
                    if policy.protocol_metadata_limits.is_some() {
                        return Err(invalid());
                    }
                    policy.protocol_metadata_limits = Some(limits);
                    Ok(Some(policy))
                }
                None => Ok(None),
            };
        }
        if policy_tag != "source-private.native5-policy-owned/11" {
            return Err(invalid());
        }
        let selection = ledger.read::<PacketControlSelection>(next(&mut fields)?, build)?;
        let mut coordinator = Fields::array(next(&mut fields)?)?;
        let coordinator_reference = ledger.read::<ContentRef>(next(&mut coordinator)?, build)?;
        let capacity = next(&mut coordinator)?;
        let bytes = next(&mut coordinator)?;
        coordinator.finish()?;
        let recorded = ledger.row(
            crate::retained_metadata::records::MetadataRecordKind::Vector,
            1,
        )?;
        let expected =
            usize::try_from(super::super::typed::unsigned(capacity)?).map_err(|_| invalid())?;
        if recorded != expected {
            return Err(invalid());
        }
        let plan = crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes::validate(
            bytes,
            ledger.limits.maximum_input_bytes,
            expected,
        )?;
        let definition = ledger.read::<ContentRef>(next(&mut fields)?, build)?;
        let connected =
            ledger.read::<PacketNative5CoordinatorInstallation>(next(&mut fields)?, build)?;
        let capture_profile =
            ledger.read::<PacketNative5CaptureProfile>(next(&mut fields)?, build)?;
        let confirmation_selection =
            ledger.read::<Option<PacketNative5ConfirmationSelection>>(next(&mut fields)?, build)?;
        let confirmation_definition =
            ledger.read::<Option<ContentRef>>(next(&mut fields)?, build)?;
        let ack_emitter_selection =
            ledger.read::<Option<PacketNative5AckEmitterSelection>>(next(&mut fields)?, build)?;
        let ack_emitter_definition =
            ledger.read::<Option<ContentRef>>(next(&mut fields)?, build)?;
        let native_codec_metadata_extent =
            ledger.read::<Option<CanonicalAckCodecMetadataExtent>>(next(&mut fields)?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        let mut coordinator_bytes = Vec::new();
        coordinator_bytes
            .try_reserve_exact(expected)
            .map_err(|_| invalid())?;
        if coordinator_bytes.capacity() != expected {
            return Err(invalid());
        }
        plan.fill_preowned(&mut coordinator_bytes)?;
        Ok(Some(Self {
            selection: selection.ok_or_else(invalid)?,
            coordinator_reference: coordinator_reference.ok_or_else(invalid)?,
            coordinator_bytes,
            definition: definition.ok_or_else(invalid)?,
            connected: connected.ok_or_else(invalid)?,
            capture_profile: capture_profile.ok_or_else(invalid)?,
            confirmation_selection: confirmation_selection.ok_or_else(invalid)?,
            confirmation_definition: confirmation_definition.ok_or_else(invalid)?,
            ack_emitter_selection: ack_emitter_selection.ok_or_else(invalid)?,
            ack_emitter_definition: ack_emitter_definition.ok_or_else(invalid)?,
            native_codec_metadata_extent: native_codec_metadata_extent.ok_or_else(invalid)?,
            protocol_metadata_limits: None,
            complete_restore_selection: None,
            complete_restore_definitions: None,
            complete_restore_transfer_definitions: None,
            restore_input_emitter_selection: None,
            restore_input_emitter_definition: None,
            capture_allocation_selection: None,
            capture_allocation_definitions: None,
            fresh_restore_allocation_selection: None,
            fresh_restore_allocation_definitions: None,
        }))
    }
}

impl HistoricalType for crate::reference_packet::service::PacketNative5ProtocolMetadataLimits {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let native_before_rows = ledger
            .read::<crucible_node_format::U64>(fields.named("native_before_rows")?, true)?
            .ok_or_else(invalid)?;
        let native_after_rows = ledger
            .read::<crucible_node_format::U64>(fields.named("native_after_rows")?, true)?
            .ok_or_else(invalid)?;
        fields.finish()?;
        let limits = Self {
            native_before_rows,
            native_after_rows,
        };
        limits.validate_data()?;
        Ok(build.then_some(limits))
    }
}

impl HistoricalType for HistoricalNativePolicy {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_selected(input, ledger, build, false)
    }
}

/// Detects the explicit fresh wrapper without consuming rows or creating data.
pub(super) fn requires_fresh_startup_class_data(input: &[u8]) -> Result<bool, ProviderError> {
    let mut fields = Fields::array(input)?;
    Ok(super::super::typed::plain_string(next(&mut fields)?)? == fresh::FRESH_POLICY_FORMAT)
}

// The closed owning walk fails to compile if a historical field is added.
super::super::retained_storage::fields!(
    HistoricalNativePolicy,
    selection,
    coordinator_reference,
    coordinator_bytes,
    definition,
    connected,
    capture_profile,
    confirmation_selection,
    confirmation_definition,
    ack_emitter_selection,
    ack_emitter_definition,
    native_codec_metadata_extent,
    complete_restore_selection,
    complete_restore_definitions,
    complete_restore_transfer_definitions,
    restore_input_emitter_selection,
    restore_input_emitter_definition,
    capture_allocation_selection,
    capture_allocation_definitions,
    fresh_restore_allocation_selection,
    fresh_restore_allocation_definitions,
    protocol_metadata_limits
);

pub(crate) mod current17;

/// Names every simultaneously retained policy-wrapper frame under raw depth128.
///
/// The complete native validator first enforces the outer structural depth
/// before invoking this direct recursive reader. Array/iterator controls belong
/// to the actual7/3-reference wrapper branches, not another model's allowance.
pub(super) fn borrowed_validation_counter_scratch_data() -> usize {
    use std::mem::size_of;
    let wrapper = size_of::<Option<HistoricalNativePolicy>>()
        + size_of::<Result<Option<HistoricalNativePolicy>, ProviderError>>()
        + size_of::<Fields<'static>>() * 3
        + size_of::<[Option<ContentRef>; 7]>()
        + size_of::<[Option<ContentRef>; 3]>()
        + size_of::<[Option<ContentRef>; 5]>()
        + size_of::<[&[u8]; 5]>()
        + size_of::<std::slice::IterMut<'static, &[u8]>>()
        + size_of::<
            std::iter::Zip<
                std::slice::IterMut<'static, Option<ContentRef>>,
                std::array::IntoIter<&'static [u8], 5>,
            >,
        >()
        + size_of::<Option<(&'static mut Option<ContentRef>, &'static [u8])>>()
        + size_of::<std::slice::IterMut<'static, Option<ContentRef>>>()
        + size_of::<Option<&'static mut Option<ContentRef>>>()
        + size_of::<Option<ContentRef>>()
        + size_of::<Result<Option<ContentRef>, ProviderError>>()
        + size_of::<bool>();
    wrapper * super::super::outer::OUTER_WORK_MAXIMUM_DEPTH
        + <PacketControlSelection as HistoricalType>::borrowed_header_counter_scratch_data()
        + <ContentRef as HistoricalType>::borrowed_header_counter_scratch_data() * 13
        + <PacketNative5CoordinatorInstallation as HistoricalType>::borrowed_header_counter_scratch_data()
        + <PacketNative5CaptureProfile as HistoricalType>::borrowed_header_counter_scratch_data()
        + <Option<PacketNative5ConfirmationSelection> as HistoricalType>::borrowed_header_counter_scratch_data()
        + <Option<PacketNative5AckEmitterSelection> as HistoricalType>::borrowed_header_counter_scratch_data()
        + <Option<CanonicalAckCodecMetadataExtent> as HistoricalType>::borrowed_header_counter_scratch_data()
        + <crate::reference_packet::service::PacketNative5ProtocolMetadataLimits as HistoricalType>::borrowed_header_counter_scratch_data()
}
