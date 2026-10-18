//! Reads complete native Policy17 fields without constructing an installed policy.
//!
//! ```text
//! {schema,selection,coordinator,definition,connected,capture_profile,...}
//! ```
//!
//! All optional definitions retain their independent state, including partial
//! pairs. The same caller ledger checks repeated full policy bytes and capacity
//! rows; decoded selections and declarations provide no route or startup grant.

use super::*;
use crate::connection::settled17::read_byte_bank_parts17;
use crate::protocol_snapshot::owned11::{
    native::policy::HistoricalNativePolicy,
    typed::{Fields, HistoricalType, Ledger, invalid, plain_string, unsigned},
};
use crate::retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind};
use std::mem::{align_of, size_of};

/// Stores complete policy DATA and its archive-local shared group.
pub(crate) struct HistoricalNativePolicy17 {
    pub(crate) data: HistoricalNativePolicy,
    pub(crate) group: usize,
}

/// Reads one complete policy group through the caller's shared ledger.
///
/// # Errors
/// Refuses another edition, malformed fields, changed rows/aliases or exhausted
/// caller backing. No native policy constructor or feature admission runs.
pub(crate) fn read_native17_policy_root_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<HistoricalNativePolicy17>, usize), ProviderError> {
    let start = ledger.rows.encoded_position();
    let layout = size_of::<Native5Policy>();
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, align_of::<Native5Policy>())? != layout {
        return Err(invalid());
    }
    let group = ledger.shared_begin(MetadataSharedKind::NativePolicy)?;
    let data = read_policy(input, ledger, build)?;
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout, input, rows)?;
    Ok((
        data.map(|data| HistoricalNativePolicy17 { data, group }),
        group,
    ))
}

fn read_policy(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalNativePolicy>, ProviderError> {
    let mut fields = Fields::object(input)?;
    if plain_string(fields.named("schema")?)? != "source-private.native5-policy-restored-settled/17"
    {
        return Err(invalid());
    }
    let selection = ledger.read::<PacketControlSelection>(fields.named("selection")?, build)?;
    let mut coordinator = Fields::array(fields.named("coordinator")?)?;
    let coordinator_reference =
        ledger.read::<ContentRef>(coordinator.next()?.ok_or_else(invalid)?, build)?;
    let capacity = usize::try_from(unsigned(coordinator.next()?.ok_or_else(invalid)?)?)
        .map_err(|_| invalid())?;
    let coordinator_bytes = read_byte_bank_parts17(
        coordinator.next()?.ok_or_else(invalid)?,
        capacity,
        ledger,
        build,
    )?;
    coordinator.finish()?;
    let definition = ledger.read::<ContentRef>(fields.named("definition")?, build)?;
    let connected =
        ledger.read::<PacketNative5CoordinatorInstallation>(fields.named("connected")?, build)?;
    let capture_profile = ledger
        .read::<crate::reference_packet::service::PacketNative5CaptureProfile>(
            fields.named("capture_profile")?,
            build,
        )?;
    let confirmation_selection = ledger.read::<Option<
        crate::reference_packet::service::PacketNative5ConfirmationSelection,
    >>(fields.named("confirmation_selection")?, build)?;
    let confirmation_definition =
        ledger.read::<Option<ContentRef>>(fields.named("confirmation_definition")?, build)?;
    let ack_emitter_selection = ledger.read::<Option<
        crate::reference_packet::service::PacketNative5AckEmitterSelection,
    >>(fields.named("ack_emitter_selection")?, build)?;
    let ack_emitter_definition =
        ledger.read::<Option<ContentRef>>(fields.named("ack_emitter_definition")?, build)?;
    let native_codec_metadata_extent =
        ledger.read::<Option<crate::client::CanonicalAckCodecMetadataExtent>>(
            fields.named("native_codec_metadata_extent")?,
            build,
        )?;
    let protocol_metadata_limits = ledger.read::<Option<
        crate::reference_packet::service::PacketNative5ProtocolMetadataLimits,
    >>(fields.named("protocol_metadata_limits")?, build)?;
    let complete_restore_selection = ledger.read::<Option<
        crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection,
    >>(
        fields.named("complete_restore_selection")?, build
    )?;
    let complete_restore_definitions = ledger
        .read::<Option<[ContentRef; 3]>>(fields.named("complete_restore_definitions")?, build)?;
    let complete_restore_transfer_definitions = ledger.read::<Option<[ContentRef; 7]>>(
        fields.named("complete_restore_transfer_definitions")?,
        build,
    )?;
    let restore_input_emitter_selection = ledger.read::<Option<
        crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection
    >>(
        fields.named("restore_input_emitter_selection")?, build
    )?;
    let restore_input_emitter_definition = ledger
        .read::<Option<ContentRef>>(fields.named("restore_input_emitter_definition")?, build)?;
    let capture_allocation_selection = ledger.read::<Option<
        crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection
    >>(
        fields.named("capture_allocation_selection")?, build
    )?;
    let capture_allocation_definitions = ledger
        .read::<Option<[ContentRef; 2]>>(fields.named("capture_allocation_definitions")?, build)?;
    let fresh_restore_allocation_selection = ledger.read::<Option<
        crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection
    >>(
        fields.named("fresh_restore_allocation_selection")?, build
    )?;
    let fresh_restore_allocation_definitions = ledger.read::<Option<[ContentRef; 5]>>(
        fields.named("fresh_restore_allocation_definitions")?,
        build,
    )?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(HistoricalNativePolicy {
        selection: selection.ok_or_else(invalid)?,
        coordinator_reference: coordinator_reference.ok_or_else(invalid)?,
        coordinator_bytes: coordinator_bytes.ok_or_else(invalid)?,
        definition: definition.ok_or_else(invalid)?,
        connected: connected.ok_or_else(invalid)?,
        capture_profile: capture_profile.ok_or_else(invalid)?,
        confirmation_selection: confirmation_selection.ok_or_else(invalid)?,
        confirmation_definition: confirmation_definition.ok_or_else(invalid)?,
        ack_emitter_selection: ack_emitter_selection.ok_or_else(invalid)?,
        ack_emitter_definition: ack_emitter_definition.ok_or_else(invalid)?,
        native_codec_metadata_extent: native_codec_metadata_extent.ok_or_else(invalid)?,
        protocol_metadata_limits: protocol_metadata_limits.ok_or_else(invalid)?,
        complete_restore_selection: complete_restore_selection.ok_or_else(invalid)?,
        complete_restore_definitions: complete_restore_definitions.ok_or_else(invalid)?,
        complete_restore_transfer_definitions: complete_restore_transfer_definitions
            .ok_or_else(invalid)?,
        restore_input_emitter_selection: restore_input_emitter_selection.ok_or_else(invalid)?,
        restore_input_emitter_definition: restore_input_emitter_definition.ok_or_else(invalid)?,
        capture_allocation_selection: capture_allocation_selection.ok_or_else(invalid)?,
        capture_allocation_definitions: capture_allocation_definitions.ok_or_else(invalid)?,
        fresh_restore_allocation_selection: fresh_restore_allocation_selection
            .ok_or_else(invalid)?,
        fresh_restore_allocation_definitions: fresh_restore_allocation_definitions
            .ok_or_else(invalid)?,
    }))
}

macro_rules! fixed_references {
    ($count:literal; $($name:ident),+) => {
        impl HistoricalType for [ContentRef; $count] {
            fn read(input: &[u8], ledger: &mut Ledger<'_, '_, '_>, build: bool) -> Result<Option<Self>, ProviderError> {
                let mut fields = Fields::array(input)?;
                $(let $name = ledger.read::<ContentRef>(fields.next()?.ok_or_else(invalid)?, build)?;)+
                fields.finish()?;
                if !build { return Ok(None); }
                Ok(Some([$($name.ok_or_else(invalid)?),+]))
            }
        }
    };
}

fixed_references!(2; a,b);
fixed_references!(3; a,b,c);
fixed_references!(5; a,b,c,d,e);
fixed_references!(7; a,b,c,d,e,f,g);

macro_rules! unit_selection {
    ($type:ty; $($text:literal => $variant:ident),+) => {
        impl HistoricalType for $type {
            fn read(input: &[u8], _: &mut Ledger<'_, '_, '_>, build: bool) -> Result<Option<Self>, ProviderError> {
                let value = match plain_string(input)? { $($text => Self::$variant,)+ _ => return Err(invalid()) };
                Ok(build.then_some(value))
            }
        }
    };
}

unit_selection!(crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection; "completed_admit13"=>CompletedAdmit13);

impl HistoricalNativePolicy17 {
    /// Checks its full immutable coordinator bytes against the retained reference.
    ///
    /// # Errors
    /// Refuses invalid framing, changed content length or changed blob digest.
    pub(crate) fn authenticate_correspondence_data(&self) -> Result<(), ProviderError> {
        crate::connection::authenticate_native17_policy_content_data(
            &self.data.coordinator_reference,
            &self.data.coordinator_bytes,
        )
    }
}
