//! Reconstructs complete immutable controller-policy data for owned edition eleven.
//!
//! Final owners preserve every typed policy field and the original coordinator
//! byte capacity. Construction never calls a live codec installer or creates an
//! original registrar, operational cut, source association or native MAC token.

use super::state::{HistoricalWireSchema, next, tag};
use super::typed::{Fields, HistoricalType, Ledger, invalid, plain_string};
use crate::ProviderError;
use crate::connection::CanonicalAckCodecMetadataExtent;
use crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes;
use crate::reference_packet::{
    control::PacketControlSelection,
    coordinator::PacketNative5CoordinatorInstallation,
    service::{
        PacketNative5CaptureProfile, ack_emitter::PacketNative5AckEmitterSelection,
        confirmation::PacketNative5ConfirmationSelection,
    },
};
use crate::retained_metadata::records::MetadataRecordKind;
use crucible_node_format::{ContentRef, U64};

/// Owns all immutable controller codec fields as historical data.
pub struct HistoricalControllerCodec {
    /// Retains the independently selected encoded-codec ceiling.
    pub metadata_extent: Option<CanonicalAckCodecMetadataExtent>,
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
    /// Retains all immutable connected-wire grammar fields.
    pub wire: HistoricalWireSchema,
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
    /// Retains the separate source-signed complete-restore choice as data.
    pub complete_restore_selection: Option<
        crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection,
    >,
    /// Retains all three full immutable restore schema definitions.
    pub complete_restore_definitions: Option<[ContentRef; 3]>,
    /// Retains the seven independently selected phase12 definitions.
    pub complete_restore_transfer_definitions: Option<[ContentRef; 7]>,
    /// Retains the separately installed closed uploader family as inert data.
    pub restore_input_emitter_selection: Option<crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection>,
    /// Retains its full source-bound schema definition.
    pub restore_input_emitter_definition: Option<ContentRef>,
}

impl HistoricalType for HistoricalControllerCodec {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut wrapper = Fields::array(input)?;
        tag(&mut wrapper, "source-private.controller-codec/11")?;
        let policy = next(&mut wrapper)?;
        wrapper.finish()?;
        let boxed = ledger.row(MetadataRecordKind::Boxed, 1)?;
        if boxed != crate::connection::controller_owned_codec_layout() {
            return Err(invalid());
        }
        let mut input_emitter = Fields::array(policy)?;
        let input_wrapper = if next(&mut input_emitter)?
            == b"\"source-private.controller-policy-owned-restore-input-emitter/16\""
        {
            if plain_string(next(&mut input_emitter)?)? != "CanonicalSdkRestoreInputs12" {
                return Err(invalid());
            }
            let definition = next(&mut input_emitter)?;
            if definition == b"null" {
                return Err(invalid());
            }
            let base = next(&mut input_emitter)?;
            input_emitter.finish()?;
            Some((definition, base))
        } else {
            None
        };
        let policy = input_wrapper.map_or(policy, |(_, base)| base);
        let mut transfer = Fields::array(policy)?;
        let transfer_wrapper = if next(&mut transfer)?
            == b"\"source-private.controller-policy-owned-restore-transfer/15\""
        {
            let definitions = next(&mut transfer)?;
            if definitions == b"null" {
                return Err(invalid());
            }
            let base = next(&mut transfer)?;
            transfer.finish()?;
            Some((definitions, base))
        } else {
            None
        };
        let mut restored = Fields::array(transfer_wrapper.map_or(policy, |(_, base)| base))?;
        let first = next(&mut restored)?;
        let restore_wrapper =
            if first == b"\"source-private.controller-policy-owned-complete-restore/14\"" {
                let choice = next(&mut restored)?;
                let expected = if transfer_wrapper.is_some() {
                    "SourceSignedTransfer12"
                } else {
                    "SourceSignedOwned11"
                };
                if plain_string(choice)? != expected {
                    return Err(invalid());
                }
                let definitions = next(&mut restored)?;
                let base = next(&mut restored)?;
                restored.finish()?;
                Some((definitions, base))
            } else {
                None
            };
        if input_wrapper.is_some() && transfer_wrapper.is_none() {
            return Err(invalid());
        }
        if transfer_wrapper.is_some() && restore_wrapper.is_none() {
            return Err(invalid());
        }
        let mut fields = Fields::array(restore_wrapper.map_or(policy, |(_, base)| base))?;
        tag(&mut fields, "source-private.controller-policy/11")?;
        let metadata_extent =
            ledger.read::<Option<CanonicalAckCodecMetadataExtent>>(next(&mut fields)?, build)?;
        let selection = ledger.read::<PacketControlSelection>(next(&mut fields)?, build)?;
        let mut coordinator = Fields::array(next(&mut fields)?)?;
        let coordinator_reference = ledger.read::<ContentRef>(next(&mut coordinator)?, build)?;
        let encoded_capacity = usize::try_from(super::typed::unsigned(next(&mut coordinator)?)?)
            .map_err(|_| invalid())?;
        let recorded_capacity = ledger.row(MetadataRecordKind::Vector, 1)?;
        if recorded_capacity != encoded_capacity {
            return Err(invalid());
        }
        let bytes = ValidatedCompactBytes::validate(
            next(&mut coordinator)?,
            ledger.limits.maximum_input_bytes,
            encoded_capacity,
        )?;
        coordinator.finish()?;
        let definition = ledger.read::<ContentRef>(next(&mut fields)?, build)?;
        let connected =
            ledger.read::<PacketNative5CoordinatorInstallation>(next(&mut fields)?, build)?;
        let wire = ledger.read::<HistoricalWireSchema>(next(&mut fields)?, build)?;
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
        fields.finish()?;
        // Capacity rows follow the actual walk: old fields first, new definitions last.
        let complete_restore_definitions = if let Some((definitions, _)) = restore_wrapper {
            let mut fields = Fields::array(definitions)?;
            let one = ledger.read::<ContentRef>(next(&mut fields)?, build)?;
            let two = ledger.read::<ContentRef>(next(&mut fields)?, build)?;
            let three = ledger.read::<ContentRef>(next(&mut fields)?, build)?;
            fields.finish()?;
            if build {
                Some([
                    one.ok_or_else(invalid)?,
                    two.ok_or_else(invalid)?,
                    three.ok_or_else(invalid)?,
                ])
            } else {
                None
            }
        } else {
            None
        };
        let complete_restore_transfer_definitions = if let Some((raw, _)) = transfer_wrapper {
            let mut fields = Fields::array(raw)?;
            let mut values: [Option<ContentRef>; 7] = std::array::from_fn(|_| None);
            for value in &mut values {
                *value = ledger.read::<ContentRef>(next(&mut fields)?, build)?;
            }
            fields.finish()?;
            if build {
                let [a, b, c, d, e, f, g] = values;
                Some([
                    a.ok_or_else(invalid)?,
                    b.ok_or_else(invalid)?,
                    c.ok_or_else(invalid)?,
                    d.ok_or_else(invalid)?,
                    e.ok_or_else(invalid)?,
                    f.ok_or_else(invalid)?,
                    g.ok_or_else(invalid)?,
                ])
            } else {
                None
            }
        } else {
            None
        };
        let restore_input_emitter_definition = if let Some((definition, _)) = input_wrapper {
            ledger.read::<ContentRef>(definition, build)?
        } else {
            None
        };
        if !build {
            return Ok(None);
        }
        let mut coordinator_bytes = Vec::new();
        coordinator_bytes
            .try_reserve_exact(encoded_capacity)
            .map_err(|_| capacity())?;
        if coordinator_bytes.capacity() != encoded_capacity {
            return Err(capacity());
        }
        bytes.fill_preowned(&mut coordinator_bytes)?;
        let coordinator_reference = coordinator_reference.ok_or_else(invalid)?;
        coordinator_reference.verify(&coordinator_bytes)?;
        Ok(Some(Self {
            metadata_extent: metadata_extent.ok_or_else(invalid)?,
            selection: selection.ok_or_else(invalid)?,
            coordinator_reference,
            coordinator_bytes,
            definition: definition.ok_or_else(invalid)?,
            connected: connected.ok_or_else(invalid)?,
            wire: wire.ok_or_else(invalid)?,
            capture_profile: capture_profile.ok_or_else(invalid)?,
            confirmation_selection: confirmation_selection.ok_or_else(invalid)?,
            confirmation_definition: confirmation_definition.ok_or_else(invalid)?,
            ack_emitter_selection: ack_emitter_selection.ok_or_else(invalid)?,
            ack_emitter_definition: ack_emitter_definition.ok_or_else(invalid)?,
            complete_restore_selection: restore_wrapper.map(|_| if transfer_wrapper.is_some() {
                crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12
            } else { crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedOwned11 }),
            complete_restore_definitions,
            complete_restore_transfer_definitions,
            restore_input_emitter_selection: input_wrapper.map(|_| crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12),
            restore_input_emitter_definition,
        }))
    }
}

macro_rules! closed_unit {
    ($type:ty, $name:literal, $value:path) => {
        impl HistoricalType for $type {
            fn read(
                input: &[u8],
                _: &mut Ledger<'_, '_, '_>,
                build: bool,
            ) -> Result<Option<Self>, ProviderError> {
                if plain_string(input)? != $name {
                    return Err(invalid());
                }
                Ok(build.then_some($value))
            }
        }
    };
}
closed_unit!(
    CanonicalAckCodecMetadataExtent,
    "CanonicalAck512KiB",
    CanonicalAckCodecMetadataExtent::CanonicalAck512KiB
);
closed_unit!(
    PacketNative5ConfirmationSelection,
    "after_protocol_poll5",
    PacketNative5ConfirmationSelection::AfterProtocolPoll5
);
closed_unit!(
    PacketNative5AckEmitterSelection,
    "canonical_sdk_blob5",
    PacketNative5AckEmitterSelection::CanonicalSdkBlob5
);

impl HistoricalType for PacketNative5CaptureProfile {
    fn borrowed_header_counter_scratch_data() -> usize {
        use std::mem::size_of;

        size_of::<Option<Self>>()
            + size_of::<Result<Option<Self>, ProviderError>>()
            + Fields::counter_scratch_data()
            + size_of::<[&'static [u8]; 3]>()
            + size_of::<std::array::IntoIter<&'static [u8], 3>>()
            + size_of::<&'static str>()
            + size_of::<u64>()
            + <U64 as HistoricalType>::borrowed_header_counter_scratch_data() * 3
    }

    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let encoding = plain_string(fields.named("encoding")?)?;
        if encoding == "original_arrays6" {
            fields.finish()?;
            return Ok(build.then_some(Self::OriginalArrays6));
        }
        if !matches!(encoding, "compact_bytes7" | "owned_protocol11") {
            return Err(invalid());
        }
        let before = fields.named("native_before_protocol_bytes")?;
        let after = fields.named("native_after_protocol_bytes")?;
        let host = fields.named("host_protocol_bytes")?;
        for value in [before, after, host] {
            let numeric = super::typed::unsigned(plain_string(value)?.as_bytes())?;
            if numeric == 0 || numeric > 512 * 1024 * 1024 {
                return Err(invalid());
            }
        }
        let native_before_protocol_bytes = ledger.read::<U64>(before, build)?;
        let native_after_protocol_bytes = ledger.read::<U64>(after, build)?;
        let host_protocol_bytes = ledger.read::<U64>(host, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        let native_before_protocol_bytes = native_before_protocol_bytes.ok_or_else(invalid)?;
        let native_after_protocol_bytes = native_after_protocol_bytes.ok_or_else(invalid)?;
        let host_protocol_bytes = host_protocol_bytes.ok_or_else(invalid)?;
        Ok(Some(if encoding == "compact_bytes7" {
            Self::CompactBytes7 {
                native_before_protocol_bytes,
                native_after_protocol_bytes,
                host_protocol_bytes,
            }
        } else {
            Self::OwnedProtocol11 {
                native_before_protocol_bytes,
                native_after_protocol_bytes,
                host_protocol_bytes,
            }
        }))
    }
}

fn capacity() -> ProviderError {
    ProviderError::ResourceExhausted("historical codec coordinator capacity")
}

// The closed owning walk fails to compile if a historical field is added.
super::retained_storage::fields!(
    HistoricalControllerCodec,
    metadata_extent,
    selection,
    coordinator_reference,
    coordinator_bytes,
    definition,
    connected,
    wire,
    capture_profile,
    confirmation_selection,
    confirmation_definition,
    ack_emitter_selection,
    ack_emitter_definition,
    complete_restore_selection,
    complete_restore_definitions,
    complete_restore_transfer_definitions,
    restore_input_emitter_selection,
    restore_input_emitter_definition
);
