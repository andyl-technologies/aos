//! Reads complete registrar history as inert data under one native17 ledger.
//!
//! The saved and observed epochs remain distinct, including revoked authorities.
//! Shared groups describe historical alias relations; no field creates a live
//! registration, mutex, atomic, selected-extension authority or connection.

use crate::ProviderError;
use crate::protocol_snapshot::owned11::state::{HistoricalAuthority, selected_extensions};
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string,
};
use crate::retained_metadata::aliases::MetadataSharedKind;
use crate::retained_metadata::records::MetadataRecordKind;
use crucible_node_format::{Id, IdSet, U64};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::collections::BTreeSet;
use std::mem::{align_of, size_of};

/// Retains complete historical registration data without physical authority.
pub(crate) struct HistoricalAuthority17 {
    pub(crate) data: HistoricalAuthority,
    observed_epoch: u64,
    gate_poisoned: bool,
    epoch_group: usize,
    gate_group: usize,
}

impl HistoricalAuthority17 {
    /// Returns the independently validated registrar backing groups.
    pub(crate) const fn group_ids_data(&self) -> (usize, usize) {
        (self.epoch_group, self.gate_group)
    }

    /// Compares full registration history, including real shared backing groups.
    pub(crate) fn same_registration_data(&self, other: &Self) -> bool {
        self.group_ids_data() == other.group_ids_data()
            && self.observed_epoch == other.observed_epoch
            && self.gate_poisoned == other.gate_poisoned
            && self.data.connection == other.data.connection
            && self.data.session == other.data.session
            && self.data.incarnation == other.data.incarnation
            && self.data.epoch == other.data.epoch
            && self.data.limits == other.data.limits
            && self.data.features == other.data.features
            && self.data.envelope_extensions == other.data.envelope_extensions
            && self.data.extensions == other.data.extensions
    }
}

impl Serialize for HistoricalAuthority17 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("RegistrationAuthorityHistory", 13)?;
        fields.serialize_field("schema", "source-private.connection-authority/17")?;
        fields.serialize_field("gate_role", "registrar-gate")?;
        fields.serialize_field("epoch_role", "registrar-epoch")?;
        fields.serialize_field("saved_epoch", &self.data.epoch.get())?;
        fields.serialize_field("observed_epoch", &self.observed_epoch)?;
        fields.serialize_field("gate_poisoned", &self.gate_poisoned)?;
        fields.serialize_field("connection", &self.data.connection)?;
        fields.serialize_field("session", &self.data.session)?;
        fields.serialize_field("incarnation", &self.data.incarnation)?;
        fields.serialize_field("limits", &self.data.limits)?;
        fields.serialize_field("features", &self.data.features)?;
        fields.serialize_field("envelope_extensions", &self.data.envelope_extensions)?;
        fields.serialize_field("extensions", &self.data.extensions)?;
        fields.end()
    }
}

impl HistoricalType for HistoricalAuthority17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_settled17_authority_fields_data(input, ledger, build).map(|result| result.0)
    }
}

/// Reads the same exact fields and retains registrar groups in both passes.
///
/// # Errors
/// Refuses another schema, malformed fields, insufficient capacities or changed
/// alias groups. It never constructs native registration or synchronization.
pub(crate) fn read_settled17_authority_fields_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<HistoricalAuthority17>, (usize, usize)), ProviderError> {
    let mut fields = Fields::object(input)?;
    exact(
        fields.named("schema")?,
        "source-private.connection-authority/17",
    )?;
    exact(fields.named("gate_role")?, "registrar-gate")?;
    exact(fields.named("epoch_role")?, "registrar-epoch")?;
    let epoch = ledger
        .read::<u64>(fields.named("saved_epoch")?, true)?
        .ok_or_else(invalid)?;
    let observed = fields.named("observed_epoch")?;
    let observed_epoch = ledger.read::<u64>(observed, true)?.ok_or_else(invalid)?;
    let poisoned = fields.named("gate_poisoned")?;
    let gate_poisoned = ledger.read::<bool>(poisoned, true)?.ok_or_else(invalid)?;

    // The defining live walker observes the Atomic and Mutex before the
    // owned identity fields. Both views bind actual observed state, rather
    // than treating a role string as proof of another group's payload.
    let epoch_layout = size_of::<std::sync::atomic::AtomicU64>();
    if ledger.row_aligned(
        MetadataRecordKind::Shared,
        1,
        align_of::<std::sync::atomic::AtomicU64>(),
    )? != epoch_layout
    {
        return Err(invalid());
    }
    let gate_layout = size_of::<std::sync::Mutex<()>>();
    if ledger.row_aligned(
        MetadataRecordKind::Shared,
        1,
        align_of::<std::sync::Mutex<()>>(),
    )? != gate_layout
    {
        return Err(invalid());
    }
    let epoch_group = ledger.shared(
        MetadataSharedKind::RegistrarEpoch,
        epoch_layout,
        observed,
        b"",
    )?;
    let gate_group = ledger.shared(
        MetadataSharedKind::RegistrarGate,
        gate_layout,
        poisoned,
        b"",
    )?;

    let connection = ledger.read::<Id>(fields.named("connection")?, build)?;
    let session = ledger.read::<Id>(fields.named("session")?, build)?;
    let incarnation = ledger.read::<Id>(fields.named("incarnation")?, build)?;
    let limits = ledger.read::<crate::handshake::Limits>(fields.named("limits")?, build)?;
    let features = ledger.read::<IdSet>(fields.named("features")?, build)?;
    let envelope_extensions =
        ledger.read::<BTreeSet<String>>(fields.named("envelope_extensions")?, build)?;
    let extensions = selected_extensions(fields.named("extensions")?, ledger, build)?;
    fields.finish()?;
    if !build {
        return Ok((None, (epoch_group, gate_group)));
    }
    Ok((
        Some(HistoricalAuthority17 {
            data: HistoricalAuthority {
                connection: connection.ok_or_else(invalid)?,
                session: session.ok_or_else(invalid)?,
                incarnation: incarnation.ok_or_else(invalid)?,
                epoch: U64::new(epoch),
                limits: limits.ok_or_else(invalid)?,
                features: features.ok_or_else(invalid)?,
                envelope_extensions: envelope_extensions.ok_or_else(invalid)?,
                extensions: extensions.ok_or_else(invalid)?,
            },
            observed_epoch,
            gate_poisoned,
            epoch_group,
            gate_group,
        }),
        (epoch_group, gate_group),
    ))
}

/// Reads exact authority17 fields without constructing registration backing.
///
/// # Errors
/// Refuses malformed fields, another edition, alias disagreement, insufficient
/// recorded capacities or work limits. A failed caller-owned ledger stays spent.
pub(crate) fn read_settled17_authority_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalAuthority17>, ProviderError> {
    ledger.read(input, build)
}

fn exact(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_snapshot::owned11::json_value::HistoricalJsonLimits;
    use crate::protocol_snapshot::restored_settled17::aliases::{
        RestoredSettledNative17AliasSummary, ValidatedRestoredSettledNative17Aliases,
    };
    use crate::retained_metadata::records::{MetadataRecordBank, ValidatedMetadataRecords};
    use crate::retained_metadata::{MetadataObserver, aliases::MetadataAliasBank};

    fn limits() -> HistoricalJsonLimits {
        HistoricalJsonLimits {
            maximum_input_bytes: 1024 * 1024,
            maximum_nodes: 32768,
            maximum_depth: 64,
            maximum_owned_backing_bytes: 64 * 1024 * 1024,
            maximum_tree_entries: 16384,
        }
    }

    #[test]
    fn actual_revoked_authority_roundtrips_both_epochs_and_same_shared_backing()
    -> Result<(), ProviderError> {
        // Keep the real registrar until the deliberate epoch revocation below.
        let (_registrar, authority) = crate::handshake::tests::authority();
        authority.ensure_live()?;
        let saved = authority.epoch;
        authority
            .shared_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        assert!(authority.ensure_live().is_err());
        let guard = authority
            .registration_gate
            .try_lock()
            .map_err(|_| invalid())?;
        let input = serde_json::to_vec(&authority.borrowed_settled_history_data())
            .map_err(crucible_node_format::ContractError::from)?;
        let mut records = MetadataRecordBank::reserve(8192)?;
        let mut aliases = MetadataAliasBank::reserve(8192)?;
        let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
        authority.observe_retained_metadata(&mut observer)?;
        let facts = observer.finish();
        let encoded_records =
            serde_json::to_vec(&records).map_err(crucible_node_format::ContractError::from)?;
        let encoded_aliases =
            serde_json::to_vec(&aliases).map_err(crucible_node_format::ContractError::from)?;
        let rows = ValidatedMetadataRecords::validate(
            &encoded_records,
            facts.capacity_records,
            limits().maximum_owned_backing_bytes,
        )?;
        let mut summaries = vec![RestoredSettledNative17AliasSummary::default(); 8192];
        let mut alias_plan = ValidatedRestoredSettledNative17Aliases::validate(
            &encoded_aliases,
            &mut summaries,
            8192,
        )?;
        {
            let mut passive = Ledger::new(rows.rows(), limits());
            passive.settled_aliases = Some(alias_plan.views()?);
            assert!(read_settled17_authority_data(&input, &mut passive, false)?.is_none());
            assert!(passive.rows.next().is_none());
            passive.finish_aliases()?;
        }
        let result = {
            let mut building = Ledger::new(rows.rows(), limits());
            building.settled_aliases = Some(alias_plan.views()?);
            let result =
                read_settled17_authority_data(&input, &mut building, true)?.ok_or_else(invalid)?;
            assert!(building.rows.next().is_none());
            building.finish_aliases()?;
            result
        };
        assert_eq!(result.data.epoch.get(), saved);
        assert_eq!(result.observed_epoch, saved + 1);
        assert!(!result.gate_poisoned);
        assert_eq!(
            serde_json::to_vec(&result).map_err(crucible_node_format::ContractError::from)?,
            input
        );
        drop(guard);
        assert!(authority.ensure_live().is_err());
        Ok(())
    }

    #[test]
    fn authority_short_record_bank_refuses_without_replacing_actual_original()
    -> Result<(), ProviderError> {
        let (_, authority) = crate::handshake::tests::authority();
        let original = serde_json::to_vec(&authority.borrowed_settled_history_data())
            .map_err(crucible_node_format::ContractError::from)?;
        let mut records = MetadataRecordBank::reserve(1)?;
        let mut aliases = MetadataAliasBank::reserve(8192)?;
        let capacity = records.capacity_rows();
        let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
        assert!(authority.observe_retained_metadata(&mut observer).is_err());
        let _ = observer.finish();
        assert_eq!(records.capacity_rows(), capacity);
        assert_eq!(records.rows().len(), 1);
        assert_eq!(
            serde_json::to_vec(&authority.borrowed_settled_history_data())
                .map_err(crucible_node_format::ContractError::from)?,
            original
        );
        Ok(())
    }
    #[test]
    fn authority_refuses_changed_actual_shared_payload_alignment() -> Result<(), ProviderError> {
        let (_, authority) = crate::handshake::tests::authority();
        let input = serde_json::to_vec(&authority.borrowed_settled_history_data())
            .map_err(crucible_node_format::ContractError::from)?;
        let mut records = MetadataRecordBank::reserve(8192)?;
        let mut aliases = MetadataAliasBank::reserve(8192)?;
        let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
        authority.observe_retained_metadata(&mut observer)?;
        let facts = observer.finish();
        let encoded_records =
            serde_json::to_string(&records).map_err(crucible_node_format::ContractError::from)?;
        let encoded_aliases =
            serde_json::to_vec(&aliases).map_err(crucible_node_format::ContractError::from)?;

        for (layout, alignment) in [
            (
                size_of::<std::sync::atomic::AtomicU64>(),
                align_of::<std::sync::atomic::AtomicU64>(),
            ),
            (
                size_of::<std::sync::Mutex<()>>(),
                align_of::<std::sync::Mutex<()>>(),
            ),
        ] {
            let wrong_alignment = if alignment == 1 { 2 } else { 1 };
            let original_row = format!("[\"shared\",{layout},1,{alignment}]");
            let changed_row = format!("[\"shared\",{layout},1,{wrong_alignment}]");
            let changed = encoded_records.replacen(&original_row, &changed_row, 1);
            assert_ne!(changed, encoded_records);
            let rows = ValidatedMetadataRecords::validate(
                changed.as_bytes(),
                facts.capacity_records,
                limits().maximum_owned_backing_bytes,
            )?;
            let mut summaries = vec![RestoredSettledNative17AliasSummary::default(); 8192];
            let mut alias_plan = ValidatedRestoredSettledNative17Aliases::validate(
                &encoded_aliases,
                &mut summaries,
                8192,
            )?;
            let mut ledger = Ledger::new(rows.rows(), limits());
            ledger.settled_aliases = Some(alias_plan.views()?);
            assert!(read_settled17_authority_fields_data(&input, &mut ledger, false).is_err());
        }
        Ok(())
    }
}

// The whole17 once owner uses the concrete child attempt on every failure.
#[path = "settled17_reader/retained.rs"]
mod retained;
