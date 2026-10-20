//! Owns historical authority, correlation and immutable controller codec data.
//!
//! These owners retain complete typed fields and original String/Vec capacity
//! records. They deliberately have no live ConnectionAuthority constructor,
//! operational clock, source permit or native token. Trusted source factories
//! must enroll new physical associations separately from historical data.

use super::typed::{Fields, HistoricalType, Ledger, invalid, plain_string};
use crate::ProviderError;
use crate::envelope::Envelope;
use crate::handshake::Limits;
use crate::retained_metadata::records::MetadataRecordKind;
use crucible_node_format::{ExtensionSelection, Id, IdSet, U64};
use std::collections::{BTreeMap, BTreeSet};

/// Owns historical registrar data without live registration backing.
pub struct HistoricalAuthority {
    /// Preserves the original connection identifier and its String capacity.
    pub connection: Id,
    /// Preserves the original session identifier and its String capacity.
    pub session: Id,
    /// Preserves the original incarnation identifier and its String capacity.
    pub incarnation: Id,
    /// Preserves the captured original registrar generation.
    pub epoch: U64,
    /// Preserves all negotiated receiving limits.
    pub limits: Limits,
    /// Preserves selected features, order and original Vec capacity.
    pub features: IdSet,
    /// Preserves the full negotiated envelope extension roster.
    pub envelope_extensions: BTreeSet<String>,
    /// Preserves the original selected-extension slice data.
    pub extensions: Option<std::sync::Arc<[ExtensionSelection]>>,
}

impl HistoricalType for HistoricalAuthority {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        tag(&mut fields, "source-private.connection-authority/11")?;
        ledger
            .row(MetadataRecordKind::Shared, 1)
            .and_then(|extent| {
                if extent == std::mem::size_of::<std::sync::atomic::AtomicU64>() {
                    Ok(())
                } else {
                    Err(invalid())
                }
            })?;
        ledger
            .row(MetadataRecordKind::Shared, 1)
            .and_then(|extent| {
                if extent == std::mem::size_of::<std::sync::Mutex<()>>() {
                    Ok(())
                } else {
                    Err(invalid())
                }
            })?;
        let mut epoch_fields = Fields::array(input)?;
        tag(&mut epoch_fields, "source-private.connection-authority/11")?;
        for _ in 0..3 {
            next(&mut epoch_fields)?;
        }
        let epoch_view = next(&mut epoch_fields)?;
        ledger.shared(
            crate::retained_metadata::aliases::MetadataSharedKind::RegistrarEpoch,
            std::mem::size_of::<std::sync::atomic::AtomicU64>(),
            epoch_view,
            b"",
        )?;
        ledger.shared(
            crate::retained_metadata::aliases::MetadataSharedKind::RegistrarGate,
            std::mem::size_of::<std::sync::Mutex<()>>(),
            b"historical-registration-gate",
            b"",
        )?;
        let connection = ledger.read::<Id>(next(&mut fields)?, build)?;
        let session = ledger.read::<Id>(next(&mut fields)?, build)?;
        let incarnation = ledger.read::<Id>(next(&mut fields)?, build)?;
        let epoch = ledger.read::<U64>(next(&mut fields)?, build)?;
        let limits = ledger.read::<Limits>(next(&mut fields)?, build)?;
        let features = ledger.read::<IdSet>(next(&mut fields)?, build)?;
        let envelope_extensions = ledger.read::<BTreeSet<String>>(next(&mut fields)?, build)?;
        let selected = next(&mut fields)?;
        let extensions = selected_extensions(selected, ledger, build)?;
        tag(
            &mut fields,
            "original-registration-backing-retained-by-opaque-source",
        )?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            connection: connection.ok_or_else(invalid)?,
            session: session.ok_or_else(invalid)?,
            incarnation: incarnation.ok_or_else(invalid)?,
            epoch: epoch.ok_or_else(invalid)?,
            limits: limits.ok_or_else(invalid)?,
            features: features.ok_or_else(invalid)?,
            envelope_extensions: envelope_extensions.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
        }))
    }
}

pub(crate) fn selected_extensions(
    selected: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<Option<std::sync::Arc<[ExtensionSelection]>>>, ProviderError> {
    Ok(if selected == b"null" {
        build.then_some(None)
    } else {
        let start = ledger.rows.encoded_position();
        let extent = ledger.row(MetadataRecordKind::Shared, 1)?;
        let element = std::mem::size_of::<ExtensionSelection>();
        if element == 0 || extent % element != 0 {
            return Err(invalid());
        }
        let count = extent / element;
        // The final Arc can coexist with its temporary Vec/boxed slice.
        // Count the largest such staging bank independently from final views.
        ledger.selected_slice_staging_bytes = ledger.selected_slice_staging_bytes.max(extent);
        if count > 4096 {
            return Err(invalid());
        }
        // Complete borrowed child admission precedes shared-owner lookup.
        let native17_targets = ledger.has_native17_targets_data();
        let pause = if native17_targets {
            Some(ledger.suspend_native17_targets_data()?)
        } else {
            None
        };
        let mut borrowed = Fields::array(selected)?;
        let mut actual = 0usize;
        let original_rows = ledger.rows.clone();
        while let Some(item) = borrowed.next()? {
            actual += 1;
            if actual > count {
                return Err(invalid());
            }
            ledger.read::<ExtensionSelection>(item, false)?;
        }
        if actual != count {
            return Err(invalid());
        }
        if let Some(pause) = pause {
            ledger.resume_native17_targets_data(pause)?;
        }
        let after_rows = ledger.rows.clone();
        let capacity_rows = ledger.rows.encoded_between(start)?;
        let group = ledger.shared(
            crate::retained_metadata::aliases::MetadataSharedKind::SelectedExtensions,
            extent,
            selected,
            capacity_rows,
        )?;
        let target_children = if native17_targets {
            ledger.native17_target_shared_slice_data::<ExtensionSelection>(group, count)?
        } else {
            false
        };
        if !build {
            // No target Arc exists in preflight. Rewalk just its first concrete
            // construction site to charge recursively owned child backing.
            if target_children {
                ledger.rows = original_rows;
                let mut items = Fields::array(selected)?;
                while let Some(item) = items.next()? {
                    ledger.read::<ExtensionSelection>(item, false)?;
                }
                ledger.rows = after_rows;
            }
            None
        } else {
            if let Some(existing) = ledger
                .selected_groups
                .as_ref()
                .and_then(|groups| groups.get(group))
                .and_then(Option::as_ref)
            {
                Some(Some(existing.clone()))
            } else {
                let mut values = Vec::new();
                values.try_reserve_exact(count).map_err(|_| capacity())?;
                if values.capacity() != count {
                    return Err(capacity());
                }
                ledger.rows = original_rows;
                let mut items = Fields::array(selected)?;
                while let Some(item) = items.next()? {
                    values.push(
                        ledger
                            .read::<ExtensionSelection>(item, true)?
                            .ok_or_else(invalid)?,
                    );
                }
                ledger.rows = after_rows;
                let values: std::sync::Arc<[ExtensionSelection]> =
                    std::sync::Arc::from(values.into_boxed_slice());
                *ledger
                    .selected_groups
                    .as_mut()
                    .and_then(|groups| groups.get_mut(group))
                    .ok_or_else(invalid)? = Some(values.clone());
                Some(Some(values))
            }
        }
    })
}

/// Owns every historical correlation namespace and sequencing field.
pub struct HistoricalCorrelations {
    /// Preserves the original correlation session.
    pub session: Id,
    /// Preserves the original correlation incarnation.
    pub incarnation: Id,
    /// Preserves the next incoming sequence without renewing it.
    pub next_received: U64,
    /// Preserves the next outgoing sequence without renewing it.
    pub next_sent: U64,
    /// Preserves the outstanding-request ceiling.
    pub maximum_requests: usize,
    /// Preserves every outstanding original outgoing request.
    pub pending: BTreeMap<Id, Envelope>,
    /// Preserves every accepted original incoming request.
    pub received_requests: BTreeMap<Id, Envelope>,
    /// Preserves every response whose original write remains unresolved.
    pub writing_responses: BTreeMap<Id, Envelope>,
    /// Preserves the complete negotiated extension roster.
    pub extensions: BTreeSet<String>,
    /// Preserves the sticky original transport failure state.
    pub failed: bool,
    /// Preserves whether an original continuation was installed.
    pub continuation_installed: bool,
}

impl HistoricalType for HistoricalCorrelations {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        tag(&mut fields, "source-private.correlations/6")?;
        let session = ledger.read::<Id>(next(&mut fields)?, build)?;
        let incarnation = ledger.read::<Id>(next(&mut fields)?, build)?;
        let next_received = ledger.read::<U64>(next(&mut fields)?, build)?;
        let next_sent = ledger.read::<U64>(next(&mut fields)?, build)?;
        let maximum = next(&mut fields)?;
        let maximum_requests = ledger.read::<usize>(maximum, build)?;
        let numeric_maximum = super::typed::unsigned(maximum)?;
        if numeric_maximum == 0 || numeric_maximum > 256 {
            return Err(invalid());
        }
        let pending = ledger.read::<BTreeMap<Id, Envelope>>(next(&mut fields)?, build)?;
        let received_requests = ledger.read::<BTreeMap<Id, Envelope>>(next(&mut fields)?, build)?;
        let writing_responses = ledger.read::<BTreeMap<Id, Envelope>>(next(&mut fields)?, build)?;
        let extensions = ledger.read::<BTreeSet<String>>(next(&mut fields)?, build)?;
        let failed = ledger.read::<bool>(next(&mut fields)?, build)?;
        let continuation_installed = ledger.read::<bool>(next(&mut fields)?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            session: session.ok_or_else(invalid)?,
            incarnation: incarnation.ok_or_else(invalid)?,
            next_received: next_received.ok_or_else(invalid)?,
            next_sent: next_sent.ok_or_else(invalid)?,
            maximum_requests: maximum_requests.ok_or_else(invalid)?,
            pending: pending.ok_or_else(invalid)?,
            received_requests: received_requests.ok_or_else(invalid)?,
            writing_responses: writing_responses.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
            failed: failed.ok_or_else(invalid)?,
            continuation_installed: continuation_installed.ok_or_else(invalid)?,
        }))
    }
}

/// Owns the exact immutable connected-wire grammar as historical data.
pub struct HistoricalWireSchema {
    /// Preserves the selected node.
    pub node: Id,
    /// Preserves the selected execution owner.
    pub execution_owner: Id,
    /// Preserves the original owner generation.
    pub owner_generation: U64,
    /// Preserves the original input epoch.
    pub input_epoch: Id,
    /// Preserves the complete immutable binding hash.
    pub binding_hash: crucible_node_format::HashRef,
}

impl HistoricalType for HistoricalWireSchema {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let node = ledger.read::<Id>(next(&mut fields)?, build)?;
        let execution_owner = ledger.read::<Id>(next(&mut fields)?, build)?;
        let owner_generation = ledger.read::<U64>(next(&mut fields)?, build)?;
        let input_epoch = ledger.read::<Id>(next(&mut fields)?, build)?;
        let binding_hash =
            ledger.read::<crucible_node_format::HashRef>(next(&mut fields)?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            node: node.ok_or_else(invalid)?,
            execution_owner: execution_owner.ok_or_else(invalid)?,
            owner_generation: owner_generation.ok_or_else(invalid)?,
            input_epoch: input_epoch.ok_or_else(invalid)?,
            binding_hash: binding_hash.ok_or_else(invalid)?,
        }))
    }
}

pub(crate) fn next<'a>(fields: &mut Fields<'a>) -> Result<&'a [u8], ProviderError> {
    fields.next()?.ok_or_else(invalid)
}

pub(crate) fn tag(fields: &mut Fields<'_>, expected: &str) -> Result<(), ProviderError> {
    if plain_string(next(fields)?)? != expected {
        return Err(invalid());
    }
    Ok(())
}

fn capacity() -> ProviderError {
    ProviderError::ResourceExhausted("historical typed backing")
}

// The closed owning walk fails to compile if a historical field is added.
super::retained_storage::fields!(
    HistoricalAuthority,
    connection,
    session,
    incarnation,
    epoch,
    limits,
    features,
    envelope_extensions,
    extensions
);
super::retained_storage::fields!(
    HistoricalCorrelations,
    session,
    incarnation,
    next_received,
    next_sent,
    maximum_requests,
    pending,
    received_requests,
    writing_responses,
    extensions,
    failed,
    continuation_installed
);
super::retained_storage::fields!(
    HistoricalWireSchema,
    node,
    execution_owner,
    owner_generation,
    input_epoch,
    binding_hash
);

pub(crate) mod current17;

/// Names fixed controls of the native authority, selection and correlation reads.
pub(crate) fn borrowed_native_validation_headers_data() -> usize {
    use std::mem::size_of;

    <Id as HistoricalType>::borrowed_header_counter_scratch_data()
        + <Id as HistoricalType>::borrowed_header_counter_scratch_data()
        + <Id as HistoricalType>::borrowed_header_counter_scratch_data()
        + <U64 as HistoricalType>::borrowed_header_counter_scratch_data()
        + <Limits as HistoricalType>::borrowed_header_counter_scratch_data()
        + <IdSet as HistoricalType>::borrowed_header_counter_scratch_data()
        + <BTreeSet<String> as HistoricalType>::borrowed_header_counter_scratch_data()
        + <ExtensionSelection as HistoricalType>::borrowed_header_counter_scratch_data()
        + <ExtensionSelection as HistoricalType>::borrowed_header_counter_scratch_data()
        + <ExtensionSelection as HistoricalType>::borrowed_header_counter_scratch_data()
        + <Id as HistoricalType>::borrowed_header_counter_scratch_data()
        + <Id as HistoricalType>::borrowed_header_counter_scratch_data()
        + <U64 as HistoricalType>::borrowed_header_counter_scratch_data()
        + <U64 as HistoricalType>::borrowed_header_counter_scratch_data()
        + <usize as HistoricalType>::borrowed_header_counter_scratch_data()
        + <BTreeMap<Id, Envelope> as HistoricalType>::borrowed_header_counter_scratch_data()
        + <BTreeMap<Id, Envelope> as HistoricalType>::borrowed_header_counter_scratch_data()
        + <BTreeMap<Id, Envelope> as HistoricalType>::borrowed_header_counter_scratch_data()
        + <BTreeSet<String> as HistoricalType>::borrowed_header_counter_scratch_data()
        + <bool as HistoricalType>::borrowed_header_counter_scratch_data()
        + <bool as HistoricalType>::borrowed_header_counter_scratch_data()
        + size_of::<Option<HistoricalAuthority>>()
        + size_of::<Result<Option<HistoricalAuthority>, ProviderError>>()
        + size_of::<Option<HistoricalCorrelations>>()
        + size_of::<Result<Option<HistoricalCorrelations>, ProviderError>>()
        + size_of::<Option<Option<std::sync::Arc<[ExtensionSelection]>>>>()
        + size_of::<Result<Option<Option<std::sync::Arc<[ExtensionSelection]>>>, ProviderError>>()
        + size_of::<crate::retained_metadata::records::MetadataRecordRows<'static>>() * 2
        + size_of::<Option<&'static std::sync::Arc<[ExtensionSelection]>>>()
        + size_of::<usize>() * 6
        + size_of::<bool>() * 3
        + Fields::counter_scratch_data()
}
