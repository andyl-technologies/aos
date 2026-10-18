//! Reconstructs original service roots as inert historical owners.

use super::super::{
    state::{next, tag},
    typed::{Fields, invalid, plain_string},
};
use super::{
    boot::HistoricalNativeBoot, bootstrap::HistoricalNativeBootstrap,
    policy::HistoricalNativePolicy, registrar::HistoricalNativeExtensionNegotiation,
    shared::NativeLedger,
};
use crate::{
    ProviderError,
    retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind},
};
use std::rc::Rc;

/// Retains closed successful service roots without callbacks, descriptors or cuts.
pub struct HistoricalNativeService {
    /// Retains the full original typed registrar and selected extension aliases.
    pub negotiation: HistoricalNativeExtensionNegotiation,
    /// Retains the complete closed private bootstrap history.
    pub bootstrap: HistoricalNativeBootstrap,
    /// Identifies the original supervisor group shared by all three roots.
    pub supervisor_group: usize,
    supervisor_banks: crate::reference_packet::service::HistoricalNativeSupervisorBanks,
    /// Shares the endpoint's full original boot owner.
    pub endpoint_boot: Rc<HistoricalNativeBoot>,
    /// Shares the endpoint's complete immutable policy owner.
    pub endpoint_policy: Rc<HistoricalNativePolicy>,
    /// Identifies historical deadline sharing without manufacturing a live cut.
    pub deadline_group: usize,
}

impl HistoricalNativeService {
    /// Reports actual capacities of the reconstructed typed empty supervisor banks.
    pub fn supervisor_capacity_rows(&self) -> (usize, usize) {
        self.supervisor_banks.capacity_rows()
    }
}

pub(super) fn read(
    input: &[u8],
    ledger: &mut NativeLedger<'_, '_, '_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalNativeService>, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(
        &mut fields,
        if ledger.requires_invocation_class()? {
            super::outer::COMPLETE_NATIVE_INVOCATION_SERVICE_FORMAT
        } else if ledger.requires_startup_class()? {
            "source-private.native-service/14"
        } else {
            super::outer::COMPLETE_NATIVE_SERVICE_FORMAT
        },
    )?;
    let negotiation = ledger
        .ledger
        .read::<HistoricalNativeExtensionNegotiation>(next(&mut fields)?, build)?;
    let bootstrap = super::bootstrap::read(
        next(&mut fields)?,
        ledger,
        build,
        crate::reference_packet::service::ack_emitter::original_native_private_bootstrap_layout(),
        crate::reference_packet::service::ack_emitter::original_native_ack_boot_layout(),
    )?;
    let marker = next(&mut fields)?;
    let layout = crate::reference_packet::service::original_native_supervisor_layout();
    if plain_string(marker)? != "source-private.native-supervisor-owner/11"
        || ledger.ledger.row(MetadataRecordKind::Shared, 1)? != layout
    {
        return Err(invalid());
    }
    let supervisor_group =
        ledger
            .ledger
            .shared(MetadataSharedKind::NativeSupervisor, layout, marker, b"")?;
    let mut supervisor = Fields::array(next(&mut fields)?)?;
    tag(&mut supervisor, "source-private.native-empty-supervisor/11")?;
    let layouts = crate::reference_packet::service::original_native_supervisor_bank_layouts();
    let mut capacities = [0usize; 2];
    let mut backing = 0usize;
    for (capacity, element_bytes) in capacities.iter_mut().zip([layouts.0, layouts.1]) {
        let mut row = Fields::array(next(&mut supervisor)?)?;
        *capacity = usize::try_from(super::super::typed::unsigned(next(&mut row)?)?)
            .map_err(|_| invalid())?;
        let encoded_layout = usize::try_from(super::super::typed::unsigned(next(&mut row)?)?)
            .map_err(|_| invalid())?;
        row.finish()?;
        if encoded_layout != element_bytes
            || ledger
                .ledger
                .row(MetadataRecordKind::Vector, element_bytes)?
                != *capacity
        {
            return Err(invalid());
        }
        backing = capacity
            .checked_mul(element_bytes)
            .and_then(|bytes| backing.checked_add(bytes))
            .ok_or_else(invalid)?;
    }
    supervisor.finish()?;
    let endpoint_boot = ledger.boot(
        next(&mut fields)?,
        build,
        crate::reference_packet::service::ack_emitter::original_native_ack_boot_layout(),
    )?;
    let endpoint_policy = ledger.policy(next(&mut fields)?, build)?;
    let deadline = next(&mut fields)?;
    if plain_string(deadline)? != "opaque-original-service-cut" {
        return Err(invalid());
    }
    let deadline_layout =
        std::mem::size_of::<std::cell::Cell<crate::operational_time::OperationalDeadline>>();
    if ledger.ledger.row(MetadataRecordKind::Shared, 1)? != deadline_layout {
        return Err(invalid());
    }
    let deadline_group = ledger.ledger.shared(
        MetadataSharedKind::OperationalDeadline,
        deadline_layout,
        deadline,
        b"",
    )?;
    fields.finish()?;
    if !build {
        return Ok(None);
    }
    let mut banks = None;
    crate::reference_packet::service::HistoricalNativeSupervisorBanks::reconstruct_empty_into(
        &mut banks,
        capacities[0],
        capacities[1],
        backing,
    )?;
    Ok(Some(HistoricalNativeService {
        negotiation: negotiation.ok_or_else(invalid)?,
        bootstrap: bootstrap.ok_or_else(invalid)?,
        supervisor_group,
        supervisor_banks: banks.ok_or_else(invalid)?,
        endpoint_boot: endpoint_boot.ok_or_else(invalid)?,
        endpoint_policy: endpoint_policy.ok_or_else(invalid)?,
        deadline_group,
    }))
}

// The closed owning walk fails to compile if a historical field is added.
super::super::retained_storage::fields!(
    HistoricalNativeService,
    negotiation,
    bootstrap,
    supervisor_group,
    supervisor_banks,
    endpoint_boot,
    endpoint_policy,
    deadline_group
);

pub(crate) mod current17;
