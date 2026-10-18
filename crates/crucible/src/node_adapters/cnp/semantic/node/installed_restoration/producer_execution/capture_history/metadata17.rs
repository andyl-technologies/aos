//! Prices full current17 generic histories before root serialization.
//!
//! The Initial15 empty-map admission remains unchanged in the parent. This
//! actual17 field walk separately counts generic Begin/Input Bytes temporaries
//! and every independent current Provider owner before its bank is created.

use super::*;

impl OriginalRestoredSettledNodeHistoryView<'_> {
    pub(crate) fn metadata_demand17_data(&self) -> Result<NodeHistoryPrequoteData, RuntimeError> {
        let (common_rows, common_shared) =
            OriginalRestoredOwnerCapacityRows(&NodeCommonCapacityView(self))
                .metadata_demand_data()?;
        let mut demand = NodeHistoryPrequoteData {
            common_rows,
            common_shared,
            ..Default::default()
        };
        use crucible_node_provider::retained_metadata::RetainedCommonProtocolData as Common;
        let mut add_transient = |body: Common<'_>| -> Result<(), RuntimeError> {
            demand.transient = demand
                .transient
                .checked_add(
                    body.historical_serialization_transient_bytes_data()
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
            Ok(())
        };
        for original in self.base.operations.values() {
            add_transient(Common::Begin(&original.begin))?;
        }
        for input in self.base.inputs.values() {
            add_transient(Common::InputRequest(&input.request))?;
            if let Some(response) = &input.response {
                add_transient(Common::InputResult(response))?;
            }
            if let Some(commitment) = &input.commitment
                && let Some(response) = &commitment.response
            {
                add_transient(Common::InputResult(response))?;
            }
        }
        for response in self
            .installed
            .completed
            .iter()
            .chain(std::iter::once(&self.installed.observation_completed))
            .flatten()
        {
            let historical = historical_response_body_data(response)
                .map_err(|_| RuntimeError::UnsupportedFacet)?;
            let facts = historical
                .retained_metadata_data()
                .map_err(|_| RuntimeError::ResourceLimit)?;
            demand.provider_records = demand
                .provider_records
                .checked_add(facts.capacity_records)
                .ok_or(RuntimeError::ResourceLimit)?;
            demand.provider_shared = demand
                .provider_shared
                .checked_add(facts.shared_backing_views)
                .ok_or(RuntimeError::ResourceLimit)?;
            demand.provider_owners = demand
                .provider_owners
                .checked_add(1)
                .ok_or(RuntimeError::ResourceLimit)?;
            demand.transient = demand
                .transient
                .checked_add(
                    historical
                        .historical_serialization_transient_bytes_data()
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        use crucible_node_provider::reference_packet::service::complete_restore::activation::HistoricalRestorationActivationData as Activation;
        if let Some(value) = &self.base.activate_response {
            demand.add_provider_owner_data(
                Activation::WorldResult(value)
                    .retained_metadata_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                Activation::WorldResult(value)
                    .historical_serialization_transient_bytes_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )?;
        }
        for command in self.installed.commands.iter().flatten() {
            demand.add_provider_owner_data(
                Activation::Command(command)
                    .retained_metadata_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                Activation::Command(command)
                    .historical_serialization_transient_bytes_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )?;
        }
        if let Some(manifest) = &self.installed.world_manifest {
            demand.add_provider_owner_data(
                Activation::Manifest(manifest)
                    .retained_metadata_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                Activation::Manifest(manifest)
                    .historical_serialization_transient_bytes_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )?;
        }
        Ok(demand)
    }
}
