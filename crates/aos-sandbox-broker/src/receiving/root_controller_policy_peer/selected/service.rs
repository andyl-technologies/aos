//! Composes the existing Controller property recipe without another observer.

pub(super) use crate::profile_data::delivery::{
    CONTROLLER_UNIT, SERVICE_PROPERTIES, ServiceObservationV1, decode_resource_producer,
    immutable_observation_into, require_same,
};
pub(super) use crate::profile_data::property_values::PropertyPairV1;
pub(super) use crate::receiving::FixedPropertyArchiveV1 as FirstGlobalPropertyArchive;
pub(super) const RESOURCE_SERVICE_PROPERTIES: &[&str] = super::super::RESOURCE_SERVICE_PROPERTIES;

pub(super) fn fixed_property_observer_demand_v1(
    materialized_bytes: usize,
) -> Result<aos_sandbox_core::ResourceVector, crate::receiving::RootObservationErrorV1> {
    crate::receiving::fixed_property_archive_demand_v1(materialized_bytes)
}
