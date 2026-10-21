//! Aggregates Create U byte ceilings from the same actual component suppliers.
//!
//! The prefix remains explicitly incomplete. The final helper adds the owned
//! continuation formats, concrete Root tail, actual Controller pair engine,
//! real profile-row recipe and bank-history progression. Both are passive DATA:
//! neither creates an account, proves original custody or admits native work.

use super::*;

use aos_sandbox_policy::storage_create_use_data::StorageCreateUseSecurityShapeDataV1;

aos_sandbox_policy::define_storage_create_use_receiving_v1! {
    ResourceVector = ResourceVector,
    D = D,
    RecordShape = RecordShape,
    ProtectedJournalPreopenReplayExtentV1 = ProtectedJournalPreopenReplayExtentV1,
    StorageSessionGeometryRefusalV1 = StorageSessionGeometryRefusalV1,
    StorageCreateUseSecurityShapeDataV1 = StorageCreateUseSecurityShapeDataV1,
    storage_create_use_prefix_receiving_demand_v1 = storage_create_use_prefix_receiving_demand_v1,
    storage_create_use_receiving_demand_v1 = storage_create_use_receiving_demand_v1,
    storage_create_use_signing_receiving_demand_v1 = storage_create_use_signing_receiving_demand_v1,
    invalid = invalid,
    add = add,
    sum = sum,
    checked_prefix = checked_prefix,
    as_u64 = as_u64,
    response_packet_bytes = response_packet_bytes,
    encoded_transaction_append_bytes = encoded_transaction_append_bytes,
    storage_create_prepare_client_request_demand_v1 = storage_create_prepare_client_request_demand_v1,
    storage_create_prepare_client_positive_outcome_demand_v1 = storage_create_prepare_client_positive_outcome_demand_v1,
    storage_retained_current_replay_demand_v1 = storage_retained_current_replay_demand_v1,
    storage_retained_traffic_reconstruction_demand_v1 = storage_retained_traffic_reconstruction_demand_v1,
    schema_demand = schema_demand,
    full_preopen = super::super::protected_journal_preopen_replay_extent_for_prefix_v1,
    names = crate::journal::create_storage_name_peak_demand_v1,
    preparation_io = crate::controller_resource_reservation::create_storage_preparation_io_receiving_demand_v1,
    cache_fixed = crate::controller_resource_reservation::create_storage_cache_current_fixed_receiving_demand_v1,
    cache_dynamic = crate::controller_resource_reservation::create_storage_cache_current_dynamic_receiving_demand_v1,
    producer_traffic = crate::normal_root::ProductionControllerNormalRootProfileV1::create_storage_producer_traffic_bound_v1,
    preparation_originals = crate::controller_resource_reservation::create_storage_preparation_originals_receiving_demand_v1,
    root_tail = crate::controller_resource_reservation::create_storage_root_use_tail_shape_v1,
    history_pair = crate::controller_resource_reservation::create_storage_use_history_pair_receiving_demand_v1,
    profile_rows = crate::controller_resource_reservation::create_storage_use_profile_rows_receiving_demand_v1,
    commit = crate::controller_resource_reservation::create_storage_use_commit_receiving_demand_v1,
    held_release = crate::controller_resource_reservation::create_storage_held_release_receiving_demand_v1,
    signing_originals = crate::controller_resource_reservation::create_storage_signing_originals_receiving_demand_v1,
}
