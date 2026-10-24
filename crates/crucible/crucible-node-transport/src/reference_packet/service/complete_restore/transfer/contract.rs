//! Registers both transfer phases and their complete portable definition.

pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::transfer::{
    PacketCompleteRestoreTransferSchema,
};

pub use crucible_source_birth_data::profile::reference_packet::service::complete_restore::transfer::{
    complete_restore_transfer_contract,
    complete_restore_transfer_schema,
};

// One borrowed compiled roster drives BOTH the existing canonical definition
// and its prospective DOM/canonical counter. No schema bytes or field values
// are regenerated independently in the admission calculation.

pub(crate) use crucible_source_birth_data::profile::reference_packet::service::native_startup::schema_shapes::contracts::complete_restore_transfer_contract_storage_data;
