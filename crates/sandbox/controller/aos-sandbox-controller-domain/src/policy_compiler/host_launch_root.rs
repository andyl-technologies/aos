//! Owns historical native and semantic prerequisites for fresh Host resources.
//!
//! The historical reader authenticates completed Create evidence without
//! treating it as a new Start, resource grant or mutable current projection.

pub(crate) mod history;

pub(crate) mod opening;
pub(crate) use opening::RootHostLaunchOpeningOriginalV2;

pub(in crate::policy_compiler) mod kind;
pub(in crate::policy_compiler) mod current_storage;
mod host_catalog;
mod compiler;
mod inputs;
mod inputs_receiving;
mod maintenance_assignment;
mod maintenance_request;
mod maintenance_final_models;
mod maintenance_native;
mod maintenance_unsigned;
mod maintenance_final;
mod maintenance_server;
mod maintenance_dispatch;
pub use maintenance_server::RootMaintenanceStorageReceivingV3;
pub(crate) use maintenance_dispatch::RootMaintenanceStorageDispatchOriginalV3;
pub(crate) mod maintenance_opening;
mod session_inventory_origin;
mod plan;
pub(in crate::policy_compiler) mod session;
mod native;
mod unsigned;
mod final_exchange;
mod server;
mod dispatch;
pub use server::RootStartResourceReceivingV2;
pub(crate) use dispatch::RootStartResourceDispatchOriginalV2;
