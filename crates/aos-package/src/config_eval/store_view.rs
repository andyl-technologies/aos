//! Selected package-store read-view contract types.
//!
//! The wire contract is provider-neutral and lives in
//! [`aos_package_store_model`]. This
//! module keeps the configuration evaluator's internal import path concise
//! without defining a second schema or decoder.

pub use aos_package_store_model::{STORE_VIEW_LOCATOR_SCHEMA, StoreViewLocator};
