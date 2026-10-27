//! Shares strict image-profile DATA and original image observations below roles.
//!
//! These are the same schema, fixed delivery predicates, property views and
//! immutable-file engines used by Root and Controller. Decoded profiles and
//! observed properties establish no C/F/R loan, journal, key custody or role
//! admission. Actual role owners retain and pay their native originals.

pub mod delivery;
pub mod error;
pub mod images;
pub mod method46_initial;
pub mod native_observation;
pub(crate) mod shared_read;
pub mod property_data;
pub mod property_values;
pub mod root_peer_data;
pub mod schema;
pub mod status;

pub use error::ControllerProfileErrorV1;

/// Shares fixed publisher profile comparison DATA without role admission.
pub mod runtime_deployment;
