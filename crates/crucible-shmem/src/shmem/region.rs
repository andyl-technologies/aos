//! Shared-memory region headers, geometry, validation, and initialization.

use super::*;

#[path = "region/allocation_access.rs"]
mod allocation_access;
#[path = "region/allocation_io.rs"]
mod allocation_io;
#[path = "region/allocation_scheduler.rs"]
mod allocation_scheduler;
#[path = "region/allocation_serialization.rs"]
mod allocation_serialization;
#[path = "region/errors.rs"]
mod errors;
#[path = "region/header.rs"]
mod header;
#[path = "region/helpers.rs"]
mod helpers;
#[path = "region/layout.rs"]
mod layout;
#[path = "region/types.rs"]
mod types;

pub use errors::*;
pub use header::*;
use helpers::*;
pub use layout::*;
pub use types::*;
