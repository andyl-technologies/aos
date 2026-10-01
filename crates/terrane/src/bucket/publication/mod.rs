//! Owns checked file-bucket publication under retained namespace exclusions.

mod lease_reads;
mod location;

pub(super) use location::configured_location;

// Collector observations preserve actual selected values and physical reads.
#[path = "../../gc/observation.rs"]
pub(crate) mod collection_observation;
