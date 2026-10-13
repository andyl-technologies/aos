//! Installs the ordinary closed public reference participant and its trusted scope.
//!
//! Configuration selects compiled source metadata. Separate original world
//! inspection and normal Accepted class policy authenticate that selection.
//! One inactive peer remains beneath the common preparation and activation;
//! unsupported mixed scopes and all preservation facets remain refused.

mod behavioral;
mod configuration;
mod currency;
mod geometry;
mod installation;
mod launch_upload;
mod negotiation;
pub(super) use negotiation::{OriginalReferenceNegotiation, OriginalReferenceTransport};
mod collecting_launch;
mod ordinary_launch;
pub(super) use collecting_launch::{
    CollectingReferenceLaunch, prepare as prepare_collecting_singleton,
};

mod provider;
mod source;

pub use configuration::{PublicReferenceVendorProfile, PublicReferenceVendorSelection};
pub use installation::{ReferenceVendorInstallation, ReferenceVendorInstallationRequest};

pub(in crate::node_observed_executor::factory) use installation::ReferenceVendorCleanup;
