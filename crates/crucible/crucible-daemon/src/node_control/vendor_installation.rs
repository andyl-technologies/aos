//! Starts the production endpoint with an independently installed vendor catalog.
//!
//! The ordinary Compile/Submit/status wire remains unchanged. A trusted actor
//! factory installs the same source and normal Accepted policy before endpoint
//! admission; neither local policy JSON nor a client request supplies authority.

use super::{NodeControlDaemon, NodeDaemonPolicy};
use crate::{
    node_control::NodeControlError, node_observed_executor::InstalledVendorServiceFactory,
};

impl NodeControlDaemon {
    /// Starts the ordinary local endpoint with a trusted vendor installation.
    ///
    /// The same actor owns source/class authorities and native participants.
    /// Complete installation succeeds before the Unix endpoint accepts public
    /// Compile/Submit requests. Existing `start` selects no vendor authority;
    /// the serialized daemon policy and control editions are unchanged.
    ///
    /// # Errors
    /// Refuses invalid local policy, incomplete source/class installation,
    /// competing state ownership, unavailable actor startup or endpoint binding.
    /// Remote selectors cannot create or replace this installation.
    pub fn start_with_vendor_installation(
        policy: NodeDaemonPolicy,
        installation: Box<dyn InstalledVendorServiceFactory>,
    ) -> Result<Self, NodeControlError> {
        Self::start_inner_installed(policy, None, None, Some(installation))
    }
}
