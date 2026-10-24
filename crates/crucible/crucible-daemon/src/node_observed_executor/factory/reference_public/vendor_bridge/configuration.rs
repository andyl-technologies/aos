//! Selects the compiled public reference package without installing authority.
//!
//! This closed configuration supplies data only. The installed source remeasures
//! the complete package/profile, and the ordinary registry separately requires
//! the original normal Accepted policy before any native preparation.
//!
//! ```json
//! {"schema_version":1,"package":{},"profile":"closed_checksum_window_v1",
//!  "node":"checksum","owner":"checksum-owner","quantum_ps":"1000",
//!  "host_budget_ns":"100000000","maximum_windows":8}
//! ```
//! The abbreviated package denotes a complete content reference.

use std::rc::Rc;

use crucible_node_format::{ContentRef, Id, U64, Validate};
use crucible_node_transport::reference_service::ReferenceProfile;
use serde::{Deserialize, Serialize};

use super::super::package::InstalledPublicReferencePackage;
use crate::node_observed_executor::{NodeObservedError, factory::refused};

/// Names the source-implemented vendor checksum subset.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicReferenceVendorProfile {
    /// Accepts only authenticated empty input cuts and quantized windows.
    ClosedChecksumWindowV1,
}

/// Selects an existing compiled installation without supplying a qualification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicReferenceVendorSelection {
    /// Selects the closed configuration edition.
    pub schema_version: u16,
    /// Commits to the complete compiled source-built package.
    pub package: ContentRef,
    /// Selects the supported application protocol subset.
    pub profile: PublicReferenceVendorProfile,
    /// Names the one logical node in the complete authored graph.
    pub node: Id,
    /// Names its independently authored mutable owner.
    pub owner: Id,
    /// Gives the positive source-selected quantized grid.
    pub quantum_ps: U64,
    /// Gives the finite per-window physical budget, distinct from model time.
    pub host_budget_ns: U64,
    /// Bounds retained original windows without recycling prior identities.
    pub maximum_windows: usize,
}

impl PublicReferenceVendorSelection {
    /// Remeasures the compiled package and regenerates the exact closed profile.
    ///
    /// Returning metadata creates no native participant, source revision or
    /// acceptance. Callers must retain the separate source/class conjunction.
    ///
    /// # Errors
    /// Refuses another edition/package, invalid identities, zero timing budgets,
    /// excessive original windows or an unsupported compiled source profile.
    pub fn describe(
        &self,
    ) -> Result<(Rc<InstalledPublicReferencePackage>, ReferenceProfile), NodeObservedError> {
        if self.schema_version != 1
            || self.quantum_ps.get() == 0
            || self.host_budget_ns.get() == 0
            || !(1..=256).contains(&self.maximum_windows)
        {
            return Err(refused("unsupported finite public vendor selection"));
        }
        self.package.validate()?;
        self.node.validate()?;
        self.owner.validate()?;

        let package = InstalledPublicReferencePackage::built_in()?;
        if package.identity() != &self.package {
            return Err(refused(
                "public vendor package is not the compiled installation",
            ));
        }
        let profile = match self.profile {
            PublicReferenceVendorProfile::ClosedChecksumWindowV1 => package.profile(
                self.node.clone(),
                self.owner.clone(),
                self.quantum_ps,
                self.host_budget_ns,
                true,
            )?,
        };
        Ok((package, profile))
    }
}
