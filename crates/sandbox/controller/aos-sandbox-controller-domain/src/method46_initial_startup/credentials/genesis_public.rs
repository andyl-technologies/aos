//! Names the existing Source and Project genesis public verifier deliveries.
//!
//! Root and Controller may select different external sources. These selectors
//! identify only original public readbacks; they contain no seed or authority.

/// Identifies a normal owner's fixed administrative genesis public pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method46InitialGenesisPublicPinV1 {
    /// Selects Root's Source-tree seed verifier credential.
    RootSourceTreeSeed,
    /// Selects Root's Project authorization issuer credential.
    RootProjectAuthorization,
    /// Selects Controller's Source-tree seed verifier credential.
    ControllerSourceTreeSeed,
    /// Selects Controller's Project authorization issuer credential.
    ControllerProjectAuthorization,
}

impl Method46InitialGenesisPublicPinV1 {
    /// Lists the original public members in their fixed read order.
    pub const ALL: [Self; 4] = [
        Self::RootSourceTreeSeed,
        Self::RootProjectAuthorization,
        Self::ControllerSourceTreeSeed,
        Self::ControllerProjectAuthorization,
    ];

    /// Lists the paired public members delivered to normal Root.
    pub const ROOT: [Self; 2] = [Self::RootSourceTreeSeed, Self::RootProjectAuthorization];

    /// Lists the public members independently selected by normal Controller.
    pub const CONTROLLER: [Self; 2] = [
        Self::ControllerSourceTreeSeed,
        Self::ControllerProjectAuthorization,
    ];

    /// Returns the normal unit's existing public credential name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RootSourceTreeSeed | Self::ControllerSourceTreeSeed => {
                "controller-source-tree-seed-issuer-v1"
            }
            Self::RootProjectAuthorization | Self::ControllerProjectAuthorization => {
                "project-authorization-issuer-v2"
            }
        }
    }

    pub(in crate::method46_initial_startup) const fn slot(self) -> usize {
        match self {
            Self::RootSourceTreeSeed => 27,
            Self::RootProjectAuthorization => 28,
            Self::ControllerSourceTreeSeed => 29,
            Self::ControllerProjectAuthorization => 30,
        }
    }
}
