//! Names fixed public policy pins without selecting files or granting custody.
//!
//! Controller ownership and broker-plan pins are required even when Nix is
//! disabled. Its recipe issuer and all Nix-owner pins follow the Source-bound
//! Nix endpoint selection. Actual PID1 deliveries establish their provenance.

/// Identifies the normal owner of an original public policy pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method46InitialPublicPinOwnerV1 {
    /// Selects the stopped normal Controller's actual credential delivery.
    Controller,
    /// Selects the configured normal Nix broker's actual credential delivery.
    NixBroker,
}

/// Identifies a fixed normal recipe or policy authority's public credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method46InitialPublicPinMemberV1 {
    /// Selects the independent Nix recipe issuer's raw Ed25519 public key.
    NixRecipeIssuer,
    /// Selects the ownership lease policy's raw Ed25519 public key.
    OwnershipLease,
    /// Selects the Host broker-plan policy's raw Ed25519 public key.
    HostBrokerPlan,
    /// Selects the Mount broker-plan policy's raw Ed25519 public key.
    MountBrokerPlan,
}

/// Lists the normal Root public policy pins in their fixed original read order.
///
/// Each is optional only when the actual Root delivery and Source-bound initial
/// unit agree on absence. Root has no Nix recipe issuer in this roster.
pub const METHOD46_INITIAL_ROOT_POLICY_PUBLIC_KEY_MEMBERS_V1: [Method46InitialPublicPinMemberV1;
    3] = [
    Method46InitialPublicPinMemberV1::OwnershipLease,
    Method46InitialPublicPinMemberV1::HostBrokerPlan,
    Method46InitialPublicPinMemberV1::MountBrokerPlan,
];

impl Method46InitialPublicPinMemberV1 {
    /// Lists the public members in their fixed original read order.
    pub const ALL: [Self; 4] = [
        Self::NixRecipeIssuer,
        Self::OwnershipLease,
        Self::HostBrokerPlan,
        Self::MountBrokerPlan,
    ];

    /// Returns the existing normal unit's fixed public credential name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NixRecipeIssuer => "nix-recipe-issuer-v2",
            Self::OwnershipLease => "ownership-lease-public-key",
            Self::HostBrokerPlan => "broker-plan-public-key",
            Self::MountBrokerPlan => "mount-broker-plan-public-key",
        }
    }

    pub(in crate::method46_initial_startup) const fn slot(
        self,
        owner: Method46InitialPublicPinOwnerV1,
    ) -> usize {
        let start = match owner {
            Method46InitialPublicPinOwnerV1::Controller => 16,
            Method46InitialPublicPinOwnerV1::NixBroker => 20,
        };
        start
            + match self {
                Self::NixRecipeIssuer => 0,
                Self::OwnershipLease => 1,
                Self::HostBrokerPlan => 2,
                Self::MountBrokerPlan => 3,
            }
    }
}
