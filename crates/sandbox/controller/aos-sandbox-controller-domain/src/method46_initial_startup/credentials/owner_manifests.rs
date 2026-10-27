//! Names the independently delivered normal Host and Nix public manifests.
//!
//! Each selector identifies a fixed original public readback. Equal public
//! sources may be shared within one protocol, but are compared at every owner.

use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1;

/// Identifies one normal owner's fixed public manifest delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method46InitialOwnerManifestV1 {
    /// Selects the Nix owner's public catalog manifest.
    NixOwnerCatalog,
    /// Selects the Nix owner's ONLINE broker manifest.
    NixOwnerOnlineBroker,
    /// Selects Controller's ONLINE Nix client manifest.
    ControllerNixOnlineClient,
    /// Selects Host's Controller-facing broker manifest.
    HostControllerBroker,
}

impl Method46InitialOwnerManifestV1 {
    /// Lists the original public members in their fixed read order.
    pub const ALL: [Self; 4] = [
        Self::NixOwnerCatalog,
        Self::NixOwnerOnlineBroker,
        Self::ControllerNixOnlineClient,
        Self::HostControllerBroker,
    ];

    /// Lists the two independent public deliveries to the normal Nix owner.
    pub const NIX_OWNER: [Self; 2] = [Self::NixOwnerCatalog, Self::NixOwnerOnlineBroker];

    /// Returns the normal unit's existing public credential name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NixOwnerCatalog => "nix-broker-session-manifest-v1",
            Self::NixOwnerOnlineBroker => "nix-online-manifest",
            Self::ControllerNixOnlineClient => "nix-online-client-manifest",
            Self::HostControllerBroker => "host-broker-manifest",
        }
    }

    /// Returns the protocol required by this fixed endpoint delivery.
    #[must_use]
    pub const fn protocol(self) -> BrokerSessionProtocolV1 {
        match self {
            Self::NixOwnerCatalog
            | Self::NixOwnerOnlineBroker
            | Self::ControllerNixOnlineClient => BrokerSessionProtocolV1::Nix,
            Self::HostControllerBroker => BrokerSessionProtocolV1::Host,
        }
    }

    pub(in crate::method46_initial_startup) const fn slot(self) -> usize {
        match self {
            Self::NixOwnerCatalog => 32,
            Self::NixOwnerOnlineBroker => 33,
            Self::ControllerNixOnlineClient => 34,
            Self::HostControllerBroker => 35,
        }
    }
}
