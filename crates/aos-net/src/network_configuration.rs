//! Provider-neutral host network configuration contracts.
//!
//! These types mirror the canonical `aos.network.configuration` ability. They
//! are shared by authorization producers and terminal network backends so a
//! runtime bootstrap result crosses the checked operation edge without a
//! backend-specific translation or duplicate wire model.

use aos_ability_model::{LocalKey, ResourceReference};
use serde::{Deserialize, Serialize};

/// Identifies the authority that owns the persistent host network policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkAuthority {
    /// The image owns the policy until an authenticated operator replaces it.
    Image,
    /// An operator-authored policy supersedes image bootstrap state.
    Operator,
}

/// Selects one or more network links without exposing backend syntax.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LinkSelector {
    /// Selects one link by its stable interface name.
    Name { value: String },
    /// Selects one link by its stable MAC address.
    Mac { value: String },
    /// Selects Ethernet links when no exact early-boot identity is required.
    Ethernet,
}

/// Describes address assignment for a realized network link.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Addressing {
    /// Enables dynamic address assignment.
    pub dhcp: bool,
    /// Lists canonical static addresses in CIDR notation.
    pub addresses: Vec<String>,
    /// Selects the optional default gateway.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// Lists link-local DNS servers.
    pub dns: Vec<String>,
}

/// Describes one provider-neutral link in the persistent host policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NetworkLink {
    /// Configures an existing Ethernet link.
    Ethernet {
        /// Names the semantic link within the policy.
        name: LocalKey,
        /// Selects the physical link.
        selector: LinkSelector,
        /// Configures address assignment.
        addressing: Addressing,
    },
    /// Creates and configures a VLAN link.
    Vlan {
        /// Names the VLAN link.
        name: LocalKey,
        /// Selects the parent link.
        parent: LinkSelector,
        /// Selects the IEEE 802.1Q VLAN identifier.
        id: u16,
        /// Configures address assignment.
        addressing: Addressing,
    },
    /// Creates and configures a bonded link.
    Bond {
        /// Names the bonded link.
        name: LocalKey,
        /// Selects the member links.
        members: Vec<LinkSelector>,
        /// Selects the provider-neutral bond mode.
        mode: String,
        /// Configures address assignment.
        addressing: Addressing,
    },
}

impl NetworkLink {
    /// Returns the semantic link name used for canonical ordering.
    pub fn name(&self) -> &LocalKey {
        match self {
            Self::Ethernet { name, .. } | Self::Vlan { name, .. } | Self::Bond { name, .. } => name,
        }
    }
}

/// Carries an authorized early-network result across a checked operation edge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapNetwork {
    /// Selects the exact early-boot link.
    pub selector: LinkSelector,
    /// Lists canonical static addresses in CIDR notation.
    pub addresses: Vec<String>,
    /// Selects the optional default gateway.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// Lists DNS servers authorized for early bootstrap.
    pub dns: Vec<String>,
}

/// Describes provider-neutral resolver policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverConfiguration {
    /// Enables the selected resolver backend.
    pub enabled: bool,
    /// Lists canonical global DNS servers.
    pub nameservers: Vec<String>,
    /// Lists canonical DNS search domains.
    pub search: Vec<String>,
    /// Selects the closed DNSSEC policy.
    pub dnssec: String,
}

/// Describes the statically planned persistent host network policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfiguration {
    /// Identifies the authority that owns the persistent policy.
    pub authority: NetworkAuthority,
    /// Lists canonical persistent link configurations.
    pub links: Vec<NetworkLink>,
    /// Describes persistent resolver policy.
    pub resolver: ResolverConfiguration,
    /// Lists resources that must remain ready with this policy.
    pub prerequisites: Vec<ResourceReference>,
}

/// Describes runtime input to the network `apply` method.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkApplyInput {
    /// Carries authorized early-network facts, or `None` to retire the seed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<BootstrapNetwork>,
}
