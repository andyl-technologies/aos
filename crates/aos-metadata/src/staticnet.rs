//! Static-network metadata parsers for DHCP-less clouds.
//!
//! On clouds with no DHCP server (DigitalOcean static/anchor IPs, OpenStack
//! `network_data.json`), the initial DHCP configuration cannot acquire a
//! route. The metadata provider parses the platform network config into a
//! [`StaticNetwork`] that crosses the effect graph as a typed semantic value.
//!
//! Parsers:
//!
//! - [`parse_openstack_network_data`] — OpenStack `network_data.json`
//!   (`.networks[]`: `link`, `ip_address`, `netmask`, `gateway`; `.links[]`:
//!   `ethernet_mac_address`).
//! - [`parse_netplan_network_config`] — NoCloud `network-config`
//!   (netplan v1/v2 YAML `ethernets.<name>.{addresses,gateway4,nameservers}`).
//!
//! Parsed values remain semantic facts. The selected portable network provider
//! receives them through a typed operation result and owns native rendering.

use anyhow::{Context, Result};
use serde::Deserialize;

use super::fetcher::StaticNetwork;

// ---------------------------------------------------------------------------
// OpenStack network_data.json
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct OpenStackNetworkData {
    #[serde(default)]
    links: Vec<OsLink>,
    #[serde(default)]
    networks: Vec<OsNetwork>,
    #[serde(default)]
    services: Vec<OsService>,
}

#[derive(Debug, Deserialize)]
struct OsLink {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    ethernet_mac_address: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsNetwork {
    #[serde(default)]
    link: Option<String>,
    #[serde(default)]
    ip_address: Option<String>,
    #[serde(default)]
    netmask: Option<String>,
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default)]
    routes: Vec<OsRoute>,
}

#[derive(Debug, Deserialize)]
struct OsRoute {
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    gateway: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsService {
    #[serde(rename = "type", default)]
    service_type: Option<String>,
    #[serde(default)]
    address: Option<String>,
}

/// Parse OpenStack `network_data.json` into a [`StaticNetwork`].
///
/// Joins the first `networks[]` entry to its `links[]` MAC via `link`/`id`,
/// converts `ip_address` + `netmask` to CIDR, and pulls the gateway from the
/// network's `gateway` or a default `0.0.0.0/0` route. DNS comes from `dns`
/// services.
///
/// # Errors
///
/// Returns `Err` when `bytes` is not valid JSON of the expected shape.
pub fn parse_openstack_network_data(bytes: &[u8]) -> Result<StaticNetwork> {
    let data: OpenStackNetworkData =
        serde_json::from_slice(bytes).context("parsing OpenStack network_data.json")?;

    let mut net = StaticNetwork::default();

    if let Some(network) = data.networks.first() {
        // Resolve the MAC by joining the network's link id to links[].id.
        if let Some(link_id) = &network.link {
            let link = data
                .links
                .iter()
                .find(|l| l.id.as_deref() == Some(link_id.as_str()));
            net.mac = link
                .and_then(|l| l.ethernet_mac_address.clone())
                .map(|m| m.to_lowercase());
            net.interface_name = link.and_then(|l| l.name.clone());
        }
        // Fall back to the sole link's MAC.
        if net.mac.is_none() {
            net.mac = data
                .links
                .first()
                .and_then(|l| l.ethernet_mac_address.clone())
                .map(|m| m.to_lowercase());
        }
        if net.interface_name.is_none() && data.links.len() == 1 {
            net.interface_name = data.links.first().and_then(|l| l.name.clone());
        }

        if let Some(ip) = &network.ip_address {
            let cidr = match &network.netmask {
                Some(mask) => format!("{ip}/{}", netmask_to_prefix(mask)),
                None => ip.clone(),
            };
            net.addresses.push(cidr);
        }

        net.gateway = network.gateway.clone().or_else(|| {
            network
                .routes
                .iter()
                .find(|r| matches!(r.network.as_deref(), Some("0.0.0.0") | Some("::")))
                .and_then(|r| r.gateway.clone())
        });
    }

    net.dns = data
        .services
        .iter()
        .filter(|s| s.service_type.as_deref() == Some("dns"))
        .filter_map(|s| s.address.clone())
        .collect();

    Ok(net)
}

/// Convert a dotted IPv4 netmask (`255.255.255.0`) to a prefix length (`24`).
///
/// A value that already looks like a prefix (`24`) is returned as-is. Falls
/// back to `32` for an unparseable mask.
pub(super) fn netmask_to_prefix(mask: &str) -> u32 {
    if let Ok(p) = mask.parse::<u32>()
        && p <= 32
    {
        return p;
    }
    mask.split('.')
        .filter_map(|o| o.parse::<u8>().ok())
        .map(|o| o.count_ones())
        .sum::<u32>()
        .min(32)
        .max(if mask.contains('.') { 0 } else { 32 })
}

// ---------------------------------------------------------------------------
// NoCloud netplan network-config
// ---------------------------------------------------------------------------

/// Parse a NoCloud netplan `network-config` (v1/v2 YAML) into a
/// [`StaticNetwork`].
///
/// Reads the first `ethernets.<name>` entry's `addresses`, `gateway4`,
/// `nameservers.addresses`, and `match.macaddress`. Returns an empty
/// [`StaticNetwork`] (not seedable) when no ethernet is declared.
///
/// # Errors
///
/// Returns `Err` when `bytes` is not valid YAML of the expected shape.
pub fn parse_netplan_network_config(bytes: &[u8]) -> Result<StaticNetwork> {
    super::yaml::parse_netplan(bytes).context("parsing NoCloud network-config (netplan YAML)")
}
