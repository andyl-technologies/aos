//! Static-networking seed for DHCP-less clouds.
//!
//! On clouds with no DHCP server (DigitalOcean static/anchor IPs, OpenStack
//! `network_data.json`), the gen-0 DHCP seed gets no lease, so stage-2 has no
//! route to the registry and eval deadlocks. The initrd `fetch` phase parses
//! the platform network config into a [`StaticNetwork`] and renders a minimal
//! `10-aos-seed.network` — a *substrate fact*, not operator config, carrying
//! no security decision (just an IP/route).
//!
//! Parsers:
//!
//! - [`parse_openstack_network_data`] — OpenStack `network_data.json`
//!   (`.networks[]`: `link`, `ip_address`, `netmask`, `gateway`; `.links[]`:
//!   `ethernet_mac_address`).
//! - [`parse_netplan_network_config`] — NoCloud `network-config`
//!   (netplan v1/v2 YAML `ethernets.<name>.{addresses,gateway4,nameservers}`).
//!
//! Renderer: [`render_networkd`] emits the `[Match]`/`[Network]` ini. The seed
//! is written only when [`StaticNetwork::is_seedable`] holds; the operator's
//! declared network in `host.nix` supersedes it at the first `/etc` swap.

use anyhow::{Context, Result};
use serde::Deserialize;

use super::fetcher::StaticNetwork;

/// Filename the seed is written under, in the stash and the `/var/etc` lower.
pub const SEED_FILENAME: &str = "10-aos-seed.network";

/// Render a [`StaticNetwork`] into a systemd-networkd `.network` unit.
///
/// Produces a deterministic `[Match]`/`[Network]` document. When `mac` is set
/// it becomes `MACAddress=`; otherwise the `[Match]` section is omitted and the
/// unit matches the first managed link by file ordering.
///
/// ```text
/// # 10-aos-seed.network — substrate-fact static seed (DHCP-less cloud).
/// [Match]
/// MACAddress=0a:1b:2c:3d:4e:5f
/// [Network]
/// Address=203.0.113.10/24
/// Gateway=203.0.113.1
/// DNS=67.207.67.2
/// ```
/// Strips control characters (incl. `\n`/`\r`) from an untrusted INI value.
///
/// The seed values come from unauthenticated platform metadata; a value with an
/// embedded newline could otherwise inject a `networkd` directive. Address/MAC/
/// DNS values never legitimately contain control characters, so dropping them is
/// lossless for any well-formed input and neutralizes injection.
fn ini_safe(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

pub fn render_networkd(net: &StaticNetwork) -> String {
    let mut out = String::new();
    out.push_str("# 10-aos-seed.network — substrate-fact static seed (DHCP-less cloud).\n");
    if let Some(mac) = &net.mac {
        out.push_str("[Match]\n");
        out.push_str(&format!("MACAddress={}\n", ini_safe(mac)));
    }
    out.push_str("[Network]\n");
    for addr in &net.addresses {
        out.push_str(&format!("Address={}\n", ini_safe(addr)));
    }
    if let Some(gw) = &net.gateway {
        out.push_str(&format!("Gateway={}\n", ini_safe(gw)));
    }
    for dns in &net.dns {
        out.push_str(&format!("DNS={}\n", ini_safe(dns)));
    }
    out
}

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
            net.mac = data
                .links
                .iter()
                .find(|l| l.id.as_deref() == Some(link_id.as_str()))
                .and_then(|l| l.ethernet_mac_address.clone())
                .map(|m| m.to_lowercase());
        }
        // Fall back to the sole link's MAC.
        if net.mac.is_none() {
            net.mac = data
                .links
                .first()
                .and_then(|l| l.ethernet_mac_address.clone())
                .map(|m| m.to_lowercase());
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
fn netmask_to_prefix(mask: &str) -> u32 {
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

#[derive(Debug, Deserialize)]
struct NetplanRoot {
    #[serde(default)]
    network: Option<NetplanNetwork>,
    // netplan v1 nests under `network:`; some emitters put ethernets at top.
    #[serde(default)]
    ethernets: Option<std::collections::BTreeMap<String, NetplanEthernet>>,
}

#[derive(Debug, Deserialize)]
struct NetplanNetwork {
    #[serde(default)]
    ethernets: std::collections::BTreeMap<String, NetplanEthernet>,
}

#[derive(Debug, Deserialize)]
struct NetplanEthernet {
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    gateway4: Option<String>,
    #[serde(default)]
    nameservers: Option<NetplanNameservers>,
    #[serde(default, rename = "match")]
    match_on: Option<NetplanMatch>,
}

#[derive(Debug, Deserialize)]
struct NetplanNameservers {
    #[serde(default)]
    addresses: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct NetplanMatch {
    #[serde(default)]
    macaddress: Option<String>,
}

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
    let root: NetplanRoot =
        serde_yaml::from_slice(bytes).context("parsing NoCloud network-config (netplan YAML)")?;

    let ethernets = root
        .network
        .map(|n| n.ethernets)
        .or(root.ethernets)
        .unwrap_or_default();

    let mut net = StaticNetwork::default();
    if let Some((_, eth)) = ethernets.into_iter().next() {
        net.addresses = eth.addresses;
        net.gateway = eth.gateway4;
        net.dns = eth.nameservers.map(|n| n.addresses).unwrap_or_default();
        net.mac = eth
            .match_on
            .and_then(|m| m.macaddress)
            .map(|m| m.to_lowercase());
    }
    Ok(net)
}
