//! Render normalized [`Facts`] into the `host-facts.nix` module.
//!
//! Facts enter eval **only** as typed `host.facts.*` declared inputs (D9),
//! keeping eval a pure function of `(modules + host.nix + facts)`. Stage-2
//! renders `/run/aos-eval/host-facts.nix` from `facts.json`; this module is
//! that pure, deterministic rendering.
//!
//! ```nix
//! # /run/aos-eval/host-facts.nix — rendered, not operator-authored.
//! {
//!   host.facts = {
//!     hostname = "ip-10-0-1-22";
//!     instance_id = "i-0abc…";
//!     region = "us-east-1";
//!     availability_zone = "us-east-1a";
//!     ssh_authorized_keys = [ "ssh-ed25519 AAAA… op@host" ];
//!     interfaces."0a:1b:…" = { names = [ "ens5" ]; addresses = [ ]; };
//!     disks."nvme-Amazon_Elastic_Block_Store_vol0abc" = { };
//!   };
//! }
//! ```
//!
//! Only set fields are emitted, so the output is stable across boots for a
//! fixed input. Strings are escaped for the Nix `"…"` literal; no fact value
//! is ever interpreted as a security decision (review M-gen0key) — the
//! renderer is pure text.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::fetcher::Facts;

/// Canonical typed tree hashed as the `instance_facts` eval input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NormalizedHostFacts {
    /// Hostname, when reported by metadata.
    pub hostname: Option<String>,
    /// Opaque platform instance identifier.
    pub instance_id: Option<String>,
    /// Cloud region, when reported.
    pub region: Option<String>,
    /// Cloud availability zone, when reported.
    pub availability_zone: Option<String>,
    /// Sorted, deduplicated SSH keys.
    pub ssh_authorized_keys: Vec<String>,
    /// Interface facts keyed by canonical MAC address.
    pub interfaces: BTreeMap<String, NormalizedInterfaceFacts>,
    /// Sorted, deduplicated stable disk identifiers.
    pub disks: Vec<String>,
    /// Static network metadata used for DHCP-less bootstrap, when present.
    pub static_network: Option<NormalizedStaticNetworkFacts>,
}

/// Deterministically ordered facts for one MAC-addressed interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NormalizedInterfaceFacts {
    /// Sorted, deduplicated kernel interface names.
    pub names: Vec<String>,
    /// Sorted, deduplicated CIDR addresses reported for this interface.
    pub addresses: Vec<String>,
}

/// Canonical static-network facts retained in the typed eval input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NormalizedStaticNetworkFacts {
    /// Canonical MAC selector, when reported.
    pub mac: Option<String>,
    /// Explicit kernel interface selector used when no MAC was reported.
    pub interface_name: Option<String>,
    /// Sorted, deduplicated CIDR addresses.
    pub addresses: Vec<String>,
    /// Default gateway, when reported.
    pub gateway: Option<String>,
    /// Sorted, deduplicated DNS server addresses.
    pub dns: Vec<String>,
}

/// Normalizes unordered platform fact collections into one deterministic tree.
pub fn normalize_host_facts(facts: &Facts) -> NormalizedHostFacts {
    let mut interfaces: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for binding in &facts.mac_to_iface {
        interfaces
            .entry(binding.mac.to_ascii_lowercase())
            .or_default()
            .insert(binding.iface.clone());
    }
    let static_network = facts.network.as_ref().map(|network| {
        let mac = network.mac.as_ref().map(|mac| mac.to_ascii_lowercase());
        if let Some(mac) = &mac {
            interfaces.entry(mac.clone()).or_default();
        }
        NormalizedStaticNetworkFacts {
            mac,
            interface_name: network.interface_name.clone(),
            addresses: network
                .addresses
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            gateway: network.gateway.clone(),
            dns: network
                .dns
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }
    });
    NormalizedHostFacts {
        hostname: facts.hostname.clone(),
        instance_id: facts.instance_id.clone(),
        region: facts.region.clone(),
        availability_zone: facts.availability_zone.clone(),
        ssh_authorized_keys: facts
            .ssh_authorized_keys
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        interfaces: interfaces
            .into_iter()
            .map(|(mac, names)| {
                let addresses = static_network
                    .as_ref()
                    .filter(|network| network.mac.as_deref() == Some(mac.as_str()))
                    .map_or_else(Vec::new, |network| network.addresses.clone());
                (
                    mac,
                    NormalizedInterfaceFacts {
                        names: names.into_iter().collect(),
                        addresses,
                    },
                )
            })
            .collect(),
        disks: facts
            .disk_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        static_network,
    }
}

/// Escape a string for a Nix double-quoted literal.
///
/// Escapes `\`, `"`, `$` (to neutralize `${…}` antiquotation), and the common
/// control characters. Facts are untrusted, so this must be airtight against a
/// hostile hostname or key comment breaking out of the literal.
fn nix_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

/// Render a single `name = "value";` line at the given indent if `value` is set.
fn opt_str_line(out: &mut String, indent: &str, name: &str, value: &Option<String>) {
    if let Some(v) = value {
        out.push_str(&format!("{indent}{name} = \"{}\";\n", nix_escape(v)));
    }
}

/// Render a Nix list-of-strings literal (`[ "a" "b" ]`).
fn nix_str_list(values: &[String]) -> String {
    if values.is_empty() {
        return "[ ]".to_string();
    }
    let items: Vec<String> = values
        .iter()
        .map(|v| format!("\"{}\"", nix_escape(v)))
        .collect();
    format!("[ {} ]", items.join(" "))
}

/// Render [`Facts`] into the `host-facts.nix` source text.
///
/// The output is a self-contained module setting `host.facts.*`. Empty
/// collections and unset scalars are omitted; an entirely-empty [`Facts`]
/// renders an empty `host.facts = { };`. The rendering is deterministic — the
/// same input always yields byte-identical output — so it can feed the
/// `facts_hash` contract directly.
pub fn render_host_facts_nix(facts: &Facts) -> String {
    let facts = normalize_host_facts(facts);
    let mut out = String::new();
    out.push_str(
        "# /run/aos-eval/host-facts.nix — rendered from facts.json, not operator-authored.\n",
    );
    out.push_str("{\n");
    out.push_str("  host.facts = {\n");

    let ind = "    ";
    opt_str_line(&mut out, ind, "hostname", &facts.hostname);
    opt_str_line(&mut out, ind, "instance_id", &facts.instance_id);
    opt_str_line(&mut out, ind, "region", &facts.region);
    opt_str_line(&mut out, ind, "availability_zone", &facts.availability_zone);

    if !facts.ssh_authorized_keys.is_empty() {
        out.push_str(&format!(
            "{ind}ssh_authorized_keys = {};\n",
            nix_str_list(&facts.ssh_authorized_keys)
        ));
    }

    if !facts.interfaces.is_empty() {
        out.push_str(&format!("{ind}interfaces = {{\n"));
        for (mac, interface) in &facts.interfaces {
            out.push_str(&format!(
                "{ind}  \"{}\" = {{ names = {}; addresses = {}; }};\n",
                nix_escape(mac),
                nix_str_list(&interface.names),
                nix_str_list(&interface.addresses)
            ));
        }
        out.push_str(&format!("{ind}}};\n"));
    }

    if let Some(network) = &facts.static_network {
        out.push_str(&format!("{ind}static_network = {{\n"));
        opt_str_line(&mut out, &format!("{ind}  "), "mac", &network.mac);
        opt_str_line(
            &mut out,
            &format!("{ind}  "),
            "interface_name",
            &network.interface_name,
        );
        out.push_str(&format!(
            "{ind}  addresses = {};\n",
            nix_str_list(&network.addresses)
        ));
        opt_str_line(&mut out, &format!("{ind}  "), "gateway", &network.gateway);
        out.push_str(&format!("{ind}  dns = {};\n", nix_str_list(&network.dns)));
        out.push_str(&format!("{ind}}};\n"));
    }

    if !facts.disks.is_empty() {
        out.push_str(&format!("{ind}disks = {{\n"));
        for disk in &facts.disks {
            out.push_str(&format!("{ind}  \"{}\" = {{ }};\n", nix_escape(disk)));
        }
        out.push_str(&format!("{ind}}};\n"));
    }

    out.push_str("  };\n");
    out.push_str("}\n");
    out
}
