//! Fixed-iproute2 decoding for exact link, address, route, and rule inventory.
//!
//! The reader executes one immutable `ip` binary retained by descriptor. A
//! host read is limited to the plan-derived veth name, while a sandbox read is
//! deliberately unfiltered so an extra link, address, route table, or policy
//! rule remains visible to the equality-oriented postcondition comparator.
//!
//! Each invocation must produce one complete newline-terminated JSON array:
//!
//! ```json
//! [{"priority":0,"src":"all","table":"local"}]
//! ```
//!
//! The normalized route model preserves Linux's family-specific defaults.
//! IPv4 connected/static routes use metrics of zero and connected scope
//! `link`; IPv6 uses metric 256 for connected routes, 1024 for static routes,
//! and also synthesizes the local-table `ff00::/8` multicast route. Unknown
//! semantic fields are rejected instead of being discarded.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::IpAddr;
use std::path::PathBuf;

use serde_json::{Map, Value};

use crate::kernel_observation::{
    NetworkKernelExpectationV1, ObservedAddressV1, ObservedIpAddressV1, ObservedIpFamilyV1,
    ObservedIpPrefixV1, ObservedIpv6AddressGenerationV1, ObservedLinkV1,
    ObservedNetworkNamespaceV1, ObservedPolicyRuleV1, ObservedRouteProtocolV1,
    ObservedRouteScopeV1, ObservedRouteTypeV1, ObservedRouteV1,
};
use crate::kernel_reader::{NetworkKernelReaderError, PinnedArtifact, successful_helper_stdout};

const MAXIMUM_LINK_BYTES: usize = 64 * 1024;
const MAXIMUM_ADDRESS_BYTES: usize = 64 * 1024;
const MAXIMUM_ROUTE_BYTES: usize = 128 * 1024;
const MAXIMUM_RULE_BYTES: usize = 16 * 1024;

/// Carries the plan-selected host veth and its complete address inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtnetlinkLinkInventoryV1 {
    /// Exact host-side veth identity.
    pub link: ObservedLinkV1,
    /// Every address returned for that veth.
    pub addresses: Vec<ObservedAddressV1>,
}

/// Carries one complete unfiltered sandbox rtnetlink snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtnetlinkNamespaceInventoryV1 {
    /// Every link in the namespace.
    pub links: Vec<ObservedLinkV1>,
    /// Every address on those links.
    pub addresses: Vec<ObservedAddressV1>,
    /// Every IPv4 and IPv6 route from every table.
    pub routes: Vec<ObservedRouteV1>,
    /// Every IPv4 and IPv6 policy-routing rule.
    pub policy_rules: Vec<ObservedPolicyRuleV1>,
}

/// Executes a retained immutable `ip` binary and decodes closed observations.
#[derive(Debug)]
pub struct FixedRtnetlinkObservationReader {
    ip: PinnedArtifact,
}

impl FixedRtnetlinkObservationReader {
    /// Resolves and retains an immutable Nix-store `ip` executable.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkKernelReaderError`] unless `ip` is a protected,
    /// root-owned, non-writable regular executable beneath `/nix/store`.
    pub fn new(ip: PathBuf) -> Result<Self, NetworkKernelReaderError> {
        Ok(Self {
            ip: PinnedArtifact::open(ip, true)?,
        })
    }

    /// Reads the host veth selected by the sealed kernel expectation.
    ///
    /// This method must run in the initial host network namespace. No caller
    /// supplies a link label: the only filter is the deterministic name already
    /// bound into `expectation`.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkKernelReaderError`] if the plan has no veth, the fixed
    /// process fails, output is incomplete, or the result is not exactly one
    /// veth and its complete address list.
    pub fn observe_host_veth(
        &self,
        expectation: &NetworkKernelExpectationV1,
    ) -> Result<RtnetlinkLinkInventoryV1, NetworkKernelReaderError> {
        let name = expectation
            .veth()
            .ok_or(NetworkKernelReaderError::InvalidRtnetlink(
                "isolated plans do not have a host veth",
            ))?
            .host_name
            .as_str();
        validate_interface_name(name)?;

        let link_json = self.run(
            &["-j", "-details", "link", "show", "dev", name],
            MAXIMUM_LINK_BYTES,
        )?;
        let address_json = self.run(
            &["-j", "address", "show", "dev", name],
            MAXIMUM_ADDRESS_BYTES,
        )?;
        let links = decode_links(&link_json)?;
        if links.len() != 1 || links[0].name != name || links[0].kind != "veth" {
            return Err(NetworkKernelReaderError::InvalidRtnetlink(
                "host link result is not the exact expected veth",
            ));
        }
        let addresses = decode_addresses(&address_json, &links, ObservedNetworkNamespaceV1::Host)?;

        Ok(RtnetlinkLinkInventoryV1 {
            link: links
                .into_iter()
                .next()
                .ok_or(NetworkKernelReaderError::InvalidRtnetlink(
                    "host veth result is empty",
                ))?,
            addresses,
        })
    }

    /// Reads every link, address, route table, and rule in the current namespace.
    ///
    /// The authenticated namespace worker must enter its retained namespace
    /// descriptor before invoking this method. All commands are unfiltered;
    /// both route families explicitly request `table all`.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkKernelReaderError`] if a fixed process fails, output is
    /// incomplete, an object is duplicated, or any semantic field lies outside
    /// the admitted rtnetlink observation schema.
    pub fn observe_sandbox(
        &self,
    ) -> Result<RtnetlinkNamespaceInventoryV1, NetworkKernelReaderError> {
        let link_json = self.run(&["-j", "-details", "link", "show"], MAXIMUM_LINK_BYTES)?;
        let address_json = self.run(&["-j", "address", "show"], MAXIMUM_ADDRESS_BYTES)?;
        let routes_v4 = self.run(
            &["-j", "-4", "route", "show", "table", "all"],
            MAXIMUM_ROUTE_BYTES,
        )?;
        let routes_v6 = self.run(
            &["-j", "-6", "route", "show", "table", "all"],
            MAXIMUM_ROUTE_BYTES,
        )?;
        let rules_v4 = self.run(&["-j", "-4", "rule", "show"], MAXIMUM_RULE_BYTES)?;
        let rules_v6 = self.run(&["-j", "-6", "rule", "show"], MAXIMUM_RULE_BYTES)?;

        let mut links = decode_links(&link_json)?;
        let addresses =
            decode_addresses(&address_json, &links, ObservedNetworkNamespaceV1::Sandbox)?;
        let interface_indices = links
            .iter()
            .map(|link| (link.name.as_str(), link.ifindex))
            .collect::<BTreeMap<_, _>>();
        let mut routes = decode_routes(&routes_v4, ObservedIpFamilyV1::Ipv4, &interface_indices)?;
        routes.extend(decode_routes(
            &routes_v6,
            ObservedIpFamilyV1::Ipv6,
            &interface_indices,
        )?);
        let mut policy_rules = decode_rules(&rules_v4, ObservedIpFamilyV1::Ipv4)?;
        policy_rules.extend(decode_rules(&rules_v6, ObservedIpFamilyV1::Ipv6)?);

        links.sort_by_key(|link| link.ifindex);
        routes.sort_unstable();
        policy_rules.sort_unstable();
        reject_duplicates(&links, "duplicate link")?;
        reject_duplicates(&routes, "duplicate route")?;
        reject_duplicates(&policy_rules, "duplicate policy rule")?;

        Ok(RtnetlinkNamespaceInventoryV1 {
            links,
            addresses,
            routes,
            policy_rules,
        })
    }

    fn run(
        &self,
        arguments: &[&str],
        maximum_stdout_bytes: usize,
    ) -> Result<Vec<u8>, NetworkKernelReaderError> {
        let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        successful_helper_stdout(self.ip.run(&arguments, maximum_stdout_bytes)?)
    }
}

fn validate_interface_name(name: &str) -> Result<(), NetworkKernelReaderError> {
    if name.is_empty()
        || name.len() > 15
        || name.as_bytes().contains(&0)
        || name == "."
        || name == ".."
        || name
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_whitespace() || *byte == b'/')
    {
        return Err(NetworkKernelReaderError::InvalidRtnetlink(
            "derived interface name is invalid",
        ));
    }
    Ok(())
}

pub(crate) fn decode_links(bytes: &[u8]) -> Result<Vec<ObservedLinkV1>, NetworkKernelReaderError> {
    let values = decode_array(bytes)?;
    values.iter().map(decode_link).collect()
}

fn decode_link(value: &Value) -> Result<ObservedLinkV1, NetworkKernelReaderError> {
    let object = as_object(value)?;
    reject_unknown_fields(object, LINK_FIELDS, "link has an unknown field")?;
    let ifindex = required_u32(object, "ifindex")?;
    let name = required_string(object, "ifname")?.to_owned();
    validate_interface_name(&name)?;
    let mtu = required_u32(object, "mtu")?;
    let flags = required_array(object, "flags")?;
    let mac = parse_mac(required_string(object, "address")?)?;

    let (peer_ifindex, peer_namespace_id, kind) = if name == "lo" {
        if required_string(object, "link_type")? != "loopback"
            || !string_array_equals(flags, &["LOOPBACK", "UP", "LOWER_UP"])
        {
            return invalid("loopback link identity is inconsistent");
        }
        (0, None, "loopback".to_owned())
    } else {
        if required_string(object, "link_type")? != "ether"
            || !string_array_equals(flags, &["BROADCAST", "MULTICAST", "UP", "LOWER_UP"])
        {
            return invalid("veth flags or link-layer type are inconsistent");
        }
        let peer_ifindex = required_u32(object, "link_index")?;
        let peer_namespace_id = required_u32(object, "link_netnsid")?;
        let linkinfo = required_object(object, "linkinfo")?;
        reject_unknown_fields(
            linkinfo,
            &["info_kind"],
            "veth link information has an unknown field",
        )?;
        let kind = required_string(linkinfo, "info_kind")?.to_owned();
        if peer_ifindex == 0 || kind != "veth" {
            return invalid("non-loopback link is not a veth peer");
        }
        (peer_ifindex, Some(peer_namespace_id), kind)
    };
    let ipv6_address_generation = validate_link_metadata(object, &kind)?;

    Ok(ObservedLinkV1 {
        ifindex,
        peer_ifindex,
        peer_namespace_id,
        name,
        kind,
        mtu,
        mac,
        up: true,
        ipv6_address_generation,
    })
}

const LINK_FIELDS: &[&str] = &[
    "ifindex",
    "link_index",
    "ifname",
    "flags",
    "mtu",
    "qdisc",
    "operstate",
    "linkmode",
    "group",
    "txqlen",
    "link_type",
    "address",
    "broadcast",
    "link_netnsid",
    "promiscuity",
    "allmulti",
    "min_mtu",
    "max_mtu",
    "netns-immutable",
    "linkinfo",
    "inet6_addr_gen_mode",
    "num_tx_queues",
    "num_rx_queues",
    "gso_max_size",
    "gso_max_segs",
    "tso_max_size",
    "tso_max_segs",
    "gro_max_size",
    "gso_ipv4_max_size",
    "gro_ipv4_max_size",
];

fn validate_link_metadata(
    object: &Map<String, Value>,
    kind: &str,
) -> Result<ObservedIpv6AddressGenerationV1, NetworkKernelReaderError> {
    let loopback = kind == "loopback";
    if required_string(object, "qdisc")? != "noqueue"
        || required_string(object, "operstate")? != if loopback { "UNKNOWN" } else { "UP" }
        || required_string(object, "linkmode")? != "DEFAULT"
        || required_string(object, "group")? != "default"
        || required_string(object, "broadcast")?
            != if loopback {
                "00:00:00:00:00:00"
            } else {
                "ff:ff:ff:ff:ff:ff"
            }
        || optional_u32(object, "promiscuity")?.unwrap_or(0) != 0
        || optional_u32(object, "allmulti")?.unwrap_or(0) != 0
    {
        return invalid("link carries unsupported behavioral attributes");
    }
    let ipv6_address_generation = match required_string(object, "inet6_addr_gen_mode")? {
        "eui64" if loopback => ObservedIpv6AddressGenerationV1::Eui64,
        "none" if !loopback => ObservedIpv6AddressGenerationV1::None,
        _ => return invalid("link IPv6 address generation differs from its role"),
    };
    if let Some(value) = object.get("netns-immutable")
        && value.as_bool() != Some(true)
    {
        return invalid("link netns-immutable metadata is malformed");
    }
    if let Some(value) = object.get("link_netnsid")
        && value.as_i64().is_none()
    {
        return invalid("link peer namespace ID is malformed");
    }
    for key in [
        "txqlen",
        "min_mtu",
        "max_mtu",
        "num_tx_queues",
        "num_rx_queues",
        "gso_max_size",
        "gso_max_segs",
        "tso_max_size",
        "tso_max_segs",
        "gro_max_size",
        "gso_ipv4_max_size",
        "gro_ipv4_max_size",
    ] {
        if object
            .get(key)
            .is_some_and(|value| value.as_u64().is_none())
        {
            return invalid("link display metadata has an invalid JSON type");
        }
    }
    Ok(ipv6_address_generation)
}

pub(crate) fn decode_addresses(
    bytes: &[u8],
    links: &[ObservedLinkV1],
    namespace: ObservedNetworkNamespaceV1,
) -> Result<Vec<ObservedAddressV1>, NetworkKernelReaderError> {
    let links_by_name = links
        .iter()
        .map(|link| (link.name.as_str(), link.ifindex))
        .collect::<BTreeMap<_, _>>();
    let mut addresses = Vec::new();
    let mut address_link_indices = Vec::new();

    for value in decode_array(bytes)? {
        let object = as_object(&value)?;
        reject_unknown_fields(
            object,
            ADDRESS_LINK_FIELDS,
            "address link record has an unknown field",
        )?;
        let ifindex = required_u32(object, "ifindex")?;
        let ifname = required_string(object, "ifname")?;
        let link = links.iter().find(|link| link.name == ifname);
        if links_by_name.get(ifname).copied() != Some(ifindex) || link.is_none() {
            return invalid("address result refers to an unknown link");
        }
        validate_address_link_record(
            object,
            link.ok_or(NetworkKernelReaderError::InvalidRtnetlink(
                "address result refers to an unknown link",
            ))?,
        )?;
        address_link_indices.push(ifindex);
        for address in required_array(object, "addr_info")? {
            let address = as_object(address)?;
            reject_unknown_fields(address, ADDRESS_FIELDS, "address has an unknown field")?;
            let family = parse_family(required_string(address, "family")?)?;
            let local = parse_address(required_string(address, "local")?, family)?;
            let prefix_length = required_u8(address, "prefixlen")?;
            validate_prefix_length(local, prefix_length)?;
            validate_address_metadata(address, ifname, family)?;
            addresses.push(ObservedAddressV1 {
                namespace,
                ifindex,
                address: local,
                prefix_length,
            });
        }
    }
    address_link_indices.sort_unstable();
    let mut expected_link_indices = links.iter().map(|link| link.ifindex).collect::<Vec<_>>();
    expected_link_indices.sort_unstable();
    if address_link_indices != expected_link_indices {
        return invalid("address result does not cover every link exactly once");
    }
    addresses.sort_unstable();
    reject_duplicates(&addresses, "duplicate address")?;
    Ok(addresses)
}

const ADDRESS_LINK_FIELDS: &[&str] = &[
    "ifindex",
    "link_index",
    "ifname",
    "flags",
    "mtu",
    "qdisc",
    "operstate",
    "group",
    "txqlen",
    "link_type",
    "address",
    "broadcast",
    "link_netnsid",
    "addr_info",
];

const ADDRESS_FIELDS: &[&str] = &[
    "family",
    "local",
    "prefixlen",
    "scope",
    "label",
    "protocol",
    "valid_life_time",
    "preferred_life_time",
];

fn validate_address_link_record(
    object: &Map<String, Value>,
    link: &ObservedLinkV1,
) -> Result<(), NetworkKernelReaderError> {
    let loopback = link.kind == "loopback";
    let expected_flags = if loopback {
        &["LOOPBACK", "UP", "LOWER_UP"][..]
    } else {
        &["BROADCAST", "MULTICAST", "UP", "LOWER_UP"][..]
    };
    if required_u32(object, "mtu")? != link.mtu
        || !string_array_equals(required_array(object, "flags")?, expected_flags)
        || required_string(object, "qdisc")? != "noqueue"
        || required_string(object, "operstate")? != if loopback { "UNKNOWN" } else { "UP" }
        || required_string(object, "group")? != "default"
        || required_string(object, "link_type")? != if loopback { "loopback" } else { "ether" }
        || parse_mac(required_string(object, "address")?)? != link.mac
        || required_string(object, "broadcast")?
            != if loopback {
                "00:00:00:00:00:00"
            } else {
                "ff:ff:ff:ff:ff:ff"
            }
    {
        return invalid("address link record differs from the link inventory");
    }
    match (link.peer_namespace_id, link.kind.as_str()) {
        (Some(peer_namespace_id), "veth")
            if required_u32(object, "link_index")? == link.peer_ifindex
                && required_u32(object, "link_netnsid")? == peer_namespace_id => {}
        (None, "loopback")
            if !object.contains_key("link_index") && !object.contains_key("link_netnsid") => {}
        _ => return invalid("address link peer identity differs from the link inventory"),
    }
    if object
        .get("txqlen")
        .is_some_and(|value| value.as_u64().is_none())
    {
        return invalid("address link transmit queue length is malformed");
    }
    Ok(())
}

fn validate_address_metadata(
    address: &Map<String, Value>,
    ifname: &str,
    family: ObservedIpFamilyV1,
) -> Result<(), NetworkKernelReaderError> {
    let scope = required_string(address, "scope")?;
    let expected_scope = if ifname == "lo" { "host" } else { "global" };
    if scope != expected_scope {
        return invalid("address scope differs from its link role");
    }
    let label = optional_string(address, "label")?;
    if (family == ObservedIpFamilyV1::Ipv4 && label != Some(ifname))
        || (family == ObservedIpFamilyV1::Ipv6 && label.is_some())
    {
        return invalid("address label differs from its family and link");
    }
    let valid = required_u64(address, "valid_life_time")?;
    let preferred = required_u64(address, "preferred_life_time")?;
    if valid != u64::from(u32::MAX) || preferred != u64::from(u32::MAX) {
        return invalid("address lifetime is not permanent");
    }
    match optional_string(address, "protocol")? {
        Some("kernel_lo") if ifname == "lo" && family == ObservedIpFamilyV1::Ipv6 => {}
        None if ifname != "lo" || family == ObservedIpFamilyV1::Ipv4 => {}
        _ => return invalid("address protocol differs from the fresh-namespace baseline"),
    }
    Ok(())
}

pub(crate) fn decode_routes(
    bytes: &[u8],
    family: ObservedIpFamilyV1,
    interface_indices: &BTreeMap<&str, u32>,
) -> Result<Vec<ObservedRouteV1>, NetworkKernelReaderError> {
    decode_array(bytes)?
        .iter()
        .map(|value| decode_route(value, family, interface_indices))
        .collect()
}

fn decode_route(
    value: &Value,
    family: ObservedIpFamilyV1,
    interface_indices: &BTreeMap<&str, u32>,
) -> Result<ObservedRouteV1, NetworkKernelReaderError> {
    let object = as_object(value)?;
    reject_unknown_fields(object, ROUTE_FIELDS, "route has an unknown field")?;
    let route_type = match optional_string(object, "type")?.unwrap_or("unicast") {
        "unicast" => ObservedRouteTypeV1::Unicast,
        "local" => ObservedRouteTypeV1::Local,
        "broadcast" if family == ObservedIpFamilyV1::Ipv4 => ObservedRouteTypeV1::Broadcast,
        "multicast" if family == ObservedIpFamilyV1::Ipv6 => ObservedRouteTypeV1::Multicast,
        _ => return invalid("route type is unsupported"),
    };
    let destination = parse_prefix(required_string(object, "dst")?, family)?;
    let gateway = optional_string(object, "gateway")?
        .map(|value| parse_address(value, family))
        .transpose()?;
    let preferred_source = optional_string(object, "prefsrc")?
        .map(|value| parse_address(value, family))
        .transpose()?;
    let dev = required_string(object, "dev")?;
    let ifindex =
        interface_indices
            .get(dev)
            .copied()
            .ok_or(NetworkKernelReaderError::InvalidRtnetlink(
                "route refers to an unknown link",
            ))?;
    let table = parse_table(optional_value(object, "table").unwrap_or(&Value::from("main")))?;
    let protocol = match required_string(object, "protocol")? {
        "kernel" => ObservedRouteProtocolV1::Kernel,
        "static" => ObservedRouteProtocolV1::Static,
        _ => return invalid("route protocol is unsupported"),
    };
    let scope = match optional_string(object, "scope")? {
        Some("host") => ObservedRouteScopeV1::Host,
        Some("link") => ObservedRouteScopeV1::Link,
        Some("global") | None if route_type == ObservedRouteTypeV1::Unicast => {
            ObservedRouteScopeV1::Universe
        }
        None if route_type == ObservedRouteTypeV1::Local => ObservedRouteScopeV1::Host,
        None if route_type == ObservedRouteTypeV1::Multicast => ObservedRouteScopeV1::Universe,
        _ => return invalid("route scope is unsupported or inconsistent"),
    };
    let metric = optional_u32(object, "metric")?.unwrap_or(0);
    if !required_array(object, "flags")?.is_empty() {
        return invalid("route flags are unsupported");
    }
    match (family, optional_string(object, "pref")?) {
        (ObservedIpFamilyV1::Ipv6, Some("medium")) | (ObservedIpFamilyV1::Ipv4, None) => {}
        _ => return invalid("route preference differs from its family baseline"),
    }
    let route = ObservedRouteV1 {
        namespace: ObservedNetworkNamespaceV1::Sandbox,
        ifindex,
        destination,
        gateway,
        preferred_source,
        table,
        route_type,
        scope,
        protocol,
        metric,
    };
    validate_route_shape(family, &route)?;
    Ok(route)
}

const ROUTE_FIELDS: &[&str] = &[
    "type", "dst", "gateway", "dev", "table", "protocol", "scope", "prefsrc", "metric", "flags",
    "pref",
];

fn validate_route_shape(
    family: ObservedIpFamilyV1,
    route: &ObservedRouteV1,
) -> Result<(), NetworkKernelReaderError> {
    let valid = match route.route_type {
        ObservedRouteTypeV1::Local => {
            route.table == 255
                && route.scope == ObservedRouteScopeV1::Host
                && route.protocol == ObservedRouteProtocolV1::Kernel
                && route.gateway.is_none()
                && (family == ObservedIpFamilyV1::Ipv6 || route.preferred_source.is_some())
                && route.metric == 0
        }
        ObservedRouteTypeV1::Broadcast => {
            family == ObservedIpFamilyV1::Ipv4
                && route.table == 255
                && route.scope == ObservedRouteScopeV1::Link
                && route.protocol == ObservedRouteProtocolV1::Kernel
                && route.gateway.is_none()
                && route.preferred_source.is_some()
                && route.metric == 0
        }
        ObservedRouteTypeV1::Multicast => {
            family == ObservedIpFamilyV1::Ipv6
                && route.table == 255
                && route.scope == ObservedRouteScopeV1::Universe
                && route.protocol == ObservedRouteProtocolV1::Kernel
                && route.gateway.is_none()
                && route.preferred_source.is_none()
                && route.metric == 256
        }
        ObservedRouteTypeV1::Unicast if route.protocol == ObservedRouteProtocolV1::Kernel => {
            let family_shape = match family {
                ObservedIpFamilyV1::Ipv4 => {
                    route.scope == ObservedRouteScopeV1::Link
                        && route.preferred_source.is_some()
                        && route.metric == 0
                }
                ObservedIpFamilyV1::Ipv6 => {
                    route.scope == ObservedRouteScopeV1::Universe
                        && route.preferred_source.is_none()
                        && route.metric == 256
                }
            };
            route.table == 254 && route.gateway.is_none() && family_shape
        }
        ObservedRouteTypeV1::Unicast => {
            let metric_matches = match family {
                ObservedIpFamilyV1::Ipv4 => route.metric == 0,
                ObservedIpFamilyV1::Ipv6 => route.metric == 1_024,
            };
            route.table == 254
                && route.scope == ObservedRouteScopeV1::Universe
                && route.gateway.is_some()
                && route.preferred_source.is_some()
                && metric_matches
        }
    };
    if !valid {
        return invalid("route shape is outside the admitted baseline");
    }
    Ok(())
}

pub(crate) fn decode_rules(
    bytes: &[u8],
    family: ObservedIpFamilyV1,
) -> Result<Vec<ObservedPolicyRuleV1>, NetworkKernelReaderError> {
    decode_array(bytes)?
        .iter()
        .map(|value| {
            let object = as_object(value)?;
            if object.len() != 3
                || required_string(object, "src")? != "all"
                || !object.contains_key("priority")
                || !object.contains_key("table")
            {
                return invalid("policy rule is not an unconditional table lookup");
            }
            Ok(ObservedPolicyRuleV1 {
                family,
                priority: required_u32(object, "priority")?,
                table: parse_table(required_value(object, "table")?)?,
            })
        })
        .collect()
}

fn parse_family(value: &str) -> Result<ObservedIpFamilyV1, NetworkKernelReaderError> {
    match value {
        "inet" => Ok(ObservedIpFamilyV1::Ipv4),
        "inet6" => Ok(ObservedIpFamilyV1::Ipv6),
        _ => invalid("address family is unsupported"),
    }
}

fn parse_address(
    value: &str,
    family: ObservedIpFamilyV1,
) -> Result<ObservedIpAddressV1, NetworkKernelReaderError> {
    match (value.parse::<IpAddr>(), family) {
        (Ok(IpAddr::V4(address)), ObservedIpFamilyV1::Ipv4) => {
            Ok(ObservedIpAddressV1::Ipv4(address.octets()))
        }
        (Ok(IpAddr::V6(address)), ObservedIpFamilyV1::Ipv6) => {
            Ok(ObservedIpAddressV1::Ipv6(address.octets()))
        }
        _ => invalid("IP address is malformed or belongs to the wrong family"),
    }
}

fn parse_prefix(
    value: &str,
    family: ObservedIpFamilyV1,
) -> Result<ObservedIpPrefixV1, NetworkKernelReaderError> {
    if value == "default" {
        return Ok(match family {
            ObservedIpFamilyV1::Ipv4 => ObservedIpPrefixV1 {
                address: ObservedIpAddressV1::Ipv4([0; 4]),
                prefix_length: 0,
            },
            ObservedIpFamilyV1::Ipv6 => ObservedIpPrefixV1 {
                address: ObservedIpAddressV1::Ipv6([0; 16]),
                prefix_length: 0,
            },
        });
    }

    let (address, prefix_length) = match value.split_once('/') {
        Some((address, prefix)) => (
            parse_address(address, family)?,
            prefix.parse::<u8>().map_err(|_| {
                NetworkKernelReaderError::InvalidRtnetlink("route prefix length is malformed")
            })?,
        ),
        None => {
            let address = parse_address(value, family)?;
            let prefix = match family {
                ObservedIpFamilyV1::Ipv4 => 32,
                ObservedIpFamilyV1::Ipv6 => 128,
            };
            (address, prefix)
        }
    };
    validate_prefix_length(address, prefix_length)?;
    if !prefix_is_canonical(address, prefix_length) {
        return invalid("route prefix has host bits set");
    }
    Ok(ObservedIpPrefixV1 {
        address,
        prefix_length,
    })
}

fn validate_prefix_length(
    address: ObservedIpAddressV1,
    prefix_length: u8,
) -> Result<(), NetworkKernelReaderError> {
    let maximum = match address {
        ObservedIpAddressV1::Ipv4(_) => 32,
        ObservedIpAddressV1::Ipv6(_) => 128,
    };
    if prefix_length > maximum {
        return invalid("IP prefix length exceeds its family width");
    }
    Ok(())
}

fn prefix_is_canonical(address: ObservedIpAddressV1, prefix_length: u8) -> bool {
    match address {
        ObservedIpAddressV1::Ipv4(octets) => {
            let host_bits = 32 - u32::from(prefix_length);
            let value = u32::from_be_bytes(octets);
            if host_bits == 32 {
                value == 0
            } else {
                value & ((1_u32 << host_bits) - 1) == 0
            }
        }
        ObservedIpAddressV1::Ipv6(octets) => {
            let host_bits = 128 - u32::from(prefix_length);
            let value = u128::from_be_bytes(octets);
            if host_bits == 128 {
                value == 0
            } else {
                value & ((1_u128 << host_bits) - 1) == 0
            }
        }
    }
}

fn parse_table(value: &Value) -> Result<u32, NetworkKernelReaderError> {
    match value {
        Value::String(name) => match name.as_str() {
            "local" => Ok(255),
            "main" => Ok(254),
            "default" => Ok(253),
            other => other.parse::<u32>().map_err(|_| {
                NetworkKernelReaderError::InvalidRtnetlink("route table is malformed")
            }),
        },
        Value::Number(number) => number
            .as_u64()
            .and_then(|number| u32::try_from(number).ok())
            .ok_or(NetworkKernelReaderError::InvalidRtnetlink(
                "route table is outside u32",
            )),
        _ => invalid("route table has an invalid JSON type"),
    }
}

fn parse_mac(value: &str) -> Result<[u8; 6], NetworkKernelReaderError> {
    let mut result = [0; 6];
    let mut parts = value.split(':');
    for octet in &mut result {
        let part = parts
            .next()
            .ok_or(NetworkKernelReaderError::InvalidRtnetlink(
                "link address is malformed",
            ))?;
        if part.len() != 2 {
            return invalid("link address is malformed");
        }
        *octet = u8::from_str_radix(part, 16)
            .map_err(|_| NetworkKernelReaderError::InvalidRtnetlink("link address is malformed"))?;
    }
    if parts.next().is_some() {
        return invalid("link address is malformed");
    }
    Ok(result)
}

fn decode_array(bytes: &[u8]) -> Result<Vec<Value>, NetworkKernelReaderError> {
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return invalid("ip JSON is empty or lacks its final newline");
    }
    let value: Value = serde_json::from_slice(bytes)?;
    value
        .as_array()
        .cloned()
        .ok_or(NetworkKernelReaderError::InvalidRtnetlink(
            "ip JSON top level is not an array",
        ))
}

fn reject_duplicates<T: Eq>(
    values: &[T],
    reason: &'static str,
) -> Result<(), NetworkKernelReaderError> {
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return invalid(reason);
    }
    Ok(())
}

fn as_object(value: &Value) -> Result<&Map<String, Value>, NetworkKernelReaderError> {
    value
        .as_object()
        .ok_or(NetworkKernelReaderError::InvalidRtnetlink(
            "ip JSON entry is not an object",
        ))
}

fn required_value<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Value, NetworkKernelReaderError> {
    object
        .get(key)
        .ok_or(NetworkKernelReaderError::InvalidRtnetlink(
            "ip JSON lacks a required field",
        ))
}

fn optional_value<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key)
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, NetworkKernelReaderError> {
    as_object(required_value(object, key)?)
}

fn required_array<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a [Value], NetworkKernelReaderError> {
    required_value(object, key)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or(NetworkKernelReaderError::InvalidRtnetlink(
            "ip JSON field is not an array",
        ))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, NetworkKernelReaderError> {
    required_value(object, key)?
        .as_str()
        .ok_or(NetworkKernelReaderError::InvalidRtnetlink(
            "ip JSON field is not text",
        ))
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, NetworkKernelReaderError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_str()
                .ok_or(NetworkKernelReaderError::InvalidRtnetlink(
                    "ip JSON field is not text",
                ))
        })
        .transpose()
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, NetworkKernelReaderError> {
    required_value(object, key)?
        .as_u64()
        .ok_or(NetworkKernelReaderError::InvalidRtnetlink(
            "ip JSON field is not an unsigned integer",
        ))
}

fn required_u32(object: &Map<String, Value>, key: &str) -> Result<u32, NetworkKernelReaderError> {
    u32::try_from(required_u64(object, key)?)
        .map_err(|_| NetworkKernelReaderError::InvalidRtnetlink("ip JSON integer exceeds u32"))
}

fn optional_u32(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<u32>, NetworkKernelReaderError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(NetworkKernelReaderError::InvalidRtnetlink(
                    "ip JSON field is not a u32",
                ))
        })
        .transpose()
}

fn required_u8(object: &Map<String, Value>, key: &str) -> Result<u8, NetworkKernelReaderError> {
    u8::try_from(required_u64(object, key)?)
        .map_err(|_| NetworkKernelReaderError::InvalidRtnetlink("ip JSON integer exceeds u8"))
}

fn invalid<T>(reason: &'static str) -> Result<T, NetworkKernelReaderError> {
    Err(NetworkKernelReaderError::InvalidRtnetlink(reason))
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    admitted: &[&str],
    reason: &'static str,
) -> Result<(), NetworkKernelReaderError> {
    if object.keys().any(|key| !admitted.contains(&key.as_str())) {
        return invalid(reason);
    }
    Ok(())
}

fn string_array_equals(values: &[Value], expected: &[&str]) -> bool {
    values.len() == expected.len()
        && values
            .iter()
            .zip(expected)
            .all(|(value, expected)| value.as_str() == Some(expected))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const MANAGED_LINKS: &[u8] =
        include_bytes!("../tests/fixtures/rtnetlink-managed-dual-stack/links.json");
    const MANAGED_ADDRESSES: &[u8] =
        include_bytes!("../tests/fixtures/rtnetlink-managed-dual-stack/addresses.json");
    const MANAGED_ROUTES_V4: &[u8] =
        include_bytes!("../tests/fixtures/rtnetlink-managed-dual-stack/routes-v4.json");
    const MANAGED_ROUTES_V6: &[u8] =
        include_bytes!("../tests/fixtures/rtnetlink-managed-dual-stack/routes-v6.json");
    const BASELINE_RULES_V4: &[u8] =
        include_bytes!("../tests/fixtures/rtnetlink-managed-dual-stack/rules-v4.json");
    const BASELINE_RULES_V6: &[u8] =
        include_bytes!("../tests/fixtures/rtnetlink-managed-dual-stack/rules-v6.json");

    #[test]
    fn actual_managed_dual_stack_fixture_decodes_completely() {
        let links = decode_links(MANAGED_LINKS).unwrap();
        let addresses = decode_addresses(
            MANAGED_ADDRESSES,
            &links,
            ObservedNetworkNamespaceV1::Sandbox,
        )
        .unwrap();
        let interface_indices = BTreeMap::from([("lo", 1), ("aog000000000001", 2)]);
        let routes_v4 = decode_routes(
            MANAGED_ROUTES_V4,
            ObservedIpFamilyV1::Ipv4,
            &interface_indices,
        )
        .unwrap();
        let routes_v6 = decode_routes(
            MANAGED_ROUTES_V6,
            ObservedIpFamilyV1::Ipv6,
            &interface_indices,
        )
        .unwrap();

        assert_eq!(links.len(), 2);
        assert_eq!(addresses.len(), 4);
        assert_eq!(routes_v4.len(), 6);
        assert_eq!(routes_v6.len(), 5);
        assert!(routes_v4.iter().any(|route| route.table == 255));
        assert!(routes_v6.iter().any(|route| {
            route.route_type == ObservedRouteTypeV1::Multicast && route.metric == 256
        }));
    }

    #[test]
    fn managed_veth_shape_binds_peer_and_disables_ipv6_autogeneration() {
        let link_json = br#"[{"ifindex":9,"link_index":17,"ifname":"aoh000000000001","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","operstate":"UP","linkmode":"DEFAULT","group":"default","link_type":"ether","address":"02:aa:bb:00:00:02","broadcast":"ff:ff:ff:ff:ff:ff","link_netnsid":0,"promiscuity":0,"allmulti":0,"min_mtu":68,"max_mtu":65535,"linkinfo":{"info_kind":"veth"},"inet6_addr_gen_mode":"none","num_tx_queues":1,"num_rx_queues":1,"gso_max_size":65536,"gso_max_segs":65535,"tso_max_size":524280,"tso_max_segs":65535,"gro_max_size":65536,"gso_ipv4_max_size":65536,"gro_ipv4_max_size":65536}]
"#;
        let address_json = br#"[{"ifindex":9,"link_index":17,"ifname":"aoh000000000001","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","operstate":"UP","group":"default","link_type":"ether","address":"02:aa:bb:00:00:02","broadcast":"ff:ff:ff:ff:ff:ff","link_netnsid":0,"addr_info":[{"family":"inet","local":"192.0.2.0","prefixlen":31,"scope":"global","label":"aoh000000000001","valid_life_time":4294967295,"preferred_life_time":4294967295}]}]
"#;

        let links = decode_links(link_json).unwrap();
        let addresses =
            decode_addresses(address_json, &links, ObservedNetworkNamespaceV1::Host).unwrap();

        assert_eq!(links[0].peer_ifindex, 17);
        assert_eq!(links[0].peer_namespace_id, Some(0));
        assert_eq!(
            links[0].ipv6_address_generation,
            ObservedIpv6AddressGenerationV1::None
        );
        assert_eq!(addresses.len(), 1);
    }

    #[test]
    fn automatic_veth_ipv6_generation_is_rejected() {
        let link_json = br#"[{"ifindex":9,"link_index":17,"ifname":"aoh000000000001","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","operstate":"UP","linkmode":"DEFAULT","group":"default","link_type":"ether","address":"02:aa:bb:00:00:02","broadcast":"ff:ff:ff:ff:ff:ff","link_netnsid":0,"promiscuity":0,"allmulti":0,"linkinfo":{"info_kind":"veth"},"inet6_addr_gen_mode":"eui64"}]
"#;

        assert!(decode_links(link_json).is_err());
    }

    #[test]
    fn unknown_negative_peer_namespace_id_is_rejected() {
        let link_json = br#"[{"ifindex":9,"link_index":17,"ifname":"aoh000000000001","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","operstate":"UP","linkmode":"DEFAULT","group":"default","link_type":"ether","address":"02:aa:bb:00:00:02","broadcast":"ff:ff:ff:ff:ff:ff","link_netnsid":-1,"promiscuity":0,"allmulti":0,"linkinfo":{"info_kind":"veth"},"inet6_addr_gen_mode":"none"}]
"#;

        assert!(decode_links(link_json).is_err());
    }

    #[test]
    fn baseline_policy_rules_decode_with_both_families() {
        let mut rules = decode_rules(BASELINE_RULES_V4, ObservedIpFamilyV1::Ipv4).unwrap();
        rules.extend(decode_rules(BASELINE_RULES_V6, ObservedIpFamilyV1::Ipv6).unwrap());
        rules.sort_unstable();

        assert_eq!(rules.len(), 5);
        assert_eq!(rules[0].table, 255);
        assert_eq!(rules[4].priority, 32_766);
    }

    #[test]
    fn truncated_json_and_missing_final_newline_are_rejected() {
        assert!(decode_links(&MANAGED_LINKS[..MANAGED_LINKS.len() - 2]).is_err());
        assert!(decode_links(&MANAGED_LINKS[..MANAGED_LINKS.len() - 1]).is_err());
    }

    #[test]
    fn behavioral_address_flags_are_not_silently_dropped() {
        let links = decode_links(MANAGED_LINKS).unwrap();
        let tentative = String::from_utf8(MANAGED_ADDRESSES.to_vec())
            .unwrap()
            .replace(
                "\"local\":\"2001:db8::1\"",
                "\"local\":\"2001:db8::1\",\"tentative\":true",
            );

        assert!(
            decode_addresses(
                tentative.as_bytes(),
                &links,
                ObservedNetworkNamespaceV1::Sandbox,
            )
            .is_err()
        );
    }

    #[test]
    fn source_specific_and_alternate_gateway_routes_are_rejected() {
        let interface_indices = BTreeMap::from([("lo", 1)]);
        for extra in [
            ",\"from\":\"192.0.2.0/24\"",
            ",\"via\":{\"family\":\"inet6\",\"host\":\"::1\"}",
            ",\"multipath\":[]",
        ] {
            let route = format!(
                "[{{\"dst\":\"192.0.2.0/24\",\"dev\":\"lo\",\"protocol\":\"kernel\",\"scope\":\"link\",\"prefsrc\":\"192.0.2.1\",\"flags\":[]{extra}}}]\n"
            );
            assert!(
                decode_routes(
                    route.as_bytes(),
                    ObservedIpFamilyV1::Ipv4,
                    &interface_indices,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn nonzero_default_prefixes_are_not_canonical() {
        assert!(!prefix_is_canonical(
            ObservedIpAddressV1::Ipv4([1, 0, 0, 0]),
            0,
        ));
        assert!(!prefix_is_canonical(
            ObservedIpAddressV1::Ipv6([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            0,
        ));
    }
}
