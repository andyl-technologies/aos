//! Fixed-nftables decoding for one exact sandbox policy table.
//!
//! The reader executes one immutable AOS `nft` binary in the current Network
//! namespace and requests handles plus JSON for only `inet aos_sandbox`. The
//! output contract admits exactly one table, the fixed ingress and egress base
//! chains, and rules emitted by the reviewed loader. Rule expressions are
//! decoded rather than trusted from their comments; comments carry only the
//! loader provenance and logical endpoint identity that netfilter does not
//! otherwise retain in a typed field.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::net::IpAddr;
use std::path::PathBuf;

use aos_sandbox_core::{NetworkEndpointId, ObjectDigest};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::{self, DeserializeSeed, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::kernel_observation::{
    ObservedFlowV1, ObservedInterfaceV1, ObservedIpAddressV1, ObservedLinkV1,
    ObservedNetworkNamespaceV1, ObservedNftAntiSpoofRuleV1, ObservedNftBaseChainV1,
    ObservedNftVerdictV1, ObservedNftablesPolicyV1,
};
use crate::kernel_reader::{NetworkKernelReaderError, PinnedArtifact, successful_helper_stdout};
use crate::policy::{
    NetworkFlowDirectionV1, NetworkIpPrefixV1, NetworkPortRangeV1, NetworkTransportProtocolV1,
};

const MAXIMUM_NFTABLES_OBSERVATION_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_NFTABLES_OBJECTS: usize = 16_899;
const MAXIMUM_JSON_NODES: usize = MAXIMUM_NFTABLES_OBJECTS * 64;
const MAXIMUM_JSON_CONTAINER_ENTRIES: usize = MAXIMUM_NFTABLES_OBJECTS;
const TABLE_FAMILY: &str = "inet";
const TABLE_NAME: &str = "aos_sandbox";
const TABLE_PROVENANCE_PREFIX: &str = "aos.net.v1:a=";
const TABLE_POLICY_SEPARATOR: &str = ":p=";
const ENCODED_DIGEST_BYTES: usize = 43;
const MAXIMUM_NFT_COMMENT_BYTES: usize = 128;
const ANTI_SPOOF_COMMENT: &str = "aos.sandbox.network.rule.v1 anti-spoof";
const FLOW_COMMENT_PREFIX: &str = "aos.sandbox.network.rule.v1 flow=";

struct StrictValue(Value);

struct StrictValueSeed<'a> {
    remaining_nodes: &'a Cell<usize>,
}

impl<'de> DeserializeSeed<'de> for StrictValueSeed<'_> {
    type Value = StrictValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let remaining = self.remaining_nodes.get();
        if remaining == 0 {
            return Err(D::Error::custom("JSON node count exceeds the closed bound"));
        }
        self.remaining_nodes.set(remaining - 1);

        deserializer.deserialize_any(StrictValueVisitor {
            remaining_nodes: self.remaining_nodes,
        })
    }
}

struct StrictValueVisitor<'a> {
    remaining_nodes: &'a Cell<usize>,
}

impl<'de> Visitor<'de> for StrictValueVisitor<'_> {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("floating-point JSON numbers are not admitted"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValueSeed {
            remaining_nodes: self.remaining_nodes,
        }
        .deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed {
            remaining_nodes: self.remaining_nodes,
        })? {
            if values.len() == MAXIMUM_JSON_CONTAINER_ENTRIES {
                return Err(A::Error::custom(
                    "JSON array length exceeds the closed bound",
                ));
            }
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        let mut values = Map::new();
        while let Some(key) = entries.next_key::<String>()? {
            if values.len() == MAXIMUM_JSON_CONTAINER_ENTRIES {
                return Err(A::Error::custom(
                    "JSON object size exceeds the closed bound",
                ));
            }
            if !keys.insert(key.clone()) {
                return Err(<A::Error as de::Error>::custom("duplicate JSON object key"));
            }
            let value = entries.next_value_seed(StrictValueSeed {
                remaining_nodes: self.remaining_nodes,
            })?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

/// Executes a retained immutable `nft` binary and measures its fixed loader.
#[derive(Debug)]
pub struct FixedNftablesObservationReader {
    nft: PinnedArtifact,
    enforcement_loader: PinnedArtifact,
}

impl FixedNftablesObservationReader {
    /// Resolves and retains immutable AOS `nft` and enforcement executables.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkKernelReaderError`] unless both paths are protected,
    /// root-owned, non-writable executable files beneath `/nix/store`.
    pub fn new(
        nft: PathBuf,
        enforcement_loader: PathBuf,
    ) -> Result<Self, NetworkKernelReaderError> {
        Ok(Self {
            nft: PinnedArtifact::open(nft, true)?,
            enforcement_loader: PinnedArtifact::open(enforcement_loader, true)?,
        })
    }

    /// Reads the complete fixed nftables policy in the current namespace.
    ///
    /// The caller must enter the catalog-authorized sandbox Network namespace
    /// before invoking this method and supply the immediately preceding
    /// rtnetlink link inventory. The inventory resolves nft's interface-name
    /// rendering back to the kernel ifindex. No caller-provided family, table,
    /// chain, rule, handle, expression, or command reaches `nft`.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkKernelReaderError`] if either retained artifact
    /// changes, the fixed process fails or exceeds its bounds, or the table is
    /// absent, incomplete, contains an extra object, or violates the closed
    /// expression and provenance schema.
    pub fn observe(
        &self,
        sandbox_links: &[ObservedLinkV1],
    ) -> Result<ObservedNftablesPolicyV1, NetworkKernelReaderError> {
        self.enforcement_loader.validate_current()?;
        let arguments = [
            "--json",
            "--handle",
            "--numeric",
            "--numeric-priority",
            "list",
            "table",
            TABLE_FAMILY,
            TABLE_NAME,
        ]
        .map(OsString::from);
        let output = self
            .nft
            .run(&arguments, MAXIMUM_NFTABLES_OBSERVATION_BYTES)?;
        let stdout = successful_helper_stdout(output)?;
        self.enforcement_loader.validate_current()?;

        decode_nftables_observation(&stdout, self.enforcement_loader.digest(), sandbox_links)
    }
}

/// Decodes one complete, newline-terminated fixed nftables JSON listing.
///
/// `installed_artifact_digest` is measured independently from the retained
/// enforcement-loader descriptor and is never taken from the JSON record.
/// `sandbox_links` must be the rtnetlink inventory read immediately before the
/// nftables listing in the same retained Network namespace.
///
/// # Errors
///
/// Returns [`NetworkKernelReaderError`] for a zero measured digest, malformed
/// JSON, unknown or duplicate objects and fields, noncanonical provenance, or
/// any rule outside the fixed expression grammar.
pub fn decode_nftables_observation(
    bytes: &[u8],
    installed_artifact_digest: ObjectDigest,
    sandbox_links: &[ObservedLinkV1],
) -> Result<ObservedNftablesPolicyV1, NetworkKernelReaderError> {
    if installed_artifact_digest.as_bytes() == &[0; 32] {
        return invalid("installed enforcement artifact digest is zero");
    }
    if bytes.is_empty()
        || bytes.len() > MAXIMUM_NFTABLES_OBSERVATION_BYTES
        || !bytes.ends_with(b"\n")
    {
        return invalid("nft JSON is empty, oversized, or lacks its final newline");
    }

    let document = decode_strict_json(bytes, MAXIMUM_JSON_NODES)?;
    let top = object(&document, "nft JSON top level is not an object")?;
    reject_unknown_fields(
        top,
        &["nftables"],
        "nft JSON has an unknown top-level field",
    )?;
    let elements = array(
        required(top, "nftables", "nft JSON omits its object array")?,
        "nftables is not an array",
    )?;
    if elements.len() < 4 || elements.len() > MAXIMUM_NFTABLES_OBJECTS {
        return invalid("nftables object count is outside the closed bound");
    }

    let interface_resolver = InterfaceResolver::new(sandbox_links)?;

    decode_metainfo(&elements[0])?;
    let (loader_artifact_digest, loader_policy_digest) = decode_table(&elements[1])?;
    let mut chains = BTreeMap::new();
    let mut chain_handles = BTreeSet::new();
    let mut rule_handles = BTreeMap::<NetworkFlowDirectionV1, BTreeSet<u64>>::new();
    let mut next_positions = BTreeMap::<NetworkFlowDirectionV1, u32>::new();
    let mut anti_spoof_rules = Vec::new();
    let mut flows = Vec::new();

    for element in &elements[2..] {
        let wrapper = object(element, "nftables entry is not an object")?;
        if wrapper.len() != 1 {
            return invalid("nftables entry does not name exactly one object");
        }
        if let Some(chain) = wrapper.get("chain") {
            let chain = decode_chain(chain)?;
            if !chain_handles.insert(chain.0)
                || chains.insert(chain.1.name.clone(), chain.1).is_some()
            {
                return invalid("nftables base chain is duplicated");
            }
            continue;
        }
        let rule = wrapper
            .get("rule")
            .ok_or(NetworkKernelReaderError::InvalidNftables(
                "nftables listing contains an unsupported object",
            ))?;
        let decoded = decode_rule(
            rule,
            &interface_resolver,
            &mut rule_handles,
            &mut next_positions,
        )?;
        match decoded {
            DecodedRule::AntiSpoof(rule) => anti_spoof_rules.push(rule),
            DecodedRule::Flow(rule) => flows.push(rule),
        }
    }

    let ingress = chains
        .remove("ingress")
        .ok_or(NetworkKernelReaderError::InvalidNftables(
            "ingress base chain is absent",
        ))?;
    let egress = chains
        .remove("egress")
        .ok_or(NetworkKernelReaderError::InvalidNftables(
            "egress base chain is absent",
        ))?;
    if !chains.is_empty() {
        return invalid("nftables listing contains an extra chain");
    }

    anti_spoof_rules.sort_unstable_by(|left, right| {
        left.local_addresses
            .cmp(&right.local_addresses)
            .then(left.direction.cmp(&right.direction))
    });
    flows.sort_unstable_by_key(|rule| {
        (
            rule.endpoint_id,
            rule.direction,
            rule.protocol,
            rule.remote_prefix,
            rule.ports,
        )
    });

    Ok(ObservedNftablesPolicyV1 {
        family: TABLE_FAMILY.to_owned(),
        table: TABLE_NAME.to_owned(),
        default_drop: ingress.policy_drop && egress.policy_drop,
        installed_artifact_digest,
        loader_artifact_digest,
        loader_policy_digest,
        base_chains: vec![ingress, egress],
        anti_spoof_rules,
        flows,
    })
}

fn decode_strict_json(bytes: &[u8], maximum_nodes: usize) -> Result<Value, serde_json::Error> {
    let remaining_nodes = Cell::new(maximum_nodes);
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let document = StrictValueSeed {
        remaining_nodes: &remaining_nodes,
    }
    .deserialize(&mut deserializer)?
    .0;
    deserializer.end()?;

    Ok(document)
}

fn decode_metainfo(value: &Value) -> Result<(), NetworkKernelReaderError> {
    let wrapper = object(value, "nft metainfo wrapper is not an object")?;
    reject_unknown_fields(wrapper, &["metainfo"], "first nft object is not metainfo")?;
    let metainfo = object(
        required(wrapper, "metainfo", "first nft object is not metainfo")?,
        "nft metainfo is not an object",
    )?;
    reject_unknown_fields(
        metainfo,
        &["version", "release_name", "json_schema_version"],
        "nft metainfo has an unknown field",
    )?;
    bounded_printable_text(metainfo, "version")?;
    bounded_printable_text(metainfo, "release_name")?;
    if unsigned(metainfo, "json_schema_version")? != 1 {
        return invalid("nft JSON schema version is unsupported");
    }
    Ok(())
}

fn decode_table(value: &Value) -> Result<(ObjectDigest, ObjectDigest), NetworkKernelReaderError> {
    let wrapper = object(value, "nft table wrapper is not an object")?;
    reject_unknown_fields(wrapper, &["table"], "second nft object is not the table")?;
    let table = object(
        required(wrapper, "table", "second nft object is not the table")?,
        "nft table is not an object",
    )?;
    reject_unknown_fields(
        table,
        &["family", "name", "handle", "comment"],
        "nft table has an unknown field",
    )?;
    require_table_identity(table, "name")?;
    if unsigned(table, "handle")? == 0 {
        return invalid("nft table handle is zero");
    }
    let comment = text(table, "comment")?;
    decode_table_provenance(comment)
}

fn decode_table_provenance(
    comment: &str,
) -> Result<(ObjectDigest, ObjectDigest), NetworkKernelReaderError> {
    if comment.len() > MAXIMUM_NFT_COMMENT_BYTES {
        return invalid("nft table provenance exceeds the kernel comment bound");
    }
    let provenance = comment.strip_prefix(TABLE_PROVENANCE_PREFIX).ok_or(
        NetworkKernelReaderError::InvalidNftables("nft table provenance is malformed"),
    )?;
    let (artifact, policy) = provenance.split_once(TABLE_POLICY_SEPARATOR).ok_or(
        NetworkKernelReaderError::InvalidNftables("nft table provenance is malformed"),
    )?;
    Ok((
        decode_provenance_digest(artifact)?,
        decode_provenance_digest(policy)?,
    ))
}

fn decode_chain(value: &Value) -> Result<(u64, ObservedNftBaseChainV1), NetworkKernelReaderError> {
    let chain = object(value, "nft chain is not an object")?;
    reject_unknown_fields(
        chain,
        &[
            "family", "table", "name", "handle", "type", "hook", "prio", "policy",
        ],
        "nft chain has an unknown field",
    )?;
    require_table_identity(chain, "table")?;
    let handle = unsigned(chain, "handle")?;
    if handle == 0 {
        return invalid("nft chain handle is zero");
    }
    let name = text(chain, "name")?;
    let expected_hook = match name {
        "ingress" => "input",
        "egress" => "output",
        _ => return invalid("nft chain name is not fixed"),
    };
    let hook = text(chain, "hook")?;
    if hook != expected_hook
        || text(chain, "type")? != "filter"
        || signed(chain, "prio")? != 0
        || text(chain, "policy")? != "drop"
    {
        return invalid("nft base chain contract is invalid");
    }

    Ok((
        handle,
        ObservedNftBaseChainV1 {
            name: name.to_owned(),
            hook: hook.to_owned(),
            chain_type: "filter".to_owned(),
            priority: 0,
            policy_drop: true,
        },
    ))
}

enum DecodedRule {
    AntiSpoof(ObservedNftAntiSpoofRuleV1),
    Flow(ObservedFlowV1),
}

struct InterfaceResolver<'a> {
    indices_by_name: BTreeMap<&'a str, u32>,
    names_by_index: BTreeMap<u32, &'a str>,
}

impl<'a> InterfaceResolver<'a> {
    fn new(links: &'a [ObservedLinkV1]) -> Result<Self, NetworkKernelReaderError> {
        let mut indices_by_name = BTreeMap::new();
        let mut names_by_index = BTreeMap::new();

        for link in links {
            if link.ifindex == 0
                || indices_by_name
                    .insert(link.name.as_str(), link.ifindex)
                    .is_some()
                || names_by_index
                    .insert(link.ifindex, link.name.as_str())
                    .is_some()
            {
                return invalid("rtnetlink interface mapping is ambiguous");
            }
        }

        Ok(Self {
            indices_by_name,
            names_by_index,
        })
    }

    fn resolve(&self, value: &Value) -> Result<u32, NetworkKernelReaderError> {
        let selector = value
            .as_str()
            .ok_or(NetworkKernelReaderError::InvalidNftables(
                "anti-spoof interface selector is not a string",
            ))?;
        let named_index = self.indices_by_name.get(selector).copied();
        // Pinned nft emits a decimal string only when its ifindex-to-name
        // lookup fails, so either representation must resolve to this snapshot.
        let numeric_index =
            canonical_ifindex(selector).filter(|ifindex| self.names_by_index.contains_key(ifindex));

        match (named_index, numeric_index) {
            (Some(named), Some(numeric)) if named != numeric => {
                invalid("anti-spoof interface selector is ambiguous")
            }
            (Some(ifindex), _) | (None, Some(ifindex)) => Ok(ifindex),
            (None, None) => invalid("anti-spoof interface selector is unknown"),
        }
    }
}

fn canonical_ifindex(value: &str) -> Option<u32> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }

    value.parse::<u32>().ok().filter(|ifindex| *ifindex != 0)
}

fn decode_rule(
    value: &Value,
    interface_resolver: &InterfaceResolver<'_>,
    handles: &mut BTreeMap<NetworkFlowDirectionV1, BTreeSet<u64>>,
    positions: &mut BTreeMap<NetworkFlowDirectionV1, u32>,
) -> Result<DecodedRule, NetworkKernelReaderError> {
    let rule = object(value, "nft rule is not an object")?;
    reject_unknown_fields(
        rule,
        &["family", "table", "chain", "handle", "comment", "expr"],
        "nft rule has an unknown field",
    )?;
    require_table_identity(rule, "table")?;
    let direction = direction_for_chain(text(rule, "chain")?)?;
    let handle = unsigned(rule, "handle")?;
    if handle == 0 || !handles.entry(direction).or_default().insert(handle) {
        return invalid("nft rule handle is zero or duplicated in its chain");
    }
    let position = positions.entry(direction).or_default();
    let current_position = *position;
    *position = position
        .checked_add(1)
        .ok_or(NetworkKernelReaderError::InvalidNftables(
            "nft rule position overflowed",
        ))?;
    let expressions = array(
        required(rule, "expr", "nft rule omits expressions")?,
        "nft rule expressions are not an array",
    )?;
    let comment = text(rule, "comment")?;

    if comment == ANTI_SPOOF_COMMENT {
        decode_anti_spoof(expressions, direction, current_position, interface_resolver)
            .map(DecodedRule::AntiSpoof)
    } else if let Some(endpoint) = comment.strip_prefix(FLOW_COMMENT_PREFIX) {
        decode_flow(expressions, direction, current_position, endpoint).map(DecodedRule::Flow)
    } else {
        invalid("nft rule comment is outside the fixed loader grammar")
    }
}

fn decode_anti_spoof(
    expressions: &[Value],
    direction: NetworkFlowDirectionV1,
    position: u32,
    interface_resolver: &InterfaceResolver<'_>,
) -> Result<ObservedNftAntiSpoofRuleV1, NetworkKernelReaderError> {
    if expressions.len() != 3 {
        return invalid("anti-spoof rule does not have three fixed statements");
    }
    let (interface_left, interface_right, interface_op) = match_statement(&expressions[0])?;
    if interface_op != "==" {
        return invalid("anti-spoof interface match is not equality");
    }
    let expected_interface_key = match direction {
        NetworkFlowDirectionV1::Ingress => "iif",
        NetworkFlowDirectionV1::Egress => "oif",
    };
    decode_meta(interface_left, expected_interface_key)?;
    let ifindex = interface_resolver.resolve(interface_right)?;

    let (address_left, address_right, address_op) = match_statement(&expressions[1])?;
    if address_op != "!=" {
        return invalid("anti-spoof address match is not inverted");
    }
    let expected_address_field = match direction {
        NetworkFlowDirectionV1::Ingress => "daddr",
        NetworkFlowDirectionV1::Egress => "saddr",
    };
    let protocol = decode_payload(address_left, expected_address_field)?;
    let local_addresses = parse_address_set(address_right)?;
    for local_address in &local_addresses {
        require_address_protocol(*local_address, protocol)?;
    }
    decode_verdict(&expressions[2], "drop")?;

    Ok(ObservedNftAntiSpoofRuleV1 {
        direction,
        interface: ObservedInterfaceV1 {
            namespace: ObservedNetworkNamespaceV1::Sandbox,
            ifindex,
        },
        local_addresses,
        inverted_match: true,
        position,
        verdict: ObservedNftVerdictV1::Drop,
    })
}

fn decode_flow(
    expressions: &[Value],
    direction: NetworkFlowDirectionV1,
    position: u32,
    endpoint: &str,
) -> Result<ObservedFlowV1, NetworkKernelReaderError> {
    if expressions.len() != 3 {
        return invalid("endpoint flow does not have three fixed statements");
    }
    let endpoint_bytes = decode_hex::<16>(endpoint)?;
    if endpoint_bytes == [0; 16] {
        return invalid("endpoint flow has a zero endpoint ID");
    }
    let (remote_left, remote_right, remote_op) = match_statement(&expressions[0])?;
    if remote_op != "==" {
        return invalid("endpoint remote-prefix match is not equality");
    }
    let expected_remote_field = match direction {
        NetworkFlowDirectionV1::Ingress => "saddr",
        NetworkFlowDirectionV1::Egress => "daddr",
    };
    let address_protocol = decode_payload(remote_left, expected_remote_field)?;
    let remote_prefix = parse_prefix_value(remote_right)?;
    require_prefix_protocol(remote_prefix, address_protocol)?;

    let (protocol, ports) = decode_transport_statement(&expressions[1])?;
    require_transport_family(protocol, remote_prefix)?;
    decode_verdict(&expressions[2], "accept")?;

    Ok(ObservedFlowV1 {
        endpoint_id: NetworkEndpointId::from_bytes(endpoint_bytes),
        direction,
        protocol,
        remote_prefix,
        ports,
        position,
        verdict: ObservedNftVerdictV1::Accept,
    })
}

fn decode_transport_statement(
    value: &Value,
) -> Result<(NetworkTransportProtocolV1, Option<NetworkPortRangeV1>), NetworkKernelReaderError> {
    let (left, right, operation) = match_statement(value)?;
    if operation != "==" {
        return invalid("endpoint transport match is not equality");
    }
    if let Ok(protocol) = decode_payload(left, "dport") {
        let protocol = match protocol {
            "tcp" => NetworkTransportProtocolV1::Tcp,
            "udp" => NetworkTransportProtocolV1::Udp,
            _ => return invalid("destination-port payload is not TCP or UDP"),
        };
        return Ok((protocol, Some(parse_port_range(right)?)));
    }

    decode_meta(left, "l4proto")?;
    let protocol = match right.as_u64() {
        Some(1) => NetworkTransportProtocolV1::IcmpV4,
        Some(58) => NetworkTransportProtocolV1::IcmpV6,
        _ => return invalid("endpoint layer-4 protocol is unsupported"),
    };
    Ok((protocol, None))
}

fn match_statement(value: &Value) -> Result<(&Value, &Value, &str), NetworkKernelReaderError> {
    let wrapper = singleton(value, "match", "nft statement is not a fixed match")?;
    let expression = object(wrapper, "nft match is not an object")?;
    reject_unknown_fields(
        expression,
        &["op", "left", "right"],
        "nft match has an unknown field",
    )?;
    Ok((
        required(expression, "left", "nft match omits its left expression")?,
        required(expression, "right", "nft match omits its right expression")?,
        text(expression, "op")?,
    ))
}

fn decode_meta(value: &Value, expected_key: &str) -> Result<(), NetworkKernelReaderError> {
    let meta = object(
        singleton(value, "meta", "nft match does not use fixed meta data")?,
        "nft meta expression is not an object",
    )?;
    reject_unknown_fields(meta, &["key"], "nft meta expression has an unknown field")?;
    if text(meta, "key")? != expected_key {
        return invalid("nft meta expression has the wrong key");
    }
    Ok(())
}

fn decode_payload<'a>(
    value: &'a Value,
    expected_field: &str,
) -> Result<&'a str, NetworkKernelReaderError> {
    let payload = object(
        singleton(
            value,
            "payload",
            "nft match does not use a fixed payload expression",
        )?,
        "nft payload expression is not an object",
    )?;
    reject_unknown_fields(
        payload,
        &["protocol", "field"],
        "nft payload expression has an unknown field",
    )?;
    if text(payload, "field")? != expected_field {
        return invalid("nft payload expression has the wrong field");
    }
    let protocol = text(payload, "protocol")?;
    if !matches!(protocol, "ip" | "ip6" | "tcp" | "udp") {
        return invalid("nft payload expression has an unsupported protocol");
    }
    Ok(protocol)
}

fn decode_verdict(value: &Value, expected: &str) -> Result<(), NetworkKernelReaderError> {
    let null = singleton(value, expected, "nft rule has the wrong terminal verdict")?;
    if !null.is_null() {
        return invalid("nft terminal verdict payload is not null");
    }
    Ok(())
}

fn parse_address_value(value: &Value) -> Result<ObservedIpAddressV1, NetworkKernelReaderError> {
    let address = value
        .as_str()
        .ok_or(NetworkKernelReaderError::InvalidNftables(
            "nft IP address is not a string",
        ))?
        .parse::<IpAddr>()
        .map_err(|_| NetworkKernelReaderError::InvalidNftables("nft IP address is malformed"))?;
    Ok(match address {
        IpAddr::V4(address) => ObservedIpAddressV1::Ipv4(address.octets()),
        IpAddr::V6(address) => ObservedIpAddressV1::Ipv6(address.octets()),
    })
}

fn parse_address_set(value: &Value) -> Result<Vec<ObservedIpAddressV1>, NetworkKernelReaderError> {
    let addresses = if value.is_string() {
        vec![parse_address_value(value)?]
    } else {
        let values = array(
            singleton(value, "set", "nft local-address guard is not a fixed set")?,
            "nft local-address set is not an array",
        )?;
        values
            .iter()
            .map(parse_address_value)
            .collect::<Result<Vec<_>, _>>()?
    };
    if addresses.is_empty()
        || addresses.windows(2).any(|pair| pair[0] >= pair[1])
        || addresses
            .iter()
            .any(|address| !same_address_family(addresses[0], *address))
    {
        return invalid("nft local-address set is empty, mixed-family, or noncanonical");
    }
    Ok(addresses)
}

fn parse_prefix_value(value: &Value) -> Result<NetworkIpPrefixV1, NetworkKernelReaderError> {
    if value.is_string() {
        return match parse_address_value(value)? {
            ObservedIpAddressV1::Ipv4(network) => NetworkIpPrefixV1::ipv4(network, 32),
            ObservedIpAddressV1::Ipv6(network) => NetworkIpPrefixV1::ipv6(network, 128),
        }
        .map_err(|_| NetworkKernelReaderError::InvalidNftables("nft host prefix is invalid"));
    }

    let prefix = object(
        singleton(value, "prefix", "nft remote prefix is not canonical")?,
        "nft prefix expression is not an object",
    )?;
    reject_unknown_fields(prefix, &["addr", "len"], "nft prefix has an unknown field")?;
    let length = value_u8(
        required(prefix, "len", "nft prefix omits its length")?,
        "nft prefix length is outside u8",
    )?;
    match parse_address_value(required(prefix, "addr", "nft prefix omits its address")?)? {
        ObservedIpAddressV1::Ipv4(network) => NetworkIpPrefixV1::ipv4(network, length),
        ObservedIpAddressV1::Ipv6(network) => NetworkIpPrefixV1::ipv6(network, length),
    }
    .map_err(|_| NetworkKernelReaderError::InvalidNftables("nft prefix is noncanonical"))
}

fn parse_port_range(value: &Value) -> Result<NetworkPortRangeV1, NetworkKernelReaderError> {
    let (first, last) = if let Some(port) = value.as_u64() {
        let port = u16::try_from(port).map_err(|_| {
            NetworkKernelReaderError::InvalidNftables("nft destination port is outside u16")
        })?;
        (port, port)
    } else {
        let range = array(
            singleton(value, "range", "nft destination port is not a fixed range")?,
            "nft destination-port range is not an array",
        )?;
        if range.len() != 2 {
            return invalid("nft destination-port range does not have two bounds");
        }
        (
            value_u16(&range[0], "nft destination-port lower bound is outside u16")?,
            value_u16(&range[1], "nft destination-port upper bound is outside u16")?,
        )
    };
    NetworkPortRangeV1::new(first, last)
        .map_err(|_| NetworkKernelReaderError::InvalidNftables("nft port range is invalid"))
}

fn require_table_identity(
    object: &Map<String, Value>,
    table_name_field: &'static str,
) -> Result<(), NetworkKernelReaderError> {
    if text(object, "family")? != TABLE_FAMILY || text(object, table_name_field)? != TABLE_NAME {
        return invalid("nftables object is outside the fixed table");
    }
    Ok(())
}

fn require_address_protocol(
    address: ObservedIpAddressV1,
    protocol: &str,
) -> Result<(), NetworkKernelReaderError> {
    if matches!(
        (address, protocol),
        (ObservedIpAddressV1::Ipv4(_), "ip") | (ObservedIpAddressV1::Ipv6(_), "ip6")
    ) {
        Ok(())
    } else {
        invalid("nft payload protocol disagrees with its address family")
    }
}

const fn same_address_family(left: ObservedIpAddressV1, right: ObservedIpAddressV1) -> bool {
    matches!(
        (left, right),
        (ObservedIpAddressV1::Ipv4(_), ObservedIpAddressV1::Ipv4(_))
            | (ObservedIpAddressV1::Ipv6(_), ObservedIpAddressV1::Ipv6(_))
    )
}

fn require_prefix_protocol(
    prefix: NetworkIpPrefixV1,
    protocol: &str,
) -> Result<(), NetworkKernelReaderError> {
    if matches!(
        (prefix, protocol),
        (NetworkIpPrefixV1::Ipv4 { .. }, "ip") | (NetworkIpPrefixV1::Ipv6 { .. }, "ip6")
    ) {
        Ok(())
    } else {
        invalid("nft payload protocol disagrees with its prefix family")
    }
}

fn require_transport_family(
    protocol: NetworkTransportProtocolV1,
    prefix: NetworkIpPrefixV1,
) -> Result<(), NetworkKernelReaderError> {
    if matches!(
        (protocol, prefix),
        (
            NetworkTransportProtocolV1::Tcp | NetworkTransportProtocolV1::Udp,
            _
        ) | (
            NetworkTransportProtocolV1::IcmpV4,
            NetworkIpPrefixV1::Ipv4 { .. }
        ) | (
            NetworkTransportProtocolV1::IcmpV6,
            NetworkIpPrefixV1::Ipv6 { .. }
        )
    ) {
        Ok(())
    } else {
        invalid("nft transport protocol disagrees with the remote prefix family")
    }
}

fn direction_for_chain(chain: &str) -> Result<NetworkFlowDirectionV1, NetworkKernelReaderError> {
    match chain {
        "ingress" => Ok(NetworkFlowDirectionV1::Ingress),
        "egress" => Ok(NetworkFlowDirectionV1::Egress),
        _ => invalid("nft rule belongs to an unknown chain"),
    }
}

fn decode_provenance_digest(text: &str) -> Result<ObjectDigest, NetworkKernelReaderError> {
    if text.len() != ENCODED_DIGEST_BYTES {
        return invalid("nft provenance digest has the wrong encoded length");
    }
    let decoded = URL_SAFE_NO_PAD.decode(text).map_err(|_| {
        NetworkKernelReaderError::InvalidNftables("nft provenance digest is invalid")
    })?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
        NetworkKernelReaderError::InvalidNftables("nft provenance digest has the wrong byte length")
    })?;
    if URL_SAFE_NO_PAD.encode(bytes) != text {
        return invalid("nft provenance digest is not canonical base64url");
    }
    if bytes == [0; 32] {
        return invalid("nft provenance digest is zero");
    }
    Ok(ObjectDigest::from_bytes(bytes))
}

fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], NetworkKernelReaderError> {
    if text.len() != N * 2 {
        return invalid("nft hexadecimal field has the wrong length");
    }
    let mut output = [0; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(NetworkKernelReaderError::InvalidNftables(
            "nft hexadecimal field is not canonical lowercase",
        ))?;
        let low = hex_nibble(pair[1]).ok_or(NetworkKernelReaderError::InvalidNftables(
            "nft hexadecimal field is not canonical lowercase",
        ))?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn singleton<'a>(
    value: &'a Value,
    key: &str,
    reason: &'static str,
) -> Result<&'a Value, NetworkKernelReaderError> {
    let object = object(value, reason)?;
    if object.len() != 1 {
        return invalid(reason);
    }
    object
        .get(key)
        .ok_or(NetworkKernelReaderError::InvalidNftables(reason))
}

fn object<'a>(
    value: &'a Value,
    reason: &'static str,
) -> Result<&'a Map<String, Value>, NetworkKernelReaderError> {
    value
        .as_object()
        .ok_or(NetworkKernelReaderError::InvalidNftables(reason))
}

fn array<'a>(
    value: &'a Value,
    reason: &'static str,
) -> Result<&'a [Value], NetworkKernelReaderError> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(NetworkKernelReaderError::InvalidNftables(reason))
}

fn required<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    reason: &'static str,
) -> Result<&'a Value, NetworkKernelReaderError> {
    object
        .get(key)
        .ok_or(NetworkKernelReaderError::InvalidNftables(reason))
}

fn text<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, NetworkKernelReaderError> {
    required(object, key, "nftables text field is absent")?
        .as_str()
        .ok_or(NetworkKernelReaderError::InvalidNftables(
            "nftables text field has an invalid type",
        ))
}

fn unsigned(object: &Map<String, Value>, key: &str) -> Result<u64, NetworkKernelReaderError> {
    required(object, key, "nftables unsigned field is absent")?
        .as_u64()
        .ok_or(NetworkKernelReaderError::InvalidNftables(
            "nftables unsigned field has an invalid type",
        ))
}

fn signed(object: &Map<String, Value>, key: &str) -> Result<i64, NetworkKernelReaderError> {
    required(object, key, "nftables signed field is absent")?
        .as_i64()
        .ok_or(NetworkKernelReaderError::InvalidNftables(
            "nftables signed field has an invalid type",
        ))
}

fn value_u16(value: &Value, reason: &'static str) -> Result<u16, NetworkKernelReaderError> {
    value
        .as_u64()
        .and_then(|number| u16::try_from(number).ok())
        .ok_or(NetworkKernelReaderError::InvalidNftables(reason))
}

fn value_u8(value: &Value, reason: &'static str) -> Result<u8, NetworkKernelReaderError> {
    value
        .as_u64()
        .and_then(|number| u8::try_from(number).ok())
        .ok_or(NetworkKernelReaderError::InvalidNftables(reason))
}

fn bounded_printable_text(
    object: &Map<String, Value>,
    key: &str,
) -> Result<(), NetworkKernelReaderError> {
    let value = text(object, key)?;
    if value.is_empty()
        || value.len() > 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        return invalid("nft metainfo text is outside the closed bound");
    }
    Ok(())
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

fn invalid<T>(reason: &'static str) -> Result<T, NetworkKernelReaderError> {
    Err(NetworkKernelReaderError::InvalidNftables(reason))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::kernel_observation::ObservedIpv6AddressGenerationV1;

    const PINNED_NFT_MANAGED_JSON: &[u8] =
        include_bytes!("../tests/data/nftables-1.1.1-managed.json");

    fn provenance_marker(artifact: [u8; 32], policy: [u8; 32]) -> String {
        format!(
            "{TABLE_PROVENANCE_PREFIX}{}{TABLE_POLICY_SEPARATOR}{}",
            URL_SAFE_NO_PAD.encode(artifact),
            URL_SAFE_NO_PAD.encode(policy),
        )
    }

    fn link(ifindex: u32, name: &str) -> ObservedLinkV1 {
        ObservedLinkV1 {
            ifindex,
            peer_ifindex: ifindex + 1,
            peer_namespace_id: Some(0),
            name: name.to_owned(),
            kind: "veth".to_owned(),
            mtu: 1500,
            mac: [2, 0, 0, 0, 0, ifindex as u8],
            up: true,
            ipv6_address_generation: ObservedIpv6AddressGenerationV1::None,
        }
    }

    fn decode_failure(document: &str) -> NetworkKernelReaderError {
        match decode_nftables_observation(
            document.as_bytes(),
            ObjectDigest::from_bytes([0x11; 32]),
            &[],
        ) {
            Err(error) => error,
            Ok(_) => panic!("the hostile nft JSON must be rejected"),
        }
    }

    #[test]
    fn rejects_duplicate_keys_at_every_relevant_depth() {
        let hostile_documents = [
            "{\"nftables\":[],\"nftables\":[]}\n",
            "{\"nftables\":[{\"table\":{\"family\":\"inet\",\"family\":\"inet\"}}]}\n",
            "{\"nftables\":[{\"rule\":{\"chain\":\"ingress\",\"chain\":\"egress\"}}]}\n",
            "{\"nftables\":[{\"rule\":{\"expr\":[{\"match\":{\"left\":1,\"left\":2}}]}}]}\n",
        ];

        for document in hostile_documents {
            let error = decode_failure(document);
            assert!(
                error.to_string().contains("duplicate JSON object key"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn rejects_noninteger_numbers_before_schema_decoding() {
        let error = decode_failure("{\"nftables\":[1.5]}\n");

        assert!(
            error
                .to_string()
                .contains("floating-point JSON numbers are not admitted"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_oversized_json_containers_during_deserialization() {
        let entries = std::iter::repeat_n("0", MAXIMUM_JSON_CONTAINER_ENTRIES + 1)
            .collect::<Vec<_>>()
            .join(",");
        let document = format!("[{entries}]\n");

        let error = decode_failure(&document);
        assert!(
            error
                .to_string()
                .contains("JSON array length exceeds the closed bound"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_excess_total_nodes_across_bounded_containers() {
        let error = match decode_strict_json(b"[[0,1],[2,3]]\n", 5) {
            Err(error) => error,
            Ok(_) => panic!("the aggregate JSON node budget must fail closed"),
        };

        assert!(
            error
                .to_string()
                .contains("JSON node count exceeds the closed bound"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn provenance_marker_fits_kernel_bound_and_round_trips_both_digests() {
        let artifact = [0x5a; 32];
        let policy = [0xc3; 32];
        let marker = provenance_marker(artifact, policy);

        assert_eq!(marker.len(), 102);
        assert!(marker.len() <= MAXIMUM_NFT_COMMENT_BYTES);
        let decoded = decode_table_provenance(&marker).unwrap();
        assert_eq!(
            decoded,
            (
                ObjectDigest::from_bytes(artifact),
                ObjectDigest::from_bytes(policy),
            )
        );
    }

    #[test]
    fn provenance_digest_rejects_padding_and_noncanonical_alphabet() {
        let encoded = URL_SAFE_NO_PAD.encode([0xfb; 32]);
        assert!(encoded.contains('-'));

        assert!(decode_provenance_digest(&format!("{encoded}=")).is_err());
        assert!(decode_provenance_digest(&encoded.replace('-', "+")).is_err());
    }

    #[test]
    fn provenance_digest_rejects_noncanonical_trailing_bits() {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        let mut encoded = URL_SAFE_NO_PAD.encode([0x37; 32]).into_bytes();
        let final_byte = encoded.last_mut().unwrap();
        let position = ALPHABET
            .iter()
            .position(|candidate| candidate == final_byte)
            .unwrap();
        assert_eq!(position % 4, 0);
        *final_byte = ALPHABET[position + 1];
        let noncanonical = String::from_utf8(encoded).unwrap();

        assert!(decode_provenance_digest(&noncanonical).is_err());
    }

    #[test]
    fn provenance_digest_rejects_short_and_long_values() {
        let short = URL_SAFE_NO_PAD.encode([0x11; 31]);
        let long = URL_SAFE_NO_PAD.encode([0x22; 33]);

        assert!(decode_provenance_digest(&short).is_err());
        assert!(decode_provenance_digest(&long).is_err());
    }

    #[test]
    fn provenance_marker_rejects_legacy_oversized_encoding() {
        let legacy = format!(
            "aos.sandbox.network.v1 artifact={} policy={}",
            "11".repeat(32),
            "22".repeat(32),
        );

        assert!(legacy.len() > MAXIMUM_NFT_COMMENT_BYTES);
        assert!(decode_table_provenance(&legacy).is_err());
    }

    #[test]
    fn decodes_pinned_nft_interface_names_against_rtnetlink_inventory() {
        let links = [link(5, "aog000000000001")];
        let observation = decode_nftables_observation(
            PINNED_NFT_MANAGED_JSON,
            ObjectDigest::from_bytes([0x11; 32]),
            &links,
        )
        .unwrap();

        assert_eq!(observation.anti_spoof_rules.len(), 4);
        assert!(
            observation
                .anti_spoof_rules
                .iter()
                .all(|rule| rule.interface.ifindex == 5)
        );
        assert_eq!(observation.flows.len(), 6);
    }

    #[test]
    fn rejects_wrong_missing_or_nonstring_table_identities() {
        let baseline: Value = serde_json::from_slice(PINNED_NFT_MANAGED_JSON).unwrap();
        let links = [link(5, "aog000000000001")];
        let mut baseline_encoding = serde_json::to_vec(&baseline).unwrap();
        baseline_encoding.push(b'\n');
        assert!(
            decode_nftables_observation(
                &baseline_encoding,
                ObjectDigest::from_bytes([0x11; 32]),
                &links,
            )
            .is_ok()
        );

        for (index, object_name, identity_field) in [
            (1, "table", "name"),
            (2, "chain", "table"),
            (4, "rule", "table"),
        ] {
            for (replacement, expected_error) in [
                (
                    Some(serde_json::json!("wrong_table")),
                    "outside the fixed table",
                ),
                (None, "text field is absent"),
                (Some(serde_json::json!(7)), "text field has an invalid type"),
            ] {
                let mut document = baseline.clone();
                let object = document
                    .get_mut("nftables")
                    .and_then(Value::as_array_mut)
                    .and_then(|objects| objects.get_mut(index))
                    .and_then(|wrapper| wrapper.get_mut(object_name))
                    .and_then(Value::as_object_mut)
                    .unwrap();
                match replacement {
                    Some(value) => {
                        object.insert(identity_field.to_owned(), value);
                    }
                    None => {
                        object.remove(identity_field);
                    }
                }
                let mut encoded = serde_json::to_vec(&document).unwrap();
                encoded.push(b'\n');

                let error = decode_nftables_observation(
                    &encoded,
                    ObjectDigest::from_bytes([0x11; 32]),
                    &links,
                )
                .unwrap_err();
                assert!(
                    error.to_string().contains(expected_error),
                    "{object_name}.{identity_field} mutation reached the wrong rejection: {error}"
                );
            }
        }
    }

    #[test]
    fn resolves_only_unambiguous_name_or_decimal_ifindex_strings() {
        let links = [link(5, "aog000000000001")];
        let resolver = InterfaceResolver::new(&links).unwrap();

        assert_eq!(
            resolver
                .resolve(&serde_json::json!("aog000000000001"))
                .unwrap(),
            5
        );
        assert_eq!(resolver.resolve(&serde_json::json!("5")).unwrap(), 5);
        for invalid in [
            serde_json::json!(5),
            serde_json::json!("05"),
            serde_json::json!("6"),
            serde_json::json!("renamed"),
        ] {
            assert!(resolver.resolve(&invalid).is_err());
        }
    }

    #[test]
    fn rejects_duplicate_and_ambiguous_rtnetlink_mappings() {
        assert!(InterfaceResolver::new(&[link(5, "sandbox0"), link(6, "sandbox0")]).is_err());
        assert!(InterfaceResolver::new(&[link(5, "sandbox0"), link(5, "sandbox1")]).is_err());

        let links = [link(5, "sandbox0"), link(7, "5")];
        let resolver = InterfaceResolver::new(&links).unwrap();
        assert!(resolver.resolve(&serde_json::json!("5")).is_err());
    }

    #[test]
    fn admits_only_numeric_icmp_protocols_from_numeric_nft_output() {
        for (number, expected) in [
            (1, NetworkTransportProtocolV1::IcmpV4),
            (58, NetworkTransportProtocolV1::IcmpV6),
        ] {
            let statement = serde_json::json!({
                "match": {
                    "op": "==",
                    "left": {"meta": {"key": "l4proto"}},
                    "right": number
                }
            });
            let Ok((protocol, ports)) = decode_transport_statement(&statement) else {
                panic!("numeric ICMP protocol {number} must be admitted");
            };

            assert_eq!(protocol, expected);
            assert_eq!(ports, None);
        }

        for right in [serde_json::json!("icmp"), serde_json::json!(6)] {
            let statement = serde_json::json!({
                "match": {
                    "op": "==",
                    "left": {"meta": {"key": "l4proto"}},
                    "right": right
                }
            });

            assert!(decode_transport_statement(&statement).is_err());
        }
    }
}
