//! Bounds the actual nftables construction before the sole mutation recipe.
//!
//! The typed grammar below measures representation DATA without constructing
//! JSON, running a helper or accepting an arbitrary command. It includes the
//! complete prospective document even when the later four-MiB check refuses.

use super::*;
use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1;

/// Counts the heap-backed components of the closed JSON construction.
#[derive(Clone, Copy, Default)]
struct Layout {
    nodes: usize,
    entries: usize,
    arrays: usize,
    slots: usize,
    strings: usize,
    wire: usize,
}

impl Layout {
    fn scalar(wire: usize) -> Self {
        Self {
            nodes: 1,
            wire,
            ..Self::default()
        }
    }

    fn string(bytes: usize) -> Option<Self> {
        Some(Self {
            strings: bytes,
            ..Self::scalar(bytes.checked_mul(6)?.checked_add(2)?)
        })
    }

    fn text(value: &str) -> Option<Self> {
        Self::string(value.len())
    }

    fn add(&mut self, other: Self) -> Option<()> {
        self.nodes = self.nodes.checked_add(other.nodes)?;
        self.entries = self.entries.checked_add(other.entries)?;
        self.arrays = self.arrays.checked_add(other.arrays)?;
        self.slots = self.slots.checked_add(other.slots)?;
        self.strings = self.strings.checked_add(other.strings)?;
        self.wire = self.wire.checked_add(other.wire)?;
        Some(())
    }

    fn object<const N: usize>(fields: [(&str, Self); N]) -> Option<Self> {
        let mut layout = Self::scalar(2);
        layout.entries = N;
        for (index, (key, value)) in fields.into_iter().enumerate() {
            layout.strings = layout.strings.checked_add(key.len())?;
            layout.wire = layout
                .wire
                .checked_add(key.len().checked_mul(6)?.checked_add(3)?)?
                .checked_add(usize::from(index != 0))?;
            layout.add(value)?;
        }
        Some(layout)
    }

    fn array<const N: usize>(values: [Self; N]) -> Option<Self> {
        let mut layout = Self::empty_array();
        for value in values {
            layout.push(value)?;
        }
        Some(layout)
    }

    fn empty_array() -> Self {
        Self {
            arrays: 1,
            ..Self::scalar(2)
        }
    }

    fn push(&mut self, value: Self) -> Option<()> {
        self.wire = self.wire.checked_add(usize::from(self.slots != 0))?;
        self.slots = self.slots.checked_add(1)?;
        self.add(value)
    }

    fn backing_bytes(self) -> Option<usize> {
        // The pinned default serde_json Map is a standard BTreeMap. One node
        // per actual entry bounds both fresh insertion and to_value's clone;
        // the canonical supplier includes the full native node geometry.
        let maps = conservative_btree_node_bytes_v1::<String, Value>(self.entries)?;
        let vectors = self
            .slots
            .checked_add(self.arrays.checked_mul(4)?)?
            .checked_mul(2)?
            .checked_mul(std::mem::size_of::<Value>())?;
        let strings = self.strings.checked_mul(2)?;
        // json!(expression) calls to_value(&expression). A typed child tree,
        // its enclosing clone, and the command-list wrapper can coexist. The
        // three full trees also cover transient format/address/hex strings.
        let trees = maps
            .checked_add(vectors)?
            .checked_add(strings)?
            .checked_mul(3)?;
        // serde_json 1.0.150 to_vec starts at128 bytes. The old and replacement
        // allocations may coexist during Vec growth: three full ceilings also
        // cover the appended newline before the existing post-encode limit.
        let output = self.wire.checked_add(1)?.max(128).checked_mul(3)?;
        trees
            .checked_add(output)?
            .checked_add(4 * std::mem::size_of::<Value>())
    }
}

fn one(key: &str, value: Layout) -> Option<Layout> {
    Layout::object([(key, value)])
}

fn text(value: &str) -> Option<Layout> {
    Layout::text(value)
}

fn base_chain_layout(name: &str, hook: &str) -> Option<Layout> {
    one(
        "create",
        one(
            "chain",
            Layout::object([
                ("family", text(TABLE_FAMILY)?),
                ("table", text(TABLE_NAME)?),
                ("name", text(name)?),
                ("type", text("filter")?),
                ("hook", text(hook)?),
                ("prio", Layout::scalar(1)),
                ("policy", text("drop")?),
            ])?,
        )?,
    )
}

fn base_layout() -> Option<Layout> {
    let provenance = TABLE_PROVENANCE_PREFIX
        .len()
        .checked_add(43)?
        .checked_add(TABLE_POLICY_SEPARATOR.len())?
        .checked_add(43)?;
    one(
        "nftables",
        Layout::array([
            one(
                "create",
                one(
                    "table",
                    Layout::object([
                        ("family", text(TABLE_FAMILY)?),
                        ("name", text(TABLE_NAME)?),
                        ("comment", Layout::string(provenance)?),
                    ])?,
                )?,
            )?,
            base_chain_layout("ingress", "input")?,
            base_chain_layout("egress", "output")?,
        ])?,
    )
}

fn payload_match(protocol: &str, field: &str, op: &str, right: Layout) -> Option<Layout> {
    one(
        "match",
        Layout::object([
            ("op", text(op)?),
            (
                "left",
                one(
                    "payload",
                    Layout::object([("protocol", text(protocol)?), ("field", text(field)?)])?,
                )?,
            ),
            ("right", right),
        ])?,
    )
}

fn meta_match(key: &str, right: Layout) -> Option<Layout> {
    one(
        "match",
        Layout::object([
            ("op", text("==")?),
            ("left", one("meta", one("key", text(key)?)?)?),
            ("right", right),
        ])?,
    )
}

fn rule_layout(chain: &str, comment_bytes: usize, expressions: Layout) -> Option<Layout> {
    one(
        "add",
        one(
            "rule",
            Layout::object([
                ("family", text(TABLE_FAMILY)?),
                ("table", text(TABLE_NAME)?),
                ("chain", text(chain)?),
                ("comment", Layout::string(comment_bytes)?),
                ("expr", expressions),
            ])?,
        )?,
    )
}

fn anti_spoof_layout(
    interface_bytes: usize,
    addresses: usize,
    ipv6: bool,
    direction: NetworkFlowDirectionV1,
) -> Option<Layout> {
    let address = Layout::string(if ipv6 { 39 } else { 15 })?;
    let right = if addresses == 1 {
        address
    } else {
        let mut values = Layout::empty_array();
        for _ in 0..addresses {
            values.push(address)?;
        }
        one("set", values)?
    };
    let (chain, key, field) = match direction {
        NetworkFlowDirectionV1::Ingress => ("ingress", "iif", "daddr"),
        NetworkFlowDirectionV1::Egress => ("egress", "oif", "saddr"),
    };
    rule_layout(
        chain,
        ANTI_SPOOF_COMMENT.len(),
        Layout::array([
            meta_match(key, Layout::string(interface_bytes)?)?,
            payload_match(if ipv6 { "ip6" } else { "ip" }, field, "!=", right)?,
            one("drop", Layout::scalar(4))?,
        ])?,
    )
}

fn flow_layout(flow: NetworkFlowPolicyV1) -> Option<Layout> {
    let (chain, field) = match flow.direction() {
        NetworkFlowDirectionV1::Ingress => ("ingress", "saddr"),
        NetworkFlowDirectionV1::Egress => ("egress", "daddr"),
    };
    let (protocol, address_bytes) = match flow.remote_prefix() {
        NetworkIpPrefixV1::Ipv4 { .. } => ("ip", 15),
        NetworkIpPrefixV1::Ipv6 { .. } => ("ip6", 39),
    };
    let prefix = one(
        "prefix",
        Layout::object([
            ("addr", Layout::string(address_bytes)?),
            ("len", Layout::scalar(3)),
        ])?,
    )?;
    let transport = match flow.protocol() {
        NetworkTransportProtocolV1::Tcp | NetworkTransportProtocolV1::Udp => {
            let ports = flow.ports()?;
            let right = if ports.first() == ports.last() {
                Layout::scalar(5)
            } else {
                one(
                    "range",
                    Layout::array([Layout::scalar(5), Layout::scalar(5)])?,
                )?
            };
            payload_match(
                if flow.protocol() == NetworkTransportProtocolV1::Tcp {
                    "tcp"
                } else {
                    "udp"
                },
                "dport",
                "==",
                right,
            )?
        }
        NetworkTransportProtocolV1::IcmpV4 | NetworkTransportProtocolV1::IcmpV6 => {
            meta_match("l4proto", Layout::scalar(2))?
        }
    };
    // NetworkEndpointId is the actual sixteen-byte identifier encoded as hex.
    rule_layout(
        chain,
        FLOW_COMMENT_PREFIX.len().checked_add(16 * 2)?,
        Layout::array([
            payload_match(protocol, field, "==", prefix)?,
            transport,
            one("accept", Layout::scalar(4))?,
        ])?,
    )
}

fn rules_layout(expectation: &NetworkKernelExpectationV1) -> Option<Layout> {
    let mut commands = Layout::empty_array();
    if let Some(veth) = expectation.veth() {
        for ipv6 in [false, true] {
            let count = expectation
                .address_pairs()
                .iter()
                .filter(|pair| matches!(pair.sandbox, ObservedIpAddressV1::Ipv6(_)) == ipv6)
                .count();
            if count == 0 {
                continue;
            }
            for direction in [
                NetworkFlowDirectionV1::Ingress,
                NetworkFlowDirectionV1::Egress,
            ] {
                commands.push(anti_spoof_layout(
                    veth.sandbox_name.len(),
                    count,
                    ipv6,
                    direction,
                )?)?;
            }
        }
    }
    for endpoint in expectation.policy().endpoints() {
        for flow in endpoint.flows() {
            commands.push(flow_layout(*flow)?)?;
        }
    }
    one("nftables", commands)
}

/// Bounds the actual transient nft trees, serialization and address grouping.
///
/// Positive base input is destroyed before realization constructs its rules.
/// A failed base cannot reach rules, so their simultaneous peak is their max.
/// Neither this bound nor the later batch limit admits a Source or an effect.
pub(super) fn nft_construction_bytes_data_v2(
    expectation: &NetworkKernelExpectationV1,
) -> Option<usize> {
    let base = base_layout()?.backing_bytes()?;
    let rules = rules_layout(expectation)?.backing_bytes()?;
    let addresses = expectation
        .address_pairs()
        .len()
        .checked_mul(2)?
        .checked_add(8)?
        .checked_mul(std::mem::size_of::<ObservedIpAddressV1>())?;
    base.max(rules).checked_add(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actual(value: &Value) -> Layout {
        let mut result = Layout {
            nodes: 1,
            ..Layout::default()
        };
        match value {
            Value::String(text) => result.strings = text.len(),
            Value::Array(values) => {
                result.arrays = 1;
                result.slots = values.len();
                for value in values {
                    result.add(actual(value)).unwrap();
                }
            }
            Value::Object(values) => {
                result.entries = values.len();
                for (key, value) in values {
                    result.strings += key.len();
                    result.add(actual(value)).unwrap();
                }
            }
            _ => {}
        }
        result
    }

    fn assert_dominates(value: &Value, layout: Layout) {
        let observed = actual(value);
        assert_eq!(observed.nodes, layout.nodes);
        assert_eq!(observed.entries, layout.entries);
        assert_eq!(observed.arrays, layout.arrays);
        assert_eq!(observed.slots, layout.slots);
        assert!(observed.strings <= layout.strings);
        assert!(serde_json::to_vec(value).unwrap().len() <= layout.wire);
    }

    #[test]
    fn measured_grammar_covers_actual_base_and_typed_rules() {
        let expected = super::super::tests::expectation();
        let base: Value =
            serde_json::from_slice(&encode_nftables_base(&expected).unwrap()).unwrap();
        let rules: Value =
            serde_json::from_slice(&encode_nftables_rules(&expected).unwrap()).unwrap();

        assert_dominates(&base, base_layout().unwrap());
        assert_dominates(&rules, rules_layout(&expected).unwrap());
        assert!(nft_construction_bytes_data_v2(&expected).unwrap() > base.to_string().len());
    }

    #[test]
    fn multiple_address_set_and_both_directions_keep_literal_shape() {
        let addresses = [
            ObservedIpAddressV1::Ipv6([0xff; 16]),
            ObservedIpAddressV1::Ipv6([0x80; 16]),
        ];
        for direction in [
            NetworkFlowDirectionV1::Ingress,
            NetworkFlowDirectionV1::Egress,
        ] {
            let value = anti_spoof_rule(direction, "aog000000000009", &addresses);

            assert_dominates(&value, anti_spoof_layout(15, 2, true, direction).unwrap());
        }
        assert!(Layout::string(usize::MAX).is_none());
    }
}
