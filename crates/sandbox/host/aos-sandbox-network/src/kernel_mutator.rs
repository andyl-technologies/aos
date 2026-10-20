//! Typed, fail-closed realization of one prepared Network kernel plan.
//!
//! The mutator accepts only a non-clone authenticated mutation authorization.
//! It first creates the nftables table and both default-drop base chains in the
//! worker's already-custodied private namespace. A distinct fresh activation
//! token is then required before a veth can be created directly into the
//! retained host namespace, the plan's policy rules can be added, and the fixed
//! disarmed TCX lease gate can be installed. Both veth ends remain
//! administratively down.
//!
//! Fixed helpers are immutable Nix-store artifacts retained and remeasured by
//! descriptor. Every invocation uses a closed environment and exact typed
//! arguments; no shell, caller path, interface label, or command text crosses
//! this boundary.

mod effect_recipe;
mod source_helpers;
pub(crate) use source_helpers::{MutationProgrammeDataV2, mutation_programme_data_v2};
mod nft_receiving_v2;
mod helper_original;
mod opening_original;
pub(crate) use opening_original::NetworkMutatorOpeningOriginalV4;
pub(crate) use helper_original::{NetworkStatusHelperOriginalV4, NetworkStatusHelperRoleV4};
pub(crate) use source_helpers::{NetworkSourceHelperOriginalV2,
    NetworkSourceArtifactOriginalV2, NetworkPrepareEffectsOriginalV2,
    NetworkDestroyEffectsOriginalV2, destroy_helper_count_data_v2, destroy_artifact_count_data_v2,
    preparation_artifact_count_data_v2, preparation_helper_count_data_v2};

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Seek as _, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::path::PathBuf;
use std::time::Duration;

use aos_sandbox_model::ObjectDigest;
use aos_sandbox_model::model::NetworkKind;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, SingleThreadedProcess};
use aos_sandbox_linux::process::{
    FixedProcessDescriptorRequest, FixedProcessOutcome, FixedProcessRequest,
    run_fixed_process_with_descriptors,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use crate::kernel_observation::{
    NetworkKernelExpectationV1, ObservedIpAddressV1, ObservedIpPrefixV1,
};
use crate::kernel_reader::{NetworkKernelReaderError, PinnedArtifact, successful_helper_stdout};
use crate::namespace_pin::{NetworkNamespacePinMutationError, publish_namespace_pin};
use crate::policy::{
    NetworkFlowDirectionV1, NetworkFlowPolicyV1, NetworkIpPrefixV1, NetworkTransportProtocolV1,
};
use crate::{
    NetworkActivationAuthorizationV1, NetworkLifecycleAuthorizedStepV1,
    NetworkLifecycleExecutionStepV1, NetworkMutationAuthorizationV1,
};

const MAXIMUM_NFT_BATCH_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_LINK_INVENTORY_BYTES: usize = 64 * 1024;
const MAXIMUM_ARGUMENTS: usize = 32;
const MAXIMUM_ARGUMENT_BYTES: usize = 16 * 1024;
const HELPER_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_HELPER_OUTPUT_BYTES: usize = 16 * 1024;
const TABLE_FAMILY: &str = "inet";
const TABLE_NAME: &str = "aos_sandbox";
const TABLE_PROVENANCE_PREFIX: &str = "aos.net.v1:a=";
const TABLE_POLICY_SEPARATOR: &str = ":p=";
const ANTI_SPOOF_COMMENT: &str = "aos.sandbox.network.rule.v1 anti-spoof";
const FLOW_COMMENT_PREFIX: &str = "aos.sandbox.network.rule.v1 flow=";

/// Reports rejected artifacts, namespace substitution, or a failed kernel effect.
#[derive(Debug, thiserror::Error)]
pub enum NetworkKernelMutationError {
    /// A fixed immutable helper or object did not match the authorized plan.
    #[error("fixed Network mutator artifact was rejected")]
    Artifact,
    /// A namespace or single-thread transition was rejected by Linux.
    #[error("Network mutator namespace authority was rejected: {0}")]
    Linux(#[from] aos_sandbox_linux::Error),
    /// A retained fixed artifact could not be revalidated.
    #[error("Network mutator artifact validation failed: {0}")]
    Reader(#[from] NetworkKernelReaderError),
    /// A fixed helper failed, timed out, or could not be executed.
    #[error("fixed Network mutator process failed")]
    Helper,
    /// The plan cannot be represented by the fixed mutation profile.
    #[error("Network kernel plan is unsupported by the fixed mutator")]
    UnsupportedPlan,
    /// Atomic nftables input exceeded its closed bound or could not be encoded.
    #[error("Network nftables mutation batch is invalid")]
    Nftables,
    /// The canonical host-visible namespace pin could not be published.
    #[error(transparent)]
    NamespacePin(#[from] NetworkNamespacePinMutationError),
}

/// Retains all immutable production artifacts used for Network mutation.
#[derive(Debug)]
pub struct FixedNetworkKernelMutator {
    ip: PinnedArtifact,
    nft: PinnedArtifact,
    enforcement_artifact: PinnedArtifact,
    lease_gate_loader: PinnedArtifact,
    lease_gate_object: PinnedArtifact,
}

/// Proves the plan's table and both default-drop base chains were created.
#[derive(Debug, Eq, PartialEq)]
pub struct PreparedDefaultDropV1 {
    plan_digest: ObjectDigest,
    namespace: NamespaceIdentity,
}

impl FixedNetworkKernelMutator {
    /// Opens and retains the fixed mutation toolchain and policy artifacts.
    ///
    /// `enforcement_artifact` names the reviewed executable whose digest is
    /// recorded in nftables provenance. `lease_gate_loader` is the fixed
    /// libbpf installer; `lease_gate_object` is the exact object it installs.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkKernelMutationError`] unless every path names an
    /// immutable root-owned Nix-store artifact of the required file type.
    pub fn new(
        ip: PathBuf,
        nft: PathBuf,
        enforcement_artifact: PathBuf,
        lease_gate_loader: PathBuf,
        lease_gate_object: PathBuf,
    ) -> Result<Self, NetworkKernelMutationError> {
        opening_original::construct_local_v4(
            ip, nft, enforcement_artifact, lease_gate_loader, lease_gate_object,
        )
    }

    /// Creates the table and default-drop chains through the sole mutation recipe.
    ///
    /// # Errors
    /// Refuses the same namespace, artifact, plan and native helper failures.
    pub fn install_default_drop(&self, authorization: &NetworkMutationAuthorizationV1,
        target_namespace: &NamespaceFd) -> Result<PreparedDefaultDropV1, NetworkKernelMutationError>
    {
        effect_recipe::Recipe::local(self).install_default_drop(authorization, target_namespace)
    }

    /// Realizes the same authorized veth and disarmed gate programme.
    ///
    /// # Errors
    /// Retains the existing activation, namespace, artifact and helper refusals.
    pub fn realize_prepared(&self, prepared: PreparedDefaultDropV1,
        activation: &NetworkActivationAuthorizationV1<'_>, target_namespace: &NamespaceFd,
        host_namespace: &NamespaceFd, worker: &SingleThreadedProcess)
        -> Result<(), NetworkKernelMutationError>
    {
        effect_recipe::Recipe::local(self).realize_prepared(
            prepared, activation, target_namespace, host_namespace, worker)
    }

    /// Publishes the same realized namespace through its canonical pin.
    ///
    /// # Errors
    /// Refuses changed artifacts, namespace, existing pin or failed publication.
    pub fn publish_prepared_namespace(&self, authorization: &NetworkMutationAuthorizationV1,
        target_namespace: &NamespaceFd) -> Result<(), NetworkKernelMutationError>
    {
        effect_recipe::Recipe::local(self).publish_prepared_namespace(authorization, target_namespace)
    }

    /// Executes the same already-admitted existing-resource step.
    ///
    /// # Errors
    /// Refuses unsupported steps, substituted namespaces and failed native effects.
    pub fn execute_lifecycle_step(&self, authorization: &NetworkLifecycleAuthorizedStepV1<'_>,
        target_namespace: &NamespaceFd, host_namespace: &NamespaceFd,
        bootstrap_namespace: &NamespaceFd, worker: &SingleThreadedProcess)
        -> Result<(), NetworkKernelMutationError>
    {
        effect_recipe::Recipe::local(self).execute_lifecycle_step(
            authorization, target_namespace, host_namespace, bootstrap_namespace, worker)
    }

}

fn link_name_present_in_inventory(
    bytes: &[u8],
    expected_name: &str,
) -> Result<bool, NetworkKernelMutationError> {
    if !bytes.ends_with(b"\n") {
        return Err(NetworkKernelMutationError::Helper);
    }
    let inventory =
        serde_json::from_slice::<Value>(bytes).map_err(|_| NetworkKernelMutationError::Helper)?;
    let records = inventory
        .as_array()
        .ok_or(NetworkKernelMutationError::Helper)?;
    let mut names = BTreeSet::new();
    for record in records {
        let name = record
            .as_object()
            .and_then(|object| object.get("ifname"))
            .and_then(Value::as_str)
            .ok_or(NetworkKernelMutationError::Helper)?;
        if name.is_empty() || name.len() > 15 || name.as_bytes().contains(&0) || !names.insert(name)
        {
            return Err(NetworkKernelMutationError::Helper);
        }
    }
    Ok(names.contains(expected_name))
}

fn run_fixed_status(
    artifact: &PinnedArtifact,
    arguments: &[OsString],
    stdin: Option<BorrowedFd<'_>>,
    inherited: &[BorrowedFd<'_>],
) -> Result<(), NetworkKernelMutationError> {
    helper_original::run_status_local_v4(artifact, arguments, stdin, inherited)
}

fn encode_nftables_base(
    expectation: &NetworkKernelExpectationV1,
) -> Result<Vec<u8>, NetworkKernelMutationError> {
    let provenance = format!(
        "{TABLE_PROVENANCE_PREFIX}{}{TABLE_POLICY_SEPARATOR}{}",
        URL_SAFE_NO_PAD.encode(expectation.enforcement_artifact_digest().as_bytes()),
        URL_SAFE_NO_PAD.encode(expectation.policy().digest().as_bytes())
    );
    encode_nftables_commands(vec![
        json!({"create":{"table":{"family":TABLE_FAMILY,"name":TABLE_NAME,"comment":provenance}}}),
        base_chain("ingress", "input"),
        base_chain("egress", "output"),
    ])
}

fn encode_nftables_rules(
    expectation: &NetworkKernelExpectationV1,
) -> Result<Vec<u8>, NetworkKernelMutationError> {
    let mut commands = Vec::new();

    if let Some(veth) = expectation.veth() {
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        for pair in expectation.address_pairs() {
            match pair.sandbox {
                ObservedIpAddressV1::Ipv4(_) => ipv4.push(pair.sandbox),
                ObservedIpAddressV1::Ipv6(_) => ipv6.push(pair.sandbox),
            }
        }
        for addresses in [ipv4, ipv6]
            .into_iter()
            .filter(|addresses| !addresses.is_empty())
        {
            commands.push(anti_spoof_rule(
                NetworkFlowDirectionV1::Ingress,
                &veth.sandbox_name,
                &addresses,
            ));
            commands.push(anti_spoof_rule(
                NetworkFlowDirectionV1::Egress,
                &veth.sandbox_name,
                &addresses,
            ));
        }
    }
    for endpoint in expectation.policy().endpoints() {
        for flow in endpoint.flows() {
            commands.push(flow_rule(
                encode_hex(endpoint.endpoint_id().as_bytes()),
                *flow,
            )?);
        }
    }

    encode_nftables_commands(commands)
}

fn nftables_destroy_arguments() -> [OsString; 4] {
    // `destroy` is the idempotent form: it removes the exact table when
    // present and succeeds when a prior attempt already removed it.
    [
        "destroy".into(),
        "table".into(),
        TABLE_FAMILY.into(),
        TABLE_NAME.into(),
    ]
}

fn encode_nftables_commands(commands: Vec<Value>) -> Result<Vec<u8>, NetworkKernelMutationError> {
    let mut bytes = serde_json::to_vec(&json!({"nftables":commands}))
        .map_err(|_| NetworkKernelMutationError::Nftables)?;
    bytes.push(b'\n');
    if bytes.len() > MAXIMUM_NFT_BATCH_BYTES {
        return Err(NetworkKernelMutationError::Nftables);
    }
    Ok(bytes)
}

fn base_chain(name: &str, hook: &str) -> Value {
    json!({"create":{"chain":{
        "family":TABLE_FAMILY,"table":TABLE_NAME,"name":name,
        "type":"filter","hook":hook,"prio":0,"policy":"drop"
    }}})
}

fn anti_spoof_rule(
    direction: NetworkFlowDirectionV1,
    interface: &str,
    addresses: &[ObservedIpAddressV1],
) -> Value {
    let (chain, interface_key, address_field) = match direction {
        NetworkFlowDirectionV1::Ingress => ("ingress", "iif", "daddr"),
        NetworkFlowDirectionV1::Egress => ("egress", "oif", "saddr"),
    };
    let protocol = match addresses[0] {
        ObservedIpAddressV1::Ipv4(_) => "ip",
        ObservedIpAddressV1::Ipv6(_) => "ip6",
    };
    let values = addresses
        .iter()
        .copied()
        .map(format_address)
        .map(Value::String)
        .collect::<Vec<_>>();
    let address_value = match values.as_slice() {
        [one] => one.clone(),
        _ => json!({"set":values}),
    };
    json!({"add":{"rule":{
        "family":TABLE_FAMILY,"table":TABLE_NAME,"chain":chain,
        "comment":ANTI_SPOOF_COMMENT,
        "expr":[
            {"match":{"op":"==","left":{"meta":{"key":interface_key}},"right":interface}},
            {"match":{"op":"!=","left":{"payload":{"protocol":protocol,"field":address_field}},"right":address_value}},
            {"drop":null}
        ]
    }}})
}

fn flow_rule(
    endpoint: String,
    flow: NetworkFlowPolicyV1,
) -> Result<Value, NetworkKernelMutationError> {
    let (chain, address_field) = match flow.direction() {
        NetworkFlowDirectionV1::Ingress => ("ingress", "saddr"),
        NetworkFlowDirectionV1::Egress => ("egress", "daddr"),
    };
    let address_protocol = match flow.remote_prefix() {
        NetworkIpPrefixV1::Ipv4 { .. } => "ip",
        NetworkIpPrefixV1::Ipv6 { .. } => "ip6",
    };
    let transport = match flow.protocol() {
        NetworkTransportProtocolV1::Tcp => transport_match("tcp", flow)?,
        NetworkTransportProtocolV1::Udp => transport_match("udp", flow)?,
        NetworkTransportProtocolV1::IcmpV4 => {
            json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":1}})
        }
        NetworkTransportProtocolV1::IcmpV6 => {
            json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":58}})
        }
    };
    Ok(json!({"add":{"rule":{
        "family":TABLE_FAMILY,"table":TABLE_NAME,"chain":chain,
        "comment":format!("{FLOW_COMMENT_PREFIX}{endpoint}"),
        "expr":[
            {"match":{"op":"==","left":{"payload":{"protocol":address_protocol,"field":address_field}},"right":prefix_value(flow.remote_prefix())}},
            transport,
            {"accept":null}
        ]
    }}}))
}

fn transport_match(
    protocol: &str,
    flow: NetworkFlowPolicyV1,
) -> Result<Value, NetworkKernelMutationError> {
    let ports = flow
        .ports()
        .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
    let right = if ports.first() == ports.last() {
        json!(ports.first())
    } else {
        json!({"range":[ports.first(),ports.last()]})
    };
    Ok(json!({"match":{
        "op":"==",
        "left":{"payload":{"protocol":protocol,"field":"dport"}},
        "right":right
    }}))
}

fn prefix_value(prefix: NetworkIpPrefixV1) -> Value {
    match prefix {
        NetworkIpPrefixV1::Ipv4 {
            network,
            prefix_length,
        } => json!({"prefix":{"addr":Ipv4Addr::from(network).to_string(),"len":prefix_length}}),
        NetworkIpPrefixV1::Ipv6 {
            network,
            prefix_length,
        } => json!({"prefix":{"addr":Ipv6Addr::from(network).to_string(),"len":prefix_length}}),
    }
}

fn format_address(address: ObservedIpAddressV1) -> String {
    match address {
        ObservedIpAddressV1::Ipv4(octets) => Ipv4Addr::from(octets).to_string(),
        ObservedIpAddressV1::Ipv6(octets) => Ipv6Addr::from(octets).to_string(),
    }
}

const fn address_family_flag(address: ObservedIpAddressV1) -> &'static str {
    match address {
        ObservedIpAddressV1::Ipv4(_) => "-4",
        ObservedIpAddressV1::Ipv6(_) => "-6",
    }
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn inherited_fd_path(fd: i32) -> OsString {
    format!("/proc/self/fd/{fd}").into()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn linux_syscall(
    operation: &'static str,
) -> impl FnOnce(rustix::io::Errno) -> NetworkKernelMutationError {
    move |source| {
        NetworkKernelMutationError::Linux(aos_sandbox_linux::Error::Syscall {
            operation,
            source: std::io::Error::from_raw_os_error(source.raw_os_error()),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_model::{
        AssignmentEpoch, BrokerAssignment, DesiredGeneration, IncarnationId, NetworkEndpointId,
        SandboxId,
    };

    use super::*;
    use crate::kernel_observation::{ExpectedAddressPairV1, ExpectedVethV1};
    use crate::policy::{NetworkEndpointPolicyV1, NetworkPolicyProgramV1, NetworkPortRangeV1};

    pub(super) fn expectation() -> NetworkKernelExpectationV1 {
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes([0x11; 16]),
            IncarnationId::from_bytes([0x22; 16]),
            AssignmentEpoch::new(41),
            DesiredGeneration::new(7),
            ObjectDigest::from_bytes([0x33; 32]),
        )
        .unwrap();
        let flow = NetworkFlowPolicyV1::new(
            NetworkFlowDirectionV1::Ingress,
            NetworkTransportProtocolV1::Tcp,
            NetworkIpPrefixV1::ipv4([198, 51, 100, 0], 24).unwrap(),
            Some(NetworkPortRangeV1::new(443, 443).unwrap()),
        )
        .unwrap();
        let endpoint =
            NetworkEndpointPolicyV1::new(NetworkEndpointId::from_bytes([0x44; 16]), vec![flow])
                .unwrap();
        let policy = NetworkPolicyProgramV1::new(
            NetworkKind::Published,
            ObjectDigest::from_bytes([0x55; 32]),
            Some(ObjectDigest::from_bytes([0x66; 32])),
            vec![endpoint],
        )
        .unwrap();

        NetworkKernelExpectationV1::new(
            assignment,
            [0x77; 32],
            9,
            NetworkKind::Published,
            ObjectDigest::from_bytes([0x88; 32]),
            ObjectDigest::from_bytes([0x55; 32]),
            Some(ObjectDigest::from_bytes([0x66; 32])),
            Some(ExpectedVethV1 {
                mtu: 1_500,
                host_name: "aoh000000000009".to_owned(),
                sandbox_name: "aog000000000009".to_owned(),
                host_mac: [0x02, 0xaa, 0xbb, 0, 0, 1],
                sandbox_mac: [0x02, 0xaa, 0xbb, 0, 0, 2],
            }),
            vec![ExpectedAddressPairV1 {
                host: ObservedIpAddressV1::Ipv4([10, 80, 0, 0]),
                sandbox: ObservedIpAddressV1::Ipv4([10, 80, 0, 1]),
                prefix_length: 31,
            }],
            Vec::new(),
            policy,
        )
    }

    #[test]
    fn first_batch_exclusively_creates_only_default_drop_objects() {
        let document: Value =
            serde_json::from_slice(&encode_nftables_base(&expectation()).unwrap()).unwrap();
        let commands = document["nftables"].as_array().unwrap();

        assert_eq!(commands.len(), 3);
        assert!(
            commands
                .iter()
                .all(|command| command.get("create").is_some())
        );
        assert!(commands.iter().all(|command| command.get("add").is_none()));
        assert_eq!(
            commands[0]["create"]["table"]["name"],
            Value::String(TABLE_NAME.to_owned())
        );
        for command in &commands[1..] {
            assert_eq!(command["create"]["chain"]["policy"], "drop");
        }
    }

    #[test]
    fn second_batch_contains_only_plan_derived_rules() {
        let document: Value =
            serde_json::from_slice(&encode_nftables_rules(&expectation()).unwrap()).unwrap();
        let commands = document["nftables"].as_array().unwrap();

        assert_eq!(commands.len(), 3);
        assert!(commands.iter().all(|command| command.get("add").is_some()));
        assert!(
            commands
                .iter()
                .all(|command| command.get("create").is_none())
        );
        assert_eq!(commands[0]["add"]["rule"]["comment"], ANTI_SPOOF_COMMENT);
        assert_eq!(commands[1]["add"]["rule"]["comment"], ANTI_SPOOF_COMMENT);
        assert_eq!(
            commands[2]["add"]["rule"]["comment"],
            format!("{FLOW_COMMENT_PREFIX}{}", "44".repeat(16))
        );
    }

    #[test]
    fn destroy_command_is_an_exact_idempotent_table_removal() {
        assert_eq!(
            nftables_destroy_arguments(),
            ["destroy", "table", TABLE_FAMILY, TABLE_NAME].map(OsString::from)
        );
    }

    #[test]
    fn complete_link_inventory_proves_presence_or_absence_without_filtering() {
        let inventory = br#"[{"ifname":"lo"},{"ifname":"aoh000000000009"}]
"#;

        assert_eq!(
            link_name_present_in_inventory(inventory, "aoh000000000009").unwrap(),
            true
        );
        assert_eq!(
            link_name_present_in_inventory(inventory, "aoh000000000010").unwrap(),
            false
        );
        assert!(
            link_name_present_in_inventory(
                br#"[{"ifname":"lo"},{"ifname":"lo"}]
"#,
                "lo"
            )
            .is_err()
        );
        assert!(
            link_name_present_in_inventory(
                br#"[{"ifindex":1}]
"#,
                "lo"
            )
            .is_err()
        );
    }

    #[test]
    fn formatting_helpers_are_canonical_and_descriptor_only() {
        assert_eq!(
            format_address(ObservedIpAddressV1::Ipv4([192, 0, 2, 1])),
            "192.0.2.1"
        );
        assert_eq!(
            format_address(ObservedIpAddressV1::Ipv6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ])),
            "2001:db8::1"
        );
        assert_eq!(format_mac([2, 0xaa, 0xbb, 0, 1, 2]), "02:aa:bb:00:01:02");
        assert_eq!(inherited_fd_path(71), "/proc/self/fd/71");
    }
}
