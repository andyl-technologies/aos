//! Private fixed-width codec and semantic validation for kernel plans.

use super::*;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::Ipv4 => 4,
            Self::Ipv6 => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct KernelAddress {
    pub(super) family: AddressFamily,
    pub(super) octets: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct KernelPrefix {
    pub(super) address: KernelAddress,
    pub(super) prefix_length: u8,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct KernelAddressPair {
    pub(super) host: KernelAddress,
    pub(super) sandbox: KernelAddress,
    pub(super) prefix_length: u8,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct KernelRoute {
    pub(super) destination: KernelPrefix,
    pub(super) gateway: KernelAddress,
}

pub(super) struct EncodedVethFields {
    pub(super) present: bool,
    pub(super) mtu: u32,
    pub(super) host_name: [u8; 16],
    pub(super) sandbox_name: [u8; 16],
    pub(super) host_mac: [u8; 6],
    pub(super) sandbox_mac: [u8; 6],
}

pub(super) struct DecodedNamespace {
    pub(super) network_handle: [u8; 32],
    pub(super) allocation_generation: u64,
    pub(super) kind: NetworkKind,
    pub(super) profile_digest: ObjectDigest,
    pub(super) packet_program_digest: ObjectDigest,
    pub(super) enforcement_program_digest: ObjectDigest,
    pub(super) lease_gate_program_digest: Option<ObjectDigest>,
    pub(super) veth_present: bool,
    pub(super) mtu: u32,
    pub(super) host_name: [u8; 16],
    pub(super) sandbox_name: [u8; 16],
    pub(super) host_mac: [u8; 6],
    pub(super) sandbox_mac: [u8; 6],
    pub(super) address_pairs: Vec<KernelAddressPair>,
    pub(super) routes: Vec<KernelRoute>,
    pub(super) digest: ObjectDigest,
}

pub(super) fn validate_typed_cross_links(
    namespace: &NetworkNamespacePlanV1,
    policy: &NetworkPolicyProgramV1,
) -> Result<(), NetworkKernelPlanError> {
    if namespace.kind() != policy.kind()
        || namespace.packet_program_digest() != policy.digest()
        || namespace.enforcement_program_digest() != policy.enforcement_program_digest()
        || namespace.lease_gate_program_digest() != policy.lease_gate_program_digest()
    {
        return Err(NetworkKernelPlanError::Invalid(
            "namespace and packet policy disagree",
        ));
    }
    if namespace.address_pairs().len() > MAXIMUM_ADDRESS_PAIRS
        || namespace.routes().len() > MAXIMUM_ROUTES
        || policy.endpoints().len() > MAXIMUM_ENDPOINTS
        || policy
            .endpoints()
            .iter()
            .any(|endpoint| endpoint.flows().len() > MAXIMUM_FLOWS_PER_ENDPOINT)
    {
        return Err(NetworkKernelPlanError::Invalid(
            "typed plan exceeds a fixed count ceiling",
        ));
    }

    Ok(())
}

pub(super) fn encode_plan(
    assignment: BrokerAssignment,
    namespace: &NetworkNamespacePlanV1,
    policy: &NetworkPolicyProgramV1,
) -> Result<Vec<u8>, NetworkKernelPlanError> {
    let address_pairs = namespace
        .address_pairs()
        .iter()
        .copied()
        .map(kernel_address_pair)
        .collect::<Vec<_>>();
    let routes = namespace
        .routes()
        .iter()
        .copied()
        .map(kernel_route)
        .collect::<Vec<_>>();
    let veth = encode_veth_fields(namespace)?;
    let decoded = DecodedNamespace {
        network_handle: *namespace.network_handle(),
        allocation_generation: namespace.allocation_generation(),
        kind: namespace.kind(),
        profile_digest: namespace.profile_digest(),
        packet_program_digest: namespace.packet_program_digest(),
        enforcement_program_digest: namespace.enforcement_program_digest(),
        lease_gate_program_digest: namespace.lease_gate_program_digest(),
        veth_present: veth.present,
        mtu: veth.mtu,
        host_name: veth.host_name,
        sandbox_name: veth.sandbox_name,
        host_mac: veth.host_mac,
        sandbox_mac: veth.sandbox_mac,
        address_pairs,
        routes,
        digest: namespace.digest(),
    };
    encode_decoded_plan(
        NetworkKernelActionV1::Prepare,
        NetworkNamespacePublicationRequirementV1::RetainedDescriptorTarget,
        assignment,
        &decoded,
        policy,
    )
}

pub(super) fn encode_decoded_plan(
    action: NetworkKernelActionV1,
    publication: NetworkNamespacePublicationRequirementV1,
    assignment: BrokerAssignment,
    namespace: &DecodedNamespace,
    policy: &NetworkPolicyProgramV1,
) -> Result<Vec<u8>, NetworkKernelPlanError> {
    let tail_bytes = checked_tail_bytes(
        namespace.address_pairs.len(),
        namespace.routes.len(),
        policy.endpoints(),
    )?;
    let total_bytes = FIXED_BYTES
        .checked_add(tail_bytes)
        .filter(|length| *length <= MAXIMUM_PLAN_BYTES)
        .ok_or(NetworkKernelPlanError::TooLarge)?;
    let total_u32 = u32::try_from(total_bytes).map_err(|_| NetworkKernelPlanError::TooLarge)?;
    let address_count = u16::try_from(namespace.address_pairs.len())
        .map_err(|_| NetworkKernelPlanError::TooLarge)?;
    let route_count =
        u16::try_from(namespace.routes.len()).map_err(|_| NetworkKernelPlanError::TooLarge)?;
    let endpoint_count =
        u16::try_from(policy.endpoints().len()).map_err(|_| NetworkKernelPlanError::TooLarge)?;

    let mut bytes = Vec::with_capacity(total_bytes);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(action as u8);
    bytes.push(publication as u8);
    bytes.extend_from_slice(&total_u32.to_be_bytes());
    encode_assignment(&mut bytes, assignment);
    bytes.extend_from_slice(&namespace.network_handle);
    bytes.extend_from_slice(&namespace.allocation_generation.to_be_bytes());
    bytes.push(network_kind_code(namespace.kind));
    bytes.push(u8::from(namespace.veth_present));
    bytes.push(u8::from(namespace.lease_gate_program_digest.is_some()));
    bytes.push(0);
    bytes.extend_from_slice(&namespace.mtu.to_be_bytes());
    bytes.extend_from_slice(&namespace.host_name);
    bytes.extend_from_slice(&namespace.sandbox_name);
    bytes.extend_from_slice(&namespace.host_mac);
    bytes.extend_from_slice(&namespace.sandbox_mac);
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(namespace.profile_digest.as_bytes());
    bytes.extend_from_slice(namespace.packet_program_digest.as_bytes());
    bytes.extend_from_slice(namespace.enforcement_program_digest.as_bytes());
    match namespace.lease_gate_program_digest {
        Some(digest) => bytes.extend_from_slice(digest.as_bytes()),
        None => bytes.extend_from_slice(&[0; 32]),
    }
    bytes.extend_from_slice(namespace.digest.as_bytes());
    bytes.extend_from_slice(policy.digest().as_bytes());
    bytes.extend_from_slice(&address_count.to_be_bytes());
    bytes.extend_from_slice(&route_count.to_be_bytes());
    bytes.extend_from_slice(&endpoint_count.to_be_bytes());
    bytes.extend_from_slice(&[0; 2]);

    for pair in &namespace.address_pairs {
        encode_address_pair(&mut bytes, *pair);
    }
    for route in &namespace.routes {
        encode_route(&mut bytes, *route);
    }
    for endpoint in policy.endpoints() {
        encode_endpoint(&mut bytes, endpoint)?;
    }
    if bytes.len() != total_bytes {
        return Err(NetworkKernelPlanError::Invalid(
            "internal encoded length mismatch",
        ));
    }

    Ok(bytes)
}

pub(super) fn encode_assignment(bytes: &mut Vec<u8>, assignment: BrokerAssignment) {
    bytes.extend_from_slice(assignment.sandbox().as_bytes());
    bytes.extend_from_slice(assignment.incarnation().as_bytes());
    bytes.extend_from_slice(&assignment.epoch().get().to_be_bytes());
    bytes.extend_from_slice(&assignment.desired_generation().get().to_be_bytes());
    bytes.extend_from_slice(assignment.digest().as_bytes());
}

pub(super) fn decode_assignment(
    decoder: &mut Decoder<'_>,
) -> Result<BrokerAssignment, NetworkKernelPlanError> {
    let sandbox = SandboxId::from_bytes(decoder.take()?);
    let incarnation = IncarnationId::from_bytes(decoder.take()?);
    let epoch = AssignmentEpoch::new(decoder.u64()?);
    let desired_generation = DesiredGeneration::new(decoder.u64()?);
    let digest = decode_digest(decoder, "missing assignment digest")?;
    BrokerAssignment::new(sandbox, incarnation, epoch, desired_generation, digest)
        .map_err(|_| NetworkKernelPlanError::Invalid("invalid assignment"))
}

pub(super) fn encode_veth_fields(
    namespace: &NetworkNamespacePlanV1,
) -> Result<EncodedVethFields, NetworkKernelPlanError> {
    match (
        namespace.mtu(),
        namespace.host_interface_name(),
        namespace.sandbox_interface_name(),
        namespace.host_mac(),
        namespace.sandbox_mac(),
    ) {
        (Some(mtu), Some(host_name), Some(sandbox_name), Some(host_mac), Some(sandbox_mac)) => {
            Ok(EncodedVethFields {
                present: true,
                mtu,
                host_name: encode_interface_name(host_name.as_str())?,
                sandbox_name: encode_interface_name(sandbox_name.as_str())?,
                host_mac: host_mac.octets(),
                sandbox_mac: sandbox_mac.octets(),
            })
        }
        (None, None, None, None, None) => Ok(EncodedVethFields {
            present: false,
            mtu: 0,
            host_name: [0; 16],
            sandbox_name: [0; 16],
            host_mac: [0; 6],
            sandbox_mac: [0; 6],
        }),
        _ => Err(NetworkKernelPlanError::Invalid(
            "partial typed veth description",
        )),
    }
}

pub(super) fn encode_interface_name(name: &str) -> Result<[u8; 16], NetworkKernelPlanError> {
    let source = name.as_bytes();
    if source.is_empty() || source.len() >= 16 || !source.is_ascii() || source.contains(&0) {
        return Err(NetworkKernelPlanError::Invalid("invalid interface name"));
    }
    let mut encoded = [0; 16];
    encoded[..source.len()].copy_from_slice(source);
    Ok(encoded)
}

pub(super) fn checked_tail_bytes(
    address_pairs: usize,
    routes: usize,
    endpoints: &[NetworkEndpointPolicyV1],
) -> Result<usize, NetworkKernelPlanError> {
    validate_counts(address_pairs, routes, endpoints.len())?;
    let mut total = address_pairs
        .checked_mul(ADDRESS_PAIR_BYTES)
        .and_then(|value| value.checked_add(routes.checked_mul(ROUTE_BYTES)?))
        .ok_or(NetworkKernelPlanError::TooLarge)?;
    for endpoint in endpoints {
        if endpoint.flows().len() > MAXIMUM_FLOWS_PER_ENDPOINT {
            return Err(NetworkKernelPlanError::Invalid(
                "endpoint flow count exceeds its fixed ceiling",
            ));
        }
        total = total
            .checked_add(ENDPOINT_BYTES)
            .and_then(|value| value.checked_add(endpoint.flows().len().checked_mul(FLOW_BYTES)?))
            .ok_or(NetworkKernelPlanError::TooLarge)?;
    }
    Ok(total)
}

pub(super) fn validate_counts(
    address_pairs: usize,
    routes: usize,
    endpoints: usize,
) -> Result<(), NetworkKernelPlanError> {
    if address_pairs > MAXIMUM_ADDRESS_PAIRS
        || routes > MAXIMUM_ROUTES
        || endpoints > MAXIMUM_ENDPOINTS
    {
        return Err(NetworkKernelPlanError::Invalid(
            "count exceeds its fixed ceiling",
        ));
    }
    Ok(())
}

pub(super) fn validate_minimum_tail(
    remaining: usize,
    address_pairs: usize,
    routes: usize,
    endpoints: usize,
) -> Result<(), NetworkKernelPlanError> {
    let minimum = address_pairs
        .checked_mul(ADDRESS_PAIR_BYTES)
        .and_then(|value| value.checked_add(routes.checked_mul(ROUTE_BYTES)?))
        .and_then(|value| value.checked_add(endpoints.checked_mul(ENDPOINT_BYTES)?))
        .ok_or(NetworkKernelPlanError::TooLarge)?;
    if minimum > remaining {
        return Err(NetworkKernelPlanError::Truncated);
    }
    Ok(())
}

pub(super) fn kernel_address(address: NetworkIpAddressV1) -> KernelAddress {
    match address {
        NetworkIpAddressV1::Ipv4(address) => {
            let mut octets = [0; 16];
            octets[..4].copy_from_slice(&address);
            KernelAddress {
                family: AddressFamily::Ipv4,
                octets,
            }
        }
        NetworkIpAddressV1::Ipv6(address) => KernelAddress {
            family: AddressFamily::Ipv6,
            octets: address,
        },
    }
}

pub(super) fn kernel_prefix(prefix: NetworkIpPrefixV1) -> KernelPrefix {
    match prefix {
        NetworkIpPrefixV1::Ipv4 {
            network,
            prefix_length,
        } => KernelPrefix {
            address: kernel_address(NetworkIpAddressV1::Ipv4(network)),
            prefix_length,
        },
        NetworkIpPrefixV1::Ipv6 {
            network,
            prefix_length,
        } => KernelPrefix {
            address: kernel_address(NetworkIpAddressV1::Ipv6(network)),
            prefix_length,
        },
    }
}

pub(super) fn kernel_address_pair(
    pair: crate::allocation::NetworkAddressPairV1,
) -> KernelAddressPair {
    KernelAddressPair {
        host: kernel_address(pair.host()),
        sandbox: kernel_address(pair.sandbox()),
        prefix_length: pair.prefix_length(),
    }
}

pub(super) fn kernel_route(route: crate::allocation::NetworkRouteV1) -> KernelRoute {
    KernelRoute {
        destination: kernel_prefix(route.destination()),
        gateway: kernel_address(route.gateway()),
    }
}

pub(super) fn encode_address_pair(bytes: &mut Vec<u8>, pair: KernelAddressPair) {
    bytes.push(pair.host.family.code());
    bytes.push(pair.prefix_length);
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(&pair.host.octets);
    bytes.extend_from_slice(&pair.sandbox.octets);
}

pub(super) fn decode_address_pair(
    decoder: &mut Decoder<'_>,
) -> Result<KernelAddressPair, NetworkKernelPlanError> {
    let family = decode_family(decoder.byte()?)?;
    let prefix_length = decoder.byte()?;
    decoder.zeroes(2)?;
    let host = decode_address_bytes(family, decoder.take()?)?;
    let sandbox = decode_address_bytes(family, decoder.take()?)?;
    Ok(KernelAddressPair {
        host,
        sandbox,
        prefix_length,
    })
}

pub(super) fn encode_route(bytes: &mut Vec<u8>, route: KernelRoute) {
    bytes.push(route.destination.address.family.code());
    bytes.push(route.destination.prefix_length);
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(&route.destination.address.octets);
    bytes.extend_from_slice(&route.gateway.octets);
}

pub(super) fn decode_route(
    decoder: &mut Decoder<'_>,
) -> Result<KernelRoute, NetworkKernelPlanError> {
    let family = decode_family(decoder.byte()?)?;
    let prefix_length = decoder.byte()?;
    decoder.zeroes(2)?;
    let destination = decode_address_bytes(family, decoder.take()?)?;
    let gateway = decode_address_bytes(family, decoder.take()?)?;
    Ok(KernelRoute {
        destination: KernelPrefix {
            address: destination,
            prefix_length,
        },
        gateway,
    })
}

pub(super) fn encode_endpoint(
    bytes: &mut Vec<u8>,
    endpoint: &NetworkEndpointPolicyV1,
) -> Result<(), NetworkKernelPlanError> {
    let flow_count =
        u16::try_from(endpoint.flows().len()).map_err(|_| NetworkKernelPlanError::TooLarge)?;
    bytes.extend_from_slice(endpoint.endpoint_id().as_bytes());
    bytes.extend_from_slice(&flow_count.to_be_bytes());
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend_from_slice(endpoint.digest().as_bytes());
    for flow in endpoint.flows() {
        encode_flow(bytes, *flow);
    }
    Ok(())
}

pub(super) fn decode_endpoint(
    decoder: &mut Decoder<'_>,
) -> Result<NetworkEndpointPolicyV1, NetworkKernelPlanError> {
    let endpoint_id = NetworkEndpointId::from_bytes(decoder.take()?);
    let flow_count = usize::from(decoder.u16()?);
    decoder.zeroes(2)?;
    let expected_digest = decode_digest(decoder, "missing endpoint digest")?;
    if flow_count == 0 || flow_count > MAXIMUM_FLOWS_PER_ENDPOINT {
        return Err(NetworkKernelPlanError::Invalid(
            "invalid endpoint flow count",
        ));
    }
    let flow_bytes = flow_count
        .checked_mul(FLOW_BYTES)
        .ok_or(NetworkKernelPlanError::TooLarge)?;
    if flow_bytes > decoder.remaining() {
        return Err(NetworkKernelPlanError::Truncated);
    }
    let mut flows = Vec::with_capacity(flow_count);
    for _ in 0..flow_count {
        flows.push(decode_flow(decoder)?);
    }
    let endpoint = NetworkEndpointPolicyV1::new(endpoint_id, flows)
        .map_err(|_| NetworkKernelPlanError::Invalid("invalid endpoint policy"))?;
    if endpoint.digest() != expected_digest {
        return Err(NetworkKernelPlanError::Invalid(
            "endpoint-policy digest mismatch",
        ));
    }
    Ok(endpoint)
}

pub(super) fn encode_flow(bytes: &mut Vec<u8>, flow: NetworkFlowPolicyV1) {
    bytes.push(direction_code(flow.direction()));
    bytes.push(protocol_code(flow.protocol()));
    let prefix = kernel_prefix(flow.remote_prefix());
    bytes.push(prefix.address.family.code());
    bytes.push(prefix.prefix_length);
    bytes.extend_from_slice(&prefix.address.octets);
    match flow.ports() {
        Some(ports) => {
            bytes.extend_from_slice(&ports.first().to_be_bytes());
            bytes.extend_from_slice(&ports.last().to_be_bytes());
            bytes.push(1);
        }
        None => {
            bytes.extend_from_slice(&[0; 4]);
            bytes.push(0);
        }
    }
    bytes.extend_from_slice(&[0; 3]);
}

pub(super) fn decode_flow(
    decoder: &mut Decoder<'_>,
) -> Result<NetworkFlowPolicyV1, NetworkKernelPlanError> {
    let direction = decode_direction(decoder.byte()?)?;
    let protocol = decode_protocol(decoder.byte()?)?;
    let family = decode_family(decoder.byte()?)?;
    let prefix_length = decoder.byte()?;
    let prefix_address = decode_address_bytes(family, decoder.take()?)?;
    let first_port = decoder.u16()?;
    let last_port = decoder.u16()?;
    let ports_present = decode_flag(decoder.byte()?, "invalid port presence")?;
    decoder.zeroes(3)?;
    let prefix = network_prefix(KernelPrefix {
        address: prefix_address,
        prefix_length,
    })?;
    let ports = match ports_present {
        true => Some(
            NetworkPortRangeV1::new(first_port, last_port)
                .map_err(|_| NetworkKernelPlanError::Invalid("invalid port range"))?,
        ),
        false => {
            if first_port != 0 || last_port != 0 {
                return Err(NetworkKernelPlanError::Invalid(
                    "absent port range is nonzero",
                ));
            }
            None
        }
    };
    NetworkFlowPolicyV1::new(direction, protocol, prefix, ports)
        .map_err(|_| NetworkKernelPlanError::Invalid("invalid packet flow"))
}

pub(super) fn validate_decoded_namespace(
    namespace: &DecodedNamespace,
) -> Result<(), NetworkKernelPlanError> {
    if namespace.network_handle == [0; 32]
        || namespace.allocation_generation == 0
        || namespace.allocation_generation > 16_384
    {
        return Err(NetworkKernelPlanError::Invalid(
            "invalid namespace allocation identity",
        ));
    }
    let veth_kind = matches!(
        namespace.kind,
        NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published
    );
    if namespace.veth_present != veth_kind
        || namespace.lease_gate_program_digest.is_some() != veth_kind
    {
        return Err(NetworkKernelPlanError::Invalid(
            "network kind, veth, and lease gate disagree",
        ));
    }

    if namespace.veth_present {
        validate_veth(namespace)?;
    } else if namespace.mtu != 0
        || namespace.host_name != [0; 16]
        || namespace.sandbox_name != [0; 16]
        || namespace.host_mac != [0; 6]
        || namespace.sandbox_mac != [0; 6]
        || !namespace.address_pairs.is_empty()
        || !namespace.routes.is_empty()
    {
        return Err(NetworkKernelPlanError::Invalid(
            "isolated plan carries veth fields",
        ));
    }

    let computed = decoded_namespace_digest(namespace);
    if computed != namespace.digest {
        return Err(NetworkKernelPlanError::Invalid(
            "namespace-plan digest mismatch",
        ));
    }
    Ok(())
}

pub(super) fn validate_veth(namespace: &DecodedNamespace) -> Result<(), NetworkKernelPlanError> {
    if !(576..=65_535).contains(&namespace.mtu) || namespace.address_pairs.is_empty() {
        return Err(NetworkKernelPlanError::Invalid("invalid veth shape"));
    }
    let host_name = decode_name_bytes(namespace.host_name)?;
    let sandbox_name = decode_name_bytes(namespace.sandbox_name)?;
    let suffix = format!("{:012x}", namespace.allocation_generation);
    if host_name != format!("aoh{suffix}") || sandbox_name != format!("aog{suffix}") {
        return Err(NetworkKernelPlanError::Invalid(
            "interface label does not match allocation generation",
        ));
    }
    if namespace.host_mac[..3] != namespace.sandbox_mac[..3] {
        return Err(NetworkKernelPlanError::Invalid("MAC prefixes disagree"));
    }
    let suffix = u32::try_from(namespace.allocation_generation)
        .ok()
        .and_then(|generation| generation.checked_mul(2))
        .filter(|value| *value <= 0x00ff_ffff)
        .ok_or(NetworkKernelPlanError::Invalid("invalid MAC generation"))?;
    let host_suffix = suffix.to_be_bytes();
    let sandbox_suffix = suffix
        .checked_add(1)
        .ok_or(NetworkKernelPlanError::Invalid("invalid sandbox MAC"))?
        .to_be_bytes();
    if namespace.host_mac[3..] != host_suffix[1..]
        || namespace.sandbox_mac[3..] != sandbox_suffix[1..]
        || namespace.host_mac[0] & 0x03 != 0x02
    {
        return Err(NetworkKernelPlanError::Invalid(
            "MACs do not match allocation generation",
        ));
    }
    if namespace
        .address_pairs
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(NetworkKernelPlanError::Invalid(
            "address pairs are not canonical",
        ));
    }
    for pair in &namespace.address_pairs {
        validate_address_pair(*pair)?;
    }
    let ipv4_pairs = namespace
        .address_pairs
        .iter()
        .filter(|pair| pair.host.family == AddressFamily::Ipv4)
        .count();
    let ipv6_pairs = namespace
        .address_pairs
        .iter()
        .filter(|pair| pair.host.family == AddressFamily::Ipv6)
        .count();
    if ipv4_pairs > 1 || ipv6_pairs > 1 {
        return Err(NetworkKernelPlanError::Invalid(
            "multiple address pairs use one family",
        ));
    }
    if namespace.routes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(NetworkKernelPlanError::Invalid("routes are not canonical"));
    }
    for route in &namespace.routes {
        validate_prefix(route.destination)?;
        let expected_gateway = namespace
            .address_pairs
            .iter()
            .find(|pair| pair.host.family == route.destination.address.family)
            .map(|pair| pair.host)
            .ok_or(NetworkKernelPlanError::Invalid(
                "route has no matching address pair",
            ))?;
        if route.gateway != expected_gateway {
            return Err(NetworkKernelPlanError::Invalid(
                "route gateway is not the host peer",
            ));
        }
    }
    if namespace
        .address_pairs
        .iter()
        .any(|pair| pair.host.family == AddressFamily::Ipv6)
        && namespace.mtu < 1_280
    {
        return Err(NetworkKernelPlanError::Invalid("IPv6 MTU is too small"));
    }
    Ok(())
}

pub(super) fn validate_address_pair(pair: KernelAddressPair) -> Result<(), NetworkKernelPlanError> {
    let (expected_prefix, host, sandbox) = match pair.host.family {
        AddressFamily::Ipv4 => (
            31,
            u128::from(u32::from_be_bytes(
                pair.host.octets[..4]
                    .try_into()
                    .map_err(|_| NetworkKernelPlanError::Invalid("invalid IPv4 host"))?,
            )),
            u128::from(u32::from_be_bytes(
                pair.sandbox.octets[..4]
                    .try_into()
                    .map_err(|_| NetworkKernelPlanError::Invalid("invalid IPv4 peer"))?,
            )),
        ),
        AddressFamily::Ipv6 => (
            127,
            u128::from_be_bytes(pair.host.octets),
            u128::from_be_bytes(pair.sandbox.octets),
        ),
    };
    if pair.sandbox.family != pair.host.family
        || pair.prefix_length != expected_prefix
        || host.checked_add(1) != Some(sandbox)
        || host & 1 != 0
    {
        return Err(NetworkKernelPlanError::Invalid(
            "invalid point-to-point address pair",
        ));
    }
    Ok(())
}

pub(super) fn decoded_namespace_digest(namespace: &DecodedNamespace) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(NAMESPACE_PLAN_DIGEST_DOMAIN);
    digest.update(namespace.network_handle);
    digest.update(namespace.allocation_generation.to_be_bytes());
    digest.update([network_kind_code(namespace.kind)]);
    digest.update(namespace.profile_digest.as_bytes());
    digest.update(namespace.packet_program_digest.as_bytes());
    digest.update(namespace.enforcement_program_digest.as_bytes());
    match namespace.lease_gate_program_digest {
        Some(gate) => {
            digest.update([1]);
            digest.update(gate.as_bytes());
        }
        None => digest.update([0]),
    }
    if namespace.veth_present {
        digest.update([1]);
        digest.update(namespace.mtu.to_be_bytes());
        let host_length = namespace
            .host_name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(namespace.host_name.len());
        let sandbox_length = namespace
            .sandbox_name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(namespace.sandbox_name.len());
        digest.update(&namespace.host_name[..host_length]);
        digest.update(&namespace.sandbox_name[..sandbox_length]);
        digest.update(namespace.host_mac);
        digest.update(namespace.sandbox_mac);
    } else {
        digest.update([0]);
    }
    digest.update((namespace.address_pairs.len() as u16).to_be_bytes());
    for pair in &namespace.address_pairs {
        digest.update(encode_digest_address(pair.host));
        digest.update(encode_digest_address(pair.sandbox));
        digest.update([pair.prefix_length]);
    }
    digest.update((namespace.routes.len() as u16).to_be_bytes());
    for route in &namespace.routes {
        digest.update(encode_digest_prefix(route.destination));
        digest.update(encode_digest_address(route.gateway));
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(super) fn encode_digest_address(address: KernelAddress) -> Vec<u8> {
    let significant = match address.family {
        AddressFamily::Ipv4 => &address.octets[..4],
        AddressFamily::Ipv6 => &address.octets[..],
    };
    let mut bytes = Vec::with_capacity(significant.len() + 1);
    bytes.push(address.family.code());
    bytes.extend_from_slice(significant);
    bytes
}

pub(super) fn encode_digest_prefix(prefix: KernelPrefix) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(18);
    bytes.push(prefix.address.family.code());
    bytes.push(prefix.prefix_length);
    bytes.extend_from_slice(match prefix.address.family {
        AddressFamily::Ipv4 => &prefix.address.octets[..4],
        AddressFamily::Ipv6 => &prefix.address.octets[..],
    });
    bytes
}

pub(super) fn decode_name_bytes(bytes: [u8; 16]) -> Result<String, NetworkKernelPlanError> {
    let length =
        bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(NetworkKernelPlanError::Invalid(
                "interface name lacks terminator",
            ))?;
    if length == 0 || bytes[length..].iter().any(|byte| *byte != 0) {
        return Err(NetworkKernelPlanError::Invalid(
            "interface name is not zero-padded",
        ));
    }
    let name = std::str::from_utf8(&bytes[..length])
        .map_err(|_| NetworkKernelPlanError::Invalid("interface name is not UTF-8"))?;
    if !name.is_ascii() {
        return Err(NetworkKernelPlanError::Invalid(
            "interface name is not ASCII",
        ));
    }
    Ok(name.to_owned())
}

pub(super) fn decode_address_bytes(
    family: AddressFamily,
    octets: [u8; 16],
) -> Result<KernelAddress, NetworkKernelPlanError> {
    if family == AddressFamily::Ipv4 && octets[4..].iter().any(|byte| *byte != 0) {
        return Err(NetworkKernelPlanError::Invalid(
            "IPv4 address is not zero-padded",
        ));
    }
    Ok(KernelAddress { family, octets })
}

pub(super) fn network_prefix(
    prefix: KernelPrefix,
) -> Result<NetworkIpPrefixV1, NetworkKernelPlanError> {
    match prefix.address.family {
        AddressFamily::Ipv4 => NetworkIpPrefixV1::ipv4(
            prefix.address.octets[..4]
                .try_into()
                .map_err(|_| NetworkKernelPlanError::Invalid("invalid IPv4 prefix"))?,
            prefix.prefix_length,
        ),
        AddressFamily::Ipv6 => NetworkIpPrefixV1::ipv6(prefix.address.octets, prefix.prefix_length),
    }
    .map_err(|_| NetworkKernelPlanError::Invalid("invalid network prefix"))
}

pub(super) fn validate_prefix(prefix: KernelPrefix) -> Result<(), NetworkKernelPlanError> {
    network_prefix(prefix).map(|_| ())
}

pub(super) fn decode_digest(
    decoder: &mut Decoder<'_>,
    error: &'static str,
) -> Result<ObjectDigest, NetworkKernelPlanError> {
    nonzero_digest(decoder.take()?, error)
}

pub(super) fn nonzero_digest(
    bytes: [u8; 32],
    error: &'static str,
) -> Result<ObjectDigest, NetworkKernelPlanError> {
    if bytes == [0; 32] {
        Err(NetworkKernelPlanError::Invalid(error))
    } else {
        Ok(ObjectDigest::from_bytes(bytes))
    }
}

pub(super) fn decode_flag(value: u8, error: &'static str) -> Result<bool, NetworkKernelPlanError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(NetworkKernelPlanError::Invalid(error)),
    }
}

const fn network_kind_code(kind: NetworkKind) -> u8 {
    match kind {
        NetworkKind::Isolated => 1,
        NetworkKind::Project => 2,
        NetworkKind::Outbound => 3,
        NetworkKind::Published => 4,
        NetworkKind::Host => 5,
    }
}

pub(super) fn decode_network_kind(value: u8) -> Result<NetworkKind, NetworkKernelPlanError> {
    match value {
        1 => Ok(NetworkKind::Isolated),
        2 => Ok(NetworkKind::Project),
        3 => Ok(NetworkKind::Outbound),
        4 => Ok(NetworkKind::Published),
        _ => Err(NetworkKernelPlanError::Invalid("unknown network kind")),
    }
}

const fn direction_code(direction: NetworkFlowDirectionV1) -> u8 {
    match direction {
        NetworkFlowDirectionV1::Ingress => 1,
        NetworkFlowDirectionV1::Egress => 2,
    }
}

pub(super) fn decode_direction(
    value: u8,
) -> Result<NetworkFlowDirectionV1, NetworkKernelPlanError> {
    match value {
        1 => Ok(NetworkFlowDirectionV1::Ingress),
        2 => Ok(NetworkFlowDirectionV1::Egress),
        _ => Err(NetworkKernelPlanError::Invalid("unknown flow direction")),
    }
}

const fn protocol_code(protocol: NetworkTransportProtocolV1) -> u8 {
    match protocol {
        NetworkTransportProtocolV1::Tcp => 1,
        NetworkTransportProtocolV1::Udp => 2,
        NetworkTransportProtocolV1::IcmpV4 => 3,
        NetworkTransportProtocolV1::IcmpV6 => 4,
    }
}

pub(super) fn decode_protocol(
    value: u8,
) -> Result<NetworkTransportProtocolV1, NetworkKernelPlanError> {
    match value {
        1 => Ok(NetworkTransportProtocolV1::Tcp),
        2 => Ok(NetworkTransportProtocolV1::Udp),
        3 => Ok(NetworkTransportProtocolV1::IcmpV4),
        4 => Ok(NetworkTransportProtocolV1::IcmpV6),
        _ => Err(NetworkKernelPlanError::Invalid(
            "unknown transport protocol",
        )),
    }
}

pub(super) fn decode_family(value: u8) -> Result<AddressFamily, NetworkKernelPlanError> {
    match value {
        4 => Ok(AddressFamily::Ipv4),
        6 => Ok(AddressFamily::Ipv6),
        _ => Err(NetworkKernelPlanError::Invalid("unknown address family")),
    }
}

pub(super) fn kernel_plan_digest(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(PLAN_DIGEST_DOMAIN);
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(super) struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub(super) fn take<const N: usize>(&mut self) -> Result<[u8; N], NetworkKernelPlanError> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(NetworkKernelPlanError::TooLarge)?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(NetworkKernelPlanError::Truncated)?;
        self.cursor = end;
        bytes
            .try_into()
            .map_err(|_| NetworkKernelPlanError::Truncated)
    }

    pub(super) fn byte(&mut self) -> Result<u8, NetworkKernelPlanError> {
        Ok(self.take::<1>()?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16, NetworkKernelPlanError> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    pub(super) fn u32(&mut self) -> Result<u32, NetworkKernelPlanError> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, NetworkKernelPlanError> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    pub(super) fn zeroes(&mut self, length: usize) -> Result<(), NetworkKernelPlanError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(NetworkKernelPlanError::TooLarge)?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(NetworkKernelPlanError::Truncated)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Err(NetworkKernelPlanError::Invalid(
                "reserved bytes are nonzero",
            ));
        }
        self.cursor = end;
        Ok(())
    }

    pub(super) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.cursor)
    }

    pub(super) fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}
