//! Durable endpoint state validation and allocation-ledger discovery.
//!
//! State is accepted only when its ownership mode and loopback allocation
//! match the authenticated physical resource. Brokered PostgreSQL endpoints
//! additionally authenticate their process identities and storage binding.

use super::*;

/// Distinguishes service-owned fixed listeners from PostgreSQL broker
/// listeners without accepting partially populated authority records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EndpointMode {
    Direct,
    Broker,
}

pub(crate) fn scan_endpoint_ledger() -> Result<Vec<(ResourceId, EndpointValue)>, io::Error> {
    let mut resources = BTreeSet::new();
    let mut ports = BTreeSet::new();
    let mut allocated = Vec::new();
    for entry in fs::read_dir(ENDPOINT_ROOT)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("endpoint ledger contains a non-UTF-8 entry"))?;
        if super::super::is_protected_atomic_temporary(&entry.path())? {
            continue;
        }
        let digest = name
            .strip_suffix(".json")
            .filter(|digest| canonical_digest(digest))
            .ok_or_else(|| invalid("endpoint ledger contains an unknown entry"))?;
        if !entry.file_type()?.is_file() {
            return Err(invalid("endpoint ledger entry is not a regular file"));
        }
        let state = read_state_optional(&entry.path())?
            .ok_or_else(|| invalid("endpoint ledger entry disappeared during scan"))?;
        if resource_key(&state.resource)? != digest || !resources.insert(state.resource.clone()) {
            return Err(invalid(
                "endpoint ledger filename or resource is inconsistent",
            ));
        }
        let NativeResourceQualification::NetworkEndpoint {
            address,
            port,
            transport,
        } = &state.qualification
        else {
            return Err(invalid("endpoint ledger has another qualification"));
        };
        let details = endpoint_details(&state)?;
        if details.requested.address != *address
            || details.requested.port != *port
            || details.requested.transport != *transport
        {
            return Err(invalid("endpoint request differs from qualification"));
        }
        let endpoint = details
            .endpoint
            .clone()
            .ok_or_else(|| invalid("endpoint ledger entry has no reserved public value"))?;
        if endpoint.address != "127.0.0.1"
            || endpoint.transport != "tcp"
            || endpoint.port == 0
            || (*port != 0 && endpoint.port != *port)
        {
            return Err(invalid("endpoint ledger has an invalid public reservation"));
        }
        match endpoint_mode(&details)? {
            EndpointMode::Direct => {
                if *port == 0
                    || endpoint.port != *port
                    || !details.port_locked
                    || !matches!(
                        details.phase,
                        EndpointPhase::Allocated | EndpointPhase::Releasing
                    )
                {
                    return Err(invalid("direct endpoint ledger has an invalid phase shape"));
                }
            }
            EndpointMode::Broker => {
                let brokers = details
                    .brokers
                    .as_ref()
                    .ok_or_else(|| invalid("endpoint broker ledger has no specification"))?;
                if brokers.ipv4.public_port != endpoint.port
                    || brokers.ipv6.public_port != endpoint.port
                {
                    return Err(invalid(
                        "endpoint broker ledger has an invalid public reservation",
                    ));
                }
                validate_broker_set_shape(brokers)?;
                authenticate_stored_binding(&details)?;
                match details.phase {
                    EndpointPhase::Preparing => {}
                    EndpointPhase::Allocated
                        if details.port_locked
                            && details.ipv4_identity.is_some()
                            && details.ipv6_identity.is_some() => {}
                    EndpointPhase::Releasing => {}
                    _ => return Err(invalid("endpoint ledger has an invalid phase shape")),
                }
            }
        }
        if !ports.insert(endpoint.port) {
            return Err(invalid("endpoint ledger contains a duplicate port"));
        }
        allocated.push((state.resource, endpoint));
    }
    Ok(allocated)
}

/// Validates the closed authority shape and returns the endpoint ownership
/// mode. Direct records must contain no PostgreSQL or broker authority.
///
/// # Errors
///
/// Returns an error when the record mixes fields from the two ownership modes.
pub(super) fn endpoint_mode(details: &EndpointStateDetails) -> Result<EndpointMode, io::Error> {
    match (
        details.storage.as_ref(),
        details.brokers.as_ref(),
        details.ipv4_identity.as_ref(),
        details.ipv6_identity.as_ref(),
    ) {
        (None, None, None, None) => Ok(EndpointMode::Direct),
        (Some(_), Some(_), _, _) => Ok(EndpointMode::Broker),
        _ => Err(invalid("endpoint ledger contains mixed ownership state")),
    }
}

/// Authenticates a settled direct allocation exclusively from its exact
/// ledger record. The consuming service owns the live listener separately.
///
/// # Errors
///
/// Returns an error when the allocation is unsettled or its fixed authority is
/// inconsistent.
pub(super) fn authenticate_direct_endpoint(
    details: &EndpointStateDetails,
) -> Result<EndpointValue, io::Error> {
    if endpoint_mode(details)? != EndpointMode::Direct
        || details.phase != EndpointPhase::Allocated
        || !details.port_locked
    {
        return Err(invalid("direct endpoint is not settled"));
    }
    direct_endpoint_authority(details)
}

/// Validates the immutable fixed-listener authority independently of its
/// transition phase so interrupted release can return to allocated state.
///
/// # Errors
///
/// Returns an error when the record is not a complete direct allocation or its
/// public endpoint differs from the original request.
pub(super) fn direct_endpoint_authority(
    details: &EndpointStateDetails,
) -> Result<EndpointValue, io::Error> {
    if endpoint_mode(details)? != EndpointMode::Direct || !details.port_locked {
        return Err(invalid("direct endpoint has invalid ownership authority"));
    }
    let endpoint = details
        .endpoint
        .as_ref()
        .ok_or_else(|| invalid("settled direct endpoint has no public value"))?;
    if details.requested.address != "127.0.0.1"
        || details.requested.transport != "tcp"
        || details.requested.port < 1024
        || endpoint.address != details.requested.address
        || endpoint.transport != details.requested.transport
        || endpoint.port != details.requested.port
    {
        return Err(invalid("direct endpoint has inconsistent fixed authority"));
    }
    Ok(endpoint.clone())
}

pub(super) fn validate_broker_set_shape(brokers: &BrokerSet) -> Result<(), io::Error> {
    validate_broker_shape(&brokers.ipv4)?;
    validate_broker_shape(&brokers.ipv6)?;
    if brokers.ipv4.family != BrokerFamily::Ipv4
        || brokers.ipv6.family != BrokerFamily::Ipv6
        || brokers.ipv4.public_port != brokers.ipv6.public_port
        || brokers.ipv4.slot != brokers.ipv6.slot
        || brokers.ipv4.uid != brokers.ipv6.uid
        || brokers.ipv4.gid != brokers.ipv6.gid
        || brokers.ipv4.server_port != brokers.ipv6.server_port
        || brokers.ipv4.backend_path != brokers.ipv6.backend_path
        || brokers.ipv4.backend_argument != brokers.ipv6.backend_argument
        || brokers.ipv4.executable != brokers.ipv6.executable
        || brokers.ipv4.principal != brokers.ipv6.principal
    {
        return Err(invalid(
            "endpoint broker families have inconsistent ownership",
        ));
    }
    Ok(())
}

pub(super) fn validate_broker_shape(spec: &BrokerSpec) -> Result<(), io::Error> {
    let server_port = 20_000_u16
        .checked_add(u16::from(spec.slot))
        .ok_or_else(|| invalid("endpoint broker internal port overflowed"))?;
    let backend_path = format!("{SOCKET_ROOT}/{:02}/.s.PGSQL.{server_port}", spec.slot);
    let executable = Path::new(&spec.executable);
    let canonical_executable = fs::canonicalize(executable)?;
    let executable_metadata = fs::metadata(&canonical_executable)?;
    if !executable.is_absolute()
        || !spec.executable.starts_with("/nix/store/")
        || canonical_executable != executable
        || !executable_metadata.file_type().is_file()
        || executable_metadata.uid() != 0
        || executable_metadata.mode() & 0o111 == 0
        || spec.principal != super::super::postgresql_broker_principal(spec.slot)?
        || spec.uid != super::super::postgresql_broker_uid(spec.slot)?
        || spec.gid != super::super::postgresql_probe_gid(spec.slot)?
        || spec.server_port != server_port
        || spec.backend_path != backend_path
        || spec.backend_argument != format!("UNIX-CONNECT:{backend_path}")
        || spec.listener_argument != expected_listener_argument(spec.family, spec.public_port)
        || spec.public_port == 0
    {
        return Err(invalid(
            "endpoint broker marker has inconsistent slot fields",
        ));
    }
    Ok(())
}

pub(super) fn expected_listener_argument(family: BrokerFamily, public_port: u16) -> String {
    match family {
        BrokerFamily::Ipv4 => format!(
            "TCP4-LISTEN:{public_port},bind=0.0.0.0,reuseaddr,fork,range=127.0.0.0/8,max-children=32"
        ),
        BrokerFamily::Ipv6 => format!(
            "TCP6-LISTEN:{public_port},bind=[::],ipv6only=1,reuseaddr,fork,range=[::1]/128,max-children=32"
        ),
    }
}

pub(super) fn authenticate_stored_binding(details: &EndpointStateDetails) -> Result<(), io::Error> {
    if endpoint_mode(details)? != EndpointMode::Broker {
        return Err(invalid("direct endpoint has no PostgreSQL storage binding"));
    }
    let binding = details
        .storage
        .as_ref()
        .ok_or_else(|| invalid("endpoint broker has no PostgreSQL storage binding"))?;
    super::super::storage::authenticate_exact_binding(binding)
}

pub(super) fn endpoint_details(state: &HostState) -> Result<EndpointStateDetails, io::Error> {
    serde_json::from_value(state.details.clone())
        .map_err(|error| invalid(format!("invalid endpoint state: {error}")))
}

pub(super) fn write_endpoint_state(
    request: &NativeHostRequest,
    details: &EndpointStateDetails,
) -> Result<(), io::Error> {
    write_state(
        &request.resource.state_path,
        &new_state(request, serde_json::to_value(details).map_err(store_error)?),
    )
}

pub(super) fn require_requested(
    expected: &EndpointInput,
    actual: &EndpointInput,
) -> Result<(), io::Error> {
    if expected.address != actual.address
        || expected.port != actual.port
        || expected.transport != actual.transport
    {
        return Err(invalid("endpoint state binds another request"));
    }
    Ok(())
}

pub(super) fn endpoint_record(
    request: &NativeHostRequest,
    endpoint: Option<EndpointValue>,
    owned: bool,
    observed_revision: Option<RevisionId>,
) -> Result<NativeHostRecord, io::Error> {
    let result = serde_json::json!({
        "schema": NETWORK_ENDPOINT_OBSERVATION_SCHEMA,
        "requested_revision": request.durable.revision.0.to_string(),
        "observed_revision": observed_revision.map(|revision| revision.0.to_string()),
        "endpoint": endpoint,
        "owned": owned,
    });
    let outputs = endpoint
        .map(|value| -> Result<_, io::Error> {
            Ok(BTreeMap::from([(
                LocalKey::new(NETWORK_ENDPOINT_OUTPUT).map_err(store_error)?,
                ability_value(serde_json::to_value(value).map_err(store_error)?)?,
            )]))
        })
        .transpose()?
        .unwrap_or_default();
    record(result, outputs)
}

pub(super) fn canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
