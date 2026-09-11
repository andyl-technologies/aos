//! Exact per-resource nftables ownership and loopback ingress enforcement.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use aos_ability_model::builtin::{
    HOST_NETWORK_POLICY_ACTIVE_OUTPUT, HOST_NETWORK_POLICY_OBSERVATION_SCHEMA,
};
use aos_ability_model::{LocalKey, ResourceId, RevisionId};
use aos_ability_runtime::adapter::RuntimeControl;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::platform::NativePlatformTools;
use super::process::{DescendantPolicy, ProcessOutput, run_bounded};
use super::{
    EndpointValue, HostState, NativeDependencyBinding, NativeHostRecord, NativeHostRequest,
    PolicyInput, bool_value, decode_input, invalid, new_state, record,
    remove_atomic_temporary_root, remove_regular_optional, require_current_state,
    require_matching_state, store_error, write_state,
};

const INPUT_CHAIN: &str = "input";
const MAX_NFT_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PolicyPhase {
    Preparing,
    Applied,
    Removing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyStateDetails {
    phase: PolicyPhase,
    table: String,
    endpoint: EndpointValue,
    ipv4_comment: String,
    ipv6_comment: String,
    ruleset: serde_json::Value,
    endpoint_authority: NativeDependencyBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prior: Option<PolicySnapshot>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicySnapshot {
    endpoint: EndpointValue,
    ruleset: serde_json::Value,
    endpoint_authority: NativeDependencyBinding,
}

pub(super) fn execute_policy(
    request: &NativeHostRequest,
    control: &dyn RuntimeControl,
) -> Result<NativeHostRecord, io::Error> {
    let input: PolicyInput = decode_input(&request.durable.inputs, "host network policy")?;
    let expected = input
        .endpoint
        .as_ref()
        .map(|endpoint| {
            policy_details(
                &request.durable.resource,
                endpoint,
                policy_endpoint_authority(request)?,
                PolicyPhase::Preparing,
            )
        })
        .transpose()?;
    match request.durable.method.as_str() {
        "apply" => apply_policy(
            request,
            expected
                .as_ref()
                .ok_or_else(|| invalid("policy apply has no concrete endpoint"))?,
            control,
        ),
        "observe" => observe_policy(
            request,
            expected
                .as_ref()
                .ok_or_else(|| invalid("policy observe has no concrete endpoint"))?,
            control,
        ),
        "remove" => remove_policy(request, control),
        _ => Err(invalid("unsupported network-policy method")),
    }
}

fn apply_policy(
    request: &NativeHostRequest,
    expected: &PolicyStateDetails,
    control: &dyn RuntimeControl,
) -> Result<NativeHostRecord, io::Error> {
    super::authenticate_endpoint(&expected.endpoint_authority, &expected.endpoint)?;
    let existing = read_policy_state(request)?;
    match existing.as_ref() {
        Some((state, details)) => validate_policy_details(&state.resource, details)?,
        None if table_exists(&request.durable.platform, &expected.table, control)? => {
            return Err(invalid(
                "network-policy table exists without an ownership marker",
            ));
        }
        None => {}
    }

    let live_document = inspect_policy_table(&request.durable.platform, &expected.table, control)?;
    let live_ruleset = live_document
        .as_ref()
        .map(normalized_policy_document)
        .transpose()?;
    if existing.as_ref().is_some_and(|(state, details)| {
        state.revision == request.durable.revision
            && details.phase == PolicyPhase::Applied
            && details.endpoint == expected.endpoint
            && details.ruleset == expected.ruleset
            && details.endpoint_authority == expected.endpoint_authority
    }) && live_ruleset.as_ref() == Some(&expected.ruleset)
    {
        return policy_record(
            request,
            Some(expected.endpoint.clone()),
            true,
            Some(request.durable.revision),
        );
    }

    let authenticated_live =
        authenticate_live_snapshot(existing.as_ref(), expected, live_ruleset.as_ref())?;
    if let Some(snapshot) = &authenticated_live {
        super::authenticate_endpoint(&snapshot.endpoint_authority, &snapshot.endpoint)?;
    }
    let mut preparing = expected.clone();
    preparing.prior = authenticated_live.or_else(|| {
        existing
            .as_ref()
            .and_then(|(_, details)| details.prior.clone())
    });
    write_policy_state(request, &preparing, PolicyPhase::Preparing)?;
    match live_ruleset {
        Some(live) if live == expected.ruleset => {}
        Some(_) => {
            replace_policy_table(&request.durable.platform, expected, control)?;
        }
        None => create_policy_table(&request.durable.platform, expected, control)?,
    }
    if !policy_table_matches(&request.durable.platform, expected, control)? {
        return Err(io::Error::other(
            "installed network policy cannot be authenticated",
        ));
    }

    write_policy_state(request, expected, PolicyPhase::Applied)?;
    policy_record(
        request,
        Some(expected.endpoint.clone()),
        true,
        Some(request.durable.revision),
    )
}

fn authenticate_live_snapshot(
    existing: Option<&(HostState, PolicyStateDetails)>,
    expected: &PolicyStateDetails,
    live: Option<&serde_json::Value>,
) -> Result<Option<PolicySnapshot>, io::Error> {
    let Some(live) = live else {
        return Ok(None);
    };
    if live == &expected.ruleset {
        return Ok(None);
    }
    let Some((_, details)) = existing else {
        return Err(invalid(
            "network-policy table exists without an ownership marker",
        ));
    };
    if live == &details.ruleset {
        return Ok(Some(PolicySnapshot {
            endpoint: details.endpoint.clone(),
            ruleset: details.ruleset.clone(),
            endpoint_authority: details.endpoint_authority.clone(),
        }));
    }
    if let Some(prior) = &details.prior
        && live == &prior.ruleset
    {
        return Ok(Some(prior.clone()));
    }
    Err(invalid(
        "live network policy is neither prior nor desired state",
    ))
}

fn observe_policy(
    request: &NativeHostRequest,
    expected: &PolicyStateDetails,
    control: &dyn RuntimeControl,
) -> Result<NativeHostRecord, io::Error> {
    super::authenticate_endpoint(&expected.endpoint_authority, &expected.endpoint)?;
    let state = require_current_state(request)?;
    let details = decode_policy_state(&state)?;
    require_same_policy(&details, expected)?;
    if details.phase != PolicyPhase::Applied {
        return Err(invalid("network-policy guarantee is not applied"));
    }
    let active = policy_table_matches(&request.durable.platform, expected, control)?;
    if !active {
        return Err(invalid("network-policy guarantee is divergent"));
    }
    policy_record(
        request,
        Some(expected.endpoint.clone()),
        true,
        Some(state.revision),
    )
}

fn policy_endpoint_authority(
    request: &NativeHostRequest,
) -> Result<NativeDependencyBinding, io::Error> {
    let mut bindings = request
        .durable
        .dependencies
        .iter()
        .filter(|binding| binding.input == "endpoint");
    let binding = bindings
        .next()
        .ok_or_else(|| invalid("network policy has no endpoint producer authority"))?;
    if bindings.next().is_some() {
        return Err(invalid(
            "network policy has multiple endpoint producer authorities",
        ));
    }
    Ok(binding.clone())
}

fn remove_policy(
    request: &NativeHostRequest,
    control: &dyn RuntimeControl,
) -> Result<NativeHostRecord, io::Error> {
    let Some(state) = super::read_state_optional(&request.resource.state_path)? else {
        let table = policy_table(&request.durable.resource)?;
        if table_exists(&request.durable.platform, &table, control)? {
            return Err(invalid(
                "network-policy table exists without an ownership marker",
            ));
        }
        remove_atomic_temporary_root(&request.resource.state_path, 0o600)?;
        return policy_record(request, None, false, None);
    };
    require_matching_state(request, &state)?;
    let details = decode_policy_state(&state)?;
    let mut live_authority = &details.endpoint_authority;
    let mut live_endpoint = &details.endpoint;
    if let Some(document) =
        inspect_policy_table(&request.durable.platform, &details.table, control)?
    {
        let live = normalized_policy_document(&document)?;
        if live == details.ruleset {
        } else if let Some(prior) = details.prior.as_ref().filter(|prior| live == prior.ruleset) {
            live_authority = &prior.endpoint_authority;
            live_endpoint = &prior.endpoint;
        } else {
            return Err(invalid("network-policy removal found a foreign live table"));
        }
    }
    if details.phase != PolicyPhase::Removing {
        super::authenticate_endpoint(live_authority, live_endpoint)?;
        write_policy_state(request, &details, PolicyPhase::Removing)?;
    }
    if table_exists(&request.durable.platform, &details.table, control)? {
        delete_policy_table(&request.durable.platform, &details.table, control)?;
    }
    if table_exists(&request.durable.platform, &details.table, control)? {
        return Err(io::Error::other(
            "network-policy table remained after deletion",
        ));
    }
    remove_regular_optional(&request.resource.state_path, 0)?;
    policy_record(request, None, false, None)
}

pub(super) fn policy_health(
    state: &HostState,
    platform: &NativePlatformTools,
    control: &dyn RuntimeControl,
) -> Result<aos_ability_plan::RuntimeResourceHealth, io::Error> {
    let details = decode_policy_state(state)?;
    if details.phase == PolicyPhase::Applied && policy_table_matches(platform, &details, control)? {
        Ok(aos_ability_plan::RuntimeResourceHealth::Healthy)
    } else {
        Ok(aos_ability_plan::RuntimeResourceHealth::Divergent)
    }
}

fn read_policy_state(
    request: &NativeHostRequest,
) -> Result<Option<(HostState, PolicyStateDetails)>, io::Error> {
    let Some(state) = super::read_state_optional(&request.resource.state_path)? else {
        return Ok(None);
    };
    require_matching_state(request, &state)?;
    let details = decode_policy_state(&state)?;
    Ok(Some((state, details)))
}

fn decode_policy_state(state: &HostState) -> Result<PolicyStateDetails, io::Error> {
    let details = serde_json::from_value(state.details.clone())
        .map_err(|error| invalid(format!("invalid network-policy state: {error}")))?;
    validate_policy_details(&state.resource, &details)?;
    Ok(details)
}

fn policy_details(
    resource: &ResourceId,
    endpoint: &EndpointValue,
    endpoint_authority: NativeDependencyBinding,
    phase: PolicyPhase,
) -> Result<PolicyStateDetails, io::Error> {
    let digest = Sha256Digest::of_canonical("aos.ability.host-policy-chain/v1", resource)
        .map_err(store_error)?
        .hex();
    let mut details = PolicyStateDetails {
        phase,
        table: format!("aos_p_{}", &digest[..24]),
        endpoint: endpoint.clone(),
        ipv4_comment: format!("aos:{digest}:ipv4"),
        ipv6_comment: format!("aos:{digest}:ipv6"),
        ruleset: serde_json::Value::Null,
        endpoint_authority,
        prior: None,
    };
    details.ruleset = serde_json::json!({"nftables": expected_policy_entries(&details)});
    Ok(details)
}

fn policy_table(resource: &ResourceId) -> Result<String, io::Error> {
    let digest = Sha256Digest::of_canonical("aos.ability.host-policy-chain/v1", resource)
        .map_err(store_error)?
        .hex();
    Ok(format!("aos_p_{}", &digest[..24]))
}

fn require_same_policy(
    actual: &PolicyStateDetails,
    expected: &PolicyStateDetails,
) -> Result<(), io::Error> {
    if actual.table != expected.table
        || actual.endpoint != expected.endpoint
        || actual.ipv4_comment != expected.ipv4_comment
        || actual.ipv6_comment != expected.ipv6_comment
        || actual.ruleset != expected.ruleset
        || actual.endpoint_authority != expected.endpoint_authority
    {
        return Err(invalid("network-policy marker binds another policy"));
    }
    Ok(())
}

fn validate_policy_details(
    resource: &ResourceId,
    details: &PolicyStateDetails,
) -> Result<(), io::Error> {
    let expected = policy_details(
        resource,
        &details.endpoint,
        details.endpoint_authority.clone(),
        details.phase,
    )?;
    if details.table != expected.table
        || details.ipv4_comment != expected.ipv4_comment
        || details.ipv6_comment != expected.ipv6_comment
        || details.ruleset != expected.ruleset
    {
        return Err(invalid(
            "network-policy marker has a foreign normalized ruleset",
        ));
    }
    if let Some(prior) = &details.prior {
        let mut prior_details = details.clone();
        prior_details.endpoint = prior.endpoint.clone();
        prior_details.endpoint_authority = prior.endpoint_authority.clone();
        prior_details.ruleset = serde_json::Value::Null;
        prior_details.prior = None;
        let expected_prior =
            serde_json::json!({"nftables": expected_policy_entries(&prior_details)});
        if prior.ruleset != expected_prior {
            return Err(invalid("network-policy prior snapshot is inconsistent"));
        }
    }
    Ok(())
}

fn write_policy_state(
    request: &NativeHostRequest,
    expected: &PolicyStateDetails,
    phase: PolicyPhase,
) -> Result<(), io::Error> {
    let mut details = expected.clone();
    details.phase = phase;
    if phase == PolicyPhase::Applied {
        details.prior = None;
    }
    write_state(
        &request.resource.state_path,
        &new_state(request, serde_json::to_value(details).map_err(store_error)?),
    )
}

fn create_policy_table(
    platform: &NativePlatformTools,
    details: &PolicyStateDetails,
    control: &dyn RuntimeControl,
) -> Result<(), io::Error> {
    let script = create_policy_script(details);
    let mut command = platform.nft_command();
    command.args(["-f", "-"]);
    require_success(
        run_bounded(
            &mut command,
            Some(script.as_bytes()),
            MAX_NFT_OUTPUT_BYTES,
            DescendantPolicy::Reap,
            control,
        )?,
        "creating network-policy table",
    )
    .map(|_| ())
}

fn create_policy_script(details: &PolicyStateDetails) -> String {
    format!(
        "add table inet {table}\nadd chain inet {table} {chain} {{ type filter hook input priority -5; policy accept; }}\nadd rule inet {table} {chain} ip daddr != 127.0.0.1 tcp dport {port} counter drop comment \"{ipv4}\"\nadd rule inet {table} {chain} ip6 daddr != ::1 tcp dport {port} counter drop comment \"{ipv6}\"\n",
        table = details.table,
        chain = INPUT_CHAIN,
        port = details.endpoint.port,
        ipv4 = details.ipv4_comment,
        ipv6 = details.ipv6_comment,
    )
}

fn replace_policy_table(
    platform: &NativePlatformTools,
    details: &PolicyStateDetails,
    control: &dyn RuntimeControl,
) -> Result<(), io::Error> {
    let script = format!(
        "delete table inet {}\n{}",
        details.table,
        create_policy_script(details),
    );
    let mut command = platform.nft_command();
    command.args(["-f", "-"]);
    require_success(
        run_bounded(
            &mut command,
            Some(script.as_bytes()),
            MAX_NFT_OUTPUT_BYTES,
            DescendantPolicy::Reap,
            control,
        )?,
        "replacing network-policy table",
    )
    .map(|_| ())
}

fn delete_policy_table(
    platform: &NativePlatformTools,
    table: &str,
    control: &dyn RuntimeControl,
) -> Result<(), io::Error> {
    let script = format!("delete table inet {table}\n");
    let mut command = platform.nft_command();
    command.args(["-f", "-"]);
    require_success(
        run_bounded(
            &mut command,
            Some(script.as_bytes()),
            MAX_NFT_OUTPUT_BYTES,
            DescendantPolicy::Reap,
            control,
        )?,
        "deleting network-policy table",
    )
    .map(|_| ())
}

fn table_exists(
    platform: &NativePlatformTools,
    table: &str,
    control: &dyn RuntimeControl,
) -> Result<bool, io::Error> {
    let mut command = platform.nft_command();
    command.args(["-j", "list", "tables"]);
    let bytes = require_success(
        run_bounded(
            &mut command,
            None,
            MAX_NFT_OUTPUT_BYTES,
            DescendantPolicy::Reap,
            control,
        )?,
        "listing nftables tables",
    )?;
    Ok(nft_table_names(&bytes)?.iter().any(|name| name == table))
}

fn inspect_policy_table(
    platform: &NativePlatformTools,
    table: &str,
    control: &dyn RuntimeControl,
) -> Result<Option<serde_json::Value>, io::Error> {
    if !table_exists(platform, table, control)? {
        return Ok(None);
    }
    let mut command = platform.nft_command();
    command.args(["-j", "-a", "list", "table", "inet", table]);
    let bytes = require_success(
        run_bounded(
            &mut command,
            None,
            MAX_NFT_OUTPUT_BYTES,
            DescendantPolicy::Reap,
            control,
        )?,
        "reading owned network-policy table",
    )?;
    aos_contract::canonical::parse_json(&bytes, "nftables policy document")
        .map(Some)
        .map_err(store_error)
}

fn policy_table_matches(
    platform: &NativePlatformTools,
    details: &PolicyStateDetails,
    control: &dyn RuntimeControl,
) -> Result<bool, io::Error> {
    let Some(document) = inspect_policy_table(platform, &details.table, control)? else {
        return Ok(false);
    };
    require_exact_policy_document(details, &document).map(|()| true)
}

fn require_exact_policy_document(
    details: &PolicyStateDetails,
    document: &serde_json::Value,
) -> Result<(), io::Error> {
    if normalized_policy_document(document)? != details.ruleset {
        return Err(invalid("owned nftables table has a foreign rule shape"));
    }
    Ok(())
}

fn normalized_policy_document(
    document: &serde_json::Value,
) -> Result<serde_json::Value, io::Error> {
    let entries = document
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid("nftables policy document has no entry array"))?;
    let mut normalized = Vec::new();
    for entry in entries {
        let object = entry
            .as_object()
            .ok_or_else(|| invalid("nftables policy entry is not an object"))?;
        if object.len() != 1 {
            return Err(invalid("nftables policy entry has an ambiguous shape"));
        }
        if object.contains_key("metainfo") {
            continue;
        }
        let mut entry = entry.clone();
        for kind in ["table", "chain", "rule"] {
            if let Some(fields) = entry
                .get_mut(kind)
                .and_then(serde_json::Value::as_object_mut)
            {
                fields.remove("handle");
            }
        }
        if let Some(expressions) = entry
            .get_mut("rule")
            .and_then(|rule| rule.get_mut("expr"))
            .and_then(serde_json::Value::as_array_mut)
        {
            for expression in expressions {
                let Some(counter) = expression.get_mut("counter") else {
                    continue;
                };
                let fields = counter
                    .as_object()
                    .ok_or_else(|| invalid("nftables counter has a foreign shape"))?;
                if fields.len() != 2
                    || !fields.contains_key("packets")
                    || !fields.contains_key("bytes")
                    || fields.values().any(|value| !value.is_u64())
                {
                    return Err(invalid("nftables counter has a foreign shape"));
                }
                *counter = serde_json::Value::Null;
            }
        }
        normalized.push(entry);
    }
    Ok(serde_json::json!({"nftables": normalized}))
}

fn expected_policy_entries(details: &PolicyStateDetails) -> Vec<serde_json::Value> {
    let payload_match = |protocol: &str, field: &str, op: &str, right: serde_json::Value| {
        serde_json::json!({
            "match": {
                "op": op,
                "left": {"payload": {"protocol": protocol, "field": field}},
                "right": right,
            }
        })
    };
    vec![
        serde_json::json!({"table": {"family": "inet", "name": details.table}}),
        serde_json::json!({"chain": {
            "family": "inet",
            "table": details.table,
            "name": INPUT_CHAIN,
            "type": "filter",
            "hook": "input",
            "prio": -5,
            "policy": "accept",
        }}),
        serde_json::json!({"rule": {
            "family": "inet",
            "table": details.table,
            "chain": INPUT_CHAIN,
            "expr": [
                payload_match("ip", "daddr", "!=", serde_json::json!("127.0.0.1")),
                payload_match("tcp", "dport", "==", serde_json::json!(details.endpoint.port)),
                {"counter": null},
                {"drop": null},
            ],
            "comment": details.ipv4_comment,
        }}),
        serde_json::json!({"rule": {
            "family": "inet",
            "table": details.table,
            "chain": INPUT_CHAIN,
            "expr": [
                payload_match("ip6", "daddr", "!=", serde_json::json!("::1")),
                payload_match("tcp", "dport", "==", serde_json::json!(details.endpoint.port)),
                {"counter": null},
                {"drop": null},
            ],
            "comment": details.ipv6_comment,
        }}),
    ]
}

fn nft_table_names(bytes: &[u8]) -> Result<Vec<String>, io::Error> {
    let document =
        aos_contract::canonical::parse_json(bytes, "nftables table list").map_err(store_error)?;
    let entries = document
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid("nftables table list has no entry array"))?;
    let mut names = Vec::new();
    let mut unique = BTreeSet::new();
    for entry in entries {
        let object = entry
            .as_object()
            .ok_or_else(|| invalid("nftables table-list entry is not an object"))?;
        if object.len() != 1 {
            return Err(invalid("nftables table-list entry has an ambiguous shape"));
        }
        let Some(table) = entry.get("table") else {
            if entry.get("metainfo").is_some() {
                continue;
            }
            return Err(invalid("nftables table list contains a foreign entry"));
        };
        let fields = table
            .as_object()
            .ok_or_else(|| invalid("nftables table entry is malformed"))?;
        if fields
            .keys()
            .any(|key| !matches!(key.as_str(), "family" | "name" | "handle"))
        {
            return Err(invalid("nftables table entry has a foreign field"));
        }
        if fields.get("family").and_then(serde_json::Value::as_str) == Some("inet") {
            let name = fields
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| invalid("nftables table entry has no name"))?;
            if !unique.insert(name.to_string()) {
                return Err(invalid("nftables table list contains a duplicate table"));
            }
            names.push(name.to_string());
        }
    }
    Ok(names)
}

fn require_success(output: ProcessOutput, operation: &str) -> Result<Vec<u8>, io::Error> {
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(io::Error::other(format!("{operation} failed")))
    }
}

fn policy_record(
    request: &NativeHostRequest,
    endpoint: Option<EndpointValue>,
    active: bool,
    observed_revision: Option<RevisionId>,
) -> Result<NativeHostRecord, io::Error> {
    let result = serde_json::json!({
        "schema": HOST_NETWORK_POLICY_OBSERVATION_SCHEMA,
        "requested_revision": request.durable.revision.0.to_string(),
        "observed_revision": observed_revision.map(|revision| revision.0.to_string()),
        "active": active,
        "endpoint": endpoint,
    });
    let outputs = matches!(request.durable.method.as_str(), "apply" | "observe")
        .then(|| -> Result<_, io::Error> {
            Ok(BTreeMap::from([(
                LocalKey::new(HOST_NETWORK_POLICY_ACTIVE_OUTPUT).map_err(store_error)?,
                bool_value(active)?,
            )]))
        })
        .transpose()?
        .unwrap_or_default();
    record(result, outputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_normalization_keeps_counter_shape_and_discards_values() {
        let document = serde_json::json!({"nftables": [
            {"metainfo": {"json_schema_version": 1}},
            {"rule": {
                "family": "inet",
                "table": "owned",
                "chain": "input",
                "handle": 9,
                "expr": [
                    {"counter": {"packets": 17, "bytes": 1234}},
                    {"drop": null}
                ]
            }}
        ]});
        let normalized = normalized_policy_document(&document).expect("normalize nft output");
        assert_eq!(
            normalized,
            serde_json::json!({"nftables": [{"rule": {
                "family": "inet",
                "table": "owned",
                "chain": "input",
                "expr": [
                    {"counter": null},
                    {"drop": null}
                ]
            }}]})
        );
    }

    #[test]
    fn policy_normalization_rejects_incomplete_counter_proof() {
        let document = serde_json::json!({"nftables": [{"rule": {
            "expr": [{"counter": {"packets": 1}}]
        }}]});
        assert!(normalized_policy_document(&document).is_err());
    }
}
