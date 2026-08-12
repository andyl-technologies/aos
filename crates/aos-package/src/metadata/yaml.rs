//! A small, safe parser for the NoCloud YAML subset used by the metadata agent.
//!
//! NoCloud's `meta-data` document is a flat scalar map, while its v2
//! `network-config` uses a narrowly structured netplan map. Pulling in a full
//! YAML implementation for those two contracts added `unsafe-libyaml` to the
//! hermetic bootstrap closure. This module instead parses only the documented
//! subset AOS consumes and rejects tabs, malformed indentation, and invalid
//! scalar/list syntax. Unknown keys remain inert platform facts.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};

use super::fetcher::StaticNetwork;

/// Parsed scalar fields from a NoCloud `meta-data` document.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct NoCloudMetadata {
    pub(super) hostname: Option<String>,
    pub(super) instance_id: Option<String>,
}

#[derive(Debug)]
struct Line<'a> {
    indent: usize,
    text: &'a str,
}

/// Parse the flat scalar subset of NoCloud `meta-data`.
pub(super) fn parse_metadata(bytes: &[u8]) -> Result<NoCloudMetadata> {
    let lines = lines(bytes)?;
    let mut metadata = NoCloudMetadata::default();
    for line in lines {
        if line.indent != 0 {
            continue;
        }
        let Some((key, value)) = key_value(line.text)? else {
            continue;
        };
        match key {
            "local-hostname" => metadata.hostname = nonempty_scalar(value)?,
            "instance-id" => metadata.instance_id = nonempty_scalar(value)?,
            _ => {}
        }
    }
    Ok(metadata)
}

/// Parse the v2 netplan subset carried by NoCloud `network-config`.
pub(super) fn parse_netplan(bytes: &[u8]) -> Result<StaticNetwork> {
    let lines = lines(bytes)?;
    let mut ethernets_entry = None;
    for (index, line) in lines.iter().enumerate() {
        if let Some((key, value)) = key_value(line.text)?
            && key == "ethernets"
        {
            ethernets_entry = Some((index, value));
            break;
        }
    }
    let Some((ethernets_index, ethernets_value)) = ethernets_entry else {
        return parse_v1(&lines);
    };
    if !ethernets_value.trim().is_empty() {
        let mut candidates = Vec::new();
        for (name, value) in flow_mapping(ethernets_value)? {
            let mut network = parse_v2_interface_flow(&value)?;
            network.interface_name = Some(name);
            candidates.push(network);
        }
        candidates.sort_by(|left, right| left.interface_name.cmp(&right.interface_name));
        return Ok(candidates
            .into_iter()
            .find(StaticNetwork::is_seedable)
            .unwrap_or_default());
    }
    let ethernets_indent = lines[ethernets_index].indent;
    let ethernet_end = lines
        .iter()
        .enumerate()
        .skip(ethernets_index + 1)
        .find_map(|(index, line)| (line.indent <= ethernets_indent).then_some(index))
        .unwrap_or(lines.len());
    let ethernet_lines = &lines[ethernets_index + 1..ethernet_end];
    let Some(interface_indent) = ethernet_lines.iter().map(|line| line.indent).min() else {
        return Ok(StaticNetwork::default());
    };
    let mut candidates = Vec::new();
    let mut index = 0;
    while index < ethernet_lines.len() {
        let line = &ethernet_lines[index];
        if line.indent != interface_indent {
            index += 1;
            continue;
        }
        let Some((name, value)) = key_value(line.text)? else {
            index += 1;
            continue;
        };
        let interface_name = nonempty_scalar(name)?
            .ok_or_else(|| anyhow!("empty netplan ethernet interface name"))?;
        let end = ethernet_lines
            .iter()
            .enumerate()
            .skip(index + 1)
            .find_map(|(next, nested)| (nested.indent <= interface_indent).then_some(next))
            .unwrap_or(ethernet_lines.len());
        let mut network = if value.trim().is_empty() {
            parse_v2_interface(&ethernet_lines[index + 1..end], interface_indent)?
        } else {
            parse_v2_interface_flow(value)?
        };
        network.interface_name = Some(interface_name);
        candidates.push(network);
        index = end;
    }
    // YAML mapping order is not semantic. Pick the lexicographically first
    // seedable interface so equivalent documents cannot change link selection
    // merely by reordering keys.
    candidates.sort_by(|left, right| left.interface_name.cmp(&right.interface_name));
    Ok(candidates
        .into_iter()
        .find(StaticNetwork::is_seedable)
        .unwrap_or_default())
}

fn parse_v1(lines: &[Line<'_>]) -> Result<StaticNetwork> {
    let Some((physical_index, physical_indent)) =
        lines.iter().enumerate().find_map(|(index, line)| {
            let item = line.text.strip_prefix('-')?.trim();
            let (key, value) = key_value(item).ok().flatten()?;
            (key == "type" && value == "physical").then_some((index, line.indent))
        })
    else {
        return Ok(StaticNetwork::default());
    };
    let physical_end = lines
        .iter()
        .enumerate()
        .skip(physical_index + 1)
        .find_map(|(index, line)| {
            (line.indent == physical_indent && line.text.starts_with('-')).then_some(index)
        })
        .unwrap_or(lines.len());
    let physical = &lines[physical_index + 1..physical_end];
    let mut network = StaticNetwork::default();
    for line in physical {
        if let Some((key, value)) = key_value(line.text)? {
            match key {
                "mac_address" | "macaddress" => {
                    network.mac = nonempty_scalar(value)?.map(|mac| mac.to_lowercase());
                }
                "name" => network.interface_name = nonempty_scalar(value)?,
                _ => {}
            }
        }
    }

    let Some((subnet_index, subnet_indent)) =
        physical.iter().enumerate().find_map(|(index, line)| {
            let item = line.text.strip_prefix('-')?.trim();
            let (key, value) = key_value(item).ok().flatten()?;
            (key == "type" && value == "static").then_some((index, line.indent))
        })
    else {
        return Ok(network);
    };
    let subnet_end = physical
        .iter()
        .enumerate()
        .skip(subnet_index + 1)
        .find_map(|(index, line)| {
            (line.indent <= subnet_indent && line.text.starts_with('-')).then_some(index)
        })
        .unwrap_or(physical.len());
    let subnet = &physical[subnet_index + 1..subnet_end];
    let mut address = None;
    let mut netmask = None;
    let mut index = 0;
    while index < subnet.len() {
        let line = &subnet[index];
        let Some((key, value)) = key_value(line.text)? else {
            index += 1;
            continue;
        };
        match key {
            "address" => address = nonempty_scalar(value)?,
            "netmask" => netmask = nonempty_scalar(value)?,
            "gateway" => network.gateway = nonempty_scalar(value)?,
            "dns_nameservers" if value.trim().is_empty() => {
                network.dns = block_list(subnet, index, line.indent)?;
            }
            "dns_nameservers" => network.dns = inline_list(value)?,
            _ => {}
        }
        index += 1;
    }
    if let Some(address) = address {
        network.addresses.push(match netmask {
            Some(netmask) if !address.contains('/') => format!(
                "{address}/{}",
                super::staticnet::netmask_to_prefix(&netmask)
            ),
            _ => address,
        });
    }
    Ok(network)
}

fn parse_v2_interface(lines: &[Line<'_>], interface_indent: usize) -> Result<StaticNetwork> {
    let mut network = StaticNetwork::default();
    let direct_indent = lines
        .iter()
        .filter(|line| line.indent > interface_indent)
        .map(|line| line.indent)
        .min()
        .unwrap_or(interface_indent + 1);
    let mut index = 0;
    while index < lines.len() {
        let line = &lines[index];
        if line.indent != direct_indent {
            index += 1;
            continue;
        }
        let Some((key, value)) = key_value(line.text)? else {
            index += 1;
            continue;
        };
        if line.indent <= interface_indent {
            break;
        }
        match key {
            "addresses" if value.trim().is_empty() => {
                network.addresses = block_list(lines, index, line.indent)?;
            }
            "addresses" => network.addresses = inline_list(value)?,
            "gateway4" | "gateway6" if network.gateway.is_none() => {
                network.gateway = nonempty_scalar(value)?;
            }
            "nameservers" if value.trim().is_empty() => {
                if let Some((nested_index, nested)) = lines
                    .iter()
                    .enumerate()
                    .skip(index + 1)
                    .take_while(|(_, nested)| nested.indent > line.indent)
                    .find_map(|(nested_index, nested)| {
                        let (nested_key, nested_value) = key_value(nested.text).ok().flatten()?;
                        (nested_key == "addresses")
                            .then_some((nested_index, (nested, nested_value)))
                    })
                {
                    network.dns = if nested.1.trim().is_empty() {
                        block_list(lines, nested_index, nested.0.indent)?
                    } else {
                        inline_list(nested.1)?
                    };
                }
            }
            "nameservers" => {
                let mapping = flow_mapping(value)?;
                if let Some(addresses) = mapping.get("addresses") {
                    network.dns = inline_list(addresses)?;
                }
            }
            "match" if value.trim().is_empty() => {
                network.mac = nested_scalar(lines, index, line.indent, "macaddress")?
                    .map(|mac| mac.to_lowercase());
            }
            "match" => {
                let mapping = flow_mapping(value)?;
                network.mac = mapping
                    .get("macaddress")
                    .map(String::as_str)
                    .map(nonempty_scalar)
                    .transpose()?
                    .flatten()
                    .map(|mac| mac.to_lowercase());
            }
            "routes" if value.trim().starts_with('[') && network.gateway.is_none() => {
                network.gateway = flow_routes_gateway(value)?;
            }
            "routes" if value.trim().is_empty() && network.gateway.is_none() => {
                network.gateway = block_routes_gateway(lines, index, line.indent)?;
            }
            _ => {}
        }
        index += 1;
    }
    Ok(network)
}

fn parse_v2_interface_flow(value: &str) -> Result<StaticNetwork> {
    let mapping = flow_mapping(value)?;
    let mut network = StaticNetwork::default();
    if let Some(addresses) = mapping.get("addresses") {
        network.addresses = inline_list(addresses)?;
    }
    network.gateway = mapping
        .get("gateway4")
        .or_else(|| mapping.get("gateway6"))
        .map(String::as_str)
        .map(nonempty_scalar)
        .transpose()?
        .flatten();
    if let Some(match_value) = mapping.get("match") {
        network.mac = flow_mapping(match_value)?
            .get("macaddress")
            .map(String::as_str)
            .map(nonempty_scalar)
            .transpose()?
            .flatten()
            .map(|mac| mac.to_lowercase());
    }
    if let Some(nameservers) = mapping.get("nameservers")
        && let Some(addresses) = flow_mapping(nameservers)?.get("addresses")
    {
        network.dns = inline_list(addresses)?;
    }
    if network.gateway.is_none()
        && let Some(routes) = mapping.get("routes")
    {
        network.gateway = flow_routes_gateway(routes)?;
    }
    Ok(network)
}

fn block_routes_gateway(
    lines: &[Line<'_>],
    parent_index: usize,
    parent_indent: usize,
) -> Result<Option<String>> {
    let mut default_route = false;
    for line in lines.iter().skip(parent_index + 1) {
        if line.indent <= parent_indent {
            break;
        }
        let text = line
            .text
            .strip_prefix('-')
            .map(str::trim)
            .unwrap_or(line.text);
        if text.starts_with('{') {
            if let Some(gateway) = route_mapping_gateway(&flow_mapping(text)?)? {
                return Ok(Some(gateway));
            }
            continue;
        }
        let Some((key, value)) = key_value(text)? else {
            continue;
        };
        match key {
            "to" => {
                default_route = nonempty_scalar(value)?
                    .is_some_and(|to| matches!(to.as_str(), "default" | "0.0.0.0/0" | "::/0"));
            }
            "via" if default_route => return nonempty_scalar(value),
            _ => {}
        }
    }
    Ok(None)
}

fn flow_routes_gateway(value: &str) -> Result<Option<String>> {
    for item in flow_sequence_items(value)? {
        if let Some(gateway) = route_mapping_gateway(&flow_mapping(item)?)? {
            return Ok(Some(gateway));
        }
    }
    Ok(None)
}

fn route_mapping_gateway(mapping: &BTreeMap<String, String>) -> Result<Option<String>> {
    let is_default = match mapping.get("to") {
        Some(to) => nonempty_scalar(to)?
            .is_some_and(|to| matches!(to.as_str(), "default" | "0.0.0.0/0" | "::/0")),
        None => false,
    };
    if !is_default {
        return Ok(None);
    }
    mapping
        .get("via")
        .map(String::as_str)
        .map(nonempty_scalar)
        .transpose()
        .map(Option::flatten)
}

fn nested_scalar(
    lines: &[Line<'_>],
    parent_index: usize,
    parent_indent: usize,
    wanted: &str,
) -> Result<Option<String>> {
    for line in lines.iter().skip(parent_index + 1) {
        if line.indent <= parent_indent {
            break;
        }
        if let Some((key, value)) = key_value(line.text)?
            && key == wanted
        {
            return nonempty_scalar(value);
        }
    }
    Ok(None)
}

fn block_list(
    lines: &[Line<'_>],
    parent_index: usize,
    parent_indent: usize,
) -> Result<Vec<String>> {
    let mut values = Vec::new();
    for line in lines.iter().skip(parent_index + 1) {
        if line.indent <= parent_indent {
            break;
        }
        let Some(value) = line.text.strip_prefix('-') else {
            continue;
        };
        if let Some(value) = nonempty_scalar(value)? {
            values.push(value);
        }
    }
    Ok(values)
}

fn inline_list(value: &str) -> Result<Vec<String>> {
    flow_sequence_items(value)?
        .into_iter()
        .map(|item| {
            nonempty_scalar(item)?.ok_or_else(|| anyhow!("empty item in YAML flow sequence"))
        })
        .collect()
}

fn flow_sequence_items(value: &str) -> Result<Vec<&str>> {
    let value = value.trim();
    let inner = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| anyhow!("expected a YAML flow sequence, got {value:?}"))?;
    split_flow_items(inner)
}

fn flow_mapping(value: &str) -> Result<BTreeMap<String, String>> {
    let value = value.trim();
    let inner = value
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .ok_or_else(|| anyhow!("expected a YAML flow mapping, got {value:?}"))?;
    let mut result = BTreeMap::new();
    for item in split_flow_items(inner)? {
        let (key, value) = split_mapping_entry(item)?;
        let key = nonempty_scalar(key)?.ok_or_else(|| anyhow!("empty key in YAML flow mapping"))?;
        if result
            .insert(key.clone(), value.trim().to_string())
            .is_some()
        {
            bail!("duplicate key {key:?} in YAML flow mapping");
        }
    }
    Ok(result)
}

fn split_flow_items(value: &str) -> Result<Vec<&str>> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut items = Vec::new();
    let mut start = 0;
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let mut square_depth = 0_u32;
    let mut brace_depth = 0_u32;
    for (index, ch) in value.char_indices() {
        if double && escaped {
            escaped = false;
            continue;
        }
        if double && ch == '\\' {
            escaped = true;
            continue;
        }
        match ch {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '[' if !single && !double => square_depth += 1,
            ']' if !single && !double => {
                square_depth = square_depth
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("unbalanced ']' in YAML flow value"))?;
            }
            '{' if !single && !double => brace_depth += 1,
            '}' if !single && !double => {
                brace_depth = brace_depth
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("unbalanced '}}' in YAML flow value"))?;
            }
            ',' if !single && !double && square_depth == 0 && brace_depth == 0 => {
                let item = value[start..index].trim();
                if item.is_empty() {
                    bail!("empty item in YAML flow value");
                }
                items.push(item);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    if single || double || square_depth != 0 || brace_depth != 0 {
        bail!("unterminated YAML flow value {value:?}");
    }
    let item = value[start..].trim();
    if item.is_empty() {
        bail!("empty item in YAML flow value");
    }
    items.push(item);
    Ok(items)
}

fn split_mapping_entry(value: &str) -> Result<(&str, &str)> {
    let mut single = false;
    let mut double = false;
    let mut square_depth = 0_u32;
    let mut brace_depth = 0_u32;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if double && escaped {
            escaped = false;
            continue;
        }
        if double && ch == '\\' {
            escaped = true;
            continue;
        }
        match ch {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '[' if !single && !double => square_depth += 1,
            ']' if !single && !double => square_depth = square_depth.saturating_sub(1),
            '{' if !single && !double => brace_depth += 1,
            '}' if !single && !double => brace_depth = brace_depth.saturating_sub(1),
            ':' if !single && !double && square_depth == 0 && brace_depth == 0 => {
                let key = value[..index].trim();
                if key.is_empty() {
                    bail!("empty YAML mapping key");
                }
                return Ok((key, value[index + ch.len_utf8()..].trim()));
            }
            _ => {}
        }
    }
    bail!("expected a YAML mapping entry, got {value:?}")
}

fn nonempty_scalar(value: &str) -> Result<Option<String>> {
    let value = value.trim();
    if value.is_empty() || matches!(value, "null" | "~") {
        return Ok(None);
    }
    if let Some(value) = value.strip_prefix('"') {
        let quoted = format!("\"{value}");
        return serde_json::from_str::<String>(&quoted)
            .map(Some)
            .context("parsing double-quoted YAML scalar");
    }
    if let Some(value) = value.strip_prefix('\'') {
        let Some(value) = value.strip_suffix('\'') else {
            bail!("unterminated single-quoted YAML scalar");
        };
        return Ok(Some(value.replace("''", "'")));
    }
    Ok(Some(value.to_string()))
}

fn key_value(line: &str) -> Result<Option<(&str, &str)>> {
    if line.starts_with('-') {
        return Ok(None);
    }
    split_mapping_entry(line).map(Some)
}

fn lines(bytes: &[u8]) -> Result<Vec<Line<'_>>> {
    let document = std::str::from_utf8(bytes).context("NoCloud YAML is not UTF-8")?;
    let mut parsed = Vec::new();
    for raw in document.lines() {
        if raw.contains('\t') {
            bail!("tabs are not permitted in NoCloud YAML indentation");
        }
        let indent = raw.len() - raw.trim_start_matches(' ').len();
        let text = strip_comment(raw[indent..].trim_end());
        if text.is_empty() || matches!(text, "---" | "...") {
            continue;
        }
        parsed.push(Line { indent, text });
    }
    Ok(parsed)
}

fn strip_comment(value: &str) -> &str {
    let mut single = false;
    let mut double = false;
    for (index, ch) in value.char_indices() {
        match ch {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '#' if !single && !double && (index == 0 || value.as_bytes()[index - 1] == b' ') => {
                return value[..index].trim_end();
            }
            _ => {}
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_supports_quotes_and_comments() {
        let parsed =
            parse_metadata(b"instance-id: 'iid-local01' # fixture\nlocal-hostname: \"web-1\"\n")
                .unwrap();
        assert_eq!(parsed.instance_id.as_deref(), Some("iid-local01"));
        assert_eq!(parsed.hostname.as_deref(), Some("web-1"));
    }

    #[test]
    fn netplan_supports_flow_and_block_sequences() {
        let parsed = parse_netplan(
            b"network:\n  version: 2\n  ethernets:\n    ens3:\n      addresses:\n        - 192.0.2.2/24\n      gateway4: 192.0.2.1\n      nameservers:\n        addresses: [1.1.1.1, 9.9.9.9]\n",
        )
        .unwrap();
        assert_eq!(parsed.addresses, ["192.0.2.2/24"]);
        assert_eq!(parsed.dns, ["1.1.1.1", "9.9.9.9"]);
    }

    #[test]
    fn netplan_v1_static_subnet_is_supported() {
        let parsed = parse_netplan(
            b"version: 1\nconfig:\n  - type: physical\n    name: eth0\n    mac_address: 0A:1B:2C:3D:4E:5F\n    subnets:\n      - type: static\n        address: 192.0.2.2\n        netmask: 255.255.255.0\n        gateway: 192.0.2.1\n        dns_nameservers:\n          - 1.1.1.1\n",
        )
        .unwrap();
        assert_eq!(parsed.addresses, ["192.0.2.2/24"]);
        assert_eq!(parsed.gateway.as_deref(), Some("192.0.2.1"));
        assert_eq!(parsed.dns, ["1.1.1.1"]);
        assert_eq!(parsed.mac.as_deref(), Some("0a:1b:2c:3d:4e:5f"));
    }

    #[test]
    fn tabs_fail_closed() {
        assert!(parse_metadata(b"\tinstance-id: bad\n").is_err());
    }
}
