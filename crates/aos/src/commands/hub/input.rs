//! Parses shared command-line durations, timestamps, references, and canonical networks.

use anyhow::{Context as _, Result};

/// Parses a CLI duration into a checked number of seconds.
///
/// # Errors
///
/// Returns an error if the duration is invalid or exceeds the supported range.
pub(in crate::commands) fn parse_duration_seconds(value: &str, flag: &str) -> Result<i64> {
    let duration: std::time::Duration = value
        .parse::<humantime::Duration>()
        .with_context(|| format!("invalid duration for {flag}"))?
        .into();
    i64::try_from(duration.as_secs()).with_context(|| format!("{flag} is too large"))
}

/// Parses a CLI timestamp into Unix seconds.
///
/// # Errors
///
/// Returns an error if the timestamp is invalid, an RFC 3339 value precedes the
/// Unix epoch, or its seconds exceed the supported range.
pub(super) fn parse_timestamp(value: &str, flag: &str) -> Result<i64> {
    if let Ok(seconds) = value.parse::<i64>() {
        return Ok(seconds);
    }
    let timestamp = humantime::parse_rfc3339(value)
        .with_context(|| format!("invalid RFC 3339 timestamp for {flag}"))?;
    let seconds = timestamp
        .duration_since(std::time::UNIX_EPOCH)
        .with_context(|| format!("{flag} must not precede the Unix epoch"))?
        .as_secs();
    i64::try_from(seconds).with_context(|| format!("{flag} is too large"))
}

/// Sorts values and removes duplicates.
pub(super) fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

/// Validates that a CIDR names a canonical network prefix.
///
/// # Errors
///
/// Returns an error if the CIDR is invalid or contains host bits.
pub(super) fn canonical_cidr(value: &str) -> Result<String> {
    let (address, prefix) = value
        .split_once('/')
        .context("CIDRs use <address>/<prefix-length>")?;
    let address: std::net::IpAddr = address.parse().context("parsing CIDR address")?;
    let prefix: u32 = prefix.parse().context("parsing CIDR prefix length")?;
    let is_network = match address {
        std::net::IpAddr::V4(address) if prefix <= 32 => {
            let bits = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            bits & mask == bits
        }
        std::net::IpAddr::V6(address) if prefix <= 128 => {
            let bits = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            bits & mask == bits
        }
        _ => false,
    };
    if !is_network {
        anyhow::bail!("CIDR '{value}' is not a canonical network prefix");
    }
    Ok(format!("{address}/{prefix}"))
}

/// Parses a resource identity and its positive generation.
///
/// # Errors
///
/// Returns an error if the reference does not contain a valid positive generation.
pub(super) fn parse_generation_ref(value: &str, kind: &str) -> Result<(String, i64)> {
    let (stable_id, generation) = value
        .rsplit_once('@')
        .with_context(|| format!("{kind} refs use <stable-id>@<generation>"))?;
    if stable_id.is_empty() {
        anyhow::bail!("{kind} refs require a non-empty stable id");
    }
    let generation = generation
        .parse::<i64>()
        .with_context(|| format!("parsing {kind} generation"))?;
    if generation <= 0 {
        anyhow::bail!("{kind} generations must be positive");
    }
    Ok((stable_id.into(), generation))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parser_requires_a_canonical_network_prefix() {
        assert_eq!(canonical_cidr("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert!(canonical_cidr("10.0.0.1/8").is_err());
        assert!(canonical_cidr("2001:db8::1/32").is_err());
        assert_eq!(canonical_cidr("2001:db8::/32").unwrap(), "2001:db8::/32");
    }
}
