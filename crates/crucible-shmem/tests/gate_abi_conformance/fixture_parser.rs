//! Frozen ABI fixture parsing and hex decoding.

use super::*;

pub(super) fn parse_fixture(fixture: &str) -> Result<Fixture, String> {
    let mut abi_version = None;
    let mut total_len = None;
    let mut segments = Vec::new();

    for (line_index, raw_line) in fixture.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {line_number}: missing `=`"))?;
        match key {
            "abi_version" => {
                abi_version = Some(parse_u32_value(value, line_number, "abi_version")?);
            }
            "total_len" => {
                total_len = Some(parse_usize_value(value, line_number, "total_len")?);
            }
            offset => {
                let offset = parse_usize_value(offset, line_number, "offset")?;
                let bytes = parse_hex_bytes(value, line_number)?;
                segments.push((offset, bytes));
            }
        }
    }

    let abi_version = abi_version.ok_or_else(|| "fixture missing abi_version".to_string())?;
    let total_len = total_len.ok_or_else(|| "fixture missing total_len".to_string())?;
    let mut bytes = vec![0; total_len];
    for (offset, segment) in segments {
        let end = offset
            .checked_add(segment.len())
            .ok_or_else(|| format!("fixture segment at {offset} overflows"))?;
        if end > bytes.len() {
            return Err(format!(
                "fixture segment at {offset} extends past total_len {total_len}"
            ));
        }
        bytes[offset..end].copy_from_slice(&segment);
    }

    Ok(Fixture { abi_version, bytes })
}

pub(super) fn parse_u32_value(value: &str, line_number: usize, label: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|error| format!("line {line_number}: invalid {label}: {error}"))
}

pub(super) fn parse_usize_value(
    value: &str,
    line_number: usize,
    label: &str,
) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|error| format!("line {line_number}: invalid {label}: {error}"))
}

pub(super) fn parse_hex_bytes(hex: &str, line_number: usize) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("line {line_number}: hex payload has odd length"));
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair_index in 0..hex.len() / 2 {
        let start = pair_index * 2;
        let end = start + 2;
        let pair = &hex[start..end];
        if !pair.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            return Err(format!("line {line_number}: invalid hex pair `{pair}`"));
        }
        let value = u8::from_str_radix(pair, 16)
            .map_err(|error| format!("line {line_number}: invalid hex pair `{pair}`: {error}"))?;
        bytes.push(value);
    }
    Ok(bytes)
}
