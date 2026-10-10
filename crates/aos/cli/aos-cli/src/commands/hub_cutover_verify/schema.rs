//! Closed `aos-cutover-schema/v1` dialect evaluation.
//!
//! Only local references, the explicitly enumerated keywords, Rust-regex
//! patterns, `utc-date-time`, and `https-or-path-uri` are accepted.

use std::collections::{BTreeSet, HashSet};

use anyhow::{Context as _, Result, anyhow, bail};
use serde_json::Value;

use super::canonical::canonical_json;
use super::{DIALECT_NAME, DIALECT_URI};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SchemaFailureCode {
    TypeMismatch,
    UnknownProperty,
}

#[derive(Debug)]
pub(super) struct SchemaFailure {
    pub(super) code: SchemaFailureCode,
    message: String,
}

impl std::fmt::Display for SchemaFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SchemaFailure {}

fn schema_failure(code: SchemaFailureCode, message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(SchemaFailure {
        code,
        message: message.into(),
    })
}

/// Validates one instance against a schema in the closed cutover dialect.
pub(super) fn validate_schema(schema: &Value, instance: &Value, label: &str) -> Result<()> {
    if schema.get("$schema").and_then(Value::as_str) != Some(DIALECT_URI) {
        bail!("unsupported_schema_dialect for {label}");
    }
    if schema.get("dialect").and_then(Value::as_str) != Some(DIALECT_NAME) {
        bail!("schema does not declare {DIALECT_NAME}");
    }
    audit_schema(schema, "")?;
    audit_reference_cycles(schema)?;
    matches_schema(schema, schema, instance, "")
        .with_context(|| format!("schema_validation_failed for {label}"))?;
    Ok(())
}

fn audit_reference_cycles(root: &Value) -> Result<()> {
    fn walk(
        root: &Value,
        schema: &Value,
        active: &mut Vec<(String, bool)>,
        steps: &mut usize,
        depth: usize,
    ) -> Result<()> {
        *steps += 1;
        if depth > 256 || *steps > 65_536 {
            bail!("schema_reference_limit_exceeded");
        }
        let Some(object) = schema.as_object() else {
            return Ok(());
        };
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            if let Some((_, productive)) = active.iter().rev().find(|(item, _)| item == reference) {
                if *productive {
                    return Ok(());
                }
                bail!("cyclic_schema_reference: {reference}");
            }
            active.push((reference.to_owned(), false));
            walk(
                root,
                resolve_reference(root, reference)?,
                active,
                steps,
                depth + 1,
            )?;
            active.pop();
        }
        if let Some(children) = object.get("properties").and_then(Value::as_object) {
            for child in children.values() {
                let mut productive = active.clone();
                productive
                    .iter_mut()
                    .for_each(|(_, crossed)| *crossed = true);
                walk(root, child, &mut productive, steps, depth + 1)?;
            }
        }
        if let Some(children) = object.get("$defs").and_then(Value::as_object) {
            for child in children.values() {
                walk(root, child, active, steps, depth + 1)?;
            }
        }
        for keyword in ["items", "additionalProperties", "unevaluatedProperties"] {
            if let Some(child) = object.get(keyword) {
                let mut productive = active.clone();
                productive
                    .iter_mut()
                    .for_each(|(_, crossed)| *crossed = true);
                walk(root, child, &mut productive, steps, depth + 1)?;
            }
        }
        for keyword in ["not", "if", "then", "else"] {
            if let Some(child) = object.get(keyword) {
                walk(root, child, active, steps, depth + 1)?;
            }
        }
        for keyword in ["allOf", "anyOf", "oneOf"] {
            if let Some(children) = object.get(keyword).and_then(Value::as_array) {
                for child in children {
                    walk(root, child, active, steps, depth + 1)?;
                }
            }
        }
        Ok(())
    }

    let mut steps = 0;
    walk(root, root, &mut Vec::new(), &mut steps, 0)
}

fn audit_schema(schema: &Value, path: &str) -> Result<()> {
    audit_schema_at(schema, path, 0)
}

fn audit_schema_at(schema: &Value, path: &str, depth: usize) -> Result<()> {
    if depth > 256 {
        bail!("schema_nesting_limit_exceeded at {path}");
    }
    const SUPPORTED: &[&str] = &[
        "$schema",
        "$id",
        "$defs",
        "$ref",
        "dialect",
        "title",
        "description",
        "type",
        "const",
        "enum",
        "properties",
        "required",
        "additionalProperties",
        "unevaluatedProperties",
        "items",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minLength",
        "maxLength",
        "pattern",
        "format",
        "minimum",
        "maximum",
        "allOf",
        "anyOf",
        "oneOf",
        "not",
        "if",
        "then",
        "else",
        "default",
        "examples",
        "deprecated",
        "readOnly",
        "writeOnly",
    ];
    let Some(object) = schema.as_object() else {
        if schema.is_boolean() {
            return Ok(());
        }
        bail!("schema at {path} is neither an object nor boolean");
    };
    for name in object.keys() {
        if !SUPPORTED.contains(&name.as_str()) {
            bail!("unsupported_schema_keyword at {path}/{name}");
        }
    }
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        if reference != "#" && !reference.starts_with("#/") {
            bail!("non-local schema reference at {path}");
        }
    }
    if let Some(format) = object.get("format").and_then(Value::as_str) {
        if !matches!(format, "utc-date-time" | "https-or-path-uri") {
            bail!("unsupported schema format: {format}");
        }
    }
    if let Some(pattern) = object.get("pattern").and_then(Value::as_str) {
        regex::Regex::new(pattern).with_context(|| format!("unsupported Rust regex at {path}"))?;
    }
    for keyword in ["properties", "$defs"] {
        if let Some(children) = object.get(keyword) {
            for (name, child) in children
                .as_object()
                .ok_or_else(|| anyhow!("{path}/{keyword} must be an object"))?
            {
                audit_schema_at(child, &format!("{path}/{keyword}/{name}"), depth + 1)?;
            }
        }
    }
    for keyword in [
        "items",
        "additionalProperties",
        "unevaluatedProperties",
        "not",
        "if",
        "then",
        "else",
    ] {
        if let Some(child) = object.get(keyword) {
            if child.is_object() || child.is_boolean() {
                audit_schema_at(child, &format!("{path}/{keyword}"), depth + 1)?;
            }
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(children) = object.get(keyword) {
            for (index, child) in children
                .as_array()
                .ok_or_else(|| anyhow!("{path}/{keyword} must be an array"))?
                .iter()
                .enumerate()
            {
                audit_schema_at(child, &format!("{path}/{keyword}/{index}"), depth + 1)?;
            }
        }
    }
    Ok(())
}

fn matches_schema(root: &Value, schema: &Value, instance: &Value, path: &str) -> Result<()> {
    if let Some(allowed) = schema.as_bool() {
        if allowed {
            return Ok(());
        }
        bail!("false schema rejects {path}");
    }
    let object = schema
        .as_object()
        .ok_or_else(|| anyhow!("schema at {path} must be an object"))?;
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        matches_schema(root, resolve_reference(root, reference)?, instance, path)?;
    }
    if let Some(types) = object.get("type") {
        let names: Vec<&str> = match types {
            Value::String(name) => vec![name],
            Value::Array(values) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| anyhow!("type entry is not a string"))
                })
                .collect::<Result<_>>()?,
            _ => bail!("schema type is not a string or array"),
        };
        let matches = names
            .iter()
            .map(|name| instance_has_type(instance, name))
            .collect::<Result<Vec<_>>>()?;
        if !matches.into_iter().any(|matched| matched) {
            return Err(schema_failure(
                SchemaFailureCode::TypeMismatch,
                format!("schema type mismatch at {path}"),
            ));
        }
    }
    if object
        .get("const")
        .is_some_and(|expected| expected != instance)
    {
        bail!("const_mismatch at {path}");
    }
    if let Some(values) = object.get("enum") {
        if !values
            .as_array()
            .ok_or_else(|| anyhow!("enum must be an array"))?
            .contains(instance)
        {
            bail!("enum_mismatch at {path}");
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = object.get(keyword) {
            let results: Vec<bool> = branches
                .as_array()
                .ok_or_else(|| anyhow!("{keyword} must be an array"))?
                .iter()
                .map(|branch| matches_schema(root, branch, instance, path).is_ok())
                .collect();
            let valid = match keyword {
                "allOf" => results.iter().all(|value| *value),
                "anyOf" => results.iter().any(|value| *value),
                "oneOf" => results.iter().filter(|value| **value).count() == 1,
                _ => false,
            };
            if !valid {
                bail!("{keyword} mismatch at {path}");
            }
        }
    }
    if object
        .get("not")
        .is_some_and(|negated| matches_schema(root, negated, instance, path).is_ok())
    {
        bail!("not schema matched at {path}");
    }
    if let Some(condition) = object.get("if") {
        let branch = if matches_schema(root, condition, instance, path).is_ok() {
            object.get("then")
        } else {
            object.get("else")
        };
        if let Some(branch) = branch {
            matches_schema(root, branch, instance, path)?;
        }
    }
    validate_object(root, object, instance, path)?;
    validate_array(root, object, instance, path)?;
    validate_string(object, instance, path)?;
    validate_integer(object, instance, path)?;
    Ok(())
}

fn validate_object(
    root: &Value,
    schema: &serde_json::Map<String, Value>,
    instance: &Value,
    path: &str,
) -> Result<()> {
    let Some(instance) = instance.as_object() else {
        return Ok(());
    };
    if let Some(required) = schema.get("required") {
        for name in required
            .as_array()
            .ok_or_else(|| anyhow!("required must be an array"))?
        {
            let name = name
                .as_str()
                .ok_or_else(|| anyhow!("required entry is not a string"))?;
            if !instance.contains_key(name) {
                bail!("missing required property {path}/{name}");
            }
        }
    }
    if let Some(properties) = schema.get("properties") {
        for (name, property_schema) in properties
            .as_object()
            .ok_or_else(|| anyhow!("properties must be an object"))?
        {
            if let Some(child) = instance.get(name) {
                matches_schema(root, property_schema, child, &format!("{path}/{name}"))?;
            }
        }
    }
    let mut evaluated = BTreeSet::new();
    collect_evaluated_properties(
        root,
        &Value::Object(schema.clone()),
        instance,
        &mut evaluated,
    )?;
    if let Some(additional) = schema.get("additionalProperties") {
        for (name, child) in instance {
            if evaluated.contains(name) {
                continue;
            }
            match additional {
                Value::Bool(true) => {}
                Value::Bool(false) => {
                    return Err(schema_failure(
                        SchemaFailureCode::UnknownProperty,
                        format!("unknown property at {path}/{name}"),
                    ));
                }
                _ => matches_schema(root, additional, child, &format!("{path}/{name}"))?,
            }
            evaluated.insert(name.clone());
        }
    }
    if let Some(unevaluated) = schema.get("unevaluatedProperties") {
        for (name, child) in instance {
            if evaluated.contains(name) {
                continue;
            }
            match unevaluated {
                Value::Bool(true) => {}
                Value::Bool(false) => {
                    return Err(schema_failure(
                        SchemaFailureCode::UnknownProperty,
                        format!("unknown property at {path}/{name}"),
                    ));
                }
                _ => matches_schema(root, unevaluated, child, &format!("{path}/{name}"))?,
            }
        }
    }
    Ok(())
}

fn collect_evaluated_properties(
    root: &Value,
    schema: &Value,
    instance: &serde_json::Map<String, Value>,
    output: &mut BTreeSet<String>,
) -> Result<()> {
    let Some(object) = schema.as_object() else {
        return Ok(());
    };
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        collect_evaluated_properties(root, resolve_reference(root, reference)?, instance, output)?;
    }
    if let Some(properties) = object.get("properties").and_then(Value::as_object) {
        output.extend(
            properties
                .keys()
                .filter(|name| instance.contains_key(*name))
                .cloned(),
        );
    }
    if let Some(branches) = object.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            collect_evaluated_properties(root, branch, instance, output)?;
        }
    }
    let instance_value = Value::Object(instance.clone());
    for keyword in ["anyOf", "oneOf"] {
        if let Some(branches) = object.get(keyword).and_then(Value::as_array) {
            for branch in branches {
                if matches_schema(root, branch, &instance_value, "").is_ok() {
                    collect_evaluated_properties(root, branch, instance, output)?;
                }
            }
        }
    }
    if let Some(condition) = object.get("if") {
        let branch = if matches_schema(root, condition, &instance_value, "").is_ok() {
            object.get("then")
        } else {
            object.get("else")
        };
        if let Some(branch) = branch {
            collect_evaluated_properties(root, branch, instance, output)?;
        }
    }
    Ok(())
}

fn validate_array(
    root: &Value,
    schema: &serde_json::Map<String, Value>,
    instance: &Value,
    path: &str,
) -> Result<()> {
    let Some(values) = instance.as_array() else {
        return Ok(());
    };
    if schema
        .get("minItems")
        .and_then(Value::as_u64)
        .is_some_and(|minimum| values.len() < minimum as usize)
    {
        bail!("minItems mismatch at {path}");
    }
    if schema
        .get("maxItems")
        .and_then(Value::as_u64)
        .is_some_and(|maximum| values.len() > maximum as usize)
    {
        bail!("maxItems mismatch at {path}");
    }
    if schema.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
        let unique: HashSet<Vec<u8>> = values.iter().map(canonical_json).collect::<Result<_>>()?;
        if unique.len() != values.len() {
            bail!("uniqueItems mismatch at {path}");
        }
    }
    if let Some(item_schema) = schema.get("items") {
        for (index, child) in values.iter().enumerate() {
            matches_schema(root, item_schema, child, &format!("{path}/{index}"))?;
        }
    }
    Ok(())
}

fn validate_string(
    schema: &serde_json::Map<String, Value>,
    instance: &Value,
    path: &str,
) -> Result<()> {
    let Some(text) = instance.as_str() else {
        return Ok(());
    };
    let length = text.chars().count() as u64;
    if schema
        .get("minLength")
        .and_then(Value::as_u64)
        .is_some_and(|minimum| length < minimum)
    {
        bail!("minLength mismatch at {path}");
    }
    if schema
        .get("maxLength")
        .and_then(Value::as_u64)
        .is_some_and(|maximum| length > maximum)
    {
        bail!("maxLength mismatch at {path}");
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        if !regex::Regex::new(pattern)?.is_match(text) {
            bail!("pattern mismatch at {path}");
        }
    }
    if let Some(format) = schema.get("format").and_then(Value::as_str) {
        match format {
            "utc-date-time" => validate_utc_date_time(text)?,
            "https-or-path-uri" => validate_https_or_path_uri(text)?,
            _ => bail!("unsupported schema format: {format}"),
        }
    }
    Ok(())
}

fn validate_integer(
    schema: &serde_json::Map<String, Value>,
    instance: &Value,
    path: &str,
) -> Result<()> {
    let Some(integer) = instance
        .as_i64()
        .map(i128::from)
        .or_else(|| instance.as_u64().map(i128::from))
    else {
        return Ok(());
    };
    if schema
        .get("minimum")
        .and_then(Value::as_i64)
        .is_some_and(|minimum| integer < i128::from(minimum))
    {
        bail!("minimum mismatch at {path}");
    }
    if schema
        .get("maximum")
        .and_then(Value::as_i64)
        .is_some_and(|maximum| integer > i128::from(maximum))
    {
        bail!("maximum mismatch at {path}");
    }
    Ok(())
}

fn instance_has_type(instance: &Value, name: &str) -> Result<bool> {
    Ok(match name {
        "null" => instance.is_null(),
        "boolean" => instance.is_boolean(),
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
        unknown => bail!("unsupported schema type: {unknown}"),
    })
}

fn resolve_reference<'a>(root: &'a Value, reference: &str) -> Result<&'a Value> {
    if reference == "#" {
        return Ok(root);
    }
    let pointer = reference
        .strip_prefix('#')
        .ok_or_else(|| anyhow!("non-local schema reference: {reference}"))?;
    root.pointer(pointer)
        .ok_or_else(|| anyhow!("unresolved schema reference: {reference}"))
}

/// Validates the exact UTC timestamp format and calendar ranges.
pub(super) fn validate_utc_date_time(value: &str) -> Result<()> {
    let body = value
        .strip_suffix('Z')
        .ok_or_else(|| anyhow!("timestamp must end in Z"))?;
    let (whole, fraction) = body
        .split_once('.')
        .map_or((body, None), |(left, right)| (left, Some(right)));
    if fraction.is_some_and(|digits| {
        digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        bail!("invalid fractional seconds");
    }
    let bytes = whole.as_bytes();
    if bytes.len() != 19
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        bail!("invalid UTC date-time structure");
    }
    let number = |range: std::ops::Range<usize>| -> Result<u32> {
        Ok(
            std::str::from_utf8(bytes.get(range).ok_or_else(|| anyhow!("timestamp range"))?)?
                .parse()?,
        )
    };
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        bail!("UTC date-time component out of range");
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum_day = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day == 0 || day > maximum_day {
        bail!("UTC date-time calendar day out of range");
    }
    Ok(())
}

fn validate_https_or_path_uri(value: &str) -> Result<()> {
    let mut decoded = value.to_owned();
    for _ in 0..8 {
        let next = percent_decode(&decoded)?;
        if next == decoded {
            break;
        }
        decoded = next;
    }
    if decoded.contains('?') || decoded.contains('#') || decoded.contains('@') {
        bail!("URI contains query, fragment, userinfo, or encoded delimiter");
    }
    if decoded.starts_with("https://") || decoded.starts_with('/') {
        return Ok(());
    }
    bail!("URI is neither an HTTPS URI nor an absolute path")
}

fn percent_decode(input: &str) -> Result<String> {
    let mut output = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                bail!("truncated percent escape");
            }
            let pair = std::str::from_utf8(&bytes[index + 1..index + 3])?;
            output.push(u8::from_str_radix(pair, 16).context("invalid percent escape")?);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).context("percent-decoded URI is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_validation_checks_calendar_ranges() {
        assert!(validate_utc_date_time("2028-02-29T23:59:59.123Z").is_ok());
        assert!(validate_utc_date_time("2027-02-29T23:59:59Z").is_err());
        assert!(validate_utc_date_time("2028-01-01T24:00:00Z").is_err());
    }

    #[test]
    fn encoded_uri_delimiters_fail_closed() {
        assert!(validate_https_or_path_uri("https://example.test/%25253fsecret").is_err());
        assert!(validate_https_or_path_uri("https://example.test/safe/path").is_ok());
    }

    #[test]
    fn cyclic_local_references_fail_closed() {
        let schema = serde_json::json!({
            "$schema": DIALECT_URI,
            "dialect": DIALECT_NAME,
            "$defs": {
                "left": {"$ref": "#/$defs/right"},
                "right": {"$ref": "#/$defs/left"}
            },
            "$ref": "#/$defs/left"
        });
        let error = validate_schema(&schema, &Value::Null, "cycle")
            .expect_err("cyclic references must be rejected");
        assert!(format!("{error:#}").contains("cyclic_schema_reference"));
    }

    #[test]
    fn excessive_schema_nesting_fails_closed() {
        let mut nested = serde_json::json!({"type":"null"});
        for _ in 0..300 {
            nested = serde_json::json!({"not": nested});
        }
        let schema = serde_json::json!({
            "$schema": DIALECT_URI,
            "dialect": DIALECT_NAME,
            "allOf": [nested]
        });
        assert!(validate_schema(&schema, &Value::Null, "deep").is_err());
    }
}
