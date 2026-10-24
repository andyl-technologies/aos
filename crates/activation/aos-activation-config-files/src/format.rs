//! Encodes text, immutable files, credential fragments, and structured configuration.

use std::io::Read as _;

use anyhow::{Context as _, Result, bail, ensure};
use serde_json::Value;

use crate::{Input, io};

pub(crate) fn contents(input: &Input) -> Result<Vec<u8>> {
    match input.format.as_str() {
        "json" => Ok(format!("{}\n", serde_json::to_string(&input.value)?).into_bytes()),
        "toml" => Ok(toml(&input.value)?.into_bytes()),
        "text" => {
            if let Some(content) = &input.content {
                ensure!(
                    !content.contains('\0'),
                    "expected a resolved string without NUL"
                );
                return Ok(content.as_bytes().to_vec());
            }
            let mut contents = Vec::new();
            for fragment in &input.fragments {
                match fragment {
                    crate::Fragment::Text(text) => contents.extend_from_slice(text.as_bytes()),
                    crate::Fragment::File {
                        store_path,
                        credential_path,
                        maximum_bytes,
                    } => {
                        let path = match (store_path, credential_path) {
                            (Some(path), None) => immutable_source(path)?,
                            (None, Some(path)) => io::absolute(path)?,
                            _ => bail!("configuration fragment requires exactly one source"),
                        };
                        contents.extend(bounded_file(path, *maximum_bytes)?);
                    }
                }
            }
            Ok(contents)
        }
        _ => bail!("unsupported configuration format"),
    }
}

fn immutable_source(value: &str) -> Result<&std::path::Path> {
    let path = io::absolute(value)?;
    ensure!(
        path.starts_with("/nix/store/")
            && path.components().count() >= 4
            && std::fs::canonicalize(path)? == path,
        "immutable configuration source must be a canonical store path"
    );
    Ok(path)
}

fn bounded_file(path: &std::path::Path, maximum_bytes: u64) -> Result<Vec<u8>> {
    ensure!(
        (1..=1048576).contains(&maximum_bytes),
        "configuration source byte limit is outside the operation bound"
    );
    let file = io::regular(path)?.context("configuration content source is absent")?;
    let mut bytes = Vec::new();
    file.take(maximum_bytes + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum_bytes,
        "configuration content exceeds configured limit"
    );
    Ok(bytes)
}

// JSON strings form valid TOML basic strings for the resolved JSON contract.
fn scalar(value: &Value) -> Result<String> {
    match value {
        Value::Array(items) => Ok(format!(
            "[{}]",
            items
                .iter()
                .map(scalar)
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        )),
        Value::Object(items) => Ok(format!(
            "{{{}}}",
            items
                .iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| Ok(format!(
                    "{} = {}",
                    serde_json::to_string(key)?,
                    scalar(value)?
                )))
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        )),
        Value::Null => bail!("unsupported TOML value"),
        _ => Ok(serde_json::to_string(value)?),
    }
}

fn toml(value: &Value) -> Result<String> {
    let mut lines = Vec::new();
    table(value, &[], &mut lines)?;
    Ok(lines.join("\n") + "\n")
}

fn table(value: &Value, path: &[String], lines: &mut Vec<String>) -> Result<()> {
    let object = value
        .as_object()
        .context("TOML configuration must be an object")?;
    if !path.is_empty() {
        lines.push(String::new());
        lines.push(format!("[{}]", path.join(".")));
    }
    for (key, value) in object {
        if !value.is_null() && !value.is_object() {
            lines.push(format!(
                "{} = {}",
                serde_json::to_string(key)?,
                scalar(value)?
            ));
        }
    }
    for (key, value) in object {
        if value.is_object() {
            let mut child = path.to_vec();
            child.push(serde_json::to_string(key)?);
            table(value, &child, lines)?;
        }
    }
    Ok(())
}
