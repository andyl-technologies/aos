//! Output bindings decoded from `nix derivation show` JSON.
//!
//! A derivation's output names and store paths are part of the derivation
//! itself, so they are read from Nix's own description of the `.drv` file
//! rather than from its environment. Derivations built with structured
//! attributes have no `outputs` environment binding at all.
//!
//! Nix has emitted two document shapes. Older releases key the document by
//! the absolute derivation path and give absolute output paths:
//!
//! ```text
//! {"/nix/store/<hash>-name.drv": {"outputs": {"out": {"path": "/nix/store/<hash>-name"}}}}
//! ```
//!
//! Newer releases wrap the derivations in a versioned document keyed by store
//! base name, and give output paths as base names relative to the store:
//!
//! ```text
//! {"derivations": {"<hash>-name.drv": {"outputs": {"out": {"path": "<hash>-name"}}}},
//!  "version": 4}
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde_json::{Map, Value};

/// Store directory that relative output paths are resolved against.
const STORE_DIR: &str = "/nix/store/";

/// Decodes the output name to absolute store path map of `derivation`.
///
/// Fails closed when the document omits the derivation, names no outputs,
/// or names an output without a static store path, such as a floating
/// content-addressed output whose path is only known after the build.
pub(super) fn parse(derivation: &Path, json: &[u8]) -> Result<BTreeMap<String, String>> {
    let document: Value =
        serde_json::from_slice(json).context("parsing Nix derivation show JSON")?;
    let entry = derivation_entry(&document, derivation)?;
    let outputs = entry
        .get("outputs")
        .and_then(Value::as_object)
        .with_context(|| format!("Nix lists no outputs for {}", derivation.display()))?;
    if outputs.is_empty() {
        bail!("Nix lists no outputs for {}", derivation.display());
    }

    let mut paths = BTreeMap::new();
    for (name, output) in outputs {
        let path = output
            .get("path")
            .and_then(Value::as_str)
            .with_context(|| {
                format!(
                    "output {name} of {} has no static store path",
                    derivation.display()
                )
            })?;
        paths.insert(name.clone(), absolute_store_path(path)?);
    }
    Ok(paths)
}

/// Finds the description of `derivation` in either document shape.
fn derivation_entry<'a>(document: &'a Value, derivation: &Path) -> Result<&'a Map<String, Value>> {
    let top = document
        .as_object()
        .context("Nix derivation show JSON is not an object")?;
    // Absolute derivation paths can never collide with the wrapper key.
    let derivations = match top.get("derivations") {
        Some(Value::Object(wrapped)) => wrapped,
        _ => top,
    };

    let full = derivation.to_string_lossy();
    let base_name = derivation
        .file_name()
        .map(|name| name.to_string_lossy())
        .with_context(|| format!("invalid derivation path {full}"))?;
    derivations
        .get(full.as_ref())
        .or_else(|| derivations.get(base_name.as_ref()))
        .and_then(Value::as_object)
        .with_context(|| format!("Nix derivation show omitted {full}"))
}

/// Resolves an output path given as a store base name or absolute path.
fn absolute_store_path(path: &str) -> Result<String> {
    let absolute = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("{STORE_DIR}{path}")
    };
    let Some(base_name) = absolute.strip_prefix(STORE_DIR) else {
        bail!("Nix output path is outside the store: {path}");
    };
    if base_name.is_empty() || base_name.contains('/') {
        bail!("Nix output path is not a store root: {path}");
    }
    Ok(absolute)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::parse;

    const DERIVATION: &str = "/nix/store/j2ykzsbanqz7ys4ih3sd476y222wlkig-glibc-2.39.drv";

    #[test]
    fn versioned_documents_resolve_base_names_against_the_store() -> anyhow::Result<()> {
        let json = br#"{"derivations": {"j2ykzsbanqz7ys4ih3sd476y222wlkig-glibc-2.39.drv": {
            "outputs": {
                "out": {"path": "7xzbpnlajpi7qsyqbnlsk4vp30z2kzgl-glibc-2.39"},
                "getent": {"path": "zjk5ab6qyp13slpj6jdd08vqkaqg6jqb-glibc-2.39-getent"}
            }}}, "version": 4}"#;

        let outputs = parse(Path::new(DERIVATION), json)?;

        assert_eq!(
            outputs.into_iter().collect::<Vec<_>>(),
            [
                (
                    "getent".to_owned(),
                    "/nix/store/zjk5ab6qyp13slpj6jdd08vqkaqg6jqb-glibc-2.39-getent".to_owned()
                ),
                (
                    "out".to_owned(),
                    "/nix/store/7xzbpnlajpi7qsyqbnlsk4vp30z2kzgl-glibc-2.39".to_owned()
                ),
            ]
        );
        Ok(())
    }

    #[test]
    fn path_keyed_documents_keep_absolute_paths() -> anyhow::Result<()> {
        let json = br#"{"/nix/store/j2ykzsbanqz7ys4ih3sd476y222wlkig-glibc-2.39.drv": {
            "outputs": {"out": {"path": "/nix/store/7xzbpnlajpi7qsyqbnlsk4vp30z2kzgl-glibc-2.39"}}
        }}"#;

        let outputs = parse(Path::new(DERIVATION), json)?;

        assert_eq!(
            outputs.get("out").map(String::as_str),
            Some("/nix/store/7xzbpnlajpi7qsyqbnlsk4vp30z2kzgl-glibc-2.39")
        );
        Ok(())
    }

    #[test]
    fn omitted_derivations_and_floating_outputs_fail_closed() {
        let other = br#"{"derivations": {"other.drv": {"outputs": {"out": {"path": "x"}}}}}"#;
        let floating = br#"{"derivations": {"j2ykzsbanqz7ys4ih3sd476y222wlkig-glibc-2.39.drv":
            {"outputs": {"out": {"method": "nar", "hashAlgo": "sha256"}}}}}"#;
        let empty = br#"{"derivations": {"j2ykzsbanqz7ys4ih3sd476y222wlkig-glibc-2.39.drv":
            {"outputs": {}}}}"#;

        assert!(parse(Path::new(DERIVATION), other).is_err());
        assert!(parse(Path::new(DERIVATION), floating).is_err());
        assert!(parse(Path::new(DERIVATION), empty).is_err());
        assert!(parse(Path::new(DERIVATION), b"[]").is_err());
    }

    #[test]
    fn output_paths_must_be_store_roots() {
        for path in ["/tmp/out", "a/b", ""] {
            let json = format!(
                r#"{{"derivations": {{"j2ykzsbanqz7ys4ih3sd476y222wlkig-glibc-2.39.drv":
                    {{"outputs": {{"out": {{"path": "{path}"}}}}}}}}}}"#
            );
            assert!(
                parse(Path::new(DERIVATION), json.as_bytes()).is_err(),
                "{path}"
            );
        }
    }
}
