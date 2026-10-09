//! Verifies canonical Hub RPC metadata, capability classification, and browser coverage.
//!
//! Repository consistency is tested here so generating portable API bindings
//! never depends on application implementation source or checked RFC manifests.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

type BuildResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct BuildFailure(String);

impl fmt::Display for BuildFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for BuildFailure {}

fn failure(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(BuildFailure(message.into()))
}

fn manifest_dir() -> BuildResult<PathBuf> {
    // A shared target directory can reuse this executable in another checkout.
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| failure("contract validation: CARGO_MANIFEST_DIR is not set"))
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ConnectMethod {
    path: String,
    service: String,
    method: String,
    input_type: String,
    output_type: String,
    input_fields: Vec<String>,
}

fn generated_methods() -> Vec<ConnectMethod> {
    let mut methods = aos_hub_api::EXPECTED_CONNECT_METHODS
        .iter()
        .map(|method| ConnectMethod {
            path: method.path.to_owned(),
            service: method.service.to_owned(),
            method: method.method.to_owned(),
            input_type: method.input_type.to_owned(),
            output_type: method.output_type.to_owned(),
            input_fields: method
                .input_fields
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
        })
        .collect::<Vec<_>>();
    methods.sort();
    methods
}

#[test]
fn checked_api_manifest_matches_generated_descriptor() -> BuildResult<()> {
    verify_checked_api_manifest(&generated_methods())
}

#[test]
fn capability_manifest_covers_descriptor_and_browser_operations() -> BuildResult<()> {
    verify_checked_capability_manifest(&generated_methods())
}

#[test]
fn browser_coverage_requires_executable_identifiers() {
    let identifier = "SERVICE_METHOD_PATH";
    for source in [
        "// SERVICE_METHOD_PATH",
        "/* SERVICE_METHOD_PATH */",
        "/* nested /* SERVICE_METHOD_PATH */ comment */",
        r####""SERVICE_METHOD_PATH""####,
        r####"r###"SERVICE_METHOD_PATH"###"####,
        r####"br#"SERVICE_METHOD_PATH"#"####,
        r####"b"SERVICE_METHOD_PATH""####,
        "SERVICE_METHOD_PATH_EXTRA",
    ] {
        assert!(
            !rust_identifier_is_used(source, identifier),
            "accepted {source}"
        );
    }
    assert!(rust_identifier_is_used(
        "call(SERVICE_METHOD_PATH)",
        identifier
    ));
}

/// Converts a protobuf CamelCase name to one collision-resistant Rust constant.
fn rust_constant_identifier(value: &str) -> String {
    let characters = value.chars().collect::<Vec<_>>();
    let mut identifier = String::with_capacity(value.len() + 8);
    for (index, character) in characters.iter().copied().enumerate() {
        let previous = index.checked_sub(1).and_then(|index| characters.get(index));
        let next = characters.get(index + 1);
        let starts_word = character.is_ascii_uppercase()
            && previous.is_some_and(|previous| {
                previous.is_ascii_lowercase()
                    || previous.is_ascii_digit()
                    || (previous.is_ascii_uppercase()
                        && next.is_some_and(|next| next.is_ascii_lowercase()))
            });
        if starts_word && !identifier.ends_with('_') {
            identifier.push('_');
        }
        identifier.push(character.to_ascii_uppercase());
    }
    identifier
}

fn verify_checked_api_manifest(generated: &[ConnectMethod]) -> BuildResult<()> {
    let manifest_path = manifest_dir()?
        .join("../../../docs/rfcs/0012-hub-surface-topology/hub-api-manifest-v1.json");

    let manifest_source = std::fs::read_to_string(&manifest_path)?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_source)?;
    if manifest
        .get("manifest_version")
        .and_then(serde_json::Value::as_str)
        != Some("aos.hub.api/v1")
    {
        return Err(failure("unexpected checked Hub API manifest version"));
    }
    let methods = manifest
        .get("methods")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| failure("checked Hub API manifest has no methods array"))?;
    let mut checked = Vec::with_capacity(methods.len());
    let mut seen = BTreeSet::new();
    for method in methods {
        let path = checked_string(method, "path")?;
        let path = format!("/{}", path.trim_start_matches('/'));
        if !seen.insert(path.clone()) {
            return Err(failure(format!("duplicate checked Hub API path {path}")));
        }
        let (qualified_service, method_name) = path
            .strip_prefix("/aos.hub.v1.")
            .and_then(|suffix| suffix.split_once('/'))
            .ok_or_else(|| failure(format!("malformed checked Hub API path {path}")))?;
        let service = checked_string(method, "service")?;
        let declared_method = checked_string(method, "method")?;
        if qualified_service != service || method_name != declared_method {
            return Err(failure(format!(
                "checked Hub API path fields disagree for {path}"
            )));
        }
        checked.push(ConnectMethod {
            path: path.clone(),
            service: service.to_owned(),
            method: declared_method.to_owned(),
            input_type: format!(".aos.hub.v1.{}", checked_string(method, "request")?),
            output_type: format!(".aos.hub.v1.{}", checked_string(method, "response")?),
            input_fields: generated
                .iter()
                .find(|generated_method| generated_method.path == path)
                .map(|generated_method| generated_method.input_fields.clone())
                .ok_or_else(|| failure(format!("checked Hub API path {path} is not generated")))?,
        });
    }
    checked.sort();
    if checked != generated {
        return Err(failure(
            "checked Hub API manifest does not exactly match descriptor metadata",
        ));
    }
    Ok(())
}

fn verify_checked_capability_manifest(generated: &[ConnectMethod]) -> BuildResult<()> {
    let manifest_path = manifest_dir()?.join(
        "../../../docs/rfcs/0012-hub-surface-topology/hub-control-plane-capabilities-v1.json",
    );

    let manifest_source = std::fs::read_to_string(&manifest_path)?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_source)?;
    if manifest
        .get("manifest_version")
        .and_then(serde_json::Value::as_str)
        != Some("aos.hub.capabilities/v1")
    {
        return Err(failure(
            "unexpected checked Hub capability manifest version",
        ));
    }

    verify_http_capabilities(&manifest)?;
    let console_source = checked_console_source()?;
    let services = checked_array(&manifest, "services")?;
    let mut classified = BTreeSet::new();
    let mut service_names = BTreeSet::new();
    for service in services {
        let service_name = checked_string(service, "service")?;
        if !service_names.insert(service_name) {
            return Err(failure(format!(
                "duplicate checked Hub capability service {service_name}"
            )));
        }
        let audience = checked_string(service, "audience")?;
        if !matches!(audience, "end-user" | "public" | "operator" | "controller") {
            return Err(failure(format!(
                "invalid capability audience {audience:?} for {service_name}"
            )));
        }

        let cli_families = checked_array(service, "cli_families")?;
        let web_workflows = checked_array(service, "web_workflows")?;
        if matches!(audience, "end-user" | "public")
            && (cli_families.is_empty() || web_workflows.is_empty())
        {
            return Err(failure(format!(
                "public capability service {service_name} requires CLI and Web owners"
            )));
        }
        if matches!(audience, "operator" | "controller") {
            if !cli_families.is_empty() || !web_workflows.is_empty() {
                return Err(failure(format!(
                    "excluded capability service {service_name} declares an end-user owner"
                )));
            }
            let exclusion = checked_string(service, "exclusion")?;
            if exclusion.trim().is_empty() {
                return Err(failure(format!(
                    "excluded capability service {service_name} has no reason"
                )));
            }
        }
        verify_string_array(cli_families, &format!("{service_name} CLI family"))?;
        verify_string_array(web_workflows, &format!("{service_name} Web workflow"))?;

        let methods = checked_array(service, "methods")?;
        if methods.is_empty() {
            return Err(failure(format!(
                "capability service {service_name} has no methods"
            )));
        }
        let mut service_methods = BTreeSet::new();
        for method in methods {
            let method_name = method.as_str().ok_or_else(|| {
                failure(format!(
                    "capability service {service_name} has a non-string method"
                ))
            })?;
            if !service_methods.insert(method_name) {
                return Err(failure(format!(
                    "duplicate capability method {service_name}/{method_name}"
                )));
            }
            if !classified.insert((service_name, method_name)) {
                return Err(failure(format!(
                    "capability method {service_name}/{method_name} is classified twice"
                )));
            }
        }
        for method_name in &service_methods {
            if let Some(default_apply_name) = method_name.strip_prefix("Plan") {
                let apply_name = match (service_name, *method_name) {
                    ("ContainerService", "PlanContainerRegistryPurgeFence") => {
                        "ApplyContainerRegistryPurgeFence"
                    }
                    ("DeliveryService", "PlanDeliveryDestination") => "ApplyDeliveryDestination",
                    _ => default_apply_name,
                };
                if !service_methods.contains(apply_name) {
                    return Err(failure(format!(
                        "planned capability {service_name}/{method_name} has no {apply_name} apply method"
                    )));
                }
            }
        }
        if matches!(audience, "end-user" | "public") {
            verify_web_method_coverage(service, service_name, &service_methods, &console_source)?;
        }
    }

    let generated = generated
        .iter()
        .map(|method| (method.service.as_str(), method.method.as_str()))
        .collect::<BTreeSet<_>>();
    if classified != generated {
        let missing = generated.difference(&classified).collect::<Vec<_>>();
        let extra = classified.difference(&generated).collect::<Vec<_>>();
        return Err(failure(format!(
            "checked Hub capability manifest differs from the descriptor; missing {missing:?}, extra {extra:?}"
        )));
    }
    Ok(())
}

fn checked_console_source() -> BuildResult<String> {
    let root = manifest_dir()?.join("../aos-hub-console/src");
    let mut paths = Vec::new();
    collect_rust_sources(&root, &mut paths)?;
    paths.sort();

    let mut source = String::new();
    for path in paths {
        source.push_str(&std::fs::read_to_string(path)?);
        source.push('\n');
    }
    Ok(source)
}

fn collect_rust_sources(directory: &Path, paths: &mut Vec<PathBuf>) -> BuildResult<()> {
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_rust_sources(&path, paths)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            paths.push(path);
        }
    }
    Ok(())
}

fn verify_web_method_coverage(
    service: &serde_json::Value,
    service_name: &str,
    methods: &BTreeSet<&str>,
    console_source: &str,
) -> BuildResult<()> {
    let exceptions = service
        .get("web_method_exceptions")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut exception_methods = BTreeSet::new();
    for exception in exceptions {
        let method = checked_string(exception, "method")?;
        let reason = checked_string(exception, "reason")?;
        if reason.trim().is_empty()
            || !methods.contains(method)
            || !exception_methods.insert(method)
        {
            return Err(failure(format!(
                "invalid Web method exception for {service_name}/{method}"
            )));
        }
    }

    for method in methods {
        let constant = rust_constant_identifier(&format!("{service_name}_{method}_PATH"));
        let is_used = rust_identifier_is_used(console_source, &constant);
        let is_excepted = exception_methods.contains(method);
        match (is_used, is_excepted) {
            (false, false) => {
                return Err(failure(format!(
                    "end-user capability {service_name}/{method} has no browser client call or documented Web exception"
                )));
            }
            (true, true) => {
                return Err(failure(format!(
                    "stale Web method exception for {service_name}/{method}"
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Returns whether Rust source uses `identifier` outside comments and literals.
///
/// This intentionally implements only the lexical boundary needed by the
/// capability gate. It rejects identifiers mentioned in documentation,
/// comments, ordinary strings, raw strings, and byte strings so prose cannot
/// satisfy Web method coverage.
fn rust_identifier_is_used(source: &str, identifier: &str) -> bool {
    RustCode::new(source).any(|token| token == identifier)
}

struct RustCode<'a> {
    source: &'a [u8],
    offset: usize,
}

impl<'a> RustCode<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source: source.as_bytes(),
            offset: 0,
        }
    }

    fn skip_quoted(&mut self, quote: u8) {
        self.offset += 1;
        while self.offset < self.source.len() {
            match self.source[self.offset] {
                b'\\' => self.offset = (self.offset + 2).min(self.source.len()),
                byte if byte == quote => {
                    self.offset += 1;
                    return;
                }
                _ => self.offset += 1,
            }
        }
    }

    fn skip_raw_string(&mut self) -> bool {
        let start = self.offset;
        if self.source.get(self.offset) == Some(&b'b') {
            self.offset += 1;
        }
        if self.source.get(self.offset) != Some(&b'r') {
            self.offset = start;
            return false;
        }
        self.offset += 1;
        let hashes = self.source[self.offset..]
            .iter()
            .take_while(|byte| **byte == b'#')
            .count();
        self.offset += hashes;
        if self.source.get(self.offset) != Some(&b'"') {
            self.offset = start;
            return false;
        }
        self.offset += 1;
        while self.offset < self.source.len() {
            if self.source[self.offset] == b'"'
                && self
                    .source
                    .get(self.offset + 1..self.offset + 1 + hashes)
                    .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
            {
                self.offset += 1 + hashes;
                return true;
            }
            self.offset += 1;
        }
        true
    }
}

impl<'a> Iterator for RustCode<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset < self.source.len() {
            if self.source[self.offset..].starts_with(b"//") {
                self.offset += self.source[self.offset..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .unwrap_or(self.source.len() - self.offset);
                continue;
            }
            if self.source[self.offset..].starts_with(b"/*") {
                let mut depth = 1_u32;
                self.offset += 2;
                while self.offset < self.source.len() && depth > 0 {
                    if self.source[self.offset..].starts_with(b"/*") {
                        depth += 1;
                        self.offset += 2;
                    } else if self.source[self.offset..].starts_with(b"*/") {
                        depth -= 1;
                        self.offset += 2;
                    } else {
                        self.offset += 1;
                    }
                }
                continue;
            }
            if self.skip_raw_string() {
                continue;
            }
            if self.source[self.offset] == b'"' {
                let quote = self.source[self.offset];
                self.skip_quoted(quote);
                continue;
            }
            if self.source[self.offset].is_ascii_alphabetic() || self.source[self.offset] == b'_' {
                let start = self.offset;
                self.offset += 1;
                while self.offset < self.source.len()
                    && (self.source[self.offset].is_ascii_alphanumeric()
                        || self.source[self.offset] == b'_')
                {
                    self.offset += 1;
                }
                return std::str::from_utf8(&self.source[start..self.offset]).ok();
            }
            self.offset += 1;
        }
        None
    }
}

fn verify_http_capabilities(manifest: &serde_json::Value) -> BuildResult<()> {
    let capabilities = checked_array(manifest, "http_capabilities")?;
    let mut ids = BTreeSet::new();
    let mut routes = BTreeSet::new();
    for capability in capabilities {
        let id = checked_string(capability, "id")?;
        if !ids.insert(id) {
            return Err(failure(format!("duplicate HTTP capability id {id}")));
        }
        let method = checked_string(capability, "method")?;
        if !matches!(method, "GET" | "HEAD" | "POST" | "DELETE" | "PATCH" | "PUT") {
            return Err(failure(format!(
                "HTTP capability {id} has unsupported method {method}"
            )));
        }
        let path = checked_string(capability, "path")?;
        if !path.starts_with('/') || !routes.insert((method, path)) {
            return Err(failure(format!(
                "HTTP capability {id} has an invalid or duplicate route"
            )));
        }
        verify_string_array(
            checked_array(capability, "cli_families")?,
            &format!("{id} CLI family"),
        )?;
        verify_string_array(
            checked_array(capability, "web_workflows")?,
            &format!("{id} Web workflow"),
        )?;
    }
    Ok(())
}

fn checked_array<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> BuildResult<&'a Vec<serde_json::Value>> {
    value
        .get(field)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| failure(format!("checked Hub capability has no {field} array")))
}

fn verify_string_array(values: &[serde_json::Value], context: &str) -> BuildResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        let value = value
            .as_str()
            .ok_or_else(|| failure(format!("{context} entry is not a string")))?;
        if value.trim().is_empty() || !seen.insert(value) {
            return Err(failure(format!("{context} entry is empty or duplicated")));
        }
    }
    Ok(())
}

fn checked_string<'a>(value: &'a serde_json::Value, field: &str) -> BuildResult<&'a str> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| failure(format!("checked Hub API method has no {field}")))
}
