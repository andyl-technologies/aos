//! Generates the `aos.hub.v1` message structs and canonical ProtoJSON codecs.
//!
//! The generated prost messages and descriptor-driven pbjson codecs are shared
//! by the native Hub, Cloudflare Worker, and remote clients without linking a
//! Connect runtime into this wasm-clean type crate.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use prost::Message;
use prost_types::{field_descriptor_proto, DescriptorProto, FileDescriptorSet};

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

fn out_dir() -> BuildResult<PathBuf> {
    std::env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| failure("prost-build: OUT_DIR is not set"))
}

fn main() -> BuildResult<()> {
    let proto_root = "../aos-proto/src/proto";
    let proto = format!("{proto_root}/aos/hub/v1/hub.proto");
    let descriptor_path = out_dir()?.join("aos.hub.v1.descriptor.bin");

    prost_build::Config::new()
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&[&proto], &[proto_root])?;

    let descriptor_bytes = std::fs::read(&descriptor_path)?;
    let descriptor = FileDescriptorSet::decode(descriptor_bytes.as_slice())?;
    pbjson_build::Builder::new()
        .register_descriptors(&descriptor_bytes)?
        .build(&[".aos.hub.v1"])?;

    preserve_protojson_integer_syntax()?;
    preserve_open_enum_numbers(&descriptor)?;
    preserve_protojson_null_as_unset()?;
    generate_connect_descriptors(&descriptor)?;

    println!("cargo:rerun-if-changed={proto}");
    Ok(())
}

fn generated_serde_path() -> BuildResult<PathBuf> {
    Ok(out_dir()?.join("aos.hub.v1.serde.rs"))
}

/// Routes every generated integer field through the exact ProtoJSON parser.
fn preserve_protojson_integer_syntax() -> BuildResult<()> {
    let path = generated_serde_path()?;
    let mut source = std::fs::read_to_string(&path)?;
    replace_at_least_once(
        &mut source,
        "::pbjson::private::NumberDeserialize<",
        "crate::ProtoJsonNumber<",
        "ProtoJSON integer decoder",
    )?;
    std::fs::write(path, source)?;
    Ok(())
}

/// Preserves unknown numeric proto3 enum values in every message field.
fn preserve_open_enum_numbers(descriptor: &FileDescriptorSet) -> BuildResult<()> {
    assert_open_enum_field_inventory(descriptor)?;
    let path = generated_serde_path()?;
    let mut source = std::fs::read_to_string(&path)?;

    for (enum_name, field_name, json_name) in [
        ("AccessClass", "access_class", "accessClass"),
        ("RegistryMirrorMode", "mode", "mode"),
        ("EndpointIngressKind", "ingress_kind", "ingressKind"),
        ("HubDeliveryKind", "delivery_kind", "deliveryKind"),
        ("ContainerRegistryPurgeFenceAction", "action", "action"),
    ] {
        let serialize = format!(
            "            let v = {enum_name}::try_from(self.{field_name})\n\
             \x20               .map_err(|_| serde::ser::Error::custom(format!(\"Invalid variant {{}}\", self.{field_name})))?;\n\
             \x20           struct_ser.serialize_field(\"{json_name}\", &v)?;"
        );
        let serialize_replacement = format!(
            "            let v = crate::OpenEnum::<{enum_name}>::new(self.{field_name});\n\
             \x20           struct_ser.serialize_field(\"{json_name}\", &v)?;"
        );
        replace_at_least_once(
            &mut source,
            &serialize,
            &serialize_replacement,
            &format!("serialize {enum_name}.{field_name}"),
        )?;

        let deserialize =
            format!("{field_name}__ = Some(map_.next_value::<{enum_name}>()? as i32);");
        let deserialize_replacement = format!(
            "{field_name}__ = map_.next_value::<::std::option::Option<crate::OpenEnum<{enum_name}>>>()?.map(crate::OpenEnum::number);"
        );
        replace_at_least_once(
            &mut source,
            &deserialize,
            &deserialize_replacement,
            &format!("deserialize {enum_name}.{field_name}"),
        )?;
    }

    correct_repeated_open_enum(
        &mut source,
        "PolicyRetryCondition",
        "retry_on",
        "repeated PolicyRetryCondition",
    )?;
    correct_repeated_open_enum(
        &mut source,
        "PinResolutionAction",
        "allowed_actions",
        "repeated PinResolutionAction",
    )?;

    std::fs::write(path, source)?;
    Ok(())
}

fn correct_repeated_open_enum(
    source: &mut String,
    enum_name: &str,
    field_name: &str,
    context: &str,
) -> BuildResult<()> {
    let serialize = format!(
        "            let v = self.{field_name}.iter().cloned().map(|v| {{\n\
         \x20               {enum_name}::try_from(v)\n\
         \x20                   .map_err(|_| serde::ser::Error::custom(format!(\"Invalid variant {{}}\", v)))\n\
         \x20               }}).collect::<std::result::Result<Vec<_>, _>>()?;"
    );
    let serialize_replacement = format!(
        "            let v = self.{field_name}.iter().copied()\n\
         \x20               .map(crate::OpenEnum::<{enum_name}>::new)\n\
         \x20               .collect::<Vec<_>>();"
    );
    replace_exactly_once(
        source,
        &serialize,
        &serialize_replacement,
        &format!("serialize {context}"),
    )?;
    let deserialize = format!(
        "{field_name}__ = Some(map_.next_value::<Vec<{enum_name}>>()?.into_iter().map(|x| x as i32).collect());"
    );
    let deserialize_replacement = format!(
        "{field_name}__ = map_.next_value::<::std::option::Option<Vec<crate::OpenEnum<{enum_name}>>>>()?.map(|values| values.into_iter().map(crate::OpenEnum::number).collect());"
    );
    replace_exactly_once(
        source,
        &deserialize,
        &deserialize_replacement,
        &format!("deserialize {context}"),
    )
}

/// Fails closed when an enum field is added without an explicit correction.
fn assert_open_enum_field_inventory(descriptor: &FileDescriptorSet) -> BuildResult<()> {
    let mut actual = BTreeSet::new();
    for file in &descriptor.file {
        if file.package.as_deref() != Some("aos.hub.v1") {
            continue;
        }
        for message in &file.message_type {
            collect_enum_fields(message, "", &mut actual)?;
        }
    }
    let expected = [
        "EndpointRevisionSpec.ingress_kind:.aos.hub.v1.EndpointIngressKind:single",
        "HubPlacementTarget.delivery_kind:.aos.hub.v1.HubDeliveryKind:single",
        "HubPolicyRevisionTarget.delivery_kind:.aos.hub.v1.HubDeliveryKind:single",
        "PlacementPolicyReplicaGroup.access_class:.aos.hub.v1.AccessClass:single",
        "PlanContainerRegistryPurgeFenceRequest.action:.aos.hub.v1.ContainerRegistryPurgeFenceAction:single",
        "PolicyFailureContract.retry_on:.aos.hub.v1.PolicyRetryCondition:repeated",
        "RegistryMirror.mode:.aos.hub.v1.RegistryMirrorMode:single",
        "RegistryMirrorSpec.mode:.aos.hub.v1.RegistryMirrorMode:single",
        "TestPlacementPolicyRevisionRequest.access_class:.aos.hub.v1.AccessClass:single",
        "TopologyPinImpact.allowed_actions:.aos.hub.v1.PinResolutionAction:repeated",
        "ContainerRegistryPurgeFence.action:.aos.hub.v1.ContainerRegistryPurgeFenceAction:single",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(failure(format!(
            "pbjson-build: open-enum field inventory changed; expected {expected:?}, found {actual:?}"
        )));
    }
    Ok(())
}

fn collect_enum_fields(
    message: &DescriptorProto,
    prefix: &str,
    fields: &mut BTreeSet<String>,
) -> BuildResult<()> {
    let name = required_proto_identifier(message.name.as_deref(), "message")?;
    let qualified = if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}.{name}")
    };
    for field in &message.field {
        if field.r#type == Some(field_descriptor_proto::Type::Enum as i32) {
            let field_name = required_proto_identifier(field.name.as_deref(), "field")?;
            let type_name = field.type_name.as_deref().ok_or_else(|| {
                failure(format!("enum field {qualified}.{field_name} has no type"))
            })?;
            let cardinality = if field.label == Some(field_descriptor_proto::Label::Repeated as i32)
            {
                "repeated"
            } else {
                "single"
            };
            fields.insert(format!(
                "{qualified}.{field_name}:{type_name}:{cardinality}"
            ));
        }
    }
    for nested in &message.nested_type {
        collect_enum_fields(nested, &qualified, fields)?;
    }
    Ok(())
}

/// Corrects null handling in generated ordinary field visitors.
fn preserve_protojson_null_as_unset() -> BuildResult<()> {
    let path = generated_serde_path()?;
    let mut source = std::fs::read_to_string(&path)?;
    replace_at_least_once(
        &mut source,
        "Some(map_.next_value()?)",
        "map_.next_value::<::std::option::Option<_>>()?",
        "nullable ordinary scalar or repeated field",
    )?;
    replace_at_least_once(
        &mut source,
        "Some(map_.next_value::<crate::ProtoJsonNumber<_>>()?.0)",
        "map_.next_value::<::std::option::Option<crate::ProtoJsonNumber<_>>>()?.map(|value| value.0)",
        "nullable ordinary numeric field",
    )?;
    replace_exactly_once(
        &mut source,
        "Some(\n                                map_.next_value::<std::collections::HashMap<_, _>>()?\n                            )",
        "map_.next_value::<::std::option::Option<std::collections::HashMap<_, _>>>()?",
        "nullable instance-settings map field",
    )?;
    std::fs::write(path, source)?;
    Ok(())
}

fn replace_at_least_once(
    source: &mut String,
    old: &str,
    new: &str,
    context: &str,
) -> BuildResult<()> {
    let count = source.matches(old).count();
    if count == 0 {
        return Err(failure(format!(
            "pbjson-build: missing expected {context} fragment"
        )));
    }
    *source = source.replace(old, new);
    Ok(())
}

fn replace_exactly_once(
    source: &mut String,
    old: &str,
    new: &str,
    context: &str,
) -> BuildResult<()> {
    let count = source.matches(old).count();
    if count != 1 {
        return Err(failure(format!(
            "pbjson-build: expected one {context} fragment, found {count}"
        )));
    }
    *source = source.replacen(old, new, 1);
    Ok(())
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

fn generate_connect_descriptors(descriptor: &FileDescriptorSet) -> BuildResult<()> {
    let methods = descriptor_connect_methods(descriptor)?;
    verify_checked_api_manifest(&methods)?;
    verify_checked_capability_manifest(&methods)?;
    let mut generated = String::from(
        "/// One Connect RPC projected directly from the canonical descriptor.\n\
         #[derive(Clone, Copy, Debug, PartialEq, Eq)]\n\
         pub struct ConnectMethodDescriptor {\n\
         \x20   /// Canonical package-qualified Connect request path.\n\
         \x20   pub path: &'static str,\n\
         \x20   /// Protobuf service name without its package.\n\
         \x20   pub service: &'static str,\n\
         \x20   /// Protobuf RPC method name.\n\
         \x20   pub method: &'static str,\n\
         \x20   /// Fully qualified protobuf input message name.\n\
         \x20   pub input_type: &'static str,\n\
         \x20   /// Fully qualified protobuf output message name.\n\
         \x20   pub output_type: &'static str,\n\
         \x20   /// Canonical declaration-ordered protobuf input field names.\n\
         \x20   pub input_fields: &'static [&'static str],\n\
         }\n\
         /// Every Connect RPC declared by the canonical Hub descriptor.\n\
         pub const EXPECTED_CONNECT_METHODS: &[ConnectMethodDescriptor] = &[\n",
    );
    for method in &methods {
        generated.push_str("    ConnectMethodDescriptor { path: \"");
        generated.push_str(&method.path);
        generated.push_str("\", service: \"");
        generated.push_str(&method.service);
        generated.push_str("\", method: \"");
        generated.push_str(&method.method);
        generated.push_str("\", input_type: \"");
        generated.push_str(&method.input_type);
        generated.push_str("\", output_type: \"");
        generated.push_str(&method.output_type);
        generated.push_str("\", input_fields: &[");
        for field in &method.input_fields {
            generated.push('"');
            generated.push_str(field);
            generated.push_str("\",");
        }
        generated.push_str("] },\n");
    }
    generated.push_str(
        "];\n/// Every canonical Connect path, retained for router coverage.\n\
         pub const EXPECTED_CONNECT_PATHS: &[&str] = &[\n",
    );
    for method in &methods {
        generated.push_str("    \"");
        generated.push_str(&method.path);
        generated.push_str("\",\n");
    }
    generated.push_str("];\n");
    for method in &methods {
        generated.push_str("/// Canonical Connect path for the generated typed client method.\n");
        generated.push_str("pub const ");
        generated.push_str(&rust_constant_identifier(&format!(
            "{}_{}_PATH",
            method.service, method.method
        )));
        generated.push_str(": &str = \"");
        generated.push_str(&method.path);
        generated.push_str("\";\n");
    }
    std::fs::write(out_dir()?.join("connect_paths.rs"), generated)?;
    Ok(())
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

fn descriptor_connect_methods(descriptor: &FileDescriptorSet) -> BuildResult<Vec<ConnectMethod>> {
    let mut methods = Vec::new();
    let mut seen = BTreeSet::new();
    let mut message_fields = BTreeMap::new();
    for file in &descriptor.file {
        let package = match file.package.as_deref() {
            Some(package) => package,
            None => "",
        };
        for message in &file.message_type {
            collect_message_fields(message, package, &mut message_fields)?;
        }
    }
    for file in &descriptor.file {
        let package = match file.package.as_deref() {
            Some(package) => package,
            None => "",
        };
        if package != "aos.hub.v1" {
            continue;
        }
        for service in &file.service {
            let service_name = required_proto_identifier(service.name.as_deref(), "service")?;
            for method in &service.method {
                let method_name = required_proto_identifier(method.name.as_deref(), "method")?;
                let input_type = method.input_type.as_deref().ok_or_else(|| {
                    failure(format!("RPC {service_name}/{method_name} has no input"))
                })?;
                let output_type = method.output_type.as_deref().ok_or_else(|| {
                    failure(format!("RPC {service_name}/{method_name} has no output"))
                })?;
                let path = format!("/{package}.{service_name}/{method_name}");
                if !seen.insert(path.clone()) {
                    return Err(failure(format!("duplicate Connect path {path}")));
                }
                methods.push(ConnectMethod {
                    path,
                    service: service_name.to_owned(),
                    method: method_name.to_owned(),
                    input_type: input_type.to_owned(),
                    output_type: output_type.to_owned(),
                    input_fields: message_fields.get(input_type).cloned().ok_or_else(|| {
                        failure(format!(
                            "RPC {service_name}/{method_name} input is unresolved"
                        ))
                    })?,
                });
            }
        }
    }
    if methods.is_empty() {
        return Err(failure("aos.hub.v1 declares no RPC methods"));
    }
    methods.sort();
    Ok(methods)
}

fn collect_message_fields(
    message: &DescriptorProto,
    prefix: &str,
    messages: &mut BTreeMap<String, Vec<String>>,
) -> BuildResult<()> {
    let name = required_proto_identifier(message.name.as_deref(), "message")?;
    let qualified = format!(".{prefix}.{name}");
    let mut fields = Vec::with_capacity(message.field.len());
    for field in &message.field {
        fields.push(required_proto_identifier(field.name.as_deref(), "field")?.to_owned());
    }
    if messages.insert(qualified.clone(), fields).is_some() {
        return Err(failure(format!("duplicate protobuf message {qualified}")));
    }
    let nested_prefix = qualified.trim_start_matches('.');
    for nested in &message.nested_type {
        collect_message_fields(nested, nested_prefix, messages)?;
    }
    Ok(())
}

fn required_proto_identifier<'a>(value: Option<&'a str>, kind: &str) -> BuildResult<&'a str> {
    let value = value.ok_or_else(|| failure(format!("{kind} name is absent")))?;
    let mut bytes = value.bytes();
    let first = bytes
        .next()
        .ok_or_else(|| failure(format!("{kind} name is empty")))?;
    if !(first == b'_' || first.is_ascii_alphabetic())
        || !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return Err(failure(format!(
            "{kind} name {value:?} is not a protobuf identifier"
        )));
    }
    Ok(value)
}

fn verify_checked_api_manifest(generated: &[ConnectMethod]) -> BuildResult<()> {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/rfcs/0012-hub-surface-topology/hub-api-manifest-v1.json");
    println!("cargo:rerun-if-changed={}", manifest_path.display());
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
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/rfcs/0012-hub-surface-topology/hub-control-plane-capabilities-v1.json");
    println!("cargo:rerun-if-changed={}", manifest_path.display());
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
                let apply_name = if service_name == "ContainerService"
                    && *method_name == "PlanContainerRegistryPurgeFence"
                {
                    "ApplyContainerRegistryPurgeFence"
                } else {
                    default_apply_name
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
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../aos-hub-console/src");
    let mut paths = Vec::new();
    collect_rust_sources(&root, &mut paths)?;
    paths.sort();

    let mut source = String::new();
    for path in paths {
        println!("cargo:rerun-if-changed={}", path.display());
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
