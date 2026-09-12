//! Validates and compiles the closed native-adapter surface.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write as _;
use std::path::PathBuf;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const SURFACE_PATH: &str = "../../qualification/native-adapter-surface.json";
const SURFACE_SCHEMA: &str = "aos.qualification.native-adapter-surface/v1";
const MATRIX_SCHEMA: &str = "aos.qualification.native-adapter-matrix/v1";
const SUBJECT_SCHEMA: &str = "aos.qualification.native-adapter-subject/v1";
const EXPECTED_ADAPTERS: usize = 13;
const EXPECTED_METHODS: usize = 50;
const EXPECTED_SCENARIOS: usize = 28;
const MAX_SURFACE_BYTES: u64 = 64 * 1024;
const EXPECTED_SURFACE_DIGEST: &str =
    "ab49c07a42c33d0a4c64532031497ea1f9a07b41bcbe22164a4106cdeb614ae7";

type BuildResult<T> = Result<T, Box<dyn Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SurfaceDocument {
    adapters: Vec<Adapter>,
    limits: Limits,
    matrix_schema: String,
    scenarios: Vec<Scenario>,
    schema: String,
    subject_schema: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    max_adapters: usize,
    max_methods: usize,
    max_scenarios: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Adapter {
    adapter: String,
    interface_abi: u32,
    interface_descriptor: String,
    interface_name: String,
    methods: Vec<Method>,
    scope: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Method {
    cancel: Option<String>,
    effect_class: String,
    method: String,
    reconcile: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    boundary: String,
    candidate: String,
    failure: String,
    id: String,
    predecessor: String,
}

/// Validates the canonical inventory and writes the generated Rust table.
pub(super) fn compile() -> BuildResult<()> {
    if std::fs::metadata(SURFACE_PATH)?.len() > MAX_SURFACE_BYTES {
        return Err("native-adapter surface exceeds its byte limit".into());
    }
    let source = std::fs::read(SURFACE_PATH)?;
    let value: serde_json::Value = serde_json::from_slice(&source)?;
    let canonical = serde_json::to_vec(&value)?;
    if format!("{:x}", Sha256::digest(&canonical)) != EXPECTED_SURFACE_DIGEST {
        return Err("native-adapter surface differs from the closed version-1 contract".into());
    }
    let document: SurfaceDocument = serde_json::from_value(value)?;
    validate(&document)?;

    let generated = generate(&document)?;
    let output = output_dir()?.join("native_adapter_surface.rs");
    std::fs::write(output, generated)?;

    println!("cargo:rerun-if-changed={SURFACE_PATH}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build/native_adapter_surface.rs");
    Ok(())
}

fn output_dir() -> BuildResult<PathBuf> {
    std::env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| "aos-package build: OUT_DIR is not set".into())
}

fn validate(document: &SurfaceDocument) -> BuildResult<()> {
    if document.schema != SURFACE_SCHEMA
        || document.matrix_schema != MATRIX_SCHEMA
        || document.subject_schema != SUBJECT_SCHEMA
    {
        return Err("native-adapter surface uses an unsupported schema".into());
    }
    if document.limits.max_adapters != EXPECTED_ADAPTERS
        || document.limits.max_methods != EXPECTED_METHODS
        || document.limits.max_scenarios != EXPECTED_SCENARIOS
        || document.adapters.len() != EXPECTED_ADAPTERS
        || document.scenarios.len() != EXPECTED_SCENARIOS
    {
        return Err("native-adapter surface differs from its closed limits".into());
    }

    let expected: BTreeMap<&str, (&str, &str, &[&str])> = BTreeMap::from([
        (
            "credential-delivery",
            (
                "aos.credential-delivery-effects",
                "host-resource",
                &["acquire", "deliver", "release"] as &[_],
            ),
        ),
        (
            "foreground-process",
            (
                "aos.foreground-process",
                "application-container-process",
                &["observe", "start", "stop"],
            ),
        ),
        (
            "host-network-policy",
            (
                "aos.host-network-policy-effects",
                "host-resource",
                &["apply", "observe", "remove"],
            ),
        ),
        (
            "host-storage",
            (
                "aos.host-storage-effects",
                "host-resource",
                &["ensure", "observe", "release"],
            ),
        ),
        (
            "image-rollout",
            (
                "aos.ab-image-rollout-effects",
                "host-machine",
                &[
                    "drain",
                    "hold",
                    "observe-boot",
                    "observe-health",
                    "prepare",
                    "retain",
                    "retire",
                    "select",
                    "withdraw",
                ],
            ),
        ),
        (
            "kubernetes-object",
            (
                "aos.kubernetes-object-effects",
                "kubernetes-cluster",
                &["apply", "delete", "observe"],
            ),
        ),
        (
            "managed-configuration",
            (
                "aos.managed-configuration-effects",
                "host-filesystem",
                &["prepare", "publish", "release"],
            ),
        ),
        (
            "network-endpoint",
            (
                "aos.network-endpoint-effects",
                "host-resource",
                &["materialize", "observe", "release"],
            ),
        ),
        (
            "nginx-validation",
            (
                "aos.nginx-validation",
                "host-process",
                &["record", "release", "validate"],
            ),
        ),
        (
            "postgresql",
            (
                "aos.postgresql-effects",
                "host-resource",
                &["materialize", "observe", "restart", "start", "stop"],
            ),
        ),
        (
            "systemd-bootstrap",
            (
                "aos.systemd-provider-bootstrap",
                "bootstrap-manager",
                &["observe-manager", "start", "stop"],
            ),
        ),
        (
            "systemd-manager",
            (
                "aos.systemd-manager",
                "host-manager",
                &["observe", "reload", "restart", "start", "stop"],
            ),
        ),
        (
            "systemd-service-legacy",
            (
                "aos.systemd-service-effects",
                "host-manager",
                &["observe", "reload", "start", "stop"],
            ),
        ),
    ]);
    let mut adapters = BTreeSet::new();
    let mut interfaces = BTreeSet::new();
    let mut methods = BTreeSet::new();
    let mut previous_adapter = None;

    for adapter in &document.adapters {
        validate_token(&adapter.adapter, "adapter")?;
        validate_token(&adapter.scope, "scope")?;
        validate_token(&adapter.interface_name, "interface")?;
        validate_digest(&adapter.interface_descriptor)?;
        let Some((interface, scope, expected_methods)) = expected.get(adapter.adapter.as_str())
        else {
            return Err(format!("unknown native adapter {}", adapter.adapter).into());
        };
        if adapter.interface_abi != 1
            || adapter.interface_name != *interface
            || adapter.scope != *scope
            || !adapters.insert(adapter.adapter.as_str())
            || !interfaces.insert((adapter.interface_name.as_str(), adapter.interface_abi))
            || previous_adapter.is_some_and(|previous| previous >= adapter.adapter.as_str())
        {
            return Err(format!("invalid or duplicate native adapter {}", adapter.adapter).into());
        }
        if adapter
            .methods
            .iter()
            .map(|method| method.method.as_str())
            .collect::<Vec<_>>()
            != *expected_methods
        {
            return Err(format!(
                "native adapter {} has the wrong method inventory",
                adapter.adapter
            )
            .into());
        }
        previous_adapter = Some(adapter.adapter.as_str());

        let declared: BTreeSet<&str> = adapter
            .methods
            .iter()
            .map(|method| method.method.as_str())
            .collect();
        let mut previous_method = None;
        for method in &adapter.methods {
            validate_token(&method.method, "method")?;
            if !matches!(method.effect_class.as_str(), "mutation" | "observation")
                || !methods.insert((adapter.adapter.as_str(), method.method.as_str()))
                || previous_method.is_some_and(|previous| previous >= method.method.as_str())
            {
                return Err(format!(
                    "invalid or duplicate native method {}:{}",
                    adapter.adapter, method.method
                )
                .into());
            }
            for route in [method.reconcile.as_deref(), method.cancel.as_deref()]
                .into_iter()
                .flatten()
            {
                if !declared.contains(route) {
                    return Err(format!(
                        "native method route {}:{} leaves its interface",
                        adapter.adapter, route
                    )
                    .into());
                }
            }
            previous_method = Some(method.method.as_str());
        }
    }
    if adapters.len() != expected.len() || methods.len() != EXPECTED_METHODS {
        return Err("native-adapter method inventory is incomplete".into());
    }

    let allowed_boundaries = BTreeSet::from([
        "after-acquisition",
        "after-durable-intent",
        "after-durable-outcome",
        "after-external-return",
        "before-acquisition",
        "before-external-effect",
        "cancellation",
        "cleanup",
        "deadline",
        "foreign-resource",
        "prerequisite",
        "recovery",
        "release",
        "retained-target-activation",
    ]);
    let mut scenarios = BTreeSet::new();
    for scenario in &document.scenarios {
        for (value, label) in [
            (&scenario.id, "scenario"),
            (&scenario.boundary, "boundary"),
            (&scenario.failure, "failure"),
            (&scenario.predecessor, "predecessor"),
            (&scenario.candidate, "candidate"),
        ] {
            validate_token(value, label)?;
        }
        if !allowed_boundaries.contains(scenario.boundary.as_str())
            || !scenarios.insert(scenario.id.as_str())
        {
            return Err(format!(
                "invalid or duplicate native matrix scenario {}",
                scenario.id
            )
            .into());
        }
    }
    Ok(())
}

fn validate_token(value: &str, label: &str) -> BuildResult<()> {
    if value.is_empty()
        || value.len() > 96
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        return Err(format!("native-adapter {label} is not a bounded token").into());
    }
    Ok(())
}

fn validate_digest(value: &str) -> BuildResult<()> {
    let Some(encoded) = value.strip_prefix("sha256:") else {
        return Err("native-adapter interface descriptor has no SHA-256 prefix".into());
    };
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("native-adapter interface descriptor is not lowercase SHA-256".into());
    }
    Ok(())
}

fn generate(document: &SurfaceDocument) -> BuildResult<String> {
    let mut output = String::from(
        "// Generated from qualification/native-adapter-surface.json.\n\
         pub(crate) const NATIVE_ADAPTER_COUNT: usize = 13;\n\
         pub(crate) const NATIVE_METHOD_COUNT: usize = 50;\n\n\
         #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]\n\
         pub(crate) enum NativeAdapterId {\n",
    );
    for adapter in &document.adapters {
        writeln!(output, "    {},", variant(&adapter.adapter)?)?;
    }
    output.push_str("}\n\npub(crate) static NATIVE_METHODS: &[NativeMethodContract] = &[\n");
    for adapter in &document.adapters {
        for method in &adapter.methods {
            writeln!(
                output,
                "    NativeMethodContract {{ adapter: NativeAdapterId::{}, interface_name: {:?}, interface_abi: {}, interface_descriptor: {}, scope: {:?}, method: {:?}, effect_class: EffectClass::{}, reconcile: {}, cancel: {} }},",
                variant(&adapter.adapter)?,
                adapter.interface_name,
                adapter.interface_abi,
                digest_literal(&adapter.interface_descriptor)?,
                adapter.scope,
                method.method,
                if method.effect_class == "mutation" {
                    "Mutation"
                } else {
                    "Observation"
                },
                option_literal(method.reconcile.as_deref()),
                option_literal(method.cancel.as_deref()),
            )?;
        }
    }
    output.push_str("];\n");
    Ok(output)
}

fn variant(adapter: &str) -> BuildResult<&'static str> {
    Ok(match adapter {
        "credential-delivery" => "CredentialDelivery",
        "foreground-process" => "ForegroundProcess",
        "host-network-policy" => "HostNetworkPolicy",
        "host-storage" => "HostStorage",
        "image-rollout" => "ImageRollout",
        "kubernetes-object" => "KubernetesObject",
        "managed-configuration" => "ManagedConfiguration",
        "network-endpoint" => "NetworkEndpoint",
        "nginx-validation" => "NginxValidation",
        "postgresql" => "Postgresql",
        "systemd-bootstrap" => "SystemdBootstrap",
        "systemd-manager" => "SystemdManager",
        "systemd-service-legacy" => "SystemdServiceLegacy",
        _ => return Err(format!("unknown native adapter {adapter}").into()),
    })
}

fn option_literal(value: Option<&str>) -> String {
    value.map_or_else(|| "None".to_string(), |value| format!("Some({value:?})"))
}

fn digest_literal(value: &str) -> BuildResult<String> {
    validate_digest(value)?;
    let encoded = &value["sha256:".len()..];
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect::<BuildResult<Vec<_>>>()?;
    let bytes = bytes
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    Ok(format!("Sha256Digest::from_bytes([{bytes}])"))
}
