//! Hermetic build frontend for canonical ability projection validation.
//!
//! This module decodes canonical Nix inputs, resolves exact exported-graph
//! artifacts, and delegates all package and static-contract semantics to the
//! shared validators. It owns no package, interface, or provider catalog.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::document::PlatformIdentity;
use aos_ability_model::{
    ArtifactClosureMemberInput, ArtifactReference, artifact_closure_identity,
    artifact_content_identity, encode_canonical,
};
use aos_contract::Sha256Digest;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    AbilityContractData, PackageOutputSelector, StaticAbilityArtifactClass,
    StaticAbilityContractExpectation, StaticAbilityExecutionStage, StaticAbilityPlatform,
    decode_package_projection, resolve_package_projection, validate_ability_contract,
    validate_static_ability_artifacts,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionResolutionSpec {
    payload: SelectedArtifact,
    source: SelectedArtifact,
    selectors: Vec<SelectedArtifact>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectedArtifact {
    #[serde(default)]
    package: Option<String>,
    #[serde(default)]
    output: Option<String>,
    path: String,
    graph: String,
}

/// Retains one resolved symbolic package output for downstream build evaluators.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedPackageOutput {
    /// Names the package from the original symbolic selector.
    pub package: String,
    /// Names the selected output from the original symbolic selector.
    pub output: String,
    /// Carries the authenticated artifact selected from the exported Nix graph.
    pub artifact: ArtifactReference,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportedGraphMember {
    path: String,
    nar_hash: String,
    nar_size: u64,
    closure_size: u64,
    valid: bool,
    ca: Option<String>,
    references: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ResolvedExportedArtifact {
    artifact: ArtifactReference,
    closure_paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StaticAssemblySpec {
    schema: String,
    media_type: String,
    artifact_class: String,
    execution_stage: Option<String>,
    platform: Option<StaticAssemblyPlatform>,
    target_platform: Option<PlatformIdentity>,
    packages: Vec<StaticAssemblyPackage>,
    contracts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticAssemblyPackage {
    payload: String,
    manifest: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StaticAssemblyPlatform {
    os: String,
    architecture: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    variant: Option<String>,
}

impl StaticAssemblyPlatform {
    fn expectation(&self, target: Option<PlatformIdentity>) -> StaticAbilityPlatform {
        StaticAbilityPlatform {
            os: self.os.clone(),
            architecture: self.architecture.clone(),
            variant: self.variant.clone(),
            target,
        }
    }
}

/// Assembles and validates one static ability contract from canonical Nix inputs.
///
/// # Errors
///
/// Returns an error when an input is malformed, inconsistent, or cannot be
/// materialized as a canonical checked contract.
pub fn assemble_static_contract(spec_path: &Path, graph_path: &Path, output: &Path) -> Result<()> {
    let spec: StaticAssemblySpec = serde_json::from_slice(&fs::read(spec_path)?)
        .context("decoding static ability assembly specification")?;
    let graph: Value = serde_json::from_slice(&fs::read(graph_path)?)
        .context("decoding static ability runtime graph")?;
    let artifact_class = parse_artifact_class(&spec.artifact_class)?;
    let execution_stage = parse_execution_stage(spec.execution_stage.as_deref())?;

    let mut platforms = if let Some(platform) = &spec.platform {
        vec![assemble_platform(&spec, platform, &graph)?]
    } else {
        assemble_combined_platforms(&spec, artifact_class, execution_stage)?
    };
    platforms.sort_by(|left, right| platform_sort_key(left).cmp(&platform_sort_key(right)));
    if platforms
        .windows(2)
        .any(|pair| pair[0]["platform"] == pair[1]["platform"])
    {
        bail!("static ability contract contains a duplicate platform");
    }

    let contract = json!({
        "schema": spec.schema,
        "platforms": platforms,
        "runtime_grants": [],
    });
    let bytes =
        aos_contract::canonical::to_vec(&contract).context("encoding static ability contract")?;
    validate_ability_contract(AbilityContractData::Static {
        contract: &bytes,
        expectation: &StaticAbilityContractExpectation {
            artifact_class,
            execution_stage,
            platform: spec
                .platform
                .as_ref()
                .map(|platform| platform.expectation(spec.target_platform.clone())),
        },
    })?;
    if bytes.len() > 4 * 1024 * 1024 {
        bail!("static ability contract violates the 4 MiB JSON bound");
    }

    fs::create_dir_all(output)?;
    fs::write(output.join("contract.json"), &bytes)?;
    let descriptor = json!({
        "mediaType": spec.media_type,
        "digest": Sha256Digest::of_bytes(&bytes).to_string(),
        "size": bytes.len(),
    });
    fs::write(
        output.join("descriptor.json"),
        aos_contract::canonical::to_vec(&descriptor)?,
    )?;
    Ok(())
}

fn assemble_platform(
    spec: &StaticAssemblySpec,
    platform: &StaticAssemblyPlatform,
    graph: &Value,
) -> Result<Value> {
    let runtime = graph
        .get("staticAbilityRuntime")
        .and_then(Value::as_array)
        .context("static runtime graph is missing")?
        .iter()
        .filter_map(|member| member.get("path").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let mut packages = Vec::new();
    let mut abilities = Vec::new();
    let mut obligations = Vec::new();

    for selected in &spec.packages {
        let manifest_path = Path::new(&selected.manifest).join("package.json");
        let manifest_bytes = fs::read(&manifest_path)
            .with_context(|| format!("reading resolved package {}", manifest_path.display()))?;
        let document: aos_ability_model::PackageDocument =
            aos_contract::canonical::from_slice(&manifest_bytes, "resolved ability package")?;
        if document.package.payload.store_path != selected.payload
            || !runtime.contains(selected.payload.as_str())
        {
            bail!("resolved ability payload is not present in the selected runtime");
        }
        let manifest = json!({
            "store_path": selected.manifest,
            "digest": Sha256Digest::of_bytes(&manifest_bytes).to_string(),
        });
        let package = json!({
            "name": document.package.name,
            "version": document.package.version,
            "payload": document.package.payload,
            "manifest": manifest,
        });
        packages.push(package.clone());

        for export in &document.exports {
            let matching = document
                .implementation
                .providers
                .iter()
                .filter(|provider| provider.interface == export.interface)
                .collect::<Vec<_>>();
            let [provider] = matching.as_slice() else {
                bail!("ability export does not have one matching provider");
            };
            abilities.push(json!({
                "package": manifest,
                "export": export.name,
                "interface": export.interface,
                "implementation": export.implementation,
                "implementation_artifact": provider.artifact,
                "availability": if runtime.contains(provider.artifact.store_path.as_str()) {
                    "baked"
                } else {
                    "unresolved-at-launch"
                },
            }));
        }
        append_requirements(&mut obligations, &document.requirements, &manifest, None)?;
        for provider in &document.implementation.providers {
            append_requirements(
                &mut obligations,
                &provider.requirements,
                &manifest,
                Some(&provider.interface),
            )?;
            if !runtime.contains(provider.artifact.store_path.as_str()) {
                obligations.push(json!({
                    "kind": "implementation-artifact",
                    "consumer": {"package": manifest, "ability": provider.interface},
                    "artifact": provider.artifact,
                    "disposition": "external-launch-obligation",
                }));
            }
        }
    }
    packages.sort_by(|left, right| package_sort_key(left).cmp(package_sort_key(right)));
    abilities.sort_by(|left, right| ability_sort_key(left).cmp(&ability_sort_key(right)));
    obligations.sort_by(|left, right| obligation_sort_key(left).cmp(&obligation_sort_key(right)));
    let mut result = json!({
        "platform": platform,
        "packages": packages,
        "abilities": abilities,
        "unresolved_launch_obligations": obligations,
    });
    if let Some(target) = &spec.target_platform {
        result["target"] = serde_json::to_value(target)?;
    }
    if let Some(stage) = &spec.execution_stage {
        result["execution_stage"] = Value::String(stage.clone());
    }
    Ok(result)
}

fn append_requirements(
    obligations: &mut Vec<Value>,
    requirements: &[aos_ability_model::RequirementDeclaration],
    manifest: &Value,
    ability: Option<&aos_ability_model::InterfaceKey>,
) -> Result<()> {
    for requirement in requirements {
        let value = serde_json::to_value(requirement)?;
        if value["strength"] != "required" {
            continue;
        }
        let consumer = if let Some(ability) = ability {
            json!({"package": manifest, "ability": ability})
        } else {
            json!({"package": manifest})
        };
        obligations.push(json!({
            "kind": "ability-requirement",
            "consumer": consumer,
            "requirement": value,
            "disposition": "external-launch-obligation",
        }));
    }
    Ok(())
}

fn assemble_combined_platforms(
    spec: &StaticAssemblySpec,
    artifact_class: StaticAbilityArtifactClass,
    execution_stage: Option<StaticAbilityExecutionStage>,
) -> Result<Vec<Value>> {
    let mut platforms = Vec::new();
    for contract_path in &spec.contracts {
        let bytes = fs::read(Path::new(contract_path).join("contract.json"))?;
        validate_ability_contract(AbilityContractData::Static {
            contract: &bytes,
            expectation: &StaticAbilityContractExpectation {
                artifact_class,
                execution_stage,
                platform: None,
            },
        })?;
        let contract: Value = serde_json::from_slice(&bytes)?;
        platforms.extend(
            contract["platforms"]
                .as_array()
                .context("static contract platforms are not an array")?
                .iter()
                .cloned(),
        );
    }
    Ok(platforms)
}

fn platform_sort_key(value: &Value) -> (&str, &str, &str, &str, &str) {
    let platform = &value["platform"];
    let target = &value["target"];
    (
        value_string(platform, "os"),
        value_string(platform, "architecture"),
        value_string(platform, "variant"),
        value_string(target, "system"),
        value_string(target, "architecture"),
    )
}

fn package_sort_key(value: &Value) -> &str {
    value_string(&value["manifest"], "store_path")
}

fn ability_sort_key(value: &Value) -> (&str, &str, u64, &str, &str) {
    (
        value_string(&value["package"], "store_path"),
        value_string(&value["interface"], "name"),
        value["interface"]["abi"].as_u64().unwrap_or_default(),
        value_string(&value["interface"], "descriptor"),
        value_string(value, "export"),
    )
}

fn obligation_sort_key(value: &Value) -> (&str, &str, u8, &str, &str) {
    (
        value_string(&value["consumer"]["package"], "store_path"),
        value_string(&value["consumer"]["ability"], "name"),
        u8::from(value_string(value, "kind") == "implementation-artifact"),
        value_string(&value["requirement"], "alias"),
        value_string(&value["artifact"], "store_path"),
    )
}

fn value_string<'a>(value: &'a Value, field: &str) -> &'a str {
    value.get(field).and_then(Value::as_str).unwrap_or_default()
}

fn parse_artifact_class(value: &str) -> Result<StaticAbilityArtifactClass> {
    match value {
        "container" => Ok(StaticAbilityArtifactClass::Container),
        "bootable" => Ok(StaticAbilityArtifactClass::Bootable),
        _ => bail!("artifact class must be container or bootable"),
    }
}

fn parse_execution_stage(value: Option<&str>) -> Result<Option<StaticAbilityExecutionStage>> {
    match value {
        None => Ok(None),
        Some("initrd") => Ok(Some(StaticAbilityExecutionStage::Initrd)),
        Some("host") => Ok(Some(StaticAbilityExecutionStage::Host)),
        Some(_) => bail!("execution stage must be initrd or host"),
    }
}

/// Resolves one canonical package projection through an exported Nix graph.
///
/// # Errors
///
/// Returns an error when a selector is missing, ambiguous, malformed, or does
/// not match its authenticated exported-graph artifact.
pub fn resolve_package_projection_file(
    projection_path: &Path,
    resolution_path: &Path,
    exported_graph_path: &Path,
    output_directory: &Path,
) -> Result<()> {
    let projection_bytes = fs::read(projection_path)
        .with_context(|| format!("reading ability projection {}", projection_path.display()))?;
    let projection = decode_package_projection(&projection_bytes)?;
    let interface_documents = projection.interface_documents.clone();
    let resolution: ProjectionResolutionSpec =
        serde_json::from_slice(&fs::read(resolution_path).with_context(|| {
            format!("reading selector resolution {}", resolution_path.display())
        })?)
        .context("decoding selector resolution")?;
    let exported_graph: serde_json::Value =
        serde_json::from_slice(&fs::read(exported_graph_path).with_context(|| {
            format!("reading exported graph {}", exported_graph_path.display())
        })?)
        .context("decoding exported Nix graph")?;

    let payload = resolve_selected_artifact(&resolution.payload, &exported_graph)?.artifact;
    let source = resolve_selected_artifact(&resolution.source, &exported_graph)?.artifact;
    let mut selectors = BTreeMap::new();
    for selected in &resolution.selectors {
        let package = selected
            .package
            .as_deref()
            .context("selector resolution is missing package")?;
        let output = selected
            .output
            .as_deref()
            .context("selector resolution is missing output")?;
        let key = (package.to_string(), output.to_string());
        if selectors.insert(key.clone(), selected).is_some() {
            bail!("selector resolution repeats ({}, {})", key.0, key.1);
        }
    }
    let supplied_selectors = selectors
        .keys()
        .map(|(package, output)| -> Result<PackageOutputSelector> {
            Ok(PackageOutputSelector {
                package: aos_ability_model::LocalKey::new(package.clone())?,
                output: aos_ability_model::LocalKey::new(output.clone())?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        supplied_selectors == projection.artifacts,
        "selector resolutions do not exactly cover the canonical projection selectors"
    );
    let resolved_selectors = selectors
        .iter()
        .map(|((package, output), selected)| {
            Ok(ResolvedPackageOutput {
                package: package.clone(),
                output: output.clone(),
                artifact: resolve_selected_artifact(selected, &exported_graph)?.artifact,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let document = resolve_package_projection(projection, payload, source, |selector| {
        let key = (
            selector.package.as_str().to_string(),
            selector.output.as_str().to_string(),
        );
        let selected = selectors
            .get(&key)
            .with_context(|| format!("selector resolution omits ({}, {})", key.0, key.1))?;
        Ok(resolve_selected_artifact(selected, &exported_graph)?.artifact)
    })?;
    let manifest = encode_canonical(&document).context("encoding resolved ability package")?;
    let selector_manifest = aos_contract::canonical::to_vec(&resolved_selectors)
        .context("encoding resolved package output selectors")?;

    fs::create_dir_all(output_directory.join("interfaces")).with_context(|| {
        format!(
            "creating resolved ability output {}",
            output_directory.display()
        )
    })?;
    fs::write(output_directory.join("package.json"), &manifest)
        .context("writing resolved ability package")?;
    fs::write(output_directory.join("selectors.json"), &selector_manifest)
        .context("writing resolved package output selectors")?;
    for interface in &interface_documents {
        let name = format!("{}.json", interface.descriptor.hex());
        fs::write(
            output_directory.join("interfaces").join(&name),
            encode_canonical(&interface.document)?,
        )
        .with_context(|| format!("writing retained interface {name}"))?;
    }
    validate_package_source(
        &output_directory.join("package.json"),
        &output_directory.join("interfaces"),
    )
}

/// Writes one artifact reference derived from an exact exported Nix graph.
///
/// The output also carries the reachable closure paths so build audits can
/// check retention without reimplementing graph traversal or digest rules.
///
/// # Errors
///
/// Returns an error when the exported graph is malformed, incomplete, or does
/// not contain the selected root, or when the result cannot be written.
pub fn write_exported_artifact_reference(
    root: &Path,
    graph_name: &str,
    exported_graph_path: &Path,
    output_path: &Path,
) -> Result<()> {
    let exported_graph: Value = serde_json::from_slice(&fs::read(exported_graph_path)?)
        .context("decoding exported Nix graph")?;
    let selected = SelectedArtifact {
        package: None,
        output: None,
        path: root
            .to_str()
            .context("selected exported-graph root is not UTF-8")?
            .to_string(),
        graph: graph_name.to_string(),
    };
    let resolved = resolve_selected_artifact(&selected, &exported_graph)?;

    fs::write(output_path, aos_contract::canonical::to_vec(&resolved)?)
        .with_context(|| format!("writing artifact reference {}", output_path.display()))
}

fn resolve_selected_artifact(
    selected: &SelectedArtifact,
    exported_graph: &serde_json::Value,
) -> Result<ResolvedExportedArtifact> {
    let members: Vec<ExportedGraphMember> = serde_json::from_value(
        exported_graph
            .get(&selected.graph)
            .with_context(|| format!("exported Nix graph omits '{}'", selected.graph))?
            .clone(),
    )
    .with_context(|| format!("decoding exported Nix graph '{}'", selected.graph))?;
    let by_path = members
        .iter()
        .map(|member| (member.path.as_str(), member))
        .collect::<BTreeMap<_, _>>();
    if by_path.len() != members.len() || !by_path.contains_key(selected.path.as_str()) {
        bail!(
            "exported Nix graph '{}' is duplicate or omits its root",
            selected.graph
        );
    }
    for member in &members {
        require_store_root(&member.path)?;
        if member.nar_size == 0
            || !member.valid
            || member.ca.as_ref().is_some_and(String::is_empty)
            || member
                .references
                .iter()
                .any(|reference| !by_path.contains_key(reference.as_str()))
        {
            bail!(
                "exported Nix graph '{}' is malformed or incomplete",
                selected.graph
            );
        }

        let mut member_closure = BTreeSet::from([member.path.as_str()]);
        loop {
            let next = member_closure
                .iter()
                .flat_map(|path| by_path[path].references.iter().map(String::as_str))
                .collect::<BTreeSet<_>>();
            let before = member_closure.len();
            member_closure.extend(next);
            if member_closure.len() == before {
                break;
            }
        }
        let expected_closure_size = member_closure.iter().try_fold(0_u64, |total, path| {
            total
                .checked_add(by_path[path].nar_size)
                .context("exported Nix graph closure size exceeds the supported integer range")
        })?;
        if member.closure_size != expected_closure_size {
            bail!(
                "exported Nix graph '{}' records an incorrect closure size for {}",
                selected.graph,
                member.path
            );
        }
    }

    let mut reachable = BTreeSet::from([selected.path.as_str()]);
    loop {
        let next = reachable
            .iter()
            .flat_map(|path| by_path[path].references.iter().map(String::as_str))
            .collect::<BTreeSet<_>>();
        let before = reachable.len();
        reachable.extend(next);
        if reachable.len() == before {
            break;
        }
    }
    let mut closure_paths = reachable
        .iter()
        .map(|path| (*path).to_string())
        .collect::<Vec<_>>();
    closure_paths.sort();
    let closure = reachable
        .iter()
        .map(|path| {
            let member = by_path[path];
            let mut references = member
                .references
                .iter()
                .filter(|reference| reference.as_str() != member.path)
                .map(|reference| store_hash(reference).map(str::to_string))
                .collect::<Result<Vec<_>>>()?;
            references.sort();
            references.dedup();
            Ok(ArtifactClosureMemberInput {
                key: store_hash(&member.path)?.to_string(),
                nar_hash: Sha256Digest::parse(&canonical_nar_hash(&member.nar_hash)?)?,
                references,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let closure_digest = artifact_closure_identity(store_hash(&selected.path)?, &closure)?;
    let root = by_path[selected.path.as_str()];
    let nar_hash = canonical_nar_hash(&root.nar_hash)?;
    let nar_hash = Sha256Digest::parse(&nar_hash)?;
    let content = artifact_content_identity(&nar_hash);
    Ok(ResolvedExportedArtifact {
        artifact: ArtifactReference {
            content,
            store_path: selected.path.clone(),
            nar_hash,
            closure: closure_digest,
        },
        closure_paths,
    })
}

fn canonical_nar_hash(value: &str) -> Result<String> {
    let bytes = if let Some(encoded) = value.strip_prefix("sha256-") {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .context("decoding exported NAR SHA-256")?
    } else if let Some(encoded) = value.strip_prefix("sha256:") {
        match encoded.len() {
            64 if encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) => {
                hex::decode(encoded).context("decoding exported hexadecimal NAR SHA-256")?
            }
            52 => decode_nix_base32(encoded).context("decoding exported nixbase32 NAR SHA-256")?,
            _ => bail!("exported NAR hash has an unsupported SHA-256 encoding"),
        }
    } else {
        bail!("exported NAR hash is not SHA-256");
    };
    if bytes.len() != 32 {
        bail!("exported NAR SHA-256 has the wrong length");
    }
    Ok(format!("sha256:{}", hex::encode(bytes)))
}

fn decode_nix_base32(encoded: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

    let mut decoded = vec![0_u8; encoded.len() * 5 / 8];
    for (position, character) in encoded.chars().rev().enumerate() {
        let digit = ALPHABET
            .iter()
            .position(|byte| *byte as char == character)? as u16;
        let bit = position * 5;
        let byte = bit / 8;
        let offset = bit % 8;
        *decoded.get_mut(byte)? |= (digit << offset) as u8;
        let carry = digit >> (8 - offset);
        match decoded.get_mut(byte + 1) {
            Some(next) => *next |= carry as u8,
            None if carry != 0 => return None,
            None => {}
        }
    }
    Some(decoded)
}

fn require_store_root(value: &str) -> Result<()> {
    let name = value
        .strip_prefix("/nix/store/")
        .filter(|name| !name.contains('/'))
        .context("exported graph path is not an exact Nix store root")?;
    let hash = name
        .get(..32)
        .filter(|_| name.as_bytes().get(32) == Some(&b'-'))
        .context("exported graph path has no store hash")?;
    if !hash
        .bytes()
        .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
    {
        bail!("exported graph path has an invalid store hash");
    }
    Ok(())
}

fn store_hash(value: &str) -> Result<&str> {
    require_store_root(value)?;
    Ok(&value["/nix/store/".len()..][..32])
}

/// Validates one materialized package contract and its retained interfaces.
///
/// # Errors
///
/// Returns an error when the package document, retained interfaces, or their
/// shared semantic contract is invalid.
pub fn validate_package_source(manifest: &Path, interface_directory: &Path) -> Result<()> {
    let manifest_bytes = fs::read(manifest)
        .with_context(|| format!("reading ability manifest {}", manifest.display()))?;
    let mut interface_paths = fs::read_dir(interface_directory)
        .with_context(|| {
            format!(
                "reading retained interface directory {}",
                interface_directory.display()
            )
        })?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    interface_paths.sort();
    let interface_paths = interface_paths
        .into_iter()
        .filter(|path| path.extension() == Some(OsStr::new("json")))
        .collect::<Vec<_>>();
    let interfaces = interface_paths
        .iter()
        .map(|path| {
            fs::read(path).with_context(|| format!("reading retained interface {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;

    let checked = validate_ability_contract(AbilityContractData::PackageSource {
        manifest: &manifest_bytes,
        retained_interfaces: &interfaces,
    })
    .context("ability package failed shared Rust semantic validation")?;
    let crate::CheckedAbilityContract::PackageSource(contract) = checked else {
        bail!("package-source validation returned the wrong checked contract family");
    };
    if let Some(module) = &contract.package().package_module {
        validate_module_locator_target(module)
            .context("validating package ability module locator")?;
    }
    validate_option_source_targets(contract.package())?;
    for provider in &contract.package().implementation.providers {
        if let Some(locator) = &provider.provider_module {
            validate_module_locator_target(locator)
                .context("validating provider ability module locator")?;
        }
    }
    Ok(())
}

fn validate_option_source_targets(package: &aos_ability_model::PackageDocument) -> Result<()> {
    let Some(module) = &package.package_module else {
        ensure!(
            package.option_declarations.is_empty(),
            "package without an ability module declares package options"
        );
        return Ok(());
    };
    let module_root = Path::new(&module.artifact.store_path);
    for declaration in &package.option_declarations {
        let target = module_root.join(declaration.source.path.as_str());
        ensure!(
            target.is_file(),
            "ability option declaration source {} is not a regular file in the authenticated module artifact",
            target.display()
        );
    }
    Ok(())
}

fn validate_module_locator_target(locator: &aos_ability_model::ModuleLocator) -> Result<()> {
    let root = Path::new(&locator.artifact.store_path);
    let target = root.join(locator.path.as_str());
    ensure!(
        target.is_file(),
        "ability module locator target {} is not a regular file",
        target.display()
    );
    Ok(())
}

/// Validates one static contract against command-line expectation fields.
///
/// # Errors
///
/// Returns an error when the expectation fields are invalid or the contract
/// fails the shared semantic validator.
pub fn validate_static_contract(arguments: &[std::ffi::OsString]) -> Result<()> {
    let contract_path = PathBuf::from(&arguments[0]);
    let artifact_class = match arguments[1].to_str() {
        Some("container") => StaticAbilityArtifactClass::Container,
        Some("bootable") => StaticAbilityArtifactClass::Bootable,
        _ => bail!("artifact class must be container or bootable"),
    };
    let execution_stage = match arguments[2].to_str() {
        Some("-") => None,
        Some("initrd") => Some(StaticAbilityExecutionStage::Initrd),
        Some("host") => Some(StaticAbilityExecutionStage::Host),
        _ => bail!("execution stage must be -, initrd, or host"),
    };
    let platform = if arguments.len() == 6 {
        let text = |index: usize, label: &str| {
            arguments[index]
                .to_str()
                .map(str::to_owned)
                .with_context(|| format!("{label} is not UTF-8"))
        };
        let variant = text(5, "platform variant")?;
        Some(StaticAbilityPlatform {
            os: text(3, "platform operating system")?,
            architecture: text(4, "platform architecture")?,
            variant: (variant != "-").then_some(variant),
            target: None,
        })
    } else {
        None
    };
    let expectation = StaticAbilityContractExpectation {
        artifact_class,
        execution_stage,
        platform,
    };
    let bytes = fs::read(&contract_path).with_context(|| {
        format!(
            "reading static ability contract {}",
            contract_path.display()
        )
    })?;

    validate_static_ability_artifacts(&bytes, &expectation)
        .context("static contract failed shared Rust semantic validation")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "/nix/store/00000000000000000000000000000000-root";
    const DEPENDENCY: &str = "/nix/store/11111111111111111111111111111111-dependency";
    const DISCONNECTED: &str = "/nix/store/22222222222222222222222222222222-disconnected";

    fn selected_root() -> SelectedArtifact {
        SelectedArtifact {
            package: None,
            output: None,
            path: ROOT.to_string(),
            graph: "runtimeGraph".to_string(),
        }
    }

    fn exported_graph() -> Value {
        json!({
            "runtimeGraph": [
                {
                    "path": ROOT,
                    "narHash": format!("sha256:{}", "11".repeat(32)),
                    "narSize": 10,
                    "closureSize": 30,
                    "valid": true,
                    "ca": "fixed:r:sha256:fixture",
                    "references": [DEPENDENCY],
                },
                {
                    "path": DEPENDENCY,
                    "narHash": format!("sha256:{}", "22".repeat(32)),
                    "narSize": 20,
                    "closureSize": 20,
                    "valid": true,
                    "references": [DEPENDENCY],
                },
                {
                    "path": DISCONNECTED,
                    "narHash": format!("sha256:{}", "33".repeat(32)),
                    "narSize": 30,
                    "closureSize": 30,
                    "valid": true,
                    "references": [],
                },
            ],
        })
    }

    #[test]
    fn exported_artifact_uses_shared_content_identity_and_reachable_closure() {
        let resolved = resolve_selected_artifact(&selected_root(), &exported_graph())
            .expect("valid exported graph should resolve");
        let nar_hash = Sha256Digest::parse(&format!("sha256:{}", "11".repeat(32)))
            .expect("test digest should parse");

        assert_eq!(
            resolved.artifact.content,
            artifact_content_identity(&nar_hash)
        );
        assert_eq!(resolved.artifact.nar_hash, nar_hash);
        assert_eq!(resolved.artifact.store_path, ROOT);
        assert_eq!(
            resolved.closure_paths,
            vec![ROOT.to_string(), DEPENDENCY.to_string()]
        );
    }

    #[test]
    fn exported_artifact_rejects_incomplete_reference_graph() {
        let mut graph = exported_graph();
        graph["runtimeGraph"][0]["references"] =
            json!(["/nix/store/33333333333333333333333333333333-missing"]);

        let error = resolve_selected_artifact(&selected_root(), &graph)
            .expect_err("an absent referenced member must fail closed");

        assert!(error.to_string().contains("malformed or incomplete"));
    }

    #[test]
    fn exported_artifact_rejects_closure_smaller_than_its_nar() {
        let mut graph = exported_graph();
        graph["runtimeGraph"][0]["closureSize"] = json!(9);

        let error = resolve_selected_artifact(&selected_root(), &graph)
            .expect_err("closure size below the member NAR must fail closed");

        assert!(error.to_string().contains("incorrect closure size"));
    }

    #[test]
    fn exported_artifact_rejects_invalid_or_empty_content_address_metadata() {
        let mut invalid = exported_graph();
        invalid["runtimeGraph"][0]["valid"] = json!(false);
        assert!(resolve_selected_artifact(&selected_root(), &invalid).is_err());

        let mut empty_content_address = exported_graph();
        empty_content_address["runtimeGraph"][0]["ca"] = json!("");
        assert!(resolve_selected_artifact(&selected_root(), &empty_content_address).is_err());
    }

    #[test]
    fn module_locator_requires_a_regular_file_below_its_artifact_root() {
        let root = std::env::temp_dir().join(format!(
            "aos-module-locator-validation-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("providers")).expect("create module fixture root");
        fs::write(root.join("providers/module.nix"), "{ ... }: {}").expect("write module fixture");
        let locator = aos_ability_model::ModuleLocator {
            artifact: ArtifactReference {
                content: Sha256Digest::of_bytes(b"module"),
                store_path: root.display().to_string(),
                nar_hash: Sha256Digest::of_bytes(b"module nar"),
                closure: Sha256Digest::of_bytes(b"module closure"),
            },
            path: aos_ability_model::RelativePath::new("providers/module.nix")
                .expect("valid relative module path"),
        };

        validate_module_locator_target(&locator).expect("regular module target must validate");

        let missing = aos_ability_model::ModuleLocator {
            path: aos_ability_model::RelativePath::new("providers/missing.nix")
                .expect("valid missing path"),
            ..locator
        };
        assert!(validate_module_locator_target(&missing).is_err());
        fs::remove_dir_all(root).expect("remove module fixture root");
    }

    #[test]
    fn option_declaration_source_must_exist_in_the_authenticated_module_artifact() {
        let root = std::env::temp_dir().join(format!(
            "aos-option-source-validation-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create option source fixture root");
        fs::write(root.join("module.nix"), "{ ... }: {}").expect("write module fixture");

        let mut fixture = crate::test_support::stateful_owner_plan_fixture();
        let mut package = fixture.binding_inputs.packages.remove(0);
        package
            .package_module
            .as_mut()
            .expect("fixture package has a module")
            .artifact
            .store_path = root.display().to_string();
        package.option_declarations = vec![aos_ability_model::PackageOptionDeclaration {
            path: vec!["service".to_string(), "enable".to_string()],
            type_signature: "boolean".to_string(),
            structured_type: aos_ability_model::OptionType::Bool,
            description: "Enables the service.".to_string(),
            default: None,
            example: None,
            visibility: aos_ability_model::OptionVisibility::Public,
            read_only: false,
            contributable: false,
            deprecated: None,
            replacement: None,
            source: aos_ability_model::OptionSource {
                path: aos_ability_model::RelativePath::new("missing.nix")
                    .expect("valid missing source path"),
            },
        }];

        assert!(validate_option_source_targets(&package).is_err());
        fs::remove_dir_all(root).expect("remove option source fixture root");
    }
}
