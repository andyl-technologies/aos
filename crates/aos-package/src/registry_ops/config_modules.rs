//! Config-module interface derivation and validation of builder-authored claims.

use crate::registry_ops::documentation::PublishDocumentationManifest;
use crate::registry_ops::store_paths::{
    StorePathInfo, TARGET_PLATFORM_RELATIVE_PATH, introspect_store_path, nix_command,
};
use crate::types::{
    ConfigModuleMeta, ConfigOptionDeclaration, ConfigOutputMeta, ModuleAbiCompat, OwnedRoot,
    RootContribution, validate_config_module_meta, validate_config_output_meta,
    validate_package_name,
};
use anyhow::{Context, Result, bail};
use aos_doc_model::{DocumentedValue, OptionType, Visibility};
use regex::Regex;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Builder-authored config-module claims copied into the trusted companion
/// output. Publish treats these fields as assertions to cross-check against
/// the module's mechanically derived interface, never as the authority for
/// declarations or contribution paths.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::registry_ops) struct PublishConfigModuleManifest {
    pub(in crate::registry_ops) schema: String,
    pub(in crate::registry_ops) module_abi_compat: ModuleAbiCompat,
    #[serde(default)]
    pub(in crate::registry_ops) declares: Vec<String>,
    #[serde(default)]
    pub(in crate::registry_ops) owns_roots: Vec<OwnedRoot>,
    #[serde(default)]
    pub(in crate::registry_ops) contributes: Vec<RootContribution>,
    #[serde(default)]
    pub(in crate::registry_ops) artifacts: crate::types::ConfigModuleArtifacts,
    #[serde(default)]
    pub(in crate::registry_ops) provides_capabilities: Vec<String>,
    #[serde(default)]
    pub(in crate::registry_ops) dependencies: Vec<String>,
    #[serde(default)]
    pub(in crate::registry_ops) documentation: PublishDocumentationManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::registry_ops) struct DerivedOptionDeclaration {
    pub(in crate::registry_ops) path: Vec<String>,
    #[serde(rename = "pathStr")]
    pub(in crate::registry_ops) path_str: String,
    #[serde(rename = "typeSig")]
    pub(in crate::registry_ops) type_sig: String,
    #[serde(rename = "type")]
    pub(in crate::registry_ops) option_type: OptionType,
    #[serde(default)]
    pub(in crate::registry_ops) description: String,
    #[serde(default)]
    pub(in crate::registry_ops) default: Option<DocumentedValue>,
    #[serde(default)]
    pub(in crate::registry_ops) example: Option<DocumentedValue>,
    pub(in crate::registry_ops) visibility: Visibility,
    #[serde(default, rename = "readOnly")]
    pub(in crate::registry_ops) read_only: bool,
    #[serde(default)]
    pub(in crate::registry_ops) contributable: bool,
    pub(in crate::registry_ops) owner: String,
}

#[derive(Debug)]
pub(in crate::registry_ops) struct PublishedConfigModule {
    pub(in crate::registry_ops) metadata: ConfigModuleMeta,
    pub(in crate::registry_ops) authored: PublishConfigModuleManifest,
    pub(in crate::registry_ops) declarations: Vec<DerivedOptionDeclaration>,
}

/// Parses and authenticates the named outputs exposed to a config module.
pub(in crate::registry_ops) fn parse_config_dependency_outputs(
    values: &[String],
    runtime_output: &StorePathInfo,
) -> Result<BTreeMap<String, String>> {
    let mut outputs = BTreeMap::new();
    for value in values {
        let (name, path) = value.split_once('=').with_context(|| {
            format!("invalid --config-dependency {value:?}; expected name=/nix/store/path")
        })?;
        validate_package_name(name)
            .with_context(|| format!("validating config dependency name {name:?}"))?;
        let dependency = introspect_store_path(path)
            .with_context(|| format!("introspecting config dependency {name:?}"))?;
        let dependency_hash = crate::registry::store_path_hash(&dependency.path);
        if !runtime_output
            .references
            .iter()
            .any(|hash| hash == dependency_hash)
        {
            bail!(
                "config dependency '{name}' output {} is not a direct runtime reference of {}",
                dependency.path,
                runtime_output.path
            );
        }
        if outputs.insert(name.to_string(), dependency.path).is_some() {
            bail!("config dependency '{name}' was supplied more than once");
        }
    }
    Ok(outputs)
}

pub(in crate::registry_ops) fn read_publish_config_module(
    config_output: &StorePathInfo,
    base_lib: &StorePathInfo,
    package_name: &str,
    runtime_output: &str,
    dependency_outputs: &BTreeMap<String, String>,
) -> Result<PublishedConfigModule> {
    let root = Path::new(&config_output.path);
    let module_path = root.join("module.nix");
    let manifest_path = root.join("config-meta.json");
    for path in [&module_path, &manifest_path] {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("reading config-module artifact {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "config-module artifact {} must be a regular file, not a symlink",
                path.display()
            );
        }
    }
    reject_config_derivation_references(&config_output.path)?;

    let manifest_bytes =
        fs::read(&manifest_path).with_context(|| format!("reading {}", manifest_path.display()))?;
    let authored: PublishConfigModuleManifest = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;
    if authored.schema != "aos.config-module-meta/v1" {
        bail!(
            "config-module artifact {} has unsupported metadata schema '{}'",
            config_output.path,
            authored.schema
        );
    }
    let mut dependency_names = dependency_outputs.keys().cloned().collect::<Vec<_>>();
    dependency_names.sort();
    let mut authored_dependencies = authored.dependencies.clone();
    authored_dependencies.sort();
    authored_dependencies.dedup();
    if dependency_names != authored_dependencies {
        bail!(
            "config-meta.json dependency claims do not match --config-dependency arguments: authored={authored_dependencies:?}, supplied={dependency_names:?}"
        );
    }

    let declarations = derive_config_option_declarations(
        &config_output.path,
        &base_lib.path,
        package_name,
        runtime_output,
        dependency_outputs,
        &authored,
    )?;
    let mut declares = declarations
        .iter()
        .map(|declaration| declaration.path_str.clone())
        .filter(|path| !path.starts_with("_module."))
        .collect::<Vec<_>>();
    declares.sort();
    declares.dedup();
    let mut declaration_schema = declarations
        .iter()
        .filter(|declaration| !declaration.path_str.starts_with("_module."))
        .map(|declaration| ConfigOptionDeclaration {
            path: declaration.path_str.clone(),
            type_signature: declaration.type_sig.clone(),
        })
        .collect::<Vec<_>>();
    declaration_schema.sort_by(|left, right| left.path.cmp(&right.path));

    let mut authored_declares = authored.declares.clone();
    authored_declares.sort();
    authored_declares.dedup();
    if declares != authored_declares {
        bail!(
            "config-meta.json declaration claims do not match options-only evaluation for package '{package_name}': authored={authored_declares:?}, derived={declares:?}"
        );
    }

    // Ownership is derived structurally: every declared non-private root is
    // owned by this module. The authored manifest supplies only the ABI number
    // for each mechanically discovered root.
    let mut owned_by_name = authored
        .owns_roots
        .iter()
        .map(|owned| (owned.root.as_str(), owned))
        .collect::<BTreeMap<_, _>>();
    let derived_owned_roots =
        derive_owned_root_names(&declares, package_name, &authored.owns_roots);
    let mut owns_roots = Vec::with_capacity(derived_owned_roots.len());
    for root in &derived_owned_roots {
        let authored_root = owned_by_name.remove(root.as_str()).with_context(|| {
            format!(
                "config-meta.json does not supply interface_abi for derived owned root '{root}'"
            )
        })?;
        let mut contributable = declarations
            .iter()
            .filter(|declaration| declaration.contributable)
            .filter_map(|declaration| {
                declaration
                    .path_str
                    .strip_prefix(&format!("{root}."))
                    .map(str::to_string)
            })
            .collect::<Vec<_>>();
        contributable.sort();
        contributable.dedup();
        let mut authored_contributable = authored_root.contributable.clone();
        authored_contributable.sort();
        authored_contributable.dedup();
        if contributable != authored_contributable {
            bail!(
                "config-meta.json contributable claims for root '{root}' do not match options-only evaluation: authored={authored_contributable:?}, derived={contributable:?}"
            );
        }
        owns_roots.push(OwnedRoot {
            root: root.clone(),
            interface_abi: authored_root.interface_abi,
            contributable,
        });
    }
    if !owned_by_name.is_empty() {
        let extras = owned_by_name.keys().copied().collect::<Vec<_>>();
        bail!("config-meta.json claims roots not owned by evaluated declarations: {extras:?}");
    }

    let (contributes, provides_capabilities, requires) = scan_config_module_interface(
        root,
        package_name,
        &derived_owned_roots,
        &authored.contributes,
    )?;
    let mut authored_contributes = authored.contributes.clone();
    normalize_contributions(&mut authored_contributes);
    if contributes != authored_contributes {
        bail!(
            "config-meta.json contribution claims do not match the conservative module scan: authored={authored_contributes:?}, derived={contributes:?}; publish scanning requires explicit config.<path> assignments for foreign contributions"
        );
    }
    let mut authored_capabilities = authored.provides_capabilities.clone();
    authored_capabilities.sort();
    authored_capabilities.dedup();
    if provides_capabilities != authored_capabilities {
        bail!(
            "config-meta.json capability claims do not match the conservative module scan: authored={authored_capabilities:?}, derived={provides_capabilities:?}; publish scanning requires explicit config.system.capabilities.<token> assignments"
        );
    }

    let module = ConfigModuleMeta {
        config_output: ConfigOutputMeta {
            store_path: config_output.path.clone(),
            nar_hash: config_output.nar_hash.clone(),
            nar_size: config_output.nar_size,
            references: config_output.references.clone(),
        },
        evaluation_base_lib: Some(ConfigOutputMeta {
            store_path: base_lib.path.clone(),
            nar_hash: base_lib.nar_hash.clone(),
            nar_size: base_lib.nar_size,
            references: base_lib.references.clone(),
        }),
        dependency_outputs: dependency_outputs.clone(),
        module_abi_compat: authored.module_abi_compat,
        declares,
        declaration_schema,
        requires,
        owns_roots,
        contributes,
        artifacts: authored.artifacts.clone(),
        provides_capabilities,
    };
    validate_config_output_meta(&module.config_output)?;
    validate_config_module_meta(package_name, &module)?;
    Ok(PublishedConfigModule {
        metadata: module,
        authored,
        declarations: declarations
            .into_iter()
            .filter(|declaration| !declaration.path_str.starts_with("_module."))
            .collect(),
    })
}

fn derive_owned_root_names(
    declares: &[String],
    package_name: &str,
    authored_roots: &[OwnedRoot],
) -> Vec<String> {
    let mut roots = declares
        .iter()
        .filter_map(|path| path.split('.').next())
        .filter(|root| {
            // Package-prefixed declarations are private by default, but an
            // explicit ownsRoots entry promotes that same-name root into a
            // versioned contributor interface. Publication must validate the
            // claim just like any differently named shared root.
            *root != package_name || authored_roots.iter().any(|owned| owned.root == *root)
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();
    roots
}

fn reject_config_derivation_references(config_output: &str) -> Result<()> {
    let output = nix_command("nix-store")
        .args(["--query", "--references", config_output])
        .output()
        .with_context(|| format!("querying config-module references for {config_output}"))?;
    if !output.status.success() {
        bail!(
            "nix-store --query --references failed for config module {config_output}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if let Some(reference) = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|reference| !reference.trim().is_empty())
    {
        bail!(
            "config module {config_output} must have an empty reference set, but references {reference}"
        );
    }
    Ok(())
}

fn derive_config_option_declarations(
    config_output: &str,
    base_lib_path: &str,
    package_name: &str,
    runtime_output: &str,
    dependency_outputs: &BTreeMap<String, String>,
    authored: &PublishConfigModuleManifest,
) -> Result<Vec<DerivedOptionDeclaration>> {
    let owns = authored
        .owns_roots
        .iter()
        .map(|owned| nix_publish_string(&owned.root))
        .collect::<Vec<_>>()
        .join(" ");
    let contributes = authored
        .contributes
        .iter()
        .map(|contribution| {
            let paths = contribution
                .paths
                .iter()
                .map(|path| nix_publish_string(path))
                .collect::<Vec<_>>()
                .join(" ");
            format!("{} = [ {paths} ];", nix_publish_string(&contribution.root))
        })
        .collect::<Vec<_>>()
        .join(" ");
    let expression = format!(
        r#"let
  base = import <aos-publish-base-lib>;
  evaluated = base.lib.evalModules {{
    modules = [];
    packageModules = [ {{
      name = {};
      configRoot = <aos-publish-config-module>;
      module = <aos-publish-config-module/module.nix>;
      outputs = {{ self = builtins.toString <aos-publish-runtime-output>; dependencies = {{ {} }}; }};
      authorization = {{ owns = [ {owns} ]; contributes = {{ {contributes} }}; }};
    }} ];
    inherit (base) lib;
  }};
in builtins.map (decl: {{
  inherit (decl)
    path pathStr typeSig type description default example visibility readOnly
    contributable owner;
}})
  (base.lib.optionSurface evaluated)"#,
        nix_publish_string(package_name),
        dependency_outputs
            .iter()
            .enumerate()
            .map(|(index, (name, _path))| {
                format!(
                    "{} = builtins.toString <aos-publish-config-dependency-{index}>;",
                    nix_publish_string(name),
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    );
    let base_search_path = format!("aos-publish-base-lib={base_lib_path}");
    let module_search_path = format!("aos-publish-config-module={config_output}");
    let runtime_search_path = format!("aos-publish-runtime-output={runtime_output}");
    let evaluator = std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|directory| directory.join("nix-instantiate"))
                .find(|candidate| candidate.is_file())
        })
        .context("cannot find nix-instantiate in the AOS command path")?;
    let mut command = Command::new(evaluator);
    command.env_clear();
    command.args([
        "--store",
        "dummy://",
        "--eval",
        "--strict",
        "--json",
        "--option",
        "restrict-eval",
        "true",
        "--option",
        "allow-import-from-derivation",
        "false",
        "-I",
        &base_search_path,
        "-I",
        &module_search_path,
        "-I",
        &runtime_search_path,
    ]);
    for (index, path) in dependency_outputs.values().enumerate() {
        let search_path = format!("aos-publish-config-dependency-{index}={path}");
        command.args(["-I", &search_path]);
    }
    let output = command
        .args(["--expr", &expression])
        .output()
        .with_context(|| {
            format!("running options-only config-module eval for package '{package_name}'")
        })?;
    if !output.status.success() {
        bail!(
            "options-only config-module eval failed for package '{package_name}': {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!("parsing options-only config-module eval for package '{package_name}'")
    })
}

pub(in crate::registry_ops) fn nix_publish_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn normalize_contributions(contributions: &mut Vec<RootContribution>) {
    for contribution in contributions.iter_mut() {
        contribution.paths.sort();
        contribution.paths.dedup();
    }
    contributions.sort_by(|left, right| left.root.cmp(&right.root));
}

fn scan_config_module_interface(
    root: &Path,
    package_name: &str,
    owned_roots: &[String],
    authored_contributions: &[RootContribution],
) -> Result<(Vec<RootContribution>, Vec<String>, Vec<String>)> {
    // The leading boundary is security-relevant: an owned path such as
    // `cloudcore.config.runtime` must not be reinterpreted from its suffix as
    // a foreign write to `runtime`.
    let access = Regex::new(
        r"(?m)(?:^|[^A-Za-z0-9_.-])(?:config|options)\.([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)",
    )?;
    let assignment =
        Regex::new(r"(?m)(?:^|[^A-Za-z0-9_.-])config\.([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)\s*=")?;
    let mut requires = Vec::new();
    let mut writes = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspecting config-module source {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!(
                "config-module source must not contain symlink {}",
                path.display()
            );
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .with_context(|| format!("reading config-module directory {}", path.display()))?
            {
                pending.push(entry?.path());
            }
            continue;
        }
        let relative = path.strip_prefix(root).unwrap_or(&path);
        if relative == Path::new("config-meta.json")
            || relative == Path::new("expose-config.json")
            || relative == Path::new("generated/expose-config.json")
            || relative == Path::new(TARGET_PLATFORM_RELATIVE_PATH)
        {
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) != Some("nix") {
            bail!(
                "config-module source contains non-Nix helper {}",
                path.display()
            );
        }
        let source = fs::read_to_string(&path)
            .with_context(|| format!("reading config-module source {}", path.display()))?;
        let code = strip_nix_comments_and_strings(&source);
        requires.extend(
            access
                .captures_iter(&code)
                .map(|capture| capture[1].to_string()),
        );
        writes.extend(
            assignment
                .captures_iter(&code)
                .map(|capture| capture[1].to_string()),
        );
    }
    requires.sort();
    requires.dedup();
    writes.sort();
    writes.dedup();

    let owned = owned_roots
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let write_set = writes.iter().map(String::as_str).collect::<HashSet<_>>();
    requires.retain(|path| {
        let root = path.split_once('.').map_or(path.as_str(), |(root, _)| root);
        root != package_name
            && root != "_module"
            && root != "assertions"
            && root != "warnings"
            && !owned.contains(root)
            && !write_set.contains(path.as_str())
    });
    let mut contribution_map = BTreeMap::<String, Vec<String>>::new();
    let mut provides_capabilities = Vec::new();
    for path in writes {
        if let Some(token) = path.strip_prefix("system.capabilities.") {
            provides_capabilities.push(format!("system.capabilities.{token}"));
            continue;
        }
        let Some((root, relative)) = path.split_once('.') else {
            continue;
        };
        if matches!(root, "_module" | "assertions" | "warnings") {
            continue;
        }
        if root != package_name && !owned.contains(root) {
            contribution_map
                .entry(root.to_string())
                .or_default()
                .push(relative.to_string());
        }
    }
    let contribution_abis = authored_contributions
        .iter()
        .map(|contribution| (contribution.root.as_str(), contribution.interface_abi))
        .collect::<BTreeMap<_, _>>();
    let mut contributes = contribution_map
        .into_iter()
        .map(|(root, paths)| {
            let interface_abi = contribution_abis.get(root.as_str()).copied().with_context(|| {
                format!(
                    "foreign contribution to root '{root}' has no authenticated interface_abi; set contributes[].interfaceAbi to the owner's current interface ABI and republish"
                )
            })?;
            Ok(RootContribution {
                root,
                interface_abi,
                paths,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    normalize_contributions(&mut contributes);
    provides_capabilities.sort();
    provides_capabilities.dedup();
    Ok((contributes, provides_capabilities, requires))
}

/// Blanks comments and string bodies while preserving byte positions/newlines.
///
/// Assignment discovery must not accept a claimed foreign write merely
/// because `config.foo =` appears in documentation or a string literal.
fn strip_nix_comments_and_strings(source: &str) -> String {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        Comment,
        DoubleQuoted { escaped: bool },
        Indented,
    }

    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut state = State::Code;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        match state {
            State::Code if byte == b'#' => {
                output.push(' ');
                state = State::Comment;
            }
            State::Code if byte == b'"' => {
                output.push(' ');
                state = State::DoubleQuoted { escaped: false };
            }
            State::Code if byte == b'\'' && bytes.get(index + 1).copied() == Some(b'\'') => {
                output.push_str("  ");
                index += 1;
                state = State::Indented;
            }
            State::Code => output.push(char::from(byte)),
            State::Comment if byte == b'\n' => {
                output.push('\n');
                state = State::Code;
            }
            State::Comment => output.push(' '),
            State::DoubleQuoted { escaped: false } if byte == b'"' => {
                output.push(' ');
                state = State::Code;
            }
            State::DoubleQuoted { escaped } => {
                output.push(if byte == b'\n' { '\n' } else { ' ' });
                state = State::DoubleQuoted {
                    escaped: !escaped && byte == b'\\',
                };
            }
            State::Indented if byte == b'\'' && bytes.get(index + 1).copied() == Some(b'\'') => {
                output.push_str("  ");
                index += 1;
                state = State::Code;
            }
            State::Indented => output.push(if byte == b'\n' { '\n' } else { ' ' }),
        }
        index += 1;
    }
    output
}

#[cfg(test)]
mod tests;
