//! Versioned Nix policy and inspectable action identities.
//!
//! A manifest declares compiler executables and their realized closure:
//! ```json
//! {"schema":1,"compilers":{"/nix/store/.../bin/gcc":"c"},
//!  "closure":[{"path":"/nix/store/...","narHash":"sha256:..."}],
//!  "remove_environment":[]}
//! ```
//! Environment exclusions affect execution as well as hashing. Ignoring a
//! value while still letting the compiler read it would permit false hits.

use std::{
    collections::BTreeMap,
    env, fs,
    io::Read,
    path::{Component, Path},
    process::Command,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Declares the realized Nix compiler closure and permitted mutable read roots.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Manifest format version; only version one is accepted.
    pub schema: u32,
    /// Absolute compiler paths mapped to their frontend adapter names.
    pub compilers: BTreeMap<String, String>,
    /// Realized compiler and dependency roots, including transitive references.
    pub closure: Vec<ClosurePath>,
    /// Variables removed from both execution and the action identity.
    #[serde(default)]
    pub remove_environment: Vec<String>,
    /// Trees whose full contents cover reads by compiler extensions.
    #[serde(default)]
    pub read_roots: Vec<String>,
}

/// Identifies one immutable path in a realized Nix closure.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClosurePath {
    /// Absolute store path exported by the Nix daemon.
    pub path: String,
    /// NAR content hash supplied by the realized reference graph.
    #[serde(rename = "narHash")]
    pub nar_hash: String,
}

impl Manifest {
    /// Loads and validates a versioned compiler manifest.
    ///
    /// # Errors
    /// Returns an error for unreadable JSON, unsupported schema, or a compiler
    /// outside the declared store closure.
    pub fn read(path: &Path) -> Result<Self> {
        let mut manifest: Self = serde_json::from_slice(&fs::read(path)?)?;
        ensure!(manifest.schema == 1, "unsupported manifest schema");
        ensure!(
            !manifest.closure.is_empty(),
            "manifest has no realized closure"
        );
        manifest.closure.sort_by(|a, b| a.path.cmp(&b.path));
        for entry in &manifest.closure {
            ensure!(
                entry.path.starts_with("/nix/store/") && !entry.nar_hash.is_empty(),
                "invalid Nix closure identity"
            );
        }
        for compiler in manifest.compilers.keys() {
            ensure!(
                manifest
                    .closure
                    .iter()
                    .any(|entry| Path::new(compiler).starts_with(&entry.path)),
                "compiler absent from declared closure: {compiler}"
            );
        }
        Ok(manifest)
    }
}

/// Returns the SHA-256 digest used by the local CAS and action identities.
pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Records the complete local action inventory used for hashing and explanation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Identity {
    /// Versioned dependency-discovery algorithm identifier.
    pub adapter: String,
    /// Executable named by the manifest.
    pub compiler: String,
    /// Original compiler argument vector, without wrapper arguments.
    pub arguments: Vec<String>,
    /// Absolute compiler working directory.
    pub cwd: String,
    /// CAS digest of the manifest used for this invocation.
    pub policy: String,
    /// Effective environment names mapped to hashes of their values.
    pub environment: BTreeMap<String, String>,
    /// Discovered input paths or synthetic names mapped to content hashes.
    pub inputs: BTreeMap<String, String>,
    /// Actual output destinations supplied by this invocation.
    pub outputs: Vec<String>,
    /// Outputs whose absence is a valid, restorable result.
    pub optional_outputs: Vec<String>,
    /// Compiler-generated side files discovered after a successful action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_outputs: Option<DynamicOutputs>,
}

/// Bounds dynamic side files to one compiler output directory and name shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DynamicOutputs {
    /// Absolute output directory selected by the compiler invocation.
    pub directory: String,
    /// Filename prefix derived from the compiler's output naming contract.
    pub prefix: String,
    /// Filename suffix produced by the selected compiler mode.
    pub suffix: String,
    /// Names of compiler-owned subdirectories containing saved intermediates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nested_prefixes: Vec<String>,
}

impl DynamicOutputs {
    /// Accepts a relative file path within the declared compiler output scope.
    pub fn accepts(&self, relative: &Path) -> bool {
        let mut components = relative.components();
        let Some(Component::Normal(first)) = components.next() else {
            return false;
        };
        let Some(first) = first.to_str() else {
            return false;
        };

        let remaining: Vec<_> = components.collect();
        if remaining.is_empty() {
            return first.starts_with(&self.prefix) && first.ends_with(&self.suffix);
        }

        self.nested_prefixes
            .iter()
            .any(|prefix| first.starts_with(prefix))
            && remaining
                .iter()
                .all(|component| matches!(component, Component::Normal(_)))
    }
}

impl Identity {
    /// Groups revisions of the same invocation for miss explanations.
    ///
    /// # Errors
    /// Returns an error if the slot identity cannot be serialized.
    pub fn slot(&self) -> Result<String> {
        Ok(hash(&serde_json::to_vec(&(
            &self.compiler,
            &self.cwd,
            &self.outputs,
        ))?))
    }

    /// Describes changed flags, policy, environment, and dependency contents.
    pub fn differences(&self, prior: &Self) -> Vec<String> {
        let mut changed = Vec::new();
        if self.policy != prior.policy {
            changed.push("Nix manifest/toolchain closure".into());
        }
        if self.arguments != prior.arguments {
            changed.push("compiler arguments".into());
        }
        if self.adapter != prior.adapter {
            changed.push("compiler adapter version".into());
        }
        if self.dynamic_outputs != prior.dynamic_outputs {
            changed.push("dynamic output scope".into());
        }
        for name in self.environment.keys().chain(prior.environment.keys()) {
            if self.environment.get(name) != prior.environment.get(name) {
                changed.push(format!("environment: {name}"));
            }
        }
        for name in self.inputs.keys().chain(prior.inputs.keys()) {
            if self.inputs.get(name) != prior.inputs.get(name) {
                changed.push(format!("input: {name}"));
            }
        }
        changed.sort();
        changed.dedup();
        changed
    }
}

/// Captures the environment after applying the manifest execution policy.
///
/// # Errors
/// Returns an error for non-UTF-8 names or values, causing a compiler bypass.
pub fn environment(manifest: &Manifest) -> Result<BTreeMap<String, String>> {
    env::vars_os()
        .filter(|(key, _)| {
            let key = key.to_string_lossy();
            !key.starts_with("ACCACHE_")
                && !manifest.remove_environment.iter().any(|item| item == &key)
        })
        .map(|(key, value)| {
            Ok((
                key.into_string()
                    .map_err(|_| anyhow::anyhow!("non-UTF-8 environment name"))?,
                value
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("non-UTF-8 environment value"))?,
            ))
        })
        .collect()
}

/// Creates a compiler process with exactly the environment included in its key.
pub fn command(compiler: &str, args: &[String], environment: &BTreeMap<String, String>) -> Command {
    let mut command = Command::new(compiler);
    command.args(args).env_clear().envs(environment);
    command
}

/// Streams a regular input file into a SHA-256 content digest.
///
/// # Errors
/// Returns an error for a missing, unreadable, or non-regular input.
pub fn fingerprint(path: &Path) -> Result<String> {
    let metadata = fs::metadata(path).with_context(|| format!("input {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "input is not a regular file: {}",
        path.display()
    );
    let mut input = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}
