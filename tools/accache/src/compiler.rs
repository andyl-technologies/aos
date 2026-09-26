//! Compiler adapters around the pinned sccache argument frontends.
//!
//! Parsing and cacheability decisions come from the frontend crate. This layer
//! discovers dependencies afresh and accounts for outputs in the local backend.
//! Compilation still receives the original arguments, including response files.

mod c;
mod dependencies;
mod rust;

use crate::{
    backend::safe_output,
    model::{Manifest, command, fingerprint, hash},
};
use accache_frontend::compiler::CompilerArguments;
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

/// Holds discovered outputs and the probes needed to recompute action inputs.
pub struct Invocation {
    /// Versioned frontend and discovery adapter name.
    pub kind: String,
    /// All possible artifact destinations, including optional outputs.
    pub outputs: Vec<String>,
    /// Artifacts whose absence is meaningful, such as optimized-away DWARF.
    pub optional_outputs: BTreeSet<String>,
    /// Expanded rustc arguments when sccache accepts a nested response file.
    pub execution_args: Option<Vec<String>>,
    scan_args: Option<Vec<String>>,
    assembly_scan_args: Option<Vec<String>>,
    scan_stdout: bool,
    dependencies: PathBuf,
    assembly_dependencies: PathBuf,
    extra_inputs: BTreeSet<PathBuf>,
    read_dirs: BTreeSet<PathBuf>,
    recursive_dirs: BTreeSet<PathBuf>,
    _temporary: tempfile::TempDir,
}

/// Parses an invocation and prepares dependency probes without compiling outputs.
///
/// # Errors
/// Returns a bypass reason for unsupported actions, invalid arguments, missing
/// extension contracts, or unsuccessful output discovery.
pub fn classify(
    kind: &str,
    compiler: &str,
    args: &[String],
    environment: &BTreeMap<String, String>,
    manifest: &Manifest,
) -> Result<Invocation> {
    let mut invocation = Invocation {
        kind: format!("{kind}-sccache-8396f020-v1"),
        outputs: Vec::new(),
        optional_outputs: BTreeSet::new(),
        execution_args: None,
        scan_args: None,
        assembly_scan_args: None,
        scan_stdout: false,
        dependencies: PathBuf::new(),
        assembly_dependencies: PathBuf::new(),
        extra_inputs: BTreeSet::new(),
        read_dirs: BTreeSet::new(),
        recursive_dirs: BTreeSet::new(),
        _temporary: tempfile::tempdir()?,
    };
    invocation.dependencies = invocation._temporary.path().join("dependencies.d");
    invocation.assembly_dependencies = invocation._temporary.path().join("assembly.d");
    let (expanded_args, nested_response) = response_inputs(
        args,
        kind == "rust",
        &mut invocation.extra_inputs,
        &mut BTreeSet::new(),
        0,
    )?;
    if kind == "rust" && nested_response {
        invocation.execution_args = Some(expanded_args);
    }
    match kind {
        "c" | "gcc" | "clang" => c::configure(&mut invocation, kind, compiler, args, manifest)?,
        "rust" => rust::configure(&mut invocation, compiler, args, environment, manifest)?,
        _ => anyhow::bail!("unknown compiler adapter {kind}"),
    }
    invocation.outputs.sort();
    invocation.outputs.dedup();
    ensure!(!invocation.outputs.is_empty(), "no compiler outputs");
    Ok(invocation)
}

fn parsed<T>(decision: CompilerArguments<T>) -> Result<T> {
    match decision {
        CompilerArguments::Ok(parsed) => Ok(parsed),
        CompilerArguments::NotCompilation => anyhow::bail!("not a cacheable compilation"),
        CompilerArguments::CannotCache(reason, detail) => anyhow::bail!(
            "sccache frontend: {reason}{}",
            detail.map(|s| format!(": {s}")).unwrap_or_default()
        ),
    }
}

fn strings(args: impl IntoIterator<Item = OsString>) -> Result<Vec<String>> {
    args.into_iter()
        .map(|arg| {
            arg.into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF-8 compiler argument"))
        })
        .collect()
}

fn output_name(path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 output path"))?
        .to_owned();
    safe_output(&value)?;
    Ok(value)
}

impl Invocation {
    fn output(&mut self, path: &Path, optional: bool) -> Result<()> {
        let path = output_name(path)?;
        if optional {
            self.optional_outputs.insert(path.clone());
        }
        self.outputs.push(path);
        Ok(())
    }

    fn extension_reads(&mut self, manifest: &Manifest) -> Result<()> {
        ensure!(
            !manifest.read_roots.is_empty(),
            "compiler extension requires manifest read_roots"
        );
        self.recursive_dirs
            .extend(manifest.read_roots.iter().map(PathBuf::from));
        Ok(())
    }

    /// Recomputes content identities, including negative include resolutions.
    ///
    /// # Errors
    /// Returns an error for failed probes, unreadable inputs, or recursive reads
    /// of cache storage. Callers bypass or decline publication as appropriate.
    pub fn discover(
        &self,
        compiler: &str,
        _args: &[String],
        environment: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>> {
        let mut inputs = BTreeMap::new();
        if let Some(scan) = &self.scan_args {
            if self.dependencies.exists() {
                fs::remove_file(&self.dependencies)?;
            }
            let output = command(compiler, scan, environment).output()?;
            ensure!(
                output.status.success(),
                "dependency discovery failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            ensure!(
                self.dependencies.is_file(),
                "dependency probe produced no depfile"
            );
            for path in dependencies::dependencies(&fs::read_to_string(&self.dependencies)?)? {
                inputs.insert(path.clone(), fingerprint(Path::new(&path))?);
            }
            if self.scan_stdout {
                // GCC represents a consumed PCH as a pragma in preprocessed
                // output. Its content is an input even when omitted by -MD.
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    if let Some(path) = line
                        .strip_prefix("#pragma GCC pch_preprocess \"")
                        .and_then(|v| v.strip_suffix('"'))
                    {
                        inputs.insert(path.into(), fingerprint(Path::new(path))?);
                    }
                }
                inputs.insert("<preprocessor-output>".into(), hash(&output.stdout));
            }
        }
        if let Some(scan) = &self.assembly_scan_args {
            if self.assembly_dependencies.exists() {
                fs::remove_file(&self.assembly_dependencies)?;
            }
            let output = command(compiler, scan, environment).output()?;
            ensure!(
                output.status.success(),
                "assembler dependency discovery failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            ensure!(
                self.assembly_dependencies.is_file(),
                "assembler probe produced no depfile"
            );
            for path in
                dependencies::dependencies(&fs::read_to_string(&self.assembly_dependencies)?)?
            {
                // -save-temps=obj keeps the compiler's generated .s file in
                // our probe directory. It is not an external action input.
                if Path::new(&path).starts_with(self._temporary.path()) {
                    continue;
                }
                inputs.insert(path.clone(), fingerprint(Path::new(&path))?);
            }
        }
        for path in &self.extra_inputs {
            inputs.insert(path.to_string_lossy().into_owned(), fingerprint(path)?);
        }
        for path in &self.read_dirs {
            self.directory_inputs(path, false, &mut inputs, &mut BTreeSet::new())?;
        }
        for path in &self.recursive_dirs {
            self.directory_inputs(path, true, &mut inputs, &mut BTreeSet::new())?;
        }
        // Native CPU flags must not share results across different hosts that
        // happen to use the same store closure. Ignore changing clock speeds.
        if let Ok(cpu) = fs::read_to_string("/proc/cpuinfo") {
            let properties: BTreeSet<_> = cpu
                .lines()
                .filter_map(|line| line.split_once(':'))
                .filter(|(key, _)| {
                    matches!(
                        key.trim(),
                        "vendor_id"
                            | "cpu family"
                            | "model"
                            | "model name"
                            | "stepping"
                            | "flags"
                            | "Features"
                            | "CPU implementer"
                            | "CPU part"
                            | "CPU revision"
                    )
                })
                .map(|(key, value)| format!("{}:{}", key.trim(), value.trim()))
                .collect();
            inputs.insert("<host-cpu>".into(), hash(&serde_json::to_vec(&properties)?));
        }
        ensure!(!inputs.is_empty(), "empty dependency inventory");
        Ok(inputs)
    }

    fn directory_inputs(
        &self,
        path: &Path,
        recursive: bool,
        inputs: &mut BTreeMap<String, String>,
        visited: &mut BTreeSet<PathBuf>,
    ) -> Result<()> {
        let canonical = path.canonicalize()?;
        // Compare resolved directories, not the caller's relative spellings.
        // A read root of "." or a symlink must not accidentally walk the CAS
        // and include the wrapper's own mutable files in the action identity.
        for variable in ["ACCACHE_DIR", "ACCACHE_STATE_DIR"] {
            if let Some(cache) = std::env::var_os(variable) {
                ensure!(
                    !canonical.starts_with(PathBuf::from(cache).canonicalize()?),
                    "manifest read root includes compiler-cache state"
                );
            }
        }
        if !visited.insert(canonical) {
            return Ok(());
        }
        let mut entries: Vec<_> = fs::read_dir(path)?.collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let cwd = std::env::current_dir()?;
            if self
                .outputs
                .iter()
                .any(|output| cwd.join(output) == cwd.join(&path))
            {
                continue;
            }
            if path.is_dir() {
                if recursive {
                    self.directory_inputs(&path, true, inputs, visited)?;
                }
            } else if path.is_file() {
                inputs.insert(path.to_string_lossy().into_owned(), fingerprint(&path)?);
            }
        }
        Ok(())
    }
}

fn response_inputs(
    args: &[String],
    rust: bool,
    inputs: &mut BTreeSet<PathBuf>,
    active: &mut BTreeSet<PathBuf>,
    depth: usize,
) -> Result<(Vec<String>, bool)> {
    ensure!(depth < 64, "response-file nesting limit exceeded");
    let mut expanded = Vec::new();
    let mut nested_response = false;
    for arg in args {
        if let Some(path) = arg.strip_prefix('@') {
            let path = PathBuf::from(path);
            let canonical = path.canonicalize()?;
            ensure!(active.insert(canonical.clone()), "recursive response file");
            inputs.insert(path.clone());
            let data = fs::read_to_string(&path)?;
            // The sccache Rust frontend expands nested @files even though
            // direct rustc leaves an inner @file as a literal argument.
            let nested = if rust {
                accache_frontend::compiler::rust::split_rust_response_file_args(&data)
            } else {
                accache_frontend::compiler::gcc::split_gnu_response_file_args(&data)
            };
            let (contents, nested_in_contents) =
                response_inputs(&strings(nested)?, rust, inputs, active, depth + 1)?;
            expanded.extend(contents);
            nested_response |= depth > 0 || nested_in_contents;
            active.remove(&canonical);
        } else {
            expanded.push(arg.clone());
        }
    }
    Ok((expanded, nested_response))
}
