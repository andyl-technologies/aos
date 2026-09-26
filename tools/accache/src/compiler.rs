//! Compiler adapters around the pinned sccache argument frontends.
//!
//! Parsing and cacheability decisions come from the frontend crate. This layer
//! discovers dependencies afresh and accounts for outputs in the local backend.
//! Compilation still receives the original arguments, including response files.

mod c;
mod dependencies;
mod llvm;
mod rust;

pub(crate) use rust::bypass_output_directory;

use crate::{
    backend::safe_output,
    model::{DynamicOutputs, Manifest, command, fingerprint, hash},
};
use accache_frontend::compiler::CompilerArguments;
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

// File timestamps and inode distinguish an output rewritten with identical
// bytes from an unrelated stale file in a persistent Cargo target directory.
#[derive(Clone, Eq, PartialEq)]
struct OutputStamp {
    inode: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

fn output_stamp(metadata: &fs::Metadata) -> OutputStamp {
    OutputStamp {
        inode: metadata.ino(),
        size: metadata.len(),
        mtime: (metadata.mtime(), metadata.mtime_nsec()),
        ctime: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

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
    /// Bounded compiler-generated side files whose names require compilation.
    pub dynamic_outputs: Option<DynamicOutputs>,
    /// Rust's selected output directory, shared by all compiler calls in a Cargo target.
    pub rust_output_directory: Option<String>,
    /// Saved Rust intermediates require exclusive access to that directory.
    pub rust_save_temps: bool,
    dynamic_before: BTreeMap<String, OutputStamp>,
    scan_args: Option<Vec<String>>,
    assembly_scan_args: Option<Vec<String>>,
    assembly_probe_if_directive: bool,
    assembly_directive_input: Option<PathBuf>,
    source_input: Option<PathBuf>,
    assembly_read_roots_if_directive: Option<Vec<PathBuf>>,
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
        dynamic_outputs: None,
        rust_output_directory: None,
        rust_save_temps: false,
        dynamic_before: BTreeMap::new(),
        scan_args: None,
        assembly_scan_args: None,
        assembly_probe_if_directive: false,
        assembly_directive_input: None,
        source_input: None,
        assembly_read_roots_if_directive: None,
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
        &mut RustArgfileFlags::default(),
        0,
    )?;
    if kind == "rust" && nested_response {
        invocation.execution_args = Some(expanded_args);
    }
    match kind {
        "c" | "gcc" | "clang" => {
            c::configure(&mut invocation, kind, compiler, args, environment, manifest)?
        }
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
    /// Records the output scope immediately before a locked compiler action.
    ///
    /// # Errors
    /// Returns an error if the compiler output directory cannot be inspected.
    pub fn capture_dynamic_before(&mut self) -> Result<()> {
        self.dynamic_before = self.dynamic_snapshot()?;
        Ok(())
    }

    fn dynamic_snapshot(&self) -> Result<BTreeMap<String, OutputStamp>> {
        let Some(dynamic) = &self.dynamic_outputs else {
            return Ok(BTreeMap::new());
        };
        let mut files = BTreeMap::new();
        for entry in fs::read_dir(&dynamic.directory)? {
            let entry = entry?;
            let relative = PathBuf::from(entry.file_name());
            let metadata = fs::symlink_metadata(entry.path())?;
            if dynamic.accepts(&relative) {
                ensure!(metadata.is_file(), "dynamic output is not a regular file");
                files.insert(
                    entry.path().to_string_lossy().into_owned(),
                    output_stamp(&metadata),
                );
            } else if metadata.is_dir()
                && dynamic
                    .nested_prefixes
                    .iter()
                    .any(|prefix| relative.to_string_lossy().starts_with(prefix))
            {
                let mut directories = vec![entry.path()];
                while let Some(directory) = directories.pop() {
                    for child in fs::read_dir(directory)? {
                        let child = child?;
                        let metadata = fs::symlink_metadata(child.path())?;
                        if metadata.is_dir() {
                            directories.push(child.path());
                        } else {
                            ensure!(
                                metadata.is_file(),
                                "nested dynamic output is not a regular file"
                            );
                            let relative =
                                child.path().strip_prefix(&dynamic.directory)?.to_owned();
                            ensure!(
                                dynamic.accepts(&relative),
                                "dynamic output escaped its scope"
                            );
                            files.insert(
                                child.path().to_string_lossy().into_owned(),
                                output_stamp(&metadata),
                            );
                        }
                    }
                }
            }
        }
        Ok(files)
    }

    /// Returns side files created or rewritten by this compiler invocation.
    ///
    /// # Errors
    /// Returns an error if the compiler output directory cannot be inspected.
    pub fn new_dynamic_outputs(&self) -> Result<Vec<String>> {
        let fixed_outputs: BTreeSet<_> = self
            .outputs
            .iter()
            .filter_map(|output| fs::canonicalize(output).ok())
            .collect();
        Ok(self
            .dynamic_snapshot()?
            .into_iter()
            .filter(|(path, stamp)| self.dynamic_before.get(path) != Some(stamp))
            .filter(|(path, _)| !fixed_outputs.contains(Path::new(path)))
            .map(|(path, _)| path)
            .collect())
    }

    fn is_output_path(&self, path: &Path) -> Result<bool> {
        let cwd = std::env::current_dir()?;
        if self
            .outputs
            .iter()
            .any(|output| cwd.join(output) == cwd.join(path))
        {
            return Ok(true);
        }
        let Some(dynamic) = &self.dynamic_outputs else {
            return Ok(false);
        };
        let Some(parent) = path.parent() else {
            return Ok(false);
        };
        let parent = parent.canonicalize()?;
        let Ok(relative_parent) = parent.strip_prefix(&dynamic.directory) else {
            return Ok(false);
        };
        let Some(name) = path.file_name() else {
            return Ok(false);
        };
        Ok(dynamic.accepts(&relative_parent.join(name)))
    }

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
        let mut assembler_file_directive = false;
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
                assembler_file_directive = has_assembler_file_directive(&output.stdout);
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
        if let Some(path) = &self.assembly_directive_input {
            assembler_file_directive = has_assembler_file_directive(&fs::read(path)?);
        }
        if let Some(scan) = &self.assembly_scan_args
            && (!self.assembly_probe_if_directive || assembler_file_directive)
        {
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
                let dependency = Path::new(&path);
                if dependency.starts_with(self._temporary.path()) {
                    continue;
                }
                // GCC's .file directive can make the assembler list only the
                // source basename. CMake often invokes GCC with an absolute
                // source outside its build cwd, so that relative name does
                // not exist there. The absolute source is already fingerprinted.
                if !dependency.exists()
                    && dependency.components().count() == 1
                    && self.source_input.as_ref().is_some_and(|source| {
                        source.is_absolute() && source.file_name() == dependency.file_name()
                    })
                {
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
        if assembler_file_directive && let Some(roots) = &self.assembly_read_roots_if_directive {
            ensure!(
                !roots.is_empty() && roots.iter().all(|path| path.is_dir()),
                "assembler directive requires manifest read_roots"
            );
            for path in roots {
                self.directory_inputs(path, true, &mut inputs, &mut BTreeSet::new())?;
            }
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
            if self.is_output_path(&path)? {
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

fn has_assembler_file_directive(bytes: &[u8]) -> bool {
    [b".include".as_slice(), b".incbin".as_slice()]
        .iter()
        .any(|directive| {
            bytes
                .windows(directive.len())
                .enumerate()
                .any(|(index, word)| {
                    if word != *directive {
                        return false;
                    }
                    let before = if index == 0 {
                        None
                    } else {
                        Some(bytes[index - 1])
                    };
                    let after = bytes.get(index + directive.len()).copied();
                    let boundary_before = match before {
                        None => true,
                        Some(value) if value.is_ascii_whitespace() => true,
                        Some(b'"' | b'\'' | b'(' | b';' | b',' | b':' | b'=') => true,
                        // A C string can place a directive after an escaped
                        // newline or tab: asm("\\n.include ...").
                        Some(value)
                            if value.is_ascii_alphanumeric()
                                && index >= 2
                                && bytes[index - 2] == b'\\' =>
                        {
                            true
                        }
                        _ => false,
                    };
                    let boundary_after =
                        after.is_none_or(|value| !value.is_ascii_alphanumeric() && value != b'_');
                    // Field access such as secinfo[index].include must not
                    // trigger an assembler probe, which may report unrelated
                    // relative .file paths for an absolute C source.
                    boundary_before && boundary_after
                })
        })
}

#[derive(Default)]
struct RustArgfileFlags {
    shell_argfiles: bool,
    next_is_unstable_option: bool,
}

impl RustArgfileFlags {
    fn observe(&mut self, argument: &str) {
        if self.next_is_unstable_option {
            self.shell_argfiles |= argument == "shell-argfiles";
            self.next_is_unstable_option = false;
        } else if argument == "-Z" {
            self.next_is_unstable_option = true;
        } else {
            self.shell_argfiles |= argument == "-Zshell-argfiles";
        }
    }
}

fn response_inputs(
    args: &[String],
    rust: bool,
    inputs: &mut BTreeSet<PathBuf>,
    active: &mut BTreeSet<PathBuf>,
    rust_flags: &mut RustArgfileFlags,
    depth: usize,
) -> Result<(Vec<String>, bool)> {
    ensure!(depth < 64, "response-file nesting limit exceeded");
    let mut expanded = Vec::new();
    let mut nested_response = false;
    for arg in args {
        if rust
            && rust_flags.shell_argfiles
            && let Some(path) = arg.strip_prefix("@shell:")
        {
            // rustc treats tokens from any argfile as literal. Restrict the
            // shell form to the top level so sccache's recursive expansion
            // of ordinary @files cannot change that execution contract.
            ensure!(depth == 0, "nested Rust shell argfile needs direct compilation");
            let path = PathBuf::from(path);
            inputs.insert(path.clone());
            let data = fs::read_to_string(&path)?;
            let arguments = accache_frontend::compiler::rust::split_rust_shell_response_file_args(&data)
                .ok_or_else(|| anyhow::anyhow!("invalid Rust shell argfile quoting"))?;
            let arguments = strings(arguments)?;
            ensure!(
                !arguments.iter().any(|argument| argument.starts_with('@')),
                "literal @ argument in Rust shell argfile needs direct compilation"
            );
            for argument in arguments {
                rust_flags.observe(&argument);
                expanded.push(argument);
            }
            continue;
        }
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
                response_inputs(&strings(nested)?, rust, inputs, active, rust_flags, depth + 1)?;
            expanded.extend(contents);
            nested_response |= depth > 0 || nested_in_contents;
            active.remove(&canonical);
        } else {
            if rust {
                rust_flags.observe(arg);
            }
            expanded.push(arg.clone());
        }
    }
    Ok((expanded, nested_response))
}
