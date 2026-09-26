//! Daemonless compiler action caching for explicit Nix build contracts.
//!
//! `compiler` classifies and discovers actions, `model` owns identities,
//! `proto` and `backend` own the Bazel-compatible disk wire representation,
//! and `report` explains each invocation. Unsupported work reaches the real
//! compiler unchanged. No server, socket, or background worker is started.

mod backend;
mod compiler;
mod model;
mod proto;
mod report;

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::{
    env,
    io::{self, Write},
    path::PathBuf,
    process::{self, ExitStatus},
    time::Instant,
};

use anyhow::{Context, Result};
use prost::Message;

use backend::{Backend, PublicationOutputs};
use model::{Identity, Manifest};
use report::Event;

const HELP: &str = "accache — daemonless Nix compiler action cache

Usage:
  accache COMPILER [COMPILER-ARGUMENTS...]
  accache stats
  accache explain [ACTION-SHA256]
  accache provenance [ACTION-SHA256]

Set ACCACHE_DIR to the Bazel-format disk-cache root, ACCACHE_STATE_DIR to a
separate metadata directory, and ACCACHE_MANIFEST to the Nix policy JSON.
Without configuration, compiler invocations run unchanged. ACCACHE_DISABLE=1
also bypasses caching. ACCACHE_DERIVATION optionally records the .drv identity
as provenance; it is never an action-key input. ACCACHE_VERBOSE=1 prints the
per-invocation outcome. Inspection prints JSON (provenance: JSON lines).

GCC/Clang and Rust parsing uses the pinned sccache frontend tables. A cacheable
Rust invocation with nested response files expands them as sccache does;
other compilations receive the original arguments. Supported outputs include
dependency, debug, coverage, PCH, Clang module, and Rust library/metadata artifacts. Linking,
incremental Rust, and other uncacheable work runs unchanged with a bypass reason.
See tools/accache/README.md for the read contract and coverage limits.
";

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(error) => {
            eprintln!("accache: {error:#}");
            process::exit(1);
        }
    }
}

fn code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}

fn backend() -> Result<Backend> {
    Backend::new(
        PathBuf::from(env::var_os("ACCACHE_DIR").context("ACCACHE_DIR is unset")?),
        PathBuf::from(env::var_os("ACCACHE_STATE_DIR").context("ACCACHE_STATE_DIR is unset")?),
    )
}

fn passthrough(compiler: &str, args: &[String]) -> Result<i32> {
    Ok(code(process::Command::new(compiler).args(args).status()?))
}

fn run() -> Result<i32> {
    let original: Vec<_> = env::args_os().skip(1).collect();
    // A wrapper must not reject an argument the real compiler can accept.
    // JSON identities currently require UTF-8, so preserve arbitrary Unix
    // bytes by bypassing before attempting that representation.
    if original.iter().any(|arg| arg.to_str().is_none()) {
        return Ok(code(
            process::Command::new(&original[0])
                .args(&original[1..])
                .status()?,
        ));
    }
    let args: Vec<String> = original
        .into_iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let Some(first) = args.first() else {
        print!("{HELP}");
        return Ok(0);
    };
    if matches!(first.as_str(), "--help" | "help" | "-h") {
        print!("{HELP}");
        return Ok(0);
    }
    if matches!(first.as_str(), "stats" | "explain" | "provenance") {
        report::inspect(&backend()?, first, args.get(1).map(String::as_str))?;
        return Ok(0);
    }
    let compiler = first;
    let args = &args[1..];
    if env::var("ACCACHE_DISABLE").as_deref() == Ok("1") || env::var_os("ACCACHE_DIR").is_none() {
        return passthrough(compiler, args);
    }
    let backend = match backend() {
        Ok(backend) => backend,
        Err(error) => {
            eprintln!("accache: cache unavailable: {error:#}");
            return passthrough(compiler, args);
        }
    };
    let start = Instant::now();
    match prepare(&backend, compiler, args) {
        Ok(prepared) => execute(&backend, args, prepared, start),
        Err(error) => {
            let mut event = Event::new("bypass", format!("{error:#}"));
            // A bypassed rustc still creates temporary metadata directories
            // while it runs. Coordinate it with cacheable save-temps actions.
            let _rust_lock = match bypass_rust_lock(&backend, compiler, args) {
                Ok(lock) => lock,
                Err(lock_error) => {
                    eprintln!("accache: Rust output lock unavailable: {lock_error:#}");
                    None
                }
            };
            let status = passthrough(compiler, args)?;
            event.duration_ms = start.elapsed().as_millis();
            record(&backend, &event);
            Ok(status)
        }
    }
}

fn bypass_rust_lock(
    backend: &Backend,
    compiler: &str,
    args: &[String],
) -> Result<Option<std::fs::File>> {
    let manifest = Manifest::read(&PathBuf::from(
        env::var_os("ACCACHE_MANIFEST").context("ACCACHE_MANIFEST is unset")?,
    ))?;
    let resolved = resolve_compiler(compiler)?;
    if manifest.compilers.get(&resolved).map(String::as_str) != Some("rust") {
        return Ok(None);
    }
    let (directory, saves_temps) = compiler::bypass_output_directory(args)?;
    Ok(Some(backend.lock_rust_directory(&directory, saves_temps)?))
}

struct Prepared {
    invocation: compiler::Invocation,
    environment: std::collections::BTreeMap<String, String>,
    identity: Identity,
    action: String,
}

fn prepare(backend: &Backend, compiler: &str, args: &[String]) -> Result<Prepared> {
    let manifest = Manifest::read(&PathBuf::from(
        env::var_os("ACCACHE_MANIFEST").context("ACCACHE_MANIFEST is unset")?,
    ))?;
    let resolved = resolve_compiler(compiler)?;
    let compiler = resolved.as_str();
    let kind = manifest
        .compilers
        .get(compiler)
        .context("compiler is not declared in the Nix manifest")?;
    let environment = model::environment(&manifest)?;
    let invocation = compiler::classify(kind, compiler, args, &environment, &manifest)?;
    let inputs = invocation.discover(compiler, args, &environment)?;
    let key_arguments = invocation.key_arguments.as_deref().unwrap_or(args);
    let identity = Identity {
        adapter: invocation.kind.clone(),
        compiler: compiler.into(),
        arguments: key_arguments.to_vec(),
        cwd: env::current_dir()?
            .to_str()
            .context("non-UTF-8 working directory")?
            .to_owned(),
        policy: backend.put(&serde_json::to_vec(&manifest)?)?.hash,
        environment: environment
            .iter()
            .map(|(key, value)| (key.clone(), model::hash(value.as_bytes())))
            .collect(),
        inputs,
        outputs: invocation.outputs.clone(),
        optional_outputs: invocation.optional_outputs.iter().cloned().collect(),
        dynamic_outputs: invocation.dynamic_outputs.clone(),
    };
    // The inventory node is deliberately versioned as a local-only action.
    // It is valid REAPI storage, but not a claim that a remote executor can
    // reconstruct a Nix sandbox from an inventory without a platform adapter.
    let inventory = backend.put(&serde_json::to_vec(&identity)?)?;
    let root = backend.put(
        &proto::Directory {
            files: vec![proto::FileNode {
                name: "accache-local-v1.json".into(),
                digest: Some(inventory),
                is_executable: false,
            }],
        }
        .encode_to_vec(),
    )?;
    let execution_args = invocation.execution_args.as_deref().unwrap_or(args);
    let command_arguments = invocation
        .key_arguments
        .as_deref()
        .unwrap_or(execution_args);
    let command = backend.put(
        &proto::Command {
            arguments: std::iter::once(compiler.to_owned())
                .chain(command_arguments.iter().cloned())
                .collect(),
            environment_variables: environment
                .iter()
                .map(|(name, value)| proto::EnvironmentVariable {
                    name: name.clone(),
                    value: value.clone(),
                })
                .collect(),
            working_directory: identity.cwd.trim_start_matches('/').into(),
            output_paths: identity
                .outputs
                .iter()
                .map(|path| backend::wire_output(path))
                .chain(
                    identity
                        .dynamic_outputs
                        .as_ref()
                        .map(backend::wire_dynamic_root)
                        .map(Ok),
                )
                .collect::<Result<_>>()?,
        }
        .encode_to_vec(),
    )?;
    let action = backend
        .put(
            &proto::Action {
                command_digest: Some(command),
                input_root_digest: Some(root),
            }
            .encode_to_vec(),
        )?
        .hash;
    Ok(Prepared {
        invocation,
        environment,
        identity,
        action,
    })
}

/// Resolves the first executable on PATH, never skipping an undeclared compiler
/// in favor of a later declared one. Absolute invocations retain their wrapper
/// path instead of canonicalizing away compiler-name-dependent behavior.
fn resolve_compiler(compiler: &str) -> Result<String> {
    if compiler.contains('/') {
        return Ok(compiler.to_owned());
    }
    for directory in env::split_paths(&env::var_os("PATH").unwrap_or_default()) {
        let path = env::current_dir()?.join(directory).join(compiler);
        if path
            .metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        {
            return path
                .into_os_string()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF-8 compiler path"));
        }
    }
    anyhow::bail!("compiler is not executable on PATH: {compiler}")
}

fn execute(backend: &Backend, args: &[String], prepared: Prepared, start: Instant) -> Result<i32> {
    let Prepared {
        mut invocation,
        environment,
        identity,
        action,
    } = prepared;
    // Discovery resolved PATH before checking the manifest. Execute exactly
    // that program even if the policy removed PATH from the effective env.
    let compiler = identity.compiler.as_str();
    let mut event = Event::new("miss", "action is absent".into());
    event.action = Some(action.clone());
    event.changes = report::changes(backend, &identity)
        .unwrap_or_else(|error| vec![format!("prior provenance unavailable: {error}")]);
    event.identity = Some(identity.clone());
    // The source-built Cargo phase holds its target-tree lock across the
    // package build. This finer lock also coordinates accache clients that
    // share an output stem, including clients outside Cargo. Take the output
    // snapshot only after acquiring it, before any restore or compilation.
    let locks = (|| -> Result<_> {
        let directory_lock = invocation
            .rust_output_directory
            .as_deref()
            .map(|directory| backend.lock_rust_directory(directory, invocation.rust_save_temps))
            .transpose()?;
        let scope_lock = invocation
            .dynamic_outputs
            .as_ref()
            .map(|scope| backend.lock_scope(scope))
            .transpose()?;
        invocation.capture_dynamic_before()?;
        Ok((directory_lock, scope_lock))
    })();
    let (_directory_lock, _scope_lock) = match locks {
        Ok(locks) => locks,
        Err(error) => {
            event.outcome = "bypass".into();
            event.reason = format!("dynamic output scope unavailable: {error:#}");
            let status = passthrough(compiler, args)?;
            event.duration_ms = start.elapsed().as_millis();
            record(backend, &event);
            return Ok(status);
        }
    };
    // Keep the descriptor alive until publishing finishes. Independent actions
    // never share a lock, and another process always rechecks after acquiring it.
    let lock = backend.lock(&action);
    if lock.is_ok() {
        match backend.restore(
            &action,
            &invocation.outputs,
            &invocation.optional_outputs,
            invocation.dynamic_outputs.as_ref(),
        ) {
            Ok(restored) => {
                io::stdout().write_all(&restored.result.stdout_raw)?;
                io::stderr().write_all(&restored.result.stderr_raw)?;
                event.outcome = "hit".into();
                event.reason = "validated action result and all output blobs".into();
                event.artifacts = restored.paths;
                event.duration_ms = start.elapsed().as_millis();
                record(backend, &event);
                return Ok(0);
            }
            Err(error) => event.reason = format!("cache lookup: {error:#}"),
        }
    } else {
        event.reason = "cache lock unavailable; compiling without publication".into();
    }

    let execution_args = invocation.execution_args.as_deref().unwrap_or(args);
    let result = model::command(compiler, execution_args, &environment).output()?;
    io::stdout().write_all(&result.stdout)?;
    io::stderr().write_all(&result.stderr)?;
    let status = code(result.status);
    if result.status.success() && lock.is_ok() {
        // Recheck the discovered inputs after compilation. A changing generated
        // input must not publish a result under the pre-compilation identity.
        match invocation.discover(compiler, args, &environment) {
            Ok(inputs) if inputs == identity.inputs => {
                let publication = invocation.new_dynamic_outputs().and_then(|dynamic_files| {
                    backend.publish(
                        &action,
                        PublicationOutputs {
                            fixed: &invocation.outputs,
                            optional: &invocation.optional_outputs,
                            dynamic: invocation.dynamic_outputs.as_ref(),
                            generated: &dynamic_files,
                        },
                        result.stdout,
                        result.stderr,
                    )
                });
                match publication {
                    Ok(paths) => event.artifacts = paths,
                    Err(error) => {
                        event.outcome = "write-error".into();
                        event.reason =
                            format!("compilation succeeded; cache publication failed: {error:#}");
                    }
                }
            }
            Ok(inputs) => {
                let mut observed = identity.clone();
                observed.inputs = inputs;
                event.changes.extend(
                    identity
                        .differences(&observed)
                        .into_iter()
                        .map(|change| format!("changed during compilation: {change}")),
                );
                event.outcome = "unstable-inputs".into();
                event.reason =
                    "dependency inventory changed during compilation; result not cached".into();
            }
            Err(error) => {
                event.outcome = "unstable-inputs".into();
                event.reason = format!("dependency inventory could not be rechecked: {error:#}");
            }
        }
    } else if !result.status.success() {
        event.outcome = "compile-failed".into();
        event.reason = format!("compiler exited with {status}; result not cached");
    }
    event.duration_ms = start.elapsed().as_millis();
    record(backend, &event);
    Ok(status)
}

fn record(backend: &Backend, event: &Event) {
    if env::var("ACCACHE_VERBOSE").as_deref() == Ok("1") {
        eprintln!("accache: {}: {}", event.outcome, event.reason);
    }
    if let Err(error) = report::record(backend, event) {
        eprintln!("accache: provenance write failed: {error:#}");
    }
}
