//! Rust output discovery, native dependencies, and extension read contracts.

use super::{Invocation, parsed, strings};
use crate::model::{DynamicOutputs, Manifest, command};
use accache_frontend::compiler::rust;
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Path, PathBuf},
};

pub(super) fn configure(
    invocation: &mut Invocation,
    compiler: &str,
    args: &[String],
    environment: &BTreeMap<String, String>,
    manifest: &Manifest,
) -> Result<()> {
    let arguments: Vec<_> = args.iter().map(OsString::from).collect();
    let parsed = parsed(rust::parse_arguments(&arguments, &std::env::current_dir()?))?;
    let expanded = strings(rust::ExpandResponseFile::new(
        &std::env::current_dir()?,
        &arguments,
    ))?;
    if let Some(option) = invocation_specific_unstable_option(&expanded) {
        // These diagnostic switches produce unlisted files or report live
        // timings. Replaying an object alone would silently lose the report.
        anyhow::bail!("Rust -Z{option} has invocation-specific output");
    }
    let saves_temps = saves_temporary_outputs(&expanded);
    let output_directory = parsed.output_dir.canonicalize()?;
    invocation.rust_output_directory = Some(output_directory.to_string_lossy().into_owned());
    invocation.rust_save_temps = saves_temps;
    let mut print_args = invocation
        .execution_args
        .as_deref()
        .unwrap_or(args)
        .to_vec();
    print_args.push("--print=file-names".into());
    let names = command(compiler, &print_args, environment).output()?;
    ensure!(names.status.success(), "rustc output discovery failed");
    let printed_names = String::from_utf8(names.stdout)?;
    for name in printed_names.lines() {
        let name = Path::new(name);
        ensure!(
            name.components().count() == 1,
            "unexpected rustc output name"
        );
        if parsed.emit.contains("link") {
            invocation.output(&parsed.output_dir.join(name), false)?;
        }
        if parsed.emit.contains("metadata") {
            invocation.output(&parsed.output_dir.join(name.with_extension("rmeta")), false)?;
        }
    }
    if saves_temps || (parsed.emit.contains("link") && unpacked_split_debug(&expanded)) {
        // rustc does not list saved bitcode, object, metadata, or .dwo files
        // in --print=file-names. Their leading stem follows the library name;
        // random metadata directories are captured separately under the
        // exclusive Rust output-directory lock.
        let library = printed_names
            .lines()
            .find(|name| name.ends_with(".rlib") || name.ends_with(".a"))
            .ok_or_else(|| anyhow::anyhow!("Rust side files have no library output name"))?;
        let stem = Path::new(library)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| stem.strip_prefix("lib"))
            .ok_or_else(|| anyhow::anyhow!("unexpected Rust library output name"))?;
        invocation.dynamic_outputs = Some(DynamicOutputs {
            directory: output_directory.to_string_lossy().into_owned(),
            prefix: format!("{stem}."),
            suffix: if saves_temps { "" } else { ".dwo" }.into(),
            nested_prefixes: if saves_temps {
                vec!["rmeta".into(), "rustc".into()]
            } else {
                Vec::new()
            },
        });
    }
    for extra in [parsed.dep_info.as_ref(), parsed.gcno.as_ref()]
        .into_iter()
        .flatten()
    {
        invocation.output(&parsed.output_dir.join(extra), false)?;
    }
    invocation
        .extra_inputs
        .extend(parsed.externs.iter().cloned());
    invocation
        .extra_inputs
        .extend(parsed.staticlibs.iter().cloned());
    invocation
        .extra_inputs
        .extend(parsed.target_json.iter().cloned());
    invocation
        .extra_inputs
        .extend(parsed.profile.iter().cloned());
    invocation
        .read_dirs
        .extend(parsed.crate_link_paths.iter().cloned());
    let mut index = 0;
    while index < expanded.len() {
        let arg = &expanded[index];
        let search = if arg == "-L" {
            index += 1;
            expanded.get(index).map(String::as_str)
        } else {
            arg.strip_prefix("-L")
        };
        if let Some(search) = search {
            let path = search.split_once('=').map_or(search, |(_, path)| path);
            invocation.read_dirs.insert(path.into());
        }
        index += 1;
    }
    // Macro executables can read files beyond rustc's dep-info. The Nix caller
    // must declare those read roots; their full contents are fingerprinted.
    if parsed.externs.iter().any(|path| {
        matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("so" | "dylib" | "dll")
        )
    }) {
        invocation.extension_reads(manifest)?;
        for variable in ["OUT_DIR", "CARGO_MANIFEST_DIR"] {
            if let Some(path) = environment.get(variable) {
                invocation.recursive_dirs.insert(path.into());
            }
        }
    }
    let mut scan = strings(parsed.command_args(true))?;
    scan.push(format!(
        "--emit=dep-info={}",
        invocation.dependencies.display()
    ));
    invocation.scan_args = Some(scan);
    Ok(())
}

/// Finds the target-directory lock for a Rust invocation that the frontend
/// cannot cache, including incremental compilations and final links.
///
/// # Errors
/// Returns an error when a response file or the selected output directory
/// cannot be read or represented by the cache.
pub(crate) fn bypass_output_directory(args: &[String]) -> Result<(String, bool)> {
    let cwd = std::env::current_dir()?;
    let arguments: Vec<_> = args.iter().map(OsString::from).collect();
    let expanded = strings(rust::ExpandResponseFile::new(&cwd, &arguments))?;
    let mut output_directory = cwd;

    let mut index = 0;
    while index < expanded.len() {
        let argument = &expanded[index];
        if argument == "--out-dir" {
            index += 1;
            if let Some(value) = expanded.get(index) {
                output_directory = PathBuf::from(value);
            }
        } else if let Some(value) = argument.strip_prefix("--out-dir=") {
            output_directory = PathBuf::from(value);
        }
        index += 1;
    }

    Ok((
        output_directory
            .canonicalize()?
            .to_string_lossy()
            .into_owned(),
        saves_temporary_outputs(&expanded),
    ))
}

fn saves_temporary_outputs(args: &[String]) -> bool {
    let mut enabled = false;
    for (index, arg) in args.iter().enumerate() {
        let value = if matches!(arg.as_str(), "-C" | "--codegen") {
            args.get(index + 1).map(String::as_str)
        } else {
            arg.strip_prefix("-C")
                .or_else(|| arg.strip_prefix("--codegen="))
        };
        if let Some(value) = value {
            if value == "save-temps" {
                enabled = true;
            } else if let Some(setting) = value.strip_prefix("save-temps=") {
                // rustc uses the last codegen setting when it is repeated.
                enabled = !matches!(setting, "no" | "false");
            }
        }
    }
    enabled
}

fn invocation_specific_unstable_option(args: &[String]) -> Option<&str> {
    for (index, arg) in args.iter().enumerate() {
        let option = if arg == "-Z" {
            args.get(index + 1).map(String::as_str)
        } else {
            arg.strip_prefix("-Z")
        };
        let Some(option) = option else {
            continue;
        };
        let name = option.split_once('=').map_or(option, |(name, _)| name);
        if matches!(
            name,
            "self-profile"
                | "time-passes"
                | "time-llvm-passes"
                | "llvm-time-trace"
                | "dump-dep-graph"
                | "dump-mir"
                | "dump-mir-dataflow"
                | "dump-mir-graphviz"
                | "metrics-dir"
                | "nll-facts"
        ) {
            return Some(name);
        }
    }
    None
}

fn unpacked_split_debug(args: &[String]) -> bool {
    let mut unpacked = false;
    for (index, arg) in args.iter().enumerate() {
        let value = if matches!(arg.as_str(), "-C" | "--codegen") {
            args.get(index + 1).map(String::as_str)
        } else {
            arg.strip_prefix("-C")
                .or_else(|| arg.strip_prefix("--codegen="))
        };
        if let Some(setting) = value.and_then(|value| value.strip_prefix("split-debuginfo=")) {
            // rustc uses the last setting when a codegen option repeats.
            unpacked = setting == "unpacked";
        }
    }
    unpacked
}
