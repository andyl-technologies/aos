//! Rust output discovery, native dependencies, and extension read contracts.

use super::{Invocation, parsed, strings};
use crate::model::{Manifest, command};
use accache_frontend::compiler::rust;
use anyhow::{Result, ensure};
use std::{collections::BTreeMap, ffi::OsString, path::Path};

pub(super) fn configure(
    invocation: &mut Invocation,
    compiler: &str,
    args: &[String],
    environment: &BTreeMap<String, String>,
    manifest: &Manifest,
) -> Result<()> {
    let arguments: Vec<_> = args.iter().map(OsString::from).collect();
    let parsed = parsed(rust::parse_arguments(&arguments, &std::env::current_dir()?))?;
    let mut print_args = invocation
        .execution_args
        .as_deref()
        .unwrap_or(args)
        .to_vec();
    print_args.push("--print=file-names".into());
    let names = command(compiler, &print_args, environment).output()?;
    ensure!(names.status.success(), "rustc output discovery failed");
    for name in String::from_utf8(names.stdout)?.lines() {
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
    let expanded = strings(rust::ExpandResponseFile::new(
        &std::env::current_dir()?,
        &arguments,
    ))?;
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
