//! GCC and Clang discovery using the complete pinned argument tables.

use super::{Invocation, parsed, strings};
use crate::model::Manifest;
use accache_frontend::compiler::{Language, c::CCompilerKind, clang, gcc};
use anyhow::{Result, ensure};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

pub(super) fn configure(
    invocation: &mut Invocation,
    kind: &str,
    compiler: &str,
    args: &[String],
    manifest: &Manifest,
) -> Result<()> {
    let clang = kind == "clang"
        || Path::new(compiler)
            .file_name()
            .is_some_and(|name| name.to_string_lossy().contains("clang"));
    let plusplus = compiler.ends_with("++");
    let arguments: Vec<_> = args.iter().map(OsString::from).collect();
    let cwd = std::env::current_dir()?;
    let parsed = parsed(if clang {
        gcc::parse_arguments(
            &arguments,
            &cwd,
            (&gcc::ARGS[..], &clang::ARGS[..]),
            plusplus,
            CCompilerKind::Clang,
        )
    } else {
        gcc::parse_arguments(
            &arguments,
            &cwd,
            &gcc::ARGS[..],
            plusplus,
            CCompilerKind::Gcc,
        )
    })?;
    for output in parsed.outputs.values() {
        invocation.output(&output.path, output.optional)?;
    }
    invocation.extra_inputs.insert(parsed.input.clone());
    invocation
        .extra_inputs
        .extend(parsed.extra_hash_files.iter().cloned());
    let expanded = strings(gcc::ExpandIncludeFile::new(&cwd, &arguments))?;
    // GCC accepts report options through sccache's generic argument path.
    // Explicit report destinations are outputs, while a dump with an implicit
    // name cannot be restored safely from the pinned frontend's output set.
    if !clang {
        for arg in &expanded {
            if arg.starts_with("-fopt-info") || arg.starts_with("-fdump-") {
                if let Some((_, destination)) = arg.split_once('=') {
                    invocation.output(Path::new(destination), false)?;
                } else if arg.starts_with("-fdump-") {
                    anyhow::bail!("GCC dump writes an unnamed side output");
                }
            }
            ensure!(
                arg != "-fdiagnostics-format=sarif-file",
                "GCC SARIF report writes an untracked side output"
            );
        }
    }
    for (index, arg) in expanded.iter().enumerate() {
        // sccache's Clang table classifies serialized diagnostics as pass-through;
        // accache must still restore the resulting side file on a hit.
        if matches!(
            arg.as_str(),
            "--serialize-diagnostics" | "-serialize-diagnostics" | "-aux-info"
        ) && let Some(output) = expanded.get(index + 1)
        {
            invocation.output(Path::new(output), false)?;
        }
    }
    let common = strings(parsed.common_args.clone())?;
    let preprocessing = strings(parsed.preprocessor_args.clone())?;
    if common
        .iter()
        .any(|arg| arg.contains("plugin") || arg == "-load")
    {
        invocation.extension_reads(manifest)?;
    }
    // Search roots selected through -B can contain an alternative assembler or
    // specs file. Their contents matter even when the compiler path is fixed.
    for arg in &common {
        if let Some(path) = arg.strip_prefix("-B")
            && !path.is_empty()
            && Path::new(path).is_dir()
        {
            invocation.recursive_dirs.insert(PathBuf::from(path));
        }
        for prefix in [
            "-specs=",
            "--specs=",
            "-fprofile-list=",
            "-fprofile-remapping-file=",
        ] {
            if let Some(path) = arg.strip_prefix(prefix) {
                invocation.extra_inputs.insert(path.into());
            }
        }
    }
    for pair in preprocessing.windows(2) {
        if matches!(
            pair[0].as_str(),
            "-include-pch" | "-ivfsoverlay" | "-vfsoverlay" | "--vfsoverlay"
        ) {
            invocation.extra_inputs.insert(pair[1].clone().into());
        }
    }
    let mut scan = Vec::new();
    if let Some(language) = if clang {
        parsed.language.to_clang_arg()
    } else {
        parsed.language.to_gcc_arg()
    } {
        scan.extend(["-x".into(), language.into()]);
    }
    // Diagnostics and auxiliary outputs from the probe belong to its private
    // temporary directory, never to the caller's final output destinations.
    let mut index = 0;
    while index < common.len() {
        let arg = &common[index];
        if matches!(
            arg.as_str(),
            "--serialize-diagnostics" | "-serialize-diagnostics" | "-aux-info"
        ) {
            index += 2;
            continue;
        }
        if !clang && (arg.starts_with("-fdump-") || arg.starts_with("-fopt-info")) {
            // A dependency probe must not create or append to a caller's
            // report before the actual compilation or a cache restoration.
            index += 1;
            continue;
        }
        scan.push(arg.clone());
        index += 1;
    }
    scan.extend(preprocessing);
    scan.extend(strings(parsed.arch_args)?);
    if parsed.language == Language::Assembler {
        // Native assembler includes are invisible to the C preprocessor. Run
        // the assembler in the probe directory and request its dependency file.
        scan.push("-c".into());
        scan.extend([
            "-o".into(),
            invocation
                ._temporary
                .path()
                .join("probe.o")
                .to_string_lossy()
                .into_owned(),
        ]);
        if clang {
            // Clang's integrated assembler has no dependency-file interface.
            // Its declared read trees account for .include/.incbin inputs.
            invocation.extension_reads(manifest)?;
            return Ok(());
        } else {
            scan.push(format!("-Wa,--MD,{}", invocation.dependencies.display()));
        }
    } else if parsed.language.needs_c_preprocessing() {
        if clang {
            if parsed.language == Language::AssemblerToPreprocess {
                // Clang's integrated assembler cannot emit .include deps.
                invocation.extension_reads(manifest)?;
            } else {
                invocation.assembly_read_roots_if_directive =
                    Some(manifest.read_roots.iter().map(PathBuf::from).collect());
            }
        } else {
            configure_assembly_scan(invocation, &scan, &parsed.input, parsed.double_dash_input);
            invocation.assembly_probe_if_directive =
                parsed.language != Language::AssemblerToPreprocess;
        }
        scan.extend([
            "-E".into(),
            "-fpch-preprocess".into(),
            "-MD".into(),
            "-MF".into(),
            invocation.dependencies.to_string_lossy().into_owned(),
        ]);
        invocation.scan_stdout = true;
    } else {
        // Already preprocessed inputs have no header discovery step. Their
        // contents and all explicit extra files remain action-key inputs.
        ensure!(
            matches!(
                parsed.language,
                Language::CPreprocessed
                    | Language::CxxPreprocessed
                    | Language::ObjectiveCPreprocessed
                    | Language::ObjectiveCxxPreprocessed
            ),
            "unsupported GCC/Clang language driver"
        );
        invocation.assembly_directive_input = Some(parsed.input.clone());
        if clang {
            invocation.assembly_read_roots_if_directive =
                Some(manifest.read_roots.iter().map(PathBuf::from).collect());
        } else {
            configure_assembly_scan(invocation, &scan, &parsed.input, parsed.double_dash_input);
            invocation.assembly_probe_if_directive = true;
        }
        return Ok(());
    }
    if parsed.double_dash_input {
        scan.push("--".into());
    }
    scan.push(parsed.input.to_string_lossy().into_owned());
    invocation.scan_args = Some(scan);
    // A missing -MF still produces the conventional object-adjacent depfile.
    if expanded
        .iter()
        .any(|arg| matches!(arg.as_str(), "-MD" | "-MMD"))
        && parsed.language.needs_c_preprocessing()
        && !parsed.outputs.contains_key("d")
        && let Some(object) = parsed.outputs.get("obj")
    {
        invocation.output(&object.path.with_extension("d"), false)?;
    }
    Ok(())
}

fn configure_assembly_scan(
    invocation: &mut Invocation,
    base: &[String],
    input: &Path,
    double_dash_input: bool,
) {
    let mut scan = base.to_vec();
    scan.extend([
        "-c".into(),
        "-save-temps=obj".into(),
        "-o".into(),
        invocation
            ._temporary
            .path()
            .join("probe.o")
            .to_string_lossy()
            .into_owned(),
        format!("-Wa,--MD,{}", invocation.assembly_dependencies.display()),
    ]);
    if double_dash_input {
        scan.push("--".into());
    }
    scan.push(input.to_string_lossy().into_owned());
    invocation.assembly_scan_args = Some(scan);
}
