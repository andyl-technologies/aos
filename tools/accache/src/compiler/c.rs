//! GCC and Clang discovery using the complete pinned argument tables.

use super::{Invocation, parsed, strings};
use crate::model::{DynamicOutputs, Manifest};
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
    invocation.source_input = Some(parsed.input.clone());
    invocation.extra_inputs.insert(parsed.input.clone());
    invocation
        .extra_inputs
        .extend(parsed.extra_hash_files.iter().cloned());
    let expanded = strings(gcc::ExpandIncludeFile::new(&cwd, &arguments))?;
    // GCC accepts report options through sccache's generic argument path.
    // The pinned frontend omits their files, so discover those destinations
    // before allowing an action to be stored.
    if !clang {
        ensure!(
            !expanded.iter().any(|arg| {
                arg.starts_with("-fdiagnostics-add-output")
                    || arg.starts_with("-fdiagnostics-set-output")
            }),
            "additional GCC diagnostic outputs need explicit tracking"
        );
        let mut implicit_dump = false;
        for arg in &expanded {
            if arg.starts_with("-fopt-info") || arg.starts_with("-fdump-") {
                if let Some((_, destination)) = arg.split_once('=') {
                    if !matches!(destination, "stdout" | "stderr" | "-") {
                        invocation.output(Path::new(destination), false)?;
                    }
                } else if arg.starts_with("-fdump-") {
                    ensure!(
                        arg.starts_with("-fdump-tree-")
                            || arg.starts_with("-fdump-rtl-")
                            || arg.starts_with("-fdump-ipa-")
                            || arg.starts_with("-fdump-lang-")
                            || arg.starts_with("-fdump-statistics"),
                        "GCC dump option has an untracked side output"
                    );
                    implicit_dump = true;
                }
            }
        }
        let sarif_file = expanded
            .iter()
            .rev()
            .find_map(|arg| arg.strip_prefix("-fdiagnostics-format="))
            == Some("sarif-file");
        if sarif_file || implicit_dump {
            // Custom dump naming has separate precedence rules. Pass those
            // invocations through until their destinations can be derived.
            ensure!(
                !uses_custom_dump_naming(&expanded),
                "GCC side output uses custom dump naming"
            );
            let object = parsed
                .outputs
                .get("obj")
                .ok_or_else(|| anyhow::anyhow!("GCC side output has no object output"))?;
            let dump_base = default_dump_base(&parsed.input, &object.path)?;
            if sarif_file {
                let mut filename = dump_base.clone();
                filename.push(".sarif");
                invocation.output(&object.path.with_file_name(filename), false)?;
            }
            if implicit_dump {
                // Pass numbers vary by GCC version and optimization pipeline.
                // Restrict dynamic discovery to the selected object's directory
                // and dump base so replay includes only this action's reports.
                let directory = object
                    .path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or(Path::new("."))
                    .canonicalize()?;
                let prefix = dump_base
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("non-UTF-8 GCC dump base"))?;
                invocation.dynamic_outputs = Some(DynamicOutputs {
                    directory: directory.to_string_lossy().into_owned(),
                    prefix: format!("{prefix}."),
                    suffix: String::new(),
                });
            }
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
        if !clang && arg == "-fdiagnostics-format=sarif-file" {
            // The discovery compile must not create a caller-visible report.
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

fn default_dump_base(input: &Path, object: &Path) -> Result<OsString> {
    let mut base = object
        .file_stem()
        .ok_or_else(|| anyhow::anyhow!("GCC side output has no object stem"))?
        .to_os_string();
    if let Some(suffix) = input.extension() {
        base.push(".");
        base.push(suffix);
    }
    Ok(base)
}

fn uses_custom_dump_naming(args: &[String]) -> bool {
    args.iter().any(|arg| {
        ["-dumpbase", "--dumpbase", "-dumpdir", "--dumpdir"]
            .iter()
            .any(|name| arg == name || arg.starts_with(&format!("{name}=")))
    })
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
