//! GCC and Clang discovery using the complete pinned argument tables.

use super::{Invocation, parsed, strings};
use crate::model::{DynamicOutputs, Manifest};
use accache_frontend::compiler::{Language, c::CCompilerKind, clang, gcc};
use anyhow::{Result, ensure};
use std::{
    collections::BTreeSet,
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
    if clang
        && expanded.iter().enumerate().any(|(index, argument)| {
            argument == "-dependency-file" && (index == 0 || expanded[index - 1] != "-Xclang")
        })
    {
        // Clang's driver warns that this cc1 option is unused. The pinned
        // frontend nevertheless expects its named file and fails on publish.
        ensure!(false, "Clang driver ignores -dependency-file");
    }
    // GCC accepts report options through sccache's generic argument path.
    // The pinned frontend omits their files, so discover those destinations
    // before allowing an action to be stored.
    if !clang {
        let mut default_reports = BTreeSet::new();
        if expanded
            .iter()
            .any(|arg| arg == "-fdiagnostics-format=sarif-file")
        {
            default_reports.insert(".sarif");
        }
        let mut explicit_reports = Vec::new();
        let mut implicit_dump = false;
        let mut ada_specs = false;
        let mut optimization_record = false;
        for arg in &expanded {
            ensure!(
                arg != "-time" && !arg.starts_with("-time="),
                "GCC timing output is not a replayable compiler artifact"
            );
            if arg == "-fsave-optimization-record" {
                optimization_record = true;
            } else if arg == "-fno-save-optimization-record" {
                optimization_record = false;
            }
            if is_gcc_debug_dump_arg(arg) {
                implicit_dump = true;
            }
            if arg.starts_with("-fdiagnostics-add-output")
                || arg.starts_with("-fdiagnostics-set-output")
            {
                let specification = arg
                    .split_once('=')
                    .map(|(_, specification)| specification)
                    .ok_or_else(|| anyhow::anyhow!("GCC diagnostic output has no specification"))?;
                match diagnostic_sink(specification)? {
                    DiagnosticSink::Text => {}
                    DiagnosticSink::DefaultFile(suffix) => {
                        default_reports.insert(suffix);
                    }
                    DiagnosticSink::File(path) => explicit_reports.push(path),
                }
            }
            if arg.starts_with("-fopt-info") || arg.starts_with("-fdump-") {
                if let Some((_, destination)) = arg.split_once('=') {
                    if arg.starts_with("-fdump-final-insns=") && destination == "." {
                        default_reports.insert(".gkd");
                    } else if !matches!(destination, "stdout" | "stderr" | "-") {
                        invocation.output(Path::new(destination), false)?;
                    }
                } else if arg.starts_with("-fdump-") {
                    if matches!(
                        arg.as_str(),
                        "-fdump-noaddr"
                            | "-fdump-unnumbered"
                            | "-fdump-unnumbered-links"
                            | "-fdump-internal-locations"
                            | "-fdump-passes"
                    ) {
                        // These change dump formatting or write only stderr;
                        // they do not create another compiler output file.
                        continue;
                    }
                    if arg == "-fdump-final-insns" {
                        default_reports.insert(".gkd");
                        continue;
                    }
                    if matches!(arg.as_str(), "-fdump-ada-spec" | "-fdump-ada-spec-slim") {
                        // The binding generator names specs after every input
                        // header, including transitive headers, in the cwd.
                        ada_specs = true;
                        continue;
                    }
                    // GCC's analyzer dumps use the same object-adjacent dump
                    // base for textual, graph, and compressed JSON outputs.
                    ensure!(
                        arg.starts_with("-fdump-tree-")
                            || arg.starts_with("-fdump-rtl-")
                            || arg.starts_with("-fdump-ipa-")
                            || arg.starts_with("-fdump-lang-")
                            || arg.starts_with("-fdump-analyzer")
                            || arg.starts_with("-fdump-statistics")
                            || matches!(arg.as_str(), "-fdump-debug" | "-fdump-earlydebug"),
                        "GCC dump option has an untracked side output"
                    );
                    implicit_dump = true;
                }
            }
        }
        if optimization_record {
            default_reports.insert(".opt-record.json.gz");
        }
        ensure!(
            !ada_specs || !implicit_dump,
            "GCC Ada specs and object-adjacent dumps need separate output scopes"
        );
        if !default_reports.is_empty() || implicit_dump {
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
            for suffix in default_reports {
                let mut filename = dump_base.clone();
                filename.push(suffix);
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
                    nested_prefixes: Vec::new(),
                });
            }
        }
        for path in explicit_reports {
            invocation.output(&path, false)?;
        }
        if ada_specs {
            // GCC emits Ada specs in the working directory even when the
            // object is placed elsewhere. The scope lock excludes other
            // wrapped writers while we attribute changed .ads files.
            invocation.dynamic_outputs = Some(DynamicOutputs {
                directory: cwd.to_string_lossy().into_owned(),
                prefix: String::new(),
                suffix: ".ads".into(),
                nested_prefixes: Vec::new(),
            });
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
    let parsed_depfile = parsed.outputs.get("d").map(|output| output.path.as_path());
    let (preprocessing, forwarded_depfile) =
        probe_preprocessor_args(&preprocessing, invocation, clang, parsed_depfile)?;
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
    let mut assembler_depfile = false;
    let mut assembler_listing_file = false;
    while index < common.len() {
        let arg = &common[index];
        if arg == "-Xassembler" && common.get(index + 1).is_some_and(|next| next == "--MD") {
            ensure!(
                parsed.uses_external_assembler && !assembler_depfile,
                "assembler dependency output cannot be tracked"
            );
            ensure!(
                common
                    .get(index + 2)
                    .is_some_and(|next| next == "-Xassembler"),
                "assembler dependency output has no filename"
            );
            let path = common
                .get(index + 3)
                .ok_or_else(|| anyhow::anyhow!("assembler dependency output has no filename"))?;
            invocation.output(Path::new(path), false)?;
            assembler_depfile = true;
            index += 4;
            continue;
        }
        if arg == "-Xassembler"
            && let Some(option) = common.get(index + 1)
            && let Some(listing) = assembler_listing_option(option)
        {
            ensure!(
                parsed.uses_external_assembler,
                "assembler listing requires an external assembler"
            );
            ensure!(
                !listing.timestamped,
                "assembler general listing contains a timestamp"
            );
            if let Some(path) = listing.output {
                ensure!(
                    !assembler_listing_file && !path.is_empty(),
                    "assembler listing output cannot be tracked"
                );
                invocation.output(Path::new(path), false)?;
                assembler_listing_file = true;
            }
            index += 2;
            continue;
        }
        if let Some(payload) = arg.strip_prefix("-Wa,") {
            let mut fields = payload.split(',');
            let mut preserved = Vec::new();
            let mut output = None;
            let mut listing_file = None;
            let mut has_listing = false;
            while let Some(field) = fields.next() {
                if field == "--MD" {
                    ensure!(output.is_none(), "multiple assembler dependency outputs");
                    output = Some(fields.next().ok_or_else(|| {
                        anyhow::anyhow!("assembler dependency output has no filename")
                    })?);
                } else if let Some(listing) = assembler_listing_option(field) {
                    ensure!(
                        !listing.timestamped,
                        "assembler general listing contains a timestamp"
                    );
                    has_listing = true;
                    if let Some(path) = listing.output {
                        ensure!(listing_file.is_none(), "multiple assembler listing outputs");
                        listing_file = Some(path);
                    }
                } else {
                    preserved.push(field);
                }
            }
            if output.is_some() || has_listing {
                ensure!(
                    parsed.uses_external_assembler,
                    "assembler side output requires an external assembler"
                );
                if let Some(path) = output {
                    ensure!(
                        !assembler_depfile && !path.is_empty(),
                        "assembler dependency output cannot be tracked"
                    );
                    invocation.output(Path::new(path), false)?;
                    assembler_depfile = true;
                }
                if let Some(path) = listing_file {
                    ensure!(
                        !assembler_listing_file && !path.is_empty(),
                        "assembler listing output cannot be tracked"
                    );
                    invocation.output(Path::new(path), false)?;
                    assembler_listing_file = true;
                }
                if !preserved.is_empty() {
                    scan.push(format!("-Wa,{}", preserved.join(",")));
                }
                index += 1;
                continue;
            }
        }
        if matches!(
            arg.as_str(),
            "--serialize-diagnostics" | "-serialize-diagnostics" | "-aux-info"
        ) {
            index += 2;
            continue;
        }
        if !clang
            && (arg.starts_with("-fdump-")
                || arg.starts_with("-fopt-info")
                || arg == "-fsave-optimization-record")
        {
            // A dependency probe must not create or append to a caller's
            // report before the actual compilation or a cache restoration.
            index += 1;
            continue;
        }
        if !clang && is_gcc_debug_dump_arg(arg) {
            // These flags can write pass-numbered dumps during compilation.
            // The dependency probe must not create them in the caller's tree.
            index += 1;
            continue;
        }
        if !clang
            && (arg == "-fdiagnostics-format=sarif-file"
                || arg.starts_with("-fdiagnostics-add-output")
                || arg.starts_with("-fdiagnostics-set-output"))
        {
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
        && !forwarded_depfile
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

struct AssemblerListing<'a> {
    output: Option<&'a str>,
    timestamped: bool,
}

fn assembler_listing_option(option: &str) -> Option<AssemblerListing<'_>> {
    let suffix = option.strip_prefix("-a")?;
    let (letters, destination) = match suffix.split_once('=') {
        Some((letters, destination)) => (letters, Some(destination)),
        None => (suffix, None),
    };
    letters
        .chars()
        .all(|letter| "cdghilmns".contains(letter))
        .then_some(AssemblerListing {
            output: destination,
            timestamped: letters.contains('g'),
        })
}

fn probe_preprocessor_args(
    arguments: &[String],
    invocation: &mut Invocation,
    clang: bool,
    parsed_depfile: Option<&Path>,
) -> Result<(Vec<String>, bool)> {
    let mut probe = Vec::new();
    let mut forwarded_depfile = None;
    let mut index = 0;

    while index < arguments.len() {
        let argument = &arguments[index];
        if let Some(payload) = argument.strip_prefix("-Wp,") {
            let mut fields = payload.split(',');
            let mut preserved = Vec::new();
            let mut writes_depfile = false;
            while let Some(field) = fields.next() {
                match field {
                    "-MD" | "-MMD" => {
                        let filename = fields.next().ok_or_else(|| {
                            anyhow::anyhow!("-Wp dependency output has no filename")
                        })?;
                        ensure!(
                            !filename.is_empty(),
                            "-Wp dependency output has no filename"
                        );
                        forwarded_depfile = Some(filename);
                        writes_depfile = true;
                    }
                    "-M" | "-MM" | "-MF" | "-MG" => {
                        anyhow::bail!("untracked -Wp dependency output option")
                    }
                    _ => preserved.push(field),
                }
            }
            ensure!(
                !clang || !writes_depfile || preserved.is_empty(),
                "Clang mixed -Wp dependency output cannot be tracked"
            );
            if !preserved.is_empty() {
                // Other forwarded CPP options still affect dependency
                // discovery. Remove only the caller-visible depfile request.
                probe.push(format!("-Wp,{}", preserved.join(",")));
            }
            index += 1;
            continue;
        }
        if argument == "-Xpreprocessor" {
            match arguments.get(index + 1).map(String::as_str) {
                Some("-MD" | "-MMD") => {
                    ensure!(
                        !clang,
                        "Clang direct preprocessor depfile option is unsupported"
                    );
                    ensure!(
                        arguments
                            .get(index + 2)
                            .is_some_and(|next| next == "-Xpreprocessor"),
                        "direct preprocessor dependency output has no filename"
                    );
                    let filename = arguments.get(index + 3).ok_or_else(|| {
                        anyhow::anyhow!("direct preprocessor dependency output has no filename")
                    })?;
                    forwarded_depfile = Some(filename);
                    index += 4;
                    continue;
                }
                Some("-M" | "-MM" | "-MF" | "-MG") => {
                    anyhow::bail!("untracked direct preprocessor dependency output option")
                }
                _ => {}
            }
        }
        probe.push(argument.clone());
        index += 1;
    }

    let has_forwarded_depfile = forwarded_depfile.is_some();
    if let Some(filename) = forwarded_depfile {
        // The frontend can infer source.d from a forwarded -MD, but GCC
        // writes only the destination consumed by CPP. Replace that inferred
        // output so publication never expects a file the compiler did not make.
        if let Some(path) = parsed_depfile {
            let path = super::output_name(path)?;
            invocation.outputs.retain(|output| output != &path);
            invocation.optional_outputs.remove(&path);
        }
        invocation.output(Path::new(filename), false)?;
    }

    Ok((probe, has_forwarded_depfile))
}

enum DiagnosticSink {
    Text,
    DefaultFile(&'static str),
    File(PathBuf),
}

fn diagnostic_sink(specification: &str) -> Result<DiagnosticSink> {
    let (scheme, parameters) = specification.split_once(':').unwrap_or((specification, ""));
    let suffix = match scheme {
        "text" => None,
        "sarif" => Some(".sarif"),
        "experimental-html" => Some(".html"),
        _ => anyhow::bail!("unknown GCC diagnostic output sink"),
    };
    let mut file = None;
    if !parameters.is_empty() {
        for parameter in parameters.split(',') {
            let (key, value) = parameter
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("invalid GCC diagnostic output parameter"))?;
            if key == "file" && suffix.is_some() {
                ensure!(!value.is_empty(), "GCC diagnostic output filename is empty");
                file = Some(PathBuf::from(value));
                continue;
            }
            let supported = match scheme {
                "text" => matches!(
                    key,
                    "color" | "show-nesting" | "show-nesting-locations" | "show-nesting-levels"
                ),
                "sarif" => matches!(key, "serialization" | "version" | "state-graphs"),
                // Diagram SVG is embedded in the HTML file. PATH selects dot
                // and is already part of the action identity.
                "experimental-html" => matches!(
                    key,
                    "css"
                        | "javascript"
                        | "show-state-diagrams"
                        | "show-graph-dot-src"
                        | "show-graph-sarif"
                ),
                _ => false,
            } || key == "cfgs";
            ensure!(supported, "unknown GCC diagnostic output parameter");
        }
    }
    Ok(match (suffix, file) {
        (_, Some(path)) => DiagnosticSink::File(path),
        (Some(suffix), None) => DiagnosticSink::DefaultFile(suffix),
        (None, None) => DiagnosticSink::Text,
    })
}

fn uses_custom_dump_naming(args: &[String]) -> bool {
    args.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "-dumpbase" | "--dumpbase" | "-dumpdir" | "--dumpdir"
        ) || arg.starts_with("--dumpbase=")
            || arg.starts_with("--dumpdir=")
    })
}

fn is_gcc_debug_dump_arg(arg: &str) -> bool {
    // GCC treats -dumpbase=foo as joined -d debug letters. Only the separate
    // -dumpbase foo form changes the dump basename.
    arg.starts_with("-d") && arg.len() > 2 && !matches!(arg, "-dumpbase" | "-dumpdir")
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
