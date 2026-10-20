//! File inputs and live outputs selected through internal LLVM options.

use anyhow::{Result, ensure};
use std::{collections::BTreeSet, path::PathBuf};

use crate::model::{LlvmOptionKind, Manifest};

/// Files LLVM reads or replaces outside the compiler's normal depfile.
pub(super) struct OptionEffects {
    pub(super) inputs: BTreeSet<PathBuf>,
    pub(super) outputs: BTreeSet<PathBuf>,
}

/// Describes effects accache can account for without inspecting LLVM itself.
pub(super) enum OptionEffect<'a> {
    FileInput(&'a str),
    FileOutput(&'a str),
    NoFileInput,
    NeedsValue,
    InvocationReport,
    Unknown,
}

/// Classifies a sequence because LLVM accepts a value in the next argument.
pub(super) fn file_effects(
    arguments: &[&str],
    compiler: &str,
    manifest: &Manifest,
) -> Result<OptionEffects> {
    let mut effects = OptionEffects {
        inputs: BTreeSet::new(),
        outputs: BTreeSet::new(),
    };
    let mut index = 0;

    while let Some(argument) = arguments.get(index) {
        let mut effect = classify(argument, manifest);
        if matches!(effect, OptionEffect::NeedsValue) {
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| anyhow::anyhow!("{compiler} LLVM option {argument} has no value"))?;
            // Classifying the joined spelling keeps literal modes such as
            // basic-block-sections=all identical across both LLVM forms.
            let joined = format!("{argument}={value}");
            effect = classify(&joined, manifest);
            match effect {
                OptionEffect::FileInput(path) => {
                    ensure!(!path.is_empty(), "LLVM file input is empty");
                    effects.inputs.insert(path.into());
                }
                OptionEffect::FileOutput(path) => {
                    ensure!(!path.is_empty(), "LLVM file output is empty");
                    effects.outputs.insert(path.into());
                }
                OptionEffect::NoFileInput => {}
                _ => {
                    anyhow::bail!("{compiler} LLVM option {argument} has no audited cache contract")
                }
            }
            index += 2;
            continue;
        }

        match effect {
            OptionEffect::FileInput(path) => {
                ensure!(!path.is_empty(), "LLVM file input is empty");
                effects.inputs.insert(path.into());
            }
            OptionEffect::FileOutput(path) => {
                ensure!(!path.is_empty(), "LLVM file output is empty");
                effects.outputs.insert(path.into());
            }
            OptionEffect::NoFileInput => {}
            OptionEffect::InvocationReport => {
                anyhow::bail!("{compiler} LLVM option {argument} writes an invocation report");
            }
            OptionEffect::Unknown | OptionEffect::NeedsValue => {
                anyhow::bail!("{compiler} LLVM option {argument} has no audited cache contract");
            }
        }
        index += 1;
    }

    Ok(effects)
}

pub(super) fn classify<'a>(argument: &'a str, manifest: &Manifest) -> OptionEffect<'a> {
    let argument = argument.trim_start_matches('-');
    let name = argument.split_once('=').map_or(argument, |(name, _)| name);
    if matches!(
        name,
        "as-secure-log-file"
            | "attributor-dump-dep-graph"
            | "attributor-view-dep-graph"
            | "callgraph-dot-filename-prefix"
            | "cfg-dot-filename-prefix"
            | "constraint-elimination-dump-reproducers"
            | "crash-diagnostics-dir"
            | "dataflow-log"
            | "dot-cfg-dir"
            | "dot-cfg-mssa"
            | "dot-ddg-filename-prefix"
            | "info-output-file"
            | "ir-dump-directory"
            | "lowertypetests-write-summary"
            | "lto-pass-remarks-output"
            | "lto-stats-file"
            | "mcfg-dot-filename-prefix"
            | "memprof-dot-file-path-prefix"
            | "module-summary-dot-file"
            | "opt-bisect-print-ir-path"
            | "print-changed-diff-path"
            | "print-changed-dot-path"
            | "pgo-view-block-coverage-graph"
            | "print-after"
            | "print-after-all"
            | "print-before"
            | "print-before-all"
            | "print-changed"
            | "print-on-crash-path"
            | "stats"
            | "time-passes"
            | "wholeprogramdevirt-write-summary"
    ) || name.starts_with("view-")
        || name.starts_with("pgo-view-")
    {
        return OptionEffect::InvocationReport;
    }

    if let Some(path) = argument.strip_prefix("basic-block-sections=") {
        // These literal modes need no file. Other values name a function and
        // block list that LLVM reads outside the compiler's normal depfile.
        return if matches!(path, "all" | "none" | "labels") {
            OptionEffect::NoFileInput
        } else {
            OptionEffect::FileInput(path)
        };
    }
    if argument == "basic-block-sections" {
        return OptionEffect::NeedsValue;
    }

    for prefix in [
        "cgscc-inline-replay=",
        "chr-function-list=",
        "chr-module-list=",
        "codegen-data-use-path=",
        "dfsan-abilist=",
        "extract-blocks-file=",
        "forceattrs-csv-path=",
        "fs-profile-file=",
        "fs-remapping-file=",
        "internalize-public-api-file=",
        "instrument-cold-function-only-path=",
        "ir2vec-vocab-path=",
        "lowertypetests-read-summary=",
        "mir2vec-vocab-path=",
        "ml-inliner-ir2vec-vocab-file=",
        "ms-secure-hotpatch-functions-file=",
        "pgo-test-profile-file=",
        "pgo-test-profile-remapping-file=",
        "rewrite-map-file=",
        "sample-profile-file=",
        "sample-profile-inline-replay=",
        "sample-profile-remapping-file=",
        "summary-file=",
        "use-ctx-profile=",
        "wholeprogramdevirt-read-summary=",
    ] {
        if let Some(path) = argument.strip_prefix(prefix) {
            return OptionEffect::FileInput(path);
        }
        if Some(argument) == prefix.strip_suffix('=') {
            return OptionEffect::NeedsValue;
        }
    }

    if matches!(
        name,
        "inline-threshold" | "preinline-threshold" | "unroll-count" | "unroll-threshold"
    ) {
        // These scalar tuning options affect generated code, and the full
        // compiler argument remains in the action key.
        return if argument.contains('=') {
            OptionEffect::NoFileInput
        } else {
            OptionEffect::NeedsValue
        };
    }

    if matches!(name, "hot-cold-split" | "enable-merge-functions") {
        // These switches select LLVM optimization passes without adding
        // external reads or report files. Their spelling stays in the key.
        return OptionEffect::NoFileInput;
    }

    // Built-in report exclusions take precedence over package contracts: a
    // caller cannot turn invocation-wide diagnostics into a reusable action.
    match manifest.llvm_options.get(name) {
        Some(LlvmOptionKind::Flag) => {
            if argument.contains('=') {
                OptionEffect::Unknown
            } else {
                OptionEffect::NoFileInput
            }
        }
        Some(LlvmOptionKind::Scalar) => {
            if argument.contains('=') {
                OptionEffect::NoFileInput
            } else {
                OptionEffect::NeedsValue
            }
        }
        Some(LlvmOptionKind::FileInput) => match argument.split_once('=') {
            Some((_, path)) => OptionEffect::FileInput(path),
            None => OptionEffect::NeedsValue,
        },
        Some(LlvmOptionKind::FileOutput) => match argument.split_once('=') {
            Some((_, path)) => OptionEffect::FileOutput(path),
            None => OptionEffect::NeedsValue,
        },
        None => OptionEffect::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn manifest() -> Manifest {
        Manifest {
            schema: 1,
            compilers: BTreeMap::new(),
            closure: Vec::new(),
            remove_environment: Vec::new(),
            read_roots: Vec::new(),
            llvm_options: BTreeMap::from([
                ("extra-input".into(), LlvmOptionKind::FileInput),
                ("extra-output".into(), LlvmOptionKind::FileOutput),
                ("print-after".into(), LlvmOptionKind::Flag),
            ]),
        }
    }

    #[test]
    fn declared_paths_cover_both_llvm_value_spellings() {
        let effects = file_effects(
            &["--extra-input=profile.txt", "--extra-output", "result.txt"],
            "Clang",
            &manifest(),
        )
        .unwrap();

        assert_eq!(effects.inputs, BTreeSet::from([PathBuf::from("profile.txt")]));
        assert_eq!(effects.outputs, BTreeSet::from([PathBuf::from("result.txt")]));
    }

    #[test]
    fn manifest_cannot_reclassify_invocation_reports() {
        let error = file_effects(&["--print-after=instcombine"], "Rust", &manifest())
            .err()
            .unwrap();

        assert!(error.to_string().contains("invocation report"));
    }
}
