//! File inputs and live outputs selected through internal LLVM options.

/// Describes effects accache can account for without inspecting LLVM itself.
pub(super) enum OptionEffect<'a> {
    FileInput(&'a str),
    NoFileInput,
    InvocationReport,
    Unknown,
}

pub(super) fn classify(argument: &str) -> OptionEffect<'_> {
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
            | "dot-cfg-mssa"
            | "dot-ddg-filename-prefix"
            | "info-output-file"
            | "ir-dump-directory"
            | "lto-pass-remarks-output"
            | "lto-stats-file"
            | "mcfg-dot-filename-prefix"
            | "memprof-dot-file-path-prefix"
            | "module-summary-dot-file"
            | "opt-bisect-print-ir-path"
            | "pgo-view-block-coverage-graph"
            | "print-after"
            | "print-after-all"
            | "print-before"
            | "print-before-all"
            | "print-changed"
            | "print-on-crash-path"
            | "stats"
            | "time-passes"
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

    for prefix in [
        "cgscc-inline-replay=",
        "chr-function-list=",
        "chr-module-list=",
        "codegen-data-use-path=",
        "extract-blocks-file=",
        "forceattrs-csv-path=",
        "fs-profile-file=",
        "fs-remapping-file=",
        "internalize-public-api-file=",
        "ir2vec-vocab-path=",
        "mir2vec-vocab-path=",
        "ml-inliner-ir2vec-vocab-file=",
        "ms-secure-hotpatch-functions-file=",
        "pgo-test-profile-file=",
        "pgo-test-profile-remapping-file=",
        "rewrite-map-file=",
        "sample-profile-file=",
        "sample-profile-inline-replay=",
        "summary-file=",
    ] {
        if let Some(path) = argument.strip_prefix(prefix) {
            return OptionEffect::FileInput(path);
        }
    }

    if matches!(name, "inline-threshold" | "preinline-threshold") {
        // These scalar tuning options affect generated code, and the full
        // compiler argument remains in the action key.
        return OptionEffect::NoFileInput;
    }

    OptionEffect::Unknown
}
