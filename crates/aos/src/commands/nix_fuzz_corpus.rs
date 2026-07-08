//! `aos nix-fuzz-corpus` -- generate source seeds for cargo-fuzz.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};

use aos_core::error::AosError;
use aos_core::nix::{NixCli, NixEvalConfig, NixEvalMode, NixRunner};
use aos_core::output::Printer;

use super::nix_diff::{
    FuzzSourceFileKind, FuzzSourceSeed, fuzz_source_seeds, fuzz_source_seeds_for_attrs,
};

const SOURCE_SEED_PREFIX: &str = "# aos-nix-fuzz-source\n";
const DEFAULT_FUZZ_SYSTEM: &str = "x86_64-linux";
const DEFAULT_PARITY_CORPUS_DIR: &[&str] = &["fuzz", "corpus", "parity_json", "generated"];
const GENERATED_SEED_PREFIX: &str = "generated-";
const GENERATED_CONFORMANCE_CORPUS: &str = "generated-conformance-corpus.nix";

#[derive(Debug, Clone, Eq, PartialEq)]
struct FuzzCorpusSummary {
    output_dir: PathBuf,
    written: usize,
    removed: usize,
}

/// Generates cargo-fuzz source seeds from the `nix-diff` corpus.
///
/// `excludes` removes seeds from the generated set by exact attribute path or
/// by dot-prefix (`systems` excludes every `systems.*` seed). This is how the
/// hermetic CI corpus check skips attributes whose *evaluation* needs
/// realization (eval-time IFD) that a sandboxed store cannot satisfy.
///
/// # Errors
///
/// Returns an error if the repository root cannot be found, C++ Nix is
/// unavailable, the `nix-diff` corpus cannot be enumerated, every generated
/// seed is excluded, or seed files cannot be written.
pub fn run(
    printer: &Printer,
    verbose: u8,
    eval_config: NixEvalConfig,
    attrs: &[String],
    excludes: &[String],
    file: Option<&Path>,
    output_dir: Option<&Path>,
    clean: bool,
) -> Result<()> {
    NixRunner::ensure_nix_instantiate_available()?;
    let root = if file.is_none() || output_dir.is_none() {
        Some(NixRunner::find_root()?)
    } else {
        None
    };
    let file = match file {
        Some(file) => file.to_path_buf(),
        None => root
            .as_ref()
            .context("repository root is required for the default nix-fuzz-corpus file")?
            .join("default.nix"),
    };
    let output_dir = match output_dir {
        Some(output_dir) => output_dir.to_path_buf(),
        None => default_output_dir(
            root.as_deref()
                .context("repository root is required for the default fuzz corpus output")?,
        ),
    };

    let eval_config = effective_fuzz_eval_config(eval_config)?;
    let oracle = NixCli::with_eval_config(verbose, eval_config.clone());
    let seeds = if attrs.is_empty() {
        fuzz_source_seeds(&oracle, &file, true, true, &eval_config)?
    } else {
        fuzz_source_seeds_for_attrs(&file, attrs, &eval_config)?
    };
    let seeds = filter_excluded_seeds(seeds, excludes);
    if seeds.is_empty() {
        return Err(AosError::InvalidArgument {
            message: "nix-fuzz-corpus generated no source seeds".to_string(),
        }
        .into());
    }

    let summary = write_source_corpus(&output_dir, &seeds, &eval_config, clean)?;
    if !printer.json_if_active(&json!({
        "output_dir": summary.output_dir,
        "written": summary.written,
        "removed": summary.removed,
    })) {
        printer.success(&format!(
            "Wrote {} fuzz source seed(s) to {}",
            summary.written,
            summary.output_dir.display()
        ));
        if summary.removed > 0 {
            printer.info(&format!(
                "Removed {} stale generated artifact(s)",
                summary.removed
            ));
        }
    }

    Ok(())
}

fn default_output_dir(root: &Path) -> PathBuf {
    DEFAULT_PARITY_CORPUS_DIR
        .iter()
        .fold(root.to_path_buf(), |dir, segment| dir.join(segment))
}

/// Drops seeds matching an exclusion by exact attr path or dot-prefix.
fn filter_excluded_seeds(seeds: Vec<FuzzSourceSeed>, excludes: &[String]) -> Vec<FuzzSourceSeed> {
    if excludes.is_empty() {
        return seeds;
    }
    seeds
        .into_iter()
        .filter(|seed| !excludes.iter().any(|exclude| seed_excluded(seed, exclude)))
        .collect()
}

fn seed_excluded(seed: &FuzzSourceSeed, exclude: &str) -> bool {
    seed.name == exclude
        || (seed.name.len() > exclude.len()
            && seed.name.starts_with(exclude)
            && seed.name.as_bytes()[exclude.len()] == b'.')
}

fn effective_fuzz_eval_config(mut eval_config: NixEvalConfig) -> Result<NixEvalConfig> {
    if eval_config.eval_mode() == NixEvalMode::Ambient {
        eval_config.set_eval_mode(NixEvalMode::Impure);
    }
    if eval_config.current_system().is_none() {
        eval_config.set_current_system(DEFAULT_FUZZ_SYSTEM)?;
    }
    Ok(eval_config)
}

fn write_source_corpus(
    output_dir: &Path,
    seeds: &[FuzzSourceSeed],
    eval_config: &NixEvalConfig,
    clean: bool,
) -> Result<FuzzCorpusSummary> {
    let removed = if clean {
        remove_seed_files(output_dir)?
    } else {
        0
    };
    fs::create_dir_all(output_dir).with_context(|| format!("creating {}", output_dir.display()))?;

    for seed in seeds {
        let seed = seed_for_output(seed, output_dir)?;
        let path = output_dir.join(seed_file_name(&seed));
        fs::write(&path, source_seed_file(&seed, eval_config))
            .with_context(|| format!("writing fuzz source seed {}", path.display()))?;
    }

    Ok(FuzzCorpusSummary {
        output_dir: output_dir.to_path_buf(),
        written: seeds.len(),
        removed,
    })
}

fn remove_seed_files(output_dir: &Path) -> Result<usize> {
    if !output_dir.exists() {
        return Ok(0);
    }

    let mut removed = 0;
    for entry in
        fs::read_dir(output_dir).with_context(|| format!("reading {}", output_dir.display()))?
    {
        let entry = entry.with_context(|| format!("reading entry in {}", output_dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("reading file type for {}", path.display()))?;
        if file_type.is_file() && is_generated_file(&path) {
            fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn is_generated_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("seed" | "nix")
    ) && path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(GENERATED_SEED_PREFIX))
}

fn seed_for_output(seed: &FuzzSourceSeed, output_dir: &Path) -> Result<FuzzSourceSeed> {
    if seed.source_file_kind != FuzzSourceFileKind::GeneratedConformance {
        return Ok(seed.clone());
    }

    let support_file = output_dir.join(GENERATED_CONFORMANCE_CORPUS);
    fs::copy(&seed.source_file, &support_file).with_context(|| {
        format!(
            "copying generated conformance corpus {} to {}",
            seed.source_file.display(),
            support_file.display()
        )
    })?;
    seed.with_source_file(support_file)
}

fn source_seed_file(seed: &FuzzSourceSeed, eval_config: &NixEvalConfig) -> String {
    let metadata = source_seed_config_lines(eval_config, seed);
    let metadata_len = metadata.iter().map(String::len).sum::<usize>() + metadata.len();
    let mut file =
        String::with_capacity(SOURCE_SEED_PREFIX.len() + metadata_len + seed.source.len() + 1);
    file.push_str(SOURCE_SEED_PREFIX);
    for line in metadata {
        file.push_str("# aos-nix-fuzz-config ");
        file.push_str(&line);
        file.push('\n');
    }
    file.push_str(seed.source.trim());
    file.push('\n');
    file
}

fn source_seed_config_lines(eval_config: &NixEvalConfig, seed: &FuzzSourceSeed) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "eval-mode={}",
        match eval_config.eval_mode() {
            NixEvalMode::Ambient => "ambient",
            NixEvalMode::Impure => "impure",
            NixEvalMode::Restricted => "restricted",
            NixEvalMode::Pure => "pure",
        }
    ));
    if let Some(current_system) = eval_config.current_system() {
        lines.push(format!("current-system={current_system}"));
    }
    if eval_config.eval_mode() == NixEvalMode::Restricted {
        lines.extend(
            eval_config
                .allowed_paths()
                .iter()
                .map(|path| format!("allowed-path={path}")),
        );
        lines.extend(
            eval_config
                .allowed_uris()
                .iter()
                .map(|uri| format!("allowed-uri={uri}")),
        );
        if seed.source_file_kind == FuzzSourceFileKind::GeneratedConformance
            && let Some(source_file) = seed.source_file.to_str()
        {
            lines.push(format!("allowed-path={source_file}"));
        }
    }
    lines
}

fn seed_file_name(seed: &FuzzSourceSeed) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seed.name.as_bytes());
    hasher.update(b"\0");
    hasher.update(seed.source.as_bytes());
    let digest = hasher.finalize();
    format!(
        "{GENERATED_SEED_PREFIX}{}-{}.seed",
        sanitize_seed_name(&seed.name),
        hex_prefix(&digest, 8)
    )
}

fn sanitize_seed_name(name: &str) -> String {
    let mut sanitized = String::new();
    for byte in name.bytes() {
        let next = match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' => byte as char,
            _ => '_',
        };
        sanitized.push(next);
        if sanitized.len() >= 96 {
            break;
        }
    }
    let sanitized = sanitized.trim_matches(['_', '.', '-']);
    if sanitized.is_empty() {
        "seed".to_string()
    } else {
        sanitized.to_string()
    }
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    let mut out = String::with_capacity(count * 2);
    for byte in bytes.iter().take(count) {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + (value - 10)) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_config_defaults_to_impure_linux() -> Result<()> {
        let config = effective_fuzz_eval_config(NixEvalConfig::new())?;

        assert_eq!(config.eval_mode(), NixEvalMode::Impure);
        assert_eq!(config.current_system(), Some(DEFAULT_FUZZ_SYSTEM));
        Ok(())
    }

    #[test]
    fn effective_config_preserves_explicit_system() -> Result<()> {
        let mut input = NixEvalConfig::with_current_system("aos-test-target")?;
        input.set_eval_mode(NixEvalMode::Pure);

        let config = effective_fuzz_eval_config(input)?;

        assert_eq!(config.eval_mode(), NixEvalMode::Pure);
        assert_eq!(config.current_system(), Some("aos-test-target"));
        Ok(())
    }

    #[test]
    fn filter_excluded_seeds_matches_exact_and_dot_prefix() {
        let seed = |name: &str| FuzzSourceSeed {
            name: name.to_string(),
            source: name.to_string(),
            source_file: PathBuf::from("/repo/default.nix"),
            source_file_kind: FuzzSourceFileKind::Direct,
            root_args: "{}".to_string(),
        };
        let seeds = vec![
            seed("pkgs.linux"),
            seed("pkgs.linux-headers"),
            seed("systems.server.build.toplevel"),
            seed("systems.edge.build.toplevel"),
            seed("pkgs.zlib"),
        ];

        let excludes = vec!["pkgs.linux".to_string(), "systems".to_string()];
        let kept = filter_excluded_seeds(seeds.clone(), &excludes);
        let names: Vec<&str> = kept.iter().map(|seed| seed.name.as_str()).collect();

        // Exact match excludes pkgs.linux but not the pkgs.linux-headers
        // sibling; the dot-prefix form excludes every systems.* seed.
        assert_eq!(names, ["pkgs.linux-headers", "pkgs.zlib"]);
        assert_eq!(filter_excluded_seeds(seeds.clone(), &[]).len(), seeds.len());
    }

    #[test]
    fn seed_file_name_is_stable_and_sanitized() {
        let seed = FuzzSourceSeed {
            name: "pkgs.rust-1_74".to_string(),
            source: "pkgs.rust-1_74".to_string(),
            source_file: PathBuf::from("/repo/default.nix"),
            source_file_kind: FuzzSourceFileKind::Direct,
            root_args: "{}".to_string(),
        };

        assert_eq!(
            seed_file_name(&seed),
            "generated-pkgs.rust-1_74-1f42d2af2f286f8e.seed"
        );
    }

    #[test]
    fn source_seed_file_wraps_literal_source() {
        let seed = FuzzSourceSeed {
            name: "pkgs.hello".to_string(),
            source: "  { a = 1; }\n".to_string(),
            source_file: PathBuf::from("/repo/default.nix"),
            source_file_kind: FuzzSourceFileKind::Direct,
            root_args: "{}".to_string(),
        };
        let mut config =
            NixEvalConfig::with_current_system("x86_64-linux").expect("test system is valid");
        config.set_eval_mode(NixEvalMode::Impure);

        assert_eq!(
            source_seed_file(&seed, &config),
            "# aos-nix-fuzz-source\n\
             # aos-nix-fuzz-config eval-mode=impure\n\
             # aos-nix-fuzz-config current-system=x86_64-linux\n\
             { a = 1; }\n"
        );
    }

    #[test]
    fn source_seed_config_lines_record_eval_mode_and_system() -> Result<()> {
        let mut config = NixEvalConfig::with_current_system("aos-test-target")?;
        config.set_eval_mode(NixEvalMode::Restricted);
        config.add_allowed_path("/repo")?;
        config.add_allowed_uri("https://cache.example/")?;
        let seed = FuzzSourceSeed {
            name: "pkgs.hello".to_string(),
            source: "{ hello = true; }".to_string(),
            source_file: PathBuf::from("/repo/default.nix"),
            source_file_kind: FuzzSourceFileKind::Direct,
            root_args: "{}".to_string(),
        };

        assert_eq!(
            source_seed_config_lines(&config, &seed),
            vec![
                "eval-mode=restricted".to_string(),
                "current-system=aos-test-target".to_string(),
                "allowed-path=/repo".to_string(),
                "allowed-uri=https://cache.example/".to_string()
            ]
        );
        Ok(())
    }

    #[test]
    fn restricted_conformance_seed_allows_copied_support_file() -> Result<()> {
        let mut config = NixEvalConfig::with_current_system("aos-test-target")?;
        config.set_eval_mode(NixEvalMode::Restricted);
        config.add_allowed_path("/repo")?;
        let seed = FuzzSourceSeed {
            name: "conformance.eval-okay-number".to_string(),
            source: "old temp source".to_string(),
            source_file: PathBuf::from("/private/tmp/generated/generated-conformance-corpus.nix"),
            source_file_kind: FuzzSourceFileKind::GeneratedConformance,
            root_args: "{ system = \"aos-test-target\"; }".to_string(),
        };

        assert_eq!(
            source_seed_config_lines(&config, &seed),
            vec![
                "eval-mode=restricted".to_string(),
                "current-system=aos-test-target".to_string(),
                "allowed-path=/repo".to_string(),
                "allowed-path=/private/tmp/generated/generated-conformance-corpus.nix".to_string(),
            ]
        );
        Ok(())
    }

    #[test]
    fn write_source_corpus_can_clean_stale_seeds() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let output_dir = tmp.path().join("generated");
        fs::create_dir_all(&output_dir)?;
        fs::write(output_dir.join("generated-stale.seed"), "stale")?;
        fs::write(output_dir.join("generated-conformance-corpus.nix"), "stale")?;
        fs::write(output_dir.join("curated.seed"), "curated")?;
        fs::write(output_dir.join("keep.txt"), "keep")?;
        let seeds = vec![FuzzSourceSeed {
            name: "pkgs.hello".to_string(),
            source: "{ hello = true; }".to_string(),
            source_file: tmp.path().join("default.nix"),
            source_file_kind: FuzzSourceFileKind::Direct,
            root_args: "{}".to_string(),
        }];

        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Impure);

        let summary = write_source_corpus(&output_dir, &seeds, &config, true)?;

        assert_eq!(summary.written, 1);
        assert_eq!(summary.removed, 2);
        assert!(!output_dir.join("generated-stale.seed").exists());
        assert!(!output_dir.join("generated-conformance-corpus.nix").exists());
        assert!(output_dir.join("curated.seed").exists());
        assert!(output_dir.join("keep.txt").exists());
        assert_eq!(
            fs::read_to_string(output_dir.join(seed_file_name(&seeds[0])))?,
            "# aos-nix-fuzz-source\n\
             # aos-nix-fuzz-config eval-mode=impure\n\
             { hello = true; }\n"
        );
        Ok(())
    }

    #[test]
    fn write_source_corpus_copies_generated_conformance_support_file() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let source_file = tmp.path().join("corpus.nix");
        let output_dir = tmp.path().join("generated");
        fs::write(
            &source_file,
            "{ system ? builtins.currentSystem }: { conformance = {}; }\n",
        )?;
        let seed = FuzzSourceSeed {
            name: "conformance.eval-okay-number".to_string(),
            source: "old temp source".to_string(),
            source_file,
            source_file_kind: FuzzSourceFileKind::GeneratedConformance,
            root_args: "{ system = \"x86_64-linux\"; }".to_string(),
        };

        let mut config = NixEvalConfig::with_current_system("x86_64-linux")?;
        config.set_eval_mode(NixEvalMode::Impure);

        let summary =
            write_source_corpus(&output_dir, std::slice::from_ref(&seed), &config, false)?;

        let support_file = output_dir.join(GENERATED_CONFORMANCE_CORPUS);
        assert_eq!(summary.written, 1);
        assert_eq!(
            fs::read_to_string(&support_file)?,
            "{ system ? builtins.currentSystem }: { conformance = {}; }\n"
        );
        let rendered_seed = seed.with_source_file(support_file.clone())?;
        let seed_path = output_dir.join(seed_file_name(&rendered_seed));
        let seed_text = fs::read_to_string(seed_path)?;
        assert!(seed_text.contains("# aos-nix-fuzz-config eval-mode=impure"));
        assert!(seed_text.contains("# aos-nix-fuzz-config current-system=x86_64-linux"));
        assert!(seed_text.contains(&support_file.display().to_string()));
        assert!(seed_text.contains("path = [ \"conformance\" \"eval-okay-number\" ];"));
        Ok(())
    }
}
