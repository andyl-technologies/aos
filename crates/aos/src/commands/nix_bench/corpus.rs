use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use aos_core::error::AosError;
use aos_core::nix::NixCli;

const DEFAULT_LEAF_PACKAGE_ATTRS: &[&str] = &[
    "pkgs.zlib",
    "pkgs.xz",
    "pkgs.bzip2",
    "pkgs.openssl",
    "pkgs.curl",
    "pkgs.sqlite",
    "pkgs.jq",
    "pkgs.socat",
    "pkgs.git",
];
const EXPLICIT_TOOLCHAIN_CORPUS_ATTRS: &[&str] = &[
    "stdenv.stdenv",
    "stdenv.cc",
    "stdenv.gcc",
    "stdenv.gccStage2",
    "stdenv.glibc",
    "stdenv.binutils",
    "stdenv.bash",
    "stdenv.coreutils",
    "stdenv.gnumake",
    "stdenv.sed",
    "stdenv.grep",
    "stdenv.findutils",
    "stdenv.gawk",
    "stdenv.diffutils",
    "stdenv.tar",
    "stdenv.gzip",
    "stdenv.patch",
    "stdenv.bootstrap.gcc",
    "stdenv.bootstrap.glibc",
    "stdenv.bootstrap.binutils",
    "stdenv.bootstrap.bash",
    "stdenv.bootstrap.gnumake",
    "stdenv.bootstrap.sed",
    "stdenv.bootstrap.grep",
    "stdenv.bootstrap.patch",
    "stdenv.bootstrap.coreutils",
    "stdenv.bootstrap.gawk",
    "stdenv.bootstrap.findutils",
    "stdenv.bootstrap.diffutils",
    "stdenv.bootstrap.tar",
    "stdenv.bootstrap.gzip",
    "pkgs.bootstrapTools",
    "pkgs.cc",
    "pkgs.gcc",
    "pkgs.gccUnwrapped",
    "pkgs.glibc",
    "pkgs.binutils",
    "pkgs.rust-1_74",
    "pkgs.rust-1_75",
    "pkgs.rust-1_76",
    "pkgs.rust-1_77",
    "pkgs.rust-1_78",
    "pkgs.rust-1_79",
    "pkgs.rust-1_80",
    "pkgs.rust-1_81",
    "pkgs.rust-1_82",
    "pkgs.rust-1_83",
    "pkgs.rust-1_84",
    "pkgs.rust-1_85",
    "pkgs.rust-1_86",
    "pkgs.rust-1_87",
    "pkgs.rust-1_88",
    "pkgs.rust-1_89",
    "pkgs.rust-1_90",
    "pkgs.rust-1_91",
    "pkgs.rust-1_92",
    "pkgs.rust",
    "pkgs.openjdk-7",
    "pkgs.openjdk-8",
    "pkgs.openjdk-9",
    "pkgs.openjdk-10",
    "pkgs.openjdk-11",
    "pkgs.openjdk-12",
    "pkgs.openjdk-13",
    "pkgs.openjdk-14",
    "pkgs.openjdk-15",
    "pkgs.openjdk-16",
    "pkgs.openjdk-17",
    "pkgs.openjdk-18",
    "pkgs.openjdk-19",
    "pkgs.openjdk-20",
    "pkgs.openjdk-21",
    "pkgs.openjdk-22",
    "pkgs.openjdk-23",
    "pkgs.openjdk-24",
    "pkgs.openjdk",
    "pkgs.bazel-bootstrap",
    "pkgs.bazel-7",
    "pkgs.bazel-8",
    "pkgs.bazel-9",
    "pkgs.bazel",
    "pkgs.llvm-17",
    "pkgs.llvm-18",
    "pkgs.llvm-19",
    "pkgs.llvm-20",
    "pkgs.llvm-21",
    "pkgs.llvm-22",
    "pkgs.llvm",
    "pkgs.go-1_4",
    "pkgs.go-1_17",
    "pkgs.go-1_20",
    "pkgs.go-1_22",
    "pkgs.go-1_24",
    "pkgs.go",
    "pkgs.python3-3_12",
    "pkgs.python3",
    "pkgs.cmake",
    "pkgs.meson",
    "pkgs.ninja",
];
const GCC_TOOLCHAIN_TIER_COMPONENTS: &[&str] = &[
    "gcc",
    "gccStage2",
    "glibc",
    "binutils",
    "linuxHeaders",
    "bash",
    "coreutils",
    "gnumake",
    "sed",
    "grep",
    "gawk",
    "findutils",
    "diffutils",
    "tar",
    "gzip",
    "patch",
    "m4",
    "flex",
    "bison",
    "perl",
    "autoconf",
    "automake",
    "texinfo",
    "help2man",
    "gperf",
    "python3",
    "xz",
    "bzip2",
    "patchelf",
];
const DIAGNOSTIC_CORPUS_BUILDER: &str =
    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-aos-nix-bench-diagnostic-builder";
/// One benchmark attribute to evaluate.
///
/// A spec is temperature-neutral: the paired-cycle driver
/// ([`super::run_one_benchmark`]) produces both the cold and warm records for it
/// from the same fresh-instance cycles, so there is no per-temperature spec.
#[derive(Debug, Clone)]
pub(crate) struct BenchmarkSpec {
    pub(crate) name: String,
    pub(crate) file: PathBuf,
    pub(crate) attr: String,
    pub(crate) category: String,
}

pub(crate) fn benchmark_specs(
    oracle: &NixCli,
    root: &Path,
    file: &Path,
    attrs: &[String],
) -> Result<Vec<BenchmarkSpec>> {
    if !attrs.is_empty() {
        return Ok(explicit_benchmark_specs(file, attrs));
    }

    let mut specs = Vec::new();
    let mut seen = BTreeSet::new();
    extend_unique_specs(&mut specs, &mut seen, system_benchmark_specs(oracle, file)?);
    extend_unique_specs(
        &mut specs,
        &mut seen,
        toolchain_benchmark_specs(oracle, file)?,
    );
    extend_unique_specs(
        &mut specs,
        &mut seen,
        existing_attr_specs(oracle, file, DEFAULT_LEAF_PACKAGE_ATTRS, "leaf")?,
    );
    extend_unique_specs(&mut specs, &mut seen, diagnostic_benchmark_specs(root)?);

    if specs.is_empty() {
        return Err(AosError::InvalidArgument {
            message: "nix-bench default corpus found no benchmarks".to_string(),
        }
        .into());
    }
    Ok(specs)
}

pub(crate) fn explicit_benchmark_specs(file: &Path, attrs: &[String]) -> Vec<BenchmarkSpec> {
    attrs
        .iter()
        .map(|attr| benchmark_spec(file.to_path_buf(), attr.clone(), "explicit"))
        .collect()
}

fn extend_unique_specs(
    specs: &mut Vec<BenchmarkSpec>,
    seen: &mut BTreeSet<(PathBuf, String)>,
    new_specs: Vec<BenchmarkSpec>,
) {
    for spec in new_specs {
        if seen.insert((spec.file.clone(), spec.attr.clone())) {
            specs.push(spec);
        }
    }
}

fn system_benchmark_specs(oracle: &NixCli, file: &Path) -> Result<Vec<BenchmarkSpec>> {
    let raw = oracle
        .eval_expr(&system_attr_expr(file)?)
        .context("evaluating nix-bench system benchmark corpus")?;
    let attrs: Vec<String> =
        serde_json::from_str(&raw).context("parsing nix-bench system benchmark corpus")?;
    Ok(attrs
        .into_iter()
        .map(|attr| benchmark_spec(file.to_path_buf(), attr, "system"))
        .collect())
}

fn existing_attr_specs(
    oracle: &NixCli,
    file: &Path,
    wanted: &[&str],
    category: &str,
) -> Result<Vec<BenchmarkSpec>> {
    let raw = oracle
        .eval_expr(&existing_attr_expr(file, wanted)?)
        .with_context(|| format!("evaluating nix-bench {category} benchmark corpus"))?;
    let attrs: Vec<String> = serde_json::from_str(&raw)
        .with_context(|| format!("parsing nix-bench {category} benchmark corpus"))?;
    Ok(attrs
        .into_iter()
        .map(|attr| benchmark_spec(file.to_path_buf(), attr, category))
        .collect())
}

fn toolchain_benchmark_specs(oracle: &NixCli, file: &Path) -> Result<Vec<BenchmarkSpec>> {
    let raw = oracle
        .eval_expr(&toolchain_attr_expr(file)?)
        .context("evaluating nix-bench toolchain benchmark corpus")?;
    let attrs: Vec<String> =
        serde_json::from_str(&raw).context("parsing nix-bench toolchain benchmark corpus")?;
    Ok(attrs
        .into_iter()
        .map(|attr| benchmark_spec(file.to_path_buf(), attr, "toolchain"))
        .collect())
}

fn diagnostic_benchmark_specs(root: &Path) -> Result<Vec<BenchmarkSpec>> {
    let file = root
        .join(".aos-benchmarks")
        .join("corpus")
        .join("diagnostics.nix");
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(&file, diagnostic_corpus_source())
        .with_context(|| format!("writing nix-bench diagnostic corpus {}", file.display()))?;
    Ok([
        "diagnostic.attrset_access",
        "diagnostic.map_genlist",
        "diagnostic.deep_recursion",
    ]
    .into_iter()
    .map(|attr| benchmark_spec(file.clone(), attr.to_string(), "diagnostic"))
    .collect())
}

/// Builds a temperature-neutral spec. Its `name` (`"<category>:<attr>"`) is a
/// diagnostic label; the per-record history names (`"<category>:<temperature>:
/// <attr>"`) are assembled by the paired-cycle driver.
fn benchmark_spec(file: PathBuf, attr: String, category: &str) -> BenchmarkSpec {
    BenchmarkSpec {
        name: format!("{category}:{attr}"),
        file,
        attr,
        category: category.to_string(),
    }
}

fn existing_attr_expr(file: &Path, wanted: &[&str]) -> Result<String> {
    let file = nix_path_literal(file)?;
    let wanted = wanted
        .iter()
        .map(|attr| {
            let path = attr
                .split('.')
                .map(nix_string_literal)
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "{{ attr = {}; path = [ {path} ]; }}",
                nix_string_literal(attr)
            )
        })
        .collect::<Vec<_>>()
        .join("\n    ");

    Ok(format!(
        r#"
let
  loaded = import (builtins.toPath {});
  root = if builtins.isFunction loaded then loaded {{}} else loaded;
  missing = {{ __aosNixBenchMissing = true; }};
  wanted = [
    {}
  ];
  isDerivation = value:
    builtins.isAttrs value && (value ? type) && value.type == "derivation";
  getPath = path:
    builtins.foldl' (
      value: name:
        if builtins.isAttrs value && builtins.hasAttr name value
        then builtins.getAttr name value
        else missing
    ) root path;
  shouldCheck = item:
    let probe = builtins.tryEval (isDerivation (getPath item.path));
    in if probe.success then probe.value else false;
in
  builtins.map (item: item.attr) (builtins.filter shouldCheck wanted)
"#,
        file, wanted
    ))
}

pub(crate) fn toolchain_attr_expr(file: &Path) -> Result<String> {
    let file = nix_path_literal(file)?;
    let wanted = EXPLICIT_TOOLCHAIN_CORPUS_ATTRS
        .iter()
        .map(|attr| {
            let path = attr
                .split('.')
                .map(nix_string_literal)
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "{{ attr = {}; path = [ {path} ]; }}",
                nix_string_literal(attr)
            )
        })
        .collect::<Vec<_>>()
        .join("\n    ");
    let tier_components = GCC_TOOLCHAIN_TIER_COMPONENTS
        .iter()
        .map(|component| nix_string_literal(component))
        .collect::<Vec<_>>()
        .join(" ");

    Ok(format!(
        r#"
let
  loaded = import (builtins.toPath {});
  root = if builtins.isFunction loaded then loaded {{}} else loaded;
  missing = {{ __aosNixBenchMissing = true; }};
  explicit = [
    {}
  ];
  gccTierComponentNames = [ {} ];
  gccTierItems =
    if builtins.isAttrs root
      && builtins.hasAttr "stdenv" root
      && builtins.isAttrs root.stdenv
      && builtins.hasAttr "toolchainTiers" root.stdenv
    then
      let
        tiers = root.stdenv.toolchainTiers;
        tierNames = builtins.attrNames tiers;
        tierItems = tierName:
          builtins.map (
            componentName: {{
              attr = "stdenv.toolchainTiers.${{tierName}}.${{componentName}}";
              path = [ "stdenv" "toolchainTiers" tierName componentName ];
            }}
          ) gccTierComponentNames;
      in
        builtins.concatLists (builtins.map tierItems tierNames)
    else [];
  wanted = explicit ++ gccTierItems;
  isDerivation = value:
    builtins.isAttrs value && (value ? type) && value.type == "derivation";
  getPath = path:
    builtins.foldl' (
      value: name:
        if builtins.isAttrs value && builtins.hasAttr name value
        then builtins.getAttr name value
        else missing
    ) root path;
  shouldCheck = item:
    let probe = builtins.tryEval (isDerivation (getPath item.path));
    in if probe.success then probe.value else false;
in
  builtins.map (item: item.attr) (builtins.filter shouldCheck wanted)
"#,
        file, wanted, tier_components
    ))
}

fn system_attr_expr(file: &Path) -> Result<String> {
    let file = nix_path_literal(file)?;
    Ok(format!(
        r#"
let
  loaded = import (builtins.toPath {});
  root = if builtins.isFunction loaded then loaded {{}} else loaded;
  systems =
    if builtins.isAttrs root && (root ? systems)
    then root.systems
    else {{}};
  toToplevel = name: "systems.${{name}}.build.toplevel";
in
  builtins.map toToplevel (builtins.attrNames systems)
"#,
        file
    ))
}

fn diagnostic_corpus_source() -> String {
    let mut source = String::from(
        r#"let
  system =
    if builtins ? currentSystem
    then builtins.currentSystem
    else "x86_64-linux";
  mkCase = name: value:
    derivationStrict {
      inherit name system;
      builder = "#,
    );
    source.push_str(&nix_string_literal(DIAGNOSTIC_CORPUS_BUILDER));
    source.push_str(
        r#";
      args = [];
      evaluated = builtins.toJSON value;
    };
in
{
  diagnostic = {
    attrset_access =
      let
        keys = builtins.genList (n: n) 200;
        attrs = builtins.listToAttrs (
          map (n: { name = "k${toString n}"; value = n; }) keys
        );
      in
        mkCase "aos-nix-bench-attrset-access" attrs.k199;
    map_genlist =
      let
        values = map (n: n + 1) (builtins.genList (n: n) 500);
      in
        mkCase "aos-nix-bench-map-genlist" (
          builtins.foldl' (acc: value: acc + value) 0 values
        );
    deep_recursion =
      let
        go = n: acc:
          if n == 0
          then acc
          else go (n - 1) (acc + n);
      in
        mkCase "aos-nix-bench-deep-recursion" (go 200 0);
  };
}
"#,
    );
    source
}

fn nix_path_literal(path: &Path) -> Result<String> {
    let path = path
        .to_str()
        .with_context(|| format!("nix-bench path is not valid UTF-8: {}", path.display()))?;
    Ok(nix_string_literal(path))
}

fn nix_string_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '$' if chars.peek() == Some(&'{') => out.push_str("\\$"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_specs_are_one_temperature_neutral_spec_per_attr() {
        // Under the paired-cycle driver each attr is a single spec; the driver
        // emits both the cold and warm records, so there is no warm split.
        let specs = explicit_benchmark_specs(
            &PathBuf::from("/repo/default.nix"),
            &["pkgs.zlib".to_string(), "pkgs.openssl".to_string()],
        );

        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].name, "explicit:pkgs.zlib");
        assert_eq!(specs[0].attr, "pkgs.zlib");
        assert_eq!(specs[0].category, "explicit");
        assert_eq!(specs[0].file, PathBuf::from("/repo/default.nix"));
        assert_eq!(specs[1].name, "explicit:pkgs.openssl");
    }
}
