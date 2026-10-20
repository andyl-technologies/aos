##! Source-built dependency generator for workerd's rules_rust module.
{
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
  callPackage,
  buildPackages,
  bash,
  stdenv,
}: let
  rulesVersion = "0.71.2";
  src = fetchurl {
    urls = ["https://github.com/bazelbuild/rules_rust/archive/refs/tags/${rulesVersion}.tar.gz"];
    hash = "078gjw7p4f4qbz5v3zjy6fzvzs0k5vr92i9kbvhjs5dzlck1r29k";
  };
  cargoVendorRaw = fetchCargoVendor {
    inherit src;
    sourceRoot = "rules_rust-${rulesVersion}/crate_universe";
    name = "workerd-cargo-bazel-vendor";
    hash = "sha256-MPaL3S2xxtzk+7JbAk5xskeKvQ7d3w353HTWrG4XHio=";
  };
  sourceOnlyCargoVendor = callPackage ../../build-support/_cargo-source-vendor.nix {};
in
  mkCargoPackage {
    pname = "workerd-cargo-bazel";
    version = "0.18.0";
    inherit src;
    cargoRoot = "crate_universe";
    cargoDeps = sourceOnlyCargoVendor {
      name = "workerd-cargo-bazel-source-only";
      vendor = cargoVendorRaw;
    };
    cargoFlags = "-p cargo-bazel";
    cargoTestFlags = "-p cargo-bazel --lib";
    doCheck = !stdenv.isCross;
    buildDeps = [buildPackages.python3];
    runtimeDeps = [bash];
    # Upstream normally supplies test runfiles through Bazel. Use the same
    # checked-in helper and fixtures when running its library tests with Cargo.
    preConfigure = ''
      cp ${./fixtures/cargo-bazel/config.json} crate_universe/test_data/serialized_configs/config.json
      cp ${./fixtures/cargo-bazel/splicing_manifest.json} crate_universe/test_data/serialized_configs/splicing_manifest.json
      ${buildPackages.python3}/bin/python3 <<'PY'
      from pathlib import Path

      manifest = Path('crate_universe/Cargo.toml')
      text = manifest.read_text()
      text = text.replace('[dev-dependencies]', '[dev-dependencies]\nrunfiles = { path = "../rust/runfiles" }')
      manifest.write_text(text)

      lockfile = Path('crate_universe/Cargo.lock')
      text = lockfile.read_text()
      marker = 'name = "cargo-bazel"\nversion = "0.18.0"\ndependencies = ['
      assert text.count(marker) == 1
      text = text.replace(marker, marker + '\n "runfiles",')
      text += '\n[[package]]\nname = "runfiles"\nversion = "0.2.0"\n'
      lockfile.write_text(text)

      source = Path('crate_universe/src/splicing/splicer.rs')
      text = source.read_text()
      marker = '    use std::fs::File;'
      assert text.count(marker) == 1
      text = text.replace(marker, marker + '\n    use std::path::PathBuf;')
      text = text.replace('PathBuf::from("cargo")', 'PathBuf::from("${buildPackages.rust}/bin/cargo")')
      text = text.replace('PathBuf::from("rustc")', 'PathBuf::from("${buildPackages.rust}/bin/rustc")')
      source.write_text(text)

      # Cargo's directory vendor records real source URLs but places Git
      # manifests outside CARGO_HOME/git/checkouts. Preserve the upstream
      # subdirectory layout when cargo-bazel renders Bazel Git repositories.
      annotation = Path('crate_universe/src/metadata/metadata_annotation.rs')
      text = annotation.read_text()
      marker = '        // {CARGO_HOME}/git/checkouts/name-hash/short-sha/[strip_prefix...]/Cargo.toml\n'
      replacement = marker + '\n'.join([
          '        if pkg.manifest_path.as_str().contains("/source-git-") {',
          '            let strip_prefix = match pkg.name.as_str() {',
          '                "lol_html" => None,',
          '                "lol_html_c_api" => Some("c-api"),',
          '                "ruff_python_parser" => Some("crates/ruff_python_parser"),',
          '                "ruff_source_file" => Some("crates/ruff_source_file"),',
          '                "ruff_python_ast" => Some("crates/ruff_python_ast"),',
          '                "ruff_text_size" => Some("crates/ruff_text_size"),',
          '                "ruff_python_trivia" => Some("crates/ruff_python_trivia"),',
          '                other => bail!("Unmapped vendored Git crate: {other}"),',
          '            };',
          '            return Ok(strip_prefix.map(String::from));',
          '        }',
          "",
      ]) + '\n'
      assert text.count(marker) == 1
      annotation.write_text(text.replace(marker, replacement))

      # The resolver writes this shell script into temporary directories at
      # runtime; its interpreter must remain in the installed closure.
      for filename in ['cargo_tree_rustc_wrapper.sh', 'cargo_tree_resolver.rs']:
          source = Path('crate_universe/src/metadata') / filename
          source.write_text(source.read_text().replace('#!/bin/sh', '#!${bash}/bin/bash'))
      PY
      mkdir -p "$NIX_BUILD_TOP/test-runfiles"
      ln -s "$PWD" "$NIX_BUILD_TOP/test-runfiles/rules_rust"
      export RUNFILES_DIR="$NIX_BUILD_TOP/test-runfiles"
      export REPOSITORY_NAME=rules_rust
      # The upstream test helper retains temporary directories only when
      # Bazel's TEST_TMPDIR is set; the Nix build cleans this directory too.
      export TEST_TMPDIR="$NIX_BUILD_TOP/cargo-bazel-tests"
      mkdir -p "$TEST_TMPDIR"
    '';
    postInstall = ''
      mkdir -p "$out/share/licenses/workerd-cargo-bazel"
      cp ../LICENSE.txt "$out/share/licenses/workerd-cargo-bazel/"
    '';
    meta = {
      description = "Cargo dependency generator for workerd's Bazel build";
      homepage = "https://github.com/bazelbuild/rules_rust";
      license = "Apache-2.0";
      mainProgram = "cargo-bazel";
    };
  }
