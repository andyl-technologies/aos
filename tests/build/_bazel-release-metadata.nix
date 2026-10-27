##! Regenerates and verifies Bazel-owned Crucible release package identities.
{pkgs}: let
  catalog = import ./_bazel-source-catalog.nix {inherit pkgs;};
  lib = pkgs.lib;
  root = ../..;
  metadataFile = ../../tools/bazel/metadata/crucible-release-packages.json;
  metadata = builtins.fromJSON (builtins.readFile metadataFile);
  readPackages = file:
    import ../../pkgs/tools/crucible/_release-packages.nix {
      inherit lib;
      metadataFile = file;
    };
  changed = name: value:
    pkgs.writeTextFile {
      name = "release-metadata-${name}.json";
      text = builtins.toJSON value;
    };
  rejects = file: !(builtins.tryEval (builtins.deepSeq (readPackages file) true)).success;
  first = builtins.head (builtins.attrNames metadata.packages);
  firstBuild = "${metadata.packages.${first}.directory}/BUILD.bazel";
  badHash = changed "stale-build" (metadata
    // {
      declaration_sha256 = metadata.declaration_sha256 // {"${firstBuild}" = builtins.concatStringsSep "" (builtins.genList (_: "0") 64);};
    });
  missingIdentity = changed "missing-identity" (metadata // {packages = builtins.removeAttrs metadata.packages [first];});
  missingDeclaration = changed "missing-declaration" (metadata // {declaration_sha256 = builtins.removeAttrs metadata.declaration_sha256 [firstBuild];});
  invalidDirectory = changed "invalid-directory" (metadata
    // {
      packages = metadata.packages // {"${first}" = metadata.packages.${first} // {directory = "crates/../outside";};};
    });
  unsupportedSchema = changed "unsupported-schema" (metadata // {schema_version = 2;});
  filesWithoutCargo =
    builtins.attrNames metadata.declaration_sha256
    ++ [
      "tools/bazel/metadata/crucible-release-packages.json"
      "pkgs/tools/crucible/_release-packages.nix"
      "pkgs/tools/crucible/_release-manifest.nix"
      "pkgs/tools/crucible/_control-protocol-version.nix"
      "crates/crucible/crucible-qemu-shmem/src/lib.rs"
      "crates/crucible/crucible-qemu-protocol/src/doorbell_abi.rs"
      "crates/crucible/crucible-qemu-protocol/src/control_protocol_version.in"
      "crates/crucible/crucible-control-api/src/rpc_abi.rs"
    ];
  withoutCargo = builtins.path {
    path = root;
    name = "crucible-release-metadata-without-cargo";
    filter = path: _: let
      relative = lib.removePrefix "${toString root}/" (toString path);
    in
      toString path == toString root || builtins.any (file: relative == file || lib.hasPrefix "${relative}/" file) filesWithoutCargo;
  };
  manifestArgs = {
    inherit lib;
    qemuPackage = pkgs.qemu-crucible;
    version = "0.1.0";
    src = "/nix/store/00000000000000000000000000000000-release-metadata-parity-source";
    cargoDepsHash = "metadata-parity-fixed-hash";
  };
  originalManifest = import ../../pkgs/tools/crucible/_release-manifest.nix manifestArgs;
  independentManifest = import (withoutCargo + "/pkgs/tools/crucible/_release-manifest.nix") manifestArgs;
  releaseSource = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  filteredManifest = import (releaseSource + "/pkgs/tools/crucible/_release-manifest.nix") manifestArgs;
  evaluation = assert rejects badHash;
  assert rejects missingIdentity;
  assert rejects missingDeclaration;
  assert rejects invalidDirectory;
  assert rejects unsupportedSchema;
  assert independentManifest == originalManifest;
  assert filteredManifest == originalManifest;
    pkgs.writeTextFile {
      name = "crucible-release-metadata-evaluation.json";
      text = builtins.toJSON {
        status = "PASS";
        packages = readPackages metadataFile;
        rejected_mutations = ["stale-build" "missing-identity" "missing-declaration" "invalid-directory" "unsupported-schema"];
        cargo_free_source = toString withoutCargo;
        release_manifest_identical_without_cargo = true;
        release_manifest_identical_in_filtered_source = true;
      };
    };
  selection = pkgs.writeTextFile {
    name = "crucible-release-package-selection.json";
    text = builtins.toJSON (import ../../pkgs/tools/crucible/_packages.nix);
  };
in rec {
  generated = pkgs.runCommand "aos-bazel-crucible-release-metadata" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 ${../../tools/bazel/metadata/export_release_packages.py} \
      --root ${catalog.workspace.source} \
      --catalog ${catalog.crates}/share/aos/source-catalog.json \
      --selection ${selection} --output "$out/crucible-release-packages.json"
  '';
  all = pkgs.runCommand "aos-bazel-crucible-release-metadata-check" {buildDeps = [pkgs.python3];} ''
    ${pkgs.python3}/bin/python3 - \
      ${generated}/crucible-release-packages.json \
      ${../../tools/bazel/metadata/crucible-release-packages.json} <<'PY'
    import json
    from pathlib import Path
    import sys

    if json.loads(Path(sys.argv[1]).read_text()) != json.loads(Path(sys.argv[2]).read_text()):
        raise ValueError("checked Crucible release metadata differs from Bazel declarations")
    PY
    mkdir -p "$out"
    cp ${generated}/crucible-release-packages.json "$out/"
    cp ${evaluation} "$out/evaluation.json"
    printf 'PASS\n' > "$out/result"
  '';
}
