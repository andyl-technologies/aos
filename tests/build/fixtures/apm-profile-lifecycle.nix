##! Real immutable packages and native envelopes for profile lifecycle tests.
{
  pkgs,
  cache ? false,
}: let
  lib = pkgs.lib;
  package = name: version: dependencies:
    pkgs.mkDerivation {
      pname = name;
      inherit version;
      src = null;
      runtimeDeps = dependencies;
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin"
            cat > "$out/bin/${name}" <<'COMMAND'
            #!${pkgs.bash}/bin/bash
            ${lib.concatMapStringsSep "\n" (dependency:
              if name == "fixture-tool"
              then "${dependency}/bin/fixture-helper"
              else ": ${dependency}")
            dependencies}
            ${lib.optionalString (name == "fixture-helper") ''
              test -s "''${0%/*}/../share/fixture-helper/payload.bin" || exit 66
            ''}
            printf '%s\n' '${name} ${version}'
            COMMAND
            chmod +x "$out/bin/${name}"
            ${lib.optionalString (name == "fixture-helper") ''
              mkdir -p "$out/share/fixture-helper"
              # A real payload keeps cache compression and transfer meaningful.
              head -c 1048576 /dev/zero > "$out/share/fixture-helper/payload.bin"
            ''}
          '';
        }
      ];
    };
  helper = package "beta-helper" "1.0.0" [];
  cacheHelperV1 = package "fixture-helper" "1.0.0" [];
  cacheHelperV2 = package "fixture-helper" "2.0.0" [];
  packages =
    if cache
    then {
      tool_v1 = package "fixture-tool" "1.0.0" [cacheHelperV1];
      tool_v2 = package "fixture-tool" "2.0.0" [cacheHelperV2];
      helper_v1 = cacheHelperV1;
      helper_v2 = cacheHelperV2;
    }
    else {
      alpha_v1 = package "alpha" "1.0.0" [];
      alpha_v2 = package "alpha" "2.0.0" [];
      beta = package "beta" "1.0.0" [helper];
      beta_without_helper = package "beta" "1.0.0" [];
      beta_helper = helper;
    };
  roots = builtins.attrValues packages ++ map (package: package.deploymentArtifact) (builtins.attrValues packages) ++ [lib.packageModuleLibrary];
  inventory = (lib.build.closureInfo {inherit pkgs lib;}) {rootPaths = roots;};
  coordinates =
    builtins.mapAttrs (_: package: {
      name = package.pname;
      inherit (package) version;
      store_path = toString package;
      envelope = toString package.deploymentArtifact;
    })
    packages;
in
  pkgs.mkDerivation {
    pname =
      if cache
      then "apr-native-cache-fixtures"
      else "apm-profile-lifecycle-fixtures";
    version = "1";
    src = null;
    buildDeps = [pkgs.python3 inventory];
    outputChecks.out = {};
    exportReferencesGraph.fixtures = roots;
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp ${inventory}/registration "$out/registration"
          ${pkgs.python3}/bin/python3 - "$NIX_ATTRS_JSON_FILE" "$out" <<'PYTHON'
          import hashlib
          import json
          from pathlib import Path
          import sys

          graph = json.loads(Path(sys.argv[1]).read_text())["fixtures"]
          entries = {entry["path"]: entry for entry in graph}
          packages = json.loads(${builtins.toJSON (builtins.toJSON coordinates)})
          for package in packages.values():
              entry = entries[package["store_path"]]
              envelope = entries[package["envelope"]]
              document = Path(package["envelope"], "deployment.json").read_bytes()
              package["version_requirement"] = json.loads(document).get("versionRequirement")
              package["hash"] = Path(package["store_path"]).name.split("-", 1)[0]
              package["nar_hash"] = entry["narHash"]
              package["nar_size"] = entry["narSize"]
              package["references"] = sorted(Path(path).name.split("-", 1)[0] for path in entry["references"])
              package["deployment"] = {
                  "store_path": envelope["path"], "nar_hash": envelope["narHash"],
                  "nar_size": envelope["narSize"],
                  "references": sorted(Path(path).name.split("-", 1)[0] for path in envelope["references"]),
                  "document_sha256": "sha256:" + hashlib.sha256(document).hexdigest(),
                  "document_size": len(document),
              }
          output = Path(sys.argv[2])
          (output / "fixtures.json").write_text(json.dumps({
              "schema_version": 1, "packages": packages, "store_graph": graph,
              "platform": "${pkgs.stdenv.hostPlatform.system}",
              "module_library": "${lib.packageModuleLibrary}",
          }, indent=2, sort_keys=True) + "\n")
          PYTHON
        '';
      }
    ];
  }
