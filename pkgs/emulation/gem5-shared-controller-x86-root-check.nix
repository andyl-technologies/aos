##! Actual fixed x86 Linux root source-gone twin process-image mechanism
{
  mkDerivation,
  gem5-x86-linux-model-assets,
  dmtcp,
  gem5-process-custody,
  python3,
  coreutils,
  abseil-cpp,
}: let
  assets = gem5-x86-linux-model-assets;
  helperSources = {
    "native-controller-x86-root.py" = ./_gem5/native-controller-x86-root.py;
    "native-controller-x86-root-model.py" = ./_gem5/native-controller-x86-root-model.py;
    "native-controller-x86-root-model-check.py" = ./_gem5/native-controller-x86-root-model-check.py;
    "native-controller-x86-root-check.py" = ./_gem5/native-controller-x86-root-check.py;
    "native-controller-image-check.py" = ./_gem5/native-controller-x86-root-image-check.py;
    "process-image-audit-core.py" = ./_gem5/process-image-audit-core.py;
    "x86-root-process-image-audit.py" = ./_gem5/x86-root-process-image-audit.py;
  };
  helperCopies = builtins.concatStringsSep "\n" (map
    (name: "cp ${helperSources.${name}} helper-source/${name}")
    (builtins.attrNames helperSources));
in
  mkDerivation {
    pname = "gem5-shared-controller-x86-root-check";
    version = "1";
    platformSupport = {
      build = [{abi = ["gnu"]; cpu = ["x86_64"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    buildDeps = [python3 coreutils];
    runtimeDeps = [assets assets.source dmtcp gem5-process-custody abseil-cpp];
    phases = [
      {
        name = "configure";
        script = ''
          mkdir helper-source
          ${helperCopies}
          # This executed check is source provenance, not a native runtime helper.
          cp ${./_gem5/native-controller-temporary-root-check.py} helper-source/native-controller-temporary-root-check.py
          ${python3}/bin/python3 -I -B - "${assets}/share/crucible/gem5/x86-linux-assets.json" <<'PY'
          import json, pathlib, shutil, sys
          document = json.loads(pathlib.Path(sys.argv[1]).read_text())
          for role, name in {
              "controller": "native-controller.py", "model": "native-controller-x86-model.py",
              "publication_model": "native-controller-models.py", "asset_checker": "native-model-assets.py",
              "loader": "x86-linux-loader.py",
          }.items():
              shutil.copyfile(document["artifacts"][role]["path"], pathlib.Path("helper-source") / name)
          pathlib.Path("selected.json").write_text(json.dumps(document))
          PY
        '';
      }
      {
        name = "check";
        script = ''
          export PYTHONDONTWRITEBYTECODE=1
          ${python3}/bin/python3 -I -B helper-source/native-controller-temporary-root-check.py
          ${python3}/bin/python3 -I -B - helper-source <<'PY'
          import hashlib, json, pathlib, sys
          root = pathlib.Path(sys.argv[1])
          check = "native-controller-temporary-root-check.py"
          record = {
              "schema": "crucible.gem5.root-qualification-sources.v1",
              "controller_sha256": hashlib.sha256((root / "native-controller.py").read_bytes()).hexdigest(),
              "checks": {check: hashlib.sha256((root / check).read_bytes()).hexdigest()},
          }
          pathlib.Path("qualification-sources.json").write_text(json.dumps(record, sort_keys=True) + "\n")
          PY
          # The witness hashes every Python file in its runtime source directory.
          # Keep the separately bound build check out of that closed inventory.
          mkdir qualification-source
          mv helper-source/native-controller-temporary-root-check.py qualification-source/
          ${python3}/bin/python3 -B helper-source/native-controller-x86-root-model-check.py
          export LD_LIBRARY_PATH="${abseil-cpp}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          ${python3}/bin/python3 -I -B - <<'PY'
          import json, pathlib
          document = json.loads(pathlib.Path("selected.json").read_text())
          values = [document["artifacts"][role]["path"] for role in ("native_executable", "kernel", "initramfs")]
          values.append(document["configuration"]["root"])
          pathlib.Path("selected-paths").write_text("\n".join(values) + "\n")
          PY
          { IFS= read -r native; IFS= read -r kernel; IFS= read -r initramfs; IFS= read -r configs; } < selected-paths
          witness_root="$(mktemp -d /tmp/gem5-x86-root.XXXXXXXX)"
          ${coreutils}/bin/timeout 600 ${python3}/bin/python3 -B \
            helper-source/native-controller-x86-root-check.py \
            "$native" "$PWD/helper-source" "$witness_root/native" "$configs" \
            "$kernel" "$initramfs" ${dmtcp} \
            ${gem5-process-custody}/lib/libcrucible-resource-custody.so > native-check.log
          cp "$witness_root/native/result.json" result.json
          rm -rf "$witness_root"
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/checks" "$out/share/gem5/x86-root-proof-source"
          cp result.json "$out/share/checks/x86-root-shared-controller.json"
          cp helper-source/*.py "$out/share/gem5/x86-root-proof-source/"
          cp qualification-source/native-controller-temporary-root-check.py "$out/share/gem5/x86-root-proof-source/"
          cp qualification-sources.json "$out/share/gem5/x86-root-proof-source/qualification-sources.json"
          cp ${./gem5-shared-controller-x86-root-check.nix} "$out/share/gem5/x86-root-proof-source/recipe.nix"
          cp ${../../LICENSES/MIT.txt} "$out/share/gem5/x86-root-proof-source/LICENSE"
        '';
      }
    ];
    meta = {
      description = "Audits actual fixed x86 Linux root capture, source namespace deletion and two current fresh recaptures without common-node, full device or timing qualification";
      license = "MIT";
    };
  }
