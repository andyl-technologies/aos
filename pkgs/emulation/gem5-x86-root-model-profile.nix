##! Source-owned x86 root constructor gated by its separate process-image witness
{
  mkDerivation,
  gem5-x86-linux-model-assets,
  gem5-shared-controller-x86-root-check,
  gem5-process-custody,
  dmtcp,
  python3,
}: let
  assets = gem5-x86-linux-model-assets;
  proof = gem5-shared-controller-x86-root-check;
  specification = builtins.toJSON {
    assets_manifest = "${assets}/share/crucible/gem5/x86-linux-assets.json";
    assets_verifier = "${assets.source}/x86-linux-bundle.py";
    qualification_inputs = {
      source_manifest = "${proof}/share/gem5/x86-root-proof-source/qualification-sources.json";
      temporary_root_check = "${proof}/share/gem5/x86-root-proof-source/native-controller-temporary-root-check.py";
    };
    selected = {
      image_guard = "${gem5-process-custody}/lib/libcrucible-resource-custody.so";
      dmtcp_launch = "${dmtcp}/bin/dmtcp_launch";
      dmtcp_restart = "${dmtcp}/bin/dmtcp_restart";
      mtcp_restart = "${dmtcp}/bin/mtcp_restart";
      python = "${python3}/bin/python3.14";
      mechanism_evidence = "${proof}/share/checks/x86-root-shared-controller.json";
      witness = "${proof}/share/gem5/x86-root-proof-source/native-controller-x86-root-check.py";
      image_witness = "${proof}/share/gem5/x86-root-proof-source/native-controller-image-check.py";
      proof_recipe = "${proof}/share/gem5/x86-root-proof-source/recipe.nix";
    };
  };
in
  mkDerivation {
    pname = "gem5-x86-root-model-profile";
    version = "1";
    platformSupport = {
      build = [{abi = ["gnu"]; cpu = ["x86_64"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    outputs = ["out" "source"];
    buildDeps = [python3];
    runtimeDeps = [assets assets.source proof gem5-process-custody dmtcp python3];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/crucible/gem5" "$source"
          cp ${./_gem5/native-controller-x86-root.py} "$source/native-controller-x86-root.py"
          cp ${./_gem5/native-controller-x86-root-model.py} "$source/native-controller-x86-root-model.py"
          cp ${./_gem5/native-controller-x86-root-model-check.py} "$source/native-controller-x86-root-model-check.py"
          cp ${./_gem5/x86-root-process-image-audit.py} "$source/x86-root-process-image-audit.py"
          cp ${./_gem5/process-image-audit-core.py} "$source/process-image-audit-core.py"
          cp ${./_gem5/x86-root-model-profile.py} "$source/x86-root-model-profile.py"
          cp ${./gem5-x86-root-model-profile.nix} "$source/recipe.nix"
          cp ${../../LICENSES/MIT.txt} "$source/LICENSE"
          chmod 444 "$source/"*
          cat > selection.json <<'EOF'
          ${specification}
          EOF
          ${python3}/bin/python3 -I -B - "$source" <<'PY'
          import json, pathlib, sys
          root = pathlib.Path(sys.argv[1])
          selection = json.loads(pathlib.Path("selection.json").read_text())
          original = json.loads(pathlib.Path(selection["assets_manifest"]).read_text())
          roles = {role: original["artifacts"][prior]["path"] for role, prior in {
              "native_executable": "native_executable", "controller": "controller",
              "board_model": "model", "publication_model": "publication_model",
              "asset_checker": "asset_checker", "loader": "loader", "kernel": "kernel",
              "initramfs": "initramfs", "native_source_manifest": "native_source_manifest",
          }.items()}
          roles.update(selection["selected"])
          roles.update({
              "entrypoint": str(root / "native-controller-x86-root.py"),
              "model": str(root / "native-controller-x86-root-model.py"),
              "auditor": str(root / "x86-root-process-image-audit.py"),
              "auditor_core": str(root / "process-image-audit-core.py"),
              "assets_manifest": selection["assets_manifest"],
              "assets_verifier": selection["assets_verifier"],
              "profile_writer": str(root / "x86-root-model-profile.py"),
              "profile_recipe": str(root / "recipe.nix"),
              "root_model_check": str(root / "native-controller-x86-root-model-check.py"),
          })
          pathlib.Path("profile-inputs.json").write_text(json.dumps({
              "artifacts": roles, "qualification_inputs": selection["qualification_inputs"],
          }))
          PY
          ${python3}/bin/python3 -I -B "$source/x86-root-model-profile.py" \
            profile-inputs.json "$out/share/crucible/gem5/x86-root-model-profile.json"
        '';
      }
    ];
    meta = {
      description = "Binds the actual fixed Linux assets, source-owned parent-zero x86 constructor and current process auditor without granting device, timing, readiness or restoration qualification";
      license = "MIT";
    };
  }
