##! Deterministic device models and their protocol dependencies qualify together.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/device-inventory.json,
}: let
  family = import ./_bazel-rust-family.nix {
    inherit pkgs sourceInventory;
    pname = "aos-bazel-device";
    dependencyProfile = "device";
    packages = {
      crucible-determinism = "crates/crucible/crucible-determinism";
      crucible-device = "crates/crucible/crucible-device";
      crucible-qemu-protocol = "crates/crucible/crucible-qemu-protocol";
      crucible-qemu-shmem = "crates/crucible/crucible-qemu-shmem";
    };
    extraSourceDirectories = ["docs/rfcs/0020-crucible-campaigns"];
  };
  license-policy = pkgs.runCommand "aos-bazel-ciborium-license-policy" {buildDeps = [pkgs.python3];} ''
    mkdir workspace
    cp -a ${family.workspace.source}/. workspace/
    chmod -R u+w workspace
    cp ${family.workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
    mkdir -p workspace/license-probe "$out"
    cat > workspace/license-probe/BUILD.bazel <<'BUILD'
    load("//tools/bazel/rules:license.bzl", "aos_license_check")
    [aos_license_check(
        name = domain,
        roots = ["//third_party/rust:core_ciborium"],
        license_domain = domain,
    ) for domain in ["apache-host", "permissive-protocol", "gpl-qemu"]]
    BUILD
    for domain in apache-host permissive-protocol gpl-qemu; do
      status=0
      ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
        --config ${family.workspace.configuration} --workspace "$PWD/workspace" \
        --output-base "$TMPDIR/$domain/bazel" --nix-sandbox --batch \
        -- build "//license-probe:$domain" --nobuild > "$out/$domain.log" 2>&1 || status=$?
      if [ "$domain" = apache-host ]; then
        test "$status" -eq 0
      else
        test "$status" -ne 0
        grep -F 'cannot link apache-host' "$out/$domain.log"
      fi
    done
    ${pkgs.python3}/bin/python3 - ${family.workspace.configuration} "$TMPDIR/core-profile.json" <<'PYTHON'
    import json
    from pathlib import Path
    import sys

    configuration = json.loads(Path(sys.argv[1]).read_text())
    configuration["dependency_profile"] = "core"
    Path(sys.argv[2]).write_text(json.dumps(configuration))
    PYTHON
    if ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
      --config "$TMPDIR/core-profile.json" --workspace "$PWD/workspace" \
      --output-base "$TMPDIR/wrong-profile/bazel" --nix-sandbox --batch \
      -- build //crates/crucible/crucible-device:license_closure --nobuild \
      > "$out/wrong-profile.log" 2>&1; then
      echo 'device dependencies accepted the core feature profile' >&2
      exit 1
    fi
    grep -F 'this dependency requires --//tools/bazel/rules:dependency_profile=device' "$out/wrong-profile.log"
    printf 'PASS\n' > "$out/result"
  '';
in
  family
  // {
    inherit license-policy;
    all = pkgs.runCommand "aos-bazel-device-qualified-checks" {buildDeps = [family.all family.editor-parity license-policy];} ''
      mkdir -p "$out"
      cp -r ${family.all}/evidence "$out/evidence"
      cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
      cp -r ${license-policy} "$out/license-policy"
      cp -r ${family.editor} "$out/editor"
      cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
    '';
  }
