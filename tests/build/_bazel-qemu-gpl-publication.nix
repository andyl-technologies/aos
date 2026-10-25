##! Exercises registry publication policy against the realized migrated suite.
{
  pkgs,
  suite,
  installed,
  authoringPackage ? (import ./_bazel-aos-cli-production.nix {inherit pkgs;}).installed,
}: let
  closureInfo = pkgs.lib.build.closureInfo {inherit pkgs;};
  wrapper = pkgs.runCommand "aos-bazel-plugin-unmarked-wrapper" {} ''
    mkdir -p "$out"
    ln -s ${installed.plugin} "$out/plugin"
  '';
  wrongSource = pkgs.runCommand "aos-bazel-wrong-corresponding-source" {} ''
    mkdir -p "$out/nix-support"
    printf 'qemu_build_id=wrong-identity\n' > "$out/nix-support/qemu-crucible-source-build-info"
  '';
  wrongAggregate = pkgs.runCommand "aos-bazel-wrong-source-aggregate" {} ''
    mkdir -p "$out/nix-support"
    cat > "$out/nix-support/aos-release-policy" <<'POLICY'
    policy_version=1
    artifact_role=aggregate-release-root
    standalone_release=true
    pair_count=1
    pair_1_component_path=${pkgs.qemu-crucible}
    pair_1_corresponding_source_path=${wrongSource}
    pair_1_identity=${pkgs.qemu-crucible.passthru.qemuBuildIdentity}
    POLICY
  '';
  cases = {
    suite = {package = suite;};
    suite-json = {
      package = suite;
      json = true;
    };
    suite-with-manual-metadata = {
      package = suite;
      arguments = ["--description" "Publication fixture override"];
      diagnostic = "manual metadata flags are valid only with --sysroot";
    };
    suite-with-restricted-named-output = {
      package = suite;
      evaluator = toString (evaluatorFor (inventoryFor (suite
        // {
          outputs = ["out" "restricted"];
          restricted = wrapper;
        })));
      diagnostic = "has no aggregate release policy";
    };
    raw-qemu = {
      package = pkgs.qemu-crucible;
      diagnostic = "is not an aggregate release root";
    };
    raw-plugin = {
      package = installed.plugin;
      diagnostic = "has no aggregate release policy";
    };
    unmarked-wrapper = {
      package = wrapper;
      diagnostic = "has no aggregate release policy";
    };
    wrong-source = {
      package = wrongAggregate;
      diagnostic = "does not match restricted component identity";
    };
  };
  inventoryFor = package:
    pkgs.writeTextFile {
      name = "aos-bazel-suite-publication-inventory.json";
      text = builtins.toJSON (pkgs.platformSupport.releaseDerivations {
        system = suite.system;
        packages = pkgs // {crucible = package;};
        names = ["crucible"];
      });
    };
  publicationInventory = inventoryFor suite;
  # Freeze the actual evaluated metadata without making the CLI evaluate the
  # whole repository again inside its isolated Nix store.
  evaluatorFor = inventory:
    pkgs.writeTextFile {
      name = "aos-bazel-suite-publication-evaluator";
      destination = "/default.nix";
      text = ''
        {crossSystem ? null, releasePlatforms ? []}: {
          releasePackageDerivations = builtins.fromJSON (builtins.readFile ${inventory});
        }
      '';
    };
  evaluator = evaluatorFor publicationInventory;
  contracts = pkgs.lib.mapAttrs (_: item: item // {package = toString item.package;}) cases;
  closure = closureInfo {
    rootPaths = pkgs.lib.unique (
      map (item: toString item.package) (builtins.attrValues cases)
      ++ [suite.drvPath (toString evaluator)]
      ++ map (item: toString (item.evaluator or evaluator)) (builtins.attrValues cases)
    );
    pname = "aos-bazel-qemu-gpl-publication-closure";
  };
in
  pkgs.runCommand "aos-bazel-qemu-gpl-publication" {
    buildDeps = [pkgs.python3 pkgs.nix pkgs.git-minimal pkgs.coreutils];
  } ''
    # Populate a genuine private local-root store. The CLI deliberately rejects
    # custom state/physical-store URIs; preserve that isolation policy and copy
    # real payloads as well as Nix's actual hashes and reference graph.
    export AOS_NIX_EVAL_STORE="local?root=$TMPDIR/publication-store"
    # The general evaluator uses Nix's standard environment. Its legacy CLI
    # also initializes profile directories before opening the selected store.
    export NIX_REMOTE="$AOS_NIX_EVAL_STORE"
    export NIX_STATE_DIR="$TMPDIR/publication-store/nix/var/nix"
    export AOS_ROOT=${evaluator}
    ${pkgs.nix}/bin/nix-store --store "$AOS_NIX_EVAL_STORE" --init
    ${pkgs.python3}/bin/python3 - ${closure}/store-paths "$TMPDIR/publication-store/nix/store" <<'PYTHON'
    from pathlib import Path
    import subprocess
    import sys

    paths = Path(sys.argv[1]).read_text().splitlines()
    for offset in range(0, len(paths), 64):
        subprocess.run([
            "${pkgs.coreutils}/bin/cp", "-a", "--reflink=auto", "--",
            *paths[offset:offset + 64], sys.argv[2],
        ], check=True)
    PYTHON
    ${pkgs.nix}/bin/nix-store --store "$AOS_NIX_EVAL_STORE" --load-db < ${closure}/registration
    ${pkgs.nix}/bin/nix-store --store "$AOS_NIX_EVAL_STORE" --verify-path \
      ${pkgs.lib.escapeShellArgs (pkgs.lib.unique (map (item: toString item.package) (builtins.attrValues cases)))}

    export XDG_CONFIG_HOME="$TMPDIR/config" XDG_DATA_HOME="$TMPDIR/data"
    export XDG_CACHE_HOME="$TMPDIR/cache"
    export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
    export GIT_AUTHOR_NAME='Publication Fixture' GIT_COMMITTER_NAME='Publication Fixture'
    export GIT_AUTHOR_EMAIL='publication@example.invalid' GIT_COMMITTER_EMAIL='publication@example.invalid'
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
    import json
    import os
    from pathlib import Path
    import subprocess
    import sys

    apr = "${authoringPackage}/bin/apr"
    contracts = json.loads(${builtins.toJSON (builtins.toJSON contracts)})
    subprocess.run([apr, "create", "bazel-publication"], check=True, capture_output=True, text=True)
    registry = Path(os.environ["XDG_DATA_HOME"]) / "apm/registries/bazel-publication"

    def files():
        return {str(p.relative_to(registry)): p.read_bytes() for p in registry.rglob("*") if p.is_file()}

    before = files()
    results = {}
    for name, contract in sorted(contracts.items()):
        command = [
            apr,
        ] + (["--json"] if contract.get("json") else []) + [
            "--dry-run", "publish", contract["package"], "--registry", "bazel-publication",
        ] + contract.get("arguments", [])
        environment = dict(os.environ, AOS_ROOT=contract.get("evaluator", os.environ["AOS_ROOT"]))
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, env=environment)
        text = result.stdout + result.stderr
        diagnostic = contract.get("diagnostic")
        if diagnostic is None:
            if result.returncode:
                raise ValueError("migrated suite failed publication validation: " + text)
            if contract.get("json"):
                preview = json.loads(result.stdout)
                if (preview.get("dry_run") is not True or preview.get("committed") is not False
                        or preview.get("authority") != "evaluated-derivation-inventory"
                        or [package["name"] for package in preview["packages"]] != ["crucible"]):
                    raise ValueError("publication preview did not retain the evaluated group: " + text)
            elif "Dry run: nothing was written" not in text:
                raise ValueError("publication preview omitted its result: " + text)
        elif result.returncode == 0 or diagnostic not in text:
            raise ValueError("publication negative control did not reject " + name + ": " + text)
        if files() != before:
            raise ValueError("publication preview changed the fixture registry: " + name)
        results[name] = {"command": command, "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}

    Path(sys.argv[1], "evidence.json").write_text(json.dumps({
        "status": "PASS", "authoring_package": "${authoringPackage}", "cases": results,
        "closure": "${closure}", "registry_unchanged": True,
        "private_store_payloads_copied": True, "selected_root_nar_hashes_verified": True,
        "evaluated_publication_inventory": json.loads(Path("${publicationInventory}").read_text()),
    }, indent=2, sort_keys=True) + "\n")
    PYTHON
  ''
