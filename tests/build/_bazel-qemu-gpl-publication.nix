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
  contracts = pkgs.lib.mapAttrs (_: item: item // {package = toString item.package;}) cases;
  closure = closureInfo {
    rootPaths = map (item: item.package) (builtins.attrValues cases);
    pname = "aos-bazel-qemu-gpl-publication-closure";
  };
in
  pkgs.runCommand "aos-bazel-qemu-gpl-publication" {
    buildDeps = [pkgs.python3 pkgs.nix pkgs.git-minimal];
  } ''
    # The database describes the actual realized inputs. Its writable state and
    # .links directory are private; no daemon or store-path payload is replaced.
    export AOS_NIX_EVAL_STORE="local?root=$TMPDIR/publication-store"
    ${pkgs.nix}/bin/nix-store --store "$AOS_NIX_EVAL_STORE" --init
    ${pkgs.nix}/bin/nix-store --store "$AOS_NIX_EVAL_STORE" --load-db < ${closure}/registration

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
            apr, "--dry-run", "publish", contract["package"], "--registry", "bazel-publication",
            "--description", "Bazel release qualification fixture",
            "--homepage", "https://example.invalid/qualification",
            "--license", "GPL-2.0-only", "--maintainer", "Publication Fixture",
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        text = result.stdout + result.stderr
        diagnostic = contract.get("diagnostic")
        if diagnostic is None:
            if result.returncode or "Dry run: nothing was written" not in text:
                raise ValueError("migrated suite failed publication validation: " + text)
        elif result.returncode == 0 or diagnostic not in text:
            raise ValueError("publication negative control did not reject " + name + ": " + text)
        if files() != before:
            raise ValueError("publication preview changed the fixture registry: " + name)
        results[name] = {"command": command, "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}

    Path(sys.argv[1], "evidence.json").write_text(json.dumps({
        "status": "PASS", "authoring_package": "${authoringPackage}", "cases": results,
        "closure": "${closure}", "registry_unchanged": True,
    }, indent=2, sort_keys=True) + "\n")
    PYTHON
  ''
