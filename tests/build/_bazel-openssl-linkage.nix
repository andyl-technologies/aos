##! Reproduces pkg-config's presence-based static switch with the actual crate.
{pkgs}: let
  source = pkgs.aosBazelRustRepositories.native-bindings."aos_native_bindings_crates__pkg-config-0.3.33";
  native = pkgs.aosBazelNativeFoundationLibraries;
  root = ../../third_party/rust;
  profiles =
    builtins.filter
    (name: builtins.pathExists (root + "/${name}/sources.json"))
    (builtins.attrNames (builtins.readDir root));
  policies = builtins.listToAttrs (map (name: let
      manifest = builtins.fromJSON (builtins.readFile (root + "/${name}/sources.json"));
    in {
      inherit name;
      value = manifest.specifications.annotations."openssl-sys *".build_script_env or null;
    })
    profiles);
in {
  all = pkgs.runCommand "aos-bazel-shared-openssl-linkage" {buildDeps = [pkgs.rust pkgs.python3];} ''
    mkdir -p "$out"
    cat > policies.json <<'JSON'
    ${builtins.toJSON policies}
    JSON
    cat > probe.rs <<'RUST'
    fn main() -> Result<(), Box<dyn std::error::Error>> {
        pkg_config::Config::new().print_system_libs(false).probe("openssl")?;
        Ok(())
    }
    RUST
    ${pkgs.rust}/bin/rustc --edition=2018 --crate-name pkg_config --crate-type rlib \
      ${source}/src/lib.rs -o libpkg_config.rlib
    ${pkgs.rust}/bin/rustc --edition=2021 --extern pkg_config=libpkg_config.rlib \
      probe.rs -o probe
    PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
    import json
    import os
    from pathlib import Path
    import subprocess
    import sys

    policies = json.loads(Path("policies.json").read_text())
    selected = {name: env for name, env in policies.items() if env is not None}
    if not policies or not selected:
        raise ValueError("missing dependency profile linkage policies")
    for name, policy in selected.items():
        if "OPENSSL_STATIC" in policy or policy.get("OPENSSL_DYNAMIC") != "1":
            raise ValueError("profile does not request shared OpenSSL: " + name)

    environment = {
        "PATH": os.environ["PATH"], "HOME": os.environ["TMPDIR"],
        "HOST": "${pkgs.stdenv.hostPlatform.config}", "TARGET": "${pkgs.stdenv.hostPlatform.config}",
        "PKG_CONFIG": "${native}/openssl/pkg-config", "PKG_CONFIG_ALLOW_CROSS": "1",
    }
    profiles = {"historical-zero": {"OPENSSL_STATIC": "0"}, "shared": {"OPENSSL_DYNAMIC": "1"}}
    results = {}
    for name, policy in profiles.items():
        result = subprocess.run(["./probe"], env={**environment, **policy}, capture_output=True, text=True, check=True)
        flags = [line.removeprefix("cargo:rustc-link-lib=") for line in result.stdout.splitlines()
                 if line.startswith("cargo:rustc-link-lib=")]
        required = {"static=ssl", "static=crypto"} if name == "historical-zero" else {"ssl", "crypto"}
        if not required.issubset(flags):
            raise ValueError("pkg-config did not reproduce expected linkage: " + name)
        if name == "shared" and any(flag.startswith("static=") for flag in flags):
            raise ValueError("shared OpenSSL probe imports an archive")
        results[name] = {"policy": policy, "link_libraries": flags, "stdout": result.stdout, "stderr": result.stderr}

    report = {"schema_version": 1, "dependency_profiles": len(policies), "shared_profiles": sorted(selected),
              "pkg_config_source": "${source}", "native_libraries": "${native}", "probes": results}
    (Path(sys.argv[1]) / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    PYTHON
    printf 'PASS\n' > "$out/result"
  '';
}
