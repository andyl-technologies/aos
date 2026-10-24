##! Temporary offline Cargo feature oracles sharing only private build state.
{
  pkgs,
  pname,
  packages,
  variants,
  compileOnlyVariants ? [],
  nativeLibraries ? [],
  nativeTools ? [],
  cargoSource ? import ../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;},
  cargoSetup ? "",
}: let
  variantScript = name: flags: let
    packageFlags = pkgs.lib.escapeShellArgs (
      pkgs.lib.concatMap (package: ["-p" package]) packages ++ flags
    );
  in ''
    echo "Qualifying Cargo feature configuration: ${name}"
    mkdir -p "$out/${name}"
    cargo test --frozen --offline --manifest-path crates/Cargo.toml \
      ${packageFlags} \
      --jobs "$NIX_BUILD_CORES" --no-run --message-format=json > "$out/${name}/cargo-messages.jsonl" || {
      ${pkgs.python3}/bin/python3 - "$out/${name}/cargo-messages.jsonl" <<'PY'
    import json
    from pathlib import Path
    import sys

    for line in Path(sys.argv[1]).read_text().splitlines():
        event = json.loads(line)
        if event.get("reason") == "compiler-message" and event["message"]["level"] == "error":
            print(event["message"].get("rendered") or event["message"]["message"], file=sys.stderr)
    PY
      exit 1
    }
    ${pkgs.lib.optionalString (!(builtins.elem name compileOnlyVariants)) ''
      cargo test --frozen --offline --manifest-path crates/Cargo.toml \
        ${packageFlags} \
        --jobs "$NIX_BUILD_CORES" > "$out/${name}/cargo-tests.log" 2>&1 || {
        tail -n 100 "$out/${name}/cargo-tests.log"
        exit 1
      }
    ''}
    cp ${builtins.toFile "cargo-${name}-execution.json" (builtins.toJSON {
      mode =
        if builtins.elem name compileOnlyVariants
        then "compile-only"
        else "executed";
      inherit packages;
      cargoFlags = flags;
    })} "$out/${name}/execution.json"
    # Keep discovered binaries so parity checks can evolve independently
    # of the Cargo compilation oracle during the migration.
    ${pkgs.python3}/bin/python3 - "$out/${name}" <<'PY'
    import json
    from pathlib import Path
    import shutil
    import sys

    output = Path(sys.argv[1])
    binaries = output / "test-binaries"
    binaries.mkdir()
    messages = output / "cargo-messages.jsonl"
    events = [json.loads(line) for line in messages.read_text().splitlines()]
    for event in events:
        executable = event.get("executable")
        if event.get("reason") == "compiler-artifact" and executable:
            target = binaries / Path(executable).name
            shutil.copy2(executable, target)
            event["executable"] = str(target)
    messages.write_text("".join(json.dumps(event) + "\n" for event in events))
    PY
  '';
in
  assert variants != {};
  assert builtins.all (name: builtins.match "[a-z][a-z0-9_-]*" name != null) (builtins.attrNames variants);
  assert builtins.all (name: builtins.hasAttr name variants) compileOnlyVariants;
    pkgs.mkDerivation {
      inherit pname;
      version = "1";
      src = cargoSource;
      buildDeps = [pkgs.rust pkgs.python3 pkgs.sed] ++ nativeTools;
      runtimeDeps = nativeLibraries;
      sharedBuildCache = false;
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "compare";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
            export CARGO_HOME="$TMPDIR/cargo" CARGO_TARGET_DIR="$TMPDIR/target"
            mkdir -p "$CARGO_HOME" .cargo "$out"
            sed 's|@vendor@|${pkgs.aos.passthru.cargoDeps}|g' \
              ${pkgs.aos.passthru.cargoDeps}/.cargo/config.toml > .cargo/config.toml
            ${cargoSetup}
            # Cargo invalidates feature-sensitive units between configurations.
            # Retained messages still describe every unit, including fresh ones.
            # This state never leaves the private derivation build directory.
            ${pkgs.lib.concatStringsSep "\n" (pkgs.lib.mapAttrsToList variantScript variants)}
            cp ${builtins.toFile "cargo-feature-variants.json" (builtins.toJSON variants)} "$out/variants.json"
          '';
        }
      ];
    }
