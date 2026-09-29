{
  pkgs,
  lib,
}: let
  registry = builtins.fromJSON (builtins.readFile ./gate_registry.json);
  gateNames = map (row: row.name) registry;
  checkNames = builtins.toFile "terrane-check-names.json" (builtins.toJSON gateNames);

  # Registration is distinct from conformance: a deferred gate is a failing
  # derivation, so requesting it cannot report an unimplemented MUST green.
  pendingGate = row:
    pkgs.mkDerivation {
      pname = "terrane-gate-${row.name}-pending";
      version = "0";
      src = null;
      phases = [
        {
          name = "pending";
          script = ''
            printf '%s\n' ${lib.escapeShellArg "gate:${row.name}: pending implementation (${row.requirements})"} >&2
            exit 1
          '';
        }
      ];
    };

  sourceGate = name: script:
    pkgs.mkDerivation {
      pname = "terrane-gate-${name}";
      version = "0.1.0";
      src = pkgs.terrane.src;
      buildDeps = [pkgs.rust pkgs.rust.dev pkgs.python3];
      phases = [
        {
          name = "check";
          script = ''
            set -eu
            cp -r "$src" source
            chmod -R u+w source
            cd source
            export CARGO_HOME="$TMPDIR/cargo-home"
            export CARGO_TARGET_DIR="$TMPDIR/cargo-target"
            mkdir -p "$CARGO_HOME" crates/.cargo "$out"
            sed 's|@vendor@|${pkgs.terrane.cargoDeps}|g' \
              ${pkgs.terrane.cargoDeps}/.cargo/config.toml > crates/.cargo/config.toml
            ${script}
          '';
        }
      ];
    };

  structureGate = name:
    sourceGate name ''
      cd crates
      cargo metadata --no-deps --offline --locked --format-version 1 > "$TMPDIR/metadata.json"
      cd ..
      python3 tests/terrane/check_structure.py ${name} "$PWD" "$TMPDIR/metadata.json" \
        > "$out/result"
    '';

  implementedGates = {
    crate-graph = structureGate "crate-graph";
    unsafe-audit = structureGate "unsafe-audit";
    core-no-std = sourceGate "core-no-std" ''
      cd crates
      cargo build --frozen --offline --no-default-features -p terrane-core --lib
      printf 'PASS: terrane-core builds without default features\n' > "$out/result"
    '';
    tree-node-distribution = sourceGate "tree-node-distribution" ''
      cd crates
      cargo build --release --frozen --offline -p terrane-core --example tree_node_distribution
      "$CARGO_TARGET_DIR/release/examples/tree_node_distribution" > "$out/tree-node-distribution.tsv"
    '';
    role-selection = pkgs.mkDerivation {
      pname = "terrane-gate-role-selection";
      version = "0.1.0";
      src = null;
      buildDeps = [pkgs.python3];
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            python3 ${./check_roles.py} ${pkgs.terrane}/bin/terrane > "$out/result"
          '';
        }
      ];
    };
    registry-complete = pkgs.mkDerivation {
      pname = "terrane-gate-registry-complete";
      version = "0.1.0";
      src = null;
      buildDeps = [pkgs.python3];
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            python3 ${./gate_registry.py} \
              ${../../docs/rfcs/0024-terrane/spec} \
              ${./gate_registry.json} ${checkNames} > "$out/result"
          '';
        }
      ];
    };
  };

  gates = builtins.listToAttrs (map (row: {
    name = row.name;
    value = implementedGates.${row.name} or (pendingGate row);
  }) registry);
in {
  package = pkgs.terrane;
  inherit gates;
  activeGates = implementedGates;
}
