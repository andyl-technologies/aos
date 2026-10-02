{
  pkgs,
  lib,
}: let
  registry = builtins.fromJSON (builtins.readFile ./gate_registry.json);
  checkNames = builtins.toFile "terrane-check-names.json" (builtins.toJSON (builtins.attrNames registeredGates));

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

  protectedCheck = import ../../pkgs/tools/terrane/_protected-check.nix {util-linux = pkgs.util-linux;};

  sourceGate = name: script:
    pkgs.mkDerivation {
      pname = "terrane-gate-${name}";
      version = "0.1.0";
      src = pkgs.terrane.src;
      buildDeps = [pkgs.rust pkgs.rust.dev pkgs.python3 pkgs.util-linux];
      phases = [
        {
          name = "check";
          script = protectedCheck ''
            set -eu
            mkdir -p "$out"
            cd "$TMPDIR"
            cp -r "$src" source
            chmod -R u+w source
            cd source
            export CARGO_HOME="$TMPDIR/cargo-home"
            export CARGO_TARGET_DIR="$TMPDIR/cargo-target"
            mkdir -p "$CARGO_HOME" crates/.cargo
            sed 's|@vendor@|${pkgs.terrane.passthru.cargoDeps}|g' \
              ${pkgs.terrane.passthru.cargoDeps}/.cargo/config.toml > crates/.cargo/config.toml
            ${script}
          '';
        }
      ];
    };

  algebraFormatVectors = import ./algebra-models.nix {inherit sourceGate;};

  structureGate = name:
    sourceGate name ''
      cd crates
      cargo metadata --no-deps --offline --locked --format-version 1 > "$TMPDIR/metadata.json"
      cd ..
      python3 tests/terrane/check_structure.py ${name} "$PWD" "$TMPDIR/metadata.json" \
        > "$out/result"
    '';

  foundationGates = {
    crate-graph = structureGate "crate-graph";
    unsafe-audit = structureGate "unsafe-audit";
    core-no-std = sourceGate "core-no-std" ''
      cd crates
      cargo build --frozen --offline --no-default-features -p terrane-core --lib
      printf 'PASS: terrane-core builds without default features\n' > "$out/result"
    '';
    formats-no-std = pkgs.mkDerivation {
      pname = "terrane-gate-formats-no-std";
      version = "0.1.0";
      src = null;
      # Compilation checks the actual core library. The graph check also
      # requires no_std + alloc and rejects host, default and std features.
      buildDeps = [foundationGates.core-no-std foundationGates.crate-graph];
      phases = [
        {
          name = "check";
          script = ''
            test -s ${foundationGates.core-no-std}/result
            test -s ${foundationGates.crate-graph}/result
            mkdir -p "$out"
            printf 'PASS: portable formats compile without default features and satisfy the core dependency policy\n' > "$out/result"
          '';
        }
      ];
    };
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

  gateFiles = builtins.filter (name: lib.hasSuffix ".nix" name) (builtins.attrNames (builtins.readDir ./gates));
  taskGates =
    builtins.foldl' (
      accumulated: file: let
        added = import (./gates + "/${file}") {
          inherit pkgs lib sourceGate structureGate;
        };
        duplicates = builtins.filter (name: builtins.hasAttr name accumulated) (builtins.attrNames added);
      in
        if duplicates == []
        then accumulated // added
        else throw "Terrane gate files register duplicate names: ${builtins.concatStringsSep ", " duplicates}"
    ) {}
    gateFiles;

  taskGateNames = builtins.attrNames taskGates;
  foundationDuplicates = builtins.filter (name: builtins.hasAttr name foundationGates) taskGateNames;
  unregisteredTaskGates = builtins.filter (name: !(builtins.elem name (map (row: row.name) registry))) taskGateNames;
  implementedGates =
    if foundationDuplicates != []
    then throw "Terrane task gates duplicate foundation gates: ${builtins.concatStringsSep ", " foundationDuplicates}"
    else if unregisteredTaskGates != []
    then throw "Terrane task gates are absent from the specification registry: ${builtins.concatStringsSep ", " unregisteredTaskGates}"
    else foundationGates // taskGates;

  registeredGates = builtins.listToAttrs (map (row: {
      name = row.name;
      value = implementedGates.${row.name} or (pendingGate row);
    })
    registry);

  # The aggregate is the current trunk floor. Named checks remain available
  # through its attributes, including deferred checks that fail on request.
  aggregate = pkgs.mkDerivation {
    pname = "terrane-current-gates";
    version = "0.1.0";
    src = null;
    buildDeps = builtins.attrValues implementedGates;
    phases = [
      {
        name = "check";
        script = ''
          mkdir -p "$out"
          printf 'PASS: %s current Terrane gates\n' ${toString (builtins.length (builtins.attrNames implementedGates))} \
            > "$out/result"
        '';
      }
    ];
    passthru.registeredGateNames = builtins.attrNames registeredGates;
  };
in {
  package = pkgs.terrane;
  gates = aggregate // registeredGates;
  activeGates = implementedGates;
  integration.local-workflow-ext4 = import ./local-workflow-ext4.nix {inherit pkgs lib;};
  integration.publication-format-vectors = import ./publication-vectors.nix {inherit sourceGate;};
  integration.pack-format-vectors = import ./pack-vectors.nix {inherit sourceGate;};
  integration.collection-reference-generator = import ./collection-reference.nix {inherit pkgs;};
  integration.collection-format-vectors = import ./collection-vectors.nix {inherit sourceGate;};
  integration.foundation-reference-generator = import ./foundation-reference.nix {inherit sourceGate;};
  integration.foundation-format-vectors = import ./foundation-vectors.nix {inherit sourceGate;};
  integration.retirement-reference-generator = import ./retirement-reference.nix {inherit sourceGate;};
  integration.retirement-reference-models = import ./retirement-models.nix {inherit sourceGate;};
  integration.authorized-principal = import ./authorized-principal.nix {inherit sourceGate;};
  integration.algebra-reference-models = algebraFormatVectors;
  integration.algebra-format-vectors = algebraFormatVectors;
  integration.legacy-format-vectors = import ./legacy-vectors.nix {inherit sourceGate;};
  integration.local-factory-construction = import ./local-factory-construction.nix {inherit sourceGate;};
  integration.namespace-reference-models = import ./namespace-models.nix {inherit sourceGate;};
  integration.attribute-reference-models = import ./attribute-models.nix {inherit sourceGate;};
  integration.container-reference-models = import ./container-models.nix {inherit sourceGate;};
  integration.refs-reference-models = import ./refs-models.nix {inherit sourceGate;};
  integration.evidence-reference-models = import ./evidence-models.nix {inherit sourceGate;};
  integration.control-reference-models = import ./control-models.nix {inherit sourceGate;};
  integration.reconciliation-reference-models = import ./reconciliation-models.nix {inherit sourceGate;};
  integration.lineage-reference-models = import ./lineage-models.nix {inherit sourceGate;};
  integration.prefix-reference-models = import ./prefix-models.nix {inherit sourceGate;};
}
