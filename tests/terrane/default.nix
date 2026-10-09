{
  pkgs,
  lib,
}: let
  registry = builtins.fromJSON (builtins.readFile ./gate_registry.json);
  checkNames = builtins.toFile "terrane-check-names.json" (builtins.toJSON (builtins.attrNames registeredGates));
  currentGateNames = builtins.toFile "terrane-current-gate-names.json" (builtins.toJSON currentTrunkGateNames);

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

  sourceGate = sourceGateWithInputs {};
  sourceGateWithInputs = {
    runtimeDeps ? [],
    nukeRefsKeep ? [],
    extraBuildDeps ? [],
  }: name: script:
    pkgs.mkDerivation {
      pname = "terrane-gate-${name}";
      version = "0.1.0";
      src = pkgs.terrane.src;
      inherit runtimeDeps nukeRefsKeep;
      buildDeps = [pkgs.rust pkgs.rust.dev pkgs.python3 pkgs.util-linux] ++ extraBuildDeps;
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
            export CARGO_BUILD_JOBS="$NIX_BUILD_CORES"
            mkdir -p "$CARGO_HOME" crates/.cargo
            sed 's|@vendor@|${pkgs.terrane.passthru.cargoDeps}|g' \
              ${pkgs.terrane.passthru.cargoDeps}/.cargo/config.toml > crates/.cargo/config.toml
            ${script}
          '';
        }
      ];
    };

  algebraFormatVectors = import ./algebra-models.nix {inherit sourceGate;};

  # Share compilation of one immutable native test image, while every gate
  # retains its own protected execution and fresh filesystem fixtures.
  # The installed runner consumes Rust's runtime libraries and compares its
  # immutable source identity. Keep these explicit references through fixup.
  nativeSdkTestImage = import ./native-sdk-test-image.nix {
    sourceGate = sourceGateWithInputs {
      runtimeDeps = [pkgs.rust pkgs.rust.dev pkgs.diffutils] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
      extraBuildDeps = [pkgs.binutils];
    };
  };
  nativeSdkGate = name: script:
    sourceGate name ''
      python3 - ${nativeSdkTestImage}/share/identity.json "$src" <<'PY'
      import json
      import pathlib
      import sys

      identity = json.loads(pathlib.Path(sys.argv[1]).read_text())
      profile = identity.get("profile", {})
      if (identity.get("schema_version") != 1
              or identity.get("source") != sys.argv[2]
              or identity.get("cargo_profile") != "test"
              or identity.get("default_features") is not False
              or identity.get("requested_features") != ["tokio", "surface-sdk"]
              or identity.get("features") != ["send", "std", "surface-sdk", "tokio"]
              or profile.get("test") is not True
              or profile.get("opt_level") != "s"
              or profile.get("debuginfo") != 0):
          raise SystemExit("native SDK test image source, feature or profile mismatch")
      PY
      export TERRANE_NATIVE_SDK_TEST_BINARY="${nativeSdkTestImage}/bin/terrane-native-sdk-tests"
      ${script}
    '';

  # A zero-node fork depends on genuine selected source lineage. Full source
  # requalification and preservation are qualified outside the cold interval.
  nativeForkPrerequisites = {
    coldSource = import ./native-cold-fork-source.nix {sourceGate = nativeSdkGate;};
    requalification = import ./native-source-requalification.nix {sourceGate = nativeSdkGate;};
    sourcePreservation = import ./native-source-preserving-retirement.nix {sourceGate = nativeSdkGate;};
    importedPreservation = import ./native-imported-source-retirement.nix {sourceGate = nativeSdkGate;};
  };

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
              ${./gate_registry.json} ${checkNames} \
              ${../../docs/rfcs/0024-terrane/integration/05-implementation-plan.md} \
              ${currentGateNames} > "$out/result"
          '';
        }
      ];
    };
  };

  gateFiles = builtins.filter (name: lib.hasSuffix ".nix" name) (builtins.attrNames (builtins.readDir ./gates));
  taskGates =
    builtins.foldl' (
      accumulated: file: let
        added = import (./gates + "/${file}") (
          {
            inherit pkgs lib sourceGate structureGate;
            forkPrerequisites = builtins.attrValues nativeForkPrerequisites;
          }
          // lib.optionalAttrs (file == "algebra.nix") {inherit nativeSdkGate;}
        );
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

  localWorkflow = import ./local-workflow-ext4.nix {inherit pkgs lib;};
  localSdkCheckout = import ./local-sdk-checkout.nix {inherit sourceGate;};
  localCliWorkflow = import ./local-cli-workflow.nix {inherit sourceGate;};

  # These T1 obligations remain in the current floor even before their task
  # files are adopted. AD-11 makes Memo and index maintenance trunk work.
  # Later milestone checks remain named failures outside this aggregate.
  currentTrunkGateNames = lib.unique (
    builtins.attrNames implementedGates
    ++ [
      "algebra-fork"
      "derivation-memo"
      "gc-two-phase-delete"
      "index-tree-maintenance"
    ]
  );

  # Registration cannot make an unimplemented current obligation green.
  aggregate = pkgs.mkDerivation {
    pname = "terrane-current-gates";
    version = "0.1.0";
    src = null;
    buildDeps = map (name: registeredGates.${name}) currentTrunkGateNames ++ [localWorkflow localSdkCheckout localCliWorkflow];
    phases = [
      {
        name = "check";
        script = ''
          mkdir -p "$out"
          printf 'PASS: %s current Terrane gates, public local SDK/CLI workflows and the local ext4 workflow\n' ${toString (builtins.length currentTrunkGateNames)} \
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
  integration.local-workflow-ext4 = localWorkflow;
  integration.local-sdk-checkout = localSdkCheckout;
  integration.local-cli-workflow = localCliWorkflow;
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
  integration.native-preownership-restore = import ./native-preownership-restore.nix {inherit sourceGate;};
  integration.native-retirement-faults = import ./native-retirement-faults.nix {inherit sourceGate;};
  integration.native-held-lease-renewal = import ./native-held-lease-renewal.nix {inherit sourceGate;};
  integration.native-lease-output-sync = import ./native-lease-output-sync.nix {inherit sourceGate;};
  integration.native-checked-mutation-publication = import ./native-checked-mutation-publication.nix {inherit sourceGate;};
  integration.native-written-mutation-sync = import ./native-written-mutation-sync.nix {inherit sourceGate;};
  integration.native-retained-request-checks = import ./native-retained-request-checks.nix {inherit sourceGate;};
  integration.native-local-first-ownership = import ./native-local-first-ownership.nix {inherit sourceGate;};
  integration.native-copied-retirement-first-ownership = import ./native-copied-retirement-first-ownership.nix {inherit sourceGate;};
  integration.native-local-deletion = import ./native-local-deletion.nix {inherit sourceGate;};
  integration.native-local-gc-conformance = let
    prerequisites = [
      (import ./native-local-first-ownership.nix {inherit sourceGate;})
      (import ./native-local-deletion.nix {inherit sourceGate;})
      (import ./native-preownership-restore.nix {inherit sourceGate;})
      (import ./native-retirement-faults.nix {inherit sourceGate;})
      taskGates.gc-roots-complete
      taskGates.gc-mark-reachability
      taskGates.gc-grace-window
      taskGates.gc-singleton-lease
      nativeForkPrerequisites.sourcePreservation
      nativeForkPrerequisites.importedPreservation
    ];
  in
    import ./native-local-gc-conformance.nix {
      inherit prerequisites;
      sourceGate = sourceGateWithInputs {extraBuildDeps = prerequisites;};
    };
  integration.native-collector-clock = import ./native-collector-clock.nix {inherit sourceGate;};
  integration.native-cold-fork-source = nativeForkPrerequisites.coldSource;
  integration.native-cold-fork-legacy = import ./native-cold-fork-legacy.nix {inherit sourceGate;};
  integration.native-guard-carry = import ./native-guard-carry.nix {inherit sourceGate;};
  integration.native-source-requalification = nativeForkPrerequisites.requalification;
  integration.native-missing-placement = import ./native-missing-placement.nix {inherit sourceGate;};
  integration.native-legacy-completion = import ./native-legacy-completion.nix {inherit sourceGate;};
  integration.native-meta-batch = import ./native-meta-batch.nix {inherit sourceGate;};
  integration.native-active-view-completion = import ./native-active-view-completion.nix {inherit sourceGate;};
  integration.native-content-observation = import ./native-content-observation.nix {inherit sourceGate;};
  integration.native-index-loading = import ./native-index-loading.nix {inherit sourceGate;};
  integration.native-index-lookup = import ./native-index-lookup.nix {inherit sourceGate;};
  integration.native-index-rebuild = import ./native-index-rebuild.nix {inherit sourceGate;};
  integration.native-index-backfill = import ./native-index-backfill.nix {inherit sourceGate;};
  integration.native-index-locality = import ./native-index-locality.nix {inherit sourceGate;};
  integration.native-memo-persistence = import ./native-memo-persistence.nix {inherit sourceGate;};
  integration.native-memo-retention = import ./native-memo-retention.nix {inherit sourceGate;};
  integration.native-source-preserving-retirement = nativeForkPrerequisites.sourcePreservation;
  integration.native-imported-source-retirement = nativeForkPrerequisites.importedPreservation;
  integration.namespace-reference-models = import ./namespace-models.nix {inherit sourceGate;};
  integration.attribute-reference-models = import ./attribute-models.nix {inherit sourceGate;};
  integration.index-format = import ./index-format.nix {inherit sourceGate;};
  integration.index-evaluation = import ./index-evaluation.nix {inherit sourceGate;};
  integration.index-completion = import ./index-completion.nix {inherit sourceGate;};
  integration.index-query = import ./index-query.nix {inherit sourceGate;};
  integration.memo-format = import ./memo-format.nix {inherit sourceGate;};
  integration.memo-evaluation = import ./memo-evaluation.nix {inherit sourceGate;};
  integration.memo-metadata = import ./memo-metadata.nix {inherit sourceGate;};
  integration.memo-replay = import ./memo-replay.nix {inherit sourceGate;};
  integration.node-metadata = import ./node-metadata.nix {inherit sourceGate;};
  integration.index-loading = import ./index-loading.nix {inherit sourceGate;};
  integration.index-source = import ./index-source.nix {inherit sourceGate;};
  integration.index-reference-models = import ./index-models.nix {inherit sourceGate;};
  integration.disclosure-denied-diagnostic = import ./disclosure-denied-diagnostic.nix {inherit sourceGate;};
  integration.native-recorded-disclosure = import ./native-recorded-disclosure.nix {inherit sourceGate;};
  integration.native-historical-index-completion = import ./native-historical-index-completion.nix {inherit sourceGate;};
  integration.native-index-publication = import ./native-index-publication.nix {inherit sourceGate;};
  integration.native-profile-quality = import ./native-profile-quality.nix {inherit sourceGate;};
  integration.mixed-view-interpretation = import ./mixed-view-interpretation.nix {inherit sourceGate;};
  integration.property-registry = import ./property-registry.nix {inherit sourceGate;};
  integration.container-reference-models = import ./container-models.nix {inherit sourceGate;};
  integration.refs-reference-models = import ./refs-models.nix {inherit sourceGate;};
  integration.evidence-reference-models = import ./evidence-models.nix {inherit sourceGate;};
  integration.control-reference-models = import ./control-models.nix {inherit sourceGate;};
  integration.reconciliation-reference-models = import ./reconciliation-models.nix {inherit sourceGate;};
  integration.lineage-reference-models = import ./lineage-models.nix {inherit sourceGate;};
  integration.consumed-view-context = import ./consumed-view-context.nix {inherit sourceGate;};
  integration.prefix-reference-models = import ./prefix-models.nix {inherit sourceGate;};
  integration.recipe-context-reference-models = import ./recipe-context-models.nix {inherit sourceGate;};
  integration.recorded-context-reference-models = import ./recorded-context-models.nix {inherit sourceGate;};
}
