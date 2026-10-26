{
  pkgs,
  lib,
  mkSystem,
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
    preserveArtifactBytes ? false,
  }: name: script:
    pkgs.mkDerivation {
      pname = "terrane-gate-${name}";
      version = "0.1.0";
      src = pkgs.terrane.src;
      inherit runtimeDeps nukeRefsKeep;
      # Proof images bind the retained ELF bytes to actual Cargo artifacts.
      # Later stripping, RPATH rewriting or reference scrubbing would invalidate
      # their recorded hashes. Ordinary checks keep the normal fixup policy.
      dontStrip = preserveArtifactBytes;
      dontPatchELF = preserveArtifactBytes;
      dontNukeRefs = preserveArtifactBytes;
      buildDeps = [pkgs.rust pkgs.rust.dev pkgs.python3 pkgs.util-linux pkgs.protobuf] ++ extraBuildDeps;
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
            export PROTOC="${pkgs.protobuf}/bin/protoc"
            mkdir -p "$CARGO_HOME" crates/.cargo
            sed 's|@vendor@|${pkgs.terrane.passthru.cargoDeps}|g' \
              ${pkgs.terrane.passthru.cargoDeps}/.cargo/config.toml > crates/.cargo/config.toml
            ${script}
          '';
        }
      ];
    };

  # Keep the native proof selectable while its implementation is isolated on
  # the current task branch. Presence alone never qualifies the owning gate.
  quotaConfinementProof =
    if builtins.pathExists ./quota-confinement-proof.nix
    then import ./quota-confinement-proof.nix {inherit pkgs lib sourceGateWithInputs;}
    else {
      image = pendingGate {
        name = "native-quota-confinement-image";
        requirements = "HOST-23 native confinement proof image";
      };
      native = pendingGate {
        name = "native-quota-confinement";
        requirements = "HOST-23 native confinement proof";
      };
    };

  configuredSdkProof =
    if builtins.pathExists ./configured-sdk-proof.nix
    then import ./configured-sdk-proof.nix {inherit pkgs lib sourceGateWithInputs;}
    else
      builtins.listToAttrs (map (name: {
        inherit name;
        value = pendingGate {
          name = "configured-sdk-${name}";
          requirements = "SURF-32 configured SDK startup proof";
        };
      }) ["image" "unit" "native"]);

  hostCacheProof =
    if builtins.pathExists ./host-cache-proof.nix
    then import ./host-cache-proof.nix {inherit pkgs lib sourceGateWithInputs;}
    else
      builtins.listToAttrs (map (name: {
        inherit name;
        value = pendingGate {
          name = "native-host-cache-${name}";
          requirements = "HOST-23/HOST-31 native host owner proof";
        };
      }) ["image" "native"]);

  hostCacheAllFeatureProof = import ./host-cache-proof.nix {
    inherit pkgs lib sourceGateWithInputs;
    allFeatureUnits = true;
  };

  # Transport components qualify actual peer and native command behavior,
  # independently of complete cache recovery or host-tier readiness.
  publisherLocalProof =
    if builtins.pathExists ./publisher-local-proof.nix
    then import ./publisher-local-proof.nix {inherit pkgs lib sourceGateWithInputs;}
    else
      builtins.listToAttrs (map (name: {
        inherit name;
        value = pendingGate {
          name = "publisher-local-${name}";
          requirements = "PROTO-56 to PROTO-59 native publisher transport component";
        };
      }) ["image" "multiUid" "native"]);

  # Enrollment must consume the genuine fresh creator receipt in one process.
  # These component checks cannot stand in for complete host-tier readiness.
  initialEnrollmentProof =
    if builtins.pathExists ./initial-enrollment-proof.nix
    then
      import ./initial-enrollment-proof.nix {
        inherit pkgs lib sourceGateWithInputs configuredSdkProof;
        surfaceImage =
          (import ./host-cache-proof.nix {
            inherit pkgs lib sourceGateWithInputs;
            surfaceIndex = true;
          }).image;
      }
    else
      builtins.listToAttrs (map (name: {
        inherit name;
        value = pendingGate {
          name = "initial-enrollment-${name}";
          requirements = "HOST-23/DOM-12 fresh native enrollment component";
        };
      }) ["image" "native" "reassembly" "sdk" "surface"]);

  algebraFormatVectors = import ./algebra-models.nix {inherit sourceGate;};

  # Share compilation of one immutable native test image, while every gate
  # retains its own protected execution and fresh filesystem fixtures.
  # The installed runner consumes Rust's runtime libraries and compares its
  # immutable source identity. Keep these explicit references through fixup.
  nativeSdkTestImage = import ./native-sdk-test-image.nix {
    sourceGate = sourceGateWithInputs {
      preserveArtifactBytes = true;
      runtimeDeps = [pkgs.rust pkgs.rust.dev pkgs.diffutils] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
      extraBuildDeps = [pkgs.binutils];
    };
  };
  # File-bucket gates use the original default+Tokio feature selection. Keep
  # that compilation separate from the no-default-features SDK surface image.
  bucketSdkTestImage = import ./native-sdk-test-image.nix {
    variant = "default-tokio";
    sourceGate = sourceGateWithInputs {
      preserveArtifactBytes = true;
      runtimeDeps = [pkgs.rust pkgs.rust.dev pkgs.diffutils] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
      extraBuildDeps = [pkgs.binutils];
    };
  };
  portableSharedModes = import ./portable-shared-modes.nix {
    inherit pkgs lib;
    image = bucketSdkTestImage;
  };
  sharedDirectoryProof = import ./shared-directory-proof.nix {
    inherit pkgs lib;
    image = nativeSdkTestImage;
  };
  # Pack gates retain their original default features without selecting Tokio.
  defaultSdkTestImage = import ./native-sdk-test-image.nix {
    variant = "default";
    sourceGate = sourceGateWithInputs {
      runtimeDeps = [pkgs.rust pkgs.rust.dev pkgs.diffutils] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
      extraBuildDeps = [pkgs.binutils];
    };
  };
  nativeSdkGate = nativeSdkGateWithInputs {};
  nativeSdkGateWithInputs = sdkTestGateWithImage {
    image = nativeSdkTestImage;
    defaultFeatures = false;
    requestedFeatures = ["tokio" "surface-sdk"];
    features = ["send" "std" "surface-sdk" "tokio"];
  };
  bucketSdkGate = sdkTestGateWithImage {
    image = bucketSdkTestImage;
    defaultFeatures = true;
    requestedFeatures = ["tokio"];
    features = ["default" "send" "std" "tokio"];
  } {};
  defaultSdkGate = sdkTestGateWithImage {
    image = defaultSdkTestImage;
    defaultFeatures = true;
    requestedFeatures = [];
    features = ["default" "std"];
  } {};
  sdkTestGateWithImage = {
    image,
    defaultFeatures,
    requestedFeatures,
    features,
  }: inputs: name: script:
    sourceGateWithInputs inputs name ''
      python3 - ${image}/share/identity.json "$src" ${lib.escapeShellArg (builtins.toJSON {
        default_features = defaultFeatures;
        requested_features = requestedFeatures;
        inherit features;
      })} <<'PY'
      import json
      import pathlib
      import sys

      identity = json.loads(pathlib.Path(sys.argv[1]).read_text())
      expected = json.loads(sys.argv[3])
      profile = identity.get("profile", {})
      if (identity.get("schema_version") != 1
              or identity.get("source") != sys.argv[2]
              or identity.get("cargo_profile") != "test"
              or identity.get("default_features") is not expected["default_features"]
              or identity.get("requested_features") != expected["requested_features"]
              or identity.get("features") != expected["features"]
              or profile.get("test") is not True
              or profile.get("opt_level") != "s"
              or profile.get("debuginfo") != 0):
          raise SystemExit("native SDK test image source, feature or profile mismatch")
      PY
      export TERRANE_NATIVE_SDK_TEST_BINARY="${image}/bin/terrane-native-sdk-tests"
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
      cargo build --frozen --offline --no-default-features -p terrane-format --lib
      printf 'PASS: terrane-format builds without default features\n' > "$out/result"
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
      cargo build --release --frozen --offline -p terrane-format --example tree_node_distribution
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
            test "$(cat ${hostCacheProof.native}/result)" = PASS
            python3 ${./check_roles.py} ${pkgs.terrane}/bin/terrane > "$out/result"
            mkdir -p "$out/nix-support"
            printf '%s\n' ${hostCacheProof.native} > "$out/nix-support/unprivileged-preflight-proof"
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

  localGcPrerequisites = [
    (import ./native-local-first-ownership.nix {sourceGate = nativeSdkGate;})
    (import ./native-local-deletion.nix {sourceGate = nativeSdkGate;})
    (import ./native-preownership-restore.nix {
      inherit pkgs lib;
      image = nativeSdkTestImage;
    })
    (import ./native-retirement-faults.nix {sourceGate = nativeSdkGate;})
    taskGates.gc-roots-complete
    taskGates.gc-mark-reachability
    taskGates.gc-grace-window
    taskGates.gc-singleton-lease
    nativeForkPrerequisites.sourcePreservation
    nativeForkPrerequisites.importedPreservation
  ];
  localGcConformance = import ./native-local-gc-conformance.nix {
    prerequisites = localGcPrerequisites;
    sourceGate = nativeSdkGateWithInputs {extraBuildDeps = localGcPrerequisites;};
  };

  # Every local retirement alternative belongs in T1's owning gate. All three
  # checks use this package source; provider qualification extends it at T3.
  localTwoPhaseGc = import ./local-two-phase-gc.nix {
    inherit pkgs;
    prerequisites = [
      localGcConformance
      (import ./native-copied-retirement-first-ownership.nix {sourceGate = nativeSdkGate;})
      (import ./local-permanent-reconciliation.nix {sourceGate = nativeSdkGate;})
    ];
  };

  wasmHostProof = import ./wasm-host-profile.nix {inherit pkgs sourceGateWithInputs;};

  workloadIssuerProof = import ./workload-issuer.nix {inherit sourceGate;};
  instanceIssuerProof = import ./gcp-instance-issuer.nix {inherit sourceGate;};
  configuredIssuerProof = import ./configured-workload-issuer.nix {inherit sourceGate;};

  gateFiles = builtins.filter (name: lib.hasSuffix ".nix" name) (builtins.attrNames (builtins.readDir ./gates));
  taskGates =
    builtins.foldl' (
      accumulated: file: let
        added = import (./gates + "/${file}") (
          {
            inherit pkgs lib sourceGate structureGate;
            forkPrerequisites = builtins.attrValues nativeForkPrerequisites;
          }
          // lib.optionalAttrs (builtins.elem file ["algebra.nix" "properties.nix" "cdc.nix" "gc.nix" "index.nix" "host-publish.nix"]) {inherit nativeSdkGate;}
          // lib.optionalAttrs (builtins.elem file ["surfaces.nix" "host-cache.nix"]) {inherit nativeSdkTestImage;}
          // lib.optionalAttrs (file == "fuse-index.nix") {inherit initialEnrollmentProof;}
          // lib.optionalAttrs (file == "gc.nix") {inherit localTwoPhaseGc;}
          // lib.optionalAttrs (builtins.elem file ["host-publish.nix" "host-cache.nix" "surfaces.nix" "fuse-index.nix" "observability.nix"]) {inherit sourceGateWithInputs;}
          // lib.optionalAttrs (builtins.elem file ["bucket.nix" "ref_advance.nix"]) {inherit bucketSdkGate;}
          // lib.optionalAttrs (file == "shared-dir.nix") {inherit portableSharedModes initialEnrollmentProof sharedDirectoryProof;}
          // lib.optionalAttrs (file == "store.nix") {inherit hostCacheProof hostCacheAllFeatureProof wasmHostProof sourceGateWithInputs;}
          // lib.optionalAttrs (file == "auth.nix") {inherit workloadIssuerProof instanceIssuerProof configuredIssuerProof;}
          // lib.optionalAttrs (file == "pack.nix") {inherit defaultSdkGate;}
          // lib.optionalAttrs (file == "host-publish.nix") {inherit publisherLocalProof hostCacheProof initialEnrollmentProof moduleEval;}
          // lib.optionalAttrs (file == "host-cache.nix") {inherit hostCacheProof initialEnrollmentProof;}
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
  moduleEval = import ./module-eval.nix {inherit pkgs lib mkSystem;};
  localSdkCheckout = import ./local-sdk-checkout.nix {inherit sourceGate;};
  localCliWorkflow = import ./local-cli-workflow.nix {inherit sourceGate;};
  planCoverage = import ./plan-coverage.nix {inherit pkgs;};

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
    buildDeps = map (name: registeredGates.${name}) currentTrunkGateNames ++ [localWorkflow localSdkCheckout localCliWorkflow planCoverage];
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
  module-eval = moduleEval;
  plan-coverage = planCoverage;
  gates = aggregate // registeredGates;
  activeGates = implementedGates;
  integration.bucket-sdk-test-image = bucketSdkTestImage;
  integration.default-sdk-test-image = defaultSdkTestImage;
  integration.local-workflow-ext4 = localWorkflow;
  integration.local-sdk-checkout = localSdkCheckout;
  integration.local-cli-workflow = localCliWorkflow;
  integration.publication-format-vectors = import ./publication-vectors.nix {inherit sourceGate;};
  integration.pack-format-vectors = import ./pack-vectors.nix {inherit sourceGate;};
  integration.collection-reference-generator = import ./collection-reference.nix {inherit pkgs;};
  integration.collection-format-vectors = import ./collection-vectors.nix {inherit sourceGate;};
  integration.foundation-reference-generator = import ./foundation-reference.nix {inherit sourceGate;};
  integration.native-quota-confinement-image = quotaConfinementProof.image;
  integration.native-quota-confinement = quotaConfinementProof.native;
  integration.configured-sdk-image = configuredSdkProof.image;
  integration.wasm-host-profile = wasmHostProof;
  integration.configured-sdk-unit = configuredSdkProof.unit;
  integration.native-configured-sdk = configuredSdkProof.native;

  integration.native-configured-gc = import ./configured-gc-proof.nix {
    inherit pkgs lib;
    image = configuredSdkProof.image;
  };
  integration.native-configured-gc-cli = import ./configured-gc-proof.nix {
    inherit pkgs lib;
    image = configuredSdkProof.image;
    launcher = "cli";
  };
  integration.host-cache-image = hostCacheProof.image;
  integration.native-host-cache = hostCacheProof.native;
  integration.native-host-cache-all-features = hostCacheAllFeatureProof.native;
  integration.host-cache-all-features-image = hostCacheAllFeatureProof.image;
  integration.native-fuse-kernel = import ./fuse-kernel.nix {inherit pkgs lib;};
  integration.publisher-local-image = publisherLocalProof.image;
  integration.publisher-local-multuid = publisherLocalProof.multiUid;
  integration.native-publisher-local = publisherLocalProof.native;
  integration.initial-enrollment-image = initialEnrollmentProof.image;
  integration.native-initial-enrollment = initialEnrollmentProof.native;
  integration.native-reassembly = initialEnrollmentProof.reassembly;
  integration.native-private-release = initialEnrollmentProof.privateRelease;
  integration.native-cold-private-release = initialEnrollmentProof.coldPrivateRelease;
  integration.native-cold-manifest-release = initialEnrollmentProof.coldManifestRelease;
  integration.native-cold-public-pressure = initialEnrollmentProof.coldPublicPressure;
  integration.native-cold-manifest-pressure = initialEnrollmentProof.coldManifestPressure;
  integration.native-sdk-cache = initialEnrollmentProof.sdk;
  integration.native-sdk-maintained = initialEnrollmentProof.sdkMaintained;
  integration.native-sdk-refusals = initialEnrollmentProof.sdkRefusals;
  integration.native-sdk-wipe = initialEnrollmentProof.sdkWipe;
  integration.native-configured-maintenance = initialEnrollmentProof.maintenance;
  integration.native-builder-environment = import ./native-builder/environment.nix {inherit pkgs lib;};
  integration.native-configured-maintenance-systemd = import ./configured-maintenance-systemd.nix {
    inherit pkgs lib mkSystem initialEnrollmentProof configuredSdkProof;
  };
  integration.native-configured-manifest-open = initialEnrollmentProof.manifestOpen;
  integration.native-configured-surface-index = initialEnrollmentProof.surface;
  integration.native-configured-worker = initialEnrollmentProof.worker;
  integration.native-configured-mounted-worker = initialEnrollmentProof.mountedWorker;
  integration.native-configured-mounted-manifest = initialEnrollmentProof.mountedManifest;
  integration.native-configured-mounted-expiry = initialEnrollmentProof.mountedExpiry;
  integration.native-configured-mounted-late = initialEnrollmentProof.mountedLate;
  integration.foundation-format-vectors = import ./foundation-vectors.nix {inherit sourceGate;};
  integration.retirement-reference-generator = import ./retirement-reference.nix {inherit sourceGate;};
  integration.retirement-reference-models = import ./retirement-models.nix {inherit sourceGate;};
  integration.authorized-principal = import ./authorized-principal.nix {inherit sourceGate;};
  integration.algebra-reference-models = algebraFormatVectors;
  integration.algebra-format-vectors = algebraFormatVectors;
  integration.legacy-format-vectors = import ./legacy-vectors.nix {inherit sourceGate;};
  integration.local-factory-construction = import ./local-factory-construction.nix {inherit sourceGate;};
  integration.native-coordination-locks = import ./local-collection-reconciliation.nix {
    inherit pkgs lib;
    image = nativeSdkTestImage;
    suite = "coordination-locks";
  };
  integration.native-readonly-repository = import ./local-collection-reconciliation.nix {
    inherit pkgs lib;
    image = nativeSdkTestImage;
    suite = "readonly-repository";
  };
  integration.native-preownership-restore = import ./native-preownership-restore.nix {
    inherit pkgs lib;
    image = nativeSdkTestImage;
  };
  integration.native-retirement-faults = import ./native-retirement-faults.nix {sourceGate = nativeSdkGate;};
  integration.native-held-lease-renewal = import ./native-held-lease-renewal.nix {sourceGate = nativeSdkGate;};
  integration.native-lease-output-sync = import ./native-lease-output-sync.nix {sourceGate = nativeSdkGate;};
  integration.native-checked-mutation-publication = import ./native-checked-mutation-publication.nix {sourceGate = nativeSdkGate;};
  integration.native-written-mutation-sync = import ./native-written-mutation-sync.nix {sourceGate = nativeSdkGate;};
  integration.native-retained-request-checks = import ./native-retained-request-checks.nix {inherit sourceGate;};
  integration.native-held-owner-history = import ./native-held-owner-history.nix {sourceGate = nativeSdkGate;};
  integration.native-overlay-history = import ./native-overlay-history.nix {sourceGate = nativeSdkGate;};
  integration.native-local-first-ownership = import ./native-local-first-ownership.nix {sourceGate = nativeSdkGate;};
  integration.native-copied-retirement-first-ownership = import ./native-copied-retirement-first-ownership.nix {sourceGate = nativeSdkGate;};

  integration.local-permanent-reconciliation = import ./local-permanent-reconciliation.nix {sourceGate = nativeSdkGate;};
  integration.native-local-deletion = import ./native-local-deletion.nix {sourceGate = nativeSdkGate;};
  integration.native-local-maintenance = import ./local-maintenance.nix {inherit pkgs lib sourceGateWithInputs;};
  integration.native-local-collection-reconciliation = import ./local-collection-reconciliation.nix {
    inherit pkgs lib;
    image = nativeSdkTestImage;
  };
  integration.native-local-maintenance-hints = import ./local-collection-reconciliation.nix {
    inherit pkgs lib;
    image = nativeSdkTestImage;
    suite = "maintenance-owner-hints";
  };
  integration.native-local-deletion-hints = import ./local-collection-reconciliation.nix {
    inherit pkgs lib;
    image = nativeSdkTestImage;
    suite = "local-deletion-hints";
  };
  integration.native-copied-shared-session = import ./local-collection-reconciliation.nix {
    inherit pkgs lib;
    image = nativeSdkTestImage;
    suite = "copied-shared-session";
  };
  integration.native-missing-trash-refresh = import ./local-collection-reconciliation.nix {
    inherit pkgs lib;
    image = nativeSdkTestImage;
    suite = "missing-trash-refresh";
  };
  integration.native-restoration-session = import ./local-collection-reconciliation.nix {
    inherit pkgs lib;
    image = nativeSdkTestImage;
    suite = "restoration-session";
  };
  integration.native-startup-restoration = import ./local-collection-reconciliation.nix {
    inherit pkgs lib;
    image = nativeSdkTestImage;
    suite = "startup-restoration";
  };
  integration.native-local-gc-conformance = localGcConformance;
  integration.native-collector-clock = import ./native-collector-clock.nix {sourceGate = nativeSdkGate;};
  integration.native-cold-fork-source = nativeForkPrerequisites.coldSource;
  integration.native-cold-fork-legacy = import ./native-cold-fork-legacy.nix {inherit sourceGate;};
  integration.native-guard-carry = import ./native-guard-carry.nix {inherit sourceGate;};
  integration.native-source-requalification = nativeForkPrerequisites.requalification;
  integration.native-missing-placement = import ./native-missing-placement.nix {inherit sourceGate;};
  integration.native-legacy-completion = import ./native-legacy-completion.nix {inherit sourceGate;};
  integration.native-meta-batch = import ./native-meta-batch.nix {inherit sourceGate;};
  integration.native-active-view-completion = import ./native-active-view-completion.nix {inherit sourceGate;};
  integration.native-content-observation = import ./native-content-observation.nix {inherit sourceGate;};
  integration.native-index-loading = import ./native-index-loading.nix {sourceGate = nativeSdkGate;};
  integration.native-index-lookup = import ./native-index-lookup.nix {sourceGate = nativeSdkGate;};
  integration.native-index-rebuild = import ./native-index-rebuild.nix {sourceGate = nativeSdkGate;};
  integration.native-index-backfill = import ./native-index-backfill.nix {sourceGate = nativeSdkGate;};
  integration.native-index-locality = import ./native-index-locality.nix {sourceGate = nativeSdkGate;};
  integration.wire-status = import ./wire-status.nix {inherit sourceGate;};
  integration.wire-contract = import ./wire-contract.nix {inherit sourceGate;};
  integration.streaming-http = import ./streaming-http.nix {inherit sourceGate;};

  integration.distribution-transport = import ./distribution-transport.nix {inherit sourceGateWithInputs;};

  integration.pack-receive = import ./pack-receive.nix {inherit sourceGate;};

  integration.workload-issuer = workloadIssuerProof;

  integration.gcp-instance-issuer = instanceIssuerProof;
  integration.store-expression-opened = import ./store-expression-opened.nix {inherit sourceGate;};
  integration.ref-history = import ./ref-history.nix {inherit sourceGate;};
  integration.indexed-presence = import ./indexed-presence.nix {inherit sourceGate;};
  integration.scoped-indexed-presence = import ./scoped-indexed-presence.nix {
    inherit pkgs lib;
    image = bucketSdkTestImage;
  };
  integration.held-indexed-presence = import ./held-indexed-presence.nix {
    inherit pkgs lib;
    image = bucketSdkTestImage;
  };
  integration.structural-index = import ./structural-index.nix {inherit pkgs sourceGateWithInputs;};
  integration.structural-mapping = (import ./structural-mapping.nix {inherit pkgs lib sourceGateWithInputs;}).native;
  integration.structural-mapping-image = (import ./structural-mapping.nix {inherit pkgs lib sourceGateWithInputs;}).image;
  integration.project-census = (import ./project-census.nix {inherit pkgs lib sourceGateWithInputs;}).native;
  integration.project-census-image = (import ./project-census.nix {inherit pkgs lib sourceGateWithInputs;}).image;
  integration.worker-channel = (import ./worker-channel.nix {inherit pkgs lib sourceGateWithInputs;}).native;
  integration.worker-channel-image = (import ./worker-channel.nix {inherit pkgs lib sourceGateWithInputs;}).image;
  integration.fuse-connection = (import ./fuse-connection.nix {inherit pkgs lib sourceGateWithInputs;}).native;
  integration.fuse-connection-image = (import ./fuse-connection.nix {inherit pkgs lib sourceGateWithInputs;}).image;
  integration.surface-index-owner =
    (import ./host-cache-proof.nix {
      inherit pkgs lib sourceGateWithInputs;
      surfaceIndex = true;
    }).native;
  integration.surface-index-owner-image =
    (import ./host-cache-proof.nix {
      inherit pkgs lib sourceGateWithInputs;
      surfaceIndex = true;
    }).image;
  integration.range-client = import ./range-client.nix {inherit sourceGate;};
  integration.scoped-worker-channel = import ./scoped-worker.nix {
    inherit pkgs lib;
    image =
      (import ./host-cache-proof.nix {
        inherit pkgs lib sourceGateWithInputs;
        surfaceIndex = true;
      }).image;
  };
  integration.worker-network-boundary = import ./scoped-worker.nix {
    inherit pkgs lib;
    workerNetwork = true;
    image =
      (import ./host-cache-proof.nix {
        inherit pkgs lib sourceGateWithInputs;
        surfaceIndex = true;
      }).image;
  };
  integration.mounted-worker = import ./scoped-worker.nix {
    inherit pkgs lib;
    workerMounted = true;
    image =
      (import ./host-cache-proof.nix {
        inherit pkgs lib sourceGateWithInputs;
        surfaceIndex = true;
      }).image;
  };
  integration.gc-maintenance-channel = import ./scoped-worker.nix {
    inherit pkgs lib;
    maintenance = true;
    image =
      (import ./host-cache-proof.nix {
        inherit pkgs lib sourceGateWithInputs;
        surfaceIndex = true;
      }).image;
  };
  integration.gc-maintenance-listener = import ./scoped-worker.nix {
    inherit pkgs lib;
    maintenanceListener = true;
    image =
      (import ./host-cache-proof.nix {
        inherit pkgs lib sourceGateWithInputs;
        surfaceIndex = true;
      }).image;
  };
  integration.worker-crash-recovery = import ./scoped-worker.nix {
    inherit pkgs lib;
    crash = true;
    image =
      (import ./host-cache-proof.nix {
        inherit pkgs lib sourceGateWithInputs;
        surfaceIndex = true;
      }).image;
  };
  integration.surface-index-admission-pressure = import ./scoped-worker.nix {
    inherit pkgs lib;
    admission = true;
    image =
      (import ./host-cache-proof.nix {
        inherit pkgs lib sourceGateWithInputs;
        surfaceIndex = true;
      }).image;
  };
  integration.surface-index-pressure = import ./scoped-worker.nix {
    inherit pkgs lib;
    pressure = true;
    image =
      (import ./host-cache-proof.nix {
        inherit pkgs lib sourceGateWithInputs;
        surfaceIndex = true;
      }).image;
  };
  integration.bundle-client = import ./bundle-client.nix {inherit sourceGate;};
  integration.bundle-receive = import ./bundle-receive.nix {inherit sourceGate;};
  integration.ref-head = import ./ref-head.nix {inherit sourceGate;};
  integration.ref-listing = import ./ref-listing.nix {inherit sourceGate;};
  integration.root-nodes = import ./root-nodes.nix {inherit sourceGate;};
  integration.configured-workload-issuer = configuredIssuerProof;
  integration.native-index-populations = import ./native-index-populations.nix {
    sourceGate = nativeSdkGateWithInputs {extraBuildDeps = [pkgs.coreutils];};
    coreutils = pkgs.coreutils;
  };
  integration.native-memo-persistence = import ./native-memo-persistence.nix {sourceGate = nativeSdkGate;};
  integration.native-memo-retention = import ./native-memo-retention.nix {sourceGate = nativeSdkGate;};
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
