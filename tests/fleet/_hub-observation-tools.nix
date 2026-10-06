# Independently built observational tools for an explicitly selected runtime.
# This recipe installs no acceptance, capture, authentication or provider state.
{
  pkgs,
  runtimeSource,
  helperSource,
  runtimeProvenance,
  runtimeArchive,
  sourceCommit,
  sourceTree,
  nativeArtifact,
  workerArtifact,
  clientArtifact ? null,
}: let
  native = pkgs.aos-hub;
  worker = pkgs.aos-hub-worker-dist;
  contract = native.passthru.cargoArtifactContract;
  vendor = builtins.elemAt native.passthru.evidenceSources 1;
  selected = builtins.fromJSON (builtins.readFile runtimeProvenance);
  selectedFile = pkgs.writeTextFile {
    name = "observation-selected-build-inputs.json";
    destination = "/selected.json";
    text = builtins.toJSON {
      inherit sourceCommit sourceTree;
      runtimeSource = "${runtimeSource}";
      runtimeArchive = "${runtimeArchive}";
      runtimeProvenance = selected;
      nativeExecutable = "${nativeArtifact}/bin/aos-hub";
      workerArtifact = "${workerArtifact}";
      workerSourceDigest = builtins.hashString "sha256" (toString worker.src);
      nativeContract = contract;
      helperSource = toString helperSource;
      vendorSource = toString vendor;
      clientSource =
        if clientArtifact == null
        then null
        else toString pkgs.aos.src;
      clientExecutable =
        if clientArtifact == null
        then null
        else "${clientArtifact}/bin/aos";
    };
  };

  prepared = pkgs.mkDerivation {
    pname = "aos-observation-helper-source";
    version = "0.1.0";
    src = null;
    # Source and wrapper references are intentional, measured build inputs.
    dontNukeRefs = true;
    buildDeps = [pkgs.python3];
    runtimeDeps = [];
    phases = [
      {
        name = "prepare";
        script = ''
          ${pkgs.python3}/bin/python3 -B -E \
            ${helperSource}/tests/fleet/observation-tools/prepare_package.py \
            ${selectedFile}/selected.json ${helperSource} "$out"
          ${pkgs.python3}/bin/python3 -B -E \
            ${helperSource}/tests/fleet/observation-tools/extract_tests.py ${runtimeSource}
          ${pkgs.python3}/bin/python3 -B -E \
            ${helperSource}/tests/fleet/observation-tools/producer_inputs_tests.py
          ${pkgs.python3}/bin/python3 -B -E \
            ${helperSource}/tests/fleet/observation-tools/native_inventory_tests.py
        '';
      }
    ];
  };

  codec = pkgs.mkCargoPackage {
    pname = "aos-storage-body-codec";
    version = "0.1.0";
    src = prepared;
    cargoRoot = "tests/fleet/storage-body-codec";
    cargoDeps = vendor;
    cargoEnv =
      contract.cargoEnv
      // {
        CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS = "true";
        NATIVE_CODEC_REVISION = selected.runtimeCodecRevision;
        NATIVE_WORKER_SOURCE_DIGEST = selected.workerSourceDigest;
        NATIVE_APP_VERSION = "aos-hub ${native.version}";
        NATIVE_BROWSER_HANDLER_SHA256 = selected.browserSource.handlerSourceSha256;
      };
    cargoFlags = "--bin aos-storage-body-codec --features native-bodies";
    cargoTestFlags = "--bin aos-storage-body-codec --features native-bodies";
    buildDeps = [pkgs.perl pkgs.pkg-config pkgs.openssl pkgs.sqlite pkgs.protobuf];
    runtimeDeps = [pkgs.openssl pkgs.sqlite pkgs.zlib];
    doCheck = true;
    sharedBuildCache = false;
  };
in
  assert clientArtifact == null || toString clientArtifact == toString pkgs.aos;
  assert toString nativeArtifact == toString native;
  assert toString workerArtifact == toString worker;
  assert selected.runtimeCodecRevision == sourceCommit;
  assert selected.workerSourceDigest == builtins.hashString "sha256" (toString worker.src);
  assert builtins.match "[0-9a-f]{40}" sourceCommit != null;
  assert builtins.match "[0-9a-f]{40}" sourceTree != null;
    pkgs.mkDerivation {
      pname = "aos-observation-tools";
      version = "0.1.0";
      src = null;
      # Source and wrapper references are intentional, measured build inputs.
      dontNukeRefs = true;
      buildDeps = [pkgs.python3];
      runtimeDeps = [pkgs.python3 pkgs.bash codec];
      phases = [
        {
          name = "install";
          script = ''
            ${pkgs.python3}/bin/python3 -B -E \
              ${helperSource}/tests/fleet/observation-tools/install.py \
              ${prepared} ${helperSource} ${codec} "$out" \
              ${pkgs.python3}/bin/python3 ${pkgs.bash}/bin/bash
          '';
        }
      ];
      passthru = {
        inherit prepared codec;
        runtimeSourceStorePath = toString runtimeSource;
        helperSourceStorePath = toString helperSource;
        runtimeQualification = false;
        selectedNativeArtifact = toString nativeArtifact;
        selectedWorkerArtifact = toString workerArtifact;
      };
    }
