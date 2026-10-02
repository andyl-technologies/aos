##! Retains a native image scope and authenticates its exact immutable inputs.
{
  lib,
  pkgs,
  packages,
  packageArtifacts ? lib.packageModules.payloads packages,
  graph,
  retire ? [],
  scope,
  system,
  osRelease ? null,
  inputs ? [],
  withProfileRecords ? false,
  configuration ? [],
  evaluationInput ? null,
  runtimeConfiguration ? [],
}: let
  modules = lib.packageModules;
  compatibility = import ../../../lib/packages/release-compatibility.nix {inherit lib;};
  moduleDependencies = import ../../../lib/packages/module-dependencies.nix;
  resolved = {
    inherit system;
    artifacts = packageArtifacts;
    modules = modules.closure packages;
  };
  sourceLibrary = lib.packageModuleLibrary;
  discard = value: builtins.unsafeDiscardStringContext (builtins.toString value);
  packageClosure = builtins.genericClosure {
    startSet =
      map (package: {
        key = discard package;
        inherit package;
      })
      packages;
    operator = record:
      map (package: {
        key = discard package;
        inherit package;
      })
      (map moduleDependencies.seed (record.package.moduleDeps or [])
        ++ (record.package.runtimeDeps or []));
  };
  artifacts = lib.packageArtifacts;
  packageForArtifact = artifact: let
    candidates = builtins.filter (record: let
      canonical = artifacts.canonicalReference record.package;
    in
      canonical.name
      == artifact.name
      && canonical.version == artifact.version
      && discard record.package == discard artifact.path)
    packageClosure;
    origins = lib.uniqueBy (record:
      builtins.toString (record.package.deploymentArtifact or
        (throw "Image package '${artifact.name}' has no retained native deployment artifact.")))
    candidates;
  in
    if builtins.length origins != 1
    then throw "Image artifact '${artifact.path}' does not resolve to one retained package envelope."
    else (builtins.head origins).package;
  profileRecord = artifact: let
    package = packageForArtifact artifact;
    envelope = package.deploymentArtifact or (throw "Image package '${modules.nameFor package}' has no retained native deployment artifact.");
    documentation = package.documentationArtifact or null;
  in {
    store_path = artifact.path;
    pushed_at = 0;
    pushed_by = "image";
    expires_at = null;
    is_root = true;
    last_accessed = 0;
    access_count = 0;
    apm = {
      name = artifact.name;
      version = artifact.version;
      explicit = builtins.elem (discard artifact.path) (map discard packages);
      registry = "image";
      installed_at = "image";
      held = false;
      source_drv = "";
      source_nar_hash = "";
      deployment = builtins.toString envelope;
      module_documentation =
        if documentation == null
        then null
        else builtins.toString documentation;
      # Image admission authenticates these seeds. Release qualification
      # retains its own probes; their build/test assets are not runtime inputs.
      qualification = null;
      attestation = {};
    };
  };
  profileRecords =
    if withProfileRecords
    then map profileRecord resolved.artifacts
    else [];
  profileRoots = lib.concatMap (record:
    [record.apm.deployment]
    ++ lib.optional (record.apm.module_documentation != null) record.apm.module_documentation
    ++ lib.optional (record.apm.qualification != null) record.apm.qualification)
  profileRecords;
  # Replay files belong to immutable store roots, which admission retains.
  storeRoot = value: let
    file = builtins.toString value;
    match = builtins.match "(/nix/store/[^/]+)(/.*)?" file;
  in
    if match == null
    then throw "Native evaluation inputs must be retained in the Nix store."
    else builtins.substring 0 (builtins.stringLength (builtins.elemAt match 0)) file;
  configurationRoots = map storeRoot (configuration ++ runtimeConfiguration);
  moduleEnvelopeRoots = builtins.attrValues evaluationFile.nativeModuleEnvelopes;
  packageEnvelopeRoots = builtins.attrValues evaluationFile.nativePackageEnvelopes;
  supplementalRoots = evaluationFile.nativeEvaluationInputs.supplementalInputs;
  retainedInputs = lib.uniqueBy builtins.toString (inputs ++ profileRoots ++ moduleEnvelopeRoots ++ packageEnvelopeRoots ++ supplementalRoots ++ configurationRoots ++ [(storeRoot evaluationFile)]);
  evaluationFile =
    if evaluationInput != null
    then evaluationInput
    else
      lib.build.evaluationInput {
        inherit lib pkgs packages packageArtifacts scope system configuration runtimeConfiguration osRelease;
      };
  profileTemplate = writeArtifact {
    name = "aos-image-installed-template";
    destination = "/template.json";
    text = builtins.toJSON profileRecords;
  };
  graphInputs = artifacts.graphInputs {
    inherit graph;
    packageArtifacts = resolved.artifacts;
    packageModules = resolved.modules;
    evaluationInputs = [sourceLibrary] ++ retainedInputs;
  };
  inputRoots = lib.uniqueBy builtins.toString (
    graphInputs ++ builtins.map (artifact: artifact.path) resolved.artifacts
  );
  buildPackages = pkgs.buildPackages;
  runArtifact = lib.build.runArtifact {pkgs = buildPackages;};
  writeArtifact = lib.build.writeArtifact {
    inherit (buildPackages) bash coreutils;
    system = buildPackages.stdenv.buildPlatform.system;
  };
  closureInfo = (lib.build.closureInfo {pkgs = buildPackages;}) {
    rootPaths = inputRoots;
    pname = "aos-image-admission-closure";
  };
  # Nix exports base32 hashes; the authenticated native protocol uses SHA256
  # hex identities. Keep conversion in the source-built Nix implementation.
  normalizedInventory = runArtifact "aos-native-admission-inventory" {} ''
    mkdir -p "$out"
    ${buildPackages.jq}/bin/jq -c '.paths[]' ${closureInfo}/inventory.json |
    while IFS= read -r entry; do
      printf '%s\n' "$entry" > entry.json
      nar_hash=$(${buildPackages.jq}/bin/jq -r .narHash entry.json)
      nar_hash=$(${buildPackages.nix}/bin/nix --extra-experimental-features nix-command \
        hash to-base16 --type sha256 "$nar_hash")
      ${buildPackages.jq}/bin/jq -c --arg hash "sha256:$nar_hash" \
        '.narHash = $hash' entry.json
    done > paths.jsonl
    ${buildPackages.jq}/bin/jq -cs '{paths:.}' paths.jsonl > "$out/inventory.json"
  '';
  receipt = runArtifact "aos-image-admission" {} ''
    ${buildPackages.jq}/bin/jq -c '
      {schema:"aos.package.admission",roots:[.paths[] | .path as $root | {
        storePath:.path,narHash:.narHash,narSize:.narSize,
        references:(.references | map(select(. != $root) | split("/")[-1] | split("-")[0]) | sort | unique)
      }]}
    ' ${normalizedInventory}/inventory.json > "$out"
  '';
  # The authenticated receipt root is its document. Its expected
  # digest is a separate image-owned artifact, avoiding receipt self-identity.
  admissionDigest = runArtifact "aos-image-admission-digest" {} ''
    mkdir -p "$out"
    digest=$(${buildPackages.coreutils}/bin/sha256sum ${receipt})
    printf 'sha256:%s\n' "''${digest%% *}" > "$out/admission-sha256"
  '';
  installed = runArtifact "aos-image-installed" {} ''
    mkdir -p "$out"
    ${buildPackages.jq}/bin/jq -c '.[] | .apm.deployment, (.apm.module_documentation // empty), (.apm.qualification // empty)' ${profileTemplate}/template.json |
    while IFS= read -r encoded; do
      artifact=$(${buildPackages.jq}/bin/jq -r '.' <<EOF
    $encoded
    EOF
      )
      document="$artifact/deployment.json"
      if [ ! -f "$document" ]; then document="$artifact/options.json"; fi
      if [ ! -f "$document" ]; then document="$artifact/qualification.json"; fi
      test -f "$document"
      digest=$(${buildPackages.coreutils}/bin/sha256sum "$document")
      size=$(${buildPackages.coreutils}/bin/wc -c < "$document")
      ${buildPackages.jq}/bin/jq -c --arg root "$artifact" --arg digest "sha256:''${digest%% *}" --argjson size "$size" '
        .paths[] | select(.path == $root) | {
          store_path:.path,nar_hash:.narHash,nar_size:.narSize,
          references:(.references | map(select(. != $root) | split("/")[-1] | split("-")[0]) | sort | unique),
          document_sha256:$digest,document_size:$size
        }
      ' ${normalizedInventory}/inventory.json
    done > "$out/locators.jsonl"
    ${buildPackages.jq}/bin/jq -cs 'map({key:.store_path,value:.}) | from_entries' "$out/locators.jsonl" > "$out/locators.json"
    ${buildPackages.jq}/bin/jq --slurpfile locators "$out/locators.json" '
      map(.apm.deployment as $deployment | .apm.module_documentation as $documentation | .apm.qualification as $qualification |
        .apm.deployment = ($locators[0][$deployment] // error("Unadmitted deployment artifact")) |
        .apm.module_documentation = (if $documentation == null then null else
          ($locators[0][$documentation] // error("Unadmitted documentation artifact")) end) |
        .apm.qualification = (if $qualification == null then null else
          ($locators[0][$qualification] // error("Unadmitted qualification artifact")) end))
    ' ${profileTemplate}/template.json > "$out/installed.json"
  '';
  # Catalogs authenticate sibling outputs and available dependencies without
  # installing them. Selected payload paths and operational graph coercions
  # retain their own contexts; module sources remain authenticated inputs.
  serializedResolved =
    resolved
    // {
      artifacts = map (artifact: artifacts.metadata artifact // {inherit (artifact) path;}) resolved.artifacts;
      modules = map (record:
        record
        // {
          artifacts = {
            package = artifacts.metadata record.artifacts.package;
            dependencies = builtins.mapAttrs (_: artifacts.metadata) record.artifacts.dependencies;
          };
        })
      resolved.modules;
    };
  transaction = {
    schema = "aos.package.transaction";
    inherit scope system graph retire;
    inherit (serializedResolved) artifacts;
    packages = serializedResolved.modules;
    inputs = builtins.map builtins.toString (lib.uniqueBy builtins.toString ([receipt] ++ graphInputs));
  };
  transactionFile = writeArtifact {
    name = "aos-image-transaction";
    destination = "/transaction.json";
    text = builtins.toJSON transaction;
  };
  packagesFile = writeArtifact {
    name = "aos-image-packages";
    destination = "/packages.json";
    text = builtins.toJSON serializedResolved;
  };
  metadata = {
    nativeTransaction = transaction;
    nativeResolvedPackages = resolved;
    nativeDeploymentParts = [closureInfo receipt admissionDigest transactionFile packagesFile] ++ lib.optional (evaluationFile.nativeEvaluationDescriptor or false) evaluationFile ++ lib.optional withProfileRecords installed;
    nativeSourceLibrary = sourceLibrary;
    nativeEvaluationInputs = graphInputs;
    nativeEvaluationDescriptor = evaluationFile;
  };
in
  assert compatibility.checkSeeds packages;
  assert compatibility.checkOsRequirements (compatibility.osRequirements packages) osRelease;
    (runArtifact "aos-${lib.concatStringsSep "-" scope}-deployment" {} ''
      # Validate the complete composed transaction at the same boundary used
      # by runtime activation, before publishing a bootable bundle.
      ${buildPackages.jq}/bin/jq -n \
        --slurpfile packages ${packagesFile}/packages.json \
        --slurpfile transaction ${transactionFile}/transaction.json \
        '{packages: $packages[0], transaction: $transaction[0]}' > check-input.json
      ${buildPackages.aos-deployment-check}/bin/aos-deployment-check < check-input.json

      mkdir -p "$out"
      ln -s ${transactionFile}/transaction.json "$out/transaction.json"
      ln -s ${packagesFile}/packages.json "$out/packages.json"
      ln -s ${receipt} "$out/admission.json"
      ln -s ${admissionDigest}/admission-sha256 "$out/admission-sha256"
      ln -s ${sourceLibrary} "$out/module-library"
      ln -s ${closureInfo}/registration "$out/registration"
      ${lib.optionalString withProfileRecords ''
        ln -s ${installed}/installed.json "$out/installed.json"
      ''}
      ln -s ${evaluationFile} "$out/evaluation.json"
    '')
    // metadata
