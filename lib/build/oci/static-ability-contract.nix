##! lib/build/oci/static-ability-contract.nix -- Static OCI ability contracts.
##!
##! A platform contract is derived from realized RFC-0022 package companions.
##! Container contracts preserve their existing schema. Bootable host and
##! initrd contracts add an explicit execution stage so an artifact cannot
##! claim that a later manager satisfies an early consumer. Every form retains
##! unresolved required bindings while carrying no runtime grants.
{
  lib,
  mkDerivation,
  coreutils,
  findutils,
  gzip,
  jq,
  tar,
  common,
}: {
  platform ? null,
  packages ? [],
  runtimeRoots ? [],
  contracts ? [],
  pname ? "aos-container-static-ability-contract",
  artifactClass ? "container",
  executionStage ? null,
}: let
  supportedArtifactClasses = ["container" "bootable"];
  supportedExecutionStages = ["initrd" "host"];
  schema =
    if artifactClass == "container"
    then "aos.container.static-abilities/v1"
    else "aos.boot.static-abilities/v1";
  mediaType =
    if artifactClass == "container"
    then "application/vnd.aos.container.static-abilities.v1+json"
    else "application/vnd.aos.boot.static-abilities.v1+json";
  packagePaths =
    map (entry: {
      payload = builtins.toString entry.payload;
      manifest = builtins.toString entry.manifest;
    })
    packages;
  contractPaths = map builtins.toString contracts;
  platformMode = platform != null && contracts == [];
  combinedMode = platform == null && packages == [] && runtimeRoots == [] && contracts != [];
  checkedArtifactClass =
    if builtins.elem artifactClass supportedArtifactClasses
    then artifactClass
    else common.fail "static ability contract artifactClass must be container or bootable";
  checkedExecutionStage =
    if artifactClass == "container" && executionStage == null
    then null
    else if artifactClass == "bootable" && builtins.elem executionStage supportedExecutionStages
    then executionStage
    else common.fail "bootable static ability contracts require an initrd or host executionStage";
  checkedPlatform =
    if platformMode
    then common.validatePlatform platform
    else null;
  checkedPackages =
    if
      lib.all (entry:
        builtins.isAttrs entry
        && (entry.manifest.passthru.abilityPackage or false))
      packages
      && lib.all (entry:
        builtins.toString entry.payload
        == builtins.toString entry.manifest.passthru.abilityPackagePayload)
      packages
      && lib.all (entry: builtins.elem (builtins.toString entry.payload) runtimeRootPaths) packages
      && builtins.length packagePaths == builtins.length (lib.unique (map (entry: entry.manifest) packagePaths))
    then packagePaths
    else common.fail "static ability contract packages must name unique AOS ability companions";
  checkedContracts =
    if
      lib.all (contract:
        builtins.isAttrs contract
        && (contract.passthru.ociStaticAbilityContract or false)
        && contract.passthru.artifactClass == checkedArtifactClass
        && contract.passthru.executionStage == checkedExecutionStage)
      contracts
    then contractPaths
    else common.fail "static ability contract inputs must be produced by mkStaticAbilityContract";
  runtimeRootPaths = map builtins.toString runtimeRoots;
  checkedRuntimeRoots =
    if
      platformMode
      && lib.all (root: builtins.isAttrs root && root ? outPath) runtimeRoots
      && builtins.length runtimeRootPaths == builtins.length (lib.unique runtimeRootPaths)
    then runtimeRoots
    else if combinedMode
    then []
    else common.fail "static ability contract runtimeRoots must contain unique derivations";
  validated =
    if platformMode || combinedMode
    then
      builtins.deepSeq [
        checkedArtifactClass
        checkedExecutionStage
        checkedPlatform
        checkedPackages
        checkedRuntimeRoots
        checkedContracts
      ]
      true
    else common.fail "static ability contract requires exactly one platform package set or a non-empty contract set";
  contractSpec = {
    mode =
      if platformMode
      then "platform"
      else "combine";
    inherit mediaType schema artifactClass executionStage;
    platform = checkedPlatform;
    packages = checkedPackages;
    contracts = checkedContracts;
  };
  inputArguments = lib.concatMapStringsSep " " lib.escapeShellArg (
    if platformMode
    then map (entry: entry.manifest) checkedPackages
    else checkedContracts
  );
  executionStageArgument =
    if executionStage == null
    then ""
    else executionStage;
in
  builtins.deepSeq validated (mkDerivation {
    inherit pname;
    version = "1";
    src = null;
    buildDeps = [coreutils jq];
    exportReferencesGraph.staticAbilityRuntime = checkedRuntimeRoots;

    outputChecks.out = {};
    inherit contractSpec;
    unsafeDiscardReferences.out = true;
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "assemble";
        script = ''
          set -eu
          export LC_ALL=C
          umask 022

          mkdir -p "$out"
          jq '.contractSpec' "$NIX_ATTRS_JSON_FILE" > contract-spec.json

          if [ "$(jq -r .mode contract-spec.json)" = platform ]; then
            jq -cS '[.staticAbilityRuntime[].path] | sort | unique' \
              "$NIX_ATTRS_JSON_FILE" > runtime-paths.json
            : > packages.jsonl
            : > abilities.jsonl
            : > obligations.jsonl

            for manifest_path in ${inputArguments}; do
              manifest="$manifest_path/package.json"
              test -f "$manifest"
              expected_payload=$(jq -er \
                --arg manifest "$manifest_path" '
                  [.packages[] | select(.manifest == $manifest) | .payload]
                  | if length == 1 then .[0] else error("missing selected package") end
                ' contract-spec.json)
              jq -e '
                def digest: type == "string" and test("^sha256:[0-9a-f]{64}$");
                def local_key: type == "string" and length > 0 and length <= 128
                  and test("^[A-Za-z0-9._-]+$");
                def interface:
                  (keys | sort) == ["abi", "descriptor", "name"]
                  and (.name | local_key)
                  and (.abi | type == "number" and . >= 1 and . <= 4294967295 and floor == .)
                  and (.descriptor | digest);
                def guarantee:
                  (keys | sort) == ["descriptor", "name", "version"]
                  and (.name | local_key)
                  and (.version | type == "number" and . >= 1 and . <= 4294967295 and floor == .)
                  and (.descriptor | digest);
                def requirement:
                  (keys | sort) == [
                    "accepted_interfaces", "alias", "fallback", "guarantees", "methods", "strength"
                  ]
                  and (.alias | local_key)
                  and (.accepted_interfaces | type == "array" and length > 0 and all(.[]; interface))
                  and (.methods | type == "array" and all(.[]; local_key))
                  and (.guarantees | type == "array" and all(.[]; guarantee))
                  and (
                    (.strength == "required" and .fallback == null)
                    or (.strength == "advisory" and (.fallback | type == "object"))
                  );
                .schema == "aos.ability.package/v1"
                and (.package.name | type == "string" and length > 0)
                and (.package.version | type == "string" and length > 0)
                and (.package.payload.store_path | type == "string")
                and (.exports | type == "array")
                and (.requirements | type == "array")
                and (.implementation.providers | type == "array")
                and all(.requirements[]; requirement)
                and all(.implementation.providers[];
                  (.interface | interface)
                  and (.artifact.store_path | type == "string")
                  and (.requirements | type == "array" and all(.[]; requirement))
                )
              ' "$manifest" >/dev/null
              jq -e \
                --arg payload "$expected_payload" \
                --slurpfile runtime runtime-paths.json '
                  .package.payload.store_path == $payload
                  and any($runtime[0][]; . == $payload)
                ' "$manifest" >/dev/null || {
                  echo "ability companion payload is not the selected image package: $manifest_path" >&2
                  exit 1
                }

              manifest_hex=$(sha256sum "$manifest" | cut -d ' ' -f 1)
              package_identity=$(jq -cS \
                --arg manifestStorePath "$manifest_path" \
                --arg manifestDigest "sha256:$manifest_hex" '
                  {
                    name: .package.name,
                    version: .package.version,
                    payload: .package.payload,
                    manifest: {
                      store_path: $manifestStorePath,
                      digest: $manifestDigest
                    }
                  }
                ' "$manifest")
              printf '%s\n' "$package_identity" >> packages.jsonl

              jq -cS \
                --argjson package "$package_identity" \
                --slurpfile runtime runtime-paths.json '
                  . as $manifest
                  | .exports[]
                  | . as $export
                  | [$manifest.implementation.providers[] | select(.interface == $export.interface)] as $providers
                  | if ($providers | length) != 1
                    then error("ability export does not have one matching provider")
                    else $providers[0]
                    end as $provider
                  | {
                      package: $package.manifest,
                      export: .name,
                      interface: .interface,
                      implementation: .implementation,
                      implementation_artifact: $provider.artifact,
                      availability: (
                        if any($runtime[0][]; . == $provider.artifact.store_path)
                        then "baked"
                        else "unresolved-at-launch"
                        end
                      )
                    }
                ' "$manifest" >> abilities.jsonl

              jq -cS \
                --argjson package "$package_identity" '
                  .requirements[]
                  | select(.strength == "required")
                  | {
                      kind: "ability-requirement",
                      consumer: {package: $package.manifest},
                      requirement: .,
                      disposition: "external-launch-obligation"
                    }
                ' "$manifest" >> obligations.jsonl

              jq -cS \
                --argjson package "$package_identity" '
                  .implementation.providers[]
                  | . as $provider
                  | .requirements[]
                  | select(.strength == "required")
                  | {
                      kind: "ability-requirement",
                      consumer: {
                        package: $package.manifest,
                        ability: $provider.interface
                      },
                      requirement: .,
                      disposition: "external-launch-obligation"
                    }
                ' "$manifest" >> obligations.jsonl

              jq -cS \
                --argjson package "$package_identity" \
                --slurpfile runtime runtime-paths.json '
                  .implementation.providers[]
                  | . as $provider
                  | select(any($runtime[0][]; . == $provider.artifact.store_path) | not)
                  | {
                      kind: "implementation-artifact",
                      consumer: {
                        package: $package.manifest,
                        ability: .interface
                      },
                      artifact: .artifact,
                      disposition: "external-launch-obligation"
                    }
                ' "$manifest" >> obligations.jsonl
            done

            jq -S -s 'sort_by(.manifest.store_path)' packages.jsonl > packages.json
            jq -S -s 'sort_by(.package.store_path, .interface.name, .interface.abi, .interface.descriptor, .export)' \
              abilities.jsonl > abilities.json
            jq -S -s 'sort_by(.consumer.package.store_path, (.consumer.ability.name // ""), .kind, (.requirement.alias // ""), (.artifact.store_path // ""))' \
              obligations.jsonl > obligations.json
            jq -S -n \
              --slurpfile spec contract-spec.json \
              --slurpfile packageSet packages.json \
              --slurpfile abilitySet abilities.json \
              --slurpfile obligationSet obligations.json '
                {
                  schema: $spec[0].schema,
                  platforms: [({
                      platform: ($spec[0].platform | with_entries(select(.value != null))),
                      packages: $packageSet[0],
                      abilities: $abilitySet[0],
                      unresolved_launch_obligations: $obligationSet[0]
                    } + (
                      if $spec[0].executionStage == null
                      then {}
                      else {execution_stage: $spec[0].executionStage}
                      end
                    ))],
                  runtime_grants: []
                }
              ' > contract.pretty.json
          else
            : > platforms.jsonl
            for contract_path in ${inputArguments}; do
              contract="$contract_path/contract.json"
              test -f "$contract"
              jq -e \
                --arg expectedSchema "$(${jq}/bin/jq -r .schema contract-spec.json)" \
                --arg artifactClass ${lib.escapeShellArg artifactClass} \
                --arg executionStage ${lib.escapeShellArg executionStageArgument} '
                .schema == $expectedSchema
                and .runtime_grants == []
                and (.platforms | type == "array" and length > 0)
                and (
                  $artifactClass != "bootable"
                  or all(.platforms[]; .execution_stage == $executionStage)
                )
              ' "$contract" >/dev/null
              jq -c '.platforms[]' "$contract" >> platforms.jsonl
            done

            jq -S -s '
              sort_by(.platform.os, .platform.architecture, (.platform.variant // ""))
              | if (group_by([.platform.os, .platform.architecture, (.platform.variant // "")]) | all(length == 1))
                then .
                else error("static ability contract contains a duplicate platform")
                end
            ' platforms.jsonl > platforms.json
            jq -S -n \
              --slurpfile spec contract-spec.json \
              --slurpfile platforms platforms.json '
                {
                  schema: $spec[0].schema,
                  platforms: $platforms[0],
                  runtime_grants: []
                }
              ' > contract.pretty.json
          fi

          jq -cS . contract.pretty.json > "$out/contract.with-newline.json"
          size=$(stat -c %s "$out/contract.with-newline.json")
          if [ "$size" -le 1 ] || [ "$size" -gt 4194304 ]; then
            echo "static ability contract violates the 4 MiB JSON bound" >&2
            exit 1
          fi
          truncate -s "$((size - 1))" "$out/contract.with-newline.json"
          mv "$out/contract.with-newline.json" "$out/contract.json"

          contract_size=$(stat -c %s "$out/contract.json")
          contract_hex=$(sha256sum "$out/contract.json" | cut -d ' ' -f 1)
          jq -cS -n \
            --arg mediaType ${lib.escapeShellArg mediaType} \
            --arg digest "sha256:$contract_hex" \
            --argjson size "$contract_size" \
            '{mediaType: $mediaType, digest: $digest, size: $size}' \
            > "$out/descriptor.json"

          rm -f *.json *.jsonl
        '';
      }
    ];

    passthru = {
      ociStaticAbilityContract = true;
      inherit mediaType schema artifactClass executionStage checkedPlatform runtimeRootPaths;
      inputContractPaths = contractPaths;
      selectedPayloadPaths = map (entry: entry.payload) packagePaths;
    };

    meta.description = "Closed static ability contract for an AOS OCI artifact";
  })
