##! lib/build/oci/image-layout.nix -- OCI image layout and archive assembly.
##!
##! The assembler treats layer outputs as untrusted build inputs: it verifies
##! descriptor syntax, size, SHA-256, and DiffID shape before copying blobs.  All
##! layout members are regular files, so the result can be copied away from the
##! Nix store without retaining or resolving its input derivations.
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
  layers,
  runtimeAudit,
  abilityContract,
  platform,
  config ? {},
  annotations ? {},
  indexAnnotations ? {},
  referenceName ? null,
  created ? common.normalizedTimestamp,
  pname ? "aos-oci-image",
}: let
  checkedPlatform = common.validatePlatform platform;
  entrypoint = common.validateStringList "config.entrypoint" (config.entrypoint or []);
  cmd = common.validateStringList "config.cmd" (config.cmd or []);
  environment = config.env or {};
  validateEnvironment =
    if !builtins.isAttrs environment
    then common.fail "config.env must be an attribute set"
    else
      lib.mapAttrs (
        name: value:
          if builtins.match "^[A-Za-z_][A-Za-z0-9_]*$" name == null
          then common.fail "invalid environment variable name ${builtins.toJSON name}"
          else common.validateText "config.env.${name}" value
      )
      environment;
  envList = map (name: "${name}=${validateEnvironment.${name}}") (builtins.attrNames validateEnvironment);
  workingDir = common.validatePath "config.workingDir" (config.workingDir or "/work");
  user = config.user or "0:0";
  stopSignal = config.stopSignal or "SIGTERM";
  exposedPorts = config.exposedPorts or [];
  validatePort = port: let
    match =
      if builtins.isString port
      then builtins.match "^([1-9][0-9]*)/(tcp|udp|sctp)$" port
      else null;
    number =
      if match == null
      then 0
      else builtins.fromJSON (builtins.elemAt match 0);
  in
    if match != null && number <= 65535
    then port
    else common.fail "invalid exposed port ${builtins.toJSON port}";
  checkedPorts = map validatePort exposedPorts;
  exposedPortObject = builtins.listToAttrs (map (port: {
      name = port;
      value = {};
    })
    checkedPorts);

  validateAnnotations = context: values: let
    checked =
      if builtins.isAttrs values
      then
        lib.mapAttrs (
          name: value:
            if builtins.match "^[A-Za-z0-9][A-Za-z0-9._/-]*$" name == null
            then common.fail "${context} contains invalid key ${builtins.toJSON name}"
            else if builtins.stringLength name > 1024
            then common.fail "${context} key exceeds 1 KiB"
            else if !builtins.isString value || builtins.stringLength value > 4096
            then common.fail "${context}.${name} exceeds 4 KiB or is not a string"
            else value
        )
        values
      else common.fail "${context} must be an attribute set";
    total =
      builtins.foldl' (
        size: name: size + builtins.stringLength name + builtins.stringLength checked.${name}
      )
      0 (builtins.attrNames checked);
  in
    if total > 65536
    then common.fail "${context} exceeds the 64 KiB aggregate limit"
    else checked;
  checkedAnnotations = validateAnnotations "annotations" annotations;
  checkedIndexAnnotations = validateAnnotations "indexAnnotations" indexAnnotations;
  labels = validateAnnotations "config.labels" (config.labels or {});
  abilityAnnotationNames = [
    "dev.andyl.aos.ability-contract.digest"
    "dev.andyl.aos.ability-contract.media-type"
    "dev.andyl.aos.ability-contract.schema"
  ];
  authoredAbilityAnnotations = builtins.filter (name:
    checkedAnnotations
    ? ${name}
    || checkedIndexAnnotations ? ${name}
    || labels ? ${name})
  abilityAnnotationNames;
  descriptorAnnotations =
    if referenceName == null
    then {}
    else {
      "org.opencontainers.image.ref.name" =
        common.validateTaggedReference "referenceName" referenceName;
    };

  layerPaths = map builtins.toString layers;
  checkedLayers =
    if !builtins.isList layers
    then common.fail "layers must be a list"
    else if builtins.length layers > 64
    then common.fail "an OCI image may contain at most 64 layers"
    else if builtins.length layerPaths != builtins.length (lib.unique layerPaths)
    then common.fail "layers contains the same derivation more than once"
    else if !lib.all (layer: builtins.isAttrs layer && (layer.passthru.ociLayer or false)) layers
    then common.fail "every layer must be produced by the AOS OCI layer API"
    else true;
  checkedRuntimeAudit =
    if builtins.isAttrs runtimeAudit && runtimeAudit ? outPath
    then runtimeAudit
    else common.fail "runtimeAudit must be an AOS runtime-closure-audit derivation";
  checkedAbilityContract =
    if builtins.isAttrs abilityContract && (abilityContract.passthru.ociStaticAbilityContract or false)
    then abilityContract
    else common.fail "abilityContract must be produced by mkStaticAbilityContract";
  validated =
    if !(builtins.isString user && builtins.match "^([0-9]+(:[0-9]+)?|[A-Za-z_][A-Za-z0-9_-]*)$" user != null)
    then common.fail "config.user must be a numeric uid[:gid] or a safe user name"
    else if !(builtins.isString stopSignal && builtins.match "^SIG[A-Z0-9]+$" stopSignal != null)
    then common.fail "config.stopSignal must be a symbolic signal such as SIGTERM"
    else if entrypoint != [] && builtins.head entrypoint == ""
    then common.fail "config.entrypoint[0] must not be empty"
    else if authoredAbilityAnnotations != []
    then common.fail "static ability contract annotations are builder-owned"
    else if checkedAbilityContract.passthru.checkedPlatform != checkedPlatform
    then common.fail "abilityContract platform must exactly match the image platform"
    else builtins.deepSeq [checkedPlatform checkedLayers checkedRuntimeAudit checkedAbilityContract envList checkedPorts checkedAnnotations checkedIndexAnnotations labels] true;

  imageSpec = {
    inherit created;
    platform = checkedPlatform;
    config = {
      Entrypoint = entrypoint;
      Cmd = cmd;
      Env = envList;
      User = user;
      WorkingDir = workingDir;
      StopSignal = stopSignal;
      ExposedPorts = exposedPortObject;
      Labels = labels;
    };
    manifestAnnotations = checkedAnnotations;
    inherit indexAnnotations descriptorAnnotations;
  };
  addLayerScripts =
    lib.concatMapStringsSep "\n" (layer: ''
      add_layer ${lib.escapeShellArg (builtins.toString layer)}
    '')
    layers;
  layerArguments =
    lib.concatMapStringsSep " "
    (layer: lib.escapeShellArg (builtins.toString layer))
    layers;
in
  builtins.deepSeq validated (mkDerivation {
    inherit pname;
    version = "1";
    src = null;
    buildDeps = [coreutils findutils gzip jq tar runtimeAudit checkedAbilityContract] ++ layers;

    outputChecks.out = {};
    inherit imageSpec;
    unsafeDiscardReferences.out = true;
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "assemble";
        script = ''
          set -eu
          export LC_ALL=C
          export SOURCE_DATE_EPOCH=1
          umask 022

          ${common.archiveScript}
          ${common.jsonScript}
          ${common.realizedStorePolicyScript}
          verify_archive_tools

          validate_disjoint_layer_inventories \
            realized-store-paths \
            ${layerArguments}

          mkdir -p "$out/layout/blobs/sha256"
          jq '.imageSpec' "$NIX_ATTRS_JSON_FILE" > image-spec.input.json
          test -f ${checkedAbilityContract}/contract.json
          test -f ${checkedAbilityContract}/descriptor.json
          contract_digest=$(jq -r .digest ${checkedAbilityContract}/descriptor.json)
          contract_media_type=$(jq -r .mediaType ${checkedAbilityContract}/descriptor.json)
          contract_size=$(jq -r .size ${checkedAbilityContract}/descriptor.json)
          contract_hex=''${contract_digest#sha256:}
          test "$(sha256sum ${checkedAbilityContract}/contract.json | cut -d ' ' -f 1)" = "$contract_hex"
          test "$(stat -c %s ${checkedAbilityContract}/contract.json)" -eq "$contract_size"
          jq -e '.schema == "aos.container.static-abilities/v1" and .runtime_grants == []' \
            ${checkedAbilityContract}/contract.json >/dev/null
          jq -e \
            --slurpfile spec image-spec.input.json '
              (.platforms | length) == 1
              and .platforms[0].platform
                == ($spec[0].platform | with_entries(select(.value != null)))
            ' ${checkedAbilityContract}/contract.json >/dev/null || {
              echo "static ability contract platform does not match the image platform" >&2
              exit 1
            }
          jq -r '.platforms[0].packages[].payload.store_path' \
            ${checkedAbilityContract}/contract.json \
            | while IFS= read -r payload_path; do
                grep -Fx "$payload_path" realized-store-paths.allowed >/dev/null || {
                  echo "static ability package payload is absent from the image: $payload_path" >&2
                  exit 1
                }
              done
          jq -r '
            .platforms[0].abilities[]
            | [.implementation_artifact.store_path, .availability]
            | @tsv
          ' ${checkedAbilityContract}/contract.json \
            | while IFS="$(printf '\t')" read -r artifact_path availability; do
                if grep -Fx "$artifact_path" realized-store-paths.allowed >/dev/null; then
                  actual=baked
                else
                  actual=unresolved-at-launch
                fi
                if [ "$availability" != "$actual" ]; then
                  echo "static ability implementation availability does not match the image: $artifact_path" >&2
                  exit 1
                fi
              done
          jq -S \
            --arg digest "$contract_digest" \
            --arg mediaType "$contract_media_type" '
              def contract_annotations: {
                "dev.andyl.aos.ability-contract.digest": $digest,
                "dev.andyl.aos.ability-contract.media-type": $mediaType,
                "dev.andyl.aos.ability-contract.schema": "aos.container.static-abilities/v1"
              };
              .manifestAnnotations += contract_annotations
              | .indexAnnotations += contract_annotations
              | .config.Labels += contract_annotations
            ' image-spec.input.json > image-spec.with-contract.json
          mv image-spec.with-contract.json image-spec.input.json
          cp --reflink=auto ${checkedAbilityContract}/contract.json "$out/static-ability-contract.json"
          cp --reflink=auto ${checkedAbilityContract}/descriptor.json "$out/static-ability-contract.descriptor.json"
          jq -e '.schema == "aos.runtime-closure-audit/v1"' \
            ${runtimeAudit}/report.json >/dev/null
          cp --reflink=auto ${runtimeAudit}/report.json "$out/runtime-closure-audit.json"
          : > layers.jsonl
          : > diffids.jsonl

          add_layer() {
            layer_path="$1"
            test -f "$layer_path/blob"
            test -f "$layer_path/descriptor.json"
            test -f "$layer_path/diffid"
            test -f "$layer_path/uncompressed-size"

            jq -e \
              --arg mediaType ${lib.escapeShellArg common.layerMediaType} '
                type == "object"
                and .mediaType == $mediaType
                and (.digest | test("^sha256:[0-9a-f]{64}$"))
                and (.size | type == "number" and . >= 0 and floor == .)
              ' "$layer_path/descriptor.json" >/dev/null

            layer_digest=$(jq -r .digest "$layer_path/descriptor.json")
            layer_hex=''${layer_digest#sha256:}
            layer_size=$(jq -r .size "$layer_path/descriptor.json")
            actual_hex=$(sha256sum "$layer_path/blob" | cut -d ' ' -f 1)
            actual_size=$(stat -c %s "$layer_path/blob")
            if [ "$actual_hex" != "$layer_hex" ] || [ "$actual_size" -ne "$layer_size" ]; then
              echo "layer descriptor does not match blob: $layer_path" >&2
              exit 1
            fi

            diffid=$(cat "$layer_path/diffid")
            jq -e -n --arg diffid "$diffid" \
              '$diffid | test("^sha256:[0-9a-f]{64}$")' >/dev/null \
              || { echo "invalid layer DiffID: $diffid" >&2; exit 1; }

            # Do not trust the producer's DiffID sidecar.  The image assembler
            # independently decompresses the exact admitted blob and hashes the
            # resulting tar stream before putting the value into rootfs.diff_ids.
            gzip -t "$layer_path/blob"
            actual_diffid="sha256:$(gzip -dc "$layer_path/blob" | sha256sum | cut -d ' ' -f 1)"
            expected_uncompressed_size=$(cat "$layer_path/uncompressed-size")
            actual_uncompressed_size=$(gzip -dc "$layer_path/blob" | wc -c)
            if [ "$actual_diffid" != "$diffid" ] \
              || [ "$actual_uncompressed_size" -ne "$expected_uncompressed_size" ]; then
              echo "layer DiffID or uncompressed size does not match blob: $layer_path" >&2
              exit 1
            fi

            destination="$out/layout/blobs/sha256/$layer_hex"
            if [ -e "$destination" ]; then
              cmp "$layer_path/blob" "$destination"
            else
              cp --reflink=auto "$layer_path/blob" "$destination"
            fi
            cat "$layer_path/descriptor.json" >> layers.jsonl
            printf '\n' >> layers.jsonl
            jq -c -n --arg diffid "$diffid" '$diffid' >> diffids.jsonl
          }

          ${addLayerScripts}

          jq -s -e 'map(.digest) | length == (unique | length)' layers.jsonl >/dev/null \
            || { echo "two image layers have the same compressed digest" >&2; exit 1; }
          jq -s '.' layers.jsonl > layers.pretty.json
          write_compact_json layers.pretty.json layers.json
          jq -s '.' diffids.jsonl > diffids.pretty.json
          write_compact_json diffids.pretty.json diffids.json

          jq -S -n \
            --slurpfile spec image-spec.input.json \
            --slurpfile diffids diffids.json \
            --slurpfile layersJson layers.json '
              $spec[0] as $specification
              | {
                  created: $specification.created,
                  architecture: $specification.platform.architecture,
                  os: $specification.platform.os,
                  config: ($specification.config | with_entries(select(.value != null))),
                  rootfs: {type: "layers", diff_ids: $diffids[0]},
                  history: [
                    $layersJson[0][] | {
                      created: $specification.created,
                      created_by: "AOS OCI builder layer ABI v2",
                      empty_layer: false
                    }
                  ]
                }
                + (if $specification.platform.variant == null
                   then {}
                   else {variant: $specification.platform.variant}
                   end)
            ' > config.pretty.json
          write_compact_json config.pretty.json "$out/config.json"

          config_hex=$(sha256sum "$out/config.json" | cut -d ' ' -f 1)
          config_size=$(stat -c %s "$out/config.json")
          cp --reflink=auto "$out/config.json" "$out/layout/blobs/sha256/$config_hex"
          jq -S -n \
            --arg mediaType ${lib.escapeShellArg common.configMediaType} \
            --arg digest "sha256:$config_hex" \
            --argjson size "$config_size" \
            '{mediaType: $mediaType, digest: $digest, size: $size}' \
            > config-descriptor.pretty.json
          write_compact_json config-descriptor.pretty.json "$out/config-descriptor.json"

          jq -S -n \
            --arg mediaType ${lib.escapeShellArg common.manifestMediaType} \
            --slurpfile configDescriptor "$out/config-descriptor.json" \
            --slurpfile layersJson layers.json \
            --slurpfile spec image-spec.input.json '
              {
                schemaVersion: 2,
                mediaType: $mediaType,
                config: $configDescriptor[0],
                layers: $layersJson[0],
                annotations: $spec[0].manifestAnnotations
              }
            ' > manifest.pretty.json
          write_compact_json manifest.pretty.json "$out/manifest.json"

          manifest_hex=$(sha256sum "$out/manifest.json" | cut -d ' ' -f 1)
          manifest_size=$(stat -c %s "$out/manifest.json")
          cp --reflink=auto "$out/manifest.json" "$out/layout/blobs/sha256/$manifest_hex"

          jq -S -n \
            --arg mediaType ${lib.escapeShellArg common.manifestMediaType} \
            --arg digest "sha256:$manifest_hex" \
            --argjson size "$manifest_size" \
            --slurpfile spec image-spec.input.json '
              {
                mediaType: $mediaType,
                digest: $digest,
                size: $size,
                platform: ($spec[0].platform | with_entries(select(.value != null)))
              }
              + (if ($spec[0].descriptorAnnotations | length) == 0
                 then {}
                 else {annotations: $spec[0].descriptorAnnotations}
                 end)
            ' > manifest-descriptor.pretty.json
          write_compact_json manifest-descriptor.pretty.json "$out/manifest-descriptor.json"
          cp --reflink=auto image-spec.input.json "$out/image-spec.json"
          write_compact_json "$out/image-spec.json" "$out/image-spec.compact.json"
          mv "$out/image-spec.compact.json" "$out/image-spec.json"

          jq -S -n \
            --arg mediaType ${lib.escapeShellArg common.indexMediaType} \
            --slurpfile manifestDescriptor "$out/manifest-descriptor.json" \
            --slurpfile spec image-spec.input.json '
              {
                schemaVersion: 2,
                mediaType: $mediaType,
                manifests: [$manifestDescriptor[0]],
                annotations: $spec[0].indexAnnotations
              }
            ' > index.pretty.json
          write_compact_json index.pretty.json "$out/layout/index.json"
          printf '%s' '{"imageLayoutVersion":"${common.layoutVersion}"}' > "$out/layout/oci-layout"

          index_hex=$(sha256sum "$out/layout/index.json" | cut -d ' ' -f 1)
          index_size=$(stat -c %s "$out/layout/index.json")
          cp --reflink=auto "$out/layout/index.json" "$out/layout/blobs/sha256/$index_hex"
          jq -S -n \
            --arg mediaType ${lib.escapeShellArg common.indexMediaType} \
            --arg digest "sha256:$index_hex" \
            --argjson size "$index_size" \
            '{mediaType: $mediaType, digest: $digest, size: $size}' \
            > index-descriptor.pretty.json
          write_compact_json index-descriptor.pretty.json "$out/index-descriptor.json"

          make_deterministic_tar "$out/layout" archive-members "$out/image.oci.tar"

          rm -f *.pretty.json layers.json layers.jsonl diffids.json diffids.jsonl \
            image-spec.input.json archive-members members realized-store-paths.*
        '';
      }
    ];

    passthru = {
      ociImage = true;
      inherit checkedPlatform checkedAbilityContract;
      mediaType = common.indexMediaType;
    };

    meta.description = "Self-contained deterministic OCI image layout and archive";
  })
