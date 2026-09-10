##! artifact-consumption-audit - actual-output checks for typed artifact use
##!
##! Produces canonical evidence for one target ELF's startup dependency on an
##! exact shared-library artifact. Artifact identities use the same content,
##! NAR and closure digests as RFC-0022 `ArtifactReference`. The audit inspects
##! realized outputs; dependency metadata alone cannot satisfy it.
{
  pkgs,
  lib,
  name,
  consumer,
  consumerPath,
  provider,
  providerPath,
  targetPlatform,
  soname,
  needed,
  searchPath,
  searchPathKind,
  symbols,
  loader,
  inspector,
}: let
  buildPkgs = pkgs.buildPackages or pkgs;
  localKeyPattern = "[A-Za-z0-9._-]+";
  artifactPathPattern = "/[^\n]+";
  storeDirectoryPattern = "/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\n]+(/[^/\n]+)*";
  storeFilePattern = "/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\n]+(/[^/\n]+)+";
  hasDotComponent = path:
    lib.hasInfix "/../" "${path}/" || lib.hasInfix "/./" "${path}/";
  isCanonicalList = values:
    builtins.isList values
    && values == lib.unique (builtins.sort builtins.lessThan values);
  validSymbol = symbol:
    builtins.isAttrs symbol
    && builtins.attrNames symbol == ["name" "version"]
    && builtins.isString symbol.name
    && builtins.match "[A-Za-z_][A-Za-z0-9_]*" symbol.name != null
    && builtins.isString symbol.version
    && builtins.match "[A-Za-z0-9_.-]+" symbol.version != null;
  symbolLessThan = left: right:
    if left.name != right.name
    then left.name < right.name
    else left.version < right.version;
  checked =
    if builtins.match localKeyPattern name == null
    then throw "artifact consumption audit: name must be a local key"
    else if builtins.match artifactPathPattern consumerPath == null || hasDotComponent consumerPath
    then throw "artifact consumption audit: consumerPath must be absolute within the consumer artifact"
    else if builtins.match artifactPathPattern providerPath == null || hasDotComponent providerPath
    then throw "artifact consumption audit: providerPath must be absolute within the provider artifact"
    else if !(builtins.isAttrs targetPlatform && builtins.attrNames targetPlatform == ["architecture" "system"])
    then throw "artifact consumption audit: targetPlatform must use the RFC-0022 platform identity"
    else if !isCanonicalList needed || needed == []
    then throw "artifact consumption audit: needed must be a sorted, unique non-empty list"
    else if !(builtins.isList searchPath && searchPath != [] && builtins.all (path: builtins.isString path && builtins.match storeDirectoryPattern path != null && !hasDotComponent path) searchPath)
    then throw "artifact consumption audit: searchPath must be a non-empty ordered list of exact Nix store directories"
    else if lib.unique searchPath != searchPath
    then throw "artifact consumption audit: searchPath must not contain duplicates"
    else if !(builtins.elem searchPathKind ["runpath" "rpath"])
    then throw "artifact consumption audit: searchPathKind must be runpath or rpath"
    else if !(builtins.isList symbols && symbols != [] && builtins.all validSymbol symbols && symbols == builtins.sort symbolLessThan symbols && symbols == lib.unique symbols)
    then throw "artifact consumption audit: symbols must contain sorted unique name/version pairs"
    else if !(builtins.isString loader && builtins.match storeFilePattern loader != null && !hasDotComponent loader)
    then throw "artifact consumption audit: loader must be an exact Nix store path"
    else true;
  artifactSpecs = [
    {
      key = "consumer";
      path = builtins.toString consumer;
      graph = "consumerGraph";
    }
    {
      key = "provider";
      path = builtins.toString provider;
      graph = "providerGraph";
    }
  ];
  template = {
    schema = "aos.artifact-consumption.evidence/v1";
    required_features = ["elf-startup-linkage-v1"];
    id = name;
    mechanism = "elf-startup-linkage";
    platforms = {
      build = {
        system = pkgs.stdenv.buildPlatform.constraints.os;
        architecture = pkgs.stdenv.buildPlatform.constraints.cpu;
      };
      host = {
        system = pkgs.stdenv.hostPlatform.constraints.os;
        architecture = pkgs.stdenv.hostPlatform.constraints.cpu;
      };
      target = targetPlatform;
    };
    consumer = {
      artifact = null;
      path = consumerPath;
      sha256 = null;
    };
    provider = {
      artifact = null;
      path = providerPath;
      sha256 = null;
    };
    contract = {
      inherit soname needed symbols loader;
      search_path = searchPath;
      search_path_kind = searchPathKind;
    };
  };
in
  assert checked;
    buildPkgs.mkDerivation {
      pname = "aos-${name}-artifact-consumption-audit";
      version = "1";
      src = null;

      outputChecks = {};
      exportReferencesGraph = {
        consumerGraph = [consumer];
        providerGraph = [provider];
      };
      buildDeps = [
        buildPkgs.bash
        buildPkgs.binutils
        buildPkgs.coreutils
        buildPkgs.gawk
        buildPkgs.grep
        buildPkgs.jq
        buildPkgs.nix
        buildPkgs.sed
        inspector
      ];
      dontStrip = true;
      dontNukeRefs = true;

      artifactSpecsJson = builtins.toJSON artifactSpecs;
      templateJson = builtins.toJSON template;

      phases = [
        {
          name = "audit";
          script = ''
            set -eu
            mkdir -p "$out" work/closures

            canonical_json() {
              source=$1
              destination=$2
              jq -cS . "$source" > "$destination.with-newline"
              size=$(stat -c %s "$destination.with-newline")
              [ "$size" -gt 1 ]
              truncate -s $((size - 1)) "$destination.with-newline"
              mv "$destination.with-newline" "$destination"
            }

            domain_digest() {
              domain=$1
              document=$2
              { printf '%s\0' "$domain"; cat "$document"; } \
                | sha256sum | cut -d ' ' -f 1
            }

            store_hash() {
              base=''${1##*/}
              hash=''${base%%-*}
              printf '%s' "$hash" | grep -Eq '^[0-9abcdfghijklmnpqrsvwxyz]{32}$' \
                || { echo "artifact consumption audit: invalid store path: $1" >&2; exit 1; }
              printf '%s' "$hash"
            }

            jq -r .artifactSpecsJson "$NIX_ATTRS_JSON_FILE" > work/specs.json
            jq -r .templateJson "$NIX_ATTRS_JSON_FILE" > work/template.json
            : > work/references.jsonl

            for spec in $(seq 0 $(($(jq 'length' work/specs.json) - 1))); do
              key=$(jq -r ".[$spec].key" work/specs.json)
              root_path=$(jq -r ".[$spec].path" work/specs.json)
              graph=$(jq -r ".[$spec].graph" work/specs.json)
              jq -c --arg graph "$graph" '.[$graph][]' "$NIX_ATTRS_JSON_FILE" > work/exported-graph.jsonl
              jq -s . work/exported-graph.jsonl > work/exported-graph.json

              # A .drv export graph can contain realized input outputs that
              # are disconnected from the root's ordinary reference edges.
              jq -c --arg root "$root_path" \
                -f ${../../pkgs/build-support/_ability-closure-graph.jq} \
                work/exported-graph.json > work/graph.jsonl

              : > work/closure-members.jsonl
              while IFS= read -r member; do
                member_path=$(printf '%s\n' "$member" | jq -r .path)
                member_nar=$(printf '%s\n' "$member" | jq -r .narHash)
                member_nar_hex=$(nix --extra-experimental-features nix-command hash convert \
                  --hash-algo sha256 --to base16 "$member_nar")
                references='[]'
                while IFS= read -r reference; do
                  [ -n "$reference" ] || continue
                  # Registry reference lists omit a member's own edge while retaining the member.
                  [ "$reference" != "$member_path" ] || continue
                  reference_hash=$(store_hash "$reference")
                  references=$(printf '%s\n' "$references" \
                    | jq -c --arg value "$reference_hash" '. + [$value] | sort | unique')
                done <<EOF
            $(printf '%s\n' "$member" | jq -r '.references[]')
            EOF
                jq -cn \
                  --arg store_path "$member_path" \
                  --arg nar_hash "sha256:$member_nar_hex" \
                  --argjson nar_size "$(printf '%s\n' "$member" | jq -r .narSize)" \
                  --argjson references "$references" \
                  '{store_path:$store_path,nar_hash:$nar_hash,nar_size:$nar_size}
                   + if $references == [] then {} else {references:$references} end' \
                  >> work/closure-members.jsonl
              done < work/graph.jsonl

              jq -cs 'sort_by(.store_path)' work/closure-members.jsonl > work/closure.json
              canonical_json work/closure.json work/closure.canonical.json
              closure="sha256:$(domain_digest aos.ability.closure/v1 work/closure.canonical.json)"
              root_member=$(jq -ce --arg path "$root_path" 'select(.path == $path)' work/graph.jsonl)
              root_nar=$(printf '%s\n' "$root_member" | jq -r .narHash)
              root_nar_hex=$(nix --extra-experimental-features nix-command hash convert \
                --hash-algo sha256 --to base16 "$root_nar")
              jq -cn --arg store_path "$root_path" --arg nar_hash "sha256:$root_nar_hex" \
                '{store_path:$store_path,nar_hash:$nar_hash}' > work/artifact-content.json
              canonical_json work/artifact-content.json work/artifact-content.canonical.json
              content="sha256:$(domain_digest aos.ability.artifact/v1 work/artifact-content.canonical.json)"

              jq -cn --arg key "$key" --arg content "$content" --arg store_path "$root_path" \
                --arg nar_hash "sha256:$root_nar_hex" --arg closure "$closure" \
                '{key:$key,value:{content:$content,store_path:$store_path,nar_hash:$nar_hash,closure:$closure}}' \
                >> work/references.jsonl
            done

            jq -cs 'map({key:.key,value:.value}) | from_entries' work/references.jsonl \
              > work/references.json
            jq --slurpfile references work/references.json \
              '.consumer.artifact = $references[0].consumer
               | .provider.artifact = $references[0].provider' \
              work/template.json > work/config.json

            jq -e --arg provider ${lib.escapeShellArg (builtins.toString provider)} \
              '.consumerGraph | any(.path == $provider)' "$NIX_ATTRS_JSON_FILE" >/dev/null \
              || { echo "artifact consumption audit: consumer closure does not retain provider" >&2; exit 1; }

            ${buildPkgs.bash}/bin/bash ${./artifact-consumption-elf-check.sh} \
              work/config.json "$out/evidence.json"

            provider_content=$(jq -er .provider.artifact.content "$out/evidence.json")
            ${inspector}/bin/aos ability artifact-consumption "$out/evidence.json" \
              --consumer ${lib.escapeShellArg "${builtins.toString consumer}${consumerPath}"} \
              --provider-content "$provider_content" \
              --format json > "$out/explanation.json"
            jq -e \
              --arg consumer ${lib.escapeShellArg "${builtins.toString consumer}${consumerPath}"} \
              --arg provider_content "$provider_content" \
              '.evidence_schema == "aos.artifact-consumption.evidence/v1"
               and (.consumer.artifact.store_path + .consumer.path) == $consumer
               and .provider.artifact.content == $provider_content
               and .provider_elf_compatible
               and .loader_elf_compatible
               and .search_resolves_exact_provider
               and .provider_retained_by_consumer
               and .provenance == "reported-realized-build-gate"
               and (.limitations | index("no-live-loader-enforcement") != null)
               and (.limitations | index("no-helper-execution-evidence") != null)
               and (.limitations | index("no-build-tool-execution-evidence") != null)
               and (.limitations | index("no-data-input-evidence") != null)' \
              "$out/explanation.json" >/dev/null
          '';
        }
      ];

      meta.description = "Actual ELF artifact-consumption evidence for ${name}";
    }
