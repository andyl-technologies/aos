##! lib/build/reference-graph.nix -- realized closure inventory primitive.
##!
##! Produces the authoritative realized reference-graph delta for `rootPaths`
##! minus `subtractPaths`.  Both the legacy Nix database registration builder
##! and OCI layer builders consume this one representation, so build-only inputs
##! and scrubbed output references cannot be mistaken for runtime closure facts.
{
  lib,
  mkDerivation,
  coreutils,
  jq,
}: {
  rootPaths,
  subtractPaths ? [],
  pname ? "aos-reference-graph",
}: let
  roots = map builtins.toString rootPaths;
  subtract = map builtins.toString subtractPaths;
  validStorePath = path: builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+$" path != null;
  validated =
    if !builtins.isList rootPaths || !builtins.isList subtractPaths
    then throw "reference-graph: rootPaths and subtractPaths must be lists"
    else if !lib.all validStorePath (roots ++ subtract)
    then throw "reference-graph: every root must be a canonical /nix/store path"
    else if builtins.length roots != builtins.length (lib.unique roots)
    then throw "reference-graph: duplicate rootPaths entry"
    else if builtins.length subtract != builtins.length (lib.unique subtract)
    then throw "reference-graph: duplicate subtractPaths entry"
    else true;
in
  builtins.deepSeq validated (mkDerivation {
    inherit pname;
    version = "1";
    src = null;
    buildDeps = [coreutils jq];

    outputChecks.out = {};
    exportReferencesGraph = {
      roots = rootPaths;
      subtract = subtractPaths;
    };

    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "build";
        script = ''
          set -eu
          export LC_ALL=C
          mkdir -p "$out"

          jq -e '
            (.roots | map(.path) | length) == (.roots | map(.path) | unique | length)
            and
            (.subtract | map(.path) | length) == (.subtract | map(.path) | unique | length)
          ' "$NIX_ATTRS_JSON_FILE" >/dev/null

          # The exported graph can include build inputs that are not reachable
          # from the requested output roots. Follow exact runtime references
          # before writing registration records or a filesystem inventory.
          jq \
            --argjson requestedRoots ${lib.escapeShellArg (builtins.toJSON roots)} \
            --argjson requestedSubtractRoots ${lib.escapeShellArg (builtins.toJSON subtract)} '
            def reachable($by_path; $pending; $seen):
              if ($pending | length) == 0 then
                $seen
              else
                ($pending[-1]) as $path
                | if $seen[$path] then
                    reachable($by_path; $pending[:-1]; $seen)
                  else
                    ($by_path[$path] // error("reference graph is missing " + $path)) as $entry
                    | reachable(
                        $by_path;
                        ($pending[:-1] + $entry.references);
                        ($seen + {($path): true})
                      )
                  end
              end;

            (.roots | INDEX(.path)) as $root_index
            | (.subtract | INDEX(.path)) as $subtract_index
            | reachable($root_index; $requestedRoots; {}) as $selected
            | reachable($subtract_index; $requestedSubtractRoots; {}) as $subtracted
            | [.roots[] | select($selected[.path] and ($subtracted[.path] | not))]
          ' "$NIX_ATTRS_JSON_FILE" > selected-order.json

          selected_count=$(jq 'length' selected-order.json)
          if [ "$selected_count" -eq 0 ]; then
            : > "$out/registration"
            : > "$out/store-paths"
          else
            jq -r '
              map([.path, .narHash, .narSize, "", (.references | length)] + .references)
              | add
              | map("\(.)\n")
              | add
            ' selected-order.json | head -n -1 > "$out/registration"
            jq -r '.[].path' selected-order.json | sort > "$out/store-paths"
          fi

          jq -S \
            --arg schema "aos.reference-graph/v1" \
            --argjson roots ${lib.escapeShellArg (builtins.toJSON roots)} \
            --argjson subtractRoots ${lib.escapeShellArg (builtins.toJSON subtract)} '
              {
                schema: $schema,
                roots: $roots,
                subtractRoots: $subtractRoots,
                paths: [
                  .[] | {
                    path: .path,
                    narHash: .narHash,
                    narSize: .narSize,
                    references: (.references | sort)
                  }
                ] | sort_by(.path)
              }
            ' selected-order.json > inventory.pretty.json
          jq -cS . inventory.pretty.json > inventory.with-newline.json
          inventory_size=$(stat -c %s inventory.with-newline.json)
          truncate -s "$((inventory_size - 1))" inventory.with-newline.json
          mv inventory.with-newline.json "$out/inventory.json"

          rm -f selected-order.json inventory.pretty.json
        '';
      }
    ];

    passthru = {
      inherit roots subtract;
      referenceGraph = true;
    };

    meta.description = "Structured realized Nix reference graph and registration stream";
  })
