##! lib/build/oci/evidence-source-graph.nix -- Realized evidence source selector
##!
##! Joins the authoritative realized runtime graph to the evaluated AOS package
##! catalog, then retains the exact source closure of every uniquely mapped
##! runtime output. All evaluated sources are derivation inputs so selection can
##! happen after realization without import-from-derivation; only selected
##! sources remain referenced by the resulting graph.
{
  lib,
  mkDerivation,
  coreutils,
  jq,
}: {
  referenceGraph,
  packageCatalog,
  candidateSources,
  pname ? "aos-evidence-source-reference-graph",
}: let
  discard = value:
    builtins.unsafeDiscardStringContext (builtins.toString value);
  sourcePaths = map discard candidateSources;
  validStorePath = path:
    builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+$" path != null;
  checkedReferenceGraph =
    if builtins.isAttrs referenceGraph && (referenceGraph.passthru.referenceGraph or false)
    then referenceGraph
    else throw "evidence-source-graph: referenceGraph must be produced by mkReferenceGraph";
  checkedCatalog =
    if builtins.isList packageCatalog
    then packageCatalog
    else throw "evidence-source-graph: packageCatalog must be a list";
  validated =
    if !builtins.isList candidateSources
    then throw "evidence-source-graph: candidateSources must be a list"
    else if !lib.all validStorePath sourcePaths
    then throw "evidence-source-graph: every candidate source must be a canonical /nix/store path"
    else if builtins.length sourcePaths != builtins.length (lib.unique sourcePaths)
    then throw "evidence-source-graph: duplicate candidateSources entry"
    else true;
in
  builtins.deepSeq [validated checkedReferenceGraph checkedCatalog] (mkDerivation {
    inherit pname;
    version = "1";
    src = null;
    buildDeps = [coreutils jq checkedReferenceGraph];

    exportReferencesGraph.candidates = candidateSources;
    outputChecks.out = {};
    inherit packageCatalog;
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "select";
        script = ''
          set -eu
          export LC_ALL=C
          mkdir -p "$out"

          jq -S '
            .packageCatalog
            | sort_by(.output.path, .pname, .version, .attribute)
            | group_by(.output.path)
            | map(
                . as $entries
                | ($entries | map(select(.aliasOnly == false))) as $primary
                | {
                    outputPath: $entries[0].output.path,
                    aliases: ($entries | map(.attribute) | unique | sort),
                    candidates: (
                      (if ($primary | length) > 0 then $primary else $entries end)
                      | map(del(.attribute, .aliasOnly))
                      | unique_by([.derivationPath, .pname, .version, .licenses, .sources, .output])
                      | sort_by(.pname, .version, .output.name, .derivationPath)
                    )
                  }
              )
            | sort_by(.outputPath)
          ' "$NIX_ATTRS_JSON_FILE" > package-catalog.json

          # An explicit override is definition-level reviewed attribution, not
          # a fallback guess. It must cover exactly one realized runtime path
          # and must not compete with an evaluated package candidate.
          jq -e \
            --slurpfile runtime "$AOS_EVIDENCE_RUNTIME_GRAPH/inventory.json" '
              .packageCatalog as $catalog
              | [$catalog[] | select(.override == true)] as $overrides
              | ([ $overrides[].output.path ] | length)
                == ([ $overrides[].output.path ] | unique | length)
              and all(
                $overrides[];
                . as $override
                |
                ([ $runtime[0].paths[] | select(.path == $override.output.path) ] | length) == 1
                and ([
                  $catalog[]
                  | select(.override == false and .output.path == $override.output.path)
                ] | length) == 0
              )
            ' "$NIX_ATTRS_JSON_FILE" >/dev/null

          jq -S \
            --slurpfile catalog package-catalog.json '
              [
                .paths[] as $path
                | ([ $catalog[0][] | select(.outputPath == $path.path) ][0] // null) as $match
                | select($match != null and ($match.candidates | length) == 1)
                | $match.candidates[0].sources[].path
              ]
              | sort
              | unique
            ' "$AOS_EVIDENCE_RUNTIME_GRAPH/inventory.json" > selected-roots.json

          jq '.candidates' "$NIX_ATTRS_JSON_FILE" > candidate-graph.json
          jq -e '
            ([.[].path] | length) == ([.[].path] | unique | length)
            and all(.[]; (.path | test("^/nix/store/[0-9a-z]{32}-[^/]+$")))
          ' candidate-graph.json >/dev/null

          jq -e \
            --slurpfile candidates candidate-graph.json '
              all(.[]; . as $root | any($candidates[0][]; .path == $root))
            ' selected-roots.json >/dev/null

          jq -S \
            --slurpfile roots selected-roots.json '
              def closure($graph; $seen):
                ([
                  $graph[]
                  | select(.path as $path | ($seen | index($path)) != null)
                  | .references[]
                ] | sort | unique) as $references
                | (($seen + $references) | sort | unique) as $next
                | if $next == $seen then $seen else closure($graph; $next) end;
              closure(.; $roots[0])
            ' candidate-graph.json > selected-paths.json

          jq -e \
            --slurpfile candidates candidate-graph.json '
              all(.[]; . as $path | any($candidates[0][]; .path == $path))
            ' selected-paths.json >/dev/null
          jq -S \
            --slurpfile selected selected-paths.json '
              [ .[] | select(.path as $path | ($selected[0] | index($path)) != null) ]
            ' candidate-graph.json > selected-order.json

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
            --slurpfile roots selected-roots.json '
              {
                schema: "aos.reference-graph/v1",
                roots: $roots[0],
                subtractRoots: [],
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

          rm -f package-catalog.json candidate-graph.json selected-roots.json \
            selected-paths.json selected-order.json inventory.pretty.json
        '';
      }
    ];

    AOS_EVIDENCE_RUNTIME_GRAPH = builtins.toString checkedReferenceGraph;
    passthru.referenceGraph = true;
    meta.description = "Exact realized source graph for OCI container evidence";
  })
