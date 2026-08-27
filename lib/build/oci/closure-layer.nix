##! lib/build/oci/closure-layer.nix -- deterministic Nix-closure OCI layers.
##!
##! `mkClosureLayer` archives the realized reference-graph delta
##! `closure(roots) - closure(subtractRoots)`.  It deliberately consumes Nix's
##! structured `exportReferencesGraph` metadata rather than derivation inputs or
##! declared runtime dependencies, neither of which is authoritative after
##! output reference scrubbing.
{
  lib,
  mkDerivation,
  coreutils,
  findutils,
  gzip,
  jq,
  tar,
  common,
  mkReferenceGraph,
}: {
  roots,
  subtractRoots ? [],
  pname ? "aos-oci-closure-layer",
  layerName ? pname,
}: let
  rootPaths = map (common.validateStorePath "closure root") roots;
  subtractPaths = map (common.validateStorePath "subtracted closure root") subtractRoots;
  validated =
    if !builtins.isList roots || !builtins.isList subtractRoots
    then common.fail "roots and subtractRoots must be lists"
    else if builtins.match "^[A-Za-z0-9][A-Za-z0-9._-]*$" layerName == null
    then common.fail "layerName is invalid"
    else if builtins.length rootPaths != builtins.length (lib.unique rootPaths)
    then common.fail "roots contains a duplicate store path"
    else if builtins.length subtractPaths != builtins.length (lib.unique subtractPaths)
    then common.fail "subtractRoots contains a duplicate store path"
    else true;
  referenceGraph = mkReferenceGraph {
    rootPaths = roots;
    subtractPaths = subtractRoots;
    pname = "${pname}-reference-graph";
  };
in
  builtins.deepSeq validated (mkDerivation {
    inherit pname;
    version = "1";
    src = null;

    buildDeps = [coreutils findutils gzip jq tar referenceGraph];

    outputChecks.out = {};

    # closure.json intentionally names embedded /nix/store paths.  The OCI
    # artifact contains their bytes already, so retaining the host copies as
    # output references would make the supposedly self-contained artifact drag
    # a second copy of its entire input closure through Nix.
    unsafeDiscardReferences.out = true;
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "build";
        script = ''
          set -eu
          export LC_ALL=C
          export SOURCE_DATE_EPOCH=1
          umask 022

          ${common.archiveScript}
          ${common.jsonScript}
          verify_archive_tools

          mkdir -p root/nix/store "$out"

          jq -e '
            .schema == "aos.reference-graph/v1"
            and (.paths | map(.path) | length) == (.paths | map(.path) | unique | length)
          ' ${referenceGraph}/inventory.json >/dev/null

          jq -r '.paths[].path' ${referenceGraph}/inventory.json | while IFS= read -r store_path; do
            case "$store_path" in
              /nix/store/*) ;;
              *)
                echo "closure graph contains a non-canonical store path: $store_path" >&2
                exit 1
                ;;
            esac
            store_name=''${store_path#/nix/store/}
            case "$store_name" in
              ""|*/*)
                echo "closure graph path escapes /nix/store: $store_path" >&2
                exit 1
                ;;
            esac
            if [ ! -e "$store_path" ] && [ ! -L "$store_path" ]; then
              echo "realized closure path is absent: $store_path" >&2
              exit 1
            fi
            destination="root/nix/store/$store_name"
            if [ -e "$destination" ] || [ -L "$destination" ]; then
              echo "closure store-path collision: $store_name" >&2
              exit 1
            fi
            cp -a --reflink=auto --no-preserve=ownership "$store_path" "$destination"
          done

          make_gzip_layer root members layer.tar "$out/blob"

          diffid_hex=$(sha256sum layer.tar | cut -d ' ' -f 1)
          diffid_size=$(stat -c %s layer.tar)
          blob_hex=$(sha256sum "$out/blob" | cut -d ' ' -f 1)
          blob_size=$(stat -c %s "$out/blob")
          printf 'sha256:%s' "$diffid_hex" > "$out/diffid"
          printf '%s' "$diffid_size" > "$out/uncompressed-size"
          printf 'sha256:%s' "$blob_hex" > "$out/blob-digest"
          printf '%s' "$blob_size" > "$out/blob-size"

          jq -S -n \
            --arg mediaType ${lib.escapeShellArg common.layerMediaType} \
            --arg digest "sha256:$blob_hex" \
            --argjson size "$blob_size" \
            '{mediaType: $mediaType, digest: $digest, size: $size}' \
            > descriptor.pretty.json
          write_compact_json descriptor.pretty.json "$out/descriptor.json"

          jq -S \
            --arg schema "aos.container.closure-layer/v1" \
            --arg name ${lib.escapeShellArg layerName} \
            --arg digest "sha256:$blob_hex" \
            --arg diffid "sha256:$diffid_hex" \
            --argjson compressedSize "$blob_size" \
            --argjson uncompressedSize "$diffid_size" \
            '{
              schema: $schema,
              layer: {
                name: $name,
                digest: $digest,
                diffID: $diffid,
                compressedSize: $compressedSize,
                uncompressedSize: $uncompressedSize
              },
              roots: .roots,
              subtractRoots: .subtractRoots,
              paths: [
                .paths[] | {
                  path: .path,
                  narHash: .narHash,
                  narSize: .narSize,
                  references: (.references | sort)
                }
              ]
            }' ${referenceGraph}/inventory.json > closure.pretty.json
          write_compact_json closure.pretty.json "$out/closure.json"

          rm -f layer.tar closure.pretty.json descriptor.pretty.json
        '';
      }
    ];

    passthru = {
      ociLayer = true;
      ociClosureLayer = true;
      inherit layerName rootPaths subtractPaths;
      mediaType = common.layerMediaType;
    };

    meta.description = "Deterministic OCI layer for the ${layerName} Nix closure delta";
  })
