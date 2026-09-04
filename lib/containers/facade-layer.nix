##! lib/containers/facade-layer.nix -- ordered golden-package PATH facade.
##!
##! The server login PATH is every golden package's `bin` directory in package
##! order followed by every `sbin` directory in that same order.  This builder
##! realizes that policy without import-from-derivation: it scans the already
##! realized roots in its build sandbox, selects the first executable for each
##! name, records every shadowed collision, and emits `/usr/bin` symlinks.
{
  lib,
  pkgs,
  oci,
  packageRoots,
  referenceGraph,
  explicit ? [],
  expectedCollisions ? [],
  pname ? "aos-container-golden-facade",
  layerName ? "golden-facade",
}: let
  rootPaths = map (oci.common.validateStorePath "facade package root") packageRoots;
  normalizeExplicit = index: entry: {
    name = let
      path = oci.common.validatePath "facade explicit[${toString index}].name" "/usr/bin/${entry.name}";
    in
      builtins.baseNameOf path;
    target = oci.common.validateStoreFile "facade explicit[${toString index}].target" entry.target;
  };
  explicitEntries = lib.imap normalizeExplicit explicit;
  checkedExpectedCollisions =
    if
      builtins.isList expectedCollisions
      && lib.all
      (name: builtins.isString name && builtins.match "[A-Za-z0-9][A-Za-z0-9._+-]*" name != null)
      expectedCollisions
      && builtins.length expectedCollisions == builtins.length (lib.unique expectedCollisions)
    then expectedCollisions
    else oci.common.fail "facade expectedCollisions must contain unique executable names";
  validated =
    if packageRoots == []
    then oci.common.fail "facade packageRoots must not be empty"
    else if !builtins.isAttrs referenceGraph || !(referenceGraph.passthru.referenceGraph or false)
    then oci.common.fail "facade referenceGraph must be produced by mkReferenceGraph"
    else if builtins.match "^[A-Za-z0-9][A-Za-z0-9._-]*$" layerName == null
    then oci.common.fail "facade layerName is invalid"
    else builtins.deepSeq [explicitEntries checkedExpectedCollisions] true;
  rootArguments = lib.concatMapStringsSep " " lib.escapeShellArg rootPaths;
  explicitScripts =
    lib.concatMapStringsSep "\n" (entry: ''
      add_candidate \
        ${lib.escapeShellArg entry.name} \
        ${lib.escapeShellArg "explicit:${entry.name}"} \
        ${lib.escapeShellArg entry.target}
    '')
    explicitEntries;
  facadeSpec = {
    schema = "aos.container.facade-policy/v1";
    inherit layerName;
    directoryOrder = ["bin" "sbin"];
    packageRoots = rootPaths;
    explicit = explicitEntries;
    expectedCollisions = checkedExpectedCollisions;
  };
in
  builtins.deepSeq validated (pkgs.mkDerivation {
    inherit pname;
    version = "1";
    src = null;
    buildDeps =
      [
        pkgs.bash
        pkgs.coreutils
        pkgs.findutils
        pkgs.gzip
        pkgs.jq
        pkgs.tar
        referenceGraph
      ]
      ++ packageRoots;

    outputChecks.out = {};
    inherit facadeSpec;
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

          ${oci.common.archiveScript}
          ${oci.common.jsonScript}
          ${oci.common.realizedStorePolicyScript}
          verify_archive_tools

          jq -e '
            .schema == "aos.reference-graph/v1"
            and (.paths | type == "array")
            and ([.paths[].path] | length == (unique | length))
          ' ${referenceGraph}/inventory.json >/dev/null
          jq -r '.paths[].path' ${referenceGraph}/inventory.json \
            | sort -u > allowed-store-paths

          mkdir -p root/usr/bin "$out"
          : > entries.jsonl
          : > collisions.jsonl

          add_candidate() {
            candidate_name="$1"
            candidate_source="$2"
            candidate_path="$3"

            [ -n "$candidate_name" ] \
              || { echo "empty executable name in golden facade" >&2; exit 1; }
            case "$candidate_name" in
              .|..|*/*)
                echo "unsafe executable name in golden facade: $candidate_name" >&2
                exit 1
                ;;
            esac
            jq -e -n --arg name "$candidate_name" \
              '$name | (contains("\\n") or contains("\\r")) | not' >/dev/null \
              || { echo "executable name contains a line separator" >&2; exit 1; }
            if [ ! -f "$candidate_path" ] || [ ! -x "$candidate_path" ]; then
              echo "golden facade candidate is not an executable file: $candidate_path" >&2
              exit 1
            fi
            candidate_target=$(readlink -f "$candidate_path")
            validate_store_symlink_target allowed-store-paths "$candidate_target" 1

            destination="root/usr/bin/$candidate_name"
            if [ -e "$destination" ] || [ -L "$destination" ]; then
              winner_target=$(readlink "$destination")
              if [ "$winner_target" = "$candidate_target" ]; then
                return
              fi
              jq -cS -n \
                --arg name "$candidate_name" \
                --arg winner "$winner_target" \
                --arg shadowed "$candidate_target" \
                --arg shadowedSource "$candidate_source" \
                '{
                  name: $name,
                  winner: $winner,
                  shadowed: $shadowed,
                  shadowedSource: $shadowedSource
                }' >> collisions.jsonl
              return
            fi

            ln -s "$candidate_target" "$destination"
            jq -cS -n \
              --arg name "$candidate_name" \
              --arg source "$candidate_source" \
              --arg target "$candidate_target" \
              '{name: $name, source: $source, target: $target}' >> entries.jsonl
          }

          ${explicitScripts}

          # Keep this loop order byte-for-byte aligned with systemPath:
          # all package bin directories, then all package sbin directories.
          for directory_name in bin sbin; do
            for package_root in ${rootArguments}; do
              candidate_directory="$package_root/$directory_name"
              [ -d "$candidate_directory" ] || continue
              for candidate_path in "$candidate_directory"/*; do
                if [ ! -e "$candidate_path" ] && [ ! -L "$candidate_path" ]; then
                  continue
                fi
                if [ ! -f "$candidate_path" ] || [ ! -x "$candidate_path" ]; then
                  continue
                fi
                candidate_name=''${candidate_path##*/}
                add_candidate \
                  "$candidate_name" \
                  "$package_root/$directory_name/$candidate_name" \
                  "$candidate_path"
              done
            done
          done

          # Compare one line per record, without deduplication: an additional
          # provider for an already reviewed command is a new collision and
          # must fail admission rather than hiding behind the allowed name.
          jq -r '.name' collisions.jsonl > collision-names.actual
          jq -r '.facadeSpec.expectedCollisions[]' "$NIX_ATTRS_JSON_FILE" \
            > collision-names.expected
          if ! cmp collision-names.expected collision-names.actual; then
            echo "golden facade collisions differ from the reviewed policy" >&2
            exit 1
          fi

          jq -s '.' entries.jsonl > entries.pretty.json
          jq -s '.' collisions.jsonl > collisions.pretty.json
          jq -S \
            --slurpfile entries entries.pretty.json \
            --slurpfile collisions collisions.pretty.json \
            '.facadeSpec + {
              entries: $entries[0],
              collisions: $collisions[0]
            }' "$NIX_ATTRS_JSON_FILE" > facade.pretty.json

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
            --arg mediaType ${lib.escapeShellArg oci.common.layerMediaType} \
            --arg digest "sha256:$blob_hex" \
            --argjson size "$blob_size" \
            '{mediaType: $mediaType, digest: $digest, size: $size}' \
            > descriptor.pretty.json
          write_compact_json descriptor.pretty.json "$out/descriptor.json"

          jq -S \
            --arg digest "sha256:$blob_hex" \
            --arg diffid "sha256:$diffid_hex" \
            --argjson compressedSize "$blob_size" \
            --argjson uncompressedSize "$diffid_size" \
            '. + {
              digest: $digest,
              diffID: $diffid,
              compressedSize: $compressedSize,
              uncompressedSize: $uncompressedSize
            }' facade.pretty.json > facade.complete.json
          write_compact_json facade.complete.json "$out/facade.json"

          rm -f \
            layer.tar members allowed-store-paths entries.jsonl collisions.jsonl \
            collision-names.actual collision-names.expected \
            entries.pretty.json collisions.pretty.json facade.pretty.json \
            facade.complete.json descriptor.pretty.json
        '';
      }
    ];

    passthru = {
      ociLayer = true;
      facadeLayer = true;
      inherit layerName;
      mediaType = oci.common.layerMediaType;
    };

    meta.description = "Ordered golden-package executable facade OCI layer";
  })
