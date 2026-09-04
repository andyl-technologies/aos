set -eu
export LC_ALL=C
export SOURCE_DATE_EPOCH=1
umask 022

max_json_bytes=4194304
oci_manifest_media_type=application/vnd.oci.image.manifest.v1+json
oci_index_media_type=application/vnd.oci.image.index.v1+json
empty_media_type=application/vnd.oci.empty.v1+json
verify_archive_tools

write_compact_json() {
  json_source="$1"
  json_destination="$2"
  jq -cS . "$json_source" > "$json_destination.with-newline"
  json_size=$(stat -c %s "$json_destination.with-newline")
  test "$json_size" -gt 0
  truncate -s "$((json_size - 1))" "$json_destination.with-newline"
  mv "$json_destination.with-newline" "$json_destination"
}

copy_verified_blob() {
  source_file="$1"
  expected_hex="$2"
  actual_hex=$(sha256sum "$source_file" | cut -d ' ' -f 1)
  if [ "$actual_hex" != "$expected_hex" ]; then
    echo "evidence blob digest mismatch: $source_file" >&2
    exit 1
  fi
  destination="$out/layout/blobs/sha256/$expected_hex"
  if [ -e "$destination" ]; then
    cmp "$source_file" "$destination"
  else
    cp --reflink=auto "$source_file" "$destination"
  fi
}

# Source inputs are not runtime filesystem layers: preserving their symlinks
# is part of retaining corresponding source. Hardlinks are dereferenced so
# Nix-store optimization cannot affect archive bytes. Keep the frozen tar/gzip
# byte policy, but reject links that could escape an extracted source tree and
# the device/FIFO/socket entries that OCI archives never admit.
make_source_gzip_archive() {
  archive_root="$1"
  member_file="$2"
  tar_output="$3"
  gzip_output="$4"

  special=$(find "$archive_root" -mindepth 1 \
    \( -type b -o -type c -o -type p -o -type s \) -print -quit)
  if [ -n "$special" ]; then
    echo "source archive rejects device, FIFO, and socket entries: $special" >&2
    exit 1
  fi
  archive_root_absolute=$(readlink -m -- "$archive_root")
  unsafe_symlinks="$PWD/unsafe-source-symlinks"
  : > "$unsafe_symlinks"
  find "$archive_root" -type l \
    -exec "$CONFIG_SHELL" -c '
      archive_root=$1
      unsafe_file=$2
      link=$3
      target=$(readlink -- "$link")
      resolved=$(readlink -m -- "$(dirname -- "$link")/$target")
      case "$resolved" in
        "$archive_root"|"$archive_root"/*) ;;
        *) printf "%s\n" "$link" >> "$unsafe_file" ;;
      esac
    ' evidence-source-link-check "$archive_root_absolute" "$unsafe_symlinks" {} \;
  unsafe_symlink=$(head -n 1 "$unsafe_symlinks")
  rm -f "$unsafe_symlinks"
  if [ -n "$unsafe_symlink" ]; then
    echo "source archive rejects an absolute or escaping symlink: $unsafe_symlink" >&2
    exit 1
  fi

  find "$archive_root" -mindepth 1 -printf '%P\0' | sort -z > "$member_file"
  tar \
    -C "$archive_root" \
    --null \
    --verbatim-files-from \
    --no-recursion \
    --format=gnu \
    --mtime=@1 \
    --clamp-mtime \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --no-acls \
    --no-selinux \
    --no-xattrs \
    --hard-dereference \
    -cf "$tar_output" \
    --files-from="$PWD/$member_file"
  gzip -n -9 -c "$tar_output" > "$gzip_output"
}

add_artifact() {
  role="$1"
  artifact_type="$2"
  payload="$3"
  archive_descriptor="${4-}"

  payload_size=$(stat -c %s "$payload")
  if [ "$payload_size" -le 0 ] || [ "$payload_size" -gt "$max_json_bytes" ]; then
    echo "$role evidence payload violates the 4 MiB JSON bound" >&2
    exit 1
  fi
  jq -e . "$payload" >/dev/null

  payload_hex=$(sha256sum "$payload" | cut -d ' ' -f 1)
  copy_verified_blob "$payload" "$payload_hex"
  jq -S -n \
    --arg mediaType "$artifact_type" \
    --arg digest "sha256:$payload_hex" \
    --argjson size "$payload_size" \
    '{mediaType: $mediaType, digest: $digest, size: $size}' \
    > "$role-payload-descriptor.pretty.json"
  write_compact_json \
    "$role-payload-descriptor.pretty.json" \
    "$out/evidence/$role.payload-descriptor.json"

  if [ -n "$archive_descriptor" ]; then
    jq -S -n \
      --slurpfile payloadDescriptor "$out/evidence/$role.payload-descriptor.json" \
      --slurpfile archiveDescriptor "$archive_descriptor" \
      '[$payloadDescriptor[0], $archiveDescriptor[0]]' \
      > "$role-layers.pretty.json"
  else
    jq -S -n \
      --slurpfile payloadDescriptor "$out/evidence/$role.payload-descriptor.json" \
      '[$payloadDescriptor[0]]' \
      > "$role-layers.pretty.json"
  fi
  write_compact_json "$role-layers.pretty.json" "$role-layers.json"

  jq -S -n \
    --arg mediaType "$oci_manifest_media_type" \
    --arg artifactType "$artifact_type" \
    --slurpfile config empty-descriptor.json \
    --slurpfile layers "$role-layers.json" \
    --slurpfile subject index-descriptor.json '
      {
        schemaVersion: 2,
        mediaType: $mediaType,
        artifactType: $artifactType,
        config: $config[0],
        layers: $layers[0],
        subject: $subject[0]
      }
    ' > "$role-manifest.pretty.json"
  write_compact_json "$role-manifest.pretty.json" "$out/evidence/$role.manifest.json"

  manifest_size=$(stat -c %s "$out/evidence/$role.manifest.json")
  if [ "$manifest_size" -le 0 ] || [ "$manifest_size" -gt "$max_json_bytes" ]; then
    echo "$role artifact manifest violates the 4 MiB JSON bound" >&2
    exit 1
  fi
  manifest_hex=$(sha256sum "$out/evidence/$role.manifest.json" | cut -d ' ' -f 1)
  copy_verified_blob "$out/evidence/$role.manifest.json" "$manifest_hex"
  jq -S -n \
    --arg mediaType "$oci_manifest_media_type" \
    --arg artifactType "$artifact_type" \
    --arg digest "sha256:$manifest_hex" \
    --argjson size "$manifest_size" \
    '{
      mediaType: $mediaType,
      artifactType: $artifactType,
      digest: $digest,
      size: $size
    }' > "$role-descriptor.pretty.json"
  write_compact_json "$role-descriptor.pretty.json" "$out/evidence/$role.descriptor.json"
  cat "$out/evidence/$role.descriptor.json" >> referrers.jsonl
  printf '\n' >> referrers.jsonl
}

test -f "$AOS_EVIDENCE_IMAGE/index-descriptor.json"
test -f "$AOS_EVIDENCE_IMAGE/image-index.json"
test -f "$AOS_EVIDENCE_REFERENCE_GRAPH/inventory.json"
test -f "$AOS_EVIDENCE_SOURCE_GRAPH/inventory.json"
test -f "$AOS_EVIDENCE_LAYER_PATHS"

mkdir -p "$out/evidence" "$out/referrers"
cp -R "$AOS_EVIDENCE_IMAGE/layout" "$out/layout"
chmod -R u+w "$out/layout"
cp --reflink=auto "$AOS_EVIDENCE_IMAGE/image-index.json" "$out/image-index.json"
cp --reflink=auto "$AOS_EVIDENCE_IMAGE/index-descriptor.json" index-descriptor.json
cp --reflink=auto index-descriptor.json "$out/index-descriptor.json"

jq -e \
  --arg mediaType "$oci_index_media_type" '
    .mediaType == $mediaType
    and (.digest | test("^sha256:[0-9a-f]{64}$"))
    and (.size | type == "number" and . > 0 and floor == .)
    and (has("platform") | not)
    and (has("artifactType") | not)
  ' index-descriptor.json >/dev/null
index_hex=$(jq -r '.digest | sub("^sha256:"; "")' index-descriptor.json)
index_size=$(jq -r .size index-descriptor.json)
test "$index_size" -le "$max_json_bytes"
test "$(stat -c %s "$out/image-index.json")" -eq "$index_size"
copy_verified_blob "$out/image-index.json" "$index_hex"

jq '.evidenceSpec' "$NIX_ATTRS_JSON_FILE" > evidence-spec.pretty.json
write_compact_json evidence-spec.pretty.json evidence-spec.json
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
' evidence-spec.json > package-catalog.pretty.json
write_compact_json package-catalog.pretty.json package-catalog.json

: > layer-map.jsonl
: > closure-layer-descriptors.jsonl
while IFS= read -r layer_path; do
  test -f "$layer_path/closure.json"
  test -f "$layer_path/descriptor.json"
  jq -e '
    .schema == "aos.container.closure-layer/v1"
    and (.paths | type == "array")
    and ([.paths[].path] | length == (unique | length))
  ' "$layer_path/closure.json" >/dev/null
  jq -e '
    .mediaType == "application/vnd.oci.image.layer.v1.tar+gzip"
    and (.digest | test("^sha256:[0-9a-f]{64}$"))
    and (.size | type == "number" and . > 0 and floor == .)
    and (keys | sort) == ["digest", "mediaType", "size"]
  ' "$layer_path/descriptor.json" >/dev/null
  jq -e \
    --slurpfile descriptor "$layer_path/descriptor.json" '
      .layer.digest == $descriptor[0].digest
      and .layer.compressedSize == $descriptor[0].size
    ' "$layer_path/closure.json" >/dev/null
  layer_hex=$(jq -r '.digest | sub("^sha256:"; "")' "$layer_path/descriptor.json")
  layer_size=$(jq -r .size "$layer_path/descriptor.json")
  layer_blob="$out/layout/blobs/sha256/$layer_hex"
  test -f "$layer_blob"
  test "$(stat -c %s "$layer_blob")" -eq "$layer_size"
  test "$(sha256sum "$layer_blob" | cut -d ' ' -f 1)" = "$layer_hex"
  cat "$layer_path/descriptor.json" >> closure-layer-descriptors.jsonl
  printf '\n' >> closure-layer-descriptors.jsonl
  jq -c '
    .layer as $layer
    | .paths[]
    | {
        path: .path,
        layer: {
          name: $layer.name,
          digest: $layer.digest,
          diffID: $layer.diffID,
          compressedSize: $layer.compressedSize,
          uncompressedSize: $layer.uncompressedSize
        }
      }
  ' "$layer_path/closure.json" >> layer-map.jsonl
done < "$AOS_EVIDENCE_LAYER_PATHS"
jq -s -S . closure-layer-descriptors.jsonl > closure-layer-descriptors.pretty.json
write_compact_json closure-layer-descriptors.pretty.json closure-layer-descriptors.json
jq -s -S 'sort_by(.path)' layer-map.jsonl > layer-map.pretty.json
write_compact_json layer-map.pretty.json layer-map.json

# The first release emits one platform. Bind the ordered closure descriptors
# to the exact runnable child manifest so independently supplied image and
# closure inputs cannot qualify together.
jq -e '
  .schemaVersion == 2
  and .mediaType == "application/vnd.oci.image.index.v1+json"
  and (.manifests | length) == 1
  and .manifests[0].mediaType == "application/vnd.oci.image.manifest.v1+json"
  and (.manifests[0].digest | test("^sha256:[0-9a-f]{64}$"))
  and (.manifests[0].size | type == "number" and . > 0 and floor == .)
  and (.manifests[0].platform.os | type == "string" and length > 0)
  and (.manifests[0].platform.architecture | type == "string" and length > 0)
' "$out/image-index.json" >/dev/null
platform_manifest_hex=$(jq -r '.manifests[0].digest | sub("^sha256:"; "")' "$out/image-index.json")
platform_manifest_size=$(jq -r '.manifests[0].size' "$out/image-index.json")
case "$platform_manifest_hex" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
  *) echo "platform manifest digest is not canonical sha256" >&2; exit 1 ;;
esac
test "${#platform_manifest_hex}" -eq 64
platform_manifest="$out/layout/blobs/sha256/$platform_manifest_hex"
test -f "$platform_manifest"
test "$(stat -c %s "$platform_manifest")" -eq "$platform_manifest_size"
test "$(sha256sum "$platform_manifest" | cut -d ' ' -f 1)" = "$platform_manifest_hex"
test "$platform_manifest_size" -le "$max_json_bytes"
jq -e \
  --slurpfile closureLayers closure-layer-descriptors.json '
    .schemaVersion == 2
    and .mediaType == "application/vnd.oci.image.manifest.v1+json"
    and (.layers | length) >= ($closureLayers[0] | length)
    and .layers[0:($closureLayers[0] | length)] == $closureLayers[0]
  ' "$platform_manifest" >/dev/null

jq -r '.[].path' layer-map.json | sort > layer-paths.sorted
jq -r '.paths[].path' "$AOS_EVIDENCE_REFERENCE_GRAPH/inventory.json" \
  | sort > reference-paths.sorted
if ! cmp layer-paths.sorted reference-paths.sorted; then
  echo "closure evidence layer map does not equal the authoritative reference graph" >&2
  exit 1
fi
duplicate_layer_path=$(uniq -d layer-paths.sorted | head -n 1)
if [ -n "$duplicate_layer_path" ]; then
  echo "closure evidence maps one store path to multiple layers: $duplicate_layer_path" >&2
  exit 1
fi

jq -S \
  --slurpfile catalog package-catalog.json '
    .paths
    | map(
        . as $path
        | ([ $catalog[0][] | select(.outputPath == $path.path) ][0] // null) as $match
        | . + {
            catalog: (
              if $match == null then
                {state: "unmapped", aliases: [], candidates: []}
              elif ($match.candidates | length) != 1 then
                {state: "ambiguous", aliases: $match.aliases, candidates: $match.candidates}
              else
                {
                  state: "mapped",
                  aliases: $match.aliases,
                  package: $match.candidates[0]
                }
              end
            )
          }
      )
    | sort_by(.path)
  ' "$AOS_EVIDENCE_REFERENCE_GRAPH/inventory.json" > joined-inventory.pretty.json
write_compact_json joined-inventory.pretty.json joined-inventory.json

mkdir -p source-root/nix/store
jq -r '.paths[].path' "$AOS_EVIDENCE_SOURCE_GRAPH/inventory.json" \
  | while IFS= read -r source_path; do
      case "$source_path" in
        /nix/store/*) ;;
        *)
          echo "source reference graph contains a non-store path: $source_path" >&2
          exit 1
          ;;
      esac
      source_name=${source_path#/nix/store/}
      case "$source_name" in
        ""|*/*)
          echo "source reference graph contains a non-root store path: $source_path" >&2
          exit 1
          ;;
      esac
      test -e "$source_path" || test -L "$source_path"
      destination="source-root/nix/store/$source_name"
      if [ -e "$destination" ] || [ -L "$destination" ]; then
        echo "source reference graph contains a duplicate path: $source_path" >&2
        exit 1
      fi
      cp -a --reflink=auto --no-preserve=ownership "$source_path" "$destination"
    done
make_source_gzip_archive source-root source-members source.tar "$out/evidence/source.archive.tar.gz"
source_archive_size=$(stat -c %s "$out/evidence/source.archive.tar.gz")
if [ "$source_archive_size" -gt 17179869184 ]; then
  echo "source archive exceeds the 16 GiB first-release blob limit" >&2
  exit 1
fi
source_archive_hex=$(sha256sum "$out/evidence/source.archive.tar.gz" | cut -d ' ' -f 1)
copy_verified_blob "$out/evidence/source.archive.tar.gz" "$source_archive_hex"
jq -S -n \
  --arg mediaType "application/vnd.aos.source-closure.v1.tar+gzip" \
  --arg digest "sha256:$source_archive_hex" \
  --argjson size "$source_archive_size" \
  '{mediaType: $mediaType, digest: $digest, size: $size}' \
  > source-archive-descriptor.pretty.json
write_compact_json \
  source-archive-descriptor.pretty.json \
  "$out/evidence/source.archive-descriptor.json"

jq -S '
  $sourcePaths as $retainedSources
  |
  def source_reason:
    if .catalog.state != "mapped" then .catalog.state
    elif (.catalog.package.sources | length) == 0 then "missing-source-identity"
    elif any(.catalog.package.sources[]; (.path as $path | ($retainedSources | index($path)) == null))
      then "source-not-retained"
    else null
    end;
  def license_reason:
    if .catalog.state != "mapped" then .catalog.state
    elif (.catalog.package.licenses | length) == 0 then "missing-license-metadata"
    else null
    end;
  {
    schema: "aos.container.evidence-qualification/v1",
    mapping: {
      complete: (all(.[]; .catalog.state == "mapped")),
      unknownPaths: [ .[] | select(.catalog.state != "mapped") | {
        path: .path,
        reason: .catalog.state,
        candidates: .catalog.candidates
      } ]
    },
    correspondingSource: {
      complete: (all(.[]; source_reason == null)),
      unknownPaths: [ .[] | source_reason as $reason | select($reason != null) | {
        path: .path,
        reason: $reason
      } ]
    },
    licensing: {
      complete: (all(.[]; license_reason == null)),
      unknownPaths: [ .[] | license_reason as $reason | select($reason != null) | {
        path: .path,
        reason: $reason
      } ]
    }
  }
  | .readyForVerifiedPublication = (
      .mapping.complete
      and .correspondingSource.complete
      and .licensing.complete
    )
' --argjson sourcePaths "$(jq -c '[.paths[].path] | sort' "$AOS_EVIDENCE_SOURCE_GRAPH/inventory.json")" \
  joined-inventory.json > qualification.pretty.json
write_compact_json qualification.pretty.json "$out/qualification.json"

jq -S \
  --slurpfile subject index-descriptor.json \
  --slurpfile graph "$AOS_EVIDENCE_REFERENCE_GRAPH/inventory.json" \
  --slurpfile layers layer-map.json \
  --slurpfile orderedLayers closure-layer-descriptors.json '
    {
      schema: "aos.container.nix-closure/v1",
      subject: $subject[0],
      roots: $graph[0].roots,
      layers: $orderedLayers[0],
      paths: [
        .[] as $path
        | ($layers[0][] | select(.path == $path.path)) as $layer
        | {
            path: $path.path,
            narHash: $path.narHash,
            narSize: $path.narSize,
            references: ($path.references | sort),
            layer: $layer.layer,
            package: (
              if $path.catalog.state == "mapped" then {
                name: $path.catalog.package.pname,
                version: $path.catalog.package.version,
                output: $path.catalog.package.output.name,
                derivationPath: $path.catalog.package.derivationPath,
                aliases: $path.catalog.aliases,
                licenses: $path.catalog.package.licenses,
                sources: $path.catalog.package.sources
              } else null end
            )
          }
      ] | sort_by(.path)
    }
  ' joined-inventory.json > closure.pretty.json
write_compact_json closure.pretty.json "$out/evidence/closure.payload.json"

jq -S \
  --slurpfile subject index-descriptor.json \
  --slurpfile qualification "$out/qualification.json" \
  --slurpfile archive "$out/evidence/source.archive-descriptor.json" \
  --slurpfile sources "$AOS_EVIDENCE_SOURCE_GRAPH/inventory.json" '
    {
      schema: "aos.container.source-closure/v1",
      subject: $subject[0],
      qualification: $qualification[0].correspondingSource,
      archive: $archive[0],
      sourceRoots: $sources[0].roots,
      retainedPaths: [
        $sources[0].paths[] | {
          path: .path,
          narHash: .narHash,
          narSize: .narSize,
          references: (.references | sort)
        }
      ] | sort_by(.path),
      paths: [
        .[] | {
          outputPath: .path,
          narHash: .narHash,
          package: (
            if .catalog.state == "mapped" then {
              name: .catalog.package.pname,
              version: .catalog.package.version,
              output: .catalog.package.output.name,
              derivationPath: .catalog.package.derivationPath
            } else null end
          ),
          sources: (
            if .catalog.state == "mapped"
            then .catalog.package.sources
            else []
            end
          )
        }
      ] | sort_by(.outputPath)
    }
  ' joined-inventory.json > source.pretty.json
write_compact_json source.pretty.json "$out/evidence/source.payload.json"

jq -S \
  --slurpfile subject index-descriptor.json \
  --slurpfile qualification "$out/qualification.json" '
    {
      schema: "aos.container.license-report/v1",
      subject: $subject[0],
      qualification: $qualification[0].licensing,
      paths: [
        .[] | {
          outputPath: .path,
          package: (
            if .catalog.state == "mapped" then {
              name: .catalog.package.pname,
              version: .catalog.package.version,
              output: .catalog.package.output.name
            } else null end
          ),
          licenses: (
            if .catalog.state == "mapped"
            then .catalog.package.licenses
            else []
            end
          )
        }
      ] | sort_by(.outputPath)
    }
  ' joined-inventory.json > license.pretty.json
write_compact_json license.pretty.json "$out/evidence/license.payload.json"

jq -S \
  --arg namespace "https://aos.dev/spdx/container/$index_hex" '
    to_entries as $entries
    | {
        spdxVersion: "SPDX-2.3",
        dataLicense: "CC0-1.0",
        SPDXID: "SPDXRef-DOCUMENT",
        name: "AOS container runtime closure",
        documentNamespace: $namespace,
        creationInfo: {
          created: "1970-01-01T00:00:01Z",
          creators: ["Tool: AOS-Nix-container-evidence-v1"]
        },
        packages: [
          $entries[] | {
            SPDXID: ("SPDXRef-Path-" + ((.key + 1) | tostring)),
            name: (
              if .value.catalog.state == "mapped"
              then .value.catalog.package.pname
              else (.value.path | split("-") | .[1:] | join("-"))
              end
            ),
            versionInfo: (
              if .value.catalog.state == "mapped"
              then .value.catalog.package.version
              else "NOASSERTION"
              end
            ),
            downloadLocation: "NOASSERTION",
            filesAnalyzed: false,
            licenseConcluded: "NOASSERTION",
            # Package metadata remains exact in `comment` and in the signed
            # license artifact. Do not reinterpret non-SPDX legacy tokens as
            # a valid SPDX expression here.
            licenseDeclared: "NOASSERTION",
            copyrightText: "NOASSERTION",
            comment: (
              "Nix output " + .value.path
              + (if .value.catalog.state == "mapped"
                 then "; AOS package metadata license: " + (.value.catalog.package.licenses | join(" AND "))
                 else "; package metadata unavailable"
                 end)
            )
          }
        ],
        relationships: [
          $entries[] | {
            spdxElementId: "SPDXRef-DOCUMENT",
            relationshipType: "DESCRIBES",
            relatedSpdxElement: ("SPDXRef-Path-" + ((.key + 1) | tostring))
          }
        ]
      }
  ' joined-inventory.json > sbom.pretty.json
write_compact_json sbom.pretty.json "$out/evidence/sbom.payload.json"

jq -S -n \
  --arg subjectName "container-image-index" \
  --arg subjectDigest "$index_hex" \
  --slurpfile spec evidence-spec.json \
  --slurpfile qualification "$out/qualification.json" \
  --slurpfile closure "$out/evidence/closure.payload.json" '
    {
      _type: "https://in-toto.io/Statement/v1",
      subject: [{name: $subjectName, digest: {sha256: $subjectDigest}}],
      predicateType: "https://aos.dev/attestations/container-build/v1",
      predicate: {
        builder: {id: "https://aos.dev/builders/nix"},
        buildType: "https://aos.dev/build-types/scratch-container/v1",
        invocation: {
          parameters: {
            definitionAttribute: $spec[0].nix.attribute,
            outputName: $spec[0].nix.outputName
          }
        },
        buildDefinition: {
          derivationPath: $spec[0].nix.derivationPath,
          outputPath: $spec[0].nix.outputPath
        },
        metadata: {
          reproducible: true,
          hermetic: true,
          qualification: $qualification[0]
        },
        materials: [
          $closure[0].paths[] | {
            uri: ("nix:" + .path),
            digest: {narHash: .narHash}
          }
        ]
      }
    }
  ' > provenance.pretty.json
write_compact_json provenance.pretty.json "$out/evidence/provenance.payload.json"

printf '%s' '{}' > empty.json
empty_hex=$(sha256sum empty.json | cut -d ' ' -f 1)
copy_verified_blob empty.json "$empty_hex"
jq -S -n \
  --arg mediaType "$empty_media_type" \
  --arg digest "sha256:$empty_hex" \
  '{mediaType: $mediaType, digest: $digest, size: 2}' \
  > empty-descriptor.pretty.json
write_compact_json empty-descriptor.pretty.json empty-descriptor.json

: > referrers.jsonl
add_artifact closure application/vnd.aos.nix-closure.v1+json "$out/evidence/closure.payload.json"
add_artifact sbom application/spdx+json "$out/evidence/sbom.payload.json"
add_artifact \
  source \
  application/vnd.aos.source-closure.v1+json \
  "$out/evidence/source.payload.json" \
  "$out/evidence/source.archive-descriptor.json"
add_artifact license application/vnd.aos.license-report.v1+json "$out/evidence/license.payload.json"
add_artifact provenance application/vnd.in-toto+json "$out/evidence/provenance.payload.json"

jq -S -s 'sort_by(.artifactType, .digest)' referrers.jsonl > referrers.pretty.json
write_compact_json referrers.pretty.json referrers.json
jq -S -n \
  --arg mediaType "$oci_index_media_type" \
  --slurpfile manifests referrers.json '
    {schemaVersion: 2, mediaType: $mediaType, manifests: $manifests[0]}
  ' > referrers-index.pretty.json
write_compact_json referrers-index.pretty.json "$out/referrers/index.json"

jq -S -n \
  --slurpfile index index-descriptor.json \
  --slurpfile refs referrers.json '
    {schema: "aos.container.publication-roots/v1", image: $index[0], referrers: $refs[0]}
  ' > publication-roots.pretty.json
write_compact_json publication-roots.pretty.json "$out/publication-roots.json"

jq -S -n \
  --slurpfile spec evidence-spec.json \
  --slurpfile index index-descriptor.json \
  --slurpfile imageIndex "$out/image-index.json" \
  --slurpfile closure "$out/evidence/closure.descriptor.json" \
  --slurpfile sbom "$out/evidence/sbom.descriptor.json" \
  --slurpfile source "$out/evidence/source.descriptor.json" \
  --slurpfile license "$out/evidence/license.descriptor.json" \
  --slurpfile provenance "$out/evidence/provenance.descriptor.json" \
  --slurpfile qualification "$out/qualification.json" '
    {
      schema: "aos.container.signature-input/v1",
      identity: $spec[0].identity,
      oci: {
        index: $index[0],
        platformManifests: $imageIndex[0].manifests
      },
      nix: {
        definition: {
          attribute: $spec[0].nix.attribute,
          derivationPath: $spec[0].nix.derivationPath
        },
        output: {
          name: $spec[0].nix.outputName,
          storePath: $spec[0].nix.outputPath
        },
        closure: $closure[0]
      },
      evidence: {
        sbom: $sbom[0],
        source: $source[0],
        license: $license[0],
        provenance: $provenance[0]
      },
      qualification: $qualification[0]
    }
  ' > signature-input.pretty.json
write_compact_json signature-input.pretty.json "$out/signature-input.json"
signature_input_size=$(stat -c %s "$out/signature-input.json")
if [ "$signature_input_size" -le 0 ] || [ "$signature_input_size" -gt "$max_json_bytes" ]; then
  echo "signature input violates the 4 MiB JSON bound" >&2
  exit 1
fi
signature_input_hex=$(sha256sum "$out/signature-input.json" | cut -d ' ' -f 1)

jq -S -n \
  --arg inputDigest "sha256:$signature_input_hex" \
  --argjson inputSize "$signature_input_size" \
  --slurpfile input "$out/signature-input.json" '
    {
      schema: "aos.container.signing-request/v1",
      input: {
        mediaType: "application/vnd.aos.container.signature-input.v1+json",
        digest: $inputDigest,
        size: $inputSize
      },
      requiredOutput: {
        payloadMediaType: "application/vnd.dsse.envelope.v1+json",
        artifactManifestMediaType: "application/vnd.oci.image.manifest.v1+json",
        artifactSubject: $input[0].oci.index,
        finalSidecarPath: "containers/v1/index.json",
        finalSidecarMediaType: "application/vnd.aos.container-release.v1+json"
      },
      constraints: {
        exactInputBytesRequired: true,
        privateMaterialPermittedInNixBuild: false,
        finalizerMustRejectUnqualifiedInput: true,
        finalizerMustVerifyEnvelope: true,
        finalizerMustAddSignatureReferrerDescriptor: true,
        releaseSurfaceMustSignFinalSidecar: true
      },
      qualified: $input[0].qualification.readyForVerifiedPublication,
      unsignedRelease: ($input[0] | del(.schema))
    }
  ' > signing-request.pretty.json
write_compact_json signing-request.pretty.json "$out/signing-request.json"
signing_request_size=$(stat -c %s "$out/signing-request.json")
if [ "$signing_request_size" -le 0 ] || [ "$signing_request_size" -gt "$max_json_bytes" ]; then
  echo "signing request violates the 4 MiB JSON bound" >&2
  exit 1
fi

make_deterministic_tar "$out/layout" archive-members "$out/evidence.oci.tar"
rm -f ./*.pretty.json ./*.jsonl empty.json empty-descriptor.json \
  evidence-spec.json package-catalog.json layer-map.json closure-layer-descriptors.json joined-inventory.json \
  layer-paths.sorted reference-paths.sorted archive-members source-members source.tar
