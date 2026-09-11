# Bind every declared closure layer to the runnable platform manifests. The
# layer list follows the coordinator's input order, which can differ from the
# canonical platform order in the OCI index.
set -eu

image_index=$1
layout=$2
closure_layers=$3
max_json_bytes=4194304

fail_platform_binding() {
  echo "container evidence platform binding: $1" >&2
  exit 1
}

jq -e '
  .schemaVersion == 2
  and .mediaType == "application/vnd.oci.image.index.v1+json"
  and (.manifests | type == "array" and length > 0)
  and all(.manifests[];
    .mediaType == "application/vnd.oci.image.manifest.v1+json"
    and (.digest | test("^sha256:[0-9a-f]{64}$"))
    and (.size | type == "number" and . > 0 and floor == .)
    and (.platform.os | type == "string" and length > 0)
    and (.platform.architecture | type == "string" and length > 0)
    and (.platform | (has("variant") | not) or (.variant | type == "string" and length > 0))
  )
  and ([.manifests[].digest] | length == (unique | length))
  and ([.manifests[].platform | [.os, .architecture, (.variant // "")]]
    | length == (unique | length))
' "$image_index" >/dev/null \
  || fail_platform_binding "invalid or repeated platform descriptor"

jq -e '
  type == "array" and length > 0
  and all(.[];
    .mediaType == "application/vnd.oci.image.layer.v1.tar+gzip"
    and (.digest | test("^sha256:[0-9a-f]{64}$"))
    and (.size | type == "number" and . > 0 and floor == .)
    and (keys | sort) == ["digest", "mediaType", "size"]
  )
  and ([.[].digest] | length == (unique | length))
' "$closure_layers" >/dev/null \
  || fail_platform_binding "invalid or repeated closure layer descriptor"

jq -c '.manifests[]' "$image_index" > evidence-platform-descriptors.jsonl
: > evidence-bound-layers.jsonl
while IFS= read -r descriptor; do
  manifest_hex=$(printf '%s\n' "$descriptor" | jq -r '.digest | sub("^sha256:"; "")')
  manifest_size=$(printf '%s\n' "$descriptor" | jq -r .size)
  manifest="$layout/blobs/sha256/$manifest_hex"
  test "$manifest_size" -le "$max_json_bytes" \
    || fail_platform_binding "platform manifest exceeds the JSON bound"
  test -f "$manifest" \
    || fail_platform_binding "platform manifest blob is absent"
  test "$(stat -c %s "$manifest")" -eq "$manifest_size" \
    || fail_platform_binding "platform manifest size mismatch"
  test "$(sha256sum "$manifest" | cut -d ' ' -f 1)" = "$manifest_hex" \
    || fail_platform_binding "platform manifest digest mismatch"

  # A platform may have its own closure layers followed by ordinary OCI
  # filesystem layers. Require its exact declared descriptors as a prefix,
  # rather than accepting a matching digest elsewhere in the layer list.
  jq -e --slurpfile declared "$closure_layers" '
    .layers as $actual
    | [$actual[] | select(.digest as $digest | any($declared[0][]; .digest == $digest))] as $bound
    | .schemaVersion == 2
      and .mediaType == "application/vnd.oci.image.manifest.v1+json"
      and ($bound | length) > 0
      and $actual[0:($bound | length)] == $bound
      and ([$bound[].digest] | length == (unique | length))
      and all($bound[]; . as $layer | any($declared[0][]; . == $layer))
  ' "$manifest" >/dev/null \
    || fail_platform_binding "closure layers are not the platform's exact prefix"
  jq -c --slurpfile declared "$closure_layers" '
    .layers[]
    | select(.digest as $digest | any($declared[0][]; .digest == $digest))
  ' "$manifest" >> evidence-bound-layers.jsonl
done < evidence-platform-descriptors.jsonl

# No caller-supplied layer may be left unattached to the signed image index.
jq -sS 'unique_by(.digest) | sort_by(.digest)' evidence-bound-layers.jsonl \
  > evidence-bound-layers.json
jq -S 'sort_by(.digest)' "$closure_layers" > evidence-declared-layers.json
cmp evidence-bound-layers.json evidence-declared-layers.json \
  || fail_platform_binding "a declared closure layer is absent from every platform"

rm -f evidence-platform-descriptors.jsonl evidence-bound-layers.jsonl \
  evidence-bound-layers.json evidence-declared-layers.json
