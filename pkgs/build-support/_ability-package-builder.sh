set -euo pipefail
export LC_ALL=C

canonical_json() {
  local source=$1
  local destination=$2

  jq -cS . "$source" > "$destination.with-newline"
  local size
  size=$(stat -c %s "$destination.with-newline")
  if [[ $size -le 1 ]]; then
    echo "ability companion generated an empty canonical document" >&2
    exit 1
  fi
  truncate -s "$((size - 1))" "$destination.with-newline"
  mv "$destination.with-newline" "$destination"
}

domain_digest() {
  local domain=$1
  local document=$2

  {
    printf '%s\0' "$domain"
    cat "$document"
  } | sha256sum | cut -d ' ' -f 1
}

canonical_nar_hash() {
  local value=$1
  printf 'sha256:%s' "${canonicalNarHashes[$value]}"
}

store_hash() {
  local path=$1
  local base=${path##*/}
  local hash=${base%%-*}

  if [[ ! $hash =~ ^[0-9abcdfghijklmnpqrsvwxyz]{32}$ ]]; then
    echo "ability artifact graph contains an invalid store path: $path" >&2
    exit 1
  fi
  printf '%s' "$hash"
}

mkdir -p "$out/interfaces" work/closures work/interfaces
jq -r .abilityTemplateJson "$NIX_ATTRS_JSON_FILE" > work/template.json
jq -r .abilityGraphSpecsJson "$NIX_ATTRS_JSON_FILE" > work/graph-specs.json
jq -r .abilityInterfacesJson "$NIX_ATTRS_JSON_FILE" > work/interfaces.json
abilityTemplateFile=work/template.json
abilityGraphSpecsFile=work/graph-specs.json
abilityInterfacesFile=work/interfaces.json

# Normalize every realized artifact and compute its complete closure identity.
: > work/artifact-references.jsonl
declare -A canonicalNarHashes
while IFS= read -r spec; do
  graph_name=$(jq -r .name <<<"$spec")
  root_path=$(jq -r .path <<<"$spec")
  jq -c --arg name "$graph_name" '.[$name][]' "$NIX_ATTRS_JSON_FILE" > work/graph.jsonl

  mapfile -t graphNarHashes < <(jq -r '.[].narHash' < <(jq -s . work/graph.jsonl))
  mapfile -t graphNarHex < <(
    nix --extra-experimental-features nix-command \
      hash convert --hash-algo sha256 --to base16 "${graphNarHashes[@]}" 2>/dev/null
  )
  if [[ ${#graphNarHashes[@]} -ne ${#graphNarHex[@]} ]]; then
    echo "ability artifact graph hash conversion returned the wrong cardinality" >&2
    exit 1
  fi
  for ((hashIndex = 0; hashIndex < ${#graphNarHashes[@]}; hashIndex++)); do
    canonicalNarHashes["${graphNarHashes[$hashIndex]}"]=${graphNarHex[$hashIndex]}
  done

  : > work/closure-members.jsonl
  while IFS= read -r member; do
    member_path=$(jq -r .path <<<"$member")
    member_nar=$(canonical_nar_hash "$(jq -r .narHash <<<"$member")")
    references='[]'
    while IFS= read -r reference; do
      [[ -n $reference ]] || continue
      reference_hash=$(store_hash "$reference")
      references=$(jq -c --arg value "$reference_hash" '. + [$value] | sort | unique' <<<"$references")
    done < <(jq -r '.references[]' <<<"$member")

    # The registry schema omits an empty references field during canonical
    # encoding, so closure identities must use that same representation.
    jq -cn \
      --arg store_path "$member_path" \
      --arg nar_hash "$member_nar" \
      --argjson nar_size "$(jq -r .narSize <<<"$member")" \
      --argjson references "$references" \
      '{store_path:$store_path,nar_hash:$nar_hash,nar_size:$nar_size}
       + if $references == [] then {} else {references:$references} end' \
      >> work/closure-members.jsonl
  done < work/graph.jsonl

  jq -cs 'sort_by(.store_path)' work/closure-members.jsonl > work/closure.json
  canonical_json work/closure.json work/closure.canonical.json
  closure_digest="sha256:$(domain_digest aos.ability.closure/v1 work/closure.canonical.json)"
  root_member=$(jq -ce --arg path "$root_path" 'select(.path == $path)' work/graph.jsonl)
  root_nar=$(canonical_nar_hash "$(jq -r .narHash <<<"$root_member")")

  jq -cn --arg store_path "$root_path" --arg nar_hash "$root_nar" \
    '{store_path:$store_path,nar_hash:$nar_hash}' > work/artifact-content.json
  canonical_json work/artifact-content.json work/artifact-content.canonical.json
  content="sha256:$(domain_digest aos.ability.artifact/v1 work/artifact-content.canonical.json)"

  jq -cn \
    --arg path "$root_path" \
    --arg content "$content" \
    --arg nar_hash "$root_nar" \
    --arg closure "$closure_digest" \
    '{path:$path,artifact:{content:$content,store_path:$path,nar_hash:$nar_hash,closure:$closure}}' \
    >> work/artifact-references.jsonl
done < <(jq -c '.[]' "$abilityGraphSpecsFile")
jq -cs 'map({key:.path,value:.artifact}) | from_entries' \
  work/artifact-references.jsonl > work/artifact-references.json

# Materialize and name every public interface by its canonical semantic digest.
: > work/interface-keys.jsonl
while IFS= read -r spec; do
  export_name=$(jq -r .name <<<"$spec")
  jq '.document' <<<"$spec" > work/interface.json
  canonical_json work/interface.json work/interface.canonical.json
  descriptor="sha256:$(domain_digest aos.ability.interface/v1 work/interface.canonical.json)"
  interface_name=$(jq -r '.interface.name' work/interface.canonical.json)
  interface_abi=$(jq -r '.interface.abi' work/interface.canonical.json)
  cp work/interface.canonical.json "$out/interfaces/${descriptor#sha256:}.json"

  jq -cn \
    --arg export_name "$export_name" \
    --arg name "$interface_name" \
    --argjson abi "$interface_abi" \
    --arg descriptor "$descriptor" \
    '{export_name:$export_name,key:{name:$name,abi:$abi,descriptor:$descriptor}}' \
    >> work/interface-keys.jsonl
done < <(jq -c '.[]' "$abilityInterfacesFile")
jq -cs 'map({key:.export_name,value:.key}) | from_entries' \
  work/interface-keys.jsonl > work/interface-keys.json

# Replace every placeholder artifact, then bind exports to their exact public
# interface and to the digest of their separately normalized implementation.
jq --slurpfile artifacts work/artifact-references.json '
  def artifact: $artifacts[0][.store_path];
  .package.payload |= artifact
  | .package.source |= artifact
  | .artifacts |= map(artifact) | .artifacts |= unique_by(.content) | .artifacts |= sort_by(.content)
  | .module_entry_points |= with_entries(.value |= artifact)
  | .implementation.providers |= map(.artifact |= artifact)
  | .implementation.handlers |= with_entries(.value.artifact |= artifact)
' "$abilityTemplateFile" > work/package.artifacts.json

provider_count=$(jq '.implementation.providers | length' work/package.artifacts.json)
for ((index = 0; index < provider_count; index++)); do
  export_name=$(jq -r ".exports[$index].name" work/package.artifacts.json)
  interface_key=$(jq -c --arg name "$export_name" '.[$name]' work/interface-keys.json)
  jq --argjson index "$index" --argjson interface "$interface_key" '
    .exports[$index].interface = $interface
    | .implementation.providers[$index].interface = $interface
  ' work/package.artifacts.json > work/package.next.json
  mv work/package.next.json work/package.artifacts.json

  jq ".implementation.providers[$index]" work/package.artifacts.json > work/provider.json
  canonical_json work/provider.json work/provider.canonical.json
  implementation="sha256:$(domain_digest aos.ability.provider-implementation/v1 work/provider.canonical.json)"
  jq --argjson index "$index" --arg implementation "$implementation" \
    '.exports[$index].implementation = $implementation' \
    work/package.artifacts.json > work/package.next.json
  mv work/package.next.json work/package.artifacts.json
done

jq '.implementation.providers |= sort_by(.interface.name, .interface.abi, .interface.descriptor)' \
  work/package.artifacts.json > work/package.next.json
mv work/package.next.json work/package.artifacts.json

canonical_json work/package.artifacts.json "$out/package.json"
