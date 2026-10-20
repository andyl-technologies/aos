set -euo pipefail
export LC_ALL=C

config=$1
output=$2

fail() {
  printf 'artifact consumption audit: %s\n' "$1" >&2
  exit 1
}

require_regular_elf() {
  local label=$1
  local path=$2

  [[ -f $path ]] || fail "$label is not a regular file: $path"
  readelf -hW "$path" >/dev/null 2>&1 || fail "$label is not an ELF object: $path"
}

read_dynamic_values() {
  local tag=$1
  local path=$2

  readelf -dW "$path" \
    | sed -n "s/.*($tag).*\[\(.*\)\]/\1/p"
}

read_header_value() {
  local field=$1
  local path=$2

  case $field in
    class) sed_pattern='Class' ;;
    data) sed_pattern='Data' ;;
    machine) sed_pattern='Machine' ;;
    os_abi) sed_pattern='OS/ABI' ;;
    abi_version) sed_pattern='ABI Version' ;;
    type) sed_pattern='Type' ;;
    *) fail "internal unsupported ELF header field '$field'" ;;
  esac
  readelf -hW "$path" \
    | sed -n "s|^[[:space:]]*$sed_pattern:[[:space:]]*||p"
}

assert_elf_compatible() {
  local label=$1
  local path=$2

  local actual_class actual_data actual_machine actual_os_abi actual_abi_version
  actual_class=$(read_header_value class "$path")
  actual_data=$(read_header_value data "$path")
  actual_machine=$(read_header_value machine "$path")
  actual_os_abi=$(read_header_value os_abi "$path")
  actual_abi_version=$(read_header_value abi_version "$path")

  [[ $actual_class == "$consumer_class" ]] \
    || fail "$label ELF class '$actual_class' does not match consumer '$consumer_class'"
  [[ $actual_data == "$consumer_data" ]] \
    || fail "$label data encoding '$actual_data' does not match consumer '$consumer_data'"
  [[ $actual_machine == "$consumer_machine" ]] \
    || fail "$label machine '$actual_machine' does not match consumer '$consumer_machine'"
  if [[ $actual_os_abi != "$consumer_os_abi" ]]; then
    case "$consumer_os_abi|$actual_os_abi|$consumer_abi_version|$actual_abi_version" in
      'UNIX - System V|UNIX - GNU|0|0'|'UNIX - GNU|UNIX - System V|0|0') ;;
      *) fail "$label OS/ABI '$actual_os_abi' is incompatible with consumer '$consumer_os_abi'" ;;
    esac
  elif [[ $actual_abi_version != "$consumer_abi_version" ]]; then
    fail "$label ABI version '$actual_abi_version' does not match consumer '$consumer_abi_version'"
  fi
}

canonical_lines_json() {
  jq -Rsc 'split("\n") | map(select(length > 0)) | sort'
}

assert_json_equal() {
  local label=$1
  local expected=$2
  local actual=$3

  if [[ $actual != "$expected" ]]; then
    printf 'artifact consumption audit: %s mismatch\nexpected: %s\nactual:   %s\n' \
      "$label" "$expected" "$actual" >&2
    exit 1
  fi
}

consumer=$(jq -er '.consumer.artifact.store_path + .consumer.path' "$config")
provider=$(jq -er '.provider.artifact.store_path + .provider.path' "$config")
expected_soname=$(jq -er .contract.soname "$config")
expected_loader=$(jq -er .contract.loader "$config")
expected_search_kind=$(jq -er .contract.search_path_kind "$config")
expected_search_path=$(jq -er '.contract.search_path | join(":")' "$config")
expected_needed=$(jq -cS '.contract.needed' "$config")

require_regular_elf consumer "$consumer"
require_regular_elf provider "$provider"
require_regular_elf loader "$expected_loader"

consumer_class=$(read_header_value class "$consumer")
consumer_data=$(read_header_value data "$consumer")
consumer_machine=$(read_header_value machine "$consumer")
consumer_os_abi=$(read_header_value os_abi "$consumer")
consumer_abi_version=$(read_header_value abi_version "$consumer")

case "$(jq -er .platforms.target.architecture "$config")" in
  x86_64) expected_machine='Advanced Micro Devices X86-64' ;;
  aarch64) expected_machine='AArch64' ;;
  *) fail "unsupported target architecture" ;;
esac
[[ $consumer_class == ELF64 ]] \
  || fail "consumer ELF class '$consumer_class' does not match the supported target ABI 'ELF64'"
[[ $consumer_data == "2's complement, little endian" ]] \
  || fail "consumer data encoding '$consumer_data' does not match the supported target ABI"
[[ $consumer_machine == "$expected_machine" ]] \
  || fail "consumer machine '$consumer_machine' does not match target '$expected_machine'"

assert_elf_compatible provider "$provider"
assert_elf_compatible loader "$expected_loader"
provider_type=$(read_header_value type "$provider")
[[ $provider_type == DYN* ]] || fail "provider is not an ELF shared object"

mapfile -t provider_sonames < <(read_dynamic_values SONAME "$provider")
[[ ${#provider_sonames[@]} -eq 1 ]] \
  || fail "provider must carry exactly one DT_SONAME"
actual_soname=${provider_sonames[0]}
[[ $actual_soname == "$expected_soname" ]] \
  || fail "provider SONAME '$actual_soname' does not match '$expected_soname'"
[[ ${provider##*/} == "$actual_soname" ]] \
  || fail "provider artifact path does not end in its exact SONAME"

actual_needed=$(read_dynamic_values NEEDED "$consumer" | canonical_lines_json)
assert_json_equal "complete DT_NEEDED set" "$expected_needed" "$actual_needed"
jq -e --arg soname "$actual_soname" 'index($soname) != null' \
  <<<"$actual_needed" >/dev/null \
  || fail "provider SONAME is absent from the consumer DT_NEEDED set"

mapfile -t runpaths < <(read_dynamic_values RUNPATH "$consumer")
mapfile -t rpaths < <(read_dynamic_values RPATH "$consumer")
[[ ${#runpaths[@]} -le 1 && ${#rpaths[@]} -le 1 ]] \
  || fail "consumer carries multiple embedded dynamic search tags"
if [[ ${#runpaths[@]} -eq 1 && ${#rpaths[@]} -eq 0 ]]; then
  actual_search_kind=runpath
  actual_search_path=${runpaths[0]}
elif [[ ${#runpaths[@]} -eq 0 && ${#rpaths[@]} -eq 1 ]]; then
  actual_search_kind=rpath
  actual_search_path=${rpaths[0]}
else
  fail "consumer must carry exactly one of DT_RUNPATH or DT_RPATH"
fi
[[ $actual_search_kind == "$expected_search_kind" ]] \
  || fail "consumer search tag '$actual_search_kind' does not match '$expected_search_kind'"
[[ $actual_search_path == "$expected_search_path" ]] \
  || fail "consumer search path '$actual_search_path' does not match '$expected_search_path'"

# Resolve the declared startup search list without executing target code. An
# earlier same-SONAME object would shadow the claimed provider and fails closed.
resolved_provider=$(readlink -f -- "$provider") \
  || fail "provider path cannot be resolved"
selected_provider=
IFS=: read -r -a search_entries <<<"$actual_search_path"
for directory in "${search_entries[@]}"; do
  [[ $directory == /* && $directory != *'$ORIGIN'* ]] \
    || fail "version-1 search entries must be exact absolute paths"
  candidate="$directory/$actual_soname"
  if [[ -e $candidate ]]; then
    selected_provider=$(readlink -f -- "$candidate") \
      || fail "selected provider candidate cannot be resolved"
    break
  fi
done
[[ -n $selected_provider ]] \
  || fail "embedded search path does not resolve the provider SONAME"
[[ $selected_provider == "$resolved_provider" ]] \
  || fail "embedded search path resolves an earlier same-SONAME artifact: $selected_provider"

actual_loader=$(
  readelf -lW "$consumer" \
    | sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p'
)
[[ -n $actual_loader ]] || fail "consumer has no program interpreter"
[[ $actual_loader == "$expected_loader" ]] \
  || fail "consumer loader '$actual_loader' does not match '$expected_loader'"

# Capture complete symbol tables before matching so pipefail cannot turn an
# early successful match into a false rejection through upstream SIGPIPE.
provider_symbols=$(
  readelf --dyn-syms -W "$provider" \
    | awk '$5 == "GLOBAL" && $7 != "UND" { print $8 }'
)
consumer_symbols=$(
  readelf --dyn-syms -W "$consumer" \
    | awk '$5 == "GLOBAL" && $7 == "UND" { print $8 }'
)
while IFS= read -r requirement; do
  name=$(jq -r .name <<<"$requirement")
  version=$(jq -r .version <<<"$requirement")
  provider_pattern="${name}@@${version}"
  consumer_pattern="${name}@${version}"

  grep -Fx "$provider_pattern" <<<"$provider_symbols" >/dev/null \
    || fail "provider does not define global default symbol version '$provider_pattern'"
  grep -Fx "$consumer_pattern" <<<"$consumer_symbols" >/dev/null \
    || fail "consumer does not require global symbol version '$consumer_pattern'"
done < <(jq -c '.contract.symbols[]' "$config")

consumer_digest=$(sha256sum "$consumer" | cut -d ' ' -f 1)
provider_digest=$(sha256sum "$provider" | cut -d ' ' -f 1)

jq -cS \
  --arg consumer_sha256 "sha256:$consumer_digest" \
  --arg provider_sha256 "sha256:$provider_digest" \
  --arg elf_class "$consumer_class" \
  --arg data_encoding "$consumer_data" \
  --arg machine "$consumer_machine" \
  --arg os_abi "$consumer_os_abi" \
  --arg abi_version "$consumer_abi_version" \
  --arg soname "$actual_soname" \
  --arg loader "$actual_loader" \
  --arg search_kind "$actual_search_kind" \
  --arg search_path "$actual_search_path" \
  --argjson needed "$actual_needed" \
  '.consumer.sha256 = $consumer_sha256
  | .provider.sha256 = $provider_sha256
  | .observation = {
      elf_class: $elf_class,
      data_encoding: $data_encoding,
      machine: $machine,
      os_abi: $os_abi,
      abi_version: $abi_version,
      soname: $soname,
      loader: $loader,
      search_path_kind: $search_kind,
      search_path: ($search_path | split(":")),
      needed: $needed,
      symbols: .contract.symbols,
      provider_elf_compatible: true,
      loader_elf_compatible: true,
      search_resolves_exact_provider: true,
      provider_retained_by_consumer: true
  }' "$config" > "$output.with-newline"

size=$(stat -c %s "$output.with-newline")
[[ $size -gt 1 ]] || fail "generated evidence is empty"
truncate -s "$((size - 1))" "$output.with-newline"
mv "$output.with-newline" "$output"
