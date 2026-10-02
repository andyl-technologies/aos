#!@bash@/bin/bash
set -euo pipefail
profile_dir=/sysroot/var/lib/profiles/system
image_dir=/sysroot/var/lib/profiles/image

# The seed pointer is a symlink the rootfs builder writes at
# /usr/lib/aos/toplevel -> /nix/store/<hash>-toplevel. readlink
# returns the literal target (a /nix/store/... path); we
# access toplevel-resident files by prefixing /sysroot
# because the real root is still under /sysroot in the
# initrd. /sysroot/nix is the merged overlay (set up by
# nix-overlay-setup.service, which we ordered After).
toplevel=$(readlink /sysroot/usr/lib/aos/toplevel)

read_meta() {
  tr -d '\n' < "/sysroot$toplevel/meta/$1" 2>/dev/null \
    || printf 'unknown'
}

fail_image_identity() {
  echo "aos-seed-profiles: $*" >&2
  exit 1
}

read_os_release() {
  wanted=$1
  source=$2
  found=0
  result=
  while IFS= read -r line; do
    case "$line" in
      "$wanted="*)
        found=$((found + 1))
        result=${line#*=}
        result=${result#\"}
        result=${result%\"}
        ;;
    esac
  done < "$source"
  [ "$found" -eq 1 ] || return 1
  printf '%s' "$result"
}

read_cmdline_value() {
  wanted=$1
  found=0
  result=
  for word in $(cat /proc/cmdline); do
    case "$word" in
      "$wanted="*)
        found=$((found + 1))
        result=${word#*=}
        ;;
    esac
  done
  [ "$found" -le 1 ] || return 1
  printf '%s' "$result"
}

validate_nix_store_root() {
  value=$1
  case "$value" in
    /nix/store/*) name=${value#/nix/store/} ;;
    *) return 1 ;;
  esac
  case "$name" in
    ""|*/*) return 1 ;;
  esac
  hash=${name%%-*}
  store_name=${name#*-}
  [ "$hash" != "$name" ] && [ -n "$store_name" ] || return 1
  [ "${#hash}" -eq 32 ] || return 1
  case "$hash" in
    *[!0123456789abcdfghijklmnpqrsvwxyz]*) return 1 ;;
  esac
  case "$store_name" in
    *[!A-Za-z0-9+._?=-]*) return 1 ;;
  esac
}

validate_rooted_executable() {
  root=$1
  command_path=$2
  target=$(readlink "$root$command_path") || return 1

  case "$target" in
    /nix/store/*/*) ;;
    *) return 1 ;;
  esac
  store_relative=${target#/nix/store/}
  store_entry=${store_relative%%/*}
  executable_relative=${store_relative#*/}
  validate_nix_store_root "/nix/store/$store_entry" || return 1
  case "/$executable_relative/" in
    *"//"*|*"/./"*|*"/../"*) return 1 ;;
  esac

  rooted_target="$root/nix/store/$store_entry/$executable_relative"
  [ ! -L "$rooted_target" ] \
    && [ -f "$rooted_target" ] \
    && [ -x "$rooted_target" ]
}

validate_module_library_identity() {
  # Native admission serializes Sha256Digest as canonical lowercase hex.
  printf '%s' "$module_library" | jq -e '
    type == "object" and (keys | sort) == ["nar_hash", "nar_size", "store_path"]
    and (.nar_hash | type == "string" and length == 71 and test("^sha256:[0-9a-f]{64}$"))
    and (.nar_size | type == "number" and . > 0 and floor == .)
  ' >/dev/null
}

validate_rooted_evaluation_descriptor() {
  local root=$1 descriptor=$2 relative entry member physical target
  case "$descriptor" in
    /nix/store/*/*) ;;
    *) return 1 ;;
  esac
  case "$descriptor/" in
    *"//"*|*"/./"*|*"/../"*) return 1 ;;
  esac
  relative=${descriptor#/nix/store/}
  entry=${relative%%/*}
  member=${relative#*/}
  validate_nix_store_root "/nix/store/$entry" || return 1

  physical="$root/nix/store/$entry"
  [ ! -L "$physical" ] && [ -d "$physical" ] || return 1
  while [[ "$member" == */* ]]; do
    physical="$physical/${member%%/*}"
    member=${member#*/}
    [ ! -L "$physical" ] && [ -d "$physical" ] || return 1
  done
  physical="$physical/$member"

  # Bundle leaves point at absolute store-root files. Resolve that one link
  # inside the mounted host store, not the initrd's separate /nix namespace.
  if [ -L "$physical" ]; then
    target=$(readlink "$physical") || return 1
    validate_nix_store_root "$target" || return 1
    physical="$root$target"
  fi
  [ ! -L "$physical" ] && [ -f "$physical" ]
}

state_version=$(read_meta state-version)
native_executor=$(read_meta native-executor-ref)
boot_contract=$(read_meta boot-artifact-contract)
evaluation_descriptor=$(read_meta evaluation-descriptor)
module_library=$(cat "/sysroot$toplevel/meta/module-library.json")
module_library_root=$(printf '%s' "$module_library" | jq -er '.store_path')
uki_path=$(read_meta uki-path)
kern=$(readlink "/sysroot$toplevel/kernel" 2>/dev/null || true)
[ -n "$kern" ] || kern="$toplevel/kernel"
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

case "$toplevel" in
  /nix/store/*) ;;
  *) fail_image_identity "immutable toplevel has unsafe target $toplevel" ;;
esac
validate_nix_store_root "$toplevel" \
  || fail_image_identity "immutable toplevel is not a canonical Nix store root"
[ "$(readlink "/sysroot$toplevel/sw" 2>/dev/null || true)" = /usr ] \
  || fail_image_identity "immutable toplevel has an invalid system command tree"
[ -d /sysroot/usr/bin ] && [ -d /sysroot/usr/sbin ] \
  || fail_image_identity "immutable rootfs has no system command directories"
validate_rooted_executable /sysroot /usr/bin/mount \
  || fail_image_identity "immutable rootfs omits the boot-storage mount command"

# The initrd's /run mount moves into the real root during switch-root,
# shadowing the rootfs tree. Publish the authenticated immutable image
# identity here so stage-2 consumers observe the toplevel that actually
# booted, independently of the mutable configured-generation pointer.
if [ -e /run/current-system ] && [ ! -L /run/current-system ]; then
  fail_image_identity "/run/current-system is not a symbolic link"
fi
ln -sfn "$toplevel" /run/current-system

validate_nix_store_root "$module_library_root" \
  || fail_image_identity "immutable native module library root is malformed"
validate_nix_store_root "$boot_contract" \
  || fail_image_identity "immutable boot contract root is malformed"
validate_module_library_identity \
  || fail_image_identity "immutable native library NAR identity is malformed"
validate_rooted_evaluation_descriptor /sysroot "$evaluation_descriptor" \
  || fail_image_identity "immutable native evaluation descriptor is missing or malformed"
validate_nix_store_root "$native_executor" \
  || fail_image_identity "immutable native executor is not a canonical Nix store root"
[ -n "$state_version" ] \
  || fail_image_identity "immutable image has an empty state version"
case "$uki_path" in
  EFI/Linux/*.efi) ;;
  *) fail_image_identity "immutable image records unsafe UKI path $uki_path" ;;
esac
os_release=$(readlink "/sysroot$toplevel/os-release") \
  || fail_image_identity "immutable toplevel has no os-release"
case "$os_release" in
  /nix/store/*) ;;
  *) fail_image_identity "immutable os-release has unsafe target $os_release" ;;
esac
os_library=$(read_os_release AOS_PACKAGE_MODULE_LIBRARY "/sysroot$os_release") \
  || fail_image_identity "immutable os-release has no unique native module library"
os_version=$(read_os_release VERSION_ID "/sysroot$os_release") \
  || fail_image_identity "immutable os-release has no unique version"
os_state_version=$(read_os_release AOS_STATE_VERSION "/sysroot$os_release") \
  || fail_image_identity "immutable os-release has no unique state version"
[ "$module_library_root" = "$os_library" ] \
  || fail_image_identity "toplevel metadata disagrees with signed native module library identity"
[ "$(read_meta version)" = "$os_version" ] \
  || fail_image_identity "toplevel metadata disagrees with measured version"
[ "$state_version" = "$os_state_version" ] \
  || fail_image_identity "toplevel metadata disagrees with measured state version"

root_hash=$(read_cmdline_value roothash) \
  || fail_image_identity "kernel command line has ambiguous roothash"
root_device=$(read_cmdline_value root) \
  || fail_image_identity "kernel command line has ambiguous root device"
verity_data=$(read_cmdline_value systemd.verity_root_data) \
  || fail_image_identity "kernel command line has ambiguous verity data device"
slot_device=$verity_data
[ -n "$slot_device" ] || slot_device=$root_device
root_a_device=$(jq -er '.devices.rootA' \
  "/sysroot$toplevel/meta/boot-storage.json") \
  || fail_image_identity "immutable image has no slot-A storage device"
root_b_device=$(jq -er '.devices.rootB' \
  "/sysroot$toplevel/meta/boot-storage.json") \
  || fail_image_identity "immutable image has no slot-B storage device"
case "$slot_device" in
  "$root_a_device") boot_slot=A ;;
  "$root_b_device") boot_slot=B ;;
  *)
    slot_real=$(readlink -f "$slot_device" 2>/dev/null || true)
    root_a_real=$(readlink -f "$root_a_device" 2>/dev/null || true)
    root_b_real=$(readlink -f "$root_b_device" 2>/dev/null || true)
    if [ -n "$slot_real" ] && [ "$slot_real" = "$root_a_real" ]; then
      boot_slot=A
    elif [ -n "$slot_real" ] && [ "$slot_real" = "$root_b_real" ]; then
      boot_slot=B
    else
      fail_image_identity "kernel command line does not identify root-a or root-b"
    fi
    ;;
esac
recovery_json=null
if [ "$AOS_RECOVERY_ENABLED" = true ]; then
  recovery_lower=$(printf '%s' "$boot_slot" | tr '[:upper:]' '[:lower:]')
  recovery_mount=/run/aos-seed-recovery-esp
  mkdir -p "$recovery_mount"
  mount -t vfat -o ro,nosuid,nodev,noexec \
    "$AOS_ESP_DEVICE" "$recovery_mount" \
    || fail_image_identity "cannot mount the recovery ESP read-only"
  recovery_uki="EFI/AOS/recovery-$recovery_lower.efi"
  recovery_entry="loader/entries/recovery-$recovery_lower.conf"
  [ -f "$recovery_mount/$recovery_uki" ] \
    || fail_image_identity "paired recovery UKI is missing"
  boot_db_certificate=/sysroot/usr/lib/aos/image-trust/boot-db.crt
  for component in /sysroot/usr /sysroot/usr/lib /sysroot/usr/lib/aos \
    /sysroot/usr/lib/aos/image-trust "$boot_db_certificate"; do
    [ ! -L "$component" ] \
      || fail_image_identity "image boot trust path contains a symlink"
  done
  [ -f "$boot_db_certificate" ] && [ -s "$boot_db_certificate" ] \
    || fail_image_identity "verified image boot trust certificate is missing"
  certificate_mount_options=$(findmnt --noheadings --output OPTIONS --target "$boot_db_certificate")
  case ",$certificate_mount_options," in
    *,ro,*) ;;
    *) fail_image_identity "image boot trust certificate is not on a read-only mount" ;;
  esac
  sbverify --cert "$boot_db_certificate" \
    "$recovery_mount/$recovery_uki" >/dev/null \
    || fail_image_identity "paired recovery UKI is not authorized by Secure Boot db"
  recovery_audit=/run/aos-seed-recovery-audit
  rm -rf "$recovery_audit"
  mkdir -p "$recovery_audit"
  @package_runtime@/bin/aos-package-runtime \
    attest __read-uki-identity-section \
    --uki "$recovery_mount/$recovery_uki" --section cmdline \
    > "$recovery_audit/cmdline" \
    || fail_image_identity "cannot inspect paired recovery command line"
  recovery_cmdline=$(cat "$recovery_audit/cmdline")
  [ "$recovery_cmdline" = "console=ttyS0,115200 rd.systemd.unit=aos-recovery.target aos.recovery=1 rd.luks=0" ] \
    || fail_image_identity "paired recovery UKI has a noncanonical signed command line"
  @package_runtime@/bin/aos-package-runtime \
    attest __read-uki-identity-section \
    --uki "$recovery_mount/$recovery_uki" --section osrel \
    > "$recovery_audit/os-release.clean" \
    || fail_image_identity "cannot inspect paired recovery identity"
  recovery_release=$(read_os_release VERSION_ID "$recovery_audit/os-release.clean") \
    || fail_image_identity "paired recovery UKI has no unique signed release"
  recovery_copy=$(read_os_release AOS_RECOVERY_COPY "$recovery_audit/os-release.clean") \
    || fail_image_identity "paired recovery UKI has no unique signed copy"
  recovery_abi=$(read_os_release AOS_RECOVERY_ABI "$recovery_audit/os-release.clean") \
    || fail_image_identity "paired recovery UKI has no unique signed ABI"
  [ "$recovery_release" = "$os_version" ] \
    || fail_image_identity "paired recovery UKI release disagrees with the running image"
  [ "$recovery_copy" = "$boot_slot" ] \
    || fail_image_identity "paired recovery UKI copy disagrees with the running slot"
  [ "$recovery_abi" = "$AOS_RECOVERY_ABI" ] \
    || fail_image_identity "paired recovery UKI ABI is unsupported"
  expected_entry=$(printf 'title AOS Recovery %s (%s)\nefi /EFI/AOS/recovery-%s.efi\n' \
    "$boot_slot" "$os_version" "$recovery_lower")
  installed_entry=$(cat "$recovery_mount/$recovery_entry") \
    || fail_image_identity "paired recovery loader entry is missing"
  [ "$installed_entry" = "$expected_entry" ] \
    || fail_image_identity "paired recovery loader entry is not canonical"
  recovery_size=$(stat -c %s "$recovery_mount/$recovery_uki")
  recovery_digest=$(sha256sum "$recovery_mount/$recovery_uki" | cut -d ' ' -f1)
  umount "$recovery_mount" \
    || fail_image_identity "cannot unmount the recovery ESP"
  rm -rf "$recovery_audit"
  recovery_json=$(jq -n \
    --arg copy "$boot_slot" --arg uki "$recovery_uki" \
    --arg entry "$recovery_entry" \
    --arg source "recovery-$recovery_lower.efi" \
    --arg digest "$recovery_digest" --arg release "$os_version" \
    --argjson size "$recovery_size" \
    --argjson abi "$AOS_RECOVERY_ABI" \
    '{copy: $copy, uki_path: $uki, entry_path: $entry,
      source_path: $source, sha256: $digest, byte_size: $size,
      release: $release, recovery_abi: $abi}')
fi
# Index the verified image independently of the native package profile. Image
# metadata retains its exact module library and input descriptor, not a second
# configuration-generation authority or a synthetic empty package deployment.
mkdir -p "$image_dir"
provider_generation=$(jq -n --arg entry "$uki_path" --arg slot "$boot_slot" \
  --argjson recovery "$recovery_json" \
  '{schema: "aos.systemd.boot-generation-state/v1",
    evidence: ({"installed-entry":$entry,"uki-source-path":$entry,slot:$slot}
      + (if $recovery == null then {} else {recovery:$recovery} end))}')
generation=$(jq -n --arg pn "$(read_meta package-name)" --arg ver "$(read_meta version)" \
  --arg top "$toplevel" --arg kern "$kern" --arg state "$state_version" \
  --arg executor "$native_executor" --arg contract "$boot_contract" \
  --arg descriptor "$evaluation_descriptor" --arg now "$now" \
  --argjson library "$module_library" --argjson provider "$provider_generation" \
  '{number:0,boot_artifact_contract:$contract,boot_provider_state:$provider,
    toplevel:$top,package_name:$pn,version:$ver,state_version:$state,
    native_executor_ref:$executor,registry:"seed",kernel_path:$kern,
    module_library:$library,evaluation_descriptor:$descriptor,created_at:$now}')

publish_image_state() {
  sync "$image_dir/.state.json.new"
  mv "$image_dir/.state.json.new" "$image_dir/state.json"
  sync "$image_dir"
}

update_running_image_state() {
  local needs_update
  needs_update=$(jq -r --arg top "$toplevel" '
    (.generations[] | select(.toplevel == $top) | .number) as $running
    | .running != $running or
      (.active_rollout != null and .active_rollout.candidate == $running
       and .active_rollout.status == "staged")
  ' "$image_dir/state.json")

  # Recurrent boots authenticate the record without rewriting durable state.
  if [ "$needs_update" = true ]; then
    jq --arg top "$toplevel" '
      (.generations[] | select(.toplevel == $top) | .number) as $running
      | .running = $running
      | if .active_rollout != null and .active_rollout.candidate == $running
           and .active_rollout.status == "staged" then
          .active_rollout.status = "candidate_booted"
        else . end
    ' "$image_dir/state.json" > "$image_dir/.state.json.new"
    publish_image_state
  fi
}

repair_image_retention() {
  local names=(toplevel native-executor boot-artifact-contract module-library evaluation-descriptor)
  # The descriptor member link also retains its containing immutable object.
  local targets=("$toplevel" "$native_executor" "$boot_contract" "$module_library_root" "$evaluation_descriptor")
  local index path changed=false

  if [ -L "$retention" ] || { [ -e "$retention" ] && [ ! -d "$retention" ]; }; then
    fail_image_identity "image retention directory is not an owned directory"
  fi
  for index in "${!names[@]}"; do
    path="$retention/${names[$index]}"
    if [ -e "$path" ] && [ ! -L "$path" ]; then
      fail_image_identity "image retention root ${names[$index]} is not a symbolic link"
    fi
  done

  if [ ! -d "$retention" ]; then
    mkdir -p "$retention"
    changed=true
  fi
  for index in "${!names[@]}"; do
    path="$retention/${names[$index]}"
    if [ "$(readlink "$path" 2>/dev/null || true)" != "${targets[$index]}" ]; then
      ln -sfn "${targets[$index]}" "$path"
      changed=true
    fi
  done
  if [ "$changed" = true ]; then
    sync "$retention"
  fi
}

if [ ! -e "$image_dir/state.json" ]; then
  jq -n --argjson generation "$generation" --argjson provider "$provider_generation" \
    '{schema:"aos.image-generation-state/v1",running:1,pending:1,
      boot_provider_state:{schema:"aos.systemd.boot-state/v1",
        evidence:$provider.evidence},generations:[$generation + {number:1}]}' \
    > "$image_dir/.state.json.new"
  publish_image_state
else
  jq -e '.schema == "aos.image-generation-state/v1" and (.generations | type == "array")' \
    "$image_dir/state.json" >/dev/null \
    || fail_image_identity "image index is not a native generation state"
  matches=$(jq --arg top "$toplevel" '[.generations[] | select(.toplevel == $top)] | length' \
    "$image_dir/state.json")
  [ "$matches" -le 1 ] || fail_image_identity "image index contains ambiguous immutable identity"
  if [ "$matches" -eq 0 ]; then
    jq --argjson generation "$generation" \
      '([.generations[].number] | max + 1) as $next
       | .generations += [$generation + {number:$next}] | .running = $next' \
      "$image_dir/state.json" > "$image_dir/.state.json.new"
    publish_image_state
  else
    jq -e --argjson expected "$generation" \
      '.generations[] | select(.toplevel == $expected.toplevel)
       | (.boot_provider_state.schema == "aos.systemd.boot-generation-state/v1")
         and (.boot_provider_state.evidence.slot == $expected.boot_provider_state.evidence.slot)
         and (.boot_provider_state.evidence.retired != true)
         and (del(.number,.created_at,.registry,.boot_provider_state)
              == ($expected | del(.number,.created_at,.registry,.boot_provider_state)))' \
      "$image_dir/state.json" >/dev/null \
      || fail_image_identity "native image index disagrees with the verified immutable image"
    update_running_image_state
  fi
fi

if jq -e '.pending != null or .active_rollout != null' "$image_dir/state.json" >/dev/null; then
  mkdir -p /run/aos
  touch /run/aos/image-reeval-required
fi

existing=$(jq -er '.running' "$image_dir/state.json")
retention="$image_dir/image-gen-$existing"
repair_image_retention

mkdir -p "$profile_dir"
current=$(@package_runtime@/bin/aos-package-runtime deployment-current --profile "$profile_dir" \
  --committed-during-recovery) \
  || fail_image_identity "native profile publication inspection failed"
GEN=$(printf '%s' "$current" | jq -er '
  if .generation == null then 0
  elif (.generation | type == "number" and . > 0 and floor == .) then .generation
  else error("invalid native profile generation") end') \
  || fail_image_identity "native profile publication is malformed"
printf 'AOS_PROFILE_GEN=%s\n' "$GEN" > /run/aos-profile-gen.env
