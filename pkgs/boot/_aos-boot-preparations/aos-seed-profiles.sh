#!@bash@/bin/bash
set -euo pipefail
profile_dir=/sysroot/var/lib/profiles/system
image_dir=/sysroot/var/lib/profiles/image

# The seed pointer is a symlink the rootfs builder writes at
# /aos-toplevel -> /nix/store/<hash>-toplevel. readlink
# returns the literal target (a /nix/store/... path); we
# access toplevel-resident files by prefixing /sysroot
# because the real root is still under /sysroot in the
# initrd. /sysroot/nix is the merged overlay (set up by
# nix-overlay-setup.service, which we ordered After).
toplevel=$(readlink /sysroot/aos-toplevel)

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

read_pcr11() {
  # cryptsetup may leave the swtpm resource manager busy briefly after
  # an unattended unlock. Never let an informational PCR read wedge
  # switch-root indefinitely.
  output=$(timeout -k 5 15 \
    tpm2_pcrread sha256:11 2>/dev/null) || return 1
  for word in $output; do
    case "$word" in
      0x*)
        value=${word#0x}
        [ "${#value}" -eq 64 ] || continue
        printf '%s' "$value" | tr '[:upper:]' '[:lower:]'
        return 0
        ;;
    esac
  done
  return 1
}

abi=$(read_meta module-abi)
state_version=$(read_meta state-version)
baselib_digest=$(read_meta baselib-digest)
native_executor=$(read_meta native-executor-ref)
base_lib=$(readlink "/sysroot$toplevel/base-lib")
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
for command in mount bootctl systemctl aos-rollout-drain aos-rollout-health; do
  validate_rooted_executable /sysroot "/usr/bin/$command" \
    || fail_image_identity "immutable rootfs omits rollout command $command"
done

# The initrd's /run mount moves into the real root during switch-root,
# shadowing the rootfs tree. Publish the authenticated immutable image
# identity here so stage-2 consumers observe the toplevel that actually
# booted, independently of the mutable configured-generation pointer.
if [ -e /run/current-system ] && [ ! -L /run/current-system ]; then
  fail_image_identity "/run/current-system is not a symbolic link"
fi
ln -sfn "$toplevel" /run/current-system

case "$base_lib" in
  /nix/store/*) ;;
  *) fail_image_identity "immutable base-lib has unsafe target $base_lib" ;;
esac
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
os_abi=$(read_os_release AOS_MODULE_ABI "/sysroot$os_release") \
  || fail_image_identity "immutable os-release has no unique module ABI"
os_digest=$(read_os_release AOS_BASELIB_DIGEST "/sysroot$os_release") \
  || fail_image_identity "immutable os-release has no unique base-lib digest"
os_version=$(read_os_release VERSION_ID "/sysroot$os_release") \
  || fail_image_identity "immutable os-release has no unique version"
os_state_version=$(read_os_release AOS_STATE_VERSION "/sysroot$os_release") \
  || fail_image_identity "immutable os-release has no unique state version"
[ "$abi" = "$os_abi" ] \
  || fail_image_identity "toplevel metadata disagrees with measured module ABI"
[ "$baselib_digest" = "$os_digest" ] \
  || fail_image_identity "toplevel metadata disagrees with measured base-lib digest"
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
  sbverify --cert "$AOS_DB_CERT" \
    "$recovery_mount/$recovery_uki" >/dev/null \
    || fail_image_identity "paired recovery UKI is not authorized by Secure Boot db"
  recovery_audit=/run/aos-seed-recovery-audit
  rm -rf "$recovery_audit"
  mkdir -p "$recovery_audit"
  .aos-package-runtime-unwrapped \
    attest __read-uki-identity-section \
    --uki "$recovery_mount/$recovery_uki" --section cmdline \
    > "$recovery_audit/cmdline" \
    || fail_image_identity "cannot inspect paired recovery command line"
  recovery_cmdline=$(cat "$recovery_audit/cmdline")
  [ "$recovery_cmdline" = "console=ttyS0,115200 rd.systemd.unit=aos-recovery.target aos.recovery=1 rd.luks=0" ] \
    || fail_image_identity "paired recovery UKI has a noncanonical signed command line"
  .aos-package-runtime-unwrapped \
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
# `/aos-toplevel` is baked into the booted immutable root. Reconcile
# the userspace image index to that identity before stage 2; the
# currently selected config generation is never used as authority.
mkdir -p "$image_dir"
publish_image_state() {
  source=$1
  sync "$source"
  mv "$source" "$image_dir/state.json"
  sync "$image_dir"
}

existing=0
if [ -e "$image_dir/state.json" ]; then
  existing=$(jq --arg top "$toplevel" \
    '[.generations[] | select(.toplevel == $top) | .number][0] // 0' \
    "$image_dir/state.json")
fi
initrd_pcr11=
steady_recurrent=false
if [ "$existing" -eq 0 ]; then
  # Indexing a genuinely new immutable image requires a live reading.
  # An unavailable TPM preserves the historical unmeasured-record
  # representation rather than inventing an expected PCR value.
  if measured=$(read_pcr11); then
    initrd_pcr11=$measured
  fi
else
  # On a recurrent boot, /var has just been unsealed and the immutable
  # image record is checked field-by-field below. Reuse its indexed
  # expectation here instead of contending with cryptsetup for the TPM;
  # stage 2 independently quotes the live PCR bank for attestation.
  initrd_pcr11=$(jq -er --argjson existing "$existing" \
    '[.generations[] | select(.number == $existing) | .initrd_pcr11][0] // ""' \
    "$image_dir/state.json")
  if [ -z "$initrd_pcr11" ]; then
    if measured=$(read_pcr11); then
      initrd_pcr11=$measured
    fi
  fi
  case "$initrd_pcr11" in
    "") ;;
    *[!0-9A-Fa-f]*)
      fail_image_identity "persisted image record has malformed initrd PCR 11"
      ;;
    *)
      [ "${#initrd_pcr11}" -eq 64 ] \
        || fail_image_identity "persisted image record has malformed initrd PCR 11"
      ;;
  esac
  initrd_pcr11=$(printf '%s' "$initrd_pcr11" | tr '[:upper:]' '[:lower:]')
fi

if [ ! -e "$image_dir/state.json" ]; then
  jq -n \
    --arg pn "$(read_meta package-name)" \
    --arg ver "$(read_meta version)" \
    --arg top "$toplevel" \
    --arg kern "$kern" \
    --arg base "$base_lib" \
    --arg state_version "$state_version" \
    --arg native_executor "$native_executor" \
    --arg digest "$baselib_digest" \
    --arg now "$now" \
    --arg uki "$uki_path" \
    --arg slot "$boot_slot" \
    --arg root_hash "$root_hash" \
    --arg initrd_pcr11 "$initrd_pcr11" \
    --argjson abi "$abi" \
    --argjson recovery "$recovery_json" \
    --argjson recovery_enabled $AOS_RECOVERY_ENABLED \
    '({ running: 1, default: 1, pending: 1,
       generations: [({ number: 1, slot: $slot, uki_path: $uki,
         toplevel: $top, package_name: $pn, version: $ver,
         state_version: $state_version,
         native_executor_ref: $native_executor,
         registry: "seed", kernel_path: $kern,
         evaluator_ref: $base, module_abi: $abi,
         baselib_digest: $digest, created_at: $now }
         + (if $root_hash == "" then {} else {root_verity_roothash: $root_hash} end)
         + (if $initrd_pcr11 == "" then {} else {initrd_pcr11: $initrd_pcr11} end)
         + (if $recovery_enabled then {recovery: $recovery} else {} end))] }
      + (if $recovery_enabled then {recovery_known_good: $slot} else {} end))' \
    > "$image_dir/.state.json.new"
  publish_image_state "$image_dir/.state.json.new"
  existing=1
else
  if [ "$existing" -eq 0 ]; then
    next=$(jq '[.generations[].number] | max + 1' "$image_dir/state.json")
    jq \
      --arg pn "$(read_meta package-name)" --arg ver "$(read_meta version)" \
      --arg top "$toplevel" --arg kern "$kern" --arg base "$base_lib" \
      --arg state_version "$state_version" --arg native_executor "$native_executor" \
      --arg digest "$baselib_digest" --arg now "$now" \
      --arg uki "$uki_path" --arg slot "$boot_slot" \
      --arg root_hash "$root_hash" --arg initrd_pcr11 "$initrd_pcr11" \
      --argjson abi "$abi" --argjson next "$next" \
      --argjson recovery "$recovery_json" \
      --argjson recovery_enabled $AOS_RECOVERY_ENABLED \
      '.generations += [({ number: $next,
         slot: $slot,
         uki_path: $uki, toplevel: $top, package_name: $pn,
         version: $ver, state_version: $state_version,
         native_executor_ref: $native_executor,
         registry: "seed", kernel_path: $kern,
         evaluator_ref: $base, module_abi: $abi,
         baselib_digest: $digest, created_at: $now }
         + (if $root_hash == "" then {} else {root_verity_roothash: $root_hash} end)
         + (if $initrd_pcr11 == "" then {} else {initrd_pcr11: $initrd_pcr11} end)
         + (if $recovery_enabled then {recovery: $recovery} else {} end))]
       | .running = $next' \
      "$image_dir/state.json" > "$image_dir/.state.json.new"
    publish_image_state "$image_dir/.state.json.new"
    existing=$next
  else
    top_count=$(jq --arg top "$toplevel" \
      '[.generations[] | select(.toplevel == $top)] | length' \
      "$image_dir/state.json")
    matching=$(jq \
      --arg top "$toplevel" --arg pn "$(read_meta package-name)" \
      --arg ver "$(read_meta version)" --arg kern "$kern" \
      --arg base "$base_lib" --arg digest "$baselib_digest" \
      --arg state_version "$state_version" --arg native_executor "$native_executor" \
      --arg uki "$uki_path" --arg slot "$boot_slot" \
      --arg root_hash "$root_hash" --arg initrd_pcr11 "$initrd_pcr11" \
      --argjson abi "$abi" --argjson recovery "$recovery_json" \
      --argjson recovery_enabled $AOS_RECOVERY_ENABLED \
      '[.generations[] | select(
         .toplevel == $top and .package_name == $pn and .version == $ver
         and .state_version == $state_version
         and .native_executor_ref == $native_executor
         and .kernel_path == $kern and .evaluator_ref == $base
         and .module_abi == $abi and .baselib_digest == $digest
         and ((.uki_source_path // .uki_path) == $uki) and .slot == $slot
         and ((.root_verity_roothash // "") == $root_hash)
         and (if $recovery_enabled then .recovery == $recovery
              else .recovery == null end)
         and ((.initrd_pcr11 == null)
              or (.initrd_pcr11 != null and $initrd_pcr11 != ""
                  and (.initrd_pcr11 | ascii_downcase) == $initrd_pcr11))
       )] | length' "$image_dir/state.json")
    [ "$top_count" -eq 1 ] && [ "$matching" -eq 1 ] \
      || fail_image_identity "persisted image record disagrees with the booted immutable image"
    recorded_running=$(jq -er '.running' \
      "$image_dir/state.json")
    recorded_initrd=$(jq -r --argjson existing "$existing" \
      '[.generations[] | select(.number == $existing) | .initrd_pcr11][0] // ""' \
      "$image_dir/state.json")
    if [ -z "$recorded_initrd" ] && [ -n "$initrd_pcr11" ]; then
      # Preserve the catalog-published stable PCR 11 separately. For
      # legacy seed records only, an equal old expected value was the
      # initrd snapshot and is migrated rather than reinterpreted as
      # the stable ready-phase value.
      jq \
        --argjson existing "$existing" --arg initrd "$initrd_pcr11" \
        '.running = $existing
         | (.generations[] | select(.number == $existing)) |=
           (.initrd_pcr11 = $initrd
            | if .registry == "seed"
                 and ((.expected_pcr11 // "") | ascii_downcase) == $initrd
              then del(.expected_pcr11)
              else .
              end)' \
        "$image_dir/state.json" > "$image_dir/.state.json.new"
      publish_image_state "$image_dir/.state.json.new"
    elif [ "$recorded_running" -ne "$existing" ]; then
      jq --argjson running "$existing" \
        '.running = $running' \
        "$image_dir/state.json" > "$image_dir/.state.json.new"
      publish_image_state "$image_dir/.state.json.new"
    else
      steady_recurrent=true
    fi
  fi
fi

# A fully reconciled recurrent boot is read-only. Avoid refreshing
# durable roots and copying state immediately after TPM-unlocking
# /var; those mutations are repair operations, not boot requirements.
# Any missing root or legacy state falls through to the repair path.
if [ "$steady_recurrent" = true ]; then
  retained_base=$(readlink \
    "$image_dir/image-gen-$existing/baselib/$abi" 2>/dev/null || true)
  if [ "$retained_base" = "$base_lib" ] && [ -e "$profile_dir/state.json" ]; then
    has_legacy=$(jq \
      '[.generations[] | has("toplevel")] | any' \
      "$profile_dir/state.json")
    if [ "$has_legacy" = false ]; then
      link=$(readlink "$profile_dir/current" 2>/dev/null || true)
      GEN=${link#gen-}
      [ -n "$GEN" ] || GEN=0
      printf 'AOS_PROFILE_GEN=%s\n' "$GEN" > /run/aos-profile-gen.env
      exit 0
    fi
  fi
fi

mkdir -p "$image_dir/image-gen-$existing/baselib"
ln -sfn "$base_lib" "$image_dir/image-gen-$existing/baselib/$abi"
mkdir -p "$profile_dir"

# One-shot legacy migration. Every bundled record must both carry the
# complete config-generation input/output binding and authenticate its
# retired toplevel fields through mutually agreeing immutable metadata,
# os-release, base-lib, and image-index fields. Migration is all-or-
# nothing; incomplete records leave the original state untouched.
if [ -e "$profile_dir/state.json" ]; then
  cp "$profile_dir/state.json" "$profile_dir/.state.json.migrate"
  has_legacy=$(jq '[.generations[] | has("toplevel")] | any' \
    "$profile_dir/.state.json.migrate")
  migration_failed=0
  for index in $(jq -r \
    '.generations | to_entries[] | select(.value | has("toplevel")) | .key' \
    "$profile_dir/.state.json.migrate"); do
    legacy_top=$(jq -r --argjson index "$index" \
      '.generations[$index].toplevel' "$profile_dir/.state.json.migrate")
    case "$legacy_top" in
      /nix/store/*) ;;
      *)
        echo "aos-seed-profiles: legacy generation $index has unsafe toplevel" >&2
        migration_failed=1
        continue
        ;;
    esac
    legacy_abi=$(tr -d '\n' < "/sysroot$legacy_top/meta/module-abi" 2>/dev/null || true)
    legacy_digest=$(tr -d '\n' < "/sysroot$legacy_top/meta/baselib-digest" 2>/dev/null || true)
    legacy_base=$(readlink "/sysroot$legacy_top/base-lib" 2>/dev/null || true)
    legacy_osrel=$(readlink "/sysroot$legacy_top/os-release" 2>/dev/null || true)
    [ -n "$legacy_abi" ] || { migration_failed=1; continue; }
    case "$legacy_abi" in *[!0-9]*) migration_failed=1; continue ;; esac
    case "$legacy_base" in /nix/store/*) ;; *) migration_failed=1; continue ;; esac
    case "$legacy_osrel" in /nix/store/*) ;; *) migration_failed=1; continue ;; esac
    legacy_os_abi=$(read_os_release AOS_MODULE_ABI "/sysroot$legacy_osrel" 2>/dev/null || true)
    legacy_os_digest=$(read_os_release AOS_BASELIB_DIGEST "/sysroot$legacy_osrel" 2>/dev/null || true)
    [ "$legacy_abi" = "$legacy_os_abi" ] || { migration_failed=1; continue; }
    [ -n "$legacy_digest" ] && [ "$legacy_digest" = "$legacy_os_digest" ] \
      || { migration_failed=1; continue; }

    legacy_matches=$(jq \
      --arg top "$legacy_top" --arg base "$legacy_base" \
      --arg digest "$legacy_digest" --argjson abi "$legacy_abi" \
      '[.generations[] | select(.toplevel == $top
         and .evaluator_ref == $base and .module_abi == $abi
         and .baselib_digest == $digest)] | length' \
      "$image_dir/state.json")
    [ "$legacy_matches" -eq 1 ] || { migration_failed=1; continue; }
    legacy_parent=$(jq -r \
      --arg top "$legacy_top" --arg base "$legacy_base" \
      --arg digest "$legacy_digest" --argjson abi "$legacy_abi" \
      '.generations[] | select(.toplevel == $top
         and .evaluator_ref == $base and .module_abi == $abi
         and .baselib_digest == $digest) | .number' \
      "$image_dir/state.json")
    jq --argjson index "$index" \
      --argjson abi "$legacy_abi" --argjson parent "$legacy_parent" \
      --arg base "$legacy_base" \
      '.generations[$index].module_abi_pinned = $abi
       | .generations[$index].image_gen_parent = $parent
       | .generations[$index].base_lib_ref = $base' \
      "$profile_dir/.state.json.migrate" > "$profile_dir/.state.json.next"
    mv "$profile_dir/.state.json.next" "$profile_dir/.state.json.migrate"
  done
  complete=$(jq '
    all(.generations[];
      (.image_gen_parent | type) == "number"
      and (.module_abi_pinned | type) == "number"
      and (.manifest_hash | type) == "string" and (.manifest_hash | length) > 0
      and (.package_module_closure | type) == "string" and (.package_module_closure | length) > 0
      and (.package_module_paths | type) == "array"
      and (.package_module_packages | type) == "array"
      and (.host_nix_ref | type) == "string" and (.host_nix_ref | length) > 0
      and (.facts_hash | type) == "string" and (.facts_hash | length) > 0
      and (.facts_ref | type) == "string" and (.facts_ref | length) > 0
      and (.base_lib_ref | type) == "string" and (.base_lib_ref | length) > 0
      and (.evaluator_ref | type) == "string" and (.evaluator_ref | length) > 0)' \
    "$profile_dir/.state.json.migrate")
  if [ "$has_legacy" = true ] && { [ "$migration_failed" -ne 0 ] || [ "$complete" != true ]; }; then
    rm -f "$profile_dir/.state.json.migrate"
    echo "aos-seed-profiles: legacy system state cannot be authenticated as complete config generations" >&2
    exit 1
  fi
  if [ "$has_legacy" = true ]; then
    jq '
      .generations |= map({
        number, image_gen_parent, module_abi_pinned, manifest_hash,
        package_module_closure, package_module_paths,
        package_module_packages, host_nix_ref, host_nix_commit,
        facts_hash, facts_ref, base_lib_ref, evaluator_ref, created_at
      })' "$profile_dir/.state.json.migrate" \
      > "$profile_dir/.state.json.next"
    mv "$profile_dir/.state.json.next" "$profile_dir/.state.json.migrate"
    sync "$profile_dir/.state.json.migrate"
    mv "$profile_dir/.state.json.migrate" "$profile_dir/state.json"
    sync "$profile_dir"
  else
    rm -f "$profile_dir/.state.json.migrate"
  fi
fi

if [ ! -e "$profile_dir/state.json" ]; then
  # A baked image is an image-generation, not an empty synthetic
  # config-generation. The first successful on-host evaluation creates
  # config-gen 1 with all authenticated input/output bindings present.
  jq -n \
    '{current: 0, next: 1, generations: []}' \
    > "$profile_dir/.state.json.new"
  sync "$profile_dir/.state.json.new"
  mv "$profile_dir/.state.json.new" "$profile_dir/state.json"
  sync "$profile_dir"
fi

link=$(readlink "$profile_dir/current" 2>/dev/null || true)
GEN=${link#gen-}
[ -n "$GEN" ] || GEN=0
printf 'AOS_PROFILE_GEN=%s\n' "$GEN" > /run/aos-profile-gen.env
