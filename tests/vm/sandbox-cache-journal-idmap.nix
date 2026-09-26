# Kernel qualification of a live, journal-only idmapped directory view.
{
  testing,
  pkgs,
}:
testing.mkVMTest {
  name = "sandbox-cache-journal-idmap";
  rootfsDeps = [pkgs.bash pkgs.coreutils pkgs.util-linux];
  memory = 256;
  testScript = ''
    set -eu
    exec > /dev/ttyS0 2>&1
    set -x
    source=/var/lib/aos/sandbox/cache-residency-journals
    view=/run/aos/sandbox-policy-cache-journals
    mkdir -p /var/lib/aos/sandbox /run/aos
    chmod 0755 /var/lib/aos /var/lib/aos/sandbox /run/aos
    mkdir -m 0700 "$source" "$view"
    chown 811:811 "$source"

    printf 'first\n' > "$source/state.journal"
    chown 811:811 "$source/state.journal"
    chmod 0600 "$source/state.journal"

    ${pkgs.util-linux}/bin/mount --bind \
      --map-users 811:0:1 --map-groups 811:0:1 \
      --options ro,nosuid,nodev,noexec,nosymfollow \
      "$source" "$view"
    trap '${pkgs.util-linux}/bin/umount --no-canonicalize /run/aos/sandbox-policy-cache-journals' EXIT

    test "$(stat -c '%F:%u:%g:%a' "$view")" = directory:0:0:700
    test "$(stat -c '%d:%i' "$source")" = "$(stat -c '%d:%i' "$view")"
    mount_options="$(${pkgs.util-linux}/bin/findmnt --noheadings --mountpoint "$view" --output VFS-OPTIONS)"
    for option in ro nosuid nodev noexec nosymfollow; do
      case ",$mount_options," in
        *,$option,*) ;;
        *) exit 1 ;;
      esac
    done
    ${pkgs.util-linux}/bin/setpriv \
      --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
      ${pkgs.coreutils}/bin/cat "$view/state.journal" > /tmp/cache-view-read
    test "$(cat /tmp/cache-view-read)" = first
    if ${pkgs.util-linux}/bin/setpriv \
      --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
      ${pkgs.coreutils}/bin/cat "$source/state.journal" >/dev/null 2>&1; then
      exit 1
    fi
    if printf 'denied\n' > "$view/state.journal"; then
      exit 1
    fi

    printf 'replacement\n' > "$source/state.journal.compact.tmp"
    chown 811:811 "$source/state.journal.compact.tmp"
    chmod 0600 "$source/state.journal.compact.tmp"
    mv "$source/state.journal.compact.tmp" "$source/state.journal"
    test "$(cat "$view/state.journal")" = replacement
    test "$(stat -c '%u:%g' "$view/state.journal")" = 0:0
    ln -s state.journal "$source/redirect"
    if cat "$view/redirect" >/dev/null 2>&1; then
      exit 1
    fi
    rm "$source/redirect"

    if ${pkgs.util-linux}/bin/setpriv --reuid 811 --regid 811 --clear-groups \
      ${pkgs.coreutils}/bin/mv "$source" "$source.replaced" >/dev/null 2>&1; then
      exit 1
    fi

    ${pkgs.util-linux}/bin/umount --no-canonicalize "$view"
    trap - EXIT
    ${pkgs.util-linux}/bin/mount --bind \
      --map-users 811:0:1 --map-groups 811:0:1 \
      --options ro,nosuid,nodev,noexec,nosymfollow \
      "$source" "$view"
    test "$(cat "$view/state.journal")" = replacement
    ${pkgs.util-linux}/bin/umount --no-canonicalize "$view"

    # The signer sees two narrow roots as UID 813. Cap-empty root retains only
    # its distinct policy journal view and cannot traverse either signer view.
    object_source=/var/lib/aos/sandbox/cache-residency-objects
    signer_journals=/run/aos/sandbox-cache-signer-journals
    signer_objects=/run/aos/sandbox-cache-signer-objects
    chmod 0755 /run
    mkdir -m 0700 "$object_source" "$signer_journals" "$signer_objects"
    chown 811:811 "$object_source"
    printf 'physical\n' > "$object_source/owner-state"
    printf 'lock\n' > "$object_source/.owner.lock"
    chown 811:811 "$object_source/owner-state" "$object_source/.owner.lock"
    chmod 0600 "$object_source/owner-state" "$object_source/.owner.lock"

    ${pkgs.util-linux}/bin/mount --bind \
      --map-users 811:0:1 --map-groups 811:0:1 \
      --options ro,nosuid,nodev,noexec,nosymfollow \
      "$source" "$view"
    ${pkgs.util-linux}/bin/mount --bind \
      --map-users 811:813:1 --map-groups 811:813:1 \
      --options ro,nosuid,nodev,noexec,nosymfollow \
      "$source" "$signer_journals"
    ${pkgs.util-linux}/bin/mount --bind \
      --map-users 811:813:1 --map-groups 811:813:1 \
      --options ro,nosuid,nodev,noexec,nosymfollow \
      "$object_source" "$signer_objects"
    trap '${pkgs.util-linux}/bin/umount --no-canonicalize /run/aos/sandbox-cache-signer-objects; ${pkgs.util-linux}/bin/umount --no-canonicalize /run/aos/sandbox-cache-signer-journals; ${pkgs.util-linux}/bin/umount --no-canonicalize /run/aos/sandbox-policy-cache-journals' EXIT

    for signer_view in "$signer_journals" "$signer_objects"; do
      test "$(stat -c '%u:%g:%a' "$signer_view")" = 813:813:700
      mount_options="$(${pkgs.util-linux}/bin/findmnt --noheadings --mountpoint "$signer_view" --output VFS-OPTIONS)"
      for option in ro nosuid nodev noexec nosymfollow; do
        case ",$mount_options," in
          *,$option,*) ;;
          *) exit 1 ;;
        esac
      done
    done
    test "$(stat -c '%u:%g:%a' "$signer_objects/owner-state")" = 813:813:600

    ${pkgs.util-linux}/bin/setpriv --reuid 813 --regid 813 --clear-groups \
      ${pkgs.coreutils}/bin/cat "$signer_journals/state.journal" > /tmp/signer-journal-read
    test "$(cat /tmp/signer-journal-read)" = replacement
    ${pkgs.util-linux}/bin/setpriv --reuid 813 --regid 813 --clear-groups \
      ${pkgs.coreutils}/bin/cat "$signer_objects/owner-state" > /tmp/signer-object-read
    test "$(cat /tmp/signer-object-read)" = physical
    if ${pkgs.util-linux}/bin/setpriv --reuid 813 --regid 813 --clear-groups \
      ${pkgs.coreutils}/bin/cat "$object_source/owner-state" >/dev/null 2>&1; then
      exit 1
    fi
    if ${pkgs.util-linux}/bin/setpriv --reuid 813 --regid 813 --clear-groups \
      ${pkgs.coreutils}/bin/cat "$source/state.journal" >/dev/null 2>&1; then
      exit 1
    fi
    if ${pkgs.util-linux}/bin/setpriv --reuid 813 --regid 813 --clear-groups \
      ${pkgs.coreutils}/bin/cat "$view/state.journal" >/dev/null 2>&1; then
      exit 1
    fi
    if ${pkgs.util-linux}/bin/setpriv \
      --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
      ${pkgs.coreutils}/bin/cat "$signer_objects/owner-state" >/dev/null 2>&1; then
      exit 1
    fi
    if ${pkgs.util-linux}/bin/setpriv \
      --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
      ${pkgs.coreutils}/bin/cat "$signer_journals/state.journal" >/dev/null 2>&1; then
      exit 1
    fi
    if ${pkgs.util-linux}/bin/setpriv --reuid 813 --regid 813 --clear-groups \
      ${pkgs.bash}/bin/bash -c 'printf denied >> "$1"' bash "$signer_objects/owner-state" >/dev/null 2>&1; then
      exit 1
    fi

    mkdir -m 0700 /var/lib/aos/sandbox/cache-residency
    chown 811:811 /var/lib/aos/sandbox/cache-residency
    if ${pkgs.util-linux}/bin/setpriv --reuid 813 --regid 813 --clear-groups \
      ${pkgs.coreutils}/bin/ls /var/lib/aos/sandbox/cache-residency >/dev/null 2>&1; then
      exit 1
    fi

    ${pkgs.util-linux}/bin/umount --no-canonicalize "$signer_objects"
    ${pkgs.util-linux}/bin/umount --no-canonicalize "$signer_journals"
    ${pkgs.util-linux}/bin/umount --no-canonicalize "$view"
    trap - EXIT
  '';
}
