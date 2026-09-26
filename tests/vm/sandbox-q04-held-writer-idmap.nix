# Kernel prerequisite for Q04 same-cut signer views under a retained Controller writer.
# The files here are synthetic: this does not qualify a V8 ACK or owner release.
{
  testing,
  pkgs,
}:
testing.mkVMTest {
  name = "sandbox-q04-held-writer-idmap";
  rootfsDeps = [pkgs.bash pkgs.coreutils pkgs.util-linux];
  memory = 256;
  testScript = ''
    set -eu
    exec > /dev/ttyS0 2>&1
    set -x

    source=/var/lib/aos/sandbox/source-domains
    cache=/var/lib/aos/sandbox/cache-residency-journals
    objects=/var/lib/aos/sandbox/cache-residency-objects
    source_view=/run/aos/sandbox-source-signer-journal
    cache_view=/run/aos/sandbox-cache-signer-journals
    object_view=/run/aos/sandbox-cache-signer-objects
    root_view=/run/aos/sandbox-policy-cache-journals

    mkdir -p /var/lib/aos/sandbox /run/aos
    chmod 0755 /var/lib/aos /var/lib/aos/sandbox /run /run/aos
    for directory in "$source" "$cache" "$objects"; do
      mkdir -m 0700 "$directory"
      chown 811:811 "$directory"
    done
    for directory in "$source_view" "$cache_view" "$object_view" "$root_view"; do
      mkdir -m 0700 "$directory"
    done

    for name in source-domains-v1.journal source-domains-v1.journal.lock; do
      printf 'source\n' > "$source/$name"
      chown 811:811 "$source/$name"
      chmod 0600 "$source/$name"
    done
    for journal in state authority clock policy-hold; do
      for suffix in journal journal.lock; do
        printf 'cache\n' > "$cache/$journal.$suffix"
        chown 811:811 "$cache/$journal.$suffix"
        chmod 0600 "$cache/$journal.$suffix"
      done
    done
    for name in owner-state .owner.lock; do
      printf 'physical\n' > "$objects/$name"
      chown 811:811 "$objects/$name"
      chmod 0600 "$objects/$name"
    done

    mount_view() {
      ${pkgs.util-linux}/bin/mount --bind \
        --map-users "811:$3:1" --map-groups "811:$3:1" \
        --options ro,nosuid,nodev,noexec,nosymfollow "$1" "$2"
      test "$(stat -c '%d:%i' "$1")" = "$(stat -c '%d:%i' "$2")"
      test "$(stat -c '%F:%u:%g:%a' "$2")" = "directory:$3:$3:700"
      options="$(${pkgs.util-linux}/bin/findmnt --noheadings --mountpoint "$2" --output VFS-OPTIONS)"
      for option in ro nosuid nodev noexec nosymfollow; do
        case ",$options," in
          *,$option,*) ;;
          *) exit 1 ;;
        esac
      done
    }
    unmount_views() {
      for view in "$object_view" "$cache_view" "$root_view" "$source_view"; do
        ${pkgs.util-linux}/bin/umount --no-canonicalize "$view"
      done
    }
    mount_view "$source" "$source_view" 814
    mount_view "$cache" "$root_view" 0
    mount_view "$cache" "$cache_view" 813
    mount_view "$objects" "$object_view" 813
    trap 'unmount_views' EXIT

    assert_named_pair() {
      test "$(stat -c '%d:%i' "$1")" = "$(stat -c '%d:%i' "$2")"
      test "$(stat -c '%u:%g:%a:%h' "$2")" = "$3:$3:600:1"
    }
    for name in source-domains-v1.journal source-domains-v1.journal.lock; do
      assert_named_pair "$source/$name" "$source_view/$name" 814
    done
    for journal in state authority clock policy-hold; do
      for suffix in journal journal.lock; do
        assert_named_pair "$cache/$journal.$suffix" "$cache_view/$journal.$suffix" 813
        assert_named_pair "$cache/$journal.$suffix" "$root_view/$journal.$suffix" 0
      done
    done
    for name in owner-state .owner.lock; do
      assert_named_pair "$objects/$name" "$object_view/$name" 813
    done
    test "$(${pkgs.util-linux}/bin/setpriv --reuid 814 --regid 814 --clear-groups \
      ${pkgs.coreutils}/bin/cat "$source_view/source-domains-v1.journal")" = source
    test "$(${pkgs.util-linux}/bin/setpriv --reuid 813 --regid 813 --clear-groups \
      ${pkgs.coreutils}/bin/cat "$cache_view/state.journal")" = cache
    test "$(${pkgs.util-linux}/bin/setpriv --reuid 813 --regid 813 --clear-groups \
      ${pkgs.coreutils}/bin/cat "$object_view/owner-state")" = physical

    # One Controller identity keeps the Source, protected Cache, and physical
    # Cache lock FDs live while the independent signer identities inspect them.
    ${pkgs.util-linux}/bin/setpriv --reuid 811 --regid 811 --clear-groups \
      ${pkgs.bash}/bin/bash -c '
        exec 8< "$1/source-domains-v1.journal"
        exec 9< "$1/source-domains-v1.journal.lock"
        exec 10< "$2/state.journal.lock"
        exec 11< "$2/authority.journal.lock"
        exec 12< "$2/clock.journal.lock"
        exec 13< "$2/policy-hold.journal.lock"
        exec 14< "$3/.owner.lock"
        for fd in 9 10 11 12 13 14; do
          ${pkgs.util-linux}/bin/flock --exclusive "$fd"
        done
        printf ready > /tmp/q04-writer-ready
        exec ${pkgs.coreutils}/bin/sleep 120
      ' bash "$source" "$cache" "$objects" &
    writer_pid=$!
    trap 'kill "$writer_pid" 2>/dev/null || true; wait "$writer_pid" 2>/dev/null || true; unmount_views' EXIT
    for attempt in 1 2 3 4 5; do
      test -e /tmp/q04-writer-ready && break
      sleep 1
    done
    test -e /tmp/q04-writer-ready

    deny_lock() {
      if ${pkgs.util-linux}/bin/setpriv --reuid "$1" --regid "$1" --clear-groups \
        ${pkgs.bash}/bin/bash -c 'exec 9< "$1"; ${pkgs.util-linux}/bin/flock --exclusive --nonblock 9' bash "$2"; then
        exit 1
      fi
    }
    deny_lock 814 "$source_view/source-domains-v1.journal.lock"
    for journal in state authority clock policy-hold; do
      deny_lock 813 "$cache_view/$journal.journal.lock"
    done
    deny_lock 813 "$object_view/.owner.lock"

    for path in "$source/source-domains-v1.journal" "$cache/state.journal" "$objects/owner-state"; do
      if ${pkgs.util-linux}/bin/setpriv --reuid 813 --regid 813 --clear-groups \
        ${pkgs.coreutils}/bin/cat "$path" >/dev/null 2>&1; then
        exit 1
      fi
    done
    if ${pkgs.util-linux}/bin/setpriv --reuid 814 --regid 814 --clear-groups \
      ${pkgs.coreutils}/bin/cat "$cache_view/state.journal" >/dev/null 2>&1; then
      exit 1
    fi
    if ${pkgs.util-linux}/bin/setpriv --reuid 813 --regid 813 --clear-groups \
      ${pkgs.coreutils}/bin/cat "$source_view/source-domains-v1.journal" >/dev/null 2>&1; then
      exit 1
    fi
    if ${pkgs.util-linux}/bin/setpriv --reuid 814 --regid 814 --clear-groups \
      ${pkgs.coreutils}/bin/cat "$source/source-domains-v1.journal" >/dev/null 2>&1; then
      exit 1
    fi
    if ${pkgs.util-linux}/bin/setpriv --reuid 813 --regid 813 --clear-groups \
      ${pkgs.coreutils}/bin/cat "$root_view/state.journal" >/dev/null 2>&1; then
      exit 1
    fi
    for pair in "814:$source_view/source-domains-v1.journal" \
      "813:$cache_view/state.journal" "813:$object_view/owner-state"; do
      uid="''${pair%%:*}"
      path="''${pair#*:}"
      if ${pkgs.util-linux}/bin/setpriv --reuid "$uid" --regid "$uid" --clear-groups \
        ${pkgs.bash}/bin/bash -c 'printf denied >> "$1"' bash "$path" >/dev/null 2>&1; then
        exit 1
      fi
    done

    # A retained FD is not a named-file proof: rename-and-replace changes the
    # signer-visible inode even though the Controller still holds the old FD.
    held_journal="$(stat -Lc '%d:%i' "/proc/$writer_pid/fd/8")"
    held_lock="$(stat -Lc '%d:%i' "/proc/$writer_pid/fd/9")"
    mv "$source/source-domains-v1.journal" "$source/source-domains-v1.journal.old"
    mv "$source/source-domains-v1.journal.lock" "$source/source-domains-v1.journal.lock.old"
    for name in source-domains-v1.journal source-domains-v1.journal.lock; do
      printf 'substituted\n' > "$source/$name"
      chown 811:811 "$source/$name"
      chmod 0600 "$source/$name"
    done
    test "$held_journal" != "$(stat -c '%d:%i' "$source_view/source-domains-v1.journal")"
    test "$held_lock" != "$(stat -c '%d:%i' "$source_view/source-domains-v1.journal.lock")"
    test "$held_journal" = "$(stat -Lc '%d:%i' "/proc/$writer_pid/fd/8")"
    test "$held_lock" = "$(stat -Lc '%d:%i' "/proc/$writer_pid/fd/9")"
    mv "$source/source-domains-v1.journal.old" "$source/source-domains-v1.journal"
    mv "$source/source-domains-v1.journal.lock.old" "$source/source-domains-v1.journal.lock"
    assert_named_pair "$source/source-domains-v1.journal" "$source_view/source-domains-v1.journal" 814
    assert_named_pair "$source/source-domains-v1.journal.lock" "$source_view/source-domains-v1.journal.lock" 814

    held_cache_lock="$(stat -Lc '%d:%i' "/proc/$writer_pid/fd/10")"
    mv "$cache/state.journal.lock" "$cache/state.journal.lock.old"
    printf 'substituted\n' > "$cache/state.journal.lock"
    chown 811:811 "$cache/state.journal.lock"
    chmod 0600 "$cache/state.journal.lock"
    test "$held_cache_lock" != "$(stat -c '%d:%i' "$cache_view/state.journal.lock")"
    test "$held_cache_lock" != "$(stat -c '%d:%i' "$root_view/state.journal.lock")"
    mv "$cache/state.journal.lock.old" "$cache/state.journal.lock"
    assert_named_pair "$cache/state.journal.lock" "$cache_view/state.journal.lock" 813
    assert_named_pair "$cache/state.journal.lock" "$root_view/state.journal.lock" 0

    held_physical_lock="$(stat -Lc '%d:%i' "/proc/$writer_pid/fd/14")"
    mv "$objects/.owner.lock" "$objects/.owner.lock.old"
    printf 'substituted\n' > "$objects/.owner.lock"
    chown 811:811 "$objects/.owner.lock"
    chmod 0600 "$objects/.owner.lock"
    test "$held_physical_lock" != "$(stat -c '%d:%i' "$object_view/.owner.lock")"
    mv "$objects/.owner.lock.old" "$objects/.owner.lock"
    assert_named_pair "$objects/.owner.lock" "$object_view/.owner.lock" 813

    kill "$writer_pid"
    wait "$writer_pid" 2>/dev/null || true
    ${pkgs.util-linux}/bin/setpriv --reuid 814 --regid 814 --clear-groups \
      ${pkgs.bash}/bin/bash -c 'exec 9< "$1"; ${pkgs.util-linux}/bin/flock --exclusive --nonblock 9' \
      bash "$source_view/source-domains-v1.journal.lock"
    ${pkgs.util-linux}/bin/setpriv --reuid 813 --regid 813 --clear-groups \
      ${pkgs.bash}/bin/bash -c 'exec 9< "$1"; ${pkgs.util-linux}/bin/flock --exclusive --nonblock 9' \
      bash "$object_view/.owner.lock"
    trap 'unmount_views' EXIT
    unmount_views
    mount_view "$source" "$source_view" 814
    mount_view "$cache" "$root_view" 0
    mount_view "$cache" "$cache_view" 813
    mount_view "$objects" "$object_view" 813
    for name in source-domains-v1.journal source-domains-v1.journal.lock; do
      assert_named_pair "$source/$name" "$source_view/$name" 814
    done
    for name in owner-state .owner.lock; do
      assert_named_pair "$objects/$name" "$object_view/$name" 813
    done
    for journal in state authority clock policy-hold; do
      for suffix in journal journal.lock; do
        assert_named_pair "$cache/$journal.$suffix" "$cache_view/$journal.$suffix" 813
        assert_named_pair "$cache/$journal.$suffix" "$root_view/$journal.$suffix" 0
      done
    done
    unmount_views
    trap - EXIT
  '';
}
