# Runs native ownership checks under a genuinely protected filesystem root.
{util-linux}: script: ''
  terrane_check_script=$(mktemp "$TMPDIR/terrane-check.XXXXXXXX")
  cat > "$terrane_check_script" <<'TERRANE_CHECK'
  set -eu
  cd "$TERRANE_CHECK_WORKDIR"
  ${script}
  TERRANE_CHECK
  export TERRANE_CHECK_WORKDIR="$PWD"
  # Genuine procfs read-error fixtures bind only their own process directory
  # beneath protected fixture storage, retaining every physical ownership check.
  export TERRANE_TEST_PROC_MOUNT="${util-linux}/bin/mount"
  export TERRANE_TEST_PROC_UMOUNT="${util-linux}/bin/umount"

  # The outer sandbox root may have an unmapped owner. A private user and
  # mount namespace supplies a real protected root while preserving the
  # sandbox's input mounts, network isolation and actual checked files.
  ${util-linux}/bin/unshare --user --map-root-user --mount --propagation private "$CONFIG_SHELL" -c '
    set -eu
    terrane_test_root=$(mktemp -d "$TMPDIR/terrane-protected-root.XXXXXXXX")
    mkdir -p "$terrane_test_root/nix/store" "$terrane_test_root/dev" \
      "$terrane_test_root/proc" "$terrane_test_root/tmp"
    chmod 1777 "$terrane_test_root/tmp"

    # Recursive binds retain locked submounts inherited from Nix. Bind the
    # build tree and any external Cargo target at their original absolute
    # paths so existing compiler fingerprints and artifact paths stay valid.
    ${util-linux}/bin/mount --rbind /nix/store "$terrane_test_root/nix/store"
    ${util-linux}/bin/mount --rbind /dev "$terrane_test_root/dev"
    ${util-linux}/bin/mount --rbind /proc "$terrane_test_root/proc"
    mkdir -p "$terrane_test_root$NIX_BUILD_TOP"
    ${util-linux}/bin/mount --rbind "$NIX_BUILD_TOP" "$terrane_test_root$NIX_BUILD_TOP"
    if [ -n "''${CARGO_TARGET_DIR:-}" ]; then
      case "$CARGO_TARGET_DIR" in
        "$NIX_BUILD_TOP"/*) ;;
        *)
          mkdir -p "$terrane_test_root$CARGO_TARGET_DIR"
          ${util-linux}/bin/mount --bind "$CARGO_TARGET_DIR" "$terrane_test_root$CARGO_TARGET_DIR"
          ;;
      esac
    fi
    chroot "$terrane_test_root" "$CONFIG_SHELL" "$1"
  ' terrane-check "$terrane_check_script"
''
