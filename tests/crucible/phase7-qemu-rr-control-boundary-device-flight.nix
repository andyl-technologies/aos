# Proves one real block completion crosses the native RR control boundary.
{
  pkgs,
  lib,
  attrPath,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  guest = import ./phase2-qemu-live-block-io-guest.nix {
    inherit pkgs;
    initialDelayNanoseconds = 5000000;
  };
  flight = pkgs.mkDerivation {
    pname = "crucible-qemu-rr-control-boundary-device-flight";
    version = "0";
    src = source;
    buildDeps = [
      pkgs.openssl
      pkgs.pkg-config
      pkgs.protobuf
      pkgs.rust
      pkgs.sed
    ];
    runtimeDeps = [pkgs.openssl];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "build";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" \
            "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          cargo build --frozen --offline --release \
            --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/target" \
            -p crucible-qemu \
            --example crucible-qemu-rr-control-boundary-device-flight
          mkdir -p "$out/bin"
          cp \
            "$TMPDIR/target/release/examples/crucible-qemu-rr-control-boundary-device-flight" \
            "$out/bin/"
        '';
      }
    ];
  };
  rootfsDeps = [
    flight
    guest
    pkgs.qemu-crucible
    pkgs.crucible-qemu-plugin
    pkgs.linux
    pkgs.e2fsprogs
    pkgs.coreutils
    pkgs.util-linux
    pkgs.grep
    pkgs.sed
  ];
  testScript = ''
    set -eu
    for option in CFS_BANDWIDTH QUOTA QFMT_V2 QUOTACTL; do
      grep -Fxq "CONFIG_$option=y" ${pkgs.linux}/boot/config-*
    done
    test -s ${guest}/initrd.img
    mkdir -p /sys/fs/cgroup
    if ! ${pkgs.util-linux}/bin/mountpoint -q /sys/fs/cgroup; then
      ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
    fi
    echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
    mkdir -p /sys/fs/cgroup/crucible
    echo '+cpu +memory +pids' > /sys/fs/cgroup/crucible/cgroup.subtree_control

    truncate -s 4G /tmp/attempts.img
    ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project \
      -E quotatype=prjquota /tmp/attempts.img
    mkdir /tmp/attempts
    ${pkgs.util-linux}/bin/mount -o loop,prjquota \
      /tmp/attempts.img /tmp/attempts
    mkdir -m 700 /tmp/attempts/run
    cleanup() {
      if ${pkgs.util-linux}/bin/mountpoint -q /tmp/attempts; then
        ${pkgs.util-linux}/bin/umount /tmp/attempts
      fi
    }
    trap cleanup EXIT

    result=/tmp/rr-control-boundary-device-flight.result
    set +e
    ${pkgs.coreutils}/bin/timeout -k 15 600 \
      ${flight}/bin/crucible-qemu-rr-control-boundary-device-flight \
      ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
      ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
      ${pkgs.linux}/boot/vmlinuz-* \
      ${guest}/initrd.img \
      ${pkgs.qemu-crucible}/share/qemu/bios-256k.bin \
      /sys/fs/cgroup/crucible /tmp/attempts/run > "$result" 2>&1
    flight_status=$?
    set -e
    cat "$result"
    if test "$flight_status" -ne 0; then
      exit "$flight_status"
    fi

    for evidence in \
      PASS \
      gate=gate:rr-control-boundary-device-flight \
      block_write_frames=1 \
      node_slot_control_request_derived=true \
      native_completed_wake_pending_request=true \
      native_ack_complete_state_contract=true \
      native_lifecycle_trace_exact=true \
      native_control_sequence_exact=true \
      trace_retained_after_reap=true \
      visible_guest_write_exact=true; do
      test "$(grep -Fxc "$evidence" "$result")" -eq 1
    done
    evidence_value() {
      sed -n "s/^$1=//p" "$result"
    }
    node_request=$(evidence_value node_slot_control_request)
    node_ack=$(evidence_value node_slot_control_ack)
    block_requests=$(evidence_value block_request_frames)
    block_completions=$(evidence_value block_completion_frames)
    native_generation=$(evidence_value native_request_generation)
    native_schedule=$(evidence_value native_schedule_token)
    native_request_state=$(evidence_value native_terminal_request_state)
    native_ack_state=$(evidence_value native_terminal_ack_state)
    native_complete_state=$(evidence_value native_terminal_complete_state)
    test "$(grep -c '^node_slot_control_request=' "$result")" -eq 1
    test "$(grep -c '^node_slot_control_ack=' "$result")" -eq 1
    test "$(grep -c '^block_request_frames=' "$result")" -eq 1
    test "$(grep -c '^block_completion_frames=' "$result")" -eq 1
    test "$(grep -c '^native_request_generation=' "$result")" -eq 1
    test "$(grep -c '^native_schedule_token=' "$result")" -eq 1
    test "$(grep -c '^native_terminal_request_state=' "$result")" -eq 1
    test "$(grep -c '^native_terminal_ack_state=' "$result")" -eq 1
    test "$(grep -c '^native_terminal_complete_state=' "$result")" -eq 1
    test "$(grep -Ec '^native_shutdown_suffix=(none|cancel)$' "$result")" -eq 1
    test "$node_request" -gt 0
    test "$((node_request % 2))" -eq 0
    test "$node_ack" -eq "$((node_request + 1))"
    test "$block_requests" -gt 0
    test "$block_completions" -eq "$block_requests"
    test "$native_generation" -gt 0
    test "$native_schedule" -gt 0
    case "$native_request_state" in
      2|3|4|5|6) ;;
      *) exit 1 ;;
    esac
    case "$native_ack_state" in
      2|4|5) ;;
      *) exit 1 ;;
    esac
    case "$native_complete_state" in
      2|4|5) ;;
      *) exit 1 ;;
    esac

    echo "check=${attrPath}"
  '';
in
  testing.mkVMTest {
    name = "crucible-qemu-rr-control-boundary-device-flight";
    memory = 2048;
    timeout = 900;
    inherit rootfsDeps testScript;
  }
