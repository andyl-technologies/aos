{
  pkgs,
  lib,
}: let
  fcLib = import ../../lib/testing/firecracker.nix {inherit pkgs lib;};
  prefixSamples = 20000;

  rootfs = fcLib.mkFirecrackerRootfs {
    pname = "crucible-phase0-s1";
    rootfsDeps = [];
    testScript = ''
      echo "CRUCIBLE_S1_READY"
      i=0
      while [ "$i" -lt 32 ]; do
        printf 'CRUCIBLE_S1_STEP:%02d\n' "$i"
        i=$((i + 1))
      done
    '';
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s1-spike";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.gawk
      pkgs.grep
      pkgs.qemu-crucible
      pkgs.crucible-qemu-trace-plugin
    ];

    ROOTFS = builtins.toString rootfs;
    KERNEL = builtins.toString pkgs.linux;
    PLUGIN = "${pkgs.crucible-qemu-trace-plugin}/lib/qemu/plugins/crucible-qemu-trace-plugin.so";
    PREFIX_SAMPLES = builtins.toString prefixSamples;

    phases = [
      {
        name = "s1-run-twice-and-diff";
        script = ''
          set -eu

          unset LD_LIBRARY_PATH || true

          vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
          if [ -z "$vmlinuz" ]; then
            echo "crucible S1: no vmlinuz under $KERNEL/boot" >&2
            exit 1
          fi

          seed="$TMPDIR/seed.bin"
          printf 'crucible-phase0-s1-seed-v1\n' > "$seed"

          run_one() {
            label="$1"
            cp "$ROOTFS" "$TMPDIR/rootfs-$label.img"
            chmod u+w "$TMPDIR/rootfs-$label.img"

            timeout 300 qemu-system-x86_64 \
              -nodefaults \
              -no-user-config \
              -display none \
              -monitor none \
              -machine q35 \
              -accel tcg,thread=single \
              -icount shift=0,sleep=off,align=off \
              -cpu qemu64 \
              -m 512 \
              -smp 1 \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -seed 0x0010c001 \
              -fw_cfg name=opt/crucible/seed,file="$seed" \
              -kernel "$vmlinuz" \
              -append "console=ttyS0 reboot=k panic=1 root=/dev/vda ro init=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0" \
              -drive id=rootfs,file="$TMPDIR/rootfs-$label.img",format=raw,if=none,cache=unsafe \
              -device virtio-blk-pci,drive=rootfs \
              -chardev file,id=serial0,path="$TMPDIR/serial-$label.log" \
              -serial chardev:serial0 \
              -plugin "$PLUGIN",out="$TMPDIR/trace-$label.jsonl",cadence=100000 \
              -no-reboot
          }

          run_one a
          run_one b

          if ! grep -q "TEST_RESULT:PASS" "$TMPDIR/serial-a.log"; then
            echo "crucible S1: first run did not pass" >&2
            cat "$TMPDIR/serial-a.log" >&2 || true
            exit 1
          fi
          if ! grep -q "TEST_RESULT:PASS" "$TMPDIR/serial-b.log"; then
            echo "crucible S1: second run did not pass" >&2
            cat "$TMPDIR/serial-b.log" >&2 || true
            exit 1
          fi

          mkdir -p "$out"

          head -n "$PREFIX_SAMPLES" "$TMPDIR/trace-a.jsonl" > "$TMPDIR/trace-a-prefix.jsonl"
          head -n "$PREFIX_SAMPLES" "$TMPDIR/trace-b.jsonl" > "$TMPDIR/trace-b-prefix.jsonl"
          trace_a_prefix_lines=$(wc -l < "$TMPDIR/trace-a-prefix.jsonl")
          trace_b_prefix_lines=$(wc -l < "$TMPDIR/trace-b-prefix.jsonl")
          if [ "$trace_a_prefix_lines" -ne "$PREFIX_SAMPLES" ] || [ "$trace_b_prefix_lines" -ne "$PREFIX_SAMPLES" ]; then
            echo "crucible S1 smoke: expected $PREFIX_SAMPLES trace samples, got $trace_a_prefix_lines/$trace_b_prefix_lines" >&2
            exit 1
          fi
          if ! diff -u "$TMPDIR/trace-a-prefix.jsonl" "$TMPDIR/trace-b-prefix.jsonl" > "$out/prefix.diff"; then
            echo "crucible S1 smoke: instruction-stream prefix mismatch" >&2
            cat "$out/prefix.diff" >&2
            exit 1
          fi

          full_match=true
          if ! cmp -s "$TMPDIR/trace-a.jsonl" "$TMPDIR/trace-b.jsonl"; then
            full_match=false
            diff -u "$TMPDIR/trace-a.jsonl" "$TMPDIR/trace-b.jsonl" > "$TMPDIR/trace.diff" || true
            head -n 200 "$TMPDIR/trace.diff" > "$out/trace.diff"
          fi

          cp "$TMPDIR/trace-a.jsonl" "$out/trace-a.jsonl"
          cp "$TMPDIR/trace-b.jsonl" "$out/trace-b.jsonl"
          cp "$TMPDIR/serial-a.log" "$out/serial-a.log"
          cp "$TMPDIR/serial-b.log" "$out/serial-b.log"
          {
            echo "PASS"
            echo "witness=instruction-stream"
            echo "cadence=100000"
            echo "prefix_samples=$PREFIX_SAMPLES"
            echo "instruction_stream_prefix_match=true"
            echo "instruction_stream_full_match=$full_match"
            echo "det29_complete=false"
            echo "s1_complete=false"
          } > "$out/result"
        '';
      }
    ];
  }
