{pkgs}:
# All emulator modes boot these exact PID 1 bytes. The serial milestone precedes
# the selectable request, which stops Sim before any subsequent guest work.
pkgs.mkDerivation {
  pname = "crucible-tcg-linux-serial-initramfs";
  version = "0";
  src = ./tcg-linux-serial-guest.c;

  buildDeps = [pkgs.coreutils pkgs.cpio pkgs.pigz pkgs.python3];

  phases = [
    {
      name = "build-common-serial-initramfs";
      script = ''
        set -eu
        ${pkgs.python3}/bin/python3 ${./tcg-linux-serial-guest-test.py} --source "$src"
        cc -static -O2 -o init "$src"
        strip --strip-all init

        mkdir -p root "$out"
        cp init root/init
        chmod 0755 root/init
        (
          cd root
          find . -print0 \
            | LC_ALL=C sort -z \
            | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
            | pigz -9 -n > "$out/initrd.img"
        )
        test -s "$out/initrd.img"

        cat > "$out/evidence.env" <<'EVIDENCE'
        guest_format=diskless-linux-initramfs
        common_milestone=CRUCIBLE_TCG_BOOT_READY_V1-complete-serial-line
        common_milestone_position=after-setup-before-authenticated-readiness-request
        serial_device=existing-COM1-kernel-console-without-reconfiguration
        serial_failure=bounded-transmitter-poll-or-DLAB-set-exits-PID1-with-112
        authenticated_readiness=flight.ready-request-sequence-2-vcpu-0
        EVIDENCE
      '';
    }
  ];
}
