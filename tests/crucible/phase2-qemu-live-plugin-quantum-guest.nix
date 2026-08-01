{pkgs}:
# A minimal diskless Linux initramfs whose PID 1 immediately blocks forever, so
# the kernel idle task runs `sti; hlt` waiting on the periodic virtual timer.
# That is the canonical idle scenario the Rust plugin's idle callback, exact
# deadline introspection, and idle-jump advancement are built for.
pkgs.mkDerivation {
  pname = "crucible-live-plugin-quantum-idle-initramfs";
  version = "0";
  src = null;

  buildDeps = [
    pkgs.coreutils
    pkgs.cpio
    pkgs.pigz
  ];

  phases = [
    {
      name = "build-idle-initramfs";
      script = ''
        set -eu
        cat > init.c <<'INIT_C'
        #include <time.h>

        int main(void) {
          /*
           * Sleep for a fixed short interval forever. Each nanosleep arms a near
           * virtual-timer deadline, so the kernel idle task parks in sti; hlt with
           * a concrete, reachable next deadline that the plugin can idle-jump to,
           * rather than going fully tickless with no near wake.
           */
          const struct timespec interval = {0, 20000000};
          for (;;) {
            nanosleep(&interval, NULL);
          }
          return 0;
        }
        INIT_C

        cc -static -O2 -o init init.c
        strip --strip-all init

        mkdir -p root
        cp init root/init
        chmod 0755 root/init

        mkdir -p "$out"
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
        guest_init=pid1-fixed-interval-nanosleep-loop
        guest_idle=kernel-idle-task-sti-hlt-on-near-virtual-timer-deadline
        EVIDENCE
      '';
    }
  ];
}
