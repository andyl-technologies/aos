{pkgs}:
# A minimal diskless Linux initramfs whose PID 1 mounts the crucible 9p export
# and then idles. Unlike virtio-blk (which the kernel probes at device init), a
# virtio-9p filesystem is touched only when userspace issues `mount -t 9p`, so a
# guest that must exercise the crucible 9p data path has to actively mount it.
# This guest performs that mount as its very first act.
#
# It is paired with the `linux-crucible` fixture kernel, which builds the 9p
# transport and filesystem support IN (CONFIG_NET_9P=y, CONFIG_9P_FS=y, no
# loadable modules), so PID 1 does not load any module -- it mounts directly.
# That keeps the initramfs tiny (a single static binary), which matters under
# the sim accelerator: a large initramfs perturbs the guest's early-boot memory
# layout and makes the boot fragile, whereas this one boots as reliably as the
# idle guest.
#
# The mount begins a 9p session (TVERSION/TATTACH) over the crucible-intercepted
# virtio transport. Pre-0039 it blocks forever inside the first 9p op: the host
# servicer computes the response's delivery_icount strictly after the request
# icount, and a guest halted on device I/O cannot advance virtual time to reach
# it. That is the SCHED-8 device-horizon stall the live 9p harness characterizes
# as its baseline. Post-0039 the completion is delivered at delivery_icount, the
# mount returns, and PID 1 idles on a near timer deadline.
pkgs.mkDerivation {
  pname = "crucible-live-9p-io-mount-initramfs";
  version = "0";
  src = null;

  buildDeps = [
    pkgs.coreutils
    pkgs.cpio
    pkgs.pigz
  ];

  phases = [
    {
      name = "build-9p-mount-initramfs";
      script = ''
        set -eu
        cat > init.c <<'INIT_C'
        #include <sys/mount.h>
        #include <sys/stat.h>
        #include <time.h>

        int main(void) {
          mkdir("/mnt", 0755);

          /*
           * Mount the crucible 9p export by its virtio mount tag. 9p support is
           * built into the fixture kernel, so no module load is needed. Pre-0039
           * this call never returns: the first 9p op forwards to the host
           * servicer, whose response is due at a future icount the halted guest
           * cannot reach. Post-0039 the completion is delivered and it returns.
           */
          mount("crucible", "/mnt", "9p", 0,
                "trans=virtio,version=9p2000.L,msize=8192");

          /* If the mount ever returns, park on a near virtual-timer deadline so
           * the guest is a well-defined idle rather than a busy spin. */
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
        guest_init=pid1-mount-9p-then-idle
        guest_kernel=linux-crucible-9p-builtin
        guest_9p_mount=mount-t-9p-crucible-trans-virtio-2000L
        guest_pre_0039=blocks-in-first-9p-op-device-horizon-stall
        EVIDENCE
      '';
    }
  ];
}
