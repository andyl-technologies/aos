# Identical ordinary Linux application bytes for resident and swap experiments.
{pkgs}:
pkgs.mkDerivation {
  pname = "crucible-kernel-swap-materialized-guest";
  version = "1";
  src = ./ram-kernel-swap-workload.c;

  buildDeps = [pkgs.binutils pkgs.coreutils pkgs.cpio pkgs.pigz];
  phases = [
    {
      name = "build-materialization-workload";
      script = ''
        set -eu
        cc -std=c11 -O2 -Wall -Wextra -Werror -static "$src" -o workload
        ./workload --self-test > self-test.log
        mkdir -p "$out" root/dev
        install -m 555 workload "$out/workload"
        install -m 555 workload root/init
        cp self-test.log "$out/self-test.log"
        # Reproducible cpio still preserves the input modification times.
        find root -exec touch -h --date=@1 {} +
        (
          cd root
          find . -print0 \
            | LC_ALL=C sort -z \
            | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
            | pigz -9 -n > "$out/initrd.img"
        )
        test -s "$out/initrd.img"
      '';
    }
  ];
}
