{
  pkgs,
  qemuPackage ? pkgs.qemu-crucible,
}:
pkgs.mkDerivation {
  pname = "crucible-phase2-qemu-exact-preemption-live";
  version = "0";
  src = null;

  buildDeps = [
    pkgs.coreutils
    pkgs.glib.dev
    pkgs.python3
  ];

  phases = [
    {
      name = "run-exact-preemption-live";
      script = ''
        set -eu

        cc -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-unused-parameter \
          -shared -fPIC -I${qemuPackage}/include \
          -I${pkgs.glib.dev}/include/glib-2.0 \
          -I${pkgs.glib.dev}/lib/glib-2.0/include \
          ${./phase2-qemu-exact-preemption-plugin.c} \
          -o exact-preemption-plugin.so

        ${pkgs.python3}/bin/python3 \
          ${./phase2-qemu-exact-preemption-live.py} \
          --x86 ${qemuPackage}/bin/qemu-system-x86_64 \
          --arm ${qemuPackage}/bin/qemu-system-aarch64 \
          --plugin "$PWD/exact-preemption-plugin.so" \
          > result

        mkdir -p "$out"
        cp result "$out/result"
      '';
    }
  ];
}
