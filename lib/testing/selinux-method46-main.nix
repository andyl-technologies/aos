##! Native main-journal custody checks without linking production policy.
{pkgs}: let
  native = pkgs.buildPackages;
  support = ../../pkgs/security/_aos-selinux-production-policy;
in
  native.mkDerivation {
    pname = "selinux-method46-main-policy-check";
    version = "1";
    src = support;
    buildDeps = [native.python3 native.setools native.libselinux native.tar native.xz];
    runtimeDeps = [];
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          cp -R "$src" policy-check
          chmod u+w policy-check
          cd policy-check

          # Reuse the production emitter and class-map parser. No copied
          # permission list can silently omit a new selected kernel operation.
          tar --occurrence=1 -xOf ${pkgs.linux.src} \
            linux-${pkgs.linux.version}/security/selinux/include/classmap.h > classmap.h
          $CC -std=c17 -Wall -Wextra -Werror -I. kernel-classmap.c -o emit-classmap
          ./emit-classmap > kernel-classmap.tsv

          export PYTHONPATH=${native.setools}/lib/python3/site-packages
          export AOS_SELINUX_FILE_CONTEXTS_LIBRARY=${native.libselinux}/lib/libselinux.so.1
          export AOS_SELINUX_KERNEL_CLASSMAP="$PWD/kernel-classmap.tsv"
          ${native.python3}/bin/python3 -B method46_policy_test.py

          mkdir -p "$out"
          cp kernel-classmap.tsv "$out/kernel-classmap.tsv"
          printf '%s\n' PASS > "$out/result"
        '';
      }
    ];
  }
