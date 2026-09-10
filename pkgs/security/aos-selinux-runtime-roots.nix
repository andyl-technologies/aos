##! aos-selinux-runtime-roots — Fixed labeled runtime-root provisioner
{
  mkDerivation,
  aos-selinux-production-policy,
  buildPackages,
}:
mkDerivation {
  pname = "aos-selinux-runtime-roots";
  version = "1";
  src = null;

  buildDeps = [
    buildPackages.binutils
  ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    {
      name = "build";
      script = ''
        set -eu

        cp \
          ${aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33 \
          expected_policy.bin
        "$LD" -r -b binary -o expected_policy.o expected_policy.bin
        "$OBJCOPY" \
          --rename-section .data=.rodata,alloc,load,readonly,data,contents \
          expected_policy.o

        mkdir -p "$out/bin"
        $CC -std=c17 -O2 -Wall -Wextra -Werror -static \
          -Wl,-z,noexecstack \
          ${./aos-selinux-runtime-roots.c} \
          expected_policy.o \
          -o "$out/bin/aos-selinux-runtime-roots"

        if ${buildPackages.binutils}/bin/readelf -lW \
          "$out/bin/aos-selinux-runtime-roots" | grep -q INTERP; then
          echo "runtime-root provisioner unexpectedly has an ELF interpreter" >&2
          exit 1
        fi
        if ${buildPackages.binutils}/bin/readelf -dW \
          "$out/bin/aos-selinux-runtime-roots" | grep -q '(NEEDED)'; then
          echo "runtime-root provisioner unexpectedly has a dynamic dependency" >&2
          exit 1
        fi
      '';
    }
  ];

  passthru = {
    expectedPolicy =
      "${aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33";
    immutablePolicy = aos-selinux-production-policy;
    evidenceSources = [
      (builtins.path {
        path = ./aos-selinux-runtime-roots.nix;
        name = "aos-selinux-runtime-roots.nix";
      })
      (builtins.path {
        path = ./aos-selinux-runtime-roots.c;
        name = "aos-selinux-runtime-roots.c";
      })
    ];
  };

  meta = {
    description = "Provision fixed SELinux-labeled runtime roots";
    license = "MIT";
  };
}
