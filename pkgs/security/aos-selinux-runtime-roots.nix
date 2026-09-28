##! aos-selinux-runtime-roots — Fixed labeled runtime-root provisioner
{
  mkDerivation,
  aos-selinux-production-policy,
  buildPackages,
  controllerUid ? 811,
  controllerGid ? 811,
  controllerFloorRequired ? false,
  storageFloorRequired ? false,
  expectedPolicy ? "${aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33",
  expectedPolicyKernel ? null,
}: let
  controllerRequiredFlag =
    if controllerFloorRequired
    then "1"
    else "0";
  storageRequiredFlag =
    if storageFloorRequired
    then "1"
    else "0";
in
  # No runtime owner scalar can change the fixed creation/validation assignment.
  assert builtins.isInt controllerUid && controllerUid > 0 && controllerUid < 65536;
  assert builtins.isInt controllerGid && controllerGid > 0 && controllerGid < 65536;
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
              ${expectedPolicy} \
              expected_policy.bin
            ${buildPackages.binutils}/bin/ld \
              -r -b binary -o expected_policy.o expected_policy.bin
            ${buildPackages.binutils}/bin/objcopy \
              --rename-section .data=.rodata,alloc,load,readonly,data,contents \
              expected_policy.o

            mkdir -p "$out/bin"
            $CC -std=c17 -O2 -Wall -Wextra -Werror -static \
              -DAOS_CONTROLLER_UID=${toString controllerUid} \
              -DAOS_CONTROLLER_GID=${toString controllerGid} \
              -DAOS_CONTROLLER_FLOOR_REQUIRED=${controllerRequiredFlag} \
              -DAOS_STORAGE_FLOOR_REQUIRED=${storageRequiredFlag} \
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
        inherit expectedPolicy expectedPolicyKernel;
        imageOwnerAssignments = {inherit controllerUid controllerGid controllerFloorRequired storageFloorRequired;};
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
