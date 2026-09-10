##! Static PID 1 loader for immutable SELinux stage-1 images.
{
  mkDerivation,
  aos-selinux-production-policy,
  aos-selinux-runtime-roots,
  systemd,
  buildPackages,
  loadedPolicy ? "${aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33",
  expectedPolicy ? "${aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33",
  admissionUnit ? "aos-selinux-stage0-hold.target",
  qualificationPostPinGate ? "",
}: let
  stage0Name = "aos-selinux-stage0";
  admissionUnitValue =
    if admissionUnit == "" || builtins.match "[A-Za-z0-9_.@:-]+\\.target" admissionUnit != null
    then admissionUnit
    else throw "aos-selinux-stage0: admissionUnit must name a .target unit";
  qualificationPostPinGateValue =
    if
      qualificationPostPinGate == ""
      || builtins.match "/run/aos/[A-Za-z0-9_.-]+" qualificationPostPinGate != null
    then qualificationPostPinGate
    else throw "aos-selinux-stage0: qualificationPostPinGate must be empty or a canonical /run/aos path";
in
  mkDerivation {
    pname = stage0Name;
    version = "1";
    src = ./aos-selinux-stage0.c;

    buildDeps = [
      buildPackages.binutils
      buildPackages.patchelf
      buildPackages.python3
    ];
    runtimeDeps = [];
    propagatedDeps = [];
    # These logical identities are executable security inputs, not build-tool
    # leakage. Preserve them through the deny-by-default reference scrub so
    # the output closure retains exactly the two authenticated entry roots.
    nukeRefsKeep = [
      systemd
      aos-selinux-runtime-roots
    ];

    exportReferencesGraph.authenticatedRuntimeClosure = [
      systemd
      aos-selinux-runtime-roots
    ];

    phases = [
      {
        name = "build";
        script = ''
          set -eu

          cp ${loadedPolicy} loaded_policy.bin
          cp ${expectedPolicy} expected_policy.bin

          ${buildPackages.python3}/bin/python3 -B \
            ${./aos-selinux-runtime-manifest.py} \
            --attrs "$NIX_ATTRS_JSON_FILE" \
            --key authenticatedRuntimeClosure \
            --systemd ${systemd}/lib/systemd/systemd \
            --required-static-executable \
              ${aos-selinux-runtime-roots}/bin/aos-selinux-runtime-roots \
            --expected-policy ${expectedPolicy} \
            --patchelf ${buildPackages.patchelf}/bin/patchelf \
            --readelf ${buildPackages.binutils}/bin/readelf \
            --output systemd_runtime_manifest.bin \
            --header systemd_runtime_manifest.h \
            --known-dlopen-soname libacl.so.1 \
            --known-dlopen-soname libaudit.so.1 \
            --known-dlopen-soname libblkid.so.1 \
            --known-dlopen-soname libc.so.6 \
            --known-dlopen-soname libcryptsetup.so.12 \
            --known-dlopen-soname libdw.so.1 \
            --known-dlopen-soname libelf.so.1 \
            --known-dlopen-soname libgcc_s.so.1 \
            --known-dlopen-soname libidn2.so.0 \
            --known-dlopen-soname libkmod.so.2 \
            --known-dlopen-soname liblz4.so.1 \
            --known-dlopen-soname liblzma.so.5 \
            --known-dlopen-soname libmount.so.1 \
            --known-dlopen-soname libnss_files.so.2 \
            --known-dlopen-soname libpam.so.0 \
            --known-dlopen-soname libpcre2-8.so.0 \
            --known-dlopen-soname libseccomp.so.2 \
            --known-dlopen-soname libselinux.so.1 \
            --known-dlopen-soname libsepol.so.2 \
            --known-dlopen-soname libtss2-esys.so.0 \
            --known-dlopen-soname libtss2-mu.so.0 \
            --known-dlopen-soname libtss2-rc.so.0 \
            --known-dlopen-soname libzstd.so.1 \
            --known-absent-dlopen-soname libtss2-tcti-default.so \
            --constructed-dlopen-family libtss2-tcti- .so.0 \
            --known-constructed-dlopen-soname libtss2-tcti-device.so.0

          # These objects are linked into the target executable. Use the
          # target-aware tools exported by the cross cc-wrapper, while all
          # programs executed for inspection remain build-platform tools.
          "$LD" -r -b binary -o loaded_policy.o loaded_policy.bin
          "$LD" -r -b binary -o expected_policy.o expected_policy.bin
          "$LD" -r -b binary \
            -o systemd_runtime_manifest.o systemd_runtime_manifest.bin
          "$OBJCOPY" \
            --rename-section .data=.rodata,alloc,load,readonly,data,contents \
            loaded_policy.o
          "$OBJCOPY" \
            --rename-section .data=.rodata,alloc,load,readonly,data,contents \
            expected_policy.o
          "$OBJCOPY" \
            --rename-section .data=.rodata,alloc,load,readonly,data,contents \
            systemd_runtime_manifest.o

          $CC \
            -std=c17 \
            -D_GNU_SOURCE \
            -Os \
            -Wall \
            -Wextra \
            -Werror \
            -static \
            -Wl,-z,noexecstack \
            "-DAOS_GUARD_PATH=\"$out/bin/${stage0Name}\"" \
            '-DAOS_SYSTEMD_PATH="${systemd}/lib/systemd/systemd"' \
            '-DAOS_ADMISSION_UNIT="${admissionUnitValue}"' \
            '-DAOS_QUALIFICATION_POST_PIN_GATE="${qualificationPostPinGateValue}"' \
            -o ${stage0Name} \
            $src \
            loaded_policy.o \
            expected_policy.o \
            systemd_runtime_manifest.o

          test -x ${stage0Name}
          if ${buildPackages.patchelf}/bin/patchelf --print-interpreter ${stage0Name} \
            > interpreter 2>/dev/null
          then
            echo "stage0 unexpectedly has an ELF interpreter" >&2
            cat interpreter >&2
            exit 1
          fi
          if ${buildPackages.binutils}/bin/readelf -d ${stage0Name} | grep -q '(NEEDED)'; then
            echo "stage0 unexpectedly has a dynamic dependency" >&2
            exit 1
          fi
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/aos-selinux-stage0"
          install -m 0555 ${stage0Name} "$out/bin/${stage0Name}"
          install -m 0444 loaded_policy.bin expected_policy.bin \
            systemd_runtime_manifest.bin systemd_runtime_manifest.h \
            "$out/share/aos-selinux-stage0/"
        '';
      }
    ];

    passthru = {
      inherit admissionUnit loadedPolicy expectedPolicy qualificationPostPinGate;
      immutablePolicy = aos-selinux-production-policy;
      runtimeRootsProvisioner = aos-selinux-runtime-roots;
    };

    meta = {
      description = "Static immutable SELinux policy loader and stage-1 guard";
      license = "Apache-2.0";
    };
  }
