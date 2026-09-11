##! NVIDIA open GPU kernel modules
{
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  patch,
  gnumake,
  bash,
  perl,
  kmod,
  elfutils,
  zlib,
  dwarves,
  linux,
  kernel ? linux,
}: let
  version = "610.43.02";
  # NVIDIA names the ARM target aarch64; Linux kbuild names it arm64.
  targetArch =
    if stdenv.hostPlatform.isAarch64
    then "aarch64"
    else "x86_64";
  kernelArch = stdenv.hostPlatform.linuxArch;
  # Kernel build utilities execute on the build machine, even for ARM modules.
  buildElfutils =
    if stdenv.isCross
    then buildPackages.elfutils
    else elfutils;
  buildZlib =
    if stdenv.isCross
    then buildPackages.zlib
    else zlib;
in
  mkDerivation {
    pname = "nvidia-open-kernel-modules";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/NVIDIA/open-gpu-kernel-modules/archive/refs/tags/${version}.tar.gz"
      ];
      hash = "sha256-Yvu+KVJ+ML4yyzizDfrS6U2xyof3elgJDlY8dmmFfmA=";
    };

    buildDeps = [patch gnumake bash perl kmod elfutils zlib dwarves];
    runtimeDeps = [];
    propagatedDeps = [];
    disallowedReferences = [kernel.dev];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd open-gpu-kernel-modules-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          patch -p1 < ${./nvidia-open-kernel-string.patch}

          # Linux renamed the global atomic transaction and its lifecycle
          # helpers. Update the probes too so they still select full-commit
          # callback signatures; per-object state types retain their names.
          if grep -q '^struct drm_atomic_commit {' \
            ${kernel.dev}/lib/modules/${kernel.version}/build/include/drm/drm_atomic.h; then
            perl -pi -e \
              's/\bdrm_atomic_state(?=\b|_(?:alloc|put|free|init|default_clear|default_release)\b)/drm_atomic_commit/g' \
              kernel-open/conftest.sh kernel-open/nvidia-drm/*.[ch]
          fi
        '';
      }
      {
        name = "build";
        script = ''
          export LD_LIBRARY_PATH="${buildElfutils}/lib:${buildZlib}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          export KCFLAGS="''${KCFLAGS:-} -ffile-prefix-map=${kernel.dev}=/build/kernel-sdk"
          make -j"$NIX_BUILD_CORES" modules \
            SYSSRC=${kernel.dev}/lib/modules/${kernel.version}/build \
            SYSOUT=${kernel.dev}/lib/modules/${kernel.version}/build \
            TARGET_ARCH=${targetArch} ARCH=${kernelArch} \
            NV_BUILD_USER=aos NV_BUILD_HOST=aos-builder
        '';
      }
      {
        name = "install";
        script = ''
          export LD_LIBRARY_PATH="${buildElfutils}/lib:${buildZlib}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          make -j"$NIX_BUILD_CORES" modules_install \
            SYSSRC=${kernel.dev}/lib/modules/${kernel.version}/build \
            SYSOUT=${kernel.dev}/lib/modules/${kernel.version}/build \
            TARGET_ARCH=${targetArch} ARCH=${kernelArch} \
            INSTALL_MOD_PATH="$out" \
            INSTALL_MOD_STRIP=1 \
            NV_BUILD_USER=aos NV_BUILD_HOST=aos-builder
          find "$out/lib/modules" -type l -delete
        '';
      }
    ];

    meta = {
      description = "Open NVIDIA GPU kernel modules built for the exact AOS kernel";
      homepage = "https://github.com/NVIDIA/open-gpu-kernel-modules";
      license = "MIT OR GPL-2.0-only";
    };

    passthru = {inherit kernel;};
  }
