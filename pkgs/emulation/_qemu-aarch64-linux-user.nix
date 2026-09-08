##! Native AArch64 Linux user-mode emulator for explicit cross-build probes.
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  meson,
  ninja,
  python3,
  setuptools,
  distlib,
  patchelf,
  gcc-libs,
  glib,
  zlib,
}: let
  series = import ./qemu-patches/_series.nix;
  version = series.qemuVersion;
  configureFlags = [
    "--target-list=aarch64-linux-user"
    "--disable-system"
    "--enable-linux-user"
    "--disable-bsd-user"
    "--disable-kvm"
    "--disable-plugins"
    "--disable-tools"
    "--disable-docs"
    "--disable-guest-agent"
    "--enable-pie"
  ];
  configureFlagsMaterial = builtins.concatStringsSep "\n" configureFlags;
  configureFlagsHash = builtins.hashString "sha256" "${configureFlagsMaterial}\n";
  configureFlagsScript = builtins.concatStringsSep " " configureFlags;
in
  mkDerivation {
    pname = "qemu-aarch64-linux-user";
    inherit version;

    src = fetchurl {
      urls = [series.qemuSourceUrl];
      hash = series.qemuSourceHash;
    };

    buildDeps = [
      gnumake
      pkg-config
      meson
      ninja
      python3
      setuptools
      distlib
      patchelf
      glib.dev
      glib.tools
    ];
    runtimeDeps = [
      gcc-libs
      glib
      zlib
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd qemu-${version}

          # QEMU's source scripts run only as native build tools here.
          find . -type f -name '*.py' | while read f; do
            if head -n 1 "$f" | grep -q '^#!'; then
              sed -i "1s|#!/usr/bin/env python3|#!${python3}/bin/python3|" "$f"
              sed -i "1s|#!/usr/bin/python3|#!${python3}/bin/python3|" "$f"
            fi
          done
        '';
      }
      {
        name = "configure";
        script = ''
          export PYTHONPATH="${meson}/lib/python3/site-packages:${distlib}/lib/python3.14/site-packages:${setuptools}/lib/python3.14/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
          export PYTHON=${python3}/bin/python3
          export PKG_CONFIG=${pkg-config}/bin/pkg-config
          export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
          export C_INCLUDE_PATH="${glib.dev}/include''${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"
          export LDFLAGS="''${LDFLAGS:-} -L${glib.dev}/lib"

          "$CONFIG_SHELL" ./configure \
            --prefix="$out" \
            ${configureFlagsScript}
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          make install
          test -x "$out/bin/qemu-aarch64"
          test ! -e "$out/bin/qemu-img"
          test ! -e "$out/bin/qemu-system-aarch64"

          # Host emulation threads require glibc's lazy unwind path when they
          # exit. Make native libgcc_s a direct, hermetic runtime dependency;
          # QEMU's link pipeline did not retain this otherwise-unused dependency
          # in the final ELF when it was supplied through ordinary link flags.
          ${patchelf}/bin/patchelf --add-needed libgcc_s.so.1 \
            "$out/bin/qemu-aarch64"
          ${patchelf}/bin/patchelf --add-rpath ${gcc-libs}/lib \
            "$out/bin/qemu-aarch64"
          ${patchelf}/bin/patchelf --print-needed "$out/bin/qemu-aarch64" | \
            grep -Fx libgcc_s.so.1
          ${patchelf}/bin/patchelf --print-rpath "$out/bin/qemu-aarch64" | \
            tr ':' '\n' | grep -Fx ${gcc-libs}/lib

          mkdir -p "$out/share/aos/qemu-user" "$out/share/licenses/qemu-aarch64-linux-user"
          cat > "$out/share/aos/qemu-user/build-identity.env" <<'IDENTITY'
          qemu_package=qemu-aarch64-linux-user
          qemu_version=${version}
          qemu_source_hash=${series.qemuSourceHash}
          qemu_configure_flags_hash=${configureFlagsHash}
          qemu_configure_target_list=aarch64-linux-user
          qemu_plugins_enabled=false
          qemu_tools_enabled=false
          qemu_crucible_patches_applied=false
          qemu_system_emulation_enabled=false
          qemu_linux_user_enabled=true
          IDENTITY

          install -m 644 COPYING "$out/share/licenses/qemu-aarch64-linux-user/COPYING"
          install -m 644 LICENSE "$out/share/licenses/qemu-aarch64-linux-user/LICENSE"
          install -m 644 ${../../LICENSES/GPL-2.0-only.txt} \
            "$out/share/licenses/qemu-aarch64-linux-user/GPL-2.0-only.txt"
          install -m 644 ${../../LICENSES/GPL-2.0-or-later.txt} \
            "$out/share/licenses/qemu-aarch64-linux-user/GPL-2.0-or-later.txt"
        '';
      }
    ];

    postFinalize = ''
      ${patchelf}/bin/patchelf --print-needed "$out/bin/qemu-aarch64" | \
        grep -Fx libgcc_s.so.1
      ${patchelf}/bin/patchelf --print-rpath "$out/bin/qemu-aarch64" | \
        tr ':' '\n' | grep -Fx ${gcc-libs}/lib
    '';

    passthru = {
      inherit configureFlags configureFlagsHash configureFlagsMaterial;
      targetList = "aarch64-linux-user";
      crucibleIntegration = false;
    };

    meta = {
      description = "QEMU AArch64 Linux user-mode emulator for explicit cross-build probes";
      homepage = "https://www.qemu.org";
      license = ["GPL-2.0-only" "GPL-2.0-or-later"];
      mainProgram = "qemu-aarch64";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }
