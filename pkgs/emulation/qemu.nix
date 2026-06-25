##! qemu — Minimal QEMU for KVM-accelerated virtual machines (headless)
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  meson,
  ninja,
  python3,
  setuptools,
  distlib,
  glib,
  pixman,
  zlib,
  libslirp,
  pname ? "qemu",
  enablePlugins ? false,
  applyCruciblePatches ? true,
}: let
  version = "10.0.0";
  pluginFlag =
    if enablePlugins
    then "--enable-plugins"
    else "--disable-plugins";
  patchPhase =
    if applyCruciblePatches
    then ''
      patch -p1 < ${./qemu-patches/0001-crucible-sim-accel.patch}
      patch -p1 < ${./qemu-patches/0002-crucible-rr-fingerprint-helpers.patch}
      patch -p1 < ${./qemu-patches/0003-crucible-icount-no-realtime.patch}
      patch -p1 < ${./qemu-patches/0004-crucible-no-warp-with-plugin.patch}
      patch -p1 < ${./qemu-patches/0005-crucible-det-glib-prng.patch}
      patch -p1 < ${./qemu-patches/0006-crucible-clock-deadline.patch}
      patch -p1 < ${./qemu-patches/0007-crucible-block-rtc-read.patch}
      patch -p1 < ${./qemu-patches/0008-crucible-det-getrandom.patch}
      patch -p1 < ${./qemu-patches/0009-crucible-net-deterministic.patch}
      patch -p1 < ${./qemu-patches/0010-crucible-plugin-time-advance.patch}
      patch -p1 < ${./qemu-patches/0011-crucible-plugin-icount-raw.patch}
      patch -p1 < ${./qemu-patches/0012-crucible-plugin-vcpu-exit.patch}
      patch -p1 < ${./qemu-patches/0013-crucible-plugin-wake-fd.patch}
      patch -p1 < ${./qemu-patches/0014-crucible-plugin-tcg-exec-cb.patch}
    ''
    else "";
in
  mkDerivation {
    inherit pname;
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.qemu.org/qemu-${version}.tar.xz"
      ];
      hash = "sha256-IsB1YB/c+MeyZxqDnr3O8dTylz62c1JU/S4b0PMLOJY=";
    };

    buildDeps = [
      gnumake
      pkg-config
      meson
      ninja
      python3
      setuptools
      distlib
    ];
    runtimeDeps = [
      glib
      pixman
      zlib
      libslirp
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd qemu-${version}
          ${patchPhase}
          # Patch Python shebangs for Nix sandbox
          find . -type f -name '*.py' | while read f; do
            if head -1 "$f" | grep -q '^#!'; then
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

          ./configure \
            --prefix=$out \
            --target-list=x86_64-softmmu \
            --enable-kvm \
            ${pluginFlag} \
            --enable-slirp \
            --enable-virtfs \
            --disable-bsd-user \
            --disable-linux-user \
            --disable-docs \
            --disable-guest-agent \
            --disable-sdl \
            --disable-gtk \
            --disable-opengl \
            --disable-virglrenderer \
            --disable-vnc \
            --disable-spice \
            --disable-curses \
            --disable-xen \
            --disable-brlapi \
            --disable-cap-ng \
            --disable-libusb \
            --disable-usb-redir \
            --disable-vde \
            --disable-nettle \
            --disable-gcrypt \
            --disable-gnutls \
            --disable-libnfs \
            --disable-libssh \
            --disable-smartcard \
            --disable-vhost-net \
            --disable-fdt \
            --audio-drv-list= \
            --enable-pie
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install

          if [ -f include/qemu/qemu-plugin.h ]; then
            mkdir -p "$out/include/qemu"
            install -m 644 include/qemu/qemu-plugin.h "$out/include/qemu/qemu-plugin.h"
          fi

          # Create qemu-kvm symlink for compatibility
          if [ -f "$out/bin/qemu-system-x86_64" ]; then
            ln -s qemu-system-x86_64 "$out/bin/qemu-kvm"
          fi
        '';
      }
    ];

    meta = {
      description = "qemu — machine emulator and virtualizer (minimal KVM build)";
      homepage = "https://www.qemu.org";
      license = "GPL-2.0-only";
    };
  }
