##! Builds the original QEMU x86 BIOS, VGA and option ROMs from source.
##!
##! This provider covers the x86 families only. The complete QEMU firmware
##! roster still requires the separately classified platform providers.
{
  mkDerivation,
  fetchurl,
  gccUnwrapped,
  binutils,
  gnumake,
  bash,
  python3,
  acpica,
  perl,
}: let
  version = "11.1.1";
  recipe = ./qemu-firmware-x86.nix;
  patchInterpreters = builtins.toFile "qemu-firmware-source-interpreters.py" ''
    from pathlib import Path
    import sys

    bash_path, python_path, perl_path = sys.argv[1:]

    replacements = {
        b"#!/bin/sh": b"#!" + bash_path.encode(),
        b"#!/bin/bash": b"#!" + bash_path.encode(),
        b"#!/usr/bin/env bash": b"#!" + bash_path.encode(),
        b"#!/usr/bin/env python": b"#!" + python_path.encode(),
        b"#!/usr/bin/env python3": b"#!" + python_path.encode(),
        b"#!/usr/bin/python": b"#!" + python_path.encode(),
        b"#!/usr/bin/python3": b"#!" + python_path.encode(),
        b"#!/usr/bin/env perl": b"#!" + perl_path.encode(),
        b"#!/usr/bin/perl": b"#!" + perl_path.encode(),
        b"#!/usr/bin/perl -w": b"#!" + perl_path.encode() + b" -w",
    }
    for root in (Path("roms/seabios"), Path("pc-bios/optionrom")):
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            body = path.read_bytes()
            line, separator, rest = body.partition(b"\n")
            if line in replacements:
                path.write_bytes(replacements[line] + separator + rest)
            elif line.startswith(b"#!"):
                raise SystemExit(f"unclassified firmware source interpreter: {path}")
  '';
in
  mkDerivation {
    # Current hosted helpers and raw -m32/-m64 GCC recipes require x86 builders.
    # ROM guest ISA is data; it does not establish another native build port.
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };

    pname = "qemu-firmware-x86";
    inherit version;
    outputs = ["out" "source"];

    src = fetchurl {
      urls = ["https://download.qemu.org/qemu-${version}.tar.xz"];
      hash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
    };

    buildDeps = [gccUnwrapped binutils gnumake bash python3 acpica perl];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar --no-same-owner -xf "$src"
          cd qemu-${version}
          ${python3}/bin/python3 ${patchInterpreters} \
            ${bash}/bin/bash ${python3}/bin/python3 ${perl}/bin/perl
        '';
      }
      {
        name = "configure";
        script = ''
          # Hosted configuration utilities use the ordinary AOS wrapper. Firmware
          # code uses raw GCC so hosted dynamic-loader flags cannot enter ROMs.
          firmware_host_cc="$CC"
          export SOURCE_DATE_EPOCH=1
          mkdir firmware-optionrom-build
          cat > firmware-optionrom-build/config.mak <<EOF
          TOPSRC_DIR=$PWD
          TARGET_DIR=pc-bios/optionrom
          CC=${gccUnwrapped}/bin/gcc
          OBJCOPY=${binutils}/bin/objcopy
          PYTHON=${python3}/bin/python3
          SHELL=${bash}/bin/bash
          EOF
          cp pc-bios/optionrom/Makefile firmware-optionrom-build/Makefile
        '';
      }
      {
        name = "build";
        script = ''
          ${gnumake}/bin/make -C firmware-optionrom-build -j"$NIX_BUILD_CORES" \
            SHELL=${bash}/bin/bash V=1 all

          # These are the original upstream BIOS configurations and all VGA
          # variants; source-built output replaces each corresponding input blob.
          ${gnumake}/bin/make -C roms -j"$NIX_BUILD_CORES" \
            SHELL=${bash}/bin/bash CONFIG_SHELL=${bash}/bin/bash \
            CC=${gccUnwrapped}/bin/gcc HOSTCC="$firmware_host_cc" \
            AS=${binutils}/bin/as LD=${binutils}/bin/ld \
            OBJCOPY=${binutils}/bin/objcopy OBJDUMP=${binutils}/bin/objdump \
            STRIP=${binutils}/bin/strip PYTHON=${python3}/bin/python3 \
            IASL=${acpica}/bin/iasl \
            FIRMWARE_EXTRAVERSION=-aos-qemu-${version} bios vgabios
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/qemu" "$source/share/qemu-firmware-source"
          for name in multiboot_dma linuxboot_dma kvmvapic pvh; do
            cp "firmware-optionrom-build/$name.bin" "$out/share/qemu/$name.bin"
          done
          for name in bios.bin bios-256k.bin bios-microvm.bin \
            vgabios.bin vgabios-stdvga.bin vgabios-cirrus.bin vgabios-vmware.bin \
            vgabios-qxl.bin vgabios-virtio.bin vgabios-bochs-display.bin \
            vgabios-ramfb.bin vgabios-ati.bin; do
            cp "pc-bios/$name" "$out/share/qemu/$name"
          done

          # Complete source retains the original archive, source edits, generated
          # configurations and exact build recipe. No prebuilt ROM is used above.
          cp "$src" "$source/share/qemu-firmware-source/qemu-${version}.tar.xz"
          mkdir "$source/share/qemu-firmware-source/patched"
          cp -R roms/seabios "$source/share/qemu-firmware-source/patched/seabios"
          cp -R pc-bios/optionrom "$source/share/qemu-firmware-source/patched/optionrom"
          cp -R include "$source/share/qemu-firmware-source/patched/include"
          cp -R scripts "$source/share/qemu-firmware-source/patched/scripts"
          cp -R firmware-optionrom-build "$source/share/qemu-firmware-source/optionrom-build"
          cp roms/Makefile roms/config.seabios-* roms/config.vga-* \
            "$source/share/qemu-firmware-source/"
          cp ${recipe} "$source/share/qemu-firmware-source/qemu-firmware-x86.nix"
          cp ${patchInterpreters} "$source/share/qemu-firmware-source/source-interpreters.py"
          cp COPYING LICENSE "$source/share/qemu-firmware-source/"
          ln -s "$source" "$out/share/qemu-firmware-source"
        '';
      }
    ];
  }
