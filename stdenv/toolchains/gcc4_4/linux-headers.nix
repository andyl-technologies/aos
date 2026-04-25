# stdenv/toolchains/gcc4_4/linux-headers.nix — Linux 2.6.32 headers (RHEL 6)
#
# Kernel headers only — no kernel build. Built with tools from the previous tier.
#
{
  prev,
  buildPlatform,
  hostPlatform,
}: let
  fetchSrc = {
    name,
    url,
    hash,
  }:
    builtins.derivation {
      inherit name;
      system = buildPlatform.system;
      builder = "builtin:fetchurl";
      inherit url;
      outputHash = hash;
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      preferLocalBuild = true;
    };

  linux-src = fetchSrc {
    name = "linux-2.6.32.tar.bz2";
    url = "https://cdn.kernel.org/pub/linux/kernel/v2.6/linux-2.6.32.tar.bz2";
    hash = "sha256-UJl4bYC4QH2YphnfACCcI1NRfyLYBP3ZUzs2Kty0UE4=";
  };
in
  builtins.derivation {
    name = "linux-headers-2.6.32";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin"

        cd "$TMPDIR"
        tar xjf ${linux-src}
        cd linux-2.6.32
        chmod -R u+w .

        # Linux 2.6.32's headers_install uses a Perl script, which we don't
        # have. Instead, generate version.h and copy/sanitize headers manually.
        # This is sufficient for glibc — the sanitization strips __user etc.
        # which are defined as empty macros in userspace.

        # Generate version.h from Makefile
        mkdir -p "$out/include/linux"
        printf '#define LINUX_VERSION_CODE %d\n' "$((2*65536 + 6*256 + 32))" > "$out/include/linux/version.h"
        printf '#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))\n' >> "$out/include/linux/version.h"

        # Copy and sanitize headers
        for dir in linux asm-generic; do
          if [ -d "include/$dir" ]; then
            mkdir -p "$out/include/$dir"
            find "include/$dir" -name '*.h' | while read f; do
              rel="''${f#include/}"
              mkdir -p "$out/include/$(dirname "$rel")"
              ${prev.sed}/bin/sed \
                -e 's/__user//g' \
                -e 's/__force//g' \
                -e 's/__iomem//g' \
                -e 's/__bitwise__//g' \
                -e 's/__bitwise//g' \
                -e 's/__packed//g' \
                -e '/^#include <linux\/compiler.h>/d' \
                "$f" > "$out/include/$rel"
            done
          fi
        done

        # Copy arch-specific asm headers
        # Map Nix linuxArch (i386, x86_64) to kernel source arch directory (x86)
        ARCH=${hostPlatform.linuxArch}
        case "$ARCH" in
          i386|x86_64) KARCH=x86 ;;
          *) KARCH="$ARCH" ;;
        esac
        if [ -d "arch/$KARCH/include/asm" ]; then
          mkdir -p "$out/include/asm"
          find "arch/$KARCH/include/asm" -name '*.h' | while read f; do
            rel="''${f#arch/$KARCH/include/}"
            mkdir -p "$out/include/$(dirname "$rel")"
            ${prev.sed}/bin/sed \
              -e 's/__user//g' \
              -e 's/__force//g' \
              -e 's/__iomem//g' \
              -e '/^#include <linux\/compiler.h>/d' \
              "$f" > "$out/include/$rel"
          done
        elif [ -d "include/asm-$ARCH" ]; then
          mkdir -p "$out/include/asm"
          find "include/asm-$ARCH" -name '*.h' | while read f; do
            rel="asm/''${f#include/asm-$ARCH/}"
            mkdir -p "$out/include/$(dirname "$rel")"
            ${prev.sed}/bin/sed \
              -e 's/__user//g' \
              -e 's/__force//g' \
              -e 's/__iomem//g' \
              -e '/^#include <linux\/compiler.h>/d' \
              "$f" > "$out/include/$rel"
          done
        fi

        echo "Linux 2.6.32 headers installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "Linux kernel headers, version 2.6.32";
      homepage = "https://www.kernel.org/";
      license = "GPL-2.0-only";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
