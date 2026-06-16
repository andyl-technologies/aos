##! gnu-efi — EFI development headers, libraries, and CRT objects
{
  mkDerivation,
  fetchurl,
  gnumake,
  binutils,
}: let
  version = "4.0.4";
in
  mkDerivation {
    pname = "gnu-efi";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/ncroxon/gnu-efi/archive/${version}/gnu-efi-${version}.tar.gz"
      ];
      hash = "sha256-QLYehCpO/L+A8+U7LyIMBE6M/kbrTdY5bIO3USQLHA0=";
    };

    buildDeps = [
      gnumake
      binutils
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    # Freestanding EFI CRT and static libraries. The wrapper's PIE and
    # link flags conflict with EFI's hosted/PE output, so opt out entirely.
    hardeningDisable = ["all"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gnu-efi-${version}
        '';
      }
      {
        name = "build";
        script = ''
          # Only build lib and gnuefi (CRT objects), skip apps which tries
          # to link EFI binaries and conflicts with ccWrapper's LDFLAGS.
          # Pre-create output dirs that the out-of-tree build expects.
          ARCH=x86_64
          mkdir -p "$ARCH/lib/runtime" "$ARCH/lib/x86_64" "$ARCH/gnuefi"
          make -j$NIX_BUILD_CORES \
            SUBDIRS="lib gnuefi inc" \
            PREFIX=/usr \
            INSTALLROOT= \
            CC=gcc
        '';
      }
      {
        name = "install";
        script = ''
          # Manual install since the Makefile's install paths are relative
          # to the source tree and don't work with Nix store paths.
          ARCH=x86_64

          # Headers
          mkdir -p $out/include/efi/protocol $out/include/efi/x86_64 $out/include/efi/legacy
          cp inc/*.h $out/include/efi/
          cp inc/protocol/*.h $out/include/efi/protocol/
          cp inc/x86_64/*.h $out/include/efi/x86_64/
          # efilib.h includes "legacy/efilib.h"; ship it so consumers that
          # pull efilib.h (e.g. efitools' lib) resolve cleanly.
          cp inc/legacy/*.h $out/include/efi/legacy/

          # Libraries and CRT objects
          mkdir -p $out/lib
          cp "$ARCH/lib/libefi.a" $out/lib/
          cp "$ARCH/gnuefi/libgnuefi.a" $out/lib/
          cp "$ARCH/gnuefi/crt0-efi-x86_64.o" $out/lib/
          cp gnuefi/elf_x86_64_efi.lds $out/lib/
        '';
      }
    ];

    meta = {
      description = "gnu-efi — EFI development headers, libraries, and CRT objects";
      homepage = "https://github.com/ncroxon/gnu-efi";
      license = "GPL-2.0-or-later";
    };
  }
