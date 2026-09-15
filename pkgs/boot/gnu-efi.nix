##! gnu-efi — EFI development headers, libraries, and CRT objects
{
  mkDerivation,
  fetchurl,
  lib,
  stdenv,
  buildPackages,
  gnumake,
  binutils,
}: let
  version = "4.0.4";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  efiArch =
    if stdenv.hostPlatform.isAarch64
    then "aarch64"
    else if stdenv.hostPlatform.isx86_64
    then "x86_64"
    else throw "gnu-efi: unsupported architecture ${stdenv.hostPlatform.system}";
  efiTarget =
    if efiArch == "aarch64"
    then "aarch64-unknown-linux-gnu"
    else "x86_64-unknown-linux-gnu";
in
  mkDerivation (
    {
      pname = "gnu-efi";
      qualification.packageProbe = lib.qualification.commandProbe {
        "primary" = {
          "artifacts" = [];
          "expected" = "The headers compile and libefi plus libgnuefi are valid Unix archives.";
          "files" = {
            "consumer.c" = "#include <efi.h>\n\nEFI_STATUS qualification(EFI_GUID *guid) {\n    return guid == 0 ? EFI_INVALID_PARAMETER : EFI_SUCCESS;\n}\n";
          };
          "input" = "A C translation unit using GNU-EFI's public GUID and status types.";
          "operation" = "Compile it against the installed architecture headers and inspect both static libraries.";
          "steps" = [
            {
              "argv" = [
                "@python@"
                "-c"
                "import pathlib, subprocess\ninclude = pathlib.Path(\"@out@/include/efi\")\narchitecture = next(path.parent for path in include.glob(\"*/efibind.h\"))\nresult = subprocess.run([\"@cc@\", \"-I\" + str(include), \"-I\" + str(architecture), \"-c\", \"consumer.c\", \"-o\", \"consumer.o\"], capture_output=True)\nassert result.returncode == 0, result.stderr\nassert pathlib.Path(\"@out@/lib/libefi.a\").read_bytes()[:8] == b\"!<arch>\\n\"\nassert pathlib.Path(\"@out@/lib/libgnuefi.a\").read_bytes()[:8] == b\"!<arch>\\n\"\nprint(\"gnu-efi data passed\")\n"
              ];
              "exit_code" = 0;
              "stderr" = {
                "exact" = "";
              };
              "stdout" = {
                "exact" = "gnu-efi data passed\n";
              };
            }
          ];
        };
        "badInput" = {
          "artifacts" = [];
          "expected" = "The compiler rejects the unknown firmware type.";
          "files" = {
            "invalid.c" = "#include <efi.h>\nAOS_MISSING_EFI_TYPE value;\n";
          };
          "input" = "A C translation unit requesting an EFI type that does not exist.";
          "operation" = "Compile it against the same installed headers.";
          "steps" = [
            {
              "argv" = [
                "@python@"
                "-c"
                "import pathlib, subprocess, sys\ninclude = pathlib.Path(\"@out@/include/efi\")\narchitecture = next(path.parent for path in include.glob(\"*/efibind.h\"))\nresult = subprocess.run([\"@cc@\", \"-I\" + str(include), \"-I\" + str(architecture), \"-c\", \"invalid.c\", \"-o\", \"invalid.o\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"gnu-efi rejected invalid input\\n\")\nraise SystemExit(7)\n"
              ];
              "exit_code" = 7;
              "observes_rejection" = true;
              "stderr" = {
                "exact" = "gnu-efi rejected invalid input\n";
              };
              "stdout" = {
                "exact" = "";
              };
            }
          ];
        };
      };

      inherit version;

      src = fetchurl {
        urls = [
          "https://github.com/ncroxon/gnu-efi/archive/${version}/gnu-efi-${version}.tar.gz"
        ];
        hash = "sha256-QLYehCpO/L+A8+U7LyIMBE6M/kbrTdY5bIO3USQLHA0=";
      };

      buildDeps =
        [
          gnumake
          binutils
        ]
        ++ lib.optional isDarwinCross buildPackages.llvm;
      runtimeDeps = [];
      propagatedDeps = [];

      # Freestanding EFI CRT and static libraries. The wrapper's PIE and
      # link flags conflict with EFI's hosted/PE output, so opt out entirely.
      hardeningDisable = ["all"];

      # Darwin strip tools must not rewrite the deliberately foreign-format
      # ELF archives and CRT objects published for firmware links.
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
          script =
            if isDarwinCross
            then ''
              # GNU-EFI is a freestanding EFI development surface. Its objects
              # remain ELF even when consumed from a Darwin package set, so use
              # Linux-executable LLVM tools without the Mach-O cc wrapper.
              ARCH=${efiArch}
              mkdir -p "$ARCH/lib/runtime" "$ARCH/lib/$ARCH" "$ARCH/gnuefi"
              make -j$NIX_BUILD_CORES \
                SUBDIRS="lib gnuefi inc" \
                PREFIX=/usr \
                INSTALLROOT= \
                ARCH="$ARCH" \
                NO_GLIBC=1 \
                USING_APPLE=0 \
                HOSTCC=${buildPackages.cc}/bin/cc \
                CC=${buildPackages.llvm}/bin/clang \
                AR=${buildPackages.llvm}/bin/llvm-ar \
                RANLIB=${buildPackages.llvm}/bin/llvm-ranlib \
                OBJCOPY=${buildPackages.binutils}/bin/objcopy \
                CFLAGS="--target=${efiTarget}"
            ''
            else ''
              # Only build lib and gnuefi (CRT objects), skip apps which tries
              # to link EFI binaries and conflicts with ccWrapper's LDFLAGS.
              # Pre-create output dirs that the out-of-tree build expects.
              ARCH=${efiArch}
              mkdir -p "$ARCH/lib/runtime" "$ARCH/lib/$ARCH" "$ARCH/gnuefi"
              make -j$NIX_BUILD_CORES \
                ARCH="$ARCH" \
                SUBDIRS="lib gnuefi inc" \
                PREFIX=/usr \
                INSTALLROOT= \
                CC=gcc
            '';
        }
        {
          name = "install";
          script =
            if isDarwinCross
            then ''
              # Preserve the architecture-specific EFI headers, libraries, CRT
              # objects, linker scripts and pkg-config contract.
              ARCH=${efiArch}
              mkdir -p "$out/include/efi/protocol" "$out/include/efi/$ARCH" "$out/include/efi/legacy"
              cp inc/*.h "$out/include/efi/"
              cp inc/protocol/*.h "$out/include/efi/protocol/"
              cp "inc/$ARCH/"*.h "$out/include/efi/$ARCH/"
              cp inc/legacy/*.h "$out/include/efi/legacy/"

              mkdir -p "$out/lib/pkgconfig"
              cp "$ARCH/lib/libefi.a" "$out/lib/"
              cp "$ARCH/gnuefi/libgnuefi.a" "$out/lib/"
              cp "$ARCH/gnuefi/crt0-efi-$ARCH.o" "$out/lib/"
              if test -f "$ARCH/gnuefi/crt0-efi-$ARCH-local.o"; then
                cp "$ARCH/gnuefi/crt0-efi-$ARCH-local.o" "$out/lib/"
              fi
              cp "gnuefi/elf_''${ARCH}_efi.lds" "$out/lib/"
              if test -f "gnuefi/elf_''${ARCH}_efi_local.lds"; then
                cp "gnuefi/elf_''${ARCH}_efi_local.lds" "$out/lib/"
              fi
              cp "$ARCH/gnuefi/gnu-efi.pc" "$out/lib/pkgconfig/"

              # Remove DWARF paths with the native ELF-aware LLVM tool. The
              # generic Darwin fixup deliberately skips these foreign objects.
              ${buildPackages.llvm}/bin/llvm-strip --strip-debug "$out"/lib/*.a "$out"/lib/*.o
            ''
            else ''
              # Manual install since the Makefile's install paths are relative
              # to the source tree and don't work with Nix store paths.
              ARCH=${efiArch}

              # Headers
              mkdir -p $out/include/efi/protocol $out/include/efi/$ARCH $out/include/efi/legacy
              cp inc/*.h $out/include/efi/
              cp inc/protocol/*.h $out/include/efi/protocol/
              cp inc/$ARCH/*.h $out/include/efi/$ARCH/
              # efilib.h includes "legacy/efilib.h"; ship it so consumers that
              # pull efilib.h (e.g. efitools' lib) resolve cleanly.
              cp inc/legacy/*.h $out/include/efi/legacy/

              # Libraries and CRT objects
              mkdir -p $out/lib
              cp "$ARCH/lib/libefi.a" $out/lib/
              cp "$ARCH/gnuefi/libgnuefi.a" $out/lib/
              cp "$ARCH/gnuefi/crt0-efi-$ARCH.o" $out/lib/
              cp "gnuefi/elf_''${ARCH}_efi.lds" $out/lib/
            '';
        }
      ];

      meta = {
        description = "gnu-efi — EFI development headers, libraries, and CRT objects";
        homepage = "https://github.com/ncroxon/gnu-efi";
        license = "GPL-2.0-or-later";
      };
    }
    // lib.optionalAttrs isDarwinCross {
      dontStrip = "1";
    }
  )
