##! elfutils — ELF utilities and libelf
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  zlib,
  m4,
  xz,
  bzip2,
  zstd,
}: let
  version = "0.196";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "elfutils";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <elf.h>\n#include <libelf.h>\n\nint main(void) {\n    Elf64_Ehdr header = {0};\n    memcpy(header.e_ident, ELFMAG, SELFMAG);\n    header.e_ident[EI_CLASS] = ELFCLASS64;\n    header.e_ident[EI_DATA] = ELFDATA2LSB;\n    header.e_ident[EI_VERSION] = EV_CURRENT;\n    header.e_version = EV_CURRENT;\n    header.e_ehsize = sizeof(header);\n    if (elf_version(EV_CURRENT) == EV_NONE) {\n        return 2;\n    }\n    Elf *object = elf_memory((char *)&header, sizeof(header));\n    if (object == NULL || elf_kind(object) != ELF_K_ELF) {\n        if (object != NULL) elf_end(object);\n        return 3;\n    }\n    elf_end(object);\n    return puts(\"elfutils api passed\") == EOF;\n}\n";
        };
        "input" = "A complete in-memory ELF64 file header.";
        "operation" = "Open the bytes with elf_memory and verify that libelf recognizes an ELF object.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lelf"
              "-o"
              "primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "elfutils api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The API reports rejection and the consumer emits the fixed diagnostic and rejection status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <libelf.h>\n\nint main(void) {\n    char invalid[64] = \"not an ELF object\";\n    if (elf_version(EV_CURRENT) == EV_NONE) {\n        return 2;\n    }\n    Elf *object = elf_memory(invalid, sizeof(invalid));\n    if (object == NULL) {\n        fputs(\"elfutils rejected invalid input\\n\", stderr);\n        return 7;\n    }\n    Elf_Kind kind = elf_kind(object);\n    elf_end(object);\n    if (kind != ELF_K_NONE) {\n        return 3;\n    }\n    fputs(\"elfutils rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A byte buffer without the ELF magic number.";
        "operation" = "Open the malformed bytes with elf_memory and inspect their object kind.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lelf"
              "-o"
              "bad-input-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-consumer"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "elfutils rejected invalid input\n";
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
        "https://sourceware.org/elfutils/ftp/${version}/elfutils-${version}.tar.bz2"
      ];
      hash = "sha256-/VzGt3rWdzysk8s/QV+TGKw7NFXuz4Afa0p0LE9scgk=";
    };

    buildDeps = [
      gnumake
      pkg-config
      m4
    ];
    runtimeDeps = [
      zlib
      xz
      bzip2
      zstd
    ];
    propagatedDeps = [];

    # elfutils still uses flexible-array idioms incompatible with
    # -fstrict-flex-arrays=3; step down to level 1 (keeps fortify3 and the
    # rest, but lets [0]/[1] trailing arrays stay flexible).
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd elfutils-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --program-prefix=eu- \
            --disable-debuginfod \
            --disable-libdebuginfod \
            --disable-demangler \
            --with-lzma \
            --with-bzlib \
            --with-zstd
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
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-elfutils";
        library = self;
        libs = ["-lelf"];
        testSource = ''
          #include <libelf.h>
          #include <stdio.h>
          int main() {
            if (elf_version(EV_CURRENT) == EV_NONE) return 1;
            printf("elfutils libelf: PASS\n");
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "elfutils — ELF utilities and libelf library";
      homepage = "https://sourceware.org/elfutils/";
      license = "GPL-3.0-or-later";
    };
  }
