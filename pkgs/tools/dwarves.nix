##! dwarves - DWARF/BTF inspection tools including pahole
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
  pkg-config,
  patch,
  elfutils,
  zlib,
  xz,
  bzip2,
  zstd,
  libbpf,
}: let
  version = "1.31";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "dwarves";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Pahole finds and decodes the requested DWARF type.";
        "files" = {
          "layout.c" = "struct ProbeLayout {\n    char tag;\n    long value;\n};\n\nstruct ProbeLayout qualification_layout;\n";
        };
        "input" = "A C object containing debug information for a named structure.";
        "operation" = "Compile the object and inspect the structure layout with pahole.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "-g"
              "-c"
              "layout.c"
              "-o"
              "layout.o"
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
              "@out@/bin/pahole"
              "--class_name=ProbeLayout"
              "layout.o"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Pahole rejects the file with status 1.";
        "files" = {
          "invalid.o" = "not an ELF object\n";
        };
        "input" = "A text file that is not an ELF object.";
        "operation" = "Inspect the malformed object with pahole.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/pahole"
              "invalid.o"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/acmel/dwarves/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-K2URaRvaKzrjKJhwkpAtMP0HPvfIdUiU9KaScaZmhvI=";
    };

    buildDeps = [
      cmake
      ninja
      pkg-config
      patch
    ];
    runtimeDeps = [
      elfutils
      zlib
      xz
      bzip2
      zstd
      libbpf
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd dwarves-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          # These trailing allocations are flexible arrays. Zero-length arrays
          # have no writable elements under strict flex-array hardening.
          patch -p1 < ${./dwarves-flexible-arrays.patch}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DLIB_INSTALL_DIR=lib \
            -DLIBBPF_EMBEDDED=OFF \
            -DDWARF_INCLUDE_DIR=${elfutils}/include \
            -DLIBDW_INCLUDE_DIR=${elfutils}/include \
            -DDWARF_LIBRARY=${elfutils}/lib/libdw.so \
            -DELF_LIBRARY=${elfutils}/lib/libelf.so \
            -DZLIB_LIBRARY=${zlib}/lib/libz.so \
            -DZLIB_INCLUDE_DIR=${zlib}/include
        '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          ninja -C build install
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-dwarves-pahole";
        tool = self;
        command = "pahole --version";
      };
    };

    meta = {
      description = "dwarves - DWARF/BTF inspection tools including pahole";
      homepage = "https://github.com/acmel/dwarves";
      license = "GPL-2.0-only";
    };
  }
