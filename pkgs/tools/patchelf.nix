##! patchelf — Utility for modifying ELF executables
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  gnumake,
}: let
  version = "0.19.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "patchelf";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "patchelf reports the exact newly stored RPATH.";
        "files" = {
          "sample.c" = "int main(void) { return 0; }\n";
        };
        "input" = "A linked ELF executable and the requested runtime search path /qualification.";
        "operation" = "Set the executable's RPATH and query it back through patchelf.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "sample.c"
              "-o"
              "sample"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@out@/bin/patchelf"
              "--set-rpath"
              "/qualification"
              "sample"
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
              "@out@/bin/patchelf"
              "--print-rpath"
              "sample"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "/qualification\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "patchelf rejects the non-ELF input with a non-success status.";
        "files" = {
          "not-elf" = "this is not an ELF object\n";
        };
        "input" = "A plain-text file with no ELF header.";
        "operation" = "Attempt to read its RPATH through patchelf.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/patchelf"
              "--print-rpath"
              "not-elf"
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
        "https://github.com/NixOS/patchelf/releases/download/${version}/patchelf-${version}.tar.bz2"
      ];
      hash = "sha256-LM4B3pNlOCn2q2iiDC7CdeHACpRhEHBKJ+ko0ubohxY=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd patchelf-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ${
            if stdenv.isCross
            then "$CONFIG_SHELL ./configure $configureFlags"
            else "./configure"
          } --prefix=$out
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

    meta = {
      description = "Utility for modifying ELF executables and libraries";
      homepage = "https://github.com/NixOS/patchelf";
      license = "GPL-3.0-or-later";
    };
  }
