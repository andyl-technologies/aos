##! lzip — Lossless LZMA-based data compressor
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "1.26";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "lzip";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The decompressed bytes exactly equal the original text.";
        "files" = {
          "answer.txt" = "answer=42\n";
        };
        "input" = "A fixed text file compressed into an lzip member.";
        "operation" = "Compress the file and decode the member back to standard output.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/lzip"
              "-k"
              "answer.txt"
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
              "@out@/bin/lzip"
              "-d"
              "-c"
              "answer.txt.lz"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "answer=42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "lzip reports corrupt input with its data-error status.";
        "files" = {
          "invalid.lz" = "not an lzip member\n";
        };
        "input" = "A byte sequence that is not an lzip member.";
        "operation" = "Attempt to decompress the malformed member.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/lzip"
              "-d"
              "-c"
              "invalid.lz"
            ];
            "exit_code" = 2;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://download.savannah.gnu.org/releases/lzip/lzip-${version}.tar.gz"
      ];
      hash = "sha256-ZBzzCWFSXL47NAzIg0NsiFTp9QMvRZ9ETeR4K2IeZXI=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd lzip-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure --prefix="$out" CPPFLAGS=-DNDEBUG CXXFLAGS=-O3
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        # Cross-target test programs run during target qualification.
        script = if stdenv.isCross then ":" else ''make check'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-lzip";
        tool = self;
        command = ''printf "lzip round trip\n" | lzip -c | lzip -dc | grep -q "lzip round trip"'';
      };
    };

    meta = {
      description = "Lossless data compressor based on the LZMA algorithm";
      homepage = "https://www.nongnu.org/lzip/lzip.html";
      license = "GPL-2.0-or-later";
      mainProgram = "lzip";
    };
  }
