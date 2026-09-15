##! GNU soelim — roff source include preprocessor
{
  lib,
  mkDerivation,
  fetchurl,
  bison,
  gnumake,
  m4,
  perl,
}: let
  version = "1.23.0";
in
  mkDerivation {
    pname = "soelim";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Soelim replaces the include request with the referenced file's exact contents.";
        "files" = {
          "answer.roff" = "answer=42\n";
          "document.roff" = ".so answer.roff\n";
        };
        "input" = "A roff document that includes a second local source file.";
        "operation" = "Expand the .so request through GNU soelim.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/soelim"
              "document.roff"
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
        "expected" = "Soelim rejects the unresolved include with a failure status.";
        "files" = {
          "document.roff" = ".so missing.roff\n";
        };
        "input" = "A roff include request naming a file that does not exist.";
        "operation" = "Resolve the missing include through GNU soelim.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/soelim"
              "document.roff"
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
        "https://ftp.gnu.org/gnu/groff/groff-${version}.tar.gz"
        "https://ftpmirror.gnu.org/groff/groff-${version}.tar.gz"
      ];
      hash = "sha256-a5dX9ZK3UYtJAutq9+VFcL3Mujeocf3bLTCuOGNRHBM=";
    };

    buildDeps = [bison gnumake m4 perl];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd groff-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure --prefix=$out
        '';
      }
      {
        name = "build";
        script = ''
          # The focused target omits this generated gnulib header from its
          # dependency edge even though libgnu consumes it.
          make lib/unitypes.h lib/uniwidth.h
          make -j$NIX_BUILD_CORES soelim
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 soelim $out/bin/soelim
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      cli = testing.mkToolCheck {
        pname = "tool-soelim";
        tool = self;
        command = "soelim --version";
      };
    };

    meta = {
      description = "GNU roff source include preprocessor";
      homepage = "https://www.gnu.org/software/groff/";
      license = "GPL-3.0-or-later";
    };
  }
