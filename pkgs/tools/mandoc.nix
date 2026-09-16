##! mandoc — mdoc and man document formatter
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
}: let
  version = "1.14.6";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "mandoc";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Mandoc accepts the document without diagnostics.";
        "files" = {
          "answer.1" = ".Dd September 8, 2026\n.Dt ANSWER 1\n.Os\n.Sh NAME\n.Nm answer\n.Nd print the value 42\n";
        };
        "input" = "A minimal mdoc document with its required title and name sections.";
        "operation" = "Validate the document through mandoc's lint formatter.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/mandoc"
              "-Tlint"
              "answer.1"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Mandoc rejects the formatter with status 5.";
        "files" = {
          "answer.1" = ".Dd September 8, 2026\n";
        };
        "input" = "A request for a mandoc output format that does not exist.";
        "operation" = "Parse the unsupported formatter name.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/mandoc"
              "-Tqualification-invalid"
              "answer.1"
            ];
            "exit_code" = 5;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://mandoc.bsd.lv/snapshots/mandoc-${version}.tar.gz"];
      hash = "sha256-i/DVcPAecKbhJIhAiIcMvtdTfzYyjVEpCesQzVMXnZw=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [zlib];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd mandoc-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cat >configure.local <<EOF
          PREFIX="$out"
          SBINDIR="$out/bin"
          MANPATH_DEFAULT="/run/current-system/sw/share/man"
          MANPATH_BASE="/run/current-system/sw/share/man"
          OSNAME="AOS"
          CC="$CC"
          AR="$AR"
          LD_OHASH="-lutil"
          LN="ln -sf"
          HAVE_WCHAR=1
          UTF8_LOCALE="C.UTF-8"
          EOF
          "$CONFIG_SHELL" ./configure
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
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
        pname = "tool-mandoc";
        tool = self;
        command = "printf '.Dd September 5, 2026\\n.Dt TEST 1\\n.Os\\n.Sh NAME\\n.Nm test\\n.Nd test document\\n' | mandoc -Tlint";
      };
    };

    meta = {
      description = "mdoc and man document formatter";
      homepage = "https://mandoc.bsd.lv/";
      license = "BSD-3-Clause";
      mainProgram = "mandoc";
    };
  }
