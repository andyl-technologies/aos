##! pv — Pipeline progress monitor
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.11.0";
in
  mkDerivation {
    pname = "pv";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "pv preserves every input byte on standard output.";
        "files" = {};
        "input" = "A fixed byte stream and a disabled progress display.";
        "operation" = "Copy the stream through pv's data path.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/pv"
              "--quiet"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdin" = "answer=42\n";
            "stdout" = {
              "exact" = "answer=42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "pv rejects the malformed numeric value with a non-success status.";
        "files" = {};
        "input" = "A numeric rate limit containing non-numeric text.";
        "operation" = "Parse the invalid rate-limit argument.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/pv"
              "--rate-limit"
              "not-a-number"
            ];
            "exit_code" = 64;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://www.ivarch.com/programs/sources/pv-${version}.tar.gz"];
      hash = "sha256-/ALJ/CuCsgqSzI2Y+ES+Y/IqvZh1Go5KvIdeHYA2Yus=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd pv-${version}
        '';
      }
      {
        name = "configure";
        script = ''./configure $configureFlags --prefix="$out"'';
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
        pname = "tool-pv";
        tool = self;
        command = "printf test | pv -q >/dev/null";
      };
    };

    meta = {
      description = "Monitors the progress of data through a pipeline";
      homepage = "https://www.ivarch.com/programs/pv.shtml";
      license = "GPL-3.0-or-later";
      mainProgram = "pv";
    };
  }
