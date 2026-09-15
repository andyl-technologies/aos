##! ALSA library — Advanced Linux Sound Architecture user-space library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.2.16.1";
in
  mkDerivation {
    pname = "alsa-lib";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <alsa/asoundlib.h>\n\nint main(void) {\n    if (snd_pcm_format_value(\"S16_LE\") != SND_PCM_FORMAT_S16_LE) {\n        return 2;\n    }\n    return puts(\"alsa-lib api passed\") == EOF;\n}\n";
        };
        "input" = "The public PCM format name S16_LE.";
        "operation" = "Resolve the name with snd_pcm_format_value and verify the enum value.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lasound"
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
              "exact" = "alsa-lib api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <alsa/asoundlib.h>\n\nint main(void) {\n    if (snd_pcm_format_value(\"AOS_NOT_A_PCM_FORMAT\") != SND_PCM_FORMAT_UNKNOWN) {\n        return 2;\n    }\n    fputs(\"alsa-lib rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A PCM format name that ALSA does not define.";
        "operation" = "Resolve the unknown format with snd_pcm_format_value.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lasound"
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
              "exact" = "alsa-lib rejected invalid input\n";
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
        "https://www.alsa-project.org/files/pub/lib/alsa-lib-${version}.tar.bz2"
      ];
      hash = "sha256-90Dbf0iCVZRP/UQoQW7jOQqWdChWkWQz30aMKBQ2SA4=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd alsa-lib-${version}
        '';
      }
      {
        name = "build";
        script = ''
          $CONFIG_SHELL ./configure \
            --prefix=$out \
            --without-debug \
            --disable-python
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
      description = "ALSA library — Advanced Linux Sound Architecture user-space library";
      homepage = "https://www.alsa-project.org";
      license = "LGPL-2.1-or-later";
    };
  }
