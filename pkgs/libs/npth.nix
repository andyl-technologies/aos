##! npth — New GNU Portable Threads library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.8";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "npth";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Every NPTH synchronization operation succeeds.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"npth primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"npth rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <npth.h>\nint main(void) {\n    npth_mutex_t mutex;\n    if (npth_init() != 0 || npth_mutex_init(&mutex, NULL) != 0) return 2;\n    if (npth_mutex_lock(&mutex) != 0 || npth_mutex_unlock(&mutex) != 0) return 3;\n    return npth_mutex_destroy(&mutex) == 0 ? pass() : 4;\n}\n\n";
        };
        "input" = "A newly initialized NPTH mutex.";
        "operation" = "Initialize, lock, unlock, and destroy the mutex.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnpth"
              "-lpthread"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "npth primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The NPTH attribute API returns EINVAL.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"npth primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"npth rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <errno.h>\n#include <npth.h>\nint main(void) {\n    npth_attr_t attributes;\n    if (npth_attr_init(&attributes) != 0) return 2;\n    int status = npth_attr_setdetachstate(&attributes, 999999);\n    npth_attr_destroy(&attributes);\n    if (status != EINVAL) return 3;\n    return reject();\n}\n\n";
        };
        "input" = "A thread detach-state value outside the pthread API's enumeration.";
        "operation" = "Apply the invalid state through npth_attr_setdetachstate.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnpth"
              "-lpthread"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "npth rejected invalid input\n";
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
        "https://gnupg.org/ftp/gcrypt/npth/npth-${version}.tar.bz2"
        "https://mirrors.dotsrc.org/gcrypt/npth/npth-${version}.tar.bz2"
      ];
      hash = "sha256-i9JLTyOjBl1uWybpirqc54PqT9eBBpwbNdFJaU6Qyj4=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd npth-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-static
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
      description = "New GNU Portable Threads library used by the GnuPG stack";
      homepage = "https://gnupg.org/software/npth/";
      license = "LGPL-2.1-or-later";
    };
  }
