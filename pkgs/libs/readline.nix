##! readline — GNU Readline library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  patch,
  ncurses,
  stdenv,
}: let
  version = "8.3p3";
  sourceVersion = "8.3";
  readlinePatches = [
    (fetchurl {
      urls = ["https://ftp.gnu.org/gnu/readline/readline-8.3-patches/readline83-001"];
      hash = "sha256-IfCgMQbb5pczfNJccOsO26or221ZW0X4MoXN01ushN4=";
    })
    (fetchurl {
      urls = ["https://ftp.gnu.org/gnu/readline/readline-8.3-patches/readline83-002"];
      hash = "sha256-4nNkOWup9t6/fLqvGmaeKyhUJBrgf37KdMqKi6DJdHI=";
    })
    (fetchurl {
      urls = ["https://ftp.gnu.org/gnu/readline/readline-8.3-patches/readline83-003"];
      hash = "sha256-ct7hNgHOOPZ0brFSOZmafFb44f9eseyBU6HyE+Ss2yk=";
    })
  ];
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "readline";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <readline/readline.h>\n\nint main(void) {\n    if (rl_variable_bind(\"editing-mode\", \"vi\") != 0 ||\n        strcmp(rl_variable_value(\"editing-mode\"), \"vi\") != 0) {\n        return 2;\n    }\n    return puts(\"readline api passed\") == EOF;\n}\n";
        };
        "input" = "The documented vi value for Readline's editing-mode variable.";
        "operation" = "Bind the variable through Readline's public API and read its normalized value.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lreadline"
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
              "exact" = "readline api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <readline/readline.h>\n\nint main(void) {\n    if (rl_variable_bind(\"editing-mode\", \"qualification-mode\") == 0) {\n        return 2;\n    }\n    fputs(\"readline rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "An editing-mode value that Readline does not support.";
        "operation" = "Attempt to bind an unsupported editing mode through rl_variable_bind.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lreadline"
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
              "exact" = "readline: editing-mode: could not set value to `qualification-mode'\nreadline rejected invalid input\n";
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
        "https://mirrors.kernel.org/gnu/readline/readline-${sourceVersion}.tar.gz"
      ];
      hash = "sha256-/lODIERngozUle6NHTwDen66E4nCK8agQfYnl2+QYcw=";
    };

    buildDeps = [gnumake patch];
    runtimeDeps = [ncurses];
    propagatedDeps = [ncurses];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd readline-${sourceVersion}
        '';
      }
      {
        name = "patch";
        script = ''
          for patchFile in ${builtins.concatStringsSep " " readlinePatches}; do
            patch -p0 < "$patchFile"
          done
        '';
      }
      {
        name = "configure";
        script = ''
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              # Mach-O debug symbols retain compilation and object paths even
              # after stripping. Remap the sandbox prefix at compile time so
              # cached libraries contain no ephemeral /build references.
              export CFLAGS="''${CFLAGS:-} -ffile-prefix-map=$PWD=. -fdebug-prefix-map=$PWD=. -fdebug-compilation-dir=."
            ''
            else ""
          }

          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static \
            --with-curses
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES SHLIB_LIBS="-lncursesw"
        '';
      }
      {
        name = "install";
        script = ''
          make install SHLIB_LIBS="-lncursesw"
        '';
      }
    ];

    meta = {
      description = "GNU Readline — command line editing library";
      homepage = "https://tiswww.cwru.edu/php/chet/readline/rltop.html";
      license = "GPL-3.0-or-later";
    };
  }
