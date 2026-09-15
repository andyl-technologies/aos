##! MPFR — GNU multiple-precision floating-point library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  gmp,
  stdenv,
}: let
  version = "4.2.2";
in
  mkDerivation {
    pname = "mpfr";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "MPFR stores a value exactly equal to 42.5.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"mpfr primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"mpfr rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <mpfr.h>\n\nint main(void) {\n    mpfr_t value;\n    mpfr_init2(value, 128);\n    int status = mpfr_set_str(value, \"42.5\", 10, MPFR_RNDN);\n    int valid = status == 0 && mpfr_cmp_d(value, 42.5) == 0;\n    mpfr_clear(value);\n    return valid ? pass() : 2;\n}\n\n";
        };
        "input" = "The decimal value 42.5 at 128-bit precision.";
        "operation" = "Parse and compare it through MPFR.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"primary.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lmpfr\",\"-lgmp\"] + [\"-o\", \"primary-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
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
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "mpfr primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "MPFR returns a nonzero conversion status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n\nstatic int pass(void) {\n    return puts(\"mpfr primary passed\") == EOF;\n}\n\nstatic int reject(void) {\n    fputs(\"mpfr rejected invalid input\\n\", stderr);\n    return 7;\n}\n\n#include <mpfr.h>\n\nint main(void) {\n    mpfr_t value;\n    mpfr_init2(value, 128);\n    int status = mpfr_set_str(value, \"not-a-number\", 10, MPFR_RNDN);\n    mpfr_clear(value);\n    return status != 0 ? reject() : 2;\n}\n\n";
        };
        "input" = "The text not-a-number.";
        "operation" = "Parse it through mpfr_set_str.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ncommand = [\"@cc@\", \"bad-input.c\"]\nfor root_text in closure:\n    root = pathlib.Path(root_text)\n    include = root / \"include\"\n    library = root / \"lib\"\n    if include.is_dir():\n        command.append(\"-I\" + str(include))\n    for nested in (root / \"include/glib-2.0\", root / \"lib/glib-2.0/include\"):\n        if nested.is_dir():\n            command.append(\"-I\" + str(nested))\n    if library.is_dir():\n        command.extend([\"-L\" + str(library), \"-Wl,-rpath,\" + str(library)])\ncommand.extend([\"-lmpfr\",\"-lgmp\"] + [\"-o\", \"bad-input-check\"])\nresult = subprocess.run(command, capture_output=True, text=True)\nassert result.returncode == 0, (result.returncode, result.stdout, result.stderr)\n"
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
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "mpfr rejected invalid input\n";
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
        "https://www.mpfr.org/mpfr-${version}/mpfr-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/mpfr/mpfr-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/mpfr/mpfr-${version}.tar.xz"
      ];
      hash = "sha256-tnugOD736KhWNzTi6InvXsPDuJigHQD6CmhprYHGzgE=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [gmp];
    propagatedDeps = [gmp];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd mpfr-${version}
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
            --with-gmp=${gmp} \
            --enable-shared \
            --disable-static \
            --with-pic
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
      description = "MPFR — GNU multiple-precision floating-point library";
      homepage = "https://www.mpfr.org/";
      license = "LGPL-3.0-or-later";
    };
  }
