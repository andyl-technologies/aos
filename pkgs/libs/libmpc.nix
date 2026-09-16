##! libmpc — GNU library for multiprecision complex arithmetic
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  gmp,
  mpfr,
  stdenv,
}: let
  version = "1.3.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libmpc";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Libmpc preserves both integer components exactly.";
        "files" = {};
        "input" = "The exact complex integer value 4-2i at 53-bit precision.";
        "operation" = "Initialize, assign, and compare the value through libmpc's exported ABI.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import ctypes\nlibrary = ctypes.CDLL(\"@out@/lib/libmpc.so\")\nvalue = ctypes.create_string_buffer(256)\nlibrary.mpc_init2.argtypes = [ctypes.c_void_p, ctypes.c_long]\nlibrary.mpc_set_si_si.argtypes = [ctypes.c_void_p, ctypes.c_long, ctypes.c_long, ctypes.c_int]\nlibrary.mpc_cmp_si_si.argtypes = [ctypes.c_void_p, ctypes.c_long, ctypes.c_long]\nlibrary.mpc_clear.argtypes = [ctypes.c_void_p]\nlibrary.mpc_init2(value, 53)\nassigned = library.mpc_set_si_si(value, 4, -2, 0)\ncomparison = library.mpc_cmp_si_si(value, 4, -2)\nlibrary.mpc_clear(value)\nassert assigned == 0 and comparison == 0\nprint(\"libmpc operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "libmpc operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libmpc returns its invalid-number status.";
        "files" = {};
        "input" = "The text not-a-number as a base-10 complex number.";
        "operation" = "Parse the malformed number through libmpc's exported ABI.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport ctypes\nlibrary = ctypes.CDLL(\"@out@/lib/libmpc.so\")\nvalue = ctypes.create_string_buffer(256)\nlibrary.mpc_init2.argtypes = [ctypes.c_void_p, ctypes.c_long]\nlibrary.mpc_set_str.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]\nlibrary.mpc_clear.argtypes = [ctypes.c_void_p]\nlibrary.mpc_init2(value, 53)\nstatus = library.mpc_set_str(value, b\"not-a-number\", 10, 0)\nlibrary.mpc_clear(value)\nassert status != 0\n\nsys.stderr.write(\"libmpc rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "libmpc rejected invalid input\n";
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
        "https://mirrors.kernel.org/gnu/mpc/mpc-${version}.tar.gz"
        "https://mirrors.kernel.org/gnu/mpc/mpc-${version}.tar.gz"
      ];
      hash = "sha256-q2QkkvXPiCt0qgy3MM1BCoHtzb7IlRg86TDnBsHHWbg=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [
      gmp
      mpfr
    ];
    propagatedDeps = [
      gmp
      mpfr
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd mpc-${version}
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
            --with-mpfr=${mpfr} \
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
      description = "libmpc — GNU library for multiprecision complex arithmetic with exact rounding";
      homepage = "https://www.multiprecision.org/mpc/";
      license = "LGPL-2.1-or-later";
    };
  }
