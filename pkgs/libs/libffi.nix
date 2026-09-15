##! libffi — Foreign Function Interface library
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
}: let
  upstream = mkGithubUpstream {
    unitId = "libffi-3";
    family = "libffi";
    stream = "3";
    owner = "pkgs/libs/libffi.nix";
    version = "3.8.0";
    upstreamId = "v3.8.0";
    repository = "libffi/libffi";
    provider = "github-releases";
    tagPrefix = "v";
    major = 3;
    source = {
      urlTemplates = [
        {
          scheme = "https";
          authority = "github.com";
          path = [
            "libffi"
            "libffi"
            "releases"
            "download"
            {
              parts = [
                {literal = "v";}
                {
                  componentField = {
                    component = "main";
                    field = "comparisonVersion";
                  };
                }
              ];
            }
            {
              parts = [
                {literal = "libffi-";}
                {
                  componentField = {
                    component = "main";
                    field = "comparisonVersion";
                  };
                }
                {literal = ".tar.gz";}
              ];
            }
          ];
        }
        {
          scheme = "https";
          authority = "gcc.gnu.org";
          path = [
            "pub"
            "libffi"
            {
              parts = [
                {literal = "libffi-";}
                {
                  componentField = {
                    component = "main";
                    field = "comparisonVersion";
                  };
                }
                {literal = ".tar.gz";}
              ];
            }
          ];
        }
      ];
      hash = "sha256-faPi2aFx6woDj1kuytP/K7JVDzSW2Hs7Ka0M9EMMDbQ=";
      allowedRedirectHosts = ["gcc.gnu.org" "github.com" "release-assets.githubusercontent.com"];
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "libffi";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The indirect call returns 42.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libffi primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libffi rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <ffi.h>\nstatic int add(int left, int right) { return left + right; }\nint main(void) {\n    ffi_cif cif; ffi_type *types[2] = {&ffi_type_sint, &ffi_type_sint};\n    int left = 19, right = 23, result = 0; void *values[2] = {&left, &right};\n    if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &ffi_type_sint, types) != FFI_OK) return 2;\n    ffi_call(&cif, FFI_FN(add), &result, values);\n    return result == 42 ? pass() : 3;\n}\n\n";
        };
        "input" = "Two integer arguments for an indirectly invoked addition function.";
        "operation" = "Prepare a call interface and invoke the function through ffi_call.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lffi"
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
              "exact" = "libffi primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "ffi_prep_cif returns FFI_BAD_ABI.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libffi primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libffi rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <ffi.h>\nint main(void) {\n    ffi_cif cif;\n    if (ffi_prep_cif(&cif, (ffi_abi)9999, 0, &ffi_type_void, NULL) != FFI_BAD_ABI) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "An ABI selector outside libffi's supported ABI range.";
        "operation" = "Prepare a call interface using the invalid ABI.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lffi"
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
              "exact" = "libffi rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libffi-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static \
            --disable-docs
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
          # libffi installs to lib64/ on x86_64 — move to lib/ for AOS conventions
          if [ -d "$out/lib64" ]; then
            cp -a "$out/lib64/"* "$out/lib/"
            rm -rf "$out/lib64"
          fi
          # Keep libtool and pkg-config metadata aligned with the normalized
          # AOS lib/ layout. Downstream libtool consumers otherwise follow the
          # original multilib path into the removed lib64 directory.
          sed -i "s|$out/lib/../lib64|$out/lib|g" \
            "$out/lib/libffi.la" "$out/lib/pkgconfig/libffi.pc"
          # Some packages look for libffi headers in include/ not lib/libffi-*/include/
          if [ -d "$out/lib/libffi-${version}/include" ]; then
            cp -n "$out/lib/libffi-${version}/include/"*.h "$out/include/" 2>/dev/null || true
          fi
        '';
      }
    ];

    meta = {
      description = "libffi — a portable foreign function interface library";
      homepage = "https://sourceware.org/libffi/";
      license = "MIT";
    };
  }
