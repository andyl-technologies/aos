##! libgit2 — C implementation of the Git core methods
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  cmake,
  ninja,
  openssl,
  zlib,
  python3,
  libssh2,
  stdenv,
}: let
  upstream = mkGithubUpstream {
    unitId = "libgit2-1";
    family = "libgit2";
    stream = "1";
    owner = "pkgs/libs/libgit2.nix";
    version = "1.9.7";
    upstreamId = "v1.9.7";
    repository = "libgit2/libgit2";
    provider = "github-releases";
    tagPrefix = "v";
    major = 1;
    source = {
      authority = "github.com";
      path = [
        "libgit2"
        "libgit2"
        "archive"
        "refs"
        "tags"
        {
          parts = [
            {literal = "v";}
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
      hash = "sha256-Gk++dYnoFHd652tkc0rYD07K0izTOiJoKiqupK5Tdec=";
    };
    riskFloor = "high";
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "libgit2";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The round-tripped hexadecimal object name is unchanged.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libgit2 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libgit2 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <git2.h>\nint main(void) {\n    const char input[] = \"0123456789abcdef0123456789abcdef01234567\"; char output[GIT_OID_HEXSZ + 1]; git_oid oid;\n    if (git_libgit2_init() < 0 || git_oid_fromstr(&oid, input) < 0) return 2;\n    git_oid_tostr(output, sizeof(output), &oid); git_libgit2_shutdown();\n    return strcmp(input, output) == 0 ? pass() : 3;\n}\n\n";
        };
        "input" = "A forty-digit hexadecimal Git object identifier.";
        "operation" = "Parse the full identifier and render it through libgit2.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lgit2"
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
              "exact" = "libgit2 primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libgit2 returns an error instead of an object identifier.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libgit2 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libgit2 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <git2.h>\nint main(void) {\n    git_oid oid; if (git_libgit2_init() < 0) return 2;\n    int status = git_oid_fromstr(&oid, \"g123456789abcdef0123456789abcdef01234567\"); git_libgit2_shutdown();\n    if (status >= 0) return 3;\n    return reject();\n}\n\n";
        };
        "input" = "A Git object identifier containing a non-hexadecimal letter.";
        "operation" = "Parse the malformed identifier with git_oid_fromstr.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lgit2"
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
              "exact" = "libgit2 rejected invalid input\n";
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

    buildDeps = [
      gnumake
      cmake
      ninja
      python3
    ];
    runtimeDeps = [
      openssl
      zlib
      libssh2
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libgit2-${version}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            export CFLAGS="$CFLAGS \
              -ffile-prefix-map=$PWD=. \
              -fdebug-prefix-map=$PWD=."

            # Fix xdiff include priority: glibc has a deprecated regexp.h that
            # shadows libgit2's src/util/regexp.h when -isystem is used.
            # Change SYSTEM to regular includes so libgit2 headers win.
            sed -i 's/target_include_directories(xdiff SYSTEM PRIVATE/target_include_directories(xdiff PRIVATE/' deps/xdiff/CMakeLists.txt
            cmake -S . -B build -G Ninja \
              $cmakeFlags \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_INSTALL_PREFIX=$out \
              -DCMAKE_INSTALL_LIBDIR=lib \
              -DBUILD_TESTS=OFF \
              -DUSE_SSH=ON \
              -DCMAKE_PREFIX_PATH=${libssh2} \
              -DUSE_HTTPS=OpenSSL \
              -DOPENSSL_ROOT_DIR=${openssl} \
              -DZLIB_LIBRARY=${zlib}/lib/libz.${stdenv.hostPlatform.sharedLibraryExtension} \
              -DZLIB_INCLUDE_DIR=${zlib}/include \
              -DNEED_LIBRT=OFF
          ''
          else ''
            # Fix xdiff include priority: glibc has a deprecated regexp.h that
            # shadows libgit2's src/util/regexp.h when -isystem is used.
            # Change SYSTEM to regular includes so libgit2 headers win.
            sed -i 's/target_include_directories(xdiff SYSTEM PRIVATE/target_include_directories(xdiff PRIVATE/' deps/xdiff/CMakeLists.txt
            cmake -S . -B build -G Ninja \
              $cmakeFlags \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_INSTALL_PREFIX=$out \
              -DCMAKE_INSTALL_LIBDIR=lib \
              -DBUILD_TESTS=OFF \
              -DUSE_SSH=ON \
              -DCMAKE_PREFIX_PATH=${libssh2} \
              -DUSE_HTTPS=OpenSSL \
              -DOPENSSL_ROOT_DIR=${openssl} \
              -DZLIB_LIBRARY=${zlib}/lib/libz.${stdenv.hostPlatform.sharedLibraryExtension} \
              -DZLIB_INCLUDE_DIR=${zlib}/include
          '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          ninja -C build install
        '';
      }
    ];

    meta = {
      description = "libgit2 — C implementation of the Git core methods";
      homepage = "https://libgit2.org";
      license = "GPL-2.0-only WITH GCC-exception-3.1";
    };
  }
