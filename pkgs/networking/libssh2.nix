##! libssh2 — Client-side C library implementing the SSH2 protocol
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  openssl,
  zlib,
  stdenv,
}: let
  version = "1.11.1";
in
  mkDerivation {
    pname = "libssh2";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The known-host collection reports an exact match.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libssh2 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libssh2 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <libssh2.h>\nint main(void) {\n    const char *key = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\";\n    const char *line = \"example.test ssh-ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\\n\";\n    LIBSSH2_SESSION *session = libssh2_session_init();\n    LIBSSH2_KNOWNHOSTS *hosts = session == NULL ? NULL : libssh2_knownhost_init(session);\n    if (hosts == NULL) return 2;\n    int loaded = libssh2_knownhost_readline(hosts, line, strlen(line), LIBSSH2_KNOWNHOST_FILE_OPENSSH);\n    int matched = libssh2_knownhost_check(\n        hosts, \"example.test\", key, 0,\n        LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_BASE64 | LIBSSH2_KNOWNHOST_KEY_ED25519,\n        NULL);\n    libssh2_knownhost_free(hosts);\n    libssh2_session_free(session);\n    return loaded == 0 && matched == LIBSSH2_KNOWNHOST_CHECK_MATCH ? pass() : 3;\n}\n\n";
        };
        "input" = "An OpenSSH known-host line for an Ed25519 key.";
        "operation" = "Load the line and match its host and key through the known-host API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lssh2"
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
              "exact" = "libssh2 primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libssh2 returns a negative parse error.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libssh2 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libssh2 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <libssh2.h>\nint main(void) {\n    const char *line = \"invalid line\\n\";\n    LIBSSH2_SESSION *session = libssh2_session_init();\n    LIBSSH2_KNOWNHOSTS *hosts = session == NULL ? NULL : libssh2_knownhost_init(session);\n    if (hosts == NULL) return 2;\n    int status = libssh2_knownhost_readline(hosts, line, strlen(line), LIBSSH2_KNOWNHOST_FILE_OPENSSH);\n    libssh2_knownhost_free(hosts);\n    libssh2_session_free(session);\n    return status < 0 ? reject() : 3;\n}\n\n";
        };
        "input" = "A known-host line without a key type or encoded key.";
        "operation" = "Load the malformed line through libssh2_knownhost_readline.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lssh2"
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
              "exact" = "libssh2 rejected invalid input\n";
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
        "https://www.libssh2.org/download/libssh2-${version}.tar.gz"
      ];
      hash = "sha256-2ex2y+NNuY7sNTn+LImdJrDIN8s+tGalaw8QnKv2WPc=";
    };

    buildDeps = [
      gnumake
    ];
    runtimeDeps = [
      openssl
      zlib
    ];
    propagatedDeps = [openssl];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd libssh2-${version}
          '';
        }
      ]
      ++ (
        if stdenv.isCross && stdenv.hostPlatform.isDarwin
        then [
          {
            name = "darwin-build-paths";
            script = ''
              export CFLAGS="$CFLAGS \
                -ffile-prefix-map=$PWD=. \
                -fdebug-prefix-map=$PWD=."
            '';
          }
        ]
        else []
      )
      ++ [
        {
          name = "configure";
          script = ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --with-crypto=openssl \
              --with-libssl-prefix=${openssl} \
              --with-libz \
              --enable-shared \
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
      description = "libssh2 — client-side C library implementing the SSH2 protocol";
      homepage = "https://libssh2.org";
      license = "BSD-3-Clause";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libssh2";
        library = self;
        libs = ["-lssh2"];
        extraDeps = [pkgs.openssl];
        testSource = ''
          #include <libssh2.h>
          #include <stdio.h>
          int main() {
            const char *ver = libssh2_version(0);
            if (!ver) return 1;
            printf("libssh2 version: %s\n", ver);
            return 0;
          }
        '';
      };
    };
  }
