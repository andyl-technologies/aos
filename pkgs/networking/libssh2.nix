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
  backports = [
    {
      identity = "aos/validate-etm-packet-length";
      file = ./libssh2-validate-etm-packet-length.patch;
      sha256 = "919563254dfcf57cc4679d6833809259f105dada15ca09e5671537d6090a29ec";
    }
    {
      identity = "libssh2/5e4776146552d898b9c0e1b313cd093fa8dc92d0";
      file = ./libssh2-clear-consumed-sftp-response.patch;
      sha256 = "e9ab6237b611d1804cef2fdc86e2605fd10d0abf9feec4734294b91db4afc565";
    }
  ];
  verifiedBackports =
    map (
      backport:
        assert builtins.hashFile "sha256" backport.file == backport.sha256;
          backport.file
    )
    backports;
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "libssh2";
    smokeTest = lib.qualification.commandProbe {
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

    # Keep module compatibility at this release until a broader policy is reviewed.
    version = "=${version}";

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
            for backport in ${lib.escapeShellArgs (map (backport: "${backport}") verifiedBackports)}; do
              patch --fuzz=0 -p1 < "$backport"
            done
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
          name = "check";
          script = ''
            guard_line=$(grep -n -m1 'p->total_num < mac_len + 4 + (size_t)blocksize' src/transport.c | cut -d: -f1)
            decrypt_line=$(grep -n -m1 'rc = decrypt(session, p->payload + 4' src/transport.c | cut -d: -f1)
            test -n "$guard_line"
            test -n "$decrypt_line"
            test "$guard_line" -lt "$decrypt_line"

            awk '
              /SSH2_FREE\(session, data\);/ { response_free_line = NR; next }
              response_free_line && /data = NULL;/ {
                response_clear_line = NR
                next
              }
              response_clear_line && /sftp_packet_require\(sftp, SSH_FXP_HANDLE/ {
                fixed = response_clear_line == response_free_line + 1
                exit
              }
              END { exit !fixed }
            ' src/sftp.c
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

    passthru = {
      evidenceSources = verifiedBackports;
      nativePatchIdentities = map (backport: builtins.removeAttrs backport ["file"]) backports;
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
