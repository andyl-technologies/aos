##! libevent — Event notification library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  openssl,
  zlib,
  python3,
  stdenv,
}: let
  version = "2.1.13";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libevent";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The parsed port is 42 and the rendered address is 127.0.0.1.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libevent primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libevent rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <arpa/inet.h>\n#include <string.h>\n#include <event2/util.h>\nint main(void) {\n    struct sockaddr_storage address; int length = sizeof(address); char host[32];\n    if (evutil_parse_sockaddr_port(\"127.0.0.1:42\", (struct sockaddr *)&address, &length) != 0) return 2;\n    struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;\n    if (ntohs(ipv4->sin_port) != 42 || evutil_inet_ntop(AF_INET, &ipv4->sin_addr, host, sizeof(host)) == NULL) return 3;\n    return strcmp(host, \"127.0.0.1\") == 0 ? pass() : 4;\n}\n\n";
        };
        "input" = "The numeric socket address 127.0.0.1:42.";
        "operation" = "Parse the address and render its IPv4 host through libevent utilities.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-levent"
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
              "exact" = "libevent primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libevent rejects the address with a negative status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libevent primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libevent rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <event2/util.h>\nint main(void) {\n    struct sockaddr_storage address; int length = sizeof(address);\n    if (evutil_parse_sockaddr_port(\"127.0.0.1:70000\", (struct sockaddr *)&address, &length) == 0) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "An IPv4 socket address whose port is above 65535.";
        "operation" = "Parse the out-of-range address with evutil_parse_sockaddr_port.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-levent"
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
              "exact" = "libevent rejected invalid input\n";
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
        "https://github.com/libevent/libevent/releases/download/release-${version}-stable/libevent-${version}-stable.tar.gz"
      ];
      hash = "sha256-9+k4O4wLqoG2h+W17swBvu+vGxm2QVHZXtYWR/56MVw=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps =
      [
        openssl
        zlib
      ]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [python3]
        else []
      );
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libevent-${version}-stable
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            # Darwin's linker requires the pthread and OpenSSL companion
            # dylibs to resolve their libevent-core references at link time.
            # Treat Darwin like libevent's other no-undefined platforms so
            # Automake also records the correct parallel-build dependency.
            sed -i \
              's/if test x$bwin32 = xtrue || test x$cygwin = xtrue || test x$midipix = xtrue; then/if test x$host_os = xdarwin || test x$bwin32 = xtrue || test x$cygwin = xtrue || test x$midipix = xtrue; then/' \
              configure

            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --enable-static \
              --with-openssl=${openssl}
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --enable-static \
              --with-openssl=${openssl}
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
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            if [ -f "$out/bin/event_rpcgen.py" ]; then
              sed -i "1s|^#!.*|#!${python3}/bin/python3|" "$out/bin/event_rpcgen.py"
            fi
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "Asynchronous event notification library";
      homepage = "https://libevent.org/";
      license = "BSD-3-Clause";
    };

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-event";
        library = self;
        libs = ["-levent"];
        testSource = ''
          #include <event2/event.h>
          int main(void) {
            struct event_base *base = event_base_new();
            if (base == 0) return 1;
            event_base_free(base);
            return 0;
          }
        '';
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libevent.so"];
      };
    };
  }
