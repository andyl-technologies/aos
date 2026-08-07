##! libevent — Event notification library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  openssl,
  zlib,
}: let
  version = "2.1.12";
in
  mkDerivation {
    pname = "libevent";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/libevent/libevent/releases/download/release-${version}-stable/libevent-${version}-stable.tar.gz"
      ];
      hash = "sha256-kubeG+nsF2Qo/SNnZ35hzv/C7hyxGQNQN6J9NGsEA7s=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      openssl
      zlib
    ];
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
        script = ''
          ./configure \
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
        script = ''
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
