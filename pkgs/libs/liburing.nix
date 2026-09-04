##! liburing — Linux io_uring userspace library
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
}: let
  upstream = mkGithubUpstream {
    unitId = "liburing-2";
    family = "liburing";
    stream = "2";
    owner = "pkgs/libs/liburing.nix";
    version = "2.12";
    upstreamId = "liburing-2.12";
    repository = "axboe/liburing";
    tagPrefix = "liburing-";
    major = 2;
    versionScheme = "numeric";
    source = {
      authority = "github.com";
      path = [
        "axboe"
        "liburing"
        "archive"
        "refs"
        "tags"
        {
          parts = [
            {literal = "liburing-";}
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
      hash = "sha256-8dEMsFjJfJU7TAxEaxHpF36MizKlqIswnyP904niY3A=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "liburing";
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
          cd liburing-liburing-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --libdir=$out/lib \
            --includedir=$out/include
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

    checks = {
      testing,
      self,
      ...
    }: {
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["liburing.so"];
      };

      link = testing.mkLinkCheck {
        pname = "lib-uring";
        library = self;
        libs = ["-luring"];
        testSource = ''
          #include <liburing.h>
          int main(void) {
            struct io_uring ring;
            return io_uring_queue_init(1, &ring, 0) < 0;
          }
        '';
      };
    };

    meta = {
      description = "Userspace library for the Linux io_uring API";
      homepage = "https://github.com/axboe/liburing";
      license = "LGPL-2.1-or-later";
    };
  }
