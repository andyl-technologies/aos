##! jemalloc — general-purpose scalable concurrent malloc implementation
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  bash,
  perl,
  stdenv,
}: let
  upstream = mkGithubUpstream {
    unitId = "jemalloc-5";
    family = "jemalloc";
    stream = "5";
    owner = "pkgs/libs/jemalloc.nix";
    version = "5.3.0";
    upstreamId = "5.3.0";
    repository = "jemalloc/jemalloc";
    major = 5;
    source = {
      authority = "github.com";
      path = [
        "jemalloc"
        "jemalloc"
        "releases"
        "download"
        {
          parts = [
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
            {literal = "jemalloc-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.bz2";}
          ];
        }
      ];
      hash = "sha256-LbgtHnEZ3z5xt2QCGbbf6EeJvAU3mDw7esT3GJrs/qo=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "jemalloc";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [gnumake];
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then [bash perl]
      else [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd jemalloc-${version}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            # jemalloc's C++ allocator API hard-codes GNU libstdc++ for its
            # link probe and shared library. Darwin's ABI uses libc++, and
            # its C++ driver supplies the target runtime search path.
            sed -i 's|-lstdc++|-lc++|g' configure
            sed -i \
              's|^\t$(CC) $(DSO_LDFLAGS)|\t$(CXX) $(DSO_LDFLAGS)|' \
              Makefile.in
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --enable-static
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --enable-static
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
            for script in "$out/bin/jemalloc-config" "$out/bin/jemalloc.sh"; do
              sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$script"
            done
            sed -i "1s|^#!.*|#!${perl}/bin/perl|" "$out/bin/jeprof"
          ''
          else ''
            make install
          '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-jemalloc";
        library = self;
        libs = ["-ljemalloc" "-lpthread" "-ldl"];
        testSource = ''
          #include <jemalloc/jemalloc.h>
          #include <stdio.h>
          #include <string.h>
          int main() {
            const char *v = NULL;
            size_t sz = sizeof(v);
            if (mallctl("version", &v, &sz, NULL, 0) != 0 || v == NULL) return 1;
            printf("jemalloc version: %s\n", v);

            void *p = malloc(1024);
            if (!p) return 2;
            memset(p, 0, 1024);
            free(p);
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "jemalloc — general-purpose scalable concurrent malloc implementation";
      homepage = "https://jemalloc.net/";
      license = "BSD-2-Clause";
    };
  }
