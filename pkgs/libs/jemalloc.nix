##! jemalloc — general-purpose scalable concurrent malloc implementation
{
  mkDerivation,
  fetchurl,
  gnumake,
  bash,
  perl,
  stdenv,
}: let
  version = "5.3.0";
in
  mkDerivation {
    pname = "jemalloc";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/jemalloc/jemalloc/releases/download/${version}/jemalloc-${version}.tar.bz2"
      ];
      hash = "sha256-LbgtHnEZ3z5xt2QCGbbf6EeJvAU3mDw7esT3GJrs/qo=";
    };

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
        script = ''
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
