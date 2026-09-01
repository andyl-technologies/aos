##! dtc — Device Tree Compiler and flattened device tree library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  flex,
  bison,
  libyaml,
  bash,
  stdenv,
}: let
  version = "1.7.2";
in
  mkDerivation {
    pname = "dtc";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.edge.kernel.org/pub/software/utils/dtc/dtc-${version}.tar.xz"
      ];
      hash = "sha256-ktjKdpgFrh8XYgQjBDj+UoCPThx5RAU8nuwOZJsjdTk=";
    };

    buildDeps = [
      gnumake
      pkg-config
      flex
      bison
    ];
    runtimeDeps =
      [libyaml]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd dtc-${version}
        '';
      }
      {
        name = "build";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            # The release makefile does not declare util.o's dependency on
            # this generated header, which races under a parallel build.
            make HOSTOS=darwin NO_PYTHON=1 version_gen.h
            make -j$NIX_BUILD_CORES \
              HOSTOS=darwin \
              SHAREDLIB_LDFLAGS="-fPIC -dynamiclib -Wl,-install_name,$out/lib/" \
              EXTRA_CFLAGS="-Wno-error=unknown-warning-option -Wno-error=unused-command-line-argument -ffile-prefix-map=$PWD=. -fdebug-prefix-map=$PWD=. -fdebug-compilation-dir=." \
              NO_PYTHON=1
          ''
          else ''
            make -j$NIX_BUILD_CORES \
              ${
              if stdenv.hostPlatform.isDarwin
              then "HOSTOS=darwin"
              else ""
            } \
              NO_PYTHON=1
          '';
      }
      {
        name = "install";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make \
              HOSTOS=darwin \
              SHAREDLIB_LDFLAGS="-fPIC -dynamiclib -Wl,-install_name,$out/lib/" \
              EXTRA_CFLAGS="-Wno-error=unknown-warning-option -Wno-error=unused-command-line-argument -ffile-prefix-map=$PWD=. -fdebug-prefix-map=$PWD=. -fdebug-compilation-dir=." \
              NO_PYTHON=1 \
              PREFIX=$out \
              install
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/dtdiff"
          ''
          else ''
            make \
              NO_PYTHON=1 \
              PREFIX=$out \
              install
          '';
      }
    ];

    meta = {
      description = "Device Tree Compiler and flattened device tree library";
      homepage = "https://git.kernel.org/pub/scm/utils/dtc/dtc.git";
      license = "GPL-2.0-or-later";
    };
  }
