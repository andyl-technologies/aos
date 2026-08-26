##! lsof — List open files
{
  mkDerivation,
  fetchurl,
  gnumake,
  patch,
  patchelf,
  pkg-config,
  linux-headers,
  libtirpc,
  stdenv,
}: let
  version = "4.99.4";
in
  mkDerivation {
    pname = "lsof";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/lsof-org/lsof/releases/download/${version}/lsof-${version}.tar.gz"
      ];
      hash = "sha256-DEROLavsFK0UbLt/W1K1q0l2coQC/zSNn+ztmtl0DGY=";
    };

    buildDeps =
      [
        gnumake
        pkg-config
      ]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [linux-headers]
      );
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then []
      else [libtirpc];
    propagatedDeps = [];

    # Guard: keep the autotools build toolchain out of lsof's
    # `-v`-baked PKG_CONFIG_PATH / CC strings.
    disallowedReferences = [
      gnumake
      pkg-config
      patch
      patchelf
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd lsof-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-dependency-tracking \
            ${
            if stdenv.hostPlatform.isDarwin
            then ""
            else "--with-libtirpc"
          }
        '';
      }
      {
        name = "build";
        script = ''
          cat > soelim-wrapper <<SCRIPT
          #!$CONFIG_SHELL
          cat "\$@"
          SCRIPT
          chmod +x soelim-wrapper
          PATH="$PWD:$PATH"
          ln -s soelim-wrapper soelim
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
      description = "List open files";
      homepage = "https://github.com/lsof-org/lsof";
      license = "lsof";
    };
  }
