##! rsync — Fast incremental file transfer
{
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
  openssl,
  zstd,
  lz4,
  bash,
  stdenv,
}: let
  version = "3.4.1";
in
  mkDerivation {
    pname = "rsync";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.samba.org/pub/rsync/src/rsync-${version}.tar.gz"
      ];
      hash = "sha256-KSS8s6Hti1UfwQH3QLnw/gogKxFQJ2R89phQ1l/YjFI=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      [
        zlib
        openssl
        zstd
        lz4
      ]
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
          cd rsync-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --with-included-popt \
            --with-included-zlib=no \
            --disable-xxhash \
            --enable-zstd \
            --enable-lz4 \
            --disable-md2man
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
            if [ -f "$out/bin/rsync-ssl" ]; then
              sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/rsync-ssl"
            fi
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "rsync — fast incremental file transfer";
      homepage = "https://rsync.samba.org/";
      license = "GPL-3.0-or-later";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-rsync";
        tool = self;
        command = "rsync --version";
      };
    };
  }
