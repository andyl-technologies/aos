# rsync — Fast incremental file transfer
{ mkDerivation, fetchurl, make, zlib, openssl }:

let version = "3.3.0"; in
mkDerivation {
  pname = "rsync";
  inherit version;

  src = fetchurl {
    urls = [
      "https://download.samba.org/pub/rsync/src/rsync-${version}.tar.gz"
    ];
    hash = "sha256-c5nppnCMMtZ4pypjIZ6W8jvgviM25Q/RNISY0HBB35A=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ zlib openssl ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd rsync-${version}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --with-included-popt \
          --with-included-zlib=no \
          --disable-xxhash \
          --disable-zstd \
          --disable-lz4 \
          --disable-md2man
      '';
    }
    { name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install
      '';
    }
  ];

  meta = {
    description = "rsync — fast incremental file transfer";
    homepage = "https://rsync.samba.org/";
    license = "GPL-3.0-or-later";
  };
}
