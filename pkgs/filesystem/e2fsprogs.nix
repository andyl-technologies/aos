##! e2fsprogs — Utilities for ext2/ext3/ext4 filesystems
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  util-linux,
}:
let
  version = "1.47.3";
in
mkDerivation {
  pname = "e2fsprogs";
  inherit version;

  src = fetchurl {
    urls = [
      "https://downloads.sourceforge.net/e2fsprogs/e2fsprogs-${version}.tar.gz"
    ];
    hash = "sha256-L1Fk5k3X2R6t0eDop32SwG3Xg3uxnx2Ric4ZObNj0rQ=";
  };

  buildDeps = [
    gnumake
    pkg-config
  ];
  runtimeDeps = [ util-linux ];
  propagatedDeps = [ util-linux ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd e2fsprogs-${version}
      '';
    }
    {
      name = "configure";
      # Binaries in $out/sbin link against libext2fs/libcom_err/libe2p
      # shipped in $out/lib. Without an explicit -rpath, the produced
      # binaries fall back on ld.so's default search path and fail with
      # "libe2p.so.2: cannot open shared object file" at runtime —
      # which manifests as systemd's "status=127/n/a" exit code because
      # the dynamic loader aborts before `main` runs.
      script = ''
        export LDFLAGS="-Wl,-rpath,$out/lib ''${LDFLAGS:-}"
        ./configure \
          --prefix=$out \
          --enable-elf-shlibs \
          --disable-libblkid \
          --disable-libuuid \
          --disable-uuidd \
          --disable-fsck
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
        make install-libs
      '';
    }
  ];

  meta = {
    description = "Utilities for ext2/ext3/ext4 filesystems";
    homepage = "http://e2fsprogs.sourceforge.net/";
    license = "GPL-2.0-only";
  };
}
