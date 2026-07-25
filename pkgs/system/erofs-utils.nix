##! erofs-utils — EROFS user-space tools (mkfs.erofs, fsck.erofs)
##!
##! The AOS `/etc` model uses EROFS as the bottom lower of the
##! three-layer overlay (`system.build.etcMetadataImage`, built by
##! composefs's `mkcomposefs`). `mkfs.erofs -z zstd` additionally builds
##! the compressed read-only system root image (`lib/build/rootfs.nix`),
##! so the build is configured `--enable-zstd`. `fsck.erofs` sanity-checks
##! both at build time.
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  autoconf,
  automake,
  libtool,
  m4,
  util-linux,
  zstd,
}: let
  # v1.8.x is the last stable line whose `lib/Makefile.am` keeps the
  # heavy optional deps (lz4, lzma, zstd, libdeflate, xxhash, json-c,
  # libxml2, libcurl, openssl, zlib) all gated behind `--enable-*`
  # `if ENABLE_*` blocks. v1.9.x unconditionally pulls in zlib +
  # libcurl + json-c + libxml2 + openssl for the new OCI / S3 / gzip
  # importer code paths, which AOS doesn't need for the
  # composefs-generated EROFS image used by `system.build.etcMetadataImage`.
  # Sticking with 1.8.10 keeps the dependency closure to just util-linux
  # (libuuid). Bump only when AOS actually grows a runtime dep on the
  # 1.9 features.
  version = "1.8.10";
in
  mkDerivation {
    pname = "erofs-utils";
    inherit version;

    # kernel.org publishes git snapshots of the upstream tree; no
    # release tarballs ship with a pre-generated `configure`, so the
    # full autotools bootstrap (aclocal/autoheader/autoconf/libtoolize/
    # automake, per upstream `autogen.sh`) runs in the unpack phase.
    src = fetchurl {
      urls = [
        "https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git/snapshot/erofs-utils-${version}.tar.gz"
      ];
      hash = "sha256-BetO3r4R3szm7LNOmNL4DIzSg8Lyln2Lp+/VhBhXBRQ=";
    };

    buildDeps = [
      gnumake
      pkg-config
      autoconf
      automake
      libtool
      m4
      zstd
    ];
    runtimeDeps = [util-linux zstd];
    propagatedDeps = [util-linux zstd];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd erofs-utils-${version}
        '';
      }
      {
        name = "autoreconf";
        # Upstream's `autogen.sh` runs `aclocal` without `-I m4` and
        # without `--install`, which fails when the m4/ aux dir hasn't
        # been seeded. `autoreconf -i` does the right thing (creates
        # m4/, installs ltmain.sh, runs everything in order). The AOS
        # stdenv does not populate ACLOCAL_PATH from buildDeps, so we
        # add libtool's and pkg-config's m4 directories explicitly —
        # without them aclocal can't see LT_INIT / PKG_CHECK_MODULES
        # and autoreconf decides to skip libtoolize entirely.
        script = ''
          export ACLOCAL_PATH="${libtool}/share/aclocal:${pkg-config}/share/aclocal''${ACLOCAL_PATH:+:$ACLOCAL_PATH}"
          mkdir -p m4
          autoreconf -i -f -v
        '';
      }
      {
        name = "configure";
        # zstd is enabled: the read-only system root image is built with
        # `mkfs.erofs -z zstd` (lib/build/rootfs.nix), so the compressor must
        # be linked in. LZ4/LZMA stay off (unused), and fuse stays off (the
        # runtime mount is the in-kernel `mount -t erofs`).
        #
        # Multithreading is enabled so `mkfs.erofs --workers=#` can compress
        # the system root in parallel. The root image build is dominated by
        # single-threaded `-z zstd,level=19` over the whole server closure
        # (hours on one core); the worker pool splits the input into fixed
        # 16 MiB segments and compresses them concurrently. Output stays
        # bit-reproducible — segments are merged in deterministic on-disk
        # order, 16 MiB is a clean multiple of the 256 KiB pcluster so
        # boundaries don't shift the per-cluster compression, and `-T0 -U`
        # pin the remaining nondeterminism. Pulls in libpthread (glibc).
        script = ''
          ./configure \
            --prefix=$out \
            --disable-fuse \
            --without-lz4 \
            --without-lzma \
            --enable-zstd \
            --enable-multithreading
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
      description = "erofs-utils — EROFS user-space tools";
      homepage = "https://erofs.docs.kernel.org/";
      license = "GPL-2.0-or-later";
    };
  }
