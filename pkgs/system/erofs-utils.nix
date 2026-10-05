##! erofs-utils — EROFS user-space tools (mkfs.erofs, fsck.erofs)
##!
##! The AOS `/etc` model uses EROFS as the bottom lower of the
##! three-layer overlay (`system.build.etcMetadataImage`, built by
##! composefs's `mkcomposefs`). `mkfs.erofs -z zstd` additionally builds
##! the compressed read-only system root image (`lib/build/rootfs.nix`),
##! so the build is configured `--enable-zstd`. `fsck.erofs` sanity-checks
##! both at build time.
{
  lib,
  mkDerivation,
  fetchurl,
  gawk,
  gnumake,
  pkg-config,
  autoconf,
  automake,
  libtool,
  m4,
  bash,
  gcc-libs,
  util-linux,
  lz4,
  xz,
  zlib,
  zstd,
  stdenv,
}: let
  version = "1.9.4";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "erofs-utils";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The checker accepts the generated read-only filesystem.";
        "files" = {
          "tree/payload.txt" = "EROFS qualification payload\n";
        };
        "input" = "A directory tree containing a fixed text payload.";
        "operation" = "Build an EROFS image and validate it with fsck.erofs.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/mkfs.erofs"
              "filesystem.erofs"
              "tree"
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@out@/bin/fsck.erofs"
              "filesystem.erofs"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The checker rejects the image with status 1.";
        "files" = {
          "invalid.erofs" = "not an EROFS filesystem\n";
        };
        "input" = "A text file without an EROFS superblock.";
        "operation" = "Validate the malformed image with fsck.erofs.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/fsck.erofs"
              "invalid.erofs"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    # Keep module compatibility at this release until a broader policy is reviewed.
    version = "=${version}";

    # kernel.org publishes git snapshots of the upstream tree; no
    # release tarballs ship with a pre-generated `configure`, so the
    # full autotools bootstrap (aclocal/autoheader/autoconf/libtoolize/
    # automake, per upstream `autogen.sh`) runs in the unpack phase.
    src = fetchurl {
      urls = [
        "https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git/snapshot/erofs-utils-${version}.tar.gz"
      ];
      hash = "sha256-fRNaolUDJqWs8g9TxRiupaiQABXOUHAAROQPgYwx3YA=";
    };

    # Compression fallback must restore raw-tail padding before publishing
    # the immutable store. Otherwise valid images contain corrupted bytes.
    patches = [./erofs-utils-raw-tail.patch];

    buildDeps = [
      gnumake
      pkg-config
      autoconf
      automake
      libtool
      m4
      lz4
      xz
      zlib
      zstd
    ];
    runtimeDeps = [bash gcc-libs util-linux lz4 xz zlib zstd];
    propagatedDeps = [util-linux lz4 xz zlib zstd];

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
        # be linked in. LZ4, LZMA, and zlib keep the tools compatible with
        # images produced by common Linux distribution tooling. Fuse stays off
        # because runtime mounts use the in-kernel `mount -t erofs` path.
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
        script =
          lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # Compression tools are also build inputs. Prefer the declared
            # target libraries over their native pkg-config metadata.
            export PKG_CONFIG_PATH="${lib.makeSearchPath "lib/pkgconfig" [util-linux lz4 xz zlib zstd]}''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
          ''
          + ''
            ./configure \
              --prefix=$out \
              --disable-fuse \
              --enable-lz4 \
              --enable-lzma \
              --with-zlib=yes \
              --with-libzstd=yes \
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

          # glibc lazily dlopen()s libgcc_s while worker threads exit. A
          # DT_RUNPATH on mkfs.erofs does not participate in that lookup, so
          # make the AOS-built unwind runtime explicit for every caller. Use
          # an exact path so an ambient host LD_LIBRARY_PATH cannot leak in.
          mv "$out/bin/mkfs.erofs" "$out/bin/.mkfs.erofs-unwrapped"
          cat > "$out/bin/mkfs.erofs" <<EOF
          #!${bash}/bin/bash
          export LD_LIBRARY_PATH="${gcc-libs}/lib"
          exec "$out/bin/.mkfs.erofs-unwrapped" "\$@"
          EOF
          chmod +x "$out/bin/mkfs.erofs"
        '';
      }
      {
        name = "check";
        script = ''
          mkdir -p "$TMPDIR/erofs-smoke/root"
          dd if=/dev/zero of="$TMPDIR/erofs-smoke/root/worker-payload" \
            bs=1M count=17 status=none
          printf 'multithreaded erofs smoke test\n' > "$TMPDIR/erofs-smoke/root/payload"
          env -i "$out/bin/mkfs.erofs" --all-root -T0 \
            -U bdfb6fc9-0000-4000-8000-000000000001 \
            --workers=1 -z zstd \
            "$TMPDIR/erofs-smoke/image-one-worker.erofs" \
            "$TMPDIR/erofs-smoke/root"
          env -i "$out/bin/mkfs.erofs" --all-root -T0 \
            -U bdfb6fc9-0000-4000-8000-000000000001 \
            --workers=2 -z zstd \
            "$TMPDIR/erofs-smoke/image-two-workers.erofs" \
            "$TMPDIR/erofs-smoke/root"
          cmp \
            "$TMPDIR/erofs-smoke/image-one-worker.erofs" \
            "$TMPDIR/erofs-smoke/image-two-workers.erofs"
          "$out/bin/fsck.erofs" \
            --extract="$TMPDIR/erofs-smoke/extracted" \
            "$TMPDIR/erofs-smoke/image-two-workers.erofs" >/dev/null
          cmp \
            "$TMPDIR/erofs-smoke/root/worker-payload" \
            "$TMPDIR/erofs-smoke/extracted/worker-payload"
          cmp \
            "$TMPDIR/erofs-smoke/root/payload" \
            "$TMPDIR/erofs-smoke/extracted/payload"

          # This incompressible PNG reaches compressed-to-raw fallback. Check
          # the published bytes, since structural fsck accepts a shifted tail.
          mkdir -p "$TMPDIR/erofs-raw-tail/root"
          cp ${gawk.src}/doc/gawk_api-figure3.png \
            "$TMPDIR/erofs-raw-tail/root/payload.png"
          for workers in 1 2; do
            env -i "$out/bin/mkfs.erofs" --all-root -T0 \
              -U bdfb6fc9-0000-4000-8000-000000000001 \
              --workers="$workers" -z zstd,level=19 \
              -C262144 -Eztailpacking \
              "$TMPDIR/erofs-raw-tail/image-$workers.erofs" \
              "$TMPDIR/erofs-raw-tail/root"
            "$out/bin/fsck.erofs" \
              --extract="$TMPDIR/erofs-raw-tail/extracted-$workers" \
              "$TMPDIR/erofs-raw-tail/image-$workers.erofs" >/dev/null
            cmp \
              "$TMPDIR/erofs-raw-tail/root/payload.png" \
              "$TMPDIR/erofs-raw-tail/extracted-$workers/payload.png"
          done
        '';
      }
    ];

    meta = {
      description = "erofs-utils — EROFS user-space tools";
      homepage = "https://erofs.docs.kernel.org/";
      license = "GPL-2.0-or-later";
    };
  }
