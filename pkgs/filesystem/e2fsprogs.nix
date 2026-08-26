##! e2fsprogs — Utilities for ext2/ext3/ext4 filesystems
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  util-linux,
  bash,
  stdenv,
}: let
  version = "1.47.4";
in
  mkDerivation {
    pname = "e2fsprogs";
    inherit version;

    src = fetchurl {
      urls = [
        "https://downloads.sourceforge.net/e2fsprogs/e2fsprogs-${version}.tar.gz"
      ];
      hash = "sha256-LOwF85wg7mIfFJJhlWZOZuYBcZCsjku9sW2GCC5Dxdo=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then [bash]
      else [util-linux];
    propagatedDeps =
      if stdenv.hostPlatform.isDarwin
      then []
      else [util-linux];

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
            $configureFlags \
            --prefix=$out \
            ${
            if stdenv.hostPlatform.isDarwin
            then "--enable-bsd-shlibs"
            else "--enable-elf-shlibs"
          } \
            ${
            if stdenv.hostPlatform.isDarwin
            then ""
            else "--disable-libblkid --disable-libuuid --disable-uuidd"
          } \
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
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            make install-libs
            for script in \
              "$out/bin/compile_et" \
              "$out/bin/mk_cmds" \
              "$out/sbin/e2scrub" \
              "$out/sbin/e2scrub_all"
            do
              [ -f "$script" ] || continue
              sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$script"
            done
            # e2initrd_helper embeds a build-time gcc store path — a text
            # reference that drags ~230 MB of compiler into e2fsprogs' closure.
            rm -f "$out/lib/e2initrd_helper"
          ''
          else ''
            make install
            make install-libs
            # e2initrd_helper embeds a build-time gcc store path — a text
            # reference that drags ~230 MB of compiler into e2fsprogs' closure.
            rm -f "$out/lib/e2initrd_helper"
          '';
      }
    ];

    meta = {
      description = "Utilities for ext2/ext3/ext4 filesystems";
      homepage = "http://e2fsprogs.sourceforge.net/";
      license = "GPL-2.0-only";
    };
  }
