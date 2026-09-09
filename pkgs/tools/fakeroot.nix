##! fakeroot — Give a fake root environment through LD_PRELOAD
{
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  automake,
  libtool,
  sed,
  coreutils,
  util-linux,
  libcap,
  bash,
  stdenv,
}: let
  version = "2.1.4";
in
  mkDerivation {
    pname = "fakeroot";
    inherit version;

    src = fetchurl {
      urls = [
        "https://deb.debian.org/debian/pool/main/f/fakeroot/fakeroot_${version}.orig.tar.xz"
      ];
      hash = "sha256-CCK9Wp8M8Z0roFRriLBDLU09mRfbYsV7dARMytugbkk=";
    };

    buildDeps = [gnumake autoconf automake libtool];
    # scripts/fakeroot.in is patched (below) to hardcode util-linux, sed,
    # and coreutils store paths. These must be in runtimeDeps so the
    # scrubPhase nuke-refs pass keeps the hashes — otherwise the wrapper
    # script invokes /nix/store/eeeee.../bin/getopt and aborts.
    runtimeDeps =
      [
        bash
        sed
        coreutils
      ]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [libcap util-linux]
      );
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd fakeroot-${version}
        '';
      }
      {
        name = "patch";
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            $CONFIG_SHELL ./bootstrap

            # Hardcode paths to runtime tools in the fakeroot wrapper script
            # so it doesn't rely on PATH resolution at runtime.
            # Darwin implements SysV message queues, but upstream only seeds
            # the non-runnable cross probe for Linux targets.
            sed -i 's/linux-gnu\*|linux-musl\*/linux-gnu*|linux-musl*|darwin*/' \
              configure
            sed -i \
              -e 's|sed |${sed}/bin/sed |g' \
              -e 's|kill |builtin kill |g' \
              -e 's|/bin/ls|${coreutils}/bin/ls|g' \
              -e 's|cut |${coreutils}/bin/cut |g' \
              scripts/fakeroot.in
          ''
          else ''
            $CONFIG_SHELL ./bootstrap

            # Hardcode paths to runtime tools in the fakeroot wrapper script
            # so it doesn't rely on PATH resolution at runtime.
            ${
              if stdenv.hostPlatform.isDarwin
              then ""
              else ''sed -i 's|getopt|${util-linux}/bin/getopt|g' scripts/fakeroot.in''
            }
            sed -i \
              -e 's|sed |${sed}/bin/sed |g' \
              -e 's|kill |builtin kill |g' \
              -e 's|/bin/ls|${coreutils}/bin/ls|g' \
              -e 's|cut |${coreutils}/bin/cut |g' \
              scripts/fakeroot.in
          '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --with-ipc=sysv
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
          # Bash supplies kill; AOS coreutils does not install that optional
          # utility. Keep daemon cleanup and the default shell on AOS tools.
          sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/fakeroot"
          sed -i 's|/bin/sh|${bash}/bin/bash|g' "$out/bin/fakeroot"
        '';
      }
    ];

    meta = {
      description = "fakeroot — give a fake root environment through LD_PRELOAD";
      homepage = "https://salsa.debian.org/clint/fakeroot";
      license = "GPL-2.0-or-later";
    };
  }
