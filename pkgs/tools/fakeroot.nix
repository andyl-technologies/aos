##! fakeroot — Give a fake root environment through LD_PRELOAD
{
  mkDerivation,
  fetchurl,
  gnumake,
  sed,
  coreutils,
  util-linux,
  libcap,
}: let
  version = "1.37.2";
in
  mkDerivation {
    pname = "fakeroot";
    inherit version;

    src = fetchurl {
      # Debian's pool keeps only the current version; 1.37.2 was
      # superseded (1.38.1 is current) and 404s there now. The
      # content-addressed snapshot.debian.org /file/<sha1> URL serves the
      # exact tarball permanently. The pool URL is kept as a secondary in
      # case the version is reinstated.
      urls = [
        "https://snapshot.debian.org/file/1a721c2b4093a4e83dc091dc41a028f19340c1b3"
        "https://deb.debian.org/debian/pool/main/f/fakeroot/fakeroot_${version}.orig.tar.gz"
      ];
      hash = "sha256-Dupg++iXcbiPz0Fcjy8KbM/p7eu887pdwCEnGNmIhNs=";
    };

    buildDeps = [gnumake];
    # scripts/fakeroot.in is patched (below) to hardcode util-linux, sed,
    # and coreutils store paths. These must be in runtimeDeps so the
    # scrubPhase nuke-refs pass keeps the hashes — otherwise the wrapper
    # script invokes /nix/store/eeeee.../bin/getopt and aborts.
    runtimeDeps = [libcap util-linux sed coreutils];
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
        script = ''
          # Hardcode paths to runtime tools in the fakeroot wrapper script
          # so it doesn't rely on PATH resolution at runtime.
          sed -i \
            -e 's|getopt|${util-linux}/bin/getopt|g' \
            -e 's|sed |${sed}/bin/sed |g' \
            -e 's|kill |${coreutils}/bin/kill |g' \
            -e 's|/bin/ls|${coreutils}/bin/ls|g' \
            -e 's|cut |${coreutils}/bin/cut |g' \
            scripts/fakeroot.in
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
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
        '';
      }
    ];

    meta = {
      description = "fakeroot — give a fake root environment through LD_PRELOAD";
      homepage = "https://salsa.debian.org/clint/fakeroot";
      license = "GPL-2.0-or-later";
    };
  }
