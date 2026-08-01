# stdenv/toolchains/gcc8/linux-headers.nix — Linux 4.18 headers (RHEL 8)
#
# Kernel headers installed via headers_install. Required by glibc 2.28.
#
{
  prev,
  gcc,
  binutils,
  buildPlatform,
  hostPlatform,
}: let
  src = builtins.fetchTarball {
    url = "https://git.kernel.org/torvalds/t/linux-4.18.tar.gz";
    sha256 = "19rb2q5i5kcq0wd1apqmcypz7lhd4x2admzndvg4iyv3hg5i4wlp";
  };
in
  builtins.derivation {
    name = "linux-headers-4.18";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"

        cd "$TMPDIR"
        mkdir linux-4.18 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd linux-4.18 && ${prev.tar}/bin/tar xf -)
        cd linux-4.18
        chmod -R u+w .

        make ARCH=${hostPlatform.linuxArch} INSTALL_HDR_PATH="$out" headers_install

        echo "Linux 4.18 headers installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "Linux kernel headers, version 4.18";
      homepage = "https://www.kernel.org/";
      license = "GPL-2.0-only";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
