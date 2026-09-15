# stdenv/toolchains/gcc8_cross/linux-headers.nix — Phase 3
#
# Linux 4.18 headers for target architecture.
# Uses `make headers_install` (proper sanitized headers).
#
{
  prev,
  buildPlatform,
  hostPlatform,
  ...
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
        export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"

        cd "$TMPDIR"
        cp -r ${src} linux-4.18
        cd linux-4.18
        chmod -R u+w .

        # Pin source helpers that configure or make can execute directly.
        AOS_RUNTIME_SHELL="${prev.bash}/bin/bash" \
          "${prev.bash}/bin/bash" ${../../runtime-scripts.sh} .

        # Header installation builds fixdep and unifdef for the build host.
        # The preceding tier provides a static libc for these helper programs.
        make SHELL="${prev.bash}/bin/bash" \
          HOSTCC="${prev.gcc}/bin/gcc -static -isystem ${prev.glibc}/include -L${prev.glibc}/lib" \
          ARCH=${hostPlatform.linuxArch} INSTALL_HDR_PATH="$out" headers_install

        echo "Linux 4.18 headers (${hostPlatform.linuxArch}) installed to $out"
      ''
    ];
  }
