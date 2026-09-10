# stdenv/toolchains/gcc4_8_cross/linux-headers.nix — Phase 3
#
# Linux 3.10.108 headers for target architecture.
# Uses `make headers_install` (proper sanitized headers).
#
{
  prev,
  buildPlatform,
  hostPlatform,
  ...
}: let
  src = builtins.fetchTarball {
    url = "https://cdn.kernel.org/pub/linux/kernel/v3.x/linux-3.10.108.tar.gz";
    sha256 = "1kggmp8gdbsaixp2qjj86jzzgz4kjvcnx8w7i1fbwr2bifaz0hzi";
  };
in
  builtins.derivation {
    name = "linux-headers-3.10";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin"

        mkdir -p "$TMPDIR/linux-3.10.108"
        (cd ${src} && tar cf - .) | (cd "$TMPDIR/linux-3.10.108" && tar xf -)
        chmod -R u+w "$TMPDIR/linux-3.10.108"

        # Pin source helpers that configure or make can execute directly.
        AOS_RUNTIME_SHELL="${prev.bash}/bin/bash" \
          "${prev.bash}/bin/bash" ${../../runtime-scripts.sh} "$TMPDIR/linux-3.10.108"
        cd "$TMPDIR/linux-3.10.108"

        # Header installation builds fixdep and unifdef for the build host.
        # The preceding tier provides a static libc for these helper programs.
        make SHELL="${prev.bash}/bin/bash" \
          HOSTCC="${prev.gcc}/bin/gcc -static -isystem ${prev.glibc}/include -L${prev.glibc}/lib" \
          ARCH=${hostPlatform.linuxArch} INSTALL_HDR_PATH="$out" headers_install

        echo "Linux 3.10.108 headers (${hostPlatform.linuxArch}) installed to $out"
      ''
    ];
  }
