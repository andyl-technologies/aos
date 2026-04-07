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
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://cdn.kernel.org/pub/linux/kernel/v3.x/linux-3.10.108.tar.gz";
    hash = "1kggmp8gdbsaixp2qjj86jzzgz4kjvcnx8w7i1fbwr2bifaz0hzi";
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

      cp -r ${src} "$TMPDIR/linux-3.10.108"
      chmod -R u+w "$TMPDIR/linux-3.10.108"
      cd "$TMPDIR/linux-3.10.108"

      make ARCH=${hostPlatform.linuxArch} INSTALL_HDR_PATH="$out" headers_install

      echo "Linux 3.10.108 headers (${hostPlatform.linuxArch}) installed to $out"
    ''
  ];
}
