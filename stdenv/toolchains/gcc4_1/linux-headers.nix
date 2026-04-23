# stdenv/toolchains/gcc4_1/linux-headers.nix — Linux 2.6.18 headers (RHEL 5)
#
# Kernel headers installed via headers_install. Required by glibc 2.5.
#
{
  prev,
  gcc,
  binutils,
  buildPlatform,
  hostPlatform,
}: let
  src = builtins.fetchTarball {
    url = "https://cdn.kernel.org/pub/linux/kernel/v2.6/linux-2.6.18.tar.bz2";
    sha256 = "0ad6d97c1z5z79gafbxsd9d9wq4f21hmvp52s91dysqk24fkbdbx";
  };

  # Linux 2.6.18 uses asm-<arch> directory names (pre-2.6.24 unification)
  asmDirMap = {
    x86_64 = "asm-x86_64";
    i686 = "asm-i386";
  };
  asmDir =
    asmDirMap.${hostPlatform.constraints.cpu}
    or (throw "unsupported CPU for linux headers: ${hostPlatform.constraints.cpu}");

  # Pre-2.6.24 kernel ARCH values
  archMap = {
    x86_64 = "x86_64";
    i686 = "i386";
  };
  linuxArch =
    archMap.${hostPlatform.constraints.cpu}
    or (throw "unsupported CPU for linux ARCH: ${hostPlatform.constraints.cpu}");
in
  builtins.derivation {
    name = "linux-headers-2.6.18";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"

        cd "$TMPDIR"
        cp -r ${src} linux-2.6.18
        cd linux-2.6.18
        chmod -R u+w .

        # Linux 2.6.18 headers_install requires unifdef which isn't available.
        # Manually install headers (same approach as gcc3_4 tier).
        mkdir -p "$out/include"
        cp -r include/linux "$out/include/"
        cp -r include/${asmDir} "$out/include/asm"
        cp -r include/asm-generic "$out/include/"

        # Create version.h
        make ARCH=${linuxArch} include/linux/version.h 2>/dev/null || true
        if ! test -f include/linux/version.h; then
          printf '#define UTS_RELEASE "2.6.18"\n#define LINUX_VERSION_CODE 132626\n#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))\n' > include/linux/version.h
        fi
        cp include/linux/version.h "$out/include/linux/"

        echo "Linux 2.6.18 headers installed to $out"
      ''
    ];
  }
  // {
    meta = {
      build = {
        os = "linux";
        cpu = [
          "x86_64"
          "i686"
        ];
      };
      execute = {
        os = "linux";
        cpu = [
          "x86_64"
          "i686"
        ];
      };
    };
  }
