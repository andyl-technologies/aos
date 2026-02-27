# stdenv/toolchains/gcc3_4/linux-headers.nix — Linux 2.6.9 headers (RHEL 4)
#
# Sanitized kernel UAPI headers for glibc 2.3.4.
# Built with this tier's GCC 3.4.6 + binutils 2.15.
# All i686-linux.
#
{
  prev,
  buildPlatform,
  hostPlatform,
  this,
  ...
}:
let
  src = builtins.fetchTarball {
    url = "https://cdn.kernel.org/pub/linux/kernel/v2.6/linux-2.6.9.tar.bz2";
    sha256 = "1hrnvjlgr4alcs1xcvc98c4vx3bmnc42idp3bav8jnvd0n4kwmq2";
  };

  # Linux 2.6.9 uses include/asm-<arch> directory names
  asmDirMap = {
    x86_64 = "asm-x86_64";
    i686 = "asm-i386";
    aarch64 = "asm-arm64";
  };
  asmDir =
    asmDirMap.${hostPlatform.constraints.cpu}
      or (throw "unsupported CPU for linux-headers: ${hostPlatform.constraints.cpu}");
in
builtins.derivation {
  name = "linux-headers-2.6.9";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${this.gcc}/bin:${this.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      # Copy source tree to writable location
      cp -r ${src} "$TMPDIR/linux-2.6.9"
      chmod -R u+w "$TMPDIR/linux-2.6.9"
      cd "$TMPDIR/linux-2.6.9"

      # Linux 2.6.9 does not have headers_install target.
      # Manually install headers.
      mkdir -p "$out/include"

      # Copy UAPI-relevant headers
      cp -r include/linux "$out/include/"
      cp -r include/${asmDir} "$out/include/asm"
      cp -r include/asm-generic "$out/include/"

      # Create version/autoconf headers.
      # Linux 2.6.9 uses ARCH=i386 (not x86, which was unified in 2.6.24).
      make ARCH=i386 include/linux/version.h 2>/dev/null || true
      if ! test -f include/linux/version.h; then
        # Manually create version.h if make failed
        printf '#define UTS_RELEASE "2.6.9"\n#define LINUX_VERSION_CODE 132617\n#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))\n' > include/linux/version.h
      fi
      cp include/linux/version.h "$out/include/linux/"

      echo "Linux 2.6.9 headers installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "Linux kernel headers, version 2.6.9";
    homepage = "https://www.kernel.org/";
    license = "GPL-2.0-only";
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
