# stdenv/toolchains/gcc3_4/linux-headers.nix — Linux 2.6.9 headers (RHEL 4)
#
# Sanitized kernel UAPI headers for glibc 2.3.4.
# Built with this tier's GCC 3.4.6 + binutils 2.15.
# All i686-linux.
#
{ prev, buildPlatform, hostPlatform, this, ... }:
let
  src = builtins.fetchTarball {
    url = "https://cdn.kernel.org/pub/linux/kernel/v2.6/linux-2.6.9.tar.bz2";
    sha256 = "11fq2afqwmb6j11b93ilj3a3rxw327knaizmd0jk7yby0yk3n0p1";
  };

  # Linux 2.6.9 uses include/asm-<arch> directory names
  asmDir =
    if hostPlatform.system == "x86_64-linux" then "asm-x86_64"
    else if hostPlatform.system == "i686-linux" then "asm-i386"
    else if hostPlatform.system == "aarch64-linux" then "asm-arm64"
    else throw "unsupported system: ${hostPlatform.system}";
in
builtins.derivation {
  name = "linux-headers-2.6.9";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${this.gcc}/bin:${this.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.patch}/bin:${prev.bash}/bin"
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

      # Create version/autoconf headers
      make ARCH=${hostPlatform.linuxArch} include/linux/version.h 2>/dev/null || true
      test -f include/linux/version.h && cp include/linux/version.h "$out/include/linux/"

      echo "Linux 2.6.9 headers installed to $out"
    ''
  ];
} // {
  meta = {
    description = "Linux kernel headers, version 2.6.9";
    homepage = "https://www.kernel.org/";
    license = "GPL-2.0-only";
    platforms = [ "i686-linux" "x86_64-linux" ];
  };
}
