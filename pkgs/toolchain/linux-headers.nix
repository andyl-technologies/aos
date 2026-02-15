##! Linux Headers — Kernel headers for userspace compilation
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "6.12.11";
in
mkDerivation {
  pname = "linux-headers";
  inherit version;

  src = fetchurl {
    urls = [
      "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${version}.tar.xz"
    ];
    hash = "sha256-R1Fy/b2HoVPxI6V5Umcudzvbba9bWKQX0aXkGfz+7Ek=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd linux-${version}
      '';
    }
    {
      name = "install";
      script = ''
        # Use 'make headers' to sanitize headers in-tree, then copy manually.
        # This avoids 'make headers_install' which requires rsync, a tool not
        # present in the bootstrap toolchain.
        make headers ARCH=x86

        mkdir -p $out/include
        cp -r usr/include/* $out/include/

        # Remove extraneous files left by the kernel build system
        find $out/include -name '*.install.cmd' -delete
        find $out/include -name '..install.cmd' -delete
        find $out/include -name '.install' -delete
      '';
    }
  ];

  meta = {
    description = "Linux kernel headers for userspace compilation";
    homepage = "https://www.kernel.org";
    license = "GPL-2.0-only";
  };
}
