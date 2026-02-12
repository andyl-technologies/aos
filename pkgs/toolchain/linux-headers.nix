# Linux Headers — Kernel headers for userspace compilation
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "linux-headers-${versions.toolchain.linux-headers}";
  version = versions.toolchain.linux-headers;

  src = fetchurl {
    inherit (sources.linux-headers) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd linux-${versions.toolchain.linux-headers}
      '';
    }
    { name = "install";
      script = ''
        make headers_install INSTALL_HDR_PATH=$out ARCH=x86
        # Remove extraneous files
        find $out/include -name '*.install.cmd' -delete
        find $out/include -name '..install.cmd' -delete
      '';
    }
  ];

  meta = {
    description = "Linux kernel headers for userspace compilation";
    homepage = "https://www.kernel.org";
    license = "GPL-2.0-only";
  };
}
