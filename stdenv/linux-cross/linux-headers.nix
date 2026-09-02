##! Linux userspace headers installed for the selected cross target.
{
  buildStdenv,
  buildPackages,
  buildPlatform,
  hostPlatform,
  sources,
}:
buildStdenv.mkDerivation {
  pname = "linux-headers";
  version = "6.12";
  src = sources.linux;
  hostPlatform = hostPlatform;
  targetPlatform = hostPlatform;

  buildDeps = [
    buildPackages.gnumake
    buildPackages.rsync
  ];
  runtimeDeps = [];
  propagatedDeps = [];

  dontStrip = true;
  dontPatchELF = true;
  dontValidateRunpath = true;

  phases = [
    {
      name = "unpack";
      script = ''
        mkdir source
        (cd $src && tar cf - .) | (cd source && tar xf -)
        chmod -R u+w source
        cd source
      '';
    }
    {
      name = "build";
      script = ''
        # The kernel's headers_install target only builds scheduler-native
        # helper programs; ARCH controls the ABI of the published headers.
        make -j"$NIX_BUILD_CORES" \
          ARCH=${hostPlatform.linuxArch} \
          HOSTCC=${buildStdenv.cc}/bin/cc \
          SHELL=${buildStdenv.bash}/bin/bash \
          INSTALL_HDR_PATH="$out" \
          headers_install
      '';
    }
    {
      name = "install";
      script = ''
        test -f "$out/include/linux/limits.h"
        test -f "$out/include/asm/types.h"
      '';
    }
  ];

  meta = {
    description = "Linux 6.12 userspace headers for ${hostPlatform.system}";
    homepage = "https://www.kernel.org/";
    license = "GPL-2.0-only";
    build = {
      os = "linux";
      cpu = [buildPlatform.constraints.cpu];
    };
    execute = {
      os = "linux";
      cpu = [hostPlatform.constraints.cpu];
    };
  };
}
