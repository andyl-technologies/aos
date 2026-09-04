##! Native-executable GNU binutils targeting the selected Linux host platform.
{
  buildStdenv,
  buildPackages,
  buildPlatform,
  hostPlatform,
  sources,
}:
buildStdenv.mkDerivation {
  pname = "binutils";
  version = "2.41";
  src = sources.binutils;
  hostPlatform = buildPlatform;
  targetPlatform = hostPlatform;

  buildDeps = [
    buildPackages.gnumake
    buildPackages.perl
    buildPackages.texinfo
  ];
  runtimeDeps = [];
  propagatedDeps = [];

  hardeningDisable = ["all"];

  phases = [
    {
      name = "unpack";
      script = ''
        mkdir source
        (cd $src && tar cf - .) | (cd source && tar xf -)
        chmod -R u+w source
      '';
    }
    {
      name = "configure";
      script = ''
        mkdir build
        cd build
        ../source/configure \
          --prefix="$out" \
          --build=${buildPlatform.config} \
          --host=${buildPlatform.config} \
          --target=${hostPlatform.config} \
          --disable-gdb \
          --disable-gdbserver \
          --disable-gprofng \
          --disable-libdecnumber \
          --disable-nls \
          --disable-readline \
          --disable-shared \
          --disable-sim \
          --disable-werror \
          --with-sysroot=/
      '';
    }
    {
      name = "build";
      script = ''
        make -j"$NIX_BUILD_CORES" MAKEINFO=true
      '';
    }
    {
      name = "install";
      script = ''
        make install MAKEINFO=true

        for tool in ar as ld nm objcopy objdump ranlib readelf size strings strip; do
          test -x "$out/bin/${hostPlatform.config}-$tool"
          ln -s "${hostPlatform.config}-$tool" "$out/bin/$tool"
        done
      '';
    }
  ];

  meta = {
    description = "GNU binutils 2.41 running on ${buildPlatform.system} and targeting ${hostPlatform.system}";
    homepage = "https://www.gnu.org/software/binutils/";
    license = "GPL-3.0-or-later";
    mainProgram = "${hostPlatform.config}-ld";
    build = {
      os = "linux";
      cpu = [buildPlatform.constraints.cpu];
    };
    execute = {
      os = "linux";
      cpu = [buildPlatform.constraints.cpu];
    };
    target = {
      os = "linux";
      cpu = [hostPlatform.constraints.cpu];
    };
  };
}
