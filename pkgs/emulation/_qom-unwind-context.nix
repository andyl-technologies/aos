# Source-derived GNU configuration for the QEMU host's private observer.
{
  lib,
  stdenv,
  buildPackages,
  gccUnwrapped,
  fileProbe,
}: let
  supportedPlatform = platform:
    platform.isLinux && platform.constraints.abi == "gnu" && builtins.elem platform.constraints.cpu ["x86_64" "aarch64"];
  supported = stdenv.buildPlatform.isLinux && stdenv.buildPlatform.constraints.abi == "gnu" && supportedPlatform stdenv.hostPlatform;
  buildWordBytes =
    if stdenv.buildPlatform.is64bit
    then 8
    else 4;

  # The public cross gccUnwrapped is Canadian-cross and runs on the host.
  # The raw cross stdenv compiler executes on the build machine instead.
  compiler =
    if stdenv.isCross
    then stdenv.gcc
    else gccUnwrapped;
  compilerExecutable = "${compiler}/bin/${lib.optionalString stdenv.isCross "${stdenv.hostPlatform.config}-"}gcc";
  buildCompiler = buildPackages.gccUnwrapped;
  buildBinutils = buildPackages.stdenv.binutils;
  buildGlibc = buildPackages.stdenv.glibc;
  buildHeaders = buildPackages.stdenv.linuxHeaders;
  inherit (stdenv) binutils glibc linuxHeaders;
  inherit (buildPackages) bash coreutils gnumake sed grep gawk findutils tar gzip diffutils patch;
  inherit (buildPackages) m4 flex bison autoconf automake texinfo help2man python3;
  target = stdenv.hostPlatform.config;
  build = stdenv.buildPlatform.config;
  elfMachine =
    if stdenv.hostPlatform.isAarch64
    then 183
    else 62;
  targetTool = name: "${binutils}/bin/${lib.optionalString stdenv.isCross "${target}-"}${name}";

  # Match the ordinary GCC16 source terms without changing that compiler recipe.
  gccSource = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-16.2.0/gcc-16.2.0.tar.xz";
    sha256 = "18mx8x4as86ngqxk9r91fppm8kkkdydn9jgvhih06245z7cjrplj";
  };
  gmpSource = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gmp/gmp-6.3.0.tar.xz";
    sha256 = "1kc3dy4jxand0y118yb9715g9xy1fnzqgkwxy02vd57y2fhg2pcw";
  };
  mpfrSource = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpfr/mpfr-4.2.1.tar.xz";
    sha256 = "1irpgc9aqyhgkwqk7cvib1dgr5v5hf4m0vaaknssyfpkjmab9ydq";
  };
  mpcSource = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/mpc/mpc-1.3.1.tar.gz";
    sha256 = "1b6layaybj039fajx8dpy2zvcfy7s02y3y4lficz16vac0fsd0jk";
  };
  islSource = builtins.fetchTarball {
    url = "https://downloads.sourceforge.net/project/libisl/isl-0.26.tar.xz";
    sha256 = "01krva4ax8zvi365akpzdv8r3a3gdl8sqcdgsg2kxmcy810gay0k";
  };

  template = builtins.readFile ./qom-unwind-configure.bash.in;
  expectedMarkers = builtins.fromJSON (builtins.readFile ./qom-unwind-template-markers.json);
  substitutions = {
    inherit gccSource gmpSource mpfrSource mpcSource islSource;
    compiler = buildCompiler;
    binutils = buildBinutils;
    glibc = buildGlibc;
    glibcDev = buildGlibc.dev;
    glibcStatic = buildGlibc.static;
    linuxHeaders = buildHeaders;
    inherit bash coreutils gnumake sed grep gawk findutils tar gzip diffutils patch;
    inherit m4 flex bison autoconf automake texinfo help2man python3;
    file = fileProbe;
    inherit build target compilerExecutable elfMachine;
    targetBinutils = binutils;
    targetGlibc = glibc;
    targetGlibcDev = glibc.dev;
    targetGlibcStatic = glibc.static;
    targetHeaders = linuxHeaders;
    targetAr = targetTool "ar";
    targetAs = targetTool "as";
    targetLd = targetTool "ld";
    targetNm = targetTool "nm";
    targetRanlib = targetTool "ranlib";
    targetStrip = targetTool "strip";
    cetArgument = lib.optionalString stdenv.hostPlatform.isx86_64 "--enable-cet";
    runtimeScripts = ../../stdenv/runtime-scripts.sh;
    bootstrapPatch = ../../stdenv/toolchains/gcc16/patches/gcc-16.2.0-strict-bootstrap-compare.patch;
    captureCommands = ./capture-qom-unwind-commands.py;
    memberVariables = ./qom-unwind-member-vars.mk;
    normalizeProbe = ./normalize-qom-unwind-file-probes.py;
    probeCatalog = ./qom-unwind-file-probes.json;
  };
  # Path interpolation imports source files into the sandbox input closure.
  # toString alone would retain an inaccessible workspace path.
  sourceReference = value:
    if builtins.isPath value
    then "${value}"
    else toString value;
  markers = builtins.attrNames expectedMarkers;
  replacement = marker: let
    name = builtins.substring 1 (builtins.stringLength marker - 2) marker;
  in
    sourceReference substitutions.${name};
  validTemplate =
    builtins.all (
      marker:
        builtins.length (lib.splitString marker template) - 1 == expectedMarkers.${marker}
    )
    markers;
  configureScript =
    if !validTemplate || builtins.length markers != builtins.length (builtins.attrNames substitutions)
    then throw "The audited GNU context marker roster changed"
    else builtins.replaceStrings markers (map replacement markers) template;
  tools = [buildCompiler buildBinutils compiler binutils bash coreutils gnumake sed grep gawk findutils tar gzip diffutils patch m4 flex bison autoconf automake texinfo help2man python3 fileProbe];
  retainedRecipes =
    [
      ./_qom-unwind-context.nix
      ./qom-unwind-configure.bash.in
      ./qom-unwind-template-markers.json
      ./capture-qom-unwind-commands.py
      ./qom-unwind-member-vars.mk
      ./normalize-qom-unwind-file-probes.py
      ./qom-unwind-file-probes.json
      ./record-qom-unwind-context.py
      ../../stdenv/runtime-scripts.sh
      ../../stdenv/toolchains/gcc16/unwind-file.nix
      ../../stdenv/toolchains/gcc16/gcc-stage2.nix
      ../../stdenv/toolchains/gcc16/patches/gcc-16.2.0-strict-bootstrap-compare.patch
      ../../stdenv/linux-cross/gcc.nix
      ../../stdenv/linux-cross/toolchain.nix
      ../../stdenv/linux-cross/gcc-16-gawk-5.4.patch
    ]
    ++ (compiler.passthru.evidenceSources or [])
    ++ (buildCompiler.passthru.evidenceSources or [])
    ++ (fileProbe.passthru.evidenceSources or []);
in
  if !supported
  then throw "The private GNU context requires a Linux GNU builder and x86_64/aarch64 Linux GNU host"
  else
    # This output is target configuration data, produced by native tools.
    # Native mkDerivation also prevents target compilers from tool splicing.
    buildPackages.mkDerivation {
      pname = "qom-unwind-context";
      version = "16.2.0-2";
      outputs = ["out" "source"];
      src = gccSource;
      # Generators and the data output remain build-native. The compiler and
      # configured libgcc recipes generate code for the QEMU host instead.
      targetPlatform = stdenv.hostPlatform;
      # Nix writes this builder input after realizing its tool dependencies.
      # A store text file cannot carry references to unrealized derivations.
      qomConfigureScript = configureScript;
      passAsFile = ["qomConfigureScript"];
      buildDeps = tools;
      runtimeDeps = [];
      propagatedDeps = [];
      dontStrip = true;
      dontNukeRefs = true;
      passthru = {
        inherit compiler compilerExecutable build target elfMachine;
        targetBinutils = binutils;
        evidenceSources = retainedRecipes;
      };
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$source/generated-context" "$out/share/qom-private-unwind" "$source/recipe"
            export TMPDIR="$source/generated-context"
            ${bash}/bin/bash --noprofile --norc "$qomConfigureScriptPath" \
              > "$out/share/qom-private-unwind/configure.stdout" \
              2> "$out/share/qom-private-unwind/configure.stderr"
          '';
        }
        {
          name = "install";
          script = ''
            for recipe in ${builtins.concatStringsSep " " (lib.unique (map sourceReference retainedRecipes))}; do
              cp -a "$recipe" "$source/recipe/$(basename "$recipe")"
            done
            cp "$qomConfigureScriptPath" "$source/recipe/configure-command.bash"
            ${python3}/bin/python3 -I -B ${./record-qom-unwind-context.py} \
              --output "$out" --source "$source" --compiler ${compilerExecutable} --binutils ${binutils}/bin \
              --target ${target} --build ${build} --elf-machine ${toString elfMachine} --build-word-bytes ${toString buildWordBytes} \
              --dependency-root ${glibc} --dependency-root ${glibc.dev} \
              --dependency-root ${glibc.static} --dependency-root ${linuxHeaders} \
              --dependency-root ${compiler} --dependency-root ${binutils} \
              --dependency-root ${buildCompiler} --dependency-root ${buildBinutils} \
              --dependency-root ${buildGlibc} --dependency-root ${buildGlibc.dev} \
              --dependency-root ${buildGlibc.static} --dependency-root ${buildHeaders} \
              --configure-script "$source/recipe/configure-command.bash"
            mkdir -p "$out/nix-support"
            printf '%s\n' "$source" > "$out/nix-support/corresponding-source"
          '';
        }
      ];
      meta = {
        description = "Source-built GNU host configuration and complete private observer inputs";
        license = "GPL-3.0-or-later WITH GCC-exception-3.1";
      };
    }
