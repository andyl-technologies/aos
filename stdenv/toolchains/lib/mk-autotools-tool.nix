# stdenv/toolchains/lib/mk-autotools-tool.nix - manifest-backed tier tools
#
# This is intentionally scoped to the post-bootstrap toolchain ladder. It
# centralizes the repeated gcc8+ POSIX tool pattern: unpack an already-fetched
# tarball directory, freeze autotools timestamps, configure with the tier
# cc-wrapper, and run make/install with regeneration tools disabled.
{
  lib,
  phases,
  tierStdenv,
  buildPlatform,
  hostPlatform,
}: spec: let
  inherit (lib) addPhaseAfter optionalAttrs replacePhase;

  concat = builtins.concatStringsSep;
  optionalString = cond: value:
    if cond
    then value
    else "";

  source =
    if (spec.fetchMode or "tarball") == "url"
    then
      builtins.derivation {
        name = spec.srcName or (builtins.baseNameOf spec.url);
        system = buildPlatform.system;
        builder = "builtin:fetchurl";
        inherit (spec) url;
        outputHash = spec.hash;
        outputHashMode = "flat";
        outputHashAlgo = "sha256";
        preferLocalBuild = true;
      }
    else
      builtins.fetchTarball {
        inherit (spec) url;
        sha256 = spec.hash;
      };

  name = spec.name or "${spec.pname}-${spec.version}";
  makeInfo = spec.makeInfo or "true";
  unpackMode = spec.unpackMode or "tar-pipe";
  freezeAutotoolsTimestamps = spec.freezeAutotoolsTimestamps or true;
  configureInSource = spec.configureInSource or false;
  useCxx = spec.useCxx or false;
  staticNssWrapper = spec.staticNssWrapper or false;
  compiler = spec.compiler or {};
  compilerGcc = compiler.gcc or tierStdenv.gcc;
  compilerGlibc = compiler.glibc or tierStdenv.glibc;
  compilerBinutils = compiler.binutils or tierStdenv.binutils;
  compilerBuildDeps =
    spec.compilerBuildDeps
    or (
      if staticNssWrapper
      then [
        compilerGcc
        compilerBinutils
      ]
      else []
    );

  gccVersion = spec.gccVersion or "8.5.0";
  cflags = spec.cflags or "-O2 -nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${compilerGlibc}/include";
  cppflags = spec.cppflags or "-nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${compilerGlibc}/include";
  ldflags = spec.ldflags or "-L${compilerGlibc}/lib -static";
  cxxflags = spec.cxxflags or "-O2 -nostdinc -nostdinc++ -isystem $CXX_INCDIR -isystem $CXX_INCDIR/${hostPlatform.config} -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${compilerGlibc}/include";
  cc =
    spec.cc
    or (
      if staticNssWrapper
      then "$TMPDIR/ccwrap/gcc"
      else "${tierStdenv.cc}/bin/gcc"
    );
  cxx =
    spec.cxx
    or (
      if staticNssWrapper
      then "$TMPDIR/ccwrap/g++"
      else "${tierStdenv.cc}/bin/g++"
    );

  configureFlagsList = spec.configureFlags or [];
  makeFlagsList = spec.makeFlags or [];
  installFlagsList = spec.installFlags or [];
  configureFlags = concat " " configureFlagsList;
  makeFlags = concat " " makeFlagsList;
  installFlags = concat " " installFlagsList;

  configureEnv = spec.configureEnv or "";
  preConfigure = spec.preConfigure or "";
  postConfigure = spec.postConfigure or "";
  buildScript =
    spec.buildScript
    or ''
      make -j"$NIX_BUILD_CORES" ${makeFlags} ${autotoolsVars}
    '';
  postBuild = spec.postBuild or "";
  installScript =
    spec.installScript
    or ''
      make install ${installFlags} ${autotoolsVars}
    '';
  postInstall = spec.postInstall or "";
  postUnpack = spec.postUnpack or "";
  postFreeze = spec.postFreeze or "";
  meta = spec.meta or {};
  extraAttrs = spec.extraAttrs or {};

  autotoolsVars = "AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true";

  commonCompilerEnv = ''
    export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
    export MAKEINFO="''${MAKEINFO:-${makeInfo}}"
    export CONFIG_SHELL="${tierStdenv.shell}"

    # setup.sh adds $out/lib to NIX_LDFLAGS for production packages. These
    # ladder tools are deliberately static and historically had no output rpath.
    export NIX_LDFLAGS=""

    export AOS_BASH="${tierStdenv.shell}"
    export AOS_GLIBC="${tierStdenv.glibc}"
    export LIBRARY_PATH="${compilerGlibc}/lib''${LIBRARY_PATH:+:$LIBRARY_PATH}"

    ${optionalString staticNssWrapper ''
      mkdir -p "$TMPDIR/ccwrap"
      cat > "$TMPDIR/ccwrap/gcc" <<'AOS_CC_WRAP'
      #!${tierStdenv.shell}
      compile=
      for arg; do
        case "$arg" in
          -c|-E|-S) compile=1 ;;
        esac
      done
      if [ -z "$compile" ]; then
        exec "${compilerGcc}/bin/gcc" -isystem "${compilerGlibc}/include" "$@" -L "${compilerGlibc}/lib" -static -Wl,--start-group -Wl,--whole-archive "${compilerGlibc}/lib/libnss_files.a" "${compilerGlibc}/lib/libnss_dns.a" "${compilerGlibc}/lib/libresolv.a" -Wl,--no-whole-archive -lc -Wl,--end-group
      fi
      exec "${compilerGcc}/bin/gcc" -isystem "${compilerGlibc}/include" "$@"
      AOS_CC_WRAP
      cat > "$TMPDIR/ccwrap/g++" <<'AOS_CXX_WRAP'
      #!${tierStdenv.shell}
      compile=
      for arg; do
        case "$arg" in
          -c|-E|-S) compile=1 ;;
        esac
      done
      if [ -z "$compile" ]; then
        exec "${compilerGcc}/bin/g++" -isystem "${compilerGlibc}/include" "$@" -L "${compilerGlibc}/lib" -static -Wl,--start-group -Wl,--whole-archive "${compilerGlibc}/lib/libnss_files.a" "${compilerGlibc}/lib/libnss_dns.a" "${compilerGlibc}/lib/libresolv.a" -Wl,--no-whole-archive -lc -Wl,--end-group
      fi
      exec "${compilerGcc}/bin/g++" -isystem "${compilerGlibc}/include" "$@"
      AOS_CXX_WRAP
      chmod +x "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"
    ''}

    GCC_INCDIR="${compilerGcc}/lib/gcc/${hostPlatform.config}/${gccVersion}/include"
    CXX_INCDIR="${compilerGcc}/include/c++/${gccVersion}"

    export CC="${cc}"
    export CXX="${cxx}"
    export LD="${compilerBinutils}/bin/ld"
    export AR="${compilerBinutils}/bin/ar"
    export RANLIB="${compilerBinutils}/bin/ranlib"
    export STRIP="${compilerBinutils}/bin/strip"
    export NM="${compilerBinutils}/bin/nm"
    export OBJDUMP="${compilerBinutils}/bin/objdump"
    export CFLAGS="${cflags}"
    export CPPFLAGS="${cppflags}"
    export LDFLAGS="${ldflags}"
    ${optionalString useCxx ''
      export CXXFLAGS="${cxxflags}"
    ''}
    ${configureEnv}
  '';

  configurePhase = {
    name = "configure";
    script =
      ''
        sourceDir="$PWD"
        ${commonCompilerEnv}
        ${preConfigure}
      ''
      + (
        if spec ? configureScript
        then spec.configureScript
        else if configureInSource
        then ''
          ./configure \
            --prefix="$out" \
            ${configureFlags}
        ''
        else ''
          mkdir -p "$TMPDIR/build"
          cd "$TMPDIR/build"

          "$sourceDir/configure" \
            --prefix="$out" \
            ${configureFlags}
        ''
      )
      + ''
        ${postConfigure}
      '';
  };

  buildPhase = {
    name = "build";
    script =
      buildScript
      + ''
        ${postBuild}
      '';
  };

  installPhase = {
    name = "install";
    script =
      installScript
      + ''
        ${postInstall}
      '';
  };

  basePhases = phases.autoconfPhases {
    doCheck = spec.doCheck or false;
    inherit unpackMode freezeAutotoolsTimestamps;
  };

  withPostUnpack =
    if postUnpack != ""
    then
      addPhaseAfter basePhases "unpack" {
        name = "post-unpack";
        script = postUnpack;
      }
    else basePhases;

  withPostFreeze =
    if postFreeze != ""
    then
      addPhaseAfter withPostUnpack "freeze-autotools-timestamps" {
        name = "post-freeze-autotools-timestamps";
        script = postFreeze;
      }
    else withPostUnpack;

  packagePhases =
    replacePhase
    (replacePhase (replacePhase withPostFreeze "configure" configurePhase) "build" buildPhase)
    "install"
    installPhase;
in
  tierStdenv.mkDerivation (
    {
      inherit name;
      inherit (spec) pname version;
      src = source;
      buildDeps = (spec.buildDeps or []) ++ compilerBuildDeps;
      runtimeDeps = spec.runtimeDeps or [];
      propagatedDeps = spec.propagatedDeps or [];
      phases = packagePhases;
      MAKEINFO = makeInfo;
      AOS_BASH = tierStdenv.shell;
      AOS_GLIBC = "${tierStdenv.glibc}";

      # Phase 1 is a structural migration. Preserve the old raw derivations'
      # lack of generic strip/shebang/rpath movement and reference scrubbing.
      dontStrip = spec.dontStrip or true;
      dontPatchShebangs = spec.dontPatchShebangs or true;
      dontPatchELF = spec.dontPatchELF or true;
      dontValidateRunpath = spec.dontValidateRunpath or true;
      dontMoveDocs = spec.dontMoveDocs or true;
      dontNukeRefs = spec.dontNukeRefs or true;
      hardeningDisable = spec.hardeningDisable or ["all"];

      meta =
        {
          build = {
            os = "linux";
          };
          execute = {
            os = "linux";
          };
        }
        // meta;
    }
    // optionalAttrs (spec ? passthru) {inherit (spec) passthru;}
    // extraAttrs
  )
