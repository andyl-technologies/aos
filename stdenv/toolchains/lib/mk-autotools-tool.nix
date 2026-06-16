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

  source = builtins.fetchTarball {
    inherit (spec) url;
    sha256 = spec.hash;
  };

  name = spec.name or "${spec.pname}-${spec.version}";
  makeInfo = spec.makeInfo or "true";
  unpackMode = spec.unpackMode or "tar-pipe";
  freezeAutotoolsTimestamps = spec.freezeAutotoolsTimestamps or true;
  configureInSource = spec.configureInSource or false;
  useCxx = spec.useCxx or false;

  gccVersion = spec.gccVersion or "8.5.0";
  cflags = spec.cflags or "-O2 -nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${tierStdenv.glibc}/include";
  cppflags = spec.cppflags or "-nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${tierStdenv.glibc}/include";
  ldflags = spec.ldflags or "-L${tierStdenv.glibc}/lib -static";
  cxxflags = spec.cxxflags or "-O2 -nostdinc -nostdinc++ -isystem $CXX_INCDIR -isystem $CXX_INCDIR/${hostPlatform.config} -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${tierStdenv.glibc}/include";

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
    export LIBRARY_PATH="${tierStdenv.glibc}/lib''${LIBRARY_PATH:+:$LIBRARY_PATH}"

    GCC_INCDIR="${tierStdenv.gcc}/lib/gcc/${hostPlatform.config}/${gccVersion}/include"
    CXX_INCDIR="${tierStdenv.gcc}/include/c++/${gccVersion}"

    export CC="${tierStdenv.cc}/bin/gcc"
    export CXX="${tierStdenv.cc}/bin/g++"
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
      buildDeps = spec.buildDeps or [];
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
