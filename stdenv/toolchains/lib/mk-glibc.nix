# stdenv/toolchains/lib/mk-glibc.nix - shared native glibc builder
#
# Native gcc8+ glibc tiers share the same source-unpack, out-of-tree
# configure, make, install, and kernel-header staging flow. The tier specs
# keep version-specific flags and post-install layout decisions local.
{
  prev,
  gcc,
  binutils,
  linuxHeaders,
  buildPlatform,
  hostPlatform,
  runtimePerl ? null,
}: spec: let
  optionalString = cond: value:
    if cond
    then value
    else "";

  concat = builtins.concatStringsSep;

  version = spec.version;
  sourceDir = spec.sourceDir or "glibc-${version}";
  name = spec.name or "glibc-${version}";

  src = builtins.fetchTarball {
    inherit (spec) url sha256;
  };

  sourceScriptFilter = spec.sourceScriptFilter or null;
  sourceScriptFilterSetup = optionalString (sourceScriptFilter != null) ''
    source_runtime_inputs="$TMPDIR/libc-runtime-scripts"
    mkdir -p "$source_runtime_inputs"
    ${sourceScriptFilter}/bin/perl ${../../filter-runtime-scripts.pl} . "$source_runtime_inputs"
  '';
  sourceScriptRoot =
    if sourceScriptFilter == null
    then "."
    else ''"$source_runtime_inputs"'';
  sourceScriptFilterCleanup = optionalString (sourceScriptFilter != null) ''

    rm -rf "$source_runtime_inputs"
  '';

  basePathDeps = [
    prev.coreutils
    gcc
    binutils
    prev.gnumake
    prev.sed
    prev.grep
    prev.gawk
    prev.findutils
    prev.tar
    prev.gzip
    prev.diffutils
    prev.bash
    prev.patch
  ];
  runtimePathDeps =
    if runtimePerl == null
    then []
    else [runtimePerl];
  path = concat ":" (map (dep: "${dep}/bin") (basePathDeps ++ (spec.extraPathDeps or []) ++ runtimePathDeps));

  # Manual installation requires a real Info output after source timestamps
  # change. Use the preceding tier's Texinfo to regenerate it hermetically.
  makeInfo = "${prev.texinfo}/bin/makeinfo";
  autotoolsVars = "AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=${makeInfo}";
  configureBuild = spec.configureBuild or buildPlatform.config;
  configureHost = spec.configureHost or hostPlatform.config;
  withHeaders = spec.withHeaders or "${linuxHeaders}/include";
  configureArgs =
    [
      ''--prefix="$out"''
      "--build=${configureBuild}"
      "--host=${configureHost}"
      "--with-binutils=${binutils}/bin"
      ''--with-headers="${withHeaders}"''
    ]
    ++ (spec.configureFlags or [])
    ++ (spec.configureCacheVars or []);
  configureArgsText = concat " \\\n          " configureArgs;

  makeFlags = concat " " (spec.makeFlags or []);
  installFlags = concat " " (spec.installFlags or []);
  cflags = spec.cflags or "-O2";
  cppflags = spec.cppflags or null;
  useCxx = spec.useCxx or false;
  cc = spec.cc or "${gcc}/bin/gcc";
  cxx = spec.cxx or "${gcc}/bin/g++";
  # Older configure scripts restore CC from their cache after checking the
  # --with-binutils override. Pin the original command as well so compilation
  # cannot silently return to the compiler's construction-stage assembler.
  configureEnv =
    [
      ''CC="${cc} -B${binutils}/bin/"''
    ]
    ++ (
      if useCxx
      then [''CXX="${cxx} -B${binutils}/bin/"'']
      else []
    )
    ++ [
      ''AR="${binutils}/bin/ar"''
      ''RANLIB="${binutils}/bin/ranlib"''
      ''CFLAGS="${cflags}"''
    ]
    ++ (
      if cppflags != null
      then [''CPPFLAGS="${cppflags}"'']
      else []
    );
  configureEnvText = concat " \\\n        " configureEnv;

  copyLinuxHeaders = spec.copyLinuxHeaders or true;
  linuxHeadersSource = spec.linuxHeadersSource or "${linuxHeaders}/include";
  linuxHeadersDest = spec.linuxHeadersDest or "$out/include";
  linuxHeadersCpFlags =
    if spec.copyLinuxHeadersNoPreserve or false
    then "-r --no-preserve=mode,ownership"
    else "-r";

  splitOutputs = spec.splitOutputs or "";
  finalMessage = spec.finalMessage or "glibc ${version} installed to $out";
in
  builtins.derivation {
    inherit name;
    outputs = spec.outputs or ["out"];
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${makeInfo}"
        export PATH="${path}"
        export CONFIG_SHELL="${prev.bash}/bin/bash"
        export SHELL="$CONFIG_SHELL"

        cd "$TMPDIR"
        mkdir ${sourceDir} && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd ${sourceDir} && ${prev.tar}/bin/tar xf -)
        cd ${sourceDir}
        chmod -R u+w .

        # Upstream helpers can be executed directly by configure or make.
        ${sourceScriptFilterSetup}AOS_RUNTIME_SHELL="$CONFIG_SHELL" \
          "$CONFIG_SHELL" ${../../runtime-scripts.sh} ${sourceScriptRoot}${sourceScriptFilterCleanup}

        ${spec.postUnpack or ""}

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        ${spec.preConfigure or ""}

        ${configureEnvText} \
        "$CONFIG_SHELL" "$TMPDIR/${sourceDir}/configure" \
          ${configureArgsText}

        make -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL" ${makeFlags} ${autotoolsVars}
        ${spec.postBuild or ""}
        make install SHELL="$CONFIG_SHELL" ${installFlags} ${autotoolsVars}

        ${optionalString copyLinuxHeaders ''
          cp ${linuxHeadersCpFlags} "${linuxHeadersSource}/linux" "${linuxHeadersDest}/" 2>/dev/null || true
          cp ${linuxHeadersCpFlags} "${linuxHeadersSource}/asm" "${linuxHeadersDest}/" 2>/dev/null || true
          cp ${linuxHeadersCpFlags} "${linuxHeadersSource}/asm-generic" "${linuxHeadersDest}/" 2>/dev/null || true
        ''}

        ${spec.postInstall or ""}

        ${splitOutputs}

        echo "${finalMessage}"
      ''
    ];
  }
  // {
    inherit version;
    pname = "glibc";
    passthru.evidenceSources = [src];
    meta =
      spec.meta
      or {
        description = "GNU C Library, version ${version}";
        homepage = "https://www.gnu.org/software/libc/";
        license = "LGPL-2.1-or-later";
        build = {
          os = "linux";
        };
        execute = {
          os = "linux";
        };
      };
  }
