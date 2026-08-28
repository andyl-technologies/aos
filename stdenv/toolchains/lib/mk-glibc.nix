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
  path = concat ":" (map (dep: "${dep}/bin") (basePathDeps ++ (spec.extraPathDeps or [])));

  autotoolsVars = "AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true";
  configureBuild = spec.configureBuild or buildPlatform.config;
  configureHost = spec.configureHost or hostPlatform.config;
  withHeaders = spec.withHeaders or "${linuxHeaders}/include";
  configureArgs =
    [
      ''--prefix="$out"''
      "--build=${configureBuild}"
      "--host=${configureHost}"
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
  configureEnv =
    [
      ''CC="${cc}"''
    ]
    ++ (
      if useCxx
      then [''CXX="${cxx}"'']
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
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
        export PATH="${path}"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        mkdir ${sourceDir} && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd ${sourceDir} && ${prev.tar}/bin/tar xf -)
        cd ${sourceDir}
        chmod -R u+w .

        ${spec.postUnpack or ""}

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        ${spec.preConfigure or ""}

        ${configureEnvText} \
        "$TMPDIR/${sourceDir}/configure" \
          ${configureArgsText}

        make -j"$NIX_BUILD_CORES" ${makeFlags} ${autotoolsVars}
        ${spec.postBuild or ""}
        make install ${installFlags} ${autotoolsVars}

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
