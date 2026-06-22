# stdenv/toolchains/lib/mk-gcc.nix - shared native GCC builder
#
# Native GCC tiers share the same source staging, in-tree dependency unpack,
# out-of-tree configure, and install scaffolding. Tier files keep the real
# version-specific work: sysroot layout, old-header fixes, specs surgery,
# target library selection, and whether the final compiler uses GCC bootstrap.
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}: spec: let
  optionalString = cond: value:
    if cond
    then value
    else "";

  concat = builtins.concatStringsSep;

  version = spec.version;
  sourceDir = spec.sourceDir or "gcc-${version}";
  name = spec.name or "gcc-${version}";
  bootstrap = spec.bootstrap or false;

  basePathDeps = [
    prev.coreutils
    prev.gcc
    prev.binutils
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
  pathDeps = spec.pathDeps or (basePathDeps ++ (spec.extraPathDeps or []));
  path = concat ":" (map (dep: "${dep}/bin") pathDeps);

  autotoolsVars = "AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true";

  inTreeDeps = spec.inTreeDeps or [];
  unpackInTreeDeps = concat "\n" (map (dep: ''
      mkdir ${dep.name} && (cd ${dep.src} && ${prev.tar}/bin/tar cf - .) | (cd ${dep.name} && ${prev.tar}/bin/tar xf -)
      chmod -R u+w ${dep.name}
    '')
    inTreeDeps);
  unpackCommands =
    spec.unpackCommands
    or ''
      mkdir ${sourceDir} && (cd ${spec.src} && ${prev.tar}/bin/tar cf - .) | (cd ${sourceDir} && ${prev.tar}/bin/tar xf -)
    '';

  freezeAutotoolsDirs = spec.freezeAutotoolsDirs or (["."] ++ (map (dep: dep.name) inTreeDeps));
  freezeAutotoolsDirText = concat " " freezeAutotoolsDirs;
  freezeAutotoolsTimestamps = spec.freezeAutotoolsTimestamps or true;
  freezeAutotoolsScript = optionalString freezeAutotoolsTimestamps ''
    for dir in ${freezeAutotoolsDirText}; do
      find "$dir" -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
    done
    sleep 1
    for dir in ${freezeAutotoolsDirText}; do
      find "$dir" -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
    done
    sleep 1
    for dir in ${freezeAutotoolsDirText}; do
      find "$dir" \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
    done
  '';

  configureArgs =
    [
      ''--prefix="$out"''
      "--build=${spec.configureBuild or buildPlatform.config}"
      "--host=${spec.configureHost or hostPlatform.config}"
      "--target=${spec.configureTarget or targetPlatform.config}"
    ]
    ++ (spec.configureFlags or []);
  configureArgsText = concat " \\\n          " configureArgs;

  configureEnv = spec.configureEnv or [];
  configureEnvText = concat " \\\n        " configureEnv;
  configureEnvPrefix = optionalString (configureEnv != []) ''
    ${configureEnvText} \
  '';

  makeFlags = concat " " (spec.makeFlags or []);
  bootstrapTarget =
    if bootstrap
    then "bootstrap"
    else "";
  defaultBuildCommands = ''
    make -j"$NIX_BUILD_CORES" ${bootstrapTarget} ${makeFlags} ${autotoolsVars}
  '';

  installFlags = concat " " (spec.installFlags or []);
  defaultInstallCommands = ''
    make install ${installFlags} ${autotoolsVars}
  '';

  aliasCommands = optionalString (spec.createCcAliases or true) ''
    [ -f "$out/bin/gcc" ] && [ ! -f "$out/bin/cc" ] && ln -sf gcc "$out/bin/cc"
    [ -f "$out/bin/g++" ] && [ ! -f "$out/bin/c++" ] && ln -sf g++ "$out/bin/c++"
  '';

  finalMessage = spec.finalMessage or "GCC ${version} installed to $out";
in
  builtins.derivation {
    inherit name;
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
        ${spec.preUnpack or ""}
        ${unpackCommands}
        cd ${sourceDir}
        chmod -R u+w .

        ${unpackInTreeDeps}

        ${spec.postUnpack or ""}
        ${freezeAutotoolsScript}

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        ${spec.preConfigure or ""}

        ${configureEnvPrefix}"$TMPDIR/${sourceDir}/configure" \
          ${configureArgsText}

        ${spec.postConfigure or ""}

        ${spec.buildCommands or defaultBuildCommands}

        ${spec.postBuild or ""}

        ${spec.installCommands or defaultInstallCommands}

        ${aliasCommands}

        ${spec.postInstall or ""}

        echo "${finalMessage}"
      ''
    ];
  }
  // {
    meta =
      spec.meta
      or {
        description = "GNU Compiler Collection, version ${version}";
        homepage = "https://gcc.gnu.org/";
        license = "GPL-3.0-or-later";
        build = {
          os = "linux";
        };
        execute = {
          os = "linux";
        };
        target = {
          os = "linux";
        };
      };
  }
