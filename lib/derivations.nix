# lib/derivations.nix — Clean derivation builder
#
# Provides:
#   mkDerivation   — build a package from source
#   mkShell        — development shell environment
#   fetchurl       — fetch a file by URL (fixed-output derivation)
#   fetchgit       — fetch a Git repository (fixed-output derivation)
#   replacePhase   — replace a phase by name
#   addPhaseAfter  — insert a phase after a named phase
#   addPhaseBefore — insert a phase before a named phase
#   removePhase    — remove a phase by name
#
# The `system` parameter must be provided by the caller (lib/default.nix)
# and is used as the default for all derivation builders.

{ system }:

let
  defaultSystem = system;

  # ---------------------------------------------------------------------------
  # Default phase definitions
  # ---------------------------------------------------------------------------

  defaultUnpackPhase = {
    name = "unpack";
    script = ''
      if [ -z "$src" ]; then
        echo ">>> No source to unpack (src is empty)"
      # Unpack source archive
      elif [ -d "$src" ]; then
        cp -r "$src" source
        chmod -R u+w source
      elif [ -f "$src" ]; then
        case "$src" in
          *.tar.gz|*.tgz)   tar xzf "$src" ;;
          *.tar.bz2|*.tbz2) tar xjf "$src" ;;
          *.tar.xz|*.txz)   tar xJf "$src" ;;
          *.tar.zst)         tar --zstd -xf "$src" ;;
          *.tar)             tar xf "$src" ;;
          *.zip)             unzip "$src" ;;
          *)                 echo "Unknown archive format: $src"; exit 1 ;;
        esac
      else
        echo "Source not found: $src"
        exit 1
      fi

      # Enter the source directory (handle single top-level directory)
      if [ -n "$src" ]; then
        if [ -d source ]; then
          cd source
        else
          ndirs=$(ls -d */ 2>/dev/null | wc -l)
          if [ "$ndirs" -eq 1 ]; then
            cd "$(ls -d */)"
          fi
        fi
      fi
    '';
  };

  defaultConfigurePhase = {
    name = "configure";
    script = ''
      # Configure: run ./configure if it exists
      if [ -x configure ]; then
        ./configure --prefix="$out" $configureFlags
      elif [ -f CMakeLists.txt ]; then
        cmake -B build -DCMAKE_INSTALL_PREFIX="$out" $cmakeFlags
      elif [ -f meson.build ]; then
        meson setup build --prefix="$out" $mesonFlags
      fi
    '';
  };

  defaultBuildPhase = {
    name = "build";
    script = ''
      # Build
      if [ -d build ] && [ -f build/build.ninja ]; then
        ninja -C build -j$NIX_BUILD_CORES
      elif [ -d build ]; then
        cmake --build build -j$NIX_BUILD_CORES
      elif [ -f Makefile ] || [ -f makefile ] || [ -f GNUmakefile ]; then
        make -j$NIX_BUILD_CORES $makeFlags
      fi
    '';
  };

  defaultInstallPhase = {
    name = "install";
    script = ''
      # Install
      if [ -d build ] && [ -f build/build.ninja ]; then
        DESTDIR="" ninja -C build install
      elif [ -d build ]; then
        cmake --install build
      elif [ -f Makefile ] || [ -f makefile ] || [ -f GNUmakefile ]; then
        make install DESTDIR="" $installFlags
      fi
    '';
  };

  defaultPhases = [
    defaultUnpackPhase
    defaultConfigurePhase
    defaultBuildPhase
    defaultInstallPhase
  ];

  # ---------------------------------------------------------------------------
  # Phase manipulation helpers
  # ---------------------------------------------------------------------------

  # replacePhase :: [phase] -> string -> phase -> [phase]
  # Replace a phase by name. Throws if the phase is not found.
  replacePhase =
    phases: name: newPhase:
    let
      found = builtins.any (p: p.name == name) phases;
    in
    if !found then
      throw "replacePhase: phase '${name}' not found in phases list"
    else
      builtins.map (p: if p.name == name then newPhase else p) phases;

  # addPhaseAfter :: [phase] -> string -> phase -> [phase]
  # Insert a new phase after the named phase.
  addPhaseAfter =
    phases: afterName: newPhase:
    let
      found = builtins.any (p: p.name == afterName) phases;
    in
    if !found then
      throw "addPhaseAfter: phase '${afterName}' not found in phases list"
    else
      builtins.concatLists (
        builtins.map (
          p:
          if p.name == afterName then
            [
              p
              newPhase
            ]
          else
            [ p ]
        ) phases
      );

  # addPhaseBefore :: [phase] -> string -> phase -> [phase]
  # Insert a new phase before the named phase.
  addPhaseBefore =
    phases: beforeName: newPhase:
    let
      found = builtins.any (p: p.name == beforeName) phases;
    in
    if !found then
      throw "addPhaseBefore: phase '${beforeName}' not found in phases list"
    else
      builtins.concatLists (
        builtins.map (
          p:
          if p.name == beforeName then
            [
              newPhase
              p
            ]
          else
            [ p ]
        ) phases
      );

  # removePhase :: [phase] -> string -> [phase]
  # Remove a phase by name.
  removePhase = phases: name: builtins.filter (p: p.name != name) phases;

  # ---------------------------------------------------------------------------
  # Internal: generate the build script from a list of phases
  # ---------------------------------------------------------------------------
  phasesToScript =
    phases: shell:
    let
      phaseScripts = builtins.map (phase: ''
        echo ">>> Phase: ${phase.name}"
        ${phase.script}
        echo "<<< Phase: ${phase.name} complete"
      '') phases;
    in
    ''
      #!${shell}
      set -euo pipefail

      # Source the stdenv setup if available
      if [ -n "''${stdenv:-}" ] && [ -f "$stdenv/setup.sh" ]; then
        source "$stdenv/setup.sh"
      fi

      ${builtins.concatStringsSep "\n" phaseScripts}
    '';

  # ---------------------------------------------------------------------------
  # Internal: build the PATH from dependency lists
  # ---------------------------------------------------------------------------
  makePath =
    deps:
    builtins.concatStringsSep ":" (
      builtins.concatLists (
        builtins.map (
          d:
          let
            p = builtins.toString d;
          in
          [
            "${p}/bin"
            "${p}/sbin"
          ]
        ) deps
      )
    );

  makeLibPath =
    deps: builtins.concatStringsSep ":" (builtins.map (d: "${builtins.toString d}/lib") deps);

  makeIncPath =
    deps: builtins.concatStringsSep ":" (builtins.map (d: "${builtins.toString d}/include") deps);

  makeRpathFlags =
    deps:
    builtins.concatStringsSep " " (builtins.map (d: "-Wl,-rpath,${builtins.toString d}/lib") deps);

  # ---------------------------------------------------------------------------
  # mkDerivation
  # ---------------------------------------------------------------------------
  # mkDerivation {
  #   pname;           — package name
  #   version;         — package version
  #   src;             — source (path, fetchurl result, etc.)
  #   buildDeps;       — build-time dependencies (nativeBuildInputs equivalent)
  #   runtimeDeps;     — runtime dependencies (buildInputs equivalent)
  #   propagatedDeps;  — propagated dependencies (propagatedBuildInputs equivalent)
  #   phases;          — ordered list of { name; script; } records
  #   meta;            — package metadata
  #   storeDir;        — store directory (default: /nix/store)
  #   ...              — additional attributes passed to builtins.derivation
  # }
  mkDerivation =
    args@{
      pname ? null,
      version ? "0",
      src ? null,
      buildDeps ? [ ],
      runtimeDeps ? [ ],
      propagatedDeps ? [ ],
      phases ? defaultPhases,
      meta ? { },
      storeDir ? "/nix/store",
      system ? defaultSystem,
      shell ? "/bin/sh",
      outputs ? [ "out" ],
      configureFlags ? "",
      makeFlags ? "",
      installFlags ? "",
      cmakeFlags ? "",
      mesonFlags ? "",
      patches ? [ ],
      postPatch ? "",
      preConfigure ? "",
      postConfigure ? "",
      preBuild ? "",
      postBuild ? "",
      preInstall ? "",
      postInstall ? "",
      passthru ? { },
      ...
    }:
    let
      # Accept either `name` (direct) or `pname` (computed as pname-version).
      name =
        args.name or (
          if pname != null then
            "${pname}-${version}"
          else
            throw "mkDerivation: either 'pname' or 'name' must be provided"
        );
      effectivePname = if pname != null then pname else name;

      # Collect all dependencies for PATH
      allBuildDeps = buildDeps ++ runtimeDeps ++ propagatedDeps;

      # Prepend patch phase if patches are provided
      patchPhase = {
        name = "patch";
        script = ''
          # Apply patches
          ${builtins.concatStringsSep "\n" (builtins.map (p: "patch -p1 < ${p}") patches)}
          ${postPatch}
        '';
      };

      effectivePhases =
        if patches != [ ] || postPatch != "" then addPhaseAfter phases "unpack" patchPhase else phases;

      # Inject pre/post hooks into phases
      finalPhases = builtins.map (
        phase:
        if phase.name == "configure" && (preConfigure != "" || postConfigure != "") then
          phase // { script = preConfigure + "\n" + phase.script + "\n" + postConfigure; }
        else if phase.name == "build" && (preBuild != "" || postBuild != "") then
          phase // { script = preBuild + "\n" + phase.script + "\n" + postBuild; }
        else if phase.name == "install" && (preInstall != "" || postInstall != "") then
          phase // { script = preInstall + "\n" + phase.script + "\n" + postInstall; }
        else
          phase
      ) effectivePhases;

      builder = phasesToScript finalPhases shell;

      # Extra args to pass through to builtins.derivation
      extraArgs = builtins.removeAttrs args [
        "name"
        "pname"
        "version"
        "src"
        "buildDeps"
        "runtimeDeps"
        "propagatedDeps"
        "phases"
        "meta"
        "storeDir"
        "system"
        "shell"
        "outputs"
        "configureFlags"
        "makeFlags"
        "installFlags"
        "cmakeFlags"
        "mesonFlags"
        "patches"
        "postPatch"
        "preConfigure"
        "postConfigure"
        "preBuild"
        "postBuild"
        "preInstall"
        "postInstall"
        "passthru"
      ];

      drv = builtins.derivation (
        {
          inherit name system;
          builder = shell;
          args = [
            "-c"
            builder
          ];
          inherit outputs;

          # Source
          src = if src != null then builtins.toString src else "";

          # Environment variables for the build
          PATH = makePath allBuildDeps;
          NIX_BUILD_CORES = "4";

          # Configuration flags
          inherit
            configureFlags
            makeFlags
            installFlags
            cmakeFlags
            mesonFlags
            ;

          # Dependency search paths — include buildDeps so build-time
          # libraries (e.g. elfutils for the kernel's objtool) are found.
          C_INCLUDE_PATH = makeIncPath allBuildDeps;
          CPLUS_INCLUDE_PATH = makeIncPath allBuildDeps;
          LIBRARY_PATH = makeLibPath allBuildDeps;
          LD_LIBRARY_PATH = makeLibPath allBuildDeps;

          # Inject -Wl,-rpath for runtime dep lib dirs so binaries can find
          # shared libraries at runtime without LD_LIBRARY_PATH.
          # Only runtimeDeps + propagatedDeps — NOT buildDeps — to avoid
          # dragging the compiler toolchain into the runtime closure.
          NIX_LDFLAGS = makeRpathFlags (runtimeDeps ++ propagatedDeps);
          PKG_CONFIG_PATH = builtins.concatStringsSep ":" (
            builtins.map (d: "${builtins.toString d}/lib/pkgconfig") allBuildDeps
          );

          # Store the dependencies for runtime reference
          buildInputs = builtins.map builtins.toString runtimeDeps;
          nativeBuildInputs = builtins.map builtins.toString buildDeps;
          propagatedBuildInputs = builtins.map builtins.toString propagatedDeps;

          # Prefer store dir parameter
          NIX_STORE_DIR = storeDir;
        }
        // extraArgs
      );

      # Attach metadata and override mechanism
      result = drv // {
        inherit meta version;
        pname = effectivePname;

        # Override mechanism
        override =
          overrideArgs:
          if builtins.isFunction overrideArgs then
            mkDerivation (overrideArgs args)
          else
            mkDerivation (args // overrideArgs);

        # overrideAttrs for modifying the derivation attributes
        overrideAttrs = f: mkDerivation (args // (f args));

        # passthru attributes (available without building the derivation)
        passthru = passthru // {
          inherit phases;
        };
      };
    in
    result;

  # ---------------------------------------------------------------------------
  # mkShell
  # ---------------------------------------------------------------------------
  # mkShell { buildDeps; runtimeDeps; shellHook; ... }
  #
  # Creates a development shell environment. Not meant to produce an installable
  # package; just sets up the environment for interactive development.
  mkShell =
    args@{
      buildDeps ? [ ],
      runtimeDeps ? [ ],
      shellHook ? "",
      name ? "aos-dev-shell",
      system ? defaultSystem,
      shell ? "/bin/sh",
      ...
    }:
    let
      allDeps = buildDeps ++ runtimeDeps;
      extraArgs = builtins.removeAttrs args [
        "buildDeps"
        "runtimeDeps"
        "shellHook"
        "name"
        "system"
        "shell"
      ];
    in
    builtins.derivation (
      {
        inherit name system;
        builder = shell;
        args = [
          "-c"
          ''
            echo "This derivation is a shell environment and is not meant to be built."
            echo "Use 'nix-shell' or 'nix develop' to enter this environment."
            exit 1
          ''
        ];

        # Environment setup
        PATH = makePath allDeps;
        C_INCLUDE_PATH = makeIncPath runtimeDeps;
        LIBRARY_PATH = makeLibPath runtimeDeps;
        inherit shellHook;

        # Mark as a shell environment
        _isShell = true;

        buildInputs = builtins.map builtins.toString runtimeDeps;
        nativeBuildInputs = builtins.map builtins.toString buildDeps;
      }
      // extraArgs
    )
    // {
      # For nix-shell compatibility, expose the input derivation
      inherit buildDeps runtimeDeps shellHook;
    };

  # ---------------------------------------------------------------------------
  # fetchurl
  # ---------------------------------------------------------------------------
  # fetchurl { url; hash; name; }   — single URL (backwards compatible)
  # fetchurl { urls; hash; name; }  — mirror list (preferred)
  #
  # Fixed-output derivation that downloads a file from a URL.
  # The hash ensures the download is reproducible.
  #
  # Accepts either `url` (string) or `urls` (list), following the nixpkgs
  # pattern.  Exactly one must be provided.  The full mirror list is exposed
  # as `.urls` on the result for CLI discovery.
  fetchurl =
    {
      url ? "",
      urls ? [ ],
      hash ? "",
      sha256 ? hash,
      name ? builtins.baseNameOf (if url != "" then url else builtins.head urls),
      executable ? false,
      system ? defaultSystem,
      storeDir ? "/nix/store",
    }:
    let
      resolvedUrls =
        if urls != [ ] && url == "" then
          urls
        else if urls == [ ] && url != "" then
          [ url ]
        else
          throw "fetchurl requires either 'url' or 'urls' to be set, not both";
    in
    builtins.derivation {
      inherit name system;
      builder = "builtin:fetchurl";
      url = builtins.head resolvedUrls;

      # Fixed-output derivation attributes
      outputHash = sha256;
      outputHashMode = "flat";
      outputHashAlgo = "sha256";

      # Nix needs network access for this derivation
      __impure = false; # Still a pure derivation (hash-verified)

      preferLocalBuild = true;

      # Make executable if requested
      inherit executable;
    }
    // {
      urls = resolvedUrls;
    };

  # ---------------------------------------------------------------------------
  # fetchgit
  # ---------------------------------------------------------------------------
  # fetchgit { url; rev; hash; }
  #
  # Fixed-output derivation that clones a Git repository at a specific revision.
  fetchgit =
    {
      url,
      rev,
      hash ? "",
      sha256 ? hash,
      name ? "source",
      fetchSubmodules ? false,
      system ? defaultSystem,
      storeDir ? "/nix/store",
      deepClone ? false,
      leaveDotGit ? false,
    }:
    builtins.derivation {
      inherit name system;
      builder = "/bin/sh";
      args = [
        "-c"
        ''
          set -euo pipefail
          export PATH="${storeDir}/git-minimal/bin:$PATH"
          export GIT_SSL_CAINFO="${storeDir}/cacert/etc/ssl/certs/ca-bundle.crt"

          git clone ${if deepClone then "" else "--depth 1"} \
            ${if fetchSubmodules then "--recurse-submodules" else ""} \
            "${url}" "$out"

          cd "$out"
          git checkout "${rev}"
          ${if fetchSubmodules then "git submodule update --init --recursive" else ""}
          ${if !leaveDotGit then "rm -rf .git" else ""}
        ''
      ];

      # Fixed-output derivation attributes
      outputHash = sha256;
      outputHashMode = "recursive";
      outputHashAlgo = "sha256";

      preferLocalBuild = true;
      inherit url rev;
    };

in
{
  inherit
    mkDerivation
    mkShell
    fetchurl
    fetchgit
    ;
  inherit
    replacePhase
    addPhaseAfter
    addPhaseBefore
    removePhase
    ;

  # Export default phases for use in stdenv/phases.nix
  inherit defaultPhases;
  phases = {
    inherit
      defaultUnpackPhase
      defaultConfigurePhase
      defaultBuildPhase
      defaultInstallPhase
      ;
  };
}
