##! lib/derivations.nix — Clean derivation builder
##!
##! Provides:
##!
##!     mkDerivation   — build a package from source
##!     mkShell        — development shell environment
##!     fetchurl       — fetch a file by URL (fixed-output derivation)
##!     fetchgit       — fetch a Git repository (fixed-output derivation)
##!     fetchCargoDeps — vendor Cargo dependencies (fixed-output derivation)
##!     fetchGoModules — download Go module dependencies (fixed-output derivation)
##!     fakeHash       — placeholder hash for iterating on FODs
##!     replacePhase   — replace a phase by name
##!     addPhaseAfter  — insert a phase after a named phase
##!     addPhaseBefore — insert a phase before a named phase
##!     removePhase    — remove a phase by name
##!
##! The `system` parameter must be provided by the caller (lib/default.nix)
##! and is used as the default for all derivation builders.

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

  ## Replace a phase by name. Throws if the phase is not found.
  ## # Type
  ## `[phase] -> string -> phase -> [phase]`
  replacePhase =
    phases: name: newPhase:
    let
      found = builtins.any (p: p.name == name) phases;
    in
    if !found then
      throw "replacePhase: phase '${name}' not found in phases list"
    else
      builtins.map (p: if p.name == name then newPhase else p) phases;

  ## Insert a new phase after the named phase.
  ## # Type
  ## `[phase] -> string -> phase -> [phase]`
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

  ## Insert a new phase before the named phase.
  ## # Type
  ## `[phase] -> string -> phase -> [phase]`
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

  ## Remove a phase by name.
  ## # Type
  ## `[phase] -> string -> [phase]`
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
  # Internal: collect transitive propagated deps
  # ---------------------------------------------------------------------------
  # Given a list of direct deps, recursively collects their propagatedDeps
  # so that PKG_CONFIG_PATH, C_INCLUDE_PATH, etc. include transitive deps.
  collectPropagated =
    deps: seen:
    let
      newPropagated = builtins.concatLists (builtins.map (d: d.propagatedDeps or [ ]) deps);
      unseen = builtins.filter (d: !(builtins.elem d seen)) newPropagated;
    in
    if unseen == [ ] then seen else collectPropagated unseen (seen ++ unseen);

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
      checks ? null,
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

      # Collect all dependencies for PATH, including transitive propagated deps.
      # e.g. if dbus depends on libselinux and libselinux propagates pcre2,
      # then pcre2 will be on dbus's PKG_CONFIG_PATH automatically.
      directDeps = buildDeps ++ runtimeDeps ++ propagatedDeps;
      allBuildDeps = collectPropagated directDeps directDeps;

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
        "checks"
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
          # Includes transitive propagated deps but NOT buildDeps to avoid
          # dragging the compiler toolchain into the runtime closure.
          NIX_LDFLAGS = makeRpathFlags (
            collectPropagated (runtimeDeps ++ propagatedDeps) (runtimeDeps ++ propagatedDeps)
          );
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
      result =
        drv
        // {
          inherit meta version propagatedDeps;
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
        }
        // (if checks != null then { inherit checks; } else { });
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

  # ---------------------------------------------------------------------------
  # fakeHash — placeholder hash for iterating on fixed-output derivations
  # ---------------------------------------------------------------------------
  fakeHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

  # ---------------------------------------------------------------------------
  # fetchCargoDeps
  # ---------------------------------------------------------------------------
  # fetchCargoDeps { cargo; bootstrapTools; src; hash; sourceRoot?; cargoPatches?; }
  #
  # Fixed-output derivation that vendors Cargo dependencies via `cargo vendor`.
  #
  # gitDeps: list of { url, rev, crate } for git-sourced crates.
  #   Each is fetched via builtins.fetchGit (no git binary needed in sandbox)
  #   and copied into the vendor directory alongside crates-io deps.
  fetchCargoDeps =
    {
      cargo,
      bootstrapTools,
      src,
      hash,
      sourceRoot ? null,
      cargoPatches ? [ ],
      extraLibPaths ? [ ],
      gitDeps ? [ ],
      name ? "cargo-deps",
      system ? defaultSystem,
    }:
    let
      ldLibPath = builtins.concatStringsSep ":" (
        builtins.map (d: "${builtins.toString d}/lib") extraLibPaths
      );

      # Fetch each git dependency via builtins.fetchGit (Nix builtin, no git binary)
      fetchedGitDeps = builtins.map (
        dep:
        dep
        // {
          fetched = builtins.fetchGit {
            inherit (dep) url rev;
          };
        }
      ) gitDeps;

      # Shell commands to patch Cargo.toml so cargo vendor ignores git deps,
      # then copy git deps into the vendor output with .cargo-checksum.json
      gitPatchScript =
        if fetchedGitDeps == [ ] then
          ""
        else
          builtins.concatStringsSep "\n" (
            [
              ''
                # Patch Cargo.toml to replace git deps with path deps (so cargo vendor succeeds)
                printf '\n' >> Cargo.toml
              ''
            ]
            ++ builtins.map (dep: ''
              printf '[patch."${dep.url}"]\n${dep.crate} = { path = "${dep.fetched}" }\n' >> Cargo.toml
            '') fetchedGitDeps
          );

      # Shell commands to copy git deps into vendor output after cargo vendor
      gitCopyScript =
        if fetchedGitDeps == [ ] then
          ""
        else
          builtins.concatStringsSep "\n" (
            builtins.map (dep: ''
              # Copy ${dep.crate} from builtins.fetchGit into vendor dir
              cp -r "${dep.fetched}" "$out/${dep.crate}"
              chmod -R u+w "$out/${dep.crate}"
              printf '{"files":{},"package":null}' > "$out/${dep.crate}/.cargo-checksum.json"
            '') fetchedGitDeps
          );
    in
    builtins.derivation {
      inherit name system;
      builder = "/bin/sh";
      args = [
        "-c"
        ''
          set -eu
          export PATH="${cargo}/bin:${bootstrapTools}/bin"
          ${if extraLibPaths != [ ] then "export LD_LIBRARY_PATH=\"${ldLibPath}\"" else ""}

          # Extract source into a clean subdirectory so ls -d */ works
          mkdir -p "$TMPDIR/src"
          cd "$TMPDIR/src"
          tar xf "${src}" || cp -r "${src}" source
          cd ${if sourceRoot != null then sourceRoot else "$(ls -d */)"}

          # Set up Cargo home (after extraction so dir doesn't interfere)
          export CARGO_HOME="$TMPDIR/cargo-home"
          mkdir -p "$CARGO_HOME"

          # Apply cargo patches if any
          ${builtins.concatStringsSep "\n" (builtins.map (p: "patch -p1 < ${p}") cargoPatches)}

          ${gitPatchScript}

          # Vendor crates-io dependencies
          cargo vendor ${if fetchedGitDeps == [ ] then "--locked " else ""}"$out"

          ${gitCopyScript}
        ''
      ];

      # Fixed-output derivation attributes
      outputHash = hash;
      outputHashMode = "recursive";
      outputHashAlgo = "sha256";

      preferLocalBuild = true;
    };

  # ---------------------------------------------------------------------------
  # fetchGoModules
  # ---------------------------------------------------------------------------
  # fetchGoModules { go; bootstrapTools; src; hash; sourceRoot?; }
  #
  # Fixed-output derivation that downloads Go module dependencies.
  fetchGoModules =
    {
      go,
      bootstrapTools,
      src,
      hash,
      sourceRoot ? null,
      name ? "go-modules",
      system ? defaultSystem,
    }:
    builtins.derivation {
      inherit name system;
      builder = "/bin/sh";
      args = [
        "-c"
        ''
          set -eu
          export PATH="${go}/bin:${bootstrapTools}/bin"
          export GOPROXY="https://proxy.golang.org,direct"
          export GONOSUMDB="*"
          export GONOSUMCHECK="*"

          # Extract source into a clean subdirectory so ls -d */ works
          mkdir -p "$TMPDIR/src"
          cd "$TMPDIR/src"
          tar xf "${src}" || cp -r "${src}" source
          srcdir="${if sourceRoot != null then sourceRoot else "$(ls -d */ 2>/dev/null | head -1)"}"
          cd "$srcdir"

          # Set up Go environment (after extraction so dirs don't interfere)
          export GOPATH="$TMPDIR/gopath"
          export GOCACHE="$TMPDIR/go-cache"
          mkdir -p "$GOPATH" "$GOCACHE"

          # Download all Go module dependencies
          go mod download -x all

          # Copy downloaded modules to output
          mkdir -p "$out"
          cp -r "$GOPATH"/* "$out/" 2>/dev/null || true
        ''
      ];

      # Fixed-output derivation attributes
      outputHash = hash;
      outputHashMode = "recursive";
      outputHashAlgo = "sha256";

      preferLocalBuild = true;
    };

in
{
  inherit
    mkDerivation
    mkShell
    fetchurl
    fetchgit
    fetchCargoDeps
    fetchGoModules
    fakeHash
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
