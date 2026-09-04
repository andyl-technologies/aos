##! lib/derivations.nix — Clean derivation builder
##!
##! Provides:
##!
##!     mkDerivation   — build a package from source
##!     mkShell        — development shell environment
##!     fetchurl       — fetch a file by URL (fixed-output derivation)
##!     fetchgit       — fetch a Git repository (fixed-output derivation)
##!     fetchCargoDeps   — vendor Cargo dependencies (fixed-output derivation)
##!     fetchCargoVendor — lockfile-driven Cargo vendoring (FOD staging + pure assembly)
##!     fetchGoModules   — download Go module dependencies (fixed-output derivation)
##!     fetchNpmDeps     — materialize node_modules from a lockfile (fixed-output derivation)
##!     fakeHash       — placeholder hash for iterating on FODs
##!     replacePhase   — replace a phase by name
##!     addPhaseAfter  — insert a phase after a named phase
##!     addPhaseBefore — insert a phase before a named phase
##!     removePhase    — remove a phase by name
##!
##! The `system` parameter must be provided by the caller (lib/default.nix)
##! and is used as the default for all derivation builders.
##!
##! The optional `bash` parameter (a derivation) specifies the AOS-built bash
##! to use as the builder for all derivations. When `null` (early bootstrap),
##! `/bin/sh` is used as a fallback.
{
  system,
  bash ? null,
}: let
  defaultSystem = system;

  # When an AOS-built bash is available, use it as the builder for all
  # derivations (FODs, mkDerivation default, mkShell).  Falls back to
  # /bin/sh for early bootstrap stages where bash hasn't been built yet.
  builderPath =
    if bash != null
    then "${bash}/bin/bash"
    else "/bin/sh";

  inherit (import ./trivial.nix) throwIfNot isDerivation;
  inherit
    (import ./platform.nix)
    satisfies
    canRun
    mkPlatform
    platformIsCompatible
    constraintsCompatible
    ;
  hardening = import ./hardening.nix;

  # Attach evaluation-only fixed-output identity without changing the
  # derivation's builder environment or store identity.
  annotateFixedOutput = drv: contract:
    drv
    // {
      passthru =
        (drv.passthru or {})
        // {
          aos =
            ((drv.passthru or {}).aos or {})
            // {
              fixedOutput =
                contract
                // {
                  schema = "aos.fixed-output/v1";
                  outputDerivation = contract.outputDerivation or drv.drvPath;
                };
            };
        };
    };

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

  # Default fixup phase: strip and shrink-rpath. Runs after install in
  # every derivation. Defined here (not imported from stdenv/phases.nix)
  # so lib/ stays self-contained; stdenv/phases.nix has a matching copy
  # used by the Cargo/Go/Bazel phase templates.
  #
  # Key for closure hygiene: `strip --strip-unneeded` on .so files removes
  # DWARF .debug_line tables that embed gcc's include-dir store path, and
  # `strip -s` on executables does the same. Without this, every compiled
  # object drags ~230 MB of gcc into its runtime closure.
  #
  # Deliberately no `patchShebangs`: packages handle their own shebangs
  # during their build phase, and a generic post-install rewriter here
  # would turn harmless `#!/usr/bin/env ...` references into live
  # `/nix/store/<hash>-python3/bin/python3` paths, pulling python/perl/etc.
  # into closures that never needed them.
  fixupPhase = {
    name = "fixup";
    script = ''
      object_format="''${AOS_OBJECT_FORMAT:-elf}"

      if [ -z "''${dontStrip:-}" ]; then
        echo "stripping..."
        for o in ''${AOS_OUTPUT_NAMES:-out}; do
          eval "p=\"\''${$o:-}\""
          [ -d "$p" ] || continue
          find "$p" -type f \( -name '*.so*' -o -name '*.dylib' -o -name '*.dylib.*' \) -exec strip --strip-unneeded {} \; 2>/dev/null || true
          find "$p" -type f -name '*.a' -exec strip -S {} \; 2>/dev/null || true
          for d in bin sbin libexec; do
            if [ -d "$p/$d" ]; then
              find "$p/$d" -type f -exec strip -s {} \; 2>/dev/null || true
            fi
          done
        done
      fi

      if [ "$object_format" = elf ] && [ -z "''${dontPatchELF:-}" ] && command -v patchelf >/dev/null 2>&1; then
        echo "shrinking ELF RPATHs..."
        for o in ''${AOS_OUTPUT_NAMES:-out}; do
          eval "p=\"\''${$o:-}\""
          [ -d "$p" ] || continue
          find "$p" -type f \( -name '*.so*' -o -perm -u+x \) | while read f; do
            patchelf --shrink-rpath "$f" 2>/dev/null || true
          done
        done
      fi

      # Cross builds cannot execute their Darwin outputs. Validate every
      # Mach-O candidate structurally and fail if it has the wrong CPU type.
      if [ "$object_format" = macho ] && [ -z "''${dontValidateMachO:-}" ]; then
        echo "validating Mach-O outputs for ''${AOS_TARGET_PLATFORM:-Darwin}..."
        case "''${AOS_TARGET_ARCH:-}" in
          x86_64) expected_cpu=X86_64 ;;
          arm64) expected_cpu=ARM64 ;;
          *)
            echo "unknown Darwin target architecture: ''${AOS_TARGET_ARCH:-unset}" >&2
            exit 1
            ;;
        esac

        for o in ''${AOS_OUTPUT_NAMES:-out}; do
          eval "p=\"\''${$o:-}\""
          [ -d "$p" ] || continue
          find "$p" -type f \( -name '*.dylib' -o -name '*.dylib.*' -o -name '*.so' -o -perm -u+x \) | while read f; do
            if ! header=$(objdump --macho --private-header "$f" 2>/dev/null); then
              # Scripts and data files may be executable, but an ELF image in
              # a Darwin output is always a host/target splice failure. Do not
              # silently stamp a Linux executable or shared library as Darwin.
              magic=$(od -An -tx1 -N4 "$f" 2>/dev/null | tr -d ' \n')
              if [ "$magic" = 7f454c46 ]; then
                echo "ELF artifact in Darwin output: $f" >&2
                exit 1
              fi
              continue
            fi
            if ! echo "$header" | grep -q "$expected_cpu"; then
              echo "Mach-O architecture mismatch in $f: expected $expected_cpu" >&2
              echo "$header" >&2
              exit 1
            fi
          done
        done
      fi
    '';
  };

  # Preserve the native phase bytes while avoiding grep -q's intentional
  # early pipe close for large Mach-O archives in Darwin cross builds.
  darwinCrossFixupPhase = let
    script =
      builtins.replaceStrings
      [
        "      if ! echo \"$header\" | grep -q \"$expected_cpu\"; then\n        echo \"Mach-O architecture mismatch in $f: expected $expected_cpu\" >&2\n        echo \"$header\" >&2\n        exit 1\n      fi"
      ]
      [
        "      case \"$header\" in\n        *\"$expected_cpu\"*) ;;\n        *)\n          echo \"Mach-O architecture mismatch in $f: expected $expected_cpu\" >&2\n          echo \"$header\" >&2\n          exit 1\n          ;;\n      esac"
      ]
      fixupPhase.script;
  in
    assert script != fixupPhase.script;
      fixupPhase // {inherit script;};

  # Scrub phase: rewrite build-time /nix/store/<hash>- references inside
  # the output so the Nix reference scanner doesn't pull build-only
  # toolchain paths into the runtime closure. Runs after fixup for every
  # derivation; appended unconditionally so cargo/go/bazel phase
  # templates (which bundle their own fixup) also get scrubbed.
  #
  # Preserves references to declared outputs, runtimeDeps, propagatedDeps,
  # and per-package `nukeRefsKeep`. Set `dontNukeRefs = true` on the
  # caller to skip (e.g. for nuke-references itself).
  scrubPhase = {
    name = "scrub";
    script = ''
      if [ -n "''${dontNukeRefs:-}" ]; then
        echo "scrub: skipped (dontNukeRefs set)"
      elif ! command -v nuke-refs >/dev/null 2>&1; then
        echo "scrub: nuke-refs not on PATH, skipping" >&2
      else
        echo "scrubbing build-time refs..."

        # Build the -e keep list: every declared output, every runtime /
        # propagated dep, plus the per-package extension `nukeRefsKeep`.
        # The env vars are nixpkgs-style ($buildInputs = runtimeDeps,
        # $propagatedBuildInputs = propagatedDeps).
        keep_args=""
        for o in ''${AOS_OUTPUT_NAMES:-out}; do
          eval "p=\"\''${$o:-}\""
          [ -n "$p" ] && keep_args="$keep_args -e $p"
        done
        for p in ''${buildInputs:-} ''${propagatedBuildInputs:-} ''${nukeRefsKeep:-}; do
          [ -n "$p" ] && keep_args="$keep_args -e $p"
        done

        # Default target set: every executable, every shared lib, every
        # pkgconfig/.la/Makefile/sysconfig file. These are the locations
        # autotools/python embed build-tool paths into. Python's
        # __pycache__ is included because import compiles _sysconfigdata
        # to .pyc at install time, baking the build-time toolchain refs
        # into a binary blob that the .py-only pattern would miss.
        for o in ''${AOS_OUTPUT_NAMES:-out}; do
          eval "p=\"\''${$o:-}\""
          [ -d "$p" ] || continue
          find "$p" \( \
               -path "*/bin/*" -o -path "*/sbin/*" -o -path "*/libexec/*" \
            -o -name "*.so" -o -name "*.so.*" \
            -o -name "*.dylib" -o -name "*.dylib.*" \
            -o -name "*.pc"  -o -name "*.la" \
            -o -name "Makefile" \
            -o -name "_sysconfigdata*.py"  -o -name "_sysconfigdata*.pyc" \
            -o -name "_sysconfig_vars*.json" \
            \) -type f -print0 \
          | xargs -0 -r nuke-refs $keep_args
        done
      fi
    '';
  };

  # Record the platform of the produced artifacts independently from the Nix
  # scheduler system. APR and cache publication consume this marker rather
  # than mistaking a Linux-hosted cross build for a Linux package. Ordinary
  # package outputs are directories. File and symlink outputs are helper
  # artifacts with no directory in which the nix-support contract can live.
  targetPlatformMetadataPhase = outputSystem: {
    name = "target-platform-metadata";
    script = ''
      for o in ''${AOS_OUTPUT_NAMES:-out}; do
        eval "p=\"\''${$o:-}\""
        [ -n "$p" ] || continue
        if [ -d "$p" ] && [ ! -L "$p" ]; then
          mkdir -p "$p/nix-support"
          printf '%s\n' '${outputSystem}' > "$p/nix-support/aos-target-platform"
        else
          echo "target-platform-metadata: $o is not a directory output; marker omitted" >&2
        fi
      done
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
  replacePhase = phases: name: newPhase: let
    found = builtins.any (p: p.name == name) phases;
  in
    if !found
    then throw "replacePhase: phase '${name}' not found in phases list"
    else
      builtins.map (p:
        if p.name == name
        then newPhase
        else p)
      phases;

  ## Insert a new phase after the named phase.
  ## # Type
  ## `[phase] -> string -> phase -> [phase]`
  addPhaseAfter = phases: afterName: newPhase: let
    found = builtins.any (p: p.name == afterName) phases;
  in
    if !found
    then throw "addPhaseAfter: phase '${afterName}' not found in phases list"
    else
      builtins.concatLists (
        builtins.map (
          p:
            if p.name == afterName
            then [
              p
              newPhase
            ]
            else [p]
        )
        phases
      );

  ## Insert a new phase before the named phase.
  ## # Type
  ## `[phase] -> string -> phase -> [phase]`
  addPhaseBefore = phases: beforeName: newPhase: let
    found = builtins.any (p: p.name == beforeName) phases;
  in
    if !found
    then throw "addPhaseBefore: phase '${beforeName}' not found in phases list"
    else
      builtins.concatLists (
        builtins.map (
          p:
            if p.name == beforeName
            then [
              newPhase
              p
            ]
            else [p]
        )
        phases
      );

  ## Remove a phase by name.
  ## # Type
  ## `[phase] -> string -> [phase]`
  removePhase = phases: name: builtins.filter (p: p.name != name) phases;

  # ---------------------------------------------------------------------------
  # Derivation path helpers
  # ---------------------------------------------------------------------------

  ## Return a named output of a derivation. Falls back to the derivation
  ## itself (its default output) when the named output doesn't exist —
  ## lets call sites express intent without forcing every package to
  ## split outputs.
  ## # Type
  ## `string -> derivation -> derivation`
  getOutput = name: drv:
    assert isDerivation drv;
      drv.${name} or drv;

  ## Return the "bin" output of a derivation, or the default output if
  ## no `bin` output is declared.
  ## # Type
  ## `derivation -> derivation`
  getBin = drv: getOutput "bin" drv;

  ## Return the "dev" output of a derivation, or the default output if
  ## no `dev` output is declared.
  ## # Type
  ## `derivation -> derivation`
  getDev = drv: getOutput "dev" drv;

  ## Return the absolute path of a named binary inside a derivation. Use
  ## when you want a specific tool rather than the "main" one.
  ## # Type
  ## `derivation -> string -> string`
  getExe' = drv: binName:
    assert isDerivation drv;
    assert builtins.isString binName; "${getBin drv}/bin/${binName}";

  ## Return the absolute path of a derivation's main binary. Reads
  ## `meta.mainProgram` first, then falls back to `pname`. Throws with a
  ## clear message if neither is set, suggesting how to fix the call site.
  ## # Type
  ## `derivation -> string`
  getExe = drv:
    getExe' drv (
      drv.meta.mainProgram
      or drv.pname
      or (
        throw "lib.getExe: ${drv.name or "unnamed derivation"} has no meta.mainProgram or pname; set meta.mainProgram on the derivation, or use lib.getExe' with an explicit binary name"
      )
    );

  # ---------------------------------------------------------------------------
  # Internal: generate the build script from a list of phases
  # ---------------------------------------------------------------------------
  phasesToScript = phases: shell: let
    phaseScripts =
      builtins.map (phase: ''
        echo ">>> Phase: ${phase.name}"
        ${phase.script}
        echo "<<< Phase: ${phase.name} complete"
      '')
      phases;
  in ''
    #!${shell}
    set -eu
    set -o pipefail 2>/dev/null || true

    # Restore env-var attrs when running with __structuredAttrs = true.
    # Idempotent: when NIX_ATTRS_SH_FILE isn't set (the default), this
    # is a no-op.
    #
    # Under __structuredAttrs Nix exposes `outputs` as a bash associative
    # array (declare -A outputs=([out]=/nix/store/… [dev]=/nix/store/…))
    # but does NOT set each output name as a scalar. Re-declare them so
    # phase scripts that reference $out / $dev / etc. keep working.
    if [ -n "''${NIX_ATTRS_SH_FILE:-}" ]; then
      . "$NIX_ATTRS_SH_FILE"
      if declare -p outputs 2>/dev/null | grep -q 'declare -A'; then
        AOS_OUTPUT_NAMES="''${!outputs[*]}"
        for __o in "''${!outputs[@]}"; do
          declare -g "$__o=''${outputs[$__o]}"
        done
        unset __o
      else
        AOS_OUTPUT_NAMES="''${outputs:-out}"
      fi
    else
      AOS_OUTPUT_NAMES="''${outputs:-out}"
    fi
    export AOS_OUTPUT_NAMES

    # Source the stdenv setup if available
    if [ -n "''${stdenv:-}" ] && [ -f "$stdenv/setup.sh" ]; then
      source "$stdenv/setup.sh"
    fi

    ${builtins.concatStringsSep "\n" phaseScripts}
  '';

  # ---------------------------------------------------------------------------
  # Internal: build the PATH from dependency lists
  # ---------------------------------------------------------------------------
  makePath = deps:
    builtins.concatStringsSep ":" (
      builtins.concatLists (
        builtins.map (
          d: let
            p = builtins.toString d;
          in [
            "${p}/bin"
            "${p}/sbin"
          ]
        )
        deps
      )
    );

  makeLibPath = deps: builtins.concatStringsSep ":" (builtins.map (d: "${builtins.toString d}/lib") deps);

  makeIncPath = deps: builtins.concatStringsSep ":" (builtins.map (d: "${builtins.toString d}/include") deps);

  makeRpathFlags = deps:
    builtins.concatStringsSep " " (
      builtins.map (
        d: "-Wl,-rpath,${builtins.toString d}/lib -Wl,-rpath-link,${builtins.toString d}/lib"
      )
      deps
    );

  # ---------------------------------------------------------------------------
  # Internal: collect transitive propagated deps
  # ---------------------------------------------------------------------------
  # Given a list of direct deps, recursively collects their propagatedDeps
  # so that PKG_CONFIG_PATH, C_INCLUDE_PATH, etc. include transitive deps.
  collectPropagated = deps: seen: let
    newPropagated = builtins.concatLists (builtins.map (d: d.propagatedDeps or []) deps);
    unseen = builtins.filter (d: !(builtins.elem d seen)) newPropagated;
  in
    if unseen == []
    then seen
    else collectPropagated unseen (seen ++ unseen);

  # ---------------------------------------------------------------------------
  # Internal: extract constraints from any dep shape
  # ---------------------------------------------------------------------------
  # Handles mkDerivation results (.constraints), tier packages (.meta), and
  # bare derivations (no data → null, skip validation).
  getDepConstraints = dep:
    if dep ? constraints
    then {
      execute = dep.constraints.execute;
      target = dep.constraints.target;
    }
    else if dep ? meta
    then {
      execute = dep.meta.execute or null;
      target = dep.meta.target or null;
    }
    else {
      execute = null;
      target = null;
    };

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
  #   update;          — primitive maintenance metadata (evaluation only)
  #   storeDir;        — store directory (default: /nix/store)
  #   hostPlatform;    — structured platform where the output executes
  #   targetPlatform;  — structured code-generation target
  #   hostSystem;      — system where the output executes
  #   buildExecutionSystem; — system where build dependencies execute
  #   ...              — additional attributes passed to builtins.derivation
  # }
  mkDerivation = args @ {
    pname ? null,
    version ? "0",
    src ? null,
    buildDeps ? [],
    runtimeDeps ? [],
    propagatedDeps ? [],
    phases ? defaultPhases,
    meta ? {},
    storeDir ? "/nix/store",
    system ? defaultSystem,
    hostPlatform ? null,
    targetPlatform ? null,
    hostSystem ? null,
    buildExecutionSystem ? null,
    shell ? builderPath,
    outputs ? ["out"],
    configureFlags ? "",
    makeFlags ? "",
    installFlags ? "",
    cmakeFlags ? "",
    mesonFlags ? "",
    patches ? [],
    postPatch ? "",
    preConfigure ? "",
    postConfigure ? "",
    preBuild ? "",
    postBuild ? "",
    preInstall ? "",
    postInstall ? "",
    passthru ? {},
    update ? null,
    checks ? null,
    expose ? null,
    # ── Compiler-hardening policy ─────────────────────────────────────
    # Per-package opt-in / opt-out over the central token set. The
    # effective set is (defaultHardeningFlags ++ hardeningEnable) minus
    # hardeningDisable, with implication and platform-filtering rules from
    # lib/hardening.nix, exported to the builder as AOS_HARDENING_ENABLE
    # and consumed by the cc-wrapper. `hardeningDisable = [ "all" ]` clears
    # every token; unknown tokens are evaluation errors. defaultHardeningFlags
    # is supplied by the stdenv and is normally not set per package.
    hardeningEnable ? [],
    hardeningDisable ? [],
    defaultHardeningFlags ? [],
    # ── Reference-control attrs (Nix-enforced at build time) ──────────
    # Pass-through to `builtins.derivation`. If set, Nix fails the build
    # if the output's closure (or direct references) breaks the rule.
    # Use to lock in Phase 2 closure-bloat wins: once a package builds
    # clean, setting `allowedRequisites = [...]` to the expected list
    # catches any future regression at build time rather than at initrd-
    # size review.
    #
    #   allowedRequisites    — whitelist (null = unconstrained). Every
    #                          path in the closure must appear here.
    #   allowedReferences    — whitelist for *direct* references only.
    #   disallowedRequisites — blacklist for closure (any path in this
    #                          list appearing anywhere in the closure
    #                          fails the build).
    #   disallowedReferences — blacklist for direct references only.
    #
    # Typical rollout: flip on a canary package (e.g. pkgs.bash) with a
    # minimal allowedRequisites of glibc/gcc/linux-headers/etc.; once it
    # builds, promote the attr through the package set. Only set on the
    # derivations you've actually audited — leaving these null means
    # "no change from historical behavior."
    allowedRequisites ? null,
    allowedReferences ? null,
    disallowedRequisites ? [],
    disallowedReferences ? [],
    # Per-output reference checks. When set, the derivation runs with
    # __structuredAttrs = true so Nix honors outputChecks.<out>.disallowed*
    # / allowed* on a per-output basis. Example:
    #   outputChecks = { out = { disallowedReferences = [ gcc ]; }; };
    # When null (default), behaves identically to historical mkDerivation.
    outputChecks ? null,
    ...
  }: let
    useStructuredAttrs = outputChecks != null;
    # Accept either `name` (direct) or `pname` (computed as pname-version).
    name =
      args.name
      or (
        if pname != null
        then "${pname}-${version}"
        else throw "mkDerivation: either 'pname' or 'name' must be provided"
      );
    effectivePname =
      if pname != null
      then pname
      else name;

    # Collect all dependencies for PATH, including transitive propagated deps.
    # e.g. if dbus depends on libselinux and libselinux propagates pcre2,
    # then pcre2 will be on dbus's PKG_CONFIG_PATH automatically.
    directDeps = buildDeps ++ runtimeDeps ++ propagatedDeps;
    allBuildDeps = collectPropagated directDeps directDeps;
    nativeBuildClosure = collectPropagated buildDeps buildDeps;

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
      if patches != [] || postPatch != ""
      then addPhaseAfter phases "unpack" patchPhase
      else phases;

    # Inject pre/post hooks into phases
    finalPhases =
      builtins.map (
        phase:
          if phase.name == "configure" && (preConfigure != "" || postConfigure != "")
          then phase // {script = preConfigure + "\n" + phase.script + "\n" + postConfigure;}
          else if phase.name == "build" && (preBuild != "" || postBuild != "")
          then phase // {script = preBuild + "\n" + phase.script + "\n" + postBuild;}
          else if phase.name == "install" && (preInstall != "" || postInstall != "")
          then phase // {script = preInstall + "\n" + phase.script + "\n" + postInstall;}
          else phase
      )
      effectivePhases;

    # Append the fixup phase (strip + shrink-rpath) defined above. The
    # fixup must run after install for every derivation; without it,
    # debug sections embed gcc store paths that drag the ~230 MB compiler
    # into every package's closure. Skip if the caller already supplied
    # a fixup — the cargo/go/bazel phase templates bundle their own.
    #
    # scrubPhase always runs last, regardless of whether the caller
    # supplied a custom fixup. Inlining it into fixup would skip it
    # whenever cargo/go/bazel templates override the fixup phase.
    defaultFixupPhase =
      if
        buildPlatform.system
        != outputPlatform.system
        && outputPlatform.objectFormat == "macho"
      then darwinCrossFixupPhase
      else fixupPhase;

    allPhases =
      (
        if builtins.any (p: p.name == "fixup") finalPhases
        then finalPhases
        else finalPhases ++ [defaultFixupPhase]
      )
      ++ [
        scrubPhase
        (targetPlatformMetadataPhase outputPlatform.system)
      ];

    builder = phasesToScript allPhases shell;

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
      "hostPlatform"
      "targetPlatform"
      "hostSystem"
      "buildExecutionSystem"
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
      "update"
      "checks"
      "expose"
      "hardeningEnable"
      "hardeningDisable"
      "defaultHardeningFlags"
      "allowedRequisites"
      "allowedReferences"
      "disallowedRequisites"
      "disallowedReferences"
      "outputChecks"
    ];

    # ── Chaining constraint validation ────────────────────────────────
    schedulingPlatform = mkPlatform system;
    buildPlatform = mkPlatform (
      if buildExecutionSystem != null
      then buildExecutionSystem
      else system
    );
    selectedOutputPlatform =
      if hostPlatform != null
      then hostPlatform
      else if hostSystem != null
      then mkPlatform hostSystem
      else buildPlatform;
    # Toolchain bootstrap records may override `.system` to the physical Nix
    # scheduler while retaining the real output identity in constraints. The
    # derivation-facing record always restores the canonical output system.
    outputPlatform =
      selectedOutputPlatform
      // {
        system = "${selectedOutputPlatform.constraints.cpu}-${selectedOutputPlatform.constraints.os}";
      };
    selectedCodeTargetPlatform =
      if targetPlatform != null
      then targetPlatform
      else if meta ? target && meta.target ? cpu && meta.target ? os
      then mkPlatform "${meta.target.cpu}-${meta.target.os}"
      else outputPlatform;
    codeTargetPlatform =
      selectedCodeTargetPlatform
      // {
        system = "${selectedCodeTargetPlatform.constraints.cpu}-${selectedCodeTargetPlatform.constraints.os}";
      };
    derivationPlatforms = {
      build = buildPlatform;
      host = outputPlatform;
      target = codeTargetPlatform;
    };

    # Effective compiler-hardening token set, exported to the builder for
    # the cc-wrapper to translate into flags. Tokens are filtered for the
    # platform where the output runs, which differs from the build platform
    # during cross-compilation.
    hardeningEnableStr = hardening.effectiveString {
      inherit name hardeningEnable hardeningDisable;
      defaultFlags = defaultHardeningFlags;
      platform = outputPlatform;
    };

    # Concrete execution identity for this derivation. `meta.execute` remains
    # an eligibility constraint; it must not erase the CPU or ABI of the
    # particular output being produced.
    ourExecute = outputPlatform.constraints;

    # Rule 1: every buildDep must execute in the logical build environment or
    # on the physical scheduler. Cross transitions use both: target-native
    # tools run through binfmt while bootstrap helpers remain scheduler-native.
    validateDepExecute = dep: let
      dc = getDepConstraints dep;
      depName = dep.name or dep.pname or "(unknown)";
    in
      dc.execute
      == null
      || throwIfNot (canRun buildPlatform dc.execute || canRun schedulingPlatform dc.execute)
      "mkDerivation (${name}): build dep '${depName}' cannot execute on ${buildPlatform.system} or scheduler ${system}"
      true;

    # Rule 2: an explicitly identified compiler/code-generator must target
    # either build-machine programs or the requested code-generation platform.
    # Canadian-cross builds legitimately carry both roles in buildDeps.
    validateDepTarget = dep: let
      dc = getDepConstraints dep;
      depName = dep.name or dep.pname or "(unknown)";
    in
      dc.target
      == null
      || throwIfNot (
        constraintsCompatible dc.target codeTargetPlatform.constraints
        || constraintsCompatible dc.target buildPlatform.constraints
        || constraintsCompatible dc.target schedulingPlatform.constraints
      )
      "mkDerivation (${name}): toolchain '${depName}' targets incompatible platform"
      true;

    chainingOk =
      builtins.all validateDepExecute nativeBuildClosure
      && builtins.all validateDepTarget allBuildDeps;

    # Platform compatibility check: supports new-style structured constraints
    # (meta.build / meta.execute) and old-style meta.platforms string lists.
    platformOk =
      # New-style BUILD and EXECUTE constraints are independent and both apply
      # when a package declares both. The old string list remains an additional
      # compatibility boundary during migration.
      (!(meta ? build) || canRun buildPlatform meta.build || canRun schedulingPlatform meta.build)
      && (!(meta ? execute) || satisfies outputPlatform meta.execute)
      && (
        !(meta ? platforms)
        || platformIsCompatible
        "${outputPlatform.constraints.cpu}-${outputPlatform.constraints.os}"
        meta.platforms
      );

    drv = throwIfNot platformOk "${name} is not supported on ${outputPlatform.constraints.cpu}-${outputPlatform.constraints.os}" (
      throwIfNot chainingOk "${name}: dependency constraint validation failed" (
        builtins.derivation (
          {
            inherit name system;
            builder = shell;
            args = [
              "-c"
              builder
            ];
            inherit outputs;

            # Source
            src =
              if src != null
              then src
              else "";

            # Environment variables for the build
            # Only native build dependencies contribute executables and loader
            # libraries. Host runtime dependencies may contain Darwin binaries
            # or Mach-O libraries that a Linux builder cannot load.
            PATH = makePath nativeBuildClosure;

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
            LD_LIBRARY_PATH = makeLibPath nativeBuildClosure;

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

            # Effective hardening tokens for the cc-wrapper. Always set (even
            # to "") so a build that opts out via hardeningDisable = [ "all" ]
            # is distinguishable from a non-build environment, where the
            # wrapper falls back to its baked-in default policy.
            AOS_HARDENING_ENABLE = hardeningEnableStr;
          }
          # Reference-control blacklists. Empty list = no constraint, so
          # unconditional inclusion is safe. Under __structuredAttrs the
          # top-level disallowed* attrs are inert and trigger a Nix
          # warning; per-output equivalents live in `outputChecks`.
          // (
            if !useStructuredAttrs
            then {inherit disallowedRequisites disallowedReferences;}
            else {}
          )
          # Reference-control whitelists. `null` = unconstrained; we only
          # forward them to builtins.derivation when actually set, so the
          # default path is a no-op (preserves historical behavior for any
          # unaudited derivation).
          // (
            if allowedRequisites != null && !useStructuredAttrs
            then {inherit allowedRequisites;}
            else {}
          )
          // (
            if allowedReferences != null && !useStructuredAttrs
            then {inherit allowedReferences;}
            else {}
          )
          # Per-output reference checks require __structuredAttrs = true.
          // (
            if useStructuredAttrs
            then {
              __structuredAttrs = true;
              inherit outputChecks;
            }
            else {}
          )
          // extraArgs
        )
      )
    );

    # Named outputs are fresh derivation attrsets. Preserve the package-level
    # dependency and execution contract when consumers select one directly.
    outputMetadata = {
      inherit meta version runtimeDeps propagatedDeps;
      pname = effectivePname;
      platforms = derivationPlatforms;
      constraints = {
        build = buildPlatform.constraints;
        execute = ourExecute;
        target =
          if meta ? target
          then codeTargetPlatform.constraints
          else null;
      };
    };
    annotatedOutputs = builtins.listToAttrs (
      builtins.map (output: {
        name = output;
        value = drv.${output} // outputMetadata;
      })
      outputs
    );

    # Attach metadata and override mechanism
    result =
      drv
      // annotatedOutputs
      // outputMetadata
      // {
        # Override mechanism
        override = overrideArgs:
          if builtins.isFunction overrideArgs
          then mkDerivation (overrideArgs args)
          else mkDerivation (args // overrideArgs);

        # overrideAttrs for modifying the derivation attributes
        overrideAttrs = f: mkDerivation (args // (f args));

        # passthru attributes (available without building the derivation)
        passthru =
          passthru
          // {
            inherit phases;
            platforms = derivationPlatforms;
          }
          // (
            if expose != null
            then {inherit expose;}
            else {}
          )
          // (
            if update != null
            then {
              aos = (passthru.aos or {}) // {maintenance = update;};
            }
            else {}
          );
      }
      // (
        if expose != null
        then {inherit expose;}
        else {}
      )
      // (
        if checks != null
        then {inherit checks;}
        else {}
      );
  in
    result;

  # ---------------------------------------------------------------------------
  # mkShell
  # ---------------------------------------------------------------------------
  # mkShell { buildDeps; runtimeDeps; shellHook; ... }
  #
  # Creates a development shell environment. Not meant to produce an installable
  # package; just sets up the environment for interactive development.
  mkShell = args @ {
    buildDeps ? [],
    runtimeDeps ? [],
    shellHook ? "",
    name ? "aos-dev-shell",
    system ? defaultSystem,
    shell ? builderPath,
    ...
  }: let
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
  fetchurl = {
    url ? "",
    urls ? [],
    hash ? "",
    sha256 ? hash,
    name ?
      builtins.baseNameOf (
        if url != ""
        then url
        else builtins.head urls
      ),
    executable ? false,
    system ? defaultSystem,
    storeDir ? "/nix/store",
  }: let
    resolvedUrls =
      if urls != [] && url == ""
      then urls
      else if urls == [] && url != ""
      then [url]
      else throw "fetchurl requires either 'url' or 'urls' to be set, not both";
    drv = builtins.derivation {
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
    };
  in
    (annotateFixedOutput drv {
      kind = "url";
      hashMode = "flat";
      sourceInputs = resolvedUrls;
      builderParameters = {inherit executable system;};
    })
    // {urls = resolvedUrls;};

  # ---------------------------------------------------------------------------
  # fetchgit
  # ---------------------------------------------------------------------------
  # fetchgit { url; rev; hash; }
  #
  # Fixed-output derivation that clones a Git repository at a specific revision.
  fetchgit = {
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
  }: let
    drv = builtins.derivation {
      inherit name system;
      builder = builderPath;
      args = [
        "-c"
        ''
          set -euo pipefail
          export PATH="${storeDir}/git-minimal/bin:$PATH"
          export GIT_SSL_CAINFO="${storeDir}/cacert/etc/ssl/certs/ca-bundle.crt"

          git clone ${
            if deepClone
            then ""
            else "--depth 1"
          } \
            ${
            if fetchSubmodules
            then "--recurse-submodules"
            else ""
          } \
            "${url}" "$out"

          cd "$out"
          git checkout "${rev}"
          ${
            if fetchSubmodules
            then "git submodule update --init --recursive"
            else ""
          }
          ${
            if !leaveDotGit
            then "rm -rf .git"
            else ""
          }
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
    annotateFixedOutput drv {
      kind = "git";
      hashMode = "recursive";
      sourceInputs = [url];
      builderParameters = {
        inherit rev fetchSubmodules deepClone leaveDotGit system;
      };
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
  # gitDeps: list of { url, rev, crate, sourceArchive? } for git-sourced crates.
  #   A pinned fixed-output sourceArchive keeps restricted evaluation
  #   network-free. Entries without one retain the builtins.fetchGit fallback.
  fetchCargoDeps = {
    cargo,
    bootstrapTools,
    src,
    hash,
    sourceRoot ? null,
    cargoPatches ? [],
    extraLibPaths ? [],
    extraPaths ? [],
    gitDeps ? [],
    name ? "cargo-deps",
    system ? defaultSystem,
  }: let
    ldLibPath = builtins.concatStringsSep ":" (
      builtins.map (d: "${builtins.toString d}/lib") extraLibPaths
    );

    # Resolve each Git dependency to a fixed-output archive or a pure fetchGit
    # store path before the vendoring derivation runs.
    fetchedGitDeps =
      builtins.map (
        dep:
          dep
          // {
            fetched =
              if dep ? sourceArchive
              then dep.sourceArchive
              else
                builtins.fetchGit {
                  inherit (dep) url rev;
                };
          }
      )
      gitDeps;

    gitPrepareScript = builtins.concatStringsSep "\n" (
      builtins.map (dep:
        if dep ? sourceArchive
        then ''
          mkdir -p "$TMPDIR/git-deps/${dep.crate}"
          tar xf "${dep.fetched}" --strip-components=1 -C "$TMPDIR/git-deps/${dep.crate}"
        ''
        else "")
      fetchedGitDeps
    );

    # Shell commands to patch Cargo.toml so cargo vendor ignores git deps,
    # then copy git deps into the vendor output with .cargo-checksum.json
    gitPatchScript =
      if fetchedGitDeps == []
      then ""
      else
        builtins.concatStringsSep "\n" (
          [
            ''
              # Patch Cargo.toml to replace git deps with path deps (so cargo vendor succeeds)
              printf '\n' >> Cargo.toml
            ''
          ]
          ++ builtins.map (dep: let
            sourcePath =
              if dep ? sourceArchive
              then "$TMPDIR/git-deps/${dep.crate}"
              else builtins.toString dep.fetched;
          in ''
            printf '[patch."${dep.url}"]\n${dep.crate} = { path = "%s" }\n' "${sourcePath}" >> Cargo.toml
          '')
          fetchedGitDeps
        );

    # Shell commands to copy git deps into vendor output after cargo vendor
    gitCopyScript =
      if fetchedGitDeps == []
      then ""
      else
        builtins.concatStringsSep "\n" (
          builtins.map (dep:
            if dep ? sourceArchive
            then ''
              # Copy the prepared fixed-output source into the vendor tree.
              rm -rf "$out/${dep.crate}"
              cp -r "$TMPDIR/git-deps/${dep.crate}" "$out/${dep.crate}"
              chmod -R u+w "$out/${dep.crate}"
              printf '{"files":{},"package":null}' > "$out/${dep.crate}/.cargo-checksum.json"
            ''
            else ''
              # Copy ${dep.crate} from builtins.fetchGit into vendor dir.
              cp -r "${dep.fetched}" "$out/${dep.crate}"
              chmod -R u+w "$out/${dep.crate}"
              printf '{"files":{},"package":null}' > "$out/${dep.crate}/.cargo-checksum.json"
            '')
          fetchedGitDeps
        );
  in
    annotateFixedOutput (builtins.derivation {
      inherit name system;
      builder = builderPath;
      args = [
        "-c"
        ''
          set -eu
          export PATH="${cargo}/bin:${bootstrapTools}/bin${builtins.concatStringsSep "" (builtins.map (p: ":${builtins.toString p}/bin") extraPaths)}"
          ${
            if extraLibPaths != []
            then "export LD_LIBRARY_PATH=\"${ldLibPath}\""
            else ""
          }

          # Extract source into a clean subdirectory so ls -d */ works
          mkdir -p "$TMPDIR/src"
          cd "$TMPDIR/src"
          if [ -d "${src}" ]; then
            cp -r "${src}" source
          else
            tar xf "${src}"
          fi
          cd ${
            if sourceRoot != null
            then sourceRoot
            else "$(ls -d */)"
          }

          # Set up Cargo home (after extraction so dir doesn't interfere)
          export CARGO_HOME="$TMPDIR/cargo-home"
          mkdir -p "$CARGO_HOME"

          # Apply cargo patches if any
          ${builtins.concatStringsSep "\n" (builtins.map (p: "patch -p1 < ${p}") cargoPatches)}

          ${gitPrepareScript}

          ${gitPatchScript}

          # Vendor crates-io dependencies
          cargo vendor ${
            if fetchedGitDeps == []
            then "--locked "
            else ""
          }"$out"

          ${gitCopyScript}
        ''
      ];

      # Fixed-output derivation attributes
      outputHash = hash;
      outputHashMode = "recursive";
      outputHashAlgo = "sha256";

      preferLocalBuild = true;
    }) {
      kind = "cargo-deps";
      hashMode = "recursive";
      sourceInputs = [builtins.toString src];
      builderParameters = {
        sourceRoot =
          if sourceRoot == null
          then "<auto>"
          else sourceRoot;
        patches = builtins.map builtins.toString cargoPatches;
        gitDependencies =
          builtins.map (dep: {
            inherit (dep) url rev crate;
            sourceArchive =
              if dep ? sourceArchive
              then builtins.toString dep.sourceArchive
              else "<builtins.fetchGit>";
          })
          gitDeps;
        cargo = builtins.toString cargo;
        inherit system;
      };
    };

  # ---------------------------------------------------------------------------
  # fetchCargoVendor
  # ---------------------------------------------------------------------------
  # fetchCargoVendor { cargo; python3; git; caCertificates; bootstrapTools;
  #                    src; hash; sourceRoot?; cargoPatches?; }
  #
  # Lockfile-driven Cargo vendoring (ported from nixpkgs's fetchCargoVendor /
  # fetch-cargo-vendor-util-v2 design). Two stages:
  #
  #   1. vendorStaging (FOD, content-hashed): reads Cargo.lock and downloads
  #      every crates.io tarball + clones every git source at its exact sha.
  #      Output layout: { Cargo.lock, tarballs/<crate>-<ver>.tar.gz,
  #                       git/<sha>/<repo contents> }.
  #
  #   2. final vendor (regular derivation): walks the lockfile again, locates
  #      each git-sourced crate inside its tree by running `cargo metadata`
  #      to match crate name, copies the crate's subtree, resolves workspace
  #      inheritance via replace-workspace-values.py, and writes
  #      .cargo/config.toml with @vendor@ placeholders.
  #
  # The build-time consumer (cargoPhases) substitutes @vendor@ with the
  # absolute store path before invoking cargo.
  #
  # Unlike fetchCargoDeps, no manual gitDeps list is needed — git sources
  # (including monorepo crates) are discovered from Cargo.lock automatically.
  fetchCargoVendor = {
    cargo,
    python3,
    git,
    caCertificates,
    bootstrapTools,
    src,
    hash,
    sourceRoot ? null,
    cargoPatches ? [],
    extraLibPaths ? [],
    extraPaths ? [],
    name ? "cargo-vendor",
    system ? defaultSystem,
  }: let
    utilDir = ./cargo-vendor;
    ldLibPath = builtins.concatStringsSep ":" (
      builtins.map (d: "${builtins.toString d}/lib") extraLibPaths
    );

    # Stage 1: fetch all crates.io tarballs and clone all git sources.
    vendorStaging = builtins.derivation {
      name = "${name}-staging";
      inherit system;
      builder = builderPath;
      args = [
        "-c"
        ''
          set -euo pipefail
          export PATH="${cargo}/bin:${python3}/bin:${git}/bin:${bootstrapTools}/bin${builtins.concatStringsSep "" (builtins.map (p: ":${builtins.toString p}/bin") extraPaths)}"
          export GIT_SSL_CAINFO="${caCertificates}/etc/ssl/certs/ca-certificates.crt"
          export SSL_CERT_FILE="$GIT_SSL_CAINFO"
          ${
            if extraLibPaths != []
            then "export LD_LIBRARY_PATH=\"${ldLibPath}\""
            else ""
          }

          mkdir -p "$TMPDIR/src"
          cd "$TMPDIR/src"
          if [ -d "${src}" ]; then
            cp -r "${src}" source
          else
            tar xf "${src}"
          fi
          cd ${
            if sourceRoot != null
            then sourceRoot
            else "$(ls -d */)"
          }

          ${builtins.concatStringsSep "\n" (builtins.map (p: "patch -p1 < ${p}") cargoPatches)}

          python3 ${utilDir}/fetch-cargo-vendor-util.py \
            create-vendor-staging Cargo.lock "$out"
        ''
      ];

      outputHash = hash;
      outputHashMode = "recursive";
      outputHashAlgo = "sha256";

      preferLocalBuild = true;
    };
  in
    # Stage 2: pure transformation of staging into cargo vendor layout.
    annotateFixedOutput (builtins.derivation {
      inherit name system;
      builder = builderPath;
      args = [
        "-c"
        ''
          set -euo pipefail
          export PATH="${cargo}/bin:${python3}/bin:${bootstrapTools}/bin${builtins.concatStringsSep "" (builtins.map (p: ":${builtins.toString p}/bin") extraPaths)}"
          python3 ${utilDir}/fetch-cargo-vendor-util.py \
            create-vendor "${vendorStaging}" "$out"
        ''
      ];

      preferLocalBuild = true;
    }) {
      kind = "cargo-vendor";
      hashMode = "recursive";
      sourceInputs = [builtins.toString src];
      outputDerivation = vendorStaging.drvPath;
      builderParameters = {
        sourceRoot =
          if sourceRoot == null
          then "<auto>"
          else sourceRoot;
        patches = builtins.map builtins.toString cargoPatches;
        cargo = builtins.toString cargo;
        inherit system;
      };
    };

  # ---------------------------------------------------------------------------
  # fetchGoModules
  # ---------------------------------------------------------------------------
  # fetchGoModules { go; bootstrapTools; src; hash; sourceRoot?; }
  #
  # Fixed-output derivation that downloads Go module dependencies.
  fetchGoModules = {
    go,
    bootstrapTools,
    src,
    hash,
    sourceRoot ? null,
    name ? "go-modules",
    system ? defaultSystem,
    extraPaths ? [],
  }:
    annotateFixedOutput (builtins.derivation {
      inherit name system;
      builder = builderPath;
      args = [
        "-c"
        ''
          set -eu
          export PATH="${go}/bin:${bootstrapTools}/bin${builtins.concatStringsSep "" (builtins.map (p: ":${p}/bin") extraPaths)}"
          export GOPROXY="https://proxy.golang.org,direct"
          export GONOSUMDB="*"
          export GONOSUMCHECK="*"

          # Extract source into a clean subdirectory so ls -d */ works
          mkdir -p "$TMPDIR/src"
          cd "$TMPDIR/src"
          tar xf "${src}" || cp -r "${src}" source
          srcdir="${
            if sourceRoot != null
            then sourceRoot
            else "$(ls -d */ 2>/dev/null | head -1)"
          }"
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
    }) {
      kind = "go-modules";
      hashMode = "recursive";
      sourceInputs = [builtins.toString src];
      builderParameters = {
        sourceRoot =
          if sourceRoot == null
          then "<auto>"
          else sourceRoot;
        go = builtins.toString go;
        inherit system;
      };
    };

  # ---------------------------------------------------------------------------
  # fetchNpmDeps
  # ---------------------------------------------------------------------------
  # fetchNpmDeps { nodejs; python3; caCertificates; bootstrapTools;
  #                src; hash; sourceRoot?; ... }
  #
  # Fixed-output derivation that materializes a complete `node_modules` tree
  # from a committed `package.json` + `package-lock.json` (the npm analogue of
  # `fetchCargoDeps`). It runs `npm ci --ignore-scripts`, which installs
  # *exactly* the lockfile — no version resolution — so the result is
  # deterministic given the lockfile, and a pure JS tree free of store-path
  # references (which a fixed-output derivation must not contain). Native
  # (node-gyp) addons are left uncompiled and are built by the *consuming*
  # derivation, which is permitted to reference the toolchain.
  #
  # Network is allowed (FODs may reach the network). Determinism is enforced by:
  #
  #   * `npm ci` against a pinned `package-lock.json` (no floating resolution).
  #   * a build-local `npm_config_cache` (no `$HOME/.npm` leakage).
  #   * `--no-audit --no-fund` and a disabled update-notifier (no network chatter
  #     that could vary the tree or timing).
  #   * `npm_config_nodedir=${nodejs}` so node-gyp builds native addons (e.g.
  #     better-sqlite3) against the AOS node headers *offline* instead of
  #     downloading a node header tarball.
  #
  # `src` here is a directory (typically `./.` of the package dir) that contains
  # `package.json` and `package-lock.json`. The output is the populated
  # `node_modules` directory itself.
  #
  # ```text
  # <out>/
  #   .bin/                  ← CLI shims (host shebangs; consumer bypasses them)
  #   wrangler/
  #   miniflare/
  #   better-sqlite3/        ← C++ sources present; .node compiled by consumer
  #   ...
  # ```
  fetchNpmDeps = {
    nodejs,
    python3,
    caCertificates,
    bootstrapTools,
    src,
    hash,
    sourceRoot ? null,
    extraPaths ? [],
    extraLibPaths ? [],
    name ? "npm-deps",
    system ? defaultSystem,
  }: let
    ldLibPath = builtins.concatStringsSep ":" (
      builtins.map (d: "${builtins.toString d}/lib") extraLibPaths
    );
  in
    annotateFixedOutput (builtins.derivation {
      inherit name system;
      builder = builderPath;
      args = [
        "-c"
        ''
          set -eu
          export PATH="${nodejs}/bin:${python3}/bin:${bootstrapTools}/bin${builtins.concatStringsSep "" (builtins.map (p: ":${builtins.toString p}/bin") extraPaths)}"
          export SSL_CERT_FILE="${caCertificates}/etc/ssl/certs/ca-certificates.crt"
          export NODE_EXTRA_CA_CERTS="$SSL_CERT_FILE"
          ${
            if extraLibPaths != []
            then "export LD_LIBRARY_PATH=\"${ldLibPath}\""
            else ""
          }

          # Stage the package manifest + lockfile into a writable build tree.
          mkdir -p "$TMPDIR/build"
          cd "$TMPDIR/build"
          srcdir="${
            if sourceRoot != null
            then "${src}/${sourceRoot}"
            else "${src}"
          }"
          cp "$srcdir/package.json" package.json
          cp "$srcdir/package-lock.json" package-lock.json

          # Build-local, hermetic npm/node-gyp configuration.
          export HOME="$TMPDIR/home"
          export npm_config_cache="$TMPDIR/npm-cache"
          export npm_config_update_notifier=false
          export npm_config_fund=false
          export npm_config_audit=false
          export npm_config_progress=false
          export NODE_ENV=production
          mkdir -p "$HOME" "$npm_config_cache"

          # npmCli — npm ships as a JS file with a `#!/usr/bin/env node` shebang,
          # which the sandbox (no /usr/bin/env) cannot execute. Invoke through
          # node directly.
          npmCli="${nodejs}/lib/node_modules/npm/bin/npm-cli.js"

          # `npm ci --ignore-scripts` populates the lockfile-exact tree WITHOUT
          # running install lifecycle scripts. Native addons (e.g. better-sqlite3)
          # are therefore left uncompiled here: a fixed-output derivation must NOT
          # reference store paths, but a compiled `.node` carries an RPATH/interp
          # to the toolchain. Compilation happens in the *consuming* build (which
          # is allowed to reference store paths) by driving node-gyp directly;
          # see the miniflare package's install phase. Skipping scripts also
          # avoids the addons' `prebuild-install || node-gyp rebuild` install
          # hooks, whose host-style shebangs cannot run in the sandbox.
          node "$npmCli" \
            ci --no-audit --no-fund --ignore-scripts

          # Emit the populated node_modules tree (pure JS, no store references)
          # as the FOD output.
          cp -a node_modules "$out"

          # Normalize timestamps/permissions for reproducibility.
          find "$out" -exec touch -h -t 200001010000.00 {} + 2>/dev/null || true
        ''
      ];

      outputHash = hash;
      outputHashMode = "recursive";
      outputHashAlgo = "sha256";

      preferLocalBuild = true;
    }) {
      kind = "npm-deps";
      hashMode = "recursive";
      sourceInputs = [builtins.toString src];
      builderParameters = {
        sourceRoot =
          if sourceRoot == null
          then "."
          else sourceRoot;
        manifest = "package.json";
        lockfile = "package-lock.json";
        lifecycleScripts = false;
        nodejs = builtins.toString nodejs;
        inherit system;
      };
    };

  # ---------------------------------------------------------------------------
  # fetchBazelDeps
  # ---------------------------------------------------------------------------
  # fetchBazelDeps { bazel; jdk; src; hash; tools; ... }
  #
  # Fixed-output derivation that fetches all Bazel external dependencies via
  # `bazel build --nobuild`. Produces a directory containing the external/
  # subtree with store paths scrubbed for reproducibility.
  #
  # The two-phase pattern (fetchBazelDeps + bazelPhases) mirrors nixpkgs's
  # buildBazelPackage: the FOD downloads deps with network access, then the
  # build phase patchelfs ELFs and builds offline.
  fetchBazelDeps = {
    bazel,
    jdk,
    src,
    hash,
    tools ? [],
    bootstrapTools,
    caCertificates,
    # Source patching script (shared with build phase)
    postPatch ? "",
    # Additional patches for fetch phase only (e.g. bootstrap=True)
    fetchPostPatch ? "",
    # Target for `bazel build --nobuild`
    bazelTarget,
    # Common bazel flags (used in both fetch and build)
    bazelFlags ? [],
    # Fetch-specific flags
    bazelFetchFlags ? [],
    # Environment variables to set
    env ? {},
    # Store path scrubbing: { storePath = "placeholder"; }
    scrubMap ? {},
    # Extra cleanup after fetch
    postFetch ? "",
    name ? "bazel-deps",
    system ? defaultSystem,
    # Built-in repos to remove (Bazel recreates them)
    removeRepos ? [
      "bazel_tools"
      "embedded_jdk"
      "local_config_cc"
      "local_jdk"
    ],
    # Whether to populate repository_cache via empty workspace sync
    populateBCR ? true,
  }: let
    toolsPath = builtins.concatStringsSep ":" (
      builtins.map (d: "${builtins.toString d}/bin") tools
    );
    flagsStr = builtins.concatStringsSep " " bazelFlags;
    fetchFlagsStr = builtins.concatStringsSep " " bazelFetchFlags;
    envExports = builtins.concatStringsSep "\n" (
      builtins.attrValues (
        builtins.mapAttrs (k: v: "export ${k}=\"${builtins.toString v}\"") env
      )
    );
    scrubSedArgs = builtins.concatStringsSep " " (
      builtins.attrValues (
        builtins.mapAttrs (
          path: placeholder: "-e 's|${path}|${placeholder}|g'"
        )
        scrubMap
      )
    );
    padPlaceholder = path: placeholder: let
      padding = builtins.stringLength path - builtins.stringLength placeholder;
    in
      if padding < 0
      then throw "fetchBazelDeps: scrub placeholder '${placeholder}' is longer than '${path}'"
      else placeholder + builtins.concatStringsSep "" (builtins.genList (_: "_") padding);
    binaryScrubSedArgs = builtins.concatStringsSep " " (
      builtins.attrValues (
        builtins.mapAttrs (
          path: placeholder: "-e 's|${path}|${padPlaceholder path placeholder}|g'"
        )
        scrubMap
      )
    );
    scrubFiles = name: sedArgs:
      builtins.toFile name ''
        set -eu

        scratch="$(mktemp "$TMPDIR/${name}.XXXXXX")"
        active_file=
        active_mode=
        cleanup() {
          if [ -n "$active_file" ] && [ -e "$active_file" ]; then
            chmod "$active_mode" "$active_file" 2>/dev/null || true
          fi
          rm -f "$scratch"
        }
        trap cleanup EXIT
        trap 'exit 1' HUP INT TERM

        for file do
          active_file="$file"
          active_mode="$(stat -c '%a' "$file")"
          sed ${sedArgs} "$file" > "$scratch"
          chmod u+w "$file"
          cat "$scratch" > "$file"
          chmod "$active_mode" "$file"
          active_file=
          active_mode=
        done
      '';
    scrubTextFiles = scrubFiles "scrub-bazel-text" scrubSedArgs;
    scrubBinaryFiles = scrubFiles "scrub-bazel-binary" binaryScrubSedArgs;
    removeReposCmds = builtins.concatStringsSep "\n" (
      builtins.map (
        repo: "rm -rf \"$bazelOut/external/${repo}\" \"$bazelOut/external/@${repo}.marker\""
      )
      removeRepos
    );
  in
    annotateFixedOutput (builtins.derivation {
      inherit name system;
      builder = builderPath;
      args = [
        "-c"
        ''
          set -eu
          export PATH="${toolsPath}:${jdk}/bin:${bazel}/bin:$PATH"
          export HOME="$TMPDIR/home"
          mkdir -p "$HOME"
          export JAVA_HOME="${jdk}"
          export SSL_CERT_FILE="${caCertificates}/etc/ssl/certs/ca-certificates.crt"

          # Set up Rust linker flags so build scripts get the correct dynamic linker
          INTERP=$(cat "${bootstrapTools}/nix-support/dynamic-linker")
          BT_LIB=$(dirname "$INTERP")
          mkdir -p "$TMPDIR/rust-link-libs"
          for compat_lib in util:1 rt:1 dl:2 pthread:0; do
            compat_name="''${compat_lib%%:*}"
            compat_soname="''${compat_lib##*:}"
            if [ -e "$BT_LIB/lib$compat_name.so.$compat_soname" ]; then
              ln -sf "$BT_LIB/lib$compat_name.so.$compat_soname" "$TMPDIR/rust-link-libs/lib$compat_name.so"
            fi
          done
          export CARGO_BUILD_RUSTFLAGS="-Lnative=$TMPDIR/rust-link-libs -Lnative=$BT_LIB -C link-arg=-Wl,-dynamic-linker,$INTERP -C link-arg=-Wl,-rpath,$BT_LIB"

          ${envExports}

          bazelOut="$TMPDIR/output"
          bazelUserRoot="$TMPDIR/tmp"

          # Extract source
          mkdir -p "$TMPDIR/src"
          cd "$TMPDIR/src"
          tar xf "${src}" 2>/dev/null || unzip -q "${src}" 2>/dev/null || { echo "Cannot extract source"; exit 1; }
          ndirs=$(ls -d */ 2>/dev/null | wc -l)
          if [ "$ndirs" -eq 1 ]; then cd "$(ls -d */)"; fi
          SRCDIR="$(pwd)"

          # Apply shared patches
          ${postPatch}

          # Apply fetch-specific patches
          ${fetchPostPatch}

          # Set up repository cache
          mkdir -p "$bazelOut/external/repository_cache"
          echo 'common --repository_cache="'"$bazelOut"'/external/repository_cache"' >> .bazelrc

          ${
            if populateBCR
            then ''
              # Populate repository_cache with built-in repo data
              mkdir -p "$TMPDIR/empty"
              cd "$TMPDIR/empty"
              touch MODULE.bazel WORKSPACE
              bazel --batch --output_user_root="$bazelUserRoot" \
                --server_javabase="${jdk}" \
                sync --noenable_bzlmod \
                --repository_cache="$bazelOut/external/repository_cache" \
                --curses=no 2>&1 || true
              cd "$SRCDIR"
            ''
            else ""
          }

          # Fetch dependencies via build --nobuild
          BAZEL_USE_CPP_ONLY_TOOLCHAIN=1 \
          USER=nix \
          bazel --batch \
            --output_base="$bazelOut" \
            --output_user_root="$bazelUserRoot" \
            --server_javabase="${jdk}" \
            build --nobuild \
            --curses=no \
            --loading_phase_threads=1 \
            ${flagsStr} \
            ${fetchFlagsStr} \
            ${bazelTarget}

          # --- Standard cleanup ---

          # Remove built-in workspaces (Bazel recreates them)
          ${removeReposCmds}

          # Clear markers
          find "$bazelOut/external" -name '@*.marker' -exec sh -c 'echo > "$1"' _ {} \;

          # Remove VCS dirs
          find "$bazelOut/external" -type d \( -name .git -o -name .svn -o -name .hg \) \
            -exec rm -rf {} + 2>/dev/null || true

          # Remove top-level symlinks (may point to temp paths)
          find "$bazelOut/external" -maxdepth 1 -type l -delete

          # Patch symlinks to remove build dir references
          # Replace the source directory path first (more specific), then TMPDIR
          find "$bazelOut/external" -type l | while read symlink; do
            new_target="$(readlink "$symlink" | sed -e "s,$SRCDIR,__BAZEL_SRCDIR__,g" -e "s,$TMPDIR,__BAZEL_TMPDIR__,g")"
            rm "$symlink"
            ln -sf "$new_target" "$symlink"
          done

          # Strip build location from requirements.bzl
          find "$bazelOut/external" -name requirements.bzl | while read f; do
            sed -i '/# Generated from /d' "$f"
          done

          # Remove compiled Python
          find "$bazelOut" -name '*.pyc' -delete

          ${
            if scrubMap != {}
            then ''
              # --- Store path scrubbing ---
              # Binary substitutions must preserve offsets; text substitutions
              # stay compact. Rewrite through scratch files so read-only caches
              # retain their original modes.
              find "$bazelOut/external" -type f -print0 \
                | xargs -0 -r grep -IlZ . \
                | xargs -0 -r sh ${scrubTextFiles}
              find "$bazelOut/external" -type f -print0 \
                | xargs -0 -r grep -ILZ . \
                | xargs -0 -r sh ${scrubBinaryFiles}
            ''
            else ""
          }

          # --- Project-specific cleanup ---
          ${postFetch}

          # Copy external/ to output
          cp -a "$bazelOut/external" "$out"

          # Normalize permissions for reproducibility
          find "$out" -type f -exec chmod 644 {} \;
          find "$out" -type d -exec chmod 755 {} \;
        ''
      ];

      outputHash = hash;
      outputHashMode = "recursive";
      outputHashAlgo = "sha256";
      preferLocalBuild = true;
    }) {
      kind = "bazel-deps";
      hashMode = "recursive";
      sourceInputs = [builtins.toString src];
      builderParameters = {
        inherit bazelTarget bazelFlags bazelFetchFlags postPatch fetchPostPatch postFetch removeRepos populateBCR system;
        environment = builtins.mapAttrs (_: value: builtins.toString value) env;
        scrub = scrubMap;
        tools = builtins.map builtins.toString tools;
        bazel = builtins.toString bazel;
        jdk = builtins.toString jdk;
      };
    };
in {
  inherit
    mkDerivation
    mkShell
    fetchurl
    fetchgit
    fetchCargoDeps
    fetchCargoVendor
    fetchGoModules
    fetchNpmDeps
    fetchBazelDeps
    fakeHash
    ;
  inherit
    replacePhase
    addPhaseAfter
    addPhaseBefore
    removePhase
    ;

  inherit
    getOutput
    getBin
    getDev
    getExe
    getExe'
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
