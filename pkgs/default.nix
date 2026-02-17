##! ANDYL OS — Package set composition.
##! Imports all package definitions and wires dependencies together.
##! Bootstrap tools (gcc, coreutils, tar, etc.) are injected into every build.
##! All other tools are built hermetically from source — no nixpkgs, no host tools.
{lib}: let
  fetchurl = lib.fetchurl;

  # Pre-built bootstrap tools provide gcc, coreutils, tar, make, etc.
  # in the Nix build sandbox where no system tools are available.
  bootstrapTools = import ../stdenv/bootstrap-tools.nix {
    system = lib.system;
  };

  # Dynamic linker path inside bootstrap-tools (architecture-dependent).
  dynamicLinker =
    if lib.system == "aarch64-linux"
    then "${bootstrapTools}/lib/ld-linux-aarch64.so.1"
    else "${bootstrapTools}/lib/ld-linux-x86-64.so.2";

  # Common compiler/linker flags needed because bootstrap tools' store
  # paths were nuked.  Every invocation of gcc/g++/cpp/ld must include these.
  defaultCFlags = "-B${bootstrapTools}/lib -isystem ${bootstrapTools}/include-glibc";
  defaultLdFlags = "-L${bootstrapTools}/lib -Wl,-dynamic-linker=${dynamicLinker} -Wl,-rpath,${bootstrapTools}/lib";

  # CC wrapper — shell scripts that prepend the required flags to every
  # gcc/g++/cpp/ld invocation.  This mirrors the nixpkgs cc-wrapper
  # approach: even when a Makefile calls bare `gcc`, the wrapper ensures
  # headers and libraries are found.
  ccWrapper = builtins.derivation {
    name = "cc-wrapper";
    system = lib.system;
    builder = "/bin/sh";
    PATH = "${bootstrapTools}/bin";
    # Pass values as env vars so the builder script can reference them
    REAL_GCC = "${bootstrapTools}/bin/gcc";
    REAL_GPP = "${bootstrapTools}/bin/g++";
    REAL_CPP = "${bootstrapTools}/bin/cpp";
    REAL_LD = "${bootstrapTools}/bin/ld";
    BT_LIB = "${bootstrapTools}/lib";
    BT_INC = "${bootstrapTools}/include-glibc";
    CRT1 = "${bootstrapTools}/lib/crt1.o";
    DYN_LINK = dynamicLinker;
    args = [
      "-c"
      ''
              set -e
              mkdir -p $out/bin $out/lib

              # Create Scrt1.o (PIE variant) — symlink to crt1.o since the
              # bootstrap glibc doesn't ship Scrt1.o separately.
              ln -s $CRT1 $out/lib/Scrt1.o
              ln -s $CRT1 $out/lib/rcrt1.o

              # Discover C++ include paths for -nostdinc++ re-addition.
              # Bootstrap GCC's built-in system header dir was nuked, so
              # #include_next <stdlib.h> from cstdlib fails.  Fix: use
              # -nostdinc++ to remove the broken built-in C++ search dirs,
              # then re-add them via -isystem WITH include-glibc placed AFTER
              # the C++ dirs.  This lets #include_next find stdlib.h.
              BT_ROOT=$(dirname $BT_LIB)
              CXX_VER=$(ls "$BT_ROOT/include/c++")
              BT_CXX="$BT_ROOT/include/c++/$CXX_VER"
              BT_CXX_ARCH=$(ls -d "$BT_CXX"/*-linux-gnu 2>/dev/null | head -1)
              BT_CXX_BACKWARD="$BT_CXX/backward"

              # Discover GCC library directory (contains libstdc++.so, libgcc_s.so)
              BT_GCC_LIB=$(ls -d "$BT_LIB/gcc"/*/*/ 2>/dev/null | head -1)

              # gcc wrapper (C only — no C++ path issues)
              # $NIX_LDFLAGS is set by mkDerivation with -Wl,-rpath for all deps
              # -isystem $BT_INC goes AFTER "$@" so build-system headers (e.g.
              # systemd override) can shadow bootstrap glibc headers (matches
              # nixpkgs cc-wrapper extraAfter ordering).
              cat > $out/bin/gcc << GCCEOF
        #!/bin/sh
        exec $REAL_GCC -B$out/lib -B$BT_LIB -L$BT_LIB -L$BT_GCC_LIB -Wl,-dynamic-linker=$DYN_LINK -Wl,-rpath,$BT_LIB -Wl,-rpath,$BT_GCC_LIB \$NIX_LDFLAGS "\$@" -isystem $BT_INC
        GCCEOF

              cp $out/bin/gcc $out/bin/cc

              # g++ wrapper — uses -nostdinc++ then re-adds C++ headers before
              # glibc headers so #include_next from cstdlib finds stdlib.h.
              # Only -isystem $BT_INC (glibc) goes AFTER "$@" so build-system
              # headers can shadow it; C++ paths stay before "$@".
              cat > $out/bin/g++ << GPPEOF
        #!/bin/sh
        exec $REAL_GPP -nostdinc++ -isystem $BT_CXX -isystem $BT_CXX_ARCH -isystem $BT_CXX_BACKWARD -B$out/lib -B$BT_LIB -L$BT_LIB -L$BT_GCC_LIB -Wl,-dynamic-linker=$DYN_LINK -Wl,-rpath,$BT_LIB -Wl,-rpath,$BT_GCC_LIB \$NIX_LDFLAGS "\$@" -isystem $BT_INC
        GPPEOF

              cp $out/bin/g++ $out/bin/c++

              # cpp wrapper (preprocessor only)
              cat > $out/bin/cpp << CPPEOF
        #!/bin/sh
        exec $REAL_CPP "\$@" -isystem $BT_INC
        CPPEOF

              # ld wrapper — note: ld uses -rpath (not -Wl,-rpath), so we don't
              # pass $NIX_LDFLAGS here (which uses gcc format).  Builds go through
              # gcc/g++ which handle it.
              cat > $out/bin/ld << LDEOF
        #!/bin/sh
        exec $REAL_LD -L$BT_LIB -L$BT_GCC_LIB -dynamic-linker=$DYN_LINK -rpath $BT_LIB -rpath $BT_GCC_LIB "\$@"
        LDEOF

              chmod +x $out/bin/*
      ''
    ];
  };

  # Wrap lib.mkDerivation to automatically include bootstrap tools in PATH
  # and set the correct compiler/linker flags so that compiled programs
  # can find the dynamic linker and shared libraries.
  mkDerivation = args:
    lib.mkDerivation (
      args
      // {
        # ccWrapper goes first in PATH so its wrappers shadow bootstrap gcc
        buildDeps =
          [
            ccWrapper
            bootstrapTools
          ]
          ++ (args.buildDeps or []);

        # Explicit CC/CXX/CPP point to wrappers so configure scripts use them
        CC = "${ccWrapper}/bin/gcc";
        CXX = "${ccWrapper}/bin/g++";
        CPP = "${ccWrapper}/bin/cpp";
        AR = "${bootstrapTools}/bin/ar";
        AS = "${bootstrapTools}/bin/as";
        LD = "${ccWrapper}/bin/ld";
        NM = "${bootstrapTools}/bin/nm";
        RANLIB = "${bootstrapTools}/bin/ranlib";
        STRIP = "${bootstrapTools}/bin/strip";
        CONFIG_SHELL = "${bootstrapTools}/bin/bash";

        # Also set CFLAGS/LDFLAGS for build systems that use them directly
        CPPFLAGS = "-isystem ${bootstrapTools}/include-glibc ${args.CPPFLAGS or ""}";
        CFLAGS = "${defaultCFlags} ${args.CFLAGS or ""}";
        LDFLAGS = "${defaultLdFlags} ${args.LDFLAGS or ""}";
      }
    );

  # Import phase generators from stdenv/phases.nix
  phases = import ../stdenv/phases.nix;

  # Wire fetchers with AOS toolchains (using lazy self-reference)
  fetchCargoDeps = args:
    lib.fetchCargoDeps (
      args
      // {
        cargo = self.rust;
        inherit bootstrapTools;
        extraLibPaths =
          [
            self.openssl
            self.zlib
          ]
          ++ (args.extraLibPaths or []);
      }
    );

  fetchGoModules = args:
    lib.fetchGoModules (
      args
      // {
        go = self.go;
        inherit bootstrapTools;
      }
    );

  # Attrs that mkCargoPackage consumes (not passed to mkDerivation)
  cargoSpecificAttrs = [
    "cargoDeps"
    "cargoFlags"
    "buildType"
    "checkType"
    "cargoTestFlags"
    "buildFeatures"
    "buildNoDefaultFeatures"
    "installBins"
    "installLibs"
    "doCheck"
    "doParallelCheck"
    "gitDeps"
  ];

  # Attrs that mkGoPackage consumes (not passed to mkDerivation)
  goSpecificAttrs = [
    "goModules"
    "goPackage"
    "goOutput"
    "cgoEnabled"
    "ldflags"
    "tags"
    "doCheck"
    "goTestFlags"
    "doParallelCheck"
  ];

  mkCargoPackage = args: let
    # Extract cargo-specific attrs for the phase generator
    cargoArgs =
      builtins.intersectAttrs (builtins.listToAttrs (
        builtins.map (n: {
          name = n;
          value = true;
        })
        cargoSpecificAttrs
      ))
      args;
    # Remove cargo-specific attrs before passing to mkDerivation
    restArgs = builtins.removeAttrs args cargoSpecificAttrs;
  in
    mkDerivation (
      restArgs
      // {
        buildDeps = [self.rust] ++ (args.buildDeps or []);
        phases = phases.cargoPhases cargoArgs;
      }
    );

  mkGoPackage = args: let
    goArgs =
      builtins.intersectAttrs (builtins.listToAttrs (
        builtins.map (n: {
          name = n;
          value = true;
        })
        goSpecificAttrs
      ))
      args;
    # Default goOutput to pname when not explicitly set
    goArgsWithDefaults =
      goArgs
      // {
        goOutput = args.goOutput or args.pname or (throw "mkGoPackage: goOutput or pname required");
      };
    restArgs = builtins.removeAttrs args goSpecificAttrs;
  in
    mkDerivation (
      restArgs
      // {
        buildDeps = [self.go] ++ (args.buildDeps or []);
        phases = phases.goPhases goArgsWithDefaults;
      }
    );

  # callPackage: import a package file and auto-fill its arguments from `self`.
  # The package file is a function whose formals are introspected via
  # builtins.functionArgs, then satisfied from the package set plus the
  # always-available helpers (mkDerivation, fetchurl).
  callPackage = path: overrides: let
    fn = import path;
    auto = builtins.intersectAttrs (builtins.functionArgs fn) (
      self
      // {
        inherit mkDerivation fetchurl;
      }
    );
  in
    fn (auto // overrides);

  # Shared Linux kernel source (single tarball for linux and linux-headers)
  linuxSource = import ./kernel/_source.nix {inherit fetchurl;};

  # Shared Kubernetes source (single tarball for kubelet, kubeadm, kubectl)
  kubeSource = import ./kubernetes/_source.nix {inherit fetchurl;};

  # Auto-discover packages from subdirectories.
  # Recursively scans for .nix files, skipping default.nix and _-prefixed
  # files/directories (used for shared resources like _source.nix).
  discoverPackages = dir: let
    entries = builtins.readDir dir;
    names = builtins.attrNames entries;

    # .nix files → packages (skip default.nix and _-prefixed)
    nixFiles =
      builtins.filter (
        name:
          entries.${name}
          == "regular"
          && lib.hasSuffix ".nix" name
          && name != "default.nix"
          && builtins.substring 0 1 name != "_"
      )
      names;

    # Subdirectories to recurse into (skip _-prefixed)
    subdirs =
      builtins.filter (
        name: entries.${name} == "directory" && builtins.substring 0 1 name != "_"
      )
      names;

    filePackages = builtins.listToAttrs (
      builtins.map (name: {
        name = lib.removeSuffix ".nix" name;
        value = callPackage (dir + "/${name}") {};
      })
      nixFiles
    );

    subdirPackages =
      builtins.foldl' (
        acc: subdir: acc // discoverPackages (dir + "/${subdir}")
      ) {}
      subdirs;
  in
    filePackages // subdirPackages;

  self =
    {
      # --- Plumbing ---
      inherit mkDerivation fetchurl lib;
      inherit mkCargoPackage mkGoPackage;
      inherit fetchCargoDeps fetchGoModules;
      inherit bootstrapTools;
      fakeHash = lib.fakeHash;
    }
    // discoverPackages ./.
    // {
      # --- Explicit overrides for packages needing non-standard arguments ---
      linux = callPackage ./kernel/linux.nix {inherit linuxSource;};
      linux-headers = callPackage ./kernel/linux-headers.nix {inherit linuxSource;};

      kubelet = callPackage ./kubernetes/kubelet.nix {inherit kubeSource;};
      kubeadm = callPackage ./kubernetes/kubeadm.nix {inherit kubeSource;};
      kubectl = callPackage ./kubernetes/kubectl.nix {inherit kubeSource;};
    };
in
  self
