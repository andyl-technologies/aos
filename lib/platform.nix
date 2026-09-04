# lib/platform.nix — Structured platform description with constraint model
#
# Converts a Nix system string (for example, "x86_64-linux" or
# "aarch64-darwin") into a record containing the canonical toolchain triple,
# object format, architecture spellings, and execution constraints.
#
# Three-platform model:
#   buildPlatform  — where the builder runs (Nix scheduling)
#   hostPlatform   — where the output binary runs
#   targetPlatform — what code a compiler generates (compilers only)
#
# For native builds all three are identical. Cross-compilation decouples them.
#
# Constraint model:
#   Every platform exposes a `constraints` attrset ({ cpu, os, abi }) and a
#   `canExecute` list of constraint sets for ISA-compatible architectures.
#   Verification functions (satisfies, canRun, canBuildOn) check compatibility
#   at evaluation time.
let
  # CPU properties deliberately exclude OS-specific triples and ABI details.
  # Adding a CPU requires one row here and an explicit decision in each kernel's
  # supportedCpus list below.
  cpus = {
    x86_64 = {
      bits = 64;
      family = "x86";
      linuxArch = "x86_64";
      darwinArch = "x86_64";
      goArch = "amd64";
      cmakeProcessor = "x86_64";
      mesonCpuFamily = "x86_64";
      mesonCpu = "x86_64";
      canExecute = ["i686"];
    };
    i686 = {
      bits = 32;
      family = "x86";
      linuxArch = "x86";
      goArch = "386";
      cmakeProcessor = "x86";
      mesonCpuFamily = "x86";
      mesonCpu = "i686";
      canExecute = [];
    };
    aarch64 = {
      bits = 64;
      family = "arm";
      linuxArch = "arm64";
      darwinArch = "arm64";
      goArch = "arm64";
      cmakeProcessor = "arm64";
      mesonCpuFamily = "aarch64";
      mesonCpu = "aarch64";
      canExecute = [];
    };
    riscv64 = {
      bits = 64;
      family = "riscv";
      linuxArch = "riscv";
      goArch = "riscv64";
      cmakeProcessor = "riscv64";
      mesonCpuFamily = "riscv64";
      mesonCpu = "riscv64";
      canExecute = [];
    };
  };

  # Kernel/ABI properties own target triples and executable compatibility.
  # Darwin intentionally has no cross-CPU `canExecute` entries: Rosetta is an
  # optional proprietary service, not an invariant of a Darwin build machine.
  kernels = {
    linux = {
      abi = "gnu";
      vendor = "unknown";
      objectFormat = "elf";
      sharedLibraryExtension = "so";
      staticLibraryExtension = "a";
      executableExtension = "";
      supportedCpus = ["x86_64" "i686" "aarch64" "riscv64"];
      config = cpuName: "${cpuName}-unknown-linux-gnu";
      dynamicLinker = cpuName:
        {
          x86_64 = "ld-linux-x86-64.so.2";
          i686 = "ld-linux.so.2";
          aarch64 = "ld-linux-aarch64.so.1";
          riscv64 = "ld-linux-riscv64-lp64d.so.1";
        }.${
          cpuName
        };
      executableCpus = cpu: cpu.canExecute;
    };
    darwin = {
      abi = "darwin";
      vendor = "apple";
      objectFormat = "macho";
      sharedLibraryExtension = "dylib";
      staticLibraryExtension = "a";
      executableExtension = "";
      supportedCpus = ["x86_64" "aarch64"];
      config = cpuName: "${cpuName}-apple-darwin";
      dynamicLinker = _: "dyld";
      executableCpus = _: [];
    };
  };

  knownCpuNames = builtins.attrNames cpus;
  knownKernelNames = builtins.attrNames kernels;

  # Construct a platform identity from a canonical Nix system string.
  mkPlatform = system: let
    parts = builtins.match "([a-z0-9_]+)-([a-z]+)" system;
    cpuName =
      if parts != null
      then builtins.elemAt parts 0
      else throw "platform: cannot parse system '${system}'";
    kernelName =
      if parts != null
      then builtins.elemAt parts 1
      else throw "platform: cannot parse system '${system}'";
  in
    if !(kernels ? ${kernelName})
    then throw "platform: unsupported kernel '${kernelName}' (known: ${builtins.concatStringsSep ", " knownKernelNames})"
    else if !(cpus ? ${cpuName})
    then throw "platform: unsupported CPU '${cpuName}' (known: ${builtins.concatStringsSep ", " knownCpuNames})"
    else let
      cpu = cpus.${cpuName};
      kernel = kernels.${kernelName};
    in
      if !(builtins.elem cpuName kernel.supportedCpus)
      then throw "platform: unsupported CPU/kernel pair '${system}'"
      else {
        inherit system;
        config = kernel.config cpuName;
        linuxArch = cpu.linuxArch or null;
        darwinArch = cpu.darwinArch or null;
        go = {
          os = kernelName;
          arch = cpu.goArch;
        };
        inherit
          (cpu)
          cmakeProcessor
          mesonCpuFamily
          mesonCpu
          ;
        dynamicLinker = kernel.dynamicLinker cpuName;
        inherit
          (kernel)
          objectFormat
          sharedLibraryExtension
          staticLibraryExtension
          executableExtension
          ;

        # Constraint identity — what this platform is.
        constraints = {
          cpu = cpuName;
          os = kernelName;
          inherit (kernel) abi;
        };

        # ISA execution compatibility is scoped to the kernel. Each entry is a
        # constraint set for binaries this platform can execute without an
        # optional translation or emulation service.
        canExecute = builtins.map (compatibleCpu: {
          cpu = compatibleCpu;
          os = kernelName;
        }) (kernel.executableCpus cpu);

        # Backward-compatible platform predicates.
        isx86_64 = cpuName == "x86_64";
        isAarch64 = cpuName == "aarch64";
        isRiscv64 = cpuName == "riscv64";
        isi686 = cpuName == "i686";
        is32bit = cpu.bits == 32;
        is64bit = cpu.bits == 64;
        isLinux = kernelName == "linux";
        isDarwin = kernelName == "darwin";

        # Backward-compatible parsed record.
        parsed = {
          cpu = {
            name = cpuName;
            inherit (cpu) bits;
          };
          inherit (kernel) vendor;
          kernel = {
            name = kernelName;
          };
          abi = {
            name = kernel.abi;
          };
        };
      };

  # Does `platform` satisfy a constraint set?
  # Keys are AND, list values within a key are OR, omitted keys are unconstrained.
  satisfies = platform: constraints:
    builtins.all (
      key: let
        req = constraints.${key};
        actual = platform.constraints.${key};
      in
        if builtins.isList req
        then builtins.elem actual req
        else actual == req
    ) (builtins.attrNames constraints);

  # Can `builder` natively execute binaries matching `targetConstraints`?
  # True if builder directly satisfies, OR if any canExecute entry satisfies.
  # Keys absent from a canExecute entry are unconstrained (match anything).
  canRun = builder: targetConstraints:
    satisfies builder targetConstraints
    || builtins.any (
      compat:
        builtins.all (
          key: let
            req = targetConstraints.${key};
          in
            !(compat ? ${key})
            || (
              if builtins.isList req
              then builtins.elem compat.${key} req
              else compat.${key} == req
            )
        ) (builtins.attrNames targetConstraints)
    ) (builder.canExecute or []);

  # Can `system` (string) build a derivation with the given BUILD constraint?
  canBuildOn = system: buildConstraint: let
    platform = mkPlatform system;
  in
    canRun platform buildConstraint;

  # Backward-compatible compatibility for a meta.platforms system list.
  platformIsCompatible = system: platforms: let
    build = mkPlatform system;
  in
    builtins.any (p: p == system || canRun build (mkPlatform p).constraints) platforms;

  # Priority-ordered list of constraint sets a platform can execute natively.
  # Self is first (highest priority), followed by ISA-compatible architectures.
  executionTargets = platform:
    [platform.constraints] ++ (platform.canExecute or []);

  # Pick the best execution platform for a given constraint set.
  # Returns the first (highest-priority) execution target that satisfies the
  # requirement, or null if no match.
  resolveTarget = buildPlatform: requiredConstraints: let
    targets = executionTargets buildPlatform;
    match =
      builtins.filter (
        t:
          builtins.all (
            key: let
              req = requiredConstraints.${key};
            in
              !(t ? ${key})
              || (
                if builtins.isList req
                then builtins.elem t.${key} req
                else t.${key} == req
              )
          ) (builtins.attrNames requiredConstraints)
      )
      targets;
  in
    if match == []
    then null
    else builtins.head match;

  # Construct a full platform record from a constraint set.
  # Inverse of platform.constraints — goes from { cpu, os } to mkPlatform.
  mkPlatformFromConstraints = constraints:
    mkPlatform "${constraints.cpu}-${constraints.os}";

  # Can a toolchain targeting `target` produce code that runs on `execute`?
  # Both args are constraint sets. Compatible = for every key present in both,
  # their values overlap (list values are OR'd).
  constraintsCompatible = target: execute:
    builtins.all (
      key:
        if !(target ? ${key}) || !(execute ? ${key})
        then true
        else let
          t = target.${key};
          e = execute.${key};
          tList =
            if builtins.isList t
            then t
            else [t];
          eList =
            if builtins.isList e
            then e
            else [e];
        in
          builtins.any (ev: builtins.elem ev tList) eList
    ) (builtins.attrNames (target // execute));
in {
  inherit
    mkPlatform
    cpus
    kernels
    satisfies
    canRun
    canBuildOn
    platformIsCompatible
    constraintsCompatible
    executionTargets
    resolveTarget
    mkPlatformFromConstraints
    ;
}
