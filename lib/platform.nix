# lib/platform.nix — Structured platform description with constraint model
#
# Converts a Nix system string (e.g. "x86_64-linux") into a rich record
# with GNU triple, architecture flags, dynamic linker path, etc.
#
# Supports: x86_64-linux, aarch64-linux, i686-linux
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
  # ── CPU table (single source of truth) ──────────────────────────────
  # Adding a new architecture = one row. ISA compat is explicit data, not code.
  cpus = {
    x86_64 = {
      bits = 64;
      family = "x86";
      linuxArch = "x86_64";
      gnuConfig = "x86_64-unknown-linux-gnu";
      dynamicLinker = "ld-linux-x86-64.so.2";
      canExecute = [ "i686" ]; # ISA supersets this CPU can natively run
    };
    i686 = {
      bits = 32;
      family = "x86";
      linuxArch = "x86";
      gnuConfig = "i686-unknown-linux-gnu";
      dynamicLinker = "ld-linux.so.2";
      canExecute = [ ];
    };
    aarch64 = {
      bits = 64;
      family = "arm";
      linuxArch = "arm64";
      gnuConfig = "aarch64-unknown-linux-gnu";
      dynamicLinker = "ld-linux-aarch64.so.1";
      canExecute = [ ]; # armv7l would go here when supported
    };
    riscv64 = {
      bits = 64;
      family = "riscv";
      linuxArch = "riscv";
      gnuConfig = "riscv64-unknown-linux-gnu";
      dynamicLinker = "ld-linux-riscv64-lp64d.so.1";
      canExecute = [ ];
    };
  };

  knownCpuNames = builtins.attrNames cpus;

  # ── mkPlatform ──────────────────────────────────────────────────────
  mkPlatform =
    system:
    let
      parts = builtins.match "([a-z0-9_]+)-([a-z]+)" system;
      cpuName =
        if parts != null then
          builtins.elemAt parts 0
        else
          throw "platform: cannot parse system '${system}'";
      kernelName =
        if parts != null then
          builtins.elemAt parts 1
        else
          throw "platform: cannot parse system '${system}'";
    in
    if kernelName != "linux" then
      throw "platform: unsupported kernel '${kernelName}' (only linux)"
    else if !(cpus ? ${cpuName}) then
      throw "platform: unsupported CPU '${cpuName}' (known: ${builtins.concatStringsSep ", " knownCpuNames})"
    else
      let
        cpu = cpus.${cpuName};
      in
      {
        inherit system;
        config = cpu.gnuConfig;
        linuxArch = cpu.linuxArch;
        dynamicLinker = cpu.dynamicLinker;

        # Constraint identity — what this platform IS
        constraints = {
          cpu = cpuName;
          os = kernelName;
          abi = "gnu";
        };

        # ISA execution compatibility — derived from CPU table
        # Each entry = a constraint set for platforms whose binaries we can natively run
        canExecute = builtins.map (c: {
          cpu = c;
          os = kernelName;
        }) (cpu.canExecute);

        # Backward-compat booleans
        isx86_64 = cpuName == "x86_64";
        isAarch64 = cpuName == "aarch64";
        isRiscv64 = cpuName == "riscv64";
        isi686 = cpuName == "i686";
        is32bit = cpu.bits == 32;
        is64bit = cpu.bits == 64;
        isLinux = true;

        # Backward-compat parsed record
        parsed = {
          cpu = {
            name = cpuName;
            inherit (cpu) bits;
          };
          vendor = "unknown";
          kernel = {
            name = kernelName;
          };
          abi = {
            name = "gnu";
          };
        };
      };

  # ── Constraint functions ────────────────────────────────────────────

  # Does `platform` satisfy a constraint set?
  # Keys are AND, list values within a key are OR, omitted keys are unconstrained.
  satisfies =
    platform: constraints:
    builtins.all (
      key:
      let
        req = constraints.${key};
        actual = platform.constraints.${key};
      in
      if builtins.isList req then builtins.elem actual req else actual == req
    ) (builtins.attrNames constraints);

  # Can `builder` natively execute binaries matching `targetConstraints`?
  # True if builder directly satisfies, OR if any canExecute entry satisfies.
  # Keys absent from a canExecute entry are unconstrained (match anything).
  canRun =
    builder: targetConstraints:
    satisfies builder targetConstraints
    || builtins.any (
      compat:
      builtins.all (
        key:
        let
          req = targetConstraints.${key};
        in
        # If compat entry doesn't specify this key, treat as "any value OK"
        !(compat ? ${key})
        || (if builtins.isList req then builtins.elem compat.${key} req else compat.${key} == req)
      ) (builtins.attrNames targetConstraints)
    ) (builder.canExecute or [ ]);

  # Can `system` (string) build a derivation with the given BUILD constraint?
  canBuildOn =
    system: buildConstraint:
    let
      platform = mkPlatform system;
    in
    canRun platform buildConstraint;

  # Backward-compat: can `system` build packages from a meta.platforms list?
  # Accounts for ISA compatibility (x86_64 accepts i686-linux packages).
  platformIsCompatible =
    system: platforms:
    let
      build = mkPlatform system;
    in
    builtins.any (p: p == system || canRun build (mkPlatform p).constraints) platforms;

  # Priority-ordered list of constraint sets a platform can natively execute.
  # Self first (highest priority), then ISA-compatible architectures.
  # e.g. x86_64 → [ {cpu="x86_64";os="linux";abi="gnu"} {cpu="i686";os="linux"} ]
  executionTargets =
    platform:
    [ platform.constraints ] ++ (platform.canExecute or [ ]);

  # Pick the best execution platform for a given constraint set.
  # Returns the first (highest-priority) execution target that satisfies the
  # requirement, or null if no match.
  resolveTarget =
    buildPlatform: requiredConstraints:
    let
      targets = executionTargets buildPlatform;
      match = builtins.filter (
        t:
        builtins.all (
          key:
          let
            req = requiredConstraints.${key};
          in
          !(t ? ${key})
          || (if builtins.isList req then builtins.elem t.${key} req else t.${key} == req)
        ) (builtins.attrNames requiredConstraints)
      ) targets;
    in
    if match == [ ] then null else builtins.head match;

  # Construct a full platform record from a constraint set.
  # Inverse of platform.constraints — goes from { cpu, os } back to mkPlatform.
  mkPlatformFromConstraints =
    constraints:
    mkPlatform "${constraints.cpu}-${constraints.os}";

  # Can a toolchain targeting `target` produce code that runs on `execute`?
  # Both args are constraint sets. Compatible = for every key present in both,
  # their values overlap (list values are OR'd).
  constraintsCompatible =
    target: execute:
    builtins.all (
      key:
      if !(target ? ${key}) || !(execute ? ${key}) then
        true
      else
        let
          t = target.${key};
          e = execute.${key};
          tList = if builtins.isList t then t else [ t ];
          eList = if builtins.isList e then e else [ e ];
        in
        builtins.any (ev: builtins.elem ev tList) eList
    ) (builtins.attrNames (target // execute));
in
{
  inherit
    mkPlatform
    cpus
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
