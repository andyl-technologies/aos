# MEMO-2 source-Merkle boundary keying — static reverse-dependency-cone analysis.
#
# Design: docs/rfcs/0007-nix-evaluator/design-notes/memo2-applied-boundary-seeding-plan.md
# §11.8. The source-Merkle boundary key (§11.2) invalidates a package boundary
# iff a file in its transitive *dependency* cone changes; conversely, editing a
# package P invalidates every boundary in P's *reverse*-dependency cone. Whether
# MEMO-2 boundary seeding is a product-level warm-coverage win therefore rests on
# the reverse-dependency-cone size distribution: small cones ⇒ a leaf edit
# replays ~everything; a fat fan-in ⇒ edits invalidate most of the set.
#
# This file computes that distribution WITHOUT building or evaluating any
# package. It uses exactly the information the source-Merkle key would use — each
# package file's static formal set (`builtins.functionArgs (import file)`, which
# is what `callPackage`'s `intersectAttrs (functionArgs fn) self` consumes) —
# resolved against the discovered package-name universe. It is underscore-prefixed
# so `discoverPackages` skips it.
#
# Run (one command; pure, no stdenv, no builds):
#   nix eval --impure --json --file pkgs/_memo2-cone-analysis.nix
#
# `--impure` is only needed because the file reads its own directory via relative
# paths; nothing impure enters the result.
let
  # Framework / plumbing names that `callPackage` supplies from `self` but which
  # are NOT package files (no source identity, "correctly global" hubs): the
  # explicit plumbing and stdenv pass-throughs from pkgs/default.nix's `self`,
  # plus the shared-source override arguments. A formal naming one of these
  # resolves but contributes no dependency-cone edge.
  frameworkNames = builtins.listToAttrs (map (n: {
    name = n;
    value = true;
  }) [
    # Plumbing
    "mkDerivation"
    "fetchurl"
    "lib"
    "mkCargoPackage"
    "mkGoPackage"
    "mkBazelPackage"
    "fetchCargoDeps"
    "fetchCargoVendor"
    "fetchGoModules"
    "fetchBazelDeps"
    "bootstrapTools"
    "fakeHash"
    "stdenv"
    "nuke-references"
    # stdenv pass-throughs exposed flat on the set
    "gcc"
    "glibc"
    "binutils"
    "cc"
    "gccUnwrapped"
    "getent"
    "bash"
    "coreutils"
    "gnumake"
    "sed"
    "grep"
    "findutils"
    "gawk"
    "diffutils"
    "tar"
    "gzip"
    "patch"
    # Trivial-builder re-exports
    "writeTextFile"
    "writeShellScriptBin"
    "runtimeShell"
    "runCommand"
    # Shared-source override arguments (provided per-package in default.nix)
    "linuxSource"
    "kubeSource"
    "kubeedgeSource"
  ]);

  # Recursively discover package files exactly as `discoverPackages` does: `.nix`
  # files that are not `default.nix` and not underscore-prefixed, recursing into
  # non-underscore subdirectories. Yields `{ name; path; }` records.
  discover = dir: let
    entries = builtins.readDir dir;
    names = builtins.attrNames entries;
    nixFiles = builtins.filter (
      name:
        entries.${name}
        == "regular"
        && builtins.match ".*\\.nix" name != null
        && name != "default.nix"
        && builtins.substring 0 1 name != "_"
    )
    names;
    subdirs = builtins.filter (
      name: entries.${name} == "directory" && builtins.substring 0 1 name != "_"
    )
    names;
    here = map (name: {
      name = builtins.substring 0 (builtins.stringLength name - 4) name;
      path = dir + "/${name}";
    })
    nixFiles;
    deeper = builtins.concatMap (subdir: discover (dir + "/${subdir}")) subdirs;
  in
    here ++ deeper;

  packages = discover ./.;
  packageNameSet = builtins.listToAttrs (map (p: {
    name = p.name;
    value = true;
  })
  packages);

  # Static formals of one package file, or `null` when the file's top-level is
  # not a resolvable function (its formals cannot be read without evaluating it).
  formalsOf = path: let
    attempt = builtins.tryEval (builtins.attrNames (builtins.functionArgs (import path)));
  in
    if attempt.success
    then attempt.value
    else null;

  # Classify every package's formals into dependency edges (formal names that
  # are package files), framework references, and declines (unresolved).
  classified = map (p: let
    formals = formalsOf p.path;
    ok = formals != null;
    resolvedFormals =
      if ok
      then formals
      else [];
    deps = builtins.filter (f: packageNameSet ? ${f}) resolvedFormals;
    framework = builtins.filter (f: (! (packageNameSet ? ${f})) && (frameworkNames ? ${f})) resolvedFormals;
    decline = builtins.filter (f: (! (packageNameSet ? ${f})) && (! (frameworkNames ? ${f}))) resolvedFormals;
  in {
    inherit (p) name;
    inherit ok deps framework decline;
    formalCount =
      if ok
      then builtins.length formals
      else 0;
  })
  packages;

  # Reverse edges: for each package, the packages that declare it as a formal.
  reverseEdges = let
    empty = builtins.listToAttrs (map (p: {
      name = p.name;
      value = [];
    })
    packages);
    add = acc: c:
      builtins.foldl' (
        a: dep:
          a // {${dep} = (a.${dep} or []) ++ [c.name];}
      )
      acc
      c.deps;
  in
    builtins.foldl' add empty classified;

  # Reverse-dependency cone size for `name`: the number of packages invalidated
  # when `name`'s source changes — itself plus every package that transitively
  # depends on it. Cycle-safe via genericClosure.
  reverseConeSize = name:
    builtins.length (builtins.genericClosure {
      startSet = [{key = name;}];
      operator = item: map (k: {key = k;}) (reverseEdges.${item.key} or []);
    });

  total = builtins.length packages;
  coneSizes = builtins.sort (a: b: a < b) (map (p: reverseConeSize p.name) packages);

  # Percentile pick from an ascending list (nearest-rank).
  pctl = p: let
    n = builtins.length coneSizes;
    idx = let
      raw = (p * n) / 100;
    in
      if raw >= n
      then n - 1
      else raw;
  in
    if n == 0
    then 0
    else builtins.elemAt coneSizes idx;

  sumList = builtins.foldl' (a: b: a + b) 0;

  # Framework-hub frequency: how many packages reference each framework name.
  hubCounts = let
    bump = acc: c:
      builtins.foldl' (
        a: f:
          a // {${f} = (a.${f} or 0) + 1;}
      )
      acc
      c.framework;
  in
    builtins.foldl' bump {} classified;
  hubList = builtins.sort (a: b: a.count > b.count) (map (n: {
    name = n;
    count = hubCounts.${n};
  }) (builtins.attrNames hubCounts));

  totalFormals = sumList (map (c: c.formalCount) classified);
  totalDeps = sumList (map (c: builtins.length c.deps) classified);
  totalFramework = sumList (map (c: builtins.length c.framework) classified);
  totalDecline = sumList (map (c: builtins.length c.decline) classified);
  unreadable = builtins.filter (c: ! c.ok) classified;
  declineNames = builtins.filter (c: builtins.length c.decline > 0) classified;
in {
  # (1) Reverse-dependency-cone size distribution (packages invalidated per edit,
  #     including the edited package). Replay fraction for editing a package =
  #     1 - cone_size / total.
  cone_distribution = {
    packages = total;
    min = pctl 0;
    median = pctl 50;
    p90 = pctl 90;
    p99 = pctl 99;
    max = pctl 100;
    mean_x1000 =
      if total == 0
      then 0
      else (1000 * sumList coneSizes) / total;
    median_replay_fraction_x1000 =
      if total == 0
      then 0
      else 1000 - (1000 * pctl 50) / total;
    p90_replay_fraction_x1000 =
      if total == 0
      then 0
      else 1000 - (1000 * pctl 90) / total;
  };

  # (2) Static-resolution coverage: how many formals resolve to a package
  #     dependency or a framework reference vs. DECLINE (unresolvable ⇒ the
  #     boundary would decline admission under §11.2).
  resolution_coverage = {
    total_formals = totalFormals;
    dep_edges = totalDeps;
    framework_refs = totalFramework;
    declines = totalDecline;
    resolved_fraction_x1000 =
      if totalFormals == 0
      then 0
      else (1000 * (totalDeps + totalFramework)) / totalFormals;
    packages_with_any_decline = builtins.length declineNames;
    packages_unreadable = builtins.length unreadable;
    # Sample of unresolved formals for auditing (are declines real, or a
    # missed framework name?).
    decline_sample = builtins.listToAttrs (map (c: {
      inherit (c) name;
      value = c.decline;
    }) (
      let
        n = builtins.length declineNames;
      in
        if n > 40
        then builtins.genList (i: builtins.elemAt declineNames i) 40
        else declineNames
    ));
    unreadable_files = map (c: c.name) unreadable;
  };

  # (3) Fat hubs — framework names (stdenv/mkDerivation/fetchurl-class) whose
  #     reverse cone is correctly global. Reported separately so they do not
  #     distort the package-to-package cone distribution above.
  framework_hubs = builtins.genList (i: builtins.elemAt hubList i) (
    let
      n = builtins.length hubList;
    in
      if n > 20
      then 20
      else n
  );
}
