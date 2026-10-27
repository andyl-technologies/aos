##! Explicit managed SDK snapshot containers and their write-authority boundary.
{lib}: let
  canonicalPath = path:
    builtins.match "/[A-Za-z0-9_./-]+" path
    != null
    && builtins.all (part: part != "" && part != "." && part != "..") (builtins.tail (lib.splitString "/" path));
  overlaps = a: b: a == b || lib.hasPrefix "${a}/" b || lib.hasPrefix "${b}/" a;
  contains = root: path: lib.hasPrefix "${root}/" path;
in {
  type = lib.types.listOf (lib.types.addCheck lib.types.str canonicalPath);

  checks = {
    outputRoots,
    exposures,
    protectedPaths,
    store,
    localRepository,
  }: let
    endpoints = map (exposure: exposure.at) (builtins.filter (exposure: exposure.surface == "sdk") exposures);
    # The configured SDK currently supports only this leaf store. Refuse an
    # unrecognized spelling rather than guessing where repository data lives.
    bucket = builtins.match "bucket\\(file://(/[^)]+)\\)" store;
    bucketPaths = lib.optionals (localRepository != null && bucket != null) bucket;
    authorityPaths = lib.optional (localRepository != null) localRepository.authorityDirectory;
    isolatedPaths =
      protectedPaths
      ++ bucketPaths
      ++ authorityPaths
      ++ [
        "/etc"
        "/nix"
        "/usr"
        "/bin"
        "/sbin"
        "/lib"
        "/lib64"
        "/boot"
        "/dev"
        "/proc"
        "/sys"
        "/home"
        "/root"
        "/tmp"
        "/var/tmp"
        "/run/systemd"
      ];
  in [
    {
      assertion =
        builtins.all canonicalPath endpoints
        && builtins.all (endpoint: builtins.length (builtins.filter (root: contains root endpoint) outputRoots) == 1) endpoints;
      message = "Terrane managed SDK endpoints must be canonical absolute paths strictly beneath one explicit sdkOutputRoots container.";
    }
    {
      assertion =
        builtins.length (lib.unique outputRoots)
        == builtins.length outputRoots
        && builtins.all (root:
          builtins.all (other: root == other || !overlaps root other) outputRoots
          && builtins.any (contains root) endpoints)
        outputRoots;
      message = "Terrane SDK output roots must be distinct, non-overlapping dedicated containers used by configured SDK endpoints.";
    }
    {
      assertion =
        outputRoots
        == []
        || (
          (localRepository == null || bucket != null)
          && builtins.all canonicalPath isolatedPaths
          && builtins.all (root: builtins.all (path: !overlaps root path) isolatedPaths) outputRoots
        );
      message = "Terrane SDK output roots must stay disjoint from canonical repository, cache, credential, control and system paths; local repository stores require an exact canonical bucket(file:///...) leaf.";
    }
  ];
}
