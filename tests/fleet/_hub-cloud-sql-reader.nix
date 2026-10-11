# Builds a source-selected SELECT-only connector observer, without cloud effects.
# goModules must be an independently retained AOS fetchGoModules output matching
# these exact go.mod/go.sum inputs; no host proxy or mutable module cache is used.
{
  pkgs,
  source,
  goModules,
}: let
  readerSource = "${source}/tests/fleet/observation-tools/cloud_sql_reader";
  querySource = "${source}/tests/fleet/_hub-native-sql-projection.py";
  querySourceSha256 = builtins.hashFile "sha256" querySource;
  readerSourceSha256 = builtins.hashString "sha256" (
    builtins.readFile "${readerSource}/main.go"
    + builtins.readFile "${readerSource}/go.mod"
    + builtins.readFile "${readerSource}/go.sum"
    + builtins.readFile querySource
  );
  pythonMajorMinor = builtins.head (builtins.match "([0-9]+\\.[0-9]+).*" pkgs.python3.version);
in
  pkgs.mkGoPackage {
    pname = "aos-cloud-sql-reader";
    version = "0.1.0";
    src = readerSource;
    inherit goModules;
    goPackage = ".";
    goOutput = "aos-cloud-sql-reader";
    ldflags = "-X main.pythonPath=${pkgs.python3}/bin/python${pythonMajorMinor} -X main.querySourcePath=${querySource} -X main.querySourceSHA=${querySourceSha256} -X main.readerSourceSHA=${readerSourceSha256}";
    runtimeDeps = [pkgs.python3];
    GOMAXPROCS = "4";
    doParallelCheck = false;
    doCheck = true;
    sharedBuildCache = false;
    dontNukeRefs = true;
    passthru.evidenceSources = [querySource ./_hub-cloud-sql-reader.nix];
    meta.description = "Source-selected read-only Cloud SQL snapshot observer";
  }
