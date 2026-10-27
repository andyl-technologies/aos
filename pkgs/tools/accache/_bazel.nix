##! Builds and checks the production compiler cache with an explicit release root.
{
  mkAosBazelWorkspace,
  mkAosBazelNativeLibraries,
  mkAosBazelCheck,
  mkAosBazelPackage,
  aosBazelRepositories,
  aosBazelRustRepositories,
  gccUnwrapped,
  stdenv,
  platformSupport,
  meta,
  passthru,
}: let
  # Match the ordinary compiler's static unwinder instead of introducing libgcc_s.
  unwinder = assert !stdenv.isCross;
    mkAosBazelNativeLibraries {
      libraries.unwinder = {
        package = gccUnwrapped // {targetSystem = stdenv.hostPlatform.system;};
        headerPackage = stdenv.glibc.dev // {targetSystem = stdenv.hostPlatform.system;};
        libraryFile = "lib/gcc/${stdenv.hostPlatform.config}/${gccUnwrapped.version}/libgcc.a";
        linkage = "static";
      };
    };
  targets = [
    "//crates/accache/accache:accache"
    "//crates/accache/accache:package"
    "//crates/accache/accache:production_license_closure"
    "//crates/accache/accache:bin_accache"
    "//crates/accache/accache-frontend:unit"
    "//crates/accache/accache-frontend:doc"
  ];
  workspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceInventory = ../../../tools/bazel/metadata/accache-inventory.json;
    dependencyProfile = "accache";
    cargoProfile = "release";
    repositories = aosBazelRepositories // aosBazelRustRepositories.accache // {aos_native = unwinder;};
    rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no" "-Cstrip=symbols"];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no" "-Cstrip=symbols"];
    analysisTargets = targets;
  };
  build = mkAosBazelCheck {
    pname = "aos-bazel-accache-production";
    inherit workspace targets;
    # The cache executable cannot acquire a dependency on its configured self.
    sharedBuildCache = false;
    retainActionGraph = true;
  };
in
  mkAosBazelPackage {
    pname = "accache";
    version = "0.1.0";
    inherit build platformSupport meta;
    passthru = passthru // {bazelWorkspace = workspace;};
    packageLabel = "//crates/accache/accache:package";
  }
