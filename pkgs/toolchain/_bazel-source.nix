##! Bazel 7 source checkout without bundled compiled artifacts.
{
  fetchgit,
  buildPackages,
}:
fetchgit {
  url = "https://github.com/bazelbuild/bazel.git";
  ref = "7.7.1";
  rev = "f4104dcf95cc726672c9d7d80dcc2907d3d57209";
  name = "bazel-7.7.1-source-only";
  hash = "sha256-lrNdrwnzlv7qe9nASUGo/R10aMWtypCp+X2Swz35YoY=";

  git = buildPackages.git-minimal;
  caCertificates = buildPackages.ca-certificates;
  coreutils = buildPackages.coreutils;

  # The pinned tag tracks 46 compiled/archive fixtures. Exclude their blobs
  # before checkout; source-built replacements enter through declared inputs.
  sparsePatterns = [
    "/*"
    "!*.jar"
    "!*.class"
    "!*.so"
    "!*.a"
    "!*.o"
    "!*.wasm"
    "!*.dll"
    "!*.dylib"
    "!*.exe"
    "!*.bin"
    "!*.zip"
    "!*.tar"
    "!*.gz"
    "!*.xz"
  ];
}
