##! Source-only platforms module embedded by Bazel's Java bootstrap.
{
  fetchgit,
  buildPackages,
}:
fetchgit {
  url = "https://github.com/bazelbuild/platforms.git";
  ref = "1.0.0";
  rev = "ab99943ab6bed53cff461a3afa99fc79d31e4351";
  hash = "sha256-8MRSiwq+ghdB9vNMuczbJxx/K6iNEiVbKRPJTllp7SA=";
  name = "bazel-platforms-1.0.0-source-only";

  git = buildPackages.git-minimal;
  caCertificates = buildPackages.ca-certificates;
  coreutils = buildPackages.coreutils;

  sparsePatterns = [
    "/*"
    "!*.jar"
    "!*.class"
    "!*.so"
    "!*.a"
    "!*.ar"
    "!*.aar"
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
