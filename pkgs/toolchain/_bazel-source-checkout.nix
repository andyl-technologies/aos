##! Pinned Bazel source checkout without bundled compiled artifacts.
{
  fetchgit,
  buildPackages,
}: {
  version,
  rev,
  hash,
}:
fetchgit {
  url = "https://github.com/bazelbuild/bazel.git";
  ref = version;
  inherit rev hash;
  name = "bazel-${version}-source-only";

  git = buildPackages.git-minimal;
  caCertificates = buildPackages.ca-certificates;
  coreutils = buildPackages.coreutils;

  # Git tracks compiled fixtures and release archives alongside the sources.
  # Fetch the source tree without checking out those blobs.
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
