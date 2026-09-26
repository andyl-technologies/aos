##! Source-only Git checkout for a pinned Bazel module.
{
  fetchgit,
  buildPackages,
}: {
  name,
  version,
  url,
  ref ? null,
  rev,
  hash,
  fetchCommit ? false,
  extraExcludes ? [],
}:
fetchgit {
  inherit url ref rev hash fetchCommit;
  name = "${name}-${version}-source-only";

  git = buildPackages.git-minimal;
  caCertificates = buildPackages.ca-certificates;
  coreutils = buildPackages.coreutils;

  # Partial clone omits excluded blobs before they enter the store.
  sparsePatterns =
    [
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
    ]
    ++ extraExcludes;
}
