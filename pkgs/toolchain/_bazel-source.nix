##! Bazel 7 source checkout without bundled compiled artifacts.
{
  fetchgit,
  buildPackages,
}:
(import ./_bazel-source-checkout.nix {inherit fetchgit buildPackages;}) {
  version = "7.7.1";
  rev = "f4104dcf95cc726672c9d7d80dcc2907d3d57209";
  hash = "sha256-mbf2cIqgzFQt0ADDjMM+sxjihTkaZh3sOAI4+d5ZO34=";
}
