##! Bazel 9 source checkout without bundled compiled artifacts.
{
  fetchgit,
  buildPackages,
}:
(import ./_bazel-source-checkout.nix {inherit fetchgit buildPackages;}) {
  version = "9.2.0";
  rev = "8220c6198837d5c13d53fea211cf3282aa12408a";
  hash = "sha256-Z5fu3Kd9mhXMPeBvTvEaEhkTbDmVrpslQdelEus1tGM=";
}
