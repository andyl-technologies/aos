##! Bazel 8 source checkout without bundled compiled artifacts.
{
  fetchgit,
  buildPackages,
}:
(import ./_bazel-source-checkout.nix {inherit fetchgit buildPackages;}) {
  version = "8.6.0";
  rev = "f473e987e30ae64c852461b51eb8e69a8542a9e0";
  hash = "sha256-TB8u6AVpZejX6LC8m1Zqil17J7+KyREHoLu2PqQfTOE=";
}
