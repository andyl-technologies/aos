##! Pinned source checkout for gRPC's xDS Bazel repository.
{
  fetchgit,
  buildPackages,
}: let
  moduleSource = import ./_bazel-module-source.nix {inherit fetchgit buildPackages;};
in
  moduleSource {
    name = "grpc-xds";
    version = "3a472e524827";
    url = "https://github.com/cncf/xds.git";
    rev = "3a472e524827f72d1ad621c4983dd5af54c46776";
    hash = "sha256-4fJxmqg0JkjSVm6IHaqu1OJw2K+i9qAUELLSC0oGwlM=";
    fetchCommit = true;
  }
