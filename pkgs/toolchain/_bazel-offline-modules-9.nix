##! Pinned source modules for Bazel 9's download-disabled dependency graph.
{
  buildPackages,
  fetchgit,
}: let
  moduleSource = import ./_bazel-module-source.nix {
    inherit buildPackages fetchgit;
  };
in {
  bazel_skylib = moduleSource {
    name = "bazel_skylib";
    version = "1.8.2";
    url = "https://github.com/bazelbuild/bazel-skylib.git";
    ref = "1.8.2";
    rev = "bce8d7f8de2e48033e771f9ccdd721edf9df84e8";
    hash = "sha256-iErRflWgJWlXw0iKQDpolWTqjiUSGwgW3owTdfQt+mI=";
  };
  rules_python = moduleSource {
    name = "rules_python";
    version = "1.7.0";
    url = "https://github.com/bazelbuild/rules_python.git";
    ref = "1.7.0";
    rev = "d3ea893113375b0c0f788c3315d8a8f488d69af6";
    hash = "sha256-MThkBmljMrE+AnFP6kxODfYJMk5dQnFcf98mKhNXVKY=";
  };
  rules_java = moduleSource {
    name = "rules_java";
    version = "9.1.0";
    url = "https://github.com/bazelbuild/rules_java.git";
    ref = "9.1.0";
    rev = "b6856588ba834750a1e66b2dd1b274a1f09f66a5";
    hash = "sha256-imlMmHqXbWjgcTqf4QjUd8HJ8M1Y+N8ZWO6jzOqPmHc=";
  };
}
