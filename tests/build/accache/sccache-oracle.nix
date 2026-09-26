##! Test-only reference implementation, pinned with the extracted frontend.
{pkgs}: let
  revision = "8396f0209d74d496b7cb27cdf323cd3ff8d4a291";
  src = pkgs.fetchurl {
    urls = ["https://codeload.github.com/mozilla/sccache/tar.gz/${revision}"];
    hash = "sha256-mVfx49aVm1ni3Y+cqxe1/MtAKCG2Y2UMOQxah4JBxlM=";
  };
in
  pkgs.mkCargoPackage {
    pname = "accache-sccache-oracle";
    version = "0.18.0";
    inherit src;
    sharedBuildCache = false;
    cargoDeps = pkgs.fetchCargoDeps {
      inherit src;
      hash = "sha256-qGiiIuWfyeww5gHUWjkRfpXnbcpt6cXYQKJ6nrMGfhE=";
    };
    # This fixture exercises the local frontend. Cloud clients and remote workers
    # are outside the oracle's contract and would add unrelated dependencies.
    buildNoDefaultFeatures = true;
    cargoFlags = "--bin sccache";
    doCheck = false;
  }
