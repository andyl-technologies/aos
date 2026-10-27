##! Supplies declared graph and configured license data in one runtime repository.
{pkgs}: let
  licenses = import ./_bazel-license-closures.nix {inherit pkgs;};
in
  pkgs.runCommand "aos-bazel-controller-audit-inputs" {} ''
    mkdir -p "$out"
    cp ${pkgs.aosBazelArchitecture}/architecture.json "$out/architecture.json"
    cp ${licenses}/license-closures.json "$out/license-closures.json"
    cat > "$out/BUILD.bazel" <<'BUILD'
    exports_files(["architecture.json", "license-closures.json"], visibility = ["//visibility:public"])
    BUILD
    touch "$out/REPO.bazel"
  ''
