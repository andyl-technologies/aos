##! Supplies actual feature qualifications to the controller's source audits.
{pkgs}: let
  policy = import ./_bazel-crucible-feature-policy.nix {inherit pkgs;};
  features = import ./_bazel-feature-powerset.nix {inherit pkgs;};
  helpers = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-controller-feature-evidence-tools";
    filter = path: type: type == "directory" || pkgs.lib.hasSuffix ".py" (baseNameOf path);
  };
in
  pkgs.runCommand "aos-bazel-controller-feature-evidence" {buildDeps = [pkgs.python3];} ''
    PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${helpers}/controller_feature_evidence.py prepare \
      --policy ${policy.all}/report.json \
      --compilation ${features.all}/report.json \
      --contract ${../../tools/bazel/metadata/crucible-feature-cases.json} \
      --policy-root ${policy.workspace.source} \
      --compilation-root ${features.workspace.source} \
      --output "$out"
    cp ${helpers}/*.py "$out/"
    cat >> "$out/BUILD.bazel" <<'BUILD'
    exports_files(["controller_feature_evidence.py"], visibility = ["//visibility:public"])
    filegroup(name = "tools", srcs = glob(["*.py"]), visibility = ["//visibility:public"])
    BUILD
  ''
