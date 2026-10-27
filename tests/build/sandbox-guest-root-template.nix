# Re-measure the registered output: Nix finalizes modes after its builder exits.
{pkgs}: let
  template = pkgs.aos-sandbox-guest-root-template;
  builder = pkgs.buildPackages.aos-sandbox-agent;
in
  pkgs.mkDerivation {
    pname = "sandbox-guest-root-template-commitment";
    version = "1";
    src = null;
    buildDeps = [builder pkgs.buildPackages.diffutils];
    runtimeDeps = [];
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          ${builder}/bin/aos-sandbox-guest-root-tree-digest \
            ${template}/root > observed-digest
          cmp ${template}/root-tree-digest observed-digest
          mkdir -p "$out"
          cp observed-digest "$out/root-tree-digest"
        '';
      }
    ];
  }
